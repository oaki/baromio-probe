// Package buffer holds check results the Probe could not yet report to
// Baromio (network down, server error), as an append-only JSONL file capped
// at 24h and 50MB - oldest dropped and counted past either limit
// (docs/design-plans/2026-10-05-private-probe.md §7.1).
package buffer

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	fileName = "buffer.jsonl"
	MaxAge   = 24 * time.Hour
	MaxBytes = 50 * 1024 * 1024
)

// Entry is one buffered check result, the shape sent as one element of
// `results` on /api/v1/probe/report.
type Entry struct {
	ID           string         `json:"id"`
	MonitorID    string         `json:"monitor_id"`
	CheckedAt    int64          `json:"checked_at"`
	IsUp         bool           `json:"is_up"`
	StatusCode   *int           `json:"status_code,omitempty"`
	ErrorCode    *int           `json:"error_code,omitempty"`
	Method       string         `json:"method,omitempty"`
	FallbackUsed bool           `json:"fallback_used,omitempty"`
	TimingsMs    map[string]int `json:"timings_ms,omitempty"`
	TLS          *TLSEntry      `json:"tls,omitempty"`
	KeywordFound *bool          `json:"keyword_found,omitempty"`
}

// NewID returns a fresh result id as a UUID v7 (RFC 9562), the format the
// report contract requires (§5.3): Baromio validates it as a UUID and
// stores it in a PostgreSQL uuid column for retry dedupe. The leading
// 48-bit millisecond timestamp keeps ids roughly in check order.
func NewID() string {
	var b [16]byte

	binary.BigEndian.PutUint64(b[:8], uint64(time.Now().UnixMilli())<<16)
	if _, err := rand.Read(b[6:]); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}

	b[6] = 0x70 | (b[6] & 0x0f) // version 7
	b[8] = 0x80 | (b[8] & 0x3f) // RFC 9562 variant

	h := hex.EncodeToString(b[:])

	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// TLSEntry is the TLS leaf certificate info attached to a result.
type TLSEntry struct {
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
}

// pruneInterval throttles the age-based prune. Without it a buffer sitting
// right at the 24h boundary would rewrite the whole file on every append,
// since each new result pushes one old one over the edge.
const pruneInterval = time.Minute

// lineHead is the part of a JSONL line the buffer itself needs. Decoding only
// this keeps pruning and removal from building a full Entry per line.
type lineHead struct {
	ID        string `json:"id"`
	CheckedAt int64  `json:"checked_at"`
}

// Buffer is the on-disk result queue. It never holds the whole file in
// memory: appends write one line, reads stream the oldest lines, and
// rewrites stream the file through a temp file, so memory use does not grow
// with the backlog.
type Buffer struct {
	mu       sync.Mutex
	path     string
	maxBytes int64

	size      int64     // bytes in the file
	oldest    int64     // checked_at of the first line, 0 when the file is empty
	lastPrune time.Time // last age-based prune
}

// Open prepares the buffer file in dataDir, creating it if absent.
func Open(dataDir string) (*Buffer, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}

	path := filepath.Join(dataDir, fileName)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening buffer file: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("reading buffer file size: %w", err)
	}

	size := info.Size()

	// A crash mid-append leaves a line without its newline; terminate it so
	// the next append does not glue onto it and lose a good result too.
	if size > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], size-1); err != nil {
			return nil, fmt.Errorf("reading buffer file: %w", err)
		}
		if last[0] != '\n' {
			if _, err := f.Write([]byte{'\n'}); err != nil {
				return nil, fmt.Errorf("terminating buffer file: %w", err)
			}
			size++
		}
	}

	b := &Buffer{path: path, maxBytes: MaxBytes, size: size}

	err = b.eachLine(func(line []byte) bool {
		var h lineHead
		if json.Unmarshal(line, &h) != nil {
			return true
		}
		b.oldest = h.CheckedAt
		return false
	})
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Append adds one entry, then prunes anything past MaxAge or MaxBytes.
// Returns the number of older entries dropped to make room, which the next
// report's `dropped_results` field carries.
func (b *Buffer) Append(e Entry) (dropped int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	line, err := json.Marshal(e)
	if err != nil {
		return 0, fmt.Errorf("encoding entry: %w", err)
	}
	line = append(line, '\n')

	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, fmt.Errorf("opening buffer file: %w", err)
	}

	if _, err := f.Write(line); err != nil {
		f.Close()
		return 0, fmt.Errorf("appending to buffer file: %w", err)
	}

	if err := f.Close(); err != nil {
		return 0, fmt.Errorf("closing buffer file: %w", err)
	}

	if b.size == 0 {
		b.oldest = e.CheckedAt
	}
	b.size += int64(len(line))

	return b.pruneLocked(time.Now())
}

// pruneLocked drops entries past MaxAge or beyond the byte limit, oldest
// first. The size limit prunes down to 90% so the next appends do not each
// trigger another rewrite.
func (b *Buffer) pruneLocked(now time.Time) (dropped int, err error) {
	cutoff := now.Add(-MaxAge).Unix()

	var excess int64
	if b.size > b.maxBytes {
		excess = b.size - (b.maxBytes - b.maxBytes/10)
	}

	aged := b.oldest != 0 && b.oldest < cutoff && now.Sub(b.lastPrune) >= pruneInterval
	if excess == 0 && !aged {
		return 0, nil
	}

	b.lastPrune = now

	var skipped int64

	return b.rewriteLocked(func(h lineHead, n int64) bool {
		if skipped < excess {
			skipped += n
			return false
		}
		return h.CheckedAt >= cutoff
	})
}

// All returns every buffered entry, oldest first. It holds the whole buffer
// in memory, so the Probe itself uses Batch instead.
func (b *Buffer) All() ([]Entry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var entries []Entry

	err := b.eachLine(func(line []byte) bool {
		var e Entry
		if json.Unmarshal(line, &e) == nil {
			entries = append(entries, e)
		}
		return true
	})
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// Batch returns up to max of the oldest entries, and whether more are left
// behind them. Baromio refuses a report over its per-request limit with 413,
// so a buffer that grew during an outage has to drain in batches - sending
// it whole would fail the same way on every retry and never empty.
func (b *Buffer) Batch(max int) (entries []Entry, more bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	err = b.eachLine(func(line []byte) bool {
		var e Entry
		if json.Unmarshal(line, &e) != nil {
			return true // a half-written line from a crash mid-append: skip, don't fail the whole buffer
		}

		if len(entries) == max {
			more = true
			return false
		}

		entries = append(entries, e)

		return true
	})
	if err != nil {
		return nil, false, err
	}

	return entries, more, nil
}

// Remove drops every entry whose ID is in ids - the results Baromio has
// already accepted.
func (b *Buffer) Remove(ids map[string]bool) error {
	if len(ids) == 0 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	_, err := b.rewriteLocked(func(h lineHead, _ int64) bool {
		return !ids[h.ID]
	})

	return err
}

// eachLine streams the buffer file in order, one line at a time, until fn
// returns false. Blank lines are skipped; the line is only valid for the
// duration of the call.
func (b *Buffer) eachLine(fn func(line []byte) bool) error {
	f, err := os.Open(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("opening buffer file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 16*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		if !fn(line) {
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading buffer file: %w", err)
	}

	return nil
}

// rewriteLocked streams the file through a temp file, keeping the lines keep
// accepts (n is the line's size on disk, newline included), then swaps it in.
// Lines that do not decode - a half-written line from a crash - are dropped
// without being counted. Returns how many entries keep refused.
func (b *Buffer) rewriteLocked(keep func(h lineHead, n int64) bool) (dropped int, err error) {
	tmp := b.path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("creating temp buffer file: %w", err)
	}

	var size, oldest int64

	w := bufio.NewWriter(f)

	err = b.eachLine(func(line []byte) bool {
		var h lineHead
		if json.Unmarshal(line, &h) != nil {
			return true
		}

		n := int64(len(line)) + 1
		if !keep(h, n) {
			dropped++
			return true
		}

		if size == 0 {
			oldest = h.CheckedAt
		}

		w.Write(line)
		w.WriteByte('\n')
		size += n

		return true
	})
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return 0, err
	}

	if err := w.Flush(); err != nil {
		f.Close()
		os.Remove(tmp)
		return 0, fmt.Errorf("flushing buffer file: %w", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("closing temp buffer file: %w", err)
	}

	if err := os.Rename(tmp, b.path); err != nil {
		os.Remove(tmp)
		return 0, fmt.Errorf("replacing buffer file: %w", err)
	}

	b.size = size
	b.oldest = oldest

	return dropped, nil
}
