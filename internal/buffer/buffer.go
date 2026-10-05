// Package buffer holds check results the Probe could not yet report to
// Baromio (network down, server error), as an append-only JSONL file capped
// at 24h and 50MB - oldest dropped and counted past either limit
// (docs/design-plans/2026-10-05-private-probe.md §7.1).
package buffer

import (
	"bufio"
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

// TLSEntry is the TLS leaf certificate info attached to a result.
type TLSEntry struct {
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Issuer    string `json:"issuer,omitempty"`
}

// Buffer is the on-disk result queue.
type Buffer struct {
	mu   sync.Mutex
	path string
}

// Open prepares the buffer file in dataDir, creating it if absent.
func Open(dataDir string) (*Buffer, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating data dir: %w", err)
	}

	path := filepath.Join(dataDir, fileName)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening buffer file: %w", err)
	}
	f.Close()

	return &Buffer{path: path}, nil
}

// Append adds one entry, then prunes anything past MaxAge or MaxBytes.
// Returns the number of older entries dropped to make room, which the next
// report's `dropped_results` field carries.
func (b *Buffer) Append(e Entry) (dropped int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	entries, err := b.readAllLocked()
	if err != nil {
		return 0, err
	}

	entries = append(entries, e)

	cutoff := time.Now().Add(-MaxAge).Unix()
	kept := entries[:0]
	for _, entry := range entries {
		if entry.CheckedAt < cutoff {
			dropped++
			continue
		}
		kept = append(kept, entry)
	}

	kept, droppedForSize := enforceByteLimit(kept)
	dropped += droppedForSize

	if err := b.writeAllLocked(kept); err != nil {
		return 0, err
	}

	return dropped, nil
}

// enforceByteLimit drops the oldest entries until the JSONL-encoded size of
// the remainder fits within MaxBytes.
func enforceByteLimit(entries []Entry) ([]Entry, int) {
	dropped := 0

	for {
		size := 0
		for _, e := range entries {
			line, _ := json.Marshal(e)
			size += len(line) + 1
		}

		if size <= MaxBytes || len(entries) == 0 {
			return entries, dropped
		}

		entries = entries[1:]
		dropped++
	}
}

// All returns every buffered entry, oldest first.
func (b *Buffer) All() ([]Entry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.readAllLocked()
}

// Remove drops every entry whose ID is in ids - the results Baromio has
// already accepted.
func (b *Buffer) Remove(ids map[string]bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	entries, err := b.readAllLocked()
	if err != nil {
		return err
	}

	kept := entries[:0]
	for _, e := range entries {
		if !ids[e.ID] {
			kept = append(kept, e)
		}
	}

	return b.writeAllLocked(kept)
}

func (b *Buffer) readAllLocked() ([]Entry, error) {
	f, err := os.Open(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("opening buffer file: %w", err)
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue // a half-written line from a crash mid-append: skip, don't fail the whole buffer
		}

		entries = append(entries, e)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading buffer file: %w", err)
	}

	return entries, nil
}

func (b *Buffer) writeAllLocked(entries []Entry) error {
	tmp := b.path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating temp buffer file: %w", err)
	}

	w := bufio.NewWriter(f)
	for _, e := range entries {
		line, err := json.Marshal(e)
		if err != nil {
			f.Close()
			return fmt.Errorf("encoding entry: %w", err)
		}
		w.Write(line)
		w.WriteByte('\n')
	}

	if err := w.Flush(); err != nil {
		f.Close()
		return fmt.Errorf("flushing buffer file: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("closing temp buffer file: %w", err)
	}

	return os.Rename(tmp, b.path)
}
