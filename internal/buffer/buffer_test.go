package buffer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// uuidV7 matches the canonical 8-4-4-4-12 form with version nibble 7 and
// the RFC 9562 variant (8, 9, a or b) - what Baromio's `uuid` validation
// rule and its PostgreSQL uuid column both require of a result id.
var uuidV7 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewIDIsAUuidV7(t *testing.T) {
	id := NewID()

	if !uuidV7.MatchString(id) {
		t.Fatalf("expected a lowercase UUID v7, got %q", id)
	}
}

func TestNewIDIsUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)

	for i := 0; i < 1000; i++ {
		id := NewID()
		if seen[id] {
			t.Fatalf("duplicate id %q after %d calls", id, i)
		}
		seen[id] = true
	}
}

func TestNewIDSortsByCreationTime(t *testing.T) {
	first := NewID()
	time.Sleep(2 * time.Millisecond)
	second := NewID()

	if first >= second {
		t.Errorf("expected a later id to sort after an earlier one, got %q then %q", first, second)
	}
}

func TestAppendAndAll(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := b.Append(Entry{ID: "a", MonitorID: "m1", CheckedAt: time.Now().Unix(), IsUp: true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := b.Append(Entry{ID: "b", MonitorID: "m1", CheckedAt: time.Now().Unix(), IsUp: false}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, err := b.All()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}

func TestAppendDropsExistingEntriesThatAgeOutOnTheNextAppend(t *testing.T) {
	dir := t.TempDir()

	// A result left over from before MaxAge, as after a long outage.
	aged := fmt.Sprintf("{\"id\":\"aged\",\"monitor_id\":\"m1\",\"checked_at\":%d}\n",
		time.Now().Add(-MaxAge-time.Minute).Unix())
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(aged), 0o600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, err := Open(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	dropped, err := b.Append(Entry{ID: "new", MonitorID: "m1", CheckedAt: time.Now().Unix()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if dropped != 1 {
		t.Errorf("expected 1 dropped entry, got %d", dropped)
	}

	remaining, _ := b.All()
	if len(remaining) != 1 || remaining[0].ID != "new" {
		t.Errorf("expected only the new entry to remain, got %+v", remaining)
	}
}

func TestAppendDropsOldestEntriesPastTheByteLimit(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b.maxBytes = 2000 // about ten of these entries

	now := time.Now().Unix()
	totalDropped := 0

	for i := 0; i < 50; i++ {
		dropped, err := b.Append(Entry{ID: fmt.Sprintf("id-%02d", i), MonitorID: "m1", CheckedAt: now})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		totalDropped += dropped
	}

	info, err := os.Stat(b.path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Size() > b.maxBytes {
		t.Errorf("expected the file within %d bytes, got %d", b.maxBytes, info.Size())
	}

	entries, _ := b.All()
	if len(entries) == 0 || entries[len(entries)-1].ID != "id-49" {
		t.Fatalf("expected the newest entry to survive, got %+v", entries)
	}
	if entries[0].ID == "id-00" {
		t.Error("expected the oldest entry to be dropped first")
	}
	if totalDropped+len(entries) != 50 {
		t.Errorf("expected dropped (%d) plus kept (%d) to account for all 50 entries", totalDropped, len(entries))
	}
}

func TestAppendDoesNotRewriteTheFileWhileUnderBothLimits(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b.Append(Entry{ID: "a", CheckedAt: time.Now().Unix()})

	before, _ := os.Stat(b.path)

	b.Append(Entry{ID: "b", CheckedAt: time.Now().Unix()})

	after, _ := os.Stat(b.path)
	if !os.SameFile(before, after) {
		t.Error("expected an append to extend the existing file, not replace it")
	}
}

func TestOpenRestoresStateFromAnExistingFile(t *testing.T) {
	dir := t.TempDir()

	b1, _ := Open(dir)
	b1.Append(Entry{ID: "a", CheckedAt: time.Now().Unix()})
	b1.Append(Entry{ID: "b", CheckedAt: time.Now().Unix()})

	b2, err := Open(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if b2.size != b1.size {
		t.Errorf("expected size %d after reopen, got %d", b1.size, b2.size)
	}

	entries, _ := b2.All()
	if len(entries) != 2 {
		t.Errorf("expected both entries after reopen, got %d", len(entries))
	}
}

func TestHalfWrittenLineDoesNotCostTheNextResult(t *testing.T) {
	dir := t.TempDir()

	now := time.Now().Unix()
	content := fmt.Sprintf("{\"id\":\"good\",\"checked_at\":%d}\n{\"id\":\"half\",\"chec", now)
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(content), 0o600); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, err := Open(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := b.Append(Entry{ID: "next", CheckedAt: now}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, _ := b.All()
	if len(entries) != 2 || entries[0].ID != "good" || entries[1].ID != "next" {
		t.Errorf("expected good and next to survive the torn line, got %+v", entries)
	}
}

func TestBatchReturnsTheOldestEntriesUpToTheLimit(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	now := time.Now().Unix()
	b.Append(Entry{ID: "first", CheckedAt: now})
	b.Append(Entry{ID: "second", CheckedAt: now})
	b.Append(Entry{ID: "third", CheckedAt: now})

	batch, more, err := b.Batch(2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(batch) != 2 || batch[0].ID != "first" || batch[1].ID != "second" {
		t.Errorf("expected the two oldest entries, got %+v", batch)
	}
	if !more {
		t.Error("expected more=true while a third entry is still waiting")
	}
}

func TestBatchReportsNoMoreWhenEverythingFits(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b.Append(Entry{ID: "only", CheckedAt: time.Now().Unix()})

	batch, more, err := b.Batch(500)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(batch) != 1 {
		t.Errorf("expected the single entry, got %d", len(batch))
	}
	if more {
		t.Error("expected more=false when the whole buffer fits in one batch")
	}
}

func TestRemoveDropsAcceptedEntries(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b.Append(Entry{ID: "a", CheckedAt: time.Now().Unix()})
	b.Append(Entry{ID: "b", CheckedAt: time.Now().Unix()})

	if err := b.Remove(map[string]bool{"a": true}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries, _ := b.All()
	if len(entries) != 1 || entries[0].ID != "b" {
		t.Errorf("expected only entry b to remain, got %+v", entries)
	}
}

func TestOpenOnExistingDataDirIsIdempotent(t *testing.T) {
	dir := t.TempDir()

	if _, err := Open(dir); err != nil {
		t.Fatalf("unexpected error on first open: %v", err)
	}

	b2, err := Open(dir)
	if err != nil {
		t.Fatalf("unexpected error on second open: %v", err)
	}

	entries, err := b2.All()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected an empty buffer, got %d entries", len(entries))
	}
}
