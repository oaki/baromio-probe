package buffer

import (
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
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Within range today, but old enough that MaxAge has elapsed by the time
	// the next result is buffered.
	agingSoon := time.Now().Add(-MaxAge + time.Minute).Unix()
	if _, err := b.Append(Entry{ID: "aging", MonitorID: "m1", CheckedAt: agingSoon}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate two minutes passing by writing the next entry with a
	// checked_at that puts "aging" outside the window.
	laterCutoffEntry := Entry{ID: "new", MonitorID: "m1", CheckedAt: time.Now().Unix()}
	b.mu.Lock()
	entries, _ := b.readAllLocked()
	entries[0].CheckedAt = time.Now().Add(-MaxAge - time.Minute).Unix()
	b.writeAllLocked(entries)
	b.mu.Unlock()

	dropped, err := b.Append(laterCutoffEntry)
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
