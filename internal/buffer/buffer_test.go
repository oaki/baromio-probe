package buffer

import (
	"testing"
	"time"
)

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
