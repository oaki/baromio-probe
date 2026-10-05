package api

import (
	"testing"
	"time"
)

func TestBackoffNeverExceedsMax(t *testing.T) {
	b := NewBackoff(time.Second, 10*time.Second)

	for i := 0; i < 20; i++ {
		if d := b.Next(); d > 10*time.Second {
			t.Fatalf("attempt %d exceeded max: %v", i, d)
		}
	}
}

func TestBackoffResetRestartsFromBase(t *testing.T) {
	b := NewBackoff(time.Millisecond, time.Hour)

	for i := 0; i < 10; i++ {
		b.Next()
	}

	b.Reset()

	// After reset, the ceiling should be back near base, so repeated calls
	// stay small far more often than not - a loose statistical check, not an
	// exact one, since Next() is randomized.
	var sawSmall bool
	for i := 0; i < 5; i++ {
		if b.Next() < 100*time.Millisecond {
			sawSmall = true
		}
	}

	if !sawSmall {
		t.Error("expected at least one small delay shortly after reset")
	}
}
