package scheduler

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNextIntervalUsesDownModeWhenDown(t *testing.T) {
	got := nextInterval(300, true)
	if got != DownModeInterval {
		t.Errorf("expected DownModeInterval while down, got %v", got)
	}
}

func TestNextIntervalUsesConfiguredIntervalWhenUp(t *testing.T) {
	got := nextInterval(300, false)
	if got != 300*time.Second {
		t.Errorf("expected the configured interval while up, got %v", got)
	}
}

func TestNextIntervalNeverSlowsDownAFastMonitor(t *testing.T) {
	// A monitor already faster than DownModeInterval must not be slowed down
	// by "down mode".
	got := nextInterval(5, true)
	if got != 5*time.Second {
		t.Errorf("expected the faster configured interval to win, got %v", got)
	}
}

func TestJitterStaysWithinTenPercent(t *testing.T) {
	interval := 100 * time.Second

	for i := 0; i < 50; i++ {
		got := jitter(interval)
		if got < 90*time.Second || got > 110*time.Second {
			t.Fatalf("jittered interval %v outside +/-10%% of %v", got, interval)
		}
	}
}

func TestSetMonitorsStartsAndChecksEachMonitor(t *testing.T) {
	var calls int32
	s := New(func(ctx context.Context, cfg MonitorConfig) bool {
		atomic.AddInt32(&calls, 1)
		return true
	})
	defer s.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.SetMonitors(ctx, []MonitorConfig{
		{ID: "m1", Type: "http", IntervalSeconds: 1},
		{ID: "m2", Type: "tcp", IntervalSeconds: 1},
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&calls) < 2 {
		time.Sleep(10 * time.Millisecond)
	}

	if atomic.LoadInt32(&calls) < 2 {
		t.Fatalf("expected both monitors to have been checked at least once, got %d calls", calls)
	}
}

func TestSetMonitorsStopsARemovedMonitor(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]bool{}

	s := New(func(ctx context.Context, cfg MonitorConfig) bool {
		mu.Lock()
		seen[cfg.ID] = true
		mu.Unlock()
		return true
	})
	defer s.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.SetMonitors(ctx, []MonitorConfig{{ID: "m1", Type: "http", IntervalSeconds: 1}})

	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		sawIt := seen["m1"]
		mu.Unlock()
		if sawIt {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.SetMonitors(ctx, []MonitorConfig{}) // removes m1

	s.mu.Lock()
	remaining := len(s.monitors)
	s.mu.Unlock()

	if remaining != 0 {
		t.Errorf("expected no monitors left running, got %d", remaining)
	}
}

func TestConcurrencyNeverExceedsTheCap(t *testing.T) {
	var current, maxSeen int32

	s := New(func(ctx context.Context, cfg MonitorConfig) bool {
		n := atomic.AddInt32(&current, 1)
		for {
			old := atomic.LoadInt32(&maxSeen)
			if n <= old || atomic.CompareAndSwapInt32(&maxSeen, old, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&current, -1)
		return true
	})
	defer s.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	configs := make([]MonitorConfig, 0, MaxConcurrentChecks*2)
	for i := 0; i < MaxConcurrentChecks*2; i++ {
		configs = append(configs, MonitorConfig{ID: string(rune('a' + i)), Type: "http", IntervalSeconds: 1})
	}

	s.SetMonitors(ctx, configs)

	time.Sleep(500 * time.Millisecond)

	if atomic.LoadInt32(&maxSeen) > MaxConcurrentChecks {
		t.Errorf("expected at most %d concurrent checks, saw %d", MaxConcurrentChecks, maxSeen)
	}
}
