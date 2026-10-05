// Package scheduler runs one independent timer per monitor, respects a
// concurrency cap, and checks a down monitor more often until it recovers
// (Down-Mode Acceleration), per
// docs/design-plans/2026-10-05-private-probe.md §7.1.
package scheduler

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// MaxConcurrentChecks caps how many checks may run at once across every
// monitor, so one slow target cannot starve the rest.
const MaxConcurrentChecks = 20

// DownModeInterval is how often a monitor already known to be down is
// re-checked, regardless of its configured interval - faster confirmation
// of a recovery without hammering a healthy target.
const DownModeInterval = 15 * time.Second

// MonitorConfig is one monitor this Probe is responsible for checking.
type MonitorConfig struct {
	ID              string
	Type            string // http, keyword, tcp
	IntervalSeconds int
	TimeoutSeconds  int
	URL             string
	Headers         map[string]string
	Keyword         string
	KeywordType     string
	Host            string
	Port            int
}

// equal reports whether two configs describe the same check, including
// their headers. MonitorConfig itself is not comparable with == because of
// the Headers map.
func (c MonitorConfig) equal(other MonitorConfig) bool {
	if c.ID != other.ID || c.Type != other.Type || c.IntervalSeconds != other.IntervalSeconds ||
		c.TimeoutSeconds != other.TimeoutSeconds || c.URL != other.URL || c.Keyword != other.Keyword ||
		c.KeywordType != other.KeywordType || c.Host != other.Host || c.Port != other.Port {
		return false
	}

	if len(c.Headers) != len(other.Headers) {
		return false
	}

	for k, v := range c.Headers {
		if other.Headers[k] != v {
			return false
		}
	}

	return true
}

// CheckFunc runs one check for a monitor and reports whether it is up.
// Supplied by the caller (main) so this package stays independent of the
// concrete http/tcp checkers and the result buffer.
type CheckFunc func(ctx context.Context, cfg MonitorConfig) (isUp bool)

// Scheduler owns one goroutine per monitor plus a semaphore enforcing
// MaxConcurrentChecks.
type Scheduler struct {
	check CheckFunc
	sem   chan struct{}

	mu       sync.Mutex
	monitors map[string]*monitorState
}

type monitorState struct {
	cfg    MonitorConfig
	cancel context.CancelFunc
	isDown bool
}

// New builds a Scheduler that calls check for every due monitor.
func New(check CheckFunc) *Scheduler {
	return &Scheduler{
		check:    check,
		sem:      make(chan struct{}, MaxConcurrentChecks),
		monitors: make(map[string]*monitorState),
	}
}

// SetMonitors reconciles the running set against the latest config: starts
// a timer for each new monitor, stops one that disappeared or changed, and
// leaves an unchanged one running undisturbed (so it keeps its down-mode
// state and does not reset its check cadence on every config poll).
func (s *Scheduler) SetMonitors(ctx context.Context, configs []MonitorConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()

	seen := make(map[string]bool, len(configs))

	for _, cfg := range configs {
		seen[cfg.ID] = true

		if existing, ok := s.monitors[cfg.ID]; ok {
			if existing.cfg.equal(cfg) {
				continue
			}
			existing.cancel()
		}

		monitorCtx, cancel := context.WithCancel(ctx)
		state := &monitorState{cfg: cfg, cancel: cancel}
		s.monitors[cfg.ID] = state

		go s.run(monitorCtx, state)
	}

	for id, state := range s.monitors {
		if !seen[id] {
			state.cancel()
			delete(s.monitors, id)
		}
	}
}

// Stop cancels every running monitor timer.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, state := range s.monitors {
		state.cancel()
	}
	s.monitors = make(map[string]*monitorState)
}

func (s *Scheduler) run(ctx context.Context, state *monitorState) {
	// Initial jitter so many monitors on the same interval don't all fire
	// together, especially right after a config change enrolls several at
	// once.
	select {
	case <-ctx.Done():
		return
	case <-time.After(jitter(time.Duration(state.cfg.IntervalSeconds) * time.Second)):
	}

	for {
		s.runOne(ctx, state)

		interval := nextInterval(state.cfg.IntervalSeconds, state.isDown)

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (s *Scheduler) runOne(ctx context.Context, state *monitorState) {
	select {
	case s.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	defer func() { <-s.sem }()

	isUp := s.check(ctx, state.cfg)

	s.mu.Lock()
	state.isDown = !isUp
	s.mu.Unlock()
}

// nextInterval picks the check cadence: the monitor's own interval normally,
// or DownModeInterval (if shorter) while it is known down.
func nextInterval(intervalSeconds int, isDown bool) time.Duration {
	configured := time.Duration(intervalSeconds) * time.Second

	if isDown && DownModeInterval < configured {
		return DownModeInterval
	}

	return configured
}

// jitter spreads an interval by up to +/-10%, so many monitors on the same
// configured interval do not all check at the same instant.
func jitter(interval time.Duration) time.Duration {
	if interval <= 0 {
		return 0
	}

	spread := interval / 10
	if spread <= 0 {
		return interval
	}

	return interval - spread + time.Duration(rand.Int63n(int64(2*spread)))
}
