package api

import (
	"math/rand"
	"time"
)

// Backoff is an exponential backoff with full jitter, for retrying a failed
// report or config poll without hammering Baromio during an outage.
type Backoff struct {
	attempt int
	base    time.Duration
	max     time.Duration
}

// NewBackoff builds a Backoff starting at base and capped at max.
func NewBackoff(base, max time.Duration) *Backoff {
	return &Backoff{base: base, max: max}
}

// Next returns the delay to wait before the next retry, and advances the
// attempt counter. Full jitter: a random duration between 0 and the
// exponentially-grown cap, so many Probes retrying after the same outage
// don't all hit Baromio in the same instant.
func (b *Backoff) Next() time.Duration {
	ceiling := b.base << b.attempt
	if ceiling <= 0 || ceiling > b.max {
		ceiling = b.max
	}

	b.attempt++

	return time.Duration(rand.Int63n(int64(ceiling)))
}

// Reset clears the attempt counter after a successful call.
func (b *Backoff) Reset() {
	b.attempt = 0
}
