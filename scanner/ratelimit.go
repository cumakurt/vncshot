package scanner

import (
	"context"
	"sync"
	"time"
)

// RateLimiter paces connection attempts at a fixed average rate using a
// simple virtual-clock token bucket. A rate of 0 disables limiting.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

// NewRateLimiter returns a limiter allowing ratePerSec attempts per second.
func NewRateLimiter(ratePerSec int) *RateLimiter {
	if ratePerSec <= 0 {
		return &RateLimiter{}
	}
	return &RateLimiter{
		interval: time.Second / time.Duration(ratePerSec),
	}
}

// Wait blocks until the caller may start the next attempt, or until ctx
// is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	if r == nil || r.interval <= 0 {
		return nil
	}

	r.mu.Lock()
	now := time.Now()
	if r.next.Before(now) {
		r.next = now
	}
	wait := r.next.Sub(now)
	r.next = r.next.Add(r.interval)
	r.mu.Unlock()

	if wait <= 0 {
		return nil
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
