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
// Rates above MaxRate are capped: the pacing interval would otherwise round
// down to zero and silently disable limiting altogether.
func NewRateLimiter(ratePerSec int) *RateLimiter {
	if ratePerSec <= 0 {
		return &RateLimiter{}
	}
	if ratePerSec > MaxRate {
		ratePerSec = MaxRate
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
		// Still surface cancellation even when no timer is needed.
		return ctx.Err()
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

// hostLimiter caps concurrent probes per target IP. A plain map of
// semaphores would grow by one entry per scanned host, so each entry also
// counts its users and is deleted as soon as the last one leaves.
type hostLimiter struct {
	mu    sync.Mutex
	slots map[string]*hostSlot
	limit int
}

type hostSlot struct {
	// sem holds one token per allowed in-flight probe.
	sem chan struct{}
	// refs counts goroutines holding or waiting for this slot.
	refs int
}

func newHostLimiter(limit int) *hostLimiter {
	if limit <= 0 {
		limit = defaultHostConcurrency
	}
	return &hostLimiter{
		slots: make(map[string]*hostSlot),
		limit: limit,
	}
}

// acquire blocks until a probe slot for host is available or ctx is
// cancelled. The returned release function must be called exactly once.
func (l *hostLimiter) acquire(ctx context.Context, host string) (release func(), err error) {
	l.mu.Lock()
	slot := l.slots[host]
	if slot == nil {
		slot = &hostSlot{sem: make(chan struct{}, l.limit)}
		l.slots[host] = slot
	}
	slot.refs++
	l.mu.Unlock()

	select {
	case slot.sem <- struct{}{}:
		return func() {
			<-slot.sem
			l.release(host)
		}, nil
	case <-ctx.Done():
		l.release(host)
		return nil, ctx.Err()
	}
}

// release drops one reference to host's slot and removes the entry once no
// goroutine holds or waits for it. The slot cannot be deleted while any
// reference exists, so a waiter always sees the same channel as its peers.
func (l *hostLimiter) release(host string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	slot := l.slots[host]
	if slot == nil {
		return
	}
	slot.refs--
	if slot.refs == 0 {
		delete(l.slots, host)
	}
}
