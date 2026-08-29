// Package authn contains shared authentication resource controls.
package authn

import (
	"errors"
	"sync"
	"time"
)

// ErrLimited reports that an authentication attempt was rejected before
// reaching the identity backend because its resource budget was exhausted.
var ErrLimited = errors.New("authentication temporarily limited")

// Limiter combines a non-blocking concurrency semaphore with a token bucket.
// It is safe for concurrent use.
type Limiter struct {
	slots chan struct{}

	mu              sync.Mutex
	tokens          float64
	lastRefill      time.Time
	tokensPerSecond float64
	burst           float64
	now             func() time.Time
}

// NewLimiter constructs an authentication limiter. Non-positive settings are
// clamped to one so callers that skipped configuration validation still fail
// closed without panicking.
func NewLimiter(maxConcurrent, ratePerSecond, burst int) *Limiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}
	if ratePerSecond <= 0 {
		ratePerSecond = 1
	}
	if burst <= 0 {
		burst = 1
	}
	now := time.Now
	return &Limiter{
		slots:           make(chan struct{}, maxConcurrent),
		tokens:          float64(burst),
		lastRefill:      now(),
		tokensPerSecond: float64(ratePerSecond),
		burst:           float64(burst),
		now:             now,
	}
}

// TryAcquire reserves one authentication slot and rate token. It never waits;
// callers should return a retryable response when ErrLimited is reported.
func (l *Limiter) TryAcquire() (release func(), err error) {
	if l == nil {
		return func() {}, nil
	}
	select {
	case l.slots <- struct{}{}:
	default:
		return nil, ErrLimited
	}

	if !l.takeToken() {
		<-l.slots
		return nil, ErrLimited
	}
	return sync.OnceFunc(func() { <-l.slots }), nil
}

func (l *Limiter) takeToken() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if elapsed := now.Sub(l.lastRefill); elapsed > 0 {
		l.tokens += elapsed.Seconds() * l.tokensPerSecond
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
		l.lastRefill = now
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
