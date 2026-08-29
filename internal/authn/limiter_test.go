package authn

import (
	"errors"
	"testing"
	"time"
)

func TestLimiterEnforcesConcurrencyAndRate(t *testing.T) {
	tests := []struct {
		name             string
		maxConcurrent    int
		ratePerSecond    int
		burst            int
		advance          time.Duration
		holdFirst        bool
		wantSecondErr    bool
		wantAfterAdvance bool
	}{
		{
			name:          "concurrent slot is non-blocking",
			maxConcurrent: 1,
			ratePerSecond: 100,
			burst:         100,
			holdFirst:     true,
			wantSecondErr: true,
		},
		{
			name:             "token bucket refills",
			maxConcurrent:    2,
			ratePerSecond:    1,
			burst:            1,
			advance:          time.Second,
			wantSecondErr:    true,
			wantAfterAdvance: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewLimiter(tt.maxConcurrent, tt.ratePerSecond, tt.burst)
			now := time.Unix(1_700_000_000, 0)
			limiter.mu.Lock()
			limiter.now = func() time.Time { return now }
			limiter.lastRefill = now
			limiter.mu.Unlock()

			releaseFirst, err := limiter.TryAcquire()
			if err != nil {
				t.Fatalf("first acquire failed: %v", err)
			}
			if !tt.holdFirst {
				releaseFirst()
			}

			releaseSecond, secondErr := limiter.TryAcquire()
			if (secondErr != nil) != tt.wantSecondErr {
				t.Fatalf("second acquire error mismatch: got=%v wantError=%v", secondErr, tt.wantSecondErr)
			}
			if secondErr != nil && !errors.Is(secondErr, ErrLimited) {
				t.Fatalf("second acquire error = %v, want ErrLimited", secondErr)
			}
			if releaseSecond != nil {
				releaseSecond()
			}
			if tt.holdFirst {
				releaseFirst()
			}

			if tt.advance > 0 {
				now = now.Add(tt.advance)
				releaseAfterAdvance, err := limiter.TryAcquire()
				if (err == nil) != tt.wantAfterAdvance {
					t.Fatalf("acquire after advance error mismatch: got=%v wantSuccess=%v", err, tt.wantAfterAdvance)
				}
				if releaseAfterAdvance != nil {
					releaseAfterAdvance()
				}
			}
		})
	}
}

func TestLimiterReleaseIsIdempotent(t *testing.T) {
	limiter := NewLimiter(1, 10, 10)
	release, err := limiter.TryAcquire()
	if err != nil {
		t.Fatalf("acquire failed: %v", err)
	}
	release()
	release()

	releaseAgain, err := limiter.TryAcquire()
	if err != nil {
		t.Fatalf("slot was not released: %v", err)
	}
	releaseAgain()
}
