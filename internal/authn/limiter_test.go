package authn

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func permissiveLimits() Limits {
	return Limits{
		MaxConcurrent:                 100,
		RatePerSecond:                 100,
		Burst:                         100,
		PerClientMaxConcurrent:        100,
		PerClientRatePerSecond:        100,
		PerClientBurst:                100,
		PerPrincipalMaxConcurrent:     100,
		PerPrincipalRatePerSecond:     100,
		PerPrincipalBurst:             100,
		IngressPerClientRatePerSecond: 100,
		IngressPerClientBurst:         100,
		MaxKeys:                       64,
		TrustedCredentialTTL:          time.Minute,
	}
}

func setLimiterTime(limiter *Limiter, now *time.Time) {
	limiter.mu.Lock()
	limiter.now = func() time.Time { return *now }
	limiter.mu.Unlock()
}

func TestLimiterEnforcesGlobalConcurrencyAndRate(t *testing.T) {
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

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			limits := permissiveLimits()
			limits.MaxConcurrent = test.maxConcurrent
			limits.RatePerSecond = test.ratePerSecond
			limits.Burst = test.burst
			limiter := NewLimiter(limits)
			now := time.Unix(1_700_000_000, 0)
			setLimiterTime(limiter, &now)

			first := NewAttempt("192.0.2.1", "first", "password")
			releaseFirst, err := limiter.TryAcquire(first)
			if err != nil {
				t.Fatalf("first acquire failed: %v", err)
			}
			if !test.holdFirst {
				releaseFirst()
			}

			second := NewAttempt("192.0.2.2", "second", "password")
			releaseSecond, secondErr := limiter.TryAcquire(second)
			if (secondErr != nil) != test.wantSecondErr {
				t.Fatalf("second acquire error mismatch: got=%v wantError=%v", secondErr, test.wantSecondErr)
			}
			if secondErr != nil && !errors.Is(secondErr, ErrLimited) {
				t.Fatalf("second acquire error = %v, want ErrLimited", secondErr)
			}
			if releaseSecond != nil {
				releaseSecond()
			}
			if test.holdFirst {
				releaseFirst()
			}

			if test.advance > 0 {
				now = now.Add(test.advance)
				releaseAfterAdvance, err := limiter.TryAcquire(second)
				if (err == nil) != test.wantAfterAdvance {
					t.Fatalf("acquire after advance error mismatch: got=%v wantSuccess=%v", err, test.wantAfterAdvance)
				}
				if releaseAfterAdvance != nil {
					releaseAfterAdvance()
				}
			}
		})
	}
}

func TestLimiterAppliesPerClientAndPerPrincipalFairness(t *testing.T) {
	t.Run("client cannot consume another client's tokens", func(t *testing.T) {
		limits := permissiveLimits()
		limits.PerClientRatePerSecond = 1
		limits.PerClientBurst = 1
		limiter := NewLimiter(limits)

		firstRelease, err := limiter.TryAcquire(NewAttempt("192.0.2.1", "alice", "one"))
		if err != nil {
			t.Fatalf("first client acquire: %v", err)
		}
		firstRelease()
		if _, err := limiter.TryAcquire(NewAttempt("192.0.2.1", "bob", "two")); !errors.Is(err, ErrLimited) {
			t.Fatalf("same client error = %v, want ErrLimited", err)
		}
		release, err := limiter.TryAcquire(NewAttempt("192.0.2.2", "carol", "three"))
		if err != nil {
			t.Fatalf("independent client was starved: %v", err)
		}
		release()
	})

	t.Run("principal cannot evade limits by changing client", func(t *testing.T) {
		limits := permissiveLimits()
		limits.PerPrincipalRatePerSecond = 1
		limits.PerPrincipalBurst = 1
		limiter := NewLimiter(limits)

		release, err := limiter.TryAcquire(NewAttempt("192.0.2.1", "Alice", "one"))
		if err != nil {
			t.Fatalf("first principal acquire: %v", err)
		}
		release()
		if _, err := limiter.TryAcquire(NewAttempt("192.0.2.2", " alice ", "two")); !errors.Is(err, ErrLimited) {
			t.Fatalf("same normalized principal error = %v, want ErrLimited", err)
		}
		release, err = limiter.TryAcquire(NewAttempt("192.0.2.2", "bob", "two"))
		if err != nil {
			t.Fatalf("independent principal was starved: %v", err)
		}
		release()
	})
}

func TestLimiterReservesCapacityForPreviouslyAuthenticatedCredentials(t *testing.T) {
	limits := permissiveLimits()
	limits.MaxConcurrent = 2
	limits.RatePerSecond = 2
	limits.Burst = 2
	limits.ReservedConcurrent = 1
	limits.ReservedRatePerSecond = 1
	limits.ReservedBurst = 1
	limiter := NewLimiter(limits)

	trusted := NewAttempt("192.0.2.20", "known-user", "correct-password")
	limiter.MarkAuthenticated(trusted)

	abusiveRelease, err := limiter.TryAcquire(NewAttempt("192.0.2.10", "random-user", "wrong"))
	if err != nil {
		t.Fatalf("shared acquire failed: %v", err)
	}
	defer abusiveRelease()

	if _, err := limiter.TryAcquire(NewAttempt("192.0.2.11", "known-user", "wrong-password")); !errors.Is(err, ErrLimited) {
		t.Fatalf("claimed principal with wrong credentials entered reserve: %v", err)
	}
	trustedRelease, err := limiter.TryAcquire(trusted)
	if err != nil {
		t.Fatalf("trusted credential could not enter reserve: %v", err)
	}
	trustedRelease()
}

func TestLimiterTrustedCredentialEligibilityExpires(t *testing.T) {
	limits := permissiveLimits()
	limits.MaxConcurrent = 2
	limits.RatePerSecond = 2
	limits.Burst = 2
	limits.ReservedConcurrent = 1
	limits.ReservedRatePerSecond = 1
	limits.ReservedBurst = 1
	limits.TrustedCredentialTTL = time.Minute
	limiter := NewLimiter(limits)
	now := time.Unix(1_700_000_000, 0)
	setLimiterTime(limiter, &now)

	trusted := NewAttempt("192.0.2.20", "known-user", "correct-password")
	limiter.MarkAuthenticated(trusted)
	now = now.Add(time.Minute + time.Nanosecond)

	sharedRelease, err := limiter.TryAcquire(NewAttempt("192.0.2.10", "random-user", "wrong"))
	if err != nil {
		t.Fatalf("shared acquire failed: %v", err)
	}
	defer sharedRelease()
	if _, err := limiter.TryAcquire(trusted); !errors.Is(err, ErrLimited) {
		t.Fatalf("expired credential retained reserve eligibility: %v", err)
	}
}

func TestLimiterRateLimitsAtIngressPerClient(t *testing.T) {
	limits := permissiveLimits()
	limits.IngressPerClientRatePerSecond = 1
	limits.IngressPerClientBurst = 1
	limiter := NewLimiter(limits)
	now := time.Unix(1_700_000_000, 0)
	setLimiterTime(limiter, &now)

	if !limiter.AllowIngress("192.0.2.1") {
		t.Fatal("first ingress request was limited")
	}
	if limiter.AllowIngress("192.0.2.1") {
		t.Fatal("same client exceeded ingress burst")
	}
	limiter.RefundIngress("192.0.2.1")
	if !limiter.AllowIngress("192.0.2.1") {
		t.Fatal("successful authentication did not restore ingress token")
	}
	if limiter.AllowIngress("192.0.2.1") {
		t.Fatal("refunded token was reusable more than once")
	}
	if !limiter.AllowIngress("192.0.2.2") {
		t.Fatal("one client starved another at ingress")
	}
	now = now.Add(time.Second)
	if !limiter.AllowIngress("192.0.2.1") {
		t.Fatal("ingress token did not refill")
	}
}

func TestLimiterBoundsUntrustedKeyState(t *testing.T) {
	limits := permissiveLimits()
	limits.MaxKeys = 2
	limiter := NewLimiter(limits)

	for index := range 100 {
		release, err := limiter.TryAcquire(NewAttempt(
			fmt.Sprintf("192.0.2.%d", index),
			fmt.Sprintf("user-%d", index),
			"password",
		))
		if err != nil {
			t.Fatalf("acquire %d: %v", index, err)
		}
		release()
	}
	if got := len(limiter.clients.states); got > limits.MaxKeys {
		t.Fatalf("client states = %d, want <= %d", got, limits.MaxKeys)
	}
	if got := len(limiter.principals.states); got > limits.MaxKeys {
		t.Fatalf("principal states = %d, want <= %d", got, limits.MaxKeys)
	}
}

func TestLimiterReleaseIsIdempotent(t *testing.T) {
	limits := permissiveLimits()
	limits.MaxConcurrent = 1
	limiter := NewLimiter(limits)
	attempt := NewAttempt("192.0.2.1", "alice", "password")
	release, err := limiter.TryAcquire(attempt)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	release()
	release()

	releaseAgain, err := limiter.TryAcquire(NewAttempt("192.0.2.2", "bob", "password"))
	if err != nil {
		t.Fatalf("slot was not released: %v", err)
	}
	releaseAgain()
}
