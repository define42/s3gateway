package groupcache

import (
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

func TestNewWithDefaultMaxEntries(t *testing.T) {
	cache := New(time.Second, 0)
	if cache.MaxEntries() != config.DefaultGroupCacheMaxEntries {
		t.Fatalf(
			"default max entries mismatch: got=%d want=%d",
			cache.MaxEntries(),
			config.DefaultGroupCacheMaxEntries,
		)
	}
}

func TestCacheRejectedCredentials(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	cache := New(2*time.Minute, 2)
	cache.now = func() time.Time { return now }

	if cache.Rejected("service", "expired-password") {
		t.Fatal("credentials unexpectedly rejected before insertion")
	}
	cache.Reject("service", "expired-password")

	if !cache.Rejected("service", "expired-password") {
		t.Fatal("exact rejected credentials were not cached")
	}
	if cache.Rejected("service", "rotated-password") {
		t.Fatal("rotated password matched old rejection")
	}
	if cache.Rejected("other-service", "expired-password") {
		t.Fatal("different username matched old rejection")
	}

	now = now.Add(2*time.Minute + time.Nanosecond)
	if cache.Rejected("service", "expired-password") {
		t.Fatal("rejected credentials remained cached after successful-cache TTL")
	}
}

func TestCacheRejectedCredentialsBoundedSeparately(t *testing.T) {
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	cache := New(2*time.Minute, 2)
	cache.now = func() time.Time { return now }
	cache.Set("valid-service", "valid-password", map[string]struct{}{"team-r": {}})

	cache.Reject("service-1", "password-1")
	now = now.Add(time.Second)
	cache.Reject("service-2", "password-2")
	now = now.Add(time.Second)
	cache.Reject("service-3", "password-3")

	if len(cache.rejectedCredentials) != 2 {
		t.Fatalf("rejection cache length = %d, want 2", len(cache.rejectedCredentials))
	}
	if cache.Rejected("service-1", "password-1") {
		t.Fatal("oldest rejection was not evicted")
	}
	if !cache.Rejected("service-2", "password-2") || !cache.Rejected("service-3", "password-3") {
		t.Fatal("newest rejections were unexpectedly evicted")
	}
	if _, ok := cache.Get("valid-service", "valid-password"); !ok {
		t.Fatal("rejection-cache pressure evicted a valid group entry")
	}
}

func TestCacheSetClearsMatchingRejection(t *testing.T) {
	cache := New(2*time.Minute, 2)
	cache.Reject("service", "password")
	cache.Set("service", "password", map[string]struct{}{"team-r": {}})

	if cache.Rejected("service", "password") {
		t.Fatal("successful authentication did not clear matching rejection")
	}
}
