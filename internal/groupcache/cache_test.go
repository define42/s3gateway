package groupcache_test

import (
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/groupcache"
)

func TestNewWithDefaultMaxEntries(t *testing.T) {
	cache := groupcache.New(time.Second, 0)
	if cache.MaxEntries() != config.DefaultGroupCacheMaxEntries {
		t.Fatalf(
			"default max entries mismatch: got=%d want=%d",
			cache.MaxEntries(),
			config.DefaultGroupCacheMaxEntries,
		)
	}
}
