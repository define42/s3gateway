package main

import (
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/groupcache"
	"github.com/define42/s3gateway/internal/config"
	sigv4 "github.com/define42/s3gateway/internal/sigv4"
)

func TestEnvAndCanonicalURIHelpers(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "/"},
		{in: "bucket/key", want: "/bucket/key"},
		{in: "/already/escaped", want: "/already/escaped"},
	}
	for _, tt := range tests {
		if got := sigv4.CanonicalURI(tt.in); got != tt.want {
			t.Fatalf("canonicalURI(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNewGroupCacheWithDefaultMaxEntries(t *testing.T) {
	c := groupcache.NewGroupCacheWithMaxEntries(time.Second, 0)
	if c.MaxEntries() != config.DefaultGroupCacheMaxEntries {
		t.Fatalf("default max entries mismatch: got=%d want=%d", c.MaxEntries(), config.DefaultGroupCacheMaxEntries)
	}
}
