package main

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidateMatrix(t *testing.T) {
	base := Config{
		GroupCacheMaxEntries: 1,
		SigV4MaxSkew:         time.Second,
		ReadHeaderTimeout:    time.Second,
		IdleTimeout:          time.Second,
		ShutdownTimeout:      time.Second,
		MaxHeaderBytes:       1,
	}

	if err := base.Validate(); err != nil {
		t.Fatalf("base config validate error = %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantMsg string
	}{
		{
			name: "group cache max entries",
			mutate: func(c *Config) {
				c.GroupCacheMaxEntries = 0
			},
			wantMsg: "LDAP_GROUP_CACHE_MAX_ENTRIES",
		},
		{
			name: "sigv4 max skew",
			mutate: func(c *Config) {
				c.SigV4MaxSkew = 0
			},
			wantMsg: "SIGV4_MAX_SKEW",
		},
		{
			name: "read header timeout",
			mutate: func(c *Config) {
				c.ReadHeaderTimeout = 0
			},
			wantMsg: "HTTP_READ_HEADER_TIMEOUT",
		},
		{
			name: "idle timeout",
			mutate: func(c *Config) {
				c.IdleTimeout = 0
			},
			wantMsg: "HTTP_IDLE_TIMEOUT",
		},
		{
			name: "shutdown timeout",
			mutate: func(c *Config) {
				c.ShutdownTimeout = 0
			},
			wantMsg: "HTTP_SHUTDOWN_TIMEOUT",
		},
		{
			name: "max header bytes",
			mutate: func(c *Config) {
				c.MaxHeaderBytes = 0
			},
			wantMsg: "HTTP_MAX_HEADER_BYTES",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("expected validation error")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("validate error mismatch: got=%q want substring %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestEnvAndCanonicalURIHelpers(t *testing.T) {
	t.Setenv("TEST_ENV_KEY", "")
	if got := env("TEST_ENV_KEY", "default"); got != "default" {
		t.Fatalf("env default mismatch: got=%q want=%q", got, "default")
	}

	t.Setenv("TEST_ENV_KEY", " configured ")
	if got := env("TEST_ENV_KEY", "default"); got != "configured" {
		t.Fatalf("env value mismatch: got=%q want=%q", got, "configured")
	}

	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: "/"},
		{in: "bucket/key", want: "/bucket/key"},
		{in: "/already/escaped", want: "/already/escaped"},
	}
	for _, tt := range tests {
		if got := canonicalURI(tt.in); got != tt.want {
			t.Fatalf("canonicalURI(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNewGroupCacheWithDefaultMaxEntries(t *testing.T) {
	c := newGroupCacheWithMaxEntries(time.Second, 0)
	if c.maxEntries != defaultGroupCacheMaxEntries {
		t.Fatalf("default max entries mismatch: got=%d want=%d", c.maxEntries, defaultGroupCacheMaxEntries)
	}
}
