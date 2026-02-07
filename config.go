package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string

	LDAPURL              string
	BaseDN               string
	GroupTTL             time.Duration
	GroupCacheMaxEntries int

	UpstreamEndpoint       string
	UpstreamRegion         string
	UpstreamAccessKey      string
	UpstreamSecretKey      string
	UpstreamForcePathStyle bool

	SigV4Secret  string        // constant, default "password"
	SigV4Service string        // default "s3"
	SigV4MaxSkew time.Duration // max absolute request age/skew based on x-amz-date

	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
	MaxHeaderBytes    int
}

const (
	defaultSigV4MaxSkew         = 15 * time.Minute
	defaultGroupCacheMaxEntries = 10000
	defaultReadHeaderTimeout    = 10 * time.Second
	defaultReadTimeout          = 0 * time.Second
	defaultWriteTimeout         = 0 * time.Second
	defaultIdleTimeout          = 120 * time.Second
	defaultShutdownTimeout      = 20 * time.Second
	defaultMaxHeaderBytes       = 1 << 20 // 1 MiB
)

func env(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}

func envRequired(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing required env var %s", key)
	}
	return v
}

func envDuration(key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid duration for %s: %v", key, err)
	}
	return d
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Fatalf("invalid int for %s: %v", key, err)
	}
	return n
}

func loadConfig() Config {
	ttl := envDuration("LDAP_GROUP_TTL", 2*time.Minute)
	groupCacheMaxEntries := envInt("LDAP_GROUP_CACHE_MAX_ENTRIES", defaultGroupCacheMaxEntries)
	if groupCacheMaxEntries <= 0 {
		log.Fatalf("LDAP_GROUP_CACHE_MAX_ENTRIES must be > 0")
	}

	sigV4MaxSkew := envDuration("SIGV4_MAX_SKEW", defaultSigV4MaxSkew)
	if sigV4MaxSkew <= 0 {
		log.Fatalf("SIGV4_MAX_SKEW must be > 0")
	}

	readHeaderTimeout := envDuration("HTTP_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout)
	if readHeaderTimeout <= 0 {
		log.Fatalf("HTTP_READ_HEADER_TIMEOUT must be > 0")
	}

	idleTimeout := envDuration("HTTP_IDLE_TIMEOUT", defaultIdleTimeout)
	if idleTimeout <= 0 {
		log.Fatalf("HTTP_IDLE_TIMEOUT must be > 0")
	}

	shutdownTimeout := envDuration("HTTP_SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if shutdownTimeout <= 0 {
		log.Fatalf("HTTP_SHUTDOWN_TIMEOUT must be > 0")
	}

	maxHeaderBytes := envInt("HTTP_MAX_HEADER_BYTES", defaultMaxHeaderBytes)
	if maxHeaderBytes <= 0 {
		log.Fatalf("HTTP_MAX_HEADER_BYTES must be > 0")
	}

	return Config{
		ListenAddr: env("LISTEN_ADDR", ":8080"),

		LDAPURL:              envRequired("LDAP_URL"),
		BaseDN:               envRequired("LDAP_BASE_DN"),
		GroupTTL:             ttl,
		GroupCacheMaxEntries: groupCacheMaxEntries,

		UpstreamEndpoint:       envRequired("S3_ENDPOINT"),
		UpstreamRegion:         env("S3_REGION", "us-east-1"),
		UpstreamAccessKey:      envRequired("S3_ACCESS_KEY"),
		UpstreamSecretKey:      envRequired("S3_SECRET_KEY"),
		UpstreamForcePathStyle: strings.EqualFold(env("S3_FORCE_PATH_STYLE", "true"), "true"),

		SigV4Secret:  env("SIGV4_SECRET", "password"),
		SigV4Service: env("SIGV4_SERVICE", "s3"),
		SigV4MaxSkew: sigV4MaxSkew,

		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       envDuration("HTTP_READ_TIMEOUT", defaultReadTimeout),
		WriteTimeout:      envDuration("HTTP_WRITE_TIMEOUT", defaultWriteTimeout),
		IdleTimeout:       idleTimeout,
		ShutdownTimeout:   shutdownTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}
