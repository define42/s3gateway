package main

import (
	"crypto/ecdh"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/define42/s3gateway/internal/s3credentials"
)

type Config struct {
	ListenAddr string

	LDAPURL              string
	LDAPDomain           string
	BaseDN               string
	GroupTTL             time.Duration
	GroupCacheMaxEntries int

	UpstreamEndpoint       string
	UpstreamRegion         string
	UpstreamAccessKey      string
	UpstreamSecretKey      string
	UpstreamForcePathStyle bool

	CookieSecret string        // admin web-session secret seed; when empty, ephemeral random keys are used (sessions lost on restart)
	SigV4MaxSkew time.Duration // max absolute request age/skew based on x-amz-date

	RequiredUploadMetadataKeys []string // metadata keys required for upload requests (without x-amz-meta- prefix, lowercase)

	ReadHeaderTimeout         time.Duration
	ReadTimeout               time.Duration
	WriteTimeout              time.Duration
	IdleTimeout               time.Duration
	ShutdownTimeout           time.Duration
	MaxHeaderBytes            int
	S3GatewayPrivateX25519Key *ecdh.PrivateKey

	AcmeCaDir   string
	AcmeDomains string
	AcmeServer  string
	AcmeDataDir string
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

func (cfg *Config) ApplyDefaults() {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.GroupTTL == 0 {
		cfg.GroupTTL = 2 * time.Minute
	}
	if cfg.GroupCacheMaxEntries == 0 {
		cfg.GroupCacheMaxEntries = defaultGroupCacheMaxEntries
	}
	if cfg.UpstreamRegion == "" {
		cfg.UpstreamRegion = "us-east-1"
	}
	if cfg.SigV4MaxSkew == 0 {
		cfg.SigV4MaxSkew = defaultSigV4MaxSkew
	}
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = defaultReadHeaderTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}
	if cfg.MaxHeaderBytes == 0 {
		cfg.MaxHeaderBytes = defaultMaxHeaderBytes
	}
}

func (cfg Config) Validate() error {
	if cfg.GroupCacheMaxEntries <= 0 {
		return errors.New("LDAP_GROUP_CACHE_MAX_ENTRIES must be > 0")
	}
	if cfg.SigV4MaxSkew <= 0 {
		return errors.New("SIGV4_MAX_SKEW must be > 0")
	}
	if cfg.ReadHeaderTimeout <= 0 {
		return errors.New("HTTP_READ_HEADER_TIMEOUT must be > 0")
	}
	if cfg.IdleTimeout <= 0 {
		return errors.New("HTTP_IDLE_TIMEOUT must be > 0")
	}
	if cfg.ShutdownTimeout <= 0 {
		return errors.New("HTTP_SHUTDOWN_TIMEOUT must be > 0")
	}
	if cfg.MaxHeaderBytes <= 0 {
		return errors.New("HTTP_MAX_HEADER_BYTES must be > 0")
	}
	if cfg.CookieSecret != "" && len(cfg.CookieSecret) < 16 {
		return errors.New("COOKIE_SECRET must be at least 16 characters when set")
	}
	return nil
}

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

func envEcdhPrivateKey(key string) *ecdh.PrivateKey {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	privatek, err := s3credentials.X25519PrivateKeyFromHex(v)
	if err != nil {
		log.Fatalf("invalid ECDH private key for %s: %v", key, err)
	}
	return privatek
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

func normalizeRequiredMetadataKey(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.TrimPrefix(key, "x-amz-meta-")
	return strings.TrimSpace(key)
}

func envCSVMetadataKeys(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		k := normalizeRequiredMetadataKey(p)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func loadConfig() Config {
	cfg := Config{
		ListenAddr: env("LISTEN_ADDR", ":8080"),

		LDAPURL:              envRequired("LDAP_URL"),
		BaseDN:               envRequired("LDAP_BASE_DN"),
		GroupTTL:             envDuration("LDAP_GROUP_TTL", 2*time.Minute),
		LDAPDomain:           env("LDAP_DOMAIN", "example.com"),
		GroupCacheMaxEntries: envInt("LDAP_GROUP_CACHE_MAX_ENTRIES", defaultGroupCacheMaxEntries),

		UpstreamEndpoint:       envRequired("S3_ENDPOINT"),
		UpstreamRegion:         env("S3_REGION", "us-east-1"),
		UpstreamAccessKey:      envRequired("S3_ACCESS_KEY"),
		UpstreamSecretKey:      envRequired("S3_SECRET_KEY"),
		UpstreamForcePathStyle: strings.EqualFold(env("S3_FORCE_PATH_STYLE", "true"), "true"),

		CookieSecret: env("COOKIE_SECRET", ""),
		SigV4MaxSkew: envDuration("SIGV4_MAX_SKEW", defaultSigV4MaxSkew),

		RequiredUploadMetadataKeys: envCSVMetadataKeys("REQUIRED_UPLOAD_METADATA_KEYS"),

		ReadHeaderTimeout:         envDuration("HTTP_READ_HEADER_TIMEOUT", defaultReadHeaderTimeout),
		ReadTimeout:               envDuration("HTTP_READ_TIMEOUT", defaultReadTimeout),
		WriteTimeout:              envDuration("HTTP_WRITE_TIMEOUT", defaultWriteTimeout),
		IdleTimeout:               envDuration("HTTP_IDLE_TIMEOUT", defaultIdleTimeout),
		ShutdownTimeout:           envDuration("HTTP_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		MaxHeaderBytes:            envInt("HTTP_MAX_HEADER_BYTES", defaultMaxHeaderBytes),
		S3GatewayPrivateX25519Key: envEcdhPrivateKey("S3GATEWAY_PRIVATE_X25519_KEY"),
		AcmeCaDir:                 env("ACME_CA_DIR", ""),
		AcmeDomains:               env("ACME_DOMAINS", ""),
		AcmeServer:                env("ACME_SERVER", certmagic.LetsEncryptProductionCA),
		AcmeDataDir:               env("ACME_DATA_DIR", "./certs"),
	}
	if err := cfg.Validate(); err != nil {
		log.Fatal(err)
	}
	cfg.ApplyDefaults()
	return cfg
}
