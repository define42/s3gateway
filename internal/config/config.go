// Package config loads and validates gateway configuration from environment
// variables.
package config

import (
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/define42/s3gateway/internal/s3credentials"
)

// Config contains the gateway's LDAP, upstream S3, notification, logging,
// HTTP, and ACME settings.
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

	KafkaBrokers             []string
	EnableKafkaBucketTopic   bool   // publish uploads to a topic whose name matches the bucket
	KafkaGlobalTopic         string // optional global upload topic
	KafkaNotificationTimeout time.Duration
	KafkaPopTimeout          time.Duration
	KafkaPopMaxConsumers     int

	SplunkHECEndpoint      string
	SplunkHECToken         string
	SplunkHECIndex         string
	SplunkHECFlushInterval time.Duration
	S3AuditHashKey         string // optional HMAC key for stable audit pseudonyms; never logged

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
	defaultSigV4MaxSkew             = 15 * time.Minute
	defaultReadTimeout              = 0 * time.Second
	defaultWriteTimeout             = 0 * time.Second
	defaultShutdownTimeout          = 20 * time.Second
	defaultKafkaNotificationTimeout = 5 * time.Second
	defaultKafkaPopTimeout          = 30 * time.Second
	defaultKafkaPopMaxConsumers     = 1000
	defaultSplunkHECFlushInterval   = 30 * time.Second

	// DefaultGroupCacheMaxEntries bounds the in-memory LDAP group cache.
	DefaultGroupCacheMaxEntries = 10000
	// DefaultReadHeaderTimeout limits the time spent reading request headers.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultIdleTimeout limits keep-alive idle time.
	DefaultIdleTimeout = 120 * time.Second
	// DefaultMaxHeaderBytes bounds HTTP request headers to 1 MiB.
	DefaultMaxHeaderBytes = 1 << 20
)

// ApplyDefaults fills zero-valued settings that have runtime defaults. It does
// not validate the resulting configuration.
func (cfg *Config) ApplyDefaults() {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.GroupTTL == 0 {
		cfg.GroupTTL = 2 * time.Minute
	}
	if cfg.GroupCacheMaxEntries == 0 {
		cfg.GroupCacheMaxEntries = DefaultGroupCacheMaxEntries
	}
	if cfg.UpstreamRegion == "" {
		cfg.UpstreamRegion = "us-east-1"
	}
	if cfg.SigV4MaxSkew == 0 {
		cfg.SigV4MaxSkew = defaultSigV4MaxSkew
	}
	if cfg.KafkaNotificationTimeout == 0 {
		cfg.KafkaNotificationTimeout = defaultKafkaNotificationTimeout
	}
	if cfg.KafkaPopTimeout == 0 {
		cfg.KafkaPopTimeout = defaultKafkaPopTimeout
	}
	if cfg.KafkaPopMaxConsumers == 0 {
		cfg.KafkaPopMaxConsumers = defaultKafkaPopMaxConsumers
	}
	if cfg.SplunkHECFlushInterval == 0 {
		cfg.SplunkHECFlushInterval = defaultSplunkHECFlushInterval
	}
	if cfg.ReadHeaderTimeout == 0 {
		cfg.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.ShutdownTimeout == 0 {
		cfg.ShutdownTimeout = defaultShutdownTimeout
	}
	if cfg.MaxHeaderBytes == 0 {
		cfg.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
}

// Validate checks numeric bounds and cross-field requirements. It expects
// defaults to have been applied when zero values should be accepted.
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
	if cfg.CookieSecret != "" && len(cfg.CookieSecret) < 32 {
		return errors.New("COOKIE_SECRET must be at least 32 characters when set")
	}
	if len(cfg.KafkaBrokers) == 0 && cfg.EnableKafkaBucketTopic {
		return errors.New("ENABLE_KAFKA_BUCKET_TOPIC requires KAFKA_BROKERS")
	}
	if len(cfg.KafkaBrokers) == 0 && strings.TrimSpace(cfg.KafkaGlobalTopic) != "" {
		return errors.New("KAFKA_GLOBAL_TOPIC requires KAFKA_BROKERS")
	}
	if len(cfg.KafkaBrokers) > 0 {
		if !cfg.EnableKafkaBucketTopic && strings.TrimSpace(cfg.KafkaGlobalTopic) == "" {
			return errors.New("KAFKA_BROKERS requires ENABLE_KAFKA_BUCKET_TOPIC or KAFKA_GLOBAL_TOPIC")
		}
		if cfg.KafkaNotificationTimeout <= 0 {
			return errors.New("KAFKA_NOTIFICATION_TIMEOUT must be > 0")
		}
		for _, broker := range cfg.KafkaBrokers {
			if strings.TrimSpace(broker) == "" {
				return errors.New("KAFKA_BROKERS must not contain empty addresses")
			}
		}
		if cfg.KafkaPopTimeout <= 0 {
			return errors.New("KAFKA_POP_TIMEOUT must be > 0")
		}
		if cfg.KafkaPopMaxConsumers <= 0 {
			return errors.New("KAFKA_POP_MAX_CONSUMERS must be > 0")
		}
	}
	if cfg.SplunkHECFlushInterval <= 0 {
		return errors.New("SPLUNK_HEC_FLUSH_INTERVAL must be > 0")
	}
	if cfg.S3AuditHashKey != "" && len(cfg.S3AuditHashKey) < 32 {
		return errors.New("S3_AUDIT_HASH_KEY must be at least 32 characters when set")
	}
	splunkConfigured := cfg.SplunkHECEndpoint != "" || cfg.SplunkHECToken != "" || cfg.SplunkHECIndex != ""
	if splunkConfigured {
		if cfg.SplunkHECEndpoint == "" {
			return errors.New("SPLUNK_HEC_ENDPOINT is required when Splunk HEC logging is configured")
		}
		if cfg.SplunkHECToken == "" {
			return errors.New("SPLUNK_HEC_TOKEN is required when Splunk HEC logging is configured")
		}
		if cfg.SplunkHECIndex == "" {
			return errors.New("SPLUNK_HEC_INDEX is required when Splunk HEC logging is configured")
		}
		endpoint, err := url.ParseRequestURI(cfg.SplunkHECEndpoint)
		if err != nil || endpoint.Host == "" {
			return errors.New("SPLUNK_HEC_ENDPOINT must be an absolute URL")
		}
		if !strings.EqualFold(endpoint.Scheme, "http") && !strings.EqualFold(endpoint.Scheme, "https") {
			return errors.New("SPLUNK_HEC_ENDPOINT must use http or https")
		}
		if endpoint.User != nil {
			return errors.New("SPLUNK_HEC_ENDPOINT must not contain user information")
		}
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
		slog.Error("missing required env var", "key", key)
		os.Exit(1)
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
		slog.Error("invalid ECDH private key", "key", key, "error", err)
		os.Exit(1)
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
		slog.Error("invalid duration", "key", key, "error", err)
		os.Exit(1)
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
		slog.Error("invalid int", "key", key, "error", err)
		os.Exit(1)
	}
	return n
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		slog.Error("invalid bool", "key", key, "error", err)
		os.Exit(1)
	}
	return b
}

func envCSV(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}

	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeRequiredMetadataKey lowercases and strips the x-amz-meta- prefix
// from a metadata key, trimming surrounding whitespace.
func NormalizeRequiredMetadataKey(raw string) string {
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
		k := NormalizeRequiredMetadataKey(p)
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

// LoadConfig reads environment variables, validates them, and applies runtime
// defaults. It logs and terminates the process with exit status 1 when a
// required variable is missing or a value is invalid.
func LoadConfig() Config {
	cfg := Config{
		ListenAddr: env("LISTEN_ADDR", ":8080"),

		LDAPURL:              envRequired("LDAP_URL"),
		BaseDN:               envRequired("LDAP_BASE_DN"),
		GroupTTL:             envDuration("LDAP_GROUP_TTL", 2*time.Minute),
		LDAPDomain:           env("LDAP_DOMAIN", "example.com"),
		GroupCacheMaxEntries: envInt("LDAP_GROUP_CACHE_MAX_ENTRIES", DefaultGroupCacheMaxEntries),

		UpstreamEndpoint:       envRequired("S3_ENDPOINT"),
		UpstreamRegion:         env("S3_REGION", "us-east-1"),
		UpstreamAccessKey:      envRequired("S3_ACCESS_KEY"),
		UpstreamSecretKey:      envRequired("S3_SECRET_KEY"),
		UpstreamForcePathStyle: strings.EqualFold(env("S3_FORCE_PATH_STYLE", "true"), "true"),

		CookieSecret: env("COOKIE_SECRET", ""),
		SigV4MaxSkew: envDuration("SIGV4_MAX_SKEW", defaultSigV4MaxSkew),

		RequiredUploadMetadataKeys: envCSVMetadataKeys("REQUIRED_UPLOAD_METADATA_KEYS"),

		KafkaBrokers:             envCSV("KAFKA_BROKERS"),
		EnableKafkaBucketTopic:   envBool("ENABLE_KAFKA_BUCKET_TOPIC", false),
		KafkaGlobalTopic:         env("KAFKA_GLOBAL_TOPIC", ""),
		KafkaNotificationTimeout: envDuration("KAFKA_NOTIFICATION_TIMEOUT", defaultKafkaNotificationTimeout),
		KafkaPopTimeout:          envDuration("KAFKA_POP_TIMEOUT", defaultKafkaPopTimeout),
		KafkaPopMaxConsumers:     envInt("KAFKA_POP_MAX_CONSUMERS", defaultKafkaPopMaxConsumers),

		SplunkHECEndpoint:      env("SPLUNK_HEC_ENDPOINT", ""),
		SplunkHECToken:         env("SPLUNK_HEC_TOKEN", ""),
		SplunkHECIndex:         env("SPLUNK_HEC_INDEX", ""),
		SplunkHECFlushInterval: envDuration("SPLUNK_HEC_FLUSH_INTERVAL", defaultSplunkHECFlushInterval),
		S3AuditHashKey:         env("S3_AUDIT_HASH_KEY", ""),

		ReadHeaderTimeout:         envDuration("HTTP_READ_HEADER_TIMEOUT", DefaultReadHeaderTimeout),
		ReadTimeout:               envDuration("HTTP_READ_TIMEOUT", defaultReadTimeout),
		WriteTimeout:              envDuration("HTTP_WRITE_TIMEOUT", defaultWriteTimeout),
		IdleTimeout:               envDuration("HTTP_IDLE_TIMEOUT", DefaultIdleTimeout),
		ShutdownTimeout:           envDuration("HTTP_SHUTDOWN_TIMEOUT", defaultShutdownTimeout),
		MaxHeaderBytes:            envInt("HTTP_MAX_HEADER_BYTES", DefaultMaxHeaderBytes),
		S3GatewayPrivateX25519Key: envEcdhPrivateKey("S3GATEWAY_PRIVATE_X25519_KEY"),
		AcmeCaDir:                 env("ACME_CA_DIR", ""),
		AcmeDomains:               env("ACME_DOMAINS", ""),
		AcmeServer:                env("ACME_SERVER", certmagic.LetsEncryptProductionCA),
		AcmeDataDir:               env("ACME_DATA_DIR", "./certs"),
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("config validation failed", "error", err)
		os.Exit(1)
	}
	cfg.ApplyDefaults()
	return cfg
}
