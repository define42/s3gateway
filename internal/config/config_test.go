package config

import (
	"crypto/ecdh"
	"strings"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/s3credentials"
)

func mustTestX25519PrivateKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	privateKeyHex, _, err := s3credentials.GenerateX25519TestKeys()
	if err != nil {
		t.Fatalf("generate X25519 test key: %v", err)
	}
	privateKey, err := s3credentials.X25519PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		t.Fatalf("parse X25519 test private key: %v", err)
	}
	return privateKey
}

func setRequiredX25519PrivateKeyEnv(t *testing.T) {
	t.Helper()
	privateKeyHex, _, err := s3credentials.GenerateX25519TestKeys()
	if err != nil {
		t.Fatalf("generate X25519 test key: %v", err)
	}
	t.Setenv("S3GATEWAY_PRIVATE_X25519_KEY", privateKeyHex)
}

func TestConfigValidateMatrix(t *testing.T) {
	base := Config{
		S3GatewayPrivateX25519Key:     mustTestX25519PrivateKey(t),
		UpstreamEndpoint:              "https://s3.example",
		LDAPGroupBaseDN:               "ou=groups,dc=example,dc=com",
		GroupCacheMaxEntries:          1,
		LDAPOperationTimeout:          time.Second,
		AuthMaxConcurrent:             4,
		AuthRatePerSecond:             4,
		AuthRateBurst:                 4,
		AuthReservedConcurrent:        1,
		AuthReservedRatePerSecond:     1,
		AuthReservedBurst:             1,
		AuthPerIPMaxConcurrent:        1,
		AuthPerIPRatePerSecond:        1,
		AuthPerIPBurst:                1,
		AuthPerPrincipalMaxConcurrent: 1,
		AuthPerPrincipalRatePerSecond: 1,
		AuthPerPrincipalBurst:         1,
		AuthIngressPerIPRatePerSecond: 1,
		AuthIngressPerIPBurst:         1,
		AuthTrustedCredentialTTL:      time.Minute,
		SigV4MaxSkew:                  time.Second,
		ReadHeaderTimeout:             time.Second,
		TransferIdleTimeout:           time.Second,
		MaxConcurrentRequests:         1,
		IdleTimeout:                   time.Second,
		ShutdownTimeout:               time.Second,
		MaxHeaderBytes:                1,
		AdminLoginReadTimeout:         time.Second,
		ReadinessCheckTimeout:         time.Second,
		ReadinessCacheTTL:             time.Second,
		ReadinessAllowedCIDRs:         []string{"127.0.0.1/32"},
		SplunkHECFlushInterval:        time.Second,
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
			name:    "insecure upstream endpoint",
			mutate:  func(c *Config) { c.UpstreamEndpoint = "http://s3.example" },
			wantMsg: "S3_ENDPOINT",
		},
		{
			name:    "missing group container",
			mutate:  func(c *Config) { c.LDAPGroupBaseDN = "" },
			wantMsg: "LDAP_GROUP_BASE_DN",
		},
		{
			name:    "blank group container",
			mutate:  func(c *Config) { c.LDAPGroupBaseDN = " \t " },
			wantMsg: "LDAP_GROUP_BASE_DN",
		},
		{
			name:    "malformed group container",
			mutate:  func(c *Config) { c.LDAPGroupBaseDN = "not-a-dn" },
			wantMsg: "LDAP_GROUP_BASE_DN",
		},
		{
			name:    "empty container attribute",
			mutate:  func(c *Config) { c.LDAPGroupBaseDN = "ou=,dc=example,dc=com" },
			wantMsg: "LDAP_GROUP_BASE_DN",
		},
		{
			name: "X25519 private key",
			mutate: func(c *Config) {
				c.S3GatewayPrivateX25519Key = nil
			},
			wantMsg: "S3GATEWAY_PRIVATE_X25519_KEY",
		},
		{
			name: "group cache max entries",
			mutate: func(c *Config) {
				c.GroupCacheMaxEntries = 0
			},
			wantMsg: "LDAP_GROUP_CACHE_MAX_ENTRIES",
		},
		{
			name: "ldap operation timeout",
			mutate: func(c *Config) {
				c.LDAPOperationTimeout = 0
			},
			wantMsg: "LDAP_OPERATION_TIMEOUT",
		},
		{
			name: "auth max concurrent",
			mutate: func(c *Config) {
				c.AuthMaxConcurrent = 0
			},
			wantMsg: "AUTH_MAX_CONCURRENT",
		},
		{
			name: "auth rate per second",
			mutate: func(c *Config) {
				c.AuthRatePerSecond = 0
			},
			wantMsg: "AUTH_RATE_PER_SECOND",
		},
		{
			name: "auth rate burst",
			mutate: func(c *Config) {
				c.AuthRateBurst = 0
			},
			wantMsg: "AUTH_RATE_BURST",
		},
		{
			name: "auth reserved max concurrent",
			mutate: func(c *Config) {
				c.AuthReservedConcurrent = c.AuthMaxConcurrent
			},
			wantMsg: "AUTH_RESERVED_MAX_CONCURRENT",
		},
		{
			name: "auth reserved rate",
			mutate: func(c *Config) {
				c.AuthReservedRatePerSecond = c.AuthRatePerSecond
			},
			wantMsg: "AUTH_RESERVED_RATE_PER_SECOND",
		},
		{
			name: "auth reserved burst",
			mutate: func(c *Config) {
				c.AuthReservedBurst = c.AuthRateBurst
			},
			wantMsg: "AUTH_RESERVED_BURST",
		},
		{
			name: "auth per IP concurrency",
			mutate: func(c *Config) {
				c.AuthPerIPMaxConcurrent = 0
			},
			wantMsg: "AUTH_PER_IP_MAX_CONCURRENT",
		},
		{
			name: "auth per IP rate",
			mutate: func(c *Config) {
				c.AuthPerIPRatePerSecond = 0
			},
			wantMsg: "AUTH_PER_IP_RATE_PER_SECOND",
		},
		{
			name: "auth per IP burst",
			mutate: func(c *Config) {
				c.AuthPerIPBurst = 0
			},
			wantMsg: "AUTH_PER_IP_BURST",
		},
		{
			name: "auth per principal concurrency",
			mutate: func(c *Config) {
				c.AuthPerPrincipalMaxConcurrent = 0
			},
			wantMsg: "AUTH_PER_PRINCIPAL_MAX_CONCURRENT",
		},
		{
			name: "auth per principal rate",
			mutate: func(c *Config) {
				c.AuthPerPrincipalRatePerSecond = 0
			},
			wantMsg: "AUTH_PER_PRINCIPAL_RATE_PER_SECOND",
		},
		{
			name: "auth per principal burst",
			mutate: func(c *Config) {
				c.AuthPerPrincipalBurst = 0
			},
			wantMsg: "AUTH_PER_PRINCIPAL_BURST",
		},
		{
			name: "auth ingress per IP rate",
			mutate: func(c *Config) {
				c.AuthIngressPerIPRatePerSecond = 0
			},
			wantMsg: "AUTH_INGRESS_PER_IP_RATE_PER_SECOND",
		},
		{
			name: "auth ingress per IP burst",
			mutate: func(c *Config) {
				c.AuthIngressPerIPBurst = 0
			},
			wantMsg: "AUTH_INGRESS_PER_IP_BURST",
		},
		{
			name: "auth trusted credential TTL",
			mutate: func(c *Config) {
				c.AuthTrustedCredentialTTL = 0
			},
			wantMsg: "AUTH_TRUSTED_CREDENTIAL_TTL",
		},
		{
			name: "trusted proxy CIDR",
			mutate: func(c *Config) {
				c.TrustedProxyCIDRs = []string{"not-a-cidr"}
			},
			wantMsg: "TRUSTED_PROXY_CIDRS",
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
			name:    "negative read timeout",
			mutate:  func(c *Config) { c.ReadTimeout = -time.Second },
			wantMsg: "HTTP_READ_TIMEOUT",
		},
		{
			name:    "negative write timeout",
			mutate:  func(c *Config) { c.WriteTimeout = -time.Second },
			wantMsg: "HTTP_WRITE_TIMEOUT",
		},
		{
			name:    "zero transfer idle timeout",
			mutate:  func(c *Config) { c.TransferIdleTimeout = 0 },
			wantMsg: "HTTP_TRANSFER_IDLE_TIMEOUT",
		},
		{
			name:    "negative transfer idle timeout",
			mutate:  func(c *Config) { c.TransferIdleTimeout = -time.Second },
			wantMsg: "HTTP_TRANSFER_IDLE_TIMEOUT",
		},
		{
			name:    "zero max concurrent requests",
			mutate:  func(c *Config) { c.MaxConcurrentRequests = 0 },
			wantMsg: "HTTP_MAX_CONCURRENT_REQUESTS",
		},
		{
			name:    "negative max concurrent requests",
			mutate:  func(c *Config) { c.MaxConcurrentRequests = -1 },
			wantMsg: "HTTP_MAX_CONCURRENT_REQUESTS",
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
		{
			name: "admin login read timeout",
			mutate: func(c *Config) {
				c.AdminLoginReadTimeout = 0
			},
			wantMsg: "ADMIN_LOGIN_READ_TIMEOUT",
		},
		{
			name: "readiness check timeout",
			mutate: func(c *Config) {
				c.ReadinessCheckTimeout = 0
			},
			wantMsg: "READINESS_CHECK_TIMEOUT",
		},
		{
			name: "readiness cache ttl",
			mutate: func(c *Config) {
				c.ReadinessCacheTTL = 0
			},
			wantMsg: "READINESS_CACHE_TTL",
		},
		{
			name: "readiness cidrs empty",
			mutate: func(c *Config) {
				c.ReadinessAllowedCIDRs = nil
			},
			wantMsg: "READINESS_ALLOWED_CIDRS",
		},
		{
			name: "readiness cidr invalid",
			mutate: func(c *Config) {
				c.ReadinessAllowedCIDRs = []string{"not-a-cidr"}
			},
			wantMsg: "READINESS_ALLOWED_CIDRS",
		},
		{
			name: "cookie secret too short",
			mutate: func(c *Config) {
				c.CookieSecret = "tooshort"
			},
			wantMsg: "COOKIE_SECRET",
		},
		{
			name: "kafka bucket topic without brokers",
			mutate: func(c *Config) {
				c.EnableKafkaBucketTopic = true
			},
			wantMsg: "ENABLE_KAFKA_BUCKET_TOPIC",
		},
		{
			name: "kafka global topic without brokers",
			mutate: func(c *Config) {
				c.KafkaGlobalTopic = "_all"
			},
			wantMsg: "KAFKA_GLOBAL_TOPIC",
		},
		{
			name: "kafka brokers without a topic",
			mutate: func(c *Config) {
				c.KafkaBrokers = []string{"kafka:9092"}
				c.KafkaNotificationTimeout = time.Second
			},
			wantMsg: "requires ENABLE_KAFKA_BUCKET_TOPIC or KAFKA_GLOBAL_TOPIC",
		},
		{
			name: "kafka notification timeout",
			mutate: func(c *Config) {
				c.KafkaBrokers = []string{"kafka:9092"}
				c.EnableKafkaBucketTopic = true
			},
			wantMsg: "KAFKA_NOTIFICATION_TIMEOUT",
		},
		{
			name: "empty kafka broker",
			mutate: func(c *Config) {
				c.KafkaBrokers = []string{"kafka:9092", " "}
				c.EnableKafkaBucketTopic = true
				c.KafkaNotificationTimeout = time.Second
			},
			wantMsg: "KAFKA_BROKERS",
		},
		{
			name: "kafka pop timeout",
			mutate: func(c *Config) {
				c.KafkaBrokers = []string{"kafka:9092"}
				c.EnableKafkaBucketTopic = true
				c.KafkaNotificationTimeout = time.Second
				c.KafkaPopMaxConsumers = 1
			},
			wantMsg: "KAFKA_POP_TIMEOUT",
		},
		{
			name: "kafka pop max consumers",
			mutate: func(c *Config) {
				c.KafkaBrokers = []string{"kafka:9092"}
				c.EnableKafkaBucketTopic = true
				c.KafkaNotificationTimeout = time.Second
				c.KafkaPopTimeout = time.Second
			},
			wantMsg: "KAFKA_POP_MAX_CONSUMERS",
		},
		{
			name: "zero kafka pop idle timeout",
			mutate: func(c *Config) {
				c.KafkaBrokers = []string{"kafka:9092"}
				c.EnableKafkaBucketTopic = true
				c.KafkaNotificationTimeout = time.Second
				c.KafkaPopTimeout = time.Second
				c.KafkaPopMaxConsumers = 1
			},
			wantMsg: "KAFKA_POP_IDLE_TIMEOUT",
		},
		{
			name: "negative kafka pop idle timeout",
			mutate: func(c *Config) {
				c.KafkaBrokers = []string{"kafka:9092"}
				c.EnableKafkaBucketTopic = true
				c.KafkaNotificationTimeout = time.Second
				c.KafkaPopTimeout = time.Second
				c.KafkaPopIdleTimeout = -time.Second
				c.KafkaPopMaxConsumers = 1
			},
			wantMsg: "KAFKA_POP_IDLE_TIMEOUT",
		},
		{
			name: "splunk flush interval",
			mutate: func(c *Config) {
				c.SplunkHECFlushInterval = 0
			},
			wantMsg: "SPLUNK_HEC_FLUSH_INTERVAL",
		},
		{
			name: "audit hash key too short",
			mutate: func(c *Config) {
				c.S3AuditHashKey = "too-short"
			},
			wantMsg: "S3_AUDIT_HASH_KEY",
		},
		{
			name: "splunk token without endpoint",
			mutate: func(c *Config) {
				c.SplunkHECToken = "token"
			},
			wantMsg: "SPLUNK_HEC_ENDPOINT",
		},
		{
			name: "splunk endpoint without token",
			mutate: func(c *Config) {
				c.SplunkHECEndpoint = "https://splunk.example/services/collector/event"
			},
			wantMsg: "SPLUNK_HEC_TOKEN",
		},
		{
			name: "splunk endpoint and token without index",
			mutate: func(c *Config) {
				c.SplunkHECEndpoint = "https://splunk.example/services/collector/event"
				c.SplunkHECToken = "token"
			},
			wantMsg: "SPLUNK_HEC_INDEX",
		},
		{
			name: "splunk relative endpoint",
			mutate: func(c *Config) {
				c.SplunkHECEndpoint = "/services/collector/event"
				c.SplunkHECToken = "token"
				c.SplunkHECIndex = "gateway"
			},
			wantMsg: "absolute URL",
		},
		{
			name: "splunk endpoint scheme",
			mutate: func(c *Config) {
				c.SplunkHECEndpoint = "ftp://splunk.example/services/collector/event"
				c.SplunkHECToken = "token"
				c.SplunkHECIndex = "gateway"
			},
			wantMsg: "http or https",
		},
		{
			name: "splunk endpoint user information",
			mutate: func(c *Config) {
				c.SplunkHECEndpoint = "https://user@splunk.example/services/collector/event"
				c.SplunkHECToken = "token"
				c.SplunkHECIndex = "gateway"
			},
			wantMsg: "user information",
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

func TestEnvHelper(t *testing.T) {
	t.Setenv("TEST_ENV_KEY", "")
	if got := env("TEST_ENV_KEY", "default"); got != "default" {
		t.Fatalf("env default mismatch: got=%q want=%q", got, "default")
	}

	t.Setenv("TEST_ENV_KEY", " configured ")
	if got := env("TEST_ENV_KEY", "default"); got != "configured" {
		t.Fatalf("env value mismatch: got=%q want=%q", got, "configured")
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("TEST_BOOL_KEY", "")
	if got := envBool("TEST_BOOL_KEY", true); !got {
		t.Fatal("envBool() default = false, want true")
	}

	t.Setenv("TEST_BOOL_KEY", " true ")
	if got := envBool("TEST_BOOL_KEY", false); !got {
		t.Fatal("envBool() configured value = false, want true")
	}

	t.Setenv("TEST_BOOL_KEY", "false")
	if got := envBool("TEST_BOOL_KEY", true); got {
		t.Fatal("envBool() configured value = true, want false")
	}
}

func TestEnvCSVMetadataKeys(t *testing.T) {
	t.Setenv("REQUIRED_UPLOAD_METADATA_KEYS", "")
	if got := envCSVMetadataKeys("REQUIRED_UPLOAD_METADATA_KEYS"); got != nil {
		t.Fatalf("expected nil for empty env, got=%v", got)
	}

	t.Setenv("REQUIRED_UPLOAD_METADATA_KEYS", " Legal-Ingest-Timestamp , x-amz-meta-case-id, legal-ingest-timestamp ,, X-Amz-Meta-Case-ID ")
	got := envCSVMetadataKeys("REQUIRED_UPLOAD_METADATA_KEYS")
	want := []string{"legal-ingest-timestamp", "case-id"}
	if len(got) != len(want) {
		t.Fatalf("metadata key count mismatch: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("metadata key mismatch at %d: got=%q want=%q (all=%v)", i, got[i], want[i], got)
		}
	}
}

func TestEnvCSV(t *testing.T) {
	t.Setenv("KAFKA_BROKERS", "")
	if got := envCSV("KAFKA_BROKERS"); got != nil {
		t.Fatalf("expected nil for empty env, got=%v", got)
	}

	t.Setenv("KAFKA_BROKERS", " kafka-1:9092, kafka-2:9092, kafka-1:9092 ,, ")
	got := envCSV("KAFKA_BROKERS")
	want := []string{"kafka-1:9092", "kafka-2:9092"}
	if len(got) != len(want) {
		t.Fatalf("CSV value count mismatch: got=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CSV value mismatch at %d: got=%q want=%q", i, got[i], want[i])
		}
	}
}

func TestApplyDefaultsDoesNotInjectPrivateX25519Key(t *testing.T) {
	cfg := Config{}
	cfg.ApplyDefaults()
	if cfg.S3GatewayPrivateX25519Key != nil {
		t.Fatalf("expected no default private key to be injected")
	}
	if cfg.KafkaNotificationTimeout != defaultKafkaNotificationTimeout {
		t.Fatalf(
			"kafka notification timeout mismatch: got=%s want=%s",
			cfg.KafkaNotificationTimeout,
			defaultKafkaNotificationTimeout,
		)
	}
	if cfg.KafkaPopTimeout != defaultKafkaPopTimeout {
		t.Fatalf(
			"kafka pop timeout mismatch: got=%s want=%s",
			cfg.KafkaPopTimeout,
			defaultKafkaPopTimeout,
		)
	}
	if cfg.KafkaPopMaxConsumers != defaultKafkaPopMaxConsumers {
		t.Fatalf(
			"kafka pop max consumers mismatch: got=%d want=%d",
			cfg.KafkaPopMaxConsumers,
			defaultKafkaPopMaxConsumers,
		)
	}
	if cfg.KafkaPopIdleTimeout != defaultKafkaPopIdleTimeout {
		t.Fatalf(
			"kafka pop idle timeout mismatch: got=%s want=%s",
			cfg.KafkaPopIdleTimeout,
			defaultKafkaPopIdleTimeout,
		)
	}
	if cfg.SplunkHECFlushInterval != defaultSplunkHECFlushInterval {
		t.Fatalf(
			"splunk HEC flush interval mismatch: got=%s want=%s",
			cfg.SplunkHECFlushInterval,
			defaultSplunkHECFlushInterval,
		)
	}
	if cfg.LDAPOperationTimeout != defaultLDAPOperationTimeout {
		t.Fatalf("LDAP operation timeout mismatch: got=%s want=%s", cfg.LDAPOperationTimeout, defaultLDAPOperationTimeout)
	}
	if cfg.AuthMaxConcurrent != defaultAuthMaxConcurrent ||
		cfg.AuthRatePerSecond != defaultAuthRatePerSecond ||
		cfg.AuthRateBurst != defaultAuthRateBurst {
		t.Fatalf(
			"auth defaults mismatch: concurrent=%d rate=%d burst=%d",
			cfg.AuthMaxConcurrent,
			cfg.AuthRatePerSecond,
			cfg.AuthRateBurst,
		)
	}
	if cfg.AuthReservedConcurrent != defaultAuthReservedConcurrent ||
		cfg.AuthReservedRatePerSecond != defaultAuthReservedRatePerSecond ||
		cfg.AuthReservedBurst != defaultAuthReservedBurst ||
		cfg.AuthPerIPMaxConcurrent != defaultAuthPerIPMaxConcurrent ||
		cfg.AuthPerIPRatePerSecond != defaultAuthPerIPRatePerSecond ||
		cfg.AuthPerIPBurst != defaultAuthPerIPBurst ||
		cfg.AuthPerPrincipalMaxConcurrent != defaultAuthPerPrincipalMaxConcurrent ||
		cfg.AuthPerPrincipalRatePerSecond != defaultAuthPerPrincipalRatePerSecond ||
		cfg.AuthPerPrincipalBurst != defaultAuthPerPrincipalBurst ||
		cfg.AuthIngressPerIPRatePerSecond != defaultAuthIngressPerIPRatePerSecond ||
		cfg.AuthIngressPerIPBurst != defaultAuthIngressPerIPBurst ||
		cfg.AuthTrustedCredentialTTL != defaultAuthTrustedCredentialTTL {
		t.Fatalf("layered authentication defaults mismatch: %+v", cfg)
	}
	if cfg.AdminLoginReadTimeout != defaultAdminLoginReadTimeout ||
		cfg.ReadinessCheckTimeout != defaultReadinessCheckTimeout ||
		cfg.ReadinessCacheTTL != defaultReadinessCacheTTL {
		t.Fatalf(
			"control-plane timeout defaults mismatch: login=%s check=%s cache=%s",
			cfg.AdminLoginReadTimeout,
			cfg.ReadinessCheckTimeout,
			cfg.ReadinessCacheTTL,
		)
	}
	if len(cfg.ReadinessAllowedCIDRs) != 2 {
		t.Fatalf("readiness CIDR defaults mismatch: %v", cfg.ReadinessAllowedCIDRs)
	}
}

func TestApplyDefaultsTransferLimits(t *testing.T) {
	tests := []struct {
		name           string
		cfg            Config
		wantIdle       time.Duration
		wantConcurrent int
	}{
		{name: "defaults", wantIdle: 60 * time.Second, wantConcurrent: 32},
		{
			name:           "configured",
			cfg:            Config{TransferIdleTimeout: 2 * time.Minute, MaxConcurrentRequests: 8},
			wantIdle:       2 * time.Minute,
			wantConcurrent: 8,
		},
		{
			name:           "negative values retained for validation",
			cfg:            Config{TransferIdleTimeout: -time.Second, MaxConcurrentRequests: -1},
			wantIdle:       -time.Second,
			wantConcurrent: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ApplyDefaults()
			if tt.cfg.TransferIdleTimeout != tt.wantIdle || tt.cfg.MaxConcurrentRequests != tt.wantConcurrent {
				t.Fatalf(
					"transfer limits = %s/%d, want %s/%d",
					tt.cfg.TransferIdleTimeout, tt.cfg.MaxConcurrentRequests,
					tt.wantIdle, tt.wantConcurrent,
				)
			}
			if tt.cfg.ReadTimeout != 0 || tt.cfg.WriteTimeout != 0 {
				t.Fatal("absolute read/write timeouts should remain disabled by default")
			}
		})
	}
}

func TestLoadConfigTransferLimits(t *testing.T) {
	setRequiredX25519PrivateKeyEnv(t)
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=com")
	t.Setenv("S3_ENDPOINT", "https://s3.example")
	t.Setenv("S3_ACCESS_KEY", "access-key")
	t.Setenv("S3_SECRET_KEY", "secret-key")

	tests := []struct {
		name           string
		idleTimeout    string
		maxConcurrent  string
		readTimeout    string
		writeTimeout   string
		wantIdle       time.Duration
		wantConcurrent int
		wantRead       time.Duration
		wantWrite      time.Duration
	}{
		{name: "defaults", wantIdle: 60 * time.Second, wantConcurrent: 32},
		{
			name:           "configured",
			idleTimeout:    "90s",
			maxConcurrent:  "12",
			readTimeout:    "5m",
			writeTimeout:   "7m",
			wantIdle:       90 * time.Second,
			wantConcurrent: 12,
			wantRead:       5 * time.Minute,
			wantWrite:      7 * time.Minute,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_TRANSFER_IDLE_TIMEOUT", tt.idleTimeout)
			t.Setenv("HTTP_MAX_CONCURRENT_REQUESTS", tt.maxConcurrent)
			t.Setenv("HTTP_READ_TIMEOUT", tt.readTimeout)
			t.Setenv("HTTP_WRITE_TIMEOUT", tt.writeTimeout)

			cfg := LoadConfig()
			if cfg.TransferIdleTimeout != tt.wantIdle || cfg.MaxConcurrentRequests != tt.wantConcurrent {
				t.Fatalf(
					"transfer limits = %s/%d, want %s/%d",
					cfg.TransferIdleTimeout, cfg.MaxConcurrentRequests,
					tt.wantIdle, tt.wantConcurrent,
				)
			}
			if cfg.ReadTimeout != tt.wantRead || cfg.WriteTimeout != tt.wantWrite {
				t.Fatalf(
					"absolute timeouts = %s/%s, want %s/%s",
					cfg.ReadTimeout, cfg.WriteTimeout, tt.wantRead, tt.wantWrite,
				)
			}
		})
	}
}

func TestLoadConfigControlPlaneLimits(t *testing.T) {
	setRequiredX25519PrivateKeyEnv(t)
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=com")
	t.Setenv("S3_ENDPOINT", "https://s3.example")
	t.Setenv("S3_ACCESS_KEY", "access-key")
	t.Setenv("S3_SECRET_KEY", "secret-key")
	t.Setenv("LDAP_OPERATION_TIMEOUT", "7s")
	t.Setenv("AUTH_MAX_CONCURRENT", "8")
	t.Setenv("AUTH_RATE_PER_SECOND", "9")
	t.Setenv("AUTH_RATE_BURST", "10")
	t.Setenv("ADMIN_LOGIN_READ_TIMEOUT", "4s")
	t.Setenv("READINESS_CHECK_TIMEOUT", "1500ms")
	t.Setenv("READINESS_CACHE_TTL", "3s")
	t.Setenv("READINESS_ALLOWED_CIDRS", "10.0.0.0/8,fd00::/8")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.1.0.0/16,fd01::/48")

	cfg := LoadConfig()
	if cfg.LDAPGroupBaseDN != "ou=groups,dc=example,dc=com" {
		t.Fatalf("group container mismatch: got=%q", cfg.LDAPGroupBaseDN)
	}
	if cfg.LDAPOperationTimeout != 7*time.Second || cfg.AuthMaxConcurrent != 8 ||
		cfg.AuthRatePerSecond != 9 || cfg.AuthRateBurst != 10 {
		t.Fatalf(
			"authentication config mismatch: timeout=%s concurrent=%d rate=%d burst=%d",
			cfg.LDAPOperationTimeout,
			cfg.AuthMaxConcurrent,
			cfg.AuthRatePerSecond,
			cfg.AuthRateBurst,
		)
	}
	if cfg.AuthReservedConcurrent != 2 ||
		cfg.AuthReservedRatePerSecond != 2 || cfg.AuthReservedBurst != 2 {
		t.Fatalf(
			"derived authentication reserve mismatch: concurrent=%d rate=%d burst=%d",
			cfg.AuthReservedConcurrent,
			cfg.AuthReservedRatePerSecond,
			cfg.AuthReservedBurst,
		)
	}
	if cfg.AdminLoginReadTimeout != 4*time.Second ||
		cfg.ReadinessCheckTimeout != 1500*time.Millisecond ||
		cfg.ReadinessCacheTTL != 3*time.Second {
		t.Fatalf(
			"control-plane config mismatch: login=%s check=%s cache=%s",
			cfg.AdminLoginReadTimeout,
			cfg.ReadinessCheckTimeout,
			cfg.ReadinessCacheTTL,
		)
	}
	if len(cfg.ReadinessAllowedCIDRs) != 2 ||
		cfg.ReadinessAllowedCIDRs[0] != "10.0.0.0/8" ||
		cfg.ReadinessAllowedCIDRs[1] != "fd00::/8" {
		t.Fatalf("readiness CIDRs mismatch: %v", cfg.ReadinessAllowedCIDRs)
	}
	if len(cfg.TrustedProxyCIDRs) != 2 ||
		cfg.TrustedProxyCIDRs[0] != "10.1.0.0/16" ||
		cfg.TrustedProxyCIDRs[1] != "fd01::/48" {
		t.Fatalf("trusted proxy CIDRs mismatch: %v", cfg.TrustedProxyCIDRs)
	}
}

func TestLoadConfigUpstreamSkipCertificateValidation(t *testing.T) {
	setRequiredX25519PrivateKeyEnv(t)
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=com")
	t.Setenv("S3_ENDPOINT", "https://s3.example")
	t.Setenv("S3_ACCESS_KEY", "access-key")
	t.Setenv("S3_SECRET_KEY", "secret-key")

	for _, tc := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "default"},
		{name: "disabled", value: "false"},
		{name: "enabled", value: "true", want: true},
		{name: "whitespace", value: " TRUE ", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("S3_UPSTREAM_TLS_SKIP_VERIFY", tc.value)
			cfg := LoadConfig()
			if cfg.UpstreamSkipCertificateValidation != tc.want {
				t.Fatalf("skip certificate validation = %t, want %t", cfg.UpstreamSkipCertificateValidation, tc.want)
			}
		})
	}
}

func TestLoadConfigSplunkHEC(t *testing.T) {
	setRequiredX25519PrivateKeyEnv(t)
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=com")
	t.Setenv("S3_ENDPOINT", "https://s3.example")
	t.Setenv("S3_ACCESS_KEY", "access-key")
	t.Setenv("S3_SECRET_KEY", "secret-key")
	t.Setenv("SPLUNK_HEC_ENDPOINT", "https://splunk.example:8088/services/collector/event")
	t.Setenv("SPLUNK_HEC_TOKEN", "hec-token")
	t.Setenv("SPLUNK_HEC_INDEX", "gateway")
	t.Setenv("SPLUNK_HEC_FLUSH_INTERVAL", "45s")
	t.Setenv("S3_AUDIT_HASH_KEY", "1234567890abcdef1234567890abcdef")

	cfg := LoadConfig()
	if cfg.SplunkHECEndpoint != "https://splunk.example:8088/services/collector/event" {
		t.Fatalf("splunk HEC endpoint mismatch: got=%q", cfg.SplunkHECEndpoint)
	}
	if cfg.SplunkHECToken != "hec-token" {
		t.Fatalf("splunk HEC token mismatch: got=%q", cfg.SplunkHECToken)
	}
	if cfg.SplunkHECIndex != "gateway" {
		t.Fatalf("splunk HEC index mismatch: got=%q", cfg.SplunkHECIndex)
	}
	if cfg.SplunkHECFlushInterval != 45*time.Second {
		t.Fatalf("splunk HEC flush interval mismatch: got=%s want=45s", cfg.SplunkHECFlushInterval)
	}
	if cfg.S3AuditHashKey != "1234567890abcdef1234567890abcdef" {
		t.Fatalf("S3 audit hash key mismatch")
	}
}

func TestLoadConfigKafkaGlobalTopic(t *testing.T) {
	setRequiredX25519PrivateKeyEnv(t)
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("LDAP_GROUP_BASE_DN", "ou=groups,dc=example,dc=com")
	t.Setenv("S3_ENDPOINT", "https://s3.example")
	t.Setenv("S3_ACCESS_KEY", "access-key")
	t.Setenv("S3_SECRET_KEY", "secret-key")
	t.Setenv("KAFKA_BROKERS", "kafka-1:9092,kafka-2:9092")
	t.Setenv("ENABLE_KAFKA_BUCKET_TOPIC", "true")
	t.Setenv("KAFKA_GLOBAL_TOPIC", "_all")
	t.Setenv("KAFKA_NOTIFICATION_TIMEOUT", "3s")
	t.Setenv("KAFKA_POP_TIMEOUT", "7s")
	t.Setenv("KAFKA_POP_IDLE_TIMEOUT", "11s")
	t.Setenv("KAFKA_POP_MAX_CONSUMERS", "42")

	cfg := LoadConfig()
	if !cfg.EnableKafkaBucketTopic {
		t.Fatal("kafka bucket topic should be enabled")
	}
	if cfg.KafkaGlobalTopic != "_all" {
		t.Fatalf("kafka global topic mismatch: got=%q want=%q", cfg.KafkaGlobalTopic, "_all")
	}
	if cfg.KafkaNotificationTimeout != 3*time.Second {
		t.Fatalf(
			"kafka notification timeout mismatch: got=%s want=3s",
			cfg.KafkaNotificationTimeout,
		)
	}
	if cfg.KafkaPopTimeout != 7*time.Second {
		t.Fatalf("kafka pop timeout mismatch: got=%s want=7s", cfg.KafkaPopTimeout)
	}
	if cfg.KafkaPopIdleTimeout != 11*time.Second {
		t.Fatalf("kafka pop idle timeout mismatch: got=%s want=11s", cfg.KafkaPopIdleTimeout)
	}
	if cfg.KafkaPopMaxConsumers != 42 {
		t.Fatalf("kafka pop max consumers mismatch: got=%d want=42", cfg.KafkaPopMaxConsumers)
	}
}

func TestCookieSecretValidation(t *testing.T) {
	base := Config{
		LDAPGroupBaseDN:  "ou=groups,dc=example,dc=com",
		UpstreamEndpoint: "https://s3.example",
	}
	base.ApplyDefaults()
	base.S3GatewayPrivateX25519Key = mustTestX25519PrivateKey(t)

	// empty string is allowed (ephemeral random keys)
	cfg := base
	cfg.CookieSecret = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty CookieSecret should pass validation, got: %v", err)
	}

	// exactly 32 characters is allowed
	cfg = base
	cfg.CookieSecret = "1234567890abcdef1234567890abcdef"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("32-char CookieSecret should pass validation, got: %v", err)
	}

	// more than 32 characters is allowed
	cfg = base
	cfg.CookieSecret = "a-very-long-secret-key-for-production"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("long CookieSecret should pass validation, got: %v", err)
	}

	// fewer than 16 characters (non-empty) must be rejected
	cfg = base
	cfg.CookieSecret = "short"
	if err := cfg.Validate(); err == nil {
		t.Fatalf("short CookieSecret should fail validation")
	} else if !strings.Contains(err.Error(), "COOKIE_SECRET") {
		t.Fatalf("expected COOKIE_SECRET in error, got: %v", err)
	}
}

func TestValidateUpstreamEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		valid    bool
	}{
		{name: "HTTPS", endpoint: "https://s3.example", valid: true},
		{name: "custom port and path", endpoint: "https://localhost:9000/s3/", valid: true},
		{name: "escaped path", endpoint: "https://s3.example/base%20path/", valid: true},
		{name: "IPv4", endpoint: "https://127.0.0.1:9000", valid: true},
		{name: "IPv6", endpoint: "https://[::1]:9000", valid: true},
		{name: "uppercase scheme", endpoint: "HTTPS://s3.example", valid: true},
		{name: "empty"},
		{name: "HTTP", endpoint: "http://s3.example"},
		{name: "missing scheme", endpoint: "s3.example:9000"},
		{name: "relative authority", endpoint: "//s3.example"},
		{name: "missing host", endpoint: "https:///s3"},
		{name: "port without host", endpoint: "https://:9000"},
		{name: "opaque URL", endpoint: "https:s3.example"},
		{name: "host whitespace", endpoint: "https://s3 .example"},
		{name: "invalid escape", endpoint: "https://s3.example/%zz"},
		{name: "invalid port", endpoint: "https://s3.example:abc"},
		{name: "port out of range", endpoint: "https://s3.example:65536"},
		{name: "zero port", endpoint: "https://s3.example:0"},
		{name: "empty port", endpoint: "https://s3.example:"},
		{name: "missing IPv6 bracket", endpoint: "https://[::1"},
		{name: "invalid IPv6", endpoint: "https://[not-an-IP]:9000"},
		{name: "unbracketed IPv6", endpoint: "https://::1"},
		{name: "embedded credentials", endpoint: "https://user:password@s3.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUpstreamEndpoint(tt.endpoint)
			if (err == nil) != tt.valid {
				t.Fatalf("ValidateUpstreamEndpoint(%q) = %v, want valid=%t", tt.endpoint, err, tt.valid)
			}
			if err != nil && !strings.Contains(err.Error(), "S3_ENDPOINT") {
				t.Fatalf("error %q does not identify S3_ENDPOINT", err)
			}
		})
	}
}
