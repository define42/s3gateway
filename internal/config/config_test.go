package config

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidateMatrix(t *testing.T) {
	base := Config{
		GroupCacheMaxEntries:   1,
		SigV4MaxSkew:           time.Second,
		ReadHeaderTimeout:      time.Second,
		IdleTimeout:            time.Second,
		ShutdownTimeout:        time.Second,
		MaxHeaderBytes:         1,
		SplunkHECFlushInterval: time.Second,
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
	if cfg.SplunkHECFlushInterval != defaultSplunkHECFlushInterval {
		t.Fatalf(
			"splunk HEC flush interval mismatch: got=%s want=%s",
			cfg.SplunkHECFlushInterval,
			defaultSplunkHECFlushInterval,
		)
	}
}

func TestLoadConfigSplunkHEC(t *testing.T) {
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
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
	t.Setenv("LDAP_URL", "ldap://ldap.example:389")
	t.Setenv("LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("S3_ENDPOINT", "https://s3.example")
	t.Setenv("S3_ACCESS_KEY", "access-key")
	t.Setenv("S3_SECRET_KEY", "secret-key")
	t.Setenv("KAFKA_BROKERS", "kafka-1:9092,kafka-2:9092")
	t.Setenv("ENABLE_KAFKA_BUCKET_TOPIC", "true")
	t.Setenv("KAFKA_GLOBAL_TOPIC", "_all")
	t.Setenv("KAFKA_NOTIFICATION_TIMEOUT", "3s")
	t.Setenv("KAFKA_POP_TIMEOUT", "7s")
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
	if cfg.KafkaPopMaxConsumers != 42 {
		t.Fatalf("kafka pop max consumers mismatch: got=%d want=42", cfg.KafkaPopMaxConsumers)
	}
}

func TestCookieSecretValidation(t *testing.T) {
	base := Config{
		GroupCacheMaxEntries:   1,
		SigV4MaxSkew:           time.Second,
		ReadHeaderTimeout:      time.Second,
		IdleTimeout:            time.Second,
		ShutdownTimeout:        time.Second,
		MaxHeaderBytes:         1,
		SplunkHECFlushInterval: time.Second,
	}

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
