package config

import (
	"strings"
	"testing"
)

func TestKafkaTopicNamespaces(t *testing.T) {
	base := Config{
		LDAPGroupBaseDN:  "ou=groups,dc=example,dc=com",
		UpstreamEndpoint: "https://s3.example",
		KafkaBrokers:     []string{"kafka:9092"},
	}
	base.ApplyDefaults()
	base.S3GatewayPrivateX25519Key = mustTestX25519PrivateKey(t)
	for _, tc := range []struct {
		name         string
		bucketTopics bool
		globalTopic  string
		wantErr      bool
	}{
		{name: "bucket only", bucketTopics: true},
		{name: "reserved global topic", bucketTopics: true, globalTopic: "_all"},
		{name: "custom reserved topic", bucketTopics: true, globalTopic: " _events "},
		{name: "bucket namespace collision", bucketTopics: true, globalTopic: "team2-images", wantErr: true},
		{name: "trimmed collision", bucketTopics: true, globalTopic: " team2-images ", wantErr: true},
		{name: "global only permits existing names", globalTopic: "team2-images"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.EnableKafkaBucketTopic = tc.bucketTopics
			cfg.KafkaGlobalTopic = tc.globalTopic
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, want error %t", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "KAFKA_GLOBAL_TOPIC") {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}
