package config

import (
	"errors"
	"strings"
)

// ValidateKafkaGlobalTopic keeps global events outside the bucket topic namespace
// when both destinations are enabled. S3 bucket names cannot start with '_'.
func ValidateKafkaGlobalTopic(bucketTopics bool, globalTopic string) error {
	globalTopic = strings.TrimSpace(globalTopic)
	if bucketTopics && globalTopic != "" && !strings.HasPrefix(globalTopic, "_") {
		return errors.New("KAFKA_GLOBAL_TOPIC must start with '_' when ENABLE_KAFKA_BUCKET_TOPIC is enabled to prevent bucket topic collisions")
	}
	return nil
}
