package uploadnotify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/twmb/franz-go/pkg/kgo"
)

type recordProducer interface {
	Produce(context.Context, *kgo.Record, func(*kgo.Record, error))
	Close()
}

// KafkaPublisher sends object-creation events to an enabled bucket-named topic, a
// configured global topic, or both.
type KafkaPublisher struct {
	producer           recordProducer
	bucketTopicEnabled bool
	globalTopic        string
	timeout            time.Duration
}

// NewKafkaPublisher constructs a pure-Go Kafka producer. Kafka connections
// are established lazily when the first event is published.
func NewKafkaPublisher(
	brokers []string,
	bucketTopicEnabled bool,
	globalTopic string,
	timeout time.Duration,
) (*KafkaPublisher, error) {
	if len(brokers) == 0 {
		return nil, errors.New("uploadnotify: at least one kafka broker is required")
	}
	if timeout <= 0 {
		return nil, errors.New("uploadnotify: kafka notification timeout must be positive")
	}
	if !bucketTopicEnabled && strings.TrimSpace(globalTopic) == "" {
		return nil, errors.New("uploadnotify: at least one kafka topic must be enabled")
	}

	client, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.ClientID("s3gateway-upload-notifier"),
		kgo.AllowAutoTopicCreation(),
		kgo.RecordDeliveryTimeout(timeout),
		kgo.RequestTimeoutOverhead(timeout),
	)
	if err != nil {
		return nil, fmt.Errorf("uploadnotify: create kafka client: %w", err)
	}

	return newKafkaPublisher(client, bucketTopicEnabled, globalTopic, timeout), nil
}

func newKafkaPublisher(
	producer recordProducer,
	bucketTopicEnabled bool,
	globalTopic string,
	timeout time.Duration,
) *KafkaPublisher {
	return &KafkaPublisher{
		producer:           producer,
		bucketTopicEnabled: bucketTopicEnabled,
		globalTopic:        strings.TrimSpace(globalTopic),
		timeout:            timeout,
	}
}

// Notify publishes one JSON event to every configured destination and waits
// for all Kafka acknowledgements until the shared timeout. A timeout may leave
// an already-sent record with an unknown delivery outcome, so consumers should
// tolerate duplicate events.
func (p *KafkaPublisher) Notify(ctx context.Context, event Event) error {
	if strings.TrimSpace(event.Bucket) == "" {
		return errors.New("uploadnotify: event bucket is required")
	}
	if strings.TrimSpace(event.Key) == "" {
		return errors.New("uploadnotify: event key is required")
	}
	if event.SchemaVersion == 0 {
		event.SchemaVersion = SchemaVersion
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if strings.TrimSpace(event.EventID) == "" {
		event.EventID = uuid.NewV7().String()
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("uploadnotify: encode event: %w", err)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	publishCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	topics := p.topicsFor(event.Bucket)
	if len(topics) == 0 {
		return errors.New("uploadnotify: no kafka topics configured")
	}
	type publishResult struct {
		topic string
		err   error
	}
	results := make(chan publishResult, len(topics))
	for _, topic := range topics {
		record := &kgo.Record{
			Topic: topic,
			Key:   []byte(event.Bucket + "/" + event.Key),
			Value: payload,
			Headers: []kgo.RecordHeader{{
				Key:   "content-type",
				Value: []byte("application/json"),
			}},
		}
		p.producer.Produce(
			publishCtx,
			record,
			func(record *kgo.Record, err error) {
				results <- publishResult{topic: record.Topic, err: err}
			},
		)
	}

	var publishErrors []error
	for remaining := len(topics); remaining > 0; remaining-- {
		select {
		case result := <-results:
			if result.err != nil {
				publishErrors = append(
					publishErrors,
					fmt.Errorf("topic %q: %w", result.topic, result.err),
				)
			}
		case <-publishCtx.Done():
			publishErrors = append(publishErrors, publishCtx.Err())
			return fmt.Errorf(
				"uploadnotify: publish event: %w",
				errors.Join(publishErrors...),
			)
		}
	}
	if len(publishErrors) > 0 {
		return fmt.Errorf(
			"uploadnotify: publish event: %w",
			errors.Join(publishErrors...),
		)
	}
	return nil
}

func (p *KafkaPublisher) topicsFor(bucket string) []string {
	topics := make([]string, 0, 2)
	if p.bucketTopicEnabled {
		topics = append(topics, bucket)
	}
	if p.globalTopic != "" && (!p.bucketTopicEnabled || p.globalTopic != bucket) {
		topics = append(topics, p.globalTopic)
	}
	return topics
}

// Close releases the Kafka client's connections and goroutines.
func (p *KafkaPublisher) Close() {
	p.producer.Close()
}
