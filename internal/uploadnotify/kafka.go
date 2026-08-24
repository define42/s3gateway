package uploadnotify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type recordProducer interface {
	Produce(context.Context, *kgo.Record, func(*kgo.Record, error))
	Close()
}

// KafkaPublisher sends upload events to either one configured topic or a
// topic whose name matches the uploaded object's bucket.
type KafkaPublisher struct {
	producer    recordProducer
	sharedTopic string
	timeout     time.Duration
}

// NewKafkaPublisher constructs a pure-Go Kafka producer. Kafka connections
// are established lazily when the first event is published.
func NewKafkaPublisher(brokers []string, sharedTopic string, timeout time.Duration) (*KafkaPublisher, error) {
	if len(brokers) == 0 {
		return nil, errors.New("uploadnotify: at least one kafka broker is required")
	}
	if timeout <= 0 {
		return nil, errors.New("uploadnotify: kafka notification timeout must be positive")
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

	return newKafkaPublisher(client, sharedTopic, timeout), nil
}

func newKafkaPublisher(producer recordProducer, sharedTopic string, timeout time.Duration) *KafkaPublisher {
	return &KafkaPublisher{
		producer:    producer,
		sharedTopic: strings.TrimSpace(sharedTopic),
		timeout:     timeout,
	}
}

// Notify publishes one JSON event and waits for Kafka acknowledgement until
// the configured timeout. A timeout may leave an already-sent record with an
// unknown delivery outcome, so consumers should tolerate duplicate events.
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

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("uploadnotify: encode event: %w", err)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	publishCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	result := make(chan error, 1)
	p.producer.Produce(
		publishCtx,
		&kgo.Record{
			Topic: p.topicFor(event.Bucket),
			Key:   []byte(event.Bucket + "/" + event.Key),
			Value: payload,
			Headers: []kgo.RecordHeader{{
				Key:   "content-type",
				Value: []byte("application/json"),
			}},
		},
		func(_ *kgo.Record, err error) {
			result <- err
		},
	)

	select {
	case err := <-result:
		if err != nil {
			return fmt.Errorf("uploadnotify: publish event: %w", err)
		}
		return nil
	case <-publishCtx.Done():
		return fmt.Errorf("uploadnotify: publish event: %w", publishCtx.Err())
	}
}

func (p *KafkaPublisher) topicFor(bucket string) string {
	if p.sharedTopic != "" {
		return p.sharedTopic
	}
	return bucket
}

// Close releases the Kafka client's connections and goroutines.
func (p *KafkaPublisher) Close() {
	p.producer.Close()
}
