package uploadnotify

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type fakeRecordProducer struct {
	records    []*kgo.Record
	produceErr error
	closeCalls int
}

func (p *fakeRecordProducer) Produce(_ context.Context, record *kgo.Record, callback func(*kgo.Record, error)) {
	p.records = append(p.records, record)
	callback(record, p.produceErr)
}

func (p *fakeRecordProducer) Close() {
	p.closeCalls++
}

func TestNewKafkaPublisherValidation(t *testing.T) {
	tests := []struct {
		name    string
		brokers []string
		timeout time.Duration
	}{
		{
			name:    "missing brokers",
			timeout: time.Second,
		},
		{
			name:    "invalid timeout",
			brokers: []string{"kafka:9092"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher, err := NewKafkaPublisher(tt.brokers, "uploads", tt.timeout)
			if err == nil {
				publisher.Close()
				t.Fatal("NewKafkaPublisher() error = nil, want validation error")
			}
		})
	}
}

func TestKafkaPublisherNotifyTopicModes(t *testing.T) {
	occurredAt := time.Date(2026, time.August, 24, 12, 30, 0, 0, time.UTC)
	tests := []struct {
		name          string
		sharedTopic   string
		expectedTopic string
	}{
		{
			name:          "shared topic",
			sharedTopic:   "all-uploads",
			expectedTopic: "all-uploads",
		},
		{
			name:          "bucket topic",
			expectedTopic: "evidence-bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producer := &fakeRecordProducer{}
			publisher := newKafkaPublisher(producer, tt.sharedTopic, time.Second)
			event := Event{
				EventName:  EventObjectCreatedPut,
				Bucket:     "evidence-bucket",
				Key:        "cases/42/document.pdf",
				ETag:       "etag-1",
				VersionID:  "version-1",
				Uploader:   "alice@example.com",
				OccurredAt: occurredAt,
			}

			if err := publisher.Notify(context.Background(), event); err != nil {
				t.Fatalf("Notify() error = %v", err)
			}
			if len(producer.records) != 1 {
				t.Fatalf("produced record count = %d, want 1", len(producer.records))
			}

			record := producer.records[0]
			if record.Topic != tt.expectedTopic {
				t.Fatalf("record topic = %q, want %q", record.Topic, tt.expectedTopic)
			}
			if got, want := string(record.Key), "evidence-bucket/cases/42/document.pdf"; got != want {
				t.Fatalf("record key = %q, want %q", got, want)
			}
			if len(record.Headers) != 1 || record.Headers[0].Key != "content-type" || string(record.Headers[0].Value) != "application/json" {
				t.Fatalf("record content-type header = %#v", record.Headers)
			}

			var got Event
			if err := json.Unmarshal(record.Value, &got); err != nil {
				t.Fatalf("decode produced event: %v", err)
			}
			if got.SchemaVersion != SchemaVersion {
				t.Fatalf("schema version = %d, want %d", got.SchemaVersion, SchemaVersion)
			}
			if got.EventName != event.EventName || got.Bucket != event.Bucket || got.Key != event.Key || got.ETag != event.ETag || got.VersionID != event.VersionID || got.Uploader != event.Uploader || !got.OccurredAt.Equal(occurredAt) {
				t.Fatalf("produced event mismatch: got=%+v want=%+v", got, event)
			}
		})
	}
}

func TestKafkaPublisherNotifyFailure(t *testing.T) {
	produceErr := errors.New("broker unavailable")
	producer := &fakeRecordProducer{produceErr: produceErr}
	publisher := newKafkaPublisher(producer, "uploads", time.Second)

	err := publisher.Notify(context.Background(), Event{
		EventName: EventObjectCreatedPut,
		Bucket:    "bucket",
		Key:       "object",
	})
	if !errors.Is(err, produceErr) {
		t.Fatalf("Notify() error = %v, want wrapped %v", err, produceErr)
	}
}

func TestKafkaPublisherNotifyValidation(t *testing.T) {
	tests := []struct {
		name  string
		event Event
	}{
		{
			name:  "missing bucket",
			event: Event{Key: "object"},
		},
		{
			name:  "missing key",
			event: Event{Bucket: "bucket"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producer := &fakeRecordProducer{}
			publisher := newKafkaPublisher(producer, "uploads", time.Second)
			if err := publisher.Notify(context.Background(), tt.event); err == nil {
				t.Fatal("Notify() error = nil, want validation error")
			}
			if len(producer.records) != 0 {
				t.Fatalf("produced record count = %d, want 0", len(producer.records))
			}
		})
	}
}

func TestKafkaPublisherClose(t *testing.T) {
	producer := &fakeRecordProducer{}
	publisher := newKafkaPublisher(producer, "uploads", time.Second)
	publisher.Close()
	if producer.closeCalls != 1 {
		t.Fatalf("producer close calls = %d, want 1", producer.closeCalls)
	}
}
