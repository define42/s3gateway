package uploadnotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/twmb/franz-go/pkg/kgo"
)

type fakeRecordProducer struct {
	records    []*kgo.Record
	produceErr error
	topicErrs  map[string]error
	closeCalls int
}

func (p *fakeRecordProducer) Produce(_ context.Context, record *kgo.Record, callback func(*kgo.Record, error)) {
	p.records = append(p.records, record)
	produceErr := p.produceErr
	if topicErr, ok := p.topicErrs[record.Topic]; ok {
		produceErr = topicErr
	}
	callback(record, produceErr)
}

func (p *fakeRecordProducer) Close() {
	p.closeCalls++
}

func TestNewKafkaPublisherValidation(t *testing.T) {
	tests := []struct {
		name               string
		brokers            []string
		bucketTopicEnabled bool
		globalTopic        string
		timeout            time.Duration
	}{
		{
			name:               "missing brokers",
			bucketTopicEnabled: true,
			timeout:            time.Second,
		},
		{
			name:               "invalid timeout",
			brokers:            []string{"kafka:9092"},
			bucketTopicEnabled: true,
		},
		{
			name:    "no topics",
			brokers: []string{"kafka:9092"},
			timeout: time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher, err := NewKafkaPublisher(
				tt.brokers,
				tt.bucketTopicEnabled,
				tt.globalTopic,
				tt.timeout,
			)
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
		name               string
		bucketTopicEnabled bool
		globalTopic        string
		expectedTopics     []string
	}{
		{
			name:               "bucket topic",
			bucketTopicEnabled: true,
			expectedTopics:     []string{"evidence-bucket"},
		},
		{
			name:           "global topic",
			globalTopic:    "_all",
			expectedTopics: []string{"_all"},
		},
		{
			name:               "bucket and global topics",
			bucketTopicEnabled: true,
			globalTopic:        "_all",
			expectedTopics:     []string{"evidence-bucket", "_all"},
		},
		{
			name:               "matching bucket and global topics",
			bucketTopicEnabled: true,
			globalTopic:        "evidence-bucket",
			expectedTopics:     []string{"evidence-bucket"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			producer := &fakeRecordProducer{}
			publisher := newKafkaPublisher(
				producer,
				tt.bucketTopicEnabled,
				tt.globalTopic,
				time.Second,
			)
			event := Event{
				EventID:    "019c0000-0000-7000-8000-000000000001",
				EventName:  EventObjectCreatedPut,
				Bucket:     "evidence-bucket",
				Key:        "cases/42/document.pdf",
				ETag:       "etag-1",
				VersionID:  "version-1",
				Uploader:   "alice@example.com",
				OccurredAt: occurredAt,
			}

			if err := publisher.Notify(t.Context(), event); err != nil {
				t.Fatalf("Notify() error = %v", err)
			}
			if len(producer.records) != len(tt.expectedTopics) {
				t.Fatalf(
					"produced record count = %d, want %d",
					len(producer.records),
					len(tt.expectedTopics),
				)
			}

			for i, record := range producer.records {
				if record.Topic != tt.expectedTopics[i] {
					t.Fatalf("record %d topic = %q, want %q", i, record.Topic, tt.expectedTopics[i])
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
				if got.EventID != event.EventID || got.EventName != event.EventName || got.Bucket != event.Bucket || got.Key != event.Key || got.ETag != event.ETag || got.VersionID != event.VersionID || got.Uploader != event.Uploader || !got.OccurredAt.Equal(occurredAt) {
					t.Fatalf("produced event mismatch: got=%+v want=%+v", got, event)
				}
			}
			if len(producer.records) == 2 && !bytes.Equal(producer.records[0].Value, producer.records[1].Value) {
				t.Fatal("bucket and global records must contain identical payloads")
			}
		})
	}
}

func TestKafkaPublisherNotifyGeneratesSharedEventID(t *testing.T) {
	producer := &fakeRecordProducer{}
	publisher := newKafkaPublisher(producer, true, "_all", time.Second)

	if err := publisher.Notify(t.Context(), Event{
		EventName: EventObjectCreatedPut,
		Bucket:    "bucket",
		Key:       "object",
	}); err != nil {
		t.Fatalf("Notify() error = %v", err)
	}
	if len(producer.records) != 2 {
		t.Fatalf("produced record count = %d, want 2", len(producer.records))
	}

	var bucketEvent Event
	if err := json.Unmarshal(producer.records[0].Value, &bucketEvent); err != nil {
		t.Fatalf("decode bucket event: %v", err)
	}
	var globalEvent Event
	if err := json.Unmarshal(producer.records[1].Value, &globalEvent); err != nil {
		t.Fatalf("decode global event: %v", err)
	}
	if bucketEvent.EventID == "" || globalEvent.EventID != bucketEvent.EventID {
		t.Fatalf(
			"event ids differ: bucket=%q global=%q",
			bucketEvent.EventID,
			globalEvent.EventID,
		)
	}
	eventID, err := uuid.Parse(bucketEvent.EventID)
	if err != nil {
		t.Fatalf("event id is not a UUID: %v", err)
	}
	if version := eventID[6] >> 4; version != 7 {
		t.Fatalf("event id version = %d, want 7", version)
	}
}

func TestKafkaPublisherNotifyFailure(t *testing.T) {
	produceErr := errors.New("broker unavailable")
	producer := &fakeRecordProducer{produceErr: produceErr}
	publisher := newKafkaPublisher(producer, false, "_all", time.Second)

	err := publisher.Notify(t.Context(), Event{
		EventName: EventObjectCreatedPut,
		Bucket:    "bucket",
		Key:       "object",
	})
	if !errors.Is(err, produceErr) {
		t.Fatalf("Notify() error = %v, want wrapped %v", err, produceErr)
	}
}

func TestKafkaPublisherNotifyDualTopicFailure(t *testing.T) {
	bucketErr := errors.New("bucket topic unavailable")
	globalErr := errors.New("global topic unavailable")
	producer := &fakeRecordProducer{topicErrs: map[string]error{
		"bucket": bucketErr,
		"_all":   globalErr,
	}}
	publisher := newKafkaPublisher(producer, true, "_all", time.Second)

	err := publisher.Notify(t.Context(), Event{
		EventName: EventObjectCreatedPut,
		Bucket:    "bucket",
		Key:       "object",
	})
	if !errors.Is(err, bucketErr) || !errors.Is(err, globalErr) {
		t.Fatalf("Notify() error = %v, want both topic errors", err)
	}
	if len(producer.records) != 2 {
		t.Fatalf("produced record count = %d, want 2", len(producer.records))
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
			publisher := newKafkaPublisher(producer, true, "", time.Second)
			if err := publisher.Notify(t.Context(), tt.event); err == nil {
				t.Fatal("Notify() error = nil, want validation error")
			}
			if len(producer.records) != 0 {
				t.Fatalf("produced record count = %d, want 0", len(producer.records))
			}
		})
	}
}

func TestKafkaPublisherNotifyWithoutTopics(t *testing.T) {
	producer := &fakeRecordProducer{}
	publisher := newKafkaPublisher(producer, false, "", time.Second)

	err := publisher.Notify(t.Context(), Event{
		EventName: EventObjectCreatedPut,
		Bucket:    "bucket",
		Key:       "object",
	})
	if err == nil {
		t.Fatal("Notify() error = nil, want missing topic error")
	}
	if len(producer.records) != 0 {
		t.Fatalf("produced record count = %d, want 0", len(producer.records))
	}
}

func TestKafkaPublisherClose(t *testing.T) {
	producer := &fakeRecordProducer{}
	publisher := newKafkaPublisher(producer, true, "", time.Second)
	publisher.Close()
	if producer.closeCalls != 1 {
		t.Fatalf("producer close calls = %d, want 1", producer.closeCalls)
	}
}
