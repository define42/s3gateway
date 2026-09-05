//go:build integration

package kafkapop_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/kafkapop"
	"github.com/define42/s3gateway/internal/testutil"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
)

func TestManagerIdleReplicaHandoffIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	broker, stopRedpanda := testutil.StartRedpanda(ctx, t)
	t.Cleanup(stopRedpanda)
	producer, err := kgo.NewClient(kgo.SeedBrokers(broker))
	if err != nil {
		t.Fatalf("create Kafka producer: %v", err)
	}
	t.Cleanup(producer.Close)

	const topic = "pop-replica-handoff"
	const group = "pop-replica-handoff-group"
	created, err := kadm.NewClient(producer).CreateTopics(ctx, 1, 1, nil, topic)
	if err != nil {
		t.Fatalf("create single-partition topic: %v", err)
	}
	if err := created[topic].Err; err != nil {
		t.Fatalf("create topic %q: %v", topic, err)
	}

	newReplica := func() *kafkapop.Manager {
		t.Helper()
		manager, newErr := kafkapop.New(kafkapop.Options{
			Brokers:      []string{broker},
			Timeout:      time.Second,
			IdleTimeout:  2 * time.Second,
			MaxConsumers: 1,
		})
		if newErr != nil {
			t.Fatalf("create replica pop manager: %v", newErr)
		}
		t.Cleanup(manager.Close)
		return manager
	}
	replicaA := newReplica()
	replicaB := newReplica()

	produce := func(value string) *kgo.Record {
		t.Helper()
		record := &kgo.Record{Topic: topic, Value: []byte(value)}
		if err := producer.ProduceSync(ctx, record).FirstErr(); err != nil {
			t.Fatalf("produce %q: %v", value, err)
		}
		return record
	}
	consume := func(replica *kafkapop.Manager, want *kgo.Record, handlerErr error) {
		t.Helper()
		pollCtx, cancelPoll := context.WithTimeout(ctx, 20*time.Second)
		defer cancelPoll()
		started := time.Now()
		var got *kgo.Record
		for {
			consumeErr := replica.Consume(pollCtx, topic, group, func(record *kgo.Record) error {
				got = record
				return handlerErr
			})
			if errors.Is(consumeErr, kafkapop.ErrNoEvent) {
				continue
			}
			if !errors.Is(consumeErr, handlerErr) {
				t.Fatalf("consume %q after %s: %v, want %v", want.Value, time.Since(started), consumeErr, handlerErr)
			}
			break
		}
		if got == nil {
			t.Fatalf("consume %q returned without delivering a record", want.Value)
		}
		if got.Topic != want.Topic || got.Partition != want.Partition || got.Offset != want.Offset ||
			string(got.Value) != string(want.Value) {
			t.Fatalf("received %s/%d offset %d value %q, want %s/%d offset %d value %q",
				got.Topic, got.Partition, got.Offset, got.Value,
				want.Topic, want.Partition, want.Offset, want.Value)
		}
	}

	// A owns the topic's only partition and commits the first event. B joins
	// the same group while there is nothing left to consume.
	consume(replicaA, produce("committed-on-a"), nil)
	if err := replicaB.Consume(ctx, topic, group, func(record *kgo.Record) error {
		t.Errorf("B redelivered the committed event at offset %d", record.Offset)
		return nil
	}); !errors.Is(err, kafkapop.ErrNoEvent) {
		t.Fatalf("initial empty poll on B = %v, want ErrNoEvent", err)
	}

	// Traffic now goes only to B. A remains open and is never polled or closed
	// to trigger the handoff, so this fails if A keeps its idle membership.
	consume(replicaB, produce("handoff-to-b"), nil)

	// A failed delivery must remain uncommitted when traffic moves back to A.
	// Checking the exact offset also detects replay of either committed event.
	failedRecord := produce("retry-after-handoff")
	handlerErr := errors.New("response delivery failed")
	consume(replicaB, failedRecord, handlerErr)
	consume(replicaA, failedRecord, nil)
	if err := replicaA.Consume(ctx, topic, group, func(record *kgo.Record) error {
		t.Errorf("A redelivered committed offset %d", record.Offset)
		return nil
	}); !errors.Is(err, kafkapop.ErrNoEvent) {
		t.Fatalf("empty poll after final commit = %v, want ErrNoEvent", err)
	}
}
