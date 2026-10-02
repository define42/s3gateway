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

func TestManagerActiveDeliveryReplicaHandoffIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	broker, cleanup := testutil.StartRedpanda(ctx, t)
	defer cleanup()
	producer, err := kgo.NewClient(kgo.SeedBrokers(broker))
	if err != nil {
		t.Fatal(err)
	}
	defer producer.Close()
	const topic = "pop-active-handoff"
	const group = "pop-active-handoff"
	created, err := kadm.NewClient(producer).CreateTopics(ctx, 1, 1, nil, topic)
	if err != nil {
		t.Fatal(err)
	}
	if err := created[topic].Err; err != nil {
		t.Fatal(err)
	}
	record := &kgo.Record{Topic: topic, Value: []byte("slow object")}
	if err := producer.ProduceSync(ctx, record).FirstErr(); err != nil {
		t.Fatal(err)
	}
	newReplica := func() *kafkapop.Manager {
		t.Helper()
		manager, err := kafkapop.New(kafkapop.Options{Brokers: []string{broker}, Timeout: time.Second, IdleTimeout: time.Minute, MaxConsumers: 1})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(manager.Close)
		return manager
	}
	a, b := newReplica(), newReplica()
	started := make(chan struct{})
	doneA := make(chan error, 1)
	go func() {
		for {
			err := a.Consume(ctx, topic, group, func(deliveryCtx context.Context, got *kgo.Record) error {
				close(started)
				// This represents a download that keeps making progress and has
				// no absolute deadline. Only cancellation releases the handler.
				<-deliveryCtx.Done()
				return context.Cause(deliveryCtx)
			})
			if errors.Is(err, kafkapop.ErrNoEvent) && ctx.Err() == nil {
				continue
			}
			doneA <- err
			return
		}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("first replica did not start delivery")
	}
	gotB := make(chan *kgo.Record, 1)
	doneB := make(chan error, 1)
	go func() {
		for {
			err := b.Consume(ctx, topic, group, func(_ context.Context, got *kgo.Record) error {
				gotB <- got
				return nil
			})
			if (errors.Is(err, kafkapop.ErrNoEvent) || errors.Is(err, kafkapop.ErrRebalance)) && ctx.Err() == nil {
				continue
			}
			doneB <- err
			return
		}
	}()
	select {
	case err := <-doneA:
		if !errors.Is(err, kafkapop.ErrRebalance) {
			t.Fatalf("interrupted delivery returned %v", err)
		}
	case <-time.After(20 * time.Second):
		cancel()
		<-doneA
		<-doneB
		t.Fatal("active delivery was not interrupted before the broker's 60-second rebalance deadline")
	}
	// Let B own the single partition. The interrupted record must still be
	// available, and its exact offset must be committed only after B handles it.
	a.Close()
	select {
	case got := <-gotB:
		if got.Topic != record.Topic || got.Partition != record.Partition || got.Offset != record.Offset || string(got.Value) != string(record.Value) {
			t.Fatalf("handoff delivered %+v, want %+v", got, record)
		}
	case <-ctx.Done():
		t.Fatal("second replica did not receive the interrupted record")
	}
	if err := <-doneB; err != nil {
		t.Fatalf("second replica commit: %v", err)
	}
	if err := b.Consume(ctx, topic, group, func(context.Context, *kgo.Record) error {
		t.Error("committed event was redelivered")
		return nil
	}); !errors.Is(err, kafkapop.ErrNoEvent) {
		t.Fatalf("empty poll after handoff: %v", err)
	}
}
