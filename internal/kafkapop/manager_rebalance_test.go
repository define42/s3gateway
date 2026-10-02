package kafkapop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestManagerRebalanceCancelsDeliveryWithoutAcknowledging(t *testing.T) {
	for _, ignoreCancellation := range []bool{false, true} {
		name := "handler reports cancellation"
		if ignoreCancellation {
			name = "handler returns success after cancellation"
		}
		t.Run(name, func(t *testing.T) {
			record := &kgo.Record{Topic: "images", Partition: 1, Offset: 42}
			client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
				return fetchWithRecord(record)
			}}
			var rebalance func()
			manager := newManager(time.Second, time.Minute, 1, func(_, _ string, interrupt func()) (consumerClient, error) {
				rebalance = interrupt
				return client, nil
			})
			defer manager.Close()
			err := manager.Consume(t.Context(), "images", "scanner", func(ctx context.Context, _ *kgo.Record) error {
				rebalance()
				select {
				case <-ctx.Done():
				case <-time.After(time.Second):
					t.Fatal("rebalance did not cancel delivery")
				}
				if !errors.Is(context.Cause(ctx), ErrRebalance) {
					t.Fatalf("delivery cancellation cause = %v", context.Cause(ctx))
				}
				if ignoreCancellation {
					return nil
				}
				return ctx.Err()
			})
			if !errors.Is(err, ErrRebalance) {
				t.Fatalf("Consume error = %v, want ErrRebalance", err)
			}
			if len(client.committed) != 0 || len(client.setOffsets) != 1 || client.allowCount != 1 {
				t.Fatalf("interrupted delivery: commits=%d rewinds=%d rebalances=%d", len(client.committed), len(client.setOffsets), client.allowCount)
			}
			if offset := client.setOffsets[0]["images"][1].Offset; offset != record.Offset {
				t.Fatalf("rewound to %d, want %d", offset, record.Offset)
			}
			// A late notification with no active delivery cannot poison the next call.
			rebalance()
			if err := manager.Consume(t.Context(), "images", "scanner", func(ctx context.Context, got *kgo.Record) error {
				if ctx.Err() != nil || got != record {
					t.Fatalf("retry context=%v record=%v", ctx.Err(), got)
				}
				return nil
			}); err != nil {
				t.Fatalf("retry: %v", err)
			}
			if len(client.committed) != 1 {
				t.Fatalf("retry committed %d records", len(client.committed))
			}
		})
	}
}

func TestManagerRebalanceUnblocksEmptyPoll(t *testing.T) {
	var rebalance func()
	client := &fakeConsumerClient{poll: func(ctx context.Context) kgo.Fetches {
		rebalance()
		<-ctx.Done()
		return kgo.Fetches{{Topics: []kgo.FetchTopic{{Topic: "images", Partitions: []kgo.FetchPartition{{Err: ctx.Err()}}}}}}
	}}
	manager := newManager(time.Second, time.Minute, 1, func(_, _ string, interrupt func()) (consumerClient, error) {
		rebalance = interrupt
		return client, nil
	})
	defer manager.Close()
	if err := manager.Consume(t.Context(), "images", "scanner", func(context.Context, *kgo.Record) error {
		t.Fatal("empty poll invoked delivery")
		return nil
	}); !errors.Is(err, ErrNoEvent) {
		t.Fatalf("Consume error = %v, want ErrNoEvent", err)
	}
	if len(client.committed) != 0 || len(client.setOffsets) != 0 || client.allowCount != 1 {
		t.Fatalf("empty poll: commits=%d rewinds=%d rebalances=%d", len(client.committed), len(client.setOffsets), client.allowCount)
	}
}

func TestManagerRebalanceCancelsPendingCommit(t *testing.T) {
	var rebalance func()
	record := &kgo.Record{Topic: "images", Partition: 1, Offset: 42}
	client := &fakeConsumerClient{
		poll: func(context.Context) kgo.Fetches { return fetchWithRecord(record) },
		commit: func(ctx context.Context) error {
			rebalance()
			<-ctx.Done()
			return ctx.Err()
		},
	}
	manager := newManager(time.Second, time.Minute, 1, func(_, _ string, interrupt func()) (consumerClient, error) {
		rebalance = interrupt
		return client, nil
	})
	defer manager.Close()
	if err := manager.Consume(t.Context(), "images", "scanner", func(context.Context, *kgo.Record) error { return nil }); !errors.Is(err, ErrRebalance) {
		t.Fatalf("Consume error = %v, want ErrRebalance", err)
	}
	if len(client.setOffsets) != 1 || client.allowCount != 1 {
		t.Fatalf("interrupted commit: rewinds=%d rebalances=%d", len(client.setOffsets), client.allowCount)
	}
}
