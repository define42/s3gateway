package kafkapop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

type fakeConsumerClient struct {
	mu             sync.Mutex
	poll           func(context.Context) kgo.Fetches
	commitErr      error
	sequence       []string
	committed      []*kgo.Record
	setOffsets     []map[string]map[int32]kgo.EpochOffset
	allowCount     int
	closeCount     int
	commitCtxError error
}

func (c *fakeConsumerClient) PollRecords(ctx context.Context, _ int) kgo.Fetches {
	c.mu.Lock()
	c.sequence = append(c.sequence, "poll")
	poll := c.poll
	c.mu.Unlock()
	if poll != nil {
		return poll(ctx)
	}
	return nil
}

func (c *fakeConsumerClient) CommitRecords(ctx context.Context, records ...*kgo.Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence = append(c.sequence, "commit")
	c.commitCtxError = ctx.Err()
	c.committed = append(c.committed, records...)
	return c.commitErr
}

func (c *fakeConsumerClient) SetOffsets(offsets map[string]map[int32]kgo.EpochOffset) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence = append(c.sequence, "rewind")
	c.setOffsets = append(c.setOffsets, offsets)
}

func (c *fakeConsumerClient) AllowRebalance() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence = append(c.sequence, "allow rebalance")
	c.allowCount++
}

func (c *fakeConsumerClient) CloseAllowingRebalance() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sequence = append(c.sequence, "close")
	c.closeCount++
}

func fetchWithRecord(record *kgo.Record) kgo.Fetches {
	return kgo.Fetches{{
		Topics: []kgo.FetchTopic{{
			Topic: record.Topic,
			Partitions: []kgo.FetchPartition{{
				Partition: record.Partition,
				Records:   []*kgo.Record{record},
			}},
		}},
	}}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		options Options
	}{
		{
			name: "missing brokers",
			options: Options{
				Timeout:      time.Second,
				MaxConsumers: 1,
			},
		},
		{
			name: "empty broker",
			options: Options{
				Brokers:      []string{"kafka:9092", " "},
				Timeout:      time.Second,
				MaxConsumers: 1,
			},
		},
		{
			name: "invalid timeout",
			options: Options{
				Brokers:      []string{"kafka:9092"},
				MaxConsumers: 1,
			},
		},
		{
			name: "invalid consumer limit",
			options: Options{
				Brokers: []string{"kafka:9092"},
				Timeout: time.Second,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := New(tt.options)
			if err == nil {
				manager.Close()
				t.Fatal("New() error = nil, want validation error")
			}
		})
	}
}

func TestManagerConsumeCommitsAfterHandler(t *testing.T) {
	record := &kgo.Record{
		Topic:       "images",
		Partition:   2,
		Offset:      41,
		LeaderEpoch: 3,
		Value:       []byte("event"),
	}
	client := &fakeConsumerClient{
		poll: func(context.Context) kgo.Fetches {
			return fetchWithRecord(record)
		},
	}
	manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
		return client, nil
	})
	defer manager.Close()

	ctx, cancel := context.WithCancel(t.Context())
	err := manager.Consume(ctx, "images", "scanner", func(got *kgo.Record) error {
		client.mu.Lock()
		client.sequence = append(client.sequence, "handle")
		client.mu.Unlock()
		if got != record {
			t.Fatalf("record mismatch: got=%p want=%p", got, record)
		}
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("Consume() error = %v", err)
	}

	client.mu.Lock()
	defer client.mu.Unlock()
	wantSequence := []string{"poll", "handle", "commit", "allow rebalance"}
	if len(client.sequence) < len(wantSequence) {
		t.Fatalf("sequence too short: got=%v want prefix=%v", client.sequence, wantSequence)
	}
	for i, want := range wantSequence {
		if client.sequence[i] != want {
			t.Fatalf("sequence[%d] = %q, want %q (all=%v)", i, client.sequence[i], want, client.sequence)
		}
	}
	if len(client.committed) != 1 || client.committed[0] != record {
		t.Fatalf("committed records = %v, want record %p", client.committed, record)
	}
	if client.commitCtxError != nil {
		t.Fatalf("commit context inherited request cancellation: %v", client.commitCtxError)
	}
}

func TestManagerConsumeRewindsUnacknowledgedRecord(t *testing.T) {
	handlerErr := errors.New("client write failed")
	commitErr := errors.New("commit failed")
	tests := []struct {
		name       string
		handleErr  error
		commitErr  error
		wantCommit int
	}{
		{
			name:      "handler failure",
			handleErr: handlerErr,
		},
		{
			name:       "commit failure",
			commitErr:  commitErr,
			wantCommit: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &kgo.Record{
				Topic:       "images",
				Partition:   4,
				Offset:      99,
				LeaderEpoch: 7,
			}
			client := &fakeConsumerClient{
				commitErr: tt.commitErr,
				poll: func(context.Context) kgo.Fetches {
					return fetchWithRecord(record)
				},
			}
			manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
				return client, nil
			})
			defer manager.Close()

			err := manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
				return tt.handleErr
			})
			if err == nil {
				t.Fatal("Consume() error = nil, want failure")
			}

			client.mu.Lock()
			defer client.mu.Unlock()
			if len(client.committed) != tt.wantCommit {
				t.Fatalf("commit count = %d, want %d", len(client.committed), tt.wantCommit)
			}
			if len(client.setOffsets) != 1 {
				t.Fatalf("rewind count = %d, want 1", len(client.setOffsets))
			}
			got := client.setOffsets[0][record.Topic][record.Partition]
			want := (kgo.EpochOffset{Epoch: record.LeaderEpoch, Offset: record.Offset})
			if got != want {
				t.Fatalf("rewind offset = %+v, want %+v", got, want)
			}
			if client.allowCount != 1 {
				t.Fatalf("allow rebalance count = %d, want 1", client.allowCount)
			}
		})
	}
}

func TestManagerConsumeNoEvent(t *testing.T) {
	client := &fakeConsumerClient{
		poll: func(ctx context.Context) kgo.Fetches {
			<-ctx.Done()
			return kgo.NewErrFetch(ctx.Err())
		},
	}
	manager := newManager(time.Millisecond, 1, func(_, _ string) (consumerClient, error) {
		return client, nil
	})
	defer manager.Close()

	err := manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
		t.Fatal("handler must not run without an event")
		return nil
	})
	if !errors.Is(err, ErrNoEvent) {
		t.Fatalf("Consume() error = %v, want ErrNoEvent", err)
	}
}

func TestManagerEvictsIdleConsumer(t *testing.T) {
	clients := make(map[string]*fakeConsumerClient)
	manager := newManager(time.Second, 1, func(topic, _ string) (consumerClient, error) {
		record := &kgo.Record{Topic: topic}
		client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
			return fetchWithRecord(record)
		}}
		clients[topic] = client
		return client, nil
	})
	defer manager.Close()

	for _, topic := range []string{"images", "documents"} {
		if err := manager.Consume(t.Context(), topic, "scanner", func(*kgo.Record) error {
			return nil
		}); err != nil {
			t.Fatalf("Consume(%q) error = %v", topic, err)
		}
	}

	clients["images"].mu.Lock()
	closeCount := clients["images"].closeCount
	clients["images"].mu.Unlock()
	if closeCount != 1 {
		t.Fatalf("evicted client close count = %d, want 1", closeCount)
	}
}

func TestManagerRejectsNewConsumerAtActiveLimit(t *testing.T) {
	handling := make(chan struct{})
	release := make(chan struct{})
	client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
		return fetchWithRecord(&kgo.Record{Topic: "images"})
	}}
	manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
		return client, nil
	})
	defer manager.Close()

	done := make(chan error, 1)
	go func() {
		done <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
			close(handling)
			<-release
			return nil
		})
	}()
	<-handling

	err := manager.Consume(t.Context(), "documents", "scanner", func(*kgo.Record) error {
		return nil
	})
	if !errors.Is(err, ErrConsumerLimit) {
		t.Fatalf("second Consume() error = %v, want ErrConsumerLimit", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}
}

func TestManagerClose(t *testing.T) {
	client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
		return fetchWithRecord(&kgo.Record{Topic: "images"})
	}}
	manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
		return client, nil
	})
	if err := manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
		return nil
	}); err != nil {
		t.Fatalf("Consume() error = %v", err)
	}

	manager.Close()
	manager.Close()
	client.mu.Lock()
	closeCount := client.closeCount
	client.mu.Unlock()
	if closeCount != 1 {
		t.Fatalf("client close count = %d, want 1", closeCount)
	}
	if err := manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
		return nil
	}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Consume() after Close error = %v, want ErrClosed", err)
	}
}
