package kafkapop

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
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
	onSetOffsets   func(map[string]map[int32]kgo.EpochOffset)
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
	if c.onSetOffsets != nil {
		c.onSetOffsets(offsets)
	}
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
	if !slices.Equal(client.sequence, wantSequence) {
		t.Fatalf("sequence = %v, want %v", client.sequence, wantSequence)
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
			wantSequence := []string{"poll"}
			if tt.wantCommit != 0 {
				wantSequence = append(wantSequence, "commit")
			}
			wantSequence = append(wantSequence, "rewind", "allow rebalance")
			if !slices.Equal(client.sequence, wantSequence) {
				t.Fatalf("sequence = %v, want %v", client.sequence, wantSequence)
			}
		})
	}
}

func TestManagerConsumeRewindsRecordReturnedWithPollError(t *testing.T) {
	pollErr := errors.New("partition fetch failed")
	tests := []struct {
		name          string
		pollErr       error
		wantErr       error
		cancelRequest bool
	}{
		{name: "partition error", pollErr: pollErr, wantErr: pollErr},
		{name: "poll timeout", pollErr: context.DeadlineExceeded, wantErr: ErrNoEvent},
		{name: "request canceled", pollErr: context.Canceled, wantErr: context.Canceled, cancelRequest: true},
	}
	for _, tt := range tests {
		for _, order := range []string{"error first", "record first"} {
			t.Run(tt.name+"/"+order, func(t *testing.T) {
				records := []*kgo.Record{
					{Topic: "images", Partition: 4, LeaderEpoch: 7, Offset: 41},
					{Topic: "images", Partition: 4, LeaderEpoch: 7, Offset: 42},
				}
				nextOffset := records[0].Offset
				firstPoll := true
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				client := &fakeConsumerClient{
					poll: func(context.Context) kgo.Fetches {
						index := nextOffset - records[0].Offset
						if index < 0 || index >= int64(len(records)) {
							return nil
						}
						fetches := fetchWithRecord(records[index])
						nextOffset++ // Polling advances the cursor even when another partition fails.
						if firstPoll {
							firstPoll = false
							if tt.cancelRequest {
								cancel()
							}
							errorFetches := kgo.Fetches{{Topics: []kgo.FetchTopic{{
								Topic: "images",
								Partitions: []kgo.FetchPartition{{
									Partition: 5,
									Err:       tt.pollErr,
								}},
							}}}}
							if order == "error first" {
								return append(errorFetches, fetches...)
							}
							return append(fetches, errorFetches...)
						}
						return fetches
					},
					onSetOffsets: func(offsets map[string]map[int32]kgo.EpochOffset) {
						offset, ok := offsets["images"][4]
						want := kgo.EpochOffset{Epoch: 7, Offset: 41}
						if !ok || offset != want {
							t.Errorf("rewind offset = %+v, want %+v", offsets, want)
							return
						}
						nextOffset = offset.Offset
					},
				}
				manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
					return client, nil
				})
				defer manager.Close()

				err := manager.Consume(ctx, "images", "scanner", func(*kgo.Record) error {
					t.Error("handler must not run when polling fails")
					return nil
				})
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Consume() error = %v, want %v", err, tt.wantErr)
				}
				if len(client.committed) != 0 {
					t.Errorf("committed records after poll error = %v, want none", client.committed)
				}
				wantSequence := []string{"poll", "rewind", "allow rebalance"}
				if !slices.Equal(client.sequence, wantSequence) {
					t.Errorf("sequence = %v, want %v", client.sequence, wantSequence)
				}

				var delivered []*kgo.Record
				for range records {
					if err := manager.Consume(t.Context(), "images", "scanner", func(record *kgo.Record) error {
						delivered = append(delivered, record)
						return nil
					}); err != nil {
						t.Errorf("Consume() retry error = %v", err)
					}
				}
				if !slices.Equal(delivered, records) {
					t.Errorf("delivered records = %v, want %v", delivered, records)
				}
				if !slices.Equal(client.committed, records) {
					t.Errorf("committed records = %v, want %v", client.committed, records)
				}
			})
		}
	}
}

func TestManagerConsumeReleasesRebalanceAfterPoll(t *testing.T) {
	pollErr := errors.New("broker unavailable")
	tests := []struct {
		name    string
		poll    func(context.Context, context.CancelFunc) kgo.Fetches
		wantErr error
	}{
		{
			name: "poll timeout",
			poll: func(ctx context.Context, _ context.CancelFunc) kgo.Fetches {
				<-ctx.Done()
				return kgo.NewErrFetch(ctx.Err())
			},
			wantErr: ErrNoEvent,
		},
		{
			name: "empty fetch",
			poll: func(context.Context, context.CancelFunc) kgo.Fetches {
				return nil
			},
			wantErr: ErrNoEvent,
		},
		{
			name: "poll error",
			poll: func(context.Context, context.CancelFunc) kgo.Fetches {
				return kgo.NewErrFetch(pollErr)
			},
			wantErr: pollErr,
		},
		{
			name: "request canceled during poll",
			poll: func(ctx context.Context, cancel context.CancelFunc) kgo.Fetches {
				cancel()
				return kgo.NewErrFetch(ctx.Err())
			},
			wantErr: context.Canceled,
		},
		{
			name: "request canceled with empty fetch",
			poll: func(_ context.Context, cancel context.CancelFunc) kgo.Fetches {
				cancel()
				return nil
			},
			wantErr: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				client := &fakeConsumerClient{
					poll: func(pollCtx context.Context) kgo.Fetches {
						return tt.poll(pollCtx, cancel)
					},
				}
				manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
					return client, nil
				})
				defer manager.Close()

				err := manager.Consume(ctx, "images", "scanner", func(*kgo.Record) error {
					t.Fatal("handler must not run without an event")
					return nil
				})
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Consume() error = %v, want %v", err, tt.wantErr)
				}
				client.mu.Lock()
				defer client.mu.Unlock()
				wantSequence := []string{"poll", "allow rebalance"}
				if !slices.Equal(client.sequence, wantSequence) {
					t.Fatalf("sequence = %v, want %v", client.sequence, wantSequence)
				}
			})
		})
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
	releaseHandler := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseHandler)
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
	releaseHandler()
	if err := <-done; err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}
}

func TestManagerCloseWaitsForInProgressConsume(t *testing.T) {
	handling := make(chan struct{})
	release := make(chan struct{})
	releaseHandler := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseHandler)
	client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
		return fetchWithRecord(&kgo.Record{Topic: "images"})
	}}
	manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
		return client, nil
	})

	consumeDone := make(chan error, 1)
	go func() {
		consumeDone <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
			close(handling)
			<-release
			return nil
		})
	}()
	<-handling

	closeDone := make(chan struct{})
	go func() {
		manager.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("Close() returned while the consume callback was active")
	case <-time.After(20 * time.Millisecond):
	}

	releaseHandler()
	if err := <-consumeDone; err != nil {
		t.Fatalf("Consume() error = %v", err)
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close() did not finish after the consume callback returned")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closeCount != 1 {
		t.Fatalf("client close count = %d, want 1", client.closeCount)
	}
}

func TestManagerSerializesConsumersWithSameKey(t *testing.T) {
	firstHandling := make(chan struct{})
	releaseFirst := make(chan struct{})
	releaseHandler := sync.OnceFunc(func() { close(releaseFirst) })
	t.Cleanup(releaseHandler)
	client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
		return fetchWithRecord(&kgo.Record{Topic: "images"})
	}}
	manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
		return client, nil
	})
	defer manager.Close()

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
			close(firstHandling)
			<-releaseFirst
			return nil
		})
	}()
	<-firstHandling

	secondHandling := make(chan struct{})
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
			close(secondHandling)
			return nil
		})
	}()
	select {
	case <-secondHandling:
		t.Fatal("second callback ran before the first callback returned")
	case <-time.After(20 * time.Millisecond):
	}

	releaseHandler()
	if err := <-firstDone; err != nil {
		t.Fatalf("first Consume() error = %v", err)
	}
	select {
	case <-secondHandling:
	case <-time.After(time.Second):
		t.Fatal("second callback did not run after the first callback returned")
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second Consume() error = %v", err)
	}
}

func TestManagerQueuedConsumeDoesNotBlockOtherGroups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		manager := newManager(time.Second, 2, func(topic, _ string) (consumerClient, error) {
			return &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
				return fetchWithRecord(&kgo.Record{Topic: topic})
			}}, nil
		})
		defer manager.Close()
		release := make(chan struct{})
		releaseHandler := sync.OnceFunc(func() { close(release) })
		defer releaseHandler()
		firstDone := make(chan error, 1)
		go func() {
			firstDone <- manager.Consume(t.Context(), "images", "slow", func(*kgo.Record) error {
				<-release
				return nil
			})
		}()
		synctest.Wait()

		queuedDone := make(chan error, 1)
		go func() {
			queuedDone <- manager.Consume(t.Context(), "images", "slow", func(*kgo.Record) error {
				return nil
			})
		}()
		synctest.Wait()

		if err := manager.Consume(t.Context(), "images", "independent", func(*kgo.Record) error {
			return nil
		}); err != nil {
			t.Fatalf("unrelated group Consume() error = %v", err)
		}
		select {
		case err := <-queuedDone:
			t.Fatalf("queued Consume() returned before the first handler finished: %v", err)
		default:
		}
		releaseHandler()
		if err := <-firstDone; err != nil {
			t.Fatalf("first Consume() error = %v", err)
		}
		if err := <-queuedDone; err != nil {
			t.Fatalf("queued Consume() error = %v", err)
		}
	})
}

func TestManagerQueuedConsumeCancellationReleasesCapacity(t *testing.T) {
	for _, tt := range []struct {
		name string
		want error
	}{
		{name: "canceled", want: context.Canceled},
		{name: "deadline", want: context.DeadlineExceeded},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				manager := newManager(time.Second, 1, func(topic, _ string) (consumerClient, error) {
					return &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
						return fetchWithRecord(&kgo.Record{Topic: topic})
					}}, nil
				})
				defer manager.Close()
				release := make(chan struct{})
				releaseHandler := sync.OnceFunc(func() { close(release) })
				defer releaseHandler()
				firstDone := make(chan error, 1)
				go func() {
					firstDone <- manager.Consume(t.Context(), "images", "slow", func(*kgo.Record) error {
						<-release
						return nil
					})
				}()
				synctest.Wait()

				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				defer cancel()
				queuedDone := make(chan error, 1)
				go func() {
					queuedDone <- manager.Consume(ctx, "images", "slow", func(*kgo.Record) error {
						return errors.New("canceled handler must not run")
					})
				}()
				synctest.Wait()
				if tt.want == context.Canceled {
					cancel()
				} else {
					time.Sleep(time.Second)
				}
				if err := <-queuedDone; !errors.Is(err, tt.want) {
					t.Fatalf("queued Consume() error = %v, want %v", err, tt.want)
				}

				releaseHandler()
				if err := <-firstDone; err != nil {
					t.Fatalf("first Consume() error = %v", err)
				}
				// The canceled waiter must not keep the sole cache entry pinned.
				if err := manager.Consume(t.Context(), "documents", "other", func(*kgo.Record) error {
					return nil
				}); err != nil {
					t.Fatalf("Consume() after cancellation and eviction = %v", err)
				}
			})
		})
	}
}

func TestManagerCloseRejectsQueuedConsume(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
			return fetchWithRecord(&kgo.Record{Topic: "images"})
		}}
		manager := newManager(time.Second, 1, func(_, _ string) (consumerClient, error) {
			return client, nil
		})
		defer manager.Close()
		release := make(chan struct{})
		releaseHandler := sync.OnceFunc(func() { close(release) })
		defer releaseHandler()
		firstDone := make(chan error, 1)
		go func() {
			firstDone <- manager.Consume(t.Context(), "images", "slow", func(*kgo.Record) error {
				<-release
				return nil
			})
		}()
		synctest.Wait()

		queuedDone := make(chan error, 1)
		go func() {
			queuedDone <- manager.Consume(t.Context(), "images", "slow", func(*kgo.Record) error {
				return errors.New("queued handler must not run after Close")
			})
		}()
		synctest.Wait()
		closeDone := make(chan struct{})
		go func() {
			manager.Close()
			close(closeDone)
		}()
		if err := <-queuedDone; !errors.Is(err, ErrClosed) {
			t.Fatalf("queued Consume() error = %v, want ErrClosed", err)
		}
		select {
		case <-closeDone:
			t.Fatal("Close() returned before the active callback finished")
		default:
		}
		releaseHandler()
		if err := <-firstDone; err != nil {
			t.Fatalf("first Consume() error = %v", err)
		}
		<-closeDone
		client.mu.Lock()
		defer client.mu.Unlock()
		if client.closeCount != 1 || len(client.committed) != 1 {
			t.Fatalf("close count = %d, committed = %d; want one each", client.closeCount, len(client.committed))
		}
	})
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
