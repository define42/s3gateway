package kafkapop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestManagerShutdownClosesConsumersConcurrently(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const count = 4
		started := make(chan struct{}, count)
		release := make(chan struct{})
		manager := newManager(time.Minute, time.Hour, count, func(_, _ string) (consumerClient, error) {
			return &fakeConsumerClient{beforeCloseContext: func(ctx context.Context) error {
				started <- struct{}{}
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			}}, nil
		})
		for i := range count {
			_ = manager.Consume(t.Context(), "images", fmt.Sprint(i), func(*kgo.Record) error { return nil })
		}
		done := make(chan error, 1)
		go func() { done <- manager.CloseContext(t.Context()) }()
		synctest.Wait()
		if len(started) != count {
			t.Fatalf("started %d closes, want all %d concurrently", len(started), count)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestManagerShutdownCancelsActiveAndDetachedConsumers(t *testing.T) {
	for _, detached := range []bool{false, true} {
		t.Run(fmt.Sprintf("detached=%t", detached), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				started := make(chan struct{})
				finished := make(chan struct{})
				client := &fakeConsumerClient{beforeCloseContext: func(ctx context.Context) error {
					close(started)
					<-ctx.Done()
					close(finished)
					return ctx.Err()
				}}
				manager := newManager(time.Minute, time.Second, 1, func(_, _ string) (consumerClient, error) { return client, nil })
				_ = manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { return nil })
				if detached {
					time.Sleep(time.Second)
					<-started
				}
				ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
				defer cancel()
				start := time.Now()
				err := manager.CloseContext(ctx)
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("close error = %v", err)
				}
				if elapsed := time.Since(start); elapsed != 100*time.Millisecond {
					t.Fatalf("close took %s", elapsed)
				}
				select {
				case <-finished:
				default:
					t.Fatal("CloseContext returned before client cleanup finished")
				}
			})
		})
	}
}

func TestManagerShutdownCancellationInterruptsPoll(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		polling := make(chan struct{})
		pollDone := make(chan struct{})
		client := &fakeConsumerClient{poll: func(ctx context.Context) kgo.Fetches {
			close(polling)
			<-ctx.Done()
			close(pollDone)
			return nil
		}}
		manager := newManager(time.Minute, time.Hour, 1, func(_, _ string) (consumerClient, error) { return client, nil })
		consumeDone := make(chan error, 1)
		go func() {
			consumeDone <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { return nil })
		}()
		<-polling
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := manager.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("close error = %v", err)
		}
		<-pollDone
		<-consumeDone
		requireConsumerCloses(t, client, 1)
	})
}

func TestManagerConcurrentCloseCancellationInterruptsExistingClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := make(chan struct{})
		client := &fakeConsumerClient{beforeCloseContext: func(ctx context.Context) error { close(started); <-ctx.Done(); return ctx.Err() }}
		manager := newManager(time.Minute, time.Hour, 1, func(_, _ string) (consumerClient, error) { return client, nil })
		_ = manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { return nil })
		var callers sync.WaitGroup
		callers.Go(func() { _ = manager.CloseContext(t.Context()) })
		<-started
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := manager.CloseContext(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("close error = %v", err)
		}
		callers.Wait()
	})
}

func TestManagerShutdownBoundsWorkersAndClosesQueuedConsumers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const count = 20
		var started, finished atomic.Int32
		manager := newManager(time.Minute, time.Hour, count, func(_, _ string) (consumerClient, error) {
			return &fakeConsumerClient{beforeCloseContext: func(ctx context.Context) error {
				started.Add(1)
				<-ctx.Done()
				finished.Add(1)
				return ctx.Err()
			}}, nil
		})
		for i := range count {
			_ = manager.Consume(t.Context(), "images", fmt.Sprint(i), func(*kgo.Record) error { return nil })
		}
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- manager.CloseContext(ctx) }()
		synctest.Wait()
		if got := started.Load(); got == 0 || got >= count {
			t.Fatalf("started %d closes; want a bounded concurrent subset", got)
		}
		if err := <-done; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("close error = %v", err)
		}
		if got := finished.Load(); got != count {
			t.Fatalf("finished %d closes, want %d", got, count)
		}
	})
}

func TestManagerShutdownDeadlineDoesNotWaitForCallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		handling := make(chan struct{})
		release := make(chan struct{})
		client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches { return fetchWithRecord(&kgo.Record{Topic: "images"}) }}
		manager := newManager(time.Minute, time.Hour, 1, func(_, _ string) (consumerClient, error) { return client, nil })
		consumed := make(chan error, 1)
		go func() {
			consumed <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { close(handling); <-release; return nil })
		}()
		<-handling
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if err := manager.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("close error = %v", err)
		}
		requireConsumerCloses(t, client, 1)
		close(release)
		if err := <-consumed; !errors.Is(err, ErrClosed) {
			t.Fatalf("consume error = %v", err)
		}
		client.mu.Lock()
		defer client.mu.Unlock()
		if len(client.committed) != 0 {
			t.Fatal("callback committed after forced shutdown")
		}
	})
}
