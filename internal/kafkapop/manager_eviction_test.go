package kafkapop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

func TestManagerEvictionCloseHonorsRequestCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "canceled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				closing := make(chan struct{})
				canceled := make(chan error, 1)
				finish := make(chan struct{})
				finished := make(chan struct{})
				finishClose := sync.OnceFunc(func() { close(finish) })
				defer finishClose()
				old := &fakeConsumerClient{beforeCloseContext: func(ctx context.Context) error {
					close(closing)
					<-ctx.Done()
					canceled <- ctx.Err()
					<-finish
					close(finished)
					return ctx.Err()
				}}
				replacement := &fakeConsumerClient{}
				created := 0
				manager := newManager(30*time.Second, time.Minute, 1, func(_, _ string) (consumerClient, error) {
					created++
					if created == 1 {
						return old, nil
					}
					return replacement, nil
				})
				defer manager.Close()
				if err := manager.Consume(t.Context(), "images", "old", func(*kgo.Record) error { return nil }); !errors.Is(err, ErrNoEvent) {
					t.Fatal(err)
				}
				var requestCtx context.Context
				var cancel context.CancelFunc
				wantErr := context.Canceled
				var wantElapsed time.Duration
				if deadline {
					requestCtx, cancel = context.WithTimeout(t.Context(), 100*time.Millisecond)
					wantErr = context.DeadlineExceeded
					wantElapsed = 100 * time.Millisecond
				} else {
					requestCtx, cancel = context.WithCancel(t.Context())
				}
				defer cancel()
				consumed := make(chan error, 1)
				started := time.Now()
				go func() {
					consumed <- manager.Consume(requestCtx, "images", "new", func(*kgo.Record) error { return nil })
				}()
				<-closing
				if !deadline {
					cancel()
				}
				if err := <-canceled; !errors.Is(err, wantErr) {
					t.Errorf("evicted close error = %v, want %v", err, wantErr)
				}
				if elapsed := time.Since(started); elapsed != wantElapsed {
					t.Errorf("canceled request waited %s, want %s", elapsed, wantElapsed)
				}
				synctest.Wait()
				select {
				case err := <-consumed:
					t.Fatalf("request returned before evicted client cleanup finished: %v", err)
				default:
				}
				finishClose()
				if err := <-consumed; !errors.Is(err, wantErr) {
					t.Fatalf("Consume error = %v, want %v", err, wantErr)
				}
				<-finished
				if len(replacement.sequence) != 0 {
					t.Fatalf("canceled request used replacement client: %v", replacement.sequence)
				}
				// One request's cancellation must leave the manager and replacement usable.
				if err := manager.Consume(t.Context(), "images", "new", func(*kgo.Record) error { return nil }); !errors.Is(err, ErrNoEvent) {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestManagerShutdownCancelsRequestEviction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		closing := make(chan struct{})
		finished := make(chan struct{})
		old := &fakeConsumerClient{beforeCloseContext: func(ctx context.Context) error {
			close(closing)
			<-ctx.Done()
			close(finished)
			return ctx.Err()
		}}
		created := 0
		manager := newManager(30*time.Second, time.Minute, 1, func(_, _ string) (consumerClient, error) {
			created++
			if created == 1 {
				return old, nil
			}
			return &fakeConsumerClient{}, nil
		})
		defer manager.Close()
		_ = manager.Consume(t.Context(), "images", "old", func(*kgo.Record) error { return nil })
		consumed := make(chan error, 1)
		go func() {
			consumed <- manager.Consume(t.Context(), "images", "new", func(*kgo.Record) error { return nil })
		}()
		<-closing
		closeCtx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		started := time.Now()
		if err := manager.CloseContext(closeCtx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("CloseContext error = %v", err)
		}
		if elapsed := time.Since(started); elapsed != 100*time.Millisecond {
			t.Fatalf("shutdown waited %s", elapsed)
		}
		select {
		case <-finished:
		default:
			t.Fatal("shutdown returned before evicted client cleanup finished")
		}
		if err := <-consumed; !errors.Is(err, ErrClosed) {
			t.Fatalf("Consume error = %v", err)
		}
	})
}
