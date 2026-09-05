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

func requireConsumerCloses(t *testing.T, client *fakeConsumerClient, want int) {
	t.Helper()
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.closeCount != want {
		t.Fatalf("client close count = %d, want %d; sequence=%v", client.closeCount, want, client.sequence)
	}
}

func TestManagerExpiresConsumerWithoutFurtherRequests(t *testing.T) {
	for _, outcome := range []string{"success", "no event", "handler failure", "commit failure"} {
		t.Run(outcome, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const idle = 5 * time.Second
				var clients []*fakeConsumerClient
				manager := newManager(time.Second, idle, 2, func(topic, _ string) (consumerClient, error) {
					client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
						if outcome == "no event" {
							return nil
						}
						return fetchWithRecord(&kgo.Record{Topic: topic})
					}}
					if outcome == "commit failure" {
						client.commitErr = errors.New("commit failed")
					}
					clients = append(clients, client)
					return client, nil
				})
				defer manager.Close()
				consume := func() {
					t.Helper()
					err := manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
						if outcome == "handler failure" {
							return errors.New("delivery failed")
						}
						return nil
					})
					if (err == nil) != (outcome == "success") {
						t.Fatalf("Consume() error = %v for %s", err, outcome)
					}
				}
				consume()
				time.Sleep(idle - time.Nanosecond)
				synctest.Wait()
				requireConsumerCloses(t, clients[0], 0)
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				requireConsumerCloses(t, clients[0], 1)
				consume()
				if len(clients) != 2 {
					t.Fatalf("created %d clients, want replacement after idle expiry", len(clients))
				}
				requireConsumerCloses(t, clients[1], 0)
			})
		})
	}
}

func TestManagerActivityRestartsIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = 5 * time.Second
		client := &fakeConsumerClient{}
		created := 0
		manager := newManager(time.Second, idle, 1, func(_, _ string) (consumerClient, error) {
			created++
			return client, nil
		})
		defer manager.Close()
		for range 3 {
			if err := manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { return nil }); !errors.Is(err, ErrNoEvent) {
				t.Fatalf("Consume() error = %v, want ErrNoEvent", err)
			}
			time.Sleep(idle - time.Second)
			synctest.Wait()
			requireConsumerCloses(t, client, 0)
		}
		if created != 1 {
			t.Fatalf("created %d clients during continuous activity, want 1", created)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		requireConsumerCloses(t, client, 1)
		manager.Close()
		time.Sleep(2 * idle)
		synctest.Wait()
		requireConsumerCloses(t, client, 1)
	})
}

func TestManagerIdleTimeoutPreservesInProgressWork(t *testing.T) {
	for _, phase := range []string{"poll", "handler", "commit"} {
		t.Run(phase, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const idle = 5 * time.Second
				started := make(chan struct{})
				release := make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				pause := func(at string) {
					if phase == at {
						close(started)
						<-release
					}
				}
				client := &fakeConsumerClient{
					poll: func(context.Context) kgo.Fetches {
						pause("poll")
						return fetchWithRecord(&kgo.Record{Topic: "images"})
					},
					beforeCommit: func() { pause("commit") },
				}
				manager := newManager(4*idle, idle, 1, func(_, _ string) (consumerClient, error) { return client, nil })
				defer manager.Close()
				defer unblock()
				done := make(chan error, 1)
				go func() {
					done <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error {
						pause("handler")
						return nil
					})
				}()
				<-started
				time.Sleep(2 * idle)
				synctest.Wait()
				requireConsumerCloses(t, client, 0)
				unblock()
				if err := <-done; err != nil {
					t.Fatalf("Consume() error = %v", err)
				}
				time.Sleep(idle - time.Nanosecond)
				synctest.Wait()
				requireConsumerCloses(t, client, 0)
				time.Sleep(time.Nanosecond)
				synctest.Wait()
				requireConsumerCloses(t, client, 1)
				client.mu.Lock()
				defer client.mu.Unlock()
				if len(client.committed) != 1 {
					t.Fatalf("committed %d records, want 1 before idle expiry", len(client.committed))
				}
			})
		})
	}
}

func TestManagerIdleTimeoutWaitsForAllQueuedCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = 5 * time.Second
		client := &fakeConsumerClient{poll: func(context.Context) kgo.Fetches {
			return fetchWithRecord(&kgo.Record{Topic: "images"})
		}}
		manager := newManager(time.Second, idle, 1, func(_, _ string) (consumerClient, error) { return client, nil })
		defer manager.Close()
		forFirst := make(chan struct{})
		forSecond := make(chan struct{})
		releaseFirst := sync.OnceFunc(func() { close(forFirst) })
		releaseSecond := sync.OnceFunc(func() { close(forSecond) })
		defer releaseFirst()
		defer releaseSecond()
		firstDone := make(chan error, 1)
		secondDone := make(chan error, 1)
		go func() {
			firstDone <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { <-forFirst; return nil })
		}()
		synctest.Wait()
		go func() {
			secondDone <- manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { <-forSecond; return nil })
		}()
		synctest.Wait()
		time.Sleep(2 * idle)
		synctest.Wait()
		requireConsumerCloses(t, client, 0)
		releaseFirst()
		if err := <-firstDone; err != nil {
			t.Fatalf("first Consume() error = %v", err)
		}
		synctest.Wait()
		time.Sleep(2 * idle)
		synctest.Wait()
		requireConsumerCloses(t, client, 0)
		releaseSecond()
		if err := <-secondDone; err != nil {
			t.Fatalf("second Consume() error = %v", err)
		}
		time.Sleep(idle)
		synctest.Wait()
		requireConsumerCloses(t, client, 1)
	})
}

func TestManagerCloseWaitsForDetachedIdleConsumer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = 5 * time.Second
		closing := make(chan struct{})
		releaseClose := make(chan struct{})
		unblock := sync.OnceFunc(func() { close(releaseClose) })
		old := &fakeConsumerClient{beforeClose: func() { close(closing); <-releaseClose }}
		replacement := &fakeConsumerClient{}
		created := 0
		manager := newManager(time.Second, idle, 1, func(_, _ string) (consumerClient, error) {
			created++
			if created == 1 {
				return old, nil
			}
			return replacement, nil
		})
		defer manager.Close()
		defer unblock()
		consume := func() {
			t.Helper()
			if err := manager.Consume(t.Context(), "images", "scanner", func(*kgo.Record) error { return nil }); !errors.Is(err, ErrNoEvent) {
				t.Fatalf("Consume() error = %v, want ErrNoEvent", err)
			}
		}
		consume()
		time.Sleep(idle)
		<-closing
		// A slow Kafka leave must not hold the manager mutex or prevent reuse.
		consume()
		if created != 2 {
			t.Fatalf("created %d clients, want replacement while old client closes", created)
		}
		done := make(chan struct{}, 2)
		for range 2 {
			go func() { manager.Close(); done <- struct{}{} }()
		}
		synctest.Wait()
		select {
		case <-done:
			t.Fatal("Close returned while idle eviction was still closing a client")
		default:
		}
		unblock()
		<-done
		<-done
		time.Sleep(2 * idle)
		synctest.Wait()
		requireConsumerCloses(t, old, 1)
		requireConsumerCloses(t, replacement, 1)
	})
}
