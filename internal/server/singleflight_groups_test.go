package server

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/s3gateway/internal/authn"
	"github.com/define42/s3gateway/internal/config"
)

func TestGroupsForCredentialsSingleflightDeduplicatesConcurrentMisses(t *testing.T) {
	s := New(config.Config{
		GroupTTL:             time.Minute,
		GroupCacheMaxEntries: 64,
	}, nil)

	var calls atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	s.fetchGroups = func(cfg config.Config, upn, pass string) (map[string]struct{}, error) {
		if calls.Add(1) == 1 {
			started <- struct{}{}
		}
		<-release
		return map[string]struct{}{"team2-r": {}}, nil
	}

	const workers = 32
	start := make(chan struct{})
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			<-start
			groups, err := s.GroupsForCredentials("singleflight-user", "singleflight-pass")
			if err != nil {
				errs <- err
				return
			}
			if _, ok := groups["team2-r"]; !ok {
				errs <- errors.New("missing expected group")
				return
			}
		}()
	}
	close(start)

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for first backend group lookup")
	}
	close(release)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for concurrent auth calls to finish")
	}
	close(errs)
	for err := range errs {
		t.Fatalf("groupsForCredentials failed: %v", err)
	}

	if got := calls.Load(); got != 1 {
		t.Fatalf("singleflight should deduplicate concurrent misses: got backend calls=%d want=1", got)
	}

	// Verify warm-cache path after singleflight returns still avoids backend fetches.
	if _, err := s.GroupsForCredentials("singleflight-user", "singleflight-pass"); err != nil {
		t.Fatalf("cache hit after singleflight failed: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cache hit should not trigger backend fetch: got backend calls=%d want=1", got)
	}
}

func TestGroupsForCredentialsContextAlreadyCanceled(t *testing.T) {
	for _, state := range []string{"miss", "cached", "rejected"} {
		t.Run(state, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := New(config.Config{AuthIngressPerIPBurst: 1}, nil)
				switch state {
				case "cached":
					s.gcache.Set("user", "pass", map[string]struct{}{"team-r": {}})
				case "rejected":
					s.gcache.Reject("user", "pass")
				}
				var calls atomic.Int32
				s.fetchGroups = func(config.Config, string, string) (map[string]struct{}, error) {
					calls.Add(1)
					return map[string]struct{}{"team-r": {}}, nil
				}
				const clientIP = "192.0.2.1"
				if !s.authLimiter.AllowIngress(clientIP) {
					t.Fatal("initial ingress admission failed")
				}
				ctx, cancel := context.WithCancel(context.WithValue(t.Context(), authClientIPContextKey{}, clientIP))
				cancel()
				groups, err := s.GroupsForCredentialsContext(ctx, "user", "pass")
				if !errors.Is(err, context.Canceled) || groups != nil {
					t.Fatalf("canceled lookup = %v, %v; want no groups and context.Canceled", groups, err)
				}
				if calls.Load() != 0 {
					t.Fatal("already canceled request reached LDAP")
				}
				if s.authLimiter.AllowIngress(clientIP) {
					t.Fatal("canceled authentication refunded ingress admission")
				}
			})
		})
	}
}

func TestGroupsForCredentialsContextCancellationPreservesSharedLookup(t *testing.T) {
	for _, canceled := range []string{"leader", "follower", "both"} {
		t.Run(canceled, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := New(config.Config{AuthMaxConcurrent: 1}, nil)
				release := make(chan struct{})
				defer func() {
					select {
					case <-release:
					default:
						close(release)
					}
				}()
				calls := 0
				s.fetchGroups = func(config.Config, string, string) (map[string]struct{}, error) {
					calls++
					<-release
					return map[string]struct{}{"team-r": {}}, nil
				}
				type result struct {
					groups map[string]struct{}
					err    error
				}
				start := func() (context.CancelFunc, <-chan result) {
					ctx, cancel := context.WithCancel(t.Context())
					done := make(chan result, 1)
					go func() {
						groups, err := s.GroupsForCredentialsContext(ctx, "user", "pass")
						done <- result{groups: groups, err: err}
					}()
					synctest.Wait()
					return cancel, done
				}
				cancelLeader, leaderDone := start()
				defer cancelLeader()
				cancelFollower, followerDone := start()
				defer cancelFollower()
				leaderCanceled := canceled == "leader" || canceled == "both"
				followerCanceled := canceled == "follower" || canceled == "both"
				if leaderCanceled {
					cancelLeader()
				}
				if followerCanceled {
					cancelFollower()
				}
				synctest.Wait()
				for _, waiter := range []struct {
					done     <-chan result
					canceled bool
				}{{leaderDone, leaderCanceled}, {followerDone, followerCanceled}} {
					select {
					case got := <-waiter.done:
						if !waiter.canceled || !errors.Is(got.err, context.Canceled) || got.groups != nil {
							t.Fatalf("waiter returned before LDAP: groups=%v err=%v canceled=%v", got.groups, got.err, waiter.canceled)
						}
					default:
						if waiter.canceled {
							t.Fatal("canceled waiter did not return while LDAP was blocked")
						}
					}
				}
				// Repeated cancellations must keep joining the existing lookup,
				// including when all of its original callers have left.
				for range 32 {
					cancel, done := start()
					cancel()
					synctest.Wait()
					select {
					case got := <-done:
						if !errors.Is(got.err, context.Canceled) || got.groups != nil {
							t.Fatalf("canceled join = %v, %v", got.groups, got.err)
						}
					default:
						t.Fatal("canceled join did not return")
					}
				}
				if calls != 1 {
					t.Fatalf("cancellation started duplicate LDAP calls: got %d, want 1", calls)
				}
				if _, err := s.GroupsForCredentialsContext(t.Context(), "other-user", "pass"); !errors.Is(err, authn.ErrLimited) {
					t.Fatalf("LDAP admission released before lookup ended: got %v", err)
				}
				close(release)
				synctest.Wait()
				for _, waiter := range []struct {
					done     <-chan result
					canceled bool
				}{{leaderDone, leaderCanceled}, {followerDone, followerCanceled}} {
					if waiter.canceled {
						continue
					}
					got := <-waiter.done
					if _, ok := got.groups["team-r"]; got.err != nil || !ok {
						t.Fatalf("live waiter lost shared result: %v, %v", got.groups, got.err)
					}
					delete(got.groups, "team-r")
				}
				groups, err := s.GroupsForCredentialsContext(t.Context(), "user", "pass")
				if _, ok := groups["team-r"]; err != nil || !ok || calls != 1 {
					t.Fatalf("cache lost or shared mutable groups: %v, %v, LDAP calls=%d", groups, err, calls)
				}
				if _, err := s.GroupsForCredentialsContext(t.Context(), "other-user", "pass"); err != nil {
					t.Fatalf("completed LDAP lookup did not release admission: %v", err)
				}
			})
		})
	}
}

func TestGroupsForCredentialsContextCachesRejectionAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := New(config.Config{}, nil)
		release := make(chan struct{})
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		calls := 0
		s.fetchGroups = func(config.Config, string, string) (map[string]struct{}, error) {
			calls++
			<-release
			return nil, authn.ErrRejectedCredentials
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() {
			_, err := s.GroupsForCredentialsContext(ctx, "user", "pass")
			done <- err
		}()
		synctest.Wait()
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled lookup = %v", err)
			}
		default:
			t.Fatal("canceled waiter did not return")
		}
		close(release)
		synctest.Wait()
		if _, err := s.GroupsForCredentialsContext(t.Context(), "user", "pass"); !errors.Is(err, authn.ErrRejectedCredentials) {
			t.Fatalf("shared LDAP rejection was not cached: %v", err)
		}
		if calls != 1 {
			t.Fatalf("cached rejection reached LDAP again: calls=%d", calls)
		}
	})
}
