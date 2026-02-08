package main

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupsForCredentialsSingleflightDeduplicatesConcurrentMisses(t *testing.T) {
	s := newServer(Config{
		GroupTTL:             time.Minute,
		GroupCacheMaxEntries: 64,
	}, nil)

	var calls atomic.Int32
	started := make(chan struct{}, 1)
	release := make(chan struct{})

	s.fetchGroups = func(cfg Config, upn, pass string) (map[string]struct{}, error) {
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
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			<-start
			groups, err := s.groupsForCredentials("singleflight-user", "singleflight-pass")
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
	if _, err := s.groupsForCredentials("singleflight-user", "singleflight-pass"); err != nil {
		t.Fatalf("cache hit after singleflight failed: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("cache hit should not trigger backend fetch: got backend calls=%d want=1", got)
	}
}
