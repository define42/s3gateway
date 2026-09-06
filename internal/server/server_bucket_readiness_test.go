package server

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func TestS3ReadinessRequestsOnlyOneBucketPage(t *testing.T) {
	var calls atomic.Int32
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/" || r.URL.Query().Get("max-buckets") != "1" || r.URL.Query().Has("continuation-token") {
			t.Errorf("unexpected readiness request: %s %s", r.Method, r.URL)
		}
		writeBucketPaginationPage(t, w, []string{"team2-first"}, "more-buckets", "")
	})
	t.Cleanup(cleanup)
	if err := gw.checkS3Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("readiness queried %d pages, want one", calls.Load())
	}
}

func TestS3ReadinessPreservesCancellation(t *testing.T) {
	for _, alreadyCanceled := range []bool{true, false} {
		name := "during upstream request"
		if alreadyCanceled {
			name = "before upstream request"
		}
		t.Run(name, func(t *testing.T) {
			var calls atomic.Int32
			started := make(chan struct{})
			upstreamCanceled := make(chan struct{})
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				close(started)
				<-r.Context().Done()
				close(upstreamCanceled)
			})
			t.Cleanup(cleanup)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if alreadyCanceled {
				cancel()
				if err := gw.checkS3Ready(ctx); !errors.Is(err, context.Canceled) {
					t.Fatalf("readiness error=%v, want cancellation", err)
				}
				if calls.Load() != 0 {
					t.Fatal("canceled readiness request reached upstream")
				}
				return
			}
			done := make(chan error, 1)
			go func() { done <- gw.checkS3Ready(ctx) }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("readiness request did not start")
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("readiness error=%v, want cancellation", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("readiness ignored request cancellation")
			}
			select {
			case <-upstreamCanceled:
			case <-time.After(5 * time.Second):
				t.Fatal("readiness left the upstream request running after cancellation")
			}
			if calls.Load() != 1 {
				t.Fatalf("readiness made %d calls, want one", calls.Load())
			}
		})
	}
}
