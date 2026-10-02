package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/kafkapop"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/twmb/franz-go/pkg/kgo"
)

type popConsumerFunc func(context.Context, string, string, func(context.Context, *kgo.Record) error) error

func (f popConsumerFunc) Consume(ctx context.Context, topic, group string, handle func(context.Context, *kgo.Record) error) error {
	return f(ctx, topic, group, handle)
}

func TestPopRebalanceCancelsUpstreamBeforeResponse(t *testing.T) {
	upstreamStarted := make(chan struct{})
	upstreamCanceled := make(chan struct{})
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		close(upstreamStarted)
		<-r.Context().Done()
		close(upstreamCanceled)
	})
	defer cleanup()
	gateway.cfg.EnableKafkaBucketTopic = true
	record := popRecord(t, "team2-images", uploadnotify.Event{Bucket: "team2-images", Key: "object", ETag: "etag"})
	gateway.popConsumer = popConsumerFunc(func(ctx context.Context, _, _ string, handle func(context.Context, *kgo.Record) error) error {
		ctx, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		go func() {
			select {
			case <-upstreamStarted:
				cancel(kafkapop.ErrRebalance)
			case <-ctx.Done():
			}
		}()
		err := handle(ctx, record)
		if !errors.Is(err, kafkapop.ErrRebalance) {
			t.Errorf("interrupted handler error = %v", err)
		}
		return err
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil).WithContext(ctx)
	response := httptest.NewRecorder()
	gateway.ServeHTTP(response, reqWithRulesAndUploader(request, fullTeam2Rule(), "alice"))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("response status=%d retry-after=%q body=%q", response.Code, response.Header().Get("Retry-After"), response.Body.String())
	}
	select {
	case <-upstreamCanceled:
	case <-ctx.Done():
		t.Fatal("rebalance did not cancel the upstream request")
	}
}

type blockedPopResponseWriter struct {
	*httptest.ResponseRecorder
	started     chan struct{}
	interrupted chan struct{}
	once        sync.Once
}

func (w *blockedPopResponseWriter) Write([]byte) (int, error) {
	close(w.started)
	<-w.interrupted
	return 0, os.ErrDeadlineExceeded
}

func (w *blockedPopResponseWriter) SetWriteDeadline(time.Time) error {
	w.once.Do(func() { close(w.interrupted) })
	return nil
}

func TestPopRebalanceInterruptsBlockedClientWrite(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("object", 1024))
	})
	defer cleanup()
	ctx, cancel := context.WithCancelCause(t.Context())
	defer cancel(nil)
	request := httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil).WithContext(ctx)
	writer := &blockedPopResponseWriter{
		ResponseRecorder: httptest.NewRecorder(),
		started:          make(chan struct{}),
		interrupted:      make(chan struct{}),
	}
	done := make(chan error, 1)
	go func() {
		done <- gateway.streamPoppedObject(writer, request, uploadnotify.Event{Bucket: "team2-images", Key: "object", ETag: "etag"})
	}()
	select {
	case <-writer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("object stream did not reach client write")
	}
	cancel(kafkapop.ErrRebalance)
	select {
	case err := <-done:
		if !errors.Is(err, errPopResponseInterrupted) || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked write returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("rebalance did not interrupt the blocked client write")
	}
}

func TestPopRebalanceBeforeRecordReturnsRetryableResponse(t *testing.T) {
	gateway, cleanup := newGatewayWithStubUpstream(t, func(http.ResponseWriter, *http.Request) {
		t.Error("unexpected upstream request")
	})
	defer cleanup()
	gateway.cfg.EnableKafkaBucketTopic = true
	gateway.popConsumer = popConsumerFunc(func(context.Context, string, string, func(context.Context, *kgo.Record) error) error {
		return kafkapop.ErrRebalance
	})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/pop/team2-images/scanner", nil)
	gateway.ServeHTTP(response, reqWithRulesAndUploader(request, fullTeam2Rule(), "alice"))
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Retry-After") != "1" {
		t.Fatalf("response status=%d retry-after=%q", response.Code, response.Header().Get("Retry-After"))
	}
}
