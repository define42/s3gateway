package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/uploadnotify"
)

func TestPopDownloadStreaming(t *testing.T) {
	payload := strings.Repeat("object data", 8192)
	for _, tc := range []struct {
		name          string
		interrupt     bool
		upstreamError bool
	}{
		{name: "interrupted chunked body", interrupt: true},
		{name: "complete chunked body"},
		{name: "upstream error before body", upstreamError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resume := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(resume) }) }
			gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.upstreamError {
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusNotFound)
					_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>Missing object</Message></Error>`)
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Errorf("flush upstream headers: %v", err)
					return
				}
				if _, err := io.WriteString(w, payload); err != nil {
					t.Errorf("write upstream payload: %v", err)
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Errorf("flush upstream payload: %v", err)
					return
				}
				select {
				case <-resume:
				case <-r.Context().Done():
					return
				}
				if tc.interrupt {
					panic(http.ErrAbortHandler)
				}
			})
			defer cleanup()
			consumer := &fakePopConsumer{record: popRecord(t, "team2-images", uploadnotify.Event{
				EventName: uploadnotify.EventObjectCreatedPut,
				Bucket:    "team2-images",
				Key:       "object.jpg",
				ETag:      "object-etag",
			})}
			configurePopGateway(gateway, consumer)
			downstream := httptest.NewServer(gateway.WithS3Audit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gateway.ServeHTTP(w, reqWithRulesAndUploader(r, fullTeam2Rule(), "alice"))
			})))
			defer downstream.Close()
			defer release()
			client := downstream.Client()
			client.Timeout = 5 * time.Second
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, downstream.URL+"/api/pop/team2-images/scanner", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Do(req)
			if err != nil {
				t.Fatalf("receive response headers: %v", err)
			}
			defer response.Body.Close()
			if tc.upstreamError {
				body, err := io.ReadAll(response.Body)
				if response.StatusCode != http.StatusNotFound || err != nil || !strings.Contains(string(body), "NoSuchKey") {
					t.Fatalf("upstream error response: status=%d body=%q error=%v", response.StatusCode, body, err)
				}
			} else {
				if response.StatusCode != http.StatusOK || response.ContentLength != -1 {
					t.Fatalf("response status/length = %d/%d, want 200/-1", response.StatusCode, response.ContentLength)
				}
				first := make([]byte, 1)
				if _, err := io.ReadFull(response.Body, first); err != nil {
					t.Fatalf("read initial byte: %v", err)
				}
				release()
				rest, err := io.ReadAll(response.Body)
				body := string(first) + string(rest)
				if tc.interrupt {
					if err == nil || errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("interrupted stream read error = %v, want immediate transfer failure", err)
					}
					if !strings.HasPrefix(payload, body) {
						t.Fatal("error text was appended to the object body")
					}
				} else if err != nil || body != payload {
					t.Fatalf("complete stream length=%d error=%v", len(body), err)
				}
			}
			consumer.mu.Lock()
			defer consumer.mu.Unlock()
			wantAcknowledged := !tc.interrupt && !tc.upstreamError
			if consumer.acknowledged != wantAcknowledged {
				t.Fatalf("record acknowledged = %v, want %v", consumer.acknowledged, wantAcknowledged)
			}
			if !wantAcknowledged && consumer.handleErr == nil {
				t.Fatal("consumer did not record the transfer failure")
			}
		})
	}
}
