package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestGetObjectStreamingTransferFailures(t *testing.T) {
	for _, protocol := range []struct {
		name  string
		http2 bool
		major int
	}{
		{name: "HTTP1", major: 1},
		{name: "HTTP2", http2: true, major: 2},
	} {
		t.Run(protocol.name, func(t *testing.T) {
			for _, tc := range []struct {
				name        string
				knownLength bool
				interrupt   bool
			}{
				{name: "interrupted chunked body", interrupt: true},
				{name: "complete chunked body"},
				{name: "premature EOF with content length", knownLength: true, interrupt: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					payload := bytes.Repeat([]byte("object data\n"), 4096)
					finish := make(chan struct{})
					releaseUpstream := sync.OnceFunc(func() { close(finish) })
					gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
						if r.Method != http.MethodGet || r.URL.Path != "/team2-bucket/key" || r.ProtoMajor != 1 {
							t.Errorf("unexpected upstream request: %s %s %s", r.Method, r.URL.Path, r.Proto)
						}
						w.Header().Set("Content-Type", "application/octet-stream")
						w.Header().Set("ETag", `"object-etag"`)
						if tc.knownLength {
							w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1))
						}
						w.WriteHeader(http.StatusOK)
						if _, err := w.Write(payload); err != nil {
							t.Errorf("write upstream object bytes: %v", err)
							return
						}
						if err := http.NewResponseController(w).Flush(); err != nil {
							t.Errorf("flush upstream object bytes: %v", err)
							return
						}
						// Fail only after the downstream client has received object bytes.
						select {
						case <-finish:
						case <-r.Context().Done():
							return
						}
						if tc.interrupt {
							// HTTP/1 closes without a terminal chunk or the remaining byte.
							panic(http.ErrAbortHandler)
						}
					})
					defer cleanup()
					handler := gw.WithS3Audit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						gw.ServeHTTP(w, reqWithRules(r, fullTeam2Rule()))
					}))
					front := httptest.NewUnstartedServer(handler)
					front.EnableHTTP2 = protocol.http2
					front.StartTLS()
					defer front.Close()
					defer releaseUpstream()

					req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, front.URL+"/team2-bucket/key", nil)
					if err != nil {
						t.Fatal(err)
					}
					client := front.Client()
					client.Timeout = 5 * time.Second
					response, err := client.Do(req)
					if err != nil {
						t.Fatalf("receive response headers before upstream failure: %v", err)
					}
					defer response.Body.Close()
					if response.ProtoMajor != protocol.major {
						t.Fatalf("negotiated %s, want HTTP/%d", response.Proto, protocol.major)
					}
					if response.StatusCode != http.StatusOK || response.Header.Get("ETag") != `"object-etag"` {
						t.Fatalf("unexpected initial response: status=%d ETag=%q", response.StatusCode, response.Header.Get("ETag"))
					}
					if !tc.knownLength && response.ContentLength != -1 {
						t.Fatalf("chunked source acquired a content length: %d", response.ContentLength)
					}
					first := make([]byte, 1024)
					if _, err := io.ReadFull(response.Body, first); err != nil {
						t.Fatalf("read initial object bytes before upstream failure: %v", err)
					}
					releaseUpstream()
					rest, readErr := io.ReadAll(response.Body)
					body := append(first, rest...)
					if !bytes.HasPrefix(payload, body) {
						t.Fatal("download contained data outside the original object bytes")
					}
					if tc.interrupt {
						if readErr == nil {
							t.Fatalf("truncated upstream returned success to the client: received %d bytes", len(body))
						}
						if errors.Is(readErr, context.DeadlineExceeded) {
							t.Fatalf("interrupted stream hung until the client deadline: %v", readErr)
						}
						return
					}
					if readErr != nil || !bytes.Equal(body, payload) {
						t.Fatalf("valid chunked download: bytes=%d want=%d error=%v", len(body), len(payload), readErr)
					}
				})
			}
		})
	}
}
