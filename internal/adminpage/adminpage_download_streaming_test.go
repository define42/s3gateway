package adminpage

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
)

func TestAdminDownloadStreaming(t *testing.T) {
	const payloadSize = 64 << 10
	payload := strings.Repeat("x", payloadSize)
	for _, protocol := range []struct {
		name  string
		http2 bool
		major int
	}{
		{name: "HTTP1", major: 1},
		{name: "HTTP2", http2: true, major: 2},
	} {
		for _, scenario := range []struct {
			name      string
			method    string
			interrupt bool
		}{
			{name: "interrupted chunked body", method: http.MethodGet, interrupt: true},
			{name: "complete chunked body", method: http.MethodGet},
			{name: "HEAD", method: http.MethodHead},
		} {
			t.Run(protocol.name+"/"+scenario.name, func(t *testing.T) {
				releaseUpstream := make(chan struct{})
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(releaseUpstream) }) }
				handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet || r.URL.Path != "/team2-logs/stream.txt" {
						t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.Header().Set("Content-Type", "application/octet-stream")
					w.WriteHeader(http.StatusOK)
					// Flush headers before writing to prevent Content-Length inference.
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Errorf("flush upstream headers: %v", err)
						return
					}
					if scenario.method == http.MethodHead {
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
					case <-releaseUpstream:
					case <-r.Context().Done():
						return
					}
					if scenario.interrupt {
						panic(http.ErrAbortHandler)
					}
				})
				defer cleanup()
				downstream := httptest.NewUnstartedServer(handler)
				downstream.EnableHTTP2 = protocol.http2
				downstream.StartTLS()
				defer downstream.Close()
				defer release()
				client := downstream.Client()
				client.Timeout = 5 * time.Second
				r, err := http.NewRequestWithContext(t.Context(), scenario.method, downstream.URL+"/admin/bucket/download?name=team2-logs&key=stream.txt", nil)
				if err != nil {
					t.Fatal(err)
				}
				r.AddCookie(cookie)
				response, err := client.Do(r)
				if err != nil {
					t.Fatalf("receive downstream response headers: %v", err)
				}
				defer response.Body.Close()
				if response.StatusCode != http.StatusOK || response.ProtoMajor != protocol.major {
					t.Fatalf("response status/protocol = %d/%s, want 200/HTTP%d", response.StatusCode, response.Proto, protocol.major)
				}
				if scenario.method == http.MethodHead {
					body, err := io.ReadAll(response.Body)
					if err != nil || len(body) != 0 {
						t.Fatalf("HEAD body = %q, error = %v", body, err)
					}
					return
				}
				if response.ContentLength != -1 {
					t.Fatalf("ContentLength = %d, want unknown length", response.ContentLength)
				}
				first := make([]byte, 1)
				if _, err := io.ReadFull(response.Body, first); err != nil {
					t.Fatalf("read initial object byte: %v", err)
				}
				release()
				rest, readErr := io.ReadAll(response.Body)
				body := string(first) + string(rest)
				if scenario.interrupt {
					if readErr == nil {
						t.Fatalf("interrupted upstream body was reported complete after %d bytes", len(body))
					}
					if errors.Is(readErr, context.DeadlineExceeded) {
						t.Fatalf("interrupted body hung until the client deadline: %v", readErr)
					}
					if !strings.HasPrefix(payload, body) {
						t.Fatalf("interrupted body is not an object prefix: length %d", len(body))
					}
				} else if readErr != nil || body != payload {
					t.Fatalf("complete body length = %d, error = %v", len(body), readErr)
				}
			})
		}
	}
}
