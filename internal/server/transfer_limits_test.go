package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

func TestTransferLimitsRejectOverloadAndReleaseCapacity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		calls := 0
		srv := NewHTTPServer(config.Config{MaxConcurrentRequests: 1}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.URL.Path == "/hold" {
				<-release
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		go srv.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/hold", nil))
		synctest.Wait()
		for _, path := range []string{"/bucket/key", "/admin/upload", "/pop/bucket"} {
			response := httptest.NewRecorder()
			srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, path, strings.NewReader("unread")))
			if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "<Code>SlowDown</Code>") {
				t.Fatalf("%s: overload response = %d %s", path, response.Code, response.Body.String())
			}
			if response.Header().Get("Retry-After") != "1" || response.Header().Get("Connection") != "close" {
				t.Fatalf("%s: overload headers = %v", path, response.Header())
			}
		}
		if calls != 1 {
			t.Fatalf("overloaded requests reached handler: calls=%d", calls)
		}
		for _, path := range []string{"/healthz", "/readyz"} {
			response := httptest.NewRecorder()
			srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusNoContent {
				t.Fatalf("health check %s unavailable while busy: %d", path, response.Code)
			}
		}
		close(release)
		synctest.Wait()
		response := httptest.NewRecorder()
		srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/bucket/next", nil))
		if response.Code != http.StatusNoContent || calls != 4 {
			t.Fatalf("capacity not released: status=%d handler calls=%d", response.Code, calls)
		}
	})
}

func TestTransferLimitsCancelIdleUpstreamWork(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = time.Second
		finished := make(chan error, 1)
		srv := NewHTTPServer(config.Config{TransferIdleTimeout: idle}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// An upstream SDK call waiting for its result observes this context.
			<-r.Context().Done()
			controller := http.NewResponseController(w)
			if err := controller.SetReadDeadline(time.Now().Add(time.Minute)); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("expired request read deadline extended: %v", err)
			}
			if err := controller.SetWriteDeadline(time.Now().Add(time.Minute)); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("expired request write deadline extended: %v", err)
			}
			finished <- r.Context().Err()
		}))
		response := &transferDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
		go srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bucket/key", nil))
		synctest.Wait()
		time.Sleep(idle - time.Nanosecond)
		synctest.Wait()
		select {
		case err := <-finished:
			t.Fatalf("request canceled before idle deadline: %v", err)
		default:
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		if err := <-finished; !errors.Is(err, context.Canceled) {
			t.Fatalf("request context error = %v", err)
		}
		if response.readDeadline.IsZero() || response.readDeadline.After(time.Now()) ||
			response.writeDeadline.IsZero() || response.writeDeadline.After(time.Now()) {
			t.Fatalf("idle expiration did not interrupt both I/O directions: read=%s write=%s", response.readDeadline, response.writeDeadline)
		}
		calls := response.deadlineCalls
		time.Sleep(2 * idle)
		synctest.Wait()
		if response.deadlineCalls != calls {
			t.Fatal("watchdog used the response writer after the handler returned")
		}
	})
}

func TestTransferLimitsObserveProgressWithinLargeWrites(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idle = time.Second
		payload := bytes.Repeat([]byte("x"), 3*(32<<10))
		response := &transferSlowWriter{ResponseRecorder: httptest.NewRecorder(), delay: idle / 2}
		srv := NewHTTPServer(config.Config{TransferIdleTimeout: idle}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n, err := w.Write(payload)
			if err != nil || n != len(payload) {
				t.Errorf("large progressing write = %d, %v", n, err)
			}
			if err := r.Context().Err(); err != nil {
				t.Errorf("progressing request canceled: %v", err)
			}
		}))
		start := time.Now()
		srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bucket/key", nil))
		if time.Since(start) <= idle || !bytes.Equal(response.Body.Bytes(), payload) {
			t.Fatal("test did not transfer complete payload over multiple idle periods")
		}
	})
}

func TestTransferLimitsPreserveExplicitDeadlines(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     config.Config
		handler bool
	}{
		{name: "server absolute deadlines", cfg: config.Config{ReadTimeout: time.Second, WriteTimeout: 2 * time.Second}},
		{name: "handler deadlines including admin login", handler: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				readDeadline := time.Now().Add(time.Second)
				writeDeadline := time.Now().Add(2 * time.Second)
				response := &transferDeadlineRecorder{
					ResponseRecorder: httptest.NewRecorder(),
					readDeadline:     readDeadline,
					writeDeadline:    writeDeadline,
				}
				srv := NewHTTPServer(tc.cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					if tc.handler {
						controller := http.NewResponseController(w)
						if err := controller.SetReadDeadline(readDeadline); err != nil {
							t.Fatal(err)
						}
						if err := controller.SetWriteDeadline(writeDeadline); err != nil {
							t.Fatal(err)
						}
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				srv.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/bucket/key", nil))
				if !response.readDeadline.Equal(readDeadline) || !response.writeDeadline.Equal(writeDeadline) {
					t.Fatalf("explicit deadlines extended: read=%s write=%s", response.readDeadline, response.writeDeadline)
				}
				calls := response.deadlineCalls
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				if response.deadlineCalls != calls {
					t.Fatal("watchdog remained active after normal completion")
				}
			})
		})
	}
}

type transferDeadlineRecorder struct {
	*httptest.ResponseRecorder
	readDeadline  time.Time
	writeDeadline time.Time
	deadlineCalls int
}

func (w *transferDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	w.readDeadline = deadline
	w.deadlineCalls++
	return nil
}

func (w *transferDeadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	w.writeDeadline = deadline
	w.deadlineCalls++
	return nil
}

type transferSlowWriter struct {
	*httptest.ResponseRecorder
	delay time.Duration
}

func (w *transferSlowWriter) Write(p []byte) (int, error) {
	time.Sleep(w.delay)
	return w.ResponseRecorder.Write(p)
}
