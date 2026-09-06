package splunkhec

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandlerRejectsRedirectsAndRetainsBatch(t *testing.T) {
	for _, clientMode := range []string{"default client", "custom client over HTTPS"} {
		t.Run(clientMode, func(t *testing.T) {
			for _, status := range []int{
				http.StatusMovedPermanently,
				http.StatusFound,
				http.StatusSeeOther,
				http.StatusTemporaryRedirect,
				http.StatusPermanentRedirect,
			} {
				t.Run(strconv.Itoa(status), func(t *testing.T) {
					var destinationRequests atomic.Int32
					destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						destinationRequests.Add(1)
						_, _ = io.WriteString(w, `{"code":0}`)
					}))
					defer destination.Close()

					requests := make(chan capturedRequest, 4)
					var redirect atomic.Bool
					redirect.Store(true)
					collector := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, _ := io.ReadAll(r.Body)
						requests <- capturedRequest{
							method:    r.Method,
							authorize: r.Header.Get("Authorization"),
							body:      body,
						}
						if redirect.Load() {
							w.Header().Set("Location", destination.URL)
							w.WriteHeader(status)
							_, _ = io.WriteString(w, "collector moved")
							return
						}
						_, _ = io.WriteString(w, `{"code":0}`)
					}))
					var suppliedClient *http.Client
					var suppliedPolicyCalls atomic.Int32
					if clientMode == "custom client over HTTPS" {
						collector.StartTLS()
						suppliedClient = collector.Client()
						suppliedClient.Timeout = 2 * time.Second
						suppliedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
							suppliedPolicyCalls.Add(1)
							return nil
						}
						jar, err := cookiejar.New(nil)
						if err != nil {
							t.Fatalf("create cookie jar: %v", err)
						}
						suppliedClient.Jar = jar
					} else {
						collector.Start()
					}
					defer collector.Close()

					handler, err := NewHandler(Options{
						Endpoint:      collector.URL,
						Token:         "test-token",
						Index:         "gateway",
						FlushInterval: time.Hour,
						HTTPClient:    suppliedClient,
						LocalHandler:  slog.NewJSONHandler(io.Discard, nil),
						ErrorWriter:   io.Discard,
					})
					if err != nil {
						t.Fatalf("create HEC handler: %v", err)
					}
					defer func() {
						redirect.Store(false)
						closeHandler(t, handler)
					}()
					logger := slog.New(handler)
					logger.Info("retain this confidential event")

					err = handler.Flush(t.Context())
					if err == nil || !strings.Contains(err.Error(), "HTTP status "+strconv.Itoa(status)) {
						t.Fatalf("redirect flush error = %v, want HTTP status %d", err, status)
					}
					if got := destinationRequests.Load(); got != 0 {
						t.Fatalf("redirect destination received %d requests; token and batch must stay at the configured endpoint", got)
					}
					if got := suppliedPolicyCalls.Load(); got != 0 {
						t.Fatalf("HEC invoked the supplied redirect policy %d times", got)
					}

					// New events must follow the rejected batch when the configured
					// collector recovers; the redirect target must never receive it.
					logger.Info("event queued after redirect")
					redirect.Store(false)
					if err := handler.Flush(t.Context()); err != nil {
						t.Fatalf("retry retained HEC batch: %v", err)
					}
					first := <-requests
					second := <-requests
					if len(decodeBatch(t, first.body)) != 1 || len(decodeBatch(t, second.body)) != 2 {
						t.Fatal("retry lost or duplicated a queued event")
					}
					if !bytes.HasPrefix(second.body, first.body) {
						t.Fatal("retained batch changed or moved behind newly queued events")
					}
					for _, request := range []capturedRequest{first, second} {
						if request.method != http.MethodPost || request.authorize != "Splunk test-token" {
							t.Fatalf("collector request method/authorization = %q/%q", request.method, request.authorize)
						}
					}
					if got := destinationRequests.Load(); got != 0 {
						t.Fatalf("retry reached redirect destination %d times", got)
					}
					if suppliedClient == nil {
						if handler.core.httpClient.Timeout != defaultHTTPTimeout {
							t.Fatalf("default timeout = %s, want %s", handler.core.httpClient.Timeout, defaultHTTPTimeout)
						}
						return
					}
					if handler.core.httpClient == suppliedClient {
						t.Fatal("HEC must own its redirect policy without modifying the supplied client")
					}
					if handler.core.httpClient.Timeout != suppliedClient.Timeout ||
						handler.core.httpClient.Transport != suppliedClient.Transport ||
						handler.core.httpClient.Jar != suppliedClient.Jar {
						t.Fatal("HEC did not preserve the supplied client timeout, transport, and cookie jar")
					}
					if err := suppliedClient.CheckRedirect(nil, nil); err != nil || suppliedPolicyCalls.Load() != 1 {
						t.Fatalf("supplied redirect policy changed: error=%v, calls=%d", err, suppliedPolicyCalls.Load())
					}
				})
			}
		})
	}
}
