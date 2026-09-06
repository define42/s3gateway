package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/sigv4"
)

func newTransferNetworkServer(t *testing.T, cfg config.Config, handler http.Handler, http2 bool) *httptest.Server {
	t.Helper()
	front := httptest.NewUnstartedServer(handler)
	front.Config = NewHTTPServer(cfg, handler)
	front.EnableHTTP2 = http2
	front.StartTLS()
	// Client cancellation must not accidentally satisfy the shorter assertions
	// that require the server's idle watchdog to interrupt a transfer.
	front.Client().Timeout = 10 * time.Second
	t.Cleanup(front.Close)
	return front
}

func awaitTransferNetworkResult[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for transfer result")
		var zero T
		return zero
	}
}

func TestTransferLimitsStalledBodyReleasesSlot(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		for _, signed := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2=%t/signed=%t", http2, signed), func(t *testing.T) {
				t.Parallel()
				started := make(chan struct{})
				readResult := make(chan error, 1)
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path != "/stall" {
						w.WriteHeader(http.StatusNoContent)
						return
					}
					body := r.Body
					if signed {
						verifier := sigv4.NewAWSChunkSignatureVerifier(&sigv4.Auth{
							Date: "20260905", Region: "us-east-1", Service: "s3",
							SignatureHex: strings.Repeat("0", 64), AmzDate: "20260905T000000Z",
						}, "test-secret")
						var err error
						body, _, err = sigv4.DecodeBodyForS3Write(r, verifier)
						if err != nil {
							readResult <- fmt.Errorf("decode signed body: %w", err)
							close(started)
							return
						}
					}
					defer func() { _ = body.Close() }()
					close(started)
					_, err := io.Copy(io.Discard, body)
					if err == nil {
						readResult <- fmt.Errorf("stalled body was accepted without an error")
						return
					}
					if r.Context().Err() == nil {
						readResult <- fmt.Errorf("body failed without canceling its request context: %w", err)
						return
					}
					readResult <- nil
				})
				front := newTransferNetworkServer(t, config.Config{
					TransferIdleTimeout: 750 * time.Millisecond, MaxConcurrentRequests: 1,
				}, handler, http2)
				reader, writer := io.Pipe()
				t.Cleanup(func() { _ = writer.Close() })
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, front.URL+"/stall", reader)
				if err != nil {
					t.Fatal(err)
				}
				initial := "partial payload"
				if signed {
					req.Header.Set("X-Amz-Content-Sha256", sigv4.StreamingSignedPayload)
					req.Header.Set("X-Amz-Decoded-Content-Length", "16777216")
					req.Header.Set("Content-Encoding", "aws-chunked")
					initial = "1000000;chunk-signature=" + strings.Repeat("0", 64) + "\r\n" + strings.Repeat("x", 16)
				}
				clientDone := make(chan struct{})
				go func() {
					defer close(clientDone)
					response, requestErr := front.Client().Do(req)
					if requestErr == nil {
						_ = response.Body.Close()
					}
				}()
				go func() { _, _ = io.WriteString(writer, initial) }()
				awaitTransferNetworkResult(t, started)
				response, err := front.Client().Get(front.URL + "/busy")
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("concurrent request status = %d, want 503", response.StatusCode)
				}
				if err := awaitTransferNetworkResult(t, readResult); err != nil {
					t.Fatal(err)
				}
				_ = writer.Close()
				awaitTransferNetworkResult(t, clientDone)
				assertTransferNetworkSlotAvailable(t, front)
			})
		}
	}
}

func assertTransferNetworkSlotAvailable(t *testing.T, front *httptest.Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		response, err := front.Client().Get(front.URL + "/available")
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode == http.StatusNoContent {
			return
		}
		if response.StatusCode != http.StatusServiceUnavailable || time.Now().After(deadline) {
			t.Fatalf("request slot was not released: status %d", response.StatusCode)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTransferLimitsProgressingBodyExceedsIdleTimeout(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			t.Parallel()
			const idle = 400 * time.Millisecond
			readResult := make(chan error, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n, err := io.Copy(io.Discard, r.Body)
				if err == nil && n != 12 {
					err = fmt.Errorf("received %d bytes, want 12", n)
				}
				readResult <- err
				w.WriteHeader(http.StatusNoContent)
			})
			front := newTransferNetworkServer(t, config.Config{TransferIdleTimeout: idle}, handler, http2)
			reader, writer := io.Pipe()
			t.Cleanup(func() { _ = writer.Close() })
			go func() {
				defer func() { _ = writer.Close() }()
				for range 12 {
					if _, err := writer.Write([]byte("x")); err != nil {
						return
					}
					time.Sleep(100 * time.Millisecond)
				}
			}()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, front.URL, reader)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			response, err := front.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("progressing upload status = %d", response.StatusCode)
			}
			if time.Since(start) <= 2*idle {
				t.Fatal("upload did not span multiple idle intervals")
			}
			if err := awaitTransferNetworkResult(t, readResult); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTransferLimitsKeepAliveContextRemainsLive(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		for _, consume := range []bool{false, true} {
			t.Run(fmt.Sprintf("http2=%t/consume=%t", http2, consume), func(t *testing.T) {
				t.Parallel()
				const idle = 200 * time.Millisecond
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if consume {
						_, _ = io.Copy(io.Discard, r.Body)
					}
					if r.Context().Err() != nil {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				})
				front := newTransferNetworkServer(t, config.Config{TransferIdleTimeout: idle}, handler, http2)
				response, err := front.Client().Post(front.URL, "text/plain", strings.NewReader("small body"))
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				time.Sleep(2 * idle)
				var reused bool
				ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
					GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
				})
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, front.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err = front.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if !reused {
					t.Fatal("healthy connection was not reused")
				}
				if response.StatusCode != http.StatusNoContent {
					t.Fatalf("reused connection request status = %d, want live context", response.StatusCode)
				}
			})
		}
	}
}

func TestTransferLimitsStalledResponseReleasesSlot(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", http2), func(t *testing.T) {
			t.Parallel()
			writeResult := make(chan error, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/stall" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				chunk := make([]byte, 32<<10)
				for range 1024 {
					if _, err := w.Write(chunk); err != nil {
						if r.Context().Err() == nil {
							writeResult <- fmt.Errorf("write failed without canceling request: %w", err)
							return
						}
						writeResult <- nil
						return
					}
				}
				writeResult <- fmt.Errorf("stalled client accepted the entire 32 MiB response")
			})
			front := newTransferNetworkServer(t, config.Config{
				TransferIdleTimeout: 750 * time.Millisecond, MaxConcurrentRequests: 1,
			}, handler, http2)
			response, err := front.Client().Get(front.URL + "/stall")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			select {
			case err := <-writeResult:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(7 * time.Second):
				// On HTTP/1.1, net/http closes TLS after the stalled write.
				// TLS close_notify can take another five seconds after the
				// 750ms idle deadline. Stay below the client's 10s timeout.
				t.Fatal("stalled response did not release its slot after TLS cleanup")
			}
			assertTransferNetworkSlotAvailable(t, front)
		})
	}
}

func TestTransferLimitsHTTP2IdleStreamDoesNotCancelActiveStream(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	idleResult := make(chan error, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/idle" {
			close(started)
			_, err := io.Copy(io.Discard, r.Body)
			if err == nil || r.Context().Err() == nil {
				idleResult <- fmt.Errorf("idle stream was not canceled: read=%v, context=%v", err, r.Context().Err())
				return
			}
			idleResult <- nil
			return
		}
		for range 12 {
			if _, err := io.WriteString(w, "x"); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	front := newTransferNetworkServer(t, config.Config{
		TransferIdleTimeout: 400 * time.Millisecond, MaxConcurrentRequests: 2,
	}, handler, true)
	reader, writer := io.Pipe()
	defer func() { _ = writer.Close() }()
	idleCtx, cancel := context.WithCancel(t.Context())
	defer cancel()
	idleConnection := make(chan net.Conn, 1)
	idleCtx = httptrace.WithClientTrace(idleCtx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { idleConnection <- info.Conn },
	})
	req, err := http.NewRequestWithContext(idleCtx, http.MethodPut, front.URL+"/idle", reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, requestErr := front.Client().Do(req)
		if requestErr == nil {
			_ = response.Body.Close()
		}
	}()
	awaitTransferNetworkResult(t, started)
	connection := awaitTransferNetworkResult(t, idleConnection)
	activeConnection := make(chan net.Conn, 1)
	activeCtx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { activeConnection <- info.Conn },
	})
	activeRequest, err := http.NewRequestWithContext(activeCtx, http.MethodGet, front.URL+"/active", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := front.Client().Do(activeRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if awaitTransferNetworkResult(t, activeConnection) != connection {
		t.Fatal("HTTP/2 streams did not share the same connection")
	}
	if response.ProtoMajor != 2 {
		t.Fatalf("response protocol = %s, want HTTP/2", response.Proto)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("healthy stream interrupted: %v", err)
	}
	if string(data) != strings.Repeat("x", 12) {
		t.Fatalf("healthy stream received %d bytes, want 12", len(data))
	}
	if err := awaitTransferNetworkResult(t, idleResult); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	awaitTransferNetworkResult(t, clientDone)
}
