package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/config"
)

type multipartProgressHTTPClient func(*http.Request) (*http.Response, error)

func (f multipartProgressHTTPClient) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestTransferLimitsMultipartCompletionProgress(t *testing.T) {
	for _, tc := range []struct {
		name          string
		stall         bool
		cancelClient  bool
		upstreamError bool
	}{
		{name: "heartbeats allow completion beyond default idle timeout"},
		{name: "stopped heartbeats still expire", stall: true},
		{name: "client cancellation still stops healthy completion", cancelClient: true},
		{name: "error after heartbeats is preserved", upstreamError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := config.Config{}
				cfg.ApplyDefaults()
				idle := cfg.TransferIdleTimeout
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if tc.cancelClient {
					timer := time.AfterFunc(2*idle, cancel)
					defer timer.Stop()
				}
				client := s3.New(s3.Options{
					Region: "us-east-1", BaseEndpoint: aws.String("https://upstream.example"), UsePathStyle: true,
					Credentials:      credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
					RetryMaxAttempts: 1,
					HTTPClient: multipartProgressHTTPClient(func(r *http.Request) (*http.Response, error) {
						if r.Method != http.MethodPost || r.URL.Query().Get("uploadId") != "upload-1" {
							t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
						}
						_, _ = io.Copy(io.Discard, r.Body)
						reader, writer := io.Pipe()
						stop := context.AfterFunc(r.Context(), func() {
							_ = writer.CloseWithError(r.Context().Err())
						})
						go func() {
							defer stop()
							defer func() { _ = writer.CloseWithError(r.Context().Err()) }()
							for i := range 9 {
								if tc.stall && i == 3 {
									<-r.Context().Done()
									return
								}
								select {
								case <-r.Context().Done():
									return
								case <-time.After(idle / 3):
								}
								if _, err := io.WriteString(writer, " \n"); err != nil {
									return
								}
							}
							result := `<CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>`
							if tc.upstreamError {
								result = `<Error><Code>InternalError</Code><Message>completion failed</Message></Error>`
							}
							_, _ = io.WriteString(writer, result)
						}()
						return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: reader}, nil
					}),
				})
				gateway := New(cfg, client)
				var handlerErr error
				srv := NewHTTPServer(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					gateway.ServeHTTP(w, reqWithRules(r, fullTeam2Rule()))
					handlerErr = r.Context().Err()
				}))
				req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1",
					strings.NewReader(completeMultipartDocument(1, "part-etag"))).WithContext(ctx)
				rr := httptest.NewRecorder()
				started := time.Now()
				srv.Handler.ServeHTTP(rr, req)
				if tc.stall || tc.cancelClient {
					if handlerErr == nil || strings.Contains(rr.Body.String(), "<CompleteMultipartUploadResult") {
						t.Fatalf("canceled completion succeeded: context=%v, response=%s", handlerErr, rr.Body.String())
					}
					if elapsed := time.Since(started); elapsed > 2*idle {
						t.Fatalf("cancellation took %s, want at most %s", elapsed, 2*idle)
					}
					return
				}
				if handlerErr != nil || time.Since(started) != 3*idle {
					t.Fatalf("healthy completion canceled: elapsed=%s context=%v response=%s", time.Since(started), handlerErr, rr.Body.String())
				}
				if tc.upstreamError {
					if !strings.Contains(rr.Body.String(), "<Code>InternalError</Code>") {
						t.Fatalf("upstream error lost: %s", rr.Body.String())
					}
				} else if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<CompleteMultipartUploadResult") {
					t.Fatalf("completion failed: %d %s", rr.Code, rr.Body.String())
				}
			})
		})
	}
}

func TestTransferLimitsMultipartCompletionNetworkKeepalives(t *testing.T) {
	const idle = time.Second
	gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		controller := http.NewResponseController(w)
		for range 50 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := io.WriteString(w, " \n"); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		}
		_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>`)
	})
	t.Cleanup(cleanup)
	srv := NewHTTPServer(config.Config{TransferIdleTimeout: idle}, gateway)
	req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1",
		strings.NewReader(completeMultipartDocument(1, "part-etag")))
	rr := httptest.NewRecorder()
	started := time.Now()
	srv.Handler.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "<ETag>\"completed\"</ETag>") {
		t.Fatalf("healthy upstream completion failed: %d %s", rr.Code, rr.Body.String())
	}
	if time.Since(started) < 2*idle {
		t.Fatal("completion did not span multiple idle intervals")
	}
}
