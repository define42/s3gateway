package server

import (
	"context"
	"encoding/xml"
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

var copyProgressOperations = []struct {
	name, target, root string
}{
	{name: "copy object", target: "/team2-bucket/dest", root: "CopyObjectResult"},
	{name: "copy part", target: "/team2-bucket/dest?uploadId=upload-1&partNumber=1", root: "CopyPartResult"},
}

func TestTransferLimitsCopyProgress(t *testing.T) {
	for _, operation := range copyProgressOperations {
		t.Run(operation.name, func(t *testing.T) {
			for _, tc := range []struct {
				name          string
				stall         bool
				cancelClient  bool
				upstreamError bool
			}{
				{name: "heartbeats allow copying beyond default idle timeout"},
				{name: "stopped heartbeats still expire", stall: true},
				{name: "client cancellation stops healthy copying", cancelClient: true},
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
								if r.Method != http.MethodPut || r.Header.Get("x-amz-copy-source") != "/team2-bucket/source" {
									t.Errorf("unexpected upstream copy: %s %s", r.Method, r.URL)
								}
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
									result := "<" + operation.root + "><ETag>\"copied\"</ETag></" + operation.root + ">"
									if tc.upstreamError {
										result = `<Error><Code>InternalError</Code><Message>copy failed</Message></Error>`
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
						req := httptest.NewRequest(http.MethodPut, operation.target, nil).WithContext(ctx)
						req.Header.Set("x-amz-copy-source", "/team2-bucket/source")
						rr := httptest.NewRecorder()
						started := time.Now()
						srv.Handler.ServeHTTP(rr, req)
						if tc.stall || tc.cancelClient {
							if handlerErr == nil || strings.Contains(rr.Body.String(), "<"+operation.root) {
								t.Fatalf("canceled copy succeeded: context=%v response=%s", handlerErr, rr.Body.String())
							}
							if elapsed := time.Since(started); elapsed > 2*idle {
								t.Fatalf("cancellation took %s, want at most %s", elapsed, 2*idle)
							}
							return
						}
						if handlerErr != nil || time.Since(started) != 3*idle {
							t.Fatalf("healthy copy canceled: elapsed=%s context=%v response=%s", time.Since(started), handlerErr, rr.Body.String())
						}
						if tc.upstreamError {
							if !strings.Contains(rr.Body.String(), "<Code>InternalError</Code>") {
								t.Fatalf("upstream error lost: %s", rr.Body.String())
							}
						} else {
							assertCopyProgressResult(t, rr, operation.root)
						}
					})
				})
			}
		})
	}
}

func TestTransferLimitsCopyNetworkKeepalives(t *testing.T) {
	for _, operation := range copyProgressOperations {
		t.Run(operation.name, func(t *testing.T) {
			const idle = time.Second
			gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
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
				_, _ = io.WriteString(w, "<"+operation.root+"><ETag>\"copied\"</ETag></"+operation.root+">")
			})
			t.Cleanup(cleanup)
			srv := NewHTTPServer(config.Config{TransferIdleTimeout: idle}, gateway)
			req := httptest.NewRequest(http.MethodPut, operation.target, nil)
			req.Header.Set("x-amz-copy-source", "/team2-bucket/source")
			rr := httptest.NewRecorder()
			started := time.Now()
			srv.Handler.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			assertCopyProgressResult(t, rr, operation.root)
			if time.Since(started) < 2*idle {
				t.Fatal("copy did not span multiple idle intervals")
			}
		})
	}
}

func assertCopyProgressResult(t *testing.T, rr *httptest.ResponseRecorder, root string) {
	t.Helper()
	var result struct {
		XMLName xml.Name
		ETag    string `xml:"ETag"`
	}
	if err := xml.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode copy result: %v", err)
	}
	if rr.Code != http.StatusOK || result.XMLName.Local != root || result.ETag != `"copied"` {
		t.Fatalf("copy failed: %d %s", rr.Code, rr.Body.String())
	}
}
