package adminpage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type adminUploadCleanupContextKey struct{}

func TestAdminUploadCleanupOutlivesRequest(t *testing.T) {
	for _, tt := range []struct {
		name           string
		expireDeadline bool
		hangAbort      bool
	}{
		{name: "canceled request"},
		{name: "expired request deadline", expireDeadline: true},
		{name: "abort deadline bounds cleanup", hangAbort: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent := context.WithValue(t.Context(), adminUploadCleanupContextKey{}, "upload-trace")
				requestCtx, cancelRequest := context.WithCancel(parent)
				if tt.expireDeadline {
					cancelRequest()
					requestCtx, cancelRequest = context.WithTimeout(parent, time.Second)
				}
				defer cancelRequest()

				var created, uploaded, completed, aborted int
				var storedPart bool
				var cleanupCtx context.Context
				var cleanupDuration time.Duration
				h := newHandlerWithNilS3(map[string]struct{}{"team2-w": {}})
				h.s3 = s3.New(s3.Options{
					Region:                     "us-east-1",
					BaseEndpoint:               aws.String("https://upstream.test"),
					UsePathStyle:               true,
					Credentials:                credentials.NewStaticCredentialsProvider("test-ak", "test-sk", ""),
					RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
					RetryMaxAttempts:           1,
					HTTPClient: adminUploadIntegrityHTTPClient(func(r *http.Request) (*http.Response, error) {
						// An HTTP transport cannot send a request whose context is already canceled.
						if err := r.Context().Err(); err != nil {
							return nil, err
						}
						responseBody := ""
						header := make(http.Header)
						q := r.URL.Query()
						switch {
						case r.Method == http.MethodPost && q.Has("uploads"):
							created++
							responseBody = `<InitiateMultipartUploadResult><UploadId>cleanup-upload</UploadId></InitiateMultipartUploadResult>`
						case r.Method == http.MethodPut && q.Get("uploadId") == "cleanup-upload":
							n, err := io.Copy(io.Discard, r.Body)
							if err != nil || n != 16 {
								t.Fatalf("store upstream part: bytes=%d err=%v", n, err)
							}
							uploaded++
							storedPart = true
							header.Set("ETag", `"part-etag"`)
							if tt.expireDeadline {
								time.Sleep(time.Second)
								synctest.Wait()
							} else {
								cancelRequest()
							}
						case r.Method == http.MethodPost && q.Get("uploadId") == "cleanup-upload":
							completed++
							responseBody = `<CompleteMultipartUploadResult><ETag>"final-etag"</ETag></CompleteMultipartUploadResult>`
						case r.Method == http.MethodDelete && q.Get("uploadId") == "cleanup-upload":
							aborted++
							cleanupCtx = r.Context()
							if r.URL.Path != "/team2-logs/existing.txt" {
								t.Errorf("abort path = %q, want original upload bucket and key", r.URL.Path)
							}
							if got := cleanupCtx.Value(adminUploadCleanupContextKey{}); got != "upload-trace" {
								t.Errorf("cleanup request context value = %v, want upload-trace", got)
							}
							deadline, ok := cleanupCtx.Deadline()
							if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 10*time.Second {
								t.Fatalf("cleanup deadline = %v, present=%v; want a fresh deadline within 10 seconds", deadline, ok)
							}
							if tt.hangAbort {
								started := time.Now()
								<-cleanupCtx.Done()
								cleanupDuration = time.Since(started)
								return nil, cleanupCtx.Err()
							}
							storedPart = false
						default:
							t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL)
						}
						return &http.Response{
							StatusCode: http.StatusOK,
							Header:     header,
							Body:       io.NopCloser(strings.NewReader(responseBody)),
							Request:    r,
						}, nil
					}),
				})
				notifier := &recordingAdminUploadNotifier{}
				h.uploadNotifier = notifier
				cookie := adminLoginSessionCookie(t, h, "alice", "secret")

				var body bytes.Buffer
				mw := multipart.NewWriter(&body)
				for _, field := range [][2]string{{"name", "team2-logs"}, {"key", "existing.txt"}, {"size", "16"}} {
					if err := mw.WriteField(field[0], field[1]); err != nil {
						t.Fatal(err)
					}
				}
				file, err := mw.CreateFormFile("file", "existing.txt")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(file, "partial contents"); err != nil {
					t.Fatal(err)
				}
				if err := mw.Close(); err != nil {
					t.Fatal(err)
				}

				r := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &body).WithContext(requestCtx)
				r.Header.Set("Content-Type", mw.FormDataContentType())
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)

				wantRequestErr := context.Canceled
				if tt.expireDeadline {
					wantRequestErr = context.DeadlineExceeded
				}
				if !errors.Is(requestCtx.Err(), wantRequestErr) {
					t.Errorf("request context error = %v, want %v", requestCtx.Err(), wantRequestErr)
				}
				if created != 1 || uploaded != 1 || aborted != 1 {
					t.Fatalf("multipart lifecycle: created=%d uploaded=%d aborted=%d; want one of each", created, uploaded, aborted)
				}
				if completed != 0 || len(notifier.events) != 0 {
					t.Errorf("canceled upload committed: completed=%d notifications=%d", completed, len(notifier.events))
				}
				if storedPart != tt.hangAbort {
					t.Errorf("part remains stored = %v, want %v", storedPart, tt.hangAbort)
				}
				wantCleanupErr := context.Canceled
				if tt.hangAbort {
					wantCleanupErr = context.DeadlineExceeded
					if cleanupDuration <= 0 || cleanupDuration > 10*time.Second {
						t.Errorf("blocked abort returned after %v, want within 10 seconds", cleanupDuration)
					}
				}
				if !errors.Is(cleanupCtx.Err(), wantCleanupErr) {
					t.Errorf("cleanup context error after handler returns = %v, want %v", cleanupCtx.Err(), wantCleanupErr)
				}
				location := parseRedirectLocation(t, w)
				if location.Query().Get("err") == "" || location.Query().Get("msg") != "" {
					t.Errorf("canceled upload did not report failure: %s", location)
				}
			})
		})
	}
}
