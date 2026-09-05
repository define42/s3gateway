package adminpage

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type adminUploadIntegrityHTTPClient func(*http.Request) (*http.Response, error)

func (f adminUploadIntegrityHTTPClient) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestAdminUploadCancellationReachesUpstreamAbort(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var created, storedParts, aborted, completed atomic.Int32
	h, creds, cleanup := newTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/team2-logs/canceled.txt" {
			t.Errorf("unexpected upstream path: %s", r.URL.Path)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		query := r.URL.Query()
		switch {
		case r.Method == http.MethodPost && query.Has("uploads"):
			created.Add(1)
			_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><UploadId>canceled-upload</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && query.Get("uploadId") == "canceled-upload":
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				t.Errorf("read upstream part: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			storedParts.Add(1)
			// The upstream has stored the part when the browser disconnects.
			cancel()
			w.Header().Set("ETag", `"part-etag"`)
		case r.Method == http.MethodDelete && query.Get("uploadId") == "canceled-upload":
			aborted.Add(1)
			storedParts.Store(0)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && query.Get("uploadId") == "canceled-upload":
			completed.Add(1)
			w.WriteHeader(http.StatusBadRequest)
		default:
			t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	defer cleanup()
	creds.set("alice", "secret", map[string]struct{}{"team2-w": {}})
	cookie := adminLoginSessionCookie(t, h, "alice", "secret")
	notifier := &recordingAdminUploadNotifier{}
	h.uploadNotifier = notifier
	body, contentType := newMultipartBody(t, func(writer *multipart.Writer) error {
		if err := writer.WriteField("name", "team2-logs"); err != nil {
			return err
		}
		file, err := writer.CreateFormFile("file", "canceled.txt")
		if err != nil {
			return err
		}
		_, err = io.WriteString(file, "stored before cancellation")
		return err
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body).WithContext(ctx)
	req.Header.Set("Content-Type", contentType)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if ctx.Err() != context.Canceled {
		t.Fatal("browser request was not canceled")
	}
	if created.Load() != 1 || aborted.Load() != 1 || storedParts.Load() != 0 {
		t.Errorf("unfinished upload cleanup: created=%d aborted=%d stored parts=%d, want 1/1/0",
			created.Load(), aborted.Load(), storedParts.Load())
	}
	if completed.Load() != 0 || len(notifier.events) != 0 {
		t.Errorf("canceled upload finalized: complete=%d notifications=%d", completed.Load(), len(notifier.events))
	}
	location := parseRedirectLocation(t, rr)
	if location.Query().Get("err") == "" || location.Query().Get("msg") != "" {
		t.Errorf("canceled upload did not report failure: %s", location)
	}
}

func TestAdminUploadValidatesIntegrityBeforeCommit(t *testing.T) {
	const partSize = 16 << 20
	for _, tt := range []struct {
		name         string
		payloadSize  int
		declaredSize *string
		ending       string
		wantSuccess  bool
	}{
		{name: "short file", payloadSize: 16, declaredSize: aws.String("16"), wantSuccess: true},
		{name: "size omitted", payloadSize: 16, wantSuccess: true},
		{name: "size blank", payloadSize: 16, declaredSize: aws.String(""), wantSuccess: true},
		{name: "empty file", declaredSize: aws.String("0"), wantSuccess: true},
		{name: "empty file without size", wantSuccess: true},
		{name: "full part", payloadSize: partSize, declaredSize: aws.String(strconv.Itoa(partSize)), wantSuccess: true},
		{name: "multiple parts", payloadSize: partSize + 16, declaredSize: aws.String(strconv.Itoa(partSize + 16)), wantSuccess: true},
		{name: "final boundary without newline", payloadSize: 16, ending: "no final newline", wantSuccess: true},
		{name: "declared size too large", payloadSize: 16, declaredSize: aws.String("1000")},
		{name: "declared size too small", payloadSize: 16, declaredSize: aws.String("1")},
		{name: "nonempty file declared empty", payloadSize: 16, declaredSize: aws.String("0")},
		{name: "empty file declared nonempty", declaredSize: aws.String("16")},
		{name: "short final part after full part", payloadSize: partSize + 16, declaredSize: aws.String(strconv.Itoa(partSize + 17))},
		{name: "empty file without boundary", declaredSize: aws.String("0"), ending: "missing"},
		{name: "short file without boundary", payloadSize: 16, declaredSize: aws.String("16"), ending: "missing"},
		{name: "full part without boundary", payloadSize: partSize, declaredSize: aws.String(strconv.Itoa(partSize)), ending: "missing"},
		{name: "multiple parts without boundary", payloadSize: partSize + 16, declaredSize: aws.String(strconv.Itoa(partSize + 16)), ending: "missing"},
		{name: "size omitted without boundary", payloadSize: 16, ending: "missing"},
		{name: "incomplete boundary", payloadSize: 16, ending: "incomplete"},
		{name: "invalid final boundary suffix", payloadSize: 16, ending: "invalid suffix"},
		{name: "file ends but form does not", payloadSize: 16, ending: "unfinished next part"},
		{name: "next delimiter without newline", payloadSize: 16, ending: "next delimiter"},
		{name: "truncated next part header", payloadSize: 16, ending: "partial header"},
		{name: "trailing field", payloadSize: 16, ending: "field"},
		{name: "second file", payloadSize: 16, ending: "file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var created, completed, put, aborted int
			var uploadedBytes int64
			h := newHandlerWithNilS3(map[string]struct{}{"team2-w": {}})
			h.s3 = s3.New(s3.Options{
				Region:                     "us-east-1",
				BaseEndpoint:               aws.String("https://upstream.test"),
				UsePathStyle:               true,
				Credentials:                credentials.NewStaticCredentialsProvider("test-ak", "test-sk", ""),
				RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
				HTTPClient: adminUploadIntegrityHTTPClient(func(r *http.Request) (*http.Response, error) {
					responseBody := ""
					header := make(http.Header)
					q := r.URL.Query()
					switch {
					case r.Method == http.MethodPost && q.Has("uploads"):
						created++
						responseBody = `<InitiateMultipartUploadResult><UploadId>integrity-upload</UploadId></InitiateMultipartUploadResult>`
					case r.Method == http.MethodPut && q.Get("uploadId") == "integrity-upload":
						n, err := io.Copy(io.Discard, r.Body)
						if err != nil {
							t.Fatalf("read upstream part: %v", err)
						}
						uploadedBytes += n
						header.Set("ETag", `"part-etag"`)
					case r.Method == http.MethodPost && q.Get("uploadId") == "integrity-upload":
						completed++
						responseBody = `<CompleteMultipartUploadResult><ETag>"final-etag"</ETag></CompleteMultipartUploadResult>`
					case r.Method == http.MethodPut && !q.Has("uploadId"):
						put++
						header.Set("ETag", `"empty-etag"`)
					case r.Method == http.MethodDelete && q.Get("uploadId") == "integrity-upload":
						aborted++
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
			for _, field := range [][2]string{{"name", "team2-logs"}, {"key", "existing.txt"}} {
				if err := mw.WriteField(field[0], field[1]); err != nil {
					t.Fatal(err)
				}
			}
			if tt.declaredSize != nil {
				if err := mw.WriteField("size", *tt.declaredSize); err != nil {
					t.Fatal(err)
				}
			}
			file, err := mw.CreateFormFile("file", "existing.txt")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(bytes.Repeat([]byte("x"), tt.payloadSize)); err != nil {
				t.Fatal(err)
			}
			switch tt.ending {
			case "missing":
				// Deliberately omit the closing boundary.
			case "incomplete":
				body.WriteString("\r\n--" + mw.Boundary() + "-")
			case "invalid suffix":
				body.WriteString("\r\n--" + mw.Boundary() + "--invalid\r\n")
			case "unfinished next part":
				body.WriteString("\r\n--" + mw.Boundary() + "\r\n")
			case "next delimiter":
				body.WriteString("\r\n--" + mw.Boundary())
			case "partial header":
				body.WriteString("\r\n--" + mw.Boundary() + "\r\nContent-Disposition: form-data;")
			case "field", "file":
				if tt.ending == "field" {
					err = mw.WriteField("size", "1000")
				} else {
					_, err = mw.CreateFormFile("file", "second.txt")
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := mw.Close(); err != nil {
					t.Fatal(err)
				}
			default:
				if err := mw.Close(); err != nil {
					t.Fatal(err)
				}
				if tt.ending == "no final newline" {
					body.Truncate(body.Len() - 2)
				}
			}

			r := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &body)
			r.Header.Set("Content-Type", mw.FormDataContentType())
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			location := parseRedirectLocation(t, w)
			if !tt.wantSuccess {
				if completed != 0 || put != 0 || len(notifier.events) != 0 {
					t.Errorf("invalid upload committed: complete=%d put=%d notifications=%d", completed, put, len(notifier.events))
				}
				if location.Query().Get("err") == "" || location.Query().Get("msg") != "" {
					t.Errorf("invalid upload did not report failure: %s", location)
				}
				if aborted != created {
					t.Errorf("unfinished uploads were not aborted: created=%d aborted=%d", created, aborted)
				}
				return
			}
			if location.Query().Get("err") != "" || location.Query().Get("msg") != "Uploaded object: existing.txt" {
				t.Fatalf("valid upload did not succeed: %s", location)
			}
			if completed+put != 1 || len(notifier.events) != 1 {
				t.Errorf("valid upload finalization: complete=%d put=%d notifications=%d", completed, put, len(notifier.events))
			}
			if uploadedBytes != int64(tt.payloadSize) {
				t.Errorf("uploaded %d bytes, want %d", uploadedBytes, tt.payloadSize)
			}
			if tt.payloadSize == 0 {
				if put != 1 || aborted != created {
					t.Errorf("empty upload cleanup: put=%d created=%d aborted=%d", put, created, aborted)
				}
			} else if completed != 1 || aborted != 0 {
				t.Errorf("completed upload was aborted: complete=%d aborted=%d", completed, aborted)
			}
		})
	}
}
