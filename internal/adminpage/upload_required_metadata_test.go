package adminpage

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

type trackedMultipartReader struct {
	data           []byte
	position       int
	metadataOffset int
	readMetadata   bool
}

func (r *trackedMultipartReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.position >= len(r.data) {
		return 0, io.EOF
	}
	if r.position >= r.metadataOffset {
		r.readMetadata = true
	}
	p[0] = r.data[r.position]
	r.position++
	return 1, nil
}

// buildAdminUploadRequest builds a multipart upload request for the admin UI,
// placing any metadata fields before the file part (as the HTML form renders
// them) so the streaming handler sees them first.
func buildAdminUploadRequest(t *testing.T, bucket, key, payload string, meta map[string]string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("name", bucket)
	_ = w.WriteField("key", key)
	_ = w.WriteField("cursor", "")
	_ = w.WriteField("history", "")
	_ = w.WriteField("size", strconv.Itoa(len(payload)))
	for k, v := range meta {
		_ = w.WriteField("meta-"+k, v)
	}
	filePart, err := w.CreateFormFile("file", "new.txt")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := filePart.Write([]byte(payload)); err != nil {
		t.Fatalf("write multipart payload: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

// TestAdminUploadRequiredMetadata verifies the admin upload path enforces
// REQUIRED_UPLOAD_METADATA_KEYS just like the S3 API (REVIEW.md F-6 #2).
func TestAdminUploadRequiredMetadata(t *testing.T) {
	t.Run("missing required key is rejected before any upstream call", func(t *testing.T) {
		gw, creds, cleanup := newTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream must not be called when required metadata is missing: %s %s", r.Method, r.URL.String())
		})
		defer cleanup()
		gw.requiredUploadMetadataKeys = []string{"case-id"}

		creds.set("alice", "secret", map[string]struct{}{"team2-wd": {}})
		cookie := adminLoginSessionCookie(t, gw, "alice", "secret")

		req := buildAdminUploadRequest(t, "team2-logs", "uploads/new.txt", "payload-123", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
		}
		loc, err := url.Parse(rr.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse location: %v", err)
		}
		if got := loc.Query().Get("err"); got == "" || !bytes.Contains([]byte(got), []byte("case-id")) {
			t.Fatalf("expected missing-metadata error naming case-id, got err=%q", got)
		}
	})

	t.Run("required key present is forwarded to upstream", func(t *testing.T) {
		const uploadID = "upload-meta-1"
		var createCaseID, createUploadedBy string
		gw, creds, cleanup := newTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			switch {
			case r.Method == http.MethodPost && q.Has("uploads"):
				createCaseID = r.Header.Get("x-amz-meta-case-id")
				createUploadedBy = r.Header.Get("x-amz-meta-uploaded-by")
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/new.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
			case r.Method == http.MethodPut && q.Get("uploadId") == uploadID:
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("ETag", `"etag-part-1"`)
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodPost && q.Get("uploadId") == uploadID:
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/new.txt</Key><ETag>"etag-uploaded"</ETag></CompleteMultipartUploadResult>`)
			default:
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
		})
		defer cleanup()
		gw.requiredUploadMetadataKeys = []string{"case-id"}

		creds.set("alice", "secret", map[string]struct{}{"team2-wd": {}})
		cookie := adminLoginSessionCookie(t, gw, "alice", "secret")

		req := buildAdminUploadRequest(t, "team2-logs", "uploads/new.txt", "payload-123", map[string]string{
			"case-id": "CASE-42",
		})
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
		}
		loc, err := url.Parse(rr.Header().Get("Location"))
		if err != nil {
			t.Fatalf("parse location: %v", err)
		}
		if msg := loc.Query().Get("msg"); msg != "Uploaded object: uploads/new.txt" {
			t.Fatalf("upload message mismatch: got=%q err=%q", msg, loc.Query().Get("err"))
		}
		if createCaseID != "CASE-42" {
			t.Fatalf("case-id metadata not forwarded: got=%q want=%q", createCaseID, "CASE-42")
		}
		if createUploadedBy != "alice" {
			t.Fatalf("uploaded-by metadata mismatch: got=%q want=%q", createUploadedBy, "alice")
		}
	})
}

func TestAdminUploadMetadataLimits(t *testing.T) {
	handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.String())
	})
	defer cleanup()

	tests := []struct {
		name         string
		writeFields  func(*multipart.Writer) error
		wantLocation string
		wantError    string
	}{
		{
			name: "metadata requires an authorized bucket first",
			writeFields: func(w *multipart.Writer) error {
				if err := w.WriteField("meta-case-id", "CASE-42"); err != nil {
					return err
				}
				return w.WriteField("name", "team2-logs")
			},
			wantLocation: "/admin",
		},
		{
			name: "part count at limit",
			writeFields: func(w *multipart.Writer) error {
				for i := 1; i < maxAdminUploadParts; i++ {
					if err := w.WriteField(fmt.Sprintf("ignored-%d", i), ""); err != nil {
						return err
					}
				}
				return nil
			},
			wantError: "A file is required for upload.",
		},
		{
			name: "part count above limit",
			writeFields: func(w *multipart.Writer) error {
				for i := range maxAdminUploadParts {
					if err := w.WriteField(fmt.Sprintf("ignored-%d", i), ""); err != nil {
						return err
					}
				}
				return nil
			},
			wantError: "Could not process upload payload.",
		},
		{
			name: "metadata count at limit",
			writeFields: func(w *multipart.Writer) error {
				for i := range maxAdminUploadMetadataFields {
					if err := w.WriteField(fmt.Sprintf("meta-key-%d", i), ""); err != nil {
						return err
					}
				}
				return nil
			},
			wantError: "A file is required for upload.",
		},
		{
			name: "metadata count above limit",
			writeFields: func(w *multipart.Writer) error {
				for i := 0; i <= maxAdminUploadMetadataFields; i++ {
					if err := w.WriteField(fmt.Sprintf("meta-key-%d", i), ""); err != nil {
						return err
					}
				}
				return nil
			},
			wantError: "Could not process upload payload.",
		},
		{
			name: "metadata key at limit",
			writeFields: func(w *multipart.Writer) error {
				return w.WriteField("meta-"+strings.Repeat("k", maxAdminUploadMetadataKeyBytes), "value")
			},
			wantError: "A file is required for upload.",
		},
		{
			name: "metadata key above limit",
			writeFields: func(w *multipart.Writer) error {
				return w.WriteField("meta-"+strings.Repeat("k", maxAdminUploadMetadataKeyBytes+1), "value")
			},
			wantError: "Could not process upload payload.",
		},
		{
			name: "metadata value at limit",
			writeFields: func(w *multipart.Writer) error {
				return w.WriteField("meta-key", strings.Repeat("v", int(maxAdminUploadMetadataValueBytes)))
			},
			wantError: "A file is required for upload.",
		},
		{
			name: "metadata value above limit",
			writeFields: func(w *multipart.Writer) error {
				return w.WriteField("meta-key", strings.Repeat("v", int(maxAdminUploadMetadataValueBytes)+1))
			},
			wantError: "Could not process upload payload.",
		},
		{
			name: "aggregate metadata at limit",
			writeFields: func(w *multipart.Writer) error {
				for _, key := range []string{"a", "b", "c", "d"} {
					if err := w.WriteField("meta-"+key, strings.Repeat("v", maxAdminUploadMetadataBytes/4-1)); err != nil {
						return err
					}
				}
				return nil
			},
			wantError: "A file is required for upload.",
		},
		{
			name: "aggregate metadata above limit",
			writeFields: func(w *multipart.Writer) error {
				for i, key := range []string{"a", "b", "c", "d"} {
					valueSize := maxAdminUploadMetadataBytes/4 - 1
					if i == 3 {
						valueSize++
					}
					if err := w.WriteField("meta-"+key, strings.Repeat("v", valueSize)); err != nil {
						return err
					}
				}
				return nil
			},
			wantError: "Could not process upload payload.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			if tt.wantLocation == "" {
				if err := writer.WriteField("name", "team2-logs"); err != nil {
					t.Fatalf("write bucket field: %v", err)
				}
			}
			if err := tt.writeFields(writer); err != nil {
				t.Fatalf("write multipart fields: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close multipart body: %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &body)
			req.Header.Set("Content-Type", writer.FormDataContentType())
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusSeeOther {
				t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
			}
			location, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse redirect location: %v", err)
			}
			if tt.wantLocation != "" {
				if location.String() != tt.wantLocation {
					t.Fatalf("location mismatch: got=%q want=%q", location.String(), tt.wantLocation)
				}
				return
			}
			if got := location.Query().Get("err"); got != tt.wantError {
				t.Fatalf("error mismatch: got=%q want=%q", got, tt.wantError)
			}
		})
	}
}

func TestAdminUploadAuthorizesBucketBeforeReadingMetadata(t *testing.T) {
	handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.String())
	})
	defer cleanup()

	const metadataValue = "SENSITIVE-METADATA-VALUE"
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("name", "team2-logs"); err != nil {
		t.Fatalf("write bucket field: %v", err)
	}
	if err := writer.WriteField("meta-case-id", metadataValue); err != nil {
		t.Fatalf("write metadata field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart body: %v", err)
	}
	metadataOffset := bytes.Index(body.Bytes(), []byte(metadataValue))
	if metadataOffset < 0 {
		t.Fatal("metadata value not found in multipart test body")
	}
	trackedBody := &trackedMultipartReader{
		data:           body.Bytes(),
		metadataOffset: metadataOffset,
	}

	req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", trackedBody)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if got := location.Query().Get("err"); got != "Write permission is required for uploads." {
		t.Fatalf("error mismatch: got=%q", got)
	}
	if trackedBody.readMetadata {
		t.Fatal("metadata body was read before bucket write authorization")
	}
}
