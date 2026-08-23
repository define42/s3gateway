package adminpage

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

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
