package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/uploadnotify"
)

func TestMultipartUploadNotifiedOnlyAfterCompletion(t *testing.T) {
	notifier := &recordingUploadNotifier{}
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		_, hasUploads := query["uploads"]
		switch {
		case r.Method == http.MethodPost && hasUploads:
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<InitiateMultipartUploadResult><Bucket>team2-bucket</Bucket><Key>large.bin</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`))
		case r.Method == http.MethodPut && query.Get("uploadId") == "upload-1":
			w.Header().Set("ETag", `"etag-part-1"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && query.Get("uploadId") == "upload-1":
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("x-amz-version-id", "version-complete")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<CompleteMultipartUploadResult><Bucket>team2-bucket</Bucket><Key>large.bin</Key><ETag>"etag-complete"</ETag></CompleteMultipartUploadResult>`))
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()
	gw.uploadNotifier = notifier

	withRequestContext := func(req *http.Request) *http.Request {
		req = reqWithRules(req, fullTeam2Rule())
		return req.WithContext(context.WithValue(req.Context(), ctxUploaderKey, "alice@example.com"))
	}

	createReq := withRequestContext(httptest.NewRequest(http.MethodPost, "/team2-bucket/large.bin?uploads", nil))
	createRR := httptest.NewRecorder()
	gw.handleCreateMultipart(createRR, createReq, "team2-bucket", "large.bin")
	if createRR.Code != http.StatusOK {
		t.Fatalf("create status = %d, want %d; body=%s", createRR.Code, http.StatusOK, createRR.Body.String())
	}
	if len(notifier.events) != 0 {
		t.Fatalf("notification count after create = %d, want 0", len(notifier.events))
	}

	partReq := withRequestContext(httptest.NewRequest(http.MethodPut, "/team2-bucket/large.bin?partNumber=1&uploadId=upload-1", strings.NewReader("part one")))
	partRR := httptest.NewRecorder()
	gw.handleUploadPart(partRR, partReq, "team2-bucket", "large.bin", "upload-1", 1)
	if partRR.Code != http.StatusOK {
		t.Fatalf("upload part status = %d, want %d; body=%s", partRR.Code, http.StatusOK, partRR.Body.String())
	}
	if len(notifier.events) != 0 {
		t.Fatalf("notification count after part upload = %d, want 0", len(notifier.events))
	}

	completeBody := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"etag-part-1"</ETag></Part></CompleteMultipartUpload>`
	completeReq := withRequestContext(httptest.NewRequest(http.MethodPost, "/team2-bucket/large.bin?uploadId=upload-1", strings.NewReader(completeBody)))
	completeRR := httptest.NewRecorder()
	gw.handleCompleteMultipart(completeRR, completeReq, "team2-bucket", "large.bin", "upload-1")
	if completeRR.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want %d; body=%s", completeRR.Code, http.StatusOK, completeRR.Body.String())
	}
	if len(notifier.events) != 1 {
		t.Fatalf("notification count after completion = %d, want 1", len(notifier.events))
	}

	event := notifier.events[0]
	if event.SchemaVersion != uploadnotify.SchemaVersion || event.EventName != uploadnotify.EventObjectCreatedCompleteMultipartUpload || event.Bucket != "team2-bucket" || event.Key != "large.bin" || event.ETag != "etag-complete" || event.VersionID != "version-complete" || event.UploadID != "upload-1" || event.Uploader != "alice@example.com" || event.OccurredAt.IsZero() {
		t.Fatalf("notification mismatch: %+v", event)
	}
}

func TestMultipartCopyNotifiedOnlyAfterCompletion(t *testing.T) {
	notifier := &recordingUploadNotifier{}
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		switch {
		case r.Method == http.MethodPut && query.Get("uploadId") == "copy-upload-1":
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<CopyPartResult><ETag>"etag-copy-part-1"</ETag></CopyPartResult>`))
		case r.Method == http.MethodPost && query.Get("uploadId") == "copy-upload-1":
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("x-amz-version-id", "version-copy-complete")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<CompleteMultipartUploadResult><Bucket>team2-destination</Bucket><Key>copied/large.bin</Key><ETag>"etag-copy-complete"</ETag></CompleteMultipartUploadResult>`))
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()
	gw.uploadNotifier = notifier

	withRequestContext := func(req *http.Request) *http.Request {
		req = reqWithRules(req, fullTeam2Rule())
		return req.WithContext(context.WithValue(req.Context(), ctxUploaderKey, "alice@example.com"))
	}

	partReq := withRequestContext(httptest.NewRequest(http.MethodPut, "/team2-destination/copied/large.bin?partNumber=1&uploadId=copy-upload-1", nil))
	partReq.Header.Set("x-amz-copy-source", "/team2-source/source.bin")
	partRR := httptest.NewRecorder()
	gw.handleUploadPartCopy(partRR, partReq, "team2-destination", "copied/large.bin", "copy-upload-1", 1)
	if partRR.Code != http.StatusOK {
		t.Fatalf("upload part copy status = %d, want %d; body=%s", partRR.Code, http.StatusOK, partRR.Body.String())
	}
	if len(notifier.events) != 0 {
		t.Fatalf("notification count after part copy = %d, want 0", len(notifier.events))
	}

	completeBody := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"etag-copy-part-1"</ETag></Part></CompleteMultipartUpload>`
	completeReq := withRequestContext(httptest.NewRequest(http.MethodPost, "/team2-destination/copied/large.bin?uploadId=copy-upload-1", strings.NewReader(completeBody)))
	completeRR := httptest.NewRecorder()
	gw.handleCompleteMultipart(completeRR, completeReq, "team2-destination", "copied/large.bin", "copy-upload-1")
	if completeRR.Code != http.StatusOK {
		t.Fatalf("complete status = %d, want %d; body=%s", completeRR.Code, http.StatusOK, completeRR.Body.String())
	}
	if len(notifier.events) != 1 {
		t.Fatalf("notification count after completion = %d, want 1", len(notifier.events))
	}

	event := notifier.events[0]
	if event.SchemaVersion != uploadnotify.SchemaVersion || event.EventName != uploadnotify.EventObjectCreatedCompleteMultipartUpload || event.Bucket != "team2-destination" || event.Key != "copied/large.bin" || event.ETag != "etag-copy-complete" || event.VersionID != "version-copy-complete" || event.UploadID != "copy-upload-1" || event.Uploader != "alice@example.com" || event.OccurredAt.IsZero() {
		t.Fatalf("notification mismatch: %+v", event)
	}
}
