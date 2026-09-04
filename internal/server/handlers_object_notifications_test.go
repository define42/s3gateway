package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/uploadnotify"
)

func TestHandlePutObjectUploadNotification(t *testing.T) {
	t.Run("successful upload", func(t *testing.T) {
		notifier := &recordingUploadNotifier{}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("ETag", `"etag-put"`)
			w.Header().Set("x-amz-version-id", "version-put")
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/path/object.txt", strings.NewReader("payload"))
		req = reqWithRules(req, fullTeam2Rule())
		req = req.WithContext(context.WithValue(req.Context(), ctxUploaderKey, "alice@example.com"))
		rr := httptest.NewRecorder()
		gw.handlePutObject(rr, req, "team2-bucket", "path/object.txt")

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if len(notifier.events) != 1 {
			t.Fatalf("notification count = %d, want 1", len(notifier.events))
		}
		event := notifier.events[0]
		if event.SchemaVersion != uploadnotify.SchemaVersion || event.EventName != uploadnotify.EventObjectCreatedPut || event.Bucket != "team2-bucket" || event.Key != "path/object.txt" || event.ETag != "etag-put" || event.VersionID != "version-put" || event.Uploader != "alice@example.com" || event.OccurredAt.IsZero() {
			t.Fatalf("notification mismatch: %+v", event)
		}
	})

	t.Run("upstream failure", func(t *testing.T) {
		notifier := &recordingUploadNotifier{}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader("payload"))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutObject(rr, req, "team2-bucket", "object.txt")

		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusBadGateway, rr.Body.String())
		}
		if len(notifier.events) != 0 {
			t.Fatalf("notification count = %d, want 0", len(notifier.events))
		}
	})

	t.Run("notification failure remains best effort", func(t *testing.T) {
		notifier := &recordingUploadNotifier{err: errors.New("kafka unavailable")}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader("payload"))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutObject(rr, req, "team2-bucket", "object.txt")

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if len(notifier.events) != 1 {
			t.Fatalf("notification attempts = %d, want 1", len(notifier.events))
		}
	})
}

func TestHandleCopyObjectUploadNotification(t *testing.T) {
	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/path/copied.txt", nil)
		req.Header.Set("x-amz-copy-source", "/team2-src/source.txt")
		req = reqWithRules(req, fullTeam2Rule())
		return req.WithContext(context.WithValue(req.Context(), ctxUploaderKey, "alice@example.com"))
	}

	t.Run("successful copy", func(t *testing.T) {
		notifier := &recordingUploadNotifier{}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("ETag", `"header-etag"`)
			w.Header().Set("x-amz-version-id", "destination-version")
			w.Header().Set("x-amz-copy-source-version-id", "source-version")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<CopyObjectResult><ETag>"nested-etag"</ETag></CopyObjectResult>`))
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		startedAt := time.Now().UTC()
		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, newRequest(), "team2-dst", "path/copied.txt")
		finishedAt := time.Now().UTC()

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if len(notifier.events) != 1 {
			t.Fatalf("notification count = %d, want 1", len(notifier.events))
		}
		event := notifier.events[0]
		if event.SchemaVersion != uploadnotify.SchemaVersion || string(event.EventName) != "ObjectCreated:Copy" || event.Bucket != "team2-dst" || event.Key != "path/copied.txt" || event.ETag != "nested-etag" || event.VersionID != "destination-version" || event.Uploader != "alice@example.com" || event.UploadID != "" {
			t.Fatalf("notification mismatch: %+v", event)
		}
		if event.OccurredAt.IsZero() || event.OccurredAt.Before(startedAt) || event.OccurredAt.After(finishedAt) {
			t.Fatalf("notification time = %s, want between %s and %s", event.OccurredAt, startedAt, finishedAt)
		}
	})

	t.Run("upstream failure", func(t *testing.T) {
		notifier := &recordingUploadNotifier{}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, newRequest(), "team2-dst", "path/copied.txt")

		if rr.Code == http.StatusOK {
			t.Fatalf("status = %d, want an upstream error; body=%s", rr.Code, rr.Body.String())
		}
		if len(notifier.events) != 0 {
			t.Fatalf("notification count = %d, want 0", len(notifier.events))
		}
	})

	t.Run("embedded error in successful HTTP response", func(t *testing.T) {
		notifier := &recordingUploadNotifier{}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<Error><Code>InternalError</Code><Message>copy failed</Message></Error>`))
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, newRequest(), "team2-dst", "path/copied.txt")

		if rr.Code == http.StatusOK {
			t.Fatalf("status = %d, want the embedded error to fail the copy; body=%s", rr.Code, rr.Body.String())
		}
		if len(notifier.events) != 0 {
			t.Fatalf("notification count = %d, want 0", len(notifier.events))
		}
	})

	t.Run("notification failure remains best effort", func(t *testing.T) {
		notifier := &recordingUploadNotifier{err: errors.New("kafka unavailable")}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<CopyObjectResult><ETag>"etag-copy"</ETag></CopyObjectResult>`))
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, newRequest(), "team2-dst", "path/copied.txt")

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if len(notifier.events) != 1 {
			t.Fatalf("notification attempts = %d, want 1", len(notifier.events))
		}
	})

	t.Run("successful copy without result", func(t *testing.T) {
		notifier := &recordingUploadNotifier{}
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("x-amz-version-id", "destination-version")
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()
		gw.uploadNotifier = notifier

		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, newRequest(), "team2-dst", "path/copied.txt")

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
		}
		if len(notifier.events) != 1 {
			t.Fatalf("notification count = %d, want 1", len(notifier.events))
		}
		if event := notifier.events[0]; event.ETag != "" || event.VersionID != "destination-version" {
			t.Fatalf("notification mismatch: %+v", event)
		}
	})
}
