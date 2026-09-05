package adminpage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/define42/s3gateway/internal/uploadnotify"
	"github.com/define42/s3gateway/internal/upstream"
)

type recordingAdminUploadNotifier struct {
	events []uploadnotify.Event
	err    error
}

func (n *recordingAdminUploadNotifier) Notify(_ context.Context, event uploadnotify.Event) error {
	n.events = append(n.events, event)
	return n.err
}

func TestAdminUploadNotifications(t *testing.T) {
	tests := []struct {
		name          string
		payload       string
		notifierError error
		wantEventName uploadnotify.EventName
		wantETag      string
		wantVersionID string
		wantUploadID  string
	}{
		{
			name:          "multipart upload",
			payload:       "browser upload payload",
			wantEventName: uploadnotify.EventObjectCreatedCompleteMultipartUpload,
			wantETag:      "etag-complete",
			wantVersionID: "version-complete",
			wantUploadID:  "upload-1",
		},
		{
			name:          "empty file uses put event",
			wantEventName: uploadnotify.EventObjectCreatedPut,
			wantETag:      "etag-put",
			wantVersionID: "version-put",
		},
		{
			name:          "notification failure does not fail upload",
			payload:       "browser upload payload",
			notifierError: errors.New("kafka unavailable"),
			wantEventName: uploadnotify.EventObjectCreatedCompleteMultipartUpload,
			wantETag:      "etag-complete",
			wantVersionID: "version-complete",
			wantUploadID:  "upload-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const (
				bucket = "team2-logs"
				key    = "uploads/from-browser.txt"
			)
			var abortCalled bool
			gw, creds, cleanup := newTestHandler(t, func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				switch {
				case r.Method == http.MethodPost && query.Has("uploads"):
					w.Header().Set("Content-Type", "application/xml")
					_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>`+bucket+`</Bucket><Key>`+key+`</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`)
				case r.Method == http.MethodPut && query.Get("uploadId") == "upload-1":
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("ETag", `"etag-part"`)
					w.WriteHeader(http.StatusOK)
				case r.Method == http.MethodPost && query.Get("uploadId") == "upload-1":
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "application/xml")
					w.Header().Set("x-amz-version-id", "version-complete")
					_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>`+bucket+`</Bucket><Key>`+key+`</Key><ETag>"etag-complete"</ETag></CompleteMultipartUploadResult>`)
				case r.Method == http.MethodPut && query.Get("uploadId") == "":
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("ETag", `"etag-put"`)
					w.Header().Set("x-amz-version-id", "version-put")
					w.WriteHeader(http.StatusOK)
				case r.Method == http.MethodDelete && query.Get("uploadId") == "upload-1":
					abortCalled = true
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
				}
			})
			defer cleanup()

			notifier := &recordingAdminUploadNotifier{err: tt.notifierError}
			gw.uploadNotifier = notifier
			creds.set("alice", "secret", map[string]struct{}{"team2-w": {}})
			cookie := adminLoginSessionCookie(t, gw, "alice", "secret")

			req := buildAdminUploadRequest(t, bucket, key, tt.payload, nil)
			req.AddCookie(cookie)
			var completionProgress int
			req = req.WithContext(upstream.WithResponseProgress(req.Context(), func() {
				completionProgress++
			}))
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, req)
			if got, want := completionProgress > 0, tt.payload != ""; got != want {
				t.Fatalf("multipart completion progress reported = %t, want %t", got, want)
			}

			if rr.Code != http.StatusSeeOther {
				t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
			}
			location, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse redirect location: %v", err)
			}
			if got := location.Query().Get("msg"); got != "Uploaded object: "+key {
				t.Fatalf("upload message mismatch: got=%q error=%q", got, location.Query().Get("err"))
			}
			if len(notifier.events) != 1 {
				t.Fatalf("notification count = %d, want 1", len(notifier.events))
			}

			event := notifier.events[0]
			if event.SchemaVersion != uploadnotify.SchemaVersion ||
				event.EventName != tt.wantEventName ||
				event.Bucket != bucket ||
				event.Key != key ||
				event.ETag != tt.wantETag ||
				event.VersionID != tt.wantVersionID ||
				event.UploadID != tt.wantUploadID ||
				event.Uploader != "alice" ||
				event.OccurredAt.IsZero() {
				t.Fatalf("unexpected upload event: %+v", event)
			}
			if got, want := abortCalled, tt.payload == ""; got != want {
				t.Fatalf("abort called = %t, want %t", got, want)
			}
		})
	}
}

func TestWithUploadNotifier(t *testing.T) {
	notifier := &recordingAdminUploadNotifier{}
	got := NewHandlerWithContext(nil, "secret", 1, nil, nil, WithUploadNotifier(notifier))
	h, ok := got.(*handler)
	if !ok {
		t.Fatalf("handler type = %T, want *handler", got)
	}
	if h.uploadNotifier != notifier {
		t.Fatal("upload notifier option was not applied")
	}
}
