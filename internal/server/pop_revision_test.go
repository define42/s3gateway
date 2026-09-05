package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/define42/s3gateway/internal/uploadnotify"
)

func TestHandlePopAPIPreservesEventRevision(t *testing.T) {
	const (
		originalBody = "original upload A"
		laterBody    = "later overwrite B"
		eventID      = "event-for-upload-a"
	)
	for _, tt := range []struct {
		name        string
		method      string
		scope       string
		attempts    int
		versionID   string
		etag        string
		currentETag string
		deleted     bool
		wantMatch   string
		wantStatus  int
		wantCode    string
		wantReads   int
	}{
		{
			name: "overwritten unversioned event stays pending", attempts: 2,
			etag: "revision-a", currentETag: `"revision-b"`,
			wantMatch: `"revision-a"`, wantStatus: http.StatusPreconditionFailed,
			wantCode: "PreconditionFailed", wantReads: 2,
		},
		{
			name: "matching unquoted event ETag", etag: "revision-a",
			wantMatch: `"revision-a"`, wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "matching quoted event ETag", etag: `"revision-a"`,
			wantMatch: `"revision-a"`, wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "global POST uses conditional read", method: http.MethodPost, scope: "_all", etag: "revision-a",
			wantMatch: `"revision-a"`, wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "matching multipart ETag", etag: "d41d8cd98f00b204e9800998ecf8427e-2",
			currentETag: `"d41d8cd98f00b204e9800998ecf8427e-2"`,
			wantMatch:   `"d41d8cd98f00b204e9800998ecf8427e-2"`, wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "overwritten null version", versionID: "null", etag: "revision-a", currentETag: `"revision-b"`,
			wantMatch: `"revision-a"`, wantStatus: http.StatusPreconditionFailed,
			wantCode: "PreconditionFailed", wantReads: 1,
		},
		{
			name: "matching null version", versionID: "null", etag: "revision-a",
			wantMatch: `"revision-a"`, wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "immutable version without ETag", versionID: "version-a", currentETag: `"revision-b"`,
			wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "immutable version preserved literally", versionID: " version-a ",
			wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "immutable version does not need conditional ETag", versionID: "version-a", etag: "*",
			wantStatus: http.StatusOK, wantReads: 1,
		},
		{
			name: "deleted unversioned object", etag: "revision-a", deleted: true,
			wantMatch: `"revision-a"`, wantStatus: http.StatusNotFound, wantCode: "NoSuchKey", wantReads: 1,
		},
		{
			name: "deleted immutable version", versionID: "version-a", deleted: true,
			wantStatus: http.StatusNotFound, wantCode: "NoSuchVersion", wantReads: 1,
		},
		{name: "missing ETag and version", wantStatus: http.StatusBadGateway},
		{name: "null version without ETag", versionID: "null", wantStatus: http.StatusBadGateway},
		{name: "empty quoted ETag", etag: `""`, wantStatus: http.StatusBadGateway},
		{name: "wildcard ETag", etag: "*", wantStatus: http.StatusBadGateway},
		{name: "quoted wildcard ETag", etag: `"*"`, wantStatus: http.StatusBadGateway},
		{name: "weak ETag", etag: `W/"revision-a"`, wantStatus: http.StatusBadGateway},
		{name: "ETag list", etag: `"revision-a", "revision-b"`, wantStatus: http.StatusBadGateway},
		{name: "unquoted ETag list", etag: "revision-a,revision-b", wantStatus: http.StatusBadGateway},
		{name: "unterminated quoted ETag", etag: `"revision-a`, wantStatus: http.StatusBadGateway},
		{name: "embedded quote", etag: `revision"a`, wantStatus: http.StatusBadGateway},
		{name: "ETag with CRLF", etag: "revision-a\r\nIf-Match: *", wantStatus: http.StatusBadGateway},
		{name: "ETag with internal space", etag: "revision a", wantStatus: http.StatusBadGateway},
		{name: "padded ETag", etag: " revision-a ", wantStatus: http.StatusBadGateway},
		{name: "ETag with control byte", etag: "revision-\x7fa", wantStatus: http.StatusBadGateway},
		{name: "non-ASCII ETag", etag: "revision-\u00e5", wantStatus: http.StatusBadGateway},
		{name: "oversized ETag", etag: strings.Repeat("a", 4097), wantStatus: http.StatusBadGateway},
	} {
		t.Run(tt.name, func(t *testing.T) {
			currentETag := tt.currentETag
			if currentETag == "" {
				currentETag = `"revision-a"`
			}
			type upstreamRead struct {
				ifMatch   string
				versionID string
			}
			var (
				mu    sync.Mutex
				reads []upstreamRead
			)
			gateway, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				reads = append(reads, upstreamRead{
					ifMatch: r.Header.Get("If-Match"), versionID: r.URL.Query().Get("versionId"),
				})
				mu.Unlock()
				if r.Method != http.MethodGet || r.URL.Path != "/team2-images/path/object.txt" {
					t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if tt.deleted {
					code := "NoSuchKey"
					if tt.versionID != "" {
						code = "NoSuchVersion"
					}
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte("<Error><Code>" + code + "</Code><Message>Deleted</Message></Error>"))
					return
				}
				if version := r.URL.Query().Get("versionId"); version != "" && version != "null" {
					w.Header().Set("x-amz-version-id", version)
					w.Header().Set("ETag", `"revision-a"`)
					_, _ = w.Write([]byte(originalBody))
					return
				}
				if match := r.Header.Get("If-Match"); match != "" && match != currentETag {
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = w.Write([]byte("<Error><Code>PreconditionFailed</Code><Message>Overwritten</Message></Error>"))
					return
				}
				w.Header().Set("ETag", currentETag)
				body := originalBody
				if currentETag == `"revision-b"` {
					body = laterBody
				}
				_, _ = w.Write([]byte(body))
			})
			defer cleanup()

			scope, rules := tt.scope, fullTeam2Rule()
			if scope == "" {
				scope = "team2-images"
			} else if scope == "_all" {
				rules = allBucketsReadRules()
			}
			consumer := &fakePopConsumer{record: popRecord(t, scope, uploadnotify.Event{
				EventID: eventID, EventName: uploadnotify.EventObjectCreatedPut,
				Bucket: "team2-images", Key: "path/object.txt", VersionID: tt.versionID, ETag: tt.etag,
			})}
			configurePopGateway(gateway, consumer)
			method := tt.method
			if method == "" {
				method = http.MethodGet
			}
			var response *httptest.ResponseRecorder
			for range max(tt.attempts, 1) {
				request := reqWithRulesAndUploader(
					httptest.NewRequest(method, "/api/pop/"+scope+"/scanner", nil), rules, "alice",
				)
				response = httptest.NewRecorder()
				gateway.ServeHTTP(response, request)
			}

			if response.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body=%q", response.Code, tt.wantStatus, response.Body.String())
			}
			if tt.wantCode != "" && !strings.Contains(response.Body.String(), "<Code>"+tt.wantCode+"</Code>") {
				t.Errorf("error body = %q, want code %s", response.Body.String(), tt.wantCode)
			}
			if strings.Contains(response.Body.String(), laterBody) {
				t.Errorf("delivered a later revision under event %q", eventID)
			}
			if tt.wantStatus == http.StatusOK {
				if response.Body.String() != originalBody || response.Header().Get("X-S3Gateway-Event-ID") != eventID {
					t.Errorf("successful pop = %q, event %q; want original upload and its event ID",
						response.Body.String(), response.Header().Get("X-S3Gateway-Event-ID"))
				}
				if !response.Flushed {
					t.Error("successful response was not flushed")
				}
			} else if got := response.Header().Get("X-S3Gateway-Event-ID"); got != "" {
				t.Errorf("failed pop claims to deliver event %q", got)
			}

			consumer.mu.Lock()
			acknowledged, handleErr := consumer.acknowledged, consumer.handleErr
			consumer.mu.Unlock()
			wantAcknowledged := tt.wantStatus == http.StatusOK
			if acknowledged != wantAcknowledged || (handleErr == nil) != wantAcknowledged {
				t.Errorf("acknowledged=%t, handler error=%v; want acknowledged=%t",
					acknowledged, handleErr, wantAcknowledged)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(reads) != tt.wantReads {
				t.Errorf("upstream reads = %d, want %d", len(reads), tt.wantReads)
			}
			for _, read := range reads {
				if read.ifMatch != tt.wantMatch || read.versionID != tt.versionID {
					t.Errorf("upstream If-Match=%q versionId=%q; want %q and %q",
						read.ifMatch, read.versionID, tt.wantMatch, tt.versionID)
				}
			}
		})
	}
}
