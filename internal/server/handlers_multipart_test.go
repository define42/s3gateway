package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/s3xml"
)

func completeMultipartDocument(count int, etag string) string {
	var body strings.Builder
	body.WriteString("<CompleteMultipartUpload>")
	for range count {
		body.WriteString("<Part><PartNumber>1</PartNumber><ETag>")
		body.WriteString(etag)
		body.WriteString("</ETag></Part>")
	}
	body.WriteString("</CompleteMultipartUpload>")
	return body.String()
}

func TestDecodeCompleteMultipartUploadLimits(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantErr   error
		wantParts int
	}{
		{
			name:      "accepts ten thousand parts",
			body:      completeMultipartDocument(maxCompleteMultipartParts, "etag"),
			wantParts: maxCompleteMultipartParts,
		},
		{
			name:      "rejects part ten thousand and one before append",
			body:      completeMultipartDocument(maxCompleteMultipartParts+1, "etag"),
			wantErr:   s3xml.ErrXMLElementLimit,
			wantParts: maxCompleteMultipartParts,
		},
		{
			name:    "rejects oversized etag",
			body:    completeMultipartDocument(1, strings.Repeat("e", maxCompleteMultipartETagBytes+1)),
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
		{
			name:    "rejects oversized body",
			body:    "<CompleteMultipartUpload>" + strings.Repeat(" ", int(maxCompleteMultipartBodyBytes)) + "</CompleteMultipartUpload>",
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeCompleteMultipartUpload(strings.NewReader(tc.body))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("decodeCompleteMultipartUpload() error = %v, want %v", err, tc.wantErr)
			}
			if len(got.Parts) != tc.wantParts {
				t.Fatalf("decodeCompleteMultipartUpload() appended %d parts, want %d", len(got.Parts), tc.wantParts)
			}
		})
	}
}

func TestHandleCompleteMultipartConditionalHeaders(t *testing.T) {
	tests := []struct {
		name       string
		header     string
		value      string
		wantStatus int
		wantCode   string
	}{
		{
			name:       "unconditional completion",
			wantStatus: http.StatusOK,
		},
		{
			name:       "matching etag",
			header:     "If-Match",
			value:      `"current-etag"`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "create only",
			header:     "If-None-Match",
			value:      "*",
			wantStatus: http.StatusOK,
		},
		{
			name:       "stale etag",
			header:     "If-Match",
			value:      `"stale-etag"`,
			wantStatus: http.StatusPreconditionFailed,
			wantCode:   "PreconditionFailed",
		},
		{
			name:       "object already exists",
			header:     "If-None-Match",
			value:      "*",
			wantStatus: http.StatusPreconditionFailed,
			wantCode:   "PreconditionFailed",
		},
		{
			name:       "conflicting upload",
			header:     "If-None-Match",
			value:      "*",
			wantStatus: http.StatusConflict,
			wantCode:   "ConditionalRequestConflict",
		},
		{
			name:       "blank condition",
			header:     "If-Match",
			value:      " \t ",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			upstreamHeaders := make(chan http.Header, 1)
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamHeaders <- r.Header.Clone()
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(tc.wantStatus)
				if tc.wantCode != "" {
					_, _ = w.Write([]byte(`<Error><Code>` + tc.wantCode + `</Code><Message>condition failed</Message></Error>`))
					return
				}
				_, _ = w.Write([]byte(`<CompleteMultipartUploadResult><ETag>"completed-etag"</ETag></CompleteMultipartUploadResult>`))
			})
			defer cleanup()
			notifier := &recordingUploadNotifier{}
			gw.uploadNotifier = notifier

			req := httptest.NewRequest(
				http.MethodPost,
				"/team2-dst/report?uploadId=upload-1",
				strings.NewReader(completeMultipartDocument(1, "part-etag")),
			)
			if tc.header != "" {
				req.Header.Set(tc.header, tc.value)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if tc.wantCode != "" && !strings.Contains(rr.Body.String(), "<Code>"+tc.wantCode+"</Code>") {
				t.Errorf("missing error code %q in response: %s", tc.wantCode, rr.Body.String())
			}
			select {
			case headers := <-upstreamHeaders:
				for _, name := range []string{"If-Match", "If-None-Match"} {
					var want string
					if name == tc.header {
						want = strings.TrimSpace(tc.value)
					}
					if got := headers.Get(name); got != want {
						t.Errorf("upstream %s = %q, want %q", name, got, want)
					}
					if want == "" && len(headers.Values(name)) != 0 {
						t.Errorf("unexpected upstream %s header: %q", name, headers.Values(name))
					}
				}
			default:
				t.Fatal("completion request did not reach upstream")
			}
			var wantNotifications int
			if tc.wantStatus == http.StatusOK {
				wantNotifications = 1
			}
			if got := len(notifier.events); got != wantNotifications {
				t.Errorf("notification count = %d, want %d", got, wantNotifications)
			}
		})
	}
}

func TestHandleCompleteMultipartRejectsConflictingConditions(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("conflicting conditions must be rejected before reaching upstream")
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<CompleteMultipartUploadResult/>`))
	})
	defer cleanup()
	notifier := &recordingUploadNotifier{}
	gw.uploadNotifier = notifier

	req := httptest.NewRequest(
		http.MethodPost,
		"/team2-dst/report?uploadId=upload-1",
		strings.NewReader(completeMultipartDocument(1, "part-etag")),
	)
	req.Header.Set("If-Match", `"current-etag"`)
	req.Header.Set("If-None-Match", "*")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidRequest</Code>") {
		t.Fatalf("expected InvalidRequest; status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if got := len(notifier.events); got != 0 {
		t.Errorf("notification count = %d, want 0", got)
	}
}
