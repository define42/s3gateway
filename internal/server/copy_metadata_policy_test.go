package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authz "github.com/define42/s3gateway/internal/authz"
)

// reqWithRulesAndUploader mirrors what WithAuth installs on the request context:
// the authz rules plus the authenticated uploader UPN.
func reqWithRulesAndUploader(req *http.Request, rules []authz.Rule, uploader string) *http.Request {
	ctx := authz.WithRules(req.Context(), rules)
	ctx = context.WithValue(ctx, ctxUploaderKey, uploader)
	return req.WithContext(ctx)
}

// TestCopyObjectMetadataPolicy verifies that CopyObject honours the same
// upload-metadata policy as PutObject when the caller replaces metadata, and
// leaves the default (COPY directive) path untouched. Regression coverage for
// the copy-path bypass called out in REVIEW.md (F-6).
func TestCopyObjectMetadataPolicy(t *testing.T) {
	newCopyReq := func(directive string) *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/copied.txt", nil)
		req.Header.Set("x-amz-copy-source", "/team2-src/source.txt")
		if directive != "" {
			req.Header.Set("x-amz-metadata-directive", directive)
		}
		return reqWithRulesAndUploader(req, fullTeam2Rule(), "testuser")
	}

	t.Run("replace directive enforces required metadata", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called when required metadata is missing: %s %s", r.Method, r.URL.String())
		})
		defer cleanup()
		gw.cfg.RequiredUploadMetadataKeys = []string{"legal-ingest-timestamp", "case-id"}

		req := newCopyReq("REPLACE")
		req.Header.Set("x-amz-meta-legal-ingest-timestamp", "2026-02-07T12:34:56Z")
		// case-id intentionally omitted.

		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, req, "team2-dst", "copied.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "x-amz-meta-case-id") {
			t.Fatalf("expected missing required metadata key in body: %s", rr.Body.String())
		}
	})

	t.Run("replace directive stamps uploaded-by and cannot be spoofed", func(t *testing.T) {
		var gotUploadedBy string
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			gotUploadedBy = r.Header.Get("x-amz-meta-uploaded-by")
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult><ETag>"etag-copied"</ETag></CopyObjectResult>`))
		})
		defer cleanup()

		req := newCopyReq("REPLACE")
		// Client attempts to spoof the uploader; the gateway must override it.
		req.Header.Set("x-amz-meta-uploaded-by", "attacker")

		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, req, "team2-dst", "copied.txt")
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
		if gotUploadedBy != "testuser" {
			t.Fatalf("uploaded-by metadata mismatch: got=%q want=%q", gotUploadedBy, "testuser")
		}
	})

	t.Run("copy directive inherits source metadata and does not enforce required keys", func(t *testing.T) {
		called := false
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			called = true
			// With the COPY directive S3 ignores request metadata, so the gateway
			// must not forward a stamped uploaded-by header.
			if v := r.Header.Get("x-amz-meta-uploaded-by"); v != "" {
				t.Fatalf("copy directive should not stamp uploaded-by, got %q", v)
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult><ETag>"etag-copied"</ETag></CopyObjectResult>`))
		})
		defer cleanup()
		gw.cfg.RequiredUploadMetadataKeys = []string{"legal-ingest-timestamp"}

		// Default directive (COPY): no metadata headers, required keys not supplied.
		req := newCopyReq("")

		rr := httptest.NewRecorder()
		gw.handleCopyObject(rr, req, "team2-dst", "copied.txt")
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
		if !called {
			t.Fatalf("expected upstream CopyObject to be called for the COPY directive path")
		}
	})
}
