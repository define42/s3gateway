package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestEncryptionHeadersRejectedBeforeDispatch(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	t.Cleanup(cleanup)

	for _, tc := range []struct {
		name, method, target string
		copy                 bool
	}{
		{name: "put", method: http.MethodPut, target: "/team2-bucket/key"},
		{name: "get", method: http.MethodGet, target: "/team2-bucket/key"},
		{name: "head", method: http.MethodHead, target: "/team2-bucket/key"},
		{name: "attributes", method: http.MethodGet, target: "/team2-bucket/key?attributes"},
		{name: "copy", method: http.MethodPut, target: "/team2-bucket/key", copy: true},
		{name: "initiate multipart", method: http.MethodPost, target: "/team2-bucket/key?uploads"},
		{name: "upload part", method: http.MethodPut, target: "/team2-bucket/key?uploadId=id&partNumber=1"},
		{name: "copy part", method: http.MethodPut, target: "/team2-bucket/key?uploadId=id&partNumber=1", copy: true},
		{name: "complete multipart", method: http.MethodPost, target: "/team2-bucket/key?uploadId=id"},
		{name: "list parts", method: http.MethodGet, target: "/team2-bucket/key?uploadId=id"},
		{name: "list uploads", method: http.MethodGet, target: "/team2-bucket?uploads"},
		{name: "abort multipart", method: http.MethodDelete, target: "/team2-bucket/key?uploadId=id"},
		{name: "pop", method: http.MethodPost, target: "/api/pop/team2-bucket/scanner"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const body = "body must remain unread"
			reader := strings.NewReader(body)
			req := httptest.NewRequest(tc.method, tc.target, reader)
			req.Header.Set("x-amz-server-side-encryption-customer-key", "private-test-key")
			if tc.copy {
				req.Header.Set("x-amz-copy-source", "/team2-bucket/source")
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "<Code>NotImplemented</Code>") {
				t.Fatalf("status=%d body=%s, want 501 NotImplemented", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "private-test-key") {
				t.Error("response exposes the supplied encryption key")
			}
			if reader.Len() != len(body) {
				t.Error("rejected encryption request body was read")
			}
			if got := upstreamCalls.Load(); got != 0 {
				t.Fatalf("rejected encryption request reached upstream %d times", got)
			}
		})
	}
}

func TestEncryptionHeaderPresence(t *testing.T) {
	for _, name := range []string{
		"x-amz-server-side-encryption",
		"x-amz-server-side-encryption-aws-kms-key-id",
		"x-amz-server-side-encryption-context",
		"x-amz-server-side-encryption-bucket-key-enabled",
		"x-amz-server-side-encryption-customer-algorithm",
		"x-amz-server-side-encryption-customer-key",
		"x-amz-server-side-encryption-customer-key-md5",
		"x-amz-copy-source-server-side-encryption-customer-algorithm",
		"x-amz-copy-source-server-side-encryption-customer-key",
		"x-amz-copy-source-server-side-encryption-customer-key-md5",
		"X-aMz-SeRvEr-SiDe-EnCrYpTiOn",
		"x-amz-server-side-encryption-unknown-option",
		"x-amz-copy-source-server-side-encryption-unknown-option",
	} {
		t.Run(name, func(t *testing.T) {
			for _, values := range [][]string{nil, {""}, {"AES256"}, {"aws:kms:dsse"}, {"", "secret"}} {
				req := httptest.NewRequest(http.MethodPut, "/team2-bucket/key", nil)
				// Set the map directly to cover non-canonical keys and empty values.
				req.Header[name] = values
				rr := httptest.NewRecorder()
				if requireNoEncryptionRequestHeaders(rr, req) || rr.Code != http.StatusNotImplemented {
					t.Fatalf("values=%q: status=%d, want rejected with 501", values, rr.Code)
				}
			}
		})
	}
}

func TestEncryptionHeaderCheckAllowsOrdinaryHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/team2-bucket/key", nil)
	req.Header.Set("x-amz-meta-x-amz-server-side-encryption", "ordinary metadata")
	req.Header.Set("x-amz-meta-x-amz-copy-source-server-side-encryption-key", "ordinary metadata")
	req.Header.Set("x-amz-checksum-sha256", "checksum")
	req.Header.Set("x-amz-expected-bucket-owner", "owner")
	req.Header.Set("x-amz-request-payer", "requester")
	req.Header.Set("x-amz-trailer", "x-amz-checksum-sha256")
	req.Trailer = http.Header{"X-Amz-Checksum-Sha256": nil}
	rr := httptest.NewRecorder()
	if !requireNoEncryptionRequestHeaders(rr, req) || rr.Body.Len() != 0 {
		t.Fatalf("ordinary headers rejected: status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestEncryptionTrailerDeclarations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		header  http.Header
		trailer http.Header
	}{
		{name: "HTTP declaration", header: http.Header{"Trailer": {"x-amz-server-side-encryption"}}},
		{name: "AWS declaration", header: http.Header{"X-Amz-Trailer": {"x-amz-server-side-encryption"}}},
		{name: "mixed case and checksum", header: http.Header{"x-aMz-TrAiLeR": {"x-amz-checksum-sha256, X-Amz-Server-Side-Encryption-Customer-Key "}}},
		{name: "repeated declaration", header: http.Header{"Trailer": {"x-amz-checksum-sha256", "x-amz-copy-source-server-side-encryption-customer-key"}}},
		{name: "net HTTP parsed declaration", trailer: http.Header{"X-Amz-Server-Side-Encryption": nil}},
		{name: "empty trailer", trailer: http.Header{"x-amz-copy-source-server-side-encryption-customer-key": {""}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket/key", nil)
			req.Header = tc.header
			req.Trailer = tc.trailer
			rr := httptest.NewRecorder()
			if requireNoEncryptionRequestHeaders(rr, req) || rr.Code != http.StatusNotImplemented {
				t.Fatalf("status=%d, want rejected with 501", rr.Code)
			}
		})
	}
}
