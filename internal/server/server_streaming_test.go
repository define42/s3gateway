package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/define42/s3gateway/internal/sigv4"
)

func TestWithAuthRejectsStreamingControlRequests(t *testing.T) {
	const versioning = `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`
	routes := []struct {
		name        string
		method      string
		path        string
		copySource  string
		unsupported bool
	}{
		{name: "versioning", method: http.MethodPut, path: "/team2-bucket?versioning"},
		{name: "versioning trailing slash", method: http.MethodPut, path: "/team2-bucket/?versioning"},
		{name: "bucket creation", method: http.MethodPut, path: "/team2-bucket"},
		{name: "bucket tagging", method: http.MethodPut, path: "/team2-bucket?tagging"},
		{name: "bucket lifecycle", method: http.MethodPut, path: "/team2-bucket?lifecycle"},
		{name: "bucket encryption", method: http.MethodPut, path: "/team2-bucket?encryption"},
		{name: "bucket ACL", method: http.MethodPut, path: "/team2-bucket?acl"},
		{name: "multi delete", method: http.MethodPost, path: "/team2-bucket?delete"},
		{name: "object tagging", method: http.MethodPut, path: "/team2-bucket/key?tagging"},
		{name: "object ACL", method: http.MethodPut, path: "/team2-bucket/key?acl"},
		{name: "multipart initiation", method: http.MethodPost, path: "/team2-bucket/key?uploads"},
		{name: "multipart completion", method: http.MethodPost, path: "/team2-bucket/key?uploadId=u1"},
		{name: "copy object", method: http.MethodPut, path: "/team2-bucket/key", copySource: "/team2-source/key"},
		{name: "copy part", method: http.MethodPut, path: "/team2-bucket/key?uploadId=u1&partNumber=1", copySource: "/team2-source/key"},
		{name: "tagging with part parameters", method: http.MethodPut, path: "/team2-bucket/key?tagging&uploadId=u1&partNumber=1"},
		{name: "ACL with part parameters", method: http.MethodPut, path: "/team2-bucket/key?acl&uploadId=u1&partNumber=1"},
		{name: "unknown subresource", method: http.MethodPut, path: "/team2-bucket/key?future-control", unsupported: true},
	}
	modes := []struct {
		name  string
		value string
	}{
		{name: "signed chunks", value: sigv4.StreamingSignedPayload},
		{name: "signed trailers", value: sigv4.StreamingSignedPayloadTrailer},
		{name: "unsigned trailers", value: sigv4.StreamingUnsignedPayloadTrailer},
		{name: "normalized marker", value: " " + strings.ToLower(sigv4.StreamingSignedPayload) + " "},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			})
			defer cleanup()
			gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-rwcdb": {}})
			accessKey, secretKey := mustGatewayCredentials(t, gw, "testuser", "dogood")

			for _, mode := range modes {
				t.Run(mode.name, func(t *testing.T) {
					// A valid header signature must not authorize unframed XML when
					// the payload marker promises independent chunk signatures.
					req := httptest.NewRequest(route.method, "https://example.com"+route.path, strings.NewReader(versioning))
					req.Header.Set("x-amz-content-sha256", mode.value)
					if route.copySource != "" {
						req.Header.Set("x-amz-copy-source", route.copySource)
					}
					credentials := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
					if err := v4.NewSigner().SignHTTP(t.Context(), credentials, req, mode.value, "s3", "us-east-1", time.Now().UTC()); err != nil {
						t.Fatalf("sign request: %v", err)
					}
					rr := httptest.NewRecorder()
					gw.WithAuth(gw, nil).ServeHTTP(rr, req)
					if got := upstreamCalls.Swap(0); got != 0 {
						t.Errorf("streaming control request reached upstream: calls=%d", got)
					}
					wantStatus, wantCode := http.StatusBadRequest, "InvalidRequest"
					if route.unsupported {
						wantStatus, wantCode = http.StatusNotImplemented, "NotImplemented"
					}
					if rr.Code != wantStatus || !strings.Contains(rr.Body.String(), "<Code>"+wantCode+"</Code>") {
						t.Fatalf("status=%d body=%s, want %d %s", rr.Code, rr.Body.String(), wantStatus, wantCode)
					}
				})
			}
		})
	}
}

func TestWithAuthVersioningPayloadDigest(t *testing.T) {
	const original = `<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`
	for _, tc := range []struct {
		name      string
		body      string
		wantCalls int32
		wantCode  int
	}{
		{name: "valid", body: original, wantCalls: 1, wantCode: http.StatusOK},
		{name: "tampered", body: strings.ReplaceAll(original, "Enabled", "Suspended"), wantCode: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				if !strings.Contains(string(body), "<Status>Enabled</Status>") {
					t.Errorf("unexpected upstream versioning configuration: %s", body)
				}
				w.WriteHeader(http.StatusOK)
			})
			defer cleanup()
			gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-c": {}})
			req := signedGatewayRequest(t, gw, http.MethodPut, "https://example.com/team2-bucket?versioning", tc.body, original, nil)
			rr := httptest.NewRecorder()
			gw.WithAuth(gw, nil).ServeHTTP(rr, req)
			if rr.Code != tc.wantCode || upstreamCalls.Load() != tc.wantCalls {
				t.Fatalf("status=%d calls=%d body=%s, want status=%d calls=%d", rr.Code, upstreamCalls.Load(), rr.Body.String(), tc.wantCode, tc.wantCalls)
			}
		})
	}
}
