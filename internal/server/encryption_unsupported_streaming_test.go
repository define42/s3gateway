package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/sigv4"
)

func TestEncryptionTrailerRejectedThroughAuthentication(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	t.Cleanup(cleanup)
	gw.fetchGroups = func(config.Config, string, string) (map[string]struct{}, error) {
		return map[string]struct{}{"team2-rw": {}}, nil
	}
	accessKey, secretKey := mustGatewayCredentials(t, gw, "testuser", "test-password")

	const body = "3\r\nabc\r\n0\r\nx-amz-server-side-encryption:aws:kms\r\n\r\n"
	reader := strings.NewReader(body)
	req := httptest.NewRequest(http.MethodPut, "https://gateway.example/team2-bucket/key", reader)
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("x-amz-decoded-content-length", "3")
	req.Header.Set("x-amz-content-sha256", sigv4.StreamingUnsignedPayloadTrailer)
	req.Header.Set("x-amz-trailer", "x-amz-server-side-encryption")
	credentials := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	if err := v4.NewSigner().SignHTTP(t.Context(), credentials, req, sigv4.StreamingUnsignedPayloadTrailer, "s3", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := NewHTTPServer(gw.cfg, gw.WithAuth(gw, adminWebpageHandler(gw))).Handler
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "<Code>NotImplemented</Code>") {
		t.Fatalf("status=%d body=%s, want 501 NotImplemented", rr.Code, rr.Body.String())
	}
	if reader.Len() != len(body) {
		t.Error("rejected encryption trailer request body was read")
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("rejected encryption trailer request reached upstream %d times", got)
	}
}
