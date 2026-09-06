package server

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

func TestDeleteObjectsHTTPChecksumTrailers(t *testing.T) {
	const body = `<Delete><Object><Key>object.txt</Key></Object></Delete>`
	for _, middleware := range []struct {
		name  string
		audit bool
	}{
		{name: "authentication and audit", audit: true},
		{name: "authentication only"},
	} {
		t.Run(middleware.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/team2-bucket" || !r.URL.Query().Has("delete") {
					t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
				}
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Errorf("read upstream body: %v", err)
				}
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<DeleteResult><Deleted><Key>object.txt</Key></Deleted></DeleteResult>`)
			})
			defer cleanup()
			gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-d": {}})
			accessKey, secretKey := mustGatewayCredentials(t, gw, "testuser", "dogood")
			credentials := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
			handler := gw.WithAuth(gw, nil)
			if middleware.audit {
				handler = gw.WithS3Audit(handler)
			}
			front := httptest.NewTLSServer(handler)
			defer front.Close()

			for _, scenario := range []struct {
				name        string
				declareHTTP bool
				declareAWS  bool
				trailer     bool
				wantInvalid bool
			}{
				{name: "declared HTTP checksum trailer", declareHTTP: true, trailer: true, wantInvalid: true},
				{name: "undeclared HTTP checksum trailer", trailer: true, wantInvalid: true},
				{name: "AWS trailer declaration", declareAWS: true, trailer: true, wantInvalid: true},
				{name: "chunked body with valid MD5 header"},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, front.URL+"/team2-bucket?delete", nil)
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/xml")
					req.Header.Set("Content-MD5", xmlBodyMD5(body))
					req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
					if scenario.declareAWS {
						req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
					}
					if err := v4.NewSigner().SignHTTP(t.Context(), credentials, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now()); err != nil {
						t.Fatalf("sign deletion request: %v", err)
					}
					// Trailer is hop-by-hop framing, removed from Header by net/http.
					// Leave it unsigned so this test reaches checksum validation.
					if scenario.declareHTTP {
						req.Header.Set("Trailer", "x-amz-checksum-crc32")
					}
					footer := ""
					if scenario.trailer {
						footer = "X-Amz-Checksum-Crc32: AAAAAA==\r\n"
					}
					before := upstreamCalls.Load()
					status, responseBody := rawChunkedXMLRequest(t, front, req, body, footer)
					calls := upstreamCalls.Load() - before
					if scenario.wantInvalid {
						if status != http.StatusBadRequest || !strings.Contains(responseBody, "<Code>InvalidRequest</Code>") || calls != 0 {
							t.Fatalf("status=%d calls=%d body=%s, want 400 InvalidRequest and zero mutations", status, calls, responseBody)
						}
					} else if status != http.StatusOK || calls != 1 {
						t.Fatalf("status=%d calls=%d body=%s, want 200 and one mutation", status, calls, responseBody)
					}
				})
			}
		})
	}
}

// Raw HTTP/1.1 is necessary because net/http's client declares trailer fields.
// Omitting that declaration tests trailers discovered only after reading EOF.
func rawChunkedXMLRequest(t *testing.T, front *httptest.Server, req *http.Request, body, footer string) (int, string) {
	t.Helper()
	endpoint, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := front.Client().Transport.(*http.Transport)
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", endpoint.Host, transport.TLSClientConfig.Clone())
	if err != nil {
		t.Fatalf("connect to gateway: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var wire strings.Builder
	fmt.Fprintf(&wire, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), endpoint.Host)
	if err := req.Header.Write(&wire); err != nil {
		t.Fatalf("encode signed headers: %v", err)
	}
	fmt.Fprintf(&wire, "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n%x\r\n%s\r\n0\r\n%s\r\n", len(body), body, footer)
	if _, err := io.WriteString(conn, wire.String()); err != nil {
		t.Fatalf("send chunked XML request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read gateway response: %v", err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read gateway response body: %v", err)
	}
	return response.StatusCode, string(responseBody)
}
