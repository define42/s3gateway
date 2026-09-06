package server

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/config"
)

type adminRejectedUploadUpstream struct{ calls atomic.Int32 }

func (c *adminRejectedUploadUpstream) Do(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("unexpected upstream request")
}

func TestAdminUploadRejectionReleasesHTTPSlotBeforeBodyEnds(t *testing.T) {
	for _, field := range []string{"name", "file", "meta-project", "ignored"} {
		t.Run(field, func(t *testing.T) {
			upstream := &adminRejectedUploadUpstream{}
			gateway := New(config.Config{MaxConcurrentRequests: 1}, s3.New(s3.Options{
				Region:       "us-east-1",
				BaseEndpoint: aws.String("https://upstream.invalid"),
				HTTPClient:   upstream,
			}))
			gateway.fetchGroups = func(config.Config, string, string) (map[string]struct{}, error) {
				return map[string]struct{}{}, nil
			}
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})
			httpServer := NewHTTPServer(gateway.cfg, gateway.WithAuth(next, adminWebpageHandler(gateway)))
			finished := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpServer.Handler.ServeHTTP(w, r)
				if r.URL.Path == "/admin/bucket/upload" {
					close(finished)
				}
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 5 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			login, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/login",
				strings.NewReader("username=review-user&password=test-password"))
			if err != nil {
				t.Fatal(err)
			}
			login.Header.Set("User-Agent", "Mozilla/5.0")
			login.Header.Set("Accept", "text/html")
			login.Header.Set("Origin", server.URL)
			login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			loginResponse, err := client.Do(login)
			if err != nil {
				t.Fatal(err)
			}
			_ = loginResponse.Body.Close()
			var cookie *http.Cookie
			for _, candidate := range loginResponse.Cookies() {
				if candidate.Name == "s3gateway_admin_session" {
					cookie = candidate
				}
			}
			if loginResponse.StatusCode != http.StatusSeeOther || cookie == nil {
				t.Fatalf("login failed: status=%d cookie=%v", loginResponse.StatusCode, cookie)
			}

			// Send only a finite prefix over HTTP/1 and wait for the rejection.
			// A drain would wait for the declared but deliberately unsent tail.
			transport := client.Transport.(*http.Transport)
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp",
				server.Listener.Addr().String(), transport.TLSClientConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			const boundary = "rejected-upload-boundary"
			prefix := "--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + field + "\"\r\n\r\n" + strings.Repeat("x", 12<<10)
			_, err = fmt.Fprintf(conn, "POST /admin/bucket/upload HTTP/1.1\r\nHost: %s\r\n"+
				"User-Agent: Mozilla/5.0\r\nAccept: text/html\r\nOrigin: %s\r\nCookie: %s\r\n"+
				"Content-Type: multipart/form-data; boundary=%s\r\nContent-Length: 65536\r\n\r\n%s",
				server.Listener.Addr().String(), server.URL, cookie.String(), boundary, prefix)
			if err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(conn)
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatalf("rejection waited for the unfinished body: %v", err)
			}
			_ = response.Body.Close()
			if response.StatusCode != http.StatusSeeOther || !response.Close {
				t.Fatalf("rejection status=%d close=%v, want 303 and closed HTTP/1 connection", response.StatusCode, response.Close)
			}
			if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
				t.Fatalf("rejected connection waited for body cleanup: %v", err)
			}
			select {
			case <-finished:
			default:
				t.Fatal("upload handler did not release its request slot")
			}
			probe, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/api/pop/review/group", nil)
			if err != nil {
				t.Fatal(err)
			}
			probe.SetBasicAuth("review-user", "test-password")
			probeResponse, err := client.Do(probe)
			if err != nil {
				t.Fatal(err)
			}
			_ = probeResponse.Body.Close()
			if probeResponse.StatusCode != http.StatusNoContent || upstream.calls.Load() != 0 {
				t.Fatalf("cached probe status=%d, upstream calls=%d; want 204 and no upstream work",
					probeResponse.StatusCode, upstream.calls.Load())
			}
		})
	}
}
