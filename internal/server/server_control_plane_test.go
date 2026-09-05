package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/s3gateway/internal/adminpage"
	"github.com/define42/s3gateway/internal/authn"
	"github.com/define42/s3gateway/internal/config"
)

func TestAdminLoginBodyReadDeadline(t *testing.T) {
	for _, requestPath := range []string{
		"/login", "/login/", "/login///", "/login%20", "/login/%20", "/login%E2%80%83",
	} {
		t.Run(requestPath, func(t *testing.T) {
			gw := New(config.Config{AdminLoginReadTimeout: 100 * time.Millisecond}, nil)
			var authenticationCalls atomic.Int32
			adminHandler := adminpage.NewHandler(nil, strings.Repeat("a", 32), 1, nil,
				func(string, string) (map[string]struct{}, error) {
					authenticationCalls.Add(1)
					return nil, errors.New("unexpected authentication")
				})
			testServer := httptest.NewServer(gw.WithAuth(http.NotFoundHandler(), adminHandler))
			defer testServer.Close()

			conn, err := net.Dial("tcp", strings.TrimPrefix(testServer.URL, "http://"))
			if err != nil {
				t.Fatalf("dial test server: %v", err)
			}
			defer conn.Close()
			if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatalf("set client read deadline: %v", err)
			}

			started := time.Now()
			request := "POST " + requestPath + " HTTP/1.1\r\n" +
				"Host: example.test\r\n" +
				"Accept: text/html\r\n" +
				"User-Agent: Mozilla/5.0\r\n" +
				"Origin: http://example.test\r\n" +
				"Content-Type: application/x-www-form-urlencoded\r\n" +
				"Content-Length: 100\r\n" +
				"Connection: close\r\n\r\n" +
				"x"
			if _, err := io.WriteString(conn, request); err != nil {
				t.Fatalf("write slow login request: %v", err)
			}
			response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatalf("read timeout response: %v", err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status mismatch: got=%d want=%d", response.StatusCode, http.StatusBadRequest)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("login body deadline took too long: %s", elapsed)
			}
			if got := authenticationCalls.Load(); got != 0 {
				t.Fatalf("incomplete login reached authentication: calls=%d", got)
			}
		})
	}
}

func TestAuthenticationIngressRateLimitRunsBeforeAdminHandler(t *testing.T) {
	for _, requestPath := range []string{
		"/login", "/login/", "/login///", "/login%20", "/login/%20", "/login%E2%80%83",
	} {
		t.Run(requestPath, func(t *testing.T) {
			gw := New(config.Config{
				AuthIngressPerIPRatePerSecond: 1,
				AuthIngressPerIPBurst:         1,
			}, nil)
			var calls atomic.Int32
			adminHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			})
			handler := gw.WithAuth(http.NotFoundHandler(), adminHandler)

			serve := func(path, remoteAddress string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, path, nil)
				req.RemoteAddr = remoteAddress
				req.Header.Set("Accept", "text/html")
				req.Header.Set("User-Agent", "Mozilla/5.0")
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				return rr
			}

			if rr := serve("/login", "192.0.2.1:1234"); rr.Code != http.StatusNoContent {
				t.Fatalf("first status = %d, want %d", rr.Code, http.StatusNoContent)
			}
			if rr := serve(requestPath, "192.0.2.1:5678"); rr.Code != http.StatusTooManyRequests {
				t.Fatalf("limited status = %d, want %d", rr.Code, http.StatusTooManyRequests)
			} else if rr.Header().Get("Retry-After") != "1" {
				t.Fatalf("Retry-After = %q, want 1", rr.Header().Get("Retry-After"))
			}
			if rr := serve(requestPath, "192.0.2.2:1234"); rr.Code != http.StatusNoContent {
				t.Fatalf("independent client status = %d, want %d", rr.Code, http.StatusNoContent)
			}
			if got := calls.Load(); got != 2 {
				t.Fatalf("admin handler calls = %d, want 2", got)
			}
		})
	}
}

func TestAuthenticationClientIPTrustsOnlyConfiguredProxies(t *testing.T) {
	tests := []struct {
		name          string
		trustedCIDRs  []string
		remoteAddress string
		forwardedFor  string
		want          string
	}{
		{
			name:          "direct client cannot spoof forwarding header",
			remoteAddress: "192.0.2.10:1234",
			forwardedFor:  "198.51.100.20",
			want:          "192.0.2.10",
		},
		{
			name:          "trusted proxy supplies client",
			trustedCIDRs:  []string{"10.0.0.0/8"},
			remoteAddress: "10.0.0.10:1234",
			forwardedFor:  "198.51.100.20",
			want:          "198.51.100.20",
		},
		{
			name:          "rightmost untrusted address wins",
			trustedCIDRs:  []string{"10.0.0.0/8"},
			remoteAddress: "10.0.0.10:1234",
			forwardedFor:  "203.0.113.99, 198.51.100.20, 10.0.0.11",
			want:          "198.51.100.20",
		},
		{
			name:          "malformed forwarding header falls back to peer",
			trustedCIDRs:  []string{"10.0.0.0/8"},
			remoteAddress: "10.0.0.10:1234",
			forwardedFor:  "not-an-ip",
			want:          "10.0.0.10",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gw := New(config.Config{TrustedProxyCIDRs: test.trustedCIDRs}, nil)
			req := httptest.NewRequest(http.MethodGet, "/bucket", nil)
			req.RemoteAddr = test.remoteAddress
			req.Header.Set("X-Forwarded-For", test.forwardedFor)
			if got := gw.authenticationClientIP(req); got != test.want {
				t.Fatalf("client IP = %q, want %q", got, test.want)
			}
		})
	}
}

func TestGroupsForCredentialsLimitsConcurrentLDAPCalls(t *testing.T) {
	gw := New(config.Config{
		AuthMaxConcurrent: 1,
		AuthRatePerSecond: 100,
		AuthRateBurst:     100,
	}, nil)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	gw.fetchGroups = func(config.Config, string, string) (map[string]struct{}, error) {
		started <- struct{}{}
		<-release
		return map[string]struct{}{"team-r": {}}, nil
	}

	firstDone := make(chan error, 1)
	go func() {
		_, err := gw.GroupsForCredentials("first-user", "first-password")
		firstDone <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first LDAP call")
	}

	if _, err := gw.GroupsForCredentials("second-user", "second-password"); !errors.Is(err, authn.ErrLimited) {
		t.Fatalf("second LDAP call error = %v, want ErrLimited", err)
	}
	close(release)
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatalf("first LDAP call failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first LDAP call to finish")
	}
}

func TestGroupsForCredentialsCachesRejectedCredentials(t *testing.T) {
	gw := New(config.Config{
		GroupTTL:             2 * time.Minute,
		GroupCacheMaxEntries: 64,
		AuthMaxConcurrent:    4,
		AuthRatePerSecond:    100,
		AuthRateBurst:        100,
	}, nil)
	var calls atomic.Int32
	gw.fetchGroups = func(_ config.Config, _ string, pass string) (map[string]struct{}, error) {
		calls.Add(1)
		switch pass {
		case "expired-password":
			return nil, fmt.Errorf("ldap rejected credentials: %w", authn.ErrRejectedCredentials)
		case "transient-failure":
			return nil, errors.New("ldap unavailable")
		default:
			return map[string]struct{}{"team-r": {}}, nil
		}
	}

	for range 2 {
		if _, err := gw.GroupsForCredentials("service", "expired-password"); !errors.Is(err, authn.ErrRejectedCredentials) {
			t.Fatalf("expired credential error = %v, want ErrRejectedCredentials", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("rejected credentials reached LDAP %d times, want 1", got)
	}

	if _, err := gw.GroupsForCredentials("service", "rotated-password"); err != nil {
		t.Fatalf("rotated credentials remained rejected: %v", err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("rotated credentials reached LDAP %d times total, want 2", got)
	}

	for range 2 {
		if _, err := gw.GroupsForCredentials("transient-service", "transient-failure"); err == nil {
			t.Fatal("transient LDAP failure unexpectedly succeeded")
		}
	}
	if got := calls.Load(); got != 4 {
		t.Fatalf("transient failures reached LDAP %d times total, want 4", got)
	}
}

func TestReadyzIsPrivateAndCached(t *testing.T) {
	tests := []struct {
		name       string
		checkErr   error
		wantStatus int
		wantBody   string
	}{
		{name: "healthy", wantStatus: http.StatusOK, wantBody: "ok\n"},
		{name: "unhealthy is generic", checkErr: errors.New("ldap: internal.example:389 refused"), wantStatus: http.StatusServiceUnavailable, wantBody: "not ready\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := New(config.Config{ReadinessCacheTTL: time.Minute}, nil)
			var calls atomic.Int32
			gw.readinessCheck = func(context.Context) error {
				calls.Add(1)
				return tt.checkErr
			}

			externalReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
			externalReq.RemoteAddr = "203.0.113.10:4321"
			externalRR := httptest.NewRecorder()
			gw.ServeHTTP(externalRR, externalReq)
			if externalRR.Code != http.StatusNotFound {
				t.Fatalf("public readiness status: got=%d want=%d", externalRR.Code, http.StatusNotFound)
			}
			if calls.Load() != 0 {
				t.Fatalf("public readiness request reached dependencies: calls=%d", calls.Load())
			}

			for range 2 {
				req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
				req.RemoteAddr = "127.0.0.1:4321"
				rr := httptest.NewRecorder()
				gw.ServeHTTP(rr, req)
				if rr.Code != tt.wantStatus {
					t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, tt.wantStatus, rr.Body.String())
				}
				if rr.Body.String() != tt.wantBody {
					t.Fatalf("body mismatch: got=%q want=%q", rr.Body.String(), tt.wantBody)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("cached readiness calls: got=%d want=1", calls.Load())
			}
		})
	}
}

func TestReadyzCacheExpiresAndCoalesces(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	gw := New(config.Config{ReadinessCacheTTL: time.Second}, nil)
	gw.readinessNow = func() time.Time { return now }
	var calls atomic.Int32
	gw.readinessCheck = func(context.Context) error {
		calls.Add(1)
		return nil
	}

	serve := func() {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		req.RemoteAddr = "127.0.0.1:4321"
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	}
	serve()
	now = now.Add(time.Second)
	serve()
	if calls.Load() != 2 {
		t.Fatalf("expired cache calls: got=%d want=2", calls.Load())
	}

	gw = New(config.Config{ReadinessCacheTTL: time.Minute}, nil)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	calls.Store(0)
	gw.readinessCheck = func(context.Context) error {
		if calls.Add(1) == 1 {
			started <- struct{}{}
		}
		<-release
		return nil
	}

	const workers = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			<-start
			serve()
		}()
	}
	close(start)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for readiness check")
	}
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("coalesced readiness calls: got=%d want=1", calls.Load())
	}
}
