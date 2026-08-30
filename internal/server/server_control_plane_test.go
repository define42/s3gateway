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

	"github.com/define42/s3gateway/internal/authn"
	"github.com/define42/s3gateway/internal/config"
)

func TestAdminLoginBodyReadDeadline(t *testing.T) {
	gw := New(config.Config{AdminLoginReadTimeout: 100 * time.Millisecond}, nil)
	readResult := make(chan error, 1)
	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(io.Discard, r.Body)
		readResult <- err
		w.WriteHeader(http.StatusRequestTimeout)
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
	request := "POST /login HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Accept: text/html\r\n" +
		"User-Agent: Mozilla/5.0\r\n" +
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
	if response.StatusCode != http.StatusRequestTimeout {
		t.Fatalf("status mismatch: got=%d want=%d", response.StatusCode, http.StatusRequestTimeout)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("login body deadline took too long: %s", elapsed)
	}
	select {
	case err := <-readResult:
		if err == nil {
			t.Fatal("slow login body read unexpectedly completed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for login body read to stop")
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
