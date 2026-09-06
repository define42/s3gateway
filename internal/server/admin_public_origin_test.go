package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/define42/s3gateway/internal/config"
)

func TestAdminPublicOriginBrowserLogin(t *testing.T) {
	for _, tt := range []struct {
		name         string
		backend      string
		publicOrigin string
		origin       string
		referer      string
		allowed      bool
		secureCookie bool
	}{
		{name: "direct HTTPS", backend: "https://gateway.example", origin: "https://gateway.example", allowed: true, secureCookie: true},
		{name: "local HTTP", backend: "http://localhost:8080", origin: "http://localhost:8080", allowed: true},
		{name: "TLS offload", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "https://gateway.example", allowed: true, secureCookie: true},
		{name: "TLS offload referer fallback", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", referer: "https://gateway.example/login", allowed: true, secureCookie: true},
		{name: "default port normalization", backend: "http://gateway.internal", publicOrigin: "https://GATEWAY.EXAMPLE:443", origin: "https://gateway.example", allowed: true, secureCookie: true},
		{name: "configured HTTP cannot downgrade TLS cookie", backend: "https://gateway.example", publicOrigin: "http://gateway.example", origin: "http://gateway.example", allowed: true, secureCookie: true},
		{name: "unconfigured offload cannot trust forwarded headers", backend: "http://gateway.example", origin: "https://gateway.example"},
		{name: "different public host", backend: "http://attacker.example", publicOrigin: "https://gateway.example", origin: "https://attacker.example"},
		{name: "different public port", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "https://gateway.example:8443"},
		{name: "different public scheme", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "http://gateway.example"},
		{name: "backend origin rejected", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "http://gateway.internal"},
		{name: "origin overrides referer", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "https://attacker.example", referer: "https://gateway.example/login"},
		{name: "missing origin", backend: "http://gateway.internal", publicOrigin: "https://gateway.example"},
		{name: "null origin", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "null"},
		{name: "origin with path", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "https://gateway.example/login"},
		{name: "origin with credentials", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "https://user@gateway.example"},
		{name: "multiple origins", backend: "http://gateway.internal", publicOrigin: "https://gateway.example", origin: "https://gateway.example https://attacker.example"},
		{name: "invalid option fails closed", backend: "https://gateway.example", publicOrigin: "https://gateway.example/admin", origin: "https://gateway.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gateway := New(config.Config{AdminPublicOrigin: tt.publicOrigin, CookieSecret: strings.Repeat("c", 32)}, nil)
			authCalls := 0
			gateway.fetchGroups = func(_ config.Config, username, password string) (map[string]struct{}, error) {
				authCalls++
				if username != "testuser" || password != "test-password" {
					t.Fatal("unexpected login credentials")
				}
				return map[string]struct{}{"team2-rw": {}}, nil
			}
			handler := NewHTTPServer(gateway.cfg, gateway.WithAuth(http.NotFoundHandler(), adminWebpageHandler(gateway))).Handler
			form := url.Values{"username": {"testuser"}, "password": {"test-password"}}
			request := httptest.NewRequest(http.MethodPost, tt.backend+"/login", strings.NewReader(form.Encode()))
			setAdminBrowserHeaders(request, tt.origin, tt.referer)
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if !tt.allowed {
				if recorder.Code != http.StatusForbidden || authCalls != 0 || len(recorder.Result().Cookies()) != 0 {
					t.Fatalf("untrusted form: status=%d auth calls=%d cookies=%v", recorder.Code, authCalls, recorder.Result().Cookies())
				}
				return
			}
			if recorder.Code != http.StatusSeeOther || recorder.Header().Get("Location") != "/admin" || authCalls != 1 {
				t.Fatalf("trusted form: status=%d location=%q auth calls=%d", recorder.Code, recorder.Header().Get("Location"), authCalls)
			}
			cookies := recorder.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Value == "" || cookies[0].Secure != tt.secureCookie ||
				!cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
				t.Fatalf("unexpected session cookie: %v", cookies)
			}

			// Session loading and logout use the same public-origin policy through
			// the production authentication router, including cookie deletion.
			login := httptest.NewRequest(http.MethodGet, tt.backend+"/login", nil)
			setAdminBrowserHeaders(login, tt.origin, tt.referer)
			login.AddCookie(cookies[0])
			loggedIn := httptest.NewRecorder()
			handler.ServeHTTP(loggedIn, login)
			if loggedIn.Code != http.StatusSeeOther || loggedIn.Header().Get("Location") != "/admin" || authCalls != 1 {
				t.Fatalf("session was not reused: status=%d auth calls=%d", loggedIn.Code, authCalls)
			}
			logout := httptest.NewRequest(http.MethodPost, tt.backend+"/logout", nil)
			setAdminBrowserHeaders(logout, tt.origin, tt.referer)
			logout.AddCookie(cookies[0])
			loggedOut := httptest.NewRecorder()
			handler.ServeHTTP(loggedOut, logout)
			deletedCookies := loggedOut.Result().Cookies()
			if loggedOut.Code != http.StatusSeeOther || loggedOut.Header().Get("Location") != "/login" ||
				len(deletedCookies) != 1 || deletedCookies[0].MaxAge >= 0 || deletedCookies[0].Secure != tt.secureCookie {
				t.Fatalf("logout: status=%d location=%q cookies=%v", loggedOut.Code, loggedOut.Header().Get("Location"), deletedCookies)
			}
		})
	}
}

func setAdminBrowserHeaders(request *http.Request, origin, referer string) {
	request.Header.Set("Accept", "text/html")
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("Origin", origin)
	request.Header.Set("Referer", referer)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "attacker.example")
	request.Header.Set("Forwarded", "for=192.0.2.1;proto=https;host=attacker.example")
}

func TestAdminPublicOriginDoesNotAuthorizeUnsignedHTTPPayload(t *testing.T) {
	gateway := New(config.Config{AdminPublicOrigin: "https://gateway.example"}, nil)
	accessKey, secretKey := mustGatewayCredentials(t, gateway, "testuser", "test-password")
	request := httptest.NewRequest(http.MethodPut, "http://gateway.example/team2-data/key", strings.NewReader("payload"))
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
	credentials := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	if err := v4.NewSigner().SignHTTP(t.Context(), credentials, request, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	gateway.fetchGroups = func(config.Config, string, string) (map[string]struct{}, error) {
		t.Fatal("unsigned HTTP payload must be rejected before LDAP authentication")
		return nil, nil
	}
	handler := NewHTTPServer(gateway.cfg, gateway.WithAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unsigned HTTP payload reached the S3 handler")
	}), adminWebpageHandler(gateway))).Handler
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned HTTP payload status=%d, want 401", recorder.Code)
	}
}
