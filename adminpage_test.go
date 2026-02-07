package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestBuildAdminGroupAccess(t *testing.T) {
	groups := map[string]struct{}{
		"team2-rw":   {},
		"team3-cdb":  {},
		"misc-group": {},
	}
	buckets := []string{
		"team2-logs",
		"team2-data",
		"team3-archive",
		"misc",
	}

	rows, ignored := buildAdminGroupAccess(groups, buckets)
	if len(rows) != 2 {
		t.Fatalf("row count mismatch: got=%d want=%d", len(rows), 2)
	}
	if len(ignored) != 1 || ignored[0] != "misc-group" {
		t.Fatalf("ignored groups mismatch: got=%v", ignored)
	}

	if rows[0].GroupName != "team2-rw" {
		t.Fatalf("first row group mismatch: got=%q want=%q", rows[0].GroupName, "team2-rw")
	}
	if rows[0].PermissionLetters != "rw" {
		t.Fatalf("team2 permission letters mismatch: got=%q want=%q", rows[0].PermissionLetters, "rw")
	}
	if got := strings.Join(rows[0].Buckets, ","); got != "team2-data,team2-logs" {
		t.Fatalf("team2 buckets mismatch: got=%q want=%q", got, "team2-data,team2-logs")
	}

	if rows[1].GroupName != "team3-cdb" {
		t.Fatalf("second row group mismatch: got=%q want=%q", rows[1].GroupName, "team3-cdb")
	}
	if rows[1].PermissionLetters != "cdb" {
		t.Fatalf("team3 permission letters mismatch: got=%q want=%q", rows[1].PermissionLetters, "cdb")
	}
	if got := strings.Join(rows[1].Buckets, ","); got != "team3-archive" {
		t.Fatalf("team3 buckets mismatch: got=%q want=%q", got, "team3-archive")
	}
}

func TestCountUniqueBuckets(t *testing.T) {
	rows := []adminGroupAccessView{
		{Buckets: []string{"team2-a", "team2-b"}},
		{Buckets: []string{"team2-b", "team3-c"}},
	}

	if got := countUniqueBuckets(rows); got != 3 {
		t.Fatalf("unique bucket count mismatch: got=%d want=%d", got, 3)
	}
}

func TestIsBrowser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	if !isBrowser(req) {
		t.Fatalf("expected request to be detected as browser")
	}

	apiReq := httptest.NewRequest(http.MethodGet, "/", nil)
	apiReq.Header.Set("Accept", "application/xml")
	apiReq.Header.Set("User-Agent", "aws-sdk-go-v2")
	if isBrowser(apiReq) {
		t.Fatalf("expected API request not to be detected as browser")
	}

	sigV4Req := httptest.NewRequest(http.MethodGet, "/", nil)
	sigV4Req.Header.Set("Accept", "text/html,application/xhtml+xml")
	sigV4Req.Header.Set("User-Agent", "Mozilla/5.0")
	sigV4Req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=akid/20260207/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature="+strings.Repeat("a", 64))
	if isBrowser(sigV4Req) {
		t.Fatalf("expected SigV4-authenticated request not to be detected as browser")
	}
}

func TestIsAdminRoute(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: "/", want: true},
		{path: "/login", want: true},
		{path: "/admin", want: true},
		{path: "/logout", want: true},
		{path: "/login/", want: true},
		{path: "/team2-bucket", want: false},
	}
	for _, tc := range cases {
		if got := isAdminRoute(tc.path); got != tc.want {
			t.Fatalf("isAdminRoute(%q) mismatch: got=%v want=%v", tc.path, got, tc.want)
		}
	}
}

func TestAdminRootRedirectsToLogin(t *testing.T) {
	handler := adminWebpageHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location mismatch: got=%q want=%q", loc, "/login")
	}
}

func TestAdminLoginGetRendersLoginPage(t *testing.T) {
	handler := adminWebpageHandler(newServer(Config{}, nil))

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusOK)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "S3 Gateway Admin") {
		t.Fatalf("missing title in login page: %q", body)
	}
	if !strings.Contains(body, `action="/login"`) {
		t.Fatalf("missing login form action: %q", body)
	}
}

func TestAdminLoginPostRequiresCredentials(t *testing.T) {
	handler := adminWebpageHandler(newServer(Config{}, nil))

	form := url.Values{}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rr.Body.String(), "LDAP username and password are required.") {
		t.Fatalf("expected missing credentials message, body=%q", rr.Body.String())
	}
}

func TestAdminLoginPostSuccessSetsCookieAndRedirects(t *testing.T) {
	s := newServer(Config{}, nil)
	s.gcache.set("alice", "secret", map[string]struct{}{
		"team2-rw": {},
	})
	handler := adminWebpageHandler(s)

	form := url.Values{
		"username": []string{"alice"},
		"password": []string{"secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/admin" {
		t.Fatalf("location mismatch: got=%q want=%q", loc, "/admin")
	}

	var found bool
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == adminSessionCookieName && ck.Value != "" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected session cookie %q to be set", adminSessionCookieName)
	}
}

func TestAdminDashboardRequiresSession(t *testing.T) {
	handler := adminWebpageHandler(newServer(Config{}, nil))

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location mismatch: got=%q want=%q", loc, "/login")
	}
}

func TestAdminDashboardWithSessionRendersGroupsAndBuckets(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>team2-logs</Name></Bucket>
    <Bucket><Name>team9-hidden</Name></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`))
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-rw":   {},
		"misc-group": {},
	})

	handler := adminWebpageHandler(gw)
	loginForm := url.Values{
		"username": []string{"alice"},
		"password": []string{"secret"},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	handler.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusSeeOther {
		t.Fatalf("login status mismatch: got=%d want=%d body=%s", loginRR.Code, http.StatusSeeOther, loginRR.Body.String())
	}

	var sessionCookie *http.Cookie
	for _, ck := range loginRR.Result().Cookies() {
		if ck.Name == adminSessionCookieName && ck.Value != "" {
			clone := *ck
			sessionCookie = &clone
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("missing session cookie from login response")
	}

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Signed in as <strong>alice</strong>") {
		t.Fatalf("missing username in admin page: %q", body)
	}
	if !strings.Contains(body, "team2-rw") {
		t.Fatalf("missing group in admin page: %q", body)
	}
	if !strings.Contains(body, "team2-logs") {
		t.Fatalf("missing bucket in admin page: %q", body)
	}
	if strings.Contains(body, "team9-hidden") {
		t.Fatalf("unexpected bucket shown in admin page: %q", body)
	}
}

func TestAdminLogoutClearsCookieAndRedirects(t *testing.T) {
	s := newServer(Config{}, nil)
	s.gcache.set("alice", "secret", map[string]struct{}{
		"team2-rw": {},
	})

	handler := adminWebpageHandler(s)
	loginForm := url.Values{
		"username": []string{"alice"},
		"password": []string{"secret"},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	handler.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusSeeOther {
		t.Fatalf("login status mismatch: got=%d want=%d", loginRR.Code, http.StatusSeeOther)
	}

	var sessionCookie *http.Cookie
	for _, ck := range loginRR.Result().Cookies() {
		if ck.Name == adminSessionCookieName && ck.Value != "" {
			clone := *ck
			sessionCookie = &clone
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("missing session cookie from login response")
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, logoutReq)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("location mismatch: got=%q want=%q", loc, "/login")
	}

	var cleared bool
	for _, ck := range rr.Result().Cookies() {
		if ck.Name == adminSessionCookieName && ck.Value == "" {
			cleared = true
			break
		}
	}
	if !cleared {
		t.Fatalf("expected cleared admin session cookie")
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/admin", nil)
	adminReq.AddCookie(sessionCookie)
	adminRR := httptest.NewRecorder()
	handler.ServeHTTP(adminRR, adminReq)
	if adminRR.Code != http.StatusSeeOther {
		t.Fatalf("expected old session cookie to be invalid after logout: got=%d want=%d", adminRR.Code, http.StatusSeeOther)
	}
	if loc := adminRR.Header().Get("Location"); loc != "/login" {
		t.Fatalf("old cookie redirect location mismatch: got=%q want=%q", loc, "/login")
	}
}
