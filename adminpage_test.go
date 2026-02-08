package main

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func adminLoginSessionCookie(t *testing.T, handler http.Handler, username, password string) *http.Cookie {
	t.Helper()

	loginForm := url.Values{
		"username": []string{username},
		"password": []string{password},
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	handler.ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusSeeOther {
		t.Fatalf("login status mismatch: got=%d want=%d body=%s", loginRR.Code, http.StatusSeeOther, loginRR.Body.String())
	}

	for _, ck := range loginRR.Result().Cookies() {
		if ck.Name == adminSessionCookieName && ck.Value != "" {
			clone := *ck
			return &clone
		}
	}
	t.Fatalf("missing session cookie from login response")
	return nil
}

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

	previews := map[string]adminBucketView{
		"team2-data": {Name: "team2-data", CanRead: true, ObjectKeys: []string{"a.txt"}},
		"team2-logs": {Name: "team2-logs", CanRead: true, ObjectKeys: []string{"b.txt"}},
		"team3-archive": {
			Name:            "team3-archive",
			CanRead:         false,
			ObjectListError: "",
		},
	}

	rows, ignored := buildAdminGroupAccess(groups, buckets, previews)
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
	if got := strings.Join([]string{rows[0].Buckets[0].Name, rows[0].Buckets[1].Name}, ","); got != "team2-data,team2-logs" {
		t.Fatalf("team2 buckets mismatch: got=%q want=%q", got, "team2-data,team2-logs")
	}
	if got := strings.Join(rows[0].Buckets[0].ObjectKeys, ","); got != "a.txt" {
		t.Fatalf("team2-data object list mismatch: got=%q want=%q", got, "a.txt")
	}

	if rows[1].GroupName != "team3-cdb" {
		t.Fatalf("second row group mismatch: got=%q want=%q", rows[1].GroupName, "team3-cdb")
	}
	if rows[1].PermissionLetters != "cdb" {
		t.Fatalf("team3 permission letters mismatch: got=%q want=%q", rows[1].PermissionLetters, "cdb")
	}
	if got := strings.Join([]string{rows[1].Buckets[0].Name}, ","); got != "team3-archive" {
		t.Fatalf("team3 buckets mismatch: got=%q want=%q", got, "team3-archive")
	}
}

func TestCountUniqueBuckets(t *testing.T) {
	rows := []adminGroupAccessView{
		{Buckets: []adminBucketView{{Name: "team2-a"}, {Name: "team2-b"}}},
		{Buckets: []adminBucketView{{Name: "team2-b"}, {Name: "team3-c"}}},
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
		{path: "/admin/create-bucket", want: true},
		{path: "/admin/bucket", want: true},
		{path: "/admin/bucket/download", want: true},
		{path: "/admin/bucket/upload", want: true},
		{path: "/admin/bucket/delete", want: true},
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
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>team2-logs</Name></Bucket>
    <Bucket><Name>team3-writeonly</Name></Bucket>
    <Bucket><Name>team9-hidden</Name></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`))
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-rw":   {},
		"team3-w":    {},
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
	if !strings.Contains(body, "/admin/bucket?name=team2-logs") {
		t.Fatalf("missing bucket link for readable bucket in admin page: %q", body)
	}
	if !strings.Contains(body, "Read permission required to list objects.") {
		t.Fatalf("missing no-read-permission message in admin page: %q", body)
	}
	if strings.Contains(body, "team9-hidden") {
		t.Fatalf("unexpected bucket shown in admin page: %q", body)
	}
}

func TestAdminDashboardShowsCreateBucketForm(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/" {
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>
  <Buckets>
    <Bucket><Name>team2-logs</Name></Bucket>
  </Buckets>
</ListAllMyBucketsResult>`))
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-c": {},
		"team3-c": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	req := httptest.NewRequest(http.MethodGet, "/admin?space=team3&suffix=newname", nil)
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `action="/admin/create-bucket"`) {
		t.Fatalf("missing create-bucket form action: %q", body)
	}
	if !strings.Contains(body, `option value="team2"`) || !strings.Contains(body, `option value="team3"`) {
		t.Fatalf("missing create-space options: %q", body)
	}
	if !strings.Contains(body, "Generated bucket: <code>team3-newname</code>") {
		t.Fatalf("missing generated bucket preview: %q", body)
	}
}

func TestAdminCreateBucketSuccess(t *testing.T) {
	var createdBucket string

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected upstream method: %s", r.Method)
		}
		createdBucket = strings.TrimPrefix(r.URL.Path, "/")
		if createdBucket != "team2-newname" {
			t.Fatalf("unexpected created bucket: %q", createdBucket)
		}
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-c": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	form := url.Values{
		"space":  []string{"team2"},
		"suffix": []string{"newname"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if loc.Path != "/admin" {
		t.Fatalf("redirect path mismatch: got=%q want=%q", loc.Path, "/admin")
	}
	if loc.Query().Get("msg") != "Created bucket: team2-newname" {
		t.Fatalf("create success message mismatch: got=%q", loc.Query().Get("msg"))
	}
	if createdBucket != "team2-newname" {
		t.Fatalf("expected bucket to be created, got=%q", createdBucket)
	}
}

func TestAdminCreateBucketRequiresPermission(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request without create permission: %s %s", r.Method, r.URL.Path)
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-rw": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	form := url.Values{
		"space":  []string{"team2"},
		"suffix": []string{"newname"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if loc.Query().Get("err") != "Create-bucket permission is required." {
		t.Fatalf("permission error mismatch: got=%q", loc.Query().Get("err"))
	}
}

func TestAdminCreateBucketRejectsInvalidSpace(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request for invalid space: %s %s", r.Method, r.URL.Path)
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-c": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	form := url.Values{
		"space":  []string{"team9"},
		"suffix": []string{"newname"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	if loc.Query().Get("err") != "Invalid bucket space selection." {
		t.Fatalf("invalid-space error mismatch: got=%q", loc.Query().Get("err"))
	}
}

func TestAdminBucketPagePagination(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/team2-logs" && r.URL.Query().Get("list-type") == "2":
			if r.URL.Query().Get("max-keys") != "25" {
				t.Fatalf("expected max-keys=25, got %q", r.URL.Query().Get("max-keys"))
			}
			w.Header().Set("Content-Type", "application/xml")
			switch r.URL.Query().Get("continuation-token") {
			case "":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>team2-logs</Name>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>tok2</NextContinuationToken>
  <Contents><Key>logs/p1.txt</Key><LastModified>2026-02-07T01:02:03.000Z</LastModified><Size>11</Size></Contents>
</ListBucketResult>`))
			case "tok2":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>team2-logs</Name>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>logs/p2.txt</Key><LastModified>2026-02-07T02:03:04.000Z</LastModified><Size>22</Size></Contents>
</ListBucketResult>`))
			default:
				t.Fatalf("unexpected continuation token: %q", r.URL.Query().Get("continuation-token"))
			}

		case r.Method == http.MethodHead && r.URL.Path == "/team2-logs/logs/p1.txt":
			w.Header().Set("x-amz-meta-owner", "alice")
			w.Header().Set("x-amz-meta-doc-type", "report")
			w.Header().Set("Expires", "Sat, 07 Feb 2026 05:00:00 GMT")
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodHead && r.URL.Path == "/team2-logs/logs/p2.txt":
			w.Header().Set("x-amz-meta-owner", "bob")
			w.Header().Set("Expires", "Sat, 07 Feb 2026 06:00:00 GMT")
			w.WriteHeader(http.StatusOK)

		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-r": {},
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

	page1Req := httptest.NewRequest(http.MethodGet, "/admin/bucket?name=team2-logs", nil)
	page1Req.AddCookie(sessionCookie)
	page1RR := httptest.NewRecorder()
	handler.ServeHTTP(page1RR, page1Req)
	if page1RR.Code != http.StatusOK {
		t.Fatalf("page1 status mismatch: got=%d want=%d body=%s", page1RR.Code, http.StatusOK, page1RR.Body.String())
	}
	page1Body := page1RR.Body.String()
	if !strings.Contains(page1Body, "logs/p1.txt") {
		t.Fatalf("missing page1 object key: %q", page1Body)
	}
	if !strings.Contains(page1Body, "<code>11</code>") {
		t.Fatalf("missing page1 size in bucket page: %q", page1Body)
	}
	if !strings.Contains(page1Body, "2026-02-07T01:02:03Z") {
		t.Fatalf("missing page1 last-modified in bucket page: %q", page1Body)
	}
	if !strings.Contains(page1Body, "2026-02-07T05:00:00Z") {
		t.Fatalf("missing page1 expires in bucket page: %q", page1Body)
	}
	if !strings.Contains(page1Body, "owner") || !strings.Contains(page1Body, "alice") {
		t.Fatalf("missing page1 metadata in bucket page: %q", page1Body)
	}
	if !strings.Contains(page1Body, "cursor=tok2") {
		t.Fatalf("missing next cursor on page1: %q", page1Body)
	}

	page2URL := adminBucketPageURL("team2-logs", "tok2", []string{""})
	page2Req := httptest.NewRequest(http.MethodGet, page2URL, nil)
	page2Req.AddCookie(sessionCookie)
	page2RR := httptest.NewRecorder()
	handler.ServeHTTP(page2RR, page2Req)
	if page2RR.Code != http.StatusOK {
		t.Fatalf("page2 status mismatch: got=%d want=%d body=%s", page2RR.Code, http.StatusOK, page2RR.Body.String())
	}
	page2Body := page2RR.Body.String()
	if !strings.Contains(page2Body, "logs/p2.txt") {
		t.Fatalf("missing page2 object key: %q", page2Body)
	}
	if !strings.Contains(page2Body, "<code>22</code>") {
		t.Fatalf("missing page2 size in bucket page: %q", page2Body)
	}
	if !strings.Contains(page2Body, "2026-02-07T02:03:04Z") {
		t.Fatalf("missing page2 last-modified in bucket page: %q", page2Body)
	}
	if !strings.Contains(page2Body, "2026-02-07T06:00:00Z") {
		t.Fatalf("missing page2 expires in bucket page: %q", page2Body)
	}
	if !strings.Contains(page2Body, "owner") || !strings.Contains(page2Body, "bob") {
		t.Fatalf("missing page2 metadata in bucket page: %q", page2Body)
	}
	if !strings.Contains(page2Body, `href="/admin/bucket?name=team2-logs"`) {
		t.Fatalf("missing prev link on page2: %q", page2Body)
	}
}

func TestAdminBucketDownload(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/team2-logs/readme.txt" {
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("ETag", `"etag-readme"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello from bucket"))
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-r": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	req := httptest.NewRequest(http.MethodGet, "/admin/bucket/download?name=team2-logs&key=readme.txt", nil)
	req.AddCookie(sessionCookie)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "text/plain" {
		t.Fatalf("content type mismatch: got=%q want=%q", got, "text/plain")
	}
	if got := rr.Header().Get("Content-Disposition"); !strings.Contains(got, `attachment; filename="readme.txt"`) {
		t.Fatalf("content disposition mismatch: got=%q", got)
	}
	if got := rr.Body.String(); got != "hello from bucket" {
		t.Fatalf("download body mismatch: got=%q want=%q", got, "hello from bucket")
	}
}

func TestAdminBucketUploadAndDelete(t *testing.T) {
	var uploadedPart1 bytes.Buffer
	var putPath string
	var putUploadedBy string
	var deletePath string
	const uploadID = "upload-new-1"

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/uploads/new.txt" && q.Has("uploads"):
			putPath = r.URL.Path
			putUploadedBy = r.Header.Get("x-amz-meta-uploaded-by")
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/new.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/uploads/new.txt" && q.Get("uploadId") == uploadID:
			if q.Get("partNumber") == "1" {
				_, _ = io.Copy(&uploadedPart1, r.Body)
			} else {
				_, _ = io.Copy(io.Discard, r.Body)
			}
			w.Header().Set("ETag", `"etag-part-1"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/uploads/new.txt" && q.Get("uploadId") == uploadID:
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/new.txt</Key><ETag>"etag-uploaded"</ETag></CompleteMultipartUploadResult>`)
		case r.Method == http.MethodDelete && r.URL.Path == "/team2-logs/uploads/new.txt":
			deletePath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-wd": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	var uploadBuf bytes.Buffer
	uploadWriter := multipart.NewWriter(&uploadBuf)
	_ = uploadWriter.WriteField("name", "team2-logs")
	_ = uploadWriter.WriteField("key", "uploads/new.txt")
	_ = uploadWriter.WriteField("cursor", "")
	_ = uploadWriter.WriteField("history", "")
	_ = uploadWriter.WriteField("size", strconv.Itoa(len("payload-123")))
	filePart, err := uploadWriter.CreateFormFile("file", "new.txt")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := filePart.Write([]byte("payload-123")); err != nil {
		t.Fatalf("write multipart payload: %v", err)
	}
	if err := uploadWriter.Close(); err != nil {
		t.Fatalf("close multipart payload: %v", err)
	}

	uploadReq := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &uploadBuf)
	uploadReq.Header.Set("Content-Type", uploadWriter.FormDataContentType())
	uploadReq.AddCookie(sessionCookie)
	uploadRR := httptest.NewRecorder()
	handler.ServeHTTP(uploadRR, uploadReq)

	if uploadRR.Code != http.StatusSeeOther {
		t.Fatalf("upload status mismatch: got=%d want=%d body=%s", uploadRR.Code, http.StatusSeeOther, uploadRR.Body.String())
	}
	uploadLoc, err := url.Parse(uploadRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upload location: %v", err)
	}
	if uploadLoc.Query().Get("msg") != "Uploaded object: uploads/new.txt" {
		t.Fatalf("upload message mismatch: got=%q", uploadLoc.Query().Get("msg"))
	}
	if putPath != "/team2-logs/uploads/new.txt" {
		t.Fatalf("put path mismatch: got=%q want=%q", putPath, "/team2-logs/uploads/new.txt")
	}
	if putUploadedBy != "alice" {
		t.Fatalf("uploaded-by metadata mismatch: got=%q want=%q", putUploadedBy, "alice")
	}
	if uploadedPart1.String() != "payload-123" {
		t.Fatalf("put body mismatch: got=%q want=%q", uploadedPart1.String(), "payload-123")
	}

	deleteForm := url.Values{
		"name": {"team2-logs"},
		"key":  {"uploads/new.txt"},
	}
	deleteReq := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(deleteForm.Encode()))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteReq.AddCookie(sessionCookie)
	deleteRR := httptest.NewRecorder()
	handler.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusSeeOther {
		t.Fatalf("delete status mismatch: got=%d want=%d body=%s", deleteRR.Code, http.StatusSeeOther, deleteRR.Body.String())
	}
	deleteLoc, err := url.Parse(deleteRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse delete location: %v", err)
	}
	if deleteLoc.Query().Get("msg") != "Deleted object: uploads/new.txt" {
		t.Fatalf("delete message mismatch: got=%q", deleteLoc.Query().Get("msg"))
	}
	if deletePath != "/team2-logs/uploads/new.txt" {
		t.Fatalf("delete path mismatch: got=%q want=%q", deletePath, "/team2-logs/uploads/new.txt")
	}
}

func TestAdminBucketUploadAndDeleteRequirePermissions(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request without permissions: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-r": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	var uploadBuf bytes.Buffer
	uploadWriter := multipart.NewWriter(&uploadBuf)
	_ = uploadWriter.WriteField("name", "team2-logs")
	_ = uploadWriter.WriteField("key", "uploads/new.txt")
	_ = uploadWriter.WriteField("size", strconv.Itoa(len("payload-123")))
	filePart, err := uploadWriter.CreateFormFile("file", "new.txt")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := filePart.Write([]byte("payload-123")); err != nil {
		t.Fatalf("write multipart payload: %v", err)
	}
	if err := uploadWriter.Close(); err != nil {
		t.Fatalf("close multipart payload: %v", err)
	}

	uploadReq := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &uploadBuf)
	uploadReq.Header.Set("Content-Type", uploadWriter.FormDataContentType())
	uploadReq.AddCookie(sessionCookie)
	uploadRR := httptest.NewRecorder()
	handler.ServeHTTP(uploadRR, uploadReq)

	if uploadRR.Code != http.StatusSeeOther {
		t.Fatalf("upload status mismatch: got=%d want=%d body=%s", uploadRR.Code, http.StatusSeeOther, uploadRR.Body.String())
	}
	uploadLoc, err := url.Parse(uploadRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upload location: %v", err)
	}
	if uploadLoc.Query().Get("err") != "Write permission is required for uploads." {
		t.Fatalf("expected write-permission error, got=%q", uploadLoc.Query().Get("err"))
	}

	deleteForm := url.Values{
		"name": {"team2-logs"},
		"key":  {"uploads/new.txt"},
	}
	deleteReq := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(deleteForm.Encode()))
	deleteReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	deleteReq.AddCookie(sessionCookie)
	deleteRR := httptest.NewRecorder()
	handler.ServeHTTP(deleteRR, deleteReq)

	if deleteRR.Code != http.StatusSeeOther {
		t.Fatalf("delete status mismatch: got=%d want=%d body=%s", deleteRR.Code, http.StatusSeeOther, deleteRR.Body.String())
	}
	deleteLoc, err := url.Parse(deleteRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse delete location: %v", err)
	}
	if deleteLoc.Query().Get("err") != "Delete permission is required for this bucket." {
		t.Fatalf("expected delete-permission error, got=%q", deleteLoc.Query().Get("err"))
	}
}

func TestAdminBucketUpload100MB(t *testing.T) {
	const uploadSize = int64(100 * 1024 * 1024)

	var putBytes int64
	var putUploadedBy string
	const uploadID = "upload-100mb-1"

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/uploads/large-100mb.bin" && q.Has("uploads"):
			putUploadedBy = r.Header.Get("x-amz-meta-uploaded-by")
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/large-100mb.bin</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/uploads/large-100mb.bin" && q.Get("uploadId") == uploadID:
			n, err := io.Copy(io.Discard, r.Body)
			if err != nil {
				t.Fatalf("read upstream upload-part body: %v", err)
			}
			putBytes += n
			w.Header().Set("ETag", `"etag-part-`+q.Get("partNumber")+`"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/uploads/large-100mb.bin" && q.Get("uploadId") == uploadID:
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/large-100mb.bin</Key><ETag>"etag-100mb"</ETag></CompleteMultipartUploadResult>`)
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-w": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	writeErr := make(chan error, 1)
	go func() {
		defer close(writeErr)
		defer pw.Close()
		defer writer.Close()

		fields := map[string]string{
			"name":    "team2-logs",
			"key":     "uploads/large-100mb.bin",
			"cursor":  "",
			"history": "",
			"size":    strconv.FormatInt(uploadSize, 10),
		}
		for k, v := range fields {
			if err := writer.WriteField(k, v); err != nil {
				writeErr <- err
				return
			}
		}

		filePart, err := writer.CreateFormFile("file", "large-100mb.bin")
		if err != nil {
			writeErr <- err
			return
		}

		chunk := bytes.Repeat([]byte("z"), 1<<20) // 1 MiB
		var remaining = uploadSize
		for remaining > 0 {
			writeLen := int64(len(chunk))
			if remaining < writeLen {
				writeLen = remaining
			}
			if _, err := filePart.Write(chunk[:writeLen]); err != nil {
				writeErr <- err
				return
			}
			remaining -= writeLen
		}
		writeErr <- nil
	}()

	uploadReq := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", pr)
	uploadReq.Header.Set("Content-Type", writer.FormDataContentType())
	uploadReq.AddCookie(sessionCookie)
	uploadRR := httptest.NewRecorder()
	handler.ServeHTTP(uploadRR, uploadReq)

	if err := <-writeErr; err != nil {
		t.Fatalf("stream multipart upload payload: %v", err)
	}
	if uploadRR.Code != http.StatusSeeOther {
		t.Fatalf("upload status mismatch: got=%d want=%d body=%s", uploadRR.Code, http.StatusSeeOther, uploadRR.Body.String())
	}
	loc, err := url.Parse(uploadRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upload location: %v", err)
	}
	if loc.Query().Get("msg") != "Uploaded object: uploads/large-100mb.bin" {
		t.Fatalf("upload success message mismatch: got=%q", loc.Query().Get("msg"))
	}
	if putBytes != uploadSize {
		t.Fatalf("uploaded bytes mismatch: got=%d want=%d", putBytes, uploadSize)
	}
	if putUploadedBy != "alice" {
		t.Fatalf("uploaded-by metadata mismatch: got=%q want=%q", putUploadedBy, "alice")
	}
}

func TestAdminBucketUploadSmallFileWithoutWritableTempDir(t *testing.T) {
	var putPath string
	var uploadedPart1 bytes.Buffer
	const uploadID = "upload-notmp-1"

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/uploads/no-tempdir.txt" && q.Has("uploads"):
			putPath = r.URL.Path
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/no-tempdir.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
		case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/uploads/no-tempdir.txt" && q.Get("uploadId") == uploadID:
			if q.Get("partNumber") == "1" {
				_, _ = io.Copy(&uploadedPart1, r.Body)
			} else {
				_, _ = io.Copy(io.Discard, r.Body)
			}
			w.Header().Set("ETag", `"etag-part-1"`)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/uploads/no-tempdir.txt" && q.Get("uploadId") == uploadID:
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>uploads/no-tempdir.txt</Key><ETag>"etag-notmp"</ETag></CompleteMultipartUploadResult>`)
		default:
			t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
	})
	defer cleanup()

	gw.gcache.set("alice", "secret", map[string]struct{}{
		"team2-w": {},
	})
	handler := adminWebpageHandler(gw)
	sessionCookie := adminLoginSessionCookie(t, handler, "alice", "secret")

	t.Setenv("TMPDIR", "/definitely-not-a-real-temp-dir")

	var uploadBuf bytes.Buffer
	uploadWriter := multipart.NewWriter(&uploadBuf)
	_ = uploadWriter.WriteField("name", "team2-logs")
	_ = uploadWriter.WriteField("key", "uploads/no-tempdir.txt")
	_ = uploadWriter.WriteField("size", strconv.Itoa(len("payload-notmp")))
	filePart, err := uploadWriter.CreateFormFile("file", "no-tempdir.txt")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	if _, err := filePart.Write([]byte("payload-notmp")); err != nil {
		t.Fatalf("write multipart payload: %v", err)
	}
	if err := uploadWriter.Close(); err != nil {
		t.Fatalf("close multipart payload: %v", err)
	}

	uploadReq := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &uploadBuf)
	uploadReq.Header.Set("Content-Type", uploadWriter.FormDataContentType())
	uploadReq.AddCookie(sessionCookie)
	uploadRR := httptest.NewRecorder()
	handler.ServeHTTP(uploadRR, uploadReq)

	if uploadRR.Code != http.StatusSeeOther {
		t.Fatalf("upload status mismatch: got=%d want=%d body=%s", uploadRR.Code, http.StatusSeeOther, uploadRR.Body.String())
	}
	uploadLoc, err := url.Parse(uploadRR.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse upload location: %v", err)
	}
	if uploadLoc.Query().Get("msg") != "Uploaded object: uploads/no-tempdir.txt" {
		t.Fatalf("upload message mismatch: got=%q", uploadLoc.Query().Get("msg"))
	}
	if putPath != "/team2-logs/uploads/no-tempdir.txt" {
		t.Fatalf("put path mismatch: got=%q want=%q", putPath, "/team2-logs/uploads/no-tempdir.txt")
	}
	if uploadedPart1.String() != "payload-notmp" {
		t.Fatalf("put body mismatch: got=%q want=%q", uploadedPart1.String(), "payload-notmp")
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
