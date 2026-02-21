package main

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/sessions"
)

type errReadCloser struct{}

func (errReadCloser) Read(_ []byte) (int, error) {
	return 0, errors.New("boom")
}

func (errReadCloser) Close() error {
	return nil
}

func newLoggedInAdminHandlerWithStub(t *testing.T, groups map[string]struct{}, h http.HandlerFunc) (http.Handler, *http.Cookie, func()) {
	t.Helper()
	gw, cleanup := newGatewayWithStubUpstream(t, h)
	gw.gcache.set("alice", "secret", groups)
	handler := adminWebpageHandler(gw)
	cookie := adminLoginSessionCookie(t, handler, "alice", "secret")
	return handler, cookie, cleanup
}

func newMultipartBody(t *testing.T, fill func(*multipart.Writer) error) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := fill(mw); err != nil {
		t.Fatalf("build multipart body: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return &body, mw.FormDataContentType()
}

func parseRedirectLocation(t *testing.T, rr *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect location: %v", err)
	}
	return loc
}

func TestNormalizeAdminRoutePathCoverage(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: "/"},
		{in: "login", want: "login"},
		{in: "/login/", want: "/login"},
		{in: "///admin///", want: "///admin"},
	}
	for _, tc := range cases {
		if got := normalizeAdminRoutePath(tc.in); got != tc.want {
			t.Fatalf("normalizeAdminRoutePath(%q) mismatch: got=%q want=%q", tc.in, got, tc.want)
		}
	}
}

func TestAdminSessionStoreCoverage(t *testing.T) {
	store := newAdminSessionStore(0, 0)
	if store.ttl != defaultAdminSessionTTL {
		t.Fatalf("ttl default mismatch: got=%s want=%s", store.ttl, defaultAdminSessionTTL)
	}
	if store.maxEntries != defaultGroupCacheMaxEntries {
		t.Fatalf("max entries default mismatch: got=%d want=%d", store.maxEntries, defaultGroupCacheMaxEntries)
	}

	if _, err := store.save("", "", map[string]struct{}{"team2-r": {}}); err == nil {
		t.Fatalf("expected missing username error")
	}

	id, err := store.save("", "alice", map[string]struct{}{"team2-r": {}})
	if err != nil {
		t.Fatalf("save alice: %v", err)
	}
	if id == "" {
		t.Fatalf("expected non-empty session id")
	}

	updatedID, err := store.save(id, "bob", map[string]struct{}{"team2-w": {}})
	if err != nil {
		t.Fatalf("update existing session: %v", err)
	}
	if updatedID != id {
		t.Fatalf("existing session id mismatch: got=%q want=%q", updatedID, id)
	}

	entry, ok := store.get(id)
	if !ok {
		t.Fatalf("expected session to exist")
	}
	if entry.Username != "bob" {
		t.Fatalf("session username mismatch: got=%q want=%q", entry.Username, "bob")
	}
	if _, ok := entry.Groups["team2-w"]; !ok {
		t.Fatalf("updated session groups missing team2-w: %v", entry.Groups)
	}

	if _, ok := store.get(""); ok {
		t.Fatalf("empty session id lookup should fail")
	}

	store.delete("")

	store.mu.Lock()
	stale := store.data[id]
	stale.Expires = time.Now().Add(-1 * time.Second)
	store.data[id] = stale
	store.mu.Unlock()
	if _, ok := store.get(id); ok {
		t.Fatalf("expired session should not be returned")
	}

	store.mu.Lock()
	store.data["expired"] = adminSession{
		Username: "expired-user",
		Expires:  time.Now().Add(-1 * time.Second),
		LastSeen: time.Now().Add(-2 * time.Second),
	}
	store.mu.Unlock()
	if _, err := store.save("", "carol", nil); err != nil {
		t.Fatalf("save carol: %v", err)
	}
	store.mu.Lock()
	_, stillThere := store.data["expired"]
	store.mu.Unlock()
	if stillThere {
		t.Fatalf("expired session entry was not evicted")
	}

	empty := newAdminSessionStore(time.Hour, 2)
	empty.evictOneOldestLocked()

	limited := newAdminSessionStore(time.Hour, 1)
	firstID, err := limited.save("", "first", nil)
	if err != nil {
		t.Fatalf("save first: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	secondID, err := limited.save("", "second", nil)
	if err != nil {
		t.Fatalf("save second: %v", err)
	}
	if firstID == secondID {
		t.Fatalf("expected different ids after eviction")
	}
	limited.mu.Lock()
	defer limited.mu.Unlock()
	if len(limited.data) != 1 {
		t.Fatalf("limited store size mismatch: got=%d want=%d", len(limited.data), 1)
	}
	if _, ok := limited.data[firstID]; ok {
		t.Fatalf("oldest session was not evicted")
	}
	if _, ok := limited.data[secondID]; !ok {
		t.Fatalf("new session missing after eviction")
	}
}

func TestParseSessionGroupsAndSessionValuesCoverage(t *testing.T) {
	groupsFromInterfaces := parseSessionGroups([]interface{}{" Team2-R ", 123, "", "Team2-R"})
	if len(groupsFromInterfaces) != 1 {
		t.Fatalf("groupsFromInterfaces size mismatch: got=%d want=%d", len(groupsFromInterfaces), 1)
	}
	if _, ok := groupsFromInterfaces["team2-r"]; !ok {
		t.Fatalf("expected normalized team2-r group: %v", groupsFromInterfaces)
	}

	groupsFromMap := parseSessionGroups(map[string]struct{}{" Team3-W ": {}})
	if len(groupsFromMap) != 1 {
		t.Fatalf("groupsFromMap size mismatch: got=%d want=%d", len(groupsFromMap), 1)
	}
	if _, ok := groupsFromMap["team3-w"]; !ok {
		t.Fatalf("expected normalized team3-w group: %v", groupsFromMap)
	}

	if got := parseSessionGroups(12345); len(got) != 0 {
		t.Fatalf("unexpected groups for unsupported type: %v", got)
	}

	if _, _, err := adminSessionFromValues(map[interface{}]interface{}{}); err == nil {
		t.Fatalf("expected missing username error")
	}
	if _, _, err := adminSessionFromValues(map[interface{}]interface{}{adminSessionValueUser: 42}); err == nil {
		t.Fatalf("expected invalid username type error")
	}
	if _, _, err := adminSessionFromValues(map[interface{}]interface{}{adminSessionValueUser: "   "}); err == nil {
		t.Fatalf("expected blank username error")
	}

	username, groups, err := adminSessionFromValues(map[interface{}]interface{}{
		adminSessionValueUser: " alice ",
		adminSessionValueGrps: []interface{}{" Team2-R ", "team3-w"},
	})
	if err != nil {
		t.Fatalf("adminSessionFromValues success path: %v", err)
	}
	if username != "alice" {
		t.Fatalf("username normalization mismatch: got=%q want=%q", username, "alice")
	}
	if _, ok := groups["team2-r"]; !ok {
		t.Fatalf("missing team2-r in parsed groups: %v", groups)
	}
	if _, ok := groups["team3-w"]; !ok {
		t.Fatalf("missing team3-w in parsed groups: %v", groups)
	}
}

func TestAdminGorillaStoreSaveCoverage(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	store := newAdminGorillaStore("secret", time.Hour, newAdminSessionStore(time.Hour, 4))

	rr := httptest.NewRecorder()
	session := sessions.NewSession(store, adminSessionCookieName)
	session.Values = map[interface{}]interface{}{
		adminSessionValueUser: "alice",
		adminSessionValueGrps: []string{"team2-r"},
	}
	session.Options = nil
	if err := store.Save(req, rr, session); err != nil {
		t.Fatalf("store.Save success path: %v", err)
	}
	if session.ID == "" {
		t.Fatalf("expected persisted session id")
	}

	expireRR := httptest.NewRecorder()
	session.Options.MaxAge = -1
	if err := store.Save(req, expireRR, session); err != nil {
		t.Fatalf("store.Save clear path: %v", err)
	}
	if session.ID != "" {
		t.Fatalf("expected session id to be cleared after MaxAge<=0")
	}
	var hasClearedCookie bool
	for _, ck := range expireRR.Result().Cookies() {
		if ck.Name == adminSessionCookieName && ck.Value == "" {
			hasClearedCookie = true
			break
		}
	}
	if !hasClearedCookie {
		t.Fatalf("expected cleared session cookie")
	}

	nilBackendStore := newAdminGorillaStore("secret", time.Hour, nil)
	nilBackendSession := sessions.NewSession(nilBackendStore, adminSessionCookieName)
	nilBackendSession.Options = &sessions.Options{MaxAge: 60}
	nilBackendSession.Values = map[interface{}]interface{}{
		adminSessionValueUser: "alice",
		adminSessionValueGrps: []string{"team2-r"},
	}
	if err := nilBackendStore.Save(req, httptest.NewRecorder(), nilBackendSession); err == nil {
		t.Fatalf("expected backend-not-configured error")
	}

	badValuesStore := newAdminGorillaStore("secret", time.Hour, newAdminSessionStore(time.Hour, 2))
	badSession := sessions.NewSession(badValuesStore, adminSessionCookieName)
	badSession.Options = &sessions.Options{MaxAge: 60}
	badSession.Values = map[interface{}]interface{}{
		adminSessionValueUser: "   ",
	}
	if err := badValuesStore.Save(req, httptest.NewRecorder(), badSession); err == nil {
		t.Fatalf("expected invalid session values error")
	}
}

func TestAdminHandlersMethodNotAllowedCoverage(t *testing.T) {
	s := newServer(Config{}, nil)
	handler := adminWebpageHandler(s)

	cases := []struct {
		method string
		target string
		allow  string
	}{
		{method: http.MethodPost, target: "/", allow: "GET, HEAD"},
		{method: http.MethodPut, target: "/login", allow: "GET, HEAD, POST"},
		{method: http.MethodPost, target: "/admin", allow: "GET, HEAD"},
		{method: http.MethodGet, target: "/admin/create-bucket", allow: "POST"},
		{method: http.MethodPost, target: "/admin/bucket", allow: "GET, HEAD"},
		{method: http.MethodPost, target: "/admin/bucket/download", allow: "GET, HEAD"},
		{method: http.MethodGet, target: "/admin/bucket/upload", allow: "POST"},
		{method: http.MethodGet, target: "/admin/bucket/delete", allow: "POST"},
		{method: http.MethodPut, target: "/logout", allow: "POST"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.target, nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status mismatch for %s %s: got=%d want=%d", tc.method, tc.target, rr.Code, http.StatusMethodNotAllowed)
		}
		if got := rr.Header().Get("Allow"); got != tc.allow {
			t.Fatalf("allow header mismatch for %s %s: got=%q want=%q", tc.method, tc.target, got, tc.allow)
		}
	}
}

func TestAdminWebpageHandlerNotFoundCoverage(t *testing.T) {
	handler := adminWebpageHandler(newServer(Config{}, nil))
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleAdminLoginAdditionalBranches(t *testing.T) {
	t.Run("head request writes no body", func(t *testing.T) {
		handler := adminWebpageHandler(newServer(Config{}, nil))
		req := httptest.NewRequest(http.MethodHead, "/login", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusOK)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("expected empty body for HEAD login response")
		}
	})

	t.Run("parse form failure", func(t *testing.T) {
		handler := adminWebpageHandler(newServer(Config{}, nil))
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = errReadCloser{}
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rr.Body.String(), "Invalid form payload.") {
			t.Fatalf("missing invalid form message: %q", rr.Body.String())
		}
	})

	t.Run("backend not configured when server nil", func(t *testing.T) {
		form := url.Values{"username": {"alice"}, "password": {"secret"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handleAdminLogin(nil, rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusInternalServerError)
		}
		if !strings.Contains(rr.Body.String(), "Admin backend is not configured.") {
			t.Fatalf("missing backend-not-configured message: %q", rr.Body.String())
		}
	})

	t.Run("ldap login failure path", func(t *testing.T) {
		handler := adminWebpageHandler(newServer(Config{}, nil))
		form := url.Values{"username": {"alice"}, "password": {"wrong"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusUnauthorized, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "LDAP login failed") {
			t.Fatalf("missing ldap failure message: %q", rr.Body.String())
		}
	})

	t.Run("already logged in redirects to admin", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-r": {}})
		handler := adminWebpageHandler(s)
		cookie := adminLoginSessionCookie(t, handler, "alice", "secret")

		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("invalid existing cookie still allows login", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-r": {}})
		handler := adminWebpageHandler(s)

		form := url.Values{"username": {"alice"}, "password": {"secret"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "invalid-cookie-value"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusSeeOther, rr.Body.String())
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("session save failure", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-r": {}})
		s.adminWebSessions.backend = nil
		handler := adminWebpageHandler(s)

		form := url.Values{"username": {"alice"}, "password": {"secret"}}
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusInternalServerError)
		}
		if !strings.Contains(rr.Body.String(), "Could not create admin session.") {
			t.Fatalf("missing session-save error message: %q", rr.Body.String())
		}
	})
}

func TestHandleAdminDashboardAdditionalBranches(t *testing.T) {
	t.Run("invalid cookie clears and redirects to login", func(t *testing.T) {
		s := newServer(Config{}, nil)
		handler := adminWebpageHandler(s)
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "invalid"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/login")
		}
		var cleared bool
		for _, ck := range rr.Result().Cookies() {
			if ck.Name == adminSessionCookieName && ck.Value == "" {
				cleared = true
				break
			}
		}
		if !cleared {
			t.Fatalf("expected cleared session cookie")
		}
	})

	t.Run("list buckets error writes bad gateway", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-r": {}})
		handler := adminWebpageHandler(s)
		cookie := adminLoginSessionCookie(t, handler, "alice", "secret")

		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, http.StatusBadGateway, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "Could not list S3 buckets.") {
			t.Fatalf("missing list-buckets error message: %q", rr.Body.String())
		}
	})

	t.Run("head request suppresses body", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/" {
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Owner><ID>o</ID><DisplayName>o</DisplayName></Owner><Buckets></Buckets></ListAllMyBucketsResult>`)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodHead, "/admin", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusOK)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("expected empty body for HEAD dashboard response")
		}
	})
}

func TestHandleAdminCreateBucketAdditionalBranches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Run("invalid cookie clears and redirects", func(t *testing.T) {
		s := newServer(Config{}, nil)
		handler := adminWebpageHandler(s)
		form := url.Values{"space": {"team2"}, "suffix": {"demo"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "invalid"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/login")
		}
	})

	t.Run("nil upstream redirects to backend error", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-c": {}})
		handler := adminWebpageHandler(s)
		cookie := adminLoginSessionCookie(t, handler, "alice", "secret")

		form := url.Values{"space": {"team2"}, "suffix": {"demo"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Path != "/admin" {
			t.Fatalf("redirect path mismatch: got=%q want=%q", loc.Path, "/admin")
		}
		if loc.Query().Get("err") != "Admin backend is not configured." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("parse form failure", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-c": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = errReadCloser{}
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Invalid form payload." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("invalid suffix triggers build bucket name error", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-c": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request for invalid suffix: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		form := url.Values{"space": {"team2"}, "suffix": {"---"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "bucket name suffix is required" {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("upstream create bucket failure", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-c": {}}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != "/team2-demo" {
				t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "boom")
		})
		defer cleanup()

		form := url.Values{"space": {"team2"}, "suffix": {"demo"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not create bucket." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})
}

func TestHandleAdminBucketPageAdditionalBranches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Run("invalid cookie clears and redirects", func(t *testing.T) {
		s := newServer(Config{}, nil)
		handler := adminWebpageHandler(s)
		req := httptest.NewRequest(http.MethodGet, "/admin/bucket?name=team2-logs", nil)
		req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "invalid"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/login")
		}
	})

	t.Run("missing bucket name", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rr.Body.String(), "Bucket name is required.") {
			t.Fatalf("missing required-bucket message: %q", rr.Body.String())
		}
	})

	t.Run("head request suppresses body", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/team2-logs" {
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>team2-logs</Name><IsTruncated>false</IsTruncated></ListBucketResult>`)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodHead, "/admin/bucket?name=team2-logs", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusOK)
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("expected empty body for HEAD bucket page")
		}
	})

	t.Run("forbidden without read permission", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket?name=team2-logs", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusForbidden)
		}
		if !strings.Contains(rr.Body.String(), "Read permission is required for this bucket.") {
			t.Fatalf("missing read-permission message: %q", rr.Body.String())
		}
	})

	t.Run("invalid history cursor state", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket?name=team2-logs&history=!!!!", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusBadRequest)
		}
		if !strings.Contains(rr.Body.String(), "Invalid pagination cursor state.") {
			t.Fatalf("missing invalid-history message: %q", rr.Body.String())
		}
	})

	t.Run("list objects upstream failure", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/team2-logs" {
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, "nope")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket?name=team2-logs", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusBadGateway)
		}
		if !strings.Contains(rr.Body.String(), "Could not list bucket objects.") {
			t.Fatalf("missing list-objects error message: %q", rr.Body.String())
		}
	})
}

func TestHandleAdminBucketDownloadAdditionalBranches(t *testing.T) {
	t.Run("invalid cookie clears and redirects", func(t *testing.T) {
		s := newServer(Config{}, nil)
		handler := adminWebpageHandler(s)
		req := httptest.NewRequest(http.MethodGet, "/admin/bucket/download?name=team2-logs&key=a.txt", nil)
		req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "invalid"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/login")
		}
	})

	t.Run("nil upstream redirects with error", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-r": {}})
		handler := adminWebpageHandler(s)
		cookie := adminLoginSessionCookie(t, handler, "alice", "secret")

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket/download?name=team2-logs&key=a.txt", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Admin backend is not configured." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("missing bucket or key", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket/download?name=team2-logs", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Bucket name and object key are required." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("read permission required", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket/download?name=team2-logs&key=a.txt", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Read permission is required for this bucket." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("upstream download failure", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/team2-logs/a.txt" {
				t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusNotFound)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/admin/bucket/download?name=team2-logs&key=a.txt", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not download object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("head request success with default content type", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/team2-logs/a.txt" {
				t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodHead, "/admin/bucket/download?name=team2-logs&key=a.txt", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusOK)
		}
		if got := rr.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("content type mismatch: got=%q want=%q", got, "application/octet-stream")
		}
		if rr.Body.Len() != 0 {
			t.Fatalf("expected empty body for HEAD download response")
		}
	})
}

func TestHandleAdminBucketDeleteAdditionalBranches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Run("invalid cookie clears and redirects", func(t *testing.T) {
		s := newServer(Config{}, nil)
		handler := adminWebpageHandler(s)
		form := url.Values{"name": {"team2-logs"}, "key": {"a.txt"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "invalid"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/login")
		}
	})

	t.Run("nil upstream redirects to admin", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-d": {}})
		handler := adminWebpageHandler(s)
		cookie := adminLoginSessionCookie(t, handler, "alice", "secret")

		form := url.Values{"name": {"team2-logs"}, "key": {"a.txt"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("parse form error", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-d": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", nil)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Body = errReadCloser{}
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("missing bucket", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-d": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		form := url.Values{"key": {"a.txt"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("missing key", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-d": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		form := url.Values{"name": {"team2-logs"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Object key is required." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("upstream delete failure", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-d": {}}, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/team2-logs/a.txt" {
				t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(http.StatusInternalServerError)
		})
		defer cleanup()

		form := url.Values{"name": {"team2-logs"}, "key": {"a.txt"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not delete object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})
}

func TestHandleAdminLogoutAdditionalBranches(t *testing.T) {
	t.Run("nil server still redirects", func(t *testing.T) {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		handleAdminLogout(nil, rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/login")
		}
	})

	t.Run("head method rejected", func(t *testing.T) {
		s := newServer(Config{}, nil)
		handler := adminWebpageHandler(s)
		req := httptest.NewRequest(http.MethodHead, "/logout", nil)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusMethodNotAllowed)
		}
		if got := rr.Header().Get("Allow"); got != "POST" {
			t.Fatalf("allow mismatch: got=%q want=%q", got, "POST")
		}
	})
}

func TestAdminMutatingRoutesRejectBrowserRequestsWithoutTrustedOrigin(t *testing.T) {
	handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-rwcdb": {}}, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
	})
	defer cleanup()

	t.Run("create bucket", func(t *testing.T) {
		form := url.Values{"space": {"team2"}, "suffix": {"new"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/create-bucket", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Invalid form origin." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("upload", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", strings.NewReader("ignored"))
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Invalid form origin." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("delete", func(t *testing.T) {
		form := url.Values{"name": {"team2-logs"}, "key": {"a.txt"}}
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Invalid form origin." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("logout", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/logout", nil)
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusForbidden)
		}
	})
}

func TestHandleAdminBucketUploadAdditionalBranches(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Run("invalid cookie clears and redirects", func(t *testing.T) {
		handler := adminWebpageHandler(newServer(Config{}, nil))
		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			if err := mw.WriteField("size", "3"); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(&http.Cookie{Name: adminSessionCookieName, Value: "invalid"})
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/login" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/login")
		}
	})

	t.Run("nil upstream redirects to admin", func(t *testing.T) {
		s := newServer(Config{}, nil)
		s.gcache.set("alice", "secret", map[string]struct{}{"team2-w": {}})
		handler := adminWebpageHandler(s)
		cookie := adminLoginSessionCookie(t, handler, "alice", "secret")

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			return mw.WriteField("name", "team2-logs")
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("multipart reader error", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", strings.NewReader("bad"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("invalid file size", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			return mw.WriteField("size", "not-an-int")
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Invalid file size." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("missing bucket when file part arrives", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("empty final key after trim", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			if err := mw.WriteField("key", "/"); err != nil {
				return err
			}
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", `form-data; name="file"; filename=""`)
			h.Set("Content-Type", "application/octet-stream")
			_, err := mw.CreatePart(h)
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Object key is required." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("size above 5 TiB rejected", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		tooLarge := strconv.FormatInt(5*1024*1024*1024*1024+1, 10)
		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			if err := mw.WriteField("size", tooLarge); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "File is too large. Maximum supported object size is 5 TiB." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("create multipart failure", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			if !(r.Method == http.MethodPost && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Has("uploads")) {
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			w.WriteHeader(http.StatusInternalServerError)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not upload object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("multipart create without upload id", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			if !(r.Method == http.MethodPost && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Has("uploads")) {
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>a.txt</Key></InitiateMultipartUploadResult>`)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not upload object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("upload part failure aborts multipart", func(t *testing.T) {
		const uploadID = "upload-part-fail"
		var abortSeen bool
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Has("uploads"):
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>a.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
			case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Get("uploadId") == uploadID:
				w.WriteHeader(http.StatusInternalServerError)
			case r.Method == http.MethodDelete && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Get("uploadId") == uploadID:
				abortSeen = true
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not upload object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
		if !abortSeen {
			t.Fatalf("expected abort multipart call after upload part failure")
		}
	})

	t.Run("missing part etag aborts multipart", func(t *testing.T) {
		const uploadID = "upload-missing-etag"
		var abortSeen bool
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Has("uploads"):
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>a.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
			case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Get("uploadId") == uploadID:
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodDelete && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Get("uploadId") == uploadID:
				abortSeen = true
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not upload object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
		if !abortSeen {
			t.Fatalf("expected abort multipart call after missing etag")
		}
	})

	t.Run("complete multipart failure aborts", func(t *testing.T) {
		const uploadID = "upload-complete-fail"
		var abortSeen bool
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Has("uploads"):
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>a.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
			case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Get("uploadId") == uploadID:
				w.Header().Set("ETag", `"etag-part-1"`)
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Get("uploadId") == uploadID:
				w.WriteHeader(http.StatusInternalServerError)
			case r.Method == http.MethodDelete && r.URL.Path == "/team2-logs/a.txt" && r.URL.Query().Get("uploadId") == uploadID:
				abortSeen = true
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			part, err := mw.CreateFormFile("file", "a.txt")
			if err != nil {
				return err
			}
			_, err = part.Write([]byte("abc"))
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not upload object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
		if !abortSeen {
			t.Fatalf("expected abort multipart call after complete failure")
		}
	})

	t.Run("empty file falls back to put object", func(t *testing.T) {
		const uploadID = "upload-empty-put"
		var putLength string
		var abortSeen bool
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/empty.txt" && r.URL.Query().Has("uploads"):
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>empty.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
			case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/empty.txt" && r.URL.Query().Get("uploadId") == uploadID:
				t.Fatalf("unexpected upload-part call for empty file")
			case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/empty.txt" && r.URL.Query().Get("uploadId") == "":
				putLength = r.Header.Get("Content-Length")
				w.Header().Set("ETag", `"etag-empty"`)
				w.WriteHeader(http.StatusOK)
			case r.Method == http.MethodDelete && r.URL.Path == "/team2-logs/empty.txt" && r.URL.Query().Get("uploadId") == uploadID:
				abortSeen = true
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			if err := mw.WriteField("key", "empty.txt"); err != nil {
				return err
			}
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", `form-data; name="file"; filename="empty.txt"`)
			h.Set("Content-Type", "text/plain")
			_, err := mw.CreatePart(h)
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("msg") != "Uploaded object: empty.txt" {
			t.Fatalf("message mismatch: got=%q", loc.Query().Get("msg"))
		}
		if putLength != "0" {
			t.Fatalf("expected put object fallback with content-length 0, got=%q", putLength)
		}
		if !abortSeen {
			t.Fatalf("expected multipart abort after empty put fallback success")
		}
	})

	t.Run("empty file put fallback failure", func(t *testing.T) {
		const uploadID = "upload-empty-put-fail"
		var abortSeen bool
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/team2-logs/empty-fail.txt" && r.URL.Query().Has("uploads"):
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-logs</Bucket><Key>empty-fail.txt</Key><UploadId>`+uploadID+`</UploadId></InitiateMultipartUploadResult>`)
			case r.Method == http.MethodPut && r.URL.Path == "/team2-logs/empty-fail.txt" && r.URL.Query().Get("uploadId") == "":
				w.WriteHeader(http.StatusInternalServerError)
			case r.Method == http.MethodDelete && r.URL.Path == "/team2-logs/empty-fail.txt" && r.URL.Query().Get("uploadId") == uploadID:
				abortSeen = true
				w.WriteHeader(http.StatusNoContent)
			default:
				t.Fatalf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			if err := mw.WriteField("key", "empty-fail.txt"); err != nil {
				return err
			}
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", `form-data; name="file"; filename="empty-fail.txt"`)
			h.Set("Content-Type", "text/plain")
			_, err := mw.CreatePart(h)
			return err
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Could not upload object." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
		if !abortSeen {
			t.Fatalf("expected abort after empty put fallback failure")
		}
	})

	t.Run("no file part and no bucket redirects admin", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			return mw.WriteField("ignored", "x")
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status mismatch: got=%d want=%d", rr.Code, http.StatusSeeOther)
		}
		if rr.Header().Get("Location") != "/admin" {
			t.Fatalf("location mismatch: got=%q want=%q", rr.Header().Get("Location"), "/admin")
		}
	})

	t.Run("no file part and no write permission", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-r": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			return mw.WriteField("ignored", "x")
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "Write permission is required for uploads." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})

	t.Run("no file part with write permission shows required message", func(t *testing.T) {
		handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-w": {}}, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		})
		defer cleanup()

		body, contentType := newMultipartBody(t, func(mw *multipart.Writer) error {
			if err := mw.WriteField("name", "team2-logs"); err != nil {
				return err
			}
			return mw.WriteField("ignored", "x")
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", body)
		req.Header.Set("Content-Type", contentType)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		loc := parseRedirectLocation(t, rr)
		if loc.Query().Get("err") != "A file is required for upload." {
			t.Fatalf("error mismatch: got=%q", loc.Query().Get("err"))
		}
	})
}
