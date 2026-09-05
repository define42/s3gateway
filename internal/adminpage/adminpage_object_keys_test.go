package adminpage

import (
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	htmlparser "golang.org/x/net/html"
)

func TestAdminObjectKeysPreserved(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  string
	}{
		{name: "leading space", key: " report.txt"},
		{name: "trailing space", key: "report.txt "},
		{name: "surrounding spaces", key: " report.txt "},
		{name: "whitespace only", key: "   "},
		{name: "unicode whitespace", key: "\u2003report.txt\u00a0"},
		{name: "escaped punctuation", key: ` folder/a&b+%?#"<.txt `},
		{name: "carriage returns", key: "\rreport\r.txt\r"},
		{name: "line feeds", key: "\nreport\n.txt\n"},
		{name: "CRLF", key: "\r\nreport\r\n.txt\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const bucket = "team2-logs"
			objects := map[string]string{tt.key: "requested object"}
			for _, sibling := range []string{strings.TrimSpace(tt.key), normalizeAdminFormNewlines(tt.key)} {
				if sibling != "" && sibling != tt.key {
					objects[sibling] = "sibling object"
				}
			}
			var mu sync.Mutex
			handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-rd": {}}, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				if r.Method == http.MethodGet && r.URL.Path == "/"+bucket && r.URL.Query().Get("list-type") == "2" {
					w.Header().Set("Content-Type", "application/xml")
					_, _ = io.WriteString(w, `<ListBucketResult><Name>`+bucket+`</Name><IsTruncated>false</IsTruncated><Contents><Key>`)
					if err := xml.EscapeText(w, []byte(tt.key)); err != nil {
						t.Errorf("write listed key: %v", err)
					}
					_, _ = io.WriteString(w, `</Key><Size>16</Size></Contents></ListBucketResult>`)
					return
				}
				key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
				if key != tt.key {
					t.Errorf("upstream %s key = %q, want %q", r.Method, key, tt.key)
				}
				body, ok := objects[key]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				switch r.Method {
				case http.MethodHead:
					w.WriteHeader(http.StatusOK)
				case http.MethodGet:
					_, _ = io.WriteString(w, body)
				case http.MethodDelete:
					delete(objects, key)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected upstream method %s", r.Method)
					w.WriteHeader(http.StatusBadRequest)
				}
			})
			defer cleanup()

			r := httptest.NewRequest(http.MethodGet, "/admin/bucket?name="+bucket, nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("listing status = %d, want 200", w.Code)
			}
			listed := false
			for _, match := range regexp.MustCompile(`<code>([^<]*)</code>`).FindAllStringSubmatch(w.Body.String(), -1) {
				if html.UnescapeString(match[1]) == tt.key {
					listed = true
				}
			}
			if !listed {
				t.Errorf("listing does not preserve key %q", tt.key)
			}
			downloadURL, deleteAction, form := adminObjectActionsFromHTML(t, w.Body.String())
			for _, action := range []string{downloadURL, deleteAction} {
				u, err := url.Parse(action)
				if err != nil || u.Query().Get("key") != tt.key {
					t.Errorf("action %q does not preserve key %q", action, tt.key)
				}
			}

			r = httptest.NewRequest(http.MethodGet, downloadURL, nil)
			r.AddCookie(cookie)
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK || w.Body.String() != "requested object" {
				t.Errorf("download status/body = %d/%q, want 200/requested object", w.Code, w.Body.String())
			}

			r = httptest.NewRequest(http.MethodPost, deleteAction, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(cookie)
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			location := parseRedirectLocation(t, w)
			if got := location.Query().Get("msg"); got != "Deleted object: "+tt.key {
				t.Errorf("delete notice = %q, want %q", got, "Deleted object: "+tt.key)
			}
			mu.Lock()
			defer mu.Unlock()
			if _, exists := objects[tt.key]; exists {
				t.Error("requested object was not deleted")
			}
			for key, body := range objects {
				if key != tt.key && body != "sibling object" {
					t.Errorf("sibling object %q was changed", key)
				}
			}
			for _, sibling := range []string{strings.TrimSpace(tt.key), normalizeAdminFormNewlines(tt.key)} {
				if sibling != "" && sibling != tt.key && objects[sibling] != "sibling object" {
					t.Errorf("deletion changed sibling object %q", sibling)
				}
			}
		})
	}
}

func TestAdminObjectActionsRejectEmptyKey(t *testing.T) {
	for _, tt := range []struct {
		name   string
		method string
		path   string
		err    string
	}{
		{name: "download", method: http.MethodGet, path: "/admin/bucket/download", err: "Bucket name and object key are required."},
		{name: "delete", method: http.MethodPost, path: "/admin/bucket/delete", err: "Object key is required."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-rd": {}}, func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("empty key reached upstream: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusBadRequest)
			})
			defer cleanup()
			form := url.Values{"name": {"team2-logs"}, "key": {""}}
			r := httptest.NewRequest(tt.method, tt.path+"?"+form.Encode(), nil)
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			location := parseRedirectLocation(t, w)
			if got := location.Query().Get("err"); got != tt.err {
				t.Errorf("error = %q, want %q", got, tt.err)
			}
		})
	}
}

func adminObjectActionsFromHTML(t *testing.T, page string) (downloadURL, deleteAction string, form url.Values) {
	t.Helper()
	form = url.Values{}
	tokens := htmlparser.NewTokenizer(strings.NewReader(page))
	inDeleteForm := false
	for {
		kind := tokens.Next()
		if kind == htmlparser.ErrorToken {
			if err := tokens.Err(); err != io.EOF {
				t.Fatalf("parse bucket page: %v", err)
			}
			break
		}
		token := tokens.Token()
		if kind == htmlparser.EndTagToken && token.Data == "form" {
			inDeleteForm = false
		}
		if kind != htmlparser.StartTagToken && kind != htmlparser.SelfClosingTagToken {
			continue
		}
		attrs := make(map[string]string, len(token.Attr))
		for _, attr := range token.Attr {
			attrs[attr.Key] = attr.Val
		}
		switch token.Data {
		case "a":
			if strings.HasPrefix(attrs["href"], "/admin/bucket/download?") {
				downloadURL = attrs["href"]
			}
		case "form":
			inDeleteForm = strings.HasPrefix(attrs["action"], "/admin/bucket/delete")
			if inDeleteForm {
				deleteAction = attrs["action"]
			}
		case "input":
			if inDeleteForm && attrs["name"] != "" {
				form.Set(attrs["name"], normalizeAdminFormNewlines(attrs["value"]))
			}
		}
	}
	if downloadURL == "" || deleteAction == "" {
		t.Fatal("listed object has no download link or delete form")
	}
	return downloadURL, deleteAction, form
}

// HTML parsing and form submission normalize CR and LF in input values.
func normalizeAdminFormNewlines(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\n", "\r\n")
}

func TestAdminDeleteFormPreservesWhitespaceKeys(t *testing.T) {
	for _, tt := range []struct{ name, key string }{
		{name: "surrounding spaces", key: " report.txt "},
		{name: "whitespace only", key: "   "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var called atomic.Bool
			handler, cookie, cleanup := newLoggedInAdminHandlerWithStub(t, map[string]struct{}{"team2-d": {}}, func(w http.ResponseWriter, r *http.Request) {
				called.Store(true)
				if r.Method != http.MethodDelete || r.URL.Path != "/team2-logs/"+tt.key {
					t.Errorf("upstream request = %s %q, want DELETE %q", r.Method, r.URL.Path, "/team2-logs/"+tt.key)
				}
				w.WriteHeader(http.StatusNoContent)
			})
			defer cleanup()
			form := url.Values{"name": {"team2-logs"}, "key": {tt.key}}
			r := httptest.NewRequest(http.MethodPost, "/admin/bucket/delete", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if !called.Load() || parseRedirectLocation(t, w).Query().Get("err") != "" {
				t.Error("nonempty whitespace key was rejected")
			}
		})
	}
}
