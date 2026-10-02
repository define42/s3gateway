package adminpage

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestAdminUploadPreservesLiteralObjectKeys(t *testing.T) {
	for _, tt := range []struct {
		name     string
		key      string
		filename string
		wantKey  string
	}{
		{name: "surrounding spaces", key: " report.txt ", wantKey: " report.txt "},
		{name: "leading slash", key: "/report.txt", wantKey: "/report.txt"},
		{name: "slash only", key: "/", wantKey: "/"},
		{name: "multiple leading slashes", key: "//report.txt", wantKey: "//report.txt"},
		{name: "whitespace only", key: "   ", wantKey: "   "},
		{name: "unicode whitespace", key: "\u2003report.txt\u00a0", wantKey: "\u2003report.txt\u00a0"},
		{name: "escaped punctuation", key: ` folder/a&b+%?#"<.txt `, wantKey: ` folder/a&b+%?#"<.txt `},
		{name: "line endings", key: "\r\nreport\n.txt\r", wantKey: "\r\nreport\n.txt\r"},
		{name: "empty key uses filename", filename: "fallback.txt", wantKey: "fallback.txt"},
		{name: "filename spaces", filename: " report.txt ", wantKey: " report.txt "},
		{name: "whitespace filename", filename: "   ", wantKey: "   "},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const bucket = "team2-logs"
			const payload = "new object contents"
			objects := map[string]string{tt.wantKey: "old object contents"}
			for _, sibling := range []string{strings.TrimSpace(tt.wantKey), strings.TrimPrefix(tt.wantKey, "/")} {
				if sibling != "" && sibling != tt.wantKey {
					objects[sibling] = "unchanged sibling"
				}
			}
			h := newHandlerWithNilS3(map[string]struct{}{"team2-w": {}})
			var uploaded string
			h.s3 = s3.New(s3.Options{
				Region:                     "us-east-1",
				BaseEndpoint:               aws.String("https://upstream.test"),
				UsePathStyle:               true,
				Credentials:                credentials.NewStaticCredentialsProvider("test-ak", "test-sk", ""),
				RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
				HTTPClient: adminUploadIntegrityHTTPClient(func(r *http.Request) (*http.Response, error) {
					key := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
					if key != tt.wantKey {
						t.Errorf("upstream %s key = %q, want %q", r.Method, key, tt.wantKey)
					}
					body := ""
					header := make(http.Header)
					switch q := r.URL.Query(); {
					case r.Method == http.MethodPost && q.Has("uploads"):
						body = `<InitiateMultipartUploadResult><UploadId>upload-keys</UploadId></InitiateMultipartUploadResult>`
					case r.Method == http.MethodPut && q.Get("uploadId") == "upload-keys":
						data, err := io.ReadAll(r.Body)
						if err != nil {
							t.Fatal(err)
						}
						uploaded = string(data)
						header.Set("ETag", `"part-etag"`)
					case r.Method == http.MethodPost && q.Get("uploadId") == "upload-keys":
						objects[key] = uploaded
						body = `<CompleteMultipartUploadResult><ETag>"object-etag"</ETag></CompleteMultipartUploadResult>`
					default:
						t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
					}
					return &http.Response{StatusCode: http.StatusOK, Header: header, Body: io.NopCloser(strings.NewReader(body))}, nil
				}),
			})
			notifier := &recordingAdminUploadNotifier{}
			h.uploadNotifier = notifier
			cookie := adminLoginSessionCookie(t, h, "alice", "secret")
			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			for _, field := range [][2]string{{"name", bucket}, {"key", tt.key}} {
				if err := writer.WriteField(field[0], field[1]); err != nil {
					t.Fatal(err)
				}
			}
			filename := tt.filename
			if filename == "" {
				filename = "fallback.txt"
			}
			file, err := writer.CreateFormFile("file", filename)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(file, payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", &body)
			r.Header.Set("Content-Type", writer.FormDataContentType())
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			location := parseRedirectLocation(t, w)
			if got := location.Query().Get("msg"); got != "Uploaded object: "+tt.wantKey {
				t.Errorf("upload notice = %q, want exact key %q; error = %q", got, tt.wantKey, location.Query().Get("err"))
			}
			if objects[tt.wantKey] != payload {
				t.Errorf("requested object contents = %q, want %q", objects[tt.wantKey], payload)
			}
			for key, contents := range objects {
				if key != tt.wantKey && contents != "unchanged sibling" {
					t.Errorf("upload changed sibling object %q", key)
				}
			}
			if len(notifier.events) != 1 || notifier.events[0].Key != tt.wantKey {
				t.Errorf("notification did not preserve key: %+v", notifier.events)
			}
		})
	}
}
