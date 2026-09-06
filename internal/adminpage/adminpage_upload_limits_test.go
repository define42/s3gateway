package adminpage

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// adminUploadReadGuard supplies enough data to reject a part, then records
// attempts to read its withheld remainder without blocking the test.
type adminUploadReadGuard struct {
	prefix  *bytes.Reader
	drained bool
}

func (r *adminUploadReadGuard) Read(p []byte) (int, error) {
	if r.prefix.Len() > 0 {
		return r.prefix.Read(p)
	}
	r.drained = true
	return 0, errors.New("read past rejection point")
}

func TestAdminUploadRejectsPartsWithoutDraining(t *testing.T) {
	for _, tt := range []struct {
		name             string
		partName         string
		bucket           bool
		fields           [][2]string
		emptyFields      int
		metadataFields   int
		requiredMetadata bool
		wantCreate       bool
		transferEncoding bool
	}{
		{name: "oversized bucket field", partName: "name"},
		{name: "metadata before authorization", partName: "meta-project"},
		{name: "file before bucket", partName: "file"},
		{name: "oversized unknown field", partName: "ignored"},
		{name: "encoded bucket field", partName: "name", transferEncoding: true},
		{name: "encoded unknown field", partName: "ignored", transferEncoding: true},
		{name: "encoded metadata", partName: "meta-project", bucket: true, transferEncoding: true},
		{name: "too many parts", partName: "ignored", emptyFields: maxAdminUploadParts},
		{name: "oversized metadata", partName: "meta-project", bucket: true},
		{name: "empty metadata key", partName: "meta-", bucket: true},
		{name: "oversized metadata key", partName: "meta-" + strings.Repeat("k", maxAdminUploadMetadataKeyBytes+1), bucket: true},
		{name: "too many metadata fields", partName: "meta-project", bucket: true, metadataFields: maxAdminUploadMetadataFields},
		{name: "missing object key", partName: "file", bucket: true},
		{name: "oversized declared file", partName: "file", bucket: true, fields: [][2]string{{"key", "large.txt"}, {"size", "5497558138881"}}},
		{name: "missing required metadata", partName: "file", bucket: true, fields: [][2]string{{"key", "file.txt"}}, requiredMetadata: true},
		{name: "upstream initiation failure", partName: "file", bucket: true, fields: [][2]string{{"key", "file.txt"}}, wantCreate: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			groups := map[string]struct{}{}
			if tt.bucket {
				groups["team2-w"] = struct{}{}
			}
			h := newHandlerWithNilS3(groups)
			calls := 0
			h.s3 = s3.New(s3.Options{
				Region:           "us-east-1",
				BaseEndpoint:     aws.String("https://upstream.test"),
				Credentials:      credentials.NewStaticCredentialsProvider("test-ak", "test-sk", ""),
				RetryMaxAttempts: 1,
				HTTPClient: adminUploadIntegrityHTTPClient(func(r *http.Request) (*http.Response, error) {
					calls++
					if !tt.wantCreate || r.Method != http.MethodPost || !r.URL.Query().Has("uploads") {
						t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
					}
					return nil, errors.New("upstream unavailable")
				}),
			})
			if tt.requiredMetadata {
				h.requiredUploadMetadataKeys = []string{"project"}
			}
			cookie := adminLoginSessionCookie(t, h, "alice", "secret")
			var body bytes.Buffer
			mw := multipart.NewWriter(&body)
			writeField := func(name, value string) {
				t.Helper()
				if err := mw.WriteField(name, value); err != nil {
					t.Fatal(err)
				}
			}
			if tt.bucket {
				writeField("name", "team2-logs")
			}
			for _, field := range tt.fields {
				writeField(field[0], field[1])
			}
			for range tt.emptyFields {
				writeField("ignored", "")
			}
			for range tt.metadataFields {
				writeField("meta-project", "")
			}
			header := make(textproto.MIMEHeader)
			header.Set("Content-Disposition", mime.FormatMediaType("form-data", map[string]string{"name": tt.partName}))
			if tt.transferEncoding {
				header.Set("Content-Transfer-Encoding", "quoted-printable")
			}
			part, err := mw.CreatePart(header)
			if err != nil {
				t.Fatal(err)
			}
			payload := strings.Repeat("x", 12<<10)
			if tt.transferEncoding {
				payload = strings.Repeat("=\r\n", 4<<10)
			}
			if _, err := io.WriteString(part, payload); err != nil {
				t.Fatal(err)
			}
			guard := &adminUploadReadGuard{prefix: bytes.NewReader(body.Bytes())}
			req := httptest.NewRequest(http.MethodPost, "/admin/bucket/upload", guard)
			req.Header.Set("Content-Type", mw.FormDataContentType())
			req.AddCookie(cookie)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if guard.drained {
				t.Error("rejection read the withheld remainder of the multipart part")
			}
			if response.Code != http.StatusSeeOther || response.Header().Get("Connection") != "close" {
				t.Errorf("rejection = %d, headers = %v; want redirect closing HTTP/1 connection", response.Code, response.Header())
			}
			wantCalls := 0
			if tt.wantCreate {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Errorf("upstream calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}
