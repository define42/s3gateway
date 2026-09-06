package server

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/define42/s3gateway/internal/sigv4"
)

type uploadPropertiesRequest struct {
	header http.Header
	body   []byte
}

func newUploadPropertiesGateway(t *testing.T) (*Server, <-chan uploadPropertiesRequest) {
	t.Helper()
	requests := make(chan uploadPropertiesRequest, 1)
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream upload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- uploadPropertiesRequest{header: r.Header.Clone(), body: body}
		if r.URL.Path != "/team2-bucket/object.gz" {
			t.Errorf("upstream path = %q, want /team2-bucket/object.gz", r.URL.Path)
		}
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("x-amz-copy-source") != "" {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, `<CopyObjectResult><ETag>"copied-etag"</ETag></CopyObjectResult>`)
				return
			}
			w.Header().Set("ETag", `"uploaded-etag"`)
		case http.MethodPost:
			if !r.URL.Query().Has("uploads") {
				t.Errorf("upstream multipart query = %q, want uploads", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`)
		default:
			t.Errorf("unexpected upstream method: %s", r.Method)
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	t.Cleanup(cleanup)
	return gw, requests
}

func receiveUploadPropertiesRequest(t *testing.T, requests <-chan uploadPropertiesRequest) uploadPropertiesRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	default:
		t.Fatal("upload did not reach upstream")
		return uploadPropertiesRequest{}
	}
}

func TestUploadPropertiesForwarded(t *testing.T) {
	payload := gzipUploadPropertiesBody(t)
	for _, operation := range []struct {
		name   string
		method string
		query  string
		body   string
	}{
		{name: "put object", method: http.MethodPut, body: string(payload)},
		{name: "create multipart upload", method: http.MethodPost, query: "?uploads"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			gw, requests := newUploadPropertiesGateway(t)
			headers := map[string]string{
				"Content-Type":                    "application/gzip",
				"Content-Encoding":                "gzip",
				"Cache-Control":                   "private, max-age=3600",
				"Content-Disposition":             `attachment; filename="report.csv.gz"`,
				"Content-Language":                "en-US",
				"Expires":                         "Wed, 01 Jan 2031 00:00:00 GMT",
				"x-amz-tagging":                   "project=release%20audit&owner=team%2B2",
				"x-amz-meta-project":              "release-audit",
				"x-amz-meta-uploaded-by":          "test-user",
				"x-amz-storage-class":             "standard_ia",
				"x-amz-acl":                       "private",
				"x-amz-website-redirect-location": "/reports/latest.csv.gz",
				"x-amz-expected-bucket-owner":     "123456789012",
				"x-amz-request-payer":             "requester",
			}
			req := httptest.NewRequest(operation.method, "/team2-bucket/object.gz"+operation.query, strings.NewReader(operation.body))
			for name, value := range headers {
				req.Header.Set(name, value)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
			}
			upstream := receiveUploadPropertiesRequest(t, requests)
			if string(upstream.body) != operation.body {
				t.Errorf("upstream body = %q, want %q", upstream.body, operation.body)
			}
			for name, want := range headers {
				switch name {
				case "x-amz-acl":
					want = "" // The gateway retains upstream ownership through its existing ACL policy.
				case "x-amz-storage-class":
					want = "STANDARD_IA"
				}
				if got := upstream.header.Get(name); got != want {
					t.Errorf("upstream %s = %q, want %q", name, got, want)
				}
			}
			assertUploadContentEncoding(t, upstream.header, "gzip")
		})
	}
}

func TestUploadPropertiesAbsent(t *testing.T) {
	for _, operation := range []struct {
		name   string
		method string
		query  string
	}{
		{name: "put object", method: http.MethodPut},
		{name: "create multipart upload", method: http.MethodPost, query: "?uploads"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			gw, requests := newUploadPropertiesGateway(t)
			req := httptest.NewRequest(operation.method, "/team2-bucket/object.gz"+operation.query, strings.NewReader("payload"))
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
			}
			upstream := receiveUploadPropertiesRequest(t, requests)
			for _, name := range []string{
				"Content-Encoding", "Cache-Control", "Content-Disposition", "Content-Language",
				"x-amz-tagging", "x-amz-storage-class", "x-amz-website-redirect-location",
				"x-amz-server-side-encryption-bucket-key-enabled", "x-amz-expected-bucket-owner", "x-amz-request-payer",
			} {
				if values := upstream.header.Values(name); len(values) != 0 {
					t.Errorf("unrequested property %s reached upstream: %q", name, values)
				}
			}
		})
	}
}

func TestUploadPropertiesRejectUnsupported(t *testing.T) {
	for _, operation := range []struct {
		name       string
		method     string
		query      string
		copySource string
	}{
		{name: "put object", method: http.MethodPut},
		{name: "create multipart upload", method: http.MethodPost, query: "?uploads"},
		{name: "copy object", method: http.MethodPut, copySource: "/team2-source/source.gz"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, property := range []struct {
				name  string
				value string
			}{
				{name: "x-amz-object-lock-mode", value: "COMPLIANCE"},
				{name: "x-amz-object-lock-retain-until-date", value: "2031-01-01T00:00:00Z"},
				{name: "x-amz-object-lock-legal-hold", value: "ON"},
				{name: "x-amz-write-offset-bytes", value: "0"},
			} {
				t.Run(property.name, func(t *testing.T) {
					for _, value := range []struct {
						name  string
						value string
					}{
						{name: "populated", value: property.value},
						{name: "empty"},
					} {
						t.Run(value.name, func(t *testing.T) {
							var calls atomic.Int32
							gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
								calls.Add(1)
								w.WriteHeader(http.StatusOK)
							})
							t.Cleanup(cleanup)
							req := httptest.NewRequest(operation.method, "/team2-bucket/object.gz"+operation.query, strings.NewReader("payload"))
							req.Header.Set(property.name, value.value)
							if operation.copySource != "" {
								req.Header.Set("x-amz-copy-source", operation.copySource)
							}
							rr := httptest.NewRecorder()
							gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
							if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "<Code>NotImplemented</Code>") {
								t.Errorf("status = %d, body = %s; want 501 NotImplemented", rr.Code, rr.Body.String())
							}
							if got := calls.Load(); got != 0 {
								t.Errorf("unsupported protection reached upstream: %d calls", got)
							}
						})
					}
				})
			}
		})
	}
}

func TestUploadPropertiesRejectInvalidHeaders(t *testing.T) {
	for _, operation := range []struct {
		name   string
		method string
		query  string
	}{
		{name: "put object", method: http.MethodPut},
		{name: "create multipart upload", method: http.MethodPost, query: "?uploads"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, property := range []struct {
				name   string
				header string
				values []string
			}{
				{name: "unknown storage class", header: "x-amz-storage-class", values: []string{"INVALID_CLASS"}},
				{name: "empty storage class", header: "x-amz-storage-class", values: []string{""}},
				{name: "conflicting storage classes", header: "x-amz-storage-class", values: []string{"STANDARD", "STANDARD_IA"}},
				{name: "conflicting content disposition", header: "Content-Disposition", values: []string{"inline", "attachment"}},
				{name: "conflicting tags", header: "x-amz-tagging", values: []string{"owner=alice", "owner=bob"}},
				{name: "conflicting redirects", header: "x-amz-website-redirect-location", values: []string{"/alice", "/bob"}},
				{name: "unframed aws chunked encoding", header: "Content-Encoding", values: []string{"gzip, aws-chunked"}},
			} {
				t.Run(property.name, func(t *testing.T) {
					var calls atomic.Int32
					gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
						calls.Add(1)
						w.WriteHeader(http.StatusOK)
					})
					t.Cleanup(cleanup)
					req := httptest.NewRequest(operation.method, "/team2-bucket/object.gz"+operation.query, strings.NewReader("payload"))
					for _, value := range property.values {
						req.Header.Add(property.header, value)
					}
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidArgument</Code>") {
						t.Errorf("status = %d, body = %s; want 400 InvalidArgument", rr.Code, rr.Body.String())
					}
					if got := calls.Load(); got != 0 {
						t.Errorf("invalid property reached upstream: %d calls", got)
					}
				})
			}
		})
	}
}

func TestUploadPropertiesPreserveListHeaders(t *testing.T) {
	for _, operation := range []struct {
		name       string
		method     string
		query      string
		copySource string
	}{
		{name: "put object", method: http.MethodPut},
		{name: "create multipart upload", method: http.MethodPost, query: "?uploads"},
		{name: "copy object", method: http.MethodPut, copySource: "/team2-bucket/source.gz"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			gw, requests := newUploadPropertiesGateway(t)
			payload := "encoded payload"
			if operation.copySource != "" {
				payload = ""
			}
			req := httptest.NewRequest(
				operation.method, "/team2-bucket/object.gz"+operation.query, strings.NewReader(payload),
			)
			if operation.copySource != "" {
				req.Header.Set("x-amz-copy-source", operation.copySource)
				req.Header.Set("x-amz-metadata-directive", "REPLACE")
			}
			properties := map[string][]string{
				"Content-Encoding": {"gzip", "br"},
				"Cache-Control":    {"no-cache", "no-store"},
				"Content-Language": {"en-US", "da"},
			}
			for name, values := range properties {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
			}
			upstream := receiveUploadPropertiesRequest(t, requests)
			for name, values := range properties {
				if got, want := strings.Join(upstream.header.Values(name), ","), strings.Join(values, ","); got != want {
					t.Errorf("upstream %s = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestUploadPropertiesRejectBucketKeyEnabled(t *testing.T) {
	for _, operation := range []struct {
		name   string
		method string
		query  string
	}{
		{name: "put object", method: http.MethodPut},
		{name: "create multipart upload", method: http.MethodPost, query: "?uploads"},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, value := range []struct {
				name  string
				value string
			}{
				{name: "enabled", value: "true"},
				{name: "disabled", value: "false"},
				{name: "invalid", value: "invalid"},
				{name: "empty"},
			} {
				t.Run(value.name, func(t *testing.T) {
					gw, requests := newUploadPropertiesGateway(t)
					req := httptest.NewRequest(operation.method, "/team2-bucket/object.gz"+operation.query, strings.NewReader("payload"))
					req.Header.Set("x-amz-server-side-encryption-bucket-key-enabled", value.value)
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if rr.Code != http.StatusNotImplemented {
						t.Fatalf("status = %d, want 501; body = %s", rr.Code, rr.Body.String())
					}
					if !strings.Contains(rr.Body.String(), "<Code>NotImplemented</Code>") {
						t.Errorf("body = %s; want NotImplemented", rr.Body.String())
					}
					select {
					case <-requests:
						t.Error("unsupported bucket key header reached upstream")
					default:
					}
				})
			}
		})
	}
}

func gzipUploadPropertiesBody(t *testing.T) []byte {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte("a compressed object uploaded through S3 streaming")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestUploadPropertiesPreserveGzipAfterStreamingDecode(t *testing.T) {
	payload := gzipUploadPropertiesBody(t)
	sum := crc32.ChecksumIEEE(payload)
	checksum := base64.StdEncoding.EncodeToString([]byte{byte(sum >> 24), byte(sum >> 16), byte(sum >> 8), byte(sum)})
	body := fmt.Sprintf("%x\r\n%s\r\n0\r\nx-amz-checksum-crc32:%s\r\n\r\n", len(payload), payload, checksum)
	gw, requests := newUploadPropertiesGateway(t)
	req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.gz", strings.NewReader(body))
	req.Header.Set("Content-Encoding", "gzip, aws-chunked")
	req.Header.Set("x-amz-content-sha256", sigv4.StreamingUnsignedPayloadTrailer)
	req.Header.Set("x-amz-decoded-content-length", strconv.Itoa(len(payload)))
	req.Header.Set("x-amz-trailer", "x-amz-checksum-crc32")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}
	upstream := receiveUploadPropertiesRequest(t, requests)
	if !bytes.Equal(upstream.body, payload) {
		t.Errorf("upstream body = %x, want original gzip bytes %x; encoding = %q", upstream.body, payload, upstream.header.Values("Content-Encoding"))
	}
	assertUploadContentEncoding(t, upstream.header, "gzip")
}

func assertUploadContentEncoding(t *testing.T, headers http.Header, want string) {
	t.Helper()
	var encodings []string
	chunkedCount := 0
	for _, value := range headers.Values("Content-Encoding") {
		for token := range strings.SplitSeq(value, ",") {
			token = strings.TrimSpace(token)
			if !strings.EqualFold(token, "aws-chunked") {
				encodings = append(encodings, token)
			} else {
				chunkedCount++
			}
		}
	}
	if chunkedCount > 1 {
		t.Errorf("upstream transport contains duplicated aws-chunked markers: %q", headers.Values("Content-Encoding"))
	}
	if got := strings.Join(encodings, ","); got != want {
		t.Errorf("upstream object content encoding = %q, want %q; wire encoding = %q", got, want, headers.Values("Content-Encoding"))
	}
}
