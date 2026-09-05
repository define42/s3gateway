package server

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var completeMultipartResponseHeaderNames = []string{
	"x-amz-version-id",
	"x-amz-expiration",
	"x-amz-server-side-encryption",
	"x-amz-server-side-encryption-aws-kms-key-id",
	"x-amz-server-side-encryption-bucket-key-enabled",
	"x-amz-request-charged",
}

func TestCompleteMultipartResponseHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "version and completion metadata",
			headers: map[string]string{
				"x-amz-version-id":                                "version-123",
				"x-amz-expiration":                                `expiry-date="Fri, 05 Sep 2031 00:00:00 GMT", rule-id="archive%20rule"`,
				"x-amz-server-side-encryption":                    "aws:kms",
				"x-amz-server-side-encryption-aws-kms-key-id":     "arn:aws:kms:us-east-1:123456789012:key/test-key",
				"x-amz-server-side-encryption-bucket-key-enabled": "true",
				"x-amz-request-charged":                           "requester",
			},
		},
		{
			name: "literal null version",
			headers: map[string]string{
				"x-amz-version-id": "null",
			},
		},
		{
			name: "bucket key explicitly disabled",
			headers: map[string]string{
				"x-amz-server-side-encryption":                    "aws:kms",
				"x-amz-server-side-encryption-bucket-key-enabled": "false",
			},
		},
		{name: "optional metadata absent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := make(http.Header)
			for name, value := range tc.headers {
				headers.Set(name, value)
			}
			const upstreamBody = `<CompleteMultipartUploadResult><Bucket>team2-bucket</Bucket><Key>object</Key><ETag>"complete-etag"</ETag><ChecksumCRC32C>4waSgw==</ChecksumCRC32C><ChecksumType>FULL_OBJECT</ChecksumType></CompleteMultipartUploadResult>`
			gw, requests := multipartChecksumStub(t, headers, upstreamBody)
			req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1", strings.NewReader(completeMultipartDocument(1, "part-etag")))
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			_ = receiveMultipartChecksumRequest(t, requests)

			// Result captures headers at the first write, as an HTTP client sees
			// them. Reading rr.Header() could miss headers added after the XML.
			response := rr.Result()
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("completion status = %d, body = %s", response.StatusCode, rr.Body.String())
			}
			for _, name := range completeMultipartResponseHeaderNames {
				values := response.Header.Values(name)
				want, present := tc.headers[name]
				if present {
					if len(values) != 1 || values[0] != want {
						t.Errorf("response %s = %q, want [%q]", name, values, want)
					}
				} else if len(values) != 0 {
					t.Errorf("unexpected response %s = %q", name, values)
				}
			}
			var body struct {
				XMLName        xml.Name `xml:"CompleteMultipartUploadResult"`
				Bucket         string   `xml:"Bucket"`
				Key            string   `xml:"Key"`
				ETag           string   `xml:"ETag"`
				ChecksumCRC32C string   `xml:"ChecksumCRC32C"`
				ChecksumType   string   `xml:"ChecksumType"`
			}
			if err := xml.NewDecoder(response.Body).Decode(&body); err != nil {
				t.Fatalf("decode completion response: %v", err)
			}
			if body.Bucket != "team2-bucket" || body.Key != "object" || body.ETag != `"complete-etag"` || body.ChecksumCRC32C != "4waSgw==" || body.ChecksumType != "FULL_OBJECT" {
				t.Errorf("completion XML changed: %+v", body)
			}
		})
	}
}

func TestCompleteMultipartErrorOmitsSuccessHeaders(t *testing.T) {
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>Forbidden</Message></Error>`)
	})
	defer cleanup()
	req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1", strings.NewReader(completeMultipartDocument(1, "part-etag")))
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	response := rr.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !strings.Contains(rr.Body.String(), "<Code>AccessDenied</Code>") {
		t.Fatalf("completion error = %d: %s", response.StatusCode, rr.Body.String())
	}
	for _, name := range completeMultipartResponseHeaderNames {
		if values := response.Header.Values(name); len(values) != 0 {
			t.Errorf("unexpected success header %s = %q", name, values)
		}
	}
}
