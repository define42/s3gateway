package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var completeMultipartRequestHeaders = map[string]string{
	"x-amz-request-payer":         "requester",
	"x-amz-expected-bucket-owner": "123456789012",
}

var customerEncryptionRequestHeaders = map[string]string{
	"x-amz-server-side-encryption-customer-algorithm": "AES256",
	"x-amz-server-side-encryption-customer-key":       "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	"x-amz-server-side-encryption-customer-key-md5":   "cLyPS3KoaSFGi/joRB3OUQ==",
}

func TestCompleteMultipartForwardsRequestHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "account headers with checksum", headers: completeMultipartRequestHeaders},
		{name: "optional headers absent"},
		{name: "payer and owner normalized", headers: map[string]string{
			"x-amz-request-payer":         " REQUESTER ",
			"x-amz-expected-bucket-owner": " 123456789012 ",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, requests := multipartChecksumStub(t, nil,
				`<CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>`)
			body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"part-etag"</ETag><ChecksumCRC32>y/Q5Jg==</ChecksumCRC32></Part></CompleteMultipartUpload>`
			req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1", strings.NewReader(body))
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			req.Header.Set("x-amz-checksum-crc32", "y/Q5Jg==")
			req.Header.Set("x-amz-checksum-type", "FULL_OBJECT")
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `<ETag>"completed"</ETag>`) {
				t.Fatalf("completion failed: %d %s", rr.Code, rr.Body.String())
			}
			sent := receiveMultipartChecksumRequest(t, requests)
			for name, normalized := range completeMultipartRequestHeaders {
				values := sent.header.Values(name)
				if _, present := tc.headers[name]; present {
					if len(values) != 1 || values[0] != normalized {
						t.Errorf("upstream %s = %q, want [%q]", name, values, normalized)
					}
				} else if len(values) != 0 {
					t.Errorf("absent header %s added upstream: %q", name, values)
				}
			}
			if sent.header.Get("x-amz-checksum-crc32") != "y/Q5Jg==" ||
				sent.header.Get("x-amz-checksum-type") != "FULL_OBJECT" ||
				!strings.Contains(sent.body, "<ChecksumCRC32>y/Q5Jg==</ChecksumCRC32>") {
				t.Fatalf("completion checksum lost: headers=%v body=%s", sent.header, sent.body)
			}
		})
	}
}

func TestCompleteMultipartRejectsCustomerEncryption(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "complete customer encryption", headers: customerEncryptionRequestHeaders},
		{name: "algorithm only", headers: map[string]string{"x-amz-server-side-encryption-customer-algorithm": "AES256"}},
		{name: "key only", headers: map[string]string{"x-amz-server-side-encryption-customer-key": "test-key"}},
		{name: "digest only", headers: map[string]string{"x-amz-server-side-encryption-customer-key-md5": "test-digest"}},
		{name: "missing digest", headers: map[string]string{
			"x-amz-server-side-encryption-customer-algorithm": "AES256",
			"x-amz-server-side-encryption-customer-key":       "test-key",
		}},
		{name: "missing key", headers: map[string]string{
			"x-amz-server-side-encryption-customer-algorithm": "AES256",
			"x-amz-server-side-encryption-customer-key-md5":   "test-digest",
		}},
		{name: "missing algorithm", headers: map[string]string{
			"x-amz-server-side-encryption-customer-key":     "test-key",
			"x-amz-server-side-encryption-customer-key-md5": "test-digest",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, requests := multipartChecksumStub(t, nil, `<CompleteMultipartUploadResult/>`)
			req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1",
				strings.NewReader(completeMultipartDocument(1, "part-etag")))
			for name, value := range tc.headers {
				req.Header.Set(name, value)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "<Code>NotImplemented</Code>") {
				t.Errorf("unsupported encryption accepted: %d %s", rr.Code, rr.Body.String())
			}
			if key := tc.headers["x-amz-server-side-encryption-customer-key"]; key != "" &&
				(rr.Header().Get("x-amz-server-side-encryption-customer-key") != "" || strings.Contains(rr.Body.String(), key)) {
				t.Error("completion response exposed the customer key")
			}
			select {
			case <-requests:
				t.Error("invalid completion reached upstream")
			default:
			}
		})
	}
}

func TestCompleteMultipartRejectsUnsupportedPayer(t *testing.T) {
	gw, requests := multipartChecksumStub(t, nil, `<CompleteMultipartUploadResult/>`)
	req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1",
		strings.NewReader(completeMultipartDocument(1, "part-etag")))
	req.Header.Set("x-amz-request-payer", "owner")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidArgument</Code>") {
		t.Errorf("unsupported payer accepted: %d %s", rr.Code, rr.Body.String())
	}
	select {
	case <-requests:
		t.Error("invalid completion reached upstream")
	default:
	}
}

func TestCompleteMultipartPreservesExpectedOwnerRejection(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/xml")
		if r.Header.Get("x-amz-expected-bucket-owner") == "123456789012" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>Bucket belongs to another owner</Message></Error>`)
			return
		}
		_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>`)
	})
	t.Cleanup(cleanup)
	req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1",
		strings.NewReader(completeMultipartDocument(1, "part-etag")))
	req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "<Code>AccessDenied</Code>") {
		t.Fatalf("expected-owner rejection lost: %d %s", rr.Code, rr.Body.String())
	}
}
