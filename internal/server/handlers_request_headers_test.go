package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var accountHeaderOperations = []struct {
	name, method, target, body, response string
	status                               int
}{
	{name: "upload part", method: http.MethodPut, target: "/team2-bucket/object?partNumber=1&uploadId=upload-1",
		body: "123456789", status: http.StatusOK},
	{name: "list parts", method: http.MethodGet, target: "/team2-bucket/object?uploadId=upload-1",
		response: `<ListPartsResult/>`, status: http.StatusOK},
	{name: "list uploads", method: http.MethodGet, target: "/team2-bucket?uploads",
		response: `<ListMultipartUploadsResult/>`, status: http.StatusOK},
	{name: "abort upload", method: http.MethodDelete, target: "/team2-bucket/object?uploadId=upload-1", status: http.StatusNoContent},
	{name: "object attributes", method: http.MethodGet, target: "/team2-bucket/object?attributes",
		response: `<GetObjectAttributesResponse><ETag>"etag"</ETag></GetObjectAttributesResponse>`, status: http.StatusOK},
}

func TestMultipartAndAttributesForwardRequestHeaders(t *testing.T) {
	for _, operation := range accountHeaderOperations {
		t.Run(operation.name, func(t *testing.T) {
			for _, present := range []bool{true, false} {
				name := "absent"
				if present {
					name = "present and normalized"
				}
				t.Run(name, func(t *testing.T) {
					gw, requests := multipartChecksumStub(t, nil, operation.response)
					req := httptest.NewRequest(operation.method, operation.target, strings.NewReader(operation.body))
					req.Header.Set("x-amz-object-attributes", "ETag")
					if present {
						req.Header.Set("x-amz-request-payer", " REQUESTER ")
						req.Header.Set("x-amz-expected-bucket-owner", " 123456789012 ")
					}
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if rr.Code != operation.status {
						t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
					}
					sent := receiveMultipartChecksumRequest(t, requests)
					for header, want := range completeMultipartRequestHeaders {
						values := sent.header.Values(header)
						if req.Header.Get(header) != "" {
							if len(values) != 1 || values[0] != want {
								t.Errorf("upstream %s=%q, want [%q]", header, values, want)
							}
						} else if len(values) != 0 {
							t.Errorf("absent header %s added upstream: %q", header, values)
						}
					}
					if sent.body != operation.body {
						t.Errorf("upstream body=%q, want %q", sent.body, operation.body)
					}
				})
			}
		})
	}
}

func TestMultipartAndAttributesRejectUnsupportedPayer(t *testing.T) {
	for _, operation := range accountHeaderOperations {
		t.Run(operation.name, func(t *testing.T) {
			gw, requests := multipartChecksumStub(t, nil, operation.response)
			req := httptest.NewRequest(operation.method, operation.target, strings.NewReader(operation.body))
			req.Header.Set("x-amz-object-attributes", "ETag")
			req.Header.Set("x-amz-request-payer", "owner")
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidArgument</Code>") {
				t.Errorf("unsupported payer accepted: %d %s", rr.Code, rr.Body.String())
			}
			select {
			case <-requests:
				t.Error("invalid request reached upstream")
			default:
			}
		})
	}
}

func TestMultipartAndAttributesRejectCustomerEncryption(t *testing.T) {
	for _, operation := range accountHeaderOperations {
		t.Run(operation.name, func(t *testing.T) {
			for _, missing := range []string{
				"",
				"x-amz-server-side-encryption-customer-algorithm",
				"x-amz-server-side-encryption-customer-key",
				"x-amz-server-side-encryption-customer-key-md5",
			} {
				name := "complete customer encryption"
				if missing != "" {
					name = "missing " + missing
				}
				t.Run(name, func(t *testing.T) {
					gw, requests := multipartChecksumStub(t, nil, operation.response)
					req := httptest.NewRequest(operation.method, operation.target, strings.NewReader(operation.body))
					req.Header.Set("x-amz-object-attributes", "ETag")
					for header, value := range customerEncryptionRequestHeaders {
						if header != missing {
							req.Header.Set(header, value)
						}
					}
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if rr.Code != http.StatusNotImplemented || !strings.Contains(rr.Body.String(), "<Code>NotImplemented</Code>") {
						t.Errorf("unsupported encryption accepted: %d %s", rr.Code, rr.Body.String())
					}
					if rr.Header().Get("x-amz-server-side-encryption-customer-key") != "" ||
						strings.Contains(rr.Body.String(), customerEncryptionRequestHeaders["x-amz-server-side-encryption-customer-key"]) {
						t.Error("response exposed the customer key")
					}
					select {
					case <-requests:
						t.Error("invalid request reached upstream")
					default:
					}
				})
			}
		})
	}
}

func TestMultipartAndAttributesPreserveExpectedOwnerRejection(t *testing.T) {
	for _, operation := range accountHeaderOperations {
		t.Run(operation.name, func(t *testing.T) {
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/xml")
				if r.Header.Get("x-amz-expected-bucket-owner") == "123456789012" {
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>Bucket belongs to another owner</Message></Error>`)
					return
				}
				_, _ = io.WriteString(w, operation.response)
			})
			t.Cleanup(cleanup)
			req := httptest.NewRequest(operation.method, operation.target, strings.NewReader(operation.body))
			req.Header.Set("x-amz-object-attributes", "ETag")
			req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "<Code>AccessDenied</Code>") {
				t.Fatalf("expected-owner rejection lost: %d %s", rr.Code, rr.Body.String())
			}
		})
	}
}
