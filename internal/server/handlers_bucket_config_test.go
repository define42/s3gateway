package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/authz"
)

// stubUpstreamHeadOK answers HEAD bucket/object probes with 200 and fails the
// test on any other upstream call.
func stubUpstreamHeadOK(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("unexpected non-HEAD upstream call: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
	}
}

func assertNoUpstreamACLHeaders(t *testing.T, r *http.Request) {
	t.Helper()
	if got := r.Header.Get("x-amz-acl"); got != "" {
		t.Errorf("upstream request contains x-amz-acl: %q", got)
	}
	for name := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-grant-") {
			t.Errorf("upstream request contains ACL grant header %q", name)
		}
	}
}

func TestCreateBucketAcceptsOnlyPrivateACLAsNoOp(t *testing.T) {
	rejectedGateway, rejectedCleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called for a rejected ACL: %s %s", r.Method, r.URL.String())
	})
	defer rejectedCleanup()

	rejected := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{
			name: "public canned ACL",
			mutate: func(r *http.Request) {
				r.Header.Set("x-amz-acl", "public-read")
			},
		},
		{
			name: "object-only owner ACL",
			mutate: func(r *http.Request) {
				r.Header.Set("x-amz-acl", "bucket-owner-full-control")
			},
		},
		{
			name: "explicit grant",
			mutate: func(r *http.Request) {
				r.Header.Set("x-amz-grant-read", `uri="http://acs.amazonaws.com/groups/global/AllUsers"`)
			},
		},
		{
			name: "multiple canned ACL values",
			mutate: func(r *http.Request) {
				r.Header.Add("x-amz-acl", "private")
				r.Header.Add("x-amz-acl", "public-read")
			},
		},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket", nil)
			tc.mutate(req)
			req = reqWithRules(req, fullTeam2Rule())
			rr := httptest.NewRecorder()

			rejectedGateway.handleCreateBucket(rr, req, "team2-bucket")

			if rr.Code != http.StatusNotImplemented {
				t.Fatalf("status=%d want=501 body=%s", rr.Code, rr.Body.String())
			}
		})
	}

	acceptedGateway, acceptedCleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		assertNoUpstreamACLHeaders(t, r)
		w.WriteHeader(http.StatusOK)
	})
	defer acceptedCleanup()

	accepted := []struct {
		name      string
		cannedACL string
	}{
		{name: "no ACL", cannedACL: ""},
		{name: "private ACL", cannedACL: "private"},
		{name: "trimmed case-insensitive private ACL", cannedACL: "  PrIvAtE  "},
	}
	for _, tc := range accepted {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket", nil)
			if tc.cannedACL != "" {
				req.Header.Set("x-amz-acl", tc.cannedACL)
			}
			req = reqWithRules(req, fullTeam2Rule())
			rr := httptest.NewRecorder()

			acceptedGateway.handleCreateBucket(rr, req, "team2-bucket")

			if rr.Code != http.StatusOK {
				t.Fatalf("status=%d want=200 body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

func TestBucketAndObjectACLReads(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, stubUpstreamHeadOK(t))
	defer cleanup()

	for _, target := range []string{"/team2-bucket?acl", "/team2-bucket/key.txt?acl"} {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: status=%d body=%s", target, rr.Code, rr.Body.String())
		}
		body := rr.Body.String()
		for _, want := range []string{
			"<AccessControlPolicy", "<Owner>", "<ID>s3gateway</ID>",
			`xsi:type="CanonicalUser"`, "<Permission>FULL_CONTROL</Permission>",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("GET %s: response missing %q: %s", target, want, body)
			}
		}
	}

	t.Run("forbidden without read permission", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?acl", nil)
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=403 body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestACLReadsKeepNotFoundSemantics(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer cleanup()

	cases := []struct {
		target   string
		wantCode string
	}{
		{"/team2-bucket?acl", "NoSuchBucket"},
		{"/team2-bucket/key.txt?acl", "NoSuchKey"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status=%d want=404 body=%s", tc.target, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), tc.wantCode) {
			t.Fatalf("GET %s: expected %s error code, got: %s", tc.target, tc.wantCode, rr.Body.String())
		}
	}
}

func TestACLWritesAcceptOnlyOwnerRetainingCannedACLs(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, stubUpstreamHeadOK(t))
	defer cleanup()

	put := func(target, cannedACL string, mutate func(*http.Request)) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, target, nil)
		if cannedACL != "" {
			req.Header.Set("x-amz-acl", cannedACL)
		}
		if mutate != nil {
			mutate(req)
		}
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		return rr
	}

	// Accepted as no-ops: full control stays with the owner.
	for _, tc := range []struct{ target, acl string }{
		{"/team2-bucket?acl", ""},
		{"/team2-bucket?acl", "private"},
		{"/team2-bucket/key.txt?acl", "private"},
		{"/team2-bucket/key.txt?acl", "bucket-owner-read"},
		{"/team2-bucket/key.txt?acl", "bucket-owner-full-control"},
	} {
		if rr := put(tc.target, tc.acl, nil); rr.Code != http.StatusOK {
			t.Fatalf("PUT %s acl=%q: status=%d want=200 body=%s", tc.target, tc.acl, rr.Code, rr.Body.String())
		}
	}

	// Rejected: anything that would grant access beyond the owner.
	for _, tc := range []struct {
		target, acl string
		mutate      func(*http.Request)
	}{
		{"/team2-bucket?acl", "public-read", nil},
		{"/team2-bucket?acl", "bucket-owner-full-control", nil}, // object-only canned ACL
		{"/team2-bucket/key.txt?acl", "public-read-write", nil},
		{"/team2-bucket/key.txt?acl", "authenticated-read", nil},
		{"/team2-bucket/key.txt?acl", "", func(req *http.Request) {
			req.Header.Set("x-amz-grant-read", `id="someone"`)
		}},
		{"/team2-bucket/key.txt?acl", "", func(req *http.Request) {
			req.Body = io.NopCloser(strings.NewReader("<AccessControlPolicy/>"))
			req.ContentLength = int64(len("<AccessControlPolicy/>"))
		}},
	} {
		rr := put(tc.target, tc.acl, tc.mutate)
		if rr.Code != http.StatusNotImplemented {
			t.Fatalf("PUT %s acl=%q: status=%d want=501 body=%s", tc.target, tc.acl, rr.Code, rr.Body.String())
		}
	}

	t.Run("requires configuration permission", func(t *testing.T) {
		for _, target := range []string{
			"/team2-bucket?acl",
			"/team2-bucket/key.txt?acl",
		} {
			t.Run(target, func(t *testing.T) {
				writeOnlyReq := httptest.NewRequest(http.MethodPut, target, nil)
				writeOnlyReq.Header.Set("x-amz-acl", "private")
				writeOnlyReq = reqWithRules(writeOnlyReq, []authz.Rule{{
					BucketPrefix: "team2",
					Perm:         authz.PermWrite,
				}})
				writeOnlyRR := httptest.NewRecorder()
				gw.ServeHTTP(writeOnlyRR, writeOnlyReq)
				if writeOnlyRR.Code != http.StatusForbidden {
					t.Fatalf("write-only status=%d want=403 body=%s", writeOnlyRR.Code, writeOnlyRR.Body.String())
				}

				configureReq := httptest.NewRequest(http.MethodPut, target, nil)
				configureReq.Header.Set("x-amz-acl", "private")
				configureReq = reqWithRules(configureReq, []authz.Rule{{
					BucketPrefix: "team2",
					Perm:         authz.PermCreateBucket,
				}})
				configureRR := httptest.NewRecorder()
				gw.ServeHTTP(configureRR, configureReq)
				if configureRR.Code != http.StatusOK {
					t.Fatalf("configuration status=%d want=200 body=%s", configureRR.Code, configureRR.Body.String())
				}
			})
		}
	})

	t.Run("forbidden without configuration permission", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/key.txt?acl", nil)
		req.Header.Set("x-amz-acl", "private")
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=403 body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestBucketConfigLocalReads(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, stubUpstreamHeadOK(t))
	defer cleanup()

	cases := []struct {
		subresource string
		wantStatus  int
		wantBody    string
	}{
		{"policy", http.StatusNotFound, "NoSuchBucketPolicy"},
		{"policyStatus", http.StatusNotFound, "NoSuchBucketPolicy"},
		{"cors", http.StatusNotFound, "NoSuchCORSConfiguration"},
		{"website", http.StatusNotFound, "NoSuchWebsiteConfiguration"},
		{"replication", http.StatusNotFound, "ReplicationConfigurationNotFoundError"},
		{"logging", http.StatusOK, "<BucketLoggingStatus"},
		{"notification", http.StatusOK, "<NotificationConfiguration"},
		{"accelerate", http.StatusOK, "<AccelerateConfiguration"},
		{"requestPayment", http.StatusOK, "<Payer>BucketOwner</Payer>"},
		{"publicAccessBlock", http.StatusOK, "<RestrictPublicBuckets>true</RestrictPublicBuckets>"},
	}
	for _, tc := range cases {
		t.Run(tc.subresource, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/team2-bucket?"+tc.subresource, nil)
			req = reqWithRules(req, fullTeam2Rule())
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, req)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), tc.wantBody) {
				t.Fatalf("response missing %q: %s", tc.wantBody, rr.Body.String())
			}

			// Reads require the read permission.
			denied := httptest.NewRequest(http.MethodGet, "/team2-bucket?"+tc.subresource, nil)
			denied = reqWithRules(denied, nil)
			rrDenied := httptest.NewRecorder()
			gw.ServeHTTP(rrDenied, denied)
			if rrDenied.Code != http.StatusForbidden {
				t.Fatalf("without permission: status=%d want=403 body=%s", rrDenied.Code, rrDenied.Body.String())
			}
		})
	}

	t.Run("missing bucket yields NoSuchBucket", func(t *testing.T) {
		gwMissing, cleanupMissing := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		defer cleanupMissing()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?publicAccessBlock", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gwMissing.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "NoSuchBucket") {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestBucketEncryptionProxied(t *testing.T) {
	t.Run("put forwards configuration upstream", func(t *testing.T) {
		var upstreamBody []byte
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != "/team2-bucket" {
				t.Errorf("unexpected upstream request: %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
			}
			if _, ok := r.URL.Query()["encryption"]; !ok {
				t.Errorf("expected encryption sub-resource upstream: %s", r.URL.RawQuery)
			}
			b, _ := io.ReadAll(r.Body)
			upstreamBody = b
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()

		body := `<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>`
		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?encryption", strings.NewReader(body))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(string(upstreamBody), "AES256") {
			t.Fatalf("upstream body missing SSE algorithm: %s", string(upstreamBody))
		}
	})

	t.Run("put rejects malformed configuration", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("upstream must not be called for malformed configuration")
		})
		defer cleanup()

		for _, body := range []string{"not-xml", "<ServerSideEncryptionConfiguration/>"} {
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket?encryption", strings.NewReader(body))
			req = reqWithRules(req, fullTeam2Rule())
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "MalformedXML") {
				t.Fatalf("body %q: status=%d body=%s", body, rr.Code, rr.Body.String())
			}
		}
	})

	t.Run("get renders upstream configuration", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>key-1</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?encryption", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		for _, want := range []string{"<SSEAlgorithm>aws:kms</SSEAlgorithm>", "<KMSMasterKeyID>key-1</KMSMasterKeyID>", "<BucketKeyEnabled>true</BucketKeyEnabled>"} {
			if !strings.Contains(rr.Body.String(), want) {
				t.Fatalf("response missing %q: %s", want, rr.Body.String())
			}
		}
	})

	t.Run("delete proxies and returns 204", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete {
				t.Errorf("unexpected upstream method: %s", r.Method)
			}
			w.WriteHeader(http.StatusNoContent)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodDelete, "/team2-bucket?encryption", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("permission mapping", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("upstream must not be called without permission")
		})
		defer cleanup()

		for _, tc := range []struct {
			method string
		}{{http.MethodPut}, {http.MethodGet}, {http.MethodDelete}} {
			req := httptest.NewRequest(tc.method, "/team2-bucket?encryption", strings.NewReader("<ServerSideEncryptionConfiguration><Rule/></ServerSideEncryptionConfiguration>"))
			req = reqWithRules(req, nil)
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s without permission: status=%d want=403 body=%s", tc.method, rr.Code, rr.Body.String())
			}
		}
	})
}
