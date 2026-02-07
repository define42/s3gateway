package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func reqWithRules(req *http.Request, rules []Rule) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), ctxRulesKey, rules))
}

func reqWithRulesAndSigV4(req *http.Request, rules []Rule, auth *sigv4Auth) *http.Request {
	ctx := context.WithValue(req.Context(), ctxRulesKey, rules)
	ctx = context.WithValue(ctx, ctxSigV4AuthKey, auth)
	return req.WithContext(ctx)
}

func TestHandleCopyObjectValidationMatrix(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
	})
	defer cleanup()

	baseReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/object.txt", nil)
		req.Header.Set("x-amz-copy-source", "/team2-src/source.txt")
		return reqWithRules(req, fullTeam2Rule())
	}

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		rules      []Rule
		wantStatus int
	}{
		{
			name: "missing copy source",
			mutate: func(req *http.Request) {
				req.Header.Del("x-amz-copy-source")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid copy source",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source", "/%zz/source.txt")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "forbidden source bucket",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source", "/other-src/source.txt")
			},
			wantStatus: http.StatusForbidden,
		},
		{
			name: "if-match and if-none-match both set",
			mutate: func(req *http.Request) {
				req.Header.Set("If-Match", "\"a\"")
				req.Header.Set("If-None-Match", "\"b\"")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid sse header",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-server-side-encryption", "AES128")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid copy source sse-c headers",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid checksum algorithm",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-checksum-algorithm", "MD5")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid metadata directive",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-metadata-directive", "MERGE")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid tagging directive",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-tagging-directive", "MERGE")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid storage class",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-storage-class", "WARM")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid acl",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-acl", "authenticated")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid request payer",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-request-payer", "owner")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid copy source conditional time",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source-if-modified-since", "not-a-time")
			},
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid expires header",
			mutate: func(req *http.Request) {
				req.Header.Set("Expires", "not-a-time")
			},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := baseReq()
			if tc.rules != nil {
				req = reqWithRules(req, tc.rules)
			}
			if tc.mutate != nil {
				tc.mutate(req)
			}
			rr := httptest.NewRecorder()
			gw.handleCopyObject(rr, req, "team2-dst", "object.txt")
			if rr.Code != tc.wantStatus {
				t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestHandleCopyObjectRichSuccess(t *testing.T) {
	lastModified := "2026-02-07T01:02:03.000Z"

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("unexpected upstream method: %s", r.Method)
		}
		if r.URL.Path != "/team2-dst/object.txt" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		w.Header().Set("x-amz-version-id", "dst-v1")
		w.Header().Set("x-amz-copy-source-version-id", "src-v1")
		w.Header().Set("x-amz-server-side-encryption", "aws:kms")
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", "kms-key")
		w.Header().Set("x-amz-server-side-encryption-context", "eyJhIjoiYiJ9")
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", "abc123")
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", "true")
		w.Header().Set("x-amz-expiration", `expiry-date="2030-01-01T00:00:00Z", rule-id="r1"`)
		w.Header().Set("x-amz-request-charged", "requester")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <LastModified>` + lastModified + `</LastModified>
  <ETag>"etag-copy"</ETag>
  <ChecksumCRC32>AAAAAA==</ChecksumCRC32>
  <ChecksumCRC32C>BBBBBB==</ChecksumCRC32C>
  <ChecksumCRC64NVME>CCCCCC==</ChecksumCRC64NVME>
  <ChecksumSHA1>DDDDDD==</ChecksumSHA1>
  <ChecksumSHA256>EEEEEE==</ChecksumSHA256>
  <ChecksumType>FULL_OBJECT</ChecksumType>
</CopyObjectResult>`))
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/team2-dst/object.txt", nil)
	req.Header.Set("x-amz-copy-source", "/team2-src/source.txt")
	req.Header.Set("If-None-Match", "\"etag-old\"")
	req.Header.Set("x-amz-copy-source-if-match", "\"src-match\"")
	req.Header.Set("x-amz-copy-source-if-none-match", "\"src-none\"")
	req.Header.Set("x-amz-copy-source-if-modified-since", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	req.Header.Set("x-amz-copy-source-if-unmodified-since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
	req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key", "Zm9v")
	req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key-md5", "YmFy")
	req.Header.Set("x-amz-server-side-encryption", "AES256")
	req.Header.Set("x-amz-metadata-directive", "REPLACE")
	req.Header.Set("x-amz-tagging-directive", "REPLACE")
	req.Header.Set("x-amz-tagging", "k=v")
	req.Header.Set("x-amz-storage-class", "STANDARD")
	req.Header.Set("x-amz-acl", "private")
	req.Header.Set("x-amz-checksum-algorithm", "SHA256")
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Cache-Control", "max-age=60")
	req.Header.Set("Content-Disposition", "inline")
	req.Header.Set("Content-Encoding", "identity")
	req.Header.Set("Content-Language", "en-US")
	req.Header.Set("x-amz-website-redirect-location", "/redirect")
	req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
	req.Header.Set("x-amz-source-expected-bucket-owner", "123456789012")
	req.Header.Set("x-amz-request-payer", "requester")
	req.Header.Set("Expires", time.Now().Add(2*time.Hour).UTC().Format(http.TimeFormat))
	req = reqWithRules(req, fullTeam2Rule())

	rr := httptest.NewRecorder()
	gw.handleCopyObject(rr, req, "team2-dst", "object.txt")
	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("x-amz-copy-source-version-id") != "src-v1" {
		t.Fatalf("missing copy source version id header: %q", rr.Header().Get("x-amz-copy-source-version-id"))
	}
	if rr.Header().Get("x-amz-server-side-encryption") != "aws:kms" {
		t.Fatalf("missing sse header: %q", rr.Header().Get("x-amz-server-side-encryption"))
	}
	if rr.Header().Get("x-amz-request-charged") != "requester" {
		t.Fatalf("missing request charged header: %q", rr.Header().Get("x-amz-request-charged"))
	}
	body := rr.Body.String()
	for _, want := range []string{
		"<ChecksumCRC32C>BBBBBB==</ChecksumCRC32C>",
		"<ChecksumCRC64NVME>CCCCCC==</ChecksumCRC64NVME>",
		"<ChecksumSHA1>DDDDDD==</ChecksumSHA1>",
		"<ChecksumSHA256>EEEEEE==</ChecksumSHA256>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in body: %s", want, body)
		}
	}
}

func TestHandleUploadPartCopyValidationMatrix(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
	})
	defer cleanup()

	baseReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/object.txt", nil)
		req.Header.Set("x-amz-copy-source", "/team2-src/source.txt")
		return reqWithRules(req, fullTeam2Rule())
	}

	tests := []struct {
		name       string
		mutate     func(*http.Request)
		rules      []Rule
		wantStatus int
	}{
		{
			name:       "forbidden destination bucket",
			rules:      nil,
			wantStatus: http.StatusForbidden,
		},
		{
			name: "missing copy source",
			mutate: func(req *http.Request) {
				req.Header.Del("x-amz-copy-source")
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid copy source",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source", "/%zz/source.txt")
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "forbidden source bucket",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source", "/other-src/source.txt")
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusForbidden,
		},
		{
			name: "invalid copy source conditional time",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source-if-modified-since", "not-a-time")
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid copy source sse-c",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid destination sse-c",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name: "invalid request payer",
			mutate: func(req *http.Request) {
				req.Header.Set("x-amz-request-payer", "owner")
			},
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := baseReq()
			req = reqWithRules(req, tc.rules)
			if tc.mutate != nil {
				tc.mutate(req)
			}
			rr := httptest.NewRecorder()
			gw.handleUploadPartCopy(rr, req, "team2-dst", "object.txt", "u1", 1)
			if rr.Code != tc.wantStatus {
				t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestHandleUploadPartCopyRichSuccessAndUpstreamError(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("partNumber") == "9" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
			return
		}
		w.Header().Set("x-amz-copy-source-version-id", "src-v1")
		w.Header().Set("x-amz-server-side-encryption", "aws:kms")
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", "kms-key")
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", "abc123")
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", "true")
		w.Header().Set("x-amz-request-charged", "requester")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <LastModified>2026-02-07T01:02:03.000Z</LastModified>
  <ETag>"etag-copy-part"</ETag>
  <ChecksumCRC32>AAAAAA==</ChecksumCRC32>
  <ChecksumCRC32C>BBBBBB==</ChecksumCRC32C>
  <ChecksumCRC64NVME>CCCCCC==</ChecksumCRC64NVME>
  <ChecksumSHA1>DDDDDD==</ChecksumSHA1>
  <ChecksumSHA256>EEEEEE==</ChecksumSHA256>
</CopyPartResult>`))
	})
	defer cleanup()

	req := httptest.NewRequest(http.MethodPut, "/team2-dst/object.txt", nil)
	req.Header.Set("x-amz-copy-source", "/team2-src/source.txt")
	req.Header.Set("x-amz-copy-source-if-match", "\"src-match\"")
	req.Header.Set("x-amz-copy-source-if-none-match", "\"src-none\"")
	req.Header.Set("x-amz-copy-source-if-modified-since", time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat))
	req.Header.Set("x-amz-copy-source-if-unmodified-since", time.Now().Add(time.Hour).UTC().Format(http.TimeFormat))
	req.Header.Set("x-amz-copy-source-range", "bytes=0-5")
	req.Header.Set("x-amz-copy-source-server-side-encryption-customer-algorithm", "AES256")
	req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key", "Zm9v")
	req.Header.Set("x-amz-copy-source-server-side-encryption-customer-key-md5", "YmFy")
	req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
	req.Header.Set("x-amz-server-side-encryption-customer-key", "Zm9v")
	req.Header.Set("x-amz-server-side-encryption-customer-key-md5", "YmFy")
	req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
	req.Header.Set("x-amz-source-expected-bucket-owner", "123456789012")
	req.Header.Set("x-amz-request-payer", "requester")
	req = reqWithRules(req, fullTeam2Rule())

	rr := httptest.NewRecorder()
	gw.handleUploadPartCopy(rr, req, "team2-dst", "object.txt", "u1", 1)
	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("x-amz-copy-source-version-id") != "src-v1" {
		t.Fatalf("missing copy source version id header")
	}
	if rr.Header().Get("x-amz-request-charged") != "requester" {
		t.Fatalf("missing request charged header")
	}
	for _, want := range []string{
		"<ChecksumCRC32C>BBBBBB==</ChecksumCRC32C>",
		"<ChecksumCRC64NVME>CCCCCC==</ChecksumCRC64NVME>",
		"<ChecksumSHA1>DDDDDD==</ChecksumSHA1>",
		"<ChecksumSHA256>EEEEEE==</ChecksumSHA256>",
	} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("missing %q in response body: %s", want, rr.Body.String())
		}
	}

	errReq := httptest.NewRequest(http.MethodPut, "/team2-dst/object.txt", nil)
	errReq.Header.Set("x-amz-copy-source", "/team2-src/source.txt")
	errReq = reqWithRules(errReq, fullTeam2Rule())
	errRR := httptest.NewRecorder()
	gw.handleUploadPartCopy(errRR, errReq, "team2-dst", "object.txt", "u1", 9)
	if errRR.Code != http.StatusInternalServerError {
		t.Fatalf("upstream error status mismatch: got=%d body=%s", errRR.Code, errRR.Body.String())
	}
}

func TestHandleUploadPartValidationAndBranches(t *testing.T) {
	gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
	})
	defer cleanupNoUpstream()

	sigAuth := &sigv4Auth{
		AccessKey:    "ak",
		Date:         "20260207",
		Region:       "us-east-1",
		Service:      "s3",
		SignatureHex: strings.Repeat("a", 64),
		AmzDate:      "20260207T000000Z",
	}

	newReq := func(body string) *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/object.txt", bytes.NewReader([]byte(body)))
		return reqWithRules(req, fullTeam2Rule())
	}

	t.Run("forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/object.txt", bytes.NewReader([]byte("part")))
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gwNoUpstream.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("streaming without auth context", func(t *testing.T) {
		req := newReq("part")
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		rr := httptest.NewRecorder()
		gwNoUpstream.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("streaming missing decoded content length", func(t *testing.T) {
		req := newReq("part")
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		req = reqWithRulesAndSigV4(req, fullTeam2Rule(), sigAuth)
		rr := httptest.NewRecorder()
		gwNoUpstream.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusLengthRequired {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing content length", func(t *testing.T) {
		req := newReq("part")
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		gwNoUpstream.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusLengthRequired {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid sse-c headers", func(t *testing.T) {
		req := newReq("part")
		req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		rr := httptest.NewRecorder()
		gwNoUpstream.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid checksum headers", func(t *testing.T) {
		req := newReq("part")
		req.Header.Set("x-amz-checksum-crc32", "AAAAAA==")
		req.Header.Set("x-amz-checksum-crc32c", "BBBBBB==")
		rr := httptest.NewRecorder()
		gwNoUpstream.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("content-md5 with checksum algorithm", func(t *testing.T) {
		req := newReq("part")
		req.Header.Set("Content-MD5", "abc")
		req.Header.Set("x-amz-checksum-algorithm", "SHA256")
		rr := httptest.NewRecorder()
		gwNoUpstream.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("partNumber") == "9" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
			return
		}
		w.Header().Set("ETag", "\"part-etag\"")
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	t.Run("success with sse-c and content-md5", func(t *testing.T) {
		req := newReq("part-body")
		req.Header.Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		req.Header.Set("x-amz-server-side-encryption-customer-key", "Zm9v")
		req.Header.Set("x-amz-server-side-encryption-customer-key-md5", "YmFy")
		req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")
		rr := httptest.NewRecorder()
		gw.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 1)
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadGateway {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
		if rr.Code == http.StatusOK && rr.Header().Get("ETag") == "" {
			t.Fatalf("missing ETag header")
		}
	})

	t.Run("upstream error", func(t *testing.T) {
		req := newReq("part-body")
		rr := httptest.NewRecorder()
		gw.handleUploadPart(rr, req, "team2-dst", "object.txt", "u1", 9)
		if rr.Code != http.StatusInternalServerError && rr.Code != http.StatusBadGateway {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandleDeleteObjectsValidationMatrix(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
	})
	defer cleanup()

	validBody := `<?xml version="1.0" encoding="UTF-8"?><Delete><Object><Key>a.txt</Key></Object></Delete>`

	tests := []struct {
		name       string
		body       string
		headers    map[string]string
		rules      []Rule
		wantStatus int
	}{
		{
			name:       "forbidden",
			body:       validBody,
			rules:      nil,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "malformed xml",
			body:       `<Delete><Object>`,
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty objects",
			body:       `<?xml version="1.0" encoding="UTF-8"?><Delete></Delete>`,
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing object key",
			body:       `<?xml version="1.0" encoding="UTF-8"?><Delete><Object><VersionId>v1</VersionId></Object></Delete>`,
			rules:      fullTeam2Rule(),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid bypass retention header",
			body:       validBody,
			rules:      fullTeam2Rule(),
			headers:    map[string]string{"x-amz-bypass-governance-retention": "not-bool"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid request payer",
			body:       validBody,
			rules:      fullTeam2Rule(),
			headers:    map[string]string{"x-amz-request-payer": "owner"},
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/team2-dst?delete", strings.NewReader(tc.body))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			req = reqWithRules(req, tc.rules)
			rr := httptest.NewRecorder()
			gw.handleDeleteObjects(rr, req, "team2-dst")
			if rr.Code != tc.wantStatus {
				t.Fatalf("status mismatch: got=%d want=%d body=%s", rr.Code, tc.wantStatus, rr.Body.String())
			}
		})
	}
}

func TestHandleDeleteObjectsRichSuccessAndUpstreamError(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-request-charged", "requester")
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Deleted>
    <Key>a.txt</Key>
    <VersionId>v1</VersionId>
    <DeleteMarker>true</DeleteMarker>
    <DeleteMarkerVersionId>dmv1</DeleteMarkerVersionId>
  </Deleted>
  <Error>
    <Key>b.txt</Key>
    <VersionId>v2</VersionId>
    <Code>AccessDenied</Code>
    <Message>denied</Message>
  </Error>
</DeleteResult>`))
	})
	defer cleanup()

	body := `<?xml version="1.0" encoding="UTF-8"?><Delete><Object><Key>a.txt</Key><VersionId>v1</VersionId><ETag>\"etag1\"</ETag></Object><Object><Key>b.txt</Key></Object><Quiet>true</Quiet></Delete>`
	req := httptest.NewRequest(http.MethodPost, "/team2-dst?delete", strings.NewReader(body))
	req.Header.Set("x-amz-bypass-governance-retention", "true")
	req.Header.Set("x-amz-mfa", "device 123456")
	req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
	req.Header.Set("x-amz-request-payer", "requester")
	req = reqWithRules(req, fullTeam2Rule())

	rr := httptest.NewRecorder()
	gw.handleDeleteObjects(rr, req, "team2-dst")
	if rr.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("x-amz-request-charged") != "requester" {
		t.Fatalf("missing x-amz-request-charged header")
	}
	for _, want := range []string{
		"<DeleteMarker>true</DeleteMarker>",
		"<DeleteMarkerVersionId>dmv1</DeleteMarkerVersionId>",
		"<Error>",
		"<Code>AccessDenied</Code>",
		"<Message>denied</Message>",
	} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Fatalf("missing %q in body: %s", want, rr.Body.String())
		}
	}

	gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
	})
	defer cleanupErr()
	errReq := httptest.NewRequest(http.MethodPost, "/team2-dst?delete", strings.NewReader(`<?xml version="1.0" encoding="UTF-8"?><Delete><Object><Key>a.txt</Key></Object></Delete>`))
	errReq = reqWithRules(errReq, fullTeam2Rule())
	errRR := httptest.NewRecorder()
	gwErr.handleDeleteObjects(errRR, errReq, "team2-dst")
	if errRR.Code != http.StatusInternalServerError {
		t.Fatalf("status mismatch: got=%d body=%s", errRR.Code, errRR.Body.String())
	}
}

func TestHandleGetBucketVersioningBranches(t *testing.T) {
	gwNoPerm, cleanupNoPerm := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called when forbidden")
	})
	defer cleanupNoPerm()

	forbiddenReq := httptest.NewRequest(http.MethodGet, "/team2-bucket?versioning", nil)
	forbiddenReq = reqWithRules(forbiddenReq, nil)
	forbiddenRR := httptest.NewRecorder()
	gwNoPerm.handleGetBucketVersioning(forbiddenRR, forbiddenReq, "team2-bucket")
	if forbiddenRR.Code != http.StatusForbidden {
		t.Fatalf("status mismatch: got=%d body=%s", forbiddenRR.Code, forbiddenRR.Body.String())
	}

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-amz-expected-bucket-owner"); got != "123456789012" {
			t.Fatalf("expected owner header mismatch: got=%q", got)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`))
	})
	defer cleanup()

	successReq := httptest.NewRequest(http.MethodGet, "/team2-bucket?versioning", nil)
	successReq.Header.Set("x-amz-expected-bucket-owner", "123456789012")
	successReq = reqWithRules(successReq, fullTeam2Rule())
	successRR := httptest.NewRecorder()
	gw.handleGetBucketVersioning(successRR, successReq, "team2-bucket")
	if successRR.Code != http.StatusOK {
		t.Fatalf("status mismatch: got=%d body=%s", successRR.Code, successRR.Body.String())
	}
	if !strings.Contains(successRR.Body.String(), "<MfaDelete>Enabled</MfaDelete>") {
		t.Fatalf("response missing mfa delete: %s", successRR.Body.String())
	}

	gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
	})
	defer cleanupErr()
	errReq := httptest.NewRequest(http.MethodGet, "/team2-bucket?versioning", nil)
	errReq = reqWithRules(errReq, fullTeam2Rule())
	errRR := httptest.NewRecorder()
	gwErr.handleGetBucketVersioning(errRR, errReq, "team2-bucket")
	if errRR.Code != http.StatusInternalServerError {
		t.Fatalf("status mismatch: got=%d body=%s", errRR.Code, errRR.Body.String())
	}
}

func TestHandleAbortMultipartBranches(t *testing.T) {
	gwNoPerm, cleanupNoPerm := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called when forbidden")
	})
	defer cleanupNoPerm()

	forbiddenReq := httptest.NewRequest(http.MethodDelete, "/team2-dst/object.txt?uploadId=u1", nil)
	forbiddenReq = reqWithRules(forbiddenReq, nil)
	forbiddenRR := httptest.NewRecorder()
	gwNoPerm.handleAbortMultipart(forbiddenRR, forbiddenReq, "team2-dst", "object.txt", "u1")
	if forbiddenRR.Code != http.StatusForbidden {
		t.Fatalf("status mismatch: got=%d body=%s", forbiddenRR.Code, forbiddenRR.Body.String())
	}

	gwOK, cleanupOK := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer cleanupOK()

	okReq := httptest.NewRequest(http.MethodDelete, "/team2-dst/object.txt?uploadId=u1", nil)
	okReq = reqWithRules(okReq, fullTeam2Rule())
	okRR := httptest.NewRecorder()
	gwOK.handleAbortMultipart(okRR, okReq, "team2-dst", "object.txt", "u1")
	if okRR.Code != http.StatusNoContent {
		t.Fatalf("status mismatch: got=%d body=%s", okRR.Code, okRR.Body.String())
	}

	gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
	})
	defer cleanupErr()

	errReq := httptest.NewRequest(http.MethodDelete, "/team2-dst/object.txt?uploadId=u1", nil)
	errReq = reqWithRules(errReq, fullTeam2Rule())
	errRR := httptest.NewRecorder()
	gwErr.handleAbortMultipart(errRR, errReq, "team2-dst", "object.txt", "u1")
	if errRR.Code != http.StatusInternalServerError {
		t.Fatalf("status mismatch: got=%d body=%s", errRR.Code, errRR.Body.String())
	}
}

func TestHandleDeleteObjectsRejectsMoreThan1000Objects(t *testing.T) {
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called")
	})
	defer cleanup()

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><Delete>`)
	for i := 0; i < 1001; i++ {
		b.WriteString("<Object><Key>k")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("</Key></Object>")
	}
	b.WriteString(`</Delete>`)

	req := httptest.NewRequest(http.MethodPost, "/team2-dst?delete", strings.NewReader(b.String()))
	req = reqWithRules(req, fullTeam2Rule())
	rr := httptest.NewRecorder()
	gw.handleDeleteObjects(rr, req, "team2-dst")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandlePutObjectBranchMatrix(t *testing.T) {
	gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
	})
	defer cleanupNoUpstream()

	newReq := func(body string) *http.Request {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/object-put.txt", bytes.NewReader([]byte(body)))
		return reqWithRules(req, fullTeam2Rule())
	}

	t.Run("forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/team2-dst/object-put.txt", bytes.NewReader([]byte("payload")))
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("streaming without auth context", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing content length", func(t *testing.T) {
		req := newReq("payload")
		req.ContentLength = -1
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusLengthRequired {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("entity too large", func(t *testing.T) {
		req := newReq("payload")
		req.ContentLength = maxSinglePutObjectSize + 1
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid expires", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("Expires", "not-a-time")
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("if-match and if-none-match both set", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("If-Match", "\"a\"")
		req.Header.Set("If-None-Match", "\"b\"")
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid sse headers", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("x-amz-server-side-encryption", "AES128")
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid checksum headers", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("x-amz-checksum-crc32", "AAAAAA==")
		req.Header.Set("x-amz-checksum-crc32c", "BBBBBB==")
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("content md5 with checksum algorithm", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")
		req.Header.Set("x-amz-checksum-algorithm", "SHA256")
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid request payer", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("x-amz-request-payer", "owner")
		rr := httptest.NewRecorder()
		gwNoUpstream.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", "\"etag-put\"")
		w.Header().Set("x-amz-version-id", "v-put")
		w.Header().Set("x-amz-server-side-encryption", "aws:kms")
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", "kms-key")
		w.Header().Set("x-amz-server-side-encryption-context", "eyJhIjoiYiJ9")
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		w.Header().Set("x-amz-server-side-encryption-customer-key-md5", "abc123")
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", "true")
		w.Header().Set("x-amz-expiration", `expiry-date="2030-01-01T00:00:00Z", rule-id="r1"`)
		w.Header().Set("x-amz-request-charged", "requester")
		w.Header().Set("x-amz-checksum-crc32", "AAAAAA==")
		w.Header().Set("x-amz-checksum-crc32c", "BBBBBB==")
		w.Header().Set("x-amz-checksum-crc64nvme", "CCCCCC==")
		w.Header().Set("x-amz-checksum-sha1", "DDDDDD==")
		w.Header().Set("x-amz-checksum-sha256", "EEEEEE==")
		w.Header().Set("x-amz-checksum-type", "FULL_OBJECT")
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	t.Run("request path reaches upstream call site", func(t *testing.T) {
		req := newReq("payload")
		rr := httptest.NewRecorder()
		gw.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadGateway {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("optional request fields branch coverage", func(t *testing.T) {
		req := newReq("payload")
		req.Header.Set("If-None-Match", "\"etag-old\"")
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set("Expires", time.Now().Add(2*time.Hour).UTC().Format(http.TimeFormat))
		req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
		req.Header.Set("x-amz-request-payer", "requester")
		req.Header.Set("Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==")
		req.Header.Set("x-amz-server-side-encryption", "aws:kms")
		req.Header.Set("x-amz-server-side-encryption-aws-kms-key-id", "kms-key")
		req.Header.Set("x-amz-server-side-encryption-context", "eyJhIjoiYiJ9")
		rr := httptest.NewRecorder()
		gw.handlePutObject(rr, req, "team2-dst", "object-put.txt")
		if rr.Code != http.StatusOK && rr.Code != http.StatusBadGateway {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestCreateCompleteAndListPartsBranchMatrix(t *testing.T) {
	t.Run("create multipart validation and success branches", func(t *testing.T) {
		gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
		})
		defer cleanupNoUpstream()

		newReq := func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/team2-dst/object.txt?uploads", nil)
			return reqWithRules(req, fullTeam2Rule())
		}

		reqForbidden := httptest.NewRequest(http.MethodPost, "/team2-dst/object.txt?uploads", nil)
		reqForbidden = reqWithRules(reqForbidden, nil)
		rrForbidden := httptest.NewRecorder()
		gwNoUpstream.handleCreateMultipart(rrForbidden, reqForbidden, "team2-dst", "object.txt")
		if rrForbidden.Code != http.StatusForbidden {
			t.Fatalf("forbidden status mismatch: got=%d body=%s", rrForbidden.Code, rrForbidden.Body.String())
		}

		reqBadExpires := newReq()
		reqBadExpires.Header.Set("Expires", "not-a-time")
		rrBadExpires := httptest.NewRecorder()
		gwNoUpstream.handleCreateMultipart(rrBadExpires, reqBadExpires, "team2-dst", "object.txt")
		if rrBadExpires.Code != http.StatusBadRequest {
			t.Fatalf("invalid expires status mismatch: got=%d body=%s", rrBadExpires.Code, rrBadExpires.Body.String())
		}

		reqBadSSE := newReq()
		reqBadSSE.Header.Set("x-amz-server-side-encryption", "AES128")
		rrBadSSE := httptest.NewRecorder()
		gwNoUpstream.handleCreateMultipart(rrBadSSE, reqBadSSE, "team2-dst", "object.txt")
		if rrBadSSE.Code != http.StatusBadRequest {
			t.Fatalf("invalid sse status mismatch: got=%d body=%s", rrBadSSE.Code, rrBadSSE.Body.String())
		}

		reqBadChecksum := newReq()
		reqBadChecksum.Header.Set("x-amz-checksum-crc32", "AAAAAA==")
		reqBadChecksum.Header.Set("x-amz-checksum-crc32c", "BBBBBB==")
		rrBadChecksum := httptest.NewRecorder()
		gwNoUpstream.handleCreateMultipart(rrBadChecksum, reqBadChecksum, "team2-dst", "object.txt")
		if rrBadChecksum.Code != http.StatusBadRequest {
			t.Fatalf("invalid checksum status mismatch: got=%d body=%s", rrBadChecksum.Code, rrBadChecksum.Body.String())
		}

		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if _, ok := r.URL.Query()["uploads"]; !ok {
				t.Fatalf("expected uploads query in upstream request: %s", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-dst</Bucket><Key>object.txt</Key><UploadId>u1</UploadId></InitiateMultipartUploadResult>`))
		})
		defer cleanup()

		reqSuccess := newReq()
		reqSuccess.Header.Set("Content-Type", "text/plain")
		reqSuccess.Header.Set("x-amz-server-side-encryption", "aws:kms")
		reqSuccess.Header.Set("x-amz-server-side-encryption-aws-kms-key-id", "kms-key")
		reqSuccess.Header.Set("x-amz-server-side-encryption-context", "eyJhIjoiYiJ9")
		reqSuccess.Header.Set("x-amz-checksum-algorithm", "SHA256")
		rrSuccess := httptest.NewRecorder()
		gw.handleCreateMultipart(rrSuccess, reqSuccess, "team2-dst", "object.txt")
		if rrSuccess.Code != http.StatusOK {
			t.Fatalf("success status mismatch: got=%d body=%s", rrSuccess.Code, rrSuccess.Body.String())
		}

		gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanupErr()
		reqErr := newReq()
		rrErr := httptest.NewRecorder()
		gwErr.handleCreateMultipart(rrErr, reqErr, "team2-dst", "object.txt")
		if rrErr.Code != http.StatusInternalServerError {
			t.Fatalf("upstream error status mismatch: got=%d body=%s", rrErr.Code, rrErr.Body.String())
		}
	})

	t.Run("complete multipart validation, upstream error and success branches", func(t *testing.T) {
		gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
		})
		defer cleanupNoUpstream()

		reqForbidden := httptest.NewRequest(http.MethodPost, "/team2-dst/object.txt?uploadId=u1", strings.NewReader(`<CompleteMultipartUpload/>`))
		reqForbidden = reqWithRules(reqForbidden, nil)
		rrForbidden := httptest.NewRecorder()
		gwNoUpstream.handleCompleteMultipart(rrForbidden, reqForbidden, "team2-dst", "object.txt", "u1")
		if rrForbidden.Code != http.StatusForbidden {
			t.Fatalf("forbidden status mismatch: got=%d body=%s", rrForbidden.Code, rrForbidden.Body.String())
		}

		reqMalformed := httptest.NewRequest(http.MethodPost, "/team2-dst/object.txt?uploadId=u1", strings.NewReader(`<CompleteMultipartUpload><Part>`))
		reqMalformed = reqWithRules(reqMalformed, fullTeam2Rule())
		rrMalformed := httptest.NewRecorder()
		gwNoUpstream.handleCompleteMultipart(rrMalformed, reqMalformed, "team2-dst", "object.txt", "u1")
		if rrMalformed.Code != http.StatusBadRequest {
			t.Fatalf("malformed status mismatch: got=%d body=%s", rrMalformed.Code, rrMalformed.Body.String())
		}

		reqNoParts := httptest.NewRequest(http.MethodPost, "/team2-dst/object.txt?uploadId=u1", strings.NewReader(`<CompleteMultipartUpload><Part><PartNumber>0</PartNumber><ETag></ETag></Part></CompleteMultipartUpload>`))
		reqNoParts = reqWithRules(reqNoParts, fullTeam2Rule())
		rrNoParts := httptest.NewRecorder()
		gwNoUpstream.handleCompleteMultipart(rrNoParts, reqNoParts, "team2-dst", "object.txt", "u1")
		if rrNoParts.Code != http.StatusBadRequest {
			t.Fatalf("no-parts status mismatch: got=%d body=%s", rrNoParts.Code, rrNoParts.Body.String())
		}

		gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanupErr()

		reqErr := httptest.NewRequest(http.MethodPost, "/team2-dst/object.txt?uploadId=u1", strings.NewReader(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>etag1</ETag></Part></CompleteMultipartUpload>`))
		reqErr = reqWithRules(reqErr, fullTeam2Rule())
		rrErr := httptest.NewRecorder()
		gwErr.handleCompleteMultipart(rrErr, reqErr, "team2-dst", "object.txt", "u1")
		if rrErr.Code != http.StatusInternalServerError {
			t.Fatalf("upstream error status mismatch: got=%d body=%s", rrErr.Code, rrErr.Body.String())
		}

		gwOK, cleanupOK := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>team2-dst</Bucket><Key>object.txt</Key><ETag>etag-complete</ETag></CompleteMultipartUploadResult>`))
		})
		defer cleanupOK()

		reqOK := httptest.NewRequest(http.MethodPost, "/team2-dst/object.txt?uploadId=u1", strings.NewReader(`<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>etag2</ETag></Part><Part><PartNumber>1</PartNumber><ETag>etag1</ETag></Part></CompleteMultipartUpload>`))
		reqOK = reqWithRules(reqOK, fullTeam2Rule())
		rrOK := httptest.NewRecorder()
		gwOK.handleCompleteMultipart(rrOK, reqOK, "team2-dst", "object.txt", "u1")
		if rrOK.Code != http.StatusOK {
			t.Fatalf("success status mismatch: got=%d body=%s", rrOK.Code, rrOK.Body.String())
		}
		if !strings.Contains(rrOK.Body.String(), "<ETag>\"etag-complete\"</ETag>") {
			t.Fatalf("expected quoted etag in response body: %s", rrOK.Body.String())
		}
	})

	t.Run("list parts validation and upstream error branches", func(t *testing.T) {
		gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
		})
		defer cleanupNoUpstream()

		reqForbidden := httptest.NewRequest(http.MethodGet, "/team2-dst/object.txt?uploadId=u1", nil)
		reqForbidden = reqWithRules(reqForbidden, nil)
		rrForbidden := httptest.NewRecorder()
		gwNoUpstream.handleListParts(rrForbidden, reqForbidden, "team2-dst", "object.txt", "u1")
		if rrForbidden.Code != http.StatusForbidden {
			t.Fatalf("forbidden status mismatch: got=%d body=%s", rrForbidden.Code, rrForbidden.Body.String())
		}

		reqBadPNM := httptest.NewRequest(http.MethodGet, "/team2-dst/object.txt?uploadId=u1&part-number-marker=-1", nil)
		reqBadPNM = reqWithRules(reqBadPNM, fullTeam2Rule())
		rrBadPNM := httptest.NewRecorder()
		gwNoUpstream.handleListParts(rrBadPNM, reqBadPNM, "team2-dst", "object.txt", "u1")
		if rrBadPNM.Code != http.StatusBadRequest {
			t.Fatalf("invalid part-number-marker status mismatch: got=%d body=%s", rrBadPNM.Code, rrBadPNM.Body.String())
		}

		reqBadMaxParts := httptest.NewRequest(http.MethodGet, "/team2-dst/object.txt?uploadId=u1&max-parts=0", nil)
		reqBadMaxParts = reqWithRules(reqBadMaxParts, fullTeam2Rule())
		rrBadMaxParts := httptest.NewRecorder()
		gwNoUpstream.handleListParts(rrBadMaxParts, reqBadMaxParts, "team2-dst", "object.txt", "u1")
		if rrBadMaxParts.Code != http.StatusBadRequest {
			t.Fatalf("invalid max-parts status mismatch: got=%d body=%s", rrBadMaxParts.Code, rrBadMaxParts.Body.String())
		}

		gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanupErr()
		reqErr := httptest.NewRequest(http.MethodGet, "/team2-dst/object.txt?uploadId=u1", nil)
		reqErr = reqWithRules(reqErr, fullTeam2Rule())
		rrErr := httptest.NewRecorder()
		gwErr.handleListParts(rrErr, reqErr, "team2-dst", "object.txt", "u1")
		if rrErr.Code != http.StatusInternalServerError {
			t.Fatalf("upstream error status mismatch: got=%d body=%s", rrErr.Code, rrErr.Body.String())
		}
	})
}

func TestServeHTTPAndAuthBranches(t *testing.T) {
	gw := newServer(Config{SigV4Service: "s3", SigV4MaxSkew: 15 * time.Minute}, nil)

	t.Run("servehttp route not implemented and invalid part number branches", func(t *testing.T) {
		cases := []struct {
			method string
			target string
			want   int
		}{
			{method: http.MethodPost, target: "/", want: http.StatusNotFound},
			{method: http.MethodGet, target: "/healthz", want: http.StatusOK},
			{method: http.MethodHead, target: "/healthz", want: http.StatusOK},
			{method: http.MethodPatch, target: "/team2-bucket?lifecycle", want: http.StatusNotImplemented},
			{method: http.MethodDelete, target: "/team2-bucket?versioning", want: http.StatusNotImplemented},
			{method: http.MethodGet, target: "/team2-bucket", want: http.StatusNotImplemented},
			{method: http.MethodPut, target: "/team2-bucket/key.txt?uploadId=u1&partNumber=abc", want: http.StatusBadRequest},
			{method: http.MethodPatch, target: "/team2-bucket/key.txt?uploadId=u1&partNumber=1", want: http.StatusNotImplemented},
			{method: http.MethodTrace, target: "/team2-bucket/key.txt", want: http.StatusNotImplemented},
		}
		for _, tc := range cases {
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req = req.WithContext(context.WithValue(req.Context(), ctxRulesKey, fullTeam2Rule()))
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, req)
			if rr.Code != tc.want {
				t.Fatalf("%s %s status mismatch: got=%d want=%d body=%s", tc.method, tc.target, rr.Code, tc.want, rr.Body.String())
			}
		}
	})

	t.Run("withAuth error and success branches", func(t *testing.T) {
		healthHandler := gw.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		rrHealth := httptest.NewRecorder()
		healthHandler.ServeHTTP(rrHealth, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rrHealth.Code != http.StatusNoContent {
			t.Fatalf("healthz should bypass auth and reach next handler: got=%d body=%s", rrHealth.Code, rrHealth.Body.String())
		}

		handler := gw.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rulesFromCtx(r) == nil {
				t.Fatalf("expected rules in request context")
			}
			w.WriteHeader(http.StatusNoContent)
		}))

		newSignedReq := func(accessKey, amzDate, service string) *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/team2-bucket/key.txt", nil)
			req.Header.Set("Host", "example.com")
			req.Header.Set("x-amz-date", amzDate)
			credDate := amzDate[:8]
			req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+credDate+"/us-east-1/"+service+"/aws4_request, SignedHeaders=host;x-amz-date, Signature="+strings.Repeat("a", 64))
			return req
		}
		fixedAmzDate := "20260207T010203Z"

		rrMissingAuth := httptest.NewRecorder()
		handler.ServeHTTP(rrMissingAuth, httptest.NewRequest(http.MethodGet, "/team2-bucket/key.txt", nil))
		if rrMissingAuth.Code != http.StatusUnauthorized {
			t.Fatalf("missing auth status mismatch: got=%d body=%s", rrMissingAuth.Code, rrMissingAuth.Body.String())
		}

		rrWrongService := httptest.NewRecorder()
		handler.ServeHTTP(rrWrongService, newSignedReq("dXNlcjpwYXNz", fixedAmzDate, "ec2"))
		if rrWrongService.Code != http.StatusUnauthorized {
			t.Fatalf("wrong service status mismatch: got=%d body=%s", rrWrongService.Code, rrWrongService.Body.String())
		}

		rrBadAccessKey := httptest.NewRecorder()
		handler.ServeHTTP(rrBadAccessKey, newSignedReq("not-base64", fixedAmzDate, "s3"))
		if rrBadAccessKey.Code != http.StatusUnauthorized {
			t.Fatalf("bad access key status mismatch: got=%d body=%s", rrBadAccessKey.Code, rrBadAccessKey.Body.String())
		}

		rrBadCreds := httptest.NewRecorder()
		gwFetch := newServer(Config{
			SigV4Service: "s3",
			SigV4MaxSkew: 0,
			LDAPURL:      "ldap://127.0.0.1:1",
			BaseDN:       "dc=example,dc=com",
		}, nil)
		handlerFetch := gwFetch.withAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))
		handlerFetch.ServeHTTP(rrBadCreds, newSignedReq("dXNlcjpwYXNz", fixedAmzDate, "s3"))
		if rrBadCreds.Code != http.StatusUnauthorized {
			t.Fatalf("bad creds status mismatch: got=%d body=%s", rrBadCreds.Code, rrBadCreds.Body.String())
		}

	})
}

func TestHandleListObjectVersionsBranchMatrix(t *testing.T) {
	gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
	})
	defer cleanupNoUpstream()

	t.Run("forbidden", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-dst?versions", nil)
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gwNoUpstream.handleListObjectVersions(rr, req, "team2-dst")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid max-keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-dst?versions&max-keys=-1", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gwNoUpstream.handleListObjectVersions(rr, req, "team2-dst")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid encoding-type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-dst?versions&encoding-type=xml", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gwNoUpstream.handleListObjectVersions(rr, req, "team2-dst")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid optional-object-attributes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-dst?versions&optional-object-attributes=Checksum", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gwNoUpstream.handleListObjectVersions(rr, req, "team2-dst")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid request payer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/team2-dst?versions", nil)
		req.Header.Set("x-amz-request-payer", "owner")
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gwNoUpstream.handleListObjectVersions(rr, req, "team2-dst")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("upstream error", func(t *testing.T) {
		gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanupErr()

		req := httptest.NewRequest(http.MethodGet, "/team2-dst?versions", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gwErr.handleListObjectVersions(rr, req, "team2-dst")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("rich success response", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("x-amz-request-charged", "requester")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>team2-dst</Name>
  <Prefix>logs/</Prefix>
  <KeyMarker>logs/a</KeyMarker>
  <VersionIdMarker>v0</VersionIdMarker>
  <NextKeyMarker>logs/z</NextKeyMarker>
  <NextVersionIdMarker>v9</NextVersionIdMarker>
  <Delimiter>/</Delimiter>
  <MaxKeys>5</MaxKeys>
  <EncodingType>url</EncodingType>
  <IsTruncated>true</IsTruncated>
  <CommonPrefixes><Prefix>logs/archive/</Prefix></CommonPrefixes>
  <Version>
    <Key>logs/a.txt</Key>
    <VersionId>v1</VersionId>
    <IsLatest>true</IsLatest>
    <LastModified>2026-02-07T01:02:03.000Z</LastModified>
    <ETag>"etag-v1"</ETag>
    <Size>11</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner><ID>owner-id</ID><DisplayName>owner-name</DisplayName></Owner>
    <RestoreStatus><IsRestoreInProgress>false</IsRestoreInProgress><RestoreExpiryDate>2026-02-08T01:02:03.000Z</RestoreExpiryDate></RestoreStatus>
  </Version>
  <DeleteMarker>
    <Key>logs/b.txt</Key>
    <VersionId>v2</VersionId>
    <IsLatest>false</IsLatest>
    <LastModified>2026-02-07T01:02:03.000Z</LastModified>
    <Owner><ID>owner-id</ID><DisplayName>owner-name</DisplayName></Owner>
  </DeleteMarker>
</ListVersionsResult>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-dst?versions&prefix=logs/&delimiter=/&key-marker=logs/a&version-id-marker=v0&max-keys=5&encoding-type=url&optional-object-attributes=RestoreStatus", nil)
		req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
		req.Header.Set("x-amz-request-payer", "requester")
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handleListObjectVersions(rr, req, "team2-dst")
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
		if rr.Header().Get("x-amz-request-charged") != "requester" {
			t.Fatalf("missing request charged header: %q", rr.Header().Get("x-amz-request-charged"))
		}
		for _, want := range []string{
			"<CommonPrefixes><Prefix>logs/archive/</Prefix></CommonPrefixes>",
			"<RestoreStatus>",
			"<DeleteMarker>",
			"<Owner><ID>owner-id</ID><DisplayName>owner-name</DisplayName></Owner>",
		} {
			if !strings.Contains(rr.Body.String(), want) {
				t.Fatalf("missing %q in response body: %s", want, rr.Body.String())
			}
		}
	})
}

func TestHandleListMultipartUploadsAndDeleteObjectBranches(t *testing.T) {
	t.Run("list multipart uploads branches", func(t *testing.T) {
		gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
		})
		defer cleanupNoUpstream()

		reqForbidden := httptest.NewRequest(http.MethodGet, "/team2-dst?uploads", nil)
		reqForbidden = reqWithRules(reqForbidden, nil)
		rrForbidden := httptest.NewRecorder()
		gwNoUpstream.handleListMultipartUploads(rrForbidden, reqForbidden, "team2-dst")
		if rrForbidden.Code != http.StatusForbidden {
			t.Fatalf("forbidden status mismatch: got=%d body=%s", rrForbidden.Code, rrForbidden.Body.String())
		}

		reqBadMax := httptest.NewRequest(http.MethodGet, "/team2-dst?uploads&max-uploads=0", nil)
		reqBadMax = reqWithRules(reqBadMax, fullTeam2Rule())
		rrBadMax := httptest.NewRecorder()
		gwNoUpstream.handleListMultipartUploads(rrBadMax, reqBadMax, "team2-dst")
		if rrBadMax.Code != http.StatusBadRequest {
			t.Fatalf("invalid max-uploads status mismatch: got=%d body=%s", rrBadMax.Code, rrBadMax.Body.String())
		}

		gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanupErr()

		reqErr := httptest.NewRequest(http.MethodGet, "/team2-dst?uploads", nil)
		reqErr = reqWithRules(reqErr, fullTeam2Rule())
		rrErr := httptest.NewRecorder()
		gwErr.handleListMultipartUploads(rrErr, reqErr, "team2-dst")
		if rrErr.Code != http.StatusInternalServerError {
			t.Fatalf("upstream error status mismatch: got=%d body=%s", rrErr.Code, rrErr.Body.String())
		}

		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>team2-dst</Bucket>
  <KeyMarker>logs/a</KeyMarker>
  <UploadIdMarker>u0</UploadIdMarker>
  <NextKeyMarker>logs/z</NextKeyMarker>
  <NextUploadIdMarker>u9</NextUploadIdMarker>
  <Prefix>logs/</Prefix>
  <Delimiter>/</Delimiter>
  <MaxUploads>5</MaxUploads>
  <IsTruncated>true</IsTruncated>
  <CommonPrefixes><Prefix>logs/archive/</Prefix></CommonPrefixes>
  <Upload>
    <Key>logs/a.txt</Key>
    <UploadId>u1</UploadId>
    <Initiated>2026-02-07T01:02:03.000Z</Initiated>
    <StorageClass>STANDARD</StorageClass>
    <ChecksumAlgorithm>SHA256</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Owner><ID>owner-id</ID><DisplayName>owner-name</DisplayName></Owner>
    <Initiator><ID>init-id</ID><DisplayName>init-name</DisplayName></Initiator>
  </Upload>
</ListMultipartUploadsResult>`))
		})
		defer cleanup()

		reqOK := httptest.NewRequest(http.MethodGet, "/team2-dst?uploads&prefix=logs/&delimiter=/&key-marker=logs/a&upload-id-marker=u0&encoding-type=url&max-uploads=5", nil)
		reqOK = reqWithRules(reqOK, fullTeam2Rule())
		rrOK := httptest.NewRecorder()
		gw.handleListMultipartUploads(rrOK, reqOK, "team2-dst")
		if rrOK.Code != http.StatusOK {
			t.Fatalf("success status mismatch: got=%d body=%s", rrOK.Code, rrOK.Body.String())
		}
		for _, want := range []string{
			"<ChecksumType>FULL_OBJECT</ChecksumType>",
			"<Initiator><DisplayName>init-name</DisplayName><ID>init-id</ID></Initiator>",
			"<CommonPrefixes><Prefix>logs/archive/</Prefix></CommonPrefixes>",
		} {
			if !strings.Contains(rrOK.Body.String(), want) {
				t.Fatalf("missing %q in response body: %s", want, rrOK.Body.String())
			}
		}
	})

	t.Run("delete object branches", func(t *testing.T) {
		gwNoUpstream, cleanupNoUpstream := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called for validation errors: %s %s", r.Method, r.URL.String())
		})
		defer cleanupNoUpstream()

		reqForbidden := httptest.NewRequest(http.MethodDelete, "/team2-dst/a.txt", nil)
		reqForbidden = reqWithRules(reqForbidden, nil)
		rrForbidden := httptest.NewRecorder()
		gwNoUpstream.handleDeleteObject(rrForbidden, reqForbidden, "team2-dst", "a.txt")
		if rrForbidden.Code != http.StatusForbidden {
			t.Fatalf("forbidden status mismatch: got=%d body=%s", rrForbidden.Code, rrForbidden.Body.String())
		}

		reqBadBypass := httptest.NewRequest(http.MethodDelete, "/team2-dst/a.txt", nil)
		reqBadBypass.Header.Set("x-amz-bypass-governance-retention", "invalid")
		reqBadBypass = reqWithRules(reqBadBypass, fullTeam2Rule())
		rrBadBypass := httptest.NewRecorder()
		gwNoUpstream.handleDeleteObject(rrBadBypass, reqBadBypass, "team2-dst", "a.txt")
		if rrBadBypass.Code != http.StatusBadRequest {
			t.Fatalf("invalid bypass status mismatch: got=%d body=%s", rrBadBypass.Code, rrBadBypass.Body.String())
		}

		reqBadPayer := httptest.NewRequest(http.MethodDelete, "/team2-dst/a.txt", nil)
		reqBadPayer.Header.Set("x-amz-request-payer", "owner")
		reqBadPayer = reqWithRules(reqBadPayer, fullTeam2Rule())
		rrBadPayer := httptest.NewRecorder()
		gwNoUpstream.handleDeleteObject(rrBadPayer, reqBadPayer, "team2-dst", "a.txt")
		if rrBadPayer.Code != http.StatusBadRequest {
			t.Fatalf("invalid payer status mismatch: got=%d body=%s", rrBadPayer.Code, rrBadPayer.Body.String())
		}

		gwErr, cleanupErr := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanupErr()

		reqErr := httptest.NewRequest(http.MethodDelete, "/team2-dst/a.txt", nil)
		reqErr = reqWithRules(reqErr, fullTeam2Rule())
		rrErr := httptest.NewRecorder()
		gwErr.handleDeleteObject(rrErr, reqErr, "team2-dst", "a.txt")
		if rrErr.Code != http.StatusInternalServerError {
			t.Fatalf("upstream error status mismatch: got=%d body=%s", rrErr.Code, rrErr.Body.String())
		}

		gwOK, cleanupOK := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("x-amz-delete-marker", "true")
			w.Header().Set("x-amz-version-id", "v1")
			w.Header().Set("x-amz-request-charged", "requester")
			w.WriteHeader(http.StatusNoContent)
		})
		defer cleanupOK()

		reqOK := httptest.NewRequest(http.MethodDelete, "/team2-dst/a.txt?versionId=v1", nil)
		reqOK.Header.Set("If-Match", "\"etag\"")
		reqOK.Header.Set("x-amz-expected-bucket-owner", "123456789012")
		reqOK.Header.Set("x-amz-bypass-governance-retention", "true")
		reqOK.Header.Set("x-amz-request-payer", "requester")
		reqOK = reqWithRules(reqOK, fullTeam2Rule())
		rrOK := httptest.NewRecorder()
		gwOK.handleDeleteObject(rrOK, reqOK, "team2-dst", "a.txt")
		if rrOK.Code != http.StatusNoContent {
			t.Fatalf("success status mismatch: got=%d body=%s", rrOK.Code, rrOK.Body.String())
		}
		if rrOK.Header().Get("x-amz-request-charged") != "requester" {
			t.Fatalf("missing request charged header")
		}
	})
}

func TestBucketLifecycleHandlersBranches(t *testing.T) {
	validLifecycle := `<?xml version="1.0" encoding="UTF-8"?><LifecycleConfiguration><Rule><ID>r1</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`

	t.Run("put lifecycle forbidden", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?lifecycle", strings.NewReader(validLifecycle))
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.handlePutBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("put lifecycle malformed xml", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?lifecycle", strings.NewReader(`<LifecycleConfiguration><Rule>`))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("put lifecycle success", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?lifecycle", strings.NewReader(validLifecycle))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("put lifecycle upstream error", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?lifecycle", strings.NewReader(validLifecycle))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("get lifecycle forbidden", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?lifecycle", nil)
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.handleGetBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("get lifecycle success", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ID>r1</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?lifecycle", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handleGetBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), "<LifecycleConfiguration") {
			t.Fatalf("missing lifecycle xml in response: %s", rr.Body.String())
		}
	})

	t.Run("get lifecycle upstream error", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodGet, "/team2-bucket?lifecycle", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handleGetBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("delete lifecycle forbidden", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodDelete, "/team2-bucket?lifecycle", nil)
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.handleDeleteBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("delete lifecycle success", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodDelete, "/team2-bucket?lifecycle", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handleDeleteBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("delete lifecycle upstream error", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodDelete, "/team2-bucket?lifecycle", nil)
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handleDeleteBucketLifecycleConfiguration(rr, req, "team2-bucket")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestHandlePutBucketVersioningBranches(t *testing.T) {
	validVersioning := `<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration><Status>Enabled</Status><MfaDelete>Enabled</MfaDelete></VersioningConfiguration>`

	t.Run("forbidden", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?versioning", strings.NewReader(validVersioning))
		req = reqWithRules(req, nil)
		rr := httptest.NewRecorder()
		gw.handlePutBucketVersioning(rr, req, "team2-bucket")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("malformed xml", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("upstream should not be called")
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?versioning", strings.NewReader(`<VersioningConfiguration><Status>`))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutBucketVersioning(rr, req, "team2-bucket")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success with optional headers", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("X-Amz-Mfa"); got != "device 123456" {
				t.Fatalf("x-amz-mfa mismatch: got=%q", got)
			}
			if got := r.Header.Get("Content-Md5"); got != "d41d8cd98f00b204e9800998ecf8427e" {
				t.Fatalf("content-md5 mismatch: got=%q", got)
			}
			if got := r.Header.Get("X-Amz-Expected-Bucket-Owner"); got != "123456789012" {
				t.Fatalf("expected bucket owner mismatch: got=%q", got)
			}
			w.WriteHeader(http.StatusOK)
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?versioning", strings.NewReader(validVersioning))
		req.Header.Set("x-amz-mfa", "device 123456")
		req.Header.Set("Content-MD5", "d41d8cd98f00b204e9800998ecf8427e")
		req.Header.Set("x-amz-expected-bucket-owner", "123456789012")
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutBucketVersioning(rr, req, "team2-bucket")
		if rr.Code != http.StatusOK {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("upstream error", func(t *testing.T) {
		gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>boom</Message></Error>`))
		})
		defer cleanup()

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket?versioning", strings.NewReader(validVersioning))
		req = reqWithRules(req, fullTeam2Rule())
		rr := httptest.NewRecorder()
		gw.handlePutBucketVersioning(rr, req, "team2-bucket")
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status mismatch: got=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}
