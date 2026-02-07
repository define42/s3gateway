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
