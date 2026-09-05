package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestObjectWritesRejectInvalidChecksumHeaders(t *testing.T) {
	var upstreamCalls atomic.Int64
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<Error><Code>BadDigest</Code><Message>Unexpected upstream request</Message></Error>`)
	})
	defer cleanup()

	for _, target := range []struct {
		name, method, path, body string
		copySource               bool
	}{
		{name: "put", method: http.MethodPut, path: "/team2-bucket/object", body: "123456789"},
		{name: "upload part", method: http.MethodPut, path: "/team2-bucket/object?uploadId=upload-1&partNumber=1", body: "123456789"},
		{name: "create", method: http.MethodPost, path: "/team2-bucket/object?uploads"},
		{name: "complete", method: http.MethodPost, path: "/team2-bucket/object?uploadId=upload-1", body: completeMultipartDocument(1, "part-etag")},
		{name: "copy", method: http.MethodPut, path: "/team2-bucket/object", copySource: true},
		{name: "copy part", method: http.MethodPut, path: "/team2-bucket/object?uploadId=upload-1&partNumber=1", copySource: true},
	} {
		t.Run(target.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, header string
				values       []string
			}{
				{name: "SHA512", header: "x-amz-checksum-sha512", values: []string{strings.Repeat("A", 86) + "=="}},
				{name: "MD5", header: "x-amz-checksum-md5", values: []string{"AAAAAAAAAAAAAAAAAAAAAA=="}},
				{name: "XXHASH64", header: "x-amz-checksum-xxhash64", values: []string{"AAAAAAAAAAA="}},
				{name: "XXHASH3", header: "x-amz-checksum-xxhash3", values: []string{"AAAAAAAAAAA="}},
				{name: "XXHASH128", header: "x-amz-checksum-xxhash128", values: []string{"AAAAAAAAAAAAAAAAAAAAAA=="}},
				{name: "unknown", header: "x-amz-checksum-future", values: []string{"checksum"}},
				{name: "empty unknown", header: "x-amz-checksum-sha512", values: []string{""}},
				{name: "empty value", header: "x-amz-checksum-crc32", values: []string{" "}},
				{name: "duplicate value", header: "x-amz-checksum-crc32", values: []string{"y/Q5Jg==", "AAAAAA=="}},
				{name: "duplicate identical value", header: "x-amz-checksum-crc32", values: []string{"y/Q5Jg==", "y/Q5Jg=="}},
				{name: "empty algorithm", header: "x-amz-checksum-algorithm", values: []string{""}},
				{name: "duplicate algorithm", header: "x-amz-checksum-algorithm", values: []string{"CRC32", "CRC32"}},
				{name: "empty SDK algorithm", header: "x-amz-sdk-checksum-algorithm", values: []string{""}},
				{name: "duplicate SDK algorithm", header: "x-amz-sdk-checksum-algorithm", values: []string{"CRC32", "CRC32"}},
				{name: "empty type", header: "x-amz-checksum-type", values: []string{""}},
				{name: "duplicate type", header: "x-amz-checksum-type", values: []string{"FULL_OBJECT", "FULL_OBJECT"}},
				{name: "read checksum mode", header: "x-amz-checksum-mode", values: []string{"ENABLED"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					before := upstreamCalls.Load()
					req := httptest.NewRequest(target.method, target.path, strings.NewReader(target.body))
					if target.copySource {
						req.Header.Set("x-amz-copy-source", "/team2-bucket/source")
					}
					for _, value := range tc.values {
						req.Header.Add(tc.header, value)
					}
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidArgument</Code>") {
						t.Errorf("status = %d, body = %s; want InvalidArgument", rr.Code, rr.Body.String())
					}
					if got := upstreamCalls.Load() - before; got != 0 {
						t.Errorf("invalid checksum request reached upstream %d times", got)
					}
				})
			}
		})
	}
}

func TestObjectWritesRejectUnsupportedChecksumSettings(t *testing.T) {
	var upstreamCalls atomic.Int64
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `<Error><Code>BadDigest</Code></Error>`)
	})
	defer cleanup()

	for _, tc := range []struct {
		name, method, path, header, value string
		copySource                        bool
	}{
		{name: "put type", method: http.MethodPut, header: "x-amz-checksum-type", value: "FULL_OBJECT"},
		{name: "upload part type", method: http.MethodPut, path: "?uploadId=upload-1&partNumber=1", header: "x-amz-checksum-type", value: "FULL_OBJECT"},
		{name: "create value", method: http.MethodPost, path: "?uploads", header: "x-amz-checksum-crc32", value: "y/Q5Jg=="},
		{name: "complete algorithm", method: http.MethodPost, path: "?uploadId=upload-1", header: "x-amz-checksum-algorithm", value: "CRC32"},
		{name: "complete SDK algorithm", method: http.MethodPost, path: "?uploadId=upload-1", header: "x-amz-sdk-checksum-algorithm", value: "CRC32"},
		{name: "copy value", method: http.MethodPut, header: "x-amz-checksum-crc32", value: "y/Q5Jg==", copySource: true},
		{name: "copy type", method: http.MethodPut, header: "x-amz-checksum-type", value: "FULL_OBJECT", copySource: true},
		{name: "copy part value", method: http.MethodPut, path: "?uploadId=upload-1&partNumber=1", header: "x-amz-checksum-crc32", value: "y/Q5Jg==", copySource: true},
		{name: "copy part algorithm", method: http.MethodPut, path: "?uploadId=upload-1&partNumber=1", header: "x-amz-checksum-algorithm", value: "CRC32", copySource: true},
		{name: "copy part SDK algorithm", method: http.MethodPut, path: "?uploadId=upload-1&partNumber=1", header: "x-amz-sdk-checksum-algorithm", value: "CRC32", copySource: true},
		{name: "copy part type", method: http.MethodPut, path: "?uploadId=upload-1&partNumber=1", header: "x-amz-checksum-type", value: "FULL_OBJECT", copySource: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := upstreamCalls.Load()
			req := httptest.NewRequest(tc.method, "/team2-bucket/object"+tc.path, strings.NewReader(completeMultipartDocument(1, "part-etag")))
			req.Header.Set(tc.header, tc.value)
			if tc.copySource {
				req.Header.Set("x-amz-copy-source", "/team2-bucket/source")
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidArgument</Code>") {
				t.Errorf("status = %d, body = %s; want InvalidArgument", rr.Code, rr.Body.String())
			}
			if got := upstreamCalls.Load() - before; got != 0 {
				t.Errorf("unsupported checksum request reached upstream %d times", got)
			}
		})
	}
}

func TestCopyObjectChecksumAlgorithmAliases(t *testing.T) {
	for _, header := range []string{"x-amz-checksum-algorithm", "x-amz-sdk-checksum-algorithm"} {
		for _, checksum := range multipartChecksumCases {
			t.Run(header+"/"+checksum.algorithm, func(t *testing.T) {
				requests := make(chan string, 1)
				gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodHead {
						w.WriteHeader(http.StatusOK)
						return
					}
					requests <- r.Header.Get("x-amz-checksum-algorithm")
					_, _ = io.WriteString(w, `<CopyObjectResult><ETag>"copied-etag"</ETag></CopyObjectResult>`)
				})
				defer cleanup()
				req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object", nil)
				req.Header.Set("x-amz-copy-source", "/team2-bucket/source")
				req.Header.Set(header, strings.ToLower(checksum.algorithm))
				rr := httptest.NewRecorder()
				gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
				if rr.Code != http.StatusOK {
					t.Fatalf("copy status = %d, body = %s", rr.Code, rr.Body.String())
				}
				select {
				case got := <-requests:
					if got != checksum.algorithm {
						t.Errorf("upstream algorithm = %q, want %q", got, checksum.algorithm)
					}
				default:
					t.Fatal("copy did not reach upstream")
				}
			})
		}
	}
}
