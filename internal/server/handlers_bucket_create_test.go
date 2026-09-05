package server

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/define42/s3gateway/internal/s3xml"
)

func TestCreateBucketForwardsConfiguration(t *testing.T) {
	var upstreamCalls atomic.Int32
	type creation struct {
		header http.Header
		body   []byte
	}
	requests := make(chan creation, 1)
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		if r.Method != http.MethodPut || r.URL.Path != "/team2-bucket" {
			t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL.Path)
		}
		if md5 := r.Header.Get("Content-MD5"); md5 != "" && md5 != xmlBodyMD5(string(body)) {
			t.Errorf("upstream Content-MD5 does not match serialized XML")
		}
		requests <- creation{header: r.Header.Clone(), body: body}
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	for _, tc := range []struct {
		name          string
		body          string
		region        string
		lock          string
		ownership     string
		unknownLength bool
	}{
		{name: "default region"},
		{name: "lock without configuration", lock: "true"},
		{name: "empty configuration", body: `<CreateBucketConfiguration/>`},
		{name: "region and lock", body: `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`, region: "eu-west-1", lock: "true"},
		{name: "explicit false", lock: "false"},
		{name: "region alias", body: `<CreateBucketConfiguration><LocationConstraint>EU</LocationConstraint></CreateBucketConfiguration>`, region: "EU"},
		{name: "custom region with unknown length", body: `<CreateBucketConfiguration><LocationConstraint>private-region</LocationConstraint></CreateBucketConfiguration>`, region: "private-region", unknownLength: true},
		{name: "owner enforced", ownership: "BucketOwnerEnforced", lock: "true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket", strings.NewReader(tc.body))
			req.Header.Set("Content-MD5", xmlBodyMD5(tc.body))
			if tc.lock != "" {
				req.Header.Set("x-amz-bucket-object-lock-enabled", tc.lock)
			}
			if tc.ownership != "" {
				req.Header.Set("x-amz-object-ownership", tc.ownership)
			}
			if tc.unknownLength {
				req.ContentLength = -1
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK || upstreamCalls.Swap(0) != 1 {
				t.Fatalf("status=%d body=%s, want 200 and one upstream call", rr.Code, rr.Body.String())
			}
			observed := <-requests
			if got := observed.header.Get("x-amz-bucket-object-lock-enabled"); got != tc.lock {
				t.Errorf("upstream Object Lock=%q, want %q", got, tc.lock)
			}
			if got := observed.header.Get("x-amz-object-ownership"); got != tc.ownership {
				t.Errorf("upstream Object Ownership=%q, want %q", got, tc.ownership)
			}
			if tc.body == "" {
				if len(observed.body) != 0 {
					t.Errorf("unexpected upstream configuration: %s", observed.body)
				}
				return
			}
			var config struct {
				XMLName            xml.Name `xml:"CreateBucketConfiguration"`
				LocationConstraint string   `xml:"LocationConstraint"`
			}
			if err := xml.Unmarshal(observed.body, &config); err != nil {
				t.Fatalf("decode upstream configuration: %v; body=%s", err, observed.body)
			}
			if config.LocationConstraint != tc.region {
				t.Errorf("upstream region=%q, want %q", config.LocationConstraint, tc.region)
			}
		})
	}
}

func TestCreateBucketRejectsInvalidConfigurationBeforeCreation(t *testing.T) {
	const config = `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()

	for _, tc := range []struct {
		name   string
		body   string
		header string
		values []string
		code   string
	}{
		{name: "blank lock", header: "x-amz-bucket-object-lock-enabled", values: []string{""}, code: "InvalidArgument"},
		{name: "invalid lock", header: "x-amz-bucket-object-lock-enabled", values: []string{"1"}, code: "InvalidArgument"},
		{name: "duplicate lock", header: "x-amz-bucket-object-lock-enabled", values: []string{"true", "false"}, code: "InvalidArgument"},
		{name: "combined lock", header: "x-amz-bucket-object-lock-enabled", values: []string{"true,false"}, code: "InvalidArgument"},
		{name: "unsupported protection", header: "x-amz-object-lock-mode", values: []string{"COMPLIANCE"}, code: "NotImplemented"},
		{name: "blank unsupported protection", header: "x-amz-object-lock-legal-hold", values: []string{""}, code: "NotImplemented"},
		{name: "unknown bucket protection", header: "x-amz-bucket-object-lock-mode", values: []string{"COMPLIANCE"}, code: "NotImplemented"},
		{name: "unsupported namespace", header: "x-amz-bucket-namespace", values: []string{"account-regional"}, code: "NotImplemented"},
		{name: "owner preferred", header: "x-amz-object-ownership", values: []string{"BucketOwnerPreferred"}, code: "NotImplemented"},
		{name: "object writer", header: "x-amz-object-ownership", values: []string{"ObjectWriter"}, code: "NotImplemented"},
		{name: "invalid ownership", header: "x-amz-object-ownership", values: []string{"unknown"}, code: "InvalidArgument"},
		{name: "blank ownership", header: "x-amz-object-ownership", values: []string{""}, code: "InvalidArgument"},
		{name: "duplicate ownership", header: "x-amz-object-ownership", values: []string{"BucketOwnerEnforced", "BucketOwnerEnforced"}, code: "InvalidArgument"},
		{name: "malformed XML", body: `<CreateBucketConfiguration>`, code: "MalformedXML"},
		{name: "extra document", body: config + config, code: "MalformedXML"},
		{name: "trailing junk", body: config + "junk", code: "MalformedXML"},
		{name: "nested region", body: `<CreateBucketConfiguration><LocationConstraint><Region>eu-west-1</Region></LocationConstraint></CreateBucketConfiguration>`, code: "MalformedXML"},
		{name: "unsupported tags", body: `<CreateBucketConfiguration><Tags><Tag><Key>key</Key><Value>value</Value></Tag></Tags></CreateBucketConfiguration>`, code: "MalformedXML"},
		{name: "oversized XML", body: config + strings.Repeat(" ", 16*1024), code: "MalformedXML"},
		{name: "bad MD5", body: config, header: "Content-MD5", values: []string{xmlBodyMD5("different")}, code: "BadDigest"},
		{name: "bad empty-body MD5", header: "Content-MD5", values: []string{xmlBodyMD5("different")}, code: "BadDigest"},
		{name: "invalid MD5", body: config, header: "Content-MD5", values: []string{"invalid"}, code: "InvalidDigest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/team2-bucket", strings.NewReader(tc.body))
			for _, value := range tc.values {
				req.Header.Add(tc.header, value)
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			status := http.StatusBadRequest
			if tc.code == "NotImplemented" {
				status = http.StatusNotImplemented
			}
			if rr.Code != status || !strings.Contains(rr.Body.String(), "<Code>"+tc.code+"</Code>") {
				t.Errorf("status=%d body=%s, want %d %s", rr.Code, rr.Body.String(), status, tc.code)
			}
			if calls := upstreamCalls.Swap(0); calls != 0 {
				t.Errorf("invalid configuration reached upstream %d times", calls)
			}
		})
	}
}

func TestCreateBucketPreservesUpstreamProtectionError(t *testing.T) {
	var calls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("x-amz-bucket-object-lock-enabled") != "true" {
			t.Error("Object Lock request was not forwarded")
		}
		s3xml.WriteError(w, http.StatusForbidden, "AccessDenied", "Object Lock permission required")
	})
	defer cleanup()
	req := httptest.NewRequest(http.MethodPut, "/team2-bucket", nil)
	req.Header.Set("x-amz-bucket-object-lock-enabled", "true")
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusForbidden || !strings.Contains(rr.Body.String(), "<Code>AccessDenied</Code>") || calls.Load() != 1 {
		t.Fatalf("status=%d calls=%d body=%s, want one call and AccessDenied", rr.Code, calls.Load(), rr.Body.String())
	}
}

func TestWithAuthCreateBucketPayloadDigest(t *testing.T) {
	const original = `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	defer cleanup()
	gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-c": {}})
	for _, tc := range []struct {
		name      string
		body      string
		wantCode  int
		wantCalls int32
	}{
		{name: "valid", body: original, wantCode: http.StatusOK, wantCalls: 1},
		{name: "tampered", body: strings.ReplaceAll(original, "eu-west-1", "eu-west-2"), wantCode: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := signedGatewayRequest(t, gw, http.MethodPut, "https://example.com/team2-bucket", tc.body, original, nil)
			rr := httptest.NewRecorder()
			gw.WithAuth(gw, nil).ServeHTTP(rr, req)
			if calls := upstreamCalls.Swap(0); rr.Code != tc.wantCode || calls != tc.wantCalls {
				t.Fatalf("status=%d calls=%d body=%s, want status=%d calls=%d", rr.Code, calls, rr.Body.String(), tc.wantCode, tc.wantCalls)
			}
		})
	}
}
