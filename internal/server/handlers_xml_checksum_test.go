package server

import (
	"crypto/md5" // #nosec G501 -- S3 Content-MD5 compatibility, not cryptographic authentication.
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/s3xml"
)

func xmlBodyMD5(body string) string {
	digest := md5.Sum([]byte(body)) // #nosec G401 -- The S3 wire protocol specifies MD5.
	return base64.StdEncoding.EncodeToString(digest[:])
}

func TestGatewayXMLContentMD5(t *testing.T) {
	const tagging = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Client formatting must be included in the incoming checksum. -->
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <TagSet>
    <Tag><Key>team</Key><Value>blue</Value></Tag>
  </TagSet>
</Tagging>
  `
	const versioning = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Client formatting must be included in the incoming checksum. -->
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>
  `
	routes := []struct {
		name    string
		path    string
		body    string
		content string
	}{
		{name: "object tagging", path: "/team2-bucket/key?tagging", body: tagging, content: "<Tag><Key>team</Key><Value>blue</Value></Tag>"},
		{name: "bucket tagging", path: "/team2-bucket?tagging", body: tagging, content: "<Tag><Key>team</Key><Value>blue</Value></Tag>"},
		{name: "bucket versioning", path: "/team2-bucket?versioning", body: versioning, content: "<Status>Enabled</Status>"},
	}
	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			type upstreamRequest struct {
				body      string
				checksum  string
				algorithm string
			}
			requests := make(chan upstreamRequest, 16)
			var upstreamCalls atomic.Int32
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				body, err := io.ReadAll(r.Body)
				if err != nil {
					s3xml.WriteError(w, http.StatusBadRequest, "InvalidRequest", "Failed to read body")
					return
				}
				checksum := r.Header.Get("x-amz-checksum-crc32")
				wantChecksum := binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(body))
				algorithm := r.Header.Get("x-amz-sdk-checksum-algorithm")
				if algorithm == "SHA256" {
					checksum = r.Header.Get("x-amz-checksum-sha256")
					digest := sha256.Sum256(body)
					wantChecksum = digest[:]
				}
				requests <- upstreamRequest{body: string(body), checksum: checksum, algorithm: algorithm}
				// Behave like an S3 service: every supplied checksum must cover
				// the bytes received after the SDK serializes the XML.
				if digest := r.Header.Get("Content-MD5"); digest != "" && digest != xmlBodyMD5(string(body)) {
					s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "Content-MD5 does not match the upstream body")
					return
				}
				if checksum != base64.StdEncoding.EncodeToString(wantChecksum) {
					s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "Checksum does not match the upstream body")
					return
				}
				w.WriteHeader(http.StatusOK)
			})
			defer cleanup()

			malformedXML := route.body + "<"
			oversizedXML := route.body + strings.Repeat(" ", 256*1024)
			cases := []struct {
				name      string
				body      string
				digests   []string
				algorithm string
				code      string
			}{
				{name: "valid digest", body: route.body, digests: []string{xmlBodyMD5(route.body)}},
				{name: "valid MD5 and SHA256 digests", body: route.body, digests: []string{xmlBodyMD5(route.body)}, algorithm: "SHA256"},
				{name: "absent digest", body: route.body},
				{name: "mismatched digest", body: route.body, digests: []string{xmlBodyMD5("different body")}, code: "BadDigest"},
				{name: "digest omits trailing whitespace", body: route.body, digests: []string{xmlBodyMD5(strings.TrimSpace(route.body))}, code: "BadDigest"},
				{name: "malformed base64", body: route.body, digests: []string{"invalid!"}, code: "InvalidDigest"},
				{name: "wrong digest length", body: route.body, digests: []string{base64.StdEncoding.EncodeToString([]byte("short"))}, code: "InvalidDigest"},
				{name: "blank digest", body: route.body, digests: []string{""}, code: "InvalidDigest"},
				{name: "duplicate digest", body: route.body, digests: []string{xmlBodyMD5(route.body), xmlBodyMD5(route.body)}, code: "InvalidDigest"},
				{name: "malformed XML", body: malformedXML, digests: []string{xmlBodyMD5(malformedXML)}, code: "MalformedXML"},
				{name: "oversized XML", body: oversizedXML, digests: []string{xmlBodyMD5(oversizedXML)}, code: "MalformedXML"},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodPut, route.path, strings.NewReader(tc.body))
					for _, digest := range tc.digests {
						req.Header.Add("Content-MD5", digest)
					}
					if tc.algorithm != "" {
						req.Header.Set("x-amz-checksum-algorithm", tc.algorithm)
						req.Header.Set("x-amz-checksum-sha256", deleteObjectsTestChecksum("SHA256", tc.body))
					}
					req = req.WithContext(authz.WithRules(req.Context(), fullTeam2Rule()))
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, req)
					calls := upstreamCalls.Swap(0)
					var observed upstreamRequest
					for range calls {
						select {
						case observed = <-requests:
						default:
							t.Fatal("upstream request was not recorded")
						}
					}
					if tc.code != "" {
						if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>"+tc.code+"</Code>") {
							t.Errorf("status=%d body=%s, want 400 %s", rr.Code, rr.Body.String(), tc.code)
						}
						if calls != 0 {
							t.Errorf("invalid request reached upstream %d times", calls)
						}
						return
					}
					if rr.Code != http.StatusOK || calls != 1 {
						t.Fatalf("status=%d calls=%d body=%s, want 200 and one upstream call", rr.Code, calls, rr.Body.String())
					}
					if observed.body == tc.body || !strings.Contains(observed.body, route.content) {
						t.Errorf("expected rewritten XML preserving request content, got %q", observed.body)
					}
					if observed.checksum == "" {
						t.Error("upstream request has no checksum for rewritten XML")
					}
				})
			}
		})
	}
}
