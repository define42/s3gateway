package server

import (
	"encoding/base64"
	"encoding/binary"
	"hash/crc32"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var bucketConfigurationRoutes = []struct {
	name, target, body, content string
	limit                       int
}{
	{name: "lifecycle", target: "/team2-bucket?lifecycle", limit: int(maxLifecycleBodyBytes), content: "<Days>30</Days>", body: `<?xml version="1.0" encoding="UTF-8"?>
<!-- The checksum covers the client's formatting. -->
<LifecycleConfiguration>
  <Rule><ID>archive</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter>
    <Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition>
  </Rule>
</LifecycleConfiguration>
  `},
}

func TestBucketConfigurationContentMD5(t *testing.T) {
	for _, route := range bucketConfigurationRoutes {
		t.Run(route.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, body, code string
				digests          []string
			}{
				{name: "valid digest", body: route.body, digests: []string{xmlBodyMD5(route.body)}},
				{name: "absent digest", body: route.body},
				{name: "mismatched digest", body: route.body, digests: []string{xmlBodyMD5("different configuration")}, code: "BadDigest"},
				{name: "digest omits trailing bytes", body: route.body, digests: []string{xmlBodyMD5(strings.TrimSpace(route.body))}, code: "BadDigest"},
				{name: "malformed digest", body: route.body, digests: []string{"not-base64"}, code: "InvalidDigest"},
				{name: "short digest", body: route.body, digests: []string{base64.StdEncoding.EncodeToString([]byte("short"))}, code: "InvalidDigest"},
				{name: "blank digest", body: route.body, digests: []string{""}, code: "InvalidDigest"},
				{name: "repeated digest", body: route.body, digests: []string{xmlBodyMD5(route.body), xmlBodyMD5(route.body)}, code: "InvalidDigest"},
				{name: "malformed XML", body: route.body + "<", digests: []string{xmlBodyMD5(route.body + "<")}, code: "MalformedXML"},
				{name: "oversized XML", body: route.body + strings.Repeat(" ", route.limit), code: "MalformedXML"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					requests := make(chan string, 1)
					gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Errorf("read upstream configuration: %v", err)
							w.WriteHeader(http.StatusBadRequest)
							return
						}
						requests <- string(body)
						// The SDK must calculate a new checksum after rebuilding the XML.
						wantCRC32 := base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(body)))
						if got := r.Header.Get("x-amz-checksum-crc32"); got != wantCRC32 {
							t.Errorf("upstream CRC32=%q, want %q", got, wantCRC32)
						}
						if digest := r.Header.Get("Content-MD5"); digest != "" && digest != xmlBodyMD5(string(body)) {
							t.Error("original MD5 forwarded over the rebuilt XML")
						}
						w.WriteHeader(http.StatusOK)
					})
					t.Cleanup(cleanup)
					req := httptest.NewRequest(http.MethodPut, route.target, strings.NewReader(tc.body))
					for _, digest := range tc.digests {
						req.Header.Add("Content-MD5", digest)
					}
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
					if tc.code != "" {
						if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>"+tc.code+"</Code>") {
							t.Fatalf("invalid request: status=%d body=%s, want %s", rr.Code, rr.Body.String(), tc.code)
						}
						select {
						case <-requests:
							t.Error("invalid configuration reached upstream")
						default:
						}
						return
					}
					if rr.Code != http.StatusOK {
						t.Fatalf("valid configuration: status=%d body=%s", rr.Code, rr.Body.String())
					}
					select {
					case sent := <-requests:
						if sent == tc.body || !strings.Contains(sent, route.content) {
							t.Fatalf("unexpected rebuilt configuration: %s", sent)
						}
					default:
						t.Fatal("configuration did not reach upstream")
					}
				})
			}
		})
	}
}

func TestBucketConfigurationExpectedOwner(t *testing.T) {
	for _, route := range bucketConfigurationRoutes {
		t.Run(route.name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
				t.Run(method, func(t *testing.T) {
					for _, owner := range []string{"", " 123456789012 ", "wrong-owner"} {
						t.Run("owner="+owner, func(t *testing.T) {
							requests := make(chan http.Header, 1)
							gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
								_, _ = io.Copy(io.Discard, r.Body)
								requests <- r.Header.Clone()
								w.Header().Set("Content-Type", "application/xml")
								if r.Header.Get("x-amz-expected-bucket-owner") == "wrong-owner" {
									w.WriteHeader(http.StatusForbidden)
									_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>Wrong owner</Message></Error>`)
									return
								}
								if method == http.MethodGet {
									_, _ = io.WriteString(w, route.body)
								} else {
									w.WriteHeader(http.StatusOK)
								}
							})
							t.Cleanup(cleanup)
							body := ""
							if method == http.MethodPut {
								body = route.body
							}
							req := httptest.NewRequest(method, route.target, strings.NewReader(body))
							if owner != "" {
								req.Header.Set("x-amz-expected-bucket-owner", owner)
							}
							rr := httptest.NewRecorder()
							gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
							wantStatus := http.StatusOK
							if owner == "wrong-owner" {
								wantStatus = http.StatusForbidden
							} else if method == http.MethodDelete {
								wantStatus = http.StatusNoContent
							}
							if rr.Code != wantStatus {
								t.Fatalf("status=%d body=%s, want %d", rr.Code, rr.Body.String(), wantStatus)
							}
							select {
							case headers := <-requests:
								if got := headers.Get("x-amz-expected-bucket-owner"); got != strings.TrimSpace(owner) {
									t.Errorf("upstream owner=%q, want %q", got, strings.TrimSpace(owner))
								}
								if owner == "" && len(headers.Values("x-amz-expected-bucket-owner")) != 0 {
									t.Error("absent owner was added upstream")
								}
							default:
								t.Fatal("request did not reach upstream")
							}
							if owner == "wrong-owner" && !strings.Contains(rr.Body.String(), "<Code>AccessDenied</Code>") {
								t.Fatalf("owner rejection lost: %s", rr.Body.String())
							}
						})
					}
				})
			}
		})
	}
}
