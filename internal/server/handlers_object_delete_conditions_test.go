package server

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDeleteRejectsUnsupportedConditionHeaders(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `<DeleteResult/>`)
	})
	t.Cleanup(cleanup)

	for _, operation := range []struct {
		name   string
		method string
		target string
		body   string
	}{
		{name: "single", method: http.MethodDelete, target: "/team2-bucket/key"},
		{name: "bulk", method: http.MethodPost, target: "/team2-bucket?delete", body: `<Delete><Object><Key>key</Key></Object></Delete>`},
	} {
		t.Run(operation.name, func(t *testing.T) {
			for _, header := range []string{"x-amz-if-match-size", "x-amz-if-match-last-modified-time"} {
				t.Run(header, func(t *testing.T) {
					for _, condition := range []struct {
						name   string
						header string
						values []string
					}{
						{name: "value", header: http.CanonicalHeaderKey(header), values: []string{"1"}},
						{name: "empty", header: header, values: []string{""}},
						{name: "blank", header: strings.ToUpper(header), values: []string{" "}},
						{name: "duplicates", header: header, values: []string{"1", "2"}},
						{name: "presence without values", header: header},
					} {
						t.Run(condition.name, func(t *testing.T) {
							req := httptest.NewRequest(operation.method, operation.target, strings.NewReader(operation.body))
							// Direct assignment also exercises header maps that middleware
							// populated without canonicalizing the field name.
							req.Header[condition.header] = condition.values
							recorder := httptest.NewRecorder()
							gw.ServeHTTP(recorder, reqWithRules(req, fullTeam2Rule()))
							if recorder.Code != http.StatusNotImplemented || !strings.Contains(recorder.Body.String(), "<Code>NotImplemented</Code>") {
								t.Fatalf("status=%d body=%s, want 501 NotImplemented", recorder.Code, recorder.Body.String())
							}
							if calls := upstreamCalls.Load(); calls != 0 {
								t.Fatalf("unsupported condition reached upstream %d times", calls)
							}
						})
					}
				})
			}
		})
	}
}

func TestDeleteObjectsRejectsUnsupportedXMLConditions(t *testing.T) {
	var upstreamCalls atomic.Int32
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, `<DeleteResult/>`)
	})
	t.Cleanup(cleanup)

	for _, field := range []string{"Size", "LastModifiedTime"} {
		t.Run(field, func(t *testing.T) {
			for _, shape := range []struct {
				name string
				body string
			}{
				{name: "value", body: `<Delete><Object><Key>key</Key><%[1]s>1</%[1]s></Object></Delete>`},
				{name: "empty", body: `<Delete><Object><Key>key</Key><%[1]s/></Object></Delete>`},
				{name: "nested value", body: `<Delete><Object><Key>key</Key><%[1]s><Value>1</Value></%[1]s></Object></Delete>`},
				{name: "unknown wrapper", body: `<Delete><Object><Key>key</Key><Condition><%[1]s/></Condition></Object></Delete>`},
				{name: "inside key", body: `<Delete><Object><Key>key<%[1]s/></Key></Object></Delete>`},
				{name: "inside ETag", body: `<Delete><Object><Key>key</Key><ETag>etag<%[1]s/></ETag></Object></Delete>`},
				{name: "inside VersionId", body: `<Delete><Object><Key>key</Key><VersionId>v1<%[1]s/></VersionId></Object></Delete>`},
				{name: "inside Quiet", body: `<Delete><Object><Key>key</Key></Object><Quiet>false<%[1]s/></Quiet></Delete>`},
				{name: "root", body: `<Delete><Object><Key>key</Key></Object><%[1]s/></Delete>`},
				{name: "namespace", body: `<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Object><Key>key</Key><%[1]s/></Object></Delete>`},
				{name: "later object", body: `<Delete><Object><Key>first</Key></Object><Object><Key>second</Key><%[1]s/></Object></Delete>`},
			} {
				t.Run(shape.name, func(t *testing.T) {
					body := fmt.Sprintf(shape.body, field)
					req := httptest.NewRequest(http.MethodPost, "/team2-bucket?delete", strings.NewReader(body))
					req.Header.Set("Content-MD5", xmlBodyMD5(body))
					req.Header.Set("x-amz-checksum-crc32", deleteObjectsTestChecksum("CRC32", body))
					recorder := httptest.NewRecorder()
					gw.ServeHTTP(recorder, reqWithRules(req, fullTeam2Rule()))
					if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "<Code>MalformedXML</Code>") {
						t.Fatalf("status=%d body=%s, want 400 MalformedXML", recorder.Code, recorder.Body.String())
					}
					if calls := upstreamCalls.Load(); calls != 0 {
						t.Fatalf("unsupported XML condition reached upstream %d times", calls)
					}
				})
			}
		})
	}
}

func TestDeletePreservesSupportedConditions(t *testing.T) {
	for _, operation := range []struct {
		name   string
		method string
		target string
		body   string
		status int
	}{
		{name: "single", method: http.MethodDelete, target: "/team2-bucket/key?versionId=v1", status: http.StatusNoContent},
		{
			name: "bulk", method: http.MethodPost, target: "/team2-bucket?delete", status: http.StatusOK,
			body: `<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Object><Key> key </Key><VersionId>v1</VersionId><ETag>"etag"</ETag></Object><Quiet>true</Quiet></Delete><!-- checksum covers this too -->`,
		},
	} {
		t.Run(operation.name, func(t *testing.T) {
			var upstreamCalls atomic.Int32
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				upstreamCalls.Add(1)
				if r.Method != operation.method {
					t.Errorf("upstream method=%s, want %s", r.Method, operation.method)
				}
				if operation.method == http.MethodDelete {
					if r.Header.Get("If-Match") != `"etag"` || r.URL.Query().Get("versionId") != "v1" {
						t.Errorf("single deletion lost If-Match or versionId: %s %v", r.URL, r.Header)
					}
					w.WriteHeader(http.StatusNoContent)
					return
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				var deletion struct {
					Objects []struct {
						Key       string `xml:"Key"`
						VersionID string `xml:"VersionId"`
						ETag      string `xml:"ETag"`
					} `xml:"Object"`
					Quiet bool `xml:"Quiet"`
				}
				if err := xml.Unmarshal(body, &deletion); err != nil {
					t.Errorf("decode upstream request: %v", err)
				} else if len(deletion.Objects) != 1 || deletion.Objects[0].Key != " key " || deletion.Objects[0].VersionID != "v1" || deletion.Objects[0].ETag != `"etag"` || !deletion.Quiet {
					t.Errorf("bulk deletion conditions changed: %+v", deletion)
				}
				if got, want := r.Header.Get("x-amz-checksum-crc32"), deleteObjectsTestChecksum("CRC32", string(body)); got != want {
					t.Errorf("upstream checksum=%q, want %q", got, want)
				}
				_, _ = io.WriteString(w, `<DeleteResult/>`)
			})
			t.Cleanup(cleanup)
			req := httptest.NewRequest(operation.method, operation.target, strings.NewReader(operation.body))
			if operation.method == http.MethodDelete {
				req.Header.Set("If-Match", `"etag"`)
			} else {
				req.Header.Set("Content-MD5", xmlBodyMD5(operation.body))
				req.Header.Set("x-amz-checksum-crc32", deleteObjectsTestChecksum("CRC32", operation.body))
			}
			recorder := httptest.NewRecorder()
			gw.ServeHTTP(recorder, reqWithRules(req, fullTeam2Rule()))
			if recorder.Code != operation.status || upstreamCalls.Load() != 1 {
				t.Fatalf("status=%d calls=%d body=%s, want %d and one deletion", recorder.Code, upstreamCalls.Load(), recorder.Body.String(), operation.status)
			}
		})
	}
}
