package server

import (
	"encoding/xml"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/define42/s3gateway/internal/s3xml"
)

func deleteObjectsDocument(count int, key string) string {
	var body strings.Builder
	body.WriteString("<Delete>")
	for range count {
		body.WriteString("<Object><Key>")
		body.WriteString(key)
		body.WriteString("</Key></Object>")
	}
	body.WriteString("</Delete>")
	return body.String()
}

func TestDecodeDeleteObjectsRequestLimits(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantErr     error
		wantObjects int
	}{
		{
			name:        "accepts one thousand objects",
			body:        deleteObjectsDocument(maxDeleteObjects, "key"),
			wantObjects: maxDeleteObjects,
		},
		{
			name:        "rejects object one thousand and one before append",
			body:        deleteObjectsDocument(maxDeleteObjects+1, "key"),
			wantErr:     s3xml.ErrXMLElementLimit,
			wantObjects: maxDeleteObjects,
		},
		{
			name:    "rejects oversized key",
			body:    deleteObjectsDocument(1, strings.Repeat("k", maxDeleteObjectKeyBytes+1)),
			wantErr: s3xml.ErrXMLFieldTooLong,
		},
		{
			name:    "rejects oversized body",
			body:    "<Delete>" + strings.Repeat(" ", int(maxDeleteObjectsBodyBytes)) + "</Delete>",
			wantErr: s3xml.ErrXMLBodyTooLarge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeDeleteObjectsRequest(strings.NewReader(tc.body))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("decodeDeleteObjectsRequest() error = %v, want %v", err, tc.wantErr)
			}
			if len(got.Objects) != tc.wantObjects {
				t.Fatalf("decodeDeleteObjectsRequest() appended %d objects, want %d", len(got.Objects), tc.wantObjects)
			}
		})
	}
}

func TestHandleDeleteObjectsPreservesKeys(t *testing.T) {
	wantKeys := []string{
		"report",
		" report",
		"report ",
		" report ",
		" ",
		"\t\r\n",
		"\u00a0report\u2003",
	}
	upstreamKeys := make(chan []string, 1)
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Objects []struct {
				Key string `xml:"Key"`
			} `xml:"Object"`
		}
		if err := xml.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode upstream delete request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		keys := make([]string, 0, len(request.Objects))
		for _, object := range request.Objects {
			keys = append(keys, object.Key)
		}
		upstreamKeys <- keys
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`))
	})
	defer cleanup()

	var body strings.Builder
	body.WriteString("<Delete>")
	for _, key := range wantKeys {
		body.WriteString("<Object><Key>")
		if err := xml.EscapeText(&body, []byte(key)); err != nil {
			t.Fatalf("escape object key: %v", err)
		}
		body.WriteString("</Key></Object>")
	}
	body.WriteString("</Delete>")

	req := httptest.NewRequest(http.MethodPost, "/team2-dst?delete", strings.NewReader(body.String()))
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
	select {
	case gotKeys := <-upstreamKeys:
		if !slices.Equal(gotKeys, wantKeys) {
			t.Fatalf("upstream keys = %q, want %q", gotKeys, wantKeys)
		}
	default:
		t.Fatal("delete request did not reach upstream")
	}
}

func TestExtractAmzMetaPreservesDistinctNames(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers http.Header
		want    map[string]string
	}{
		{name: "no headers"},
		{name: "ignore unrelated and empty headers", headers: http.Header{
			"Content-Type": {"text/plain"}, "X-Amz-Meta-": {"ignored"}, "X-Amz-Meta-Empty": nil,
		}},
		{name: "case insensitive names and unchanged values", headers: http.Header{
			"X-AmZ-MeTa-Case-ID": {" Case-123 "},
		}, want: map[string]string{"case-id": " Case-123 "}},
		{name: "repeated values preserve order and contents", headers: http.Header{
			"X-Amz-Meta-Tags": {"alpha", "beta,gamma", "", " delta "},
		}, want: map[string]string{"tags": "alpha,beta,gamma,, delta "}},
		{name: "repeated prefix is part of the name", headers: http.Header{
			"X-Amz-Meta-Id":                       {"plain"},
			"X-Amz-Meta-X-Amz-Meta-Id":            {"prefixed"},
			"X-Amz-Meta-X-Amz-Meta-X-Amz-Meta-Id": {"twice-prefixed"},
			"X-Amz-Meta-X-Amz-Meta-":              {"prefix-only"},
		}, want: map[string]string{
			"id": "plain", "x-amz-meta-id": "prefixed",
			"x-amz-meta-x-amz-meta-id": "twice-prefixed", "x-amz-meta-": "prefix-only",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := extractAmzMeta(tc.headers)
			if !maps.Equal(got, tc.want) || (got == nil) != (tc.want == nil) {
				t.Fatalf("metadata = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUploadPreservesMetadataNamesAndValues(t *testing.T) {
	for _, tc := range []struct {
		name, method, target, response string
		copy                           bool
	}{
		{name: "put", method: http.MethodPut, target: "/team2-dst/object"},
		{name: "copy", method: http.MethodPut, target: "/team2-dst/object", copy: true,
			response: `<CopyObjectResult><ETag>"copied"</ETag></CopyObjectResult>`},
		{name: "multipart initiation", method: http.MethodPost, target: "/team2-dst/object?uploads",
			response: `<InitiateMultipartUploadResult><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := make(chan http.Header, 1)
			gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				requests <- r.Header.Clone()
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, tc.response)
			})
			t.Cleanup(cleanup)
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(""))
			req.Header.Set("x-amz-meta-id", "plain")
			req.Header.Add("X-AmZ-MeTa-ID", "second")
			req.Header.Set("x-amz-meta-x-amz-meta-id", "prefixed")
			req.Header.Add("x-amz-meta-x-amz-meta-id", "another")
			if tc.copy {
				req.Header.Set("x-amz-copy-source", "/team2-src/source")
				req.Header.Set("x-amz-metadata-directive", "REPLACE")
			}
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("upload failed: %d %s", rr.Code, rr.Body.String())
			}
			select {
			case headers := <-requests:
				if headers.Get("x-amz-meta-id") != "plain,second" || headers.Get("x-amz-meta-x-amz-meta-id") != "prefixed,another" {
					t.Fatalf("upstream metadata lost: %v", headers)
				}
			default:
				t.Fatal("upload did not reach upstream")
			}
		})
	}
}

func TestPrefixedMetadataDoesNotSatisfyRequiredName(t *testing.T) {
	meta := extractAmzMeta(http.Header{"X-Amz-Meta-X-Amz-Meta-Id": {"prefixed"}})
	if got := missingRequiredUploadMetadata(meta, []string{"id"}); !slices.Equal(got, []string{"x-amz-meta-id"}) {
		t.Fatalf("missing required metadata = %v, want [x-amz-meta-id]", got)
	}
}
