package server

import (
	"encoding/xml"
	"errors"
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
