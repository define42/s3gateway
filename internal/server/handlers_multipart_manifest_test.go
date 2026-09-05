package server

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCompleteMultipartRejectsMalformedManifestParts(t *testing.T) {
	tests := []struct {
		name string
		part string
	}{
		{name: "missing etag", part: `<Part><PartNumber>2</PartNumber></Part>`},
		{name: "empty etag", part: `<Part><PartNumber>2</PartNumber><ETag></ETag></Part>`},
		{name: "whitespace etag", part: "<Part><PartNumber>2</PartNumber><ETag> \t\n </ETag></Part>"},
		{name: "missing part number", part: `<Part><ETag>"second"</ETag></Part>`},
		{name: "zero part number", part: `<Part><PartNumber>0</PartNumber><ETag>"second"</ETag></Part>`},
		{name: "negative part number", part: `<Part><PartNumber>-1</PartNumber><ETag>"second"</ETag></Part>`},
	}
	positions := []struct {
		name  string
		first bool
	}{
		{name: "last"},
		{name: "first", first: true},
	}
	for _, tc := range tests {
		for _, position := range positions {
			t.Run(tc.name+"/"+position.name, func(t *testing.T) {
				var upstreamCalls atomic.Int32
				gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
					upstreamCalls.Add(1)
					w.Header().Set("Content-Type", "application/xml")
					_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>`)
				})
				t.Cleanup(cleanup)
				notifier := &recordingUploadNotifier{}
				gw.uploadNotifier = notifier

				const validPart = `<Part><PartNumber>1</PartNumber><ETag>"first"</ETag></Part>`
				parts := validPart + tc.part
				if position.first {
					parts = tc.part + validPart
				}
				body := "<CompleteMultipartUpload>" + parts + "</CompleteMultipartUpload>"
				req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1", strings.NewReader(body))
				rr := httptest.NewRecorder()
				gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))

				if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>MalformedXML</Code>") {
					t.Errorf("expected MalformedXML; status = %d, body = %s", rr.Code, rr.Body.String())
				}
				if got := upstreamCalls.Load(); got != 0 {
					t.Errorf("upstream request count = %d, want 0", got)
				}
				if got := len(notifier.events); got != 0 {
					t.Errorf("notification count = %d, want 0", got)
				}
			})
		}
	}
}

func TestCompleteMultipartPreservesValidManifestParts(t *testing.T) {
	requests := make(chan []byte, 1)
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream completion manifest: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- body
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>`)
	})
	t.Cleanup(cleanup)
	notifier := &recordingUploadNotifier{}
	gw.uploadNotifier = notifier

	const body = `<CompleteMultipartUpload>
		<Part><PartNumber>1</PartNumber><ETag>"first"</ETag><ChecksumCRC32>AAAAAA==</ChecksumCRC32></Part>
		<Part><PartNumber>2</PartNumber><ETag>second</ETag><ChecksumCRC32>AQAAAA==</ChecksumCRC32></Part>
	</CompleteMultipartUpload>`
	req := httptest.NewRequest(http.MethodPost, "/team2-bucket/object?uploadId=upload-1", strings.NewReader(body))
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusOK {
		t.Fatalf("completion status = %d, want 200; body = %s", rr.Code, rr.Body.String())
	}

	type part struct {
		PartNumber    int    `xml:"PartNumber"`
		ETag          string `xml:"ETag"`
		ChecksumCRC32 string `xml:"ChecksumCRC32"`
	}
	var manifest struct {
		Parts []part `xml:"Part"`
	}
	select {
	case upstreamBody := <-requests:
		if err := xml.Unmarshal(upstreamBody, &manifest); err != nil {
			t.Fatalf("decode upstream completion manifest: %v", err)
		}
	default:
		t.Fatal("completion manifest did not reach upstream")
	}
	want := []part{
		{PartNumber: 1, ETag: `"first"`, ChecksumCRC32: "AAAAAA=="},
		{PartNumber: 2, ETag: `"second"`, ChecksumCRC32: "AQAAAA=="},
	}
	if !slices.Equal(manifest.Parts, want) {
		t.Errorf("upstream manifest parts = %+v, want %+v", manifest.Parts, want)
	}
	if got := len(notifier.events); got != 1 {
		t.Errorf("notification count = %d, want 1", got)
	}
}
