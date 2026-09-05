package server

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLifecyclePutPreservesLiteralPrefixes(t *testing.T) {
	for _, shape := range []struct {
		name   string
		before string
		after  string
		inAnd  bool
	}{
		{name: "filter prefix", before: "<Filter><Prefix>", after: "</Prefix></Filter>"},
		{name: "legacy prefix", before: "<Prefix>", after: "</Prefix>"},
		{name: "And prefix", before: "<Filter><And><Prefix>", after: "</Prefix><Tag><Key>scope</Key><Value>archive</Value></Tag></And></Filter>", inAnd: true},
	} {
		t.Run(shape.name, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				prefix string
			}{
				{name: "leading space", prefix: " archive/"},
				{name: "trailing space", prefix: "archive/ "},
				{name: "space only", prefix: " "},
				{name: "whitespace only", prefix: "\t\r\n"},
				{name: "intentional empty prefix", prefix: ""},
				{name: "unicode spaces and XML characters", prefix: "\u00a0a&b<c>\u00a0"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					gw, requests := newLifecycleWireGateway(t, "")
					filter := shape.before + lifecycleXMLText(t, tc.prefix) + shape.after
					body := lifecycleWireDocument(filter)
					putLifecycleWireDocument(t, gw, body)
					rule := readLifecycleWireRule(t, requests)
					if rule.Prefix != nil || rule.Filter == nil {
						t.Fatalf("expected a normalized Filter element, got %+v", rule)
					}
					prefix := rule.Filter.Prefix
					if shape.inAnd {
						if rule.Filter.And == nil {
							t.Fatal("missing forwarded And filter")
						}
						prefix = rule.Filter.And.Prefix
					}
					if prefix == nil {
						t.Fatalf("forwarded prefix is absent, want exact value %q", tc.prefix)
					}
					if *prefix != tc.prefix {
						t.Fatalf("forwarded prefix = %q, want exact value %q", *prefix, tc.prefix)
					}
				})
			}
		})
	}
}

func TestLifecyclePutPreservesLiteralTags(t *testing.T) {
	for _, shape := range []struct {
		name   string
		before string
		after  string
		inAnd  bool
	}{
		{name: "standalone tag", before: "<Filter>", after: "</Filter>"},
		{name: "And tag", before: "<Filter><And><Prefix>archive/</Prefix>", after: "</And></Filter>", inAnd: true},
	} {
		t.Run(shape.name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				key   string
				value string
			}{
				{name: "surrounding spaces", key: " owner ", value: " archive "},
				{name: "space only key", key: " ", value: "archive"},
				{name: "space only value", key: "owner", value: " "},
				{name: "empty value", key: "owner", value: ""},
				{name: "unicode spaces and XML characters", key: "\u00a0a&b\u00a0", value: "\u00a0<c>\u00a0"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					gw, requests := newLifecycleWireGateway(t, "")
					tag := "<Tag><Key>" + lifecycleXMLText(t, tc.key) + "</Key><Value>" + lifecycleXMLText(t, tc.value) + "</Value></Tag>"
					putLifecycleWireDocument(t, gw, lifecycleWireDocument(shape.before+tag+shape.after))
					rule := readLifecycleWireRule(t, requests)
					if rule.Filter == nil {
						t.Fatal("missing forwarded filter")
					}
					forwarded := rule.Filter.Tag
					if shape.inAnd {
						if rule.Filter.And == nil || len(rule.Filter.And.Tags) != 1 {
							t.Fatal("expected one forwarded And tag")
						}
						forwarded = &rule.Filter.And.Tags[0]
					}
					if forwarded == nil || forwarded.Key != tc.key || forwarded.Value != tc.value {
						t.Fatalf("forwarded tag = %+v, want key=%q value=%q", forwarded, tc.key, tc.value)
					}
				})
			}
		})
	}
}

func TestLifecycleLegacyPrefixGetPutRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{name: "surrounding spaces", prefix: " archive/ "},
		{name: "space only", prefix: " "},
		{name: "intentional empty prefix", prefix: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := lifecycleWireDocument("<Prefix>" + lifecycleXMLText(t, tc.prefix) + "</Prefix>")
			gw, requests := newLifecycleWireGateway(t, original)
			req := httptest.NewRequest(http.MethodGet, "/team2-bucket?lifecycle", nil).WithContext(t.Context())
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
			if rr.Code != http.StatusOK {
				t.Fatalf("GET lifecycle status=%d body=%s", rr.Code, rr.Body.String())
			}
			returned := decodeLifecycleWireRule(t, rr.Body.Bytes())
			if returned.Filter == nil || returned.Filter.Prefix == nil || *returned.Filter.Prefix != tc.prefix {
				t.Errorf("GET did not preserve legacy prefix %q: %+v", tc.prefix, returned.Filter)
			}
			putLifecycleWireDocument(t, gw, rr.Body.String())
			forwarded := readLifecycleWireRule(t, requests)
			if forwarded.Filter == nil || forwarded.Filter.Prefix == nil || *forwarded.Filter.Prefix != tc.prefix {
				t.Fatalf("GET then PUT did not preserve legacy prefix %q: %+v", tc.prefix, forwarded.Filter)
			}
		})
	}
}

type lifecycleWireTag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type lifecycleWireRule struct {
	Status string  `xml:"Status"`
	Prefix *string `xml:"Prefix"`
	Filter *struct {
		Prefix *string           `xml:"Prefix"`
		Tag    *lifecycleWireTag `xml:"Tag"`
		And    *struct {
			Prefix *string            `xml:"Prefix"`
			Tags   []lifecycleWireTag `xml:"Tag"`
		} `xml:"And"`
	} `xml:"Filter"`
	Expiration struct {
		Days int `xml:"Days"`
	} `xml:"Expiration"`
}

func newLifecycleWireGateway(t *testing.T, getResponse string) (*Server, <-chan []byte) {
	t.Helper()
	requests := make(chan []byte, 1)
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/team2-bucket" || !r.URL.Query().Has("lifecycle") {
			t.Errorf("unexpected upstream route: %s %s", r.Method, r.URL)
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, getResponse)
			return
		}
		if r.Method != http.MethodPut {
			t.Errorf("unexpected upstream method: %s", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream lifecycle body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case requests <- body:
		default:
			t.Error("unexpected repeated lifecycle write")
		}
		w.WriteHeader(http.StatusOK)
	})
	t.Cleanup(cleanup)
	return gw, requests
}

func putLifecycleWireDocument(t *testing.T, gw *Server, body string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/team2-bucket?lifecycle", strings.NewReader(body)).WithContext(t.Context())
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusOK {
		t.Fatalf("PUT lifecycle status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func readLifecycleWireRule(t *testing.T, requests <-chan []byte) lifecycleWireRule {
	t.Helper()
	select {
	case body := <-requests:
		return decodeLifecycleWireRule(t, body)
	default:
		t.Fatal("lifecycle configuration was not forwarded upstream")
		return lifecycleWireRule{}
	}
}

func decodeLifecycleWireRule(t *testing.T, body []byte) lifecycleWireRule {
	t.Helper()
	var document struct {
		XMLName xml.Name            `xml:"LifecycleConfiguration"`
		Rules   []lifecycleWireRule `xml:"Rule"`
	}
	if err := xml.Unmarshal(body, &document); err != nil {
		t.Fatalf("decode lifecycle XML: %v; body=%s", err, body)
	}
	if len(document.Rules) != 1 {
		t.Fatalf("expected one lifecycle rule, got %d", len(document.Rules))
	}
	rule := document.Rules[0]
	if rule.Status != "Enabled" || rule.Expiration.Days != 1 {
		t.Fatalf("expiration action changed: %+v", rule)
	}
	return rule
}

func lifecycleWireDocument(filter string) string {
	return `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><Status>Enabled</Status>` + filter + `<Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`
}

func lifecycleXMLText(t *testing.T, value string) string {
	t.Helper()
	var escaped strings.Builder
	if err := xml.EscapeText(&escaped, []byte(value)); err != nil {
		t.Fatalf("escape lifecycle XML text: %v", err)
	}
	return escaped.String()
}
