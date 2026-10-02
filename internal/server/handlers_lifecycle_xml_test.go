package server

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLifecycleRejectsMalformedStructureBeforeUpstream(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule string
	}{
		{name: "unknown rule field", rule: `<Unknown/>`},
		{name: "misspelled filter", rule: `<filter><Prefix>archive/</Prefix></filter>`},
		{name: "unknown filter predicate", rule: `<Filter><prefix>archive/</prefix></Filter>`},
		{name: "nested prefix", rule: `<Filter><Prefix><Value>archive/</Value></Prefix></Filter>`},
		{name: "nested legacy prefix", rule: `<Prefix><Value>archive/</Value></Prefix>`},
		{name: "nested And prefix", rule: `<Filter><And><Prefix><Value>archive/</Value></Prefix><Tag><Key>scope</Key><Value>archive</Value></Tag></And></Filter>`},
		{name: "unknown And predicate", rule: `<Filter><And><Prefix>archive/</Prefix><Unknown/></And></Filter>`},
		{name: "duplicate filter", rule: `<Filter><Prefix>archive/</Prefix></Filter><Filter/>`},
		{name: "duplicate prefix", rule: `<Filter><Prefix>archive/</Prefix><Prefix/></Filter>`},
		{name: "duplicate legacy prefix", rule: `<Prefix>archive/</Prefix><Prefix/>`},
		{name: "duplicate ID", rule: `<ID>first</ID><ID>second</ID>`},
		{name: "duplicate status", rule: `<Status>Disabled</Status>`},
		{name: "duplicate expiration", rule: `<Expiration><Days>365</Days></Expiration>`},
		{name: "duplicate Tag predicate", rule: `<Filter><Tag><Key>first</Key><Value>one</Value></Tag><Tag><Key>second</Key><Value>two</Value></Tag></Filter>`},
		{name: "duplicate And predicate", rule: `<Filter><And><Prefix>archive/</Prefix></And><And><Prefix/></And></Filter>`},
		{name: "duplicate object size", rule: `<Filter><ObjectSizeLessThan>1</ObjectSizeLessThan><ObjectSizeLessThan>100</ObjectSizeLessThan></Filter>`},
		{name: "duplicate And prefix", rule: `<Filter><And><Prefix>archive/</Prefix><Prefix/></And></Filter>`},
		{name: "duplicate And object size", rule: `<Filter><And><ObjectSizeGreaterThan>100</ObjectSizeGreaterThan><ObjectSizeGreaterThan>0</ObjectSizeGreaterThan></And></Filter>`},
		{name: "unknown tag field", rule: `<Filter><Tag><Key>scope</Key><Value>archive</Value><Unknown/></Tag></Filter>`},
		{name: "missing tag value", rule: `<Filter><Tag><Key>scope</Key></Tag></Filter>`},
		{name: "missing tag key", rule: `<Filter><Tag><Value>archive</Value></Tag></Filter>`},
		{name: "duplicate tag key", rule: `<Filter><Tag><Key>scope</Key><Key>other</Key><Value>archive</Value></Tag></Filter>`},
		{name: "duplicate tag value", rule: `<Filter><Tag><Key>scope</Key><Value>archive</Value><Value/></Tag></Filter>`},
		{name: "nested tag key", rule: `<Filter><Tag><Key><Value>scope</Value></Key><Value>archive</Value></Tag></Filter>`},
		{name: "nested tag value", rule: `<Filter><Tag><Key>scope</Key><Value><Prefix>archive</Prefix></Value></Tag></Filter>`},
		{name: "unknown transition field", rule: `<Transition><Days>1</Days><StorageClass>GLACIER</StorageClass><Unknown/></Transition>`},
		{name: "duplicate transition days", rule: `<Transition><Days>365</Days><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition>`},
		{name: "duplicate transition date", rule: `<Transition><Date>2030-01-01</Date><Date>2020-01-01</Date><StorageClass>GLACIER</StorageClass></Transition>`},
		{name: "duplicate transition storage", rule: `<Transition><Days>1</Days><StorageClass>GLACIER</StorageClass><StorageClass>DEEP_ARCHIVE</StorageClass></Transition>`},
		{name: "nested storage class", rule: `<Transition><Days>1</Days><StorageClass>GLACIER<Value>DEEP_ARCHIVE</Value></StorageClass></Transition>`},
		{name: "unknown noncurrent transition field", rule: `<NoncurrentVersionTransition><NoncurrentDays>1</NoncurrentDays><StorageClass>GLACIER</StorageClass><Unknown/></NoncurrentVersionTransition>`},
		{name: "duplicate noncurrent transition days", rule: `<NoncurrentVersionTransition><NoncurrentDays>365</NoncurrentDays><NoncurrentDays>1</NoncurrentDays><StorageClass>GLACIER</StorageClass></NoncurrentVersionTransition>`},
		{name: "duplicate retained transition versions", rule: `<NoncurrentVersionTransition><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>5</NewerNoncurrentVersions><NewerNoncurrentVersions>1</NewerNoncurrentVersions><StorageClass>GLACIER</StorageClass></NoncurrentVersionTransition>`},
		{name: "unknown noncurrent expiration field", rule: `<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><Unknown/></NoncurrentVersionExpiration>`},
		{name: "duplicate noncurrent expiration", rule: `<NoncurrentVersionExpiration><NoncurrentDays>365</NoncurrentDays></NoncurrentVersionExpiration><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>`},
		{name: "duplicate noncurrent expiration days", rule: `<NoncurrentVersionExpiration><NoncurrentDays>365</NoncurrentDays><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration>`},
		{name: "duplicate retained expiration versions", rule: `<NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>5</NewerNoncurrentVersions><NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration>`},
		{name: "unknown abort field", rule: `<AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation><Unknown/></AbortIncompleteMultipartUpload>`},
		{name: "duplicate abort", rule: `<AbortIncompleteMultipartUpload><DaysAfterInitiation>365</DaysAfterInitiation></AbortIncompleteMultipartUpload><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload>`},
		{name: "duplicate abort days", rule: `<AbortIncompleteMultipartUpload><DaysAfterInitiation>365</DaysAfterInitiation><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload>`},
		{name: "foreign predicate namespace", rule: `<Filter><Prefix xmlns="urn:other">archive/</Prefix></Filter>`},
		{name: "filter attribute", rule: `<Filter Prefix="archive/"/>`},
		{name: "prefix attribute", rule: `<Filter><Prefix value="archive/"/></Filter>`},
		{name: "filter text", rule: `<Filter>archive/</Filter>`},
		{name: "rule text", rule: `archive/`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertLifecycleRejectedBeforeUpstream(t, lifecycleWireDocument(tc.rule))
		})
	}

	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "unknown root field", body: `<LifecycleConfiguration><Unknown/><Rule><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`},
		{name: "unknown expiration field", body: lifecycleWireDocumentWithExpiration(`<Days>1</Days><Unknown/>`)},
		{name: "duplicate expiration days", body: lifecycleWireDocumentWithExpiration(`<Days>365</Days><Days>1</Days>`)},
		{name: "duplicate expiration date", body: lifecycleWireDocumentWithExpiration(`<Date>2030-01-01</Date><Date>2020-01-01</Date>`)},
		{name: "duplicate delete marker", body: lifecycleWireDocumentWithExpiration(`<ExpiredObjectDeleteMarker>false</ExpiredObjectDeleteMarker><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>`)},
		{name: "nested expiration days", body: lifecycleWireDocumentWithExpiration(`<Days>1<Value>365</Value></Days>`)},
		{name: "foreign document namespace", body: strings.Replace(lifecycleWireDocument(`<Filter/>`), `http://s3.amazonaws.com/doc/2006-03-01/`, `urn:other`, 1)},
		{name: "unknown root attribute", body: strings.Replace(lifecycleWireDocument(`<Filter/>`), `<LifecycleConfiguration `, `<LifecycleConfiguration Prefix="archive/" `, 1)},
		{name: "trailing document", body: lifecycleWireDocument(`<Filter/>`) + `<LifecycleConfiguration/>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertLifecycleRejectedBeforeUpstream(t, tc.body)
		})
	}
}

func assertLifecycleRejectedBeforeUpstream(t *testing.T, body string) {
	t.Helper()
	gw, requests := newLifecycleWireGateway(t, "")
	req := httptest.NewRequest(http.MethodPut, "/team2-bucket?lifecycle", strings.NewReader(body))
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(req, fullTeam2Rule()))
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>MalformedXML</Code>") {
		t.Errorf("malformed lifecycle response = %d %s", rr.Code, rr.Body.String())
	}
	select {
	case sent := <-requests:
		t.Errorf("malformed lifecycle reached upstream: %s", sent)
	default:
	}
}

func lifecycleWireDocumentWithExpiration(expiration string) string {
	return `<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix>archive/</Prefix></Filter><Expiration>` + expiration + `</Expiration></Rule></LifecycleConfiguration>`
}

func TestLifecyclePreservesEmptyFiltersAndRepeatedElements(t *testing.T) {
	const document = `<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
		<Rule><ID>empty-filter</ID><Status>Enabled</Status><Filter/><Expiration><Days>1</Days></Expiration></Rule>
		<Rule><ID>repeated-actions</ID><Status>Enabled</Status>
			<Filter><And><Prefix> archive/ </Prefix><Tag><Key>scope</Key><Value> archive </Value></Tag><Tag><Key>empty</Key><Value/></Tag></And></Filter>
			<Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition>
			<Transition><Days>90</Days><StorageClass>DEEP_ARCHIVE</StorageClass></Transition>
			<NoncurrentVersionTransition><NoncurrentDays>30</NoncurrentDays><StorageClass>GLACIER</StorageClass></NoncurrentVersionTransition>
			<NoncurrentVersionTransition><NoncurrentDays>90</NoncurrentDays><StorageClass>DEEP_ARCHIVE</StorageClass></NoncurrentVersionTransition>
		</Rule>
	</LifecycleConfiguration>`
	gw, requests := newLifecycleWireGateway(t, "")
	putLifecycleWireDocument(t, gw, document)
	var sent []byte
	select {
	case sent = <-requests:
	default:
		t.Fatal("valid lifecycle was not forwarded")
	}
	var out struct {
		Rules []struct {
			ID     string `xml:"ID"`
			Filter *struct {
				Prefix *string `xml:"Prefix"`
				And    *struct {
					Prefix string `xml:"Prefix"`
					Tags   []struct {
						Key   string `xml:"Key"`
						Value string `xml:"Value"`
					} `xml:"Tag"`
				} `xml:"And"`
			} `xml:"Filter"`
			Transitions []struct {
				Days int `xml:"Days"`
			} `xml:"Transition"`
			NoncurrentTransitions []struct {
				Days int `xml:"NoncurrentDays"`
			} `xml:"NoncurrentVersionTransition"`
		} `xml:"Rule"`
	}
	if err := xml.Unmarshal(sent, &out); err != nil {
		t.Fatalf("decode upstream lifecycle: %v", err)
	}
	if len(out.Rules) != 2 {
		t.Fatalf("forwarded rules = %d, want 2", len(out.Rules))
	}
	empty, repeated := out.Rules[0], out.Rules[1]
	if empty.ID != "empty-filter" || empty.Filter == nil || empty.Filter.Prefix != nil || empty.Filter.And != nil {
		t.Errorf("intentional empty filter changed: %+v", empty)
	}
	if repeated.Filter == nil || repeated.Filter.And == nil {
		t.Fatalf("And filter missing: %s", sent)
	}
	and := repeated.Filter.And
	if and.Prefix != " archive/ " || len(and.Tags) != 2 || and.Tags[0].Key != "scope" || and.Tags[0].Value != " archive " || and.Tags[1].Key != "empty" || and.Tags[1].Value != "" {
		t.Errorf("literal filter predicates changed: %+v", and)
	}
	if len(repeated.Transitions) != 2 || repeated.Transitions[0].Days != 30 || repeated.Transitions[1].Days != 90 ||
		len(repeated.NoncurrentTransitions) != 2 || repeated.NoncurrentTransitions[0].Days != 30 || repeated.NoncurrentTransitions[1].Days != 90 {
		t.Errorf("repeated transitions changed: %+v", repeated)
	}
}

func TestLifecycleXMLRejectsTruncatedDocument(t *testing.T) {
	_, err := decodeLifecycleConfigXML(io.LimitReader(strings.NewReader(lifecycleWireDocument(`<Filter/>`)), 100))
	if err == nil {
		t.Fatal("truncated lifecycle document accepted")
	}
}

func TestLifecycleAcceptsSupportedNamespaceForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "no namespace",
			body: `<LifecycleConfiguration><Rule><Status>Enabled</Status><Filter><Prefix> archive/ </Prefix></Filter><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>`,
		},
		{
			name: "prefixed S3 namespace",
			body: `<s3:LifecycleConfiguration xmlns:s3="http://s3.amazonaws.com/doc/2006-03-01/"><s3:Rule><s3:Status>Enabled</s3:Status><s3:Filter><s3:Prefix> archive/ </s3:Prefix></s3:Filter><s3:Expiration><s3:Days>1</s3:Days></s3:Expiration></s3:Rule></s3:LifecycleConfiguration>`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, requests := newLifecycleWireGateway(t, "")
			putLifecycleWireDocument(t, gw, tc.body)
			rule := readLifecycleWireRule(t, requests)
			if rule.Filter == nil || rule.Filter.Prefix == nil || *rule.Filter.Prefix != " archive/ " {
				t.Fatalf("literal prefix changed: %+v", rule.Filter)
			}
		})
	}
}
