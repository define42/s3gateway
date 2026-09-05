package server

import (
	"crypto/sha1" // #nosec G505 -- S3 supports SHA-1 request checksums.
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/define42/s3gateway/internal/s3xml"
)

const deleteObjectsChecksumXML = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Include the original formatting in the client's checksum. -->
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object><Key> important &amp; object </Key><VersionId>v1</VersionId></Object>
  <Quiet>false</Quiet>
</Delete>
<!-- Trailing comments are also part of the checksummed body. -->
  `

func TestDeleteObjectsContentMD5(t *testing.T) {
	fixture := newDeleteObjectsChecksumFixture(t)
	for _, tc := range []struct {
		name    string
		digests []string
		code    string
	}{
		{name: "valid original XML including trailing comment", digests: []string{xmlBodyMD5(deleteObjectsChecksumXML)}},
		{name: "wrong digest", digests: []string{xmlBodyMD5("different deletion body")}, code: "BadDigest"},
		{name: "digest omits trailing whitespace", digests: []string{xmlBodyMD5(strings.TrimSpace(deleteObjectsChecksumXML))}, code: "BadDigest"},
		{name: "malformed base64", digests: []string{strings.Repeat("!", 24)}, code: "InvalidDigest"},
		{name: "wrong digest length", digests: []string{base64.StdEncoding.EncodeToString([]byte("short"))}, code: "InvalidDigest"},
		{name: "empty digest", digests: []string{""}, code: "InvalidDigest"},
		{name: "blank digest", digests: []string{" "}, code: "InvalidDigest"},
		{name: "duplicate digest", digests: []string{xmlBodyMD5(deleteObjectsChecksumXML), xmlBodyMD5(deleteObjectsChecksumXML)}, code: "InvalidDigest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := make(http.Header)
			for _, digest := range tc.digests {
				header.Add("Content-MD5", digest)
			}
			fixture.checkRequest(t, header, tc.code)
		})
	}
}

func TestDeleteObjectsAlternateChecksums(t *testing.T) {
	fixture := newDeleteObjectsChecksumFixture(t)
	for _, algorithm := range []string{"CRC32", "CRC32C", "CRC64NVME", "SHA1", "SHA256"} {
		t.Run(algorithm, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				body string
				code string
			}{
				{name: "valid original XML", body: deleteObjectsChecksumXML},
				{name: "wrong digest", body: "different deletion body", code: "BadDigest"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					header := make(http.Header)
					header.Set("x-amz-checksum-"+strings.ToLower(algorithm), deleteObjectsTestChecksum(algorithm, tc.body))
					fixture.checkRequest(t, header, tc.code)
				})
			}
		})
	}
}

func TestDeleteObjectsChecksumSelection(t *testing.T) {
	fixture := newDeleteObjectsChecksumFixture(t)
	validCRC32 := deleteObjectsTestChecksum("CRC32", deleteObjectsChecksumXML)
	validMD5 := xmlBodyMD5(deleteObjectsChecksumXML)
	for _, tc := range []struct {
		name   string
		header http.Header
		code   string
	}{
		{name: "no supplied checksum remains supported", header: http.Header{}},
		{name: "SDK algorithm selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32"}, "x-amz-checksum-crc32": {validCRC32}}},
		{name: "legacy algorithm selector", header: http.Header{"x-amz-checksum-algorithm": {"CRC32"}, "x-amz-checksum-crc32": {validCRC32}}},
		{name: "both matching selectors", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32"}, "x-amz-checksum-algorithm": {"CRC32"}, "x-amz-checksum-crc32": {validCRC32}}},
		{name: "MD5 and alternate checksum", header: http.Header{"Content-MD5": {validMD5}, "x-amz-checksum-crc32": {validCRC32}}},
		{name: "valid MD5 does not excuse bad alternate checksum", header: http.Header{"Content-MD5": {validMD5}, "x-amz-checksum-crc32": {deleteObjectsTestChecksum("CRC32", "wrong body")}}, code: "BadDigest"},
		{name: "valid alternate checksum does not excuse bad MD5", header: http.Header{"Content-MD5": {xmlBodyMD5("wrong body")}, "x-amz-checksum-crc32": {validCRC32}}, code: "BadDigest"},
		{name: "empty alternate checksum", header: http.Header{"x-amz-checksum-crc32": {""}}, code: "InvalidDigest"},
		{name: "malformed alternate base64", header: http.Header{"x-amz-checksum-crc32": {"!!!!"}}, code: "InvalidDigest"},
		{name: "wrong alternate digest length", header: http.Header{"x-amz-checksum-crc32": {base64.StdEncoding.EncodeToString([]byte("short"))}}, code: "InvalidDigest"},
		{name: "duplicate alternate checksum", header: http.Header{"x-amz-checksum-crc32": {validCRC32, validCRC32}}, code: "InvalidDigest"},
		{name: "multiple alternate algorithms", header: http.Header{"x-amz-checksum-crc32": {validCRC32}, "x-amz-checksum-sha256": {deleteObjectsTestChecksum("SHA256", deleteObjectsChecksumXML)}}, code: "InvalidRequest"},
		{name: "SDK selector mismatch", header: http.Header{"x-amz-sdk-checksum-algorithm": {"SHA256"}, "x-amz-checksum-crc32": {validCRC32}}, code: "InvalidRequest"},
		{name: "legacy selector mismatch", header: http.Header{"x-amz-checksum-algorithm": {"SHA256"}, "x-amz-checksum-crc32": {validCRC32}}, code: "InvalidRequest"},
		{name: "SDK selector without value", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32"}}, code: "InvalidRequest"},
		{name: "legacy selector without value", header: http.Header{"x-amz-checksum-algorithm": {"CRC32"}}, code: "InvalidRequest"},
		{name: "unknown alternate algorithm", header: http.Header{"x-amz-checksum-sha512": {validCRC32}}, code: "InvalidRequest"},
		{name: "unknown selected algorithm", header: http.Header{"x-amz-sdk-checksum-algorithm": {"SHA512"}, "x-amz-checksum-crc32": {validCRC32}}, code: "InvalidRequest"},
		{name: "empty selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {""}, "x-amz-checksum-crc32": {validCRC32}}, code: "InvalidRequest"},
		{name: "duplicate selector", header: http.Header{"x-amz-sdk-checksum-algorithm": {"CRC32", "CRC32"}, "x-amz-checksum-crc32": {validCRC32}}, code: "InvalidRequest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.checkRequest(t, tc.header, tc.code)
		})
	}
}

func deleteObjectsTestChecksum(algorithm, body string) string {
	var digest []byte
	switch algorithm {
	case "CRC32":
		digest = binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE([]byte(body)))
	case "CRC32C":
		digest = binary.BigEndian.AppendUint32(nil, crc32.Checksum([]byte(body), crc32.MakeTable(crc32.Castagnoli)))
	case "CRC64NVME":
		const nvmePolynomial = 0x9a6c9329ac4bc9b5
		digest = binary.BigEndian.AppendUint64(nil, crc64.Checksum([]byte(body), crc64.MakeTable(nvmePolynomial)))
	case "SHA1":
		sum := sha1.Sum([]byte(body)) // #nosec G401 -- S3 supports SHA-1 request checksums.
		digest = sum[:]
	case "SHA256":
		sum := sha256.Sum256([]byte(body))
		digest = sum[:]
	default:
		panic("unsupported test checksum algorithm: " + algorithm)
	}
	return base64.StdEncoding.EncodeToString(digest)
}

type deleteObjectsChecksumRequest struct {
	body   string
	header http.Header
}

type deleteObjectsChecksumFixture struct {
	front       *httptest.Server
	credentials aws.Credentials
	calls       atomic.Int32
	requests    chan deleteObjectsChecksumRequest
}

func newDeleteObjectsChecksumFixture(t *testing.T) *deleteObjectsChecksumFixture {
	t.Helper()
	fixture := &deleteObjectsChecksumFixture{requests: make(chan deleteObjectsChecksumRequest, 8)}
	gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		fixture.calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/team2-bucket" || !r.URL.Query().Has("delete") {
			t.Errorf("unexpected upstream request: %s %s", r.Method, r.URL)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream deletion body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fixture.requests <- deleteObjectsChecksumRequest{body: string(body), header: r.Header.Clone()}
		if checksum := r.Header.Get("Content-MD5"); checksum != "" && checksum != xmlBodyMD5(string(body)) {
			s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "Content-MD5 does not match reserialized XML")
			return
		}
		wantCRC32 := base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE(body)))
		if r.Header.Get("x-amz-checksum-crc32") != wantCRC32 {
			s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "CRC32 does not match reserialized XML")
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<DeleteResult><Deleted><Key> important &amp; object </Key><VersionId>v1</VersionId></Deleted></DeleteResult>`)
	})
	t.Cleanup(cleanup)
	gw.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-d": {}})
	accessKey, secretKey := mustGatewayCredentials(t, gw, "testuser", "dogood")
	fixture.credentials = aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	fixture.front = httptest.NewTLSServer(gw.WithAuth(gw, nil))
	t.Cleanup(fixture.front.Close)
	return fixture
}

func (f *deleteObjectsChecksumFixture) checkRequest(t *testing.T, header http.Header, wantCode string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.front.URL+"/team2-bucket?delete", strings.NewReader(deleteObjectsChecksumXML))
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	// Exercise the real TLS authentication path where only the supplied checksum
	// protects the original body, not an independently verified SigV4 body hash.
	req.Header.Set("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
	if err := v4.NewSigner().SignHTTP(t.Context(), f.credentials, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now()); err != nil {
		t.Fatalf("sign deletion request: %v", err)
	}
	response, err := f.front.Client().Do(req)
	if err != nil {
		t.Fatalf("send signed deletion request over TLS: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read gateway response: %v", err)
	}
	calls := f.calls.Swap(0)
	var observed deleteObjectsChecksumRequest
	for range calls {
		select {
		case observed = <-f.requests:
		default:
			t.Fatal("upstream deletion request was not captured")
		}
	}
	if wantCode != "" {
		if calls != 0 {
			t.Errorf("invalid checksum reached upstream %d times, want zero deletes", calls)
		}
		if response.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "<Code>"+wantCode+"</Code>") {
			t.Fatalf("status=%d body=%s, want 400 %s", response.StatusCode, body, wantCode)
		}
		return
	}
	if response.StatusCode != http.StatusOK || calls != 1 {
		t.Fatalf("status=%d calls=%d body=%s, want 200 and one deletion request", response.StatusCode, calls, body)
	}
	if observed.body == deleteObjectsChecksumXML {
		t.Fatal("test did not exercise XML reserialization")
	}
	var deletion struct {
		Objects []struct {
			Key       string `xml:"Key"`
			VersionID string `xml:"VersionId"`
		} `xml:"Object"`
	}
	if err := xml.Unmarshal([]byte(observed.body), &deletion); err != nil {
		t.Fatalf("decode upstream deletion XML: %v", err)
	}
	if len(deletion.Objects) != 1 || deletion.Objects[0].Key != " important & object " || deletion.Objects[0].VersionID != "v1" {
		t.Fatalf("deletion targets changed during serialization: %+v", deletion.Objects)
	}
	wantCRC32 := base64.StdEncoding.EncodeToString(binary.BigEndian.AppendUint32(nil, crc32.ChecksumIEEE([]byte(observed.body))))
	if observed.header.Get("x-amz-checksum-crc32") != wantCRC32 {
		t.Fatalf("outgoing checksum does not cover reserialized body: %q", observed.header.Get("x-amz-checksum-crc32"))
	}
}
