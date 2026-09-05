package s3xml

import (
	"crypto/md5" // #nosec G501 -- Verify full consumption for S3 Content-MD5.
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestDecodeCreateBucketConfig(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		body     string
		location string
		wantNil  bool
	}{
		{name: "empty body", wantNil: true},
		{name: "empty root", body: `<CreateBucketConfiguration/>`},
		{name: "empty location", body: `<CreateBucketConfiguration><LocationConstraint/></CreateBucketConfiguration>`},
		{name: "region", body: `<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>`, location: "eu-west-1"},
		{name: "legacy EU", body: `<CreateBucketConfiguration><LocationConstraint>EU</LocationConstraint></CreateBucketConfiguration>`, location: "EU"},
		{name: "custom region", body: `<CreateBucketConfiguration><LocationConstraint>private-region-42</LocationConstraint></CreateBucketConfiguration>`, location: "private-region-42"},
		{name: "preserves location text", body: `<CreateBucketConfiguration><LocationConstraint> EU </LocationConstraint></CreateBucketConfiguration>`, location: " EU "},
		{name: "default namespace", body: `<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>eu-north-1</LocationConstraint></CreateBucketConfiguration>`, location: "eu-north-1"},
		{name: "namespace prefix", body: `<s3:CreateBucketConfiguration xmlns:s3="http://s3.amazonaws.com/doc/2006-03-01/"><s3:LocationConstraint>EU</s3:LocationConstraint></s3:CreateBucketConfiguration>`, location: "EU"},
		{name: "comments and trailing whitespace", body: "<?xml version=\"1.0\"?><CreateBucketConfiguration>\n<!-- region --><LocationConstraint>EU</LocationConstraint>\n</CreateBucketConfiguration>\n<!-- done -->\n", location: "EU"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A caller hashes the original bytes, including trailing whitespace.
			digest := md5.New() // #nosec G401 -- S3 request-integrity checksum.
			got, err := DecodeCreateBucketConfig(io.TeeReader(iotest.OneByteReader(strings.NewReader(tt.body)), digest))
			if err != nil {
				t.Fatalf("DecodeCreateBucketConfig() error = %v", err)
			}
			if (got == nil) != tt.wantNil {
				t.Fatalf("config = %#v, want nil = %t", got, tt.wantNil)
			}
			if got != nil && !reflect.DeepEqual(got, &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(tt.location)}) {
				t.Errorf("config = %#v, want location %q only", got, tt.location)
			}
			wantDigest := md5.Sum([]byte(tt.body)) // #nosec G401 -- S3 request-integrity checksum.
			if string(digest.Sum(nil)) != string(wantDigest[:]) {
				t.Error("successful decoding did not consume the entire original body")
			}
		})
	}
}

func TestDecodeCreateBucketConfigRejectsInvalidXML(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		body string
	}{
		{name: "whitespace only", body: " \t\n"},
		{name: "wrong root", body: `<BucketConfiguration/>`},
		{name: "leading text", body: `ignored<CreateBucketConfiguration/>`},
		{name: "leading text after comment", body: `<!-- config -->ignored<CreateBucketConfiguration/>`},
		{name: "root namespace", body: `<CreateBucketConfiguration xmlns="urn:unsupported"/>`},
		{name: "location namespace", body: `<CreateBucketConfiguration><LocationConstraint xmlns="urn:unsupported">EU</LocationConstraint></CreateBucketConfiguration>`},
		{name: "unknown field", body: `<CreateBucketConfiguration><ObjectLockEnabled>true</ObjectLockEnabled></CreateBucketConfiguration>`},
		{name: "directory bucket", body: `<CreateBucketConfiguration><Bucket><Type>Directory</Type></Bucket></CreateBucketConfiguration>`},
		{name: "directory location", body: `<CreateBucketConfiguration><Location><Name>zone</Name></Location></CreateBucketConfiguration>`},
		{name: "unsupported tags", body: `<CreateBucketConfiguration><Tags/></CreateBucketConfiguration>`},
		{name: "unknown field alongside region", body: `<CreateBucketConfiguration><LocationConstraint>EU</LocationConstraint><Unsupported/></CreateBucketConfiguration>`},
		{name: "duplicate location", body: `<CreateBucketConfiguration><LocationConstraint>EU</LocationConstraint><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>`},
		{name: "nested location value", body: `<CreateBucketConfiguration><LocationConstraint><Region>EU</Region></LocationConstraint></CreateBucketConfiguration>`},
		{name: "nested root", body: `<CreateBucketConfiguration><CreateBucketConfiguration/></CreateBucketConfiguration>`},
		{name: "root attribute", body: `<CreateBucketConfiguration object-lock="true"/>`},
		{name: "location attribute", body: `<CreateBucketConfiguration><LocationConstraint region="EU"/></CreateBucketConfiguration>`},
		{name: "root text", body: `<CreateBucketConfiguration>EU</CreateBucketConfiguration>`},
		{name: "text after location", body: `<CreateBucketConfiguration><LocationConstraint>EU</LocationConstraint>extra</CreateBucketConfiguration>`},
		{name: "unclosed root", body: `<CreateBucketConfiguration>`},
		{name: "unclosed location", body: `<CreateBucketConfiguration><LocationConstraint>EU`},
		{name: "mismatched end", body: `<CreateBucketConfiguration><LocationConstraint>EU</Wrong></CreateBucketConfiguration>`},
		{name: "trailing XML", body: `<CreateBucketConfiguration/><Other/>`},
		{name: "trailing text", body: `<CreateBucketConfiguration/>ignored`},
		{name: "malformed trailing XML", body: `<CreateBucketConfiguration/><`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, err := DecodeCreateBucketConfig(strings.NewReader(tt.body)); err == nil || got != nil {
				t.Errorf("DecodeCreateBucketConfig() = %#v, %v; want nil config and error", got, err)
			}
		})
	}
}

func TestDecodeCreateBucketConfigLimits(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		body    string
		wantErr error
	}{
		{name: "oversized location", body: `<CreateBucketConfiguration><LocationConstraint>` + strings.Repeat("a", maxCreateBucketLocationBytes+1) + `</LocationConstraint></CreateBucketConfiguration>`, wantErr: ErrXMLFieldTooLong},
		{name: "oversized body", body: `<CreateBucketConfiguration>` + strings.Repeat(" ", int(maxCreateBucketBodyBytes)) + `</CreateBucketConfiguration>`, wantErr: ErrXMLBodyTooLarge},
		{name: "oversized trailing whitespace", body: `<CreateBucketConfiguration/>` + strings.Repeat(" ", int(maxCreateBucketBodyBytes)), wantErr: ErrXMLBodyTooLarge},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got, err := DecodeCreateBucketConfig(strings.NewReader(tt.body)); !errors.Is(err, tt.wantErr) || got != nil {
				t.Errorf("DecodeCreateBucketConfig() = %#v, %v; want nil config and %v", got, err, tt.wantErr)
			}
		})
	}
}

func TestDecodeCreateBucketConfigPropagatesBodyReadError(t *testing.T) {
	t.Parallel()
	readErr := errors.New("body read failed")
	for _, body := range []string{"", `<CreateBucketConfiguration/>`, `<CreateBucketConfiguration><LocationConstraint>EU`} {
		t.Run(body, func(t *testing.T) {
			t.Parallel()
			reader := io.MultiReader(strings.NewReader(body), iotest.ErrReader(readErr))
			if got, err := DecodeCreateBucketConfig(reader); !errors.Is(err, readErr) || got != nil {
				t.Errorf("DecodeCreateBucketConfig() = %#v, %v; want body read error", got, err)
			}
		})
	}
}
