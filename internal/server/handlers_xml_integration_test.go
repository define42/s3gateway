//go:build integration

package server

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestXMLContentMD5Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping XML checksum integration test in short mode")
	}
	env := setupIntegrationEnv(t)
	const bucket = "team2-xml-checksums"
	const key = "tagged-object"
	if _, err := env.upstreamClient.CreateBucket(env.ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	if _, err := env.upstreamClient.PutObject(env.ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader("test object"),
	}); err != nil {
		t.Fatalf("create object: %v", err)
	}

	const taggingXML = `<?xml version="1.0" encoding="UTF-8"?>
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <!-- Formatting and character references change during SDK serialization. -->
  <TagSet><Tag><Key>purpose</Key><Value>origi&#110;al</Value></Tag></TagSet>
</Tagging>
`
	const versioningXML = `<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>Enabled</Status>
</VersioningConfiguration>
`
	cases := []struct {
		name     string
		target   string
		body     string
		tampered string
		verify   func(*testing.T)
	}{
		{
			name: "object tagging", target: "/" + bucket + "/" + key + "?tagging",
			body: taggingXML, tampered: strings.ReplaceAll(taggingXML, "origi&#110;al", "changed"),
			verify: func(t *testing.T) {
				t.Helper()
				out, err := env.upstreamClient.GetObjectTagging(env.ctx, &s3.GetObjectTaggingInput{
					Bucket: aws.String(bucket), Key: aws.String(key),
				})
				if err != nil {
					t.Fatalf("read object tags: %v", err)
				}
				verifyXMLIntegrationTags(t, out.TagSet)
			},
		},
		{
			name: "bucket tagging", target: "/" + bucket + "?tagging",
			body: taggingXML, tampered: strings.ReplaceAll(taggingXML, "origi&#110;al", "changed"),
			verify: func(t *testing.T) {
				t.Helper()
				out, err := env.upstreamClient.GetBucketTagging(env.ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
				if err != nil {
					t.Fatalf("read bucket tags: %v", err)
				}
				verifyXMLIntegrationTags(t, out.TagSet)
			},
		},
		{
			name: "bucket versioning", target: "/" + bucket + "?versioning",
			body: versioningXML, tampered: strings.ReplaceAll(versioningXML, "Enabled", "Suspended"),
			verify: func(t *testing.T) {
				t.Helper()
				out, err := env.upstreamClient.GetBucketVersioning(env.ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket)})
				if err != nil {
					t.Fatalf("read bucket versioning: %v", err)
				}
				if out.Status != types.BucketVersioningStatusEnabled {
					t.Fatalf("versioning status = %q, want Enabled", out.Status)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checksum := xmlBodyMD5(tc.body)
			putXMLIntegrationRequest(t, env, tc.target, tc.body, checksum, http.StatusOK)
			tc.verify(t)
			putXMLIntegrationRequest(t, env, tc.target, tc.tampered, checksum, http.StatusBadRequest)
			tc.verify(t)
		})
	}
}

func verifyXMLIntegrationTags(t *testing.T, tags []types.Tag) {
	t.Helper()
	if len(tags) != 1 || aws.ToString(tags[0].Key) != "purpose" || aws.ToString(tags[0].Value) != "original" {
		t.Fatalf("persisted tags = %#v, want purpose=original", tags)
	}
}

func putXMLIntegrationRequest(t *testing.T, env *integrationEnv, target, body, checksum string, wantStatus int) {
	t.Helper()
	options := env.rwClient.Options()
	req, err := http.NewRequestWithContext(env.ctx, http.MethodPut, aws.ToString(options.BaseEndpoint)+target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("create XML request: %v", err)
	}
	req.Header.Set("Content-Type", "application/xml")
	req.Header.Set("Content-MD5", checksum)
	payloadHash := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
	req.Header.Set("x-amz-content-sha256", payloadHash)
	credentials, err := options.Credentials.Retrieve(env.ctx)
	if err != nil {
		t.Fatalf("retrieve gateway credentials: %v", err)
	}
	if err := v4.NewSigner().SignHTTP(env.ctx, credentials, req, payloadHash, "s3", options.Region, time.Now().UTC()); err != nil {
		t.Fatalf("sign XML request: %v", err)
	}
	response, err := options.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("send XML request: %v", err)
	}
	responseBody, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("read XML response: read=%v close=%v", readErr, closeErr)
	}
	if response.StatusCode != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", response.StatusCode, wantStatus, responseBody)
	}
	if wantStatus == http.StatusBadRequest && !strings.Contains(string(responseBody), "<Code>BadDigest</Code>") {
		t.Fatalf("expected BadDigest error, got %s", responseBody)
	}
}
