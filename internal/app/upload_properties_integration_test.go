//go:build integration

package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"maps"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/define42/s3gateway/internal/testutil"
)

func TestUploadPropertiesIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	gatewayS3, upstreamS3 := uploadPropertyClients(t, ctx)
	const (
		bucket             = "team2-upload-properties"
		contentType        = "text/plain"
		contentEncoding    = "gzip"
		contentDisposition = `attachment; filename="evidence.txt.gz"`
		contentLanguage    = "en-GB"
		cacheControl       = "private, max-age=120"
		tagging            = "category=upload+test&literal=a%2Bb%3Ac"
	)
	if _, err := upstreamS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	metadata := map[string]string{"source": "upload-properties-integration", "format": "gzip"}
	wantTags := map[string]string{"category": "upload test", "literal": "a+b:c"}
	var compressed bytes.Buffer
	// Use an uncompressed gzip stream so it can span two valid multipart parts.
	writer, err := gzip.NewWriterLevel(&compressed, gzip.NoCompression)
	if err != nil {
		t.Fatalf("create gzip writer: %v", err)
	}
	if _, err := writer.Write(bytes.Repeat([]byte("stored upload properties\n"), 1<<18)); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	payload := compressed.Bytes()

	for _, name := range []string{"put-object", "streaming-put-object", "multipart"} {
		t.Run(name, func(t *testing.T) {
			key := name + ".txt.gz"
			if name != "multipart" {
				var body io.Reader = bytes.NewReader(payload)
				var checksumAlgorithm types.ChecksumAlgorithm
				if name == "streaming-put-object" {
					body = struct{ io.Reader }{body}
					checksumAlgorithm = types.ChecksumAlgorithmCrc32
				}
				_, err := gatewayS3.PutObject(ctx, &s3.PutObjectInput{
					Bucket:             aws.String(bucket),
					Key:                aws.String(key),
					Body:               body,
					ChecksumAlgorithm:  checksumAlgorithm,
					ContentLength:      aws.Int64(int64(len(payload))),
					ContentType:        aws.String(contentType),
					ContentEncoding:    aws.String(contentEncoding),
					ContentDisposition: aws.String(contentDisposition),
					ContentLanguage:    aws.String(contentLanguage),
					CacheControl:       aws.String(cacheControl),
					StorageClass:       types.StorageClassStandard,
					Tagging:            aws.String(tagging),
					Metadata:           metadata,
				})
				if err != nil {
					t.Fatalf("put object: %v", err)
				}
			} else {
				created, err := gatewayS3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
					Bucket:             aws.String(bucket),
					Key:                aws.String(key),
					ContentType:        aws.String(contentType),
					ContentEncoding:    aws.String(contentEncoding),
					ContentDisposition: aws.String(contentDisposition),
					ContentLanguage:    aws.String(contentLanguage),
					CacheControl:       aws.String(cacheControl),
					StorageClass:       types.StorageClassStandard,
					Tagging:            aws.String(tagging),
					Metadata:           metadata,
				})
				if err != nil {
					t.Fatalf("create multipart upload: %v", err)
				}
				var parts []types.CompletedPart
				const partSize = 5 << 20
				for offset := 0; offset < len(payload); offset += partSize {
					partBody := payload[offset:min(offset+partSize, len(payload))]
					partNumber := int32(len(parts) + 1)
					part, err := gatewayS3.UploadPart(ctx, &s3.UploadPartInput{
						Bucket: aws.String(bucket), Key: aws.String(key), UploadId: created.UploadId,
						PartNumber: aws.Int32(partNumber), Body: bytes.NewReader(partBody),
						ContentLength: aws.Int64(int64(len(partBody))),
					})
					if err != nil {
						t.Fatalf("upload part %d: %v", partNumber, err)
					}
					parts = append(parts, types.CompletedPart{
						PartNumber: aws.Int32(partNumber), ETag: part.ETag,
						ChecksumCRC32: part.ChecksumCRC32,
					})
				}
				if _, err := gatewayS3.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
					Bucket: aws.String(bucket), Key: aws.String(key), UploadId: created.UploadId,
					MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
				}); err != nil {
					t.Fatalf("complete multipart upload: %v", err)
				}
			}

			head, err := upstreamS3.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
			if err != nil {
				t.Fatalf("head stored object: %v", err)
			}
			for _, property := range []struct {
				name string
				got  *string
				want string
			}{
				{"Content-Type", head.ContentType, contentType},
				{"Content-Encoding", head.ContentEncoding, contentEncoding},
				{"Content-Disposition", head.ContentDisposition, contentDisposition},
				{"Content-Language", head.ContentLanguage, contentLanguage},
				{"Cache-Control", head.CacheControl, cacheControl},
			} {
				if got := aws.ToString(property.got); got != property.want {
					t.Errorf("stored %s = %q, want %q", property.name, got, property.want)
				}
			}
			// S3 may omit the header for its default STANDARD storage class.
			if head.StorageClass != "" && head.StorageClass != types.StorageClassStandard {
				t.Errorf("stored storage class = %q, want STANDARD", head.StorageClass)
			}
			if got := aws.ToInt64(head.ContentLength); got != int64(len(payload)) {
				t.Errorf("stored content length = %d, want %d", got, len(payload))
			}
			for name, want := range metadata {
				if got := head.Metadata[name]; got != want {
					t.Errorf("stored metadata %q = %q, want %q", name, got, want)
				}
			}
			tags, err := upstreamS3.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{Bucket: aws.String(bucket), Key: aws.String(key)})
			if err != nil {
				t.Fatalf("get stored object tags: %v", err)
			}
			gotTags := make(map[string]string, len(tags.TagSet))
			for _, tag := range tags.TagSet {
				gotTags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			if !maps.Equal(gotTags, wantTags) {
				t.Errorf("stored tags = %v, want %v", gotTags, wantTags)
			}
			object, err := upstreamS3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
			if err != nil {
				t.Fatalf("get stored object: %v", err)
			}
			defer func() { _ = object.Body.Close() }()
			body, err := io.ReadAll(object.Body)
			if err != nil {
				t.Fatalf("read stored object: %v", err)
			}
			if !bytes.Equal(body, payload) {
				t.Error("stored gzip bytes differ from uploaded payload")
			}
		})
	}
}

func uploadPropertyClients(t *testing.T, ctx context.Context) (gatewayS3, upstreamS3 *s3.Client) {
	t.Helper()
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, testutil.WriteGatewayGlauthConfig(t), "ldap")
	t.Cleanup(stopLDAP)
	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	t.Cleanup(stopMinio)
	privateKeyHex, publicKey, err := s3credentials.GenerateX25519TestKeys()
	if err != nil {
		t.Fatalf("generate X25519 keys: %v", err)
	}
	privateKey, err := s3credentials.X25519PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		t.Fatalf("parse X25519 private key: %v", err)
	}
	httpServer, cleanup, err := boot(config.Config{
		LDAPURL: ldapURL, BaseDN: "dc=glauth,dc=com", LDAPGroupBaseDN: "ou=groups,dc=glauth,dc=com",
		LDAPDomain: "example.com", UpstreamEndpoint: minioURL, UpstreamRegion: "us-east-1",
		UpstreamAccessKey: "minioadmin", UpstreamSecretKey: "minioadmin", UpstreamForcePathStyle: true,
		S3GatewayPrivateX25519Key: privateKey,
	})
	if err != nil {
		t.Fatalf("boot gateway: %v", err)
	}
	t.Cleanup(cleanup)
	gateway := testutil.NewTLSServer(t, httpServer.Handler)
	accessKey, secretKey, err := s3credentials.GenerateKeysX25519("testuser", "dogood", publicKey)
	if err != nil {
		t.Fatalf("generate gateway credentials: %v", err)
	}
	gatewayS3 = testutil.NewS3Client(t, ctx, gateway.URL, "us-east-1", accessKey, secretKey)
	upstreamOptions := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", "minioadmin", "minioadmin").Options()
	upstreamHTTP := testutil.NewHTTPClient(t)
	// Inspect stored compressed bytes without net/http transparently decoding them.
	upstreamHTTP.Transport.(*http.Transport).DisableCompression = true
	upstreamOptions.HTTPClient = upstreamHTTP
	return gatewayS3, s3.New(upstreamOptions)
}
