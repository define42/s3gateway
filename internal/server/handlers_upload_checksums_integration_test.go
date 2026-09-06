//go:build integration

package server

import (
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

func TestUploadCombinedChecksumsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping upload checksum integration test in short mode")
	}
	env := setupIntegrationEnv(t)
	const bucket = "team2-combined-checksums"
	const payload = "the original object with two integrity checks"
	if _, err := env.upstreamClient.CreateBucket(env.ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create checksum test bucket: %v", err)
	}
	for _, operation := range []string{"PutObject", "UploadPart"} {
		for _, algorithm := range []types.ChecksumAlgorithm{types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmSha256} {
			t.Run(operation+"/"+string(algorithm), func(t *testing.T) {
				key := operation + "-" + string(algorithm)
				var uploadID string
				if operation == "UploadPart" {
					out, err := env.upstreamClient.CreateMultipartUpload(env.ctx, &s3.CreateMultipartUploadInput{
						Bucket: aws.String(bucket), Key: aws.String(key), ChecksumAlgorithm: algorithm,
					})
					if err != nil {
						t.Fatalf("create multipart upload: %v", err)
					}
					uploadID = aws.ToString(out.UploadId)
				}
				if err := uploadWithCombinedChecksums(env.ctx, env.rwClient, operation, bucket, key, uploadID, payload, algorithm, xmlBodyMD5(payload), nil); err != nil {
					t.Fatalf("valid combined-checksum upload: %v", err)
				}
				for _, tc := range []struct {
					name     string
					md5      string
					checksum *string
					code     string
				}{
					{name: "bad MD5", md5: xmlBodyMD5(payload), code: "BadDigest"},
					{name: "bad alternate checksum", md5: xmlBodyMD5("replacement"), checksum: aws.String(deleteObjectsTestChecksum(string(algorithm), payload)), code: "XAmzContentChecksumMismatch"},
				} {
					t.Run(tc.name, func(t *testing.T) {
						err := uploadWithCombinedChecksums(env.ctx, env.rwClient, operation, bucket, key, uploadID, "replacement", algorithm, tc.md5, tc.checksum)
						assertCombinedUploadError(t, err, tc.code)
					})
				}
				if operation == "UploadPart" {
					parts, err := env.upstreamClient.ListParts(env.ctx, &s3.ListPartsInput{
						Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
					})
					if err != nil {
						t.Fatalf("read persisted parts: %v", err)
					}
					if len(parts.Parts) != 1 || aws.ToInt64(parts.Parts[0].Size) != int64(len(payload)) {
						t.Fatalf("invalid checksum changed the persisted part: %#v", parts.Parts)
					}
					_, err = env.upstreamClient.AbortMultipartUpload(env.ctx, &s3.AbortMultipartUploadInput{
						Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID),
					})
					if err != nil {
						t.Fatalf("clean up multipart upload: %v", err)
					}
					return
				}
				out, err := env.upstreamClient.GetObject(env.ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
				if err != nil {
					t.Fatalf("read persisted object: %v", err)
				}
				body, readErr := io.ReadAll(out.Body)
				closeErr := out.Body.Close()
				if readErr != nil || closeErr != nil || string(body) != payload {
					t.Fatalf("invalid checksum changed the persisted object: body=%q read=%v close=%v", body, readErr, closeErr)
				}
			})
		}
	}
}
