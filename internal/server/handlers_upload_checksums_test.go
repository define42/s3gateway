package server

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/define42/s3gateway/internal/s3xml"
)

func TestSDKUploadsCombineContentMD5AndAlternateChecksums(t *testing.T) {
	const payload = "object protected by both checksum headers"
	for _, operation := range []string{"PutObject", "UploadPart"} {
		t.Run(operation, func(t *testing.T) {
			for _, algorithm := range []types.ChecksumAlgorithm{types.ChecksumAlgorithmCrc32, types.ChecksumAlgorithmSha256} {
				t.Run(string(algorithm), func(t *testing.T) {
					for _, tc := range []struct {
						name     string
						md5      string
						checksum *string
						code     string
					}{
						{name: "generated checksum trailer", md5: xmlBodyMD5(payload)},
						{name: "explicit checksum header", md5: xmlBodyMD5(payload), checksum: aws.String(deleteObjectsTestChecksum(string(algorithm), payload))},
						{name: "bad MD5 with valid trailer", md5: xmlBodyMD5("different body"), code: "BadDigest"},
						{name: "malformed MD5 with valid trailer", md5: "invalid-base64", code: "InvalidDigest"},
						{name: "bad alternate checksum with valid MD5", md5: xmlBodyMD5(payload), checksum: aws.String(deleteObjectsTestChecksum(string(algorithm), "different body")), code: "BadDigest"},
					} {
						t.Run(tc.name, func(t *testing.T) {
							var calls, stored atomic.Int32
							gw, cleanup := newGatewayWithStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
								calls.Add(1)
								body, err := io.ReadAll(r.Body)
								if err != nil {
									t.Errorf("decode upstream checksum trailer: %v", err)
									w.WriteHeader(http.StatusBadRequest)
									return
								}
								if string(body) != payload || r.Header.Get("Content-MD5") != tc.md5 {
									t.Error("gateway changed the object bytes or Content-MD5")
								}
								if got := r.Header.Get("x-amz-sdk-checksum-algorithm"); got != string(algorithm) {
									t.Errorf("upstream checksum algorithm = %q, want %q", got, algorithm)
								}
								// Behave like S3: validate every supplied digest before
								// storing anything. The fixture already verifies trailers.
								md5, err := base64.StdEncoding.Strict().DecodeString(r.Header.Get("Content-MD5"))
								if err != nil || len(md5) != 16 {
									s3xml.WriteError(w, http.StatusBadRequest, "InvalidDigest", "Invalid Content-MD5")
									return
								}
								if r.Header.Get("Content-MD5") != xmlBodyMD5(string(body)) {
									s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "Content-MD5 mismatch")
									return
								}
								if tc.checksum != nil {
									got := r.Header.Get("x-amz-checksum-" + strings.ToLower(string(algorithm)))
									if got != *tc.checksum {
										t.Error("gateway changed the supplied alternate checksum")
									}
									if got != deleteObjectsTestChecksum(string(algorithm), string(body)) {
										s3xml.WriteError(w, http.StatusBadRequest, "BadDigest", "Alternate checksum mismatch")
										return
									}
								}
								stored.Add(1)
								w.Header().Set("ETag", `"stored-etag"`)
								w.WriteHeader(http.StatusOK)
							})
							t.Cleanup(cleanup)
							front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								if tc.checksum == nil && r.Header.Get("x-amz-trailer") == "" {
									t.Error("SDK request did not exercise checksum trailers")
								}
								gw.ServeHTTP(w, reqWithRules(r, fullTeam2Rule()))
							}))
							t.Cleanup(front.Close)
							client := s3.New(s3.Options{
								Region: "us-east-1", BaseEndpoint: aws.String(front.URL), UsePathStyle: true,
								Credentials: credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
								HTTPClient:  front.Client(), RetryMaxAttempts: 1,
							})
							err := uploadWithCombinedChecksums(t.Context(), client, operation, "team2-bucket", "key", "upload", payload, algorithm, tc.md5, tc.checksum)
							assertCombinedUploadError(t, err, tc.code)
							wantStored := int32(1)
							if tc.code != "" {
								wantStored = 0
							}
							if calls.Load() != 1 || stored.Load() != wantStored {
								t.Errorf("upstream calls=%d stored=%d, want calls=1 stored=%d", calls.Load(), stored.Load(), wantStored)
							}
						})
					}
				})
			}
		})
	}
}

func uploadWithCombinedChecksums(
	ctx context.Context, client *s3.Client, operation, bucket, key, uploadID, body string,
	algorithm types.ChecksumAlgorithm, md5 string, checksum *string,
) error {
	var crc32, sha256 *string
	switch algorithm {
	case types.ChecksumAlgorithmCrc32:
		crc32 = checksum
	case types.ChecksumAlgorithmSha256:
		sha256 = checksum
	}
	if operation == "UploadPart" {
		_, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: aws.String(bucket), Key: aws.String(key), UploadId: aws.String(uploadID), PartNumber: aws.Int32(1),
			Body: strings.NewReader(body), ContentMD5: aws.String(md5), ChecksumAlgorithm: algorithm,
			ChecksumCRC32: crc32, ChecksumSHA256: sha256,
		})
		return err
	}
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), Body: strings.NewReader(body),
		ContentMD5: aws.String(md5), ChecksumAlgorithm: algorithm, ChecksumCRC32: crc32, ChecksumSHA256: sha256,
	})
	return err
}

func assertCombinedUploadError(t *testing.T, err error, code string) {
	t.Helper()
	if code == "" {
		if err != nil {
			t.Fatalf("valid upload failed: %v", err)
		}
		return
	}
	var apiError smithy.APIError
	if !errors.As(err, &apiError) || apiError.ErrorCode() != code {
		t.Fatalf("upload error = %v, want %s", err, code)
	}
}
