//go:build integration

package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/define42/s3gateway/internal/testutil"
)

func TestMultipartChecksumsIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
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
		LDAPURL:                   ldapURL,
		BaseDN:                    "dc=glauth,dc=com",
		LDAPGroupBaseDN:           "ou=groups,dc=glauth,dc=com",
		LDAPDomain:                "example.com",
		UpstreamEndpoint:          minioURL,
		UpstreamRegion:            "us-east-1",
		UpstreamAccessKey:         "minioadmin",
		UpstreamSecretKey:         "minioadmin",
		UpstreamForcePathStyle:    true,
		S3GatewayPrivateX25519Key: privateKey,
	})
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatalf("boot gateway: %v", err)
	}
	accessKey, secretKey, err := s3credentials.GenerateKeysX25519("testuser", "dogood", publicKey)
	if err != nil {
		t.Fatalf("generate gateway credentials: %v", err)
	}
	payload := make([]byte, 20<<20)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	upstreamS3 := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", "minioadmin", "minioadmin")
	const bucket = "team2-multipart-checksums"
	if _, err := upstreamS3.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); err != nil {
		t.Fatalf("create bucket: %v", err)
	}

	for _, transport := range []string{"http", "https"} {
		t.Run(transport, func(t *testing.T) {
			gateway := httptest.NewUnstartedServer(httpServer.Handler)
			if transport == "https" {
				gateway.StartTLS()
			} else {
				gateway.Start()
			}
			t.Cleanup(gateway.Close)
			clientOptions := testutil.NewS3Client(t, ctx, gateway.URL, "us-east-1", accessKey, secretKey).Options()
			clientOptions.HTTPClient = gateway.Client()
			gatewayS3 := s3.New(clientOptions)

			for _, test := range []struct {
				name         string
				algorithm    types.ChecksumAlgorithm
				checksumType types.ChecksumType
			}{
				{"crc32-composite", types.ChecksumAlgorithmCrc32, types.ChecksumTypeComposite},
				{"crc64nvme-full-object", types.ChecksumAlgorithmCrc64nvme, types.ChecksumTypeFullObject},
			} {
				t.Run(test.name, func(t *testing.T) {
					key := transport + "/" + test.name + ".bin"
					created, err := gatewayS3.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
						Bucket:            aws.String(bucket),
						Key:               aws.String(key),
						ChecksumAlgorithm: test.algorithm,
						ChecksumType:      test.checksumType,
					})
					if err != nil {
						t.Fatalf("create multipart upload: %v", err)
					}
					t.Cleanup(func() {
						cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cleanupCancel()
						_, _ = upstreamS3.AbortMultipartUpload(cleanupCtx, &s3.AbortMultipartUploadInput{
							Bucket: aws.String(bucket), Key: aws.String(key), UploadId: created.UploadId,
						})
					})
					if created.ChecksumAlgorithm != test.algorithm || created.ChecksumType != test.checksumType {
						t.Errorf("initiate checksum settings = %s/%s, want %s/%s", created.ChecksumAlgorithm, created.ChecksumType, test.algorithm, test.checksumType)
					}
					// Checksummed uploads must stream even when no temporary
					// directory is available to buffer their request bodies.
					t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "unavailable"))

					var parts []types.CompletedPart
					var partChecksums []byte
					const partSize = 8 << 20
					for offset := 0; offset < len(payload); offset += partSize {
						partBody := payload[offset:min(offset+partSize, len(payload))]
						partNumber := int32(len(parts) + 1)
						part, err := gatewayS3.UploadPart(ctx, &s3.UploadPartInput{
							Bucket:            aws.String(bucket),
							Key:               aws.String(key),
							UploadId:          created.UploadId,
							PartNumber:        aws.Int32(partNumber),
							Body:              bytes.NewReader(partBody),
							ContentLength:     aws.Int64(int64(len(partBody))),
							ChecksumAlgorithm: test.algorithm,
						})
						if err != nil {
							t.Fatalf("upload part %d: %v", partNumber, err)
						}
						digest := multipartChecksumDigest(test.algorithm, partBody)
						partChecksums = append(partChecksums, digest...)
						gotChecksum := aws.ToString(part.ChecksumCRC32)
						if test.algorithm == types.ChecksumAlgorithmCrc64nvme {
							gotChecksum = aws.ToString(part.ChecksumCRC64NVME)
						}
						if want := base64.StdEncoding.EncodeToString(digest); gotChecksum != want {
							t.Errorf("part %d checksum = %q, want %q", partNumber, gotChecksum, want)
						}
						parts = append(parts, types.CompletedPart{
							PartNumber: aws.Int32(partNumber), ETag: part.ETag,
							ChecksumCRC32: part.ChecksumCRC32, ChecksumCRC64NVME: part.ChecksumCRC64NVME,
						})
					}
					completeInput := &s3.CompleteMultipartUploadInput{
						Bucket: aws.String(bucket), Key: aws.String(key), UploadId: created.UploadId,
						MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
						ChecksumType:    test.checksumType,
						MpuObjectSize:   aws.Int64(int64(len(payload))),
					}
					wantChecksum := base64.StdEncoding.EncodeToString(multipartChecksumDigest(test.algorithm, payload))
					if test.checksumType == types.ChecksumTypeComposite {
						wantChecksum = fmt.Sprintf("%s-%d", base64.StdEncoding.EncodeToString(multipartChecksumDigest(test.algorithm, partChecksums)), len(parts))
					} else {
						completeInput.ChecksumCRC64NVME = aws.String(wantChecksum)
					}
					completed, err := gatewayS3.CompleteMultipartUpload(ctx, completeInput)
					if err != nil {
						t.Fatalf("complete multipart upload: %v", err)
					}
					gotChecksum := aws.ToString(completed.ChecksumCRC32)
					if test.algorithm == types.ChecksumAlgorithmCrc64nvme {
						gotChecksum = aws.ToString(completed.ChecksumCRC64NVME)
					}
					if gotChecksum != wantChecksum {
						t.Errorf("completed checksum = %q, want %q", gotChecksum, wantChecksum)
					}
					// MinIO omits ChecksumType from its completion response. Its
					// stored object must still retain the requested checksum mode.
					if completed.ChecksumType != "" && completed.ChecksumType != test.checksumType {
						t.Errorf("completed checksum type = %s, want %s", completed.ChecksumType, test.checksumType)
					}
					head, err := gatewayS3.HeadObject(ctx, &s3.HeadObjectInput{
						Bucket: aws.String(bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled,
					})
					if err != nil {
						t.Fatalf("head completed object: %v", err)
					}
					gotChecksum = aws.ToString(head.ChecksumCRC32)
					if test.algorithm == types.ChecksumAlgorithmCrc64nvme {
						gotChecksum = aws.ToString(head.ChecksumCRC64NVME)
					}
					if gotChecksum != wantChecksum || head.ChecksumType != test.checksumType {
						t.Errorf("stored checksum = %q/%s, want %q/%s", gotChecksum, head.ChecksumType, wantChecksum, test.checksumType)
					}
					assertMultipartContents(t, ctx, gatewayS3, bucket, key, payload)
					assertMultipartContents(t, ctx, upstreamS3, bucket, key, payload)
				})
			}

			t.Run("boto3-upload-file", func(t *testing.T) {
				python := os.Getenv("S3GATEWAY_BOTO3_PYTHON")
				if python == "" {
					t.Skip("set S3GATEWAY_BOTO3_PYTHON to a Python interpreter with boto3[crt] for the upload_file smoke test")
				}
				filename := filepath.Join(t.TempDir(), "multipart.bin")
				if err := os.WriteFile(filename, payload, 0o600); err != nil {
					t.Fatalf("write upload file: %v", err)
				}
				caFile := ""
				if transport == "https" {
					caFile = filepath.Join(t.TempDir(), "gateway-ca.pem")
					certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: gateway.Certificate().Raw})
					if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
						t.Fatalf("write gateway CA: %v", err)
					}
				}
				t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "unavailable"))
				command := exec.CommandContext(ctx, python, "-c", boto3MultipartChecksumScript)
				command.Env = append(os.Environ(),
					"S3GATEWAY_TEST_ENDPOINT="+gateway.URL,
					"S3GATEWAY_TEST_ACCESS_KEY="+accessKey,
					"S3GATEWAY_TEST_SECRET_KEY="+secretKey,
					"S3GATEWAY_TEST_BUCKET="+bucket,
					"S3GATEWAY_TEST_FILE="+filename,
					"S3GATEWAY_TEST_PREFIX="+transport+"/boto3/",
					"S3GATEWAY_TEST_CA="+caFile,
				)
				output, err := command.CombinedOutput()
				if err != nil {
					t.Fatalf("boto3 upload_file: %v\n%s", err, output)
				}
				t.Log(strings.TrimSpace(string(output)))
				for _, name := range []string{"default", "crc32", "crc64nvme"} {
					assertMultipartContents(t, ctx, gatewayS3, bucket, transport+"/boto3/"+name+".bin", payload)
				}
			})
		})
	}
}

func multipartChecksumDigest(algorithm types.ChecksumAlgorithm, payload []byte) []byte {
	if algorithm == types.ChecksumAlgorithmCrc64nvme {
		hash := crc64.New(crc64.MakeTable(0x9a6c9329ac4bc9b5))
		_, _ = hash.Write(payload)
		return hash.Sum(nil)
	}
	hash := crc32.NewIEEE()
	_, _ = hash.Write(payload)
	return hash.Sum(nil)
}

func assertMultipartContents(t *testing.T, ctx context.Context, client *s3.Client, bucket, key string, payload []byte) {
	t.Helper()
	object, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket), Key: aws.String(key), ChecksumMode: types.ChecksumModeEnabled,
	})
	if err != nil {
		t.Fatalf("get multipart object %q: %v", key, err)
	}
	defer object.Body.Close()
	stored, err := io.ReadAll(object.Body)
	if err != nil {
		t.Fatalf("read multipart object %q: %v", key, err)
	}
	if !bytes.Equal(stored, payload) {
		t.Fatalf("multipart object %q differs from uploaded payload: got %d bytes, want %d", key, len(stored), len(payload))
	}
}

const boto3MultipartChecksumScript = `
import os
import boto3
import botocore
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

client = boto3.client(
    "s3", endpoint_url=os.environ["S3GATEWAY_TEST_ENDPOINT"], region_name="us-east-1",
    aws_access_key_id=os.environ["S3GATEWAY_TEST_ACCESS_KEY"],
    aws_secret_access_key=os.environ["S3GATEWAY_TEST_SECRET_KEY"],
    verify=os.environ["S3GATEWAY_TEST_CA"] or True,
    config=Config(s3={"addressing_style": "path"}),
)
transfer = TransferConfig(multipart_threshold=8*1024*1024, multipart_chunksize=8*1024*1024,
                          max_concurrency=2, preferred_transfer_client="classic")
print("boto3=" + boto3.__version__ + " botocore=" + botocore.__version__)
for name, extra in [
    ("default", {}),
    ("crc32", {"ChecksumAlgorithm": "CRC32", "ChecksumType": "COMPOSITE"}),
    ("crc64nvme", {"ChecksumAlgorithm": "CRC64NVME", "ChecksumType": "FULL_OBJECT"}),
]:
    client.upload_file(os.environ["S3GATEWAY_TEST_FILE"], os.environ["S3GATEWAY_TEST_BUCKET"],
                       os.environ["S3GATEWAY_TEST_PREFIX"] + name + ".bin",
                       ExtraArgs=extra, Config=transfer)
    print(name + " upload_file succeeded")
`
