package main_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	s3gateway "github.com/define42/s3gateway"
	minio "github.com/minio/minio-go/v7"
	minioCredentials "github.com/minio/minio-go/v7/pkg/credentials"
)

func TestBootS3GatewayFullIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := s3gateway.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := s3gateway.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := s3gateway.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_BASE_DN", "dc=glauth,dc=com")
	t.Setenv("LDAP_DOMAIN", "example.com")
	t.Setenv("LDAP_GROUP_TTL", "45s")
	t.Setenv("LDAP_GROUP_CACHE_MAX_ENTRIES", "256")
	t.Setenv("S3_ENDPOINT", minioURL)
	t.Setenv("S3_REGION", "us-east-1")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
	t.Setenv("S3_FORCE_PATH_STYLE", "true")
	t.Setenv("SIGV4_SECRET", "password")
	t.Setenv("SIGV4_SERVICE", "s3")
	t.Setenv("SIGV4_MAX_SKEW", "20m")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "3s")
	t.Setenv("HTTP_IDLE_TIMEOUT", "11s")
	t.Setenv("HTTP_SHUTDOWN_TIMEOUT", "13s")
	t.Setenv("HTTP_MAX_HEADER_BYTES", "65536")

	httpSrv, cfg, err := s3gateway.BootS3Gateway()
	if err != nil {
		t.Fatalf("bootS3Gateway returned error: %v", err)
	}

	if cfg.LDAPURL != ldapURL {
		t.Fatalf("cfg.LDAPURL mismatch: got=%q want=%q", cfg.LDAPURL, ldapURL)
	}
	if cfg.UpstreamEndpoint != minioURL {
		t.Fatalf("cfg.UpstreamEndpoint mismatch: got=%q want=%q", cfg.UpstreamEndpoint, minioURL)
	}
	if cfg.GroupCacheMaxEntries != 256 {
		t.Fatalf("cfg.GroupCacheMaxEntries mismatch: got=%d want=256", cfg.GroupCacheMaxEntries)
	}
	if cfg.SigV4MaxSkew != 20*time.Minute {
		t.Fatalf("cfg.SigV4MaxSkew mismatch: got=%s want=20m", cfg.SigV4MaxSkew)
	}
	if cfg.ReadHeaderTimeout != 3*time.Second {
		t.Fatalf("cfg.ReadHeaderTimeout mismatch: got=%s want=3s", cfg.ReadHeaderTimeout)
	}
	if cfg.IdleTimeout != 11*time.Second {
		t.Fatalf("cfg.IdleTimeout mismatch: got=%s want=11s", cfg.IdleTimeout)
	}
	if cfg.ShutdownTimeout != 13*time.Second {
		t.Fatalf("cfg.ShutdownTimeout mismatch: got=%s want=13s", cfg.ShutdownTimeout)
	}
	if cfg.MaxHeaderBytes != 65536 {
		t.Fatalf("cfg.MaxHeaderBytes mismatch: got=%d want=65536", cfg.MaxHeaderBytes)
	}
	if httpSrv.Handler == nil {
		t.Fatalf("booted server handler should not be nil")
	}
	if httpSrv.ReadHeaderTimeout != cfg.ReadHeaderTimeout {
		t.Fatalf("http server read header timeout mismatch: got=%s want=%s", httpSrv.ReadHeaderTimeout, cfg.ReadHeaderTimeout)
	}
	if httpSrv.IdleTimeout != cfg.IdleTimeout {
		t.Fatalf("http server idle timeout mismatch: got=%s want=%s", httpSrv.IdleTimeout, cfg.IdleTimeout)
	}
	if httpSrv.MaxHeaderBytes != cfg.MaxHeaderBytes {
		t.Fatalf("http server max header bytes mismatch: got=%d want=%d", httpSrv.MaxHeaderBytes, cfg.MaxHeaderBytes)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for booted gateway: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpSrv.Serve(ln)
	}()
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("shutdown booted gateway: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("booted gateway serve error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("timeout waiting for booted gateway to stop")
		}
	})

	gatewayURL := "http://" + ln.Addr().String()
	waitForGatewayReady(t, gatewayURL)
	for _, probePath := range []string{"/healthz", "/readyz"} {
		req, err := http.NewRequest(http.MethodGet, gatewayURL+probePath, nil)
		if err != nil {
			t.Fatalf("build %s request: %v", probePath, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s request failed: %v", probePath, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status mismatch: got=%d want=%d", probePath, resp.StatusCode, http.StatusOK)
		}
	}

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))

	rwClient := s3gateway.NewS3Client(t, ctx, gatewayURL, "us-east-1", rwAccessKey, cfg.SigV4Secret)
	roClient := s3gateway.NewS3Client(t, ctx, gatewayURL, "us-east-1", roAccessKey, cfg.SigV4Secret)
	upstreamClient := s3gateway.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)
	parsedGatewayURL, err := url.Parse(gatewayURL)
	if err != nil {
		t.Fatalf("parse gateway url %q: %v", gatewayURL, err)
	}
	minioGatewayClient, err := minio.New(parsedGatewayURL.Host, &minio.Options{
		Creds:        minioCredentials.NewStaticV4(rwAccessKey, cfg.SigV4Secret, ""),
		Secure:       strings.EqualFold(parsedGatewayURL.Scheme, "https"),
		Region:       "us-east-1",
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("init minio gateway client: %v", err)
	}

	bucket := fmt.Sprintf("team2-boot-%d", time.Now().UnixNano())
	key := "boot/object.txt"
	sseKey := "boot/object-sse-aes256.txt"
	getPartKey := "boot/object-multipart-parts.txt"
	mpuKey := "boot/multipart/pending.bin"
	payload := []byte("bootS3Gateway integration payload")
	ssePayload := []byte("bootS3Gateway integration payload (sse aes256)")

	if _, err := rwClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket through booted gateway: %v", err)
	}
	t.Cleanup(func() {
		_, _ = rwClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		_, _ = rwClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(sseKey),
		})
		_, _ = rwClient.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(getPartKey),
		})
		_, _ = rwClient.DeleteBucket(ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(bucket),
		})
	})

	if _, err := roClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(fmt.Sprintf("team2-boot-ro-%d", time.Now().UnixNano())),
	}); err == nil {
		t.Fatalf("expected readonly CreateBucket to fail")
	} else {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected smithy api error for readonly create bucket, got: %v", err)
		}
		if apiErr.ErrorCode() != "AccessDenied" {
			t.Fatalf("readonly CreateBucket error code mismatch: got=%q want=%q", apiErr.ErrorCode(), "AccessDenied")
		}
	}

	if _, err := rwClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		t.Fatalf("put object through booted gateway: %v", err)
	}

	assertAccessDenied := func(label string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("expected %s to fail with AccessDenied", label)
		}
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected smithy api error for %s, got: %v", label, err)
		}
		if apiErr.ErrorCode() != "AccessDenied" {
			t.Fatalf("%s error code mismatch: got=%q want=%q", label, apiErr.ErrorCode(), "AccessDenied")
		}
	}
	tagSetSig := func(tags []s3types.Tag) []string {
		out := make([]string, 0, len(tags))
		for _, tag := range tags {
			out = append(out, fmt.Sprintf("%s=%s", aws.ToString(tag.Key), aws.ToString(tag.Value)))
		}
		sort.Strings(out)
		return out
	}
	assertTagSetMatches := func(label string, got, want []s3types.Tag) {
		t.Helper()
		if gotSig, wantSig := fmt.Sprintf("%v", tagSetSig(got)), fmt.Sprintf("%v", tagSetSig(want)); gotSig != wantSig {
			t.Fatalf("%s tag set mismatch: got=%q want=%q", label, gotSig, wantSig)
		}
	}

	bucketTagging := &s3types.Tagging{
		TagSet: []s3types.Tag{
			{Key: aws.String("scope"), Value: aws.String("boot")},
			{Key: aws.String("suite"), Value: aws.String("integration")},
		},
	}
	if _, err := rwClient.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket:  aws.String(bucket),
		Tagging: bucketTagging,
	}); err != nil {
		t.Fatalf("put bucket tagging through booted gateway: %v", err)
	}
	if _, err := roClient.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{
		Bucket:  aws.String(bucket),
		Tagging: bucketTagging,
	}); err == nil {
		t.Fatalf("expected readonly PutBucketTagging to fail")
	} else {
		assertAccessDenied("readonly PutBucketTagging", err)
	}

	gatewayBucketTaggingOut, err := rwClient.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("get bucket tagging through booted gateway: %v", err)
	}
	upstreamBucketTaggingOut, err := upstreamClient.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("get bucket tagging from upstream: %v", err)
	}
	assertTagSetMatches("bucket tagging gateway vs upstream", gatewayBucketTaggingOut.TagSet, upstreamBucketTaggingOut.TagSet)
	assertTagSetMatches("bucket tagging gateway vs expected", gatewayBucketTaggingOut.TagSet, bucketTagging.TagSet)

	roBucketTaggingOut, err := roClient.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("readonly get bucket tagging through booted gateway: %v", err)
	}
	assertTagSetMatches("readonly bucket tagging vs expected", roBucketTaggingOut.TagSet, bucketTagging.TagSet)

	objectTagging := &s3types.Tagging{
		TagSet: []s3types.Tag{
			{Key: aws.String("kind"), Value: aws.String("document")},
			{Key: aws.String("owner"), Value: aws.String("testuser")},
		},
	}
	if _, err := rwClient.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket:  aws.String(bucket),
		Key:     aws.String(key),
		Tagging: objectTagging,
	}); err != nil {
		t.Fatalf("put object tagging through booted gateway: %v", err)
	}
	if _, err := roClient.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket:  aws.String(bucket),
		Key:     aws.String(key),
		Tagging: objectTagging,
	}); err == nil {
		t.Fatalf("expected readonly PutObjectTagging to fail")
	} else {
		assertAccessDenied("readonly PutObjectTagging", err)
	}

	gatewayObjectTaggingOut, err := rwClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object tagging through booted gateway: %v", err)
	}
	upstreamObjectTaggingOut, err := upstreamClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object tagging from upstream: %v", err)
	}
	assertTagSetMatches("object tagging gateway vs upstream", gatewayObjectTaggingOut.TagSet, upstreamObjectTaggingOut.TagSet)
	assertTagSetMatches("object tagging gateway vs expected", gatewayObjectTaggingOut.TagSet, objectTagging.TagSet)

	roObjectTaggingOut, err := roClient.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("readonly get object tagging through booted gateway: %v", err)
	}
	assertTagSetMatches("readonly object tagging vs expected", roObjectTaggingOut.TagSet, objectTagging.TagSet)

	newSSEPutInput := func() *s3.PutObjectInput {
		return &s3.PutObjectInput{
			Bucket:               aws.String(bucket),
			Key:                  aws.String(sseKey),
			Body:                 bytes.NewReader(ssePayload),
			ContentLength:        aws.Int64(int64(len(ssePayload))),
			ContentType:          aws.String("text/plain"),
			ServerSideEncryption: s3types.ServerSideEncryptionAes256,
		}
	}
	upstreamSSEPutOut, upstreamSSEPutErr := upstreamClient.PutObject(ctx, newSSEPutInput())
	gatewaySSEPutOut, gatewaySSEPutErr := rwClient.PutObject(ctx, newSSEPutInput())
	if (upstreamSSEPutErr != nil) != (gatewaySSEPutErr != nil) {
		t.Fatalf("put object with sse-aes256 error mismatch: gatewayErr=%v upstreamErr=%v", gatewaySSEPutErr, upstreamSSEPutErr)
	}
	if upstreamSSEPutErr != nil {
		var upstreamAPIErr smithy.APIError
		var gatewayAPIErr smithy.APIError
		if !errors.As(upstreamSSEPutErr, &upstreamAPIErr) || !errors.As(gatewaySSEPutErr, &gatewayAPIErr) {
			t.Fatalf("put object with sse-aes256 expected smithy errors: gatewayErr=%v upstreamErr=%v", gatewaySSEPutErr, upstreamSSEPutErr)
		}
		if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
			t.Fatalf("put object with sse-aes256 error code mismatch: gateway=%q upstream=%q", gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
		}
	} else {
		if gatewaySSEPutOut.ServerSideEncryption != upstreamSSEPutOut.ServerSideEncryption {
			t.Fatalf("put object with sse-aes256 response encryption mismatch: gateway=%q upstream=%q", gatewaySSEPutOut.ServerSideEncryption, upstreamSSEPutOut.ServerSideEncryption)
		}
		if gatewaySSEPutOut.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
			t.Fatalf("put object with sse-aes256 response encryption mismatch: got=%q want=%q", gatewaySSEPutOut.ServerSideEncryption, s3types.ServerSideEncryptionAes256)
		}
		gatewaySSEHead, err := rwClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(sseKey),
		})
		if err != nil {
			t.Fatalf("head sse-aes256 object through booted gateway: %v", err)
		}
		upstreamSSEHead, err := upstreamClient.HeadObject(ctx, &s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(sseKey),
		})
		if err != nil {
			t.Fatalf("head sse-aes256 object from upstream: %v", err)
		}
		if aws.ToInt64(gatewaySSEHead.ContentLength) != int64(len(ssePayload)) {
			t.Fatalf("gateway sse-aes256 head content length mismatch: got=%d want=%d", aws.ToInt64(gatewaySSEHead.ContentLength), len(ssePayload))
		}
		if aws.ToInt64(upstreamSSEHead.ContentLength) != int64(len(ssePayload)) {
			t.Fatalf("upstream sse-aes256 head content length mismatch: got=%d want=%d", aws.ToInt64(upstreamSSEHead.ContentLength), len(ssePayload))
		}
		if gatewaySSEHead.ServerSideEncryption != upstreamSSEHead.ServerSideEncryption {
			t.Fatalf("head sse-aes256 encryption mismatch: gateway=%q upstream=%q", gatewaySSEHead.ServerSideEncryption, upstreamSSEHead.ServerSideEncryption)
		}
		if gatewaySSEHead.ServerSideEncryption != s3types.ServerSideEncryptionAes256 {
			t.Fatalf("head sse-aes256 encryption mismatch: got=%q want=%q", gatewaySSEHead.ServerSideEncryption, s3types.ServerSideEncryptionAes256)
		}
	}

	newListInputWithOptionalAttrs := func() *s3.ListObjectsV2Input {
		return &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
			Prefix: aws.String("boot/"),
			OptionalObjectAttributes: []s3types.OptionalObjectAttributes{
				s3types.OptionalObjectAttributesRestoreStatus,
			},
		}
	}
	upstreamListWithOptionalAttrs, upstreamListWithOptionalAttrsErr := upstreamClient.ListObjectsV2(ctx, newListInputWithOptionalAttrs())
	gatewayListWithOptionalAttrs, gatewayListWithOptionalAttrsErr := rwClient.ListObjectsV2(ctx, newListInputWithOptionalAttrs())
	if (upstreamListWithOptionalAttrsErr != nil) != (gatewayListWithOptionalAttrsErr != nil) {
		t.Fatalf("list objects v2 with optional-object-attributes error mismatch: gatewayErr=%v upstreamErr=%v", gatewayListWithOptionalAttrsErr, upstreamListWithOptionalAttrsErr)
	}
	if upstreamListWithOptionalAttrsErr != nil {
		var upstreamAPIErr smithy.APIError
		var gatewayAPIErr smithy.APIError
		if !errors.As(upstreamListWithOptionalAttrsErr, &upstreamAPIErr) || !errors.As(gatewayListWithOptionalAttrsErr, &gatewayAPIErr) {
			t.Fatalf("list objects v2 with optional-object-attributes expected smithy errors: gatewayErr=%v upstreamErr=%v", gatewayListWithOptionalAttrsErr, upstreamListWithOptionalAttrsErr)
		}
		if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
			t.Fatalf("list objects v2 with optional-object-attributes error code mismatch: gateway=%q upstream=%q", gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
		}
	} else {
		makeObjectSigs := func(objs []s3types.Object) []string {
			out := make([]string, 0, len(objs))
			for _, o := range objs {
				restoreInProgress := "<nil>"
				restoreExpiry := "<nil>"
				if o.RestoreStatus != nil {
					if o.RestoreStatus.IsRestoreInProgress != nil {
						restoreInProgress = fmt.Sprintf("%t", aws.ToBool(o.RestoreStatus.IsRestoreInProgress))
					}
					if o.RestoreStatus.RestoreExpiryDate != nil {
						restoreExpiry = o.RestoreStatus.RestoreExpiryDate.UTC().Format(time.RFC3339Nano)
					}
				}
				out = append(out, fmt.Sprintf(
					"%s|%d|%s|%s",
					aws.ToString(o.Key),
					aws.ToInt64(o.Size),
					restoreInProgress,
					restoreExpiry,
				))
			}
			sort.Strings(out)
			return out
		}
		if got, want := fmt.Sprintf(
			"%v|%v|%v",
			makeObjectSigs(gatewayListWithOptionalAttrs.Contents),
			aws.ToInt32(gatewayListWithOptionalAttrs.KeyCount),
			aws.ToBool(gatewayListWithOptionalAttrs.IsTruncated),
		), fmt.Sprintf(
			"%v|%v|%v",
			makeObjectSigs(upstreamListWithOptionalAttrs.Contents),
			aws.ToInt32(upstreamListWithOptionalAttrs.KeyCount),
			aws.ToBool(upstreamListWithOptionalAttrs.IsTruncated),
		); got != want {
			t.Fatalf("list objects v2 with optional-object-attributes mismatch: gateway=%q upstream=%q", got, want)
		}
	}

	minioListOpts := minio.ListObjectsOptions{
		Prefix:    "boot/",
		Recursive: true,
	}
	minioListOpts.Set("x-amz-optional-object-attributes", string(s3types.OptionalObjectAttributesRestoreStatus))
	minioSeen := map[string]bool{}
	for obj := range minioGatewayClient.ListObjects(ctx, bucket, minioListOpts) {
		if obj.Err != nil {
			t.Fatalf("minio list objects with optional attributes via gateway: %v", obj.Err)
		}
		minioSeen[obj.Key] = true
	}
	if !minioSeen[key] {
		t.Fatalf("minio list objects via gateway missing %q; got=%v", key, minioSeen)
	}

	mpuCreateOut, err := rwClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(mpuKey),
	})
	if err != nil {
		t.Fatalf("create multipart upload through booted gateway: %v", err)
	}
	if mpuCreateOut.UploadId == nil || *mpuCreateOut.UploadId == "" {
		t.Fatalf("create multipart upload should return non-empty upload id")
	}
	mpuPartBody := []byte("x")
	if _, err := rwClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(mpuKey),
		UploadId:      mpuCreateOut.UploadId,
		PartNumber:    aws.Int32(1),
		Body:          bytes.NewReader(mpuPartBody),
		ContentLength: aws.Int64(int64(len(mpuPartBody))),
	}); err != nil {
		t.Fatalf("upload part for multipart upload through booted gateway: %v", err)
	}
	t.Cleanup(func() {
		_, _ = rwClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(mpuKey),
			UploadId: mpuCreateOut.UploadId,
		})
	})

	var upstreamMPUList *s3.ListMultipartUploadsOutput
	var gatewayMPUList *s3.ListMultipartUploadsOutput
	listDeadline := time.Now().Add(10 * time.Second)
	for {
		upstreamMPUList, err = upstreamClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			t.Fatalf("list multipart uploads from upstream: %v", err)
		}
		gatewayMPUList, err = rwClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			t.Fatalf("list multipart uploads through booted gateway: %v", err)
		}
		if len(upstreamMPUList.Uploads) > 0 && len(gatewayMPUList.Uploads) > 0 {
			break
		}
		if time.Now().After(listDeadline) {
			t.Fatalf("multipart upload not visible in list within timeout: upstreamUploads=%d gatewayUploads=%d", len(upstreamMPUList.Uploads), len(gatewayMPUList.Uploads))
		}
		time.Sleep(100 * time.Millisecond)
	}

	findUploadByKey := func(out *s3.ListMultipartUploadsOutput, wantKey string) *s3types.MultipartUpload {
		for i := range out.Uploads {
			u := out.Uploads[i]
			if aws.ToString(u.Key) == wantKey {
				return &out.Uploads[i]
			}
		}
		return nil
	}

	upstreamUpload := findUploadByKey(upstreamMPUList, mpuKey)
	if upstreamUpload == nil {
		t.Fatalf("upstream list multipart uploads missing expected upload key=%q", mpuKey)
	}
	if upstreamUpload.Initiator == nil {
		t.Fatalf("upstream multipart upload initiator should not be nil for key=%q", mpuKey)
	}

	gatewayUpload := findUploadByKey(gatewayMPUList, mpuKey)
	if gatewayUpload == nil {
		t.Fatalf("gateway list multipart uploads missing expected upload key=%q", mpuKey)
	}
	if gatewayUpload.Initiator == nil {
		t.Fatalf("gateway multipart upload initiator should not be nil for key=%q", mpuKey)
	}
	if aws.ToString(gatewayUpload.Initiator.ID) != aws.ToString(upstreamUpload.Initiator.ID) {
		t.Fatalf("multipart upload initiator id mismatch: gateway=%q upstream=%q", aws.ToString(gatewayUpload.Initiator.ID), aws.ToString(upstreamUpload.Initiator.ID))
	}
	if aws.ToString(gatewayUpload.Initiator.DisplayName) != aws.ToString(upstreamUpload.Initiator.DisplayName) {
		t.Fatalf("multipart upload initiator display name mismatch: gateway=%q upstream=%q", aws.ToString(gatewayUpload.Initiator.DisplayName), aws.ToString(upstreamUpload.Initiator.DisplayName))
	}

	part1Body := bytes.Repeat([]byte("p"), 5*1024*1024)
	part2Body := []byte("tail-part-2")
	getPartCreateOut, err := rwClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(getPartKey),
	})
	if err != nil {
		t.Fatalf("create multipart upload for get-object partNumber through booted gateway: %v", err)
	}
	getPartCompleted := false
	t.Cleanup(func() {
		if getPartCompleted {
			return
		}
		_, _ = rwClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(bucket),
			Key:      aws.String(getPartKey),
			UploadId: getPartCreateOut.UploadId,
		})
	})
	getPart1Out, err := rwClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(getPartKey),
		UploadId:      getPartCreateOut.UploadId,
		PartNumber:    aws.Int32(1),
		Body:          bytes.NewReader(part1Body),
		ContentLength: aws.Int64(int64(len(part1Body))),
	})
	if err != nil {
		t.Fatalf("upload part 1 for get-object partNumber through booted gateway: %v", err)
	}
	getPart2Out, err := rwClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(getPartKey),
		UploadId:      getPartCreateOut.UploadId,
		PartNumber:    aws.Int32(2),
		Body:          bytes.NewReader(part2Body),
		ContentLength: aws.Int64(int64(len(part2Body))),
	})
	if err != nil {
		t.Fatalf("upload part 2 for get-object partNumber through booted gateway: %v", err)
	}
	if _, err := rwClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(getPartKey),
		UploadId: getPartCreateOut.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: []s3types.CompletedPart{
				{PartNumber: aws.Int32(1), ETag: getPart1Out.ETag},
				{PartNumber: aws.Int32(2), ETag: getPart2Out.ETag},
			},
		},
	}); err != nil {
		t.Fatalf("complete multipart upload for get-object partNumber through booted gateway: %v", err)
	}
	getPartCompleted = true

	assertGetObjectPartMatchesUpstream := func(partNumber int32, wantBody []byte) {
		t.Helper()
		upstreamPartOut, upstreamPartErr := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:     aws.String(bucket),
			Key:        aws.String(getPartKey),
			PartNumber: aws.Int32(partNumber),
		})
		gatewayPartOut, gatewayPartErr := rwClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:     aws.String(bucket),
			Key:        aws.String(getPartKey),
			PartNumber: aws.Int32(partNumber),
		})
		if (upstreamPartErr != nil) != (gatewayPartErr != nil) {
			t.Fatalf("get object with partNumber=%d error mismatch: gatewayErr=%v upstreamErr=%v", partNumber, gatewayPartErr, upstreamPartErr)
		}
		if upstreamPartErr != nil {
			var upstreamAPIErr smithy.APIError
			var gatewayAPIErr smithy.APIError
			if !errors.As(upstreamPartErr, &upstreamAPIErr) || !errors.As(gatewayPartErr, &gatewayAPIErr) {
				t.Fatalf("get object with partNumber=%d expected smithy errors: gatewayErr=%v upstreamErr=%v", partNumber, gatewayPartErr, upstreamPartErr)
			}
			if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
				t.Fatalf("get object with partNumber=%d error code mismatch: gateway=%q upstream=%q", partNumber, gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
			}
			return
		}
		defer upstreamPartOut.Body.Close()
		defer gatewayPartOut.Body.Close()

		upstreamPartBody, err := io.ReadAll(upstreamPartOut.Body)
		if err != nil {
			t.Fatalf("read upstream get object partNumber=%d body: %v", partNumber, err)
		}
		gatewayPartBody, err := io.ReadAll(gatewayPartOut.Body)
		if err != nil {
			t.Fatalf("read gateway get object partNumber=%d body: %v", partNumber, err)
		}
		if !bytes.Equal(gatewayPartBody, upstreamPartBody) {
			t.Fatalf("get object partNumber=%d body mismatch between gateway and upstream", partNumber)
		}
		if !bytes.Equal(gatewayPartBody, wantBody) {
			t.Fatalf("get object partNumber=%d body mismatch: gotLen=%d wantLen=%d", partNumber, len(gatewayPartBody), len(wantBody))
		}
		if aws.ToInt64(gatewayPartOut.ContentLength) != aws.ToInt64(upstreamPartOut.ContentLength) {
			t.Fatalf("get object partNumber=%d content-length mismatch: gateway=%d upstream=%d", partNumber, aws.ToInt64(gatewayPartOut.ContentLength), aws.ToInt64(upstreamPartOut.ContentLength))
		}
		if aws.ToInt32(gatewayPartOut.PartsCount) != aws.ToInt32(upstreamPartOut.PartsCount) {
			t.Fatalf("get object partNumber=%d parts-count mismatch: gateway=%d upstream=%d", partNumber, aws.ToInt32(gatewayPartOut.PartsCount), aws.ToInt32(upstreamPartOut.PartsCount))
		}
	}
	assertGetObjectPartMatchesUpstream(1, part1Body)
	assertGetObjectPartMatchesUpstream(2, part2Body)

	getPartHead, err := upstreamClient.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(getPartKey),
	})
	if err != nil {
		t.Fatalf("head multipart object for get-object conditionals from upstream: %v", err)
	}
	if getPartHead.ETag == nil || *getPartHead.ETag == "" {
		t.Fatalf("multipart object etag for get-object conditionals should be non-empty")
	}
	multipartETag := *getPartHead.ETag
	nonMatchingETag := "\"00000000000000000000000000000000\""
	farPast := time.Unix(0, 0).UTC()
	farFuture := time.Now().Add(24 * time.Hour).UTC()
	assertConditionalGetObjectPartMatchesUpstream := func(
		label string,
		expectErr bool,
		mutate func(*s3.GetObjectInput),
	) {
		t.Helper()
		newInput := func() *s3.GetObjectInput {
			in := &s3.GetObjectInput{
				Bucket:     aws.String(bucket),
				Key:        aws.String(getPartKey),
				PartNumber: aws.Int32(1),
			}
			mutate(in)
			return in
		}
		upstreamPartOut, upstreamPartErr := upstreamClient.GetObject(ctx, newInput())
		gatewayPartOut, gatewayPartErr := rwClient.GetObject(ctx, newInput())
		if (upstreamPartErr != nil) != (gatewayPartErr != nil) {
			t.Fatalf("%s get object with partNumber error mismatch: gatewayErr=%v upstreamErr=%v", label, gatewayPartErr, upstreamPartErr)
		}
		if expectErr != (upstreamPartErr != nil) {
			t.Fatalf("%s get object with partNumber error expectation mismatch: gotErr=%v wantErr=%v", label, upstreamPartErr != nil, expectErr)
		}
		if upstreamPartErr != nil {
			var upstreamAPIErr smithy.APIError
			var gatewayAPIErr smithy.APIError
			if !errors.As(upstreamPartErr, &upstreamAPIErr) || !errors.As(gatewayPartErr, &gatewayAPIErr) {
				t.Fatalf("%s get object with partNumber expected smithy errors: gatewayErr=%v upstreamErr=%v", label, gatewayPartErr, upstreamPartErr)
			}
			if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
				t.Fatalf("%s get object with partNumber error code mismatch: gateway=%q upstream=%q", label, gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
			}
			return
		}
		defer upstreamPartOut.Body.Close()
		defer gatewayPartOut.Body.Close()

		upstreamPartBody, err := io.ReadAll(upstreamPartOut.Body)
		if err != nil {
			t.Fatalf("%s read upstream get object with partNumber body: %v", label, err)
		}
		gatewayPartBody, err := io.ReadAll(gatewayPartOut.Body)
		if err != nil {
			t.Fatalf("%s read gateway get object with partNumber body: %v", label, err)
		}
		if !bytes.Equal(gatewayPartBody, upstreamPartBody) {
			t.Fatalf("%s get object with partNumber body mismatch between gateway and upstream", label)
		}
		if !bytes.Equal(gatewayPartBody, part1Body) {
			t.Fatalf("%s get object with partNumber body mismatch: gotLen=%d wantLen=%d", label, len(gatewayPartBody), len(part1Body))
		}
		if aws.ToInt64(gatewayPartOut.ContentLength) != aws.ToInt64(upstreamPartOut.ContentLength) {
			t.Fatalf("%s get object with partNumber content-length mismatch: gateway=%d upstream=%d", label, aws.ToInt64(gatewayPartOut.ContentLength), aws.ToInt64(upstreamPartOut.ContentLength))
		}
	}
	assertConditionalGetObjectPartMatchesUpstream(
		"If-Match match",
		false,
		func(in *s3.GetObjectInput) {
			in.IfMatch = aws.String(multipartETag)
		},
	)
	assertConditionalGetObjectPartMatchesUpstream(
		"If-Match mismatch",
		true,
		func(in *s3.GetObjectInput) {
			in.IfMatch = aws.String(nonMatchingETag)
		},
	)
	assertConditionalGetObjectPartMatchesUpstream(
		"If-None-Match match",
		true,
		func(in *s3.GetObjectInput) {
			in.IfNoneMatch = aws.String(multipartETag)
		},
	)
	assertConditionalGetObjectPartMatchesUpstream(
		"If-None-Match mismatch",
		false,
		func(in *s3.GetObjectInput) {
			in.IfNoneMatch = aws.String(nonMatchingETag)
		},
	)
	assertConditionalGetObjectPartMatchesUpstream(
		"If-Modified-Since old",
		false,
		func(in *s3.GetObjectInput) {
			in.IfModifiedSince = aws.Time(farPast)
		},
	)
	assertConditionalGetObjectPartMatchesUpstream(
		"If-Modified-Since future",
		true,
		func(in *s3.GetObjectInput) {
			in.IfModifiedSince = aws.Time(farFuture)
		},
	)
	assertConditionalGetObjectPartMatchesUpstream(
		"If-Unmodified-Since old",
		true,
		func(in *s3.GetObjectInput) {
			in.IfUnmodifiedSince = aws.Time(farPast)
		},
	)
	assertConditionalGetObjectPartMatchesUpstream(
		"If-Unmodified-Since future",
		false,
		func(in *s3.GetObjectInput) {
			in.IfUnmodifiedSince = aws.Time(farFuture)
		},
	)
	assertGetObjectPartChecksumModeMatchesUpstream := func(mode s3types.ChecksumMode) {
		t.Helper()
		upstreamPartOut, upstreamPartErr := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:       aws.String(bucket),
			Key:          aws.String(getPartKey),
			PartNumber:   aws.Int32(1),
			ChecksumMode: mode,
		})
		gatewayPartOut, gatewayPartErr := rwClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:       aws.String(bucket),
			Key:          aws.String(getPartKey),
			PartNumber:   aws.Int32(1),
			ChecksumMode: mode,
		})
		if (upstreamPartErr != nil) != (gatewayPartErr != nil) {
			t.Fatalf("get object with partNumber and checksum-mode=%q error mismatch: gatewayErr=%v upstreamErr=%v", mode, gatewayPartErr, upstreamPartErr)
		}
		if upstreamPartErr != nil {
			var upstreamAPIErr smithy.APIError
			var gatewayAPIErr smithy.APIError
			if !errors.As(upstreamPartErr, &upstreamAPIErr) || !errors.As(gatewayPartErr, &gatewayAPIErr) {
				t.Fatalf("get object with partNumber and checksum-mode=%q expected smithy errors: gatewayErr=%v upstreamErr=%v", mode, gatewayPartErr, upstreamPartErr)
			}
			if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
				t.Fatalf("get object with partNumber and checksum-mode=%q error code mismatch: gateway=%q upstream=%q", mode, gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
			}
			return
		}
		defer upstreamPartOut.Body.Close()
		defer gatewayPartOut.Body.Close()

		upstreamPartBody, err := io.ReadAll(upstreamPartOut.Body)
		if err != nil {
			t.Fatalf("read upstream get object with partNumber and checksum-mode=%q body: %v", mode, err)
		}
		gatewayPartBody, err := io.ReadAll(gatewayPartOut.Body)
		if err != nil {
			t.Fatalf("read gateway get object with partNumber and checksum-mode=%q body: %v", mode, err)
		}
		if !bytes.Equal(gatewayPartBody, upstreamPartBody) {
			t.Fatalf("get object with partNumber and checksum-mode=%q body mismatch between gateway and upstream", mode)
		}
		if !bytes.Equal(gatewayPartBody, part1Body) {
			t.Fatalf("get object with partNumber and checksum-mode=%q body mismatch: gotLen=%d wantLen=%d", mode, len(gatewayPartBody), len(part1Body))
		}
		if aws.ToInt64(gatewayPartOut.ContentLength) != aws.ToInt64(upstreamPartOut.ContentLength) {
			t.Fatalf("get object with partNumber and checksum-mode=%q content-length mismatch: gateway=%d upstream=%d", mode, aws.ToInt64(gatewayPartOut.ContentLength), aws.ToInt64(upstreamPartOut.ContentLength))
		}
	}
	assertGetObjectPartChecksumModeMatchesUpstream(s3types.ChecksumModeEnabled)
	assertGetObjectPartExpectedOwnerMatchesUpstream := func(expectedOwner string) {
		t.Helper()
		upstreamPartOut, upstreamPartErr := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:              aws.String(bucket),
			Key:                 aws.String(getPartKey),
			PartNumber:          aws.Int32(1),
			ExpectedBucketOwner: aws.String(expectedOwner),
		})
		gatewayPartOut, gatewayPartErr := rwClient.GetObject(ctx, &s3.GetObjectInput{
			Bucket:              aws.String(bucket),
			Key:                 aws.String(getPartKey),
			PartNumber:          aws.Int32(1),
			ExpectedBucketOwner: aws.String(expectedOwner),
		})
		if (upstreamPartErr != nil) != (gatewayPartErr != nil) {
			t.Fatalf("get object with partNumber and expected-bucket-owner=%q error mismatch: gatewayErr=%v upstreamErr=%v", expectedOwner, gatewayPartErr, upstreamPartErr)
		}
		if upstreamPartErr != nil {
			var upstreamAPIErr smithy.APIError
			var gatewayAPIErr smithy.APIError
			if !errors.As(upstreamPartErr, &upstreamAPIErr) || !errors.As(gatewayPartErr, &gatewayAPIErr) {
				t.Fatalf("get object with partNumber and expected-bucket-owner=%q expected smithy errors: gatewayErr=%v upstreamErr=%v", expectedOwner, gatewayPartErr, upstreamPartErr)
			}
			if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
				t.Fatalf("get object with partNumber and expected-bucket-owner=%q error code mismatch: gateway=%q upstream=%q", expectedOwner, gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
			}
			return
		}
		defer upstreamPartOut.Body.Close()
		defer gatewayPartOut.Body.Close()

		upstreamPartBody, err := io.ReadAll(upstreamPartOut.Body)
		if err != nil {
			t.Fatalf("read upstream get object with partNumber and expected-bucket-owner=%q body: %v", expectedOwner, err)
		}
		gatewayPartBody, err := io.ReadAll(gatewayPartOut.Body)
		if err != nil {
			t.Fatalf("read gateway get object with partNumber and expected-bucket-owner=%q body: %v", expectedOwner, err)
		}
		if !bytes.Equal(gatewayPartBody, upstreamPartBody) {
			t.Fatalf("get object with partNumber and expected-bucket-owner=%q body mismatch between gateway and upstream", expectedOwner)
		}
		if !bytes.Equal(gatewayPartBody, part1Body) {
			t.Fatalf("get object with partNumber and expected-bucket-owner=%q body mismatch: gotLen=%d wantLen=%d", expectedOwner, len(gatewayPartBody), len(part1Body))
		}
		if aws.ToInt64(gatewayPartOut.ContentLength) != aws.ToInt64(upstreamPartOut.ContentLength) {
			t.Fatalf("get object with partNumber and expected-bucket-owner=%q content-length mismatch: gateway=%d upstream=%d", expectedOwner, aws.ToInt64(gatewayPartOut.ContentLength), aws.ToInt64(upstreamPartOut.ContentLength))
		}
	}
	assertGetObjectPartExpectedOwnerMatchesUpstream("123456789012")
	assertHeadObjectPartMatchesUpstream := func(
		partNumber int32,
		label string,
		expectErr bool,
		wantContentLength int64,
		mutate func(*s3.HeadObjectInput),
	) {
		t.Helper()
		newInput := func() *s3.HeadObjectInput {
			in := &s3.HeadObjectInput{
				Bucket:     aws.String(bucket),
				Key:        aws.String(getPartKey),
				PartNumber: aws.Int32(partNumber),
			}
			if mutate != nil {
				mutate(in)
			}
			return in
		}
		upstreamHeadOut, upstreamHeadErr := upstreamClient.HeadObject(ctx, newInput())
		gatewayHeadOut, gatewayHeadErr := rwClient.HeadObject(ctx, newInput())
		if (upstreamHeadErr != nil) != (gatewayHeadErr != nil) {
			t.Fatalf("%s head object with partNumber=%d error mismatch: gatewayErr=%v upstreamErr=%v", label, partNumber, gatewayHeadErr, upstreamHeadErr)
		}
		if expectErr != (upstreamHeadErr != nil) {
			t.Fatalf("%s head object with partNumber=%d error expectation mismatch: gotErr=%v wantErr=%v", label, partNumber, upstreamHeadErr != nil, expectErr)
		}
		if upstreamHeadErr != nil {
			var upstreamAPIErr smithy.APIError
			var gatewayAPIErr smithy.APIError
			if !errors.As(upstreamHeadErr, &upstreamAPIErr) || !errors.As(gatewayHeadErr, &gatewayAPIErr) {
				t.Fatalf("%s head object with partNumber=%d expected smithy errors: gatewayErr=%v upstreamErr=%v", label, partNumber, gatewayHeadErr, upstreamHeadErr)
			}
			if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
				t.Fatalf("%s head object with partNumber=%d error code mismatch: gateway=%q upstream=%q", label, partNumber, gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
			}
			return
		}
		if aws.ToInt64(gatewayHeadOut.ContentLength) != aws.ToInt64(upstreamHeadOut.ContentLength) {
			t.Fatalf("%s head object with partNumber=%d content-length mismatch: gateway=%d upstream=%d", label, partNumber, aws.ToInt64(gatewayHeadOut.ContentLength), aws.ToInt64(upstreamHeadOut.ContentLength))
		}
		if aws.ToInt64(gatewayHeadOut.ContentLength) != wantContentLength {
			t.Fatalf("%s head object with partNumber=%d content-length mismatch: got=%d want=%d", label, partNumber, aws.ToInt64(gatewayHeadOut.ContentLength), wantContentLength)
		}
		if aws.ToInt32(gatewayHeadOut.PartsCount) != aws.ToInt32(upstreamHeadOut.PartsCount) {
			t.Fatalf("%s head object with partNumber=%d parts-count mismatch: gateway=%d upstream=%d", label, partNumber, aws.ToInt32(gatewayHeadOut.PartsCount), aws.ToInt32(upstreamHeadOut.PartsCount))
		}
		if aws.ToString(gatewayHeadOut.ETag) != aws.ToString(upstreamHeadOut.ETag) {
			t.Fatalf("%s head object with partNumber=%d etag mismatch: gateway=%q upstream=%q", label, partNumber, aws.ToString(gatewayHeadOut.ETag), aws.ToString(upstreamHeadOut.ETag))
		}
	}
	assertHeadObjectPartMatchesUpstream(1, "baseline part 1", false, int64(len(part1Body)), nil)
	assertHeadObjectPartMatchesUpstream(2, "baseline part 2", false, int64(len(part2Body)), nil)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-Match match",
		false,
		int64(len(part1Body)),
		func(in *s3.HeadObjectInput) {
			in.IfMatch = aws.String(multipartETag)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-Match mismatch",
		true,
		0,
		func(in *s3.HeadObjectInput) {
			in.IfMatch = aws.String(nonMatchingETag)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-None-Match match",
		true,
		0,
		func(in *s3.HeadObjectInput) {
			in.IfNoneMatch = aws.String(multipartETag)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-None-Match mismatch",
		false,
		int64(len(part1Body)),
		func(in *s3.HeadObjectInput) {
			in.IfNoneMatch = aws.String(nonMatchingETag)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-Modified-Since old",
		false,
		int64(len(part1Body)),
		func(in *s3.HeadObjectInput) {
			in.IfModifiedSince = aws.Time(farPast)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-Modified-Since future",
		true,
		0,
		func(in *s3.HeadObjectInput) {
			in.IfModifiedSince = aws.Time(farFuture)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-Unmodified-Since old",
		true,
		0,
		func(in *s3.HeadObjectInput) {
			in.IfUnmodifiedSince = aws.Time(farPast)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"If-Unmodified-Since future",
		false,
		int64(len(part1Body)),
		func(in *s3.HeadObjectInput) {
			in.IfUnmodifiedSince = aws.Time(farFuture)
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"checksum mode enabled",
		false,
		int64(len(part1Body)),
		func(in *s3.HeadObjectInput) {
			in.ChecksumMode = s3types.ChecksumModeEnabled
		},
	)
	assertHeadObjectPartMatchesUpstream(
		1,
		"expected bucket owner",
		false,
		int64(len(part1Body)),
		func(in *s3.HeadObjectInput) {
			in.ExpectedBucketOwner = aws.String("123456789012")
		},
	)

	roObj, err := roClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("readonly get object through booted gateway: %v", err)
	}
	defer roObj.Body.Close()
	roBody, err := io.ReadAll(roObj.Body)
	if err != nil {
		t.Fatalf("read readonly object body: %v", err)
	}
	if !bytes.Equal(roBody, payload) {
		t.Fatalf("readonly object body mismatch: got=%q want=%q", string(roBody), string(payload))
	}

	upObj, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object from upstream after gateway write: %v", err)
	}
	defer upObj.Body.Close()
	upBody, err := io.ReadAll(upObj.Body)
	if err != nil {
		t.Fatalf("read upstream object body: %v", err)
	}
	if !bytes.Equal(upBody, payload) {
		t.Fatalf("upstream object body mismatch: got=%q want=%q", string(upBody), string(payload))
	}
}

func waitForGatewayReady(t *testing.T, gatewayURL string) {
	t.Helper()

	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for {
		req, err := http.NewRequest(http.MethodGet, gatewayURL+"/", nil)
		if err != nil {
			t.Fatalf("build readiness request: %v", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway did not become ready in time: lastErr=%v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
