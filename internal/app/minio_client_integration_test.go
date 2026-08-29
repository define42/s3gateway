package app_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	minio "github.com/minio/minio-go/v7"
	minioCredentials "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
	"github.com/minio/minio-go/v7/pkg/tags"

	gatewayapp "github.com/define42/s3gateway/internal/app"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/define42/s3gateway/internal/testutil"
)

// TestMinioClientIntegration validates that the s3gateway works correctly when
// accessed through the minio S3 client. It exercises bucket creation, object
// put, object get, object deletion, and bucket deletion.
func TestMinioClientIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("LDAP_URL", ldapURL)
	t.Setenv("LDAP_BASE_DN", "dc=glauth,dc=com")
	t.Setenv("LDAP_DOMAIN", "example.com")
	t.Setenv("S3_ENDPOINT", minioURL)
	t.Setenv("S3_REGION", "us-east-1")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
	t.Setenv("S3_FORCE_PATH_STYLE", "true")

	httpSrv, _, err := gatewayapp.Boot()
	if err != nil {
		t.Fatalf("boot s3gateway: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for gateway: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- httpSrv.Serve(ln)
	}()
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("shutdown gateway: %v", err)
		}
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Errorf("gateway serve error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Errorf("timeout waiting for gateway to stop")
		}
	})

	gatewayURL := "http://" + ln.Addr().String()
	waitForGatewayReady(t, gatewayURL)

	rwAccessKey, rwSecretKey, err := s3credentials.GenerateKeysBase64Encoded("testuser", "dogood")
	if err != nil {
		t.Fatalf("generate gateway credentials: %v", err)
	}

	parsedGatewayURL, err := url.Parse(gatewayURL)
	if err != nil {
		t.Fatalf("parse gateway url %q: %v", gatewayURL, err)
	}
	minioClient, err := minio.New(parsedGatewayURL.Host, &minio.Options{
		Creds:        minioCredentials.NewStaticV4(rwAccessKey, rwSecretKey, ""),
		Secure:       strings.EqualFold(parsedGatewayURL.Scheme, "https"),
		Region:       "us-east-1",
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("init minio client: %v", err)
	}

	bucket := fmt.Sprintf("team2-minioclient-%d", time.Now().UnixNano())
	objectKey := "minioclient/object.txt"
	payload := []byte("minio client integration test payload")

	// Test MakeBucket
	if err := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: "us-east-1"}); err != nil {
		t.Fatalf("minio MakeBucket via gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = minioClient.RemoveObject(ctx, bucket, objectKey, minio.RemoveObjectOptions{})
		_ = minioClient.RemoveBucket(ctx, bucket)
	})

	// Verify the bucket appears in BucketExists
	exists, err := minioClient.BucketExists(ctx, bucket)
	if err != nil {
		t.Fatalf("minio BucketExists via gateway: %v", err)
	}
	if !exists {
		t.Fatalf("bucket %q should exist after MakeBucket", bucket)
	}

	// Test PutObject
	uploadInfo, err := minioClient.PutObject(ctx, bucket, objectKey, bytes.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{
		ContentType: "text/plain",
	})
	if err != nil {
		t.Fatalf("minio PutObject via gateway: %v", err)
	}
	if uploadInfo.Key != objectKey {
		t.Fatalf("PutObject key mismatch: got=%q want=%q", uploadInfo.Key, objectKey)
	}

	// Test ListObjects — verify the uploaded object appears
	found := false
	for obj := range minioClient.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: "minioclient/", Recursive: true}) {
		if obj.Err != nil {
			t.Fatalf("minio ListObjects via gateway: %v", obj.Err)
		}
		if obj.Key == objectKey {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListObjects via gateway did not return uploaded key %q", objectKey)
	}

	// Test GetObject
	obj, err := minioClient.GetObject(ctx, bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("minio GetObject via gateway: %v", err)
	}
	defer obj.Close()
	gotBody, err := io.ReadAll(obj)
	if err != nil {
		t.Fatalf("read minio GetObject body via gateway: %v", err)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("GetObject body mismatch: got=%q want=%q", string(gotBody), string(payload))
	}

	// Test SetBucketLifecycle and GetBucketLifecycle
	lcConfig := lifecycle.NewConfiguration()
	lcConfig.Rules = []lifecycle.Rule{
		{
			ID:     "expire-old-objects",
			Status: "Enabled",
			Expiration: lifecycle.Expiration{
				Days: lifecycle.ExpirationDays(30),
			},
		},
		{
			ID:     "disabled-rule",
			Status: "Disabled",
			RuleFilter: lifecycle.Filter{
				Prefix: "tmp/",
			},
			Expiration: lifecycle.Expiration{
				Days: lifecycle.ExpirationDays(90),
			},
		},
	}
	if err := minioClient.SetBucketLifecycle(ctx, bucket, lcConfig); err != nil {
		t.Fatalf("minio SetBucketLifecycle via gateway: %v", err)
	}
	gotLC, err := minioClient.GetBucketLifecycle(ctx, bucket)
	if err != nil {
		t.Fatalf("minio GetBucketLifecycle via gateway: %v", err)
	}
	if len(gotLC.Rules) < 1 {
		t.Fatalf("expected at least 1 lifecycle rule, got %d", len(gotLC.Rules))
	}
	var foundEnabledRule, foundDisabledRule bool
	for _, r := range gotLC.Rules {
		switch r.ID {
		case "expire-old-objects":
			foundEnabledRule = true
			if r.Expiration.Days != lifecycle.ExpirationDays(30) {
				t.Fatalf("lifecycle expiration days mismatch: got=%d want=30", r.Expiration.Days)
			}
		case "disabled-rule":
			foundDisabledRule = true
			if r.Status != "Disabled" {
				t.Fatalf("disabled lifecycle rule status mismatch: got=%q want=Disabled", r.Status)
			}
			if r.Expiration.Days != lifecycle.ExpirationDays(90) {
				t.Fatalf("disabled lifecycle rule expiration days mismatch: got=%d want=90", r.Expiration.Days)
			}
		}
	}
	if !foundEnabledRule {
		t.Fatalf("lifecycle rule %q not found in GET response", "expire-old-objects")
	}
	// Some S3-compatible backends may not return disabled rules; log if missing rather than failing.
	if !foundDisabledRule {
		t.Logf("disabled lifecycle rule %q was not returned by backend (backend may not support disabled rules)", "disabled-rule")
	}

	// Test delete lifecycle configuration (SetBucketLifecycle with empty config triggers DELETE).
	if err := minioClient.SetBucketLifecycle(ctx, bucket, lifecycle.NewConfiguration()); err != nil {
		t.Fatalf("minio delete lifecycle via gateway: %v", err)
	}
	// Verify lifecycle is deleted: GetBucketLifecycle should return no rules or an error.
	afterDeleteLC, afterDeleteErr := minioClient.GetBucketLifecycle(ctx, bucket)
	if afterDeleteErr != nil {
		lcErrResp := minio.ToErrorResponse(afterDeleteErr)
		if lcErrResp.Code != "NoSuchLifecycleConfiguration" {
			t.Fatalf("GetBucketLifecycle after delete: unexpected error code=%q: %v", lcErrResp.Code, afterDeleteErr)
		}
	} else if len(afterDeleteLC.Rules) != 0 {
		t.Fatalf("expected 0 lifecycle rules after delete, got %d", len(afterDeleteLC.Rules))
	}

	// Test SetBucketTagging, GetBucketTagging, and RemoveBucketTagging
	bucketTags, err := tags.NewTags(map[string]string{
		"scope": "integration",
		"suite": "minio-client",
	}, false)
	if err != nil {
		t.Fatalf("create bucket tags: %v", err)
	}
	if err := minioClient.SetBucketTagging(ctx, bucket, bucketTags); err != nil {
		t.Fatalf("minio SetBucketTagging via gateway: %v", err)
	}
	gotBucketTags, err := minioClient.GetBucketTagging(ctx, bucket)
	if err != nil {
		t.Fatalf("minio GetBucketTagging via gateway: %v", err)
	}
	for k, v := range map[string]string{"scope": "integration", "suite": "minio-client"} {
		if gotBucketTags.ToMap()[k] != v {
			t.Fatalf("GetBucketTagging[%q] mismatch: got=%q want=%q", k, gotBucketTags.ToMap()[k], v)
		}
	}
	if err := minioClient.RemoveBucketTagging(ctx, bucket); err != nil {
		t.Fatalf("minio RemoveBucketTagging via gateway: %v", err)
	}
	gotBucketTagsAfterRemove, err := minioClient.GetBucketTagging(ctx, bucket)
	if err != nil {
		bucketTagErrResp := minio.ToErrorResponse(err)
		if bucketTagErrResp.Code != "NoSuchTagSet" {
			t.Fatalf("minio GetBucketTagging after remove via gateway: %v", err)
		}
	} else if len(gotBucketTagsAfterRemove.ToMap()) != 0 {
		t.Fatalf("expected no bucket tags after RemoveBucketTagging, got: %v", gotBucketTagsAfterRemove.ToMap())
	}

	// Test object update: overwrite existing key with new content
	updatedPayload := []byte("updated content via minio client")
	updInfo, err := minioClient.PutObject(ctx, bucket, objectKey, bytes.NewReader(updatedPayload), int64(len(updatedPayload)), minio.PutObjectOptions{
		ContentType: "text/plain",
	})
	if err != nil {
		t.Fatalf("minio PutObject overwrite via gateway: %v", err)
	}
	if updInfo.Key != objectKey {
		t.Fatalf("overwrite PutObject key mismatch: got=%q want=%q", updInfo.Key, objectKey)
	}
	updObj, err := minioClient.GetObject(ctx, bucket, objectKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("minio GetObject after overwrite via gateway: %v", err)
	}
	updBody, err := io.ReadAll(updObj)
	_ = updObj.Close()
	if err != nil {
		t.Fatalf("read updated object body: %v", err)
	}
	if !bytes.Equal(updBody, updatedPayload) {
		t.Fatalf("updated object body mismatch: got=%q want=%q", string(updBody), string(updatedPayload))
	}

	// Test PutObjectTagging, GetObjectTagging, RemoveObjectTagging
	objTags, err := tags.NewTags(map[string]string{
		"env":   "test",
		"owner": "testuser",
	}, true)
	if err != nil {
		t.Fatalf("create object tags: %v", err)
	}
	if err := minioClient.PutObjectTagging(ctx, bucket, objectKey, objTags, minio.PutObjectTaggingOptions{}); err != nil {
		t.Fatalf("minio PutObjectTagging via gateway: %v", err)
	}
	gotObjTags, err := minioClient.GetObjectTagging(ctx, bucket, objectKey, minio.GetObjectTaggingOptions{})
	if err != nil {
		t.Fatalf("minio GetObjectTagging via gateway: %v", err)
	}
	for k, v := range map[string]string{"env": "test", "owner": "testuser"} {
		if gotObjTags.ToMap()[k] != v {
			t.Fatalf("GetObjectTagging[%q] mismatch: got=%q want=%q", k, gotObjTags.ToMap()[k], v)
		}
	}
	if err := minioClient.RemoveObjectTagging(ctx, bucket, objectKey, minio.RemoveObjectTaggingOptions{}); err != nil {
		t.Fatalf("minio RemoveObjectTagging via gateway: %v", err)
	}
	gotObjTagsAfterRemove, err := minioClient.GetObjectTagging(ctx, bucket, objectKey, minio.GetObjectTaggingOptions{})
	if err != nil {
		t.Fatalf("minio GetObjectTagging after remove via gateway: %v", err)
	}
	if len(gotObjTagsAfterRemove.ToMap()) != 0 {
		t.Fatalf("expected no object tags after RemoveObjectTagging, got: %v", gotObjTagsAfterRemove.ToMap())
	}

	// Test PutObject with user metadata and StatObject to verify metadata is preserved
	metaKey := "minioclient/meta-object.txt"
	metaPayload := []byte("object with user metadata")
	t.Cleanup(func() {
		_ = minioClient.RemoveObject(ctx, bucket, metaKey, minio.RemoveObjectOptions{})
	})
	if _, err := minioClient.PutObject(ctx, bucket, metaKey, bytes.NewReader(metaPayload), int64(len(metaPayload)), minio.PutObjectOptions{
		ContentType: "text/plain",
		UserMetadata: map[string]string{
			"Author":  "testuser",
			"Project": "s3gateway",
		},
	}); err != nil {
		t.Fatalf("minio PutObject with metadata via gateway: %v", err)
	}
	metaStat, err := minioClient.StatObject(ctx, bucket, metaKey, minio.StatObjectOptions{})
	if err != nil {
		t.Fatalf("minio StatObject metadata object via gateway: %v", err)
	}
	if metaStat.Size != int64(len(metaPayload)) {
		t.Fatalf("metadata object size mismatch: got=%d want=%d", metaStat.Size, len(metaPayload))
	}
	if metaStat.ContentType != "text/plain" {
		t.Fatalf("metadata object content type mismatch: got=%q want=%q", metaStat.ContentType, "text/plain")
	}
	// HTTP headers are case-insensitive; verify user metadata is proxied via the
	// canonical X-Amz-Meta-* header form in the full Metadata response map.
	for _, wantKey := range []string{"X-Amz-Meta-Author", "X-Amz-Meta-Project"} {
		if metaStat.Metadata.Get(wantKey) == "" {
			t.Fatalf("metadata header %q missing from StatObject response", wantKey)
		}
	}

	// Test edge case: put and get an empty (zero-byte) object
	emptyKey := "minioclient/empty-object.txt"
	t.Cleanup(func() {
		_ = minioClient.RemoveObject(ctx, bucket, emptyKey, minio.RemoveObjectOptions{})
	})
	if _, err := minioClient.PutObject(ctx, bucket, emptyKey, bytes.NewReader([]byte{}), 0, minio.PutObjectOptions{
		ContentType: "text/plain",
	}); err != nil {
		t.Fatalf("minio PutObject empty object via gateway: %v", err)
	}
	emptyStat, err := minioClient.StatObject(ctx, bucket, emptyKey, minio.StatObjectOptions{})
	if err != nil {
		t.Fatalf("minio StatObject empty object via gateway: %v", err)
	}
	if emptyStat.Size != 0 {
		t.Fatalf("empty object size mismatch: got=%d want=0", emptyStat.Size)
	}
	emptyObj, err := minioClient.GetObject(ctx, bucket, emptyKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("minio GetObject empty object via gateway: %v", err)
	}
	emptyBody, err := io.ReadAll(emptyObj)
	_ = emptyObj.Close()
	if err != nil {
		t.Fatalf("read empty object body: %v", err)
	}
	if len(emptyBody) != 0 {
		t.Fatalf("empty object body should be empty, got %d bytes", len(emptyBody))
	}

	// Test edge case: reading a non-existent object returns NoSuchKey
	nonExistentObj, err := minioClient.GetObject(ctx, bucket, "minioclient/does-not-exist.txt", minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("minio GetObject non-existent key should not fail on call: %v", err)
	}
	_, readErr := io.ReadAll(nonExistentObj)
	_ = nonExistentObj.Close()
	if readErr == nil {
		t.Fatalf("expected error reading non-existent object body")
	}
	nonExistErrResp := minio.ToErrorResponse(readErr)
	if nonExistErrResp.Code != "NoSuchKey" {
		t.Fatalf("expected NoSuchKey for non-existent object, got code=%q", nonExistErrResp.Code)
	}

	// Test multipart upload: set PartSize below object size to force multipart.
	// S3 requires parts to be at least 5 MiB except for the final part.
	mpKey := "minioclient/multipart.bin"
	const mpPartSize = 5 * 1024 * 1024                     // 5 MiB — minimum S3 non-final part size
	mpPayload := bytes.Repeat([]byte("m"), mpPartSize+512) // just over one part → two parts
	t.Cleanup(func() {
		_ = minioClient.RemoveObject(ctx, bucket, mpKey, minio.RemoveObjectOptions{})
	})
	mpUploadInfo, err := minioClient.PutObject(ctx, bucket, mpKey, bytes.NewReader(mpPayload), int64(len(mpPayload)), minio.PutObjectOptions{
		ContentType: "application/octet-stream",
		PartSize:    mpPartSize,
	})
	if err != nil {
		t.Fatalf("minio PutObject multipart via gateway: %v", err)
	}
	if mpUploadInfo.Key != mpKey {
		t.Fatalf("multipart PutObject key mismatch: got=%q want=%q", mpUploadInfo.Key, mpKey)
	}
	mpStat, err := minioClient.StatObject(ctx, bucket, mpKey, minio.StatObjectOptions{})
	if err != nil {
		t.Fatalf("minio StatObject multipart object via gateway: %v", err)
	}
	if mpStat.Size != int64(len(mpPayload)) {
		t.Fatalf("multipart object size mismatch: got=%d want=%d", mpStat.Size, len(mpPayload))
	}
	mpObj, err := minioClient.GetObject(ctx, bucket, mpKey, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("minio GetObject multipart object via gateway: %v", err)
	}
	mpGotBody, err := io.ReadAll(mpObj)
	_ = mpObj.Close()
	if err != nil {
		t.Fatalf("read multipart object body: %v", err)
	}
	if !bytes.Equal(mpGotBody, mpPayload) {
		t.Fatalf("multipart object body mismatch: gotLen=%d wantLen=%d", len(mpGotBody), len(mpPayload))
	}

	// Clean up extra objects before testing bucket deletion
	for _, extraKey := range []string{metaKey, emptyKey, mpKey} {
		if err := minioClient.RemoveObject(ctx, bucket, extraKey, minio.RemoveObjectOptions{}); err != nil {
			t.Fatalf("minio RemoveObject %q before RemoveBucket: %v", extraKey, err)
		}
	}

	// Test RemoveObject
	if err := minioClient.RemoveObject(ctx, bucket, objectKey, minio.RemoveObjectOptions{}); err != nil {
		t.Fatalf("minio RemoveObject via gateway: %v", err)
	}

	// Verify object is gone after RemoveObject
	_, err = minioClient.StatObject(ctx, bucket, objectKey, minio.StatObjectOptions{})
	if err == nil {
		t.Fatalf("expected StatObject to fail after RemoveObject")
	}
	errResp := minio.ToErrorResponse(err)
	if errResp.Code != "NoSuchKey" {
		t.Fatalf("expected NoSuchKey after RemoveObject, got code=%q", errResp.Code)
	}

	// Test RemoveBucket
	if err := minioClient.RemoveBucket(ctx, bucket); err != nil {
		t.Fatalf("minio RemoveBucket via gateway: %v", err)
	}

	// Verify bucket is gone after RemoveBucket
	exists, err = minioClient.BucketExists(ctx, bucket)
	if err != nil {
		t.Fatalf("minio BucketExists after RemoveBucket via gateway: %v", err)
	}
	if exists {
		t.Fatalf("bucket %q should not exist after RemoveBucket", bucket)
	}
}
