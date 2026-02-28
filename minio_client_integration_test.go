package main_test

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

	s3gateway "github.com/define42/s3gateway"
	"github.com/define42/s3gateway/internal/s3credentials"
)

// TestMinioClientIntegration validates that the s3gateway works correctly when
// accessed through the minio S3 client. It exercises bucket creation, object
// put, object get, object deletion, and bucket deletion.
func TestMinioClientIntegration(t *testing.T) {
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
	t.Setenv("S3_ENDPOINT", minioURL)
	t.Setenv("S3_REGION", "us-east-1")
	t.Setenv("S3_ACCESS_KEY", "minioadmin")
	t.Setenv("S3_SECRET_KEY", "minioadmin")
	t.Setenv("S3_FORCE_PATH_STYLE", "true")

	httpSrv, _, err := s3gateway.BootS3Gateway()
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
