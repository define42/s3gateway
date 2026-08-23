package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	authz "github.com/define42/s3gateway/internal/authz"
	gatewayconfig "github.com/define42/s3gateway/internal/config"
	gatewaycache "github.com/define42/s3gateway/internal/groupcache"
	ldapinternal "github.com/define42/s3gateway/internal/ldap"
	"github.com/define42/s3gateway/internal/s3credentials"
	sigv4 "github.com/define42/s3gateway/internal/sigv4"
	"github.com/define42/s3gateway/internal/testutil"
	"github.com/define42/s3gateway/internal/upstream"
	minio "github.com/minio/minio-go/v7"
	minioCredentials "github.com/minio/minio-go/v7/pkg/credentials"
)

func TestLdapS3upstreamWithClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	// Sanity-check LDAP bind + group mapping used by gateway authz.
	grps, err := ldapinternal.FetchGroupsUPN(cfg, "testuser", "dogood")
	if err != nil {
		t.Fatalf("ldap auth/group lookup failed: %v", err)
	}
	if !authz.CanWrite(authz.RulesFromGroups(grps), "team2-integration-check") {
		t.Fatalf("expected team2-rwcdb write permission, got groups: %v", mapKeys(grps))
	}
	if !authz.CanCreateBucket(authz.RulesFromGroups(grps), "team2-integration-check") {
		t.Fatalf("expected team2-rwcdb create-bucket permission, got groups: %v", mapKeys(grps))
	}
	if !authz.CanDeleteObject(authz.RulesFromGroups(grps), "team2-integration-check") {
		t.Fatalf("expected team2-rwcdb delete-object permission, got groups: %v", mapKeys(grps))
	}
	if !authz.CanDeleteBucket(authz.RulesFromGroups(grps), "team2-integration-check") {
		t.Fatalf("expected team2-rwcdb delete-bucket permission, got groups: %v", mapKeys(grps))
	}
	roGrps, err := ldapinternal.FetchGroupsUPN(cfg, "readonly", "dogood")
	if err != nil {
		t.Fatalf("ldap auth/group lookup failed for readonly user: %v", err)
	}
	roRules := authz.RulesFromGroups(roGrps)
	if !authz.CanRead(roRules, "team2-integration-check") || authz.CanWrite(roRules, "team2-integration-check") {
		t.Fatalf("expected team2-r read-only permission, got groups: %v", mapKeys(roGrps))
	}
	if authz.CanCreateBucket(roRules, "team2-integration-check") || authz.CanDeleteObject(roRules, "team2-integration-check") || authz.CanDeleteBucket(roRules, "team2-integration-check") {
		t.Fatalf("expected team2-r to deny create/delete permissions, got groups: %v", mapKeys(roGrps))
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	gatewayAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	gatewayClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", gatewayAccessKey, mustGatewaySecretForAccessKey(t, gatewayAccessKey))
	readonlyAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	readonlyClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", readonlyAccessKey, mustGatewaySecretForAccessKey(t, readonlyAccessKey))
	upstreamClient := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-integration-%d", time.Now().UnixNano())
	key := "smoke/hello.txt"
	wantBody := []byte("hello through s3gateway")
	metadata := map[string]string{
		"owner":   "integration",
		"purpose": "metadata-ttl-check",
	}
	expiresAt := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Second)

	if _, err := gatewayClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	if _, err := gatewayClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(wantBody),
		ContentLength: aws.Int64(int64(len(wantBody))),
		ContentType:   aws.String("text/plain"),
		Metadata:      metadata,
		Expires:       aws.Time(expiresAt),
	}); err != nil {
		t.Fatalf("put object via gateway: %v", err)
	}

	gotObj, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object from upstream minio: %v", err)
	}
	defer gotObj.Body.Close()

	gotBody, err := io.ReadAll(gotObj.Body)
	if err != nil {
		t.Fatalf("read upstream object body: %v", err)
	}
	if !bytes.Equal(gotBody, wantBody) {
		t.Fatalf("upstream object mismatch: got %q want %q", string(gotBody), string(wantBody))
	}
	if gotObj.Metadata["owner"] != metadata["owner"] || gotObj.Metadata["purpose"] != metadata["purpose"] {
		t.Fatalf("upstream metadata mismatch: got=%v want=%v", gotObj.Metadata, metadata)
	}
	if gotObj.Metadata["uploaded-by"] != "testuser" {
		t.Fatalf("upstream uploaded-by metadata mismatch: got=%q want=%q (all=%v)", gotObj.Metadata["uploaded-by"], "testuser", gotObj.Metadata)
	}
	if gotObj.ExpiresString == nil {
		t.Fatalf("expected upstream object ExpiresString to be set")
	}
	gotObjExpires, err := http.ParseTime(*gotObj.ExpiresString)
	if err != nil {
		t.Fatalf("parse upstream expires header %q: %v", *gotObj.ExpiresString, err)
	}
	if gotObjExpires.UTC().Unix() != expiresAt.Unix() {
		t.Fatalf("upstream expires mismatch: got=%s want=%s", gotObjExpires.UTC().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	}
	readonlyObj, err := readonlyClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("readonly get object via gateway: %v", err)
	}
	defer readonlyObj.Body.Close()

	readonlyBody, err := io.ReadAll(readonlyObj.Body)
	if err != nil {
		t.Fatalf("read readonly get object body: %v", err)
	}
	if !bytes.Equal(readonlyBody, wantBody) {
		t.Fatalf("readonly object mismatch: got %q want %q", string(readonlyBody), string(wantBody))
	}
	if readonlyObj.Metadata["owner"] != metadata["owner"] || readonlyObj.Metadata["purpose"] != metadata["purpose"] {
		t.Fatalf("readonly metadata mismatch through gateway: got=%v want=%v", readonlyObj.Metadata, metadata)
	}
	if readonlyObj.ExpiresString == nil {
		t.Fatalf("expected readonly get through gateway to include ExpiresString")
	}
	readonlyExpires, err := http.ParseTime(*readonlyObj.ExpiresString)
	if err != nil {
		t.Fatalf("parse readonly expires header %q: %v", *readonlyObj.ExpiresString, err)
	}
	if readonlyExpires.UTC().Unix() != expiresAt.Unix() {
		t.Fatalf("readonly expires mismatch through gateway: got=%s want=%s", readonlyExpires.UTC().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
	}

	readonlyDeniedKey := "smoke/readonly-put-should-fail.txt"
	if _, err := readonlyClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(readonlyDeniedKey),
		Body:          bytes.NewReader([]byte("should fail")),
		ContentLength: aws.Int64(int64(len("should fail"))),
		ContentType:   aws.String("text/plain"),
	}); err == nil {
		t.Fatalf("expected readonly user put object to fail, but it succeeded")
	}
	if _, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(readonlyDeniedKey),
	}); err == nil {
		t.Fatalf("readonly denied key unexpectedly exists in upstream")
	}

	if _, err := gatewayClient.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err != nil {
		t.Fatalf("delete object via gateway: %v", err)
	}

	if _, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err == nil {
		t.Fatalf("expected upstream object to be deleted, but get object succeeded")
	}
}

func TestLdapS3upstreamWithMinioClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	gatewayAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	gatewayAwsClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", gatewayAccessKey, mustGatewaySecretForAccessKey(t, gatewayAccessKey))
	gatewayMinioClient := newMinioGatewayClient(t, gwSrv.URL, gatewayAccessKey, mustGatewaySecretForAccessKey(t, gatewayAccessKey))
	upstreamClient := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-minio-client-%d", time.Now().UnixNano())
	key := "smoke/minio-client.txt"
	wantBody := []byte("hello through minio-go client and s3gateway")

	if _, err := gatewayAwsClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via aws client through gateway: %v", err)
	}

	if _, err := gatewayMinioClient.PutObject(
		ctx,
		bucket,
		key,
		bytes.NewReader(wantBody),
		int64(len(wantBody)),
		minio.PutObjectOptions{
			ContentType:          "text/plain",
			DisableContentSha256: true,
		},
	); err != nil {
		t.Fatalf("put object via minio client through gateway: %v", err)
	}

	gotObj, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("get object from upstream minio: %v", err)
	}
	defer gotObj.Body.Close()

	gotBody, err := io.ReadAll(gotObj.Body)
	if err != nil {
		t.Fatalf("read upstream object body: %v", err)
	}
	if !bytes.Equal(gotBody, wantBody) {
		t.Fatalf("upstream object mismatch: got %q want %q", string(gotBody), string(wantBody))
	}

	if err := gatewayMinioClient.RemoveObject(ctx, bucket, key, minio.RemoveObjectOptions{}); err != nil {
		t.Fatalf("remove object via minio client through gateway: %v", err)
	}

	if _, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err == nil {
		t.Fatalf("expected upstream object to be deleted, but get object succeeded")
	}
}

func TestLdapS3upstreamListBuckets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	rwClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(t, rwAccessKey))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	roClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, mustGatewaySecretForAccessKey(t, roAccessKey))
	upstreamClient := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	suffix := time.Now().UnixNano()
	allowedBucketA := fmt.Sprintf("team2-list-%d-a", suffix)
	allowedBucketB := fmt.Sprintf("team2-list-%d-b", suffix)
	deniedBucket := fmt.Sprintf("team1-list-%d-x", suffix)

	for _, b := range []string{allowedBucketA, allowedBucketB, deniedBucket} {
		if _, err := upstreamClient.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String(b),
		}); err != nil {
			t.Fatalf("create upstream bucket %q: %v", b, err)
		}
	}

	rwList, err := rwClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("list buckets via gateway rw user: %v", err)
	}
	rwNames := map[string]bool{}
	for _, b := range rwList.Buckets {
		if b.Name != nil {
			rwNames[*b.Name] = true
		}
	}

	if !rwNames[allowedBucketA] || !rwNames[allowedBucketB] {
		t.Fatalf("rw list missing allowed buckets: got=%v", mapBoolKeys(rwNames))
	}
	if rwNames[deniedBucket] {
		t.Fatalf("rw list unexpectedly included denied bucket %q: got=%v", deniedBucket, mapBoolKeys(rwNames))
	}

	roList, err := roClient.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("list buckets via gateway readonly user: %v", err)
	}
	roNames := map[string]bool{}
	for _, b := range roList.Buckets {
		if b.Name != nil {
			roNames[*b.Name] = true
		}
	}

	if !roNames[allowedBucketA] || !roNames[allowedBucketB] {
		t.Fatalf("readonly list missing allowed buckets: got=%v", mapBoolKeys(roNames))
	}
	if roNames[deniedBucket] {
		t.Fatalf("readonly list unexpectedly included denied bucket %q: got=%v", deniedBucket, mapBoolKeys(roNames))
	}
}

func TestLdapS3upstreamListObjectsV2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	rwClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(t, rwAccessKey))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	roClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, mustGatewaySecretForAccessKey(t, roAccessKey))

	bucket := fmt.Sprintf("team2-listobj-%d", time.Now().UnixNano())
	if _, err := rwClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	objects := map[string][]byte{
		"docs/a.txt":   []byte("alpha"),
		"docs/b.txt":   []byte("bravo"),
		"images/c.jpg": []byte("charlie"),
	}
	for key, body := range objects {
		if _, err := rwClient.PutObject(ctx, &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			Body:          bytes.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
			ContentType:   aws.String("application/octet-stream"),
		}); err != nil {
			t.Fatalf("put object %q via gateway: %v", key, err)
		}
	}

	assertListObjectsV2WithPrefix := func(client *s3.Client, userLabel string) {
		t.Helper()
		out, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(bucket),
			Prefix: aws.String("docs/"),
		})
		if err != nil {
			t.Fatalf("list objects v2 via gateway (%s): %v", userLabel, err)
		}

		got := map[string]bool{}
		for _, o := range out.Contents {
			if o.Key != nil {
				got[*o.Key] = true
			}
		}
		if !got["docs/a.txt"] || !got["docs/b.txt"] {
			t.Fatalf("%s list objects missing docs keys: got=%v", userLabel, mapBoolKeys(got))
		}
		if got["images/c.jpg"] {
			t.Fatalf("%s list objects unexpectedly included non-prefix key: got=%v", userLabel, mapBoolKeys(got))
		}
	}

	assertListObjectsV2WithPrefix(rwClient, "rw")
	assertListObjectsV2WithPrefix(roClient, "readonly")
}

func TestLdapS3upstreamListMultipartUploads(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	rwClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(t, rwAccessKey))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	roClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, mustGatewaySecretForAccessKey(t, roAccessKey))
	upstreamClient := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-listmpu-%d", time.Now().UnixNano())
	if _, err := rwClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	type uploadRef struct {
		key      string
		uploadID *string
	}
	var uploads []uploadRef
	for _, key := range []string{"uploads/a.bin", "uploads/b.bin", "other/c.bin"} {
		out, err := rwClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("create multipart upload %q via gateway: %v", key, err)
		}
		partBody := []byte("x")
		if _, err := rwClient.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			UploadId:      out.UploadId,
			PartNumber:    aws.Int32(1),
			Body:          bytes.NewReader(partBody),
			ContentLength: aws.Int64(int64(len(partBody))),
		}); err != nil {
			t.Fatalf("upload part for multipart upload %q via gateway: %v", key, err)
		}
		uploads = append(uploads, uploadRef{key: key, uploadID: out.UploadId})
	}
	defer func() {
		for _, up := range uploads {
			if up.uploadID == nil {
				continue
			}
			_, _ = rwClient.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(bucket),
				Key:      aws.String(up.key),
				UploadId: up.uploadID,
			})
		}
	}()

	type listMultipartResult struct {
		keys        map[string]bool
		isTruncated bool
		keyMarker   string
		uploadID    string
	}
	extractListMultipartResult := func(out *s3.ListMultipartUploadsOutput) listMultipartResult {
		keys := map[string]bool{}
		for _, u := range out.Uploads {
			if u.Key != nil {
				keys[*u.Key] = true
			}
		}
		return listMultipartResult{
			keys:        keys,
			isTruncated: aws.ToBool(out.IsTruncated),
			keyMarker:   aws.ToString(out.NextKeyMarker),
			uploadID:    aws.ToString(out.NextUploadIdMarker),
		}
	}
	assertListUploadsMatchesUpstream := func(client *s3.Client, label string) {
		t.Helper()
		upstreamOut, err := upstreamClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(bucket),
			Prefix: aws.String("uploads/"),
		})
		if err != nil {
			t.Fatalf("list multipart uploads via upstream: %v", err)
		}
		gatewayOut, err := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
			Bucket: aws.String(bucket),
			Prefix: aws.String("uploads/"),
		})
		if err != nil {
			t.Fatalf("list multipart uploads via gateway (%s): %v", label, err)
		}
		upstreamRes := extractListMultipartResult(upstreamOut)
		gatewayRes := extractListMultipartResult(gatewayOut)
		if strings.Join(mapBoolKeys(gatewayRes.keys), ",") != strings.Join(mapBoolKeys(upstreamRes.keys), ",") {
			t.Fatalf("%s list multipart uploads keys mismatch: gateway=%v upstream=%v", label, mapBoolKeys(gatewayRes.keys), mapBoolKeys(upstreamRes.keys))
		}
		if gatewayRes.isTruncated != upstreamRes.isTruncated {
			t.Fatalf("%s list multipart uploads truncation mismatch: gateway=%v upstream=%v", label, gatewayRes.isTruncated, upstreamRes.isTruncated)
		}
	}

	assertListUploadsMatchesUpstream(rwClient, "rw")
	assertListUploadsMatchesUpstream(roClient, "readonly")

	upstreamPage1, err := upstreamClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket:     aws.String(bucket),
		Prefix:     aws.String("uploads/"),
		MaxUploads: aws.Int32(1),
	})
	if err != nil {
		t.Fatalf("list multipart uploads page 1 via upstream: %v", err)
	}
	gatewayPage1, err := rwClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket:     aws.String(bucket),
		Prefix:     aws.String("uploads/"),
		MaxUploads: aws.Int32(1),
	})
	if err != nil {
		t.Fatalf("list multipart uploads page 1 via gateway: %v", err)
	}

	upstreamPage1Res := extractListMultipartResult(upstreamPage1)
	gatewayPage1Res := extractListMultipartResult(gatewayPage1)
	if strings.Join(mapBoolKeys(gatewayPage1Res.keys), ",") != strings.Join(mapBoolKeys(upstreamPage1Res.keys), ",") {
		t.Fatalf("list multipart uploads page 1 keys mismatch: gateway=%v upstream=%v", mapBoolKeys(gatewayPage1Res.keys), mapBoolKeys(upstreamPage1Res.keys))
	}
	if gatewayPage1Res.isTruncated != upstreamPage1Res.isTruncated {
		t.Fatalf("list multipart uploads page 1 truncation mismatch: gateway=%v upstream=%v", gatewayPage1Res.isTruncated, upstreamPage1Res.isTruncated)
	}

	upstreamPage2, err := upstreamClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket:         aws.String(bucket),
		Prefix:         aws.String("uploads/"),
		MaxUploads:     aws.Int32(1),
		KeyMarker:      upstreamPage1.NextKeyMarker,
		UploadIdMarker: upstreamPage1.NextUploadIdMarker,
	})
	if err != nil {
		t.Fatalf("list multipart uploads page 2 via upstream: %v", err)
	}
	gatewayPage2, err := rwClient.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket:         aws.String(bucket),
		Prefix:         aws.String("uploads/"),
		MaxUploads:     aws.Int32(1),
		KeyMarker:      gatewayPage1.NextKeyMarker,
		UploadIdMarker: gatewayPage1.NextUploadIdMarker,
	})
	if err != nil {
		t.Fatalf("list multipart uploads page 2 via gateway: %v", err)
	}
	upstreamPage2Res := extractListMultipartResult(upstreamPage2)
	gatewayPage2Res := extractListMultipartResult(gatewayPage2)
	if strings.Join(mapBoolKeys(gatewayPage2Res.keys), ",") != strings.Join(mapBoolKeys(upstreamPage2Res.keys), ",") {
		t.Fatalf("list multipart uploads page 2 keys mismatch: gateway=%v upstream=%v", mapBoolKeys(gatewayPage2Res.keys), mapBoolKeys(upstreamPage2Res.keys))
	}
	if gatewayPage2Res.isTruncated != upstreamPage2Res.isTruncated {
		t.Fatalf("list multipart uploads page 2 truncation mismatch: gateway=%v upstream=%v", gatewayPage2Res.isTruncated, upstreamPage2Res.isTruncated)
	}
}

func TestLdapS3upstreamGetObjectAttributes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	rwClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(t, rwAccessKey))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	roClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, mustGatewaySecretForAccessKey(t, roAccessKey))

	bucket := fmt.Sprintf("team2-getattrs-%d", time.Now().UnixNano())
	if _, err := rwClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	simpleKey := "attrs/simple.txt"
	simpleBody := []byte("simple attrs body")
	if _, err := rwClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(simpleKey),
		Body:          bytes.NewReader(simpleBody),
		ContentLength: aws.Int64(int64(len(simpleBody))),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		t.Fatalf("put simple object via gateway: %v", err)
	}

	simpleAttrs, err := rwClient.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(simpleKey),
		ObjectAttributes: []s3types.ObjectAttributes{
			s3types.ObjectAttributesEtag,
			s3types.ObjectAttributesObjectSize,
		},
	})
	if err != nil {
		t.Fatalf("get object attributes (rw) via gateway: %v", err)
	}
	if simpleAttrs.ETag == nil || *simpleAttrs.ETag == "" {
		t.Fatalf("expected etag in get object attributes response")
	}
	if aws.ToInt64(simpleAttrs.ObjectSize) != int64(len(simpleBody)) {
		t.Fatalf("unexpected object size from attributes: got=%d want=%d", aws.ToInt64(simpleAttrs.ObjectSize), len(simpleBody))
	}

	if _, err := roClient.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(simpleKey),
		ObjectAttributes: []s3types.ObjectAttributes{
			s3types.ObjectAttributesEtag,
			s3types.ObjectAttributesObjectSize,
		},
	}); err != nil {
		t.Fatalf("get object attributes (readonly) via gateway: %v", err)
	}

	multiKey := "attrs/multi.txt"
	part1Body := bytes.Repeat([]byte("m"), 5*1024*1024)
	part2Body := []byte("tail")

	createOut, err := rwClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(multiKey),
	})
	if err != nil {
		t.Fatalf("create multipart for attrs via gateway: %v", err)
	}

	part1Out, err := rwClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(multiKey),
		UploadId:      createOut.UploadId,
		PartNumber:    aws.Int32(1),
		Body:          bytes.NewReader(part1Body),
		ContentLength: aws.Int64(int64(len(part1Body))),
	})
	if err != nil {
		t.Fatalf("upload part 1 for attrs via gateway: %v", err)
	}
	part2Out, err := rwClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(multiKey),
		UploadId:      createOut.UploadId,
		PartNumber:    aws.Int32(2),
		Body:          bytes.NewReader(part2Body),
		ContentLength: aws.Int64(int64(len(part2Body))),
	})
	if err != nil {
		t.Fatalf("upload part 2 for attrs via gateway: %v", err)
	}
	if _, err := rwClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(multiKey),
		UploadId: createOut.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: []s3types.CompletedPart{
				{PartNumber: aws.Int32(1), ETag: part1Out.ETag},
				{PartNumber: aws.Int32(2), ETag: part2Out.ETag},
			},
		},
	}); err != nil {
		t.Fatalf("complete multipart for attrs via gateway: %v", err)
	}

	attrsPage1, err := rwClient.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(multiKey),
		MaxParts: aws.Int32(1),
		ObjectAttributes: []s3types.ObjectAttributes{
			s3types.ObjectAttributesObjectParts,
			s3types.ObjectAttributesObjectSize,
		},
	})
	if err != nil {
		t.Fatalf("get multipart object attributes page 1 via gateway: %v", err)
	}
	if aws.ToInt64(attrsPage1.ObjectSize) != int64(len(part1Body)+len(part2Body)) {
		t.Fatalf("unexpected multipart object size from attributes: got=%d want=%d", aws.ToInt64(attrsPage1.ObjectSize), len(part1Body)+len(part2Body))
	}
	if attrsPage1.ObjectParts == nil || len(attrsPage1.ObjectParts.Parts) != 1 {
		gotLen := 0
		if attrsPage1.ObjectParts != nil {
			gotLen = len(attrsPage1.ObjectParts.Parts)
		}
		t.Fatalf("expected 1 part in attrs page 1, got %d", gotLen)
	}
	if !aws.ToBool(attrsPage1.ObjectParts.IsTruncated) {
		t.Fatalf("expected attrs page 1 to be truncated")
	}
	if attrsPage1.ObjectParts.NextPartNumberMarker == nil || *attrsPage1.ObjectParts.NextPartNumberMarker == "" {
		t.Fatalf("expected attrs page 1 next part number marker")
	}

	attrsPage2, err := rwClient.GetObjectAttributes(ctx, &s3.GetObjectAttributesInput{
		Bucket:           aws.String(bucket),
		Key:              aws.String(multiKey),
		MaxParts:         aws.Int32(1),
		PartNumberMarker: attrsPage1.ObjectParts.NextPartNumberMarker,
		ObjectAttributes: []s3types.ObjectAttributes{
			s3types.ObjectAttributesObjectParts,
		},
	})
	if err != nil {
		t.Fatalf("get multipart object attributes page 2 via gateway: %v", err)
	}
	if attrsPage2.ObjectParts == nil || len(attrsPage2.ObjectParts.Parts) != 1 {
		gotLen := 0
		if attrsPage2.ObjectParts != nil {
			gotLen = len(attrsPage2.ObjectParts.Parts)
		}
		t.Fatalf("expected 1 part in attrs page 2, got %d", gotLen)
	}
	if aws.ToBool(attrsPage2.ObjectParts.IsTruncated) {
		t.Fatalf("expected attrs page 2 to be non-truncated")
	}
	if aws.ToInt32(attrsPage2.ObjectParts.Parts[0].PartNumber) != 2 {
		t.Fatalf("expected page 2 to return part number 2, got %d", aws.ToInt32(attrsPage2.ObjectParts.Parts[0].PartNumber))
	}
}

func TestLdapS3upstreamMultipartLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	gatewayClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(t, rwAccessKey))
	upstreamClient := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-multipart-%d", time.Now().UnixNano())
	if _, err := gatewayClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	completeKey := "multi/complete.txt"
	part1Body := bytes.Repeat([]byte("a"), 5*1024*1024)
	part2Body := []byte("multipart")

	createOut, err := gatewayClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(completeKey),
	})
	if err != nil {
		t.Fatalf("create multipart upload via gateway: %v", err)
	}
	if createOut.UploadId == nil || *createOut.UploadId == "" {
		t.Fatalf("create multipart upload returned empty upload id")
	}

	part1Out, err := gatewayClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(completeKey),
		UploadId:      createOut.UploadId,
		PartNumber:    aws.Int32(1),
		Body:          bytes.NewReader(part1Body),
		ContentLength: aws.Int64(int64(len(part1Body))),
	})
	if err != nil {
		t.Fatalf("upload part 1 via gateway: %v", err)
	}
	if part1Out.ETag == nil || *part1Out.ETag == "" {
		t.Fatalf("upload part 1 returned empty etag")
	}

	part2Out, err := gatewayClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(completeKey),
		UploadId:      createOut.UploadId,
		PartNumber:    aws.Int32(2),
		Body:          bytes.NewReader(part2Body),
		ContentLength: aws.Int64(int64(len(part2Body))),
	})
	if err != nil {
		t.Fatalf("upload part 2 via gateway: %v", err)
	}
	if part2Out.ETag == nil || *part2Out.ETag == "" {
		t.Fatalf("upload part 2 returned empty etag")
	}

	listOut, err := gatewayClient.ListParts(ctx, &s3.ListPartsInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(completeKey),
		UploadId: createOut.UploadId,
	})
	if err != nil {
		t.Fatalf("list parts via gateway: %v", err)
	}
	if len(listOut.Parts) != 2 {
		t.Fatalf("expected 2 parts in list parts, got %d", len(listOut.Parts))
	}
	if aws.ToInt32(listOut.Parts[0].PartNumber) != 1 || aws.ToInt32(listOut.Parts[1].PartNumber) != 2 {
		t.Fatalf("unexpected part order from list parts: got [%d, %d]",
			aws.ToInt32(listOut.Parts[0].PartNumber),
			aws.ToInt32(listOut.Parts[1].PartNumber))
	}
	if aws.ToInt64(listOut.Parts[0].Size) != int64(len(part1Body)) || aws.ToInt64(listOut.Parts[1].Size) != int64(len(part2Body)) {
		t.Fatalf("unexpected part sizes from list parts: got [%d, %d] want [%d, %d]",
			aws.ToInt64(listOut.Parts[0].Size),
			aws.ToInt64(listOut.Parts[1].Size),
			len(part1Body),
			len(part2Body))
	}

	listPage1, err := gatewayClient.ListParts(ctx, &s3.ListPartsInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(completeKey),
		UploadId: createOut.UploadId,
		MaxParts: aws.Int32(1),
	})
	if err != nil {
		t.Fatalf("list parts page 1 via gateway: %v", err)
	}
	firstPartNumPage1 := int32(-1)
	if len(listPage1.Parts) > 0 {
		firstPartNumPage1 = aws.ToInt32(listPage1.Parts[0].PartNumber)
	}
	if len(listPage1.Parts) != 1 || firstPartNumPage1 != 1 {
		t.Fatalf("unexpected list parts page 1: len=%d firstPart=%d",
			len(listPage1.Parts), firstPartNumPage1)
	}
	if !aws.ToBool(listPage1.IsTruncated) {
		t.Fatalf("expected list parts page 1 to be truncated")
	}

	listPage2, err := gatewayClient.ListParts(ctx, &s3.ListPartsInput{
		Bucket:           aws.String(bucket),
		Key:              aws.String(completeKey),
		UploadId:         createOut.UploadId,
		MaxParts:         aws.Int32(1),
		PartNumberMarker: listPage1.NextPartNumberMarker,
	})
	if err != nil {
		t.Fatalf("list parts page 2 via gateway: %v", err)
	}
	firstPartNumPage2 := int32(-1)
	if len(listPage2.Parts) > 0 {
		firstPartNumPage2 = aws.ToInt32(listPage2.Parts[0].PartNumber)
	}
	if len(listPage2.Parts) != 1 || firstPartNumPage2 != 2 {
		t.Fatalf("unexpected list parts page 2: len=%d firstPart=%d",
			len(listPage2.Parts), firstPartNumPage2)
	}
	if aws.ToBool(listPage2.IsTruncated) {
		t.Fatalf("expected list parts page 2 to be non-truncated")
	}

	if _, err := gatewayClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(completeKey),
		UploadId: createOut.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: []s3types.CompletedPart{
				{PartNumber: aws.Int32(1), ETag: part1Out.ETag},
				{PartNumber: aws.Int32(2), ETag: part2Out.ETag},
			},
		},
	}); err != nil {
		t.Fatalf("complete multipart upload via gateway: %v", err)
	}

	completeObj, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(completeKey),
	})
	if err != nil {
		t.Fatalf("get completed multipart object from upstream: %v", err)
	}
	defer completeObj.Body.Close()

	completeBody, err := io.ReadAll(completeObj.Body)
	if err != nil {
		t.Fatalf("read completed multipart object body: %v", err)
	}
	wantComplete := append(append([]byte{}, part1Body...), part2Body...)
	if !bytes.Equal(completeBody, wantComplete) {
		t.Fatalf("completed multipart body mismatch: gotLen=%d wantLen=%d", len(completeBody), len(wantComplete))
	}
	if completeObj.Metadata["uploaded-by"] != "testuser" {
		t.Fatalf("completed multipart uploaded-by metadata mismatch: got=%q want=%q (all=%v)", completeObj.Metadata["uploaded-by"], "testuser", completeObj.Metadata)
	}

	abortKey := "multi/abort.txt"
	abortCreateOut, err := gatewayClient.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(abortKey),
	})
	if err != nil {
		t.Fatalf("create multipart upload for abort via gateway: %v", err)
	}
	if abortCreateOut.UploadId == nil || *abortCreateOut.UploadId == "" {
		t.Fatalf("create multipart upload for abort returned empty upload id")
	}

	abortPartBody := []byte("to be aborted")
	if _, err := gatewayClient.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(abortKey),
		UploadId:      abortCreateOut.UploadId,
		PartNumber:    aws.Int32(1),
		Body:          bytes.NewReader(abortPartBody),
		ContentLength: aws.Int64(int64(len(abortPartBody))),
	}); err != nil {
		t.Fatalf("upload part for abort via gateway: %v", err)
	}

	if _, err := gatewayClient.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(abortKey),
		UploadId: abortCreateOut.UploadId,
	}); err != nil {
		t.Fatalf("abort multipart upload via gateway: %v", err)
	}

	if _, err := upstreamClient.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(abortKey),
	}); err == nil {
		t.Fatalf("expected aborted multipart object to be absent in upstream")
	}
}

func TestLdapS3upstreamLifecycleConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	rwClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(t, rwAccessKey))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	roClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, mustGatewaySecretForAccessKey(t, roAccessKey))
	upstreamClient := testutil.NewS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-lifecycle-%d", time.Now().UnixNano())
	if _, err := rwClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	lifecycleCfg := &s3types.BucketLifecycleConfiguration{
		Rules: []s3types.LifecycleRule{
			{
				ID:     aws.String("expire-logs"),
				Status: s3types.ExpirationStatusEnabled,
				Filter: &s3types.LifecycleRuleFilter{
					Prefix: aws.String("logs/"),
				},
				Expiration: &s3types.LifecycleExpiration{
					Days: aws.Int32(7),
				},
				AbortIncompleteMultipartUpload: &s3types.AbortIncompleteMultipartUpload{
					DaysAfterInitiation: aws.Int32(2),
				},
			},
		},
	}
	if _, err := rwClient.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 aws.String(bucket),
		LifecycleConfiguration: lifecycleCfg,
	}); err != nil {
		t.Fatalf("put lifecycle via gateway rw user: %v", err)
	}

	if _, err := roClient.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 aws.String(bucket),
		LifecycleConfiguration: lifecycleCfg,
	}); err == nil {
		t.Fatalf("expected readonly put lifecycle via gateway to fail, but it succeeded")
	}

	makeRuleSigs := func(rules []s3types.LifecycleRule) []string {
		out := make([]string, 0, len(rules))
		for _, r := range rules {
			prefix := ""
			if r.Filter != nil && r.Filter.Prefix != nil {
				prefix = *r.Filter.Prefix
			}
			expDays := int32(0)
			if r.Expiration != nil && r.Expiration.Days != nil {
				expDays = *r.Expiration.Days
			}
			abortDays := int32(0)
			if r.AbortIncompleteMultipartUpload != nil && r.AbortIncompleteMultipartUpload.DaysAfterInitiation != nil {
				abortDays = *r.AbortIncompleteMultipartUpload.DaysAfterInitiation
			}
			out = append(out, fmt.Sprintf(
				"id=%s|status=%s|prefix=%s|expDays=%d|abortDays=%d",
				aws.ToString(r.ID),
				string(r.Status),
				prefix,
				expDays,
				abortDays,
			))
		}
		sort.Strings(out)
		return out
	}

	upstreamOut, err := upstreamClient.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("get lifecycle from upstream: %v", err)
	}
	upstreamSigs := strings.Join(makeRuleSigs(upstreamOut.Rules), ",")

	rwOut, err := rwClient.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("get lifecycle via gateway rw user: %v", err)
	}
	if got := strings.Join(makeRuleSigs(rwOut.Rules), ","); got != upstreamSigs {
		t.Fatalf("rw lifecycle mismatch: gateway=%q upstream=%q", got, upstreamSigs)
	}

	roOut, err := roClient.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("get lifecycle via gateway readonly user: %v", err)
	}
	if got := strings.Join(makeRuleSigs(roOut.Rules), ","); got != upstreamSigs {
		t.Fatalf("readonly lifecycle mismatch: gateway=%q upstream=%q", got, upstreamSigs)
	}

	if _, err := roClient.DeleteBucketLifecycle(ctx, &s3.DeleteBucketLifecycleInput{
		Bucket: aws.String(bucket),
	}); err == nil {
		t.Fatalf("expected readonly delete lifecycle via gateway to fail, but it succeeded")
	}

	if _, err := rwClient.DeleteBucketLifecycle(ctx, &s3.DeleteBucketLifecycleInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("delete lifecycle via gateway rw user: %v", err)
	}

	if _, err := upstreamClient.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	}); err == nil {
		t.Fatalf("expected upstream lifecycle config to be deleted")
	}

	if _, err := rwClient.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(bucket),
	}); err == nil {
		t.Fatalf("expected gateway lifecycle config get to fail after delete")
	}
}

func TestLifecycleConfigXMLExpandedRoundTrip(t *testing.T) {
	const inputXML = `<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration>
  <Rule>
    <ID>archive-logs</ID>
    <Status>Enabled</Status>
    <Filter>
      <And>
        <Prefix>logs/</Prefix>
        <Tag>
          <Key>app</Key>
          <Value>api</Value>
        </Tag>
        <ObjectSizeGreaterThan>128</ObjectSizeGreaterThan>
        <ObjectSizeLessThan>4096</ObjectSizeLessThan>
      </And>
    </Filter>
    <Expiration>
      <Date>2030-01-01T00:00:00.000Z</Date>
    </Expiration>
    <Transition>
      <Days>30</Days>
      <StorageClass>GLACIER</StorageClass>
    </Transition>
    <NoncurrentVersionTransition>
      <NoncurrentDays>14</NoncurrentDays>
      <NewerNoncurrentVersions>3</NewerNoncurrentVersions>
      <StorageClass>STANDARD_IA</StorageClass>
    </NoncurrentVersionTransition>
    <NoncurrentVersionExpiration>
      <NoncurrentDays>60</NoncurrentDays>
      <NewerNoncurrentVersions>10</NewerNoncurrentVersions>
    </NoncurrentVersionExpiration>
    <AbortIncompleteMultipartUpload>
      <DaysAfterInitiation>7</DaysAfterInitiation>
    </AbortIncompleteMultipartUpload>
  </Rule>
  <Rule>
    <ID>expire-delete-markers</ID>
    <Status>Enabled</Status>
    <Filter>
      <Prefix>tmp/</Prefix>
    </Filter>
    <Expiration>
      <ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>
    </Expiration>
  </Rule>
</LifecycleConfiguration>`

	cfg, err := decodeLifecycleConfigXML(strings.NewReader(inputXML))
	if err != nil {
		t.Fatalf("decode expanded lifecycle xml: %v", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("expected 2 lifecycle rules, got %d", len(cfg.Rules))
	}

	r0 := cfg.Rules[0]
	if aws.ToString(r0.ID) != "archive-logs" || r0.Status != s3types.ExpirationStatusEnabled {
		t.Fatalf("rule 0 basic fields mismatch: id=%q status=%q", aws.ToString(r0.ID), string(r0.Status))
	}
	if r0.Filter == nil || r0.Filter.And == nil || aws.ToString(r0.Filter.And.Prefix) != "logs/" {
		t.Fatalf("rule 0 filter and prefix mismatch: %+v", r0.Filter)
	}
	if len(r0.Filter.And.Tags) != 1 || aws.ToString(r0.Filter.And.Tags[0].Key) != "app" || aws.ToString(r0.Filter.And.Tags[0].Value) != "api" {
		t.Fatalf("rule 0 filter tags mismatch: %+v", r0.Filter.And.Tags)
	}
	if aws.ToInt64(r0.Filter.And.ObjectSizeGreaterThan) != 128 || aws.ToInt64(r0.Filter.And.ObjectSizeLessThan) != 4096 {
		t.Fatalf("rule 0 filter size bounds mismatch: gt=%d lt=%d", aws.ToInt64(r0.Filter.And.ObjectSizeGreaterThan), aws.ToInt64(r0.Filter.And.ObjectSizeLessThan))
	}
	if r0.Expiration == nil || r0.Expiration.Date == nil || r0.Expiration.Date.UTC().Format("2006-01-02T15:04:05.000Z") != "2030-01-01T00:00:00.000Z" {
		t.Fatalf("rule 0 expiration date mismatch: %+v", r0.Expiration)
	}
	if len(r0.Transitions) != 1 || aws.ToInt32(r0.Transitions[0].Days) != 30 || r0.Transitions[0].StorageClass != s3types.TransitionStorageClassGlacier {
		t.Fatalf("rule 0 transition mismatch: %+v", r0.Transitions)
	}
	if len(r0.NoncurrentVersionTransitions) != 1 {
		t.Fatalf("rule 0 expected one noncurrent transition, got %d", len(r0.NoncurrentVersionTransitions))
	}
	if aws.ToInt32(r0.NoncurrentVersionTransitions[0].NoncurrentDays) != 14 ||
		aws.ToInt32(r0.NoncurrentVersionTransitions[0].NewerNoncurrentVersions) != 3 ||
		r0.NoncurrentVersionTransitions[0].StorageClass != s3types.TransitionStorageClassStandardIa {
		t.Fatalf("rule 0 noncurrent transition mismatch: %+v", r0.NoncurrentVersionTransitions[0])
	}
	if r0.NoncurrentVersionExpiration == nil ||
		aws.ToInt32(r0.NoncurrentVersionExpiration.NoncurrentDays) != 60 ||
		aws.ToInt32(r0.NoncurrentVersionExpiration.NewerNoncurrentVersions) != 10 {
		t.Fatalf("rule 0 noncurrent expiration mismatch: %+v", r0.NoncurrentVersionExpiration)
	}
	if r0.AbortIncompleteMultipartUpload == nil || aws.ToInt32(r0.AbortIncompleteMultipartUpload.DaysAfterInitiation) != 7 {
		t.Fatalf("rule 0 abort multipart mismatch: %+v", r0.AbortIncompleteMultipartUpload)
	}

	r1 := cfg.Rules[1]
	if aws.ToString(r1.ID) != "expire-delete-markers" || r1.Filter == nil || aws.ToString(r1.Filter.Prefix) != "tmp/" {
		t.Fatalf("rule 1 basic filter mismatch: %+v", r1)
	}
	if r1.Expiration == nil || !aws.ToBool(r1.Expiration.ExpiredObjectDeleteMarker) {
		t.Fatalf("rule 1 expired delete marker mismatch: %+v", r1.Expiration)
	}

	encoded, err := encodeLifecycleConfigXML(cfg.Rules)
	if err != nil {
		t.Fatalf("encode expanded lifecycle xml: %v", err)
	}
	roundTrip, err := decodeLifecycleConfigXML(bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("decode roundtrip lifecycle xml: %v", err)
	}
	if len(roundTrip.Rules) != 2 {
		t.Fatalf("expected 2 roundtrip rules, got %d", len(roundTrip.Rules))
	}
	rt0 := roundTrip.Rules[0]
	if len(rt0.Transitions) != 1 || rt0.Transitions[0].StorageClass != s3types.TransitionStorageClassGlacier {
		t.Fatalf("roundtrip transition mismatch: %+v", rt0.Transitions)
	}
	if rt0.Filter == nil || rt0.Filter.And == nil || len(rt0.Filter.And.Tags) != 1 {
		t.Fatalf("roundtrip filter mismatch: %+v", rt0.Filter)
	}
	if rt0.NoncurrentVersionExpiration == nil || rt0.AbortIncompleteMultipartUpload == nil {
		t.Fatalf("roundtrip noncurrent/abort mismatch: noncurrent=%+v abort=%+v", rt0.NoncurrentVersionExpiration, rt0.AbortIncompleteMultipartUpload)
	}
	rt1 := roundTrip.Rules[1]
	if rt1.Expiration == nil || !aws.ToBool(rt1.Expiration.ExpiredObjectDeleteMarker) {
		t.Fatalf("roundtrip expired delete marker mismatch: %+v", rt1.Expiration)
	}
}

func TestDecodeBodyForS3WriteAWSChunked(t *testing.T) {
	newAuth := func() *sigv4.Auth {
		return &sigv4.Auth{
			AccessKey:    "test-access-key",
			Date:         "20260207",
			Region:       "us-east-1",
			Service:      "s3",
			SignatureHex: strings.Repeat("0", 64),
			AmzDate:      "20260207T010203Z",
		}
	}

	t.Run("valid aws-chunked payload", func(t *testing.T) {
		auth := newAuth()
		encoded := signedAWSChunkedPayloadForTest(t, "password", auth, [][]byte{
			[]byte("hello"),
			[]byte(" world"),
		})

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader(encoded))
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		req.Header.Set("x-amz-decoded-content-length", "11")

		body, cl, err := sigv4.DecodeBodyForS3Write(req, sigv4.NewAWSChunkSignatureVerifier(auth, "password"))
		if err != nil {
			t.Fatalf("decodeBodyForS3Write returned error: %v", err)
		}
		defer body.Close()
		if cl != 11 {
			t.Fatalf("decoded content length mismatch: got=%d want=11", cl)
		}

		got, err := io.ReadAll(body)
		if err != nil {
			t.Fatalf("read decoded aws-chunked body: %v", err)
		}
		if string(got) != "hello world" {
			t.Fatalf("decoded body mismatch: got=%q want=%q", string(got), "hello world")
		}
	})

	t.Run("invalid chunk signature", func(t *testing.T) {
		auth := newAuth()
		encoded := signedAWSChunkedPayloadForTest(t, "password", auth, [][]byte{
			[]byte("hello"),
		})
		encoded = tamperFirstChunkSignatureForTest(t, encoded)

		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader(encoded))
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		req.Header.Set("x-amz-decoded-content-length", "5")

		body, _, err := sigv4.DecodeBodyForS3Write(req, sigv4.NewAWSChunkSignatureVerifier(auth, "password"))
		if err != nil {
			t.Fatalf("decodeBodyForS3Write returned unexpected error: %v", err)
		}
		defer body.Close()

		if _, err := io.ReadAll(body); !errors.Is(err, sigv4.ErrInvalidChunkSignature) {
			t.Fatalf("expected invalid chunk signature error, got: %v", err)
		}
	})

	t.Run("missing decoded length header", func(t *testing.T) {
		auth := newAuth()
		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader(""))
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		if _, _, err := sigv4.DecodeBodyForS3Write(req, sigv4.NewAWSChunkSignatureVerifier(auth, "password")); err == nil {
			t.Fatalf("expected decodeBodyForS3Write to fail for missing x-amz-decoded-content-length")
		}
	})
}

func TestValidateSigV4RequestTime(t *testing.T) {
	now := time.Date(2026, 2, 7, 12, 0, 0, 0, time.UTC)

	t.Run("within allowed skew", func(t *testing.T) {
		reqTime := now.Add(-10 * time.Minute)
		auth := &sigv4.Auth{
			Date:    reqTime.Format("20060102"),
			AmzDate: reqTime.Format("20060102T150405Z"),
		}
		if err := sigv4.ValidateSigV4RequestTime(auth, now, 15*time.Minute); err != nil {
			t.Fatalf("expected valid request time, got error: %v", err)
		}
	})

	t.Run("too old", func(t *testing.T) {
		reqTime := now.Add(-16 * time.Minute)
		auth := &sigv4.Auth{
			Date:    reqTime.Format("20060102"),
			AmzDate: reqTime.Format("20060102T150405Z"),
		}
		if err := sigv4.ValidateSigV4RequestTime(auth, now, 15*time.Minute); !errors.Is(err, sigv4.ErrSigV4RequestOutsideMaxSkew) {
			t.Fatalf("expected skew error, got: %v", err)
		}
	})

	t.Run("too far in future", func(t *testing.T) {
		reqTime := now.Add(16 * time.Minute)
		auth := &sigv4.Auth{
			Date:    reqTime.Format("20060102"),
			AmzDate: reqTime.Format("20060102T150405Z"),
		}
		if err := sigv4.ValidateSigV4RequestTime(auth, now, 15*time.Minute); !errors.Is(err, sigv4.ErrSigV4RequestOutsideMaxSkew) {
			t.Fatalf("expected skew error, got: %v", err)
		}
	})

	t.Run("invalid amz date", func(t *testing.T) {
		auth := &sigv4.Auth{
			Date:    now.Format("20060102"),
			AmzDate: "not-a-date",
		}
		if err := sigv4.ValidateSigV4RequestTime(auth, now, 15*time.Minute); !errors.Is(err, sigv4.ErrInvalidAmzDate) {
			t.Fatalf("expected invalid amz date error, got: %v", err)
		}
	})

	t.Run("credential scope date mismatch", func(t *testing.T) {
		reqTime := now
		auth := &sigv4.Auth{
			Date:    "20000101",
			AmzDate: reqTime.Format("20060102T150405Z"),
		}
		if err := sigv4.ValidateSigV4RequestTime(auth, now, 15*time.Minute); !errors.Is(err, sigv4.ErrSigV4DateScopeMismatch) {
			t.Fatalf("expected date mismatch error, got: %v", err)
		}
	})
}

func TestGroupCacheCredentialAwareAndBounded(t *testing.T) {
	c := gatewaycache.New(2*time.Second, 2)

	g1 := map[string]struct{}{"team1-rw": {}}
	c.Set("u1@example.com", "pass1", g1)
	if _, ok := c.Get("u1@example.com", "wrong-pass"); ok {
		t.Fatalf("cache hit with wrong password should not be allowed")
	}
	got, ok := c.Get("u1@example.com", "pass1")
	if !ok {
		t.Fatalf("expected cache hit for correct credentials")
	}
	if _, ok := got["team1-rw"]; !ok {
		t.Fatalf("expected cached group in returned map")
	}
	got["tamper"] = struct{}{}
	gotAgain, ok := c.Get("u1@example.com", "pass1")
	if !ok {
		t.Fatalf("expected cache hit for correct credentials after tamper attempt")
	}
	if _, ok := gotAgain["tamper"]; ok {
		t.Fatalf("cache returned mutable shared map; tampered key should not persist")
	}

	time.Sleep(10 * time.Millisecond)
	c.Set("u2@example.com", "pass2", map[string]struct{}{"team2-r": {}})
	time.Sleep(10 * time.Millisecond)
	c.Set("u3@example.com", "pass3", map[string]struct{}{"team3-rw": {}})

	if c.Len() > 2 {
		t.Fatalf("cache exceeded max size: len=%d max=2", c.Len())
	}
	if _, ok := c.Get("u1@example.com", "pass1"); ok {
		t.Fatalf("expected oldest entry to be evicted when cache is full")
	}
	if _, ok := c.Get("u2@example.com", "pass2"); !ok {
		t.Fatalf("expected second entry to remain in cache")
	}
	if _, ok := c.Get("u3@example.com", "pass3"); !ok {
		t.Fatalf("expected newest entry to remain in cache")
	}
}

func TestGroupCacheExpiredEntryIsRemovedOnLookup(t *testing.T) {
	c := gatewaycache.New(20*time.Millisecond, 10)
	c.Set("u1@example.com", "pass1", map[string]struct{}{"team1-rw": {}})
	time.Sleep(30 * time.Millisecond)

	if _, ok := c.Get("u1@example.com", "pass1"); ok {
		t.Fatalf("expected expired cache entry to miss")
	}
	if c.Len() != 0 {
		t.Fatalf("expected expired entry to be removed from cache, len=%d", c.Len())
	}
}

func TestNewHTTPServerAppliesDefaultsAndOverrides(t *testing.T) {
	srv := NewHTTPServer(gatewayconfig.Config{ListenAddr: ":8080"}, http.NewServeMux())
	if srv.ReadHeaderTimeout != gatewayconfig.DefaultReadHeaderTimeout {
		t.Fatalf("default read header timeout mismatch: got=%s want=%s", srv.ReadHeaderTimeout, gatewayconfig.DefaultReadHeaderTimeout)
	}
	if srv.IdleTimeout != gatewayconfig.DefaultIdleTimeout {
		t.Fatalf("default idle timeout mismatch: got=%s want=%s", srv.IdleTimeout, gatewayconfig.DefaultIdleTimeout)
	}
	if srv.MaxHeaderBytes != gatewayconfig.DefaultMaxHeaderBytes {
		t.Fatalf("default max header bytes mismatch: got=%d want=%d", srv.MaxHeaderBytes, gatewayconfig.DefaultMaxHeaderBytes)
	}

	overrideCfg := gatewayconfig.Config{
		ListenAddr:        ":9090",
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       11 * time.Second,
		WriteTimeout:      12 * time.Second,
		IdleTimeout:       13 * time.Second,
		MaxHeaderBytes:    8192,
	}
	overrideSrv := NewHTTPServer(overrideCfg, http.NewServeMux())
	if overrideSrv.ReadHeaderTimeout != 3*time.Second {
		t.Fatalf("override read header timeout mismatch: got=%s", overrideSrv.ReadHeaderTimeout)
	}
	if overrideSrv.ReadTimeout != 11*time.Second {
		t.Fatalf("override read timeout mismatch: got=%s", overrideSrv.ReadTimeout)
	}
	if overrideSrv.WriteTimeout != 12*time.Second {
		t.Fatalf("override write timeout mismatch: got=%s", overrideSrv.WriteTimeout)
	}
	if overrideSrv.IdleTimeout != 13*time.Second {
		t.Fatalf("override idle timeout mismatch: got=%s", overrideSrv.IdleTimeout)
	}
	if overrideSrv.MaxHeaderBytes != 8192 {
		t.Fatalf("override max header bytes mismatch: got=%d", overrideSrv.MaxHeaderBytes)
	}
}

func TestGatewayPreservesUpstreamErrorStatusAndHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	ctx := context.Background()

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("x-amz-request-id", "req-123")
		w.Header().Set("x-amz-id-2", "id2-abc")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>SlowDown</Code><Message>please retry</Message></Error>`))
	}))
	defer upstreamSrv.Close()

	upstreamClient := testutil.NewS3Client(t, ctx, upstreamSrv.URL, "us-east-1", "upstream-ak", "upstream-sk")
	gw := New(gatewayconfig.Config{}, upstreamClient)
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := authz.WithRules(r.Context(), []authz.Rule{{BucketPrefix: "team2", Perm: authz.PermReadWrite}})
		gw.ServeHTTP(w, r.WithContext(ctx))
	}))
	defer gwSrv.Close()

	resp, err := http.Get(gwSrv.URL + "/team2-chaos/missing-object.txt")
	if err != nil {
		t.Fatalf("get object through gateway: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read gateway error body: %v", err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status mismatch: got=%d want=%d body=%s", resp.StatusCode, http.StatusServiceUnavailable, string(body))
	}
	if got := resp.Header.Get("x-amz-request-id"); got != "req-123" {
		t.Fatalf("x-amz-request-id mismatch: got=%q want=%q", got, "req-123")
	}
	if got := resp.Header.Get("x-amz-id-2"); got != "id2-abc" {
		t.Fatalf("x-amz-id-2 mismatch: got=%q want=%q", got, "id2-abc")
	}
	if !strings.Contains(string(body), "<Code>SlowDown</Code>") {
		t.Fatalf("expected SlowDown error code, body=%s", string(body))
	}
}

func TestGatewayHandlesUpstreamLatencySpike(t *testing.T) {
	ctx := context.Background()

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets></Buckets></ListAllMyBucketsResult>`))
	}))
	defer upstreamSrv.Close()

	upstreamClient := testutil.NewS3Client(t, ctx, upstreamSrv.URL, "us-east-1", "upstream-ak", "upstream-sk")
	gw := New(gatewayconfig.Config{}, upstreamClient)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	timeoutCtx, cancel := context.WithTimeout(req.Context(), 150*time.Millisecond)
	defer cancel()
	req = req.WithContext(authz.WithRules(timeoutCtx, []authz.Rule{{BucketPrefix: "team2", Perm: authz.PermReadWrite}}))

	rr := httptest.NewRecorder()
	start := time.Now()
	gw.ServeHTTP(rr, req)
	elapsed := time.Since(start)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on upstream timeout, got=%d body=%s", rr.Code, rr.Body.String())
	}
	if elapsed > 1200*time.Millisecond {
		t.Fatalf("gateway took too long to fail on latency spike: elapsed=%s", elapsed)
	}
}

func TestHandleGetObjectAttributesIncludesChecksum(t *testing.T) {
	ctx := context.Background()

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("upstream expected method GET, got %s", r.Method)
		}
		if _, ok := r.URL.Query()["attributes"]; !ok {
			t.Fatalf("upstream expected ?attributes query, got raw query %q", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<GetObjectAttributesOutput xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <ETag>"etag-1"</ETag>
  <Checksum>
    <ChecksumCRC32>AAAAAA==</ChecksumCRC32>
    <ChecksumCRC32C>BBBBBB==</ChecksumCRC32C>
    <ChecksumCRC64NVME>CCCCCC==</ChecksumCRC64NVME>
    <ChecksumSHA1>DDDDDD==</ChecksumSHA1>
    <ChecksumSHA256>EEEEEE==</ChecksumSHA256>
    <ChecksumType>FULL_OBJECT</ChecksumType>
  </Checksum>
</GetObjectAttributesOutput>`))
	}))
	defer upstreamSrv.Close()

	upstreamClient := testutil.NewS3Client(t, ctx, upstreamSrv.URL, "us-east-1", "upstream-ak", "upstream-sk")
	gw := New(gatewayconfig.Config{}, upstreamClient)

	req := httptest.NewRequest(http.MethodGet, "/team2-checksum/object.txt?attributes", nil)
	req.Header.Set("x-amz-object-attributes", "Checksum")
	req = req.WithContext(authz.WithRules(req.Context(), []authz.Rule{{BucketPrefix: "team2", Perm: authz.PermRead}}))

	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from get object attributes, got=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"<Checksum>",
		"<ChecksumCRC32>AAAAAA==</ChecksumCRC32>",
		"<ChecksumCRC32C>BBBBBB==</ChecksumCRC32C>",
		"<ChecksumCRC64NVME>CCCCCC==</ChecksumCRC64NVME>",
		"<ChecksumSHA1>DDDDDD==</ChecksumSHA1>",
		"<ChecksumSHA256>EEEEEE==</ChecksumSHA256>",
		"<ChecksumType>FULL_OBJECT</ChecksumType>",
		"</Checksum>",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected checksum element %q in response body=%s", want, body)
		}
	}
}

func TestLdapS3upstreamAuthCacheSurvivesLDAPOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := testutil.WriteGatewayGlauthConfig(t)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	ldapStopped := false
	stopLDAPOnce := func() {
		if ldapStopped {
			return
		}
		stopLDAP()
		ldapStopped = true
	}
	defer stopLDAPOnce()

	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               2 * time.Minute,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))
	defer gwSrv.Close()

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	rwClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(t, rwAccessKey))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	roClient := testutil.NewS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, mustGatewaySecretForAccessKey(t, roAccessKey))

	bucket := fmt.Sprintf("team2-ldap-cache-%d", time.Now().UnixNano())
	if _, err := rwClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway for cache warm-up: %v", err)
	}

	stopLDAPOnce()

	if _, err := rwClient.ListBuckets(ctx, &s3.ListBucketsInput{}); err != nil {
		t.Fatalf("cached rw user should continue to work while ldap is down: %v", err)
	}

	putBody := []byte("ldap cache survives outage")
	if _, err := rwClient.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String("cache/probe.txt"),
		Body:          bytes.NewReader(putBody),
		ContentLength: aws.Int64(int64(len(putBody))),
	}); err != nil {
		t.Fatalf("cached rw user put object should work while ldap is down: %v", err)
	}

	if _, err := roClient.ListBuckets(ctx, &s3.ListBucketsInput{}); err == nil {
		t.Fatalf("expected uncached readonly user auth to fail while ldap is down")
	} else {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected smithy API error for readonly auth failure, got: %v", err)
		}
		if apiErr.ErrorCode() != "AccessDenied" {
			t.Fatalf("expected AccessDenied for readonly auth failure, got code=%q err=%v", apiErr.ErrorCode(), err)
		}
	}
}

type integrationEnv struct {
	ctx            context.Context
	cfg            gatewayconfig.Config
	rwClient       *s3.Client
	roClient       *s3.Client
	upstreamClient *s3.Client
	cleanup        func()
}

func setupIntegrationEnv(tb testing.TB) *integrationEnv {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	ldapCfgPath := testutil.WriteGatewayGlauthConfig(tb)
	ldapURL, stopLDAP := testutil.StartGlauthWithConfig(ctx, tb, ldapCfgPath, "ldap")
	minioURL, stopMinio := testutil.StartMinio(ctx, tb, "minioadmin", "minioadmin")

	cfg := gatewayconfig.Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		LDAPDomain:             "example.com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}

	up, err := upstream.New(ctx, cfg)
	if err != nil {
		stopMinio()
		stopLDAP()
		cancel()
		tb.Fatalf("init upstream s3: %v", err)
	}
	gw := New(cfg, up)
	gwSrv := httptest.NewServer(gw.WithAuth(gw, adminWebpageHandler(gw)))

	rwAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("testuser:dogood"))
	rwClient := testutil.NewS3Client(tb, ctx, gwSrv.URL, "us-east-1", rwAccessKey, mustGatewaySecretForAccessKey(tb, rwAccessKey))
	roAccessKey := "AD" + base64.StdEncoding.EncodeToString([]byte("readonly:dogood"))
	roClient := testutil.NewS3Client(tb, ctx, gwSrv.URL, "us-east-1", roAccessKey, mustGatewaySecretForAccessKey(tb, roAccessKey))
	upstreamClient := testutil.NewS3Client(tb, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	env := &integrationEnv{
		ctx:            ctx,
		cfg:            cfg,
		rwClient:       rwClient,
		roClient:       roClient,
		upstreamClient: upstreamClient,
	}
	env.cleanup = func() {
		gwSrv.Close()
		stopMinio()
		stopLDAP()
		cancel()
	}
	tb.Cleanup(env.cleanup)
	return env
}

func TestFullIntegrationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full integration performance test in short mode")
	}

	env := setupIntegrationEnv(t)
	payload := bytes.Repeat([]byte("perf-gateway-"), 16*1024) // ~192 KiB
	ops := 24

	gatewayBucket := fmt.Sprintf("team2-perf-%d", time.Now().UnixNano())
	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(gatewayBucket),
	}); err != nil {
		t.Fatalf("create gateway performance bucket: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < ops; i++ {
			key := fmt.Sprintf("perf/gateway/%03d.bin", i)
			_, _ = env.rwClient.DeleteObject(env.ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(gatewayBucket),
				Key:    aws.String(key),
			})
		}
		_, _ = env.rwClient.DeleteBucket(env.ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(gatewayBucket),
		})
	})

	upstreamBucket := fmt.Sprintf("upstream-perf-%d", time.Now().UnixNano())
	if _, err := env.upstreamClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(upstreamBucket),
	}); err != nil {
		t.Fatalf("create upstream performance bucket: %v", err)
	}
	t.Cleanup(func() {
		for i := 0; i < ops; i++ {
			key := fmt.Sprintf("perf/upstream/%03d.bin", i)
			_, _ = env.upstreamClient.DeleteObject(env.ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(upstreamBucket),
				Key:    aws.String(key),
			})
		}
		_, _ = env.upstreamClient.DeleteBucket(env.ctx, &s3.DeleteBucketInput{
			Bucket: aws.String(upstreamBucket),
		})
	})

	gatewayPutStart := time.Now()
	for i := 0; i < ops; i++ {
		key := fmt.Sprintf("perf/gateway/%03d.bin", i)
		if _, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
			Bucket:        aws.String(gatewayBucket),
			Key:           aws.String(key),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
			ContentType:   aws.String("application/octet-stream"),
		}); err != nil {
			t.Fatalf("gateway put object %q: %v", key, err)
		}
	}
	gatewayPutDur := time.Since(gatewayPutStart)

	gatewayGetStart := time.Now()
	for i := 0; i < ops; i++ {
		key := fmt.Sprintf("perf/gateway/%03d.bin", i)
		out, err := env.rwClient.GetObject(env.ctx, &s3.GetObjectInput{
			Bucket: aws.String(gatewayBucket),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("gateway get object %q: %v", key, err)
		}
		body, readErr := io.ReadAll(out.Body)
		closeErr := out.Body.Close()
		if readErr != nil {
			t.Fatalf("read gateway object %q: %v", key, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close gateway object %q body: %v", key, closeErr)
		}
		if !bytes.Equal(body, payload) {
			t.Fatalf("gateway payload mismatch for key %q: got=%d want=%d", key, len(body), len(payload))
		}
	}
	gatewayGetDur := time.Since(gatewayGetStart)

	upstreamPutStart := time.Now()
	for i := 0; i < ops; i++ {
		key := fmt.Sprintf("perf/upstream/%03d.bin", i)
		if _, err := env.upstreamClient.PutObject(env.ctx, &s3.PutObjectInput{
			Bucket:        aws.String(upstreamBucket),
			Key:           aws.String(key),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
			ContentType:   aws.String("application/octet-stream"),
		}); err != nil {
			t.Fatalf("upstream put object %q: %v", key, err)
		}
	}
	upstreamPutDur := time.Since(upstreamPutStart)

	upstreamGetStart := time.Now()
	for i := 0; i < ops; i++ {
		key := fmt.Sprintf("perf/upstream/%03d.bin", i)
		out, err := env.upstreamClient.GetObject(env.ctx, &s3.GetObjectInput{
			Bucket: aws.String(upstreamBucket),
			Key:    aws.String(key),
		})
		if err != nil {
			t.Fatalf("upstream get object %q: %v", key, err)
		}
		body, readErr := io.ReadAll(out.Body)
		closeErr := out.Body.Close()
		if readErr != nil {
			t.Fatalf("read upstream object %q: %v", key, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close upstream object %q body: %v", key, closeErr)
		}
		if !bytes.Equal(body, payload) {
			t.Fatalf("upstream payload mismatch for key %q: got=%d want=%d", key, len(body), len(payload))
		}
	}
	upstreamGetDur := time.Since(upstreamGetStart)

	totalBytes := float64(len(payload) * ops)
	gatewayPutMBps := totalBytes / gatewayPutDur.Seconds() / (1024 * 1024)
	gatewayGetMBps := totalBytes / gatewayGetDur.Seconds() / (1024 * 1024)
	upstreamPutMBps := totalBytes / upstreamPutDur.Seconds() / (1024 * 1024)
	upstreamGetMBps := totalBytes / upstreamGetDur.Seconds() / (1024 * 1024)

	gatewayPutRatio := float64(gatewayPutDur) / float64(upstreamPutDur)
	gatewayGetRatio := float64(gatewayGetDur) / float64(upstreamGetDur)

	t.Logf(
		"performance summary: ops=%d payload=%dB gatewayPut=%s (%.2f MiB/s) gatewayGet=%s (%.2f MiB/s) upstreamPut=%s (%.2f MiB/s) upstreamGet=%s (%.2f MiB/s) putRatio=%.2fx getRatio=%.2fx",
		ops, len(payload),
		gatewayPutDur, gatewayPutMBps,
		gatewayGetDur, gatewayGetMBps,
		upstreamPutDur, upstreamPutMBps,
		upstreamGetDur, upstreamGetMBps,
		gatewayPutRatio, gatewayGetRatio,
	)

	// Validate performance results with conservative thresholds to avoid flaky CI failures.
	if gatewayPutMBps <= 0 || gatewayGetMBps <= 0 {
		t.Fatalf("gateway throughput should be > 0 MiB/s: put=%.2f get=%.2f", gatewayPutMBps, gatewayGetMBps)
	}
	if upstreamPutMBps <= 0 || upstreamGetMBps <= 0 {
		t.Fatalf("upstream throughput should be > 0 MiB/s: put=%.2f get=%.2f", upstreamPutMBps, upstreamGetMBps)
	}
	if gatewayPutRatio > 50 {
		t.Fatalf("gateway put slowdown too high: ratio=%.2fx threshold=50x", gatewayPutRatio)
	}
	if gatewayGetRatio > 50 {
		t.Fatalf("gateway get slowdown too high: ratio=%.2fx threshold=50x", gatewayGetRatio)
	}
}

func TestLdapS3upstreamHeadAndDeleteBucket(t *testing.T) {
	env := setupIntegrationEnv(t)
	bucket := fmt.Sprintf("team2-head-%d", time.Now().UnixNano())
	key := "head/object.txt"
	body := []byte("head object payload")

	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}
	if _, err := env.rwClient.HeadBucket(env.ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("head bucket via gateway rw: %v", err)
	}
	if _, err := env.roClient.HeadBucket(env.ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("head bucket via gateway readonly: %v", err)
	}

	if _, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader(body),
		ContentLength: aws.Int64(int64(len(body))),
		ContentType:   aws.String("text/plain"),
	}); err != nil {
		t.Fatalf("put object via gateway: %v", err)
	}

	rwHead, err := env.rwClient.HeadObject(env.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("head object via gateway rw: %v", err)
	}
	if aws.ToInt64(rwHead.ContentLength) != int64(len(body)) {
		t.Fatalf("head object content length mismatch: got=%d want=%d", aws.ToInt64(rwHead.ContentLength), len(body))
	}
	if rwHead.ETag == nil || *rwHead.ETag == "" {
		t.Fatalf("head object should include ETag")
	}
	roHead, err := env.roClient.HeadObject(env.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("head object via gateway readonly: %v", err)
	}
	if aws.ToInt64(roHead.ContentLength) != int64(len(body)) {
		t.Fatalf("readonly head object content length mismatch: got=%d want=%d", aws.ToInt64(roHead.ContentLength), len(body))
	}

	if _, err := env.roClient.DeleteBucket(env.ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	}); err == nil {
		t.Fatalf("expected readonly DeleteBucket to fail")
	}

	if _, err := env.rwClient.DeleteObject(env.ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}); err != nil {
		t.Fatalf("delete object via gateway: %v", err)
	}
	if _, err := env.rwClient.DeleteBucket(env.ctx, &s3.DeleteBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("delete bucket via gateway: %v", err)
	}
	if _, err := env.upstreamClient.HeadBucket(env.ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucket),
	}); err == nil {
		t.Fatalf("expected upstream head bucket to fail after delete")
	}
}

func TestLdapS3upstreamCopyObjectAndUploadPartCopy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	env := setupIntegrationEnv(t)
	bucket := fmt.Sprintf("team2-copy-%d", time.Now().UnixNano())
	srcKey := "copy/source.bin"
	dstKey := "copy/direct.bin"
	mpDstKey := "copy/mp.bin"
	srcBody := bytes.Repeat([]byte("abcdef"), 1024*1024) // 6 MiB

	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}
	if _, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(srcKey),
		Body:          bytes.NewReader(srcBody),
		ContentLength: aws.Int64(int64(len(srcBody))),
		ContentType:   aws.String("application/octet-stream"),
		Metadata: map[string]string{
			"origin": "source",
		},
	}); err != nil {
		t.Fatalf("put source object via gateway: %v", err)
	}

	copySource := bucket + "/" + srcKey
	if _, err := env.rwClient.CopyObject(env.ctx, &s3.CopyObjectInput{
		Bucket:            aws.String(bucket),
		Key:               aws.String(dstKey),
		CopySource:        aws.String(copySource),
		MetadataDirective: s3types.MetadataDirectiveReplace,
		Metadata: map[string]string{
			"origin": "copy",
		},
	}); err != nil {
		t.Fatalf("copy object via gateway: %v", err)
	}

	dstObj, err := env.upstreamClient.GetObject(env.ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(dstKey),
	})
	if err != nil {
		t.Fatalf("get copied object from upstream: %v", err)
	}
	defer dstObj.Body.Close()
	dstBody, err := io.ReadAll(dstObj.Body)
	if err != nil {
		t.Fatalf("read copied object from upstream: %v", err)
	}
	if !bytes.Equal(dstBody, srcBody) {
		t.Fatalf("copied body mismatch: got=%d want=%d", len(dstBody), len(srcBody))
	}
	if dstObj.Metadata["origin"] != "copy" {
		t.Fatalf("copied metadata mismatch: got=%v", dstObj.Metadata)
	}

	if _, err := env.rwClient.CopyObject(env.ctx, &s3.CopyObjectInput{
		Bucket:            aws.String(bucket),
		Key:               aws.String("copy/conditional-fail.bin"),
		CopySource:        aws.String(copySource),
		CopySourceIfMatch: aws.String(`"does-not-match"`),
	}); err == nil {
		t.Fatalf("expected copy object with failing source condition to fail")
	}

	mpCreate, err := env.rwClient.CreateMultipartUpload(env.ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(mpDstKey),
	})
	if err != nil {
		t.Fatalf("create multipart upload for upload-part-copy: %v", err)
	}
	if mpCreate.UploadId == nil || *mpCreate.UploadId == "" {
		t.Fatalf("multipart upload id should not be empty")
	}

	part1, err := env.rwClient.UploadPartCopy(env.ctx, &s3.UploadPartCopyInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(mpDstKey),
		UploadId:        mpCreate.UploadId,
		PartNumber:      aws.Int32(1),
		CopySource:      aws.String(copySource),
		CopySourceRange: aws.String("bytes=0-5242879"),
	})
	if err != nil {
		t.Fatalf("upload part copy 1 via gateway: %v", err)
	}
	part2, err := env.rwClient.UploadPartCopy(env.ctx, &s3.UploadPartCopyInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(mpDstKey),
		UploadId:        mpCreate.UploadId,
		PartNumber:      aws.Int32(2),
		CopySource:      aws.String(copySource),
		CopySourceRange: aws.String(fmt.Sprintf("bytes=5242880-%d", len(srcBody)-1)),
	})
	if err != nil {
		t.Fatalf("upload part copy 2 via gateway: %v", err)
	}
	if part1.CopyPartResult == nil || part1.CopyPartResult.ETag == nil || part2.CopyPartResult == nil || part2.CopyPartResult.ETag == nil {
		t.Fatalf("upload part copy should return etags for completed parts")
	}
	if _, err := env.rwClient.CompleteMultipartUpload(env.ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(mpDstKey),
		UploadId: mpCreate.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: []s3types.CompletedPart{
				{PartNumber: aws.Int32(1), ETag: part1.CopyPartResult.ETag},
				{PartNumber: aws.Int32(2), ETag: part2.CopyPartResult.ETag},
			},
		},
	}); err != nil {
		t.Fatalf("complete multipart upload-part-copy via gateway: %v", err)
	}
	mpObj, err := env.upstreamClient.GetObject(env.ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(mpDstKey),
	})
	if err != nil {
		t.Fatalf("get multipart-copied object from upstream: %v", err)
	}
	defer mpObj.Body.Close()
	mpBody, err := io.ReadAll(mpObj.Body)
	if err != nil {
		t.Fatalf("read multipart-copied object from upstream: %v", err)
	}
	if !bytes.Equal(mpBody, srcBody) {
		t.Fatalf("multipart copied body mismatch: got=%d want=%d", len(mpBody), len(srcBody))
	}

	if _, err := env.roClient.CopyObject(env.ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String("copy/readonly-fail.bin"),
		CopySource: aws.String(copySource),
	}); err == nil {
		t.Fatalf("expected readonly copy object to fail")
	}
}

func TestLdapS3upstreamCopySourceBucketAuthorization(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	env := setupIntegrationEnv(t)
	sourceBucket := fmt.Sprintf("private-src-%d", time.Now().UnixNano())
	destBucket := fmt.Sprintf("team2-copyauth-%d", time.Now().UnixNano())
	sourceKey := "secret/source.txt"
	destKey := "copy/denied.txt"
	sourceBody := []byte("sensitive payload")

	if _, err := env.upstreamClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(sourceBucket),
	}); err != nil {
		t.Fatalf("create source bucket via upstream: %v", err)
	}
	if _, err := env.upstreamClient.PutObject(env.ctx, &s3.PutObjectInput{
		Bucket:        aws.String(sourceBucket),
		Key:           aws.String(sourceKey),
		Body:          bytes.NewReader(sourceBody),
		ContentLength: aws.Int64(int64(len(sourceBody))),
	}); err != nil {
		t.Fatalf("put source object via upstream: %v", err)
	}
	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(destBucket),
	}); err != nil {
		t.Fatalf("create destination bucket via gateway: %v", err)
	}

	copySource := sourceBucket + "/" + sourceKey
	if _, err := env.rwClient.CopyObject(env.ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(destBucket),
		Key:        aws.String(destKey),
		CopySource: aws.String(copySource),
	}); err == nil {
		t.Fatalf("expected copy object from unauthorized source bucket to fail")
	} else {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected smithy API error for unauthorized copy object, got: %v", err)
		}
		if apiErr.ErrorCode() != "AccessDenied" {
			t.Fatalf("expected AccessDenied for unauthorized copy object, got code=%q err=%v", apiErr.ErrorCode(), err)
		}
	}
	if _, err := env.upstreamClient.HeadObject(env.ctx, &s3.HeadObjectInput{
		Bucket: aws.String(destBucket),
		Key:    aws.String(destKey),
	}); err == nil {
		t.Fatalf("copy object should not have created destination object when source bucket is unauthorized")
	}

	mpKey := "copy/denied-multipart.bin"
	createOut, err := env.rwClient.CreateMultipartUpload(env.ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(destBucket),
		Key:    aws.String(mpKey),
	})
	if err != nil {
		t.Fatalf("create multipart upload via gateway: %v", err)
	}
	if createOut.UploadId == nil || *createOut.UploadId == "" {
		t.Fatalf("multipart upload id should not be empty")
	}
	defer func() {
		_, _ = env.rwClient.AbortMultipartUpload(env.ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(destBucket),
			Key:      aws.String(mpKey),
			UploadId: createOut.UploadId,
		})
	}()

	if _, err := env.rwClient.UploadPartCopy(env.ctx, &s3.UploadPartCopyInput{
		Bucket:     aws.String(destBucket),
		Key:        aws.String(mpKey),
		UploadId:   createOut.UploadId,
		PartNumber: aws.Int32(1),
		CopySource: aws.String(copySource),
	}); err == nil {
		t.Fatalf("expected upload part copy from unauthorized source bucket to fail")
	} else {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("expected smithy API error for unauthorized upload part copy, got: %v", err)
		}
		if apiErr.ErrorCode() != "AccessDenied" {
			t.Fatalf("expected AccessDenied for unauthorized upload part copy, got code=%q err=%v", apiErr.ErrorCode(), err)
		}
	}
}

func TestLdapS3upstreamDeleteObjectsVersioningAndListObjectVersions(t *testing.T) {
	env := setupIntegrationEnv(t)
	bucket := fmt.Sprintf("team2-versions-%d", time.Now().UnixNano())
	key := "versions/item.txt"

	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}
	if _, err := env.rwClient.PutBucketVersioning(env.ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucket),
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusEnabled,
		},
	}); err != nil {
		t.Fatalf("enable versioning via gateway: %v", err)
	}
	if _, err := env.roClient.PutBucketVersioning(env.ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucket),
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: s3types.BucketVersioningStatusSuspended,
		},
	}); err == nil {
		t.Fatalf("expected readonly put bucket versioning to fail")
	}

	verOut, err := env.rwClient.GetBucketVersioning(env.ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("get bucket versioning via gateway: %v", err)
	}
	if verOut.Status != s3types.BucketVersioningStatusEnabled {
		t.Fatalf("unexpected versioning status: got=%q want=%q", verOut.Status, s3types.BucketVersioningStatusEnabled)
	}

	put1, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader([]byte("v1")),
		ContentLength: aws.Int64(2),
	})
	if err != nil {
		t.Fatalf("put version 1 via gateway: %v", err)
	}
	put2, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
		Bucket:        aws.String(bucket),
		Key:           aws.String(key),
		Body:          bytes.NewReader([]byte("v2")),
		ContentLength: aws.Int64(2),
	})
	if err != nil {
		t.Fatalf("put version 2 via gateway: %v", err)
	}
	if put1.VersionId == nil || put2.VersionId == nil || *put1.VersionId == "" || *put2.VersionId == "" {
		t.Fatalf("expected version ids for versioned puts: v1=%v v2=%v", put1.VersionId, put2.VersionId)
	}
	delOut, err := env.rwClient.DeleteObject(env.ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("delete current object to create delete marker via gateway: %v", err)
	}
	if delOut.VersionId == nil || *delOut.VersionId == "" {
		t.Fatalf("expected delete marker version id after delete")
	}

	upstreamVersions, err := env.upstreamClient.ListObjectVersions(env.ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String("versions/"),
	})
	if err != nil {
		t.Fatalf("list object versions via upstream: %v", err)
	}
	gatewayVersions, err := env.rwClient.ListObjectVersions(env.ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String("versions/"),
	})
	if err != nil {
		t.Fatalf("list object versions via gateway: %v", err)
	}

	makeVersionSigs := func(out *s3.ListObjectVersionsOutput) []string {
		sigs := make([]string, 0, len(out.Versions)+len(out.DeleteMarkers))
		for _, v := range out.Versions {
			sigs = append(sigs, fmt.Sprintf("V|%s|%s|%v", aws.ToString(v.Key), aws.ToString(v.VersionId), aws.ToBool(v.IsLatest)))
		}
		for _, d := range out.DeleteMarkers {
			sigs = append(sigs, fmt.Sprintf("D|%s|%s|%v", aws.ToString(d.Key), aws.ToString(d.VersionId), aws.ToBool(d.IsLatest)))
		}
		sort.Strings(sigs)
		return sigs
	}
	if got, want := strings.Join(makeVersionSigs(gatewayVersions), ","), strings.Join(makeVersionSigs(upstreamVersions), ","); got != want {
		t.Fatalf("list object versions mismatch: gateway=%q upstream=%q", got, want)
	}

	newListVersionsWithOptionalAttrsInput := func() *s3.ListObjectVersionsInput {
		return &s3.ListObjectVersionsInput{
			Bucket: aws.String(bucket),
			Prefix: aws.String("versions/"),
			OptionalObjectAttributes: []s3types.OptionalObjectAttributes{
				s3types.OptionalObjectAttributesRestoreStatus,
			},
		}
	}

	upstreamWithOptionalAttrs, upstreamWithOptionalAttrsErr := env.upstreamClient.ListObjectVersions(env.ctx, newListVersionsWithOptionalAttrsInput())
	gatewayWithOptionalAttrs, gatewayWithOptionalAttrsErr := env.rwClient.ListObjectVersions(env.ctx, newListVersionsWithOptionalAttrsInput())
	if (upstreamWithOptionalAttrsErr != nil) != (gatewayWithOptionalAttrsErr != nil) {
		t.Fatalf("list object versions with optional-object-attributes error mismatch: gatewayErr=%v upstreamErr=%v", gatewayWithOptionalAttrsErr, upstreamWithOptionalAttrsErr)
	}
	if upstreamWithOptionalAttrsErr != nil {
		var upstreamAPIErr smithy.APIError
		var gatewayAPIErr smithy.APIError
		if !errors.As(upstreamWithOptionalAttrsErr, &upstreamAPIErr) || !errors.As(gatewayWithOptionalAttrsErr, &gatewayAPIErr) {
			t.Fatalf("list object versions with optional-object-attributes expected smithy errors: gatewayErr=%v upstreamErr=%v", gatewayWithOptionalAttrsErr, upstreamWithOptionalAttrsErr)
		}
		if gatewayAPIErr.ErrorCode() != upstreamAPIErr.ErrorCode() {
			t.Fatalf("list object versions with optional-object-attributes error code mismatch: gateway=%q upstream=%q", gatewayAPIErr.ErrorCode(), upstreamAPIErr.ErrorCode())
		}
	} else if got, want := strings.Join(makeVersionSigs(gatewayWithOptionalAttrs), ","), strings.Join(makeVersionSigs(upstreamWithOptionalAttrs), ","); got != want {
		t.Fatalf("list object versions with optional-object-attributes mismatch: gateway=%q upstream=%q", got, want)
	}

	if _, err := env.roClient.DeleteObjects(env.ctx, &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &s3types.Delete{
			Objects: []s3types.ObjectIdentifier{
				{Key: aws.String(key)},
			},
		},
	}); err == nil {
		t.Fatalf("expected readonly delete objects to fail")
	}

	deleteReq := &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &s3types.Delete{
			Objects: []s3types.ObjectIdentifier{
				{Key: aws.String(key), VersionId: put1.VersionId},
				{Key: aws.String(key), VersionId: put2.VersionId},
				{Key: aws.String(key), VersionId: delOut.VersionId},
			},
		},
	}
	deleteRes, err := env.rwClient.DeleteObjects(env.ctx, deleteReq)
	if err != nil {
		t.Fatalf("delete objects via gateway: %v", err)
	}
	if len(deleteRes.Deleted) != 3 {
		t.Fatalf("expected 3 deleted entries, got %d", len(deleteRes.Deleted))
	}

	postDeleteVersions, err := env.rwClient.ListObjectVersions(env.ctx, &s3.ListObjectVersionsInput{
		Bucket: aws.String(bucket),
		Prefix: aws.String("versions/"),
	})
	if err != nil {
		t.Fatalf("list object versions after delete via gateway: %v", err)
	}
	for _, v := range postDeleteVersions.Versions {
		if aws.ToString(v.Key) == key {
			t.Fatalf("expected no remaining object versions for key %q, got version=%s", key, aws.ToString(v.VersionId))
		}
	}
	for _, d := range postDeleteVersions.DeleteMarkers {
		if aws.ToString(d.Key) == key {
			t.Fatalf("expected no remaining delete markers for key %q, got version=%s", key, aws.ToString(d.VersionId))
		}
	}
}

func TestLdapS3upstreamListObjectsV2FullSemantics(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	env := setupIntegrationEnv(t)
	bucket := fmt.Sprintf("team2-listv2full-%d", time.Now().UnixNano())

	if _, err := env.rwClient.CreateBucket(env.ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	}); err != nil {
		t.Fatalf("create bucket via gateway: %v", err)
	}

	objects := map[string][]byte{
		"a/1.txt":      []byte("one"),
		"a/2.txt":      []byte("two"),
		"a/sub/3.txt":  []byte("three"),
		"a/file 4.txt": []byte("four"),
		"b/1.txt":      []byte("b"),
		"z.txt":        []byte("z"),
	}
	for key, body := range objects {
		if _, err := env.rwClient.PutObject(env.ctx, &s3.PutObjectInput{
			Bucket:        aws.String(bucket),
			Key:           aws.String(key),
			Body:          bytes.NewReader(body),
			ContentLength: aws.Int64(int64(len(body))),
		}); err != nil {
			t.Fatalf("put object %q via gateway: %v", key, err)
		}
	}

	type listV2Sig struct {
		keys         []string
		commonPrefix []string
		nextToken    string
		isTruncated  bool
		keyCount     int32
		delimiter    string
		prefix       string
		startAfter   string
		encodingType string
	}
	makeListV2Sig := func(out *s3.ListObjectsV2Output) listV2Sig {
		keys := make([]string, 0, len(out.Contents))
		for _, o := range out.Contents {
			keys = append(keys, aws.ToString(o.Key))
		}
		prefixes := make([]string, 0, len(out.CommonPrefixes))
		for _, cp := range out.CommonPrefixes {
			prefixes = append(prefixes, aws.ToString(cp.Prefix))
		}
		sort.Strings(keys)
		sort.Strings(prefixes)
		return listV2Sig{
			keys:         keys,
			commonPrefix: prefixes,
			nextToken:    aws.ToString(out.NextContinuationToken),
			isTruncated:  aws.ToBool(out.IsTruncated),
			keyCount:     aws.ToInt32(out.KeyCount),
			delimiter:    aws.ToString(out.Delimiter),
			prefix:       aws.ToString(out.Prefix),
			startAfter:   aws.ToString(out.StartAfter),
			encodingType: string(out.EncodingType),
		}
	}

	assertMatchesUpstream := func(in *s3.ListObjectsV2Input, label string) *s3.ListObjectsV2Output {
		t.Helper()
		upstreamOut, err := env.upstreamClient.ListObjectsV2(env.ctx, in)
		if err != nil {
			t.Fatalf("%s list objects v2 via upstream: %v", label, err)
		}
		gatewayOut, err := env.rwClient.ListObjectsV2(env.ctx, in)
		if err != nil {
			t.Fatalf("%s list objects v2 via gateway: %v", label, err)
		}
		got, want := makeListV2Sig(gatewayOut), makeListV2Sig(upstreamOut)
		if fmt.Sprintf("%v", got) != fmt.Sprintf("%v", want) {
			t.Fatalf("%s list objects v2 mismatch: gateway=%+v upstream=%+v", label, got, want)
		}
		return gatewayOut
	}

	page1 := assertMatchesUpstream(&s3.ListObjectsV2Input{
		Bucket:       aws.String(bucket),
		Prefix:       aws.String("a/"),
		Delimiter:    aws.String("/"),
		MaxKeys:      aws.Int32(2),
		FetchOwner:   aws.Bool(true),
		EncodingType: s3types.EncodingTypeUrl,
		OptionalObjectAttributes: []s3types.OptionalObjectAttributes{
			s3types.OptionalObjectAttributesRestoreStatus,
		},
	}, "page1")
	if page1.NextContinuationToken != nil && *page1.NextContinuationToken != "" {
		_ = assertMatchesUpstream(&s3.ListObjectsV2Input{
			Bucket:            aws.String(bucket),
			Prefix:            aws.String("a/"),
			Delimiter:         aws.String("/"),
			MaxKeys:           aws.Int32(2),
			ContinuationToken: page1.NextContinuationToken,
			FetchOwner:        aws.Bool(true),
			EncodingType:      s3types.EncodingTypeUrl,
			OptionalObjectAttributes: []s3types.OptionalObjectAttributes{
				s3types.OptionalObjectAttributesRestoreStatus,
			},
		}, "page2")
	}

	_ = assertMatchesUpstream(&s3.ListObjectsV2Input{
		Bucket:       aws.String(bucket),
		Prefix:       aws.String("a/"),
		StartAfter:   aws.String("a/1.txt"),
		MaxKeys:      aws.Int32(1000),
		FetchOwner:   aws.Bool(true),
		EncodingType: s3types.EncodingTypeUrl,
	}, "start-after")
}

func mapKeys(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	return out
}

func mapBoolKeys(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mustGatewaySecretForAccessKey(tb testing.TB, accessKey string) string {
	tb.Helper()
	_, _, secretKey, err := s3credentials.Decode(accessKey, nil)
	if err != nil {
		tb.Fatalf("derive secret key for access key %q: %v", accessKey, err)
	}
	return secretKey
}

func signedAWSChunkedPayloadForTest(t *testing.T, secret string, auth *sigv4.Auth, chunks [][]byte) string {
	t.Helper()

	signingKey := sigv4.DeriveSigningKey(secret, auth.Date, auth.Region, auth.Service)
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", auth.Date, auth.Region, auth.Service)
	prevSig := strings.ToLower(auth.SignatureHex)
	emptyHash := sha256.Sum256(nil)
	emptyHashHex := fmt.Sprintf("%x", emptyHash[:])

	var b strings.Builder
	for _, chunk := range chunks {
		chunkHash := sha256.Sum256(chunk)
		chunkHashHex := fmt.Sprintf("%x", chunkHash[:])
		stringToSign := strings.Join([]string{
			"AWS4-HMAC-SHA256-PAYLOAD",
			auth.AmzDate,
			scope,
			prevSig,
			emptyHashHex,
			chunkHashHex,
		}, "\n")
		sig := sigv4.HmacSHA256Hex(signingKey, []byte(stringToSign))
		b.WriteString(fmt.Sprintf("%x;chunk-signature=%s\r\n", len(chunk), sig))
		b.Write(chunk)
		b.WriteString("\r\n")
		prevSig = sig
	}

	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		auth.AmzDate,
		scope,
		prevSig,
		emptyHashHex,
		emptyHashHex,
	}, "\n")
	finalSig := sigv4.HmacSHA256Hex(signingKey, []byte(stringToSign))
	b.WriteString(fmt.Sprintf("0;chunk-signature=%s\r\n\r\n", finalSig))
	return b.String()
}

func tamperFirstChunkSignatureForTest(t *testing.T, encoded string) string {
	t.Helper()

	const marker = "chunk-signature="
	idx := strings.Index(encoded, marker)
	if idx < 0 {
		t.Fatalf("missing %q marker in encoded payload", marker)
	}
	sigPos := idx + len(marker)
	if sigPos >= len(encoded) {
		t.Fatalf("invalid signature position in encoded payload")
	}

	out := []byte(encoded)
	if out[sigPos] == '0' {
		out[sigPos] = '1'
	} else {
		out[sigPos] = '0'
	}
	return string(out)
}

func newMinioGatewayClient(t *testing.T, gatewayURL, accessKey, secretKey string) *minio.Client {
	t.Helper()

	parsedURL, err := url.Parse(gatewayURL)
	if err != nil {
		t.Fatalf("parse gateway url %q: %v", gatewayURL, err)
	}
	client, err := minio.New(parsedURL.Host, &minio.Options{
		Creds:        minioCredentials.NewStaticV4(accessKey, secretKey, ""),
		Secure:       strings.EqualFold(parsedURL.Scheme, "https"),
		Region:       "us-east-1",
		BucketLookup: minio.BucketLookupPath,
	})
	if err != nil {
		t.Fatalf("init minio client for %s: %v", gatewayURL, err)
	}
	return client
}
