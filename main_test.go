package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	minio "github.com/minio/minio-go/v7"
	minioCredentials "github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestLdapS3upstreamWithClient(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := writeGatewayGlauthConfig(t)
	ldapURL, stopLDAP := startGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := startMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
		SigV4Secret:            "password",
		SigV4Service:           "s3",
	}

	// Sanity-check LDAP bind + group mapping used by gateway authz.
	grps, err := fetchGroupsUPN(cfg, "testuser@example.com", "dogood")
	if err != nil {
		t.Fatalf("ldap auth/group lookup failed: %v", err)
	}
	if !canWrite(rulesFromGroups(grps), "team2-integration-check") {
		t.Fatalf("expected team2-rw write permission, got groups: %v", mapKeys(grps))
	}
	roGrps, err := fetchGroupsUPN(cfg, "readonly@example.com", "dogood")
	if err != nil {
		t.Fatalf("ldap auth/group lookup failed for readonly user: %v", err)
	}
	roRules := rulesFromGroups(roGrps)
	if !canRead(roRules, "team2-integration-check") || canWrite(roRules, "team2-integration-check") {
		t.Fatalf("expected team2-r read-only permission, got groups: %v", mapKeys(roGrps))
	}

	up, err := newUpstreamS3(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCache(cfg.GroupTTL),
	}
	gwSrv := httptest.NewServer(gw.withAuth(gw))
	defer gwSrv.Close()

	gatewayAccessKey := base64.StdEncoding.EncodeToString([]byte("testuser@example.com:dogood"))
	gatewayClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", gatewayAccessKey, cfg.SigV4Secret)
	readonlyAccessKey := base64.StdEncoding.EncodeToString([]byte("readonly@example.com:dogood"))
	readonlyClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", readonlyAccessKey, cfg.SigV4Secret)
	upstreamClient := newS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

	bucket := fmt.Sprintf("team2-integration-%d", time.Now().UnixNano())
	key := "smoke/hello.txt"
	wantBody := []byte("hello through s3gateway")

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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := writeGatewayGlauthConfig(t)
	ldapURL, stopLDAP := startGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := startMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
		SigV4Secret:            "password",
		SigV4Service:           "s3",
	}

	up, err := newUpstreamS3(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCache(cfg.GroupTTL),
	}
	gwSrv := httptest.NewServer(gw.withAuth(gw))
	defer gwSrv.Close()

	gatewayAccessKey := base64.StdEncoding.EncodeToString([]byte("testuser@example.com:dogood"))
	gatewayAwsClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", gatewayAccessKey, cfg.SigV4Secret)
	gatewayMinioClient := newMinioGatewayClient(t, gwSrv.URL, gatewayAccessKey, cfg.SigV4Secret)
	upstreamClient := newS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

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

	ldapCfgPath := writeGatewayGlauthConfig(t)
	ldapURL, stopLDAP := startGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := startMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
		SigV4Secret:            "password",
		SigV4Service:           "s3",
	}

	up, err := newUpstreamS3(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCache(cfg.GroupTTL),
	}
	gwSrv := httptest.NewServer(gw.withAuth(gw))
	defer gwSrv.Close()

	rwAccessKey := base64.StdEncoding.EncodeToString([]byte("testuser@example.com:dogood"))
	rwClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, cfg.SigV4Secret)
	roAccessKey := base64.StdEncoding.EncodeToString([]byte("readonly@example.com:dogood"))
	roClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, cfg.SigV4Secret)
	upstreamClient := newS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := writeGatewayGlauthConfig(t)
	ldapURL, stopLDAP := startGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := startMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
		SigV4Secret:            "password",
		SigV4Service:           "s3",
	}

	up, err := newUpstreamS3(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCache(cfg.GroupTTL),
	}
	gwSrv := httptest.NewServer(gw.withAuth(gw))
	defer gwSrv.Close()

	rwAccessKey := base64.StdEncoding.EncodeToString([]byte("testuser@example.com:dogood"))
	rwClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, cfg.SigV4Secret)
	roAccessKey := base64.StdEncoding.EncodeToString([]byte("readonly@example.com:dogood"))
	roClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", roAccessKey, cfg.SigV4Secret)

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

func TestLdapS3upstreamMultipartLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := writeGatewayGlauthConfig(t)
	ldapURL, stopLDAP := startGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	defer stopLDAP()

	minioURL, stopMinio := startMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		GroupTTL:               30 * time.Second,
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
		SigV4Secret:            "password",
		SigV4Service:           "s3",
	}

	up, err := newUpstreamS3(ctx, cfg)
	if err != nil {
		t.Fatalf("init upstream s3: %v", err)
	}

	gw := &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCache(cfg.GroupTTL),
	}
	gwSrv := httptest.NewServer(gw.withAuth(gw))
	defer gwSrv.Close()

	rwAccessKey := base64.StdEncoding.EncodeToString([]byte("testuser@example.com:dogood"))
	gatewayClient := newS3Client(t, ctx, gwSrv.URL, "us-east-1", rwAccessKey, cfg.SigV4Secret)
	upstreamClient := newS3Client(t, ctx, minioURL, "us-east-1", cfg.UpstreamAccessKey, cfg.UpstreamSecretKey)

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

func startGlauthWithConfig(ctx context.Context, t *testing.T, cfg string, scheme string) (string, func()) {
	t.Helper()

	cert := pathRelative(t, "testldap", "cert.pem")
	key := pathRelative(t, "testldap", "key.pem")
	waitLog := "LDAPS server listening"
	if strings.EqualFold(scheme, "ldap") {
		waitLog = "LDAP server listening"
	}

	req := testcontainers.ContainerRequest{
		Image:        "glauth/glauth:latest",
		ExposedPorts: []string{"389/tcp"},
		Env: map[string]string{
			"GLAUTH_CONFIG": "/app/config/config.cfg",
		},
		Files: []testcontainers.ContainerFile{
			{HostFilePath: cfg, ContainerFilePath: "/app/config/config.cfg", FileMode: 0o644},
			{HostFilePath: cert, ContainerFilePath: "/app/config/cert.pem", FileMode: 0o644},
			{HostFilePath: key, ContainerFilePath: "/app/config/key.pem", FileMode: 0o600},
		},
		Networks:       nil,
		NetworkAliases: nil,
		WaitingFor: wait.ForLog(waitLog).
			WithStartupTimeout(1 * time.Minute).
			WithPollInterval(2 * time.Second),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("failed to start glauth container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}
	port, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	url := fmt.Sprintf("%s://%s:%s", scheme, host, port.Port())

	return url, func() {
		_ = container.Terminate(context.Background())
	}
}

func writeGatewayGlauthConfig(t *testing.T) string {
	t.Helper()

	const cfg = `
debug = true

[ldap]
  enabled = true
  listen = "0.0.0.0:389"
  tls = false

[ldaps]
  enabled = false

[backend]
  datastore = "config"
  baseDN = "dc=glauth,dc=com"
  nameformat = "userPrincipalName"
  groupformat = "cn"

[behaviors]
  IgnoreCapabilities = true

[[users]]
  name = "testuser"
  mail = "testuser@example.com"
  primarygroup = 5506
  othergroups = [5506]
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood
    [[users.capabilities]]
    action = "search"
    object = "*"

[[users]]
  name = "readonly"
  mail = "readonly@example.com"
  primarygroup = 5507
  othergroups = [5507]
  passsha256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a" # dogood
    [[users.capabilities]]
    action = "search"
    object = "*"

[[groups]]
  name = "team2-rw"
  gidnumber = 5506

[[groups]]
  name = "team2-r"
  gidnumber = 5507
`

	cfgPath := filepath.Join(t.TempDir(), "glauth-integration.cfg")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write glauth config: %v", err)
	}
	return cfgPath
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
	return out
}

func newS3Client(t *testing.T, ctx context.Context, endpoint, region, accessKey, secretKey string) *s3.Client {
	t.Helper()

	resolver := aws.EndpointResolverWithOptionsFunc(
		func(service, _ string, _ ...interface{}) (aws.Endpoint, error) {
			if service == s3.ServiceID {
				return aws.Endpoint{URL: endpoint, HostnameImmutable: true}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		},
	)

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithEndpointResolverWithOptions(resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		config.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		t.Fatalf("load aws config for %s: %v", endpoint, err)
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})
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

func pathRelative(t *testing.T, elems ...string) string {
	t.Helper()
	p := filepath.Join(elems...)
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	return abs
}

func startMinio(ctx context.Context, t *testing.T, accessKey string, secretKey string) (string, func()) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "minio/minio:latest",
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     accessKey,
			"MINIO_ROOT_PASSWORD": secretKey,
		},
		Cmd: []string{
			"server",
			"/data",
			"--address",
			":9000",
		},
		WaitingFor: wait.ForHTTP("/minio/health/ready").
			WithPort("9000/tcp").
			WithStartupTimeout(1 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(
		ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		},
	)
	if err != nil {
		t.Fatalf("failed to start minio container: %v", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("get host: %v", err)
	}

	port, err := container.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Fatalf("get mapped port: %v", err)
	}

	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	return endpoint, func() {
		_ = container.Terminate(context.Background())
	}
}
