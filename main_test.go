package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
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
	if gotObj.Expires == nil {
		t.Fatalf("expected upstream object Expires to be set")
	}
	if gotObj.Expires.UTC().Unix() != expiresAt.Unix() {
		t.Fatalf("upstream expires mismatch: got=%s want=%s", gotObj.Expires.UTC().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
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
	if readonlyObj.Expires == nil {
		t.Fatalf("expected readonly get through gateway to include Expires")
	}
	if readonlyObj.Expires.UTC().Unix() != expiresAt.Unix() {
		t.Fatalf("readonly expires mismatch through gateway: got=%s want=%s", readonlyObj.Expires.UTC().Format(time.RFC3339), expiresAt.Format(time.RFC3339))
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

func TestLdapS3upstreamListMultipartUploads(t *testing.T) {
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
				Prefix: aws.String("logs/"),
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
			} else if r.Prefix != nil {
				prefix = *r.Prefix
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
	t.Run("valid aws-chunked payload", func(t *testing.T) {
		const encoded = "5;chunk-signature=abc\r\nhello\r\n6;chunk-signature=def\r\n world\r\n0;chunk-signature=ghi\r\nx-amz-checksum-crc32:AAAAAA==\r\n\r\n"
		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader(encoded))
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		req.Header.Set("x-amz-decoded-content-length", "11")

		body, cl, err := decodeBodyForS3Write(req)
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

	t.Run("missing decoded length header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/team2-bucket/object.txt", strings.NewReader(""))
		req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		if _, _, err := decodeBodyForS3Write(req); err == nil {
			t.Fatalf("expected decodeBodyForS3Write to fail for missing x-amz-decoded-content-length")
		}
	})
}

func TestGatewayPreservesUpstreamErrorStatusAndHeaders(t *testing.T) {
	ctx := context.Background()

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("x-amz-request-id", "req-123")
		w.Header().Set("x-amz-id-2", "id2-abc")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>SlowDown</Code><Message>please retry</Message></Error>`))
	}))
	defer upstreamSrv.Close()

	upstreamClient := newS3Client(t, ctx, upstreamSrv.URL, "us-east-1", "upstream-ak", "upstream-sk")
	gw := &server{
		up: upstreamClient,
	}
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxRulesKey, []Rule{{BucketPrefix: "team2-", Perm: PermReadWrite}})
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

	upstreamClient := newS3Client(t, ctx, upstreamSrv.URL, "us-east-1", "upstream-ak", "upstream-sk")
	gw := &server{
		up: upstreamClient,
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	timeoutCtx, cancel := context.WithTimeout(req.Context(), 150*time.Millisecond)
	defer cancel()
	req = req.WithContext(context.WithValue(timeoutCtx, ctxRulesKey, []Rule{{BucketPrefix: "team2-", Perm: PermReadWrite}}))

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

func TestLdapS3upstreamAuthCacheSurvivesLDAPOutage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	ldapCfgPath := writeGatewayGlauthConfig(t)
	ldapURL, stopLDAP := startGlauthWithConfig(ctx, t, ldapCfgPath, "ldap")
	ldapStopped := false
	stopLDAPOnce := func() {
		if ldapStopped {
			return
		}
		stopLDAP()
		ldapStopped = true
	}
	defer stopLDAPOnce()

	minioURL, stopMinio := startMinio(ctx, t, "minioadmin", "minioadmin")
	defer stopMinio()

	cfg := Config{
		LDAPURL:                ldapURL,
		BaseDN:                 "dc=glauth,dc=com",
		GroupTTL:               2 * time.Minute,
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
	sort.Strings(out)
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
