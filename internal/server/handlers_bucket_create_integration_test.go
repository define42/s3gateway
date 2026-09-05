//go:build integration

package server

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/testutil"
	"github.com/define42/s3gateway/internal/upstream"
)

func TestCreateBucketObjectLockIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Object Lock integration test in short mode")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	minioURL, stopMinio := testutil.StartMinio(ctx, t, "minioadmin", "minioadmin")
	t.Cleanup(stopMinio)
	cfg := config.Config{
		UpstreamEndpoint:       minioURL,
		UpstreamRegion:         "us-east-1",
		UpstreamAccessKey:      "minioadmin",
		UpstreamSecretKey:      "minioadmin",
		UpstreamForcePathStyle: true,
	}
	upstreamClient, err := upstream.New(ctx, cfg)
	if err != nil {
		t.Fatalf("initialize upstream client: %v", err)
	}
	gateway := New(cfg, upstreamClient)
	gateway.gcache.Set("testuser", "dogood", map[string]struct{}{"team2-rwcdb": {}})
	accessKey, secretKey := mustGatewayCredentials(t, gateway, "testuser", "dogood")
	gatewayServer := testutil.NewTLSServer(t, gateway.WithAuth(gateway, adminWebpageHandler(gateway)))
	gatewayClient := testutil.NewS3Client(t, ctx, gatewayServer.URL, cfg.UpstreamRegion, accessKey, secretKey)

	const bucket = "team2-object-lock"
	if _, err := gatewayClient.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket:                     aws.String(bucket),
		ObjectLockEnabledForBucket: aws.Bool(true),
	}); err != nil {
		t.Fatalf("create bucket with Object Lock through gateway: %v", err)
	}
	lock, err := upstreamClient.GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("read persisted Object Lock configuration: %v", err)
	}
	if lock.ObjectLockConfiguration == nil || lock.ObjectLockConfiguration.ObjectLockEnabled != types.ObjectLockEnabledEnabled {
		t.Fatalf("persisted Object Lock configuration = %#v, want Enabled", lock.ObjectLockConfiguration)
	}
	versioning, err := upstreamClient.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		t.Fatalf("read persisted bucket versioning: %v", err)
	}
	if versioning.Status != types.BucketVersioningStatusEnabled {
		t.Fatalf("persisted bucket versioning = %q, want Enabled", versioning.Status)
	}
}
