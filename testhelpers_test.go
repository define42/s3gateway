package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/testutil"
)

func WriteGatewayGlauthConfig(tb testing.TB) string {
	tb.Helper()
	return testutil.WriteGatewayGlauthConfig(tb)
}

func StartGlauthWithConfig(ctx context.Context, tb testing.TB, cfg string, scheme string) (string, func()) {
	tb.Helper()
	return testutil.StartGlauthWithConfig(ctx, tb, cfg, scheme)
}

func StartMinio(ctx context.Context, tb testing.TB, accessKey string, secretKey string) (string, func()) {
	tb.Helper()
	return testutil.StartMinio(ctx, tb, accessKey, secretKey)
}

func NewS3Client(tb testing.TB, ctx context.Context, endpoint, region, accessKey, secretKey string) *s3.Client {
	tb.Helper()
	return testutil.NewS3Client(tb, ctx, endpoint, region, accessKey, secretKey)
}
