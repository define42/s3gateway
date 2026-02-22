package main

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ==================== Upstream S3 client (service creds) ====================
//
// Key point: for PutObject/UploadPart with unseekable bodies, use
// v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware and provide ContentLength. :contentReference[oaicite:6]{index=6}
func newUpstreamS3(ctx context.Context, cfg Config) (*s3.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.DialContext = (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 2048
	transport.MaxIdleConnsPerHost = 512
	transport.MaxConnsPerHost = 0
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second

	upHTTP := &http.Client{Transport: transport}

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.UpstreamRegion),
		config.WithBaseEndpoint(cfg.UpstreamEndpoint),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.UpstreamAccessKey, cfg.UpstreamSecretKey, "")),
		config.WithHTTPClient(upHTTP),
		// Gateway forwards request bodies as non-seekable streams; avoid optional precomputed request checksums.
		config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		// Upstream responses may not include optional checksum headers.
		config.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.UpstreamForcePathStyle
	}), nil
}

