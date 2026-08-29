// Package upstream constructs the AWS SDK client used to forward gateway
// operations to the configured S3-compatible service.
package upstream

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/config"
)

// New constructs an S3 client with static service credentials, a tuned shared
// HTTP transport, and checksum policies compatible with streamed request
// bodies. The supplied context bounds AWS SDK configuration loading.
//
// New panics if http.DefaultTransport is not an *http.Transport.
func New(ctx context.Context, cfg config.Config) (*s3.Client, error) {
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

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.UpstreamRegion),
		awsconfig.WithBaseEndpoint(cfg.UpstreamEndpoint),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.UpstreamAccessKey, cfg.UpstreamSecretKey, "")),
		awsconfig.WithHTTPClient(upHTTP),
		// Gateway forwards request bodies as non-seekable streams; avoid optional precomputed request checksums.
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		// Upstream responses may not include optional checksum headers.
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.UpstreamForcePathStyle
	}), nil
}
