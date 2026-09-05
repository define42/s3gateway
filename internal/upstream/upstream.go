// Package upstream constructs the AWS SDK client used to forward gateway
// operations to the configured S3-compatible service.
package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/config"
)

// New constructs an S3 client with static service credentials, a tuned shared
// HTTP transport, and checksum policies compatible with streamed request
// bodies. The endpoint must use HTTPS, and AWS_CA_BUNDLE can supply trusted
// certificates for a private upstream. The supplied context bounds AWS SDK
// configuration loading.
func New(ctx context.Context, cfg config.Config) (*s3.Client, error) {
	if err := config.ValidateUpstreamEndpoint(cfg.UpstreamEndpoint); err != nil {
		return nil, err
	}
	// The SDK can install AWS_CA_BUNDLE roots only on its BuildableClient.
	upHTTP := awshttp.NewBuildableClient().WithDialerOptions(func(dialer *net.Dialer) {
		dialer.Timeout = 5 * time.Second
		dialer.KeepAlive = 30 * time.Second
	}).WithTransportOptions(func(transport *http.Transport) {
		transport.Proxy = http.ProxyFromEnvironment
		transport.ForceAttemptHTTP2 = true
		transport.MaxIdleConns = 2048
		transport.MaxIdleConnsPerHost = 512
		transport.MaxConnsPerHost = 0
		transport.IdleConnTimeout = 90 * time.Second
		transport.TLSHandshakeTimeout = 5 * time.Second
		transport.ExpectContinueTimeout = 1 * time.Second
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		// #nosec G402 -- Explicit operator opt-in, scoped to this upstream client.
		transport.TLSClientConfig.InsecureSkipVerify = cfg.UpstreamSkipCertificateValidation
	})

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
	resolvedHTTP, ok := awsCfg.HTTPClient.(*awshttp.BuildableClient)
	if !ok {
		return nil, errors.New("upstream HTTP client does not support secure transport configuration")
	}
	// Keep the SDK-resolved CA roots, but prevent redirects from downgrading
	// encrypted uploads to HTTP. Preserve net/http's default redirect limit.
	awsCfg.HTTPClient = &http.Client{
		Transport: resolvedHTTP.GetTransport(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return errors.New("upstream redirect must use HTTPS")
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.UpstreamForcePathStyle
	}), nil
}
