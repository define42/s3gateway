package upstream

import (
	"context"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type responseProgressKey struct{}

// WithResponseProgress attaches the request's transfer watchdog to ctx. The
// callback must be safe for concurrent use and ignore progress after completion.
// Only SDK operations using TrackResponseProgress report upstream activity.
func WithResponseProgress(ctx context.Context, progress func()) context.Context {
	return context.WithValue(ctx, responseProgressKey{}, progress)
}

// TrackResponseProgress observes response headers and body reads before the SDK
// consumes them. Use it for multipart completion and server-side copies, whose
// whitespace keepalives would otherwise be invisible while the SDK waits for
// the final XML result.
// This changes only the operation's client copy, retaining its transport,
// cancellation, retries, and response parsing.
func TrackResponseProgress(options *s3.Options) {
	options.HTTPClient = responseProgressClient{HTTPClient: options.HTTPClient}
}

type responseProgressClient struct {
	s3.HTTPClient
}

func (c responseProgressClient) Do(r *http.Request) (*http.Response, error) {
	response, err := c.HTTPClient.Do(r)
	progress, _ := r.Context().Value(responseProgressKey{}).(func())
	if err == nil && response != nil && progress != nil {
		progress()
		if response.Body != nil {
			response.Body = &responseProgressBody{ReadCloser: response.Body, progress: progress}
		}
	}
	return response, err
}

type responseProgressBody struct {
	io.ReadCloser
	progress func()
}

func (b *responseProgressBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.progress()
	}
	return n, err
}
