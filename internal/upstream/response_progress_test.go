package upstream

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type progressTestHTTPClient func(*http.Request) (*http.Response, error)

func (f progressTestHTTPClient) Do(r *http.Request) (*http.Response, error) {
	return f(r)
}

type progressTestBody struct {
	io.Reader
	closed bool
}

func (b *progressTestBody) Close() error {
	b.closed = true
	return nil
}

func TestTrackResponseProgressIsScopedToOperation(t *testing.T) {
	var bodies []*progressTestBody
	client := s3.New(s3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String("https://upstream.example"), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
		HTTPClient: progressTestHTTPClient(func(_ *http.Request) (*http.Response, error) {
			body := &progressTestBody{Reader: strings.NewReader(
				` <CompleteMultipartUploadResult><ETag>"completed"</ETag></CompleteMultipartUploadResult>`)}
			bodies = append(bodies, body)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body}, nil
		}),
	})
	var progress int
	ctx := WithResponseProgress(t.Context(), func() { progress++ })
	input := &s3.CompleteMultipartUploadInput{
		Bucket: aws.String("bucket"), Key: aws.String("key"), UploadId: aws.String("upload"),
		MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{
			{PartNumber: aws.Int32(1), ETag: aws.String("part")},
		}},
	}
	for _, observe := range []bool{true, false} {
		before := progress
		var options []func(*s3.Options)
		if observe {
			options = append(options, TrackResponseProgress)
		}
		out, err := client.CompleteMultipartUpload(ctx, input, options...)
		if err != nil || aws.ToString(out.ETag) != `"completed"` {
			t.Fatalf("completion: output=%v error=%v", out, err)
		}
		if observed := progress > before; observed != observe {
			t.Fatalf("progress observed = %t, want %t", observed, observe)
		}
	}
	for _, body := range bodies {
		if !body.closed {
			t.Error("SDK response body was not closed")
		}
	}
}
