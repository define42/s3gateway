package upstream

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// DefaultBucketPageSize is the maximum number of buckets requested per page.
const DefaultBucketPageSize int32 = 10000

// ListAllBuckets retrieves every bucket page. It returns no partial result if a
// request fails, the context is canceled, or the upstream repeats a page token.
func ListAllBuckets(ctx context.Context, client s3.ListBucketsAPIClient) (*s3.ListBucketsOutput, error) {
	var result *s3.ListBucketsOutput
	var token *string
	seen := make(map[string]struct{})
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := client.ListBuckets(ctx, &s3.ListBucketsInput{
			MaxBuckets:        aws.Int32(DefaultBucketPageSize),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("list buckets: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if page == nil {
			return nil, errors.New("list buckets: upstream returned no response")
		}
		if result == nil {
			firstPage := *page
			result = &firstPage
			result.Buckets = nil
			result.ContinuationToken = nil
		}
		result.Buckets = append(result.Buckets, page.Buckets...)
		next := aws.ToString(page.ContinuationToken)
		if next == "" {
			return result, nil
		}
		if _, repeated := seen[next]; repeated {
			return nil, errors.New("list buckets: upstream repeated a continuation token")
		}
		seen[next] = struct{}{}
		token = aws.String(next)
	}
}
