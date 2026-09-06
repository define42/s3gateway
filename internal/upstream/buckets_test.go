package upstream

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type listBucketsFunc func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error)

func (fn listBucketsFunc) ListBuckets(ctx context.Context, in *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	return fn(ctx, in)
}

func TestListAllBuckets(t *testing.T) {
	firstOwner := &types.Owner{ID: aws.String("first-owner"), DisplayName: aws.String("First Owner")}
	pages := []*s3.ListBucketsOutput{
		{Buckets: []types.Bucket{{Name: aws.String("first")}}, Owner: firstOwner, ContinuationToken: aws.String("opaque/+?=&")},
		{Owner: &types.Owner{ID: aws.String("later-owner")}, ContinuationToken: aws.String(" token with spaces ")},
		{Buckets: []types.Bucket{{Name: aws.String("second")}, {Name: aws.String("third")}}, ContinuationToken: aws.String("")},
	}
	pages[0].ResultMetadata.Set("first-page", true)
	wantTokens := []string{"", "opaque/+?=&", " token with spaces "}
	calls := 0
	ctx := t.Context()
	client := listBucketsFunc(func(gotCtx context.Context, in *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
		if gotCtx != ctx {
			t.Fatal("request context was replaced")
		}
		if calls >= len(pages) {
			t.Fatal("requested an extra page")
		}
		if got := aws.ToInt32(in.MaxBuckets); got != 10000 {
			t.Fatalf("MaxBuckets = %d, want 10000", got)
		}
		if got := aws.ToString(in.ContinuationToken); got != wantTokens[calls] {
			t.Fatalf("page %d token = %q, want %q", calls, got, wantTokens[calls])
		}
		page := pages[calls]
		calls++
		return page, nil
	})
	out, err := ListAllBuckets(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, bucket := range out.Buckets {
		names = append(names, aws.ToString(bucket.Name))
	}
	if !slices.Equal(names, []string{"first", "second", "third"}) || calls != len(pages) {
		t.Fatalf("names = %v, calls = %d", names, calls)
	}
	if out.Owner != firstOwner || out.ResultMetadata.Get("first-page") != true {
		t.Fatalf("first-page metadata changed: owner=%+v metadata=%+v", out.Owner, out.ResultMetadata)
	}
	if out.ContinuationToken != nil {
		t.Fatalf("complete result retained token %q", aws.ToString(out.ContinuationToken))
	}
	if len(pages[0].Buckets) != 1 || aws.ToString(pages[0].ContinuationToken) != wantTokens[1] {
		t.Fatal("first page was modified")
	}
}

func TestListAllBucketsEmpty(t *testing.T) {
	calls := 0
	client := listBucketsFunc(func(_ context.Context, in *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
		calls++
		if aws.ToInt32(in.MaxBuckets) != 10000 || in.ContinuationToken != nil {
			t.Fatalf("unexpected initial request: %+v", in)
		}
		return &s3.ListBucketsOutput{}, nil
	})
	out, err := ListAllBuckets(t.Context(), client)
	if err != nil || out == nil || len(out.Buckets) != 0 || calls != 1 {
		t.Fatalf("output = %+v, error = %v, calls = %d", out, err, calls)
	}
}

func TestListAllBucketsRejectsTokenCycles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tokens []string
	}{
		{name: "immediate repeat", tokens: []string{"a", "a"}},
		{name: "cycle", tokens: []string{"a", "b", "c", "a"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			client := listBucketsFunc(func(_ context.Context, _ *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
				if calls >= len(tc.tokens) {
					t.Fatal("continued after a repeated token")
				}
				token := tc.tokens[calls]
				calls++
				return &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("partial")}}, ContinuationToken: aws.String(token),
				}, nil
			})
			out, err := ListAllBuckets(t.Context(), client)
			if err == nil || out != nil || calls != len(tc.tokens) {
				t.Fatalf("output = %+v, error = %v, calls = %d", out, err, calls)
			}
		})
	}
}

func TestListAllBucketsDiscardsPartialResultsOnError(t *testing.T) {
	wantErr := errors.New("second page failed")
	calls := 0
	client := listBucketsFunc(func(_ context.Context, _ *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
		calls++
		if calls == 1 {
			return &s3.ListBucketsOutput{
				Buckets: []types.Bucket{{Name: aws.String("partial")}}, ContinuationToken: aws.String("next"),
			}, nil
		}
		return nil, wantErr
	})
	out, err := ListAllBuckets(t.Context(), client)
	if out != nil || !errors.Is(err, wantErr) || calls != 2 {
		t.Fatalf("output = %+v, error = %v, calls = %d", out, err, calls)
	}
}

func TestListAllBucketsCancellation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cancelAt  int
		lastToken *string
	}{
		{name: "before first request"},
		{name: "between pages", cancelAt: 1, lastToken: aws.String("next")},
		{name: "final page", cancelAt: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			if tc.cancelAt == 0 {
				cancel()
			}
			client := listBucketsFunc(func(gotCtx context.Context, _ *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
				if gotCtx != ctx {
					t.Fatal("request context was replaced")
				}
				calls++
				token := aws.String("next")
				if calls == tc.cancelAt {
					cancel()
					token = tc.lastToken
				}
				return &s3.ListBucketsOutput{
					Buckets: []types.Bucket{{Name: aws.String("partial")}}, ContinuationToken: token,
				}, nil
			})
			out, err := ListAllBuckets(ctx, client)
			if out != nil || !errors.Is(err, context.Canceled) || calls != tc.cancelAt {
				t.Fatalf("output = %+v, error = %v, calls = %d", out, err, calls)
			}
		})
	}
}

func TestListAllBucketsRejectsMissingResponse(t *testing.T) {
	client := listBucketsFunc(func(context.Context, *s3.ListBucketsInput) (*s3.ListBucketsOutput, error) {
		return nil, nil
	})
	if out, err := ListAllBuckets(t.Context(), client); out != nil || err == nil {
		t.Fatalf("output = %+v, error = %v", out, err)
	}
}
