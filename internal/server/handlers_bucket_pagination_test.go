package server

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/authz"
)

type bucketPaginationDocument struct {
	XMLName           xml.Name                `xml:"ListAllMyBucketsResult"`
	Buckets           []bucketPaginationEntry `xml:"Buckets>Bucket"`
	ContinuationToken string                  `xml:"ContinuationToken,omitempty"`
	Prefix            string                  `xml:"Prefix,omitempty"`
}

type bucketPaginationEntry struct {
	Name string `xml:"Name"`
}

func writeBucketPaginationPage(t *testing.T, w http.ResponseWriter, names []string, token, prefix string) {
	t.Helper()
	doc := bucketPaginationDocument{ContinuationToken: token, Prefix: prefix}
	for _, name := range names {
		doc.Buckets = append(doc.Buckets, bucketPaginationEntry{Name: name})
	}
	body, err := xml.Marshal(doc)
	if err != nil {
		t.Errorf("encode bucket page: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_, _ = w.Write(body)
}

func newBucketPaginationClient(t *testing.T, gateway *Server, rules []authz.Rule) *s3.Client {
	t.Helper()
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gateway.ServeHTTP(w, reqWithRules(r, rules))
	}))
	t.Cleanup(front.Close)
	return s3.New(s3.Options{
		Region:           "us-east-1",
		BaseEndpoint:     aws.String(front.URL),
		UsePathStyle:     true,
		Credentials:      credentials.NewStaticCredentialsProvider("test-access", "test-secret", ""),
		HTTPClient:       front.Client(),
		RetryMaxAttempts: 1,
	})
}

func TestListBucketsLegacyAggregatesAuthorizedPages(t *testing.T) {
	var calls atomic.Int32
	const firstToken = " first/+?= & token "
	const secondToken = "second-page"
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("max-buckets") != "10000" {
			t.Errorf("legacy enumeration must still paginate upstream: %s", r.URL.RawQuery)
		}
		switch r.URL.Query().Get("continuation-token") {
		case "":
			writeBucketPaginationPage(t, w, []string{"hidden-first", "team2-first"}, firstToken, "")
		case firstToken:
			writeBucketPaginationPage(t, w, []string{"hidden-middle"}, secondToken, "")
		case secondToken:
			writeBucketPaginationPage(t, w, []string{"team2-last", "hidden-last"}, "", "")
		default:
			t.Errorf("opaque continuation token changed: %q", r.URL.Query().Get("continuation-token"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	t.Cleanup(cleanup)
	client := newBucketPaginationClient(t, gw, []authz.Rule{{BucketPrefix: "team2", Perm: authz.PermWrite}})
	output, err := client.ListBuckets(t.Context(), &s3.ListBucketsInput{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, bucket := range output.Buckets {
		names = append(names, aws.ToString(bucket.Name))
	}
	if !slices.Equal(names, []string{"team2-first", "team2-last"}) || output.ContinuationToken != nil || calls.Load() != 3 {
		t.Fatalf("legacy listing names=%v token=%v calls=%d", names, output.ContinuationToken, calls.Load())
	}
}

func TestListBucketsSDKPaginatorTraversesFilteredEmptyPage(t *testing.T) {
	var calls atomic.Int32
	const token = "next/+?=&% token"
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		q := r.URL.Query()
		if q.Get("max-buckets") != "1" || q.Get("prefix") != "team" || q.Get("bucket-region") != "us-east-1" {
			t.Errorf("pagination filters changed upstream: %s", r.URL.RawQuery)
		}
		switch q.Get("continuation-token") {
		case "":
			writeBucketPaginationPage(t, w, []string{"team9-hidden"}, token, "team")
		case token:
			writeBucketPaginationPage(t, w, []string{"team2-visible"}, "", "team")
		default:
			t.Errorf("unexpected continuation token %q", q.Get("continuation-token"))
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	t.Cleanup(cleanup)
	client := newBucketPaginationClient(t, gw, []authz.Rule{{BucketPrefix: "team2", Perm: authz.PermDeleteBucket}})
	paginator := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{
		MaxBuckets: aws.Int32(1), Prefix: aws.String("team"), BucketRegion: aws.String("us-east-1"),
	})
	first, err := paginator.NextPage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Buckets) != 0 || aws.ToString(first.ContinuationToken) != token || aws.ToString(first.Prefix) != "team" || calls.Load() != 1 || !paginator.HasMorePages() {
		t.Fatalf("filtered first page lost pagination: output=%+v calls=%d", first, calls.Load())
	}
	second, err := paginator.NextPage(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Buckets) != 1 || aws.ToString(second.Buckets[0].Name) != "team2-visible" || aws.ToString(second.Prefix) != "team" || paginator.HasMorePages() || calls.Load() != 2 {
		t.Fatalf("second page output=%+v calls=%d hasMore=%t", second, calls.Load(), paginator.HasMorePages())
	}
}

func TestListBucketsExplicitParametersForwardOnePage(t *testing.T) {
	for _, query := range []string{
		"max-buckets=1", "max-buckets=10000", "prefix=team", "prefix=", "bucket-region=us-east-1",
		"continuation-token=", "continuation-token=" + url.QueryEscape(strings.Repeat("x", 1024)),
		"continuation-token=" + url.QueryEscape(strings.Repeat("é", 512)),
		"continuation-token=" + url.QueryEscape(" opaque/+?=& token "),
	} {
		t.Run(query, func(t *testing.T) {
			want, err := url.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			if !want.Has("max-buckets") {
				want.Set("max-buckets", "10000")
			}
			var calls atomic.Int32
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				for _, key := range []string{"max-buckets", "prefix", "bucket-region", "continuation-token"} {
					if got := r.URL.Query().Get(key); got != want.Get(key) {
						t.Errorf("upstream %s=%q, want %q", key, got, want.Get(key))
					}
				}
				writeBucketPaginationPage(t, w, []string{"team2-one", "other-hidden"}, "another-page", want.Get("prefix"))
			})
			t.Cleanup(cleanup)
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(httptest.NewRequest(http.MethodGet, "/?"+query, nil), fullTeam2Rule()))
			var output bucketPaginationDocument
			if err := xml.Unmarshal(rr.Body.Bytes(), &output); err != nil {
				t.Fatal(err)
			}
			if rr.Code != http.StatusOK || calls.Load() != 1 || output.ContinuationToken != "another-page" || output.Prefix != want.Get("prefix") || len(output.Buckets) != 1 || output.Buckets[0].Name != "team2-one" {
				t.Fatalf("status=%d calls=%d output=%+v", rr.Code, calls.Load(), output)
			}
		})
	}
}

func TestListBucketsInvalidPaginationNeverReachesUpstream(t *testing.T) {
	var calls atomic.Int32
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writeBucketPaginationPage(t, w, nil, "", "")
	})
	t.Cleanup(cleanup)
	queries := []string{
		"max-buckets=", "max-buckets=0", "max-buckets=-1", "max-buckets=10001", "max-buckets=1.5", "max-buckets=abc",
		"max-buckets=999999999999999999999", "max-buckets=1&max-buckets=1", "bucket-region=", "bucket-region=++", "bucket-region=a&bucket-region=a",
		"prefix=team&prefix=team", "continuation-token=a&continuation-token=a", "continuation-token=" + strings.Repeat("x", 1025),
		"continuation-token=" + url.QueryEscape(strings.Repeat("é", 513)),
		"lifecycle", "versioning", "versions", "uploads", "list-type=2",
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(httptest.NewRequest(http.MethodGet, "/?"+query, nil), fullTeam2Rule()))
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "<Code>InvalidArgument</Code>") || calls.Load() != 0 {
				t.Fatalf("status=%d upstream calls=%d body=%s", rr.Code, calls.Load(), rr.Body.String())
			}
		})
	}
}

func TestListBucketsExclusiveParametersCannotFallThrough(t *testing.T) {
	var calls atomic.Int32
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	t.Cleanup(cleanup)
	for _, query := range []string{"max-buckets=1", "bucket-region=us-east-1"} {
		for _, target := range []string{"/", "/team2-bucket", "/team2-bucket/key"} {
			for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPost, http.MethodDelete} {
				if target == "/" && method == http.MethodGet {
					continue
				}
				t.Run(method+target+"?"+query, func(t *testing.T) {
					rr := httptest.NewRecorder()
					gw.ServeHTTP(rr, reqWithRules(httptest.NewRequest(method, target+"?"+query, strings.NewReader("unchanged")), fullTeam2Rule()))
					if rr.Code != http.StatusBadRequest || calls.Load() != 0 {
						t.Fatalf("status=%d upstream calls=%d body=%s", rr.Code, calls.Load(), rr.Body.String())
					}
				})
			}
		}
	}
}

func TestListBucketsLegacyErrorsBeforeSuccessResponse(t *testing.T) {
	for _, failure := range []string{"upstream error", "malformed page", "repeated token", "token cycle"} {
		t.Run(failure, func(t *testing.T) {
			var calls atomic.Int32
			gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				if call == 1 {
					writeBucketPaginationPage(t, w, []string{"team2-incomplete"}, "page-a", "")
					return
				}
				switch failure {
				case "upstream error":
					w.WriteHeader(http.StatusForbidden)
					_, _ = io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>Denied later page</Message></Error>`)
				case "malformed page":
					_, _ = io.WriteString(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>truncated`)
				default:
					if call > 4 {
						w.WriteHeader(http.StatusForbidden)
						return // Bound an accidental loop in a failing implementation.
					}
					token := "page-a"
					if failure == "token cycle" && call == 2 {
						token = "page-b"
					}
					writeBucketPaginationPage(t, w, []string{"team2-incomplete"}, token, "")
				}
			})
			t.Cleanup(cleanup)
			rr := httptest.NewRecorder()
			gw.ServeHTTP(rr, reqWithRules(httptest.NewRequest(http.MethodGet, "/", nil), fullTeam2Rule()))
			wantStatus, wantCode := http.StatusBadGateway, "BadGateway"
			if failure == "upstream error" {
				wantStatus, wantCode = http.StatusForbidden, "AccessDenied"
			}
			if rr.Code != wantStatus || !strings.Contains(rr.Body.String(), "<Code>"+wantCode+"</Code>") || strings.Contains(rr.Body.String(), "ListAllMyBucketsResult") || calls.Load() < 2 || calls.Load() > 3 {
				t.Fatalf("status=%d calls=%d body=%s", rr.Code, calls.Load(), rr.Body.String())
			}
		})
	}
}

func TestListBucketsExplicitPageRejectsUnchangedToken(t *testing.T) {
	gw, cleanup := newGatewayWithRawStubUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		writeBucketPaginationPage(t, w, []string{"team2-one"}, "same-token", "")
	})
	t.Cleanup(cleanup)
	rr := httptest.NewRecorder()
	gw.ServeHTTP(rr, reqWithRules(httptest.NewRequest(http.MethodGet, "/?continuation-token=same-token", nil), fullTeam2Rule()))
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "<Code>BadGateway</Code>") {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
