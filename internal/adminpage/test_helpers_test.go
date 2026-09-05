package adminpage

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/sigv4"
	"github.com/define42/s3gateway/internal/testutil"
)

func newTestS3Client(t *testing.T, upstreamURL string) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(t.Context(),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("upstream-ak", "upstream-sk", "")),
		awsconfig.WithRegion("us-east-1"),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(upstreamURL)
		o.UsePathStyle = true
	})
}

type testCredentials struct {
	groups map[string]map[string]struct{}
}

func (c *testCredentials) set(upn, pass string, groups map[string]struct{}) {
	key := upn + "\x00" + pass
	if c.groups == nil {
		c.groups = make(map[string]map[string]struct{})
	}
	c.groups[key] = groups
}

func (c *testCredentials) authenticate(upn, pass string) (map[string]struct{}, error) {
	key := upn + "\x00" + pass
	if g, ok := c.groups[key]; ok {
		return g, nil
	}
	return nil, errors.New("invalid credentials")
}

// newTestHandler creates a test admin handler with stub upstream.
// Returns the handler, a credentials helper, and a cleanup function.
func newTestHandler(t *testing.T, h http.HandlerFunc) (*handler, *testCredentials, func()) {
	t.Helper()
	upstreamSrv := testutil.NewTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Content-Encoding"), "aws-chunked") {
			body, length, err := sigv4.DecodeBodyForS3Write(r, nil)
			if err != nil {
				t.Errorf("decode upstream aws-chunked request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			r.Body = body
			r.ContentLength = length
			r.Header.Set("Content-Length", strconv.FormatInt(length, 10))
		}
		h(w, r)
	}))
	s3Client := newTestS3Client(t, upstreamSrv.URL)
	creds := &testCredentials{}
	sessions := NewAdminSessionStore(defaultAdminSessionTTL, 100)
	webSessions := NewAdminGorillaStore("test-secret-key", defaultAdminSessionTTL, sessions)
	h2 := &handler{
		s3:           s3Client,
		webSessions:  webSessions,
		authenticate: creds.authenticate,
	}
	return h2, creds, func() { upstreamSrv.Close() }
}

// newHandlerWithNilS3 creates a handler with nil S3 client and simple auth.
func newHandlerWithNilS3(groups map[string]struct{}) *handler {
	creds := &testCredentials{}
	if groups != nil {
		creds.set("alice", "secret", groups)
	}
	sessions := NewAdminSessionStore(defaultAdminSessionTTL, 100)
	webSessions := NewAdminGorillaStore("test-secret-key", defaultAdminSessionTTL, sessions)
	return &handler{
		s3:           nil,
		webSessions:  webSessions,
		authenticate: creds.authenticate,
	}
}

// newLoggedInAdminHandlerWithStub creates a handler with a logged-in session.
func newLoggedInAdminHandlerWithStub(t *testing.T, groups map[string]struct{}, h http.HandlerFunc) (http.Handler, *http.Cookie, func()) {
	t.Helper()
	gw, creds, cleanup := newTestHandler(t, h)
	creds.set("alice", "secret", groups)
	cookie := adminLoginSessionCookie(t, gw, "alice", "secret")
	return gw, cookie, cleanup
}
