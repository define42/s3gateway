package server

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	adminpage "github.com/define42/s3gateway/internal/adminpage"
	"github.com/define42/s3gateway/internal/authn"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/config"
	"github.com/define42/s3gateway/internal/groupcache"
	ldapinternal "github.com/define42/s3gateway/internal/ldap"
	"github.com/define42/s3gateway/internal/s3credentials"
	"github.com/define42/s3gateway/internal/s3xml"
	sigv4 "github.com/define42/s3gateway/internal/sigv4"
	"github.com/define42/s3gateway/internal/uploadnotify"
	"golang.org/x/sync/singleflight"
)

const popBasicAuthChallenge = `Basic realm="s3gateway-pop", charset="UTF-8"`

const maxForwardedForHops = 32

// EffectiveShutdownTimeout returns the configured shutdown timeout after
// applying the default when it is zero.
func EffectiveShutdownTimeout(cfg config.Config) time.Duration {
	cfg.ApplyDefaults()
	return cfg.ShutdownTimeout
}

// NewHTTPServer constructs an HTTP server using the gateway's listener and
// timeout settings. Zero-valued settings receive configuration defaults.
func NewHTTPServer(cfg config.Config, handler http.Handler) *http.Server {
	cfg.ApplyDefaults()

	return &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
}

// ==================== Gateway ====================
type ctxKey string

const ctxUploaderKey ctxKey = "uploader-upn"

type authClientIPContextKey struct{}

// Server authenticates gateway requests, enforces LDAP-derived authorization,
// and dispatches supported path-style S3 operations to an upstream client.
type Server struct {
	cfg                  config.Config
	up                   *s3.Client
	uploadNotifier       UploadNotifier
	popConsumer          PopConsumer
	logger               *slog.Logger
	auditHashKeys        [auditHashScopeCount][sha256.Size]byte
	auditHashReady       bool
	gcache               *groupcache.Cache
	groupLookupSF        singleflight.Group
	fetchGroups          func(cfg config.Config, upn, pass string) (map[string]struct{}, error)
	authLimiter          *authn.Limiter
	trustedProxyPrefixes []netip.Prefix

	readinessAllowedPrefixes []netip.Prefix
	readinessMu              sync.Mutex
	readinessCachedAt        time.Time
	readinessCachedErr       error
	readinessCacheValid      bool
	readinessSF              singleflight.Group
	readinessNow             func() time.Time
	readinessCheck           func(context.Context) error
}

// UploadNotifier receives events only after the upstream S3 operation has
// successfully created an object.
type UploadNotifier interface {
	// Notify publishes one confirmed object-creation event.
	Notify(context.Context, uploadnotify.Event) error
}

// Option customizes a Server during construction.
type Option func(*Server)

// WithUploadNotifier configures publication of successful object-creation
// events. A nil notifier disables publication.
func WithUploadNotifier(notifier UploadNotifier) Option {
	return func(s *Server) {
		s.uploadNotifier = notifier
	}
}

// WithPopConsumer configures the Kafka-backed object pop API. A nil consumer
// leaves the API unavailable.
func WithPopConsumer(consumer PopConsumer) Option {
	return func(s *Server) {
		s.popConsumer = consumer
	}
}

// New constructs the gateway handler and its in-memory LDAP group cache. It
// applies zero-value configuration defaults but does not validate cfg or up.
func New(cfg config.Config, up *s3.Client, opts ...Option) *Server {
	cfg.ApplyDefaults()
	auditHashKeys, auditHashReady := newAuditHashKeys(cfg.S3AuditHashKey)
	s := &Server{
		cfg:            cfg,
		up:             up,
		logger:         slog.Default(),
		auditHashKeys:  auditHashKeys,
		auditHashReady: auditHashReady,
		gcache:         groupcache.New(cfg.GroupTTL, cfg.GroupCacheMaxEntries),
		fetchGroups:    ldapinternal.FetchGroupsUPN,
		authLimiter: authn.NewLimiter(authn.Limits{
			MaxConcurrent:                 cfg.AuthMaxConcurrent,
			RatePerSecond:                 cfg.AuthRatePerSecond,
			Burst:                         cfg.AuthRateBurst,
			ReservedConcurrent:            cfg.AuthReservedConcurrent,
			ReservedRatePerSecond:         cfg.AuthReservedRatePerSecond,
			ReservedBurst:                 cfg.AuthReservedBurst,
			PerClientMaxConcurrent:        cfg.AuthPerIPMaxConcurrent,
			PerClientRatePerSecond:        cfg.AuthPerIPRatePerSecond,
			PerClientBurst:                cfg.AuthPerIPBurst,
			PerPrincipalMaxConcurrent:     cfg.AuthPerPrincipalMaxConcurrent,
			PerPrincipalRatePerSecond:     cfg.AuthPerPrincipalRatePerSecond,
			PerPrincipalBurst:             cfg.AuthPerPrincipalBurst,
			IngressPerClientRatePerSecond: cfg.AuthIngressPerIPRatePerSecond,
			IngressPerClientBurst:         cfg.AuthIngressPerIPBurst,
			MaxKeys:                       cfg.GroupCacheMaxEntries,
			TrustedCredentialTTL:          cfg.AuthTrustedCredentialTTL,
		}),
		readinessNow: time.Now,
	}
	for _, rawPrefix := range cfg.TrustedProxyCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rawPrefix))
		if err == nil {
			s.trustedProxyPrefixes = append(s.trustedProxyPrefixes, prefix.Masked())
		}
	}
	for _, rawPrefix := range cfg.ReadinessAllowedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(rawPrefix))
		if err == nil {
			s.readinessAllowedPrefixes = append(s.readinessAllowedPrefixes, prefix.Masked())
		}
	}
	if !auditHashReady {
		s.logger.Warn("S3 audit identifiers disabled: could not initialize hash key")
	}
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
	return s
}

// GroupsForCredentials returns LDAP groups without request-specific client
// attribution. HTTP request paths should use GroupsForCredentialsContext.
func (s *Server) GroupsForCredentials(upn, pass string) (map[string]struct{}, error) {
	return s.GroupsForCredentialsContext(context.Background(), upn, pass)
}

// GroupsForCredentialsContext returns LDAP groups for a username and password,
// using the credential-bound cache and coalescing concurrent identical
// lookups. The returned map is detached from cached state.
func (s *Server) GroupsForCredentialsContext(ctx context.Context, upn, pass string) (map[string]struct{}, error) {
	if upn == "" || pass == "" {
		return nil, errors.New("missing credentials")
	}

	grps, ok := s.gcache.Get(upn, pass)
	if ok {
		s.authLimiter.RefundIngress(authClientIPFromContext(ctx))
		return grps, nil
	}
	if s.gcache.Rejected(upn, pass) {
		return nil, authn.ErrRejectedCredentials
	}

	sfKey := groupcache.SingleflightCredentialKey(upn, pass)
	fetchGroups := s.fetchGroups
	if fetchGroups == nil {
		fetchGroups = ldapinternal.FetchGroupsUPN
	}
	attempt := authn.NewAttempt(authClientIPFromContext(ctx), upn, pass)
	v, err, _ := s.groupLookupSF.Do(sfKey, func() (any, error) {
		if cached, ok := s.gcache.Get(upn, pass); ok {
			return cached, nil
		}
		if s.gcache.Rejected(upn, pass) {
			return nil, authn.ErrRejectedCredentials
		}
		release, err := s.authLimiter.TryAcquire(attempt)
		if err != nil {
			return nil, err
		}
		defer release()
		fetched, err := fetchGroups(s.cfg, upn, pass)
		if err != nil {
			if errors.Is(err, authn.ErrRejectedCredentials) {
				s.gcache.Reject(upn, pass)
			}
			return nil, err
		}
		s.gcache.Set(upn, pass, fetched)
		s.authLimiter.MarkAuthenticated(attempt)
		return fetched, nil
	})
	if err != nil {
		return nil, err
	}
	s.authLimiter.RefundIngress(authClientIPFromContext(ctx))
	shared, ok := v.(map[string]struct{})
	if !ok {
		return nil, errors.New("internal auth error")
	}
	return groupcache.CloneGroups(shared), nil
}

// WithAuth routes health checks and browser-admin requests before authenticating
// API traffic. Pop requests use HTTP Basic authentication; S3 requests require
// a valid, timely SigV4 signature and LDAP credentials encoded in the access
// key. Successful requests receive authorization and identity context values.
func (s *Server) WithAuth(next http.Handler, adminHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := s.authenticationClientIP(r)
		r = r.WithContext(context.WithValue(r.Context(), authClientIPContextKey{}, clientIP))
		if isAuthenticationIngressRequest(r) && !s.authLimiter.AllowIngress(clientIP) {
			writeAuthenticationIngressLimited(w, r)
			return
		}
		if adminpage.IsBrowser(r) && adminpage.IsAdminRoute(r.URL.Path) {
			if r.Method == http.MethodPost && adminpage.IsLoginRoute(r.URL.Path) {
				controller := http.NewResponseController(w)
				// Keep the deadline through request-body cleanup; net/http replaces it
				// with the next request's header deadline on a reused connection.
				_ = controller.SetReadDeadline(time.Now().Add(s.cfg.AdminLoginReadTimeout))
			}
			adminHandler.ServeHTTP(w, r)
			return
		}
		if isPopAPIPath(r.URL.Path) {
			s.authenticatePopBasic(w, r, next)
			return
		}

		auth, err := sigv4.ParseSigV4Authorization(r)
		if err != nil || auth.Service != "s3" {
			s3xml.WriteError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}
		if err := sigv4.ValidateSigV4RequestTime(auth, time.Now(), s.cfg.SigV4MaxSkew); err != nil {
			s3xml.WriteError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		upn, pass, secretKey, err := s3credentials.Decode(auth.AccessKey, s.cfg.S3GatewayPrivateX25519Key)
		if err != nil {
			s3xml.WriteError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		if err := sigv4.VerifySigV4(r, auth, secretKey); err != nil {
			s3xml.WriteError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}
		s.setS3AuditPrincipal(r, upn)

		grps, err := s.GroupsForCredentialsContext(r.Context(), upn, pass)
		if err != nil {
			if errors.Is(err, authn.ErrLimited) {
				w.Header().Set("Retry-After", "1")
				s3xml.WriteError(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate")
				return
			}
			s3xml.WriteError(w, http.StatusUnauthorized, "AccessDenied", "Bad credentials")
			return
		}
		markS3AuditAuthenticated(r)

		rules := authz.RulesFromGroups(grps)
		ctx := authz.WithRules(r.Context(), rules)
		ctx = sigv4.WithSigV4Auth(ctx, auth)
		ctx = sigv4.WithSigV4Secret(ctx, secretKey)
		ctx = context.WithValue(ctx, ctxUploaderKey, upn)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) authenticatePopBasic(
	w http.ResponseWriter,
	r *http.Request,
	next http.Handler,
) {
	upn, pass, ok := r.BasicAuth()
	if !ok || strings.TrimSpace(upn) == "" || pass == "" {
		writePopBasicAuthChallenge(w)
		return
	}

	s.setS3AuditPrincipal(r, upn)
	grps, err := s.GroupsForCredentialsContext(r.Context(), upn, pass)
	if err != nil {
		if errors.Is(err, authn.ErrLimited) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		writePopBasicAuthChallenge(w)
		return
	}
	markS3AuditAuthenticated(r)

	ctx := authz.WithRules(r.Context(), authz.RulesFromGroups(grps))
	ctx = context.WithValue(ctx, ctxUploaderKey, upn)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func isAuthenticationIngressRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if adminpage.IsBrowser(r) && adminpage.IsAdminRoute(r.URL.Path) {
		return r.Method == http.MethodPost && adminpage.IsLoginRoute(r.URL.Path)
	}
	return true
}

func writeAuthenticationIngressLimited(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "1")
	if adminpage.IsBrowser(r) && adminpage.IsAdminRoute(r.URL.Path) {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	if isPopAPIPath(r.URL.Path) {
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}
	s3xml.WriteError(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate")
}

func authClientIPFromContext(ctx context.Context) string {
	if ctx == nil {
		return "unknown"
	}
	clientIP, _ := ctx.Value(authClientIPContextKey{}).(string)
	if clientIP == "" {
		return "unknown"
	}
	return clientIP
}

func (s *Server) authenticationClientIP(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	peer, ok := parseRemoteIP(r.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if !prefixesContain(s.trustedProxyPrefixes, peer) {
		return peer.String()
	}

	forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	parts := strings.Split(forwarded, ",")
	if forwarded == "" || len(parts) > maxForwardedForHops {
		return peer.String()
	}
	addresses := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		address, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return peer.String()
		}
		addresses = append(addresses, address.Unmap())
	}
	for _, address := range slices.Backward(addresses) {
		if !prefixesContain(s.trustedProxyPrefixes, address) {
			return address.String()
		}
	}
	return addresses[0].String()
}

func parseRemoteIP(remoteAddress string) (netip.Addr, bool) {
	remoteAddress = strings.TrimSpace(remoteAddress)
	if remoteAddress == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func prefixesContain(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func writePopBasicAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", popBasicAuthChallenge)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

// UploaderFromRequest returns the domainless LDAP username stored by WithAuth,
// or an empty string when the request has no gateway identity.
func UploaderFromRequest(r *http.Request) string {
	v := r.Context().Value(ctxUploaderKey)
	if v == nil {
		return ""
	}
	uploader, _ := v.(string)
	return strings.TrimSpace(uploader)
}

// unsupportedSubresources are the S3 sub-resource query keys of operations the
// gateway does not implement. They must be rejected before method dispatch:
// a sub-resource request that fell through would otherwise be executed as the
// plain bucket/object operation (e.g. PutObjectAcl `PUT /b/k?acl` would
// overwrite the object via PutObject, and DeleteBucketPolicy
// `DELETE /b?policy` would delete the bucket).
var unsupportedSubresources = map[string]struct{}{
	"analytics":             {},
	"intelligent-tiering":   {},
	"inventory":             {},
	"legal-hold":            {},
	"metadataConfiguration": {},
	"metadataTable":         {},
	"metrics":               {},
	"object-lock":           {},
	"ownershipControls":     {},
	"renameObject":          {},
	"restore":               {},
	"retention":             {},
	"select":                {},
	"session":               {},
	"torrent":               {},
}

// bucketOnlySubresources are implemented bucket-level sub-resources that have
// no meaning on an object path. They must be rejected there explicitly so a
// request like `PUT /bucket/key?policy` can never fall through to PutObject.
var bucketOnlySubresources = map[string]struct{}{
	"accelerate":        {},
	"cors":              {},
	"delete":            {},
	"encryption":        {},
	"lifecycle":         {},
	"location":          {},
	"logging":           {},
	"notification":      {},
	"policy":            {},
	"policyStatus":      {},
	"publicAccessBlock": {},
	"replication":       {},
	"requestPayment":    {},
	"versioning":        {},
	"versions":          {},
	"website":           {},
}

func firstUnsupportedSubresource(q url.Values) string {
	found := make([]string, 0, 1)
	for k := range q {
		if _, ok := unsupportedSubresources[k]; ok {
			found = append(found, k)
		}
	}
	if len(found) == 0 {
		return ""
	}
	sort.Strings(found)
	return found[0]
}

// ServeHTTP dispatches health checks, the Kafka pop API, and the supported
// path-style S3 bucket and object operations. Unsupported subresources are
// rejected before dispatch so they cannot fall through to a different S3
// operation.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path-style only:
	//   /                 => ListBuckets
	//   /bucket           => CreateBucket, ListObjects (v1+v2), GetBucketLocation, ListMultipartUploads, Lifecycle config
	//   /bucket/key       => GetObject, PutObject, DeleteObject, GetObjectAttributes, Multipart ops via query
	// Sub-resources of unimplemented operations are rejected up front so they
	// can never fall through to a plain bucket/object handler.

	p := r.URL.Path
	if p == "" {
		p = "/"
	}
	if p == "/healthz" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("ok\n"))
		}
		return
	}
	if p == "/readyz" {
		if !s.readinessClientAllowed(r) {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleReadyz(w, r)
		return
	}
	if isPopAPIPath(p) {
		s.handlePopAPI(w, r)
		return
	}

	if sub := firstUnsupportedSubresource(r.URL.Query()); sub != "" {
		s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented: "+sub)
		return
	}

	if p == "/" && r.Method == http.MethodGet {
		s.handleListBuckets(w, r)
		return
	}

	rest := strings.TrimPrefix(p, "/")
	if rest == "" {
		s3xml.WriteError(w, http.StatusNotFound, "NoSuchKey", "Not Found")
		return
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) == 2 && parts[1] == "" {
		parts = parts[:1]
	}
	bucket := parts[0]

	// /bucket
	if len(parts) == 1 {
		q := r.URL.Query()
		if _, ok := q["lifecycle"]; ok {
			switch r.Method {
			case http.MethodPut:
				s.handlePutBucketLifecycleConfiguration(w, r, bucket)
				return
			case http.MethodGet:
				s.handleGetBucketLifecycleConfiguration(w, r, bucket)
				return
			case http.MethodDelete:
				s.handleDeleteBucketLifecycleConfiguration(w, r, bucket)
				return
			default:
				s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
				return
			}
		}
		if _, ok := q["versioning"]; ok {
			switch r.Method {
			case http.MethodPut:
				s.handlePutBucketVersioning(w, r, bucket)
				return
			case http.MethodGet:
				s.handleGetBucketVersioning(w, r, bucket)
				return
			default:
				s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
				return
			}
		}
		if _, ok := q["tagging"]; ok {
			switch r.Method {
			case http.MethodPut:
				s.handlePutBucketTagging(w, r, bucket)
				return
			case http.MethodGet:
				s.handleGetBucketTagging(w, r, bucket)
				return
			case http.MethodDelete:
				s.handleDeleteBucketTagging(w, r, bucket)
				return
			default:
				s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
				return
			}
		}
		if _, ok := q["acl"]; ok {
			switch r.Method {
			case http.MethodGet:
				s.handleGetBucketACL(w, r, bucket)
				return
			case http.MethodPut:
				s.handlePutBucketACL(w, r, bucket)
				return
			default:
				s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
				return
			}
		}
		if _, ok := q["encryption"]; ok {
			switch r.Method {
			case http.MethodPut:
				s.handlePutBucketEncryption(w, r, bucket)
				return
			case http.MethodGet:
				s.handleGetBucketEncryption(w, r, bucket)
				return
			case http.MethodDelete:
				s.handleDeleteBucketEncryption(w, r, bucket)
				return
			default:
				s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
				return
			}
		}
		for _, cfgKey := range bucketConfigReadKeys {
			if _, ok := q[cfgKey]; !ok {
				continue
			}
			if r.Method == http.MethodGet {
				s.handleBucketConfigRead(w, r, bucket, cfgKey)
				return
			}
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
		if _, ok := q["delete"]; ok {
			if r.Method == http.MethodPost {
				s.handleDeleteObjects(w, r, bucket)
				return
			}
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
		if _, ok := q["location"]; ok {
			if r.Method == http.MethodGet {
				s.handleGetBucketLocation(w, r, bucket)
				return
			}
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
		if _, ok := q["versions"]; ok {
			if r.Method == http.MethodGet {
				s.handleListObjectVersions(w, r, bucket)
				return
			}
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
		if _, ok := q["uploads"]; ok {
			if r.Method == http.MethodGet {
				s.handleListMultipartUploads(w, r, bucket)
				return
			}
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
		if r.Method == http.MethodPut {
			s.handleCreateBucket(w, r, bucket)
			return
		}
		if r.Method == http.MethodDelete {
			s.handleDeleteBucket(w, r, bucket)
			return
		}
		if r.Method == http.MethodHead {
			s.handleHeadBucket(w, r, bucket)
			return
		}
		if r.Method == http.MethodGet {
			if lt := q.Get("list-type"); lt != "" {
				if lt != "2" {
					s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "Invalid List Type")
					return
				}
				s.handleListObjectsV2(w, r, bucket)
				return
			}
			s.handleListObjects(w, r, bucket)
			return
		}
		s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}

	// /bucket/key
	key := parts[1]
	q := r.URL.Query()

	for subresource := range q {
		if _, ok := bucketOnlySubresources[subresource]; ok {
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented: "+subresource)
			return
		}
	}

	if _, ok := q["acl"]; ok {
		switch r.Method {
		case http.MethodGet:
			s.handleGetObjectACL(w, r, bucket, key)
			return
		case http.MethodPut:
			s.handlePutObjectACL(w, r, bucket, key)
			return
		default:
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
	}

	if _, ok := q["tagging"]; ok {
		switch r.Method {
		case http.MethodPut:
			s.handlePutObjectTagging(w, r, bucket, key)
			return
		case http.MethodGet:
			s.handleGetObjectTagging(w, r, bucket, key)
			return
		case http.MethodDelete:
			s.handleDeleteObjectTagging(w, r, bucket, key)
			return
		default:
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
	}

	// Multipart
	if _, ok := q["uploads"]; ok {
		if r.Method == http.MethodPost {
			s.handleCreateMultipart(w, r, bucket, key)
			return
		}
		s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}
	if _, ok := q["attributes"]; ok {
		if r.Method == http.MethodGet {
			s.handleGetObjectAttributes(w, r, bucket, key)
			return
		}
		s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}
	if uploadID := q.Get("uploadId"); uploadID != "" {
		switch r.Method {
		case http.MethodGet:
			s.handleListParts(w, r, bucket, key, uploadID)
			return
		case http.MethodPut:
			pnStr := q.Get("partNumber")
			pn, err := strconv.ParseInt(pnStr, 10, 32)
			if err != nil || pn <= 0 {
				s3xml.WriteError(w, http.StatusBadRequest, "InvalidArgument", "partNumber required")
				return
			}
			partNum := int32(pn)
			if strings.TrimSpace(r.Header.Get("x-amz-copy-source")) != "" {
				s.handleUploadPartCopy(w, r, bucket, key, uploadID, partNum)
				return
			}
			s.handleUploadPart(w, r, bucket, key, uploadID, partNum)
			return
		case http.MethodPost:
			s.handleCompleteMultipart(w, r, bucket, key, uploadID)
			return
		case http.MethodDelete:
			s.handleAbortMultipart(w, r, bucket, key, uploadID)
			return
		default:
			s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetObject(w, r, bucket, key)
		return
	case http.MethodHead:
		s.handleHeadObject(w, r, bucket, key)
		return
	case http.MethodPut:
		if strings.TrimSpace(r.Header.Get("x-amz-copy-source")) != "" {
			s.handleCopyObject(w, r, bucket, key)
			return
		}
		s.handlePutObject(w, r, bucket, key)
		return
	case http.MethodDelete:
		s.handleDeleteObject(w, r, bucket, key)
		return
	default:
		s3xml.WriteError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}
}

// ---------- handlers ----------

func (s *Server) checkLDAPReady(ctx context.Context) error {
	if strings.TrimSpace(s.cfg.LDAPURL) == "" {
		return errors.New("url not configured")
	}
	timeout := s.cfg.ReadinessCheckTimeout
	if d, ok := ctx.Deadline(); ok {
		remaining := time.Until(d)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	conn, err := ldapinternal.DialWithTimeout(s.cfg.LDAPURL, timeout)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (s *Server) checkS3Ready(ctx context.Context) error {
	if s.up == nil {
		return errors.New("client not configured")
	}
	_, err := s.up.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err
}

func (s *Server) checkReady(ctx context.Context) error {
	var errs []string
	if err := s.checkLDAPReady(ctx); err != nil {
		errs = append(errs, fmt.Sprintf("ldap: %v", err))
	}
	if err := s.checkS3Ready(ctx); err != nil {
		errs = append(errs, fmt.Sprintf("s3: %v", err))
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}

type readinessResult struct {
	err error
}

func (s *Server) readinessClientAllowed(r *http.Request) bool {
	if r == nil || strings.TrimSpace(r.RemoteAddr) == "" {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(r.RemoteAddr)
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, prefix := range s.readinessAllowedPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) cachedReadiness(ctx context.Context) error {
	now := s.readinessNow()
	if cachedErr, ok := s.readinessCacheAt(now); ok {
		return cachedErr
	}

	value, err, _ := s.readinessSF.Do("readiness", func() (any, error) {
		now := s.readinessNow()
		if cachedErr, ok := s.readinessCacheAt(now); ok {
			return readinessResult{err: cachedErr}, nil
		}

		checkCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ReadinessCheckTimeout)
		defer cancel()
		check := s.readinessCheck
		if check == nil {
			check = s.checkReady
		}
		checkErr := check(checkCtx)
		checkedAt := s.readinessNow()
		s.readinessMu.Lock()
		s.readinessCachedAt = checkedAt
		s.readinessCachedErr = checkErr
		s.readinessCacheValid = true
		s.readinessMu.Unlock()
		if checkErr != nil {
			s.auditLogger().Warn("readiness check failed", "error", checkErr)
		}
		return readinessResult{err: checkErr}, nil
	})
	if err != nil {
		return err
	}
	result, ok := value.(readinessResult)
	if !ok {
		return errors.New("invalid readiness result")
	}
	return result.err
}

func (s *Server) readinessCacheAt(now time.Time) (error, bool) {
	s.readinessMu.Lock()
	defer s.readinessMu.Unlock()
	if !s.readinessCacheValid {
		return nil, false
	}
	age := now.Sub(s.readinessCachedAt)
	if age < 0 || age >= s.cfg.ReadinessCacheTTL {
		return nil, false
	}
	return s.readinessCachedErr, true
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if err := s.cachedReadiness(r.Context()); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("not ready\n"))
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("ok\n"))
	}
}
