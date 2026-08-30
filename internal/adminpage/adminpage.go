// Package adminpage provides the browser-based administration interface and
// its server-side session storage.
package adminpage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/define42/s3gateway/internal/authn"
	authz "github.com/define42/s3gateway/internal/authz"
	"github.com/define42/s3gateway/internal/config"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

const (
	adminSessionCookieName = "s3gateway_admin_session"
	defaultAdminSessionTTL = 30 * time.Minute
	adminSessionValueUser  = "username"
	adminSessionValueGrps  = "groups"
	adminPreviewMaxKeys    = int32(25)
	maxAdminFormBodySize   = 64 * 1024 // 64 KiB is more than enough for any admin form

	maxAdminUploadParts              = 128
	maxAdminUploadMetadataFields     = 64
	maxAdminUploadFieldBytes         = int64(8 << 10)
	maxAdminUploadMetadataKeyBytes   = 256
	maxAdminUploadMetadataValueBytes = int64(4 << 10)
	maxAdminUploadMetadataBytes      = 16 << 10
)

// IsBrowser reports whether a request looks like interactive browser traffic.
// SigV4 authorization always takes precedence, even when the request also
// advertises HTML support and a Mozilla-compatible user agent.
func IsBrowser(r *http.Request) bool {
	auth := strings.ToLower(strings.TrimSpace(r.Header.Get("Authorization")))
	if strings.HasPrefix(auth, "aws4-hmac-sha256 ") {
		return false
	}

	accept := strings.ToLower(r.Header.Get("Accept"))
	ua := strings.ToLower(r.Header.Get("User-Agent"))

	return strings.Contains(accept, "text/html") &&
		strings.Contains(ua, "mozilla")
}

func normalizeAdminRoutePath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return "/"
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	if p == "" {
		return "/"
	}
	return p
}

// IsAdminRoute reports whether path names a route owned by the administration
// interface. It ignores trailing slashes on non-root paths.
func IsAdminRoute(path string) bool {
	switch normalizeAdminRoutePath(path) {
	case "/", "/login", "/admin", "/admin/create-bucket", "/admin/bucket", "/admin/bucket/download", "/admin/bucket/upload", "/admin/bucket/delete", "/logout":
		return true
	default:
		return false
	}
}

func requestOrigin(r *http.Request) string {
	host := strings.TrimSpace(r.Host)
	if host == "" {
		host = strings.TrimSpace(r.URL.Host)
	}
	if host == "" {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strings.ToLower(scheme + "://" + host)
}

func isSameOrigin(rawURL, expectedOrigin string) bool {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || expectedOrigin == "" {
		return false
	}
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return strings.EqualFold(parsed.Scheme+"://"+parsed.Host, expectedOrigin)
}

func hasTrustedAdminOrigin(r *http.Request) bool {
	// Non-browser requests cannot reach admin routes in production because withAuth
	// dispatches admin handlers only for browser traffic.
	if !IsBrowser(r) {
		return true
	}
	expectedOrigin := requestOrigin(r)
	if expectedOrigin == "" {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		return isSameOrigin(origin, expectedOrigin)
	}
	referer := strings.TrimSpace(r.Header.Get("Referer"))
	if referer != "" {
		return isSameOrigin(referer, expectedOrigin)
	}
	return false
}

type adminPermissionView struct {
	Letter string
	Name   string
}

type adminGroupAccessView struct {
	GroupName         string
	BucketPrefix      string
	PermissionLetters string
	Permissions       []adminPermissionView
	Buckets           []adminBucketView
}

type adminBucketView struct {
	Name             string
	CanRead          bool
	ObjectKeys       []string
	ObjectsTruncated bool
	ObjectListError  string
}

type adminBucketPageData struct {
	Username             string
	BucketName           string
	Error                string
	Notice               string
	GeneratedAt          string
	Objects              []adminBucketObjectView
	HasNext              bool
	HasPrev              bool
	NextURL              string
	PrevURL              string
	CurrentCursor        string
	CurrentHistory       string
	CanUploadObjects     bool
	CanDeleteObjects     bool
	RequiredMetadataKeys []string
}

type adminBucketObjectView struct {
	Key         string
	SizeBytes   int64
	LastModUTC  string
	ExpiresUTC  string
	Metadata    []adminMetadataPair
	MetadataErr string
}

type adminMetadataPair struct {
	Key   string
	Value string
}

type adminPageData struct {
	Username          string
	Error             string
	Notice            string
	GeneratedAt       string
	GroupCount        int
	TotalBuckets      int
	Groups            []adminGroupAccessView
	IgnoredGroups     []string
	CreateSpaces      []string
	CanCreateBuckets  bool
	CreateSpace       string
	CreateSuffix      string
	CreateBucketLabel string
}

type adminLoginPageData struct {
	Username string
	Error    string
}

type adminSession struct {
	Username string
	Groups   map[string]struct{}
	Expires  time.Time
	LastSeen time.Time
}

// AdminSessionStore holds authenticated admin sessions in memory. Sessions
// expire after an idle TTL, and saving beyond the capacity evicts the
// least-recently-seen session.
type AdminSessionStore struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	data       map[string]adminSession
}

// NewAdminSessionStore constructs an in-memory admin session backend.
// Non-positive arguments use the package defaults.
func NewAdminSessionStore(ttl time.Duration, maxEntries int) *AdminSessionStore {
	if ttl <= 0 {
		ttl = defaultAdminSessionTTL
	}
	if maxEntries <= 0 {
		maxEntries = 100
	}
	return &AdminSessionStore{
		ttl:        ttl,
		maxEntries: maxEntries,
		data:       map[string]adminSession{},
	}
}

func (s *AdminSessionStore) save(sessionID, username string, groups map[string]struct{}) (string, error) {
	if username == "" {
		return "", errors.New("missing username")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	s.evictExpiredLocked(now)

	existingID := strings.TrimSpace(sessionID)
	if existingID != "" {
		if _, ok := s.data[existingID]; ok {
			s.data[existingID] = adminSession{
				Username: username,
				Groups:   cloneGroups(groups),
				Expires:  now.Add(s.ttl),
				LastSeen: now,
			}
			return existingID, nil
		}
	}

	if len(s.data) >= s.maxEntries {
		s.evictOneOldestLocked()
	}

	for range 5 {
		newID, err := newAdminSessionID()
		if err != nil {
			return "", err
		}
		if _, exists := s.data[newID]; exists {
			continue
		}
		s.data[newID] = adminSession{
			Username: username,
			Groups:   cloneGroups(groups),
			Expires:  now.Add(s.ttl),
			LastSeen: now,
		}
		return newID, nil
	}

	return "", errors.New("failed to allocate unique session id")
}

func (s *AdminSessionStore) get(sessionID string) (adminSession, bool) {
	if sessionID == "" {
		return adminSession{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.data[sessionID]
	if !ok {
		return adminSession{}, false
	}

	now := time.Now()
	if now.After(e.Expires) {
		delete(s.data, sessionID)
		return adminSession{}, false
	}

	e.LastSeen = now
	e.Expires = now.Add(s.ttl)
	s.data[sessionID] = e

	return adminSession{
		Username: e.Username,
		Groups:   cloneGroups(e.Groups),
		Expires:  e.Expires,
		LastSeen: e.LastSeen,
	}, true
}

func (s *AdminSessionStore) delete(sessionID string) {
	if sessionID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, sessionID)
}

func (s *AdminSessionStore) evictExpiredLocked(now time.Time) {
	for key, e := range s.data {
		if now.After(e.Expires) {
			delete(s.data, key)
		}
	}
}

func (s *AdminSessionStore) evictOneOldestLocked() {
	var victimKey string
	var victim adminSession
	set := false
	for k, v := range s.data {
		if !set || v.LastSeen.Before(victim.LastSeen) {
			victimKey = k
			victim = v
			set = true
		}
	}
	if set {
		delete(s.data, victimKey)
	}
}

func cloneGroups(groups map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(groups))
	for k := range groups {
		out[k] = struct{}{}
	}
	return out
}

func newAdminSessionID() (string, error) {
	raw := make([]byte, 32)
	if err := readAdminSessionRandom(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// AdminGorillaStore implements sessions.Store with encrypted cookies that
// contain only an opaque ID; authenticated session data remains in its
// AdminSessionStore backend.
type AdminGorillaStore struct {
	backend *AdminSessionStore
	Codecs  []securecookie.Codec
	Options *sessions.Options
}

var adminSessionRandomReader io.Reader = rand.Reader

func readAdminSessionRandom(dst []byte) error {
	_, err := io.ReadFull(adminSessionRandomReader, dst)
	return err
}

func random32() [32]byte {
	var b [32]byte
	if err := readAdminSessionRandom(b[:]); err != nil {
		panic("admin session key generation failed: " + err.Error())
	}
	return b
}

// NewAdminGorillaStore constructs the cookie-facing session store. An empty
// cookieSecret generates ephemeral keys, invalidating cookies after restart;
// a non-positive TTL uses the package default.
//
// With an empty cookieSecret, the function panics if secure random key
// generation fails.
func NewAdminGorillaStore(cookieSecret string, ttl time.Duration, backend *AdminSessionStore) *AdminGorillaStore {

	if ttl <= 0 {
		ttl = defaultAdminSessionTTL
	}
	var hashKey, blockKey [32]byte
	if cookieSecret == "" {
		slog.Warn("COOKIE_SECRET is not set; admin sessions will use ephemeral random keys and will be invalidated on restart")
		hashKey = random32()
		blockKey = random32()
	} else {
		hashKey = sha256.Sum256([]byte("s3gateway-admin-hash:" + cookieSecret))
		blockKey = sha256.Sum256([]byte("s3gateway-admin-block:" + cookieSecret))
	}
	codecs := securecookie.CodecsFromPairs(hashKey[:], blockKey[:])

	store := &AdminGorillaStore{
		backend: backend,
		Codecs:  codecs,
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   int(ttl.Seconds()),
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}
	store.MaxAge(store.Options.MaxAge)
	return store
}

// MaxAge updates the default cookie lifetime and the age accepted by each
// secure-cookie codec.
func (s *AdminGorillaStore) MaxAge(age int) {
	s.Options.MaxAge = age
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// Get returns the named session from the request-scoped Gorilla registry,
// loading it through New on the first access.
func (s *AdminGorillaStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(s, name)
}

func sessionGroupsSlice(groups map[string]struct{}) []string {
	if len(groups) == 0 {
		return nil
	}
	out := make([]string, 0, len(groups))
	for g := range groups {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func parseSessionGroups(v any) map[string]struct{} {
	out := make(map[string]struct{})
	switch raw := v.(type) {
	case []string:
		for _, g := range raw {
			g = strings.TrimSpace(strings.ToLower(g))
			if g != "" {
				out[g] = struct{}{}
			}
		}
	case []any:
		for _, item := range raw {
			s, ok := item.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(strings.ToLower(s))
			if s != "" {
				out[s] = struct{}{}
			}
		}
	case map[string]struct{}:
		for g := range raw {
			g = strings.TrimSpace(strings.ToLower(g))
			if g != "" {
				out[g] = struct{}{}
			}
		}
	}
	return out
}

func adminSessionToValues(s adminSession) map[any]any {
	return map[any]any{
		adminSessionValueUser: s.Username,
		adminSessionValueGrps: sessionGroupsSlice(s.Groups),
	}
}

func adminSessionFromValues(values map[any]any) (string, map[string]struct{}, error) {
	rawUser, ok := values[adminSessionValueUser]
	if !ok {
		return "", nil, errors.New("missing admin session username")
	}
	username, ok := rawUser.(string)
	if !ok {
		return "", nil, errors.New("invalid admin session username")
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return "", nil, errors.New("missing admin session username")
	}

	groups := parseSessionGroups(values[adminSessionValueGrps])
	return username, groups, nil
}

// New decodes a named session cookie and loads the corresponding server-side
// session. Missing or expired backend entries are treated as new sessions.
func (s *AdminGorillaStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(s, name)
	opts := *s.Options
	opts.Secure = r.TLS != nil
	session.Options = &opts
	session.IsNew = true

	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, s.Codecs...)
		if err == nil && session.ID != "" && s.backend != nil {
			stored, ok := s.backend.get(session.ID)
			if ok {
				session.Values = adminSessionToValues(stored)
				session.IsNew = false
			} else {
				session.ID = ""
			}
		}
	}
	return session, err
}

// Save persists the authenticated session data and writes an encrypted ID
// cookie. A non-positive session MaxAge deletes the backend entry and cookie.
// Save returns an error for an unconfigured backend, invalid session values,
// backend persistence failures, or cookie-encoding failures.
func (s *AdminGorillaStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.Options == nil {
		opts := *s.Options
		session.Options = &opts
	}
	session.Options.Secure = r.TLS != nil

	if session.Options.MaxAge <= 0 {
		if s.backend != nil && session.ID != "" {
			s.backend.delete(session.ID)
		}
		session.ID = ""
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if s.backend == nil {
		return errors.New("admin session backend is not configured")
	}

	username, groups, err := adminSessionFromValues(session.Values)
	if err != nil {
		return err
	}

	sessionID, err := s.backend.save(session.ID, username, groups)
	if err != nil {
		return err
	}
	session.ID = sessionID

	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID, s.Codecs...)
	if err != nil {
		return err
	}

	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func permLetters(perm authz.Perm) string {
	var b strings.Builder
	if perm&authz.PermRead != 0 {
		b.WriteByte('r')
	}
	if perm&authz.PermWrite != 0 {
		b.WriteByte('w')
	}
	if perm&authz.PermCreateBucket != 0 {
		b.WriteByte('c')
	}
	if perm&authz.PermDeleteObject != 0 {
		b.WriteByte('d')
	}
	if perm&authz.PermDeleteBucket != 0 {
		b.WriteByte('b')
	}
	return b.String()
}

func permViews(perm authz.Perm) []adminPermissionView {
	out := make([]adminPermissionView, 0, 5)
	if perm&authz.PermRead != 0 {
		out = append(out, adminPermissionView{Letter: "r", Name: "Read"})
	}
	if perm&authz.PermWrite != 0 {
		out = append(out, adminPermissionView{Letter: "w", Name: "Write"})
	}
	if perm&authz.PermCreateBucket != 0 {
		out = append(out, adminPermissionView{Letter: "c", Name: "Create bucket"})
	}
	if perm&authz.PermDeleteObject != 0 {
		out = append(out, adminPermissionView{Letter: "d", Name: "Delete object"})
	}
	if perm&authz.PermDeleteBucket != 0 {
		out = append(out, adminPermissionView{Letter: "b", Name: "Delete bucket"})
	}
	return out
}

func buildAdminGroupAccess(groups map[string]struct{}, buckets []string, previews map[string]adminBucketView) ([]adminGroupAccessView, []string) {
	allBuckets := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		bucket = strings.TrimSpace(bucket)
		if bucket == "" {
			continue
		}
		allBuckets = append(allBuckets, bucket)
	}
	sort.Strings(allBuckets)

	groupRows := make([]adminGroupAccessView, 0, len(groups))
	ignored := make([]string, 0)
	for group := range groups {
		prefix, perm, ok := authz.ParseGroup(group)
		if !ok {
			ignored = append(ignored, group)
			continue
		}

		bucketNS := strings.ToLower(prefix)
		row := adminGroupAccessView{
			GroupName:         group,
			BucketPrefix:      bucketNS,
			PermissionLetters: permLetters(perm),
			Permissions:       permViews(perm),
			Buckets:           make([]adminBucketView, 0),
		}
		for _, bucket := range allBuckets {
			if authz.BucketNamespace(bucket) == bucketNS {
				bucketView, ok := previews[bucket]
				if !ok {
					bucketView = adminBucketView{Name: bucket}
				}
				if bucketView.Name == "" {
					bucketView.Name = bucket
				}
				row.Buckets = append(row.Buckets, bucketView)
			}
		}

		groupRows = append(groupRows, row)
	}

	sort.Slice(groupRows, func(i, j int) bool {
		return groupRows[i].GroupName < groupRows[j].GroupName
	})
	sort.Strings(ignored)

	return groupRows, ignored
}

func countUniqueBuckets(rows []adminGroupAccessView) int {
	seen := make(map[string]struct{})
	for _, row := range rows {
		for _, bucket := range row.Buckets {
			if bucket.Name == "" {
				continue
			}
			seen[bucket.Name] = struct{}{}
		}
	}
	return len(seen)
}

func adminCreateBucketSpaces(groups map[string]struct{}) []string {
	seen := make(map[string]struct{})
	for group := range groups {
		prefix, perm, ok := authz.ParseGroup(group)
		if !ok {
			continue
		}
		if perm&authz.PermCreateBucket == 0 {
			continue
		}
		prefix = strings.ToLower(strings.TrimSpace(prefix))
		if prefix == "" {
			continue
		}
		seen[prefix] = struct{}{}
	}

	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func adminHasCreateSpace(spaces []string, space string) bool {
	space = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(space, "-")))
	return slices.Contains(spaces, space)
}

func adminBuildBucketName(space, suffix string) (string, error) {
	space = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(space, "-")))
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	if space == "" {
		return "", errors.New("bucket space is required")
	}
	if suffix == "" {
		return "", errors.New("bucket name suffix is required")
	}

	if after, ok := strings.CutPrefix(suffix, space+"-"); ok {
		suffix = after
	}
	suffix = strings.TrimSpace(strings.Trim(suffix, "-"))
	if suffix == "" {
		return "", errors.New("bucket name suffix is required")
	}
	return space + "-" + suffix, nil
}

func (h *handler) listAllBuckets(ctx context.Context) ([]string, error) {
	if h == nil {
		return nil, errors.New("handler not configured")
	}
	if h.s3 == nil {
		return nil, errors.New("upstream s3 client is not configured")
	}

	out, err := h.s3.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(out.Buckets))
	for _, bucket := range out.Buckets {
		if bucket.Name == nil {
			continue
		}
		name := strings.TrimSpace(*bucket.Name)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func metadataPairsFromMap(meta map[string]string) []adminMetadataPair {
	if len(meta) == 0 {
		return nil
	}

	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]adminMetadataPair, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, adminMetadataPair{
			Key:   k,
			Value: meta[k],
		})
	}
	return pairs
}

func formatObjectExpiresUTC(expiresString *string) string {
	raw := strings.TrimSpace(aws.ToString(expiresString))
	if raw == "" {
		return ""
	}
	parsed, err := http.ParseTime(raw)
	if err != nil {
		return raw
	}
	return parsed.UTC().Format(time.RFC3339)
}

func (h *handler) headObjectMetadata(ctx context.Context, bucket, key string) ([]adminMetadataPair, string, string) {
	out, err := h.s3.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		return nil, "", "Could not load metadata."
	}
	return metadataPairsFromMap(out.Metadata), formatObjectExpiresUTC(out.ExpiresString), ""
}

func formatObjectLastModifiedUTC(lastModified *time.Time) string {
	if lastModified == nil || lastModified.IsZero() {
		return ""
	}
	return lastModified.UTC().Format(time.RFC3339)
}

func (h *handler) listBucketObjects(ctx context.Context, bucket, continuationToken string, maxKeys int32) ([]adminBucketObjectView, string, bool, error) {
	if h == nil {
		return nil, "", false, errors.New("handler not configured")
	}
	if h.s3 == nil {
		return nil, "", false, errors.New("upstream s3 client is not configured")
	}
	if strings.TrimSpace(bucket) == "" {
		return nil, "", false, errors.New("bucket is required")
	}
	if maxKeys <= 0 {
		maxKeys = adminPreviewMaxKeys
	}

	in := &s3.ListObjectsV2Input{
		Bucket:  &bucket,
		MaxKeys: aws.Int32(maxKeys),
	}
	if tok := strings.TrimSpace(continuationToken); tok != "" {
		in.ContinuationToken = aws.String(tok)
	}

	out, err := h.s3.ListObjectsV2(ctx, in)
	if err != nil {
		return nil, "", false, err
	}

	objects := make([]adminBucketObjectView, 0, len(out.Contents))
	for _, obj := range out.Contents {
		if obj.Key == nil {
			continue
		}
		key := strings.TrimSpace(*obj.Key)
		if key == "" {
			continue
		}
		view := adminBucketObjectView{
			Key:        key,
			SizeBytes:  aws.ToInt64(obj.Size),
			LastModUTC: formatObjectLastModifiedUTC(obj.LastModified),
		}
		view.Metadata, view.ExpiresUTC, view.MetadataErr = h.headObjectMetadata(ctx, bucket, key)
		objects = append(objects, view)
	}
	return objects, strings.TrimSpace(aws.ToString(out.NextContinuationToken)), out.IsTruncated != nil && *out.IsTruncated, nil
}

func (h *handler) bucketPreviewsForGroups(groups map[string]struct{}, buckets []string) map[string]adminBucketView {
	previews := make(map[string]adminBucketView, len(buckets))
	rules := authz.RulesFromGroups(groups)

	for _, bucket := range buckets {
		bucket = strings.TrimSpace(bucket)
		if bucket == "" {
			continue
		}

		view := adminBucketView{
			Name:    bucket,
			CanRead: authz.CanRead(rules, bucket),
		}
		previews[bucket] = view
	}

	return previews
}

func decodeAdminCursorHistory(raw string) ([]string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return nil, nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}

	var history []string
	if err := json.Unmarshal(payload, &history); err != nil {
		return nil, err
	}
	for i := range history {
		history[i] = strings.TrimSpace(history[i])
	}
	return history, nil
}

func encodeAdminCursorHistory(history []string) string {
	if len(history) == 0 {
		return ""
	}

	payload, err := json.Marshal(history)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(payload)
}

func adminBucketPageURL(bucket, cursor string, history []string) string {
	return adminBucketPageURLWithStatus(bucket, cursor, encodeAdminCursorHistory(history), "", "")
}

func adminDashboardURL(notice, pageErr, selectedSpace, suffix string) string {
	q := url.Values{}
	if strings.TrimSpace(notice) != "" {
		q.Set("msg", notice)
	}
	if strings.TrimSpace(pageErr) != "" {
		q.Set("err", pageErr)
	}
	if strings.TrimSpace(selectedSpace) != "" {
		q.Set("space", selectedSpace)
	}
	if strings.TrimSpace(suffix) != "" {
		q.Set("suffix", suffix)
	}
	if len(q) == 0 {
		return "/admin"
	}
	return "/admin?" + q.Encode()
}

func adminBucketPageURLWithStatus(bucket, cursor, encodedHistory, notice, pageErr string) string {
	q := url.Values{}
	q.Set("name", bucket)
	if strings.TrimSpace(cursor) != "" {
		q.Set("cursor", cursor)
	}
	if strings.TrimSpace(encodedHistory) != "" {
		q.Set("history", encodedHistory)
	}
	if strings.TrimSpace(notice) != "" {
		q.Set("msg", notice)
	}
	if strings.TrimSpace(pageErr) != "" {
		q.Set("err", pageErr)
	}
	return "/admin/bucket?" + q.Encode()
}

func adminBucketFileActionRedirectURL(r *http.Request, bucket, notice, pageErr string) string {
	cursor := strings.TrimSpace(r.FormValue("cursor"))
	history := strings.TrimSpace(r.FormValue("history"))
	return adminBucketPageURLWithStatus(bucket, cursor, history, notice, pageErr)
}

func (h *handler) currentAdminSession(r *http.Request) (adminSession, *sessions.Session, bool) {
	if h == nil || h.webSessions == nil {
		return adminSession{}, nil, false
	}

	webSession, err := h.webSessions.Get(r, adminSessionCookieName)
	if err != nil || webSession == nil {
		return adminSession{}, webSession, false
	}
	if webSession.IsNew || webSession.ID == "" {
		return adminSession{}, webSession, false
	}

	username, groups, err := adminSessionFromValues(webSession.Values)
	if err != nil {
		return adminSession{}, webSession, false
	}
	return adminSession{Username: username, Groups: groups}, webSession, true
}

func clearAdminSession(w http.ResponseWriter, r *http.Request, webSession *sessions.Session) {
	if webSession == nil {
		return
	}
	webSession.Values = map[any]any{}
	webSession.Options.MaxAge = -1
	_ = webSession.Save(r, w)
}

func writeAdminLoginPage(w http.ResponseWriter, r *http.Request, status int, data adminLoginPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = adminLoginTmpl.Execute(w, data)
}

func writeAdminDashboardPage(w http.ResponseWriter, r *http.Request, status int, data adminPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = adminDashboardTmpl.Execute(w, data)
}

func writeAdminBucketPage(w http.ResponseWriter, r *http.Request, status int, data adminBucketPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method == http.MethodHead {
		return
	}
	_ = adminBucketTmpl.Execute(w, data)
}

func handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (h *handler) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if h != nil {
		if _, _, ok := h.currentAdminSession(r); ok {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		writeAdminLoginPage(w, r, http.StatusOK, adminLoginPageData{})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBodySize)
	if err := r.ParseForm(); err != nil {
		writeAdminLoginPage(w, r, http.StatusBadRequest, adminLoginPageData{
			Error: "Invalid form payload.",
		})
		return
	}

	upn := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	if upn == "" || pass == "" {
		writeAdminLoginPage(w, r, http.StatusBadRequest, adminLoginPageData{
			Username: upn,
			Error:    "LDAP username and password are required.",
		})
		return
	}

	if h == nil || h.webSessions == nil {
		writeAdminLoginPage(w, r, http.StatusInternalServerError, adminLoginPageData{
			Username: upn,
			Error:    "Admin backend is not configured.",
		})
		return
	}

	groups, err := h.authenticateCredentials(r.Context(), upn, pass)
	if err != nil {
		if errors.Is(err, authn.ErrLimited) {
			w.Header().Set("Retry-After", "1")
			writeAdminLoginPage(w, r, http.StatusTooManyRequests, adminLoginPageData{
				Username: upn,
				Error:    "Too many login attempts. Try again shortly.",
			})
			return
		}
		writeAdminLoginPage(w, r, http.StatusUnauthorized, adminLoginPageData{
			Username: upn,
			Error:    "LDAP login failed. Check your username and password.",
		})
		return
	}

	webSession, err := h.webSessions.Get(r, adminSessionCookieName)
	if webSession == nil {
		webSession = sessions.NewSession(h.webSessions, adminSessionCookieName)
		opts := *h.webSessions.Options
		opts.Secure = r.TLS != nil
		webSession.Options = &opts
	}
	if err != nil {
		webSession.Values = map[any]any{}
		webSession.ID = ""
	}

	webSession.Values[adminSessionValueUser] = upn
	webSession.Values[adminSessionValueGrps] = sessionGroupsSlice(groups)
	webSession.Options.MaxAge = int(defaultAdminSessionTTL.Seconds())

	if err := webSession.Save(r, w); err != nil {
		writeAdminLoginPage(w, r, http.StatusInternalServerError, adminLoginPageData{
			Username: upn,
			Error:    "Could not create admin session.",
		})
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (h *handler) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := h.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := adminPageData{
		Username:    session.Username,
		Notice:      strings.TrimSpace(r.URL.Query().Get("msg")),
		Error:       strings.TrimSpace(r.URL.Query().Get("err")),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}
	data.CreateSpaces = adminCreateBucketSpaces(session.Groups)
	data.CanCreateBuckets = len(data.CreateSpaces) > 0
	data.CreateSpace = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r.URL.Query().Get("space"), "-")))
	data.CreateSuffix = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("suffix")))
	if data.CreateSpace == "" && len(data.CreateSpaces) > 0 {
		data.CreateSpace = data.CreateSpaces[0]
	}
	if data.CreateSpace != "" && !adminHasCreateSpace(data.CreateSpaces, data.CreateSpace) && len(data.CreateSpaces) > 0 {
		data.CreateSpace = data.CreateSpaces[0]
	}
	if bucketName, err := adminBuildBucketName(data.CreateSpace, data.CreateSuffix); err == nil {
		data.CreateBucketLabel = bucketName
	}

	buckets, err := h.listAllBuckets(r.Context())
	if err != nil {
		data.Error = "Could not list S3 buckets."
		data.Groups, data.IgnoredGroups = buildAdminGroupAccess(session.Groups, nil, nil)
		data.GroupCount = len(data.Groups)
		writeAdminDashboardPage(w, r, http.StatusBadGateway, data)
		return
	}

	previews := h.bucketPreviewsForGroups(session.Groups, buckets)
	data.Groups, data.IgnoredGroups = buildAdminGroupAccess(session.Groups, buckets, previews)
	data.GroupCount = len(data.Groups)
	data.TotalBuckets = countUniqueBuckets(data.Groups)

	writeAdminDashboardPage(w, r, http.StatusOK, data)
}

func (h *handler) handleAdminCreateBucket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := h.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if h == nil || h.s3 == nil {
		http.Redirect(w, r, adminDashboardURL("", "Admin backend is not configured.", "", ""), http.StatusSeeOther)
		return
	}
	if !hasTrustedAdminOrigin(r) {
		http.Redirect(w, r, adminDashboardURL("", "Invalid form origin.", "", ""), http.StatusSeeOther)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBodySize)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, adminDashboardURL("", "Invalid form payload.", "", ""), http.StatusSeeOther)
		return
	}

	spaces := adminCreateBucketSpaces(session.Groups)
	if len(spaces) == 0 {
		http.Redirect(w, r, adminDashboardURL("", "Create-bucket permission is required.", "", ""), http.StatusSeeOther)
		return
	}

	space := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(r.FormValue("space"), "-")))
	suffix := strings.ToLower(strings.TrimSpace(r.FormValue("suffix")))
	if !adminHasCreateSpace(spaces, space) {
		http.Redirect(w, r, adminDashboardURL("", "Invalid bucket space selection.", space, suffix), http.StatusSeeOther)
		return
	}

	bucketName, err := adminBuildBucketName(space, suffix)
	if err != nil {
		http.Redirect(w, r, adminDashboardURL("", err.Error(), space, suffix), http.StatusSeeOther)
		return
	}

	rules := authz.RulesFromGroups(session.Groups)
	if !authz.CanCreateBucket(rules, bucketName) {
		http.Redirect(w, r, adminDashboardURL("", "Create-bucket permission is required.", space, suffix), http.StatusSeeOther)
		return
	}

	if _, err := h.s3.CreateBucket(r.Context(), &s3.CreateBucketInput{
		Bucket: &bucketName,
	}); err != nil {
		http.Redirect(w, r, adminDashboardURL("", "Could not create bucket.", space, suffix), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, adminDashboardURL("Created bucket: "+bucketName, "", space, ""), http.StatusSeeOther)
}

func (h *handler) handleAdminBucketPage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := h.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	bucket := strings.TrimSpace(r.URL.Query().Get("name"))
	if bucket == "" {
		writeAdminBucketPage(w, r, http.StatusBadRequest, adminBucketPageData{
			Username:    session.Username,
			Error:       "Bucket name is required.",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	rules := authz.RulesFromGroups(session.Groups)
	canUpload := authz.CanWrite(rules, bucket)
	canDelete := authz.CanDeleteObject(rules, bucket)
	if !authz.CanRead(rules, bucket) {
		writeAdminBucketPage(w, r, http.StatusForbidden, adminBucketPageData{
			Username:             session.Username,
			BucketName:           bucket,
			Error:                "Read permission is required for this bucket.",
			GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
			CanUploadObjects:     canUpload,
			CanDeleteObjects:     canDelete,
			RequiredMetadataKeys: h.requiredUploadMetadataKeys,
		})
		return
	}

	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	historyEncoded := strings.TrimSpace(r.URL.Query().Get("history"))
	history, err := decodeAdminCursorHistory(historyEncoded)
	if err != nil {
		writeAdminBucketPage(w, r, http.StatusBadRequest, adminBucketPageData{
			Username:             session.Username,
			BucketName:           bucket,
			Error:                "Invalid pagination cursor state.",
			GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
			CanUploadObjects:     canUpload,
			CanDeleteObjects:     canDelete,
			RequiredMetadataKeys: h.requiredUploadMetadataKeys,
		})
		return
	}

	objects, nextCursor, truncated, err := h.listBucketObjects(r.Context(), bucket, cursor, adminPreviewMaxKeys)
	if err != nil {
		writeAdminBucketPage(w, r, http.StatusBadGateway, adminBucketPageData{
			Username:             session.Username,
			BucketName:           bucket,
			Error:                "Could not list bucket objects.",
			GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
			CanUploadObjects:     canUpload,
			CanDeleteObjects:     canDelete,
			RequiredMetadataKeys: h.requiredUploadMetadataKeys,
		})
		return
	}

	data := adminBucketPageData{
		Username:             session.Username,
		BucketName:           bucket,
		Notice:               strings.TrimSpace(r.URL.Query().Get("msg")),
		Error:                strings.TrimSpace(r.URL.Query().Get("err")),
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		Objects:              objects,
		CurrentCursor:        cursor,
		CurrentHistory:       historyEncoded,
		CanUploadObjects:     canUpload,
		CanDeleteObjects:     canDelete,
		RequiredMetadataKeys: h.requiredUploadMetadataKeys,
	}

	if len(history) > 0 {
		prevCursor := history[len(history)-1]
		prevHistory := append([]string(nil), history[:len(history)-1]...)
		data.HasPrev = true
		data.PrevURL = adminBucketPageURL(bucket, prevCursor, prevHistory)
	}

	if truncated && nextCursor != "" {
		nextHistory := append(append([]string(nil), history...), cursor)
		data.HasNext = true
		data.NextURL = adminBucketPageURL(bucket, nextCursor, nextHistory)
	}

	writeAdminBucketPage(w, r, http.StatusOK, data)
}

func adminDownloadFilenameForKey(key string) string {
	base := strings.TrimSpace(path.Base(strings.TrimSpace(key)))
	if base == "" || base == "." || base == "/" {
		return "download.bin"
	}
	return base
}

func contentDispositionAttachment(filename string) string {
	f := strings.ReplaceAll(strings.ReplaceAll(filename, `\`, `_`), `"`, `_`)
	return `attachment; filename="` + f + `"`
}

func (h *handler) handleAdminBucketDownload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := h.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	bucket := strings.TrimSpace(r.URL.Query().Get("name"))
	key := strings.TrimSpace(r.URL.Query().Get("key"))
	if h == nil || h.s3 == nil {
		http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, "", "", "", "Admin backend is not configured."), http.StatusSeeOther)
		return
	}
	if bucket == "" || key == "" {
		http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, "", "", "", "Bucket name and object key are required."), http.StatusSeeOther)
		return
	}

	rules := authz.RulesFromGroups(session.Groups)
	if !authz.CanRead(rules, bucket) {
		http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, "", "", "", "Read permission is required for this bucket."), http.StatusSeeOther)
		return
	}

	out, err := h.s3.GetObject(r.Context(), &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, "", "", "", "Could not download object."), http.StatusSeeOther)
		return
	}
	defer func() { _ = out.Body.Close() }()

	contentType := strings.TrimSpace(aws.ToString(out.ContentType))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", contentDispositionAttachment(adminDownloadFilenameForKey(key)))
	if out.ContentLength != nil && *out.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	if out.LastModified != nil && !out.LastModified.IsZero() {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.ETag != nil {
		w.Header().Set("ETag", aws.ToString(out.ETag))
	}

	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, out.Body)
}

func (h *handler) handleAdminBucketUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := h.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if h == nil || h.s3 == nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if !hasTrustedAdminOrigin(r) {
		http.Redirect(w, r, adminDashboardURL("", "Invalid form origin.", "", ""), http.StatusSeeOther)
		return
	}

	var (
		bucket                 string
		key                    string
		cursor                 string
		history                string
		size                   int64 = -1
		bucketWriteAuthorized  bool
		partCount              int
		metadataCount          int
		metadataAggregateBytes int
	)
	metaValues := map[string]string{}

	redirectUploadPayloadError := func(pageErr string) {
		if strings.TrimSpace(bucket) == "" {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, cursor, history, "", pageErr), http.StatusSeeOther)
	}

	reader, err := r.MultipartReader()
	if err != nil {
		redirectUploadPayloadError("Could not process upload payload.")
		return
	}

	rules := authz.RulesFromGroups(session.Groups)

	for {
		part, partErr := reader.NextPart()
		if errors.Is(partErr, io.EOF) {
			break
		}
		if partErr != nil {
			redirectUploadPayloadError("Could not process upload payload.")
			return
		}
		partCount++
		if partCount > maxAdminUploadParts {
			_ = part.Close()
			redirectUploadPayloadError("Could not process upload payload.")
			return
		}

		partName := strings.TrimSpace(part.FormName())
		if rawKey, ok := strings.CutPrefix(partName, "meta-"); ok {
			metadataCount++
			if !bucketWriteAuthorized || metadataCount > maxAdminUploadMetadataFields ||
				len(rawKey) == 0 || len(rawKey) > maxAdminUploadMetadataKeyBytes {
				_ = part.Close()
				redirectUploadPayloadError("Could not process upload payload.")
				return
			}

			valueBytes, readErr := io.ReadAll(io.LimitReader(part, maxAdminUploadMetadataValueBytes+1))
			_ = part.Close()
			if readErr != nil || int64(len(valueBytes)) > maxAdminUploadMetadataValueBytes {
				redirectUploadPayloadError("Could not process upload payload.")
				return
			}
			if len(rawKey) > maxAdminUploadMetadataBytes-metadataAggregateBytes ||
				len(valueBytes) > maxAdminUploadMetadataBytes-metadataAggregateBytes-len(rawKey) {
				redirectUploadPayloadError("Could not process upload payload.")
				return
			}
			metadataAggregateBytes += len(rawKey) + len(valueBytes)
			if metaKey := config.NormalizeRequiredMetadataKey(rawKey); metaKey != "" {
				metaValues[metaKey] = strings.TrimSpace(string(valueBytes))
			}
			continue
		}
		switch partName {
		case "name", "key", "cursor", "history", "size":
			valueBytes, readErr := io.ReadAll(io.LimitReader(part, maxAdminUploadFieldBytes+1))
			_ = part.Close()
			if readErr != nil || int64(len(valueBytes)) > maxAdminUploadFieldBytes {
				redirectUploadPayloadError("Could not process upload payload.")
				return
			}

			value := strings.TrimSpace(string(valueBytes))
			switch partName {
			case "name":
				if bucket == "" {
					bucket = value
					if bucket != "" {
						if !authz.CanWrite(rules, bucket) {
							http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, cursor, history, "", "Write permission is required for uploads."), http.StatusSeeOther)
							return
						}
						bucketWriteAuthorized = true
					}
				}
			case "key":
				if key == "" {
					key = value
				}
			case "cursor":
				if cursor == "" {
					cursor = value
				}
			case "history":
				if history == "" {
					history = value
				}
			case "size":
				if size >= 0 || value == "" {
					break
				}
				parsedSize, parseErr := strconv.ParseInt(value, 10, 64)
				if parseErr != nil || parsedSize < 0 {
					redirectUploadPayloadError("Invalid file size.")
					return
				}
				size = parsedSize
			}
		case "file":
			fileName := strings.TrimSpace(part.FileName())
			fileContentType := strings.TrimSpace(part.Header.Get("Content-Type"))

			if bucket == "" {
				_ = part.Close()
				redirectUploadPayloadError("Bucket name is required.")
				return
			}

			redirectToBucket := func(notice, pageErr string) {
				http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, cursor, history, notice, pageErr), http.StatusSeeOther)
			}
			if !bucketWriteAuthorized {
				_ = part.Close()
				redirectToBucket("", "Write permission is required for uploads.")
				return
			}

			finalKey := key
			if finalKey == "" {
				finalKey = fileName
			}
			finalKey = strings.TrimSpace(strings.TrimPrefix(finalKey, "/"))
			if finalKey == "" {
				_ = part.Close()
				redirectToBucket("", "Object key is required.")
				return
			}

			// Guard against S3's maximum object size (5 TiB) when the browser provided file size.
			const maxMultipartObjectSize = int64(5 * 1024 * 1024 * 1024 * 1024)
			if size > maxMultipartObjectSize {
				_ = part.Close()
				redirectToBucket("", "File is too large. Maximum supported object size is 5 TiB.")
				return
			}

			// Apply the same upload-metadata policy as the S3 API: stamp
			// uploaded-by (overriding any client-supplied value) and enforce
			// REQUIRED_UPLOAD_METADATA_KEYS, which the browser form collects as
			// meta-<key> fields.
			meta := make(map[string]string, len(metaValues)+1)
			maps.Copy(meta, metaValues)
			meta["uploaded-by"] = strings.TrimSpace(session.Username)
			if missing := missingRequiredMetadata(meta, h.requiredUploadMetadataKeys); len(missing) > 0 {
				_ = part.Close()
				redirectToBucket("", "Missing required metadata: "+strings.Join(missing, ", "))
				return
			}

			createIn := &s3.CreateMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &finalKey,
				Metadata: meta,
			}
			if fileContentType != "" {
				createIn.ContentType = aws.String(fileContentType)
			}

			createOut, err := h.s3.CreateMultipartUpload(r.Context(), createIn)
			if err != nil {
				_ = part.Close()
				redirectToBucket("", "Could not upload object.")
				return
			}
			uploadID := strings.TrimSpace(aws.ToString(createOut.UploadId))
			if uploadID == "" {
				_ = part.Close()
				redirectToBucket("", "Could not upload object.")
				return
			}

			completed := false
			defer func() {
				if completed {
					return
				}
				_, _ = h.s3.AbortMultipartUpload(r.Context(), &s3.AbortMultipartUploadInput{
					Bucket:   &bucket,
					Key:      &finalKey,
					UploadId: &uploadID,
				})
			}()

			const uploadPartSize = int64(16 << 20) // 16 MiB
			buf := make([]byte, uploadPartSize)
			completedParts := make([]types.CompletedPart, 0, 16)
			var partNumber int32 = 1

			for {
				n, readErr := io.ReadFull(part, buf)
				if errors.Is(readErr, io.EOF) {
					break
				}
				if readErr != nil && !errors.Is(readErr, io.ErrUnexpectedEOF) {
					_ = part.Close()
					redirectToBucket("", "Could not upload object.")
					return
				}
				if n == 0 {
					break
				}
				if partNumber > 10000 {
					_ = part.Close()
					redirectToBucket("", "File is too large. Maximum multipart part count exceeded.")
					return
				}

				partBody := bytes.NewReader(buf[:n])
				uploadOut, uploadErr := h.s3.UploadPart(r.Context(), &s3.UploadPartInput{
					Bucket:        &bucket,
					Key:           &finalKey,
					UploadId:      &uploadID,
					PartNumber:    aws.Int32(partNumber),
					Body:          partBody,
					ContentLength: aws.Int64(int64(n)),
				})
				if uploadErr != nil {
					_ = part.Close()
					redirectToBucket("", "Could not upload object.")
					return
				}

				etag := strings.TrimSpace(aws.ToString(uploadOut.ETag))
				if etag == "" {
					_ = part.Close()
					redirectToBucket("", "Could not upload object.")
					return
				}
				completedParts = append(completedParts, types.CompletedPart{
					ETag:       aws.String(etag),
					PartNumber: aws.Int32(partNumber),
				})
				partNumber++

				if errors.Is(readErr, io.ErrUnexpectedEOF) {
					break
				}
			}
			_ = part.Close()

			if len(completedParts) == 0 {
				// Multipart uploads require at least one uploaded part.
				putOut, putErr := h.s3.PutObject(r.Context(), &s3.PutObjectInput{
					Bucket:        &bucket,
					Key:           &finalKey,
					Body:          bytes.NewReader(nil),
					ContentLength: aws.Int64(0),
					ContentType:   createIn.ContentType,
					Metadata:      createIn.Metadata,
				})
				if putErr != nil || putOut == nil {
					redirectToBucket("", "Could not upload object.")
					return
				}
				redirectToBucket("Uploaded object: "+finalKey, "")
				return
			}

			_, err = h.s3.CompleteMultipartUpload(r.Context(), &s3.CompleteMultipartUploadInput{
				Bucket:   &bucket,
				Key:      &finalKey,
				UploadId: &uploadID,
				MultipartUpload: &types.CompletedMultipartUpload{
					Parts: completedParts,
				},
			})
			if err != nil {
				redirectToBucket("", "Could not upload object.")
				return
			}

			completed = true
			redirectToBucket("Uploaded object: "+finalKey, "")
			return
		default:
			_, _ = io.Copy(io.Discard, part)
			_ = part.Close()
		}
	}

	if bucket == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if !bucketWriteAuthorized {
		http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, cursor, history, "", "Write permission is required for uploads."), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, adminBucketPageURLWithStatus(bucket, cursor, history, "", "A file is required for upload."), http.StatusSeeOther)
}

func (h *handler) handleAdminBucketDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := h.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if h == nil || h.s3 == nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if !hasTrustedAdminOrigin(r) {
		http.Redirect(w, r, adminDashboardURL("", "Invalid form origin.", "", ""), http.StatusSeeOther)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAdminFormBodySize)
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	bucket := strings.TrimSpace(r.FormValue("name"))
	key := strings.TrimSpace(r.FormValue("key"))
	if bucket == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	if key == "" {
		http.Redirect(w, r, adminBucketFileActionRedirectURL(r, bucket, "", "Object key is required."), http.StatusSeeOther)
		return
	}

	rules := authz.RulesFromGroups(session.Groups)
	if !authz.CanDeleteObject(rules, bucket) {
		http.Redirect(w, r, adminBucketFileActionRedirectURL(r, bucket, "", "Delete permission is required for this bucket."), http.StatusSeeOther)
		return
	}

	if _, err := h.s3.DeleteObject(r.Context(), &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}); err != nil {
		http.Redirect(w, r, adminBucketFileActionRedirectURL(r, bucket, "", "Could not delete object."), http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, adminBucketFileActionRedirectURL(r, bucket, "Deleted object: "+key, ""), http.StatusSeeOther)
}

func (h *handler) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
	default:
		w.Header().Set("Allow", "POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if !hasTrustedAdminOrigin(r) {
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if h != nil && h.webSessions != nil {
		webSession, _ := h.webSessions.Get(r, adminSessionCookieName)
		clearAdminSession(w, r, webSession)
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type handler struct {
	s3                         *s3.Client
	webSessions                *AdminGorillaStore
	authenticate               func(upn, pass string) (map[string]struct{}, error)
	authenticateContext        func(context.Context, string, string) (map[string]struct{}, error)
	requiredUploadMetadataKeys []string // normalized (lowercase, no x-amz-meta- prefix) keys required on uploads
}

// missingRequiredMetadata returns the required keys absent from meta (in the
// order they were configured). meta keys are the normalized, prefix-stripped
// form used for object metadata.
func missingRequiredMetadata(meta map[string]string, required []string) []string {
	if len(required) == 0 {
		return nil
	}
	missing := make([]string, 0, len(required))
	for _, key := range required {
		if v, ok := meta[key]; !ok || strings.TrimSpace(v) == "" {
			missing = append(missing, key)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return missing
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")

	switch normalizeAdminRoutePath(r.URL.Path) {
	case "/":
		handleAdminRoot(w, r)
	case "/login":
		h.handleAdminLogin(w, r)
	case "/admin":
		h.handleAdminDashboard(w, r)
	case "/admin/create-bucket":
		h.handleAdminCreateBucket(w, r)
	case "/admin/bucket":
		h.handleAdminBucketPage(w, r)
	case "/admin/bucket/download":
		h.handleAdminBucketDownload(w, r)
	case "/admin/bucket/upload":
		h.handleAdminBucketUpload(w, r)
	case "/admin/bucket/delete":
		h.handleAdminBucketDelete(w, r)
	case "/logout":
		h.handleAdminLogout(w, r)
	default:
		http.NotFound(w, r)
	}
}

// NewHandler constructs the admin HTTP handler with an in-memory session
// backend. requiredUploadMetadataKeys are enforced by the upload form.
func NewHandler(s3Client *s3.Client, cookieSecret string, maxSessions int, requiredUploadMetadataKeys []string, authenticate func(upn, pass string) (map[string]struct{}, error)) http.Handler {
	sessions := NewAdminSessionStore(defaultAdminSessionTTL, maxSessions)
	webSessions := NewAdminGorillaStore(cookieSecret, defaultAdminSessionTTL, sessions)
	return &handler{
		s3:                         s3Client,
		webSessions:                webSessions,
		authenticate:               authenticate,
		requiredUploadMetadataKeys: requiredUploadMetadataKeys,
	}
}

// NewHandlerWithContext constructs the admin handler with a request-aware
// authentication callback. The request context carries ingress attribution to
// layered authentication controls.
func NewHandlerWithContext(s3Client *s3.Client, cookieSecret string, maxSessions int, requiredUploadMetadataKeys []string, authenticate func(context.Context, string, string) (map[string]struct{}, error)) http.Handler {
	sessions := NewAdminSessionStore(defaultAdminSessionTTL, maxSessions)
	webSessions := NewAdminGorillaStore(cookieSecret, defaultAdminSessionTTL, sessions)
	return &handler{
		s3:                         s3Client,
		webSessions:                webSessions,
		authenticateContext:        authenticate,
		requiredUploadMetadataKeys: requiredUploadMetadataKeys,
	}
}

// NewHandlerWithSessions constructs the admin HTTP handler with a caller-owned
// session store. It is intended for callers that need to control session
// lifetime or persistence.
func NewHandlerWithSessions(s3Client *s3.Client, webSessions *AdminGorillaStore, authenticate func(upn, pass string) (map[string]struct{}, error)) http.Handler {
	return &handler{
		s3:           s3Client,
		webSessions:  webSessions,
		authenticate: authenticate,
	}
}

func (h *handler) authenticateCredentials(ctx context.Context, upn, pass string) (map[string]struct{}, error) {
	if h.authenticateContext != nil {
		return h.authenticateContext(ctx, upn, pass)
	}
	if h.authenticate == nil {
		return nil, errors.New("admin authentication is not configured")
	}
	return h.authenticate(upn, pass)
}

var (
	//go:embed webtemplate/admin-login.html webtemplate/admin-dashboard.html webtemplate/admin-bucket.html
	adminWebTemplatesFS embed.FS

	adminLoginTmpl     = template.Must(template.ParseFS(adminWebTemplatesFS, "webtemplate/admin-login.html"))
	adminDashboardTmpl = template.Must(template.ParseFS(adminWebTemplatesFS, "webtemplate/admin-dashboard.html"))
	adminBucketTmpl    = template.Must(template.ParseFS(adminWebTemplatesFS, "webtemplate/admin-bucket.html"))
)
