package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

const (
	adminSessionCookieName = "s3gateway_admin_session"
	defaultAdminSessionTTL = 30 * time.Minute
	adminSessionValueUser  = "username"
	adminSessionValueGrps  = "groups"
	adminPreviewMaxKeys    = int32(25)
)

func isBrowser(r *http.Request) bool {
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

func isAdminRoute(path string) bool {
	switch normalizeAdminRoutePath(path) {
	case "/", "/login", "/admin", "/admin/bucket", "/logout":
		return true
	default:
		return false
	}
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
	Username    string
	BucketName  string
	Error       string
	GeneratedAt string
	ObjectKeys  []string
	HasNext     bool
	HasPrev     bool
	NextURL     string
	PrevURL     string
}

type adminPageData struct {
	Username      string
	Error         string
	GeneratedAt   string
	GroupCount    int
	TotalBuckets  int
	Groups        []adminGroupAccessView
	IgnoredGroups []string
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

type adminSessionStore struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxEntries int
	data       map[string]adminSession
}

func newAdminSessionStore(ttl time.Duration, maxEntries int) *adminSessionStore {
	if ttl <= 0 {
		ttl = defaultAdminSessionTTL
	}
	if maxEntries <= 0 {
		maxEntries = defaultGroupCacheMaxEntries
	}
	return &adminSessionStore{
		ttl:        ttl,
		maxEntries: maxEntries,
		data:       map[string]adminSession{},
	}
}
func (s *adminSessionStore) save(sessionID, username string, groups map[string]struct{}) (string, error) {
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

	for i := 0; i < 5; i++ {
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

func (s *adminSessionStore) get(sessionID string) (adminSession, bool) {
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

func (s *adminSessionStore) delete(sessionID string) {
	if sessionID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, sessionID)
}

func (s *adminSessionStore) evictExpiredLocked(now time.Time) {
	for key, e := range s.data {
		if now.After(e.Expires) {
			delete(s.data, key)
		}
	}
}

func (s *adminSessionStore) evictOneOldestLocked() {
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

func newAdminSessionID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

type adminGorillaStore struct {
	backend *adminSessionStore
	Codecs  []securecookie.Codec
	Options *sessions.Options
}

func newAdminGorillaStore(sigV4Secret string, ttl time.Duration, backend *adminSessionStore) *adminGorillaStore {
	if strings.TrimSpace(sigV4Secret) == "" {
		sigV4Secret = "password"
	}
	if ttl <= 0 {
		ttl = defaultAdminSessionTTL
	}

	hashKey := sha256.Sum256([]byte("s3gateway-admin-hash:" + sigV4Secret))
	blockKey := sha256.Sum256([]byte("s3gateway-admin-block:" + sigV4Secret))
	codecs := securecookie.CodecsFromPairs(hashKey[:], blockKey[:])

	store := &adminGorillaStore{
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

func (s *adminGorillaStore) MaxAge(age int) {
	s.Options.MaxAge = age
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (s *adminGorillaStore) Get(r *http.Request, name string) (*sessions.Session, error) {
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

func parseSessionGroups(v interface{}) map[string]struct{} {
	out := make(map[string]struct{})
	switch raw := v.(type) {
	case []string:
		for _, g := range raw {
			g = strings.TrimSpace(strings.ToLower(g))
			if g != "" {
				out[g] = struct{}{}
			}
		}
	case []interface{}:
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

func adminSessionToValues(s adminSession) map[interface{}]interface{} {
	return map[interface{}]interface{}{
		adminSessionValueUser: s.Username,
		adminSessionValueGrps: sessionGroupsSlice(s.Groups),
	}
}

func adminSessionFromValues(values map[interface{}]interface{}) (string, map[string]struct{}, error) {
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

func (s *adminGorillaStore) New(r *http.Request, name string) (*sessions.Session, error) {
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

func (s *adminGorillaStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
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

func permLetters(perm Perm) string {
	var b strings.Builder
	if perm&PermRead != 0 {
		b.WriteByte('r')
	}
	if perm&PermWrite != 0 {
		b.WriteByte('w')
	}
	if perm&PermCreateBucket != 0 {
		b.WriteByte('c')
	}
	if perm&PermDeleteObject != 0 {
		b.WriteByte('d')
	}
	if perm&PermDeleteBucket != 0 {
		b.WriteByte('b')
	}
	return b.String()
}

func permViews(perm Perm) []adminPermissionView {
	out := make([]adminPermissionView, 0, 5)
	if perm&PermRead != 0 {
		out = append(out, adminPermissionView{Letter: "r", Name: "Read"})
	}
	if perm&PermWrite != 0 {
		out = append(out, adminPermissionView{Letter: "w", Name: "Write"})
	}
	if perm&PermCreateBucket != 0 {
		out = append(out, adminPermissionView{Letter: "c", Name: "Create bucket"})
	}
	if perm&PermDeleteObject != 0 {
		out = append(out, adminPermissionView{Letter: "d", Name: "Delete object"})
	}
	if perm&PermDeleteBucket != 0 {
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
		prefix, perm, ok := parseGroup(group)
		if !ok {
			ignored = append(ignored, group)
			continue
		}

		bucketPrefix := strings.ToLower(prefix) + "-"
		row := adminGroupAccessView{
			GroupName:         group,
			BucketPrefix:      bucketPrefix,
			PermissionLetters: permLetters(perm),
			Permissions:       permViews(perm),
			Buckets:           make([]adminBucketView, 0),
		}
		for _, bucket := range allBuckets {
			if strings.HasPrefix(strings.ToLower(bucket), bucketPrefix) {
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

func (s *server) listAllBuckets(ctx context.Context) ([]string, error) {
	if s == nil {
		return nil, errors.New("server not configured")
	}
	if s.up == nil {
		return nil, errors.New("upstream s3 client is not configured")
	}

	out, err := s.up.ListBuckets(ctx, &s3.ListBucketsInput{})
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

func (s *server) listBucketObjectKeys(ctx context.Context, bucket, continuationToken string, maxKeys int32) ([]string, string, bool, error) {
	if s == nil {
		return nil, "", false, errors.New("server not configured")
	}
	if s.up == nil {
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

	out, err := s.up.ListObjectsV2(ctx, in)
	if err != nil {
		return nil, "", false, err
	}

	keys := make([]string, 0, len(out.Contents))
	for _, obj := range out.Contents {
		if obj.Key == nil {
			continue
		}
		key := strings.TrimSpace(*obj.Key)
		if key == "" {
			continue
		}
		keys = append(keys, key)
	}
	return keys, strings.TrimSpace(aws.ToString(out.NextContinuationToken)), out.IsTruncated != nil && *out.IsTruncated, nil
}

func (s *server) bucketPreviewsForGroups(groups map[string]struct{}, buckets []string) map[string]adminBucketView {
	previews := make(map[string]adminBucketView, len(buckets))
	rules := rulesFromGroups(groups)

	for _, bucket := range buckets {
		bucket = strings.TrimSpace(bucket)
		if bucket == "" {
			continue
		}

		view := adminBucketView{
			Name:    bucket,
			CanRead: canRead(rules, bucket),
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
	q := url.Values{}
	q.Set("name", bucket)
	if strings.TrimSpace(cursor) != "" {
		q.Set("cursor", cursor)
	}
	if encoded := encodeAdminCursorHistory(history); encoded != "" {
		q.Set("history", encoded)
	}
	return "/admin/bucket?" + q.Encode()
}

func (s *server) currentAdminSession(r *http.Request) (adminSession, *sessions.Session, bool) {
	if s == nil || s.adminWebSessions == nil {
		return adminSession{}, nil, false
	}

	webSession, err := s.adminWebSessions.Get(r, adminSessionCookieName)
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
	webSession.Values = map[interface{}]interface{}{}
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

func handleAdminLogin(s *server, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if s != nil {
		if _, _, ok := s.currentAdminSession(r); ok {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
	}

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		writeAdminLoginPage(w, r, http.StatusOK, adminLoginPageData{})
		return
	}

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

	if s == nil || s.adminWebSessions == nil {
		writeAdminLoginPage(w, r, http.StatusInternalServerError, adminLoginPageData{
			Username: upn,
			Error:    "Admin backend is not configured.",
		})
		return
	}

	groups, err := s.groupsForCredentials(upn, pass)
	if err != nil {
		writeAdminLoginPage(w, r, http.StatusUnauthorized, adminLoginPageData{
			Username: upn,
			Error:    "LDAP login failed. Check your username and password.",
		})
		return
	}

	webSession, err := s.adminWebSessions.Get(r, adminSessionCookieName)
	if webSession == nil {
		webSession = sessions.NewSession(s.adminWebSessions, adminSessionCookieName)
		opts := *s.adminWebSessions.Options
		opts.Secure = r.TLS != nil
		webSession.Options = &opts
	}
	if err != nil {
		webSession.Values = map[interface{}]interface{}{}
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

func handleAdminDashboard(s *server, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := s.currentAdminSession(r)
	if !ok {
		if webSession != nil {
			clearAdminSession(w, r, webSession)
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := adminPageData{
		Username:    session.Username,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	buckets, err := s.listAllBuckets(r.Context())
	if err != nil {
		data.Error = "Could not list S3 buckets."
		data.Groups, data.IgnoredGroups = buildAdminGroupAccess(session.Groups, nil, nil)
		data.GroupCount = len(data.Groups)
		writeAdminDashboardPage(w, r, http.StatusBadGateway, data)
		return
	}

	previews := s.bucketPreviewsForGroups(session.Groups, buckets)
	data.Groups, data.IgnoredGroups = buildAdminGroupAccess(session.Groups, buckets, previews)
	data.GroupCount = len(data.Groups)
	data.TotalBuckets = countUniqueBuckets(data.Groups)

	writeAdminDashboardPage(w, r, http.StatusOK, data)
}

func handleAdminBucketPage(s *server, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	session, webSession, ok := s.currentAdminSession(r)
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

	rules := rulesFromGroups(session.Groups)
	if !canRead(rules, bucket) {
		writeAdminBucketPage(w, r, http.StatusForbidden, adminBucketPageData{
			Username:    session.Username,
			BucketName:  bucket,
			Error:       "Read permission is required for this bucket.",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	history, err := decodeAdminCursorHistory(r.URL.Query().Get("history"))
	if err != nil {
		writeAdminBucketPage(w, r, http.StatusBadRequest, adminBucketPageData{
			Username:    session.Username,
			BucketName:  bucket,
			Error:       "Invalid pagination cursor state.",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	keys, nextCursor, truncated, err := s.listBucketObjectKeys(r.Context(), bucket, cursor, adminPreviewMaxKeys)
	if err != nil {
		writeAdminBucketPage(w, r, http.StatusBadGateway, adminBucketPageData{
			Username:    session.Username,
			BucketName:  bucket,
			Error:       "Could not list bucket objects.",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	data := adminBucketPageData{
		Username:    session.Username,
		BucketName:  bucket,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		ObjectKeys:  keys,
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

func handleAdminLogout(s *server, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodPost:
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	if s != nil && s.adminWebSessions != nil {
		webSession, _ := s.adminWebSessions.Get(r, adminSessionCookieName)
		clearAdminSession(w, r, webSession)
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func adminWebpageHandler(s *server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch normalizeAdminRoutePath(r.URL.Path) {
		case "/":
			handleAdminRoot(w, r)
		case "/login":
			handleAdminLogin(s, w, r)
		case "/admin":
			handleAdminDashboard(s, w, r)
		case "/admin/bucket":
			handleAdminBucketPage(s, w, r)
		case "/logout":
			handleAdminLogout(s, w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

var adminLoginTmpl = template.Must(template.New("admin-login-page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>S3 Gateway Login</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --panel: #ffffff;
      --text: #10212f;
      --muted: #5f7283;
      --accent: #0b5cab;
      --border: #d6dce2;
      --error: #b00020;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Avenir Next", "Trebuchet MS", sans-serif;
      background: linear-gradient(160deg, #f4f6f8 0%, #dde8f1 100%);
      color: var(--text);
    }
    main {
      max-width: 980px;
      margin: 2rem auto;
      padding: 0 1rem 2rem;
      display: grid;
      gap: 1rem;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
      box-shadow: 0 2px 8px rgba(16, 33, 47, 0.06);
      animation: panel-in 180ms ease-out;
    }
    h1, h2, h3 { margin-top: 0; }
    p { margin: 0.5rem 0; }
    .muted { color: var(--muted); }
    .error {
      margin-top: 0.75rem;
      color: var(--error);
      font-weight: 600;
    }
    form {
      display: grid;
      gap: 0.75rem;
      margin-top: 0.75rem;
    }
    label {
      display: grid;
      gap: 0.35rem;
      font-weight: 600;
    }
    input {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 0.6rem;
      font-size: 1rem;
    }
    button {
      border: 0;
      border-radius: 6px;
      padding: 0.65rem 1rem;
      font-size: 1rem;
      font-weight: 600;
      color: #fff;
      background: var(--accent);
      cursor: pointer;
      width: fit-content;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.75rem;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 0.65rem;
      vertical-align: top;
      text-align: left;
    }
    th {
      background: #edf3f8;
      font-weight: 700;
    }
    ul {
      margin: 0;
      padding-left: 1rem;
    }
    .badge {
      display: inline-block;
      margin: 0 0.35rem 0.35rem 0;
      padding: 0.25rem 0.45rem;
      border-radius: 999px;
      background: #e6f0f9;
      color: #0a3e73;
      font-size: 0.85rem;
      white-space: nowrap;
    }
    @media (max-width: 700px) {
      table, tbody, tr, td, th { display: block; }
      tr { margin-bottom: 0.75rem; }
      th { border-bottom: 0; }
      td { border-top: 0; }
    }
    @keyframes panel-in {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="panel">
      <h1>S3 Gateway Admin</h1>
      <p class="muted">Sign in with LDAP credentials.</p>
      <form method="post" action="/login">
        <label>
          LDAP Username
          <input type="text" name="username" autocomplete="username" value="{{.Username}}" required>
        </label>
        <label>
          LDAP Password
          <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <button type="submit">Sign in</button>
      </form>
      {{if .Error}}
      <p class="error">{{.Error}}</p>
      {{end}}
    </section>
  </main>
</body>
</html>`))

var adminDashboardTmpl = template.Must(template.New("admin-dashboard-page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>S3 Gateway Admin</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --panel: #ffffff;
      --text: #10212f;
      --muted: #5f7283;
      --accent: #0b5cab;
      --border: #d6dce2;
      --error: #b00020;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Avenir Next", "Trebuchet MS", sans-serif;
      background: linear-gradient(160deg, #f4f6f8 0%, #dde8f1 100%);
      color: var(--text);
    }
    main {
      max-width: 1100px;
      margin: 2rem auto;
      padding: 0 1rem 2rem;
      display: grid;
      gap: 1rem;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
      box-shadow: 0 2px 8px rgba(16, 33, 47, 0.06);
      animation: panel-in 180ms ease-out;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 0.75rem;
      flex-wrap: wrap;
    }
    h1, h2, h3 { margin-top: 0; }
    p { margin: 0.5rem 0; }
    .muted { color: var(--muted); }
    .error {
      margin-top: 0.75rem;
      color: var(--error);
      font-weight: 600;
    }
    .logout-form {
      margin: 0;
    }
    button {
      border: 0;
      border-radius: 6px;
      padding: 0.65rem 1rem;
      font-size: 1rem;
      font-weight: 600;
      color: #fff;
      background: var(--accent);
      cursor: pointer;
      width: fit-content;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 0.75rem;
    }
    th, td {
      border: 1px solid var(--border);
      padding: 0.65rem;
      vertical-align: top;
      text-align: left;
    }
    th {
      background: #edf3f8;
      font-weight: 700;
    }
    ul {
      margin: 0;
      padding-left: 1rem;
    }
    .badge {
      display: inline-block;
      margin: 0 0.35rem 0.35rem 0;
      padding: 0.25rem 0.45rem;
      border-radius: 999px;
      background: #e6f0f9;
      color: #0a3e73;
      font-size: 0.85rem;
      white-space: nowrap;
    }
    @media (max-width: 700px) {
      table, tbody, tr, td, th { display: block; }
      tr { margin-bottom: 0.75rem; }
      th { border-bottom: 0; }
      td { border-top: 0; }
    }
    @keyframes panel-in {
      from {
        opacity: 0;
        transform: translateY(8px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="panel">
      <div class="header">
        <div>
          <h1>S3 Gateway Admin</h1>
          <p>Signed in as <strong>{{.Username}}</strong></p>
          <p class="muted">Generated: {{.GeneratedAt}}</p>
        </div>
        <form class="logout-form" method="post" action="/logout">
          <button type="submit">Log out</button>
        </form>
      </div>
      <p><strong>S3 groups:</strong> {{.GroupCount}} | <strong>Visible buckets:</strong> {{.TotalBuckets}}</p>
      {{if .Error}}
      <p class="error">{{.Error}}</p>
      {{end}}
    </section>

    <section class="panel">
      {{if .Groups}}
      <table>
        <thead>
          <tr>
            <th>LDAP Group</th>
            <th>Bucket Prefix</th>
            <th>Permissions</th>
            <th>Buckets</th>
          </tr>
        </thead>
        <tbody>
          {{range .Groups}}
          <tr>
            <td><code>{{.GroupName}}</code></td>
            <td><code>{{.BucketPrefix}}</code></td>
            <td>
              {{range .Permissions}}
              <span class="badge">{{.Letter}}: {{.Name}}</span>
              {{end}}
            </td>
            <td>
              {{if .Buckets}}
              <ul>
                {{range .Buckets}}
                <li>
                  {{if .CanRead}}
                  <a href="/admin/bucket?name={{.Name | urlquery}}"><code>{{.Name}}</code></a>
                  {{else}}
                  <code>{{.Name}}</code>
                  <div class="muted">Read permission required to list objects.</div>
                  {{end}}
                </li>
                {{end}}
              </ul>
              {{else}}
              <span class="muted">No existing buckets under this prefix.</span>
              {{end}}
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
      {{else}}
      <p>No LDAP groups matched the S3 rule format <code>&lt;prefix&gt;-&lt;permissions&gt;</code>.</p>
      {{end}}

      {{if .IgnoredGroups}}
      <h3>Ignored LDAP Groups</h3>
      <p class="muted">These groups do not match the S3 naming rule:</p>
      <ul>
        {{range .IgnoredGroups}}
        <li><code>{{.}}</code></li>
        {{end}}
      </ul>
      {{end}}
    </section>
  </main>
</body>
</html>`))

var adminBucketTmpl = template.Must(template.New("admin-bucket-page").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>S3 Bucket Viewer</title>
  <style>
    :root {
      --bg: #f4f6f8;
      --panel: #ffffff;
      --text: #10212f;
      --muted: #5f7283;
      --accent: #0b5cab;
      --border: #d6dce2;
      --error: #b00020;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Avenir Next", "Trebuchet MS", sans-serif;
      background: linear-gradient(160deg, #f4f6f8 0%, #dde8f1 100%);
      color: var(--text);
    }
    main {
      max-width: 980px;
      margin: 2rem auto;
      padding: 0 1rem 2rem;
      display: grid;
      gap: 1rem;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
      box-shadow: 0 2px 8px rgba(16, 33, 47, 0.06);
    }
    .muted { color: var(--muted); }
    .error {
      margin-top: 0.75rem;
      color: var(--error);
      font-weight: 600;
    }
    ul {
      margin: 0;
      padding-left: 1rem;
    }
    .actions {
      display: flex;
      gap: 0.75rem;
      margin-top: 1rem;
      flex-wrap: wrap;
    }
    .btn {
      display: inline-block;
      border-radius: 6px;
      padding: 0.55rem 0.85rem;
      font-size: 0.95rem;
      font-weight: 600;
      color: #fff;
      background: var(--accent);
      text-decoration: none;
    }
    .btn.disabled {
      opacity: 0.45;
      pointer-events: none;
    }
  </style>
</head>
<body>
  <main>
    <section class="panel">
      <p><a href="/admin">Back to admin</a></p>
      <h1>Bucket: <code>{{.BucketName}}</code></h1>
      <p>Signed in as <strong>{{.Username}}</strong></p>
      <p class="muted">Generated: {{.GeneratedAt}}</p>
      {{if .Error}}
      <p class="error">{{.Error}}</p>
      {{else if .ObjectKeys}}
      <ul>
        {{range .ObjectKeys}}
        <li><code>{{.}}</code></li>
        {{end}}
      </ul>
      {{else}}
      <p class="muted">No objects found.</p>
      {{end}}

      <div class="actions">
        {{if .HasPrev}}
        <a class="btn" href="{{.PrevURL}}">Prev</a>
        {{else}}
        <span class="btn disabled">Prev</span>
        {{end}}

        {{if .HasNext}}
        <a class="btn" href="{{.NextURL}}">Next</a>
        {{else}}
        <span class="btn disabled">Next</span>
        {{end}}
      </div>
    </section>
  </main>
</body>
</html>`))
