package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/define42/s3gateway/internal/cache"
	"github.com/define42/s3gateway/internal/config"
	ldapinternal "github.com/define42/s3gateway/internal/ldap"
	"github.com/define42/s3gateway/internal/s3credentials"
	"golang.org/x/sync/singleflight"
)

const defaultReadyCheckTimeout = 2 * time.Second

// ==================== Gateway ====================
type ctxKey string

const ctxRulesKey ctxKey = "rules"
const ctxSigV4AuthKey ctxKey = "sigv4-auth"
const ctxSigV4SecretKey ctxKey = "sigv4-secret"
const ctxUploaderKey ctxKey = "uploader-upn"

type server struct {
	cfg              config.Config
	up               *s3.Client
	gcache           *cache.GroupCache
	groupLookupSF    singleflight.Group
	fetchGroups      func(cfg config.Config, upn, pass string) (map[string]struct{}, error)
	adminSessions    *adminSessionStore
	adminWebSessions *adminGorillaStore
}

func newServer(cfg config.Config, up *s3.Client) *server {
	cfg.ApplyDefaults()
	adminSessions := newAdminSessionStore(defaultAdminSessionTTL, cfg.GroupCacheMaxEntries)
	return &server{
		cfg:              cfg,
		up:               up,
		gcache:           cache.NewGroupCacheWithMaxEntries(cfg.GroupTTL, cfg.GroupCacheMaxEntries),
		fetchGroups:      ldapinternal.FetchGroupsUPN,
		adminSessions:    adminSessions,
		adminWebSessions: newAdminGorillaStore(cfg.CookieSecret, defaultAdminSessionTTL, adminSessions),
	}
}

func (s *server) groupsForCredentials(upn, pass string) (map[string]struct{}, error) {
	if upn == "" || pass == "" {
		return nil, errors.New("missing credentials")
	}

	grps, ok := s.gcache.Get(upn, pass)
	if ok {
		return grps, nil
	}

	sfKey := cache.SingleflightCredentialKey(upn, pass)
	fetchGroups := s.fetchGroups
	if fetchGroups == nil {
		fetchGroups = ldapinternal.FetchGroupsUPN
	}
	v, err, _ := s.groupLookupSF.Do(sfKey, func() (any, error) {
		if cached, ok := s.gcache.Get(upn, pass); ok {
			return cached, nil
		}
		fetched, err := fetchGroups(s.cfg, upn, pass)
		if err != nil {
			return nil, err
		}
		s.gcache.Set(upn, pass, fetched)
		return fetched, nil
	})
	if err != nil {
		return nil, err
	}
	shared, ok := v.(map[string]struct{})
	if !ok {
		return nil, errors.New("internal auth error")
	}
	return cache.CloneGroups(shared), nil
}

func (s *server) withAuth(next http.Handler, adminHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		if isBrowser(r) && isAdminRoute(r.URL.Path) {
			adminHandler.ServeHTTP(w, r)
			return
		}

		auth, err := parseSigV4Authorization(r)
		if err != nil || auth.Service != "s3" {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}
		if err := validateSigV4RequestTime(auth, time.Now(), s.cfg.SigV4MaxSkew); err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		upn, pass, secretKey, err := s3credentials.S3credentials(auth.AccessKey, s.cfg.S3GatewayPrivateX25519Key)
		if err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		if err := verifySigV4(r, auth, secretKey); err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		grps, err := s.groupsForCredentials(upn, pass)
		if err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Bad credentials")
			return
		}

		rules := rulesFromGroups(grps)
		ctx := context.WithValue(r.Context(), ctxRulesKey, rules)
		ctx = context.WithValue(ctx, ctxSigV4AuthKey, auth)
		ctx = context.WithValue(ctx, ctxSigV4SecretKey, secretKey)
		ctx = context.WithValue(ctx, ctxUploaderKey, upn)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func rulesFromCtx(r *http.Request) []Rule {
	v := r.Context().Value(ctxRulesKey)
	if v == nil {
		return nil
	}
	rules, _ := v.([]Rule)
	return rules
}

func sigV4AuthFromCtx(r *http.Request) *sigv4Auth {
	v := r.Context().Value(ctxSigV4AuthKey)
	if v == nil {
		return nil
	}
	auth, _ := v.(*sigv4Auth)
	return auth
}

func sigV4SecretFromCtx(r *http.Request) string {
	v := r.Context().Value(ctxSigV4SecretKey)
	if v == nil {
		return ""
	}
	secret, _ := v.(string)
	return secret
}

func uploaderFromCtx(r *http.Request) string {
	v := r.Context().Value(ctxUploaderKey)
	if v == nil {
		return ""
	}
	uploader, _ := v.(string)
	return strings.TrimSpace(uploader)
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path-style only:
	//   /                 => ListBuckets
	//   /bucket           => CreateBucket, ListObjects (v2), ListMultipartUploads, Lifecycle config
	//   /bucket/key       => GetObject, PutObject, DeleteObject, GetObjectAttributes, Multipart ops via query

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
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		s.handleReadyz(w, r)
		return
	}

	if p == "/" && r.Method == http.MethodGet {
		s.handleListBuckets(w, r)
		return
	}

	rest := strings.TrimPrefix(p, "/")
	if rest == "" {
		writeXMLError(w, http.StatusNotFound, "NoSuchKey", "Not Found")
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
				writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
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
				writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
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
				writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
				return
			}
		}
		if _, ok := q["delete"]; ok && r.Method == http.MethodPost {
			s.handleDeleteObjects(w, r, bucket)
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
			if _, ok := q["versions"]; ok {
				s.handleListObjectVersions(w, r, bucket)
				return
			}
			if q.Get("list-type") == "2" {
				s.handleListObjectsV2(w, r, bucket)
				return
			}
			if _, ok := q["uploads"]; ok {
				s.handleListMultipartUploads(w, r, bucket)
				return
			}
		}
		writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}

	// /bucket/key
	key := parts[1]
	q := r.URL.Query()

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
			writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
			return
		}
	}

	// Multipart
	if _, ok := q["uploads"]; ok && r.Method == http.MethodPost {
		s.handleCreateMultipart(w, r, bucket, key)
		return
	}
	if _, ok := q["attributes"]; ok && r.Method == http.MethodGet {
		s.handleGetObjectAttributes(w, r, bucket, key)
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
				writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "partNumber required")
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
			writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
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
		writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}
}

// ---------- handlers ----------

func (s *server) checkLDAPReady(ctx context.Context) error {
	if strings.TrimSpace(s.cfg.LDAPURL) == "" {
		return errors.New("url not configured")
	}
	timeout := defaultReadyCheckTimeout
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

func (s *server) checkS3Ready(ctx context.Context) error {
	if s.up == nil {
		return errors.New("client not configured")
	}
	_, err := s.up.ListBuckets(ctx, &s3.ListBucketsInput{})
	return err
}

func (s *server) checkReady(ctx context.Context) error {
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

func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	ctx, cancel := context.WithTimeout(r.Context(), defaultReadyCheckTimeout)
	defer cancel()
	if err := s.checkReady(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte("not ready: " + err.Error() + "\n")) // #nosec G705 -- plain text response, not HTML
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("ok\n"))
	}
}

