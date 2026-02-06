package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	ldap "github.com/go-ldap/ldap/v3"
)

type Config struct {
	ListenAddr string

	LDAPURL  string
	BaseDN   string
	GroupTTL time.Duration

	UpstreamEndpoint       string
	UpstreamRegion         string
	UpstreamAccessKey      string
	UpstreamSecretKey      string
	UpstreamForcePathStyle bool

	SigV4Secret  string // constant, default "password"
	SigV4Service string // default "s3"
}

func env(key, def string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	return v
}
func envRequired(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing required env var %s", key)
	}
	return v
}

func loadConfig() Config {
	ttl := 2 * time.Minute
	if s := strings.TrimSpace(os.Getenv("LDAP_GROUP_TTL")); s != "" {
		if d, err := time.ParseDuration(s); err == nil {
			ttl = d
		}
	}
	return Config{
		ListenAddr: env("LISTEN_ADDR", ":8080"),

		LDAPURL:  envRequired("LDAP_URL"),
		BaseDN:   envRequired("LDAP_BASE_DN"),
		GroupTTL: ttl,

		UpstreamEndpoint:       envRequired("S3_ENDPOINT"),
		UpstreamRegion:         env("S3_REGION", "us-east-1"),
		UpstreamAccessKey:      envRequired("S3_ACCESS_KEY"),
		UpstreamSecretKey:      envRequired("S3_SECRET_KEY"),
		UpstreamForcePathStyle: strings.EqualFold(env("S3_FORCE_PATH_STYLE", "true"), "true"),

		SigV4Secret:  env("SIGV4_SECRET", "password"),
		SigV4Service: env("SIGV4_SERVICE", "s3"),
	}
}

// ==================== Credential hack ====================
// accessKey = base64("userPrincipalName:password")
// secretKey = constant "password"
func decodeUserPassFromAccessKey(accessKey string) (upn, password string, err error) {
	raw, err := base64.StdEncoding.DecodeString(accessKey)
	if err != nil {
		return "", "", fmt.Errorf("accessKey not base64: %w", err)
	}
	s := string(raw)
	i := strings.IndexByte(s, ':')
	if i <= 0 || i+1 >= len(s) {
		return "", "", fmt.Errorf("accessKey must decode to 'user:pass'")
	}
	return strings.TrimSpace(s[:i]), s[i+1:], nil
}

// ==================== AD group lookup ====================
func ldapDial(ldapURL string) (*ldap.Conn, error) {
	_, err := url.Parse(ldapURL)
	if err != nil {
		return nil, err
	}
	return ldap.DialURL(ldapURL)
}

func fetchGroupsUPN(cfg Config, upn, password string) (map[string]struct{}, error) {
	conn, err := ldapDial(cfg.LDAPURL)
	if err != nil {
		return nil, fmt.Errorf("ldap dial: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(upn, password); err != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", err)
	}

	filter := fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(upn))
	req := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		1, 5, false,
		filter,
		[]string{"memberOf"},
		nil,
	)

	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, fmt.Errorf("expected 1 entry for %q, got %d", upn, len(res.Entries))
	}

	groups := make(map[string]struct{})
	for _, dn := range res.Entries[0].GetAttributeValues("memberOf") {
		if cn := cnFromDN(dn); cn != "" {
			groups[strings.ToLower(cn)] = struct{}{}
		}
	}
	return groups, nil
}

func cnFromDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil || parsed == nil {
		return ""
	}
	for _, rdn := range parsed.RDNs {
		for _, a := range rdn.Attributes {
			if strings.EqualFold(a.Type, "CN") {
				return strings.TrimSpace(a.Value)
			}
		}
	}
	return ""
}

// ==================== Cache ====================
type groupCacheEntry struct {
	groups  map[string]struct{}
	expires time.Time
}
type groupCache struct {
	mu   sync.Mutex
	data map[string]groupCacheEntry
	ttl  time.Duration
}

func newGroupCache(ttl time.Duration) *groupCache {
	return &groupCache{data: map[string]groupCacheEntry{}, ttl: ttl}
}

func (c *groupCache) get(upn string) (map[string]struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.data[upn]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.groups, true
}
func (c *groupCache) set(upn string, groups map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[upn] = groupCacheEntry{groups: groups, expires: time.Now().Add(c.ttl)}
}

// ==================== AuthZ: <prefix>-r / <prefix>-rw => bucket prefix "<prefix>-" ====================
type Perm int

const (
	PermNone Perm = iota
	PermRead
	PermReadWrite
)

type Rule struct {
	BucketPrefix string // e.g. "test-"
	Perm         Perm
}

func rulesFromGroups(groups map[string]struct{}) []Rule {
	byPrefix := map[string]Perm{}
	for g := range groups {
		prefix, perm, ok := parseGroup(g)
		if !ok {
			continue
		}
		bp := strings.ToLower(prefix) + "-"
		if cur, ok := byPrefix[bp]; !ok || perm > cur {
			byPrefix[bp] = perm
		}
	}
	out := make([]Rule, 0, len(byPrefix))
	for p, perm := range byPrefix {
		out = append(out, Rule{BucketPrefix: p, Perm: perm})
	}
	return out
}

func parseGroup(g string) (prefix string, perm Perm, ok bool) {
	g = strings.ToLower(strings.TrimSpace(g))
	switch {
	case strings.HasSuffix(g, "-rw"):
		p := strings.TrimSpace(strings.TrimSuffix(g, "-rw"))
		return p, PermReadWrite, p != ""
	case strings.HasSuffix(g, "-r"):
		p := strings.TrimSpace(strings.TrimSuffix(g, "-r"))
		return p, PermRead, p != ""
	default:
		return "", PermNone, false
	}
}

func bucketPerm(rules []Rule, bucket string) Perm {
	b := strings.ToLower(bucket)
	best := PermNone
	for _, r := range rules {
		if strings.HasPrefix(b, r.BucketPrefix) && r.Perm > best {
			best = r.Perm
		}
	}
	return best
}

func canRead(rules []Rule, bucket string) bool  { return bucketPerm(rules, bucket) >= PermRead }
func canWrite(rules []Rule, bucket string) bool { return bucketPerm(rules, bucket) >= PermReadWrite }

// ==================== Upstream S3 client (service creds) ====================
//
// Key point: for PutObject/UploadPart with unseekable bodies, use
// v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware and provide ContentLength. :contentReference[oaicite:6]{index=6}
func newUpstreamS3(ctx context.Context, cfg Config) (*s3.Client, error) {
	resolver := aws.EndpointResolverWithOptionsFunc(
		func(service, region string, _ ...interface{}) (aws.Endpoint, error) {
			if service == s3.ServiceID {
				return aws.Endpoint{URL: cfg.UpstreamEndpoint, HostnameImmutable: true}, nil
			}
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		},
	)

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.UpstreamRegion),
		config.WithEndpointResolverWithOptions(resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.UpstreamAccessKey, cfg.UpstreamSecretKey, "")),
		// Gateway forwards request bodies as non-seekable streams; avoid optional precomputed request checksums.
		config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
	)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = cfg.UpstreamForcePathStyle
	}), nil
}

// ==================== SigV4 verify (minimal header-based) ====================
//
// We verify signature using constant secret (SIGV4_SECRET).
// Real auth is then done by decoding accessKey -> upn:pass and binding to AD.
type sigv4Auth struct {
	AccessKey     string
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	SignatureHex  string
	AmzDate       string
}

func parseSigV4Authorization(r *http.Request) (*sigv4Auth, error) {
	az := r.Header.Get("Authorization")
	if az == "" {
		return nil, errors.New("missing Authorization")
	}
	if !strings.HasPrefix(az, "AWS4-HMAC-SHA256 ") {
		return nil, errors.New("unsupported auth scheme")
	}

	rest := strings.TrimPrefix(az, "AWS4-HMAC-SHA256 ")
	parts := splitAuthParts(rest)

	cred := parts["Credential"]
	signed := parts["SignedHeaders"]
	sig := parts["Signature"]
	if cred == "" || signed == "" || sig == "" {
		return nil, errors.New("invalid Authorization header")
	}

	// Credential = <accessKey>/<date>/<region>/<service>/aws4_request
	// accessKey might contain '/', so parse from the right (last 4 segments fixed)
	segs := strings.Split(cred, "/")
	if len(segs) < 5 || segs[len(segs)-1] != "aws4_request" {
		return nil, errors.New("invalid Credential scope")
	}
	service := segs[len(segs)-2]
	region := segs[len(segs)-3]
	date := segs[len(segs)-4]
	accessKey := strings.Join(segs[:len(segs)-4], "/")

	amzDate := r.Header.Get("x-amz-date")
	if amzDate == "" {
		return nil, errors.New("missing x-amz-date")
	}

	sh := strings.Split(signed, ";")
	for i := range sh {
		sh[i] = strings.ToLower(strings.TrimSpace(sh[i]))
	}

	return &sigv4Auth{
		AccessKey:     accessKey,
		Date:          date,
		Region:        region,
		Service:       service,
		SignedHeaders: sh,
		SignatureHex:  strings.ToLower(sig),
		AmzDate:       amzDate,
	}, nil
}

func splitAuthParts(s string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		out[k] = v
	}
	return out
}

func verifySigV4(r *http.Request, auth *sigv4Auth, secret string) error {
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		return errors.New("missing x-amz-content-sha256")
	}
	// Reject aws-chunked streaming (needs special decoding/re-signing). :contentReference[oaicite:7]{index=7}
	if strings.HasPrefix(payloadHash, "STREAMING-") {
		return errors.New("aws-chunked streaming not supported")
	}

	canonURI := canonicalURI(r.URL.EscapedPath())
	canonQuery := canonicalQuery(r.URL.Query())
	canonHeaders, signedHeadersStr, err := canonicalHeaders(r, auth.SignedHeaders)
	if err != nil {
		return err
	}

	canonicalRequest := strings.Join([]string{
		r.Method,
		canonURI,
		canonQuery,
		canonHeaders,
		signedHeadersStr,
		payloadHash, // may be UNSIGNED-PAYLOAD :contentReference[oaicite:8]{index=8}
	}, "\n")

	crHash := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		auth.AmzDate,
		fmt.Sprintf("%s/%s/%s/aws4_request", auth.Date, auth.Region, auth.Service),
		hex.EncodeToString(crHash[:]),
	}, "\n")

	signingKey := deriveSigningKey(secret, auth.Date, auth.Region, auth.Service)
	gotSig := hmacSHA256Hex(signingKey, []byte(stringToSign))

	if !constantTimeEq(auth.SignatureHex, gotSig) {
		return errors.New("signature mismatch")
	}
	return nil
}

func canonicalURI(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	if !strings.HasPrefix(escapedPath, "/") {
		return "/" + escapedPath
	}
	return escapedPath
}

func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	type kv struct{ k, v string }
	var items []kv
	for k, vs := range q {
		ek := awsURLEncode(k, true)
		sort.Strings(vs)
		for _, v := range vs {
			items = append(items, kv{ek, awsURLEncode(v, true)})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].k == items[j].k {
			return items[i].v < items[j].v
		}
		return items[i].k < items[j].k
	})
	var b strings.Builder
	for i, it := range items {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(it.k)
		b.WriteByte('=')
		b.WriteString(it.v)
	}
	return b.String()
}

func canonicalHeaders(r *http.Request, signedHeaders []string) (string, string, error) {
	hm := map[string]string{}
	for name, vals := range r.Header {
		ln := strings.ToLower(name)
		v := strings.Join(vals, ",")
		hm[ln] = compressSpaces(strings.TrimSpace(v))
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	hm["host"] = compressSpaces(strings.TrimSpace(host))

	// SigV4 expects signed headers list in lowercase sorted order (most clients do this already).
	sh := make([]string, len(signedHeaders))
	copy(sh, signedHeaders)
	sort.Strings(sh)

	var b strings.Builder
	for _, k := range sh {
		v, ok := hm[k]
		if !ok {
			return "", "", fmt.Errorf("signed header missing: %s", k)
		}
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(v)
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(sh, ";"), nil
}

func compressSpaces(s string) string {
	var out bytes.Buffer
	inSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' {
			if !inSpace {
				out.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		out.WriteRune(r)
	}
	return out.String()
}

func awsURLEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		isSafe := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~'
		if isSafe {
			b.WriteByte(c)
			continue
		}
		if c == '/' && !encodeSlash {
			b.WriteByte('/')
			continue
		}
		b.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return b.String()
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	return kSigning
}
func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
func hmacSHA256Hex(key, data []byte) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}
func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := []byte(a)
	bb := []byte(b)
	var v byte
	for i := range aa {
		v |= aa[i] ^ bb[i]
	}
	return v == 0
}

// ==================== XML helpers ====================
func xmlEscape(s string) string {
	repl := strings.NewReplacer(
		`&`, "&amp;",
		`<`, "&lt;",
		`>`, "&gt;",
		`"`, "&quot;",
		`'`, "&apos;",
	)
	return repl.Replace(s)
}

func writeXMLError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>`))
	_, _ = w.Write([]byte("<Error>"))
	_, _ = w.Write([]byte("<Code>" + xmlEscape(code) + "</Code>"))
	_, _ = w.Write([]byte("<Message>" + xmlEscape(msg) + "</Message>"))
	_, _ = w.Write([]byte("</Error>"))
}

// ==================== Gateway ====================
type ctxKey string

const ctxRulesKey ctxKey = "rules"

type server struct {
	cfg    Config
	up     *s3.Client
	gcache *groupCache
}

func (s *server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := parseSigV4Authorization(r)
		if err != nil || auth.Service != s.cfg.SigV4Service {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}
		if err := verifySigV4(r, auth, s.cfg.SigV4Secret); err != nil {
			if strings.Contains(err.Error(), "aws-chunked") {
				writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "aws-chunked streaming not supported")
				return
			}
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		upn, pass, err := decodeUserPassFromAccessKey(auth.AccessKey)
		if err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		grps, ok := s.gcache.get(upn)
		if !ok {
			grps, err = fetchGroupsUPN(s.cfg, upn, pass)
			if err != nil {
				writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Bad credentials")
				return
			}
			s.gcache.set(upn, grps)
		}

		rules := rulesFromGroups(grps)
		ctx := context.WithValue(r.Context(), ctxRulesKey, rules)
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

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path-style only:
	//   /                 => ListBuckets
	//   /bucket           => CreateBucket, ListObjects (v2)
	//   /bucket/key       => GetObject, PutObject, Multipart ops via query

	p := r.URL.Path
	if p == "" {
		p = "/"
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
	bucket := parts[0]

	// /bucket
	if len(parts) == 1 {
		if r.Method == http.MethodPut {
			s.handleCreateBucket(w, r, bucket)
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
			s.handleListObjectsV2(w, r, bucket)
			return
		}
		writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}

	// /bucket/key
	key := parts[1]
	q := r.URL.Query()

	// Multipart
	if _, ok := q["uploads"]; ok && r.Method == http.MethodPost {
		s.handleCreateMultipart(w, r, bucket, key)
		return
	}
	if uploadID := q.Get("uploadId"); uploadID != "" {
		switch r.Method {
		case http.MethodPut:
			pnStr := q.Get("partNumber")
			pn, err := strconv.Atoi(pnStr)
			if err != nil || pn <= 0 {
				writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "partNumber required")
				return
			}
			s.handleUploadPart(w, r, bucket, key, uploadID, int32(pn))
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
	case http.MethodPut:
		s.handlePutObject(w, r, bucket, key)
		return
	default:
		writeXMLError(w, http.StatusNotImplemented, "NotImplemented", "Operation not implemented")
		return
	}
}

// ---------- handlers ----------

func (s *server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rules := rulesFromCtx(r)

	out, err := s.up.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	b.WriteString(`<Buckets>`)
	for _, bk := range out.Buckets {
		if bk.Name == nil {
			continue
		}
		if bucketPerm(rules, *bk.Name) >= PermRead {
			b.WriteString("<Bucket><Name>")
			b.WriteString(xmlEscape(*bk.Name))
			b.WriteString("</Name></Bucket>")
		}
	}
	b.WriteString(`</Buckets></ListAllMyBucketsResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleCreateBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	_, err := s.up.CreateBucket(r.Context(), &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	prefix := r.URL.Query().Get("prefix")
	in := &s3.ListObjectsV2Input{Bucket: &bucket}
	if prefix != "" {
		in.Prefix = &prefix
	}
	out, err := s.up.ListObjectsV2(r.Context(), in)
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	b.WriteString("<Name>")
	b.WriteString(xmlEscape(bucket))
	b.WriteString("</Name>")
	if prefix != "" {
		b.WriteString("<Prefix>")
		b.WriteString(xmlEscape(prefix))
		b.WriteString("</Prefix>")
	}
	for _, o := range out.Contents {
		if o.Key == nil {
			continue
		}
		b.WriteString("<Contents><Key>")
		b.WriteString(xmlEscape(*o.Key))
		b.WriteString("</Key></Contents>")
	}
	b.WriteString(`</ListBucketResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleGetObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetObjectInput{Bucket: &bucket, Key: &key}
	if rng := r.Header.Get("Range"); rng != "" {
		in.Range = &rng
	}

	out, err := s.up.GetObject(r.Context(), in)
	if err != nil {
		writeXMLError(w, http.StatusNotFound, "NoSuchKey", "Not Found")
		return
	}
	defer out.Body.Close()

	// Propagate a few headers
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, out.Body)
}

func (s *server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	// Need Content-Length for unseekable streaming. :contentReference[oaicite:9]{index=9}
	if r.ContentLength < 0 {
		writeXMLError(w, http.StatusLengthRequired, "MissingContentLength", "Content-Length required")
		return
	}
	cl := r.ContentLength

	ct := r.Header.Get("Content-Type")
	meta := extractAmzMeta(r.Header)

	in := &s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          r.Body,
		ContentLength: aws.Int64(cl),
		Metadata:      meta,
	}
	if ct != "" {
		in.ContentType = &ct
	}

	out, err := s.up.PutObject(r.Context(), in,
		// Allow streaming io.Reader without Seek by using Unsigned Payload middleware. :contentReference[oaicite:10]{index=10}
		s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware),
	)
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	w.WriteHeader(http.StatusOK)
}

func extractAmzMeta(h http.Header) map[string]string {
	meta := map[string]string{}
	for k, vs := range h {
		kl := strings.ToLower(k)
		if strings.HasPrefix(kl, "x-amz-meta-") && len(vs) > 0 {
			meta[strings.TrimPrefix(kl, "x-amz-meta-")] = vs[0]
		}
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}

// ---------- Multipart ----------

type completeMultipartUpload struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		PartNumber int32  `xml:"PartNumber"`
		ETag       string `xml:"ETag"`
	} `xml:"Part"`
}

func (s *server) handleCreateMultipart(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	ct := r.Header.Get("Content-Type")
	meta := extractAmzMeta(r.Header)

	in := &s3.CreateMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		Metadata: meta,
	}
	if ct != "" {
		in.ContentType = &ct
	}

	out, err := s.up.CreateMultipartUpload(r.Context(), in)
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	b.WriteString("<Bucket>" + xmlEscape(bucket) + "</Bucket>")
	b.WriteString("<Key>" + xmlEscape(key) + "</Key>")
	b.WriteString("<UploadId>" + xmlEscape(aws.ToString(out.UploadId)) + "</UploadId>")
	b.WriteString(`</InitiateMultipartUploadResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleUploadPart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int32) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	if r.ContentLength < 0 {
		writeXMLError(w, http.StatusLengthRequired, "MissingContentLength", "Content-Length required")
		return
	}
	cl := r.ContentLength

	in := &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &uploadID,
		PartNumber:    aws.Int32(partNumber),
		Body:          r.Body,
		ContentLength: aws.Int64(cl),
	}

	out, err := s.up.UploadPart(r.Context(), in,
		// Allow streaming io.Reader without Seek. :contentReference[oaicite:11]{index=11}
		s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware),
	)
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}

	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	w.WriteHeader(http.StatusOK)
}

// CompleteMultipartUpload requires PartNumber + ETag for each part. :contentReference[oaicite:12]{index=12}
func (s *server) handleCompleteMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	var cmu completeMultipartUpload
	if err := xml.NewDecoder(r.Body).Decode(&cmu); err != nil {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid XML")
		return
	}

	parts := make([]types.CompletedPart, 0, len(cmu.Parts))
	for _, p := range cmu.Parts {
		etag := strings.Trim(strings.TrimSpace(p.ETag), `"`)
		if p.PartNumber <= 0 || etag == "" {
			continue
		}
		pn := p.PartNumber
		parts = append(parts, types.CompletedPart{
			ETag:       &etag,
			PartNumber: aws.Int32(pn),
		})
	}
	if len(parts) == 0 {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "No parts provided")
		return
	}
	sort.Slice(parts, func(i, j int) bool {
		return aws.ToInt32(parts[i].PartNumber) < aws.ToInt32(parts[j].PartNumber)
	})

	in := &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: parts,
		},
	}

	out, err := s.up.CompleteMultipartUpload(r.Context(), in)
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	b.WriteString("<Bucket>" + xmlEscape(bucket) + "</Bucket>")
	b.WriteString("<Key>" + xmlEscape(key) + "</Key>")
	if out.ETag != nil {
		b.WriteString("<ETag>\"" + xmlEscape(strings.Trim(*out.ETag, `"`)) + "\"</ETag>")
	}
	b.WriteString(`</CompleteMultipartUploadResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleAbortMultipart(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}
	_, err := s.up.AbortMultipartUpload(r.Context(), &s3.AbortMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	})
	if err != nil {
		writeXMLError(w, http.StatusBadGateway, "BadGateway", "Upstream error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	cfg := loadConfig()

	up, err := newUpstreamS3(context.Background(), cfg)
	if err != nil {
		log.Fatalf("init upstream s3: %v", err)
	}

	s := &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCache(cfg.GroupTTL),
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           s.withAuth(s),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("listening on %s", cfg.ListenAddr)
	log.Fatal(httpSrv.ListenAndServe())
}
