package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	ldap "github.com/go-ldap/ldap/v3"
)

const maxSinglePutObjectSize = int64(5 * 1024 * 1024 * 1024) // 5 GiB

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
	groups         map[string]struct{}
	credentialHash [32]byte
	expires        time.Time
	lastSeen       time.Time
}
type groupCache struct {
	mu         sync.Mutex
	data       map[string]groupCacheEntry
	ttl        time.Duration
	maxEntries int
}

func newGroupCache(ttl time.Duration) *groupCache {
	return newGroupCacheWithMaxEntries(ttl, defaultGroupCacheMaxEntries)
}

func newGroupCacheWithMaxEntries(ttl time.Duration, maxEntries int) *groupCache {
	if maxEntries <= 0 {
		maxEntries = defaultGroupCacheMaxEntries
	}
	return &groupCache{
		data:       map[string]groupCacheEntry{},
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func cacheCredentialHash(upn, password string) [32]byte {
	return sha256.Sum256([]byte(upn + "\x00" + password))
}

func cloneGroups(groups map[string]struct{}) map[string]struct{} {
	if len(groups) == 0 {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(groups))
	for g := range groups {
		out[g] = struct{}{}
	}
	return out
}

func (c *groupCache) get(upn, password string) (map[string]struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	e, ok := c.data[upn]
	if !ok {
		return nil, false
	}
	if now.After(e.expires) {
		delete(c.data, upn)
		return nil, false
	}
	wantHash := cacheCredentialHash(upn, password)
	if subtle.ConstantTimeCompare(e.credentialHash[:], wantHash[:]) != 1 {
		return nil, false
	}
	e.lastSeen = now
	c.data[upn] = e
	return cloneGroups(e.groups), true
}

func (c *groupCache) evictExpiredLocked(now time.Time) {
	for upn, e := range c.data {
		if now.After(e.expires) {
			delete(c.data, upn)
		}
	}
}

func (c *groupCache) evictOneOldestLocked() {
	var victim string
	var victimEntry groupCacheEntry
	found := false

	for upn, e := range c.data {
		if !found {
			victim, victimEntry, found = upn, e, true
			continue
		}
		if e.expires.Before(victimEntry.expires) {
			victim, victimEntry = upn, e
			continue
		}
		if e.expires.Equal(victimEntry.expires) && e.lastSeen.Before(victimEntry.lastSeen) {
			victim, victimEntry = upn, e
		}
	}
	if found {
		delete(c.data, victim)
	}
}

func (c *groupCache) set(upn, password string, groups map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	c.evictExpiredLocked(now)

	if _, exists := c.data[upn]; !exists {
		for len(c.data) >= c.maxEntries {
			c.evictOneOldestLocked()
		}
	}

	c.data[upn] = groupCacheEntry{
		groups:         cloneGroups(groups),
		credentialHash: cacheCredentialHash(upn, password),
		expires:        now.Add(c.ttl),
		lastSeen:       now,
	}
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyFromEnvironment
	transport.DialContext = (&net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext
	transport.ForceAttemptHTTP2 = true
	transport.MaxIdleConns = 2048
	transport.MaxIdleConnsPerHost = 512
	transport.MaxConnsPerHost = 0
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ExpectContinueTimeout = 1 * time.Second

	upHTTP := &http.Client{Transport: transport}

	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.UpstreamRegion),
		config.WithBaseEndpoint(cfg.UpstreamEndpoint),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.UpstreamAccessKey, cfg.UpstreamSecretKey, "")),
		config.WithHTTPClient(upHTTP),
		// Gateway forwards request bodies as non-seekable streams; avoid optional precomputed request checksums.
		config.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		// Upstream responses may not include optional checksum headers.
		config.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
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

var (
	errInvalidAmzDate             = errors.New("invalid x-amz-date")
	errSigV4DateScopeMismatch     = errors.New("credential scope date mismatch")
	errSigV4RequestOutsideMaxSkew = errors.New("request outside allowed time skew")
)

func validateSigV4RequestTime(auth *sigv4Auth, now time.Time, maxSkew time.Duration) error {
	amzTime, err := time.Parse("20060102T150405Z", strings.TrimSpace(auth.AmzDate))
	if err != nil {
		return errInvalidAmzDate
	}
	if auth.Date != amzTime.UTC().Format("20060102") {
		return errSigV4DateScopeMismatch
	}
	if maxSkew <= 0 {
		return nil
	}

	delta := now.UTC().Sub(amzTime.UTC())
	if delta > maxSkew || delta < -maxSkew {
		return errSigV4RequestOutsideMaxSkew
	}
	return nil
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

func formatS3Time(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
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

type upstreamErrorInfo struct {
	status  int
	code    string
	message string
	headers http.Header
}

func extractUpstreamErrorInfo(err error) upstreamErrorInfo {
	info := upstreamErrorInfo{
		status:  http.StatusBadGateway,
		code:    "BadGateway",
		message: "Upstream error",
		headers: make(http.Header),
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		if c := strings.TrimSpace(apiErr.ErrorCode()); c != "" {
			info.code = c
		}
		if m := strings.TrimSpace(apiErr.ErrorMessage()); m != "" {
			info.message = m
		}
		if info.status == http.StatusBadGateway && apiErr.ErrorFault() == smithy.FaultClient {
			info.status = http.StatusBadRequest
		}
	}

	var respErr *smithyhttp.ResponseError
	if errors.As(err, &respErr) {
		if sc := respErr.HTTPStatusCode(); sc >= 400 {
			info.status = sc
		}
		if hr := respErr.HTTPResponse(); hr != nil {
			for k, vals := range hr.Header {
				kl := strings.ToLower(k)
				if strings.HasPrefix(kl, "x-amz-") || kl == "retry-after" {
					for _, v := range vals {
						info.headers.Add(k, v)
					}
				}
			}
		}
	}
	return info
}

func writeUpstreamError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	writeXMLError(w, info.status, info.code, info.message)
}

func writeUpstreamHeadError(w http.ResponseWriter, err error) {
	info := extractUpstreamErrorInfo(err)
	for k, vals := range info.headers {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(info.status)
}

func parseEncodingType(v string) (types.EncodingType, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	if strings.EqualFold(raw, string(types.EncodingTypeUrl)) {
		return types.EncodingTypeUrl, nil
	}
	return "", fmt.Errorf("unsupported encoding-type %q", raw)
}

func parseRequestPayerHeader(h http.Header) (types.RequestPayer, error) {
	raw := strings.TrimSpace(h.Get("x-amz-request-payer"))
	if raw == "" {
		return "", nil
	}
	if strings.EqualFold(raw, string(types.RequestPayerRequester)) {
		return types.RequestPayerRequester, nil
	}
	return "", fmt.Errorf("unsupported request payer %q", raw)
}

func parseOptionalObjectAttributes(v string) ([]types.OptionalObjectAttributes, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return nil, nil
	}
	seen := map[types.OptionalObjectAttributes]struct{}{}
	out := make([]types.OptionalObjectAttributes, 0, 2)
	for _, token := range strings.Split(raw, ",") {
		t := strings.TrimSpace(token)
		if t == "" {
			continue
		}
		var attr types.OptionalObjectAttributes
		switch strings.ToLower(t) {
		case strings.ToLower(string(types.OptionalObjectAttributesRestoreStatus)):
			attr = types.OptionalObjectAttributesRestoreStatus
		default:
			return nil, fmt.Errorf("unsupported optional object attribute %q", t)
		}
		if _, ok := seen[attr]; ok {
			continue
		}
		seen[attr] = struct{}{}
		out = append(out, attr)
	}
	if len(out) == 0 {
		return nil, errors.New("no optional object attributes requested")
	}
	return out, nil
}

func parseMetadataDirective(v string) (types.MetadataDirective, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.MetadataDirective("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported metadata directive %q", raw)
}

func parseTaggingDirective(v string) (types.TaggingDirective, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.TaggingDirective("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported tagging directive %q", raw)
}

func parseStorageClass(v string) (types.StorageClass, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.StorageClass("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported storage class %q", raw)
}

func parseObjectCannedACL(v string) (types.ObjectCannedACL, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	for _, allowed := range types.ObjectCannedACL("").Values() {
		if strings.EqualFold(raw, string(allowed)) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported x-amz-acl %q", raw)
}

func parseOptionalHTTPTime(v string) (*time.Time, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return nil, nil
	}
	t, err := http.ParseTime(raw)
	if err != nil {
		return nil, err
	}
	utc := t.UTC()
	return &utc, nil
}

func parseOptionalBool(v string) (bool, bool, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return false, false, nil
	}
	switch strings.ToLower(raw) {
	case "true":
		return true, true, nil
	case "false":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("invalid boolean %q", raw)
	}
}

func parseSSECustomerHeaders(h http.Header) (algo, key, keyMD5 *string, present bool, err error) {
	a := strings.TrimSpace(h.Get("x-amz-server-side-encryption-customer-algorithm"))
	k := strings.TrimSpace(h.Get("x-amz-server-side-encryption-customer-key"))
	m := strings.TrimSpace(h.Get("x-amz-server-side-encryption-customer-key-md5"))
	present = a != "" || k != "" || m != ""
	if !present {
		return nil, nil, nil, false, nil
	}
	if a == "" || k == "" || m == "" {
		return nil, nil, nil, true, errors.New("incomplete SSE-C headers")
	}
	return aws.String(a), aws.String(k), aws.String(m), true, nil
}

func parseCopySourceSSECustomerHeaders(h http.Header) (algo, key, keyMD5 *string, present bool, err error) {
	a := strings.TrimSpace(h.Get("x-amz-copy-source-server-side-encryption-customer-algorithm"))
	k := strings.TrimSpace(h.Get("x-amz-copy-source-server-side-encryption-customer-key"))
	m := strings.TrimSpace(h.Get("x-amz-copy-source-server-side-encryption-customer-key-md5"))
	present = a != "" || k != "" || m != ""
	if !present {
		return nil, nil, nil, false, nil
	}
	if a == "" || k == "" || m == "" {
		return nil, nil, nil, true, errors.New("incomplete copy-source SSE-C headers")
	}
	return aws.String(a), aws.String(k), aws.String(m), true, nil
}

func parseCopySourceConditionalHeaders(h http.Header) (ifMatch, ifNoneMatch *string, ifModifiedSince, ifUnmodifiedSince *time.Time, err error) {
	if raw := strings.TrimSpace(h.Get("x-amz-copy-source-if-match")); raw != "" {
		ifMatch = aws.String(raw)
	}
	if raw := strings.TrimSpace(h.Get("x-amz-copy-source-if-none-match")); raw != "" {
		ifNoneMatch = aws.String(raw)
	}
	if ifModifiedSince, err = parseOptionalHTTPTime(h.Get("x-amz-copy-source-if-modified-since")); err != nil {
		return nil, nil, nil, nil, err
	}
	if ifUnmodifiedSince, err = parseOptionalHTTPTime(h.Get("x-amz-copy-source-if-unmodified-since")); err != nil {
		return nil, nil, nil, nil, err
	}
	return ifMatch, ifNoneMatch, ifModifiedSince, ifUnmodifiedSince, nil
}

func sourceBucketFromCopySource(copySource string) (string, error) {
	raw := strings.TrimSpace(copySource)
	if raw == "" {
		return "", errors.New("empty copy source")
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimPrefix(raw, "/")
	if raw == "" {
		return "", errors.New("invalid copy source")
	}
	parts := strings.SplitN(raw, "/", 2)
	bucketEnc := strings.TrimSpace(parts[0])
	if bucketEnc == "" {
		return "", errors.New("invalid copy source bucket")
	}
	bucket, err := url.PathUnescape(bucketEnc)
	if err != nil {
		return "", err
	}
	bucket = strings.TrimSpace(bucket)
	if bucket == "" {
		return "", errors.New("invalid copy source bucket")
	}
	return bucket, nil
}

type sseWriteHeaders struct {
	ServerSideEncryption    types.ServerSideEncryption
	SSEKMSKeyID             *string
	SSEKMSEncryptionContext *string
	SSECustomerAlgorithm    *string
	SSECustomerKey          *string
	SSECustomerKeyMD5       *string
}

func parseSSEWriteHeaders(h http.Header) (sseWriteHeaders, error) {
	out := sseWriteHeaders{}
	sse := strings.TrimSpace(h.Get("x-amz-server-side-encryption"))
	if sse != "" {
		switch strings.ToLower(sse) {
		case "aes256":
			out.ServerSideEncryption = types.ServerSideEncryptionAes256
		case "aws:kms":
			out.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		case "aws:kms:dsse":
			out.ServerSideEncryption = types.ServerSideEncryptionAwsKmsDsse
		default:
			return out, fmt.Errorf("unsupported server-side encryption %q", sse)
		}
	}

	kmsKeyID := strings.TrimSpace(h.Get("x-amz-server-side-encryption-aws-kms-key-id"))
	if kmsKeyID != "" {
		if out.ServerSideEncryption != types.ServerSideEncryptionAwsKms &&
			out.ServerSideEncryption != types.ServerSideEncryptionAwsKmsDsse {
			return out, errors.New("kms key id requires aws:kms or aws:kms:dsse")
		}
		out.SSEKMSKeyID = aws.String(kmsKeyID)
	}

	kmsCtx := strings.TrimSpace(h.Get("x-amz-server-side-encryption-context"))
	if kmsCtx != "" {
		if out.ServerSideEncryption != types.ServerSideEncryptionAwsKms &&
			out.ServerSideEncryption != types.ServerSideEncryptionAwsKmsDsse {
			return out, errors.New("kms context requires aws:kms or aws:kms:dsse")
		}
		out.SSEKMSEncryptionContext = aws.String(kmsCtx)
	}

	ssecAlgo, ssecKey, ssecMD5, presentSSEC, err := parseSSECustomerHeaders(h)
	if err != nil {
		return out, err
	}
	if presentSSEC {
		if out.ServerSideEncryption != "" {
			return out, errors.New("SSE-C cannot be combined with x-amz-server-side-encryption")
		}
		out.SSECustomerAlgorithm = ssecAlgo
		out.SSECustomerKey = ssecKey
		out.SSECustomerKeyMD5 = ssecMD5
	}

	return out, nil
}

type checksumWriteHeaders struct {
	ChecksumAlgorithm types.ChecksumAlgorithm
	ChecksumCRC32     *string
	ChecksumCRC32C    *string
	ChecksumCRC64NVME *string
	ChecksumSHA1      *string
	ChecksumSHA256    *string
}

func parseChecksumAlgorithmHeader(v string) (types.ChecksumAlgorithm, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	switch strings.ToUpper(raw) {
	case "CRC32":
		return types.ChecksumAlgorithmCrc32, nil
	case "CRC32C":
		return types.ChecksumAlgorithmCrc32c, nil
	case "CRC64NVME":
		return types.ChecksumAlgorithmCrc64nvme, nil
	case "SHA1":
		return types.ChecksumAlgorithmSha1, nil
	case "SHA256":
		return types.ChecksumAlgorithmSha256, nil
	default:
		return "", fmt.Errorf("unsupported checksum algorithm %q", raw)
	}
}

func parseChecksumWriteHeaders(h http.Header) (checksumWriteHeaders, error) {
	out := checksumWriteHeaders{}
	var err error
	out.ChecksumAlgorithm, err = parseChecksumAlgorithmHeader(h.Get("x-amz-checksum-algorithm"))
	if err != nil {
		return out, err
	}

	var setCount int
	setField := func(v string) *string {
		s := strings.TrimSpace(v)
		if s == "" {
			return nil
		}
		setCount++
		return aws.String(s)
	}
	out.ChecksumCRC32 = setField(h.Get("x-amz-checksum-crc32"))
	out.ChecksumCRC32C = setField(h.Get("x-amz-checksum-crc32c"))
	out.ChecksumCRC64NVME = setField(h.Get("x-amz-checksum-crc64nvme"))
	out.ChecksumSHA1 = setField(h.Get("x-amz-checksum-sha1"))
	out.ChecksumSHA256 = setField(h.Get("x-amz-checksum-sha256"))

	if setCount > 1 {
		return out, errors.New("multiple checksum value headers are not allowed")
	}
	return out, nil
}

func parseChecksumMode(v string) (types.ChecksumMode, error) {
	raw := strings.TrimSpace(v)
	if raw == "" {
		return "", nil
	}
	switch strings.ToUpper(raw) {
	case "ENABLED":
		return types.ChecksumModeEnabled, nil
	default:
		return "", fmt.Errorf("unsupported checksum mode %q", raw)
	}
}

var (
	errMissingDecodedContentLength = errors.New("missing x-amz-decoded-content-length")
	errInvalidDecodedContentLength = errors.New("invalid x-amz-decoded-content-length")
	errContentLengthRequired       = errors.New("content length required")
	errUnsupportedStreamingMode    = errors.New("unsupported streaming payload mode")
	errMissingSigV4AuthContext     = errors.New("missing sigv4 auth context")
	errMissingChunkSignature       = errors.New("missing aws-chunked chunk signature")
	errInvalidChunkSignature       = errors.New("invalid aws-chunked chunk signature")
	errInvalidChunkHeader          = errors.New("invalid aws-chunked chunk header")
)

func isAWSChunkedPayload(h http.Header) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(h.Get("x-amz-content-sha256"))), "STREAMING-")
}

func streamingPayloadMode(h http.Header) string {
	return strings.ToUpper(strings.TrimSpace(h.Get("x-amz-content-sha256")))
}

func parseDecodedContentLength(h http.Header) (int64, error) {
	raw := strings.TrimSpace(h.Get("x-amz-decoded-content-length"))
	if raw == "" {
		return 0, errMissingDecodedContentLength
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, errInvalidDecodedContentLength
	}
	return n, nil
}

type awsChunkSignatureVerifier struct {
	signingKey []byte
	amzDate    string
	scope      string
	prevSig    string
}

func newAWSChunkSignatureVerifier(auth *sigv4Auth, secret string) *awsChunkSignatureVerifier {
	return &awsChunkSignatureVerifier{
		signingKey: deriveSigningKey(secret, auth.Date, auth.Region, auth.Service),
		amzDate:    auth.AmzDate,
		scope:      fmt.Sprintf("%s/%s/%s/aws4_request", auth.Date, auth.Region, auth.Service),
		prevSig:    strings.ToLower(auth.SignatureHex),
	}
}

func (v *awsChunkSignatureVerifier) verifyChunk(signatureHex string, chunk []byte) error {
	sig := strings.ToLower(strings.TrimSpace(signatureHex))
	if len(sig) != 64 {
		return fmt.Errorf("%w: invalid signature length", errInvalidChunkSignature)
	}
	if _, err := hex.DecodeString(sig); err != nil {
		return fmt.Errorf("%w: invalid signature encoding", errInvalidChunkSignature)
	}

	emptyHash := sha256.Sum256(nil)
	chunkHash := sha256.Sum256(chunk)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		v.amzDate,
		v.scope,
		v.prevSig,
		hex.EncodeToString(emptyHash[:]),
		hex.EncodeToString(chunkHash[:]),
	}, "\n")

	expected := hmacSHA256Hex(v.signingKey, []byte(stringToSign))
	if !constantTimeEq(sig, expected) {
		return fmt.Errorf("%w: signature mismatch", errInvalidChunkSignature)
	}
	v.prevSig = sig
	return nil
}

func chunkSignatureVerifierFromRequest(r *http.Request, secret string) (*awsChunkSignatureVerifier, error) {
	if !isAWSChunkedPayload(r.Header) {
		return nil, nil
	}

	mode := streamingPayloadMode(r.Header)
	if mode != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		return nil, fmt.Errorf("%w: %s", errUnsupportedStreamingMode, mode)
	}

	auth := sigV4AuthFromCtx(r)
	if auth == nil {
		return nil, errMissingSigV4AuthContext
	}
	return newAWSChunkSignatureVerifier(auth, secret), nil
}

func isChunkSignatureValidationError(err error) bool {
	return errors.Is(err, errInvalidChunkSignature) ||
		errors.Is(err, errMissingChunkSignature) ||
		errors.Is(err, errInvalidChunkHeader)
}

type awsChunkedReadCloser struct {
	io.Reader
	c io.Closer
}

func (r *awsChunkedReadCloser) Close() error { return r.c.Close() }

type awsChunkedReader struct {
	br       *bufio.Reader
	verifier *awsChunkSignatureVerifier
	buf      []byte
	offset   int
	done     bool
}

func newAWSChunkedReader(r io.Reader, verifier *awsChunkSignatureVerifier) *awsChunkedReader {
	return &awsChunkedReader{br: bufio.NewReader(r), verifier: verifier}
}

func (r *awsChunkedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		if r.offset < len(r.buf) {
			n := copy(p, r.buf[r.offset:])
			r.offset += n
			if r.offset == len(r.buf) {
				r.buf = nil
				r.offset = 0
			}
			return n, nil
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.beginChunk(); err != nil {
			return 0, err
		}
	}
}

func (r *awsChunkedReader) beginChunk() error {
	line, err := r.br.ReadString('\n')
	if err != nil {
		return err
	}
	n, sig, err := parseAWSChunkHeader(line)
	if err != nil {
		return err
	}
	if n == 0 {
		if r.verifier != nil {
			if sig == "" {
				return errMissingChunkSignature
			}
			if err := r.verifier.verifyChunk(sig, nil); err != nil {
				return err
			}
		}
		if err := r.consumeTrailers(); err != nil {
			return err
		}
		r.done = true
		return nil
	}

	if n > int64(^uint(0)>>1) {
		return fmt.Errorf("%w: chunk too large", errInvalidChunkHeader)
	}
	chunk := make([]byte, int(n))
	if _, err := io.ReadFull(r.br, chunk); err != nil {
		return err
	}
	if err := r.consumeCRLF(); err != nil {
		return err
	}

	if r.verifier != nil {
		if sig == "" {
			return errMissingChunkSignature
		}
		if err := r.verifier.verifyChunk(sig, chunk); err != nil {
			return err
		}
	}

	r.buf = chunk
	r.offset = 0
	return nil
}

func parseAWSChunkHeader(line string) (int64, string, error) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return 0, "", fmt.Errorf("%w: empty chunk header", errInvalidChunkHeader)
	}
	parts := strings.Split(line, ";")
	chunkSizeHex := strings.TrimSpace(parts[0])
	if chunkSizeHex == "" {
		return 0, "", fmt.Errorf("%w: missing chunk size", errInvalidChunkHeader)
	}
	n, err := strconv.ParseInt(chunkSizeHex, 16, 64)
	if err != nil || n < 0 {
		return 0, "", fmt.Errorf("%w: invalid chunk size", errInvalidChunkHeader)
	}

	var sig string
	for _, ext := range parts[1:] {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		kv := strings.SplitN(ext, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(kv[0]), "chunk-signature") {
			sig = strings.Trim(strings.TrimSpace(kv[1]), `"`)
			break
		}
	}
	return n, sig, nil
}

func (r *awsChunkedReader) consumeCRLF() error {
	b1, err := r.br.ReadByte()
	if err != nil {
		return err
	}
	b2, err := r.br.ReadByte()
	if err != nil {
		return err
	}
	if b1 != '\r' || b2 != '\n' {
		return errors.New("invalid aws-chunked payload: missing chunk CRLF")
	}
	return nil
}

func (r *awsChunkedReader) consumeTrailers() error {
	for {
		line, err := r.br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			return nil
		}
	}
}

func decodeBodyForS3Write(r *http.Request, verifier *awsChunkSignatureVerifier) (io.ReadCloser, int64, error) {
	if isAWSChunkedPayload(r.Header) {
		mode := streamingPayloadMode(r.Header)
		if mode != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
			return nil, 0, fmt.Errorf("%w: %s", errUnsupportedStreamingMode, mode)
		}
		if verifier == nil {
			return nil, 0, errMissingSigV4AuthContext
		}
		decodedLen, err := parseDecodedContentLength(r.Header)
		if err != nil {
			return nil, 0, err
		}
		return &awsChunkedReadCloser{
			Reader: newAWSChunkedReader(r.Body, verifier),
			c:      r.Body,
		}, decodedLen, nil
	}
	if r.ContentLength < 0 {
		return nil, 0, errContentLengthRequired
	}
	return r.Body, r.ContentLength, nil
}

// ==================== Gateway ====================
type ctxKey string

const ctxRulesKey ctxKey = "rules"
const ctxSigV4AuthKey ctxKey = "sigv4-auth"

type server struct {
	cfg    Config
	up     *s3.Client
	gcache *groupCache
}

func newServer(cfg Config, up *s3.Client) *server {
	cfg.ApplyDefaults()
	return &server{
		cfg:    cfg,
		up:     up,
		gcache: newGroupCacheWithMaxEntries(cfg.GroupTTL, cfg.GroupCacheMaxEntries),
	}
}

func (s *server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, err := parseSigV4Authorization(r)
		if err != nil || auth.Service != s.cfg.SigV4Service {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}
		if err := validateSigV4RequestTime(auth, time.Now(), s.cfg.SigV4MaxSkew); err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}
		if err := verifySigV4(r, auth, s.cfg.SigV4Secret); err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		upn, pass, err := decodeUserPassFromAccessKey(auth.AccessKey)
		if err != nil {
			writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Unauthorized")
			return
		}

		grps, ok := s.gcache.get(upn, pass)
		if !ok {
			grps, err = fetchGroupsUPN(s.cfg, upn, pass)
			if err != nil {
				writeXMLError(w, http.StatusUnauthorized, "AccessDenied", "Bad credentials")
				return
			}
			s.gcache.set(upn, pass, grps)
		}

		rules := rulesFromGroups(grps)
		ctx := context.WithValue(r.Context(), ctxRulesKey, rules)
		ctx = context.WithValue(ctx, ctxSigV4AuthKey, auth)
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

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path-style only:
	//   /                 => ListBuckets
	//   /bucket           => CreateBucket, ListObjects (v2), ListMultipartUploads, Lifecycle config
	//   /bucket/key       => GetObject, PutObject, DeleteObject, GetObjectAttributes, Multipart ops via query

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

func (s *server) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	rules := rulesFromCtx(r)

	out, err := s.up.ListBuckets(r.Context(), &s3.ListBucketsInput{})
	if err != nil {
		writeUpstreamError(w, err)
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
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type versioningConfigXML struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	XMLNS     string   `xml:"xmlns,attr,omitempty"`
	Status    *string  `xml:"Status,omitempty"`
	MFADelete *string  `xml:"MfaDelete,omitempty"`
}

func decodeVersioningConfigXML(r io.Reader) (*types.VersioningConfiguration, error) {
	var in versioningConfigXML
	if err := xml.NewDecoder(r).Decode(&in); err != nil {
		return nil, err
	}

	var out types.VersioningConfiguration
	if in.Status != nil {
		rawStatus := strings.TrimSpace(*in.Status)
		if rawStatus != "" {
			matched := false
			for _, allowed := range types.BucketVersioningStatus("").Values() {
				if strings.EqualFold(rawStatus, string(allowed)) {
					out.Status = allowed
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("invalid versioning status %q", rawStatus)
			}
		}
	}
	if in.MFADelete != nil {
		rawMFA := strings.TrimSpace(*in.MFADelete)
		if rawMFA != "" {
			matched := false
			for _, allowed := range types.MFADelete("").Values() {
				if strings.EqualFold(rawMFA, string(allowed)) {
					out.MFADelete = allowed
					matched = true
					break
				}
			}
			if !matched {
				return nil, fmt.Errorf("invalid mfa delete status %q", rawMFA)
			}
		}
	}
	return &out, nil
}

func encodeVersioningConfigXML(status types.BucketVersioningStatus, mfaDelete types.MFADeleteStatus) ([]byte, error) {
	out := versioningConfigXML{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
	}
	if status != "" {
		s := string(status)
		out.Status = &s
	}
	if mfaDelete != "" {
		m := string(mfaDelete)
		out.MFADelete = &m
	}

	body, err := xml.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

type deleteObjectsReqXML struct {
	XMLName xml.Name                 `xml:"Delete"`
	Objects []deleteObjectReqItemXML `xml:"Object"`
	Quiet   *bool                    `xml:"Quiet,omitempty"`
}

type deleteObjectReqItemXML struct {
	Key       *string `xml:"Key"`
	VersionID *string `xml:"VersionId,omitempty"`
	ETag      *string `xml:"ETag,omitempty"`
}

type lifecycleConfigReqXML struct {
	XMLName xml.Name           `xml:"LifecycleConfiguration"`
	Rules   []lifecycleRuleXML `xml:"Rule"`
}

type lifecycleTagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type lifecycleAndXML struct {
	Prefix                *string           `xml:"Prefix,omitempty"`
	Tag                   []lifecycleTagXML `xml:"Tag,omitempty"`
	ObjectSizeGreaterThan *int64            `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64            `xml:"ObjectSizeLessThan,omitempty"`
}

type lifecycleFilterXML struct {
	Prefix                *string          `xml:"Prefix,omitempty"`
	Tag                   *lifecycleTagXML `xml:"Tag,omitempty"`
	And                   *lifecycleAndXML `xml:"And,omitempty"`
	ObjectSizeGreaterThan *int64           `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64           `xml:"ObjectSizeLessThan,omitempty"`
}

type lifecycleExpirationXML struct {
	Days                      *int32  `xml:"Days,omitempty"`
	Date                      *string `xml:"Date,omitempty"`
	ExpiredObjectDeleteMarker *bool   `xml:"ExpiredObjectDeleteMarker,omitempty"`
}

type lifecycleTransitionXML struct {
	Date         *string `xml:"Date,omitempty"`
	Days         *int32  `xml:"Days,omitempty"`
	StorageClass *string `xml:"StorageClass,omitempty"`
}

type lifecycleNoncurrentVersionTransitionXML struct {
	NoncurrentDays          *int32  `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions *int32  `xml:"NewerNoncurrentVersions,omitempty"`
	StorageClass            *string `xml:"StorageClass,omitempty"`
}

type lifecycleNoncurrentVersionExpirationXML struct {
	NoncurrentDays          *int32 `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions *int32 `xml:"NewerNoncurrentVersions,omitempty"`
}

type lifecycleAbortIncompleteMultipartUploadXML struct {
	DaysAfterInitiation *int32 `xml:"DaysAfterInitiation,omitempty"`
}

type lifecycleRuleXML struct {
	ID                             *string                                     `xml:"ID,omitempty"`
	Status                         string                                      `xml:"Status"`
	Prefix                         *string                                     `xml:"Prefix,omitempty"`
	Filter                         *lifecycleFilterXML                         `xml:"Filter,omitempty"`
	Expiration                     *lifecycleExpirationXML                     `xml:"Expiration,omitempty"`
	Transition                     []lifecycleTransitionXML                    `xml:"Transition,omitempty"`
	NoncurrentVersionTransition    []lifecycleNoncurrentVersionTransitionXML   `xml:"NoncurrentVersionTransition,omitempty"`
	NoncurrentVersionExpiration    *lifecycleNoncurrentVersionExpirationXML    `xml:"NoncurrentVersionExpiration,omitempty"`
	AbortIncompleteMultipartUpload *lifecycleAbortIncompleteMultipartUploadXML `xml:"AbortIncompleteMultipartUpload,omitempty"`
}

type lifecycleConfigRespXML struct {
	XMLName xml.Name           `xml:"LifecycleConfiguration"`
	XMLNS   string             `xml:"xmlns,attr,omitempty"`
	Rules   []lifecycleRuleXML `xml:"Rule"`
}

func parseLifecycleDate(raw string) (*time.Time, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, errors.New("empty lifecycle date")
	}
	formats := []string{
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			utc := t.UTC()
			return &utc, nil
		}
	}
	return nil, errors.New("invalid lifecycle date")
}

func formatLifecycleDate(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format("2006-01-02T15:04:05.000Z")
	return &s
}

func parseTransitionStorageClass(v string) (types.TransitionStorageClass, error) {
	raw := strings.ToUpper(strings.TrimSpace(v))
	if raw == "" {
		return "", errors.New("missing storage class")
	}
	for _, allowed := range types.TransitionStorageClass("").Values() {
		if raw == string(allowed) {
			return allowed, nil
		}
	}
	return "", fmt.Errorf("unsupported storage class %q", raw)
}

func decodeLifecycleTag(x *lifecycleTagXML) (*types.Tag, error) {
	if x == nil {
		return nil, nil
	}
	key := strings.TrimSpace(x.Key)
	if key == "" {
		return nil, errors.New("missing lifecycle tag key")
	}
	val := strings.TrimSpace(x.Value)
	return &types.Tag{
		Key:   aws.String(key),
		Value: aws.String(val),
	}, nil
}

func encodeLifecycleTag(t *types.Tag) *lifecycleTagXML {
	if t == nil {
		return nil
	}
	return &lifecycleTagXML{
		Key:   aws.ToString(t.Key),
		Value: aws.ToString(t.Value),
	}
}

func decodeLifecycleAnd(x *lifecycleAndXML) (*types.LifecycleRuleAndOperator, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.LifecycleRuleAndOperator{}
	var hasPred bool
	if x.Prefix != nil {
		out.Prefix = aws.String(strings.TrimSpace(*x.Prefix))
		hasPred = true
	}
	if x.ObjectSizeGreaterThan != nil {
		if *x.ObjectSizeGreaterThan < 0 {
			return nil, errors.New("invalid object size greater-than")
		}
		out.ObjectSizeGreaterThan = aws.Int64(*x.ObjectSizeGreaterThan)
		hasPred = true
	}
	if x.ObjectSizeLessThan != nil {
		if *x.ObjectSizeLessThan < 0 {
			return nil, errors.New("invalid object size less-than")
		}
		out.ObjectSizeLessThan = aws.Int64(*x.ObjectSizeLessThan)
		hasPred = true
	}
	if out.ObjectSizeGreaterThan != nil && out.ObjectSizeLessThan != nil &&
		aws.ToInt64(out.ObjectSizeGreaterThan) >= aws.ToInt64(out.ObjectSizeLessThan) {
		return nil, errors.New("object size greater-than must be less than object size less-than")
	}
	if len(x.Tag) > 0 {
		out.Tags = make([]types.Tag, 0, len(x.Tag))
		for _, xt := range x.Tag {
			tag, err := decodeLifecycleTag(&xt)
			if err != nil {
				return nil, err
			}
			out.Tags = append(out.Tags, *tag)
		}
		hasPred = true
	}
	if !hasPred {
		return nil, errors.New("empty And filter")
	}
	return out, nil
}

func encodeLifecycleAnd(a *types.LifecycleRuleAndOperator) *lifecycleAndXML {
	if a == nil {
		return nil
	}
	out := &lifecycleAndXML{}
	if a.Prefix != nil {
		out.Prefix = aws.String(aws.ToString(a.Prefix))
	}
	if a.ObjectSizeGreaterThan != nil {
		out.ObjectSizeGreaterThan = aws.Int64(aws.ToInt64(a.ObjectSizeGreaterThan))
	}
	if a.ObjectSizeLessThan != nil {
		out.ObjectSizeLessThan = aws.Int64(aws.ToInt64(a.ObjectSizeLessThan))
	}
	if len(a.Tags) > 0 {
		out.Tag = make([]lifecycleTagXML, 0, len(a.Tags))
		for _, t := range a.Tags {
			out.Tag = append(out.Tag, lifecycleTagXML{
				Key:   aws.ToString(t.Key),
				Value: aws.ToString(t.Value),
			})
		}
	}
	return out
}

func decodeLifecycleFilter(x *lifecycleFilterXML) (*types.LifecycleRuleFilter, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.LifecycleRuleFilter{}
	var topLevelPredicates int
	if x.Prefix != nil {
		out.Prefix = aws.String(strings.TrimSpace(*x.Prefix))
		topLevelPredicates++
	}
	if x.Tag != nil {
		tag, err := decodeLifecycleTag(x.Tag)
		if err != nil {
			return nil, err
		}
		out.Tag = tag
		topLevelPredicates++
	}
	if x.And != nil {
		and, err := decodeLifecycleAnd(x.And)
		if err != nil {
			return nil, err
		}
		out.And = and
		topLevelPredicates++
	}
	if x.ObjectSizeGreaterThan != nil {
		if *x.ObjectSizeGreaterThan < 0 {
			return nil, errors.New("invalid object size greater-than")
		}
		out.ObjectSizeGreaterThan = aws.Int64(*x.ObjectSizeGreaterThan)
		topLevelPredicates++
	}
	if x.ObjectSizeLessThan != nil {
		if *x.ObjectSizeLessThan < 0 {
			return nil, errors.New("invalid object size less-than")
		}
		out.ObjectSizeLessThan = aws.Int64(*x.ObjectSizeLessThan)
		topLevelPredicates++
	}
	if topLevelPredicates > 1 {
		return nil, errors.New("filter must have exactly one top-level predicate")
	}
	return out, nil
}

func encodeLifecycleFilter(f *types.LifecycleRuleFilter) *lifecycleFilterXML {
	if f == nil {
		return nil
	}
	out := &lifecycleFilterXML{}
	if f.Prefix != nil {
		out.Prefix = aws.String(aws.ToString(f.Prefix))
	}
	if f.Tag != nil {
		out.Tag = encodeLifecycleTag(f.Tag)
	}
	if f.And != nil {
		out.And = encodeLifecycleAnd(f.And)
	}
	if f.ObjectSizeGreaterThan != nil {
		out.ObjectSizeGreaterThan = aws.Int64(aws.ToInt64(f.ObjectSizeGreaterThan))
	}
	if f.ObjectSizeLessThan != nil {
		out.ObjectSizeLessThan = aws.Int64(aws.ToInt64(f.ObjectSizeLessThan))
	}
	return out
}

func decodeLifecycleExpiration(x *lifecycleExpirationXML) (*types.LifecycleExpiration, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.LifecycleExpiration{}
	var hasField bool
	if x.Days != nil {
		if *x.Days <= 0 {
			return nil, errors.New("invalid expiration days")
		}
		out.Days = aws.Int32(*x.Days)
		hasField = true
	}
	if x.Date != nil {
		d, err := parseLifecycleDate(*x.Date)
		if err != nil {
			return nil, err
		}
		out.Date = d
		hasField = true
	}
	if x.ExpiredObjectDeleteMarker != nil {
		out.ExpiredObjectDeleteMarker = aws.Bool(*x.ExpiredObjectDeleteMarker)
		hasField = true
	}
	if !hasField {
		return nil, errors.New("empty expiration")
	}
	if out.ExpiredObjectDeleteMarker != nil && (out.Days != nil || out.Date != nil) {
		return nil, errors.New("expired object delete marker cannot be combined with days/date")
	}
	return out, nil
}

func encodeLifecycleExpiration(exp *types.LifecycleExpiration) *lifecycleExpirationXML {
	if exp == nil {
		return nil
	}
	out := &lifecycleExpirationXML{}
	if exp.Days != nil {
		out.Days = aws.Int32(aws.ToInt32(exp.Days))
	}
	if exp.Date != nil {
		out.Date = formatLifecycleDate(exp.Date)
	}
	if exp.ExpiredObjectDeleteMarker != nil {
		out.ExpiredObjectDeleteMarker = aws.Bool(aws.ToBool(exp.ExpiredObjectDeleteMarker))
	}
	return out
}

func decodeLifecycleTransition(x lifecycleTransitionXML) (types.Transition, error) {
	var out types.Transition
	if x.Days != nil {
		if *x.Days < 0 {
			return out, errors.New("invalid transition days")
		}
		out.Days = aws.Int32(*x.Days)
	}
	if x.Date != nil {
		d, err := parseLifecycleDate(*x.Date)
		if err != nil {
			return out, err
		}
		out.Date = d
	}
	if out.Days != nil && out.Date != nil {
		return out, errors.New("transition cannot have both date and days")
	}
	if out.Days == nil && out.Date == nil {
		return out, errors.New("transition must have date or days")
	}
	if x.StorageClass == nil || strings.TrimSpace(*x.StorageClass) == "" {
		return out, errors.New("transition missing storage class")
	}
	sc, err := parseTransitionStorageClass(*x.StorageClass)
	if err != nil {
		return out, err
	}
	out.StorageClass = sc
	return out, nil
}

func encodeLifecycleTransition(t types.Transition) lifecycleTransitionXML {
	out := lifecycleTransitionXML{}
	if t.Date != nil {
		out.Date = formatLifecycleDate(t.Date)
	}
	if t.Days != nil {
		out.Days = aws.Int32(aws.ToInt32(t.Days))
	}
	if t.StorageClass != "" {
		sc := string(t.StorageClass)
		out.StorageClass = &sc
	}
	return out
}

func decodeLifecycleNoncurrentTransition(x lifecycleNoncurrentVersionTransitionXML) (types.NoncurrentVersionTransition, error) {
	var out types.NoncurrentVersionTransition
	if x.NoncurrentDays != nil {
		if *x.NoncurrentDays <= 0 {
			return out, errors.New("invalid noncurrent transition days")
		}
		out.NoncurrentDays = aws.Int32(*x.NoncurrentDays)
	}
	if x.NewerNoncurrentVersions != nil {
		if *x.NewerNoncurrentVersions <= 0 {
			return out, errors.New("invalid newer noncurrent versions")
		}
		out.NewerNoncurrentVersions = aws.Int32(*x.NewerNoncurrentVersions)
	}
	if out.NoncurrentDays == nil {
		return out, errors.New("noncurrent transition requires noncurrent days")
	}
	if x.StorageClass == nil || strings.TrimSpace(*x.StorageClass) == "" {
		return out, errors.New("noncurrent transition missing storage class")
	}
	sc, err := parseTransitionStorageClass(*x.StorageClass)
	if err != nil {
		return out, err
	}
	out.StorageClass = sc
	return out, nil
}

func encodeLifecycleNoncurrentTransition(t types.NoncurrentVersionTransition) lifecycleNoncurrentVersionTransitionXML {
	out := lifecycleNoncurrentVersionTransitionXML{}
	if t.NoncurrentDays != nil {
		out.NoncurrentDays = aws.Int32(aws.ToInt32(t.NoncurrentDays))
	}
	if t.NewerNoncurrentVersions != nil {
		out.NewerNoncurrentVersions = aws.Int32(aws.ToInt32(t.NewerNoncurrentVersions))
	}
	if t.StorageClass != "" {
		sc := string(t.StorageClass)
		out.StorageClass = &sc
	}
	return out
}

func decodeLifecycleNoncurrentExpiration(x *lifecycleNoncurrentVersionExpirationXML) (*types.NoncurrentVersionExpiration, error) {
	if x == nil {
		return nil, nil
	}
	out := &types.NoncurrentVersionExpiration{}
	var hasField bool
	if x.NoncurrentDays != nil {
		if *x.NoncurrentDays <= 0 {
			return nil, errors.New("invalid noncurrent expiration days")
		}
		out.NoncurrentDays = aws.Int32(*x.NoncurrentDays)
		hasField = true
	}
	if x.NewerNoncurrentVersions != nil {
		if *x.NewerNoncurrentVersions <= 0 {
			return nil, errors.New("invalid newer noncurrent versions")
		}
		out.NewerNoncurrentVersions = aws.Int32(*x.NewerNoncurrentVersions)
		hasField = true
	}
	if !hasField {
		return nil, errors.New("empty noncurrent expiration")
	}
	return out, nil
}

func encodeLifecycleNoncurrentExpiration(exp *types.NoncurrentVersionExpiration) *lifecycleNoncurrentVersionExpirationXML {
	if exp == nil {
		return nil
	}
	out := &lifecycleNoncurrentVersionExpirationXML{}
	if exp.NoncurrentDays != nil {
		out.NoncurrentDays = aws.Int32(aws.ToInt32(exp.NoncurrentDays))
	}
	if exp.NewerNoncurrentVersions != nil {
		out.NewerNoncurrentVersions = aws.Int32(aws.ToInt32(exp.NewerNoncurrentVersions))
	}
	return out
}

func decodeLifecycleAbortIncompleteMultipartUpload(x *lifecycleAbortIncompleteMultipartUploadXML) (*types.AbortIncompleteMultipartUpload, error) {
	if x == nil {
		return nil, nil
	}
	if x.DaysAfterInitiation == nil || *x.DaysAfterInitiation <= 0 {
		return nil, errors.New("invalid days after initiation")
	}
	return &types.AbortIncompleteMultipartUpload{
		DaysAfterInitiation: aws.Int32(*x.DaysAfterInitiation),
	}, nil
}

func encodeLifecycleAbortIncompleteMultipartUpload(a *types.AbortIncompleteMultipartUpload) *lifecycleAbortIncompleteMultipartUploadXML {
	if a == nil {
		return nil
	}
	out := &lifecycleAbortIncompleteMultipartUploadXML{}
	if a.DaysAfterInitiation != nil {
		out.DaysAfterInitiation = aws.Int32(aws.ToInt32(a.DaysAfterInitiation))
	}
	return out
}

func decodeLifecycleConfigXML(r io.Reader) (*types.BucketLifecycleConfiguration, error) {
	var in lifecycleConfigReqXML
	if err := xml.NewDecoder(r).Decode(&in); err != nil {
		return nil, err
	}
	if len(in.Rules) == 0 {
		return nil, errors.New("missing lifecycle rules")
	}

	rules := make([]types.LifecycleRule, 0, len(in.Rules))
	for i, xr := range in.Rules {
		var status types.ExpirationStatus
		switch strings.ToLower(strings.TrimSpace(xr.Status)) {
		case "enabled":
			status = types.ExpirationStatusEnabled
		case "disabled":
			status = types.ExpirationStatusDisabled
		default:
			return nil, fmt.Errorf("rule %d has invalid status", i)
		}

		rule := types.LifecycleRule{Status: status}
		if xr.ID != nil {
			id := strings.TrimSpace(*xr.ID)
			if id != "" {
				rule.ID = aws.String(id)
			}
		}
		if xr.Prefix != nil && xr.Filter != nil {
			return nil, fmt.Errorf("rule %d cannot contain both Prefix and Filter", i)
		}
		filter, err := decodeLifecycleFilter(xr.Filter)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid filter: %w", i, err)
		}
		if xr.Prefix != nil {
			filter = &types.LifecycleRuleFilter{
				Prefix: aws.String(strings.TrimSpace(*xr.Prefix)),
			}
		}
		rule.Filter = filter
		exp, err := decodeLifecycleExpiration(xr.Expiration)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid expiration: %w", i, err)
		}
		rule.Expiration = exp

		if len(xr.Transition) > 0 {
			rule.Transitions = make([]types.Transition, 0, len(xr.Transition))
			for j, xt := range xr.Transition {
				t, err := decodeLifecycleTransition(xt)
				if err != nil {
					return nil, fmt.Errorf("rule %d transition %d invalid: %w", i, j, err)
				}
				rule.Transitions = append(rule.Transitions, t)
			}
		}

		if len(xr.NoncurrentVersionTransition) > 0 {
			rule.NoncurrentVersionTransitions = make([]types.NoncurrentVersionTransition, 0, len(xr.NoncurrentVersionTransition))
			for j, xt := range xr.NoncurrentVersionTransition {
				t, err := decodeLifecycleNoncurrentTransition(xt)
				if err != nil {
					return nil, fmt.Errorf("rule %d noncurrent transition %d invalid: %w", i, j, err)
				}
				rule.NoncurrentVersionTransitions = append(rule.NoncurrentVersionTransitions, t)
			}
		}

		nce, err := decodeLifecycleNoncurrentExpiration(xr.NoncurrentVersionExpiration)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid noncurrent expiration: %w", i, err)
		}
		rule.NoncurrentVersionExpiration = nce

		abort, err := decodeLifecycleAbortIncompleteMultipartUpload(xr.AbortIncompleteMultipartUpload)
		if err != nil {
			return nil, fmt.Errorf("rule %d has invalid abort multipart settings: %w", i, err)
		}
		rule.AbortIncompleteMultipartUpload = abort

		rules = append(rules, rule)
	}

	return &types.BucketLifecycleConfiguration{Rules: rules}, nil
}

func encodeLifecycleConfigXML(rules []types.LifecycleRule) ([]byte, error) {
	out := lifecycleConfigRespXML{
		XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/",
		Rules: make([]lifecycleRuleXML, 0, len(rules)),
	}
	for _, r := range rules {
		xr := lifecycleRuleXML{
			ID:     r.ID,
			Status: string(r.Status),
		}
		filter := r.Filter
		if filter == nil {
			if legacyPrefix := lifecycleRuleLegacyPrefix(r); legacyPrefix != nil {
				filter = &types.LifecycleRuleFilter{
					Prefix: legacyPrefix,
				}
			}
		}
		xr.Filter = encodeLifecycleFilter(filter)
		xr.Expiration = encodeLifecycleExpiration(r.Expiration)
		if len(r.Transitions) > 0 {
			xr.Transition = make([]lifecycleTransitionXML, 0, len(r.Transitions))
			for _, t := range r.Transitions {
				xr.Transition = append(xr.Transition, encodeLifecycleTransition(t))
			}
		}
		if len(r.NoncurrentVersionTransitions) > 0 {
			xr.NoncurrentVersionTransition = make([]lifecycleNoncurrentVersionTransitionXML, 0, len(r.NoncurrentVersionTransitions))
			for _, t := range r.NoncurrentVersionTransitions {
				xr.NoncurrentVersionTransition = append(xr.NoncurrentVersionTransition, encodeLifecycleNoncurrentTransition(t))
			}
		}
		xr.NoncurrentVersionExpiration = encodeLifecycleNoncurrentExpiration(r.NoncurrentVersionExpiration)
		xr.AbortIncompleteMultipartUpload = encodeLifecycleAbortIncompleteMultipartUpload(r.AbortIncompleteMultipartUpload)
		out.Rules = append(out.Rules, xr)
	}
	body, err := xml.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

func lifecycleRuleLegacyPrefix(r types.LifecycleRule) *string {
	field := reflect.ValueOf(r).FieldByName("Prefix")
	if !field.IsValid() || field.Kind() != reflect.Pointer || field.IsNil() {
		return nil
	}
	legacy, ok := field.Interface().(*string)
	if !ok || legacy == nil {
		return nil
	}
	return aws.String(strings.TrimSpace(*legacy))
}

func (s *server) handlePutBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	cfg, err := decodeLifecycleConfigXML(r.Body)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Invalid lifecycle configuration")
		return
	}

	_, err = s.up.PutBucketLifecycleConfiguration(r.Context(), &s3.PutBucketLifecycleConfigurationInput{
		Bucket:                 &bucket,
		LifecycleConfiguration: cfg,
	})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	out, err := s.up.GetBucketLifecycleConfiguration(r.Context(), &s3.GetBucketLifecycleConfigurationInput{
		Bucket: &bucket,
	})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	body, err := encodeLifecycleConfigXML(out.Rules)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *server) handleDeleteBucketLifecycleConfiguration(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	_, err := s.up.DeleteBucketLifecycle(r.Context(), &s3.DeleteBucketLifecycleInput{
		Bucket: &bucket,
	})
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleHeadBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.HeadBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.HeadBucket(r.Context(), in)
	if err != nil {
		writeUpstreamHeadError(w, err)
		return
	}

	if out.BucketRegion != nil {
		w.Header().Set("x-amz-bucket-region", *out.BucketRegion)
	}
	if out.BucketArn != nil {
		w.Header().Set("x-amz-bucket-arn", *out.BucketArn)
	}
	if out.BucketLocationName != nil {
		w.Header().Set("x-amz-bucket-location-name", *out.BucketLocationName)
	}
	if out.BucketLocationType != "" {
		w.Header().Set("x-amz-bucket-location-type", string(out.BucketLocationType))
	}
	if out.AccessPointAlias != nil {
		w.Header().Set("x-amz-access-point-alias", boolString(*out.AccessPointAlias))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleDeleteBucket(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteBucketInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err := s.up.DeleteBucket(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	cfg, err := decodeVersioningConfigXML(r.Body)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid versioning configuration")
		return
	}
	in := &s3.PutBucketVersioningInput{
		Bucket:                  &bucket,
		VersioningConfiguration: cfg,
	}
	if mfa := strings.TrimSpace(r.Header.Get("x-amz-mfa")); mfa != "" {
		in.MFA = aws.String(mfa)
	}
	if contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5")); contentMD5 != "" {
		in.ContentMD5 = aws.String(contentMD5)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	_, err = s.up.PutBucketVersioning(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.GetBucketVersioningInput{Bucket: &bucket}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	out, err := s.up.GetBucketVersioning(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	body, err := encodeVersioningConfigXML(out.Status, out.MFADelete)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *server) handleDeleteObjects(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	var req deleteObjectsReqXML
	if err := xml.NewDecoder(r.Body).Decode(&req); err != nil {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "Invalid DeleteObjects payload")
		return
	}
	if len(req.Objects) == 0 || len(req.Objects) > 1000 {
		writeXMLError(w, http.StatusBadRequest, "MalformedXML", "DeleteObjects requires 1..1000 objects")
		return
	}

	objects := make([]types.ObjectIdentifier, 0, len(req.Objects))
	for i, obj := range req.Objects {
		key := strings.TrimSpace(aws.ToString(obj.Key))
		if key == "" {
			writeXMLError(w, http.StatusBadRequest, "MalformedXML", fmt.Sprintf("DeleteObjects object[%d] missing Key", i))
			return
		}
		item := types.ObjectIdentifier{Key: aws.String(key)}
		if obj.VersionID != nil {
			v := strings.TrimSpace(*obj.VersionID)
			if v != "" {
				item.VersionId = aws.String(v)
			}
		}
		if obj.ETag != nil {
			e := strings.TrimSpace(*obj.ETag)
			if e != "" {
				item.ETag = aws.String(e)
			}
		}
		objects = append(objects, item)
	}

	in := &s3.DeleteObjectsInput{
		Bucket: &bucket,
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   req.Quiet,
		},
	}
	if bypass, set, err := parseOptionalBool(r.Header.Get("x-amz-bypass-governance-retention")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-bypass-governance-retention header")
		return
	} else if set {
		in.BypassGovernanceRetention = aws.Bool(bypass)
	}
	if mfa := strings.TrimSpace(r.Header.Get("x-amz-mfa")); mfa != "" {
		in.MFA = aws.String(mfa)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.DeleteObjects(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, d := range out.Deleted {
		b.WriteString("<Deleted>")
		if d.Key != nil {
			b.WriteString("<Key>" + xmlEscape(*d.Key) + "</Key>")
		}
		if d.VersionId != nil {
			b.WriteString("<VersionId>" + xmlEscape(*d.VersionId) + "</VersionId>")
		}
		if d.DeleteMarker != nil {
			b.WriteString("<DeleteMarker>" + boolString(*d.DeleteMarker) + "</DeleteMarker>")
		}
		if d.DeleteMarkerVersionId != nil {
			b.WriteString("<DeleteMarkerVersionId>" + xmlEscape(*d.DeleteMarkerVersionId) + "</DeleteMarkerVersionId>")
		}
		b.WriteString("</Deleted>")
	}
	for _, e := range out.Errors {
		b.WriteString("<Error>")
		if e.Key != nil {
			b.WriteString("<Key>" + xmlEscape(*e.Key) + "</Key>")
		}
		if e.VersionId != nil {
			b.WriteString("<VersionId>" + xmlEscape(*e.VersionId) + "</VersionId>")
		}
		if e.Code != nil {
			b.WriteString("<Code>" + xmlEscape(*e.Code) + "</Code>")
		}
		if e.Message != nil {
			b.WriteString("<Message>" + xmlEscape(*e.Message) + "</Message>")
		}
		b.WriteString("</Error>")
	}
	b.WriteString(`</DeleteResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleListObjectVersions(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	q := r.URL.Query()
	in := &s3.ListObjectVersionsInput{Bucket: &bucket}
	if v := q.Get("prefix"); v != "" {
		in.Prefix = &v
	}
	if v := q.Get("delimiter"); v != "" {
		in.Delimiter = &v
	}
	if v := q.Get("key-marker"); v != "" {
		in.KeyMarker = &v
	}
	if v := q.Get("version-id-marker"); v != "" {
		in.VersionIdMarker = &v
	}
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-keys")
			return
		}
		in.MaxKeys = aws.Int32(int32(n))
	}
	if et, err := parseEncodingType(q.Get("encoding-type")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid encoding-type")
		return
	} else if et != "" {
		in.EncodingType = et
	}
	if attrs, err := parseOptionalObjectAttributes(q.Get("optional-object-attributes")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid optional-object-attributes")
		return
	} else if len(attrs) > 0 {
		in.OptionalObjectAttributes = attrs
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.ListObjectVersions(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if out.Name != nil {
		b.WriteString("<Name>" + xmlEscape(*out.Name) + "</Name>")
	}
	if out.Prefix != nil {
		b.WriteString("<Prefix>" + xmlEscape(*out.Prefix) + "</Prefix>")
	}
	if out.KeyMarker != nil {
		b.WriteString("<KeyMarker>" + xmlEscape(*out.KeyMarker) + "</KeyMarker>")
	}
	if out.VersionIdMarker != nil {
		b.WriteString("<VersionIdMarker>" + xmlEscape(*out.VersionIdMarker) + "</VersionIdMarker>")
	}
	if out.NextKeyMarker != nil {
		b.WriteString("<NextKeyMarker>" + xmlEscape(*out.NextKeyMarker) + "</NextKeyMarker>")
	}
	if out.NextVersionIdMarker != nil {
		b.WriteString("<NextVersionIdMarker>" + xmlEscape(*out.NextVersionIdMarker) + "</NextVersionIdMarker>")
	}
	if out.Delimiter != nil {
		b.WriteString("<Delimiter>" + xmlEscape(*out.Delimiter) + "</Delimiter>")
	}
	if out.MaxKeys != nil {
		b.WriteString("<MaxKeys>" + strconv.Itoa(int(*out.MaxKeys)) + "</MaxKeys>")
	}
	if out.EncodingType != "" {
		b.WriteString("<EncodingType>" + xmlEscape(string(out.EncodingType)) + "</EncodingType>")
	}
	b.WriteString("<IsTruncated>" + boolString(aws.ToBool(out.IsTruncated)) + "</IsTruncated>")
	for _, cp := range out.CommonPrefixes {
		if cp.Prefix == nil {
			continue
		}
		b.WriteString("<CommonPrefixes><Prefix>" + xmlEscape(*cp.Prefix) + "</Prefix></CommonPrefixes>")
	}
	for _, v := range out.Versions {
		b.WriteString("<Version>")
		if v.Key != nil {
			b.WriteString("<Key>" + xmlEscape(*v.Key) + "</Key>")
		}
		if v.VersionId != nil {
			b.WriteString("<VersionId>" + xmlEscape(*v.VersionId) + "</VersionId>")
		}
		if v.IsLatest != nil {
			b.WriteString("<IsLatest>" + boolString(*v.IsLatest) + "</IsLatest>")
		}
		if v.LastModified != nil {
			b.WriteString("<LastModified>" + formatS3Time(*v.LastModified) + "</LastModified>")
		}
		if v.ETag != nil {
			b.WriteString("<ETag>" + xmlEscape(*v.ETag) + "</ETag>")
		}
		if v.Size != nil {
			b.WriteString("<Size>" + strconv.FormatInt(*v.Size, 10) + "</Size>")
		}
		if v.StorageClass != "" {
			b.WriteString("<StorageClass>" + xmlEscape(string(v.StorageClass)) + "</StorageClass>")
		}
		if v.Owner != nil {
			b.WriteString("<Owner>")
			if v.Owner.ID != nil {
				b.WriteString("<ID>" + xmlEscape(*v.Owner.ID) + "</ID>")
			}
			if v.Owner.DisplayName != nil {
				b.WriteString("<DisplayName>" + xmlEscape(*v.Owner.DisplayName) + "</DisplayName>")
			}
			b.WriteString("</Owner>")
		}
		if v.RestoreStatus != nil {
			b.WriteString("<RestoreStatus>")
			if v.RestoreStatus.IsRestoreInProgress != nil {
				b.WriteString("<IsRestoreInProgress>" + boolString(*v.RestoreStatus.IsRestoreInProgress) + "</IsRestoreInProgress>")
			}
			if v.RestoreStatus.RestoreExpiryDate != nil {
				b.WriteString("<RestoreExpiryDate>" + formatS3Time(*v.RestoreStatus.RestoreExpiryDate) + "</RestoreExpiryDate>")
			}
			b.WriteString("</RestoreStatus>")
		}
		b.WriteString("</Version>")
	}
	for _, d := range out.DeleteMarkers {
		b.WriteString("<DeleteMarker>")
		if d.Key != nil {
			b.WriteString("<Key>" + xmlEscape(*d.Key) + "</Key>")
		}
		if d.VersionId != nil {
			b.WriteString("<VersionId>" + xmlEscape(*d.VersionId) + "</VersionId>")
		}
		if d.IsLatest != nil {
			b.WriteString("<IsLatest>" + boolString(*d.IsLatest) + "</IsLatest>")
		}
		if d.LastModified != nil {
			b.WriteString("<LastModified>" + formatS3Time(*d.LastModified) + "</LastModified>")
		}
		if d.Owner != nil {
			b.WriteString("<Owner>")
			if d.Owner.ID != nil {
				b.WriteString("<ID>" + xmlEscape(*d.Owner.ID) + "</ID>")
			}
			if d.Owner.DisplayName != nil {
				b.WriteString("<DisplayName>" + xmlEscape(*d.Owner.DisplayName) + "</DisplayName>")
			}
			b.WriteString("</Owner>")
		}
		b.WriteString("</DeleteMarker>")
	}
	b.WriteString(`</ListVersionsResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleListObjectsV2(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	q := r.URL.Query()
	in := &s3.ListObjectsV2Input{Bucket: &bucket}
	if v := q.Get("prefix"); v != "" {
		in.Prefix = &v
	}
	if v := q.Get("delimiter"); v != "" {
		in.Delimiter = &v
	}
	if v := q.Get("continuation-token"); v != "" {
		in.ContinuationToken = &v
	}
	if v := q.Get("start-after"); v != "" {
		in.StartAfter = &v
	}
	if v := q.Get("max-keys"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n < 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-keys")
			return
		}
		in.MaxKeys = aws.Int32(int32(n))
	}
	if fetchOwner, set, err := parseOptionalBool(q.Get("fetch-owner")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid fetch-owner")
		return
	} else if set {
		in.FetchOwner = aws.Bool(fetchOwner)
	}
	if et, err := parseEncodingType(q.Get("encoding-type")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid encoding-type")
		return
	} else if et != "" {
		in.EncodingType = et
	}
	if attrs, err := parseOptionalObjectAttributes(q.Get("optional-object-attributes")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid optional-object-attributes")
		return
	} else if len(attrs) > 0 {
		in.OptionalObjectAttributes = attrs
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.ListObjectsV2(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if out.Name != nil {
		b.WriteString("<Name>" + xmlEscape(*out.Name) + "</Name>")
	}
	if out.Prefix != nil {
		b.WriteString("<Prefix>" + xmlEscape(*out.Prefix) + "</Prefix>")
	}
	if out.StartAfter != nil {
		b.WriteString("<StartAfter>" + xmlEscape(*out.StartAfter) + "</StartAfter>")
	}
	if out.Delimiter != nil {
		b.WriteString("<Delimiter>" + xmlEscape(*out.Delimiter) + "</Delimiter>")
	}
	if out.MaxKeys != nil {
		b.WriteString("<MaxKeys>" + strconv.Itoa(int(*out.MaxKeys)) + "</MaxKeys>")
	}
	if out.KeyCount != nil {
		b.WriteString("<KeyCount>" + strconv.Itoa(int(*out.KeyCount)) + "</KeyCount>")
	}
	if out.EncodingType != "" {
		b.WriteString("<EncodingType>" + xmlEscape(string(out.EncodingType)) + "</EncodingType>")
	}
	if out.ContinuationToken != nil {
		b.WriteString("<ContinuationToken>" + xmlEscape(*out.ContinuationToken) + "</ContinuationToken>")
	}
	if out.NextContinuationToken != nil {
		b.WriteString("<NextContinuationToken>" + xmlEscape(*out.NextContinuationToken) + "</NextContinuationToken>")
	}
	b.WriteString("<IsTruncated>" + boolString(aws.ToBool(out.IsTruncated)) + "</IsTruncated>")
	for _, cp := range out.CommonPrefixes {
		if cp.Prefix == nil {
			continue
		}
		b.WriteString("<CommonPrefixes><Prefix>" + xmlEscape(*cp.Prefix) + "</Prefix></CommonPrefixes>")
	}
	for _, o := range out.Contents {
		b.WriteString("<Contents>")
		if o.Key != nil {
			b.WriteString("<Key>" + xmlEscape(*o.Key) + "</Key>")
		}
		if o.LastModified != nil {
			b.WriteString("<LastModified>" + formatS3Time(*o.LastModified) + "</LastModified>")
		}
		if o.ETag != nil {
			b.WriteString("<ETag>" + xmlEscape(*o.ETag) + "</ETag>")
		}
		for _, c := range o.ChecksumAlgorithm {
			if c == "" {
				continue
			}
			b.WriteString("<ChecksumAlgorithm>" + xmlEscape(string(c)) + "</ChecksumAlgorithm>")
		}
		if o.ChecksumType != "" {
			b.WriteString("<ChecksumType>" + xmlEscape(string(o.ChecksumType)) + "</ChecksumType>")
		}
		if o.Size != nil {
			b.WriteString("<Size>" + strconv.FormatInt(*o.Size, 10) + "</Size>")
		}
		if o.StorageClass != "" {
			b.WriteString("<StorageClass>" + xmlEscape(string(o.StorageClass)) + "</StorageClass>")
		}
		if o.Owner != nil {
			b.WriteString("<Owner>")
			if o.Owner.ID != nil {
				b.WriteString("<ID>" + xmlEscape(*o.Owner.ID) + "</ID>")
			}
			if o.Owner.DisplayName != nil {
				b.WriteString("<DisplayName>" + xmlEscape(*o.Owner.DisplayName) + "</DisplayName>")
			}
			b.WriteString("</Owner>")
		}
		if o.RestoreStatus != nil {
			b.WriteString("<RestoreStatus>")
			if o.RestoreStatus.IsRestoreInProgress != nil {
				b.WriteString("<IsRestoreInProgress>" + boolString(*o.RestoreStatus.IsRestoreInProgress) + "</IsRestoreInProgress>")
			}
			if o.RestoreStatus.RestoreExpiryDate != nil {
				b.WriteString("<RestoreExpiryDate>" + formatS3Time(*o.RestoreStatus.RestoreExpiryDate) + "</RestoreExpiryDate>")
			}
			b.WriteString("</RestoreStatus>")
		}
		b.WriteString("</Contents>")
	}
	b.WriteString(`</ListBucketResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleListMultipartUploads(w http.ResponseWriter, r *http.Request, bucket string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.ListMultipartUploadsInput{Bucket: &bucket}
	q := r.URL.Query()
	if v := q.Get("prefix"); v != "" {
		in.Prefix = &v
	}
	if v := q.Get("delimiter"); v != "" {
		in.Delimiter = &v
	}
	if v := q.Get("key-marker"); v != "" {
		in.KeyMarker = &v
	}
	if v := q.Get("upload-id-marker"); v != "" {
		in.UploadIdMarker = &v
	}
	if v := q.Get("encoding-type"); v != "" {
		in.EncodingType = types.EncodingType(v)
	}
	if v := q.Get("max-uploads"); v != "" {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil || n <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-uploads")
			return
		}
		in.MaxUploads = aws.Int32(int32(n))
	}

	out, err := s.up.ListMultipartUploads(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	b.WriteString("<Bucket>" + xmlEscape(bucket) + "</Bucket>")
	if out.KeyMarker != nil {
		b.WriteString("<KeyMarker>" + xmlEscape(*out.KeyMarker) + "</KeyMarker>")
	}
	if out.UploadIdMarker != nil {
		b.WriteString("<UploadIdMarker>" + xmlEscape(*out.UploadIdMarker) + "</UploadIdMarker>")
	}
	if out.NextKeyMarker != nil {
		b.WriteString("<NextKeyMarker>" + xmlEscape(*out.NextKeyMarker) + "</NextKeyMarker>")
	}
	if out.NextUploadIdMarker != nil {
		b.WriteString("<NextUploadIdMarker>" + xmlEscape(*out.NextUploadIdMarker) + "</NextUploadIdMarker>")
	}
	if out.Prefix != nil {
		b.WriteString("<Prefix>" + xmlEscape(*out.Prefix) + "</Prefix>")
	}
	if out.Delimiter != nil {
		b.WriteString("<Delimiter>" + xmlEscape(*out.Delimiter) + "</Delimiter>")
	}
	if out.MaxUploads != nil {
		b.WriteString("<MaxUploads>" + strconv.Itoa(int(*out.MaxUploads)) + "</MaxUploads>")
	}
	b.WriteString("<IsTruncated>")
	if aws.ToBool(out.IsTruncated) {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString("</IsTruncated>")
	for _, cp := range out.CommonPrefixes {
		if cp.Prefix == nil {
			continue
		}
		b.WriteString("<CommonPrefixes><Prefix>" + xmlEscape(*cp.Prefix) + "</Prefix></CommonPrefixes>")
	}
	for _, u := range out.Uploads {
		b.WriteString("<Upload>")
		if u.Key != nil {
			b.WriteString("<Key>" + xmlEscape(*u.Key) + "</Key>")
		}
		if u.UploadId != nil {
			b.WriteString("<UploadId>" + xmlEscape(*u.UploadId) + "</UploadId>")
		}
		if u.Initiated != nil {
			b.WriteString("<Initiated>" + u.Initiated.UTC().Format("2006-01-02T15:04:05.000Z") + "</Initiated>")
		}
		if u.StorageClass != "" {
			b.WriteString("<StorageClass>" + xmlEscape(string(u.StorageClass)) + "</StorageClass>")
		}
		if u.ChecksumAlgorithm != "" {
			b.WriteString("<ChecksumAlgorithm>" + xmlEscape(string(u.ChecksumAlgorithm)) + "</ChecksumAlgorithm>")
		}
		if u.ChecksumType != "" {
			b.WriteString("<ChecksumType>" + xmlEscape(string(u.ChecksumType)) + "</ChecksumType>")
		}
		if u.Owner != nil {
			b.WriteString("<Owner>")
			if u.Owner.DisplayName != nil {
				b.WriteString("<DisplayName>" + xmlEscape(*u.Owner.DisplayName) + "</DisplayName>")
			}
			if u.Owner.ID != nil {
				b.WriteString("<ID>" + xmlEscape(*u.Owner.ID) + "</ID>")
			}
			b.WriteString("</Owner>")
		}
		if u.Initiator != nil {
			b.WriteString("<Initiator>")
			if u.Initiator.DisplayName != nil {
				b.WriteString("<DisplayName>" + xmlEscape(*u.Initiator.DisplayName) + "</DisplayName>")
			}
			if u.Initiator.ID != nil {
				b.WriteString("<ID>" + xmlEscape(*u.Initiator.ID) + "</ID>")
			}
			b.WriteString("</Initiator>")
		}
		b.WriteString("</Upload>")
	}
	b.WriteString(`</ListMultipartUploadsResult>`)

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
	if versionID := r.URL.Query().Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if partNumStr := strings.TrimSpace(r.URL.Query().Get("partNumber")); partNumStr != "" {
		partNum, err := strconv.ParseInt(partNumStr, 10, 32)
		if err != nil || partNum <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid partNumber")
			return
		}
		in.PartNumber = aws.Int32(int32(partNum))
	}
	if rng := r.Header.Get("Range"); rng != "" {
		in.Range = &rng
	}
	if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
		in.IfMatch = &ifMatch
	}
	if ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match")); ifNoneMatch != "" {
		in.IfNoneMatch = &ifNoneMatch
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Modified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Modified-Since header")
		return
	} else if t != nil {
		in.IfModifiedSince = t
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Unmodified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Unmodified-Since header")
		return
	} else if t != nil {
		in.IfUnmodifiedSince = t
	}
	if mode, err := parseChecksumMode(r.Header.Get("x-amz-checksum-mode")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-checksum-mode header")
		return
	} else if mode != "" {
		in.ChecksumMode = mode
	}
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}
	q := r.URL.Query()
	if v := q.Get("response-cache-control"); v != "" {
		in.ResponseCacheControl = aws.String(v)
	}
	if v := q.Get("response-content-disposition"); v != "" {
		in.ResponseContentDisposition = aws.String(v)
	}
	if v := q.Get("response-content-encoding"); v != "" {
		in.ResponseContentEncoding = aws.String(v)
	}
	if v := q.Get("response-content-language"); v != "" {
		in.ResponseContentLanguage = aws.String(v)
	}
	if v := q.Get("response-content-type"); v != "" {
		in.ResponseContentType = aws.String(v)
	}
	if v := q.Get("response-expires"); v != "" {
		t, err := parseOptionalHTTPTime(v)
		if err != nil || t == nil {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid response-expires")
			return
		}
		in.ResponseExpires = t
	}

	out, err := s.up.GetObject(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	defer out.Body.Close()

	// Propagate a few headers
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	if out.LastModified != nil {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	}
	if out.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	if out.ContentRange != nil {
		w.Header().Set("Content-Range", *out.ContentRange)
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", strconv.FormatBool(*out.DeleteMarker))
	}
	if out.ExpiresString != nil {
		w.Header().Set("Expires", *out.ExpiresString)
	}
	if out.AcceptRanges != nil {
		w.Header().Set("Accept-Ranges", *out.AcceptRanges)
	}
	if out.CacheControl != nil {
		w.Header().Set("Cache-Control", *out.CacheControl)
	}
	if out.ContentDisposition != nil {
		w.Header().Set("Content-Disposition", *out.ContentDisposition)
	}
	if out.ContentEncoding != nil {
		w.Header().Set("Content-Encoding", *out.ContentEncoding)
	}
	if out.ContentLanguage != nil {
		w.Header().Set("Content-Language", *out.ContentLanguage)
	}
	if out.StorageClass != "" {
		w.Header().Set("x-amz-storage-class", string(out.StorageClass))
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.Restore != nil {
		w.Header().Set("x-amz-restore", *out.Restore)
	}
	if out.WebsiteRedirectLocation != nil {
		w.Header().Set("x-amz-website-redirect-location", *out.WebsiteRedirectLocation)
	}
	if out.ReplicationStatus != "" {
		w.Header().Set("x-amz-replication-status", string(out.ReplicationStatus))
	}
	if out.TagCount != nil {
		w.Header().Set("x-amz-tagging-count", strconv.Itoa(int(*out.TagCount)))
	}
	if out.PartsCount != nil {
		w.Header().Set("x-amz-mp-parts-count", strconv.Itoa(int(*out.PartsCount)))
	}
	if out.MissingMeta != nil {
		w.Header().Set("x-amz-missing-meta", strconv.Itoa(int(*out.MissingMeta)))
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}
	if out.ChecksumCRC32 != nil {
		w.Header().Set("x-amz-checksum-crc32", *out.ChecksumCRC32)
	}
	if out.ChecksumCRC32C != nil {
		w.Header().Set("x-amz-checksum-crc32c", *out.ChecksumCRC32C)
	}
	if out.ChecksumCRC64NVME != nil {
		w.Header().Set("x-amz-checksum-crc64nvme", *out.ChecksumCRC64NVME)
	}
	if out.ChecksumSHA1 != nil {
		w.Header().Set("x-amz-checksum-sha1", *out.ChecksumSHA1)
	}
	if out.ChecksumSHA256 != nil {
		w.Header().Set("x-amz-checksum-sha256", *out.ChecksumSHA256)
	}
	if out.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", string(out.ChecksumType))
	}
	for k, v := range out.Metadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}
	status := http.StatusOK
	if out.ContentRange != nil {
		status = http.StatusPartialContent
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, out.Body)
}

func (s *server) handleHeadObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.HeadObjectInput{Bucket: &bucket, Key: &key}
	q := r.URL.Query()
	if versionID := q.Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if partNumStr := strings.TrimSpace(q.Get("partNumber")); partNumStr != "" {
		partNum, err := strconv.ParseInt(partNumStr, 10, 32)
		if err != nil || partNum <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid partNumber")
			return
		}
		in.PartNumber = aws.Int32(int32(partNum))
	}
	if rng := r.Header.Get("Range"); rng != "" {
		in.Range = &rng
	}
	if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
		in.IfMatch = &ifMatch
	}
	if ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match")); ifNoneMatch != "" {
		in.IfNoneMatch = &ifNoneMatch
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Modified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Modified-Since header")
		return
	} else if t != nil {
		in.IfModifiedSince = t
	}
	if t, err := parseOptionalHTTPTime(r.Header.Get("If-Unmodified-Since")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid If-Unmodified-Since header")
		return
	} else if t != nil {
		in.IfUnmodifiedSince = t
	}
	if mode, err := parseChecksumMode(r.Header.Get("x-amz-checksum-mode")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-checksum-mode header")
		return
	} else if mode != "" {
		in.ChecksumMode = mode
	}
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}
	if v := q.Get("response-cache-control"); v != "" {
		in.ResponseCacheControl = aws.String(v)
	}
	if v := q.Get("response-content-disposition"); v != "" {
		in.ResponseContentDisposition = aws.String(v)
	}
	if v := q.Get("response-content-encoding"); v != "" {
		in.ResponseContentEncoding = aws.String(v)
	}
	if v := q.Get("response-content-language"); v != "" {
		in.ResponseContentLanguage = aws.String(v)
	}
	if v := q.Get("response-content-type"); v != "" {
		in.ResponseContentType = aws.String(v)
	}
	if v := q.Get("response-expires"); v != "" {
		t, err := parseOptionalHTTPTime(v)
		if err != nil || t == nil {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid response-expires")
			return
		}
		in.ResponseExpires = t
	}

	out, err := s.up.HeadObject(r.Context(), in)
	if err != nil {
		writeUpstreamHeadError(w, err)
		return
	}

	if out.AcceptRanges != nil {
		w.Header().Set("Accept-Ranges", *out.AcceptRanges)
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	if out.LastModified != nil {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.ContentType != nil {
		w.Header().Set("Content-Type", *out.ContentType)
	}
	if out.ContentLength != nil {
		w.Header().Set("Content-Length", strconv.FormatInt(*out.ContentLength, 10))
	}
	if out.ContentRange != nil {
		w.Header().Set("Content-Range", *out.ContentRange)
	}
	if out.CacheControl != nil {
		w.Header().Set("Cache-Control", *out.CacheControl)
	}
	if out.ContentDisposition != nil {
		w.Header().Set("Content-Disposition", *out.ContentDisposition)
	}
	if out.ContentEncoding != nil {
		w.Header().Set("Content-Encoding", *out.ContentEncoding)
	}
	if out.ContentLanguage != nil {
		w.Header().Set("Content-Language", *out.ContentLanguage)
	}
	if out.ExpiresString != nil {
		w.Header().Set("Expires", *out.ExpiresString)
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", boolString(*out.DeleteMarker))
	}
	if out.StorageClass != "" {
		w.Header().Set("x-amz-storage-class", string(out.StorageClass))
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.Restore != nil {
		w.Header().Set("x-amz-restore", *out.Restore)
	}
	if out.WebsiteRedirectLocation != nil {
		w.Header().Set("x-amz-website-redirect-location", *out.WebsiteRedirectLocation)
	}
	if out.ReplicationStatus != "" {
		w.Header().Set("x-amz-replication-status", string(out.ReplicationStatus))
	}
	if out.TagCount != nil {
		w.Header().Set("x-amz-tagging-count", strconv.Itoa(int(*out.TagCount)))
	}
	if out.PartsCount != nil {
		w.Header().Set("x-amz-mp-parts-count", strconv.Itoa(int(*out.PartsCount)))
	}
	if out.MissingMeta != nil {
		w.Header().Set("x-amz-missing-meta", strconv.Itoa(int(*out.MissingMeta)))
	}
	if out.ObjectLockMode != "" {
		w.Header().Set("x-amz-object-lock-mode", string(out.ObjectLockMode))
	}
	if out.ObjectLockLegalHoldStatus != "" {
		w.Header().Set("x-amz-object-lock-legal-hold", string(out.ObjectLockLegalHoldStatus))
	}
	if out.ObjectLockRetainUntilDate != nil {
		w.Header().Set("x-amz-object-lock-retain-until-date", out.ObjectLockRetainUntilDate.UTC().Format(time.RFC3339))
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}
	if out.ChecksumCRC32 != nil {
		w.Header().Set("x-amz-checksum-crc32", *out.ChecksumCRC32)
	}
	if out.ChecksumCRC32C != nil {
		w.Header().Set("x-amz-checksum-crc32c", *out.ChecksumCRC32C)
	}
	if out.ChecksumCRC64NVME != nil {
		w.Header().Set("x-amz-checksum-crc64nvme", *out.ChecksumCRC64NVME)
	}
	if out.ChecksumSHA1 != nil {
		w.Header().Set("x-amz-checksum-sha1", *out.ChecksumSHA1)
	}
	if out.ChecksumSHA256 != nil {
		w.Header().Set("x-amz-checksum-sha256", *out.ChecksumSHA256)
	}
	if out.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", string(out.ChecksumType))
	}
	for k, v := range out.Metadata {
		w.Header().Set("x-amz-meta-"+k, v)
	}
	w.WriteHeader(http.StatusOK)
}

func parseObjectAttributesHeader(h http.Header) ([]types.ObjectAttributes, error) {
	values := h.Values("x-amz-object-attributes")
	if len(values) == 0 {
		return nil, errors.New("missing x-amz-object-attributes")
	}

	seen := map[types.ObjectAttributes]struct{}{}
	out := make([]types.ObjectAttributes, 0, len(values))
	for _, raw := range values {
		for _, token := range strings.Split(raw, ",") {
			v := strings.Trim(strings.TrimSpace(token), `"`)
			if v == "" {
				continue
			}
			var attr types.ObjectAttributes
			switch strings.ToLower(v) {
			case "etag":
				attr = types.ObjectAttributesEtag
			case "checksum":
				attr = types.ObjectAttributesChecksum
			case "objectparts":
				attr = types.ObjectAttributesObjectParts
			case "storageclass":
				attr = types.ObjectAttributesStorageClass
			case "objectsize":
				attr = types.ObjectAttributesObjectSize
			default:
				return nil, fmt.Errorf("unsupported object attribute %q", v)
			}
			if _, ok := seen[attr]; ok {
				continue
			}
			seen[attr] = struct{}{}
			out = append(out, attr)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no object attributes requested")
	}
	return out, nil
}

func (s *server) handleGetObjectAttributes(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	attrs, err := parseObjectAttributesHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-object-attributes")
		return
	}

	in := &s3.GetObjectAttributesInput{
		Bucket:           &bucket,
		Key:              &key,
		ObjectAttributes: attrs,
	}
	if versionID := r.URL.Query().Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if mpStr := strings.TrimSpace(r.Header.Get("x-amz-max-parts")); mpStr != "" {
		mp, err := strconv.ParseInt(mpStr, 10, 32)
		if err != nil || mp <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-max-parts")
			return
		}
		in.MaxParts = aws.Int32(int32(mp))
	}
	if marker := strings.TrimSpace(r.Header.Get("x-amz-part-number-marker")); marker != "" {
		if _, err := strconv.Atoi(marker); err != nil {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-part-number-marker")
			return
		}
		in.PartNumberMarker = &marker
	}

	out, err := s.up.GetObjectAttributes(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	if out.LastModified != nil {
		w.Header().Set("Last-Modified", out.LastModified.UTC().Format(http.TimeFormat))
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", strconv.FormatBool(*out.DeleteMarker))
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<GetObjectAttributesOutput xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if out.ETag != nil {
		b.WriteString("<ETag>" + xmlEscape(*out.ETag) + "</ETag>")
	}
	if out.ObjectSize != nil {
		b.WriteString("<ObjectSize>" + strconv.FormatInt(*out.ObjectSize, 10) + "</ObjectSize>")
	}
	if out.StorageClass != "" {
		b.WriteString("<StorageClass>" + xmlEscape(string(out.StorageClass)) + "</StorageClass>")
	}
	if out.Checksum != nil {
		b.WriteString("<Checksum>")
		if out.Checksum.ChecksumCRC32 != nil {
			b.WriteString("<ChecksumCRC32>" + xmlEscape(*out.Checksum.ChecksumCRC32) + "</ChecksumCRC32>")
		}
		if out.Checksum.ChecksumCRC32C != nil {
			b.WriteString("<ChecksumCRC32C>" + xmlEscape(*out.Checksum.ChecksumCRC32C) + "</ChecksumCRC32C>")
		}
		if out.Checksum.ChecksumCRC64NVME != nil {
			b.WriteString("<ChecksumCRC64NVME>" + xmlEscape(*out.Checksum.ChecksumCRC64NVME) + "</ChecksumCRC64NVME>")
		}
		if out.Checksum.ChecksumSHA1 != nil {
			b.WriteString("<ChecksumSHA1>" + xmlEscape(*out.Checksum.ChecksumSHA1) + "</ChecksumSHA1>")
		}
		if out.Checksum.ChecksumSHA256 != nil {
			b.WriteString("<ChecksumSHA256>" + xmlEscape(*out.Checksum.ChecksumSHA256) + "</ChecksumSHA256>")
		}
		if out.Checksum.ChecksumType != "" {
			b.WriteString("<ChecksumType>" + xmlEscape(string(out.Checksum.ChecksumType)) + "</ChecksumType>")
		}
		b.WriteString("</Checksum>")
	}
	if out.ObjectParts != nil {
		b.WriteString("<ObjectParts>")
		if out.ObjectParts.PartNumberMarker != nil {
			b.WriteString("<PartNumberMarker>" + xmlEscape(*out.ObjectParts.PartNumberMarker) + "</PartNumberMarker>")
		}
		if out.ObjectParts.NextPartNumberMarker != nil {
			b.WriteString("<NextPartNumberMarker>" + xmlEscape(*out.ObjectParts.NextPartNumberMarker) + "</NextPartNumberMarker>")
		}
		if out.ObjectParts.MaxParts != nil {
			b.WriteString("<MaxParts>" + strconv.Itoa(int(*out.ObjectParts.MaxParts)) + "</MaxParts>")
		}
		if out.ObjectParts.TotalPartsCount != nil {
			b.WriteString("<PartsCount>" + strconv.Itoa(int(*out.ObjectParts.TotalPartsCount)) + "</PartsCount>")
		}
		b.WriteString("<IsTruncated>")
		if aws.ToBool(out.ObjectParts.IsTruncated) {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
		b.WriteString("</IsTruncated>")
		for _, p := range out.ObjectParts.Parts {
			b.WriteString("<Part>")
			if p.PartNumber != nil {
				b.WriteString("<PartNumber>" + strconv.Itoa(int(*p.PartNumber)) + "</PartNumber>")
			}
			if p.Size != nil {
				b.WriteString("<Size>" + strconv.FormatInt(*p.Size, 10) + "</Size>")
			}
			if p.ChecksumCRC32 != nil {
				b.WriteString("<ChecksumCRC32>" + xmlEscape(*p.ChecksumCRC32) + "</ChecksumCRC32>")
			}
			if p.ChecksumCRC32C != nil {
				b.WriteString("<ChecksumCRC32C>" + xmlEscape(*p.ChecksumCRC32C) + "</ChecksumCRC32C>")
			}
			if p.ChecksumCRC64NVME != nil {
				b.WriteString("<ChecksumCRC64NVME>" + xmlEscape(*p.ChecksumCRC64NVME) + "</ChecksumCRC64NVME>")
			}
			if p.ChecksumSHA1 != nil {
				b.WriteString("<ChecksumSHA1>" + xmlEscape(*p.ChecksumSHA1) + "</ChecksumSHA1>")
			}
			if p.ChecksumSHA256 != nil {
				b.WriteString("<ChecksumSHA256>" + xmlEscape(*p.ChecksumSHA256) + "</ChecksumSHA256>")
			}
			b.WriteString("</Part>")
		}
		b.WriteString("</ObjectParts>")
	}
	b.WriteString(`</GetObjectAttributesOutput>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handlePutObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	verifier, err := chunkSignatureVerifierFromRequest(r, s.cfg.SigV4Secret)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Unsupported or invalid streaming payload signature")
		return
	}

	body, cl, err := decodeBodyForS3Write(r, verifier)
	if err != nil {
		if errors.Is(err, errContentLengthRequired) || errors.Is(err, errMissingDecodedContentLength) || errors.Is(err, errInvalidDecodedContentLength) {
			writeXMLError(w, http.StatusLengthRequired, "MissingContentLength", "Content-Length required")
			return
		}
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Invalid request body")
		return
	}
	defer body.Close()
	if cl > maxSinglePutObjectSize {
		writeXMLError(w, http.StatusBadRequest, "EntityTooLarge", "Use multipart upload for objects larger than 5 GiB")
		return
	}

	ct := r.Header.Get("Content-Type")
	meta := extractAmzMeta(r.Header)
	expires, err := parseExpiresHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid Expires header")
		return
	}
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if ifMatch != "" && ifNoneMatch != "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "If-Match and If-None-Match cannot both be set")
		return
	}

	sse, err := parseSSEWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid server-side encryption headers")
		return
	}
	checksum, err := parseChecksumWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum headers")
		return
	}
	contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5"))
	if contentMD5 != "" && checksum.ChecksumAlgorithm != "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Content-MD5 cannot be combined with x-amz-checksum-algorithm")
		return
	}
	expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner"))
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	in := &s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          body,
		ContentLength: aws.Int64(cl),
		Metadata:      meta,
		Expires:       expires,
		IfMatch:       nil,
		IfNoneMatch:   nil,
	}
	if ifMatch != "" {
		in.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch != "" {
		in.IfNoneMatch = aws.String(ifNoneMatch)
	}
	if expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}
	if contentMD5 != "" {
		in.ContentMD5 = aws.String(contentMD5)
	}
	if ct != "" {
		in.ContentType = &ct
	}
	if sse.ServerSideEncryption != "" {
		in.ServerSideEncryption = sse.ServerSideEncryption
	}
	in.SSEKMSKeyId = sse.SSEKMSKeyID
	in.SSEKMSEncryptionContext = sse.SSEKMSEncryptionContext
	in.SSECustomerAlgorithm = sse.SSECustomerAlgorithm
	in.SSECustomerKey = sse.SSECustomerKey
	in.SSECustomerKeyMD5 = sse.SSECustomerKeyMD5
	if checksum.ChecksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksum.ChecksumAlgorithm
	}
	in.ChecksumCRC32 = checksum.ChecksumCRC32
	in.ChecksumCRC32C = checksum.ChecksumCRC32C
	in.ChecksumCRC64NVME = checksum.ChecksumCRC64NVME
	in.ChecksumSHA1 = checksum.ChecksumSHA1
	in.ChecksumSHA256 = checksum.ChecksumSHA256

	out, err := s.up.PutObject(r.Context(), in,
		// Allow streaming io.Reader without Seek by using Unsigned Payload middleware. :contentReference[oaicite:10]{index=10}
		s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware),
	)
	if err != nil {
		if isChunkSignatureValidationError(err) {
			writeXMLError(w, http.StatusBadRequest, "SignatureDoesNotMatch", "Invalid aws-chunked chunk signature")
			return
		}
		writeUpstreamError(w, err)
		return
	}
	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSEKMSEncryptionContext != nil {
		w.Header().Set("x-amz-server-side-encryption-context", *out.SSEKMSEncryptionContext)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}
	if out.ChecksumCRC32 != nil {
		w.Header().Set("x-amz-checksum-crc32", *out.ChecksumCRC32)
	}
	if out.ChecksumCRC32C != nil {
		w.Header().Set("x-amz-checksum-crc32c", *out.ChecksumCRC32C)
	}
	if out.ChecksumCRC64NVME != nil {
		w.Header().Set("x-amz-checksum-crc64nvme", *out.ChecksumCRC64NVME)
	}
	if out.ChecksumSHA1 != nil {
		w.Header().Set("x-amz-checksum-sha1", *out.ChecksumSHA1)
	}
	if out.ChecksumSHA256 != nil {
		w.Header().Set("x-amz-checksum-sha256", *out.ChecksumSHA256)
	}
	if out.ChecksumType != "" {
		w.Header().Set("x-amz-checksum-type", string(out.ChecksumType))
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleCopyObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	copySource := strings.TrimSpace(r.Header.Get("x-amz-copy-source"))
	if copySource == "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "x-amz-copy-source is required")
		return
	}
	sourceBucket, err := sourceBucketFromCopySource(copySource)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "invalid x-amz-copy-source")
		return
	}
	if !canRead(rules, sourceBucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	ifNoneMatch := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if ifMatch != "" && ifNoneMatch != "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "If-Match and If-None-Match cannot both be set")
		return
	}

	sse, err := parseSSEWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid server-side encryption headers")
		return
	}
	copySSECAlgo, copySSECKey, copySSECMD5, hasCopySSEC, err := parseCopySourceSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source SSE-C headers")
		return
	}
	checksumAlgorithm, err := parseChecksumAlgorithmHeader(r.Header.Get("x-amz-checksum-algorithm"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum algorithm")
		return
	}

	metadataDirective, err := parseMetadataDirective(r.Header.Get("x-amz-metadata-directive"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-metadata-directive header")
		return
	}
	taggingDirective, err := parseTaggingDirective(r.Header.Get("x-amz-tagging-directive"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-tagging-directive header")
		return
	}
	storageClass, err := parseStorageClass(r.Header.Get("x-amz-storage-class"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-storage-class header")
		return
	}
	acl, err := parseObjectCannedACL(r.Header.Get("x-amz-acl"))
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-acl header")
		return
	}
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	copyIfMatch, copyIfNoneMatch, copyIfModifiedSince, copyIfUnmodifiedSince, err := parseCopySourceConditionalHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source conditional header")
		return
	}
	expires, err := parseExpiresHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid Expires header")
		return
	}

	in := &s3.CopyObjectInput{
		Bucket:     &bucket,
		Key:        &key,
		CopySource: aws.String(copySource),
		Metadata:   extractAmzMeta(r.Header),
		Expires:    expires,
	}
	if ifMatch != "" {
		in.IfMatch = aws.String(ifMatch)
	}
	if ifNoneMatch != "" {
		in.IfNoneMatch = aws.String(ifNoneMatch)
	}
	if copyIfMatch != nil {
		in.CopySourceIfMatch = copyIfMatch
	}
	if copyIfNoneMatch != nil {
		in.CopySourceIfNoneMatch = copyIfNoneMatch
	}
	if copyIfModifiedSince != nil {
		in.CopySourceIfModifiedSince = copyIfModifiedSince
	}
	if copyIfUnmodifiedSince != nil {
		in.CopySourceIfUnmodifiedSince = copyIfUnmodifiedSince
	}
	if hasCopySSEC {
		in.CopySourceSSECustomerAlgorithm = copySSECAlgo
		in.CopySourceSSECustomerKey = copySSECKey
		in.CopySourceSSECustomerKeyMD5 = copySSECMD5
	}
	if metadataDirective != "" {
		in.MetadataDirective = metadataDirective
	}
	if taggingDirective != "" {
		in.TaggingDirective = taggingDirective
	}
	if tagging := strings.TrimSpace(r.Header.Get("x-amz-tagging")); tagging != "" {
		in.Tagging = aws.String(tagging)
	}
	if storageClass != "" {
		in.StorageClass = storageClass
	}
	if acl != "" {
		in.ACL = acl
	}
	if checksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksumAlgorithm
	}
	if ct := strings.TrimSpace(r.Header.Get("Content-Type")); ct != "" {
		in.ContentType = aws.String(ct)
	}
	if cc := strings.TrimSpace(r.Header.Get("Cache-Control")); cc != "" {
		in.CacheControl = aws.String(cc)
	}
	if cd := strings.TrimSpace(r.Header.Get("Content-Disposition")); cd != "" {
		in.ContentDisposition = aws.String(cd)
	}
	if ce := strings.TrimSpace(r.Header.Get("Content-Encoding")); ce != "" {
		in.ContentEncoding = aws.String(ce)
	}
	if cl := strings.TrimSpace(r.Header.Get("Content-Language")); cl != "" {
		in.ContentLanguage = aws.String(cl)
	}
	if redirect := strings.TrimSpace(r.Header.Get("x-amz-website-redirect-location")); redirect != "" {
		in.WebsiteRedirectLocation = aws.String(redirect)
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if sourceExpectedOwner := strings.TrimSpace(r.Header.Get("x-amz-source-expected-bucket-owner")); sourceExpectedOwner != "" {
		in.ExpectedSourceBucketOwner = aws.String(sourceExpectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}
	if sse.ServerSideEncryption != "" {
		in.ServerSideEncryption = sse.ServerSideEncryption
	}
	in.SSEKMSKeyId = sse.SSEKMSKeyID
	in.SSEKMSEncryptionContext = sse.SSEKMSEncryptionContext
	in.SSECustomerAlgorithm = sse.SSECustomerAlgorithm
	in.SSECustomerKey = sse.SSECustomerKey
	in.SSECustomerKeyMD5 = sse.SSECustomerKeyMD5

	out, err := s.up.CopyObject(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.CopySourceVersionId != nil {
		w.Header().Set("x-amz-copy-source-version-id", *out.CopySourceVersionId)
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSEKMSEncryptionContext != nil {
		w.Header().Set("x-amz-server-side-encryption-context", *out.SSEKMSEncryptionContext)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.Expiration != nil {
		w.Header().Set("x-amz-expiration", *out.Expiration)
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<CopyObjectResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if out.CopyObjectResult != nil {
		if out.CopyObjectResult.LastModified != nil {
			b.WriteString("<LastModified>" + formatS3Time(*out.CopyObjectResult.LastModified) + "</LastModified>")
		}
		if out.CopyObjectResult.ETag != nil {
			b.WriteString("<ETag>" + xmlEscape(*out.CopyObjectResult.ETag) + "</ETag>")
		}
		if out.CopyObjectResult.ChecksumCRC32 != nil {
			b.WriteString("<ChecksumCRC32>" + xmlEscape(*out.CopyObjectResult.ChecksumCRC32) + "</ChecksumCRC32>")
		}
		if out.CopyObjectResult.ChecksumCRC32C != nil {
			b.WriteString("<ChecksumCRC32C>" + xmlEscape(*out.CopyObjectResult.ChecksumCRC32C) + "</ChecksumCRC32C>")
		}
		if out.CopyObjectResult.ChecksumCRC64NVME != nil {
			b.WriteString("<ChecksumCRC64NVME>" + xmlEscape(*out.CopyObjectResult.ChecksumCRC64NVME) + "</ChecksumCRC64NVME>")
		}
		if out.CopyObjectResult.ChecksumSHA1 != nil {
			b.WriteString("<ChecksumSHA1>" + xmlEscape(*out.CopyObjectResult.ChecksumSHA1) + "</ChecksumSHA1>")
		}
		if out.CopyObjectResult.ChecksumSHA256 != nil {
			b.WriteString("<ChecksumSHA256>" + xmlEscape(*out.CopyObjectResult.ChecksumSHA256) + "</ChecksumSHA256>")
		}
		if out.CopyObjectResult.ChecksumType != "" {
			b.WriteString("<ChecksumType>" + xmlEscape(string(out.CopyObjectResult.ChecksumType)) + "</ChecksumType>")
		}
	}
	b.WriteString(`</CopyObjectResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleUploadPartCopy(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string, partNumber int32) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	copySource := strings.TrimSpace(r.Header.Get("x-amz-copy-source"))
	if copySource == "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "x-amz-copy-source is required")
		return
	}
	sourceBucket, err := sourceBucketFromCopySource(copySource)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "invalid x-amz-copy-source")
		return
	}
	if !canRead(rules, sourceBucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	copyIfMatch, copyIfNoneMatch, copyIfModifiedSince, copyIfUnmodifiedSince, err := parseCopySourceConditionalHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source conditional header")
		return
	}
	copySSECAlgo, copySSECKey, copySSECMD5, hasCopySSEC, err := parseCopySourceSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid copy-source SSE-C headers")
		return
	}
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	payer, err := parseRequestPayerHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	}

	in := &s3.UploadPartCopyInput{
		Bucket:     &bucket,
		Key:        &key,
		UploadId:   &uploadID,
		PartNumber: aws.Int32(partNumber),
		CopySource: aws.String(copySource),
	}
	if copyIfMatch != nil {
		in.CopySourceIfMatch = copyIfMatch
	}
	if copyIfNoneMatch != nil {
		in.CopySourceIfNoneMatch = copyIfNoneMatch
	}
	if copyIfModifiedSince != nil {
		in.CopySourceIfModifiedSince = copyIfModifiedSince
	}
	if copyIfUnmodifiedSince != nil {
		in.CopySourceIfUnmodifiedSince = copyIfUnmodifiedSince
	}
	if copySourceRange := strings.TrimSpace(r.Header.Get("x-amz-copy-source-range")); copySourceRange != "" {
		in.CopySourceRange = aws.String(copySourceRange)
	}
	if hasCopySSEC {
		in.CopySourceSSECustomerAlgorithm = copySSECAlgo
		in.CopySourceSSECustomerKey = copySSECKey
		in.CopySourceSSECustomerKeyMD5 = copySSECMD5
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if sourceExpectedOwner := strings.TrimSpace(r.Header.Get("x-amz-source-expected-bucket-owner")); sourceExpectedOwner != "" {
		in.ExpectedSourceBucketOwner = aws.String(sourceExpectedOwner)
	}
	if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.UploadPartCopy(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	if out.CopySourceVersionId != nil {
		w.Header().Set("x-amz-copy-source-version-id", *out.CopySourceVersionId)
	}
	if out.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption", string(out.ServerSideEncryption))
	}
	if out.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *out.SSEKMSKeyId)
	}
	if out.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *out.SSECustomerAlgorithm)
	}
	if out.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *out.SSECustomerKeyMD5)
	}
	if out.BucketKeyEnabled != nil {
		w.Header().Set("x-amz-server-side-encryption-bucket-key-enabled", boolString(*out.BucketKeyEnabled))
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<CopyPartResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if out.CopyPartResult != nil {
		if out.CopyPartResult.LastModified != nil {
			b.WriteString("<LastModified>" + formatS3Time(*out.CopyPartResult.LastModified) + "</LastModified>")
		}
		if out.CopyPartResult.ETag != nil {
			b.WriteString("<ETag>" + xmlEscape(*out.CopyPartResult.ETag) + "</ETag>")
		}
		if out.CopyPartResult.ChecksumCRC32 != nil {
			b.WriteString("<ChecksumCRC32>" + xmlEscape(*out.CopyPartResult.ChecksumCRC32) + "</ChecksumCRC32>")
		}
		if out.CopyPartResult.ChecksumCRC32C != nil {
			b.WriteString("<ChecksumCRC32C>" + xmlEscape(*out.CopyPartResult.ChecksumCRC32C) + "</ChecksumCRC32C>")
		}
		if out.CopyPartResult.ChecksumCRC64NVME != nil {
			b.WriteString("<ChecksumCRC64NVME>" + xmlEscape(*out.CopyPartResult.ChecksumCRC64NVME) + "</ChecksumCRC64NVME>")
		}
		if out.CopyPartResult.ChecksumSHA1 != nil {
			b.WriteString("<ChecksumSHA1>" + xmlEscape(*out.CopyPartResult.ChecksumSHA1) + "</ChecksumSHA1>")
		}
		if out.CopyPartResult.ChecksumSHA256 != nil {
			b.WriteString("<ChecksumSHA256>" + xmlEscape(*out.CopyPartResult.ChecksumSHA256) + "</ChecksumSHA256>")
		}
	}
	b.WriteString(`</CopyPartResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
}

func (s *server) handleDeleteObject(w http.ResponseWriter, r *http.Request, bucket, key string) {
	rules := rulesFromCtx(r)
	if !canWrite(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}
	if versionID := r.URL.Query().Get("versionId"); versionID != "" {
		in.VersionId = &versionID
	}
	if ifMatch := strings.TrimSpace(r.Header.Get("If-Match")); ifMatch != "" {
		in.IfMatch = &ifMatch
	}
	if expectedOwner := strings.TrimSpace(r.Header.Get("x-amz-expected-bucket-owner")); expectedOwner != "" {
		in.ExpectedBucketOwner = aws.String(expectedOwner)
	}
	if bypass, set, err := parseOptionalBool(r.Header.Get("x-amz-bypass-governance-retention")); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-bypass-governance-retention header")
		return
	} else if set {
		in.BypassGovernanceRetention = aws.Bool(bypass)
	}
	if payer, err := parseRequestPayerHeader(r.Header); err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid x-amz-request-payer header")
		return
	} else if payer != "" {
		in.RequestPayer = payer
	}

	out, err := s.up.DeleteObject(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}
	if out.DeleteMarker != nil {
		w.Header().Set("x-amz-delete-marker", boolString(*out.DeleteMarker))
	}
	if out.VersionId != nil {
		w.Header().Set("x-amz-version-id", *out.VersionId)
	}
	if out.RequestCharged != "" {
		w.Header().Set("x-amz-request-charged", string(out.RequestCharged))
	}
	w.WriteHeader(http.StatusNoContent)
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

func parseExpiresHeader(h http.Header) (*time.Time, error) {
	raw := strings.TrimSpace(h.Get("Expires"))
	if raw == "" {
		return nil, nil
	}
	t, err := http.ParseTime(raw)
	if err != nil {
		return nil, err
	}
	utc := t.UTC()
	return &utc, nil
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
	expires, err := parseExpiresHeader(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid Expires header")
		return
	}
	sse, err := parseSSEWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid server-side encryption headers")
		return
	}
	checksum, err := parseChecksumWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum headers")
		return
	}

	in := &s3.CreateMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &key,
		Metadata: meta,
		Expires:  expires,
	}
	if ct != "" {
		in.ContentType = &ct
	}
	if sse.ServerSideEncryption != "" {
		in.ServerSideEncryption = sse.ServerSideEncryption
	}
	in.SSEKMSKeyId = sse.SSEKMSKeyID
	in.SSEKMSEncryptionContext = sse.SSEKMSEncryptionContext
	in.SSECustomerAlgorithm = sse.SSECustomerAlgorithm
	in.SSECustomerKey = sse.SSECustomerKey
	in.SSECustomerKeyMD5 = sse.SSECustomerKeyMD5
	if checksum.ChecksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksum.ChecksumAlgorithm
	}

	out, err := s.up.CreateMultipartUpload(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
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

	verifier, err := chunkSignatureVerifierFromRequest(r, s.cfg.SigV4Secret)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Unsupported or invalid streaming payload signature")
		return
	}

	body, cl, err := decodeBodyForS3Write(r, verifier)
	if err != nil {
		if errors.Is(err, errContentLengthRequired) || errors.Is(err, errMissingDecodedContentLength) || errors.Is(err, errInvalidDecodedContentLength) {
			writeXMLError(w, http.StatusLengthRequired, "MissingContentLength", "Content-Length required")
			return
		}
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Invalid request body")
		return
	}
	defer body.Close()
	ssecAlgo, ssecKey, ssecMD5, hasSSEC, err := parseSSECustomerHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid SSE-C headers")
		return
	}
	checksum, err := parseChecksumWriteHeaders(r.Header)
	if err != nil {
		writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid checksum headers")
		return
	}
	contentMD5 := strings.TrimSpace(r.Header.Get("Content-MD5"))
	if contentMD5 != "" && checksum.ChecksumAlgorithm != "" {
		writeXMLError(w, http.StatusBadRequest, "InvalidRequest", "Content-MD5 cannot be combined with x-amz-checksum-algorithm")
		return
	}

	in := &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &key,
		UploadId:      &uploadID,
		PartNumber:    aws.Int32(partNumber),
		Body:          body,
		ContentLength: aws.Int64(cl),
	}
	if hasSSEC {
		in.SSECustomerAlgorithm = ssecAlgo
		in.SSECustomerKey = ssecKey
		in.SSECustomerKeyMD5 = ssecMD5
	}
	if checksum.ChecksumAlgorithm != "" {
		in.ChecksumAlgorithm = checksum.ChecksumAlgorithm
	}
	in.ChecksumCRC32 = checksum.ChecksumCRC32
	in.ChecksumCRC32C = checksum.ChecksumCRC32C
	in.ChecksumCRC64NVME = checksum.ChecksumCRC64NVME
	in.ChecksumSHA1 = checksum.ChecksumSHA1
	in.ChecksumSHA256 = checksum.ChecksumSHA256
	if contentMD5 != "" {
		in.ContentMD5 = aws.String(contentMD5)
	}

	out, err := s.up.UploadPart(r.Context(), in,
		// Allow streaming io.Reader without Seek. :contentReference[oaicite:11]{index=11}
		s3.WithAPIOptions(v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware),
	)
	if err != nil {
		if isChunkSignatureValidationError(err) {
			writeXMLError(w, http.StatusBadRequest, "SignatureDoesNotMatch", "Invalid aws-chunked chunk signature")
			return
		}
		writeUpstreamError(w, err)
		return
	}

	if out.ETag != nil {
		w.Header().Set("ETag", *out.ETag)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *server) handleListParts(w http.ResponseWriter, r *http.Request, bucket, key, uploadID string) {
	rules := rulesFromCtx(r)
	if !canRead(rules, bucket) {
		writeXMLError(w, http.StatusForbidden, "AccessDenied", "Forbidden")
		return
	}

	in := &s3.ListPartsInput{
		Bucket:   &bucket,
		Key:      &key,
		UploadId: &uploadID,
	}

	if pnmStr := r.URL.Query().Get("part-number-marker"); pnmStr != "" {
		pnm, err := strconv.Atoi(pnmStr)
		if err != nil || pnm < 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid part-number-marker")
			return
		}
		in.PartNumberMarker = aws.String(strconv.Itoa(pnm))
	}
	if mpStr := r.URL.Query().Get("max-parts"); mpStr != "" {
		mp, err := strconv.ParseInt(mpStr, 10, 32)
		if err != nil || mp <= 0 {
			writeXMLError(w, http.StatusBadRequest, "InvalidArgument", "invalid max-parts")
			return
		}
		in.MaxParts = aws.Int32(int32(mp))
	}

	out, err := s.up.ListParts(r.Context(), in)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString(`<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	b.WriteString("<Bucket>" + xmlEscape(bucket) + "</Bucket>")
	b.WriteString("<Key>" + xmlEscape(key) + "</Key>")
	b.WriteString("<UploadId>" + xmlEscape(uploadID) + "</UploadId>")
	b.WriteString("<PartNumberMarker>" + xmlEscape(aws.ToString(out.PartNumberMarker)) + "</PartNumberMarker>")
	b.WriteString("<NextPartNumberMarker>" + xmlEscape(aws.ToString(out.NextPartNumberMarker)) + "</NextPartNumberMarker>")
	b.WriteString("<MaxParts>" + strconv.Itoa(int(aws.ToInt32(out.MaxParts))) + "</MaxParts>")
	b.WriteString("<IsTruncated>")
	if aws.ToBool(out.IsTruncated) {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString("</IsTruncated>")
	for _, p := range out.Parts {
		b.WriteString("<Part>")
		b.WriteString("<PartNumber>" + strconv.Itoa(int(aws.ToInt32(p.PartNumber))) + "</PartNumber>")
		if p.LastModified != nil {
			b.WriteString("<LastModified>" + p.LastModified.UTC().Format("2006-01-02T15:04:05.000Z") + "</LastModified>")
		}
		if p.ETag != nil {
			b.WriteString("<ETag>" + xmlEscape(*p.ETag) + "</ETag>")
		}
		b.WriteString("<Size>" + strconv.FormatInt(aws.ToInt64(p.Size), 10) + "</Size>")
		b.WriteString("</Part>")
	}
	b.WriteString(`</ListPartsResult>`)

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(b.String()))
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
		etag := strings.TrimSpace(p.ETag)
		if p.PartNumber <= 0 || etag == "" {
			continue
		}
		if !strings.HasPrefix(etag, `"`) {
			etag = `"` + etag
		}
		if !strings.HasSuffix(etag, `"`) {
			etag = etag + `"`
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
		writeUpstreamError(w, err)
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
		writeUpstreamError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func effectiveShutdownTimeout(cfg Config) time.Duration {
	cfg.ApplyDefaults()
	return cfg.ShutdownTimeout
}

func newHTTPServer(cfg Config, handler http.Handler) *http.Server {
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

func main() {
	cfg := loadConfig()

	up, err := newUpstreamS3(context.Background(), cfg)
	if err != nil {
		log.Fatalf("init upstream s3: %v", err)
	}

	s := newServer(cfg, up)

	httpSrv := newHTTPServer(cfg, s.withAuth(s))

	log.Printf("listening on %s", cfg.ListenAddr)

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- httpSrv.ListenAndServe()
	}()

	shutdownSignalsCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serverErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
		return
	case <-shutdownSignalsCtx.Done():
		log.Printf("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), effectiveShutdownTimeout(cfg))
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		if closeErr := httpSrv.Close(); closeErr != nil {
			log.Printf("force close failed: %v", closeErr)
		}
	}

	if err := <-serverErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server shutdown error: %v", err)
	}
	log.Printf("server stopped")
}
