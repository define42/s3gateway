package sigv4

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ==================== SigV4 verify (minimal header-based) ====================
//
// We verify signatures using the secret derived from access key credentials.
// Real auth is then done by decoding accessKey -> upn:pass and binding to AD.
type SigV4Auth struct {
	AccessKey     string // #nosec G117 -- AccessKey is a public identifier, not a secret
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	SignatureHex  string
	AmzDate       string
}

var (
	ErrInvalidAmzDate             = errors.New("invalid x-amz-date")
	ErrSigV4DateScopeMismatch     = errors.New("credential scope date mismatch")
	ErrSigV4RequestOutsideMaxSkew = errors.New("request outside allowed time skew")
)

func ValidateSigV4RequestTime(auth *SigV4Auth, now time.Time, maxSkew time.Duration) error {
	amzTime, err := time.Parse("20060102T150405Z", strings.TrimSpace(auth.AmzDate))
	if err != nil {
		return ErrInvalidAmzDate
	}
	if auth.Date != amzTime.UTC().Format("20060102") {
		return ErrSigV4DateScopeMismatch
	}
	if maxSkew <= 0 {
		return nil
	}

	delta := now.UTC().Sub(amzTime.UTC())
	if delta > maxSkew || delta < -maxSkew {
		return ErrSigV4RequestOutsideMaxSkew
	}
	return nil
}

func ParseSigV4Authorization(r *http.Request) (*SigV4Auth, error) {
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

	return &SigV4Auth{
		AccessKey:     accessKey,
		Date:          date,
		Region:        region,
		Service:       service,
		SignedHeaders:  sh,
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

func VerifySigV4(r *http.Request, auth *SigV4Auth, secret string) error {
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		return errors.New("missing x-amz-content-sha256")
	}

	canonURI := CanonicalURI(r.URL.EscapedPath())
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

	signingKey := DeriveSigningKey(secret, auth.Date, auth.Region, auth.Service)
	gotSig := HmacSHA256Hex(signingKey, []byte(stringToSign))

	if !constantTimeEq(auth.SignatureHex, gotSig) {
		return errors.New("signature mismatch")
	}
	return nil
}

func CanonicalURI(escapedPath string) string {
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

func DeriveSigningKey(secret, date, region, service string) []byte {
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
func HmacSHA256Hex(key, data []byte) string {
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

var (
	ErrMissingDecodedContentLength = errors.New("missing x-amz-decoded-content-length")
	ErrInvalidDecodedContentLength = errors.New("invalid x-amz-decoded-content-length")
	ErrContentLengthRequired       = errors.New("content length required")
	ErrUnsupportedStreamingMode    = errors.New("unsupported streaming payload mode")
	ErrMissingSigV4AuthContext     = errors.New("missing sigv4 auth context")
	ErrMissingSigV4SecretContext   = errors.New("missing sigv4 secret context")
	ErrMissingChunkSignature       = errors.New("missing aws-chunked chunk signature")
	ErrInvalidChunkSignature       = errors.New("invalid aws-chunked chunk signature")
	ErrInvalidChunkHeader          = errors.New("invalid aws-chunked chunk header")
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
		return 0, ErrMissingDecodedContentLength
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, ErrInvalidDecodedContentLength
	}
	return n, nil
}

type AWSChunkSignatureVerifier struct {
	signingKey []byte
	amzDate    string
	scope      string
	PrevSig    string
}

func NewAWSChunkSignatureVerifier(auth *SigV4Auth, secret string) *AWSChunkSignatureVerifier {
	return &AWSChunkSignatureVerifier{
		signingKey: DeriveSigningKey(secret, auth.Date, auth.Region, auth.Service),
		amzDate:    auth.AmzDate,
		scope:      fmt.Sprintf("%s/%s/%s/aws4_request", auth.Date, auth.Region, auth.Service),
		PrevSig:    strings.ToLower(auth.SignatureHex),
	}
}

func (v *AWSChunkSignatureVerifier) verifyChunk(signatureHex string, chunk []byte) error {
	sig := strings.ToLower(strings.TrimSpace(signatureHex))
	if len(sig) != 64 {
		return fmt.Errorf("%w: invalid signature length", ErrInvalidChunkSignature)
	}
	if _, err := hex.DecodeString(sig); err != nil {
		return fmt.Errorf("%w: invalid signature encoding", ErrInvalidChunkSignature)
	}

	emptyHash := sha256.Sum256(nil)
	chunkHash := sha256.Sum256(chunk)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		v.amzDate,
		v.scope,
		v.PrevSig,
		hex.EncodeToString(emptyHash[:]),
		hex.EncodeToString(chunkHash[:]),
	}, "\n")

	expected := HmacSHA256Hex(v.signingKey, []byte(stringToSign))
	if !constantTimeEq(sig, expected) {
		return fmt.Errorf("%w: signature mismatch", ErrInvalidChunkSignature)
	}
	v.PrevSig = sig
	return nil
}

// CtxKey is the type used for context keys in the sigv4 package.
type CtxKey string

const (
	CtxSigV4AuthKey   CtxKey = "sigv4-auth"
	CtxSigV4SecretKey CtxKey = "sigv4-secret"
)

// SigV4AuthFromCtx retrieves the SigV4Auth from the request context.
func SigV4AuthFromCtx(r *http.Request) *SigV4Auth {
	v := r.Context().Value(CtxSigV4AuthKey)
	if v == nil {
		return nil
	}
	auth, _ := v.(*SigV4Auth)
	return auth
}

// SigV4SecretFromCtx retrieves the SigV4 secret from the request context.
func SigV4SecretFromCtx(r *http.Request) string {
	v := r.Context().Value(CtxSigV4SecretKey)
	if v == nil {
		return ""
	}
	secret, _ := v.(string)
	return secret
}

// WithSigV4Auth returns a context with the SigV4Auth set.
func WithSigV4Auth(ctx context.Context, auth *SigV4Auth) context.Context {
	return context.WithValue(ctx, CtxSigV4AuthKey, auth)
}

// WithSigV4Secret returns a context with the SigV4 secret set.
func WithSigV4Secret(ctx context.Context, secret string) context.Context {
	return context.WithValue(ctx, CtxSigV4SecretKey, secret)
}

func ChunkSignatureVerifierFromRequest(r *http.Request) (*AWSChunkSignatureVerifier, error) {
	if !isAWSChunkedPayload(r.Header) {
		return nil, nil
	}

	mode := streamingPayloadMode(r.Header)
	if mode != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedStreamingMode, mode)
	}

	auth := SigV4AuthFromCtx(r)
	if auth == nil {
		return nil, ErrMissingSigV4AuthContext
	}
	secret := SigV4SecretFromCtx(r)
	if strings.TrimSpace(secret) == "" {
		return nil, ErrMissingSigV4SecretContext
	}
	return NewAWSChunkSignatureVerifier(auth, secret), nil
}

func IsChunkSignatureValidationError(err error) bool {
	return errors.Is(err, ErrInvalidChunkSignature) ||
		errors.Is(err, ErrMissingChunkSignature) ||
		errors.Is(err, ErrInvalidChunkHeader)
}

type awsChunkedReadCloser struct {
	io.Reader
	c io.Closer
}

func (r *awsChunkedReadCloser) Close() error { return r.c.Close() }

type awsChunkedReader struct {
	br       *bufio.Reader
	verifier *AWSChunkSignatureVerifier
	buf      []byte
	offset   int
	done     bool
}

func newAWSChunkedReader(r io.Reader, verifier *AWSChunkSignatureVerifier) *awsChunkedReader {
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
				return ErrMissingChunkSignature
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
		return fmt.Errorf("%w: chunk too large", ErrInvalidChunkHeader)
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
			return ErrMissingChunkSignature
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
		return 0, "", fmt.Errorf("%w: empty chunk header", ErrInvalidChunkHeader)
	}
	parts := strings.Split(line, ";")
	chunkSizeHex := strings.TrimSpace(parts[0])
	if chunkSizeHex == "" {
		return 0, "", fmt.Errorf("%w: missing chunk size", ErrInvalidChunkHeader)
	}
	n, err := strconv.ParseInt(chunkSizeHex, 16, 64)
	if err != nil || n < 0 {
		return 0, "", fmt.Errorf("%w: invalid chunk size", ErrInvalidChunkHeader)
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

func DecodeBodyForS3Write(r *http.Request, verifier *AWSChunkSignatureVerifier) (io.ReadCloser, int64, error) {
	if isAWSChunkedPayload(r.Header) {
		mode := streamingPayloadMode(r.Header)
		if mode != "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" {
			return nil, 0, fmt.Errorf("%w: %s", ErrUnsupportedStreamingMode, mode)
		}
		if verifier == nil {
			return nil, 0, ErrMissingSigV4AuthContext
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
		return nil, 0, ErrContentLengthRequired
	}
	return r.Body, r.ContentLength, nil
}
