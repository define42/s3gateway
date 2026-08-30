// Package sigv4 parses and verifies AWS Signature Version 4 requests and
// decodes SigV4 streaming payloads used by S3 writes.
package sigv4

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- SHA-1 is one of the S3 trailing-checksum algorithms, not used for security
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Auth contains the credential scope and signature material parsed from a
// header-based SigV4 Authorization value.
type Auth struct {
	AccessKey     string // #nosec G117 -- AccessKey is a public identifier, not a secret
	Date          string
	Region        string
	Service       string
	SignedHeaders []string
	SignatureHex  string
	AmzDate       string
}

var (
	// ErrInvalidAmzDate indicates that x-amz-date is not a SigV4 timestamp.
	ErrInvalidAmzDate = errors.New("invalid x-amz-date")
	// ErrSigV4DateScopeMismatch indicates that the credential-scope date does
	// not match x-amz-date.
	ErrSigV4DateScopeMismatch = errors.New("credential scope date mismatch")
	// ErrSigV4RequestOutsideMaxSkew indicates that request time lies outside the
	// configured past-or-future tolerance.
	ErrSigV4RequestOutsideMaxSkew = errors.New("request outside allowed time skew")
	// ErrInvalidPayloadHash indicates that x-amz-content-sha256 is neither a
	// supported streaming mode nor a 64-character hexadecimal SHA-256 digest.
	ErrInvalidPayloadHash = errors.New("invalid x-amz-content-sha256")
	// ErrPayloadHashMismatch indicates that a non-streaming body did not match
	// its signed x-amz-content-sha256 digest.
	ErrPayloadHashMismatch = errors.New("request payload SHA-256 mismatch")
	// ErrUnsignedPayloadRequiresTLS prevents an on-path attacker from changing
	// an unsigned request body without invalidating its SigV4 signature.
	ErrUnsignedPayloadRequiresTLS = errors.New("UNSIGNED-PAYLOAD requires TLS")
	// ErrRequiredHeaderNotSigned indicates that an operation-changing header was
	// present but omitted from the SigV4 SignedHeaders set.
	ErrRequiredHeaderNotSigned = errors.New("security-relevant header is not signed")
)

// ValidateSigV4RequestTime checks timestamp syntax, agreement with the
// credential-scope date, and absolute clock skew. A non-positive maxSkew
// disables only the skew check. auth must be non-nil.
func ValidateSigV4RequestTime(auth *Auth, now time.Time, maxSkew time.Duration) error {
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

// ParseSigV4Authorization parses a header-based AWS4-HMAC-SHA256 authorization
// value and the required x-amz-date header. Access keys containing slashes are
// supported because the credential scope is parsed from the right.
func ParseSigV4Authorization(r *http.Request) (*Auth, error) {
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

	return &Auth{
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
	for p := range strings.SplitSeq(s, ",") {
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

// VerifySigV4 recomputes and compares a header-based request signature. It
// requires x-amz-content-sha256, every header named by auth.SignedHeaders, and
// signatures over headers that can change S3 operation semantics. Hexadecimal
// non-streaming payload hashes are verified as r.Body is consumed. auth must
// be non-nil.
func VerifySigV4(r *http.Request, auth *Auth, secret string) error {
	payloadHash := r.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		return errors.New("missing x-amz-content-sha256")
	}
	if err := requireSignedHeaders(r, auth.SignedHeaders); err != nil {
		return err
	}
	expectedPayloadHash, verifyPayload, err := parsePayloadHash(r, payloadHash)
	if err != nil {
		return err
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
	if verifyPayload {
		if r.ContentLength == 0 || r.Body == nil || r.Body == http.NoBody {
			emptyHash := sha256.Sum256(nil)
			if subtle.ConstantTimeCompare(expectedPayloadHash[:], emptyHash[:]) != 1 {
				return ErrPayloadHashMismatch
			}
			return nil
		}
		r.Body = newPayloadHashReadCloser(r.Body, expectedPayloadHash)
	}
	return nil
}

var requiredSignedHTTPHeaders = map[string]struct{}{
	"cache-control":       {},
	"content-disposition": {},
	"content-encoding":    {},
	"content-language":    {},
	"content-md5":         {},
	"content-type":        {},
	"expires":             {},
	"if-match":            {},
	"if-modified-since":   {},
	"if-none-match":       {},
	"if-unmodified-since": {},
	"range":               {},
}

func requireSignedHeaders(r *http.Request, signedHeaders []string) error {
	signed := make(map[string]struct{}, len(signedHeaders))
	for _, name := range signedHeaders {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			signed[name] = struct{}{}
		}
	}

	required := map[string]struct{}{"host": {}, "x-amz-date": {}}
	for name := range r.Header {
		name = strings.ToLower(name)
		if name == "x-amz-content-sha256" {
			// S3 implicitly includes this value as HashedPayload, so listing it
			// in SignedHeaders is optional.
			continue
		}
		if strings.HasPrefix(name, "x-amz-") {
			required[name] = struct{}{}
			continue
		}
		if _, ok := requiredSignedHTTPHeaders[name]; ok {
			required[name] = struct{}{}
		}
	}
	for name := range required {
		if _, ok := signed[name]; !ok {
			return fmt.Errorf("%w: %s", ErrRequiredHeaderNotSigned, name)
		}
	}
	return nil
}

func parsePayloadHash(r *http.Request, value string) ([sha256.Size]byte, bool, error) {
	var expected [sha256.Size]byte
	normalized := strings.TrimSpace(value)
	switch strings.ToUpper(normalized) {
	case StreamingSignedPayload, StreamingSignedPayloadTrailer:
		return expected, false, nil
	case StreamingUnsignedPayloadTrailer:
		if r.TLS == nil {
			return expected, false, ErrUnsignedPayloadRequiresTLS
		}
		return expected, false, nil
	case "UNSIGNED-PAYLOAD":
		if r.TLS == nil && r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody {
			return expected, false, ErrUnsignedPayloadRequiresTLS
		}
		return expected, false, nil
	}

	decoded, err := hex.DecodeString(normalized)
	if err != nil || len(decoded) != sha256.Size {
		return expected, false, ErrInvalidPayloadHash
	}
	copy(expected[:], decoded)
	return expected, true, nil
}

// CanonicalURI ensures an escaped request path is non-empty and begins with a
// slash. It preserves all other escaping and path structure.
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
	if r.ContentLength >= 0 {
		hm["content-length"] = strconv.FormatInt(r.ContentLength, 10)
	}

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

// DeriveSigningKey derives the SigV4 request-signing key for a credential
// scope.
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

// HmacSHA256Hex returns the lowercase hexadecimal HMAC-SHA256 of data.
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

const (
	// StreamingSignedPayload identifies signed aws-chunked data without signed
	// trailers.
	StreamingSignedPayload = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
	// StreamingSignedPayloadTrailer identifies signed aws-chunked data with a
	// signed trailer block.
	StreamingSignedPayloadTrailer = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
	// StreamingUnsignedPayloadTrailer identifies unsigned aws-chunked data whose
	// declared trailing checksums provide payload-integrity validation.
	StreamingUnsignedPayloadTrailer = "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
)

const (
	// Chunk header lines are ~90 bytes (hex size + chunk-signature extension);
	// trailer lines carry a base64 checksum or a 64-hex signature. The caps
	// keep a malicious stream from accumulating unbounded header/trailer data.
	maxChunkHeaderLineBytes = 4 * 1024
	maxTrailerLineBytes     = 16 * 1024
	maxTrailerLines         = 32
	// Signed chunks must be buffered until their signatures are verified. Keep
	// that attacker-controlled allocation bounded; AWS SDKs normally use much
	// smaller chunks (typically tens of KiB).
	maxSignedChunkBytes int64 = 16 * 1024 * 1024
)

var (
	// ErrMissingDecodedContentLength indicates that a streaming request omitted
	// x-amz-decoded-content-length.
	ErrMissingDecodedContentLength = errors.New("missing x-amz-decoded-content-length")
	// ErrInvalidDecodedContentLength indicates that the decoded content length
	// is not a non-negative base-10 integer.
	ErrInvalidDecodedContentLength = errors.New("invalid x-amz-decoded-content-length")
	// ErrDecodedContentLengthMismatch indicates that aws-chunked frame sizes do
	// not exactly match x-amz-decoded-content-length.
	ErrDecodedContentLengthMismatch = errors.New("aws-chunked decoded content length mismatch")
	// ErrContentLengthRequired indicates that a non-streaming write has unknown
	// content length.
	ErrContentLengthRequired = errors.New("content length required")
	// ErrUnsupportedStreamingMode indicates an unrecognized streaming
	// x-amz-content-sha256 value.
	ErrUnsupportedStreamingMode = errors.New("unsupported streaming payload mode")
	// ErrMissingSigV4AuthContext indicates that signed streaming validation lacks
	// parsed authentication context.
	ErrMissingSigV4AuthContext = errors.New("missing sigv4 auth context")
	// ErrMissingSigV4SecretContext indicates that signed streaming validation
	// lacks the request's derived signing secret.
	ErrMissingSigV4SecretContext = errors.New("missing sigv4 secret context")
	// ErrMissingChunkSignature indicates that a signed aws-chunked frame omitted
	// its chunk-signature extension.
	ErrMissingChunkSignature = errors.New("missing aws-chunked chunk signature")
	// ErrInvalidChunkSignature indicates malformed or mismatched chunk or trailer
	// signature data.
	ErrInvalidChunkSignature = errors.New("invalid aws-chunked chunk signature")
	// ErrInvalidChunkHeader indicates malformed aws-chunked size or framing data.
	ErrInvalidChunkHeader = errors.New("invalid aws-chunked chunk header")
	// ErrInvalidTrailer indicates malformed or excessive aws-chunked trailer
	// fields.
	ErrInvalidTrailer = errors.New("invalid aws-chunked trailer")
	// ErrMissingTrailerSignature indicates that signed-trailer mode ended without
	// x-amz-trailer-signature.
	ErrMissingTrailerSignature = errors.New("missing x-amz-trailer-signature")
	// ErrTrailerChecksumMismatch indicates that decoded payload bytes do not match
	// a declared trailing checksum.
	ErrTrailerChecksumMismatch = errors.New("aws-chunked trailing checksum mismatch")
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

// AWSChunkSignatureVerifier tracks the signature chain for one signed
// aws-chunked request body. It is stateful and not safe for concurrent use.
type AWSChunkSignatureVerifier struct {
	signingKey []byte
	amzDate    string
	scope      string
	PrevSig    string
}

// NewAWSChunkSignatureVerifier initializes a chunk-signature chain from the
// request's header signature. auth must be non-nil.
func NewAWSChunkSignatureVerifier(auth *Auth, secret string) *AWSChunkSignatureVerifier {
	return &AWSChunkSignatureVerifier{
		signingKey: DeriveSigningKey(secret, auth.Date, auth.Region, auth.Service),
		amzDate:    auth.AmzDate,
		scope:      fmt.Sprintf("%s/%s/%s/aws4_request", auth.Date, auth.Region, auth.Service),
		PrevSig:    strings.ToLower(auth.SignatureHex),
	}
}

func (v *AWSChunkSignatureVerifier) verifyChunk(signatureHex string, chunk []byte) error {
	sig, err := normalizeChunkSignature(signatureHex)
	if err != nil {
		return err
	}
	return v.verifyNormalizedChunk(sig, chunk)
}

func normalizeChunkSignature(signatureHex string) (string, error) {
	sig := strings.ToLower(strings.TrimSpace(signatureHex))
	if len(sig) != 64 {
		return "", fmt.Errorf("%w: invalid signature length", ErrInvalidChunkSignature)
	}
	if _, err := hex.DecodeString(sig); err != nil {
		return "", fmt.Errorf("%w: invalid signature encoding", ErrInvalidChunkSignature)
	}
	return sig, nil
}

func (v *AWSChunkSignatureVerifier) verifyNormalizedChunk(sig string, chunk []byte) error {
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

// verifyTrailerSignature verifies the x-amz-trailer-signature that terminates
// a STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER body. The signature chains from
// the final (zero-byte) chunk signature and covers the canonicalized trailing
// headers: "lowercase(name):trim(value)\n" per trailer, sorted by name.
func (v *AWSChunkSignatureVerifier) verifyTrailerSignature(signatureHex string, trailers [][2]string) error {
	sig := strings.ToLower(strings.TrimSpace(signatureHex))
	if len(sig) != 64 {
		return fmt.Errorf("%w: invalid trailer signature length", ErrInvalidChunkSignature)
	}
	if _, err := hex.DecodeString(sig); err != nil {
		return fmt.Errorf("%w: invalid trailer signature encoding", ErrInvalidChunkSignature)
	}

	entries := make([]string, 0, len(trailers))
	for _, kv := range trailers {
		entries = append(entries, kv[0]+":"+kv[1]+"\n")
	}
	sort.Strings(entries)
	blockHash := sha256.Sum256([]byte(strings.Join(entries, "")))
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256-TRAILER",
		v.amzDate,
		v.scope,
		v.PrevSig,
		hex.EncodeToString(blockHash[:]),
	}, "\n")

	expected := HmacSHA256Hex(v.signingKey, []byte(stringToSign))
	if !constantTimeEq(sig, expected) {
		return fmt.Errorf("%w: trailer signature mismatch", ErrInvalidChunkSignature)
	}
	v.PrevSig = sig
	return nil
}

// crc64NVMEPolynomial is crc64.MakeTable's representation of the CRC64-NVME
// polynomial (same constant the AWS SDK checksum package uses).
const crc64NVMEPolynomial = 0x9a6c9329ac4bc9b5

type trailerChecksum struct {
	name string
	hash hash.Hash
}

func newTrailerChecksumHash(name string) hash.Hash {
	switch name {
	case "x-amz-checksum-crc32":
		return crc32.NewIEEE()
	case "x-amz-checksum-crc32c":
		return crc32.New(crc32.MakeTable(crc32.Castagnoli))
	case "x-amz-checksum-crc64nvme":
		return crc64.New(crc64.MakeTable(crc64NVMEPolynomial))
	case "x-amz-checksum-sha1":
		return sha1.New() // #nosec G401 -- S3 trailing-checksum algorithm mandated by clients, not used for security
	case "x-amz-checksum-sha256":
		return sha256.New()
	default:
		return nil
	}
}

// trailerChecksumsForRequest returns a running hash per checksum algorithm the
// client declared in x-amz-trailer, so the decoded payload can be verified
// against the trailing checksum header. Unknown trailer names are ignored.
func trailerChecksumsForRequest(h http.Header) []trailerChecksum {
	var out []trailerChecksum
	seen := map[string]struct{}{}
	for _, v := range h.Values("x-amz-trailer") {
		for name := range strings.SplitSeq(v, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if _, dup := seen[name]; dup {
				continue
			}
			seen[name] = struct{}{}
			if hs := newTrailerChecksumHash(name); hs != nil {
				out = append(out, trailerChecksum{name: name, hash: hs})
			}
		}
	}
	return out
}

// CtxKey is the type used for context keys in the sigv4 package.
type CtxKey string

const (
	// CtxSigV4AuthKey stores parsed SigV4 authentication in a request context.
	CtxSigV4AuthKey CtxKey = "sigv4-auth"
	// CtxSigV4SecretKey stores the derived signing secret in a request context.
	CtxSigV4SecretKey CtxKey = "sigv4-secret"
)

// AuthFromRequest retrieves the Auth from the request context.
func AuthFromRequest(r *http.Request) *Auth {
	v := r.Context().Value(CtxSigV4AuthKey)
	if v == nil {
		return nil
	}
	auth, _ := v.(*Auth)
	return auth
}

// SecretFromRequest retrieves the SigV4 secret from the request context.
func SecretFromRequest(r *http.Request) string {
	v := r.Context().Value(CtxSigV4SecretKey)
	if v == nil {
		return ""
	}
	secret, _ := v.(string)
	return secret
}

// WithSigV4Auth returns a context with the Auth set.
func WithSigV4Auth(ctx context.Context, auth *Auth) context.Context {
	return context.WithValue(ctx, CtxSigV4AuthKey, auth)
}

// WithSigV4Secret returns a context with the SigV4 secret set.
func WithSigV4Secret(ctx context.Context, secret string) context.Context {
	return context.WithValue(ctx, CtxSigV4SecretKey, secret)
}

// ChunkSignatureVerifierFromRequest returns a verifier for signed streaming
// payload modes. Non-streaming and unsigned-trailer requests return nil; signed
// modes require Auth and secret values previously stored in the request context.
func ChunkSignatureVerifierFromRequest(r *http.Request) (*AWSChunkSignatureVerifier, error) {
	if !isAWSChunkedPayload(r.Header) {
		return nil, nil
	}

	switch mode := streamingPayloadMode(r.Header); mode {
	case StreamingSignedPayload, StreamingSignedPayloadTrailer:
		auth := AuthFromRequest(r)
		if auth == nil {
			return nil, ErrMissingSigV4AuthContext
		}
		secret := SecretFromRequest(r)
		if strings.TrimSpace(secret) == "" {
			return nil, ErrMissingSigV4SecretContext
		}
		return NewAWSChunkSignatureVerifier(auth, secret), nil
	case StreamingUnsignedPayloadTrailer:
		// Chunks carry no signatures; integrity comes from TLS plus the
		// trailing checksum, which the chunked reader verifies.
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedStreamingMode, mode)
	}
}

// IsChunkSignatureValidationError reports whether err represents aws-chunked
// framing, chunk-signature, or signed-trailer validation failure. Trailing
// checksum mismatches are classified separately.
func IsChunkSignatureValidationError(err error) bool {
	return errors.Is(err, ErrInvalidChunkSignature) ||
		errors.Is(err, ErrMissingChunkSignature) ||
		errors.Is(err, ErrInvalidChunkHeader) ||
		errors.Is(err, ErrDecodedContentLengthMismatch) ||
		errors.Is(err, ErrMissingTrailerSignature) ||
		errors.Is(err, ErrInvalidTrailer)
}

// IsTrailerChecksumMismatchError reports whether err means the decoded payload
// did not match the client's trailing x-amz-checksum-* header (S3: BadDigest).
func IsTrailerChecksumMismatchError(err error) bool {
	return errors.Is(err, ErrTrailerChecksumMismatch)
}

type awsChunkedReadCloser struct {
	reader *awsChunkedReader
	guard  trailerGuardReader
	c      io.Closer
}

func (r *awsChunkedReadCloser) Read(p []byte) (int, error) { return r.guard.Read(p) }

func (r *awsChunkedReadCloser) Close() error {
	if r.reader != nil {
		r.reader.releaseChunkBuffer()
	}
	return r.c.Close()
}

func (r *awsChunkedReadCloser) validationError() error {
	if r.reader == nil {
		return nil
	}
	return r.reader.err
}

type payloadHashReader struct {
	r        io.Reader
	hash     hash.Hash
	expected [sha256.Size]byte
	err      error
}

func (r *payloadHashReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err := r.r.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
	}
	if errors.Is(err, io.EOF) {
		actual := r.hash.Sum(nil)
		if subtle.ConstantTimeCompare(actual, r.expected[:]) != 1 {
			r.err = ErrPayloadHashMismatch
			return n, r.err
		}
	} else if err != nil {
		r.err = err
	}
	return n, err
}

type payloadHashReadCloser struct {
	reader *payloadHashReader
	guard  trailerGuardReader
	c      io.Closer
}

func newPayloadHashReadCloser(body io.ReadCloser, expected [sha256.Size]byte) *payloadHashReadCloser {
	reader := &payloadHashReader{
		r:        body,
		hash:     sha256.New(),
		expected: expected,
	}
	return &payloadHashReadCloser{
		reader: reader,
		guard:  trailerGuardReader{r: reader},
		c:      body,
	}
}

func (r *payloadHashReadCloser) Read(p []byte) (int, error) { return r.guard.Read(p) }

func (r *payloadHashReadCloser) Close() error { return r.c.Close() }

func (r *payloadHashReadCloser) validationError() error {
	if r.reader == nil {
		return nil
	}
	return r.reader.err
}

// trailerGuardReader delays the final byte of the decoded stream until the
// underlying chunked reader reports a clean EOF, i.e. until every
// end-of-stream validation (final chunk signature, trailer signature,
// trailing checksums) has passed. Without it the upstream would hold a
// complete body — and could commit the object — before a bad trailer is
// discovered; with it, a failed validation leaves the upstream one byte short
// of Content-Length, so the upstream write is aborted instead of committed.
type trailerGuardReader struct {
	r         io.Reader
	carry     byte
	haveCarry bool
	err       error
}

func (g *trailerGuardReader) Read(p []byte) (int, error) {
	if g.err != nil {
		if !errors.Is(g.err, io.EOF) || !g.haveCarry {
			return 0, g.err
		}
		if len(p) == 0 {
			return 0, nil
		}
		// The underlying reader returned data and EOF together. Validation
		// therefore passed, so the remaining held byte is safe to release.
		p[0] = g.carry
		g.haveCarry = false
		return 1, nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	for {
		hadCarry := g.haveCarry
		if hadCarry && len(p) == 1 {
			// Read the next byte into p, then restore the existing carry. Once
			// another byte exists, the carry is known not to be final and is safe
			// to emit. This avoids both a heap-backed scratch byte and a memmove.
			carry := g.carry
			n, err := g.r.Read(p)
			if n > 0 {
				next := p[0]
				p[0] = carry
				if err != nil {
					g.err = err
					if errors.Is(err, io.EOF) {
						g.carry = next
						return 1, nil
					}
					g.haveCarry = false
					return 1, nil
				}
				g.carry = next
				return 1, nil
			}

			p[0] = carry
			if err == nil {
				continue
			}
			g.err = err
			g.haveCarry = false
			if errors.Is(err, io.EOF) {
				return 1, nil
			}
			return 0, err
		}

		dst := p
		if hadCarry {
			p[0] = g.carry
			// Read directly behind the carry. In the steady state this
			// replaces the old overlapping full-buffer copy.
			dst = p[1:]
		}

		n, err := g.r.Read(dst)
		if n > 0 {
			if err != nil {
				g.err = err
				if errors.Is(err, io.EOF) {
					// EOF validates every byte returned by this read.
					g.haveCarry = false
					if hadCarry {
						return n + 1, nil
					}
					return n, nil
				}

				// Validation failed. Exclude the final new byte, but return
				// any preceding bytes before surfacing the error next time.
				g.haveCarry = false
				safe := n - 1
				if hadCarry {
					safe++
				}
				if safe > 0 {
					return safe, nil
				}
				return 0, err
			}

			g.carry = dst[n-1]
			g.haveCarry = true
			safe := n - 1
			if hadCarry {
				safe++
			}
			if safe > 0 {
				return safe, nil
			}
			continue
		}
		if err == nil {
			continue
		}
		g.err = err
		g.haveCarry = false
		if errors.Is(err, io.EOF) && hadCarry {
			return 1, nil
		}
		return 0, err
	}
}

// StreamValidationError returns the payload validation error the request body
// hit while being streamed upstream, if any. The upstream SDK may mask body-
// reader errors (e.g. behind "failed to rewind transport stream for retry"),
// so handlers should consult this to classify the failure.
func StreamValidationError(body io.ReadCloser) error {
	source, ok := body.(interface{ validationError() error })
	if !ok {
		return nil
	}
	return source.validationError()
}

type awsChunkedReader struct {
	br *bufio.Reader
	// verifier is nil in unsigned-trailer mode, where chunk headers carry no
	// signatures.
	verifier *AWSChunkSignatureVerifier
	// signedTrailer requires and verifies an x-amz-trailer-signature after the
	// final chunk (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER).
	signedTrailer bool
	// checksums are running hashes of the decoded payload, verified against
	// the trailing x-amz-checksum-* header(s) in the trailer modes.
	checksums []trailerChecksum
	// decodedBytes is compared with the declared decoded length before each
	// chunk is accepted and again when the final zero-length chunk arrives.
	expectedDecodedBytes int64
	decodedBytes         int64

	// Signed chunks are buffered so their signature is verified before any
	// byte is handed out. The backing array is retained across chunks within
	// this request and released on a terminal read or Close.
	buf    []byte
	offset int
	// Unsigned chunks are streamed through without buffering (SDKs may send
	// the whole payload as a single chunk); remaining counts the bytes left in
	// the current chunk and needCRLF marks its unconsumed trailing CRLF.
	remaining int64
	needCRLF  bool
	done      bool
	// err records the first non-EOF error so callers can still classify the
	// failure after the consuming SDK has wrapped or replaced it.
	err error
}

func newAWSChunkedReader(r io.Reader, verifier *AWSChunkSignatureVerifier, signedTrailer bool, checksums []trailerChecksum, decodedLen int64) *awsChunkedReader {
	return &awsChunkedReader{
		br:                   bufio.NewReader(r),
		verifier:             verifier,
		signedTrailer:        signedTrailer,
		checksums:            checksums,
		expectedDecodedBytes: decodedLen,
	}
}

func (r *awsChunkedReader) Read(p []byte) (int, error) {
	n, err := r.read(p)
	if err != nil && r.err == nil && !errors.Is(err, io.EOF) {
		r.err = err
	}
	if err != nil {
		r.releaseChunkBuffer()
	}
	return n, err
}

func (r *awsChunkedReader) releaseChunkBuffer() {
	r.buf = nil
	r.offset = 0
}

func (r *awsChunkedReader) read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	for {
		if r.offset < len(r.buf) {
			n := copy(p, r.buf[r.offset:])
			r.offset += n
			if r.offset == len(r.buf) {
				// Keep the backing array for the next signed chunk in this request.
				r.buf = r.buf[:0]
				r.offset = 0
			}
			return n, nil
		}
		if r.remaining > 0 {
			limit := len(p)
			if int64(limit) > r.remaining {
				limit = int(r.remaining)
			}
			n, err := r.br.Read(p[:limit])
			if n > 0 {
				r.remaining -= int64(n)
				r.decodedBytes += int64(n)
				r.hashPayload(p[:n])
				return n, nil
			}
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if r.done {
			return 0, io.EOF
		}
		if err := r.beginChunk(); err != nil {
			return 0, err
		}
	}
}

func (r *awsChunkedReader) hashPayload(b []byte) {
	for _, cs := range r.checksums {
		_, _ = cs.hash.Write(b)
	}
}

func (r *awsChunkedReader) beginChunk() error {
	if r.needCRLF {
		if err := r.consumeCRLF(); err != nil {
			return err
		}
		r.needCRLF = false
	}
	line, err := readLineBounded(r.br, maxChunkHeaderLineBytes)
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
		if r.decodedBytes != r.expectedDecodedBytes {
			return fmt.Errorf("%w: got %d bytes, expected %d", ErrDecodedContentLengthMismatch, r.decodedBytes, r.expectedDecodedBytes)
		}
		if err := r.finishTrailers(); err != nil {
			return err
		}
		r.done = true
		return nil
	}
	if r.verifier != nil && n > maxSignedChunkBytes {
		return fmt.Errorf("%w: signed chunk exceeds %d-byte limit", ErrInvalidChunkHeader, maxSignedChunkBytes)
	}
	if r.decodedBytes > r.expectedDecodedBytes || n > r.expectedDecodedBytes-r.decodedBytes {
		return fmt.Errorf("%w: chunk of %d bytes exceeds %d remaining bytes", ErrDecodedContentLengthMismatch, n, r.expectedDecodedBytes-r.decodedBytes)
	}

	if r.verifier == nil {
		// Unsigned chunk: stream it through instead of buffering.
		r.remaining = n
		r.needCRLF = true
		return nil
	}

	if sig == "" {
		return ErrMissingChunkSignature
	}
	normalizedSig, err := normalizeChunkSignature(sig)
	if err != nil {
		return err
	}
	chunkLen := int(n)
	if cap(r.buf) < chunkLen {
		// Signed chunks can be multi-megabyte. Retain the high-water capacity
		// only for this request instead of putting large buffers in a global pool.
		r.buf = make([]byte, 0, chunkLen)
	}
	chunk := r.buf[:chunkLen]
	if _, err := io.ReadFull(r.br, chunk); err != nil {
		return err
	}
	if err := r.consumeCRLF(); err != nil {
		return err
	}

	if err := r.verifier.verifyNormalizedChunk(normalizedSig, chunk); err != nil {
		return err
	}
	r.decodedBytes += n
	r.hashPayload(chunk)

	r.buf = chunk
	r.offset = 0
	return nil
}

// readLineBounded reads up to and including a '\n', returning the line without
// the '\n' (a trailing '\r' is kept for the caller to strip). Lines longer
// than maxLen fail instead of accumulating unbounded data.
func readLineBounded(br *bufio.Reader, maxLen int) (string, error) {
	var b strings.Builder
	for {
		c, err := br.ReadByte()
		if err != nil {
			return b.String(), err
		}
		if c == '\n' {
			return b.String(), nil
		}
		if b.Len() >= maxLen {
			return "", fmt.Errorf("%w: line too long", ErrInvalidChunkHeader)
		}
		b.WriteByte(c)
	}
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

// finishTrailers handles everything after the final zero-length chunk header.
func (r *awsChunkedReader) finishTrailers() error {
	if r.verifier != nil && !r.signedTrailer {
		// Plain signed streaming: no declared trailers; skip padding lines
		// until the terminating blank line, as before.
		return r.consumeTrailers()
	}

	trailers, trailerSig, err := r.readTrailerSection()
	if err != nil {
		return err
	}
	if r.signedTrailer {
		if trailerSig == "" {
			return ErrMissingTrailerSignature
		}
		if err := r.verifier.verifyTrailerSignature(trailerSig, trailers); err != nil {
			return err
		}
	}
	return r.verifyTrailingChecksums(trailers)
}

// readTrailerSection parses "name:value" trailer lines after the final chunk.
// It tolerates both CRLF and bare-LF line endings and a stream that ends at
// EOF instead of a blank line (framings seen from the AWS SDKs and minio-go).
func (r *awsChunkedReader) readTrailerSection() (trailers [][2]string, trailerSig string, err error) {
	for range maxTrailerLines {
		line, err := readLineBounded(r.br, maxTrailerLineBytes)
		eof := false
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, "", err
			}
			eof = true
		}
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			if !eof && r.signedTrailer && trailerSig == "" {
				// minio-go writes a CRLF separator between the trailing
				// headers and the x-amz-trailer-signature line.
				continue
			}
			return trailers, trailerSig, nil
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, "", fmt.Errorf("%w: malformed trailer line", ErrInvalidTrailer)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "x-amz-trailer-signature" {
			trailerSig = value
			if r.signedTrailer {
				// The signature terminates the section; drain the optional
				// final blank line so the body is fully consumed.
				r.discardOptionalBlankLine()
				return trailers, trailerSig, nil
			}
		} else {
			trailers = append(trailers, [2]string{name, value})
		}
		if eof {
			return trailers, trailerSig, nil
		}
	}
	return nil, "", fmt.Errorf("%w: too many trailer lines", ErrInvalidTrailer)
}

func (r *awsChunkedReader) discardOptionalBlankLine() {
	if b, err := r.br.Peek(2); err == nil && b[0] == '\r' && b[1] == '\n' {
		_, _ = r.br.Discard(2)
		return
	}
	if b, err := r.br.Peek(1); err == nil && b[0] == '\n' {
		_, _ = r.br.Discard(1)
	}
}

func (r *awsChunkedReader) verifyTrailingChecksums(trailers [][2]string) error {
	for _, kv := range trailers {
		for _, cs := range r.checksums {
			if cs.name != kv[0] {
				continue
			}
			want := base64.StdEncoding.EncodeToString(cs.hash.Sum(nil))
			if kv[1] != want {
				return fmt.Errorf("%w: %s", ErrTrailerChecksumMismatch, cs.name)
			}
		}
	}
	return nil
}

func (r *awsChunkedReader) consumeTrailers() error {
	for range maxTrailerLines {
		line, err := readLineBounded(r.br, maxTrailerLineBytes)
		if err != nil {
			return err
		}
		if line == "" || line == "\r" {
			return nil
		}
	}
	return fmt.Errorf("%w: too many trailer lines", ErrInvalidTrailer)
}

// DecodeBodyForS3Write returns a request body and decoded content length
// suitable for an upstream S3 write. Streaming bodies are decoded as they are
// read; chunk signatures, signed trailers, and declared trailing checksums are
// validated before the final payload byte is released. Non-streaming bodies
// require a known Content-Length.
func DecodeBodyForS3Write(r *http.Request, verifier *AWSChunkSignatureVerifier) (io.ReadCloser, int64, error) {
	if isAWSChunkedPayload(r.Header) {
		mode := streamingPayloadMode(r.Header)
		signedTrailer := false
		var checksums []trailerChecksum
		switch mode {
		case StreamingSignedPayload:
			if verifier == nil {
				return nil, 0, ErrMissingSigV4AuthContext
			}
		case StreamingSignedPayloadTrailer:
			if verifier == nil {
				return nil, 0, ErrMissingSigV4AuthContext
			}
			signedTrailer = true
			checksums = trailerChecksumsForRequest(r.Header)
		case StreamingUnsignedPayloadTrailer:
			verifier = nil
			checksums = trailerChecksumsForRequest(r.Header)
		default:
			return nil, 0, fmt.Errorf("%w: %s", ErrUnsupportedStreamingMode, mode)
		}
		decodedLen, err := parseDecodedContentLength(r.Header)
		if err != nil {
			return nil, 0, err
		}
		reader := newAWSChunkedReader(r.Body, verifier, signedTrailer, checksums, decodedLen)
		rc := &awsChunkedReadCloser{
			reader: reader,
			guard:  trailerGuardReader{r: reader},
			c:      r.Body,
		}
		if decodedLen == 0 {
			// A zero-length payload has no byte the trailer guard could hold
			// back, and the upstream request body is complete the moment it
			// starts. Validate the whole (payload-free) stream up front so an
			// invalid trailer fails before any upstream write begins.
			if _, err := io.Copy(io.Discard, rc); err != nil {
				return nil, 0, err
			}
		}
		return rc, decodedLen, nil
	}
	if r.ContentLength < 0 {
		return nil, 0, ErrContentLengthRequired
	}
	return r.Body, r.ContentLength, nil
}
