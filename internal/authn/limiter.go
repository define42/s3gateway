// Package authn contains shared authentication resource controls.
package authn

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

var (
	// ErrLimited reports that an authentication attempt was rejected before
	// reaching the identity backend because its resource budget was exhausted.
	ErrLimited = errors.New("authentication temporarily limited")
	// ErrRejectedCredentials reports a definitive identity-backend rejection
	// that may be safely cached for the exact credential pair.
	ErrRejectedCredentials = errors.New("authentication credentials rejected")
)

// Limits configures layered authentication admission control. Reserved limits
// are carved out of the global totals and are available only to credentials
// that previously authenticated successfully.
type Limits struct {
	MaxConcurrent int
	RatePerSecond int
	Burst         int

	ReservedConcurrent    int
	ReservedRatePerSecond int
	ReservedBurst         int

	PerClientMaxConcurrent int
	PerClientRatePerSecond int
	PerClientBurst         int

	PerPrincipalMaxConcurrent int
	PerPrincipalRatePerSecond int
	PerPrincipalBurst         int

	IngressPerClientRatePerSecond int
	IngressPerClientBurst         int

	MaxKeys              int
	TrustedCredentialTTL time.Duration
}

// Attempt contains opaque digests used to apply per-client and per-principal
// limits. It deliberately retains neither the principal nor the password.
type Attempt struct {
	clientKey     [sha256.Size]byte
	principalKey  [sha256.Size]byte
	credentialKey [sha256.Size]byte
}

// NewAttempt builds a limiter key for one authentication attempt. Principal
// casing and surrounding whitespace are normalized so they cannot be used to
// bypass per-principal limits.
func NewAttempt(clientIP, principal, password string) Attempt {
	principal = strings.ToLower(strings.TrimSpace(principal))
	return Attempt{
		clientKey:     limiterDigest("client", strings.TrimSpace(clientIP)),
		principalKey:  limiterDigest("principal", principal),
		credentialKey: limiterDigest("credential", principal, password),
	}
}

func limiterDigest(parts ...string) [sha256.Size]byte {
	hasher := sha256.New()
	var encodedLength [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(encodedLength[:], uint64(len(part)))
		_, _ = hasher.Write(encodedLength[:])
		_, _ = io.WriteString(hasher, part)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

func (b *tokenBucket) refill(now time.Time, tokensPerSecond, burst float64) {
	if b.lastRefill.IsZero() {
		b.tokens = burst
		b.lastRefill = now
		return
	}
	if elapsed := now.Sub(b.lastRefill); elapsed > 0 {
		b.tokens += elapsed.Seconds() * tokensPerSecond
		if b.tokens > burst {
			b.tokens = burst
		}
		b.lastRefill = now
	}
}

type resourcePool struct {
	maxConcurrent   int
	inFlight        int
	tokensPerSecond float64
	burst           float64
	bucket          tokenBucket
}

func newResourcePool(maxConcurrent, ratePerSecond, burst int) resourcePool {
	return resourcePool{
		maxConcurrent:   maxConcurrent,
		tokensPerSecond: float64(ratePerSecond),
		burst:           float64(burst),
	}
}

func (p *resourcePool) available(now time.Time) bool {
	if p.maxConcurrent <= 0 || p.tokensPerSecond <= 0 || p.burst <= 0 {
		return false
	}
	p.bucket.refill(now, p.tokensPerSecond, p.burst)
	return p.inFlight < p.maxConcurrent && p.bucket.tokens >= 1
}

func (p *resourcePool) acquire() {
	p.inFlight++
	p.bucket.tokens--
}

type keyedState struct {
	key        [sha256.Size]byte
	inFlight   int
	bucket     tokenBucket
	lruElement *list.Element
}

// keyedLimiter is a bounded LRU of per-key token buckets and concurrency
// counters. Entries with in-flight work are never evicted.
type keyedLimiter struct {
	states          map[[sha256.Size]byte]*keyedState
	lru             list.List
	maxEntries      int
	maxConcurrent   int
	tokensPerSecond float64
	burst           float64
}

func newKeyedLimiter(maxEntries, maxConcurrent, ratePerSecond, burst int) keyedLimiter {
	return keyedLimiter{
		states:          make(map[[sha256.Size]byte]*keyedState),
		maxEntries:      maxEntries,
		maxConcurrent:   maxConcurrent,
		tokensPerSecond: float64(ratePerSecond),
		burst:           float64(burst),
	}
}

func (l *keyedLimiter) state(key [sha256.Size]byte) *keyedState {
	if state, ok := l.states[key]; ok {
		l.lru.MoveToFront(state.lruElement)
		return state
	}

	for len(l.states) >= l.maxEntries {
		var victim *list.Element
		for element := l.lru.Back(); element != nil; element = element.Prev() {
			state, ok := element.Value.(*keyedState)
			if ok && state.inFlight == 0 {
				victim = element
				break
			}
		}
		if victim == nil {
			return nil
		}
		state, _ := victim.Value.(*keyedState)
		delete(l.states, state.key)
		l.lru.Remove(victim)
	}

	state := &keyedState{key: key}
	state.lruElement = l.lru.PushFront(state)
	l.states[key] = state
	return state
}

func (l *keyedLimiter) available(state *keyedState, now time.Time) bool {
	if state == nil || l.maxConcurrent <= 0 || l.tokensPerSecond <= 0 || l.burst <= 0 {
		return false
	}
	state.bucket.refill(now, l.tokensPerSecond, l.burst)
	return state.inFlight < l.maxConcurrent && state.bucket.tokens >= 1
}

func (l *keyedLimiter) acquire(state *keyedState) {
	state.inFlight++
	state.bucket.tokens--
}

func (l *keyedLimiter) release(state *keyedState) {
	if state != nil && state.inFlight > 0 {
		state.inFlight--
	}
}

func (l *keyedLimiter) allow(key [sha256.Size]byte, now time.Time) bool {
	state := l.state(key)
	if !l.available(state, now) {
		return false
	}
	l.acquire(state)
	l.release(state)
	return true
}

func (l *keyedLimiter) refund(key [sha256.Size]byte, now time.Time) {
	state := l.state(key)
	if state == nil {
		return
	}
	state.bucket.refill(now, l.tokensPerSecond, l.burst)
	state.bucket.tokens = min(state.bucket.tokens+1, l.burst)
}

type trustedCredential struct {
	key        [sha256.Size]byte
	expires    time.Time
	lruElement *list.Element
}

// Limiter enforces early per-client rate limiting, per-client and
// per-principal fairness, and partitioned global backend capacity. It is safe
// for concurrent use.
type Limiter struct {
	mu sync.Mutex

	sharedPool   resourcePool
	reservedPool resourcePool
	clients      keyedLimiter
	principals   keyedLimiter
	ingress      keyedLimiter

	trustedCredentialTTL time.Duration
	trustedCredentials   map[[sha256.Size]byte]*trustedCredential
	trustedLRU           list.List
	maxKeys              int
	now                  func() time.Time
}

// NewLimiter constructs a layered authentication limiter. Non-positive
// settings are clamped to safe minimums so callers that skipped configuration
// validation fail closed without panicking.
func NewLimiter(limits Limits) *Limiter {
	limits = normalizeLimits(limits)
	sharedConcurrent := limits.MaxConcurrent - limits.ReservedConcurrent
	sharedRate := limits.RatePerSecond - limits.ReservedRatePerSecond
	sharedBurst := limits.Burst - limits.ReservedBurst

	return &Limiter{
		sharedPool: newResourcePool(
			sharedConcurrent,
			sharedRate,
			sharedBurst,
		),
		reservedPool: newResourcePool(
			limits.ReservedConcurrent,
			limits.ReservedRatePerSecond,
			limits.ReservedBurst,
		),
		clients: newKeyedLimiter(
			limits.MaxKeys,
			limits.PerClientMaxConcurrent,
			limits.PerClientRatePerSecond,
			limits.PerClientBurst,
		),
		principals: newKeyedLimiter(
			limits.MaxKeys,
			limits.PerPrincipalMaxConcurrent,
			limits.PerPrincipalRatePerSecond,
			limits.PerPrincipalBurst,
		),
		ingress: newKeyedLimiter(
			limits.MaxKeys,
			1,
			limits.IngressPerClientRatePerSecond,
			limits.IngressPerClientBurst,
		),
		trustedCredentialTTL: limits.TrustedCredentialTTL,
		trustedCredentials:   make(map[[sha256.Size]byte]*trustedCredential),
		maxKeys:              limits.MaxKeys,
		now:                  time.Now,
	}
}

func normalizeLimits(limits Limits) Limits {
	limits.MaxConcurrent = atLeastOne(limits.MaxConcurrent)
	limits.RatePerSecond = atLeastOne(limits.RatePerSecond)
	limits.Burst = atLeastOne(limits.Burst)
	limits.MaxKeys = atLeastOne(limits.MaxKeys)
	if limits.TrustedCredentialTTL <= 0 {
		limits.TrustedCredentialTTL = time.Minute
	}

	reservePossible := limits.MaxConcurrent > 1 && limits.RatePerSecond > 1 && limits.Burst > 1
	if !reservePossible {
		limits.ReservedConcurrent = 0
		limits.ReservedRatePerSecond = 0
		limits.ReservedBurst = 0
	} else {
		limits.ReservedConcurrent = clampReserve(limits.ReservedConcurrent, limits.MaxConcurrent)
		limits.ReservedRatePerSecond = clampReserve(limits.ReservedRatePerSecond, limits.RatePerSecond)
		limits.ReservedBurst = clampReserve(limits.ReservedBurst, limits.Burst)
		if limits.ReservedConcurrent == 0 || limits.ReservedRatePerSecond == 0 || limits.ReservedBurst == 0 {
			limits.ReservedConcurrent = 0
			limits.ReservedRatePerSecond = 0
			limits.ReservedBurst = 0
		}
	}

	limits.PerClientMaxConcurrent = atLeastOne(limits.PerClientMaxConcurrent)
	limits.PerClientRatePerSecond = atLeastOne(limits.PerClientRatePerSecond)
	limits.PerClientBurst = atLeastOne(limits.PerClientBurst)
	limits.PerPrincipalMaxConcurrent = atLeastOne(limits.PerPrincipalMaxConcurrent)
	limits.PerPrincipalRatePerSecond = atLeastOne(limits.PerPrincipalRatePerSecond)
	limits.PerPrincipalBurst = atLeastOne(limits.PerPrincipalBurst)
	limits.IngressPerClientRatePerSecond = atLeastOne(limits.IngressPerClientRatePerSecond)
	limits.IngressPerClientBurst = atLeastOne(limits.IngressPerClientBurst)
	return limits
}

func atLeastOne(value int) int {
	if value <= 0 {
		return 1
	}
	return value
}

func clampReserve(value, total int) int {
	if value <= 0 {
		return 0
	}
	if value >= total {
		return total - 1
	}
	return value
}

// AllowIngress consumes one early per-client request token. Callers should do
// this before parsing authentication material or reading a login body.
func (l *Limiter) AllowIngress(clientIP string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ingress.allow(limiterDigest("client", strings.TrimSpace(clientIP)), l.now())
}

// RefundIngress restores the early admission token for a request that
// authenticated successfully. This makes ingress limiting penalize anonymous
// failures without imposing a sustained request-rate ceiling on valid cached
// traffic.
func (l *Limiter) RefundIngress(clientIP string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ingress.refund(limiterDigest("client", strings.TrimSpace(clientIP)), l.now())
}

// TryAcquire reserves per-client, per-principal, and global backend capacity.
// It never waits. Previously authenticated credentials may fall back to the
// reserved global pool when the shared pool is exhausted.
func (l *Limiter) TryAcquire(attempt Attempt) (release func(), err error) {
	if l == nil {
		return func() {}, nil
	}

	l.mu.Lock()
	now := l.now()
	client := l.clients.state(attempt.clientKey)
	principal := l.principals.state(attempt.principalKey)
	if !l.clients.available(client, now) || !l.principals.available(principal, now) {
		l.mu.Unlock()
		return nil, ErrLimited
	}

	pool := &l.sharedPool
	if !pool.available(now) {
		if !l.isTrustedLocked(attempt.credentialKey, now) || !l.reservedPool.available(now) {
			l.mu.Unlock()
			return nil, ErrLimited
		}
		pool = &l.reservedPool
	}

	l.clients.acquire(client)
	l.principals.acquire(principal)
	pool.acquire()
	l.mu.Unlock()

	return sync.OnceFunc(func() {
		l.mu.Lock()
		l.clients.release(client)
		l.principals.release(principal)
		if pool.inFlight > 0 {
			pool.inFlight--
		}
		l.mu.Unlock()
	}), nil
}

// MarkAuthenticated makes a credential eligible for reserved capacity for a
// bounded period. Call it only after the identity backend succeeds.
func (l *Limiter) MarkAuthenticated(attempt Attempt) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if credential, ok := l.trustedCredentials[attempt.credentialKey]; ok {
		credential.expires = now.Add(l.trustedCredentialTTL)
		l.trustedLRU.MoveToFront(credential.lruElement)
		return
	}
	for len(l.trustedCredentials) >= l.maxKeys {
		victim := l.trustedLRU.Back()
		if victim == nil {
			return
		}
		credential, _ := victim.Value.(*trustedCredential)
		delete(l.trustedCredentials, credential.key)
		l.trustedLRU.Remove(victim)
	}
	credential := &trustedCredential{
		key:     attempt.credentialKey,
		expires: now.Add(l.trustedCredentialTTL),
	}
	credential.lruElement = l.trustedLRU.PushFront(credential)
	l.trustedCredentials[credential.key] = credential
}

func (l *Limiter) isTrustedLocked(key [sha256.Size]byte, now time.Time) bool {
	credential, ok := l.trustedCredentials[key]
	if !ok {
		return false
	}
	if now.After(credential.expires) {
		delete(l.trustedCredentials, key)
		l.trustedLRU.Remove(credential.lruElement)
		return false
	}
	l.trustedLRU.MoveToFront(credential.lruElement)
	return true
}
