// Package groupcache caches LDAP group membership and definitive credential
// rejections without retaining plaintext passwords.
package groupcache

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"

	"github.com/define42/s3gateway/internal/config"
)

// ==================== Cache ====================
type groupCacheEntry struct {
	groups         map[string]struct{}
	credentialHash [32]byte
	expires        time.Time
	lastSeen       time.Time
}

// Cache is a concurrency-safe, TTL-bound cache of LDAP group memberships and
// exact rejected credentials. Successful entries are keyed by UPN and accept
// hits only when the supplied password's hash matches the stored hash.
type Cache struct {
	mu                  sync.Mutex
	data                map[string]groupCacheEntry
	rejectedCredentials map[[sha256.Size]byte]time.Time
	ttl                 time.Duration
	maxEntries          int
	now                 func() time.Time
}

// New constructs a cache with the supplied TTL and capacity. A non-positive
// maxEntries value uses config.DefaultGroupCacheMaxEntries; a non-positive TTL
// causes stored entries to be unavailable on subsequent lookups.
func New(ttl time.Duration, maxEntries int) *Cache {
	if maxEntries <= 0 {
		maxEntries = config.DefaultGroupCacheMaxEntries
	}
	return &Cache{
		data:                map[string]groupCacheEntry{},
		rejectedCredentials: map[[sha256.Size]byte]time.Time{},
		ttl:                 ttl,
		maxEntries:          maxEntries,
		now:                 time.Now,
	}
}

// MaxEntries returns the separate capacity used for successful and rejected
// credential entries.
func (c *Cache) MaxEntries() int {
	return c.maxEntries
}

// Len returns the number of successful group entries, including entries that
// have expired but have not yet been accessed or evicted.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}

func cacheCredentialHash(upn, password string) [32]byte {
	return sha256.Sum256([]byte(upn + "\x00" + password))
}

// SingleflightCredentialKey returns a deterministic, non-plaintext key for
// coalescing simultaneous lookups of the same credentials.
func SingleflightCredentialKey(upn, password string) string {
	h := cacheCredentialHash(upn, password)
	return hex.EncodeToString(h[:])
}

// CloneGroups copies a group set so callers cannot mutate cached state. A nil
// or empty input produces a non-nil empty map.
func CloneGroups(groups map[string]struct{}) map[string]struct{} {
	if len(groups) == 0 {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(groups))
	for g := range groups {
		out[g] = struct{}{}
	}
	return out
}

// Get returns a copy of the cached groups when both credentials match and the
// entry has not expired. Password hashes are compared in constant time.
func (c *Cache) Get(upn, password string) (map[string]struct{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
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
	return CloneGroups(e.groups), true
}

// Rejected reports whether the identity backend recently rejected this exact
// username and password. Expired entries are removed on access.
func (c *Cache) Rejected(upn, password string) bool {
	credentialHash := cacheCredentialHash(upn, password)

	c.mu.Lock()
	defer c.mu.Unlock()

	expires, ok := c.rejectedCredentials[credentialHash]
	if !ok {
		return false
	}
	if c.now().After(expires) {
		delete(c.rejectedCredentials, credentialHash)
		return false
	}
	return true
}

func (c *Cache) evictExpiredRejectedLocked(now time.Time) {
	for credentialHash, expires := range c.rejectedCredentials {
		if now.After(expires) {
			delete(c.rejectedCredentials, credentialHash)
		}
	}
}

func (c *Cache) evictOldestRejectedLocked() {
	var victim [sha256.Size]byte
	var victimExpiry time.Time
	found := false
	for credentialHash, expires := range c.rejectedCredentials {
		if !found || expires.Before(victimExpiry) {
			victim = credentialHash
			victimExpiry = expires
			found = true
		}
	}
	if found {
		delete(c.rejectedCredentials, victim)
	}
}

// Reject caches a definitive identity-backend rejection for this exact
// username and password. Rejections use the successful cache TTL and have a
// separate, equally sized bound so untrusted misses cannot evict valid users.
func (c *Cache) Reject(upn, password string) {
	credentialHash := cacheCredentialHash(upn, password)

	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	c.evictExpiredRejectedLocked(now)
	if _, exists := c.rejectedCredentials[credentialHash]; !exists {
		for len(c.rejectedCredentials) >= c.maxEntries {
			c.evictOldestRejectedLocked()
		}
	}
	c.rejectedCredentials[credentialHash] = now.Add(c.ttl)
}

func (c *Cache) evictExpiredLocked(now time.Time) {
	for upn, e := range c.data {
		if now.After(e.expires) {
			delete(c.data, upn)
		}
	}
}

func (c *Cache) evictOneOldestLocked() {
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

// Set replaces the cached entry for upn. When at capacity, it first removes
// expired entries and then evicts the entry with the earliest expiry and
// oldest access time.
func (c *Cache) Set(upn, password string, groups map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	c.evictExpiredLocked(now)

	if _, exists := c.data[upn]; !exists {
		for len(c.data) >= c.maxEntries {
			c.evictOneOldestLocked()
		}
	}

	credentialHash := cacheCredentialHash(upn, password)
	c.data[upn] = groupCacheEntry{
		groups:         CloneGroups(groups),
		credentialHash: credentialHash,
		expires:        now.Add(c.ttl),
		lastSeen:       now,
	}
	delete(c.rejectedCredentials, credentialHash)
}
