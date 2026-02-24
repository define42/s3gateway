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

type GroupCache struct {
	mu         sync.Mutex
	data       map[string]groupCacheEntry
	ttl        time.Duration
	maxEntries int
}

func NewGroupCacheWithMaxEntries(ttl time.Duration, maxEntries int) *GroupCache {
	if maxEntries <= 0 {
		maxEntries = config.DefaultGroupCacheMaxEntries
	}
	return &GroupCache{
		data:       map[string]groupCacheEntry{},
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

func (c *GroupCache) MaxEntries() int {
	return c.maxEntries
}

func (c *GroupCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.data)
}

func cacheCredentialHash(upn, password string) [32]byte {
	return sha256.Sum256([]byte(upn + "\x00" + password))
}

func SingleflightCredentialKey(upn, password string) string {
	h := cacheCredentialHash(upn, password)
	return hex.EncodeToString(h[:])
}

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

func (c *GroupCache) Get(upn, password string) (map[string]struct{}, bool) {
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
	return CloneGroups(e.groups), true
}

func (c *GroupCache) evictExpiredLocked(now time.Time) {
	for upn, e := range c.data {
		if now.After(e.expires) {
			delete(c.data, upn)
		}
	}
}

func (c *GroupCache) evictOneOldestLocked() {
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

func (c *GroupCache) Set(upn, password string, groups map[string]struct{}) {
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
		groups:         CloneGroups(groups),
		credentialHash: cacheCredentialHash(upn, password),
		expires:        now.Add(c.ttl),
		lastSeen:       now,
	}
}
