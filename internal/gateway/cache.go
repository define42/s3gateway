package gateway

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

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

func singleflightCredentialKey(upn, password string) string {
	h := cacheCredentialHash(upn, password)
	return hex.EncodeToString(h[:])
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
