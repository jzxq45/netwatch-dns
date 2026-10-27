package dns

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type cacheEntry struct {
	msg       *dns.Msg
	expiresAt time.Time
}

type dnsCache struct {
	mu      sync.RWMutex
	maxSize int
	entries map[string]cacheEntry
}

func newDNSCache(maxSize int) *dnsCache {
	return &dnsCache{
		maxSize: maxSize,
		entries: make(map[string]cacheEntry),
	}
}

func (c *dnsCache) key(name string, qtype uint16) string {
	return strings.ToLower(strings.TrimSuffix(name, ".")) + "\x00" + dns.TypeToString[qtype]
}

// Get returns a copy of the cached message if present and not expired.
func (c *dnsCache) Get(name string, qtype uint16) *dns.Msg {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	entry, ok := c.entries[c.key(name, qtype)]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.msg.Copy()
}

// Set stores a response in the cache with calculated TTL bounded between 5s and 1h.
func (c *dnsCache) Set(name string, qtype uint16, msg *dns.Msg) {
	if c == nil || msg == nil {
		return
	}
	ttl := uint32(60) // default fallback 60s
	var foundTTL bool
	for _, rr := range append(append(msg.Answer, msg.Ns...), msg.Extra...) {
		if rr != nil && rr.Header() != nil {
			headerTTL := rr.Header().Ttl
			if !foundTTL || headerTTL < ttl {
				ttl = headerTTL
				foundTTL = true
			}
		}
	}
	if ttl < 5 {
		ttl = 5
	}
	if ttl > 3600 {
		ttl = 3600
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.maxSize {
			dropCount := c.maxSize / 4
			for k := range c.entries {
				delete(c.entries, k)
				dropCount--
				if dropCount <= 0 {
					break
				}
			}
		}
	}
	c.entries[c.key(name, qtype)] = cacheEntry{
		msg:       msg.Copy(),
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}
