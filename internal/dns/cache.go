package dns

import (
	"fmt"
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
	return fmt.Sprintf("%s\x00%d", strings.ToLower(strings.TrimSuffix(name, ".")), qtype)
}

// inBailiwick reports whether rrName is qname itself or one of its
// subdomains. Comparison is case-insensitive and FQDN-form agnostic
// (trailing dot does not matter); boundary must be a full dot, so
// evil-example.com is NOT inside example.com.
func inBailiwick(qname, rrName string) bool {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	rrName = strings.ToLower(strings.TrimSuffix(rrName, "."))
	if qname == "" || rrName == "" {
		return false
	}
	return rrName == qname || strings.HasSuffix(rrName, "."+qname)
}

// ancestorOrSelf reports whether rrName is qname itself or one of its
// enclosing zones (upper / parent domains).
func ancestorOrSelf(qname, rrName string) bool {
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))
	rrName = strings.ToLower(strings.TrimSuffix(rrName, "."))
	if qname == "" || rrName == "" {
		return false
	}
	return rrName == qname || strings.HasSuffix(qname, "."+rrName)
}

// keepAnswerBailiwick filters out records whose owner name is not in the queried
// name's zone or its CNAME alias chain. If a CNAME points outside the original
// zone (e.g. www.example.com -> cdn.cloudflare.net), the target's address records
// in the answer section are preserved so the client receives a complete answer.
func keepAnswerBailiwick(qname string, rrs []dns.RR) []dns.RR {
	kept := make([]dns.RR, 0, len(rrs))
	validTargets := map[string]struct{}{
		strings.ToLower(strings.TrimSuffix(qname, ".")): {},
	}

	for _, rr := range rrs {
		if rr == nil || rr.Header() == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
		matched := false
		for vt := range validTargets {
			if inBailiwick(vt, name) {
				matched = true
				break
			}
		}
		if matched {
			kept = append(kept, rr)
			if cname, ok := rr.(*dns.CNAME); ok {
				target := strings.ToLower(strings.TrimSuffix(cname.Target, "."))
				if target != "" {
					validTargets[target] = struct{}{}
				}
			}
		}
	}
	return kept
}

// keepBailiwick filters out records whose owner name is not in the queried
// name's zone. Never returns the input slice: out-of-bailiwick records are
// dropped, in-bailiwick ones (RR pointers) are shared with the caller's msg.
func keepBailiwick(qname string, rrs []dns.RR) []dns.RR {
	kept := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr != nil && rr.Header() != nil && inBailiwick(qname, rr.Header().Name) {
			kept = append(kept, rr)
		}
	}
	return kept
}

// keepAuthorityBailiwick filters authority-section records. The usual
// in-bailiwick rule applies, but an SOA is also kept when it names the queried
// name itself or one of its enclosing zones: a negative (NXDOMAIN) response's
// SOA belongs to the authority zone (e.g. example.com. for the query
// missing.example.com.), not to the missing name itself.
func keepAuthorityBailiwick(qname string, rrs []dns.RR) []dns.RR {
	kept := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr == nil || rr.Header() == nil {
			continue
		}
		if inBailiwick(qname, rr.Header().Name) {
			kept = append(kept, rr)
			continue
		}
		if soa, ok := rr.(*dns.SOA); ok && ancestorOrSelf(qname, soa.Header().Name) {
			kept = append(kept, soa)
		}
	}
	return kept
}

// Get returns a copy of the cached message if present and not expired,
// with remaining TTL adjusted per RFC 1035.
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
	now := time.Now()
	if now.After(entry.expiresAt) {
		return nil
	}
	resp := entry.msg.Copy()
	rem := uint32(time.Until(entry.expiresAt).Seconds())
	if rem < 1 {
		rem = 1
	}
	for _, rr := range resp.Answer {
		if rr != nil && rr.Header() != nil {
			rr.Header().Ttl = rem
		}
	}
	for _, rr := range resp.Ns {
		if rr != nil && rr.Header() != nil {
			rr.Header().Ttl = rem
		}
	}
	for _, rr := range resp.Extra {
		if rr != nil && rr.Header() != nil && rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = rem
		}
	}
	return resp
}

// Set stores a response in the cache. Records outside the queried name's
// bailiwick (or CNAME chain in answers) are dropped (cache poisoning guard).
// TTL bounds: positive answers 5s..1h; NXDOMAIN 5s..300s per RFC 2308
// (SOA TTL vs SOA.MINIMUM, safe 60s default when no SOA is present).
func (c *dnsCache) Set(name string, qtype uint16, msg *dns.Msg) {
	if c == nil || msg == nil {
		return
	}
	// Copy first, then filter: the caller keeps ownership of msg as-is.
	filtered := msg.Copy()
	filtered.Answer = keepAnswerBailiwick(name, msg.Answer)
	filtered.Ns = keepAuthorityBailiwick(name, msg.Ns)
	filtered.Extra = keepBailiwick(name, msg.Extra)

	var ttl uint32
	if msg.Rcode == dns.RcodeNameError {
		// Compute the TTL from the incoming msg: negativeTTL inspects msg.Ns,
		// whose SOA may name the enclosing zone and would otherwise be
		// discarded by bailiwick filtering before the TTL is known.
		ttl = negativeTTL(msg)
		if ttl < 5 {
			ttl = 5
		}
		if ttl > 300 {
			ttl = 300
		}
	} else {
		ttl = uint32(60) // default fallback 60s
		var foundTTL bool
		for _, rr := range append(append(filtered.Answer, filtered.Ns...), filtered.Extra...) {
			if rr.Header() != nil {
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
		msg:       filtered,
		expiresAt: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

// negativeTTL returns the negative-TTL from the SOA record of an NXDOMAIN
// response (RFC 2308 §3: min(SOA TTL, SOA.MINIMUM)); 60s when absent.
func negativeTTL(msg *dns.Msg) uint32 {
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok && soa.Header() != nil {
			t := soa.Header().Ttl
			if soa.Minttl < t {
				t = soa.Minttl
			}
			return t
		}
	}
	return 60
}
