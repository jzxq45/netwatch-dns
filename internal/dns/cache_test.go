package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSCacheCaseInsensitive(t *testing.T) {
	c := newDNSCache(100)
	msg := new(dns.Msg)
	msg.SetQuestion("eXaMpLe.CoM.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{93, 184, 216, 34},
		},
	}

	c.Set("eXaMpLe.CoM.", dns.TypeA, msg)

	// Look up with lowercase without trailing dot
	hit, _ := c.Get("example.com", dns.TypeA)
	if hit == nil {
		t.Fatalf("expected cache hit for lowercase name without dot")
	}
	if len(hit.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(hit.Answer))
	}

	// Look up with uppercase with dot
	hitUpper, _ := c.Get("EXAMPLE.COM.", dns.TypeA)
	if hitUpper == nil {
		t.Fatalf("expected cache hit for uppercase name with dot")
	}
}

func TestInBailiwick(t *testing.T) {
	tests := []struct {
		qname, rrName string
		want          bool
	}{
		{"example.com.", "example.com.", true},           // exact
		{"example.com.", "sub.example.com.", true},       // subdomain
		{"example.com.", "deep.a.b.example.com.", true},  // deep subdomain
		{"EXAMPLE.COM.", "SUB.ExAmPlE.CoM.", true},       // case-insensitive
		{"example.com", "example.com.", true},            // form-agnostic
		{"example.com.", "evil-example.com.", false},     // no dot boundary
		{"example.com.", "example.com.evil.com.", false}, // zone escape
		{"example.com.", "other.com.", false},            // unrelated zone
		{"example.com.", "", false},                      // empty RR name
		{"", "example.com.", false},                      // empty qname
	}
	for _, tt := range tests {
		if got := inBailiwick(tt.qname, tt.rrName); got != tt.want {
			t.Errorf("inBailiwick(%q, %q) = %v, want %v", tt.qname, tt.rrName, got, tt.want)
		}
	}
}

func TestDNSCacheBailiwickFilter(t *testing.T) {
	c := newDNSCache(100)
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{93, 184, 216, 34},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "out.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{1, 2, 3, 4},
		},
	}
	msg.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{Name: "example.net.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns1.example.net.",
		},
	}
	msg.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "ns1.example.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{5, 6, 7, 8},
		},
	}

	c.Set("example.com.", dns.TypeA, msg)

	// The caller's message must stay untouched.
	if n := len(msg.Answer); n != 2 {
		t.Fatalf("original msg.Answer mutated: %d answers", n)
	}

	hit, _ := c.Get("example.com.", dns.TypeA)
	if hit == nil {
		t.Fatal("expected cache hit")
	}
	if len(hit.Answer) != 1 || hit.Answer[0].Header().Name != "example.com." {
		t.Fatalf("expected only the in-bailiwick answer, got %+v", hit.Answer)
	}
	if len(hit.Ns) != 0 {
		t.Fatalf("expected Ns section filtered, got %+v", hit.Ns)
	}
	if len(hit.Extra) != 0 {
		t.Fatalf("expected Extra section filtered, got %+v", hit.Extra)
	}
}

func TestDNSCacheNegativeNXDOMAIN(t *testing.T) {
	c := newDNSCache(100)
	msg := new(dns.Msg)
	msg.SetQuestion("missing.example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError
	// SOA TTL 7 < Minttl 200: RFC 2308 negative TTL is the minimum.
	msg.Ns = []dns.RR{
		&dns.SOA{
			Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 7},
			Ns:     "ns1.example.com.",
			Mbox:   "hostmaster.example.com.",
			Minttl: 200,
		},
	}

	c.Set("missing.example.com.", dns.TypeA, msg)

	entry, ok := c.entries[c.key("missing.example.com.", dns.TypeA)]
	if !ok {
		t.Fatal("expected NXDOMAIN to be cached")
	}
	if ttl := time.Until(entry.expiresAt); ttl > 8*time.Second || ttl < 5*time.Second {
		t.Fatalf("expected ~7s negative TTL, got %v", ttl)
	}

	hit, _ := c.Get("missing.example.com.", dns.TypeA)
	if hit == nil {
		t.Fatal("expected cached NXDOMAIN to be returned")
	}
	if hit.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %s", dns.RcodeToString[hit.Rcode])
	}
	if len(hit.Ns) != 1 {
		t.Fatalf("expected SOA to survive bailiwick filtering, got %+v", hit.Ns)
	}
}

func TestDNSCacheNegativeNXDOMAINDefaultTTL(t *testing.T) {
	c := newDNSCache(100)
	msg := new(dns.Msg)
	msg.SetQuestion("noso.example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeNameError

	c.Set("noso.example.com.", dns.TypeA, msg)

	entry, ok := c.entries[c.key("noso.example.com.", dns.TypeA)]
	if !ok {
		t.Fatal("expected NXDOMAIN without SOA to be cached")
	}
	elapsed := time.Until(entry.expiresAt)
	if elapsed > 61*time.Second {
		t.Fatalf("expected 60s default negative TTL, got %v", elapsed)
	}
}

func TestDNSCacheCNAMEChain(t *testing.T) {
	c := newDNSCache(100)
	msg := new(dns.Msg)
	msg.SetQuestion("www.example.com.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "cdn.external.net.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "cdn.external.net.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{104, 16, 12, 34},
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "unrelated.evil.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{6, 6, 6, 6},
		},
	}

	c.Set("www.example.com.", dns.TypeA, msg)

	hit, _ := c.Get("www.example.com.", dns.TypeA)
	if hit == nil {
		t.Fatal("expected cache hit for CNAME query")
	}
	if len(hit.Answer) != 2 {
		t.Fatalf("expected CNAME + A (2 answers), got %d: %+v", len(hit.Answer), hit.Answer)
	}
	if hit.Answer[0].Header().Name != "www.example.com." || hit.Answer[1].Header().Name != "cdn.external.net." {
		t.Fatalf("unexpected answers preserved: %+v", hit.Answer)
	}
}

func TestDNSCacheTTLCountdown(t *testing.T) {
	c := newDNSCache(100)
	msg := new(dns.Msg)
	msg.SetQuestion("ttl.example.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "ttl.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 100},
			A:   []byte{1, 2, 3, 4},
		},
	}
	c.Set("ttl.example.com.", dns.TypeA, msg)

	hit, _ := c.Get("ttl.example.com.", dns.TypeA)
	if hit == nil {
		t.Fatal("expected cache hit")
	}
	if hit.Answer[0].Header().Ttl > 100 || hit.Answer[0].Header().Ttl < 95 {
		t.Fatalf("expected TTL ~100s, got %d", hit.Answer[0].Header().Ttl)
	}
}

// TestDNSCachePrefetch pins the optimistic-prefetch contract: a fresh entry
// is served without a prefetch hint; an entry with less than 20% of its
// original TTL (or under 15s) left is served immediately but flagged hot;
// expired entries are misses (never served, never flagged).
func TestDNSCachePrefetch(t *testing.T) {
	c := newDNSCache(100)
	msg := new(dns.Msg)
	msg.SetQuestion("hot.example.com.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{Name: "hot.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{1, 2, 3, 4},
		},
	}

	if _, prefetch := c.Get("hot.example.com.", dns.TypeA); prefetch {
		t.Fatal("empty cache must miss, not prefetch")
	}

	c.Set("hot.example.com.", dns.TypeA, msg)
	if _, prefetch := c.Get("hot.example.com.", dns.TypeA); prefetch {
		t.Fatal("fresh entry must not be flagged for prefetch")
	}

	// Age the entry: 220s lived of a 300s life → 80s left (>20%), no hint.
	entry := c.entries[c.key("hot.example.com.", dns.TypeA)]
	entry.expiresAt = time.Now().Add(80 * time.Second)
	entry.cachedAt = entry.expiresAt.Add(-300 * time.Second)
	c.entries[c.key("hot.example.com.", dns.TypeA)] = entry
	if _, prefetch := c.Get("hot.example.com.", dns.TypeA); prefetch {
		t.Fatal("80s of 300s left must not be prefetchable")
	}

	// 20s left of a 300s life (< ~7%): hot.
	entry = c.entries[c.key("hot.example.com.", dns.TypeA)]
	entry.expiresAt = time.Now().Add(20 * time.Second)
	entry.cachedAt = entry.expiresAt.Add(-300 * time.Second)
	c.entries[c.key("hot.example.com.", dns.TypeA)] = entry
	hit, prefetch := c.Get("hot.example.com.", dns.TypeA)
	if hit == nil || !prefetch {
		t.Fatal("entry near expiry must be served and flagged for prefetch")
	}
	if hit.Answer[0].Header().Ttl > 20 || hit.Answer[0].Header().Ttl < 19 {
		t.Fatalf("cached answer TTL should reflect ~20s remaining, got %d", hit.Answer[0].Header().Ttl)
	}

	// Absolute rule: under 15s remaining is hot even when the entry is young.
	c.Set("short.example.com.", dns.TypeA, msg)
	short := c.entries[c.key("short.example.com.", dns.TypeA)]
	short.expiresAt = time.Now().Add(14 * time.Second)
	short.cachedAt = short.expiresAt.Add(-300 * time.Second)
	c.entries[c.key("short.example.com.", dns.TypeA)] = short
	if _, prefetch := c.Get("short.example.com.", dns.TypeA); !prefetch {
		t.Fatal("under 15s remaining must be prefetchable regardless of ratio")
	}

	// Just expired: still a miss.
	short = c.entries[c.key("short.example.com.", dns.TypeA)]
	short.expiresAt = time.Now().Add(-time.Second)
	c.entries[c.key("short.example.com.", dns.TypeA)] = short
	if hit, prefetch := c.Get("short.example.com.", dns.TypeA); hit != nil || prefetch {
		t.Fatal("expired entry must not be served")
	}
}
