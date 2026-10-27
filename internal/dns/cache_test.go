package dns

import (
	"testing"

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
	hit := c.Get("example.com", dns.TypeA)
	if hit == nil {
		t.Fatalf("expected cache hit for lowercase name without dot")
	}
	if len(hit.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %d", len(hit.Answer))
	}

	// Look up with uppercase with dot
	hitUpper := c.Get("EXAMPLE.COM.", dns.TypeA)
	if hitUpper == nil {
		t.Fatalf("expected cache hit for uppercase name with dot")
	}
}
