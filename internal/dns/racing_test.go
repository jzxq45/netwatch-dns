package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// raceUpstream builds one race-mode upstream: after addDelay before answering
// with its own marker IP (each upstream overlaps distinctive records).
func raceUpstream(t *testing.T, marker net.IP, addDelay time.Duration) string {
	t.Helper()
	return startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if addDelay > 0 {
			time.Sleep(addDelay)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   marker.To4(),
		})
		_ = w.WriteMsg(m)
	}))
}

// TestParallelRacingFastestWins: with two healthy upstreams the query is sent
// to both in parallel and the answer comes from the faster one — within a
// fraction of the slow upstream's delay.
func TestParallelRacingFastestWins(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a live UDP exchange")
	}
	const slowDelay = 1500 * time.Millisecond
	fastAddr := startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IPv4(1, 2, 3, 4).To4(),
		})
		_ = w.WriteMsg(m)
	}))
	slowAddr := raceUpstream(t, net.IPv4(5, 6, 7, 8), slowDelay)

	s := New(Config{
		Upstream:         fastAddr,
		FallbackUpstream: slowAddr,
	}, nil, discardLogger())

	start := time.Now()
	resp, err := s.resolveUpstream(qA("example.com."), 0)
	if err != nil {
		t.Fatalf("raced resolveUpstream: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed >= slowDelay {
		t.Fatalf("racing did not win: elapsed %v with slow upstream at %v", elapsed, slowDelay)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 answer, got %+v", resp.Answer)
	}
	if a := resp.Answer[0].(*dns.A); !a.A.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("expected the fast upstream answer, got %+v", resp.Answer[0])
	}
	if got := s.consecutiveFails.Load(); got != 0 {
		t.Fatalf("healthy race must reset fail tracking, got %d", got)
	}
}

// TestParallelRacingFallbackWins: primary is dead, fallback answers — races
// must still return the healthy answer (first non-error result).
func TestParallelRacingFallbackWins(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a live UDP exchange")
	}
	dead := deadUpstream(t)
	live := raceUpstream(t, net.IPv4(7, 7, 7, 7), 0)

	s := New(Config{
		Upstream:         dead,
		FallbackUpstream: live,
	}, nil, discardLogger())

	resp, err := s.resolveUpstream(qA("example.com."), 0)
	if err != nil {
		t.Fatalf("raced resolveUpstream with dead primary: %v", err)
	}
	if a := resp.Answer[0].(*dns.A); !a.A.Equal(net.IPv4(7, 7, 7, 7)) {
		t.Fatalf("expected the fallback answer, got %+v", resp.Answer[0])
	}
	// Blocked network is healthy again after the live answer.
	if got := s.consecutiveFails.Load(); got != 0 {
		t.Fatalf("expected fail tracking reset, got %d", got)
	}
}
