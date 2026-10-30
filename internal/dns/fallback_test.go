package dns

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// deadUpstream reserves an address and closes it right away: UDP and TCP
// exchanges against it fail fast with connection refused — no real network.
func deadUpstream(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("dead upstream listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("dead upstream close: %v", err)
	}
	return addr
}

func answerHandler() dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IPv4(93, 184, 216, 34).To4(),
		})
		_ = w.WriteMsg(m)
	})
}

func qA(name string) dns.Question {
	return dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}
}

func TestFallbackUpstreamRescuesPrimaryFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a live UDP exchange")
	}
	fallbackAddr := startUpstream(t, answerHandler())
	dead := deadUpstream(t)

	s := New(Config{
		Upstream:         dead,
		FallbackUpstream: fallbackAddr,
	}, nil, slogDiscard())

	resp, err := s.resolveUpstream(qA("example.com."), 0)
	if err != nil {
		t.Fatalf("resolveUpstream with fallback: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("unexpected fallback response: rcode=%d answers=%d", resp.Rcode, len(resp.Answer))
	}
	if a, ok := resp.Answer[0].(*dns.A); !ok || !a.A.Equal(net.IPv4(93, 184, 216, 34)) {
		t.Fatalf("unexpected answer %+v", resp.Answer[0])
	}
	if got := s.consecutiveFails.Load(); got != 0 {
		t.Fatalf("expected consecutive fails reset after fallback success, got %d", got)
	}
}

func TestFallbackUpstreamBothFail(t *testing.T) {
	dead1 := deadUpstream(t)
	dead2 := deadUpstream(t)
	s := New(Config{
		Upstream:         dead1,
		FallbackUpstream: dead2,
	}, nil, discardLogger())

	if _, err := s.resolveUpstream(qA("example.com."), 0); err == nil {
		t.Fatal("expected error when both upstreams fail")
	}
	if got := s.consecutiveFails.Load(); got < 1 {
		t.Fatalf("expected consecutive fails to increment, got %d", got)
	}
}

func TestFallbackUpstreamDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a live UDP exchange")
	}
	dead := deadUpstream(t)
	s := New(Config{Upstream: dead}, nil, slogDiscard())

	done := make(chan error, 1)
	go func() {
		_, err := s.resolveUpstream(qA("example.com."), 0)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error without fallback")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("resolveUpstream did not return in time")
	}
	if got := s.consecutiveFails.Load(); got != 0 {
		t.Fatalf("expected fails counter untouched without fallback, got %d", got)
	}
}

// slogDiscard keeps fallback test output clean (the warn line on primary
// failure is expected).
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
