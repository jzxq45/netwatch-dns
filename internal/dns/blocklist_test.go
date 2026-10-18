package dns

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"monitor/internal/store"
)

// captureUpstream answers NOERROR for anything and records every question
// name it receives (proves blocked queries never reach it, and forwarded
// names keep their original form).
func captureUpstream(got *capNames) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		got.mu.Lock()
		got.names = append(got.names, r.Question[0].Name)
		got.mu.Unlock()
		m := new(dns.Msg)
		m.SetReply(r)
		//nolint:errcheck // in-memory fake conn; only a lost UDP packet
		_ = w.WriteMsg(m)
	})
}

type capNames struct {
	mu    sync.Mutex
	names []string
}

// syncBuffer is a mutex-guarded bytes.Buffer: the leaky logger writes from
// the flusher goroutine while the test polls the text concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func (c *capNames) has(name string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.names) > 0 && c.names[len(c.names)-1] == name
}

func startBlockTestServer(t *testing.T, echo func(*Config)) (addr string, db *store.Store) {
	t.Helper()
	var cap capNames
	up := startUpstream(t, captureUpstream(&cap))

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	addr = l.Addr().String()
	_ = l.Close()

	cfg := Config{Upstream: up}
	if echo != nil {
		echo(&cfg)
	}
	srv := New(cfg, db.DB(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start(ctx, addr) }()
	select {
	case err := <-serveErr:
		t.Fatalf("server exited immediately: %v", err)
	case <-time.After(300 * time.Millisecond): // bind warm-up (same as server_test)
	}
	return addr, db
}

// TestDoHBlockedLogEmitted is the regression guard for the DoH pipeline:
// dns.google must return NXDOMAIN and produce a dns_blocked_doh line (after
// one aggregation window), without ever reaching upstream.
func TestDoHBlockedLogEmitted(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("network bind test")
	}
	var cap capNames
	up := startUpstream(t, captureUpstream(&cap))

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Default blocklist (Blocklist stays nil), short window for fast flush.
	srv := New(Config{Upstream: up, DoHWindow: "50ms", DoHLogLevel: "debug"}, db.DB(), log)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start(ctx, addr) }()
	select {
	case err := <-serveErr:
		t.Fatalf("server exited immediately: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	c := &dns.Client{Timeout: 3 * time.Second}
	for i := 0; i < 2; i++ {
		m := new(dns.Msg)
		m.SetQuestion("dns.google.", dns.TypeA)
		resp, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if resp.Rcode != dns.RcodeNameError {
			t.Fatalf("query %d: rcode=%d, want NXDOMAIN", i, resp.Rcode)
		}
	}

	// Never forwarded upstream.
	cap.mu.Lock()
	forwarded := len(cap.names)
	cap.mu.Unlock()
	if forwarded != 0 {
		t.Fatalf("blocked query reached upstream %d times", forwarded)
	}

	// Exactly one aggregated line with count=2 after the 50ms window.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s := logs.String()
		if strings.Contains(s, "msg=dns_blocked_doh") && strings.Contains(s, "count=2") {
			if n := strings.Count(s, "msg=dns_blocked_doh"); n != 1 {
				t.Fatalf("want 1 aggregated line, got %d:\n%s", n, s)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("dns_blocked_doh never emitted:\n%s", s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func TestDoHBlocklist(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("network bind test")
	}
	addr, db := startBlockTestServer(t, nil)

	tests := []struct {
		name string
		q    string
		nx   bool
	}{
		{"exact", "dns.google.", true},
		{"case-insensitive", "DNS.GOOGLE", true},
		{"subdomain", "secure.dns.adguard.com", true},
		{"deep subdomain", "iphone.a.b.doh.opendns.com", true},
		{"cloudflare chrome profile", "chrome.cloudflare-dns.com", true},
		{"quad9", "dns.quad9.net", true},
		{"unrelated domain passes", "example.com", false},
		{"similar but not subdomain", "notdns.google", false},
		{"suffix must be full label", "xdns.google", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &dns.Client{Timeout: 3 * time.Second}
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(tt.q), dns.TypeA)
			resp, _, err := c.Exchange(m, addr)
			if err != nil {
				t.Fatalf("exchange: %v", err)
			}
			gotNX := resp.Rcode == dns.RcodeNameError
			if gotNX != tt.nx {
				t.Fatalf("rcode = %d, wantNX(%q) = %v", resp.Rcode, tt.q, tt.nx)
			}
		})
	}

	// Blocked queries still land in dns_log (intel), but no upstream hit.
	var n int
	if err := db.DB().QueryRow(`SELECT count(*) FROM dns_log WHERE domain=?`, "dns.google.").Scan(&n); err != nil {
		t.Fatalf("log query: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for n == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		if err := db.DB().QueryRow(`SELECT count(*) FROM dns_log WHERE domain=?`, "dns.google.").Scan(&n); err != nil {
			t.Fatalf("log query: %v", err)
		}
	}
	if n < 1 {
		t.Fatal("blocked query missing from dns_log")
	}
}

func TestDoHBlocklistOverride(t *testing.T) {
	t.Parallel()
	addr, _ := startBlockTestServer(t, func(c *Config) {
		c.Blocklist = []string{"blocked.example", "other.blocked.example"}
	})

	tests := []struct {
		name string
		q    string
		nx   bool
	}{
		{"blocked override", "blocked.example", true},
		{"deep subdomain of override", "deep.BLOCKED.example", true},
		{"default-list replaced entirely", "dns.google.", false}, // yaml replaced it
	}
	for _, tt := range tests {
		c := &dns.Client{Timeout: 3 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(tt.q), dns.TypeA)
		resp, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("exchange %s: %v", tt.q, err)
		}
		if got := resp.Rcode == dns.RcodeNameError; got != tt.nx {
			t.Fatalf("%s: NX=%v, want %v", tt.q, got, tt.nx)
		}
	}
}
