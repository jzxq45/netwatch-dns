package dns

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"monitor/internal/store"
)

// TestIsNoise: wildcard boundary semantics per spec.
func TestIsNoise(t *testing.T) {
	t.Parallel()
	s := New("127.0.0.1:9953", nil, nil)
	tests := []struct {
		name string
		q    string
		want bool
	}{
		{"wildcard sub matches", "sub.gstatic.com.", true},
		{"wildcard base matches", "gstatic.com.", true},
		{"wildcard boundary holds", "notgstatic.com.", false},
		{"deeper sub matches", "a.b.gstatic.com.", true},
		{"plain pattern exact", "mtalk.google.com.", true},
		{"plain pattern subdomain", "x.mtalk.google.com.", true},
		{"plain pattern other", "vedomosti.ru.", false},
		{"arpa wildcard", "1.0.0.127.in-addr.arpa.", true},
		{"case insensitive", "SUB.GSTATIC.COM.", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.isNoise(tt.q); got != tt.want {
				t.Fatalf("isNoise(%q) = %v, want %v", tt.q, got, tt.want)
			}
		})
	}
}

// TestNoisePathIntegration: noise domains → dns_log noise=1, no stdout Info;
// clean domains → normal Info + noise=0.
func TestNoisePathIntegration(t *testing.T) {
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
	// Info handler: noise domain must produce zero Info lines.
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	srv := New(up, db.DB(), log)
	srv.NoiseDomains = []string{"*.gstatic.com", "mtalk.google.com"}

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
	tests := []struct {
		q     string
		noise bool
	}{
		{"sub.gstatic.com.", true},
		{"mtalk.google.com.", true},
		{"vedomosti.ru.", false},
	}
	for _, tt := range tests {
		m := new(dns.Msg)
		m.SetQuestion(tt.q, dns.TypeA)
		if _, _, err := c.Exchange(m, addr); err != nil {
			t.Fatalf("exchange %s: %v", tt.q, err)
		}
	}

	for _, tt := range tests {
		expected := 0
		if tt.noise {
			expected = 1
		}
		waitForLogRowCustom(t, db, tt.q, expected)
	}

	// stdout: only the clean query appears in Info.
	got := logs.String()
	if strings.Contains(got, "gstatic.com") || strings.Contains(got, "mtalk.google.com") {
		t.Fatalf("noise domain leaked into Info stdout:\n%s", got)
	}
	if !strings.Contains(got, "dns query") || !strings.Contains(got, "vedomosti.ru") {
		t.Fatalf("clean query missing from Info stdout:\n%s", got)
	}
}

// waitForLogRowCustom polls until the dns_log noise flag for domain equals want.
func waitForLogRowCustom(t *testing.T, db *store.Store, domain string, wantNoise int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var n, nz int
		if err := db.DB().QueryRow(
			`SELECT count(*), COALESCE(sum(noise),0) FROM dns_log WHERE domain=?`, domain).
			Scan(&n, &nz); err != nil {
			t.Fatalf("log query: %v", err)
		}
		if n > 0 {
			if nz != wantNoise*n {
				t.Fatalf("%s: noise sum = %d over %d rows, want %d", domain, nz, n, wantNoise*n)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("row for %s never appeared", domain)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
