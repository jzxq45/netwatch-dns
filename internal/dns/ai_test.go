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

	"monitor/internal/metrics"
	"monitor/internal/store"
)

// TestAIShieldIntegration is the end-to-end guard for the heuristic AI engine:
// DGA and phishing names are answered NXDOMAIN (never forwarded upstream),
// counted in dns_ai_blocked_total, stored as noise=1 and logged with the
// threat class; a legitimate name still resolves normally.
func TestAIShieldIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("network bind test")
	}
	var upstream capNames
	up := startUpstream(t, captureUpstream(&upstream))

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var logs syncBuffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := New(Config{Upstream: up}, db.DB(), log)

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

	before := metrics.DNSAIBlockedTotal.Value()
	c := &dns.Client{Timeout: 3 * time.Second}
	query := func(name string) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), dns.TypeA)
		resp, _, err := c.Exchange(m, addr)
		if err != nil {
			t.Fatalf("exchange %s: %v", name, err)
		}
		return resp
	}

	threats := []string{"x8a19bkc92.biz", "paypal-security-update.com"}
	for _, name := range threats {
		if resp := query(name); resp.Rcode != dns.RcodeNameError {
			t.Fatalf("%s: rcode = %d, want NXDOMAIN", name, resp.Rcode)
		}
	}
	if got := metrics.DNSAIBlockedTotal.Value(); got != before+int64(len(threats)) {
		t.Fatalf("dns_ai_blocked_total = %d, want %d", got, before+int64(len(threats)))
	}

	// Never forwarded upstream.
	upstream.mu.Lock()
	forwarded := append([]string(nil), upstream.names...)
	upstream.mu.Unlock()
	if len(forwarded) != 0 {
		t.Fatalf("AI-blocked names reached upstream: %v", forwarded)
	}

	// Stored as noise=1 (intel feed) and logged with threat classification.
	for _, name := range threats {
		waitForLogRowCustom(t, db, name+".", 1)
	}
	got := logs.String()
	for _, want := range []string{
		"msg=\"dns ai blocked zero-day threat\"",
		"threat=dga",
		"threat=phishing",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("log missing %q:\n%s", want, got)
		}
	}

	// Legitimate name still resolves and is not counted.
	if resp := query("example.com"); resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("legit rcode = %d, want NOERROR", resp.Rcode)
	}
	if got := metrics.DNSAIBlockedTotal.Value(); got != before+int64(len(threats)) {
		t.Fatalf("legit query changed AI counter: %d", got)
	}
	upstream.mu.Lock()
	resolved := append([]string(nil), upstream.names...)
	upstream.mu.Unlock()
	if len(resolved) != 1 || !strings.EqualFold(resolved[0], "example.com.") {
		t.Fatalf("upstream names = %v, want [example.com.]", resolved)
	}
}
