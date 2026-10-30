package dns

import (
	"context"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"monitor/internal/store"
)

type upstreamCounter struct {
	hits int
}

func rewriteUpstream(t *testing.T, hits *upstreamCounter) string {
	t.Helper()
	return startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		hits.hits++
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IPv4(93, 184, 216, 34).To4(),
		})
		_ = w.WriteMsg(m)
	}))
}

func queryMsg(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

// TestRewriteAnswerAAAA pinned via the A path: rewrite serves the mapped
// IPv4 authoritatively without touching upstream, case-insensitively.
func TestRewriteAAnswer(t *testing.T) {
	t.Parallel()
	hits := &upstreamCounter{}
	up := rewriteUpstream(t, hits)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := New(Config{Upstream: up}, db.DB(), slogDiscard())

	srv.ApplyRewrite("NAS.Local.", "192.168.10.20")
	// Same mapping spelled differently replaces, never duplicates.
	srv.ApplyRewrite("nas.local", "192.168.10.21")

	resp, err := srv.exchange(queryMsg("nas.local", dns.TypeA))
	if err != nil {
		t.Fatalf("exchange rewritten domain: %v", err)
	}
	if !resp.Authoritative {
		t.Error("rewrite answer must be authoritative")
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("unexpected rewrite answer: rcode=%d answers=%+v", resp.Rcode, resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4(192, 168, 10, 21)) {
		t.Fatalf("wrong rewrite value: %+v", resp.Answer[0])
	}
	if a.Header().Ttl != rewriteTTL {
		t.Errorf("rewrite TTL = %d, want %d", a.Header().Ttl, rewriteTTL)
	}
	if hits.hits != 0 {
		t.Errorf("rewritten lookup reached upstream %d times", hits.hits)
	}

	// Case-insensitivity: the client's spelling must not matter.
	if _, err := srv.exchange(queryMsg("NAS.LOCAL.", dns.TypeA)); err != nil {
		t.Fatalf("exchange uppercase: %v", err)
	}
	if hits.hits != 0 {
		t.Errorf("uppercase rewritten lookup reached upstream (%d hits)", hits.hits)
	}
}

// TestRewriteNodataFamilyMismatch pins the RFC NODATA behavior: a query for
// an address family the mapping does not provide gets empty authoritative
// NOERROR, not an answer and not NXDOMAIN.
func TestRewriteNodataFamilyMismatch(t *testing.T) {
	t.Parallel()
	hits := &upstreamCounter{}
	up := rewriteUpstream(t, hits)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := New(Config{Upstream: up}, db.DB(), slogDiscard())

	// IPv4 mapping queried as AAAA.
	srv.ApplyRewrite("v4.lan", "192.168.10.20")
	resp, err := srv.exchange(queryMsg("v4.lan", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("exchange AAAA on v4 rewrite: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("expected NODATA, got rcode=%d answers=%+v", resp.Rcode, resp.Answer)
	}
	if !resp.Authoritative {
		t.Error("NODATA answer must be authoritative")
	}

	// IPv6 mapping queried as A.
	srv.ApplyRewrite("v6.lan", "fd00::41")
	resp, err = srv.exchange(queryMsg("v6.lan", dns.TypeA))
	if err != nil {
		t.Fatalf("exchange A on v6 rewrite: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("expected NODATA, got rcode=%d answers=%+v", resp.Rcode, resp.Answer)
	}

	// Pure IPv6 mapping served as AAAA.
	resp, err = srv.exchange(queryMsg("v6.lan", dns.TypeAAAA))
	if err != nil {
		t.Fatalf("exchange AAAA on v6 rewrite: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected 1 AAAA answer, got %+v", resp.Answer)
	}
	if aaaa, ok := resp.Answer[0].(*dns.AAAA); !ok || !aaaa.AAAA.Equal(net.ParseIP("fd00::41").To16()) {
		t.Fatalf("wrong AAAA value: %+v", resp.Answer[0])
	}
	if hits.hits != 0 {
		t.Errorf("rewritten lookups reached upstream %d times", hits.hits)
	}
}

// TestRewriteSubdomainAndRemoval: parent-domain rewrite covers its hosts;
// RemoveRewrite returns the flow to normal upstream resolution.
func TestRewriteSubdomainAndRemoval(t *testing.T) {
	t.Parallel()
	hits := &upstreamCounter{}
	up := rewriteUpstream(t, hits)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := New(Config{Upstream: up}, db.DB(), slogDiscard())

	srv.ApplyRewrite("nas.lan", "192.168.10.2")
	resp, err := srv.exchange(queryMsg("www.nas.lan", dns.TypeA))
	if err != nil {
		t.Fatalf("exchange subdomain of rewrite: %v", err)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected rewrite answer for subdomain, got %+v", resp.Answer)
	}
	if hits.hits != 0 {
		t.Errorf("rewritten subdomain reached upstream %d times", hits.hits)
	}

	srv.RemoveRewrite("NAS.LAN.")
	if _, err := srv.exchange(queryMsg("nas.lan", dns.TypeA)); err != nil {
		t.Fatalf("exchange after removal: %v", err)
	}
	if hits.hits != 1 {
		t.Fatalf("after removal upstream hits = %d, want 1", hits.hits)
	}
}

// TestRewriteBeatsBlocklistCacheAndStale: rewrite must win over the
// blocklist, and ApplyRewrite must purge a stale cached upstream answer.
func TestRewriteBeatsBlocklistAndCache(t *testing.T) {
	t.Parallel()
	hits := &upstreamCounter{}
	up := rewriteUpstream(t, hits)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := New(Config{Upstream: up, Blocklist: []string{"blocked.lan"}}, db.DB(), slogDiscard())

	// 1) Cache a real upstream answer for the domain.
	resp, err := srv.exchange(queryMsg("blocked.lan", dns.TypeA))
	if err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	if hits.hits != 1 {
		t.Fatalf("cache warmup upstream hits = %d, want 1", hits.hits)
	}

	// 2) Introduce the rewrite: cached upstream answer must be dropped and
	// the synthetic value served instead.
	srv.ApplyRewrite("blocked.lan", "192.168.10.9")
	if got, _ := srv.cache.Get("blocked.lan", dns.TypeA); got != nil {
		t.Fatal("ApplyRewrite did not purge the cached answer")
	}
	resp, err = srv.exchange(queryMsg("blocked.lan", dns.TypeA))
	if err != nil {
		t.Fatalf("exchange after rewrite: %v", err)
	}
	// Blocklist hit must not shadow the rewrite (handled before the NXDOMAIN
	// branch in handle; exchange answers the rewrite unconditionally).
	if len(resp.Answer) != 1 || !resp.Answer[0].(*dns.A).A.Equal(net.IPv4(192, 168, 10, 9)) {
		t.Fatalf("expected rewritten 192.168.10.9, got %+v", resp.Answer)
	}
	if hits.hits != 1 {
		t.Errorf("rewritten lookup hit upstream again (%d hits)", hits.hits)
	}

	// 3) Removal re-purges: next query goes upstream again.
	srv.RemoveRewrite("blocked.lan")
	if got, _ := srv.cache.Get("blocked.lan", dns.TypeA); got != nil {
		t.Fatal("RemoveRewrite did not purge the leftover cache entry")
	}
}

// TestRewriteBrokenIPFallsThrough: a mapping with a non-IP value must not
// wedge the resolution path — the server falls through to upstream.
func TestRewriteBrokenIPFallsThrough(t *testing.T) {
	t.Parallel()
	hits := &upstreamCounter{}
	up := rewriteUpstream(t, hits)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := New(Config{Upstream: up}, db.DB(), slogDiscard())

	srv.rewritesMu.Lock()
	srv.rewrites["legacy.lan"] = "not-an-ip"
	srv.rewritesMu.Unlock()

	if _, err := srv.exchange(queryMsg("legacy.lan", dns.TypeA)); err != nil {
		t.Fatalf("exchange with broken rewrite: %v", err)
	}
	if hits.hits != 1 {
		t.Fatalf("broken rewrite should fall through to upstream, hits=%d", hits.hits)
	}
}

// TestRewriteHandleBypassesBlocklist is the end-to-end guard: a real query
// over UDP for a blocklisted-rewritten domain gets the rewrite answer.
func TestRewriteHandleBypassesBlocklist(t *testing.T) {
	if testing.Short() {
		t.Skip("network bind test")
	}
	hits := &upstreamCounter{}
	up := rewriteUpstream(t, hits)
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	srv := New(Config{Upstream: up, Blocklist: []string{"nas.lan"}}, nil, discardLogger())
	srv.snk = store.NewSink(db.DB(), nil, "")
	srv.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	srv.ApplyRewrite("nas.lan", "192.168.10.2")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start(ctx, addr) }()
	select {
	case err := <-serveErr:
		t.Fatalf("server exited immediately: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	c := &dns.Client{Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(queryMsg("nas.lan", dns.TypeA), addr)
	if err != nil {
		t.Fatalf("client exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("expected rewrite answer, got rcode=%d answers=%+v", resp.Rcode, resp.Answer)
	}
	if a := resp.Answer[0].(*dns.A); !a.A.Equal(net.IPv4(192, 168, 10, 2)) {
		t.Fatalf("wrong rewrite value: %+v", resp.Answer[0])
	}
	if hits.hits != 0 {
		t.Errorf("rewritten query reached upstream %d times", hits.hits)
	}
	if got := srv.blockMatcher.Match("nas.lan"); !got {
		t.Fatal("test setup: domain expected to be blocklisted")
	}
}
