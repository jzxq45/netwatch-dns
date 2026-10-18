// Package dns implements a forwarding DNS server that logs every query
// (client, domain, qtype) into SQLite before resolving via upstream.
package dns

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"monitor/internal/metrics"
	"monitor/internal/store"
)

const upstreamTO = 2 * time.Second

// maxInflight bounds in-flight upstream-pending lookups. Each handler holds
// at most 2 upstream timeouts (~4s); without a cap a query flood spawns an
// unbounded goroutine/socket storm. Over the cap → REFUSED (fail-closed).
const maxInflight = 512

// defaultDoHBlocklist: endpoints popular DoH resolvers use; router-side
// blocking cannot keep up with CDN-hosted ones, so we drop them at DNS level.
// Config Blocklist (non-nil) replaces this list entirely.
var defaultDoHBlocklist = []string{
	"dns.google",
	"dns.google.com",
	"chrome.cloudflare-dns.com",
	"cloudflare-dns.com",
	"mozilla.cloudflare-dns.com",
	"doh.opendns.com",
	"dns.quad9.net",
	"doh.adguard.com",
	"dns.adguard.com",
}

// defaultNoiseDomains — SDK/телеметрия и прочий фоновый трафик.
// Пишем в dns_log с noise=1 (intel), но не в stdout и не в дефолтную ленту.
// Config NoiseDomains (non-nil) replaces this list entirely.
var defaultNoiseDomains = []string{
	"*.gstatic.com", // connectivitycheck и прочие поддмены
	"*.in-addr.arpa",
	"mtalk.google.com",
	"optimizationguide-pa.googleapis.com",
	"readaloud.googleapis.com",
}

const insertQuery = "INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)"

type Record struct {
	ClientIP string
	Domain   string
	QType    string
	TS       int64
}

// Config carries every tunable. Values are normalized once in New, so the
// serve path never races field mutation ("set the field before Start" was a
// contract nobody could enforce).
type Config struct {
	Upstream       string   // host:port of the upstream resolver
	SkipPTR        bool     // answer empty NOERROR for PTR in-addr.arpa; no log/upstream
	Blocklist      []string // non-nil replaces defaultDoHBlocklist
	NoiseDomains   []string // non-nil replaces defaultNoiseDomains
	SearchSuffixes []string // LAN search suffixes stripped from logged names only
	DoHLogLevel    string   // debug|info|off for dns_blocked_doh lines
	DoHWindow      string   // aggregation window, e.g. "10s"
}

// Server forwards queries to upstream and records them asynchronously.
type Server struct {
	upstream string
	log      *slog.Logger
	snk      *store.Sink

	// OnRecord, when set, is called for every accepted query (devices feed).
	// Must be set before Start; invoked synchronously on the serve path.
	OnRecord func(Record)

	// Effective lists/levels, normalized once in New (handler code reads
	// them concurrently — never written after construction).
	skipPTR   bool
	blocklist []string
	noiselist []string
	dohLevel  slog.Level
	window    time.Duration
	suffixes  []string
	aggr      *blockAggregator

	// inflight bounds concurrent handlers (admission control; DNSInflight is
	// the observable mirror).
	inflight atomic.Int64
}

func New(cfg Config, db *sql.DB, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	blocklist := defaultDoHBlocklist
	if cfg.Blocklist != nil {
		blocklist = cfg.Blocklist
	}
	noiselist := defaultNoiseDomains
	if cfg.NoiseDomains != nil {
		noiselist = cfg.NoiseDomains
	}
	return &Server{
		upstream:  cfg.Upstream,
		log:       log,
		snk:       store.NewSink(db, log, insertQuery),
		skipPTR:   cfg.SkipPTR,
		blocklist: normalizeEntries(blocklist),
		noiselist: normalizeEntries(noiselist),
		dohLevel:  dohLevel(cfg.DoHLogLevel),
		window:    parseWindow(cfg.DoHWindow, 10*time.Second, log),
		suffixes:  normalizeEntries(cfg.SearchSuffixes),
		aggr:      newBlockAggregator(dohLevel(cfg.DoHLogLevel), log),
	}
}

// normalizeEntries lowercases, trims spaces and drops trailing dots so the
// match below is case-insensitive and FQDN-form agnostic.
func normalizeEntries(list []string) []string {
	out := make([]string, 0, len(list))
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		e = strings.TrimSuffix(e, ".")
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

// isBlocked: exact or subdomain (suffix) match against the list.
func (s *Server) isBlocked(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, e := range s.blocklist {
		if name == e || strings.HasSuffix(name, "."+e) {
			return true
		}
	}
	return false
}

// isNoise: pattern match against the noise list. Patterns:
//   - "*.suffix.tld" — wildcard label: sub.suffix.tld and suffix.tld match,
//     nonsuffix.tld does not (boundary must be a full dot);
//   - plain "host.tld" — exact-or-subdomain like the blocklist.
func (s *Server) isNoise(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, p := range s.noiselist {
		if strings.HasPrefix(p, "*.") {
			base := p[2:]
			if name == base || strings.HasSuffix(name, "."+base) {
				return true
			}
			continue
		}
		if name == p || strings.HasSuffix(name, "."+p) {
			return true
		}
	}
	return false
}

// trustedClient reports whether the source is a LAN client we serve
// (loopback, private ranges, link-local). Anything else — e.g. a packet
// DNAT'ed from the WAN — gets REFUSED: we are not an open recursive resolver
// or an amplification target.
func trustedClient(host string) bool {
	a, err := netip.ParseAddr(host) // ParseAddr, not ParseIP: handles v6 zones
	if err != nil {
		return false
	}
	return a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast()
}

// Start serves DNS (UDP+TCP) on addr until ctx is done. Returns only after
// both listeners closed, the block-log flushed and the async writer flushed
// accepted records — the caller may close the DB once Start returns.
func (s *Server) Start(ctx context.Context, addr string) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sinkDone := make(chan error, 1)
	go func() { sinkDone <- s.snk.Start(sctx) }()

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(s.handle)}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(s.handle)}

	eg, egctx := errgroup.WithContext(sctx)
	for _, srv := range []*dns.Server{udp, tcp} {
		srv := srv
		eg.Go(func() error { return serve(egctx, srv) })
	}
	// Block-log flusher: one aggregated line per (client, domain) per window;
	// final flush on ctx done, before Start returns.
	eg.Go(func() error {
		t := time.NewTicker(s.window)
		defer t.Stop()
		for {
			select {
			case <-egctx.Done():
				s.aggr.flush()
				return nil
			case <-t.C:
				s.aggr.flush()
			}
		}
	})
	err := eg.Wait()
	cancel()   // sink exits via sctx.Done
	<-sinkDone // drain+flush finished — safe for caller to close the DB
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("dns serve %s: %w", addr, err)
	}
	return nil
}

// serve runs one listener (ListenAndServe creates the socket from Addr) and
// closes it gracefully on ctx done. Shutdown is tracked and awaited: Start
// must not return (and let the caller close the DB) while a listener is still
// serving queries. UDP Shutdown returns immediately; TCP waits for live
// session reads, which is fine on the shutdown path.
func serve(ctx context.Context, srv *dns.Server) error {
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("listener %s: %w", srv.Net, err)
		}
		return nil
	case <-ctx.Done():
		// WithoutCancel: shutdown must finish even though the group ctx that
		// triggered it is already canceled.
		if err := srv.ShutdownContext(context.WithoutCancel(ctx)); err != nil {
			return fmt.Errorf("shutdown %s: %w", srv.Net, err)
		}
		return nil
	}
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	// Admission control before anything else: bound handler goroutines and
	// refuse non-LAN sources. A flood must fail (fast) — not wedge the host.
	n := s.inflight.Add(1)
	metrics.DNSInflight.Add(1)
	if n > maxInflight {
		s.inflight.Add(-1)
		metrics.DNSInflight.Add(-1)
		metrics.DNSRefusedTotal.Add(1)
		refused(w, r)
		return
	}
	defer metrics.DNSInflight.Add(-1)
	defer s.inflight.Add(-1)
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("dns handler panic", "client", clientIP(w.RemoteAddr()),
				"panic", p, "stack", string(debug.Stack()))
			fail(w, r)
		}
	}()

	srcIP := clientIP(w.RemoteAddr())
	if !trustedClient(srcIP) {
		metrics.DNSRefusedTotal.Add(1)
		refused(w, r)
		return
	}
	ts := time.Now().Unix()
	if n := len(r.Question); n == 0 {
		fail(w, r)
		return
	}
	q := r.Question[0]
	// Search suffixes are stripped for logging/storage only; upstream always
	// sees the original name so LAN names like "foo.IGD_Rostelecom" resolve.
	domain := stripSuffixes(q.Name, s.suffixes)
	rec := Record{ClientIP: srcIP, Domain: domain, QType: dns.TypeToString[q.Qtype], TS: ts}

	if s.skipPTR && q.Qtype == dns.TypePTR && strings.HasSuffix(strings.ToLower(q.Name), ".in-addr.arpa.") {
		// PTR noise: answer empty NOERROR locally; client activity still
		// reaches the devices feed, but dns_log and upstream stay clean.
		if s.OnRecord != nil {
			s.OnRecord(rec)
		}
		empty := new(dns.Msg)
		empty.SetReply(r)
		//nolint:errcheck // miekg writes to an in-memory conn; failure is only a lost packet
		_ = w.WriteMsg(empty)
		return
	}

	blocked := s.isBlocked(q.Name)
	noisy := s.isNoise(domain)
	if noisy {
		// noise=1 rows land in the DB (intel) but never in stdout Info.
		s.log.Debug("dns noise", "client", srcIP, "domain", domain, "qtype", dns.TypeToString[q.Qtype])
	} else {
		s.log.Info("dns query", "client", srcIP, "domain", domain, "qtype", dns.TypeToString[q.Qtype], "ts", ts)
	}
	if s.OnRecord != nil {
		s.OnRecord(rec)
	}
	noiseFlag := 0
	if noisy || blocked {
		noiseFlag = 1 // blocked DoH attempts are noise in the feed, too
	}
	if !s.snk.TrySend(srcIP, domain, dns.TypeToString[q.Qtype], ts, noiseFlag) {
		// Overflow is dropped instead of stalling the serve loop — and counted.
		metrics.LogRowsRejectedTotal.Add(1)
		s.log.Warn("dns queue full, record dropped", "client", srcIP, "domain", domain)
	}
	if blocked {
		// DoH endpoints are answered NXDOMAIN here; the request itself is
		// aggregated: one dns_blocked_doh line per (client, domain) per window.
		s.aggr.add(srcIP, domain)
		nxdomain(w, r)
		return
	}
	resp, err := s.exchange(r)
	if err != nil {
		s.log.Error("upstream", "err", err, "upstream", s.upstream)
		fail(w, r)
		return
	}
	// Forwarded queries are built with Id 0; restore the client's transaction ID.
	resp.Id = r.Id
	resp.RecursionAvailable = true
	//nolint:errcheck // miekg writes to an in-memory conn; failure is only a lost packet
	_ = w.WriteMsg(resp)
}

// exchange creates a client per query: dns.Client is not documented as safe for concurrent use.
func (s *Server) exchange(r *dns.Msg) (resp *dns.Msg, err error) {
	q := new(dns.Msg)
	q.SetQuestion(r.Question[0].Name, r.Question[0].Qtype)
	q.RecursionDesired = true

	// TCP fallback: truncated or lost UDP answer retried once over TCP.
	resp, _, err = (&dns.Client{Timeout: upstreamTO, Net: "udp"}).Exchange(q, s.upstream)
	if err != nil || (resp != nil && resp.Truncated) {
		resp, _, err = (&dns.Client{Timeout: upstreamTO, Net: "tcp"}).Exchange(q, s.upstream)
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("upstream: empty response")
	}
	return resp, nil
}

func fail(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeServerFailure)
	//nolint:errcheck // only a lost UDP packet
	_ = w.WriteMsg(m)
}

// refused answers REFUSED — the right signal for clients we decline to serve.
func refused(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeRefused)
	//nolint:errcheck // only a lost UDP packet
	_ = w.WriteMsg(m)
}

// nxdomain answers non-existence without touching upstream.
func nxdomain(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeNameError)
	//nolint:errcheck // only a lost UDP packet
	_ = w.WriteMsg(m)
}

func clientIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
