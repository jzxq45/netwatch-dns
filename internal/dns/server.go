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
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"monitor/internal/store"
)

const upstreamTO = 2 * time.Second

// defaultDoHBlocklist: endpoints popular DoH resolvers use; router-side
// blocking cannot keep up with CDN-hosted ones, so we drop them at DNS level.
// YAML `doh_blocklist` replaces this list entirely when set.
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

const insertQuery = "INSERT INTO dns_log (client_ip, domain, qtype, ts) VALUES (?,?,?,?)"

type Record struct {
	ClientIP string
	Domain   string
	QType    string
	TS       int64
}

// Server forwards queries to upstream and records them asynchronously.
type Server struct {
	upstream string
	log      *slog.Logger
	snk      *store.Sink

	// OnRecord, when set, is called for every accepted query (devices feed).
	// Must be set before Start; invoked synchronously on the serve path.
	OnRecord func(Record)

	// Blocklist replaces defaultDoHBlocklist when set before Start.
	Blocklist []string

	// Log-filter knobs (set before Start):
	SkipPTR        bool     // answer empty NOERROR for PTR in-addr.arpa; no log/upstream
	SearchSuffixes []string // LAN search suffixes stripped from logged names only
	DoHLogLevel    string   // debug|info|off for dns_blocked_doh lines
	DoHWindow      string   // aggregation window, e.g. "10s"

	blocklist []string // normalized effective list (set by New/Start)
	dohLevel  slog.Level
	window    time.Duration
	suffixes  []string // normalized lowercase search suffixes
	aggr      *blockAggregator
}

func New(upstream string, db *sql.DB, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		upstream:  upstream,
		log:       log,
		snk:       store.NewSink(db, log, insertQuery),
		blocklist: normalizeEntries(defaultDoHBlocklist),
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

// effective overrides/defaults are normalized once at Start (handlers are concurrent).
func (s *Server) effectiveBlocklist() []string { return s.blocklist }

// isBlocked: exact or subdomain (suffix) match against the list.
func (s *Server) isBlocked(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, e := range s.effectiveBlocklist() {
		if name == e || strings.HasSuffix(name, "."+e) {
			return true
		}
	}
	return false
}

// Start serves DNS (UDP+TCP) on addr until ctx is done. Returns only after
// the async writer flushed accepted records, so the caller may close the DB.
func (s *Server) Start(ctx context.Context, addr string) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sinkDone := make(chan error, 1)
	go func() { sinkDone <- s.snk.Start(sctx) }()

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(s.handle)}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(s.handle)}
	if s.Blocklist != nil {
		// YAML replaces the built-in list entirely; normalize once (no concurrency).
		s.blocklist = normalizeEntries(s.Blocklist)
	}
	s.dohLevel = dohLevel(s.DoHLogLevel)
	s.window = parseWindow(s.DoHWindow, 10*time.Second, s.log)
	s.suffixes = normalizeEntries(s.SearchSuffixes)
	s.aggr = newBlockAggregator(s.dohLevel, s.log)

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
// tells it to close on ctx done. Fire-and-forget Shutdown: waiting for the
// close-wait (~dns read-timeout) is not worth delaying Start's exit path.
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
		go func() {
			if err := srv.Shutdown(); err != nil {
				slog.Error("dns shutdown", "net", srv.Net, "err", err)
			}
		}()
		return nil
	}
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	clientIP := clientIP(w.RemoteAddr())
	ts := time.Now().Unix()
	if n := len(r.Question); n == 0 {
		fail(w, r)
		return
	}
	q := r.Question[0]
	// Search suffixes are stripped for logging/storage only; upstream always
	// sees the original name so LAN names like "foo.IGD_Rostelecom" resolve.
	domain := stripSuffixes(q.Name, s.suffixes)
	rec := Record{ClientIP: clientIP, Domain: domain, QType: dns.TypeToString[q.Qtype], TS: ts}

	if s.SkipPTR && q.Qtype == dns.TypePTR && strings.HasSuffix(strings.ToLower(q.Name), ".in-addr.arpa.") {
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

	s.log.Info("dns query", "client", clientIP, "domain", domain, "qtype", dns.TypeToString[q.Qtype], "ts", ts)
	if s.OnRecord != nil {
		s.OnRecord(rec)
	}
	if !s.snk.TrySend(clientIP, domain, dns.TypeToString[q.Qtype], ts) {
		// Overflow is dropped instead of stalling the serve loop.
		s.log.Warn("dns queue full, record dropped", "client", clientIP, "domain", domain)
	}
	if s.isBlocked(q.Name) {
		// DoH endpoints are answered NXDOMAIN here; the request itself is
		// aggregated: one dns_blocked_doh line per (client, domain) per window.
		s.aggr.add(clientIP, domain)
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
