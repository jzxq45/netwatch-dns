// Package dns implements a forwarding DNS server that logs every query
// (client, domain, qtype) into SQLite before resolving via upstream.
package dns

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"

	"monitor/internal/filter"
	"monitor/internal/metrics"
	"monitor/internal/store"
	"monitor/internal/sysnet"
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

type Record struct {
	ClientIP string
	Domain   string
	QType    string
	TS       int64
	Noise    bool
}

// Config carries every tunable. Values are normalized once in New, so the
// serve path never races field mutation ("set the field before Start" was a
// contract nobody could enforce).
type Config struct {
	Upstream              string   // host:port of the upstream resolver
	FallbackUpstream      string   // used when the primary upstream fails; empty disables
	SkipPTR               bool     // answer empty NOERROR for PTR in-addr.arpa; no log/upstream
	Blocklist             []string // non-nil replaces defaultDoHBlocklist
	BlocklistFiles        []string // hosts/adblock files merged into the blocklist
	BlocklistURLs         []string // remote hosts/adblock lists (cached on disk)
	BlocklistRefreshHours int      // periodic refresh; 0 disables
	NoiseDomains          []string // non-nil replaces defaultNoiseDomains
	SearchSuffixes        []string // LAN search suffixes stripped from logged names only
	DoHLogLevel           string   // debug|info|off for dns_blocked_doh lines
	DoHWindow             string   // aggregation window, e.g. "10s"
}

// Server forwards queries to upstream and records them asynchronously.
type Server struct {
	upstream         string
	fallbackUpstream string
	log              *slog.Logger
	snk              *store.Sink

	// OnRecord, when set, is called for every accepted query (devices feed).
	// Must be set before Start; invoked synchronously on the serve path.
	OnRecord func(Record)

	// Effective lists/levels, normalized once in New (handler code reads
	// them concurrently — never written after construction).
	skipPTR       bool
	blocklist     []string
	blockMatcher  *filter.Matcher
	blocklistURLs []string
	refreshEvery  time.Duration
	noiselist     []string
	dohLevel      slog.Level
	window        time.Duration
	suffixes      []string
	aggr          *blockAggregator

	udpClient *dns.Client
	tcpClient *dns.Client
	dohClient *http.Client
	cache     *dnsCache
	sf        singleflight.Group

	// prefetching tracks async cache-refreshes in flight per cache key so a
	// hot entry is refreshed once, not once per query (cache stampede guard).
	prefetchMu  sync.Mutex
	prefetching map[string]struct{}

	// inflight bounds concurrent handlers (admission control; DNSInflight is
	// the observable mirror).
	inflight atomic.Int64

	// consecutiveFails counts sequential primary upstream errors for circuit breaking.
	consecutiveFails atomic.Int32

	// fallbackUntil holds unix seconds until when primary is in cooldown
	// and queries route directly to fallback without waiting on primary timeouts.
	fallbackUntil atomic.Int64
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
	normalizedBlocklist := normalizeEntries(blocklist)
	blockMatcher := filter.NewMatcher()
	for _, entry := range normalizedBlocklist {
		blockMatcher.Add(entry)
	}
	// Never self-block configured upstream resolvers even if listed in DoH blocks
	for _, up := range []string{cfg.Upstream, cfg.FallbackUpstream} {
		if host := extractUpstreamHost(up); host != "" {
			blockMatcher.AddAllow(host)
		}
	}
	for _, path := range cfg.BlocklistFiles {
		addBlocklistFile(blockMatcher, path, log)
	}
	if len(cfg.BlocklistURLs) > 0 {
		// Bounded timeout on initial startup to ensure UI health probe succeeds
		client := &http.Client{Timeout: 5 * time.Second}
		for _, u := range cfg.BlocklistURLs {
			domains, err := filter.FetchURL(context.Background(), u, blocklistCacheDir, client)
			if err != nil {
				log.Warn("blocklist url", "url", u, "err", err)
				continue
			}
			for _, domain := range domains {
				blockMatcher.Add(domain)
			}
		}
	}
	var refreshEvery time.Duration
	if cfg.BlocklistRefreshHours > 0 {
		refreshEvery = time.Duration(cfg.BlocklistRefreshHours) * time.Hour
	}
	return &Server{
		upstream:         cfg.Upstream,
		fallbackUpstream: cfg.FallbackUpstream,
		log:              log,
		snk:              store.NewSink(db, log, ""),
		skipPTR:          cfg.SkipPTR,
		blocklist:        normalizedBlocklist,
		blockMatcher:     blockMatcher,
		blocklistURLs:    cfg.BlocklistURLs,
		refreshEvery:     refreshEvery,
		noiselist:        normalizeEntries(noiselist),
		dohLevel:         dohLevel(cfg.DoHLogLevel),
		window:           parseWindow(cfg.DoHWindow, 10*time.Second, log),
		suffixes:         normalizeEntries(cfg.SearchSuffixes),
		aggr:             newBlockAggregator(dohLevel(cfg.DoHLogLevel), log),
		udpClient:        &dns.Client{Timeout: upstreamTO, Net: "udp"},
		tcpClient:        &dns.Client{Timeout: upstreamTO, Net: "tcp"},
		dohClient:        &http.Client{Timeout: upstreamTO},
		cache:            newDNSCache(10000),
		prefetching:      make(map[string]struct{}),
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

// addBlocklistFile parses one hosts/adblock/plain file into m. A broken file
// is logged and skipped: blocking the whole DNS server over it is worse.
func addBlocklistFile(m *filter.Matcher, path string, log *slog.Logger) {
	f, err := os.Open(path)
	if err != nil {
		log.Warn("blocklist file open", "path", path, "err", err)
		return
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Warn("blocklist file close", "path", path, "err", cerr)
		}
	}()
	domains, err := filter.Parse(f)
	if err != nil {
		log.Warn("blocklist file parse", "path", path, "err", err)
		return
	}
	for _, domain := range domains {
		m.Add(domain)
	}
}

// BlockedRulesCount returns the number of unique domains in the blocklist.
func (s *Server) BlockedRulesCount() int {
	return s.blockMatcher.Count()
}

// ApplyCustomRule adds a runtime block or allow override.
func (s *Server) ApplyCustomRule(domain, action string) {
	switch action {
	case store.RuleBlock:
		s.blockMatcher.Add(domain)
	case store.RuleAllow:
		s.blockMatcher.AddAllow(domain)
	}
}

// RemoveCustomRule drops a runtime override from both rule sets.
func (s *Server) RemoveCustomRule(domain string) {
	s.blockMatcher.RemoveRule(domain)
}

// isBlocked reports whether name is in the blocklist (exact or parent domain).
func (s *Server) isBlocked(name string) bool {
	return s.blockMatcher.Match(name)
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

var (
	localV6PrefixesMu sync.RWMutex
	localV6Prefixes   []netip.Prefix
	localV6Updated    time.Time
)

func isLocalSubnetIPv6(addr netip.Addr) bool {
	localV6PrefixesMu.RLock()
	if time.Since(localV6Updated) < 30*time.Second {
		for _, p := range localV6Prefixes {
			if p.Contains(addr) {
				localV6PrefixesMu.RUnlock()
				return true
			}
		}
		localV6PrefixesMu.RUnlock()
		return false
	}
	localV6PrefixesMu.RUnlock()

	localV6PrefixesMu.Lock()
	defer localV6PrefixesMu.Unlock()
	localV6Prefixes = localV6Prefixes[:0]
	if ifaddrs, err := net.InterfaceAddrs(); err == nil {
		for _, ia := range ifaddrs {
			if ipnet, ok := ia.(*net.IPNet); ok {
				if pref, err := netip.ParsePrefix(ipnet.String()); err == nil && pref.Addr().Is6() {
					localV6Prefixes = append(localV6Prefixes, pref)
				}
			}
		}
	}
	localV6Updated = time.Now()
	for _, p := range localV6Prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func extractUpstreamHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		u, err := url.Parse(addr)
		if err == nil && u.Hostname() != "" {
			return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
		}
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil && host != "" {
		return strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return strings.ToLower(strings.TrimSuffix(addr, "."))
}

// trustedClient reports whether the source is a LAN client we serve
// (loopback, private ranges, link-local, or belonging to a locally attached IPv6 prefix).
// Anything else — e.g. a packet DNAT'ed from the WAN — gets REFUSED: we are not an open recursive resolver
// or an amplification target.
func trustedClient(host string) bool {
	a, err := netip.ParseAddr(host) // ParseAddr, not ParseIP: handles v6 zones
	if err != nil {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() {
		return true
	}
	if a.Is6() {
		return isLocalSubnetIPv6(a)
	}
	return false
}

// Start serves DNS (UDP+TCP) on addr until ctx is done. Returns only after
// both listeners closed, the block-log flushed and the async writer flushed
// accepted records — the caller may close the DB once Start returns.
func (s *Server) Start(ctx context.Context, addr string) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sinkDone := make(chan error, 1)
	go func() { sinkDone <- s.snk.Start(sctx) }()

	var refreshDone chan struct{}
	if s.refreshEvery > 0 && len(s.blocklistURLs) > 0 {
		refreshDone = make(chan struct{})
		go func() {
			defer close(refreshDone)
			s.refreshLoop(sctx)
		}()
	}

	usedAddr := addr
	err := s.serveListeners(sctx, usedAddr)
	// Windows: ICS/WSL often owns 0.0.0.0:53 while the LAN interface is free.
	// Bind on the concrete LAN address instead of giving up entirely.
	if err != nil && isAddrInUse(err) && isWildcardAddr(addr) {
		if lanIP := sysnet.OutboundLANIP(); lanIP != "" && lanIP != "127.0.0.1" {
			fallbackAddr := net.JoinHostPort(lanIP, "53")
			s.log.Warn("dns 0.0.0.0:53 busy, falling back to LAN IP", "lan_addr", fallbackAddr)
			usedAddr = fallbackAddr
			err = s.serveListeners(sctx, fallbackAddr)
		}
	}
	cancel() // sink and refresh stop via sctx.Done
	if refreshDone != nil {
		<-refreshDone
	}
	sinkErr := <-sinkDone // drain+flush finished — safe for caller to close the DB
	if err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("dns serve %s: %w", usedAddr, err)
	}
	if sinkErr != nil && !errors.Is(sinkErr, context.Canceled) {
		return fmt.Errorf("sink: %w", sinkErr)
	}
	return nil
}

// blocklistCacheDir keeps downloaded lists across restarts for offline use.
var blocklistCacheDir = filepath.Join(".", ".cache", "blocklists")

// refreshLoop periodically re-downloads remote blocklists until ctx is done.
func (s *Server) refreshLoop(ctx context.Context) {
	t := time.NewTicker(s.refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshBlocklists(ctx)
		}
	}
}

// refreshBlocklists fetches every configured URL and merges new domains into
// the live matcher (existing rules are never removed: fail-open on shrink).
func (s *Server) refreshBlocklists(ctx context.Context) {
	client := &http.Client{Timeout: 30 * time.Second}
	for _, u := range s.blocklistURLs {
		domains, err := filter.FetchURL(ctx, u, blocklistCacheDir, client)
		if err != nil {
			s.log.Warn("blocklist url refresh", "url", u, "err", err)
			continue
		}
		for _, domain := range domains {
			s.blockMatcher.Add(domain)
		}
	}
}

// serveListeners runs the UDP+TCP listeners and the block-log flusher until
// ctx is done or one listener fails.
func (s *Server) serveListeners(ctx context.Context, addr string) error {
	udp := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(s.handle)}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(s.handle)}

	eg, egctx := errgroup.WithContext(ctx)
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
	return eg.Wait()
}

// isWildcardAddr reports whether a listen address covers every interface.
func isWildcardAddr(addr string) bool {
	return addr == ":53" || strings.HasPrefix(addr, "0.0.0.0:")
}

// isAddrInUse recognizes a bind conflict, including the localized Windows
// message ("только одно использование") seen under a non-English locale.
func isAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "только одно использование")
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
		// triggered it is already canceled, but bounded with a strict timeout.
		sctx, scancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer scancel()
		if err := srv.ShutdownContext(sctx); err != nil {
			return fmt.Errorf("shutdown %s: %w", srv.Net, err)
		}
		if waitErr := <-errCh; waitErr != nil && !errors.Is(waitErr, net.ErrClosed) {
			return fmt.Errorf("listener %s: %w", srv.Net, waitErr)
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
	rec.Noise = noisy || blocked
	if s.OnRecord != nil {
		s.OnRecord(rec)
	}
	noiseFlag := 0
	if noisy || blocked {
		noiseFlag = 1 // blocked DoH attempts are noise in the feed, too
	}
	if !s.snk.TrySend(store.DNSRow{
		ClientIP: srcIP,
		Domain:   domain,
		QType:    dns.TypeToString[q.Qtype],
		TS:       ts,
		Noise:    noiseFlag,
	}) {
		// Overflow is dropped instead of stalling the serve loop — and counted.
		metrics.LogRowsRejectedTotal.Add(1)
		s.log.Warn("dns queue full, record dropped", "client", srcIP, "domain", domain)
	}
	if blocked {
		metrics.DNSBlockedTotal.Add(1)
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

func (s *Server) exchange(r *dns.Msg) (resp *dns.Msg, err error) {
	q := r.Question[0]
	cacheKey := fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSuffix(q.Name, ".")), q.Qtype)

	// Client's EDNS0 UDP payload size (RFC 6891), sent downstream when the
	// client advertised one. Clamped to 1232 (DNS Flag Day 2020) so big
	// answers never push the upstream UDP path into IP fragmentation — the
	// main truncation/amplification hazard on the open Internet.
	clientEDNS := ednsUDPSize(r)

	if cached, prefetch := s.cache.Get(q.Name, q.Qtype); cached != nil {
		metrics.DNSCacheHitsTotal.Add(1)
		if prefetch {
			s.refreshAsync(q, clientEDNS)
		}
		return cached, nil
	}
	metrics.DNSCacheMissesTotal.Add(1)

	val, err, _ := s.sf.Do(cacheKey, func() (any, error) {
		if cached, prefetch := s.cache.Get(q.Name, q.Qtype); cached != nil {
			if prefetch {
				s.refreshAsync(q, clientEDNS)
			}
			// The outer path already counted this miss; a lucky hit here
			// (entry refreshed between the two Get calls) just answers fast.
			return cached, nil
		}
		res, upErr := s.resolveUpstream(q, clientEDNS)
		if upErr != nil {
			return nil, upErr
		}
		if res.Rcode == dns.RcodeSuccess || res.Rcode == dns.RcodeNameError {
			s.cache.Set(q.Name, q.Qtype, res)
		}
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	msg, ok := val.(*dns.Msg)
	if !ok || msg == nil {
		return nil, errors.New("upstream: empty response")
	}
	return msg.Copy(), nil
}

// refreshAsync re-resolves a soon-to-expire ("hot") cache entry in the
// background without delaying the answer served from the cache — the
// AdGuard Home / CoreDNS optimistic prefetch pattern. Refreshes never
// count cache hits/misses: they are upstream maintenance, not client traffic.
func (s *Server) refreshAsync(q dns.Question, ednsSize uint16) {
	cacheKey := fmt.Sprintf("%s:%d", strings.ToLower(strings.TrimSuffix(q.Name, ".")), q.Qtype)
	s.prefetchMu.Lock()
	if _, busy := s.prefetching[cacheKey]; busy {
		s.prefetchMu.Unlock()
		return
	}
	s.prefetching[cacheKey] = struct{}{}
	s.prefetchMu.Unlock()
	go func() {
		defer func() {
			s.prefetchMu.Lock()
			delete(s.prefetching, cacheKey)
			s.prefetchMu.Unlock()
		}()
		s.sf.Do(cacheKey, func() (any, error) {
			res, err := s.resolveUpstream(q, ednsSize)
			if err != nil {
				return nil, err
			}
			if res.Rcode == dns.RcodeSuccess || res.Rcode == dns.RcodeNameError {
				s.cache.Set(q.Name, q.Qtype, res)
			}
			return res, nil
		})
	}()
}

func (s *Server) resolveUpstream(q dns.Question, ednsSize uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(q.Name, q.Qtype)
	msg.RecursionDesired = true
	// RFC 6891: only advertise EDNS0 downstream when the client used it;
	// size is the client's, clamped by DNS Flag Day 2020 (max 1232).
	if size := clampEDNSUDP(ednsSize); size > 0 {
		msg.SetEdns0(size, false)
	}
	hasFallback := s.fallbackUpstream != "" && s.fallbackUpstream != s.upstream
	now := time.Now().Unix()

	// Circuit breaker: if primary is in cooldown, query fallback directly to avoid 2-4s timeout penalty
	if hasFallback && now < s.fallbackUntil.Load() {
		resp, err := s.tryUpstream(msg, s.fallbackUpstream)
		if err == nil {
			return resp, nil
		}
		// Fallback failed; reset cooldown and attempt primary as fallback
		s.fallbackUntil.Store(0)
	}

	resp, err := s.tryUpstream(msg, s.upstream)
	if err != nil {
		if hasFallback {
			s.log.Warn("primary upstream failed, trying fallback",
				"upstream", s.upstream, "fallback", s.fallbackUpstream, "err", err)
			fails := s.consecutiveFails.Add(1)
			if fails >= 3 {
				// Trip circuit breaker: route directly to fallback for 30s
				s.fallbackUntil.Store(time.Now().Add(30 * time.Second).Unix())
			}
			resp, err = s.tryUpstream(msg, s.fallbackUpstream)
			if err != nil {
				return nil, err
			}
			s.consecutiveFails.Store(0)
			return resp, nil
		}
		return nil, err
	}
	s.consecutiveFails.Store(0)
	s.fallbackUntil.Store(0)
	return resp, nil
}

// tryUpstream exchanges one query against addr (DoH endpoint or host:port
// UDP with TCP retry on truncation/error).
func (s *Server) tryUpstream(msg *dns.Msg, addr string) (*dns.Msg, error) {
	if strings.HasPrefix(addr, "https://") || strings.HasPrefix(addr, "http://") {
		return s.exchangeDoH(msg, addr)
	}

	// UDP with TCP fallback
	resp, _, err := s.udpClient.Exchange(msg, addr)
	if err != nil || (resp != nil && resp.Truncated) {
		resp, _, err = s.tcpClient.Exchange(msg, addr)
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("upstream: empty response")
	}
	return resp, nil
}

func (s *Server) exchangeDoH(msg *dns.Msg, url string) (*dns.Msg, error) {
	wire, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack doh query: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("create doh req: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	httpResp, err := s.dohClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("doh upstream: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("doh upstream status %d", httpResp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(httpResp.Body, 65536))
	if err != nil {
		return nil, fmt.Errorf("read doh resp: %w", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpack doh resp: %w", err)
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

// maxUpstreamEDNS is the largest UDP payload size we advertise upstream
// (DNS Flag Day 2020): 1232 guarantees DNS-over-UDP answers avoid IP
// fragmentation on typical MTU 1500 / tunnel paths.
const maxUpstreamEDNS = 1232

// ednsUDPSize extracts the client's advertised EDNS0 UDP payload size
// (RFC 6891); 0 means the client sent no EDNS0 record.
func ednsUDPSize(r *dns.Msg) uint16 {
	if opt := r.IsEdns0(); opt != nil && opt.UDPSize() > 0 {
		return opt.UDPSize()
	}
	return 0
}

// clampEDNSUDP maps a client EDNS0 size onto a safe upstream value:
// 0 (no EDNS0) stays 0, smaller clients are lifted to the 512 minimum,
// and anything above 1232 is capped.
func clampEDNSUDP(size uint16) uint16 {
	switch {
	case size == 0:
		return 0
	case size < 512:
		return 512
	case size > maxUpstreamEDNS:
		return maxUpstreamEDNS
	default:
		return size
	}
}
