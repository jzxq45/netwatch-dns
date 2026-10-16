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
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"monitor/internal/store"
)

const upstreamTO = 2 * time.Second

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
}

func New(upstream string, db *sql.DB, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		upstream: upstream,
		log:      log,
		snk:      store.NewSink(db, log, insertQuery),
	}
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
	eg, egctx := errgroup.WithContext(sctx)
	for _, srv := range []*dns.Server{udp, tcp} {
		srv := srv
		eg.Go(func() error { return serve(egctx, srv) })
	}
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
	rec := Record{ClientIP: clientIP, Domain: q.Name, QType: dns.TypeToString[q.Qtype], TS: ts}
	s.log.Info("dns query", "client", clientIP, "domain", q.Name, "qtype", dns.TypeToString[q.Qtype], "ts", ts)
	if s.OnRecord != nil {
		s.OnRecord(rec)
	}
	if !s.snk.TrySend(clientIP, q.Name, dns.TypeToString[q.Qtype], ts) {
		// Overflow is dropped instead of stalling the serve loop.
		s.log.Warn("dns queue full, record dropped", "client", clientIP, "domain", q.Name)
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

func clientIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
