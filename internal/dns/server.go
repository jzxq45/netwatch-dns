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
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	chanBuffer = 1024 // absorbs bursts; overflow is dropped, never blocks serving
	batchSize  = 100  // matches store batch-insert target from spec
	flushEvery = 100 * time.Millisecond
	upstreamTO = 2 * time.Second
)

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
	db       *sql.DB

	records chan Record
	wg      sync.WaitGroup

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
		db:       db,
		records:  make(chan Record, chanBuffer),
	}
}

// Start serves DNS (UDP+TCP) on addr until ctx is done. Returns only after
// the async writer flushed accepted records, so the caller may close the DB.
func (s *Server) Start(ctx context.Context, addr string) error {
	sctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel() // stops writeLoop via sctx.Done
		s.wg.Wait()
	}()
	s.wg.Add(1)
	go s.writeLoop(sctx)

	udp := &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(s.handle)}
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(s.handle)}
	eg, egctx := errgroup.WithContext(sctx)
	for _, srv := range []*dns.Server{udp, tcp} {
		srv := srv
		eg.Go(func() error { return serve(egctx, srv) })
	}
	if err := eg.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("dns serve %s: %w", addr, err)
	}
	return nil
}

// serve runs one listener and shuts it down on ctx done.
// ListenAndServe creates the socket from Addr; ActivateAndServe needs an explicit conn.
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
		// Fire-and-forget Shutdown: waiting for the listeners' close-wait
		// (ShutdownContext blocks until the last read deadlines expire, ~2s)
		// is not worth delaying Start's exit path; residuals die on their own.
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
	select {
	case s.records <- Record{ClientIP: clientIP, Domain: q.Name, QType: dns.TypeToString[q.Qtype], TS: ts}:
	default:
		// Drop instead of blocking the serve loop when storage lags.
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
func (s *Server) exchange(r *dns.Msg) (*dns.Msg, error) {
	q := new(dns.Msg)
	q.SetQuestion(r.Question[0].Name, r.Question[0].Qtype)
	q.RecursionDesired = true

	resp, _, err := (&dns.Client{Timeout: upstreamTO, Net: "udp"}).Exchange(q, s.upstream)
	// TCP fallback: truncated or lost UDP answer retried once over TCP.
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
	//nolint:errcheck // see handle: only a lost UDP packet
	_ = w.WriteMsg(m)
}

func clientIP(a net.Addr) string {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}

// writeLoop batches inserts; exits after draining whatever was accepted at cancel time.
func (s *Server) writeLoop(ctx context.Context) {
	defer s.wg.Done()
	batch := make([]Record, 0, batchSize)
	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// WithoutCancel: shutdown flush must outlive the canceled loop context.
		ictx := context.WithoutCancel(ctx)
		tx, err := s.db.BeginTx(ictx, nil)
		if err != nil {
			s.log.Error("dns batch begin", "err", err)
			batch = batch[:0]
			return
		}
		stmt, err := tx.PrepareContext(ictx, insertQuery)
		if err != nil {
			s.log.Error("dns batch prepare", "err", err)
			batch = batch[:0]
			return
		}
		for _, rec := range batch {
			if _, err := stmt.ExecContext(ictx, rec.ClientIP, rec.Domain, rec.QType, rec.TS); err != nil {
				s.log.Error("dns insert", "err", err, "domain", rec.Domain)
			}
		}
		if err := stmt.Close(); err != nil {
			s.log.Error("dns stmt close", "err", err)
		}
		if err := tx.Commit(); err != nil {
			s.log.Error("dns batch commit", "err", err)
		}
		batch = batch[:0]
	}

	for {
		select {
		case rec, ok := <-s.records:
			if !ok {
				flush()
				return
			}
			batch = append(batch, rec)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			// Drain: every record accepted by handle must land in the DB.
			for {
				select {
				case rec := <-s.records:
					batch = append(batch, rec)
				default:
					flush()
					return
				}
			}
		}
	}
}
