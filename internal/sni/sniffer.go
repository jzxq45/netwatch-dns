// Package sni logs TLS server names seen in ClientHello traffic on TCP/443.
// Capture backends: none (stub) by default; pcap-backed source when built
// with -tags pcap on a host that has Npcap.
package sni

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"monitor/internal/store"
)

// Frame is one TCP payload segment from a client towards a 443 server.
type Frame struct {
	ClientIP string
	Payload  []byte
}

// Source produces frames until ctx is done.
type Source interface {
	Start(ctx context.Context) (<-chan Frame, error)
}

const insertQuery = "INSERT INTO sni_log (client_ip, sni, ts) VALUES (?,?,?)"

// Sniffer parses frames and persists rows via the shared store sink.
type Sniffer struct {
	log *slog.Logger
	snk Sink

	// OnRecord, when set, is called for every accepted row (devices feed).
	// Must be set before Start; invoked on the writer path.
	OnRecord func(clientIP, host string, ts int64)
}

// Sink pins the minimal surface of store.Sink used here (consumer-side
// interface; the concrete store.Sink implements it).
type Sink interface {
	TrySend(vals ...any) bool
	Start(ctx context.Context) error
}

func New(db *sql.DB, log *slog.Logger) *Sniffer {
	if log == nil {
		log = slog.Default()
	}
	return &Sniffer{
		log: log,
		snk: store.NewSink(db, log, insertQuery),
	}
}

func nowUnix() int64 { return time.Now().Unix() }

// Start consumes frames until ctx is done; returns after the sink flushed.
func (s *Sniffer) Start(ctx context.Context, src Source) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := src.Start(sctx)
	if err != nil {
		return errors.New("no capture backend available") // wrapped by caller
	}
	sinkDone := make(chan error, 1)
	go func() { sinkDone <- s.snk.Start(sctx) }()

	for {
		select {
		case f, ok := <-ch:
			if !ok {
				cancel()
				<-sinkDone
				return nil
			}
			s.handle(f)
		case <-sctx.Done():
			// Source channel may still hold frames — drain what arrived.
		drain:
			for {
				select {
				case f := <-ch:
					s.handle(f)
				default:
					break drain
				}
			}
			<-sinkDone
			return nil
		}
	}
}

func (s *Sniffer) handle(f Frame) {
	res, ok := Parse(f.Payload)
	if !ok {
		return
	}
	host := res.Host
	if host == "" {
		if !res.ECH {
			return // legacy hello without extensions — nothing to log
		}
		host = "<ech>"
	}
	ts := nowUnix()
	if s.OnRecord != nil {
		s.OnRecord(f.ClientIP, host, ts)
	}
	if !s.snk.TrySend(f.ClientIP, host, ts) {
		s.log.Warn("sni queue full, row dropped", "client", f.ClientIP, "host", host)
	}
}
