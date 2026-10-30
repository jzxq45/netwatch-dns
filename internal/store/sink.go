package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	"monitor/internal/metrics"
)

// DNSRow is the strongly typed record pushed to the batch insert sink.
type DNSRow struct {
	ClientIP string
	Domain   string
	QType    string
	TS       int64
	Noise    int
}

// Sink is the shared async batch writer for log tables. Producers TrySend()
// typed records without blocking or allocating; one writer goroutine flushes in transactions.
const (
	sinkBuffer     = 2048 // burst absorb; overflow drops by design (serve paths must not block)
	sinkBatchSize  = 100  // batch-insert chunk
	sinkFlushEvery = 100 * time.Millisecond

	// sinkMaxFlushFails: retries on the next tick before a batch is declared lost.
	sinkMaxFlushFails = 5
)

type Sink struct {
	db  *sql.DB
	log *slog.Logger

	values chan DNSRow
}

func NewSink(db *sql.DB, log *slog.Logger, _ string) *Sink {
	if log == nil {
		log = slog.Default()
	}
	return &Sink{
		db:     db,
		log:    log,
		values: make(chan DNSRow, sinkBuffer),
	}
}

// TrySend queues one row; returns false when the queue is full.
func (s *Sink) TrySend(row DNSRow) bool {
	select {
	case s.values <- row:
		return true
	default:
		return false
	}
}

// Start flushes until ctx is done, then drains everything already accepted.
// Returns only after the last accepted row is committed — the caller may close
// the DB once Start returns.
func (s *Sink) Start(ctx context.Context) error {
	defer func() {
		if p := recover(); p != nil {
			s.log.Error("sink panic recovered", "panic", p, "stack", string(debug.Stack()))
		}
	}()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	flushFails := 0
	batch := make([]DNSRow, 0, sinkBatchSize)
	ticker := time.NewTicker(sinkFlushEvery)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		// WithoutCancel: shutdown flush must outlive the canceled loop context,
		// but bounded with a strict timeout so a stuck DB never wedges graceful shutdown.
		ictx, icancel := context.WithTimeout(context.WithoutCancel(sctx), 5*time.Second)
		defer icancel()

		tx, err := s.db.BeginTx(ictx, nil)
		if err != nil {
			flushFails++
			if flushFails < sinkMaxFlushFails {
				s.log.Error("batch begin, will retry on next tick", "err", err)
				return // keep the batch for the next flush attempt
			}
			metrics.SinkRowsDroppedTotal.Add(int64(len(batch)))
			s.log.Error("batch dropped after repeated begin failures", "count", len(batch), "err", err)
			batch = batch[:0]
			flushFails = 0
			return
		}
		defer func() {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				s.log.Error("batch rollback", "err", err)
			}
		}()

		// Multi-row bulk insert: single ExecContext avoids N+1 driver round-trips.
		var sb strings.Builder
		sb.WriteString("INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES ")
		args := make([]any, 0, len(batch)*5)
		for i, r := range batch {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString("(?,?,?,?,?)")
			args = append(args, r.ClientIP, r.Domain, r.QType, r.TS, r.Noise)
		}

		if _, err := tx.ExecContext(ictx, sb.String(), args...); err != nil {
			flushFails++
			if flushFails < sinkMaxFlushFails {
				s.log.Error("batch multi-insert, will retry", "err", err)
				return
			}
			metrics.SinkRowsDroppedTotal.Add(int64(len(batch)))
			s.log.Error("batch dropped after repeated exec failures", "count", len(batch), "err", err)
			batch = batch[:0]
			flushFails = 0
			return
		}

		if err := tx.Commit(); err != nil {
			metrics.SinkRowsDroppedTotal.Add(int64(len(batch)))
			s.log.Error("batch commit", "err", err)
		}
		flushFails = 0
		batch = batch[:0]
	}

	for {
		select {
		case r, ok := <-s.values:
			if !ok {
				flush()
				return nil
			}
			batch = append(batch, r)
			if len(batch) >= sinkBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-sctx.Done():
			// Drain: every row accepted by producers must reach the DB.
			for {
				select {
				case r := <-s.values:
					batch = append(batch, r)
					if len(batch) >= sinkBatchSize {
						flush()
					}
				default:
					for len(batch) > 0 && flushFails < sinkMaxFlushFails {
						flush()
					}
					return nil
				}
			}
		}
	}
}
