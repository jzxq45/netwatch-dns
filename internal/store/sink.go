package store

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"monitor/internal/metrics"
)

// Sink is the shared async batch writer for log tables. Producers TrySend()
// row-values without blocking; one writer goroutine flushes in transactions.
const (
	sinkBuffer     = 1024 // burst absorb; overflow drops by design (serve paths must not block)
	sinkBatchSize  = 100  // matches batch-insert target from spec
	sinkFlushEvery = 100 * time.Millisecond

	// sinkMaxFlushFails: retries on the next tick before a batch is declared
	// lost. Short DB hiccups (busy, IO burst) stay lossless; a hard outage
	// converges instead of growing memory forever — losses are counted in
	// metrics.SinkRowsDroppedTotal.
	sinkMaxFlushFails = 5
)

type Sink struct {
	db    *sql.DB
	log   *slog.Logger
	query string

	values chan []any
}

func NewSink(db *sql.DB, log *slog.Logger, insertQuery string) *Sink {
	if log == nil {
		log = slog.Default()
	}
	return &Sink{
		db:     db,
		log:    log,
		query:  insertQuery,
		values: make(chan []any, sinkBuffer),
	}
}

// TrySend queues one row; returns false when the queue is full (caller logs
// the drop — losing a monitoring row beats stalling the capture path).
func (s *Sink) TrySend(vals ...any) bool {
	select {
	case s.values <- vals:
		return true
	default:
		return false
	}
}

// Start flushes until ctx is done, then drains everything already accepted.
// Returns only after the last accepted row is committed — the caller may close
// the DB once Start returns.
func (s *Sink) Start(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	flushFails := 0
	batch := make([][]any, 0, sinkBatchSize)
	ticker := time.NewTicker(sinkFlushEvery)
	defer ticker.Stop()
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// WithoutCancel: shutdown flush must outlive the canceled loop context.
		ictx := context.WithoutCancel(sctx)
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
		// Rollback on every exit path but a successful Commit (no-op then, but
		// required on prepare/exec failures — otherwise the transaction holds
		// the single connection until the next Commit somehow happens).
		defer func() {
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				s.log.Error("batch rollback", "err", err)
			}
		}()
		stmt, err := tx.PrepareContext(ictx, s.query)
		if err != nil {
			flushFails++
			if flushFails < sinkMaxFlushFails {
				s.log.Error("batch prepare, will retry on next tick", "err", err)
				return
			}
			metrics.SinkRowsDroppedTotal.Add(int64(len(batch)))
			s.log.Error("batch dropped after repeated prepare failures", "count", len(batch), "err", err)
			batch = batch[:0]
			flushFails = 0
			return
		}
		flushFails = 0
		dropped := 0
		for _, vals := range batch {
			if _, err := stmt.ExecContext(ictx, vals...); err != nil {
				// Per-row failures don't abort siblings and don't poison the batch.
				dropped++
				s.log.Error("batch row insert", "err", err)
			}
		}
		if err := stmt.Close(); err != nil {
			s.log.Error("batch stmt close", "err", err)
		}
		if err := tx.Commit(); err != nil {
			// Committed rows are indistinguishable from lost ones — count all.
			metrics.SinkRowsDroppedTotal.Add(int64(len(batch)))
			s.log.Error("batch commit", "err", err)
		}
		if dropped > 0 {
			s.log.Warn("batch rows dropped", "count", dropped)
		}
		batch = batch[:0]
	}

	for {
		select {
		case vals, ok := <-s.values:
			if !ok {
				flush()
				return nil
			}
			batch = append(batch, vals)
			if len(batch) >= sinkBatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-sctx.Done():
			// Drain: every row accepted by producers must reach the DB.
			for {
				select {
				case vals := <-s.values:
					batch = append(batch, vals)
				default:
					flush()
					return nil
				}
			}
		}
	}
}
