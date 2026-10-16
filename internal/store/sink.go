package store

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
	"time"
)

// Sink is the shared async batch writer for log tables. Producers TrySend()
// row-values without blocking; one writer goroutine flushes in transactions.
const (
	sinkBuffer     = 1024 // burst absorb; overflow drops by design (serve paths must not block)
	sinkBatchSize  = 100  // matches batch-insert target from spec
	sinkFlushEvery = 100 * time.Millisecond
)

type Sink struct {
	db    *sql.DB
	log   *slog.Logger
	query string

	values chan []any
	wg     sync.WaitGroup
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
	s.wg.Add(1)
	defer s.wg.Done()

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
			s.log.Error("batch begin", "err", err)
			batch = batch[:0]
			return
		}
		stmt, err := tx.PrepareContext(ictx, s.query)
		if err != nil {
			s.log.Error("batch prepare", "err", err)
			batch = batch[:0]
			return
		}
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
