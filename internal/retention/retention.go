// Package retention prunes log tables older than the configured window.
package retention

import (
	"context"
	"log/slog"
	"time"

	"monitor/internal/store"
)

// Start sweeps daily (plus once at startup) and removes rows older than days.
// It blocks until ctx is done, so it can run in an errgroup: g.Wait() returns
// only after this stops sweeping, which the caller relies on to close the DB
// without racing an in-flight DeleteOld.
func Start(ctx context.Context, db *store.Store, days int) error {
	tick := time.NewTicker(24 * time.Hour)
	defer tick.Stop()
	cutoff := func() int64 { return time.Now().AddDate(0, 0, -days).Unix() }
	sweep := func() {
		for table := range store.RetentionTables {
			n, err := db.DeleteOld(ctx, table, cutoff())
			if err != nil {
				slog.Error("retention", "table", table, "err", err)
				continue
			}
			if n > 0 {
				slog.Info("retention", "table", table, "deleted", n)
			}
		}
	}
	// Startup sweep covers long offline gaps after host downtime.
	sweep()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			sweep()
		}
	}
}
