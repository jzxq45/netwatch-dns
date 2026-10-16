// Package retention prunes log tables older than the configured window.
package retention

import (
	"context"
	"log/slog"
	"time"

	"monitor/internal/store"
)

// Start sweeps daily (plus once at startup) and removes rows older than days.
func Start(ctx context.Context, db *store.Store, days int) {
	go func() {
		tick := time.NewTicker(24 * time.Hour)
		defer tick.Stop()
		cutoff := func() int64 { return time.Now().AddDate(0, 0, -days).Unix() }
		sweep := func() {
			for table := range store.RetentionTables {
				n, err := db.DeleteOld(table, cutoff())
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
				return
			case <-tick.C:
				sweep()
			}
		}
	}()
}
