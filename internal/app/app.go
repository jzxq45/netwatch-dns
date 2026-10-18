// Package app wires every monitor component (DNS server, device resolver,
// web UI, retention) under one errgroup lifecycle. cmd/monitor (console)
// and cmd/netwatch (Windows GUI) both run through Run — one ownership path,
// no duplicated wiring that can drift.
package app

import (
	"context"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"monitor/internal/config"
	"monitor/internal/devices"
	dnssrv "monitor/internal/dns"
	"monitor/internal/retention"
	"monitor/internal/store"
	"monitor/internal/web"
)

// Run starts every component and blocks until ctx is done or one of them
// fails (errgroup cancels the rest). Returns only after all components
// stopped — the caller may release anything Run touched (the DB handle is
// owned here and closed last).
func Run(ctx context.Context, cfg config.Config) error {
	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			slog.Error("db close", "err", err)
		}
	}()

	g, ctx := errgroup.WithContext(ctx)

	// dns owns DB writes and stops before the deferred db.Close runs.
	dnsSrv := dnssrv.New(dnssrv.Config{
		Upstream:       cfg.UpstreamDNS,
		SkipPTR:        cfg.SkipPTR,
		Blocklist:      cfg.DoHBlocklist, // nil → built-in defaults
		NoiseDomains:   cfg.NoiseDomains, // nil → built-in defaults
		SearchSuffixes: cfg.SearchSuffixes,
		DoHLogLevel:    cfg.DoHLogLevel,
		DoHWindow:      cfg.DoHWindow,
	}, db.DB(), slog.Default())
	devRes := devices.New(db, slog.Default())
	dnsSrv.OnRecord = func(rec dnssrv.Record) {
		devRes.Feed(devices.Record{ClientIP: rec.ClientIP, TS: rec.TS})
	}
	g.Go(func() error { return dnsSrv.Start(ctx, cfg.DNSListen) })
	g.Go(func() error { return devRes.Start(ctx) })

	// Web UI: read-only on SQLite.
	w := web.New(db, slog.Default())
	w.Token = cfg.WebToken
	g.Go(func() error { return w.Start(ctx, cfg.WebListen) })

	// Retention sweeps on its own schedule inside the group: g.Wait() returns
	// only after it stops, so the deferred db.Close never races a DeleteOld.
	g.Go(func() error { return retention.Start(ctx, db, cfg.RetentionDays) })

	slog.Info("started",
		"db", cfg.DBPath,
		"dns", cfg.DNSListen,
		"upstream", cfg.UpstreamDNS,
		"web", cfg.WebListen)
	// Components run until parent ctx is signaled; the deferred close runs
	// after the group exits, so no component is still touching the DB.
	return g.Wait()
}
