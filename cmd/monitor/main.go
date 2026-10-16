package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"

	"monitor/internal/capture"
	"monitor/internal/config"
	"monitor/internal/devices"
	dnssrv "monitor/internal/dns"
	"monitor/internal/sni"
	"monitor/internal/store"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := flag.String("config", "monitor.yaml", "path to config file")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	db, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("store open: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			slog.Error("db close", "err", err)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	g, ctx := errgroup.WithContext(ctx)

	// dns owns DB writes and stops before the deferred db.Close runs.
	dnsSrv := dnssrv.New(cfg.UpstreamDNS, db.DB(), slog.Default())
	devRes := devices.New(db, slog.Default())
	dnsSrv.OnRecord = func(rec dnssrv.Record) {
		devRes.Feed(devices.Record{ClientIP: rec.ClientIP, TS: rec.TS})
	}
	g.Go(func() error { return dnsSrv.Start(ctx, cfg.DNSListen) })
	g.Go(func() error { return devRes.Start(ctx) })

	// Capture is best-effort: its absence only disables SNI (+ARP) data.
	sniff := sni.New(db.DB(), slog.Default())
	sniff.OnRecord = func(clientIP, host string, ts int64) {
		devRes.Feed(devices.Record{ClientIP: clientIP, TS: ts})
	}
	src := capture.New(cfg.Interface, slog.Default())
	if _, err := src.Start(ctx); err != nil {
		slog.Warn("capture unavailable, SNI sniffer disabled", "reason", err.Error())
	} else {
		g.Go(func() error { return sniff.Start(ctx, src) })
	}

	slog.Info("started",
		"db", cfg.DBPath,
		"dns", cfg.DNSListen,
		"upstream", cfg.UpstreamDNS,
		"web", cfg.WebListen)
	// Components run until parent ctx is signaled; the deferred close runs after
	// the group exits, so no component is still writing at that point.
	return g.Wait()
}
