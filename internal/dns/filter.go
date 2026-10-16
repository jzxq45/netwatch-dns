package dns

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// stripSuffixes removes a known LAN search suffix (e.g. "IGD_Rostelecom")
// from a query name for LOGGING only. The original name is still forwarded
// to upstream, so resolution keeps working. Case-insensitive; keeps the
// trailing dot on the cleaned name ("foo.IGD_Rostelecom." -> "foo.").
func stripSuffixes(name string, suffixes []string) string {
	if len(suffixes) == 0 {
		return name
	}
	n := strings.TrimSuffix(name, ".")
	low := strings.ToLower(n)
	// Prefer the longest matching suffix so "a.bar.Sfx." with suffixes
	// ["Sfx", "bar.Sfx"] collapses to "a." rather than "a.bar..".
	best := ""
	for _, sfx := range suffixes {
		if strings.HasSuffix(low, sfx) && len(sfx) > len(best) && len(n) > len(sfx) {
			best = sfx
		}
	}
	if best == "" {
		return name
	}
	res := n[:len(n)-len(best)]
	if !strings.HasSuffix(res, ".") {
		res += "."
	}
	return res
}

// dohLevel maps the yaml doh_log_level string to slog.Level.
// Unknown/empty values default to debug (quiet under the default Info logger).
func dohLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return slog.LevelInfo
	case "off":
		return offLevel
	default:
		return slog.LevelDebug
	}
}

const offLevel = slog.Level(12) // above everything slog knows; emission is skipped

// blockAggregator collapses bursts of dns_blocked_doh events: one line per
// (client, domain) per window instead of one line per request.
type blockAggregator struct {
	log   *slog.Logger
	level slog.Level

	mu     sync.Mutex
	counts map[string]int // client+"\x00"+domain -> hits in current window
}

func newBlockAggregator(level slog.Level, log *slog.Logger) *blockAggregator {
	return &blockAggregator{log: log, level: level, counts: make(map[string]int)}
}

func (a *blockAggregator) add(client, domain string) {
	if a.level == offLevel {
		return // counting would be wasted work: nothing is ever emitted
	}
	a.mu.Lock()
	a.counts[client+"\x00"+domain]++
	a.mu.Unlock()
}

// flush emits one log line per key with the hits collected so far and resets
// the counters. Called from the window ticker and once on graceful shutdown.
func (a *blockAggregator) flush() {
	a.mu.Lock()
	if len(a.counts) == 0 {
		a.mu.Unlock()
		return
	}
	old := a.counts
	a.counts = make(map[string]int)
	a.mu.Unlock()
	for k, n := range old {
		client, domain, _ := strings.Cut(k, "\x00")
		a.log.Log(context.Background(), a.level, "dns_blocked_doh",
			"client", client, "domain", domain, "count", n)
	}
}

// parseWindow parses the doh_aggregate_window string, falling back to def.
func parseWindow(s string, def time.Duration, log *slog.Logger) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		log.Warn("bad doh_aggregate_window, using default", "value", s, "default", def)
		return def
	}
	return d
}
