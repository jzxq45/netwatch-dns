// Package metrics centralizes expvar counters gauges observable via the web
// /metrics endpoint. Values are the failure/pressure signals the silent-drop
// paths must not hide: without them a degraded system looks healthy until
// someone reads logs line by line.
package metrics

import "expvar"

// DNSInflight: gauge of in-flight upstream-pending queries (admission control
// bound). Update via Add(1)/Add(-1).
var DNSInflight = expvar.NewInt("dns_inflight")

// Counters.
var (
	// DNSRefusedTotal: REFUSED answers from admission-control denial
	// (over max in-flight) and the open-resolver ACL.
	DNSRefusedTotal = expvar.NewInt("dns_refused_total")

	// DNSCacheHitsTotal: queries answered from the local cache. Ratio with
	// DNSCacheMissesTotal is the cache hit ratio shown in the UI and exposed
	// in /metrics/prometheus.
	DNSCacheHitsTotal = expvar.NewInt("dns_cache_hits_total")

	// DNSCacheMissesTotal: queries that had to go to an upstream resolver.
	DNSCacheMissesTotal = expvar.NewInt("dns_cache_misses_total")

	// BlockAggrCapTotal: aggregator window entries dropped beyond the
	// per-window key cap (flood protection, data-plane stays alive).
	BlockAggrCapTotal = expvar.NewInt("dns_blocklog_capped_total")

	// DNSBlockedTotal: queries answered NXDOMAIN from a blocklist match.
	DNSBlockedTotal = expvar.NewInt("dns_blocked_total")

	// LogRowsRejectedTotal: serve-path rows the sink queue could not accept.
	LogRowsRejectedTotal = expvar.NewInt("dns_log_rows_rejected_total")

	// DevicesDroppedTotal: device sightings the resolver queue could not accept.
	DevicesDroppedTotal = expvar.NewInt("devices_sightings_dropped_total")

	// SinkRowsDroppedTotal: accepted rows irreversibly lost to repeated DB
	// failures — the counter that must stay at 0 in a healthy system.
	SinkRowsDroppedTotal = expvar.NewInt("sink_rows_dropped_total")
)
