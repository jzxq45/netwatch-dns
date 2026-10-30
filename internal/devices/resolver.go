// Package devices maintains the device table: which LAN IP belongs to what
// hardware/hostname. Phase 3 passive source: DNS client IPs (always present).
// ARP/DHCP-backed discovery requires packet capture (Phase 4 plumbing).
package devices

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"monitor/internal/metrics"
)

// Record duplicates the fields the devices package needs from a DNS query;
// defined locally to keep the consumer-side interface thin (no import of dns).
type Record struct {
	ClientIP string
	TS       int64
}

// Store is the persistence surface the resolver needs.
type Store interface {
	UpsertDevice(ctx context.Context, ip string, mac, hostname *string, lastSeen int64) error
}

// channel tuning: drops instead of backpressure on the DNS serve path.
const (
	chanBuffer = 256
	// debouncedSeconds: one device upsert per IP per window instead of one
	// per DNS query. Without it the resolver is a second, unbached writer
	// racing the sink for the single writer connection.
	debouncedSeconds = 30
	maxTrackedIPs    = 4096
	maxConcurrentARP = 8
)

type macCacheEntry struct {
	mac        string
	retryAfter time.Time
}

// Resolver turns DNS sightings into device rows. mac/hostname stay untouched —
// no capture source yet; they get filled when ARP/DHCP sniffing is enabled.
type Resolver struct {
	store Store
	log   *slog.Logger

	sightings chan Record
	macCache  sync.Map
	arpSem    chan struct{}
}

func New(st Store, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	return &Resolver{
		store:     st,
		log:       log,
		sightings: make(chan Record, chanBuffer),
		arpSem:    make(chan struct{}, maxConcurrentARP),
	}
}

// Feed accepts a sighting without blocking the DNS serve loop.
func (r *Resolver) Feed(rec Record) {
	select {
	case r.sightings <- rec:
	default:
		metrics.DevicesDroppedTotal.Add(1)
		r.log.Warn("devices queue full, sighting dropped", "ip", rec.ClientIP)
	}
}

// Start processes sightings until ctx is done; returns when drained.
func (r *Resolver) Start(ctx context.Context) error {
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("resolver panic recovered", "panic", p)
		}
	}()

	// IP → freshest persisted sighting; LAN-sized (a handful of entries).
	last := make(map[string]int64)
	for {
		select {
		case rec, ok := <-r.sightings:
			if !ok {
				return nil
			}
			if len(last) >= maxTrackedIPs {
				now := time.Now().Unix()
				for ip, seen := range last {
					if now-seen > 3600 {
						delete(last, ip)
					}
				}
				if len(last) >= maxTrackedIPs {
					drop := maxTrackedIPs / 2
					for ip := range last {
						delete(last, ip)
						drop--
						if drop <= 0 {
							break
						}
					}
				}
			}
			seenAt, seen := last[rec.ClientIP]
			last[rec.ClientIP] = rec.TS // freshest state always remembered
			if seen && rec.TS-seenAt < debouncedSeconds {
				continue // inside the debounce window: in-memory refresh only
			}
			r.upsert(ctx, rec)
		case <-ctx.Done():
			// Drain: bounded timeout so stuck DB never blocks graceful shutdown.
			dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			defer dcancel()
			for {
				select {
				case rec := <-r.sightings:
					r.upsert(dctx, rec)
				default:
					// Persist the freshest debounced state, then exit — the
					// caller may close the DB once Start returns.
					for ip, ts := range last {
						r.upsert(dctx, Record{ClientIP: ip, TS: ts})
					}
					return nil
				}
			}
		}
	}
}

// upsert persists one device row; empty IPs are invalid sightings, not errors.
func (r *Resolver) upsert(ctx context.Context, rec Record) {
	if rec.ClientIP == "" {
		return
	}
	var macPtr *string
	now := time.Now()
	var shouldLookup bool

	if val, ok := r.macCache.Load(rec.ClientIP); ok {
		entry := val.(macCacheEntry)
		if entry.mac != "" {
			macPtr = &entry.mac
		} else if now.After(entry.retryAfter) {
			shouldLookup = true
		}
	} else {
		shouldLookup = true
	}

	if shouldLookup {
		select {
		case r.arpSem <- struct{}{}:
			// Mark as pending with 1m retry cooldown to prevent duplicate lookups
			r.macCache.Store(rec.ClientIP, macCacheEntry{retryAfter: now.Add(time.Minute)})
			go func(ip string, ts int64) {
				defer func() { <-r.arpSem }()
				actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
				defer cancel()
				if mac, err := LookupMAC(ip); err == nil && mac != "" {
					r.macCache.Store(ip, macCacheEntry{mac: mac})
					_ = r.store.UpsertDevice(actx, ip, &mac, nil, ts)
				}
			}(rec.ClientIP, rec.TS)
		default:
			// Worker pool saturated; skip lookup on this tick to avoid thread exhaustion
		}
	}
	if err := r.store.UpsertDevice(ctx, rec.ClientIP, macPtr, nil, rec.TS); err != nil {
		r.log.Error("device upsert", "err", err)
	}
}

// upsert was folded into the persist closure above (the only real caller).
