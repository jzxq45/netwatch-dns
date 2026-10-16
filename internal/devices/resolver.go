// Package devices maintains the device table: which LAN IP belongs to what
// hardware/hostname. Phase 3 passive source: DNS client IPs (always present).
// ARP/DHCP-backed discovery requires packet capture (Phase 4 plumbing).
package devices

import (
	"context"
	"errors"
	"log/slog"
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

// Resolver turns DNS sightings into device rows. mac/hostname stay untouched —
// no capture source yet; they get filled when ARP/DHCP sniffing is enabled.
type Resolver struct {
	store Store
	log   *slog.Logger

	sightings chan Record
}

// buffer sizes: drops instead of backpressure on the DNS serve path.
const chanBuffer = 256

func New(st Store, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	return &Resolver{
		store:     st,
		log:       log,
		sightings: make(chan Record, chanBuffer),
	}
}

// Feed accepts a sighting without blocking the DNS serve loop.
func (r *Resolver) Feed(rec Record) {
	select {
	case r.sightings <- rec:
	default:
		r.log.Warn("devices queue full, sighting dropped", "ip", rec.ClientIP)
	}
}

// Start processes sightings until ctx is done; returns when drained.
func (r *Resolver) Start(ctx context.Context) error {
	for {
		select {
		case rec, ok := <-r.sightings:
			if !ok {
				return nil
			}
			if err := r.upsert(ctx, rec); err != nil {
				r.log.Error("device upsert", "err", err)
			}
		case <-ctx.Done():
			// Drain so all recorded sightings reach the store before exit.
			for {
				select {
				case rec := <-r.sightings:
					if err := r.upsert(ctx, rec); err != nil {
						r.log.Error("device upsert", "err", err)
					}
				default:
					return nil
				}
			}
		}
	}
}

func (r *Resolver) upsert(ctx context.Context, rec Record) error {
	if rec.ClientIP == "" {
		return errors.New("empty client IP")
	}
	return r.store.UpsertDevice(ctx, rec.ClientIP, nil, nil, rec.TS)
}
