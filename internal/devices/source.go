package devices

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// timeNow is a test seam (no real clock dependency in upsert paths).
var timeNow = time.Now

// Event mirrors capture.DeviceEvent fields the resolver needs; declared here
// (consumer side) to keep the capture package unaware of persistence.
type Event struct {
	IP       string
	MAC      string
	Hostname string
}

// Source produces LAN identity observations (ARP/DHCP sniff).
type Source interface {
	Start(ctx context.Context) (<-chan Event, error)
}

// Start consumes identity events and persists them; exits after ctx done
// drained the channel. main owns the source lifecycle.
func Start(ctx context.Context, src Source, st Store, log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	ch, err := src.Start(ctx)
	if err != nil {
		return fmt.Errorf("device source: %w", err)
	}
	upsert := func(e Event) {
		var mac, host *string
		if e.MAC != "" {
			v := e.MAC
			mac = &v
		}
		if e.Hostname != "" {
			v := e.Hostname
			host = &v
		}
		// WithoutCancel: drain-after-cancel flush must still persist.
		if err := st.UpsertDevice(context.WithoutCancel(ctx), e.IP, mac, host, now()); err != nil {
			log.Error("device upsert", "err", err)
		}
	}
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return nil
			}
			upsert(e)
		case <-ctx.Done():
			// Drain whatever capture already emitted.
			for {
				select {
				case e := <-ch:
					upsert(e)
				default:
					return nil
				}
			}
		}
	}
}

func now() int64 { return timeNow().Unix() }
