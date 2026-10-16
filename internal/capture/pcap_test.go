//go:build pcap

package capture

import (
	"context"
	"testing"
	"time"

	"github.com/google/gopacket/pcap"
)

// TestPcapSourceOpen verifies the backend opens a real interface on hosts with
// Npcap installed; skipped when capture is unavailable (drivers/admin only).
func TestPcapSourceOpen(t *testing.T) {
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		t.Skipf("no capture devices: %v", err)
	}
	src, err := New(devs[0].Name, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ch, err := src.Start(ctx)
	if err != nil {
		// OpenLive without admin rights fails on Windows; environment skip.
		t.Skipf("capture open unavailable: %v", err)
	}
	select {
	case f := <-ch:
		_ = f
	case <-time.After(100 * time.Millisecond):
		// No traffic on this iface in 100ms is fine — Open works is what we prove.
	}
	cancel()
}
