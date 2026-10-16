// Package capture provides packet-capture backends for the SNI sniffer and
// (later) the ARP scanner. Default backend is the stub: capture needs libpcap.
package capture

import (
	"errors"
	"log/slog"

	"monitor/internal/sni"
)

// New returns the capture backend for this build. The stub always reports
// why capture is unavailable; the pcap backend arrives via build tag `pcap`.
func New(iface string, log *slog.Logger) (sni.Source, error) {
	if iface == "" {
		return nil, errors.New("config: interface not set")
	}
	return nil, errors.New("this build has no capture backend (needs Npcap + -tags pcap)")
}
