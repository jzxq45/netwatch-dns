// Package capture provides packet-capture backends for the SNI sniffer and
// (later) the ARP scanner. Default backend is the stub: capture needs libpcap.
package capture

import (
	"context"
	"errors"
	"log/slog"

	"monitor/internal/sni"
)

// New returns the capture backend available on this build/runtime. The stub
// reports why capture is unavailable; the pcap backend arrives via build tag `pcap`.
func New(iface string, log *slog.Logger) sni.Source {
	if iface == "" {
		return stub{why: "config: interface not set"}
	}
	return stub{why: "this build has no capture backend (needs Npcap + -tags pcap)"}
}

type stub struct{ why string }

func (s stub) Start(_ context.Context) (<-chan sni.Frame, error) {
	return nil, errors.New(s.why)
}
