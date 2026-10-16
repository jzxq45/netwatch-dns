//go:build pcap

// Package capture: libpcap/Npcap-backed Source for the SNI sniffer.
// Compiled only with `-tags pcap` (needs the Npcap/WinPcap-compatible DLL
// on Windows, libpcap-dev on Linux).
package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"monitor/internal/sni"
)

type pcapSource struct {
	iface string
	log   *slog.Logger
}

// New returns the pcap-backed capture backend (build tag `pcap`).
func New(iface string, log *slog.Logger) (sni.Source, error) {
	if iface == "" {
		return nil, errors.New("config: interface not set")
	}
	if log == nil {
		log = slog.Default()
	}
	return &pcapSource{iface: iface, log: log}, nil
}

// Start opens the device with the SNI BPF filter and streams client→443 payloads.
func (p *pcapSource) Start(ctx context.Context) (<-chan sni.Frame, error) {
	// 65535: full TCP segment for ClientHello; 1s read timeout keeps ctx responsiveness.
	h, err := pcap.OpenLive(p.iface, 65535, true, time.Second)
	if err != nil {
		return nil, fmt.Errorf("pcap open %s: %w", p.iface, err)
	}
	if err := h.SetBPFFilter("tcp port 443 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"); err != nil {
		h.Close()
		return nil, fmt.Errorf("pcap bpf: %w", err)
	}

	out := make(chan sni.Frame, 256)
	go func() {
		defer close(out)
		defer h.Close()
		src := gopacket.NewPacketSource(h, h.LinkType())
		src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}
		for pkt := range src.Packets() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			frame, ok := decode(pkt)
			if !ok {
				continue
			}
			select {
			case out <- frame:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// decode pulls SNI-bearing TCP payload (server port 443 = client→server direction)
// from eth/ip6/tcp stack; returns ok=false for anything else.
func decode(pkt gopacket.Packet) (sni.Frame, bool) {
	tcpL := pkt.Layer(layers.LayerTypeTCP)
	if tcpL == nil {
		return sni.Frame{}, false
	}
	tcp := tcpL.(*layers.TCP)
	if tcp.SrcPort == 443 { // server→client: never carries ClientHello
		return sni.Frame{}, false
	}
	payload := tcpL.LayerPayload()
	if len(payload) == 0 {
		return sni.Frame{}, false
	}

	ipL := pkt.Layer(layers.LayerTypeIPv4)
	ip6L := pkt.Layer(layers.LayerTypeIPv6)
	switch {
	case ipL != nil:
		return sni.Frame{ClientIP: ipL.(*layers.IPv4).SrcIP.String(), Payload: payload}, true
	case ip6L != nil:
		return sni.Frame{ClientIP: ip6L.(*layers.IPv6).SrcIP.String(), Payload: payload}, true
	}
	return sni.Frame{}, false
}
