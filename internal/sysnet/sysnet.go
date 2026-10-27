package sysnet

import (
	"net"
)

type NetworkInfo struct {
	LANIP           string `json:"lan_ip"`
	GatewayIP       string `json:"gateway_ip"`
	LocalDNSEnabled bool   `json:"local_dns_enabled"`
	Autostart       bool   `json:"autostart"`
	FirewallAllowed bool   `json:"firewall_allowed"`
}

// OutboundLANIP determines the primary local IP used to communicate with the network.
func OutboundLANIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer func() { _ = conn.Close() }()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// FallbackGateway derives the .1 gateway for standard /24 subnets.
func FallbackGateway(lanIP string) string {
	ip := net.ParseIP(lanIP)
	if ip == nil {
		return ""
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return ""
	}
	return net.IPv4(ipv4[0], ipv4[1], ipv4[2], 1).String()
}
