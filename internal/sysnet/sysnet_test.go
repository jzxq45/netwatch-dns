package sysnet

import (
	"net"
	"testing"
)

func TestOutboundLANIP(t *testing.T) {
	ip := OutboundLANIP()
	if ip == "" {
		t.Fatal("empty outbound IP")
	}
	if parsed := net.ParseIP(ip); parsed == nil {
		t.Fatalf("invalid IP: %s", ip)
	}
}

func TestFallbackGateway(t *testing.T) {
	tests := []struct {
		lan  string
		want string
	}{
		{"192.168.1.55", "192.168.1.1"},
		{"10.0.0.99", "10.0.0.1"},
		{"invalid", ""},
	}
	for _, tt := range tests {
		if got := FallbackGateway(tt.lan); got != tt.want {
			t.Errorf("FallbackGateway(%q) = %q, want %q", tt.lan, got, tt.want)
		}
	}
}

func TestGetNetworkInfo(t *testing.T) {
	info := GetNetworkInfo()
	if info.LANIP == "" {
		t.Error("missing LANIP")
	}
}
