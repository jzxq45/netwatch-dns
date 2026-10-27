//go:build !windows

package sysnet

func GetNetworkInfo() NetworkInfo {
	lanIP := OutboundLANIP()
	return NetworkInfo{
		LANIP:           lanIP,
		GatewayIP:       FallbackGateway(lanIP),
		LocalDNSEnabled: false,
		Autostart:       false,
		FirewallAllowed: true,
	}
}

func EnsureFirewallRules() error {
	return nil
}

func IsFirewallAllowed() bool {
	return true
}

func IsLocalDNSActive() bool {
	return false
}

func SetLocalDNS(enabled bool) error {
	return nil
}

func IsAutostartEnabled() bool {
	return false
}

func SetAutostart(enabled bool) error {
	return nil
}
