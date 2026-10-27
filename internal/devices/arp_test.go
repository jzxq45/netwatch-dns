package devices

import (
	"testing"
)

func TestLookupMAC(t *testing.T) {
	// 127.0.0.1 won't have an ARP entry, but call should not crash
	_, _ = LookupMAC("127.0.0.1")

	// Try querying standard router IP
	mac, err := LookupMAC("192.168.0.1")
	if err == nil {
		t.Logf("Found router MAC: %s", mac)
		if len(mac) != 17 {
			t.Errorf("unexpected mac format: %s", mac)
		}
	}
}
