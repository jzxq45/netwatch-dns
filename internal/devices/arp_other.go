//go:build !windows

package devices

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// LookupMAC parses /proc/net/arp on Linux for an IP's MAC address.
func LookupMAC(ipStr string) (string, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == ipStr {
			mac := fields[3]
			if mac != "00:00:00:00:00:00" {
				return mac, nil
			}
		}
	}
	return "", fmt.Errorf("ip %s not found in arp cache", ipStr)
}

