//go:build windows

package devices

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = modiphlpapi.NewProc("SendARP")
)

// LookupMAC queries the MAC address for an IPv4 address on the LAN using Win32 SendARP.
func LookupMAC(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return "", fmt.Errorf("invalid or non-ipv4 address: %s", ipStr)
	}

	// SendARP expects IP in network byte order as uint32 on x86/x64 Windows
	destIP := binary.LittleEndian.Uint32(ip)
	var mac [6]byte
	macLen := uint32(len(mac))

	ret, _, _ := procSendARP.Call(
		uintptr(destIP),
		0,
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	if ret != 0 {
		return "", fmt.Errorf("SendARP failed with code %d", ret)
	}

	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]), nil
}
