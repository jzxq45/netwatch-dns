//go:build windows

package sysnet

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	autostartKey      = "NetWatchDNS"
	firewallRuleDNS   = "NetWatch DNS Server"
	firewallRuleWebUI = "NetWatch Web UI"
)

func GetNetworkInfo() NetworkInfo {
	lanIP := OutboundLANIP()
	gatewayIP := detectGatewayWindows()
	if gatewayIP == "" {
		gatewayIP = FallbackGateway(lanIP)
	}
	return NetworkInfo{
		LANIP:           lanIP,
		GatewayIP:       gatewayIP,
		LocalDNSEnabled: IsLocalDNSActive(),
		Autostart:       IsAutostartEnabled(),
		FirewallAllowed: IsFirewallAllowed(),
	}
}

// EnsureFirewallRules adds inbound UDP/53 and TCP/8080 rules when missing.
// It returns a friendly error when the process is not elevated.
func EnsureFirewallRules() error {
	if firewallRuleExists(firewallRuleDNS) && firewallRuleExists(firewallRuleWebUI) {
		return nil
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		return fmt.Errorf("для настройки брандмауэра Windows требуются права администратора")
	}

	const script = `
$ErrorActionPreference = 'Stop'
netsh advfirewall firewall add rule name="NetWatch DNS Server" dir=in action=allow protocol=UDP localport=53 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "netsh add DNS rule failed ($LASTEXITCODE)" }
netsh advfirewall firewall add rule name="NetWatch Web UI" dir=in action=allow protocol=TCP localport=8080 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "netsh add Web UI rule failed ($LASTEXITCODE)" }
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if strings.Contains(msg, "Access is denied") ||
			strings.Contains(msg, "PermissionDenied") ||
			strings.Contains(msg, "Отказано в доступе") {
			return fmt.Errorf("для настройки брандмауэра Windows требуются права администратора")
		}
		return fmt.Errorf("настройка брандмауэра: %s", msg)
	}
	return nil
}

// IsFirewallAllowed reports whether both NetWatch firewall rules exist.
func IsFirewallAllowed() bool {
	return firewallRuleExists(firewallRuleDNS) && firewallRuleExists(firewallRuleWebUI)
}

func firewallRuleExists(name string) bool {
	safe := strings.ReplaceAll(name, "'", "''")
	script := fmt.Sprintf(
		"$r = Get-NetFirewallRule -DisplayName '%s' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($r) { 'yes' }",
		safe)
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	return err == nil && strings.Contains(string(out), "yes")
}

func IsAutostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = k.Close() }()
	val, _, err := k.GetStringValue(autostartKey)
	return err == nil && val != ""
}

func SetAutostart(enabled bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry run key: %w", err)
	}
	defer func() { _ = k.Close() }()

	if enabled {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("resolve executable path: %w", err)
		}
		return k.SetStringValue(autostartKey, `"`+exe+`"`)
	}
	err = k.DeleteValue(autostartKey)
	if err != nil && !errors.Is(err, registry.ErrNotExist) {
		return fmt.Errorf("delete registry autostart value: %w", err)
	}
	return nil
}

func detectGatewayWindows() string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	gw := strings.TrimSpace(string(out))
	if gw == "0.0.0.0" || gw == "" {
		return ""
	}
	return gw
}

func IsLocalDNSActive() bool {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "127.0.0.1")
}

func SetLocalDNS(enabled bool) error {
	var script string
	if enabled {
		script = `
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($r) {
    Set-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -ServerAddresses ('127.0.0.1') -ErrorAction Stop
} else {
    throw "No active default route found"
}
`
	} else {
		script = `
$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($r) {
    Set-DnsClientServerAddress -InterfaceIndex $r.InterfaceIndex -ResetServerAddresses -ErrorAction Stop
} else {
    throw "No active default route found"
}
`
	}
	cmd := exec.Command("powershell", "-NoProfile", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if strings.Contains(msg, "PermissionDenied") || strings.Contains(msg, "Access is denied") {
			return fmt.Errorf("требуются права администратора для изменения настроек DNS Windows")
		}
		return fmt.Errorf("настройка DNS: %s", msg)
	}
	return nil
}
