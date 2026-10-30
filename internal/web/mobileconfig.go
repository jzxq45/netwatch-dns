package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"monitor/internal/sysnet"
)

// MobileConfigOptions describes the Apple DNS profile to generate.
//
// Exactly one of ServerURL (DNS-over-HTTPS / RFC 8484) or ServerAddress
// (local cleartext DNS) is used: a non-empty ServerURL wins.
type MobileConfigOptions struct {
	ServerAddress string
	ServerURL     string
	DisplayName   string
}

const mobileConfigFilename = "netwatch.mobileconfig"

// BuildMobileConfig renders a signed-format-agnostic Apple configuration
// profile (plist) with a com.apple.dnsSettings.managed payload.
func BuildMobileConfig(opt MobileConfigOptions) ([]byte, error) {
	useHTTPS := strings.TrimSpace(opt.ServerURL) != ""
	addr := strings.TrimSpace(opt.ServerAddress)
	if !useHTTPS && addr == "" {
		return nil, errors.New("mobileconfig: server address or DoH URL is required")
	}
	name := strings.TrimSpace(opt.DisplayName)
	if name == "" {
		name = "NetWatch DNS Protection"
	}
	seed := "cleartext:" + addr
	if useHTTPS {
		seed = "https:" + opt.ServerURL
	}
	profileUUID := deterministicUUID(seed + "|profile")
	dnsUUID := deterministicUUID(seed + "|dns")

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n")
	b.WriteString("\t<key>PayloadContent</key>\n\t<array>\n\t\t<dict>\n")
	b.WriteString("\t\t\t<key>DNSSettings</key>\n\t\t\t<dict>\n")
	if useHTTPS {
		writePlistString(&b, 4, "DNSProtocol", "HTTPS")
		writePlistString(&b, 4, "ServerURL", opt.ServerURL)
	} else {
		writePlistString(&b, 4, "DNSProtocol", "Cleartext")
		b.WriteString("\t\t\t\t<key>ServerAddresses</key>\n\t\t\t\t<array>\n")
		b.WriteString("\t\t\t\t\t<string>" + xmlEscape(addr) + "</string>\n")
		b.WriteString("\t\t\t\t</array>\n")
	}
	b.WriteString("\t\t\t</dict>\n")
	writePlistString(&b, 3, "PayloadDescription", "Filter DNS traffic through NetWatch (ads, trackers, zero-day threats).")
	writePlistString(&b, 3, "PayloadDisplayName", "NetWatch DNS")
	writePlistString(&b, 3, "PayloadIdentifier", "local.netwatch.dns."+dnsUUID)
	writePlistString(&b, 3, "PayloadType", "com.apple.dnsSettings.managed")
	writePlistString(&b, 3, "PayloadUUID", dnsUUID)
	b.WriteString("\t\t\t<key>PayloadVersion</key>\n\t\t\t<integer>1</integer>\n")
	b.WriteString("\t\t</dict>\n\t</array>\n")
	writePlistString(&b, 1, "PayloadDescription", "NetWatch DNS filtering profile for iPhone, iPad and Mac.")
	writePlistString(&b, 1, "PayloadDisplayName", name)
	writePlistString(&b, 1, "PayloadIdentifier", "local.netwatch.profile."+profileUUID)
	writePlistString(&b, 1, "PayloadOrganization", "NetWatch")
	b.WriteString("\t<key>PayloadRemovalDisallowed</key>\n\t<false/>\n")
	writePlistString(&b, 1, "PayloadType", "Configuration")
	writePlistString(&b, 1, "PayloadUUID", profileUUID)
	b.WriteString("\t<key>PayloadVersion</key>\n\t<integer>1</integer>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.Bytes(), nil
}

func writePlistString(b *bytes.Buffer, indent int, key, value string) {
	tabs := strings.Repeat("\t", indent)
	b.WriteString(tabs + "<key>" + xmlEscape(key) + "</key>\n")
	b.WriteString(tabs + "<string>" + xmlEscape(value) + "</string>\n")
}

func xmlEscape(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// deterministicUUID derives a stable RFC-4122-shaped UUID from seed. Stable
// UUIDs make profile reinstalls update the existing entry instead of stacking
// duplicates on the device.
func deterministicUUID(seed string) string {
	sum := sha256.Sum256([]byte("netwatch.mobileconfig/" + seed))
	b := sum[:16]
	b[6] = (b[6] & 0x0F) | 0x40 // version 4
	b[8] = (b[8] & 0x3F) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// mobileConfigOptionsForRequest derives the DNS endpoint from the request:
// the Host header when it is an IP, otherwise the detected LAN IP. When the
// panel is served over HTTPS the profile uses DNS-over-HTTPS.
func mobileConfigOptionsForRequest(r *http.Request) MobileConfigOptions {
	host := r.Host
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}
	addr := ""
	if net.ParseIP(hostname) != nil {
		addr = hostname
	} else if info := sysnet.GetNetworkInfo(); info.LANIP != "" {
		addr = info.LANIP
	} else {
		addr = hostname
	}

	opt := MobileConfigOptions{ServerAddress: addr}
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		opt.ServerURL = "https://" + host + "/dns-query"
	}
	return opt
}

func (s *Server) appleMobileConfig(w http.ResponseWriter, r *http.Request) {
	data, err := BuildMobileConfig(mobileConfigOptionsForRequest(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+mobileConfigFilename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}
