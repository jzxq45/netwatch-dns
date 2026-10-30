package web

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// parsePlist validates the XML and returns keys and string values in document
// order (enough to assert the DNS payload contract).
func parsePlist(t *testing.T, data []byte) (keys, values []string) {
	t.Helper()
	dec := xml.NewDecoder(bytes.NewReader(data))
	inKey, inString := false, false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid plist XML: %v\n%s", err, data)
		}
		switch v := tok.(type) {
		case xml.StartElement:
			inKey = v.Name.Local == "key"
			inString = v.Name.Local == "string"
		case xml.EndElement:
			inKey, inString = false, false
		case xml.CharData:
			text := string(v)
			if inKey {
				keys = append(keys, text)
			}
			if inString {
				values = append(values, text)
			}
		}
	}
	return keys, values
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestBuildMobileConfigCleartext(t *testing.T) {
	t.Parallel()
	data, err := BuildMobileConfig(MobileConfigOptions{ServerAddress: "192.168.1.15"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	keys, values := parsePlist(t, data)
	if !containsStr(values, "com.apple.dnsSettings.managed") {
		t.Error("missing com.apple.dnsSettings.managed payload type")
	}
	if !containsStr(keys, "PayloadUUID") {
		t.Error("missing PayloadUUID key")
	}
	if !containsStr(values, "Cleartext") {
		t.Error("missing Cleartext DNS protocol")
	}
	if !containsStr(values, "192.168.1.15") {
		t.Error("missing ServerAddresses entry")
	}
	if containsStr(values, "HTTPS") {
		t.Error("cleartext profile must not use HTTPS protocol")
	}

	uuidCount := 0
	for _, v := range values {
		if uuidRE.MatchString(v) {
			uuidCount++
		}
	}
	if uuidCount != 2 {
		t.Errorf("UUID strings = %d, want 2 (profile + DNS payload)", uuidCount)
	}

	again, err := BuildMobileConfig(MobileConfigOptions{ServerAddress: "192.168.1.15"})
	if err != nil {
		t.Fatalf("rebuild: %v", err)
	}
	if !bytes.Equal(data, again) {
		t.Error("mobileconfig is not deterministic for the same address")
	}
	other, _ := BuildMobileConfig(MobileConfigOptions{ServerAddress: "192.168.1.16"})
	if bytes.Equal(data, other) {
		t.Error("different addresses must yield different profiles")
	}
}

func TestBuildMobileConfigHTTPS(t *testing.T) {
	t.Parallel()
	data, err := BuildMobileConfig(MobileConfigOptions{
		ServerURL: "https://192.168.1.15:8443/dns-query",
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	keys, values := parsePlist(t, data)
	if !containsStr(values, "HTTPS") {
		t.Error("missing HTTPS DNS protocol")
	}
	if !containsStr(keys, "ServerURL") {
		t.Error("missing ServerURL key")
	}
	if !containsStr(values, "https://192.168.1.15:8443/dns-query") {
		t.Error("missing ServerURL value")
	}
	if containsStr(values, "Cleartext") {
		t.Error("HTTPS profile must not use Cleartext protocol")
	}
	if containsStr(keys, "ServerAddresses") {
		t.Error("HTTPS profile should use ServerURL, not ServerAddresses")
	}

	if _, err := BuildMobileConfig(MobileConfigOptions{}); err == nil {
		t.Fatal("empty options must fail")
	}
}

func TestMobileConfigHandler(t *testing.T) {
	t.Parallel()
	tests := []string{"/api/apple.mobileconfig", "/netwatch.mobileconfig"}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			srv := New(seedStore(t), nil)
			req := httptest.NewRequest(http.MethodGet, "http://192.168.1.15:8080"+path, nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/x-apple-aspen-config; charset=utf-8" {
				t.Errorf("content-type = %q", ct)
			}
			if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="netwatch.mobileconfig"` {
				t.Errorf("content-disposition = %q", cd)
			}
			keys, values := parsePlist(t, rec.Body.Bytes())
			if !containsStr(values, "com.apple.dnsSettings.managed") {
				t.Error("missing DNS payload type")
			}
			if !containsStr(keys, "PayloadUUID") {
				t.Error("missing PayloadUUID")
			}
			if !containsStr(values, "192.168.1.15") {
				t.Error("Host IP not used as DNS server address")
			}
		})
	}
}

func TestMobileConfigHandlerHTTPSRequest(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	req := httptest.NewRequest(http.MethodGet, "https://dns.example.lan/netwatch.mobileconfig", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	keys, values := parsePlist(t, rec.Body.Bytes())
	if !containsStr(values, "HTTPS") || !containsStr(keys, "ServerURL") {
		t.Error("HTTPS request must produce a DNS-over-HTTPS payload")
	}
	if !containsStr(values, "https://dns.example.lan/dns-query") {
		t.Errorf("missing DoH URL, values=%v", values)
	}
}

func TestMobileConfigOptionsForRequest(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://192.168.1.15:8080/api/apple.mobileconfig", nil)
	opt := mobileConfigOptionsForRequest(req)
	if opt.ServerAddress != "192.168.1.15" {
		t.Errorf("address = %q, want 192.168.1.15", opt.ServerAddress)
	}
	if opt.ServerURL != "" {
		t.Errorf("url = %q, want cleartext", opt.ServerURL)
	}
	if !strings.HasPrefix(strings.ToLower(opt.ServerAddress), "192.168.") {
		t.Errorf("unexpected address %q", opt.ServerAddress)
	}
}
