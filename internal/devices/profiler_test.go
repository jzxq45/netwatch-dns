package devices

import (
	"testing"
)

// TestProfileDevice pins hostname/vendor classification and icons.
func TestProfileDevice(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		mac      string
		hostname string
		wantType DeviceType
		wantIcon string
		wantVend string
	}{
		{"smart tv by hostname", "0012fb000001", "Samsung Smart TV", DeviceTV, "📺", "Samsung"},
		{"tizen tv", "0012fb000001", "TIZEN-55", DeviceTV, "📺", "Samsung"},
		{"android tv beats mobile", "", "androidtv-box", DeviceTV, "📺", ""},
		{"chromecast", "", "Chromecast-Ultra", DeviceTV, "📺", ""},
		{"iphone", "001cb3000001", "iPhone-12", DeviceMobile, "📱", "Apple"},
		{"galaxy", "0012fb000001", "Galaxy-S21", DeviceMobile, "📱", "Samsung"},
		{"windows pc", "", "DESKTOP-ABC123", DevicePC, "💻", ""},
		{"macbook", "001cb3000001", "MacBook-Pro", DevicePC, "💻", "Apple"},
		{"esp32", "240ac4000001", "esp_ab12cd", DeviceIoT, "💡", "Espressif (IoT)"},
		{"espressif vendor", "240ac4000001", "espressif-node", DeviceIoT, "💡", "Espressif (IoT)"},
		{"playstation", "fc0f4b000001", "PS5-living-room", DeviceConsole, "🎮", "Sony PlayStation"},
		{"xbox", "7cfeb9000001", "xbox-series-x", DeviceConsole, "🎮", "Microsoft Xbox"},
		{"router vendor", "6813e2000001", "Keenetic-1234", DeviceRouter, "📡", "Keenetic"},
		{"apple default mobile", "001cb3000001", "living-room", DeviceMobile, "📱", "Apple"},
		{"samsung default mobile", "0012fb000001", "kitchen", DeviceMobile, "📱", "Samsung"},
		{"unknown", "", "", DeviceUnknown, "🌐", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := ProfileDevice(tt.mac, tt.hostname)
			if got.Type != tt.wantType {
				t.Errorf("type = %q, want %q", got.Type, tt.wantType)
			}
			if got.Icon != tt.wantIcon {
				t.Errorf("icon = %q, want %q", got.Icon, tt.wantIcon)
			}
			if got.Vendor != tt.wantVend {
				t.Errorf("vendor = %q, want %q", got.Vendor, tt.wantVend)
			}
		})
	}
}

// TestProfileDeviceModelName: the FQDN suffix is stripped for display.
func TestProfileDeviceModelName(t *testing.T) {
	t.Parallel()
	p := ProfileDevice("", "Galaxy-S21.lan")
	if p.ModelName != "Galaxy-S21" {
		t.Fatalf("model = %q, want Galaxy-S21", p.ModelName)
	}
}

// TestCalculatePrivacyScore pins scoring, grades and colors.
func TestCalculatePrivacyScore(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		total     int64
		blocked   int64
		wantScore int
		wantGrade string
		wantColor string
	}{
		{"no traffic is perfect", 0, 0, 100, "A+", "#80ff80"},
		{"clean device", 100, 0, 100, "A+", "#80ff80"},
		{"light tracking", 100, 8, 92, "A", "#80ff80"},
		{"moderate tracking", 100, 20, 80, "B", "#b3ff80"},
		{"heavy tracking", 100, 30, 70, "C", "#ffff80"},
		{"very heavy", 100, 55, 45, "D", "#ffb380"},
		{"smart tv without shield", 100, 72, 28, "F", "#ff8080"},
		{"clamp impossible block rate", 10, 20, 0, "F", "#ff8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CalculatePrivacyScore(tt.total, tt.blocked, nil)
			if got.Score != tt.wantScore {
				t.Errorf("score = %d, want %d", got.Score, tt.wantScore)
			}
			if got.Grade != tt.wantGrade {
				t.Errorf("grade = %q, want %q", got.Grade, tt.wantGrade)
			}
			if got.GradeColor != tt.wantColor {
				t.Errorf("color = %q, want %q", got.GradeColor, tt.wantColor)
			}
		})
	}
}

// TestLeakCategories: each pattern family maps to its category chip.
func TestLeakCategories(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		domains []string
		want    string
	}{
		{"acr samsung", []string{"samsungcloudsolution.com."}, LeakACR},
		{"acr lg", []string{"lgtvcommon.com."}, LeakACR},
		{"acr smartclip", []string{"vod.smartclip.tv."}, LeakACR},
		{"ads doubleclick", []string{"doubleclick.net."}, LeakAds},
		{"ads analytics", []string{"www.google-analytics.com."}, LeakAds},
		{"ads appsflyer", []string{"app.appsflyer.com."}, LeakAds},
		{"telemetry xiaomi", []string{"data.mistat.xiaomi.com."}, LeakTelemetry},
		{"telemetry microsoft", []string{"telemetry.microsoft.com."}, LeakTelemetry},
		{"malware dga", []string{"x8a19bkc92.biz."}, LeakMalware},
		{"malware phishing", []string{"paypal-security-update.com."}, LeakMalware},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := CalculatePrivacyScore(10, 1, tt.domains).LeakCategories
			found := false
			for _, c := range got {
				if c == tt.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("categories = %v, want %q", got, tt.want)
			}
		})
	}

	clean := CalculatePrivacyScore(10, 0, []string{"example.com.", "cdn.example.org."})
	if len(clean.LeakCategories) != 0 {
		t.Fatalf("clean domains produced categories: %v", clean.LeakCategories)
	}
}

// TestPrivacyScoreMultipleCategories: ordering and dedupe across signal types.
func TestPrivacyScoreMultipleCategories(t *testing.T) {
	t.Parallel()
	got := CalculatePrivacyScore(100, 40, []string{
		"doubleclick.net.",
		"samsungcloudsolution.com.",
		"data.mistat.xiaomi.com.",
		"x8a19bkc92.biz.",
		"another.doubleclick.net.",
	})
	want := []string{LeakACR, LeakAds, LeakTelemetry, LeakMalware}
	if len(got.LeakCategories) != len(want) {
		t.Fatalf("categories = %v, want %v", got.LeakCategories, want)
	}
	for i := range want {
		if got.LeakCategories[i] != want[i] {
			t.Fatalf("category[%d] = %q, want %q", i, got.LeakCategories[i], want[i])
		}
	}
}

// TestGradeHelpers pins the UI traffic-light and verdict text.
func TestGradeHelpers(t *testing.T) {
	t.Parallel()
	if GradeIcon("A+") != "🟢" || GradeIcon("B") != "🟡" || GradeIcon("F") != "🔴" {
		t.Fatal("unexpected grade icons")
	}
	if GradeAdvice("A") == "" || GradeAdvice("F") == "" {
		t.Fatal("missing grade advice")
	}
}
