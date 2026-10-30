package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"monitor/internal/devices"
	"monitor/internal/store"
)

// TestAPIDevicesAudit checks the JSON contract of the privacy X-ray endpoint.
func TestAPIDevicesAudit(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices/audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}

	var got []auditDevice
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("devices = %d, want 1", len(got))
	}
	d := got[0]
	if d.IP != "192.168.1.8" || d.MAC != "aa:bb:cc:01" || d.Hostname != "phone" {
		t.Errorf("identity = %+v", d)
	}
	if d.LastSeen <= 0 {
		t.Errorf("last_seen = %d, want > 0", d.LastSeen)
	}
	if d.Profile.Type != "mobile" || d.Profile.Icon != "📱" {
		t.Errorf("profile = %+v, want mobile/📱", d.Profile)
	}
	// Seed: 3 queries, 1 noise-flagged.
	if d.Privacy.Total != 3 || d.Privacy.Blocked != 1 {
		t.Errorf("total/blocked = %d/%d, want 3/1", d.Privacy.Total, d.Privacy.Blocked)
	}
	if d.Privacy.Score != 67 || d.Privacy.Grade != "C" || d.Privacy.GradeColor != "#ffff80" {
		t.Errorf("privacy = %+v, want 67/C/#ffff80", d.Privacy)
	}
	if d.Privacy.BlockPct < 33 || d.Privacy.BlockPct > 34 {
		t.Errorf("block_pct = %v, want ~33.3", d.Privacy.BlockPct)
	}
	if d.Privacy.LeakCategories == nil {
		t.Error("leak_categories = null, want empty array")
	}
}

// TestAPIDevicesAuditTrackingDevice seeds a Smart TV leaking ACR/ads/malware
// traffic and checks classification, categories and rating.
func TestAPIDevicesAuditTrackingDevice(t *testing.T) {
	t.Parallel()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	now := time.Now().Unix()
	seed := []struct {
		q string
		a []any
	}{
		{`INSERT INTO devices (ip, mac, hostname, last_seen) VALUES (?,?,?,?)`, []any{"192.168.1.4", "0012fb000001", "Samsung Smart TV.lan", now}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`, []any{"192.168.1.4", "samsungcloudsolution.com.", "A", now - 30, 1}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`, []any{"192.168.1.4", "doubleclick.net.", "A", now - 20, 1}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`, []any{"192.168.1.4", "x8a19bkc92.biz.", "A", now - 10, 1}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`, []any{"192.168.1.4", "example.com.", "A", now - 5, 0}},
	}
	for _, s := range seed {
		if _, err := db.DB().ExecContext(ctx, s.q, s.a...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	srv := New(db, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/devices/audit", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	var got []auditDevice
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("devices = %d, want 1", len(got))
	}
	d := got[0]
	if d.Profile.Vendor != "Samsung" {
		t.Errorf("vendor = %q, want Samsung", d.Profile.Vendor)
	}
	if d.Profile.Type != string(devices.DeviceTV) || d.Profile.Icon != "📺" {
		t.Errorf("profile = %+v, want tv/📺", d.Profile)
	}
	if d.Privacy.Score != 25 || d.Privacy.Grade != "F" || d.Privacy.GradeColor != "#ff8080" {
		t.Errorf("privacy = %+v, want 25/F/#ff8080", d.Privacy)
	}
	want := []string{devices.LeakACR, devices.LeakAds, devices.LeakMalware}
	if len(d.Privacy.LeakCategories) != len(want) {
		t.Fatalf("categories = %v, want %v", d.Privacy.LeakCategories, want)
	}
	for i := range want {
		if d.Privacy.LeakCategories[i] != want[i] {
			t.Fatalf("category[%d] = %q, want %q", i, d.Privacy.LeakCategories[i], want[i])
		}
	}
}

// TestDevicesPagePrivacy ensures /devices renders the X-ray card server-side.
func TestDevicesPagePrivacy(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/devices", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, marker := range []string{
		"aa:bb:cc:01", "phone", "Рейтинг: C (67/100)", "67%", "Запросов:",
	} {
		if !contains(body, marker) {
			t.Errorf("body missing %q", marker)
		}
	}
}
