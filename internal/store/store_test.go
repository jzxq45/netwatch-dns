package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestCustomRules(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	rules, err := s.ListCustomRules(ctx)
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("initial rules = %v, want empty", rules)
	}

	if err := s.SetCustomRule(ctx, "ads.example.com", RuleBlock); err != nil {
		t.Fatalf("set block: %v", err)
	}
	if err := s.SetCustomRule(ctx, "safe.example.com", RuleAllow); err != nil {
		t.Fatalf("set allow: %v", err)
	}

	rules, err = s.ListCustomRules(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules = %v, want 2", rules)
	}
	got := make(map[string]CustomRule, len(rules))
	for _, r := range rules {
		got[r.Domain] = r
		if r.CreatedAt <= 0 {
			t.Fatalf("rule %q has created_at = %d, want > 0", r.Domain, r.CreatedAt)
		}
	}
	if r := got["ads.example.com"]; r.Action != RuleBlock {
		t.Fatalf("ads.example.com action = %q, want %q", r.Action, RuleBlock)
	}
	if r := got["safe.example.com"]; r.Action != RuleAllow {
		t.Fatalf("safe.example.com action = %q, want %q", r.Action, RuleAllow)
	}

	if err := s.SetCustomRule(ctx, "ads.example.com", RuleAllow); err != nil {
		t.Fatalf("replace rule: %v", err)
	}
	rules, err = s.ListCustomRules(ctx)
	if err != nil {
		t.Fatalf("list after replace: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("rules after replace = %v, want 2 (upsert)", rules)
	}
	for _, r := range rules {
		if r.Domain == "ads.example.com" && r.Action != RuleAllow {
			t.Fatalf("replaced action = %q, want %q", r.Action, RuleAllow)
		}
	}

	if err := s.SetCustomRule(ctx, "bad.example.com", "drop"); err == nil {
		t.Fatal("invalid action must be rejected")
	}

	if err := s.DeleteCustomRule(ctx, "ads.example.com"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	rules, err = s.ListCustomRules(ctx)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(rules) != 1 || rules[0].Domain != "safe.example.com" {
		t.Fatalf("rules after delete = %v, want only safe.example.com", rules)
	}
}

func TestStats24h(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	now := time.Now().Unix()
	seed := []struct {
		ip     string
		domain string
		ts     int64
		noise  int
	}{
		{"192.168.1.10", "example.com.", now - 60, 0},
		{"192.168.1.10", "ads.example.com.", now - 50, 1},
		{"192.168.1.11", "example.com.", now - 40, 0},
		{"192.168.1.12", "other.example.net.", now - 30, 0},
		// Outside the 24h window: must not be counted at all.
		{"192.168.1.13", "old.example.org.", now - 25*3600, 1},
	}
	for _, row := range seed {
		if _, err := s.write.ExecContext(ctx,
			`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`,
			row.ip, row.domain, "A", row.ts, row.noise); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Two recent devices + one stale (out of window).
	for _, dev := range []struct {
		ip, mac  string
		lastSeen int64
	}{
		{"192.168.1.10", "aa:00:00:00:00:01", now},
		{"192.168.1.11", "aa:00:00:00:00:02", now - 100},
		{"192.168.1.13", "aa:00:00:00:00:03", now - 25*3600},
	} {
		if _, err := s.write.ExecContext(ctx,
			`INSERT INTO devices (ip, mac, hostname, last_seen) VALUES (?,?,?,?)`,
			dev.ip, dev.mac, "", dev.lastSeen); err != nil {
			t.Fatalf("seed device: %v", err)
		}
	}

	sum, err := s.Stats24h(ctx)
	if err != nil {
		t.Fatalf("stats 24h: %v", err)
	}
	if want := now - 24*3600; sum.CutTS < want-2 || sum.CutTS > want+2 {
		t.Errorf("cut_ts = %d, want ~%d", sum.CutTS, want)
	}
	if sum.Total != 4 {
		t.Errorf("total = %d, want 4", sum.Total)
	}
	if sum.Blocked != 1 {
		t.Errorf("blocked = %d, want 1", sum.Blocked)
	}
	if sum.Domains != 3 {
		t.Errorf("distinct domains = %d, want 3", sum.Domains)
	}
	if sum.Devices != 2 {
		t.Errorf("active devices = %d, want 2", sum.Devices)
	}

	// Empty store: zeros without rows are fine.
	empty, err := s.Stats24h(ctx)
	if err != nil {
		t.Fatalf("re-query stats: %v", err)
	}
	if empty.Total != 4 || empty.Blocked != 1 {
		t.Errorf("summary drifted between reads: %+v", empty)
	}
}

func TestHourlyActivity(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	base := int64(1_700_000_000)
	base = (base / 3600) * 3600
	seed := []struct {
		ts    int64
		noise int
	}{
		{base + 10, 0},
		{base + 20, 1},
		{base + 3600 + 5, 0},
	}
	for _, row := range seed {
		if _, err := s.write.ExecContext(ctx,
			`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`,
			"192.168.1.2", "example.com.", "A", row.ts, row.noise); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	buckets, err := s.HourlyActivity(ctx, base)
	if err != nil {
		t.Fatalf("hourly activity: %v", err)
	}
	if len(buckets) != 2 {
		t.Fatalf("buckets = %+v, want 2", buckets)
	}
	if buckets[0].TS != base || buckets[0].Total != 2 || buckets[0].Blocked != 1 {
		t.Fatalf("first bucket = %+v", buckets[0])
	}
	if buckets[1].TS != base+3600 || buckets[1].Total != 1 || buckets[1].Blocked != 0 {
		t.Fatalf("second bucket = %+v", buckets[1])
	}

	empty, err := s.HourlyActivity(ctx, base+7200)
	if err != nil {
		t.Fatalf("empty activity: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty buckets = %+v, want none", empty)
	}
}

func TestDeviceActivity(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	now := time.Now().Unix()
	seed := []struct {
		ip     string
		domain string
		ts     int64
		noise  int
	}{
		{"192.168.1.10", "example.com.", now - 60, 0},
		{"192.168.1.10", "ads.example.com.", now - 50, 1},
		{"192.168.1.10", "doubleclick.net.", now - 40, 1},
		{"192.168.1.10", "doubleclick.net.", now - 30, 1},
		{"192.168.1.11", "example.com.", now - 20, 0},
		// Outside the window: ignored entirely.
		{"192.168.1.12", "old.example.org.", now - 25*3600, 1},
	}
	for _, row := range seed {
		if _, err := s.write.ExecContext(ctx,
			`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`,
			row.ip, row.domain, "A", row.ts, row.noise); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	got, err := s.DeviceActivity(ctx, now-24*3600)
	if err != nil {
		t.Fatalf("device activity: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("devices = %d, want 2 (%+v)", len(got), got)
	}
	a := got["192.168.1.10"]
	if a.Total != 4 || a.Blocked != 3 {
		t.Errorf("192.168.1.10 total/blocked = %d/%d, want 4/3", a.Total, a.Blocked)
	}
	if len(a.TopDomains) != 2 {
		t.Errorf("top domains = %v, want 2 unique blocked domains", a.TopDomains)
	}
	if len(a.TopDomains) > 0 && a.TopDomains[0] != "doubleclick.net" {
		t.Errorf("top domain[0] = %q, want doubleclick.net (most frequent)", a.TopDomains[0])
	}
	b := got["192.168.1.11"]
	if b.Total != 1 || b.Blocked != 0 || len(b.TopDomains) != 0 {
		t.Errorf("192.168.1.11 = %+v, want 1/0 no samples", b)
	}

	// Empty window: empty (non-nil) map.
	empty, err := s.DeviceActivity(ctx, now+3600)
	if err != nil {
		t.Fatalf("empty device activity: %v", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("empty map = %+v", empty)
	}
}

func TestDeviceActivitySampleCap(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	now := time.Now().Unix()
	for i := 0; i < 8; i++ {
		domain := fmt.Sprintf("blocked%d.example.", i)
		if _, err := s.write.ExecContext(ctx,
			`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`,
			"192.168.1.20", domain, "A", now-int64(i), 1); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	got, err := s.DeviceActivity(ctx, now-3600)
	if err != nil {
		t.Fatalf("device activity: %v", err)
	}
	a := got["192.168.1.20"]
	if a.Total != 8 || a.Blocked != 8 {
		t.Errorf("total/blocked = %d/%d, want 8/8", a.Total, a.Blocked)
	}
	if len(a.TopDomains) != deviceSampleDomains {
		t.Errorf("sample domains = %v, want capped at %d", a.TopDomains, deviceSampleDomains)
	}
}
