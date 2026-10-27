package store

import (
	"context"
	"path/filepath"
	"testing"
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
