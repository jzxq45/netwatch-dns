package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestRewritesCRUD pins the store contract for dns_rewrites: empty list,
// upsert (replace wins), normalization (lower-case, no trailing dot) and
// delete absorbs even the no-dot / upper-case spellings.
func TestRewritesCRUD(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	list, err := s.ListRewrites(ctx)
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("initial rewrites = %v, want empty", list)
	}

	if err := s.SetRewrite(ctx, "NAS.local", "192.168.10.20"); err != nil {
		t.Fatalf("set rewrite: %v", err)
	}
	// Replace: same domain must not duplicate.
	if err := s.SetRewrite(ctx, "nas.local.", "192.168.10.21"); err != nil {
		t.Fatalf("replace rewrite: %v", err)
	}
	if err := s.SetRewrite(ctx, "printer.lan", "fd00::41"); err != nil {
		t.Fatalf("set v6 rewrite: %v", err)
	}

	list, err = s.ListRewrites(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("rewrites = %+v, want 2 (upsert)", list)
	}
	got := make(map[string]DNSRewrite, len(list))
	for _, r := range list {
		got[r.Domain] = r
		if r.CreatedAt <= 0 {
			t.Errorf("rewrite %q has created_at = %d, want > 0", r.Domain, r.CreatedAt)
		}
	}
	if r := got["nas.local"]; r.IP != "192.168.10.21" {
		t.Errorf("nas.local = %+v, want replaced IP 192.168.10.21", r)
	}
	if r := got["printer.lan"]; r.IP != "fd00::41" {
		t.Errorf("printer.lan = %+v", r)
	}
	if _, ok := got["NAS.local"]; ok {
		t.Error("raw spelling stored: domain not normalized to lower-case")
	}

	if err := s.DeleteRewrite(ctx, "NAS.Local."); err != nil {
		t.Fatalf("delete rewrite: %v", err)
	}
	list, err = s.ListRewrites(ctx)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(list) != 1 || list[0].Domain != "printer.lan" {
		t.Fatalf("after delete = %+v, want only printer.lan", list)
	}
}

// TestRewritesValidation rejects malformed mappings before they reach the
// in-memory rewrite map of the DNS server.
func TestRewritesValidation(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	bad := []struct{ domain, ip string }{
		{"nas.local", "999.1.2.3"},
		{"nas.local", "192.168.10.999"},
		{"nas.local", "not-an-ip"},
		{"nas.local", ""},
		{"", "192.168.10.20"},
	}
	for _, b := range bad {
		if err := s.SetRewrite(ctx, b.domain, b.ip); err == nil {
			t.Errorf("SetRewrite(%q, %q) accepted, want rejection", b.domain, b.ip)
		}
	}
	// Whitelist-style notation is invalid as a raw IP as well.
	if err := s.SetRewrite(ctx, "nas.local", "192.168.10.20/24"); err == nil {
		t.Error("CIDR accepted as rewrite IP")
	}

	if _, err := s.ListRewrites(ctx); err != nil {
		t.Fatalf("list after failed sets: %v", err)
	}
}

// TestRewritesUpdateTimestamp: replacing a mapping refreshes created_at.
func TestRewritesUpdateTimestamp(t *testing.T) {
	t.Parallel()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	if err := s.SetRewrite(ctx, "tv.lan", "192.168.10.30"); err != nil {
		t.Fatalf("set: %v", err)
	}
	before, _ := s.ListRewrites(ctx)
	if len(before) != 1 {
		t.Fatalf("list = %+v", before)
	}
	// Backdate, then replace and check the timestamp moved forward.
	old := before[0].CreatedAt
	if old <= 0 {
		t.Fatalf("created_at = %d", old)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Unix() == old && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if err := s.SetRewrite(ctx, "tv.lan", "192.168.10.31"); err != nil {
		t.Fatalf("replace: %v", err)
	}
	after, err := s.ListRewrites(ctx)
	if err != nil {
		t.Fatalf("list after replace: %v", err)
	}
	if len(after) != 1 || after[0].CreatedAt <= old {
		t.Fatalf("expected fresh created_at after replace, got %+v (old %d)", after, old)
	}
	if after[0].IP != "192.168.10.31" {
		t.Fatalf("replaced IP = %q", after[0].IP)
	}
}
