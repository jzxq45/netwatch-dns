package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBlocklistYAMLSemantics guards the doh_blocklist contract:
//   - key absent in yaml  -> nil slice  -> built-in defaults stay active;
//   - `doh_blocklist: []` -> non-nil empty -> explicit opt-out (no blocking);
//   - list given          -> replaces defaults entirely.
func TestBlocklistYAMLSemantics(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	tests := []struct {
		name    string
		body    string // yaml content or "" for a missing file
		missing bool   // do not create the file at all
		wantNil bool   // DoHBlocklist == nil means "defaults keep working"
		wantLen int    // -1: not asserted
	}{
		{"absent key keeps defaults", "retention_days: 7\n", false, true, -1},
		{"missing file keeps defaults", "", true, true, -1},
		{"explicit [] disables blocking", "doh_blocklist: []\n", false, false, 0},
		{"list replaces defaults", "doh_blocklist: [dns.google]\n", false, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.name+".yaml")
			if !tt.missing {
				if err := os.WriteFile(path, []byte(tt.body), 0o600); err != nil {
					t.Fatalf("write yaml: %v", err)
				}
			}
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if tt.wantNil && cfg.DoHBlocklist != nil {
				t.Fatalf("DoHBlocklist = %v, want nil (defaults must survive)", cfg.DoHBlocklist)
			}
			if !tt.wantNil && cfg.DoHBlocklist == nil {
				t.Fatal("DoHBlocklist = nil, want non-nil slice")
			}
			if tt.wantLen >= 0 && len(cfg.DoHBlocklist) != tt.wantLen {
				t.Fatalf("len(DoHBlocklist) = %d, want %d", len(cfg.DoHBlocklist), tt.wantLen)
			}
		})
	}
}
