package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"monitor/internal/filter"
	"monitor/internal/store"
)

// svcYT / svcDiscord unwrap the catalog entries used by these tests.
func svcYT() filter.Service      { s, _ := filter.ServiceByID("youtube"); return s }
func svcDiscord() filter.Service { s, _ := filter.ServiceByID("discord"); return s }

// TestAPIServices pins the /api/services contract: full built-in catalog in
// order, per-service blocked status driven by custom_rules (blocked when any
// of the service's domains is rule-blocked).
func TestAPIServices(t *testing.T) {
	t.Parallel()
	db := seedStore(t)
	srv := New(db, nil)
	h := srv.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/services", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var list []serviceStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(list) != len(filter.Services) {
		t.Fatalf("catalog size = %d, want %d", len(list), len(filter.Services))
	}
	ids := make(map[string]serviceStatus, len(list))
	for _, s := range list {
		ids[s.ID] = s
		if s.Blocked {
			t.Errorf("%s: blocked with an empty rule set", s.ID)
		}
		if s.Main == "" || len(s.Domains) == 0 {
			t.Errorf("%s: missing main/domains", s.ID)
		}
	}
	if ids["youtube"].Name != "YouTube" {
		t.Errorf("youtube name = %q", ids["youtube"].Name)
	}

	// Seed a block for youtube: only youtube flips to blocked.
	sdb := db.DB()
	for _, d := range svcYT().Domains {
		if _, err := sdb.Exec(`INSERT OR REPLACE INTO custom_rules (domain, action, created_at) VALUES (?, ?, 1)`, d, store.RuleBlock); err != nil {
			t.Fatalf("seed rule: %v", err)
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/services", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	for _, s := range list {
		want := s.ID == "youtube"
		if s.Blocked != want {
			t.Errorf("%s blocked = %v, want %v", s.ID, s.Blocked, want)
		}
	}
}

// TestAPIServiceToggle pins /api/services/toggle: on adds a block rule per
// service domain (live matcher updated via OnRuleChanged), off deletes them.
func TestAPIServiceToggle(t *testing.T) {
	t.Parallel()
	db := seedStore(t)
	srv := New(db, nil)
	var applied, removed []string
	srv.OnRuleChanged = func(domain, action string, deleted bool) {
		if deleted {
			removed = append(removed, domain)
		} else {
			applied = append(applied, domain)
		}
	}
	h := srv.Handler()

	toggle := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/api/services/toggle", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Block Discord: every catalog domain becomes a block rule.
	rec := toggle(t, `{"id":"discord","blocked":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle-on status = %d; body=%s", rec.Code, rec.Body)
	}
	ctx := context.Background()
	if len(applied) != len(svcDiscord().Domains) {
		t.Fatalf("applied = %v", applied)
	}
	rules, err := db.ListCustomRules(ctx)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	ruleDomains := make(map[string]string, len(rules))
	for _, r := range rules {
		ruleDomains[r.Domain] = r.Action
	}
	for _, d := range svcDiscord().Domains {
		if ruleDomains[d] != store.RuleBlock {
			t.Errorf("domain %q: rule = %q, want block", d, ruleDomains[d])
		}
	}

	// GET reflects the toggle...
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/services", nil))
	var list []serviceStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	for _, s := range list {
		if s.Blocked != (s.ID == "discord") {
			t.Errorf("%s blocked = %v after on-toggle", s.ID, s.Blocked)
		}
	}

	// ...and unblocking removes every domain again.
	applied = nil
	rec = toggle(t, `{"id":"discord","blocked":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle-off status = %d", rec.Code)
	}
	rules, err = db.ListCustomRules(ctx)
	if err != nil {
		t.Fatalf("list rules after off: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("rules after off = %+v, want empty", rules)
	}
	if len(removed) != len(svcDiscord().Domains) {
		t.Fatalf("removed callbacks = %v", removed)
	}

	// Unknown id → 400; nothing applied.
	rec = toggle(t, `{"id":"netflix","blocked":true}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown id status = %d, want 400", rec.Code)
	}
	if len(applied) != 0 {
		t.Fatalf("applied for unknown id: %v", applied)
	}
}
