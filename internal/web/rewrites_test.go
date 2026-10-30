package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"monitor/internal/store"
)

// TestAPIRewritesCRUD pins the /api/rewrites contract over a real store: GET
// list, POST create+apply (with callback), validation, DELETE by body domain.
func TestAPIRewritesCRUD(t *testing.T) {
	t.Parallel()
	db := seedStore(t)
	srv := New(db, nil)
	var cbDomain, cbIP string
	var cbDeleted bool
	srv.OnRewriteChanged = func(domain, ip string, deleted bool) {
		cbDomain, cbIP, cbDeleted = domain, ip, deleted
	}
	h := srv.Handler()

	// GET starts empty (JSON [] not null).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/rewrites", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var list []store.DNSRewrite
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if list == nil || len(list) != 0 {
		t.Fatalf("initial list = %v, want empty []", rec.Body.String())
	}

	// POST creates a rewrite and fires the live-map callback.
	req := httptest.NewRequest(http.MethodPost, "/api/rewrites",
		strings.NewReader(`{"domain":"NAS.Local.","ip":"192.168.1.50"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set status = %d; body=%s", rec.Code, rec.Body)
	}
	if cbDomain != "nas.local" || cbIP != "192.168.1.50" || cbDeleted {
		t.Fatalf("callback = (%q,%q,%v), want (\"nas.local\",\"192.168.1.50\",false)", cbDomain, cbIP, cbDeleted)
	}
	rows, err := db.ListRewrites(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Domain != "nas.local" || rows[0].IP != "192.168.1.50" {
		t.Fatalf("store rows = %+v err=%v, want normalized nas.local -> 192.168.1.50", rows, err)
	}

	// GET shows the stored row.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/rewrites", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("bad list json: %v", err)
	}
	if len(list) != 1 || list[0].Domain != "nas.local" {
		t.Fatalf("list = %+v", list)
	}

	// Validation: bad IP and bad domain shape must fail with 400 (no callback).
	cbDomain, cbIP = "", ""
	bad := []string{
		`{"domain":"x.lan","ip":"999.1.1.1"}`,
		`{"domain":"x.lan","ip":"fd00::41extra"}`,
		`{"domain":"","ip":"192.168.1.50"}`,
	}
	for i, b := range bad {
		req = httptest.NewRequest(http.MethodPost, "/api/rewrites", strings.NewReader(b))
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("case %d: status = %d, want 400", i, rec.Code)
		}
		if cbDomain != "" {
			t.Fatalf("case %d: invalid rewrite applied callback %q", i, cbDomain)
		}
	}

	// DELETE removes by JSON body domain (also fires callback).
	req = httptest.NewRequest(http.MethodDelete, "/api/rewrites",
		strings.NewReader(`{"domain":"NAS.LOCAL"}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d; body=%s", rec.Code, rec.Body)
	}
	if !cbDeleted || cbDomain != "nas.local" {
		t.Fatalf("delete callback = (%q,%v), want (nas.local, true)", cbDomain, cbDeleted)
	}
	rows, err = db.ListRewrites(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows after delete = %+v, want empty", rows)
	}
}

// TestAPIRewritesDeleteFallbackQuery: DELETE accepts ?domain= too (scripts).
func TestAPIRewritesDeleteFallbackQuery(t *testing.T) {
	t.Parallel()
	db := seedStore(t)
	srv := New(db, nil)
	ctx := context.Background()
	if err := db.SetRewrite(ctx, "tv.lan", "192.168.1.60"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/rewrites?domain=tv.lan", http.NoBody)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body)
	}
	rows, _ := db.ListRewrites(ctx)
	if len(rows) != 0 {
		t.Fatalf("rows after query delete = %+v", rows)
	}
}
