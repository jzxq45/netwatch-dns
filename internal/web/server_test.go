package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"monitor/internal/store"
)

// seedStore opens a real SQLite store and fills the log tables.
func seedStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	// Timestamps relative to now so time-window endpoints (top) match.
	now := time.Now().Unix()
	seed := []struct {
		q string
		a []any
	}{
		{`INSERT INTO devices (ip, mac, hostname, last_seen) VALUES (?,?,?,?)`, []any{"192.168.1.8", "aa:bb:cc:01", "phone", now}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`, []any{"192.168.1.8", "example.com.", "A", now - 100, 0}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`, []any{"192.168.1.8", "maps.example.net", "A", now - 50, 0}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts, noise) VALUES (?,?,?,?,?)`, []any{"192.168.1.8", "ads.example.ru", "A", now - 10, 1}},
		{`INSERT INTO sni_log (client_ip, sni, ts) VALUES (?,?,?)`, []any{"192.168.1.8", "cdn.example.org", now - 40}},
	}
	sdb := db.DB()
	for _, s := range seed {
		if _, err := sdb.ExecContext(ctx, s.q, s.a...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	return db
}

func TestRoutes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		path   string
		status int
		want   string // substring — one page marker
	}{
		{"healthz", "/healthz", http.StatusOK, "ok"},
		{"feed shows dns+sni", "/", http.StatusOK, "example.com."},
		{"feed also sni", "/", http.StatusOK, "cdn.example.org"},
		{"devices", "/devices", http.StatusOK, "aa:bb:cc:01"},
		{"device page", "/device?ip=192.168.1.8", http.StatusOK, "example.com."},
		{"device page shows hostname", "/device?ip=192.168.1.8", http.StatusOK, "phone"},
		{"device bad ip", "/device?ip=zzz", http.StatusBadRequest, ""},
		{"device unknown ip", "/device?ip=10.0.0.99", http.StatusOK, "10.0.0.99"},
		{"top", "/top?period=1h", http.StatusOK, "example.com."},
		{"bad period", "/top?period=-h", http.StatusBadRequest, ""},
		{"api", "/api/events?since=0", http.StatusOK, ""},
		{"api network", "/api/network", http.StatusOK, "lan_ip"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := New(seedStore(t), nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.status, rec.Body)
			}
			if tt.want != "" && !contains(rec.Body.String(), tt.want) {
				t.Fatalf("body missing %q", tt.want)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// TestWebTokenAuth guards the web_token contract: empty token = open;
// set token closes everything except /healthz and /static/;
// X-Auth-Token, ?token= (minting a cookie) and cookie all pass.
func TestWebTokenAuth(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	srv.Token = "secret-token-1"

	tests := []struct {
		name    string
		path    string
		header  string
		want    int
		wantSub string
	}{
		{"no token", "/", "", http.StatusUnauthorized, ""},
		{"wrong token", "/", "nope", http.StatusUnauthorized, ""},
		{"healthz open", "/healthz", "", http.StatusOK, "ok"},
		{"static open", "/static/style.css", "", http.StatusOK, "topbar"},
		{"header ok", "/", "secret-token-1", http.StatusOK, "example.com."},
		{"query ok mints cookie", "/?token=secret-token-1", "", http.StatusOK, "example.com."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.header != "" {
				req.Header.Set("X-Auth-Token", tt.header)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d; body=%s", rec.Code, tt.want, rec.Body)
			}
			if tt.wantSub != "" && !contains(rec.Body.String(), tt.wantSub) {
				t.Fatalf("body missing %q", tt.wantSub)
			}
			if tt.name == "query ok mints cookie" {
				if len(rec.Result().Cookies()) == 0 {
					t.Fatal("expected auth_token cookie from ?token=")
				}
			}
		})
	}
}

// TestFeedNoiseView guards the noise-visibility UI contract:
// default view hides noise (and counts it), /?show=all reveals everything,
// /top excludes noise always.
func TestFeedNoiseView(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		path       string
		noiseShown bool
		counter    bool
	}{
		{"default hides noise", "/", false, true},
		{"show=all reveals noise", "/?show=all", true, false},
		{"top excludes noise", "/top?period=1h", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := New(seedStore(t), nil)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d", rec.Code)
			}
			body := rec.Body.String()
			if contains(body, "ads.example.ru") != tt.noiseShown {
				t.Fatalf("noise visibility = %v, want %v", contains(body, "ads.example.ru"), tt.noiseShown)
			}
			if contains(body, "шумных скрыто") != tt.counter {
				t.Fatalf("hidden-counter presence = %v, want %v", contains(body, "шумных скрыто"), tt.counter)
			}
		})
	}
}

func TestAPIEventsJSON(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/events?since=-1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var ev []store.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &ev); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	if len(ev) != 4 {
		t.Fatalf("got %d events, want 4 (incl. noise row): %+v", len(ev), ev)
	}
	// Newest first.
	for i := 1; i < len(ev); i++ {
		if ev[i-1].TS < ev[i].TS {
			t.Fatalf("not sorted desc: %+v", ev)
		}
	}
}

// TestAPIStats pins the /api/stats JSON contract over the seeded data:
// 3 dns rows in window (1 blocked), 3 distinct domains, 1 active device,
// and cache metrics mirrored from expvar.
func TestAPIStats(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rec.Code, rec.Body)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("content type = %q", ct)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	eq := map[string]float64{
		"total":   3,
		"blocked": 1,
		"devices": 1,
		"domains": 3,
	}
	for k, want := range eq {
		if got := out[k]; int(got.(float64)) != int(want) {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
	blockPct := out["block_pct"].(float64)
	if blockPct < 33.0 || blockPct > 34.0 {
		t.Errorf("block_pct = %v, want ~33.3", blockPct)
	}
	if _, ok := out["cache_hit_ratio"]; !ok {
		t.Error("cache_hit_ratio missing")
	}
	if _, ok := out["cache_hits"]; !ok {
		t.Error("cache_hits missing")
	}
	if _, ok := out["cache_misses"]; !ok {
		t.Error("cache_misses missing")
	}
}

// TestMetricsPrometheus pins the Prometheus exposition format of
// /metrics/prometheus: HELP/TYPE headers and a named sample per metric.
func TestMetricsPrometheus(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics/prometheus", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("content type = %q, want Prometheus text/plain", ct)
	}
	body := rec.Body.String()
	for _, name := range []string{
		"dns_cache_hits_total",
		"dns_cache_misses_total",
		"dns_blocked_total",
		"dns_refused_total",
		"dns_inflight",
		"sink_rows_dropped_total",
	} {
		help := "# HELP " + name + " "
		typ := "# TYPE " + name + " "
		if !strings.Contains(body, help) {
			t.Errorf("missing %q", help)
		}
		if !strings.Contains(body, typ) {
			t.Errorf("missing %q", typ)
		}
		if !strings.Contains(body, "\n"+name+" ") {
			t.Errorf("missing sample line for %s", name)
		}
	}
}

func TestAPICustomRules(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	var gotDomain, gotAction string
	var gotDeleted bool
	srv.OnRuleChanged = func(domain, action string, deleted bool) {
		gotDomain, gotAction, gotDeleted = domain, action, deleted
	}
	h := srv.Handler()

	list := func() []store.CustomRule {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/rules", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("list status = %d", rec.Code)
		}
		var rules []store.CustomRule
		if err := json.Unmarshal(rec.Body.Bytes(), &rules); err != nil {
			t.Fatalf("list json: %v", err)
		}
		return rules
	}

	if rules := list(); len(rules) != 0 {
		t.Fatalf("initial rules = %v, want empty", rules)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/rules",
		strings.NewReader(`{"domain":"ads.example.com","action":"block"}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set status = %d; body=%s", rec.Code, rec.Body)
	}
	if gotDomain != "ads.example.com" || gotAction != store.RuleBlock || gotDeleted {
		t.Fatalf("callback = (%q,%q,%v)", gotDomain, gotAction, gotDeleted)
	}

	rules := list()
	if len(rules) != 1 || rules[0].Domain != "ads.example.com" || rules[0].Action != store.RuleBlock {
		t.Fatalf("rules after set = %+v", rules)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/rules",
		strings.NewReader(`{"domain":"ads.example.com","action":"drop"}`))
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid action status = %d, want 400", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/api/rules?domain=ads.example.com", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d; body=%s", rec.Code, rec.Body)
	}
	if !gotDeleted || gotDomain != "ads.example.com" {
		t.Fatalf("delete callback = (%q,%q,%v)", gotDomain, gotAction, gotDeleted)
	}
	if rules := list(); len(rules) != 0 {
		t.Fatalf("rules after delete = %v, want empty", rules)
	}
}
