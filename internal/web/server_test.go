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
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts) VALUES (?,?,?,?)`, []any{"192.168.1.8", "example.com.", "A", now - 100}},
		{`INSERT INTO dns_log (client_ip, domain, qtype, ts) VALUES (?,?,?,?)`, []any{"192.168.1.8", "maps.example.net", "A", now - 50}},
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
		{"top", "/top?period=1h", http.StatusOK, "example.com."},
		{"bad period", "/top?period=-h", http.StatusBadRequest, ""},
		{"api", "/api/events?since=0", http.StatusOK, ""},
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
	if len(ev) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(ev), ev)
	}
	// Newest first.
	for i := 1; i < len(ev); i++ {
		if ev[i-1].TS < ev[i].TS {
			t.Fatalf("not sorted desc: %+v", ev)
		}
	}
}
