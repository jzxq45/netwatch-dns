package web

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"monitor/internal/store"
)

func TestExportCSV(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/export?format=csv&since=0&limit=100", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, `filename="dns_export.csv"`) {
		t.Fatalf("Content-Disposition = %q", got)
	}

	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	wantHeader := []string{"timestamp", "time_iso", "client_ip", "kind", "domain", "noise"}
	if len(rows) == 0 || strings.Join(rows[0], ",") != strings.Join(wantHeader, ",") {
		t.Fatalf("header = %v, want %v", rows, wantHeader)
	}
	if len(rows) < 2 {
		t.Fatalf("no data rows: %v", rows)
	}

	var found bool
	for _, row := range rows[1:] {
		if len(row) != 6 {
			t.Fatalf("row width = %d, want 6: %v", len(row), row)
		}
		if row[4] == "example.com." {
			found = true
			if row[2] != "192.168.1.8" || row[5] != "0" {
				t.Fatalf("unexpected example.com row: %v", row)
			}
		}
		if row[4] == "ads.example.ru" && row[5] != "1" {
			t.Fatalf("noise flag for ads.example.ru = %q, want 1", row[5])
		}
	}
	if !found {
		t.Fatalf("example.com. missing from CSV: %v", rows)
	}
}

func TestExportJSON(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/export?format=json&since=0&limit=100", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); !strings.Contains(got, `filename="dns_export.json"`) {
		t.Fatalf("Content-Disposition = %q", got)
	}

	var events []store.Event
	if err := json.Unmarshal(rec.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no events exported")
	}
	var found bool
	for _, e := range events {
		if e.Name == "example.com." {
			found = true
			if e.Kind != "dns" || e.ClientIP != "192.168.1.8" {
				t.Fatalf("unexpected event: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("example.com. missing from JSON: %+v", events)
	}
}
