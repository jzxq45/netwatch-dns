package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAPIAdult(t *testing.T) {
	t.Parallel()

	srv := New(seedStore(t), nil)
	var active atomic.Bool
	srv.BlockAdult = active.Load
	srv.OnBlockAdultToggle = active.Store

	h := srv.Handler()

	// 1. Initially disabled
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/adult", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var res struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if res.Enabled {
		t.Fatal("expected BlockAdult to be false initially")
	}

	// 2. Toggle enabled
	recToggle := httptest.NewRecorder()
	body := strings.NewReader(`{"enabled":true}`)
	h.ServeHTTP(recToggle, httptest.NewRequest(http.MethodPost, "/api/adult/toggle", body))
	if recToggle.Code != http.StatusOK {
		t.Fatalf("toggle status = %d, want 200", recToggle.Code)
	}
	if !active.Load() {
		t.Fatal("expected active to be true after toggle")
	}

	// 3. Verify GET returns true now
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/adult", nil))
	if err := json.Unmarshal(rec2.Body.Bytes(), &res); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if !res.Enabled {
		t.Fatal("expected BlockAdult to be true after toggle")
	}
}

