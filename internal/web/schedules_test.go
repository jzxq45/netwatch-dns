package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"monitor/internal/store"
)

func doScheduleRequest(t *testing.T, srv *Server, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSchedulesAPI(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	reloads := 0
	srv.OnScheduleChanged = func() { reloads++ }

	rec := doScheduleRequest(t, srv, http.MethodGet, "/api/schedules", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("empty list status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Errorf("empty list body = %q, want []", rec.Body.String())
	}

	body := `{"client_ip":"192.168.1.8","target":"YouTube.","start_hour":22,"start_min":0,"end_hour":7,"end_min":30,"days_mask":127}`
	rec = doScheduleRequest(t, srv, http.MethodPost, "/api/schedules", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("add status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	var created struct {
		Status string `json:"status"`
		ID     int64  `json:"id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode add: %v", err)
	}
	if created.ID <= 0 {
		t.Fatalf("id = %d, want > 0", created.ID)
	}
	if reloads != 1 {
		t.Errorf("reloads = %d, want 1 after add", reloads)
	}

	rec = doScheduleRequest(t, srv, http.MethodGet, "/api/schedules", "")
	var list []store.Schedule
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	got := list[0]
	if got.ID != created.ID || got.ClientIP != "192.168.1.8" || got.Target != "youtube" {
		t.Errorf("schedule = %+v", got)
	}
	if got.StartHour != 22 || got.EndHour != 7 || got.EndMin != 30 || got.DaysMask != 127 {
		t.Errorf("window = %+v", got)
	}
	if !got.Enabled {
		t.Error("enabled should default to true")
	}

	// Explicitly disabled rule round-trips as false.
	rec = doScheduleRequest(t, srv, http.MethodPost, "/api/schedules",
		`{"target":"tiktok","days_mask":0,"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled add status = %d", rec.Code)
	}
	var second struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&second)
	rec = doScheduleRequest(t, srv, http.MethodGet, "/api/schedules", "")
	list = nil
	_ = json.NewDecoder(rec.Body).Decode(&list)
	if len(list) != 2 || list[1].Enabled {
		t.Fatalf("second schedule = %+v", list)
	}

	beforeInvalid := reloads
	invalid := []string{
		`{"target":"youtube","start_hour":25}`,
		`{"target":""}`,
		`{"target":"youtube","client_ip":"not-an-ip"}`,
		`{"target":"youtube","days_mask":200}`,
	}
	for _, body := range invalid {
		rec = doScheduleRequest(t, srv, http.MethodPost, "/api/schedules", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("invalid body %s → status %d, want 400", body, rec.Code)
		}
	}
	if reloads != beforeInvalid {
		t.Error("invalid adds must not trigger a live reload")
	}

	rec = doScheduleRequest(t, srv, http.MethodDelete, "/api/schedules?id="+itoa(second.ID), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", rec.Code)
	}
	if reloads != beforeInvalid+1 {
		t.Errorf("reloads = %d, want %d after delete", reloads, beforeInvalid+1)
	}
	rec = doScheduleRequest(t, srv, http.MethodGet, "/api/schedules", "")
	list = nil
	_ = json.NewDecoder(rec.Body).Decode(&list)
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("after delete = %+v", list)
	}

	for _, target := range []string{"/api/schedules", "/api/schedules?id=abc", "/api/schedules?id=0"} {
		rec = doScheduleRequest(t, srv, http.MethodDelete, target, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s → status %d, want 400", target, rec.Code)
		}
	}
}

func TestSchedulesAPIStoreFailure(t *testing.T) {
	t.Parallel()
	srv := New(&failingStore{}, nil)

	if rec := doScheduleRequest(t, srv, http.MethodGet, "/api/schedules", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("list status = %d, want 500", rec.Code)
	}
	if rec := doScheduleRequest(t, srv, http.MethodPost, "/api/schedules",
		`{"target":"youtube"}`); rec.Code != http.StatusInternalServerError {
		t.Errorf("add status = %d, want 500", rec.Code)
	}
	if rec := doScheduleRequest(t, srv, http.MethodDelete, "/api/schedules?id=1", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("delete status = %d, want 500", rec.Code)
	}
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
