package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"monitor/internal/store"
)

// apiListSchedules returns every bedtime / time-limit rule as JSON.
func (s *Server) apiListSchedules(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListSchedules(r.Context())
	if err != nil {
		s.fail(w, "api list schedules", err)
		return
	}
	if list == nil {
		list = []store.Schedule{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list) //nolint:errcheck // client may vanish mid-write
}

// apiAddSchedule creates one rule. Omitted "enabled" defaults to true so the
// common UI flow (pick target + window, save) is immediately effective.
func (s *Server) apiAddSchedule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClientIP  string `json:"client_ip"`
		Target    string `json:"target"`
		StartHour int    `json:"start_hour"`
		StartMin  int    `json:"start_min"`
		EndHour   int    `json:"end_hour"`
		EndMin    int    `json:"end_min"`
		DaysMask  int    `json:"days_mask"`
		Enabled   *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	id, err := s.st.AddSchedule(r.Context(), store.Schedule{
		ClientIP:  body.ClientIP,
		Target:    body.Target,
		StartHour: body.StartHour,
		StartMin:  body.StartMin,
		EndHour:   body.EndHour,
		EndMin:    body.EndMin,
		DaysMask:  body.DaysMask,
		Enabled:   enabled,
	})
	if err != nil {
		if errors.Is(err, store.ErrInvalidSchedule) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.fail(w, "api add schedule", err)
		return
	}
	s.notifyScheduleChanged()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "id": id}) //nolint:errcheck
}

// apiDeleteSchedule removes one rule by ?id=.
func (s *Server) apiDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := s.st.DeleteSchedule(r.Context(), id); err != nil {
		s.fail(w, "api delete schedule", err)
		return
	}
	s.notifyScheduleChanged()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) notifyScheduleChanged() {
	if s.OnScheduleChanged != nil {
		s.OnScheduleChanged()
	}
}
