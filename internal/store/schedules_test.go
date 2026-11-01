package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func openScheduleStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSchedulesCRUD(t *testing.T) {
	t.Parallel()
	s := openScheduleStore(t)
	ctx := context.Background()

	empty, err := s.ListSchedules(ctx)
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty list = %+v", empty)
	}

	id1, err := s.AddSchedule(ctx, Schedule{
		ClientIP:  "192.168.1.50",
		Target:    "YouTube.",
		StartHour: 22, StartMin: 0,
		EndHour: 7, EndMin: 0,
		DaysMask: 0x7F,
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("add first: %v", err)
	}
	if id1 <= 0 {
		t.Fatalf("id = %d, want > 0", id1)
	}

	id2, err := s.AddSchedule(ctx, Schedule{
		ClientIP: "*",
		Target:   "games.example.com",
		DaysMask: 0,
		Enabled:  false,
	})
	if err != nil {
		t.Fatalf("add second: %v", err)
	}

	list, err := s.ListSchedules(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2", len(list))
	}
	first := list[0]
	if first.ID != id1 || first.ClientIP != "192.168.1.50" || first.Target != "youtube" {
		t.Errorf("first = %+v", first)
	}
	if first.StartHour != 22 || first.StartMin != 0 || first.EndHour != 7 || first.EndMin != 0 {
		t.Errorf("first window = %+v", first)
	}
	if first.DaysMask != 0x7F || !first.Enabled {
		t.Errorf("first flags = %+v", first)
	}
	second := list[1]
	if second.ID != id2 || second.ClientIP != "" || second.Target != "games.example.com" {
		t.Errorf("second = %+v", second)
	}
	if second.Enabled {
		t.Error("second should be disabled")
	}

	if err := s.ToggleSchedule(ctx, id1, false); err != nil {
		t.Fatalf("toggle off: %v", err)
	}
	list, _ = s.ListSchedules(ctx)
	if list[0].Enabled {
		t.Error("toggle off had no effect")
	}
	if err := s.ToggleSchedule(ctx, id1, true); err != nil {
		t.Fatalf("toggle on: %v", err)
	}
	list, _ = s.ListSchedules(ctx)
	if !list[0].Enabled {
		t.Error("toggle on had no effect")
	}

	if err := s.DeleteSchedule(ctx, id1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	list, _ = s.ListSchedules(ctx)
	if len(list) != 1 || list[0].ID != id2 {
		t.Fatalf("after delete = %+v", list)
	}
	// Idempotent for unknown ids.
	if err := s.DeleteSchedule(ctx, 999); err != nil {
		t.Errorf("delete missing: %v", err)
	}
	if err := s.ToggleSchedule(ctx, 999, false); err != nil {
		t.Errorf("toggle missing: %v", err)
	}
}

func TestScheduleValidation(t *testing.T) {
	t.Parallel()
	s := openScheduleStore(t)
	ctx := context.Background()

	bad := []Schedule{
		{Target: ""},
		{Target: "youtube", ClientIP: "not-an-ip"},
		{Target: "youtube", StartHour: 24},
		{Target: "youtube", EndHour: -1},
		{Target: "youtube", StartMin: 60},
		{Target: "youtube", EndMin: -1},
		{Target: "youtube", DaysMask: 128},
		{Target: strings.Repeat("a", scheduleMaxTargetLen+1)},
	}
	for i, sc := range bad {
		if _, err := s.AddSchedule(ctx, sc); !errors.Is(err, ErrInvalidSchedule) {
			t.Errorf("case %d: err = %v, want ErrInvalidSchedule", i, err)
		}
	}

	valid := []Schedule{
		{Target: "youtube", StartHour: 0, EndHour: 23, StartMin: 0, EndMin: 59, DaysMask: 0},
		{Target: "example.com", StartHour: 23, EndHour: 23, StartMin: 59, EndMin: 59, DaysMask: 0x7F},
	}
	for i, sc := range valid {
		if _, err := s.AddSchedule(ctx, sc); err != nil {
			t.Errorf("valid case %d: %v", i, err)
		}
	}
}
