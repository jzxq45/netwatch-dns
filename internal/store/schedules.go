package store

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrInvalidSchedule marks user-input validation failures so HTTP handlers can
// answer 400 while real storage failures stay 500.
var ErrInvalidSchedule = errors.New("invalid schedule")

// Schedule is a time-limited block rule. ClientIP empty means every device;
// Target is either a service ID from filter.Services (youtube, tiktok, ...)
// or one concrete domain (blocking it and all subdomains).
//
// DaysMask uses Go's time.Weekday bit numbering: bit 0 = Sunday ... bit 6 =
// Saturday. Zero means every day. Windows may cross midnight (22:00 -> 07:00);
// start == end means the whole day.
type Schedule struct {
	ID        int64  `json:"id"`
	ClientIP  string `json:"client_ip"`
	Target    string `json:"target"`
	StartHour int    `json:"start_hour"`
	StartMin  int    `json:"start_min"`
	EndHour   int    `json:"end_hour"`
	EndMin    int    `json:"end_min"`
	DaysMask  int    `json:"days_mask"`
	Enabled   bool   `json:"enabled"`
}

const scheduleMaxTargetLen = 253

// normalizeSchedule maps "all"/"*" to the empty IP (any device) and
// canonicalizes the target (lower case, no trailing dot).
func normalizeSchedule(s Schedule) Schedule {
	s.ClientIP = strings.TrimSpace(s.ClientIP)
	switch strings.ToLower(s.ClientIP) {
	case "*", "all":
		s.ClientIP = ""
	}
	s.Target = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s.Target), "."))
	return s
}

// validateSchedule enforces column ranges so the DNS engine never has to
// interpret nonsense times.
func validateSchedule(s Schedule) error {
	if s.ClientIP != "" && net.ParseIP(s.ClientIP) == nil {
		return fmt.Errorf("%w: invalid client ip %q", ErrInvalidSchedule, s.ClientIP)
	}
	if s.Target == "" {
		return fmt.Errorf("%w: empty target", ErrInvalidSchedule)
	}
	if len(s.Target) > scheduleMaxTargetLen {
		return fmt.Errorf("%w: target too long", ErrInvalidSchedule)
	}
	if s.StartHour < 0 || s.StartHour > 23 || s.EndHour < 0 || s.EndHour > 23 {
		return fmt.Errorf("%w: hour out of range", ErrInvalidSchedule)
	}
	if s.StartMin < 0 || s.StartMin > 59 || s.EndMin < 0 || s.EndMin > 59 {
		return fmt.Errorf("%w: minute out of range", ErrInvalidSchedule)
	}
	if s.DaysMask < 0 || s.DaysMask > 0x7F {
		return fmt.Errorf("%w: days mask out of range", ErrInvalidSchedule)
	}
	return nil
}

// ListSchedules returns every schedule in creation order.
func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT id, client_ip, target, start_hour, start_min, end_hour, end_min, days_mask, enabled
		FROM schedules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list schedules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []Schedule
	for rows.Next() {
		var (
			sc      Schedule
			enabled int
		)
		if err := rows.Scan(&sc.ID, &sc.ClientIP, &sc.Target, &sc.StartHour, &sc.StartMin,
			&sc.EndHour, &sc.EndMin, &sc.DaysMask, &enabled); err != nil {
			return nil, fmt.Errorf("scan schedule: %w", err)
		}
		sc.Enabled = enabled != 0
		out = append(out, sc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schedules: %w", err)
	}
	return out, nil
}

// AddSchedule validates and inserts one rule, returning its new ID.
func (s *Store) AddSchedule(ctx context.Context, sc Schedule) (int64, error) {
	sc = normalizeSchedule(sc)
	if err := validateSchedule(sc); err != nil {
		return 0, err
	}
	enabled := 0
	if sc.Enabled {
		enabled = 1
	}
	res, err := s.write.ExecContext(ctx, `
		INSERT INTO schedules
			(client_ip, target, start_hour, start_min, end_hour, end_min, days_mask, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sc.ClientIP, sc.Target, sc.StartHour, sc.StartMin,
		sc.EndHour, sc.EndMin, sc.DaysMask, enabled)
	if err != nil {
		return 0, fmt.Errorf("add schedule: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("schedule id: %w", err)
	}
	return id, nil
}

// DeleteSchedule removes one rule by id (no-op when it no longer exists).
func (s *Store) DeleteSchedule(ctx context.Context, id int64) error {
	_, err := s.write.ExecContext(ctx, `DELETE FROM schedules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete schedule %d: %w", id, err)
	}
	return nil
}

// ToggleSchedule enables or disables one rule by id.
func (s *Store) ToggleSchedule(ctx context.Context, id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.write.ExecContext(ctx, `UPDATE schedules SET enabled = ? WHERE id = ?`, v, id)
	if err != nil {
		return fmt.Errorf("toggle schedule %d: %w", id, err)
	}
	return nil
}
