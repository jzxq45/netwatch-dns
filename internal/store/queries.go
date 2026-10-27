package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
)

// EventKind values of unified log rows.
const (
	EventDNS = "dns"
	EventSNI = "sni"
)

// Event is a unified dns/sni log row for the live feed.
type Event struct {
	Kind     string
	ClientIP string
	Name     string
	TS       int64
	Noise    bool
}

// HourlyBucket is one hour of DNS activity for the timeline chart.
type HourlyBucket struct {
	TS      int64 `json:"ts"`
	Total   int   `json:"total"`
	Blocked int   `json:"blocked"`
}

// DeviceRow is one devices entry.
type DeviceRow struct {
	IP       string
	MAC      string
	Hostname string
	LastSeen int64
}

// TopRow is a per-device domain count within a time window.
type TopRow struct {
	DeviceIP string
	Hostname string
	Domain   string
	Count    int
}

// The unified feed readers fetch per-table top-N slices (index-backed
// ORDER BY ts DESC LIMIT n — no full-window sorts) and merge in Go. That is
// the "push the work to the index" layout: SQLite cannot push ORDER BY+LIMIT
// of an outer query into the branches of a UNION ALL view — the previous
// view-based queries sorted the whole retention window on every page render.

// queryDNSEvents returns the newest dns rows, newest first.
// where carries an optional condition with its own ? placeholders.
func (s *Store) queryDNSEvents(ctx context.Context, where string, args []any, limit int) ([]Event, error) {
	q := "SELECT client_ip, domain, ts, noise FROM dns_log " + where +
		" ORDER BY ts DESC LIMIT " + strconv.Itoa(limit)
	rows, err := s.read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("dns events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, limit)
	for rows.Next() {
		var e Event
		var noise int
		if err := rows.Scan(&e.ClientIP, &e.Name, &e.TS, &noise); err != nil {
			return nil, fmt.Errorf("scan dns event: %w", err)
		}
		e.Kind = EventDNS
		e.Noise = noise == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// querySNIEvents is queryDNSEvents over sni_log (no noise flag).
func (s *Store) querySNIEvents(ctx context.Context, where string, args []any, limit int) ([]Event, error) {
	q := "SELECT client_ip, sni, ts FROM sni_log " + where +
		" ORDER BY ts DESC LIMIT " + strconv.Itoa(limit)
	rows, err := s.read.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("sni events: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]Event, 0, limit)
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ClientIP, &e.Name, &e.TS); err != nil {
			return nil, fmt.Errorf("scan sni event: %w", err)
		}
		e.Kind = EventSNI
		e.Noise = false
		out = append(out, e)
	}
	return out, rows.Err()
}

// mergeEvents merges two newest-first slices into a single newest-first
// result capped at limit (ties keep dns rows ahead — totals never drop).
func mergeEvents(a, b []Event, limit int) []Event {
	out := make([]Event, 0, min(limit, len(a)+len(b)))
	i, j := 0, 0
	for i < len(a) && j < len(b) && len(out) < limit {
		if a[i].TS >= b[j].TS {
			out = append(out, a[i])
			i++
		} else {
			out = append(out, b[j])
			j++
		}
	}
	for i < len(a) && len(out) < limit {
		out = append(out, a[i])
		i++
	}
	for j < len(b) && len(out) < limit {
		out = append(out, b[j])
		j++
	}
	return out
}

// RecentEvents returns the newest clear (non-noise) events, newest first.
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]Event, error) {
	dnsa, err := s.queryDNSEvents(ctx, "WHERE noise = 0", nil, limit)
	if err != nil {
		return nil, err
	}
	snie, err := s.querySNIEvents(ctx, "", nil, limit)
	if err != nil {
		return nil, err
	}
	return mergeEvents(dnsa, snie, limit), nil
}

// RecentEventsAll is RecentEvents without the noise filter (show=all view).
func (s *Store) RecentEventsAll(ctx context.Context, limit int) ([]Event, error) {
	dnsa, err := s.queryDNSEvents(ctx, "", nil, limit)
	if err != nil {
		return nil, err
	}
	snie, err := s.querySNIEvents(ctx, "", nil, limit)
	if err != nil {
		return nil, err
	}
	return mergeEvents(dnsa, snie, limit), nil
}

// NoisyEventsSince counts noise-flagged dns rows at or after sinceTS —
// the "hidden noise" counter under the clean feed.
func (s *Store) NoisyEventsSince(ctx context.Context, sinceTS int64) (int, error) {
	var n int
	if err := s.read.QueryRowContext(ctx,
		`SELECT count(*) FROM dns_log WHERE noise = 1 AND ts >= ?`, sinceTS).
		Scan(&n); err != nil {
		return 0, fmt.Errorf("noise count: %w", err)
	}
	return n, nil
}

// EventsSince returns events with ts > since (unix seconds), newest first
// (any noise flag — this feeds the JSON API for scripts).
func (s *Store) EventsSince(ctx context.Context, since int64, limit int) ([]Event, error) {
	dnsa, err := s.queryDNSEvents(ctx, "WHERE ts > ?", []any{since}, limit)
	if err != nil {
		return nil, err
	}
	snie, err := s.querySNIEvents(ctx, "WHERE ts > ?", []any{since}, limit)
	if err != nil {
		return nil, err
	}
	return mergeEvents(dnsa, snie, limit), nil
}

// HourlyActivity aggregates dns_log into hour buckets. Blocked uses the
// noise flag (blocked and noisy rows are both stored as noise=1).
func (s *Store) HourlyActivity(ctx context.Context, sinceTS int64) ([]HourlyBucket, error) {
	rows, err := s.read.QueryContext(ctx, `
		SELECT (ts / 3600) * 3600 AS bucket,
		       COUNT(*) AS total,
		       COALESCE(SUM(CASE WHEN noise = 1 THEN 1 ELSE 0 END), 0) AS blocked
		FROM dns_log
		WHERE ts >= ?
		GROUP BY bucket
		ORDER BY bucket ASC`, sinceTS)
	if err != nil {
		return nil, fmt.Errorf("hourly activity: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]HourlyBucket, 0, 24)
	for rows.Next() {
		var b HourlyBucket
		if err := rows.Scan(&b.TS, &b.Total, &b.Blocked); err != nil {
			return nil, fmt.Errorf("scan hourly activity: %w", err)
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate hourly activity: %w", err)
	}
	return out, nil
}

// DeviceByIP returns one device row or nil when unknown.
func (s *Store) DeviceByIP(ctx context.Context, ip string) (*DeviceRow, error) {
	var d DeviceRow
	err := s.read.QueryRowContext(ctx,
		`SELECT ip, COALESCE(mac,''), COALESCE(hostname,''), last_seen FROM devices WHERE ip = ?`, ip).
		Scan(&d.IP, &d.MAC, &d.Hostname, &d.LastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("device %s: %w", ip, err)
	}
	return &d, nil
}

// DeviceEvents returns one device's log rows (any noise flag), newest first.
func (s *Store) DeviceEvents(ctx context.Context, ip string, limit int) ([]Event, error) {
	dnsa, err := s.queryDNSEvents(ctx, "WHERE client_ip = ?", []any{ip}, limit)
	if err != nil {
		return nil, err
	}
	snie, err := s.querySNIEvents(ctx, "WHERE client_ip = ?", []any{ip}, limit)
	if err != nil {
		return nil, err
	}
	return mergeEvents(dnsa, snie, limit), nil
}

// ListDevices returns the device table ordered by last_seen desc.
func (s *Store) ListDevices(ctx context.Context) ([]DeviceRow, error) {
	rows, err := s.read.QueryContext(ctx,
		`SELECT ip, COALESCE(mac,''), COALESCE(hostname,''), last_seen
		 FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []DeviceRow
	for rows.Next() {
		var d DeviceRow
		if err := rows.Scan(&d.IP, &d.MAC, &d.Hostname, &d.LastSeen); err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// TopDomains aggregates non-noise DNS domain counts per device since sinceTS.
func (s *Store) TopDomains(ctx context.Context, sinceTS int64, limit int) ([]TopRow, error) {
	q := `
SELECT d.ip, COALESCE(d.hostname,''), t.domain, t.cnt
FROM (
    SELECT client_ip, domain, count(*) AS cnt
    FROM dns_log WHERE ts > ? AND noise = 0
    GROUP BY client_ip, domain
) t JOIN devices d ON d.ip = t.client_ip
ORDER BY d.ip, cnt DESC LIMIT ?`
	rows, err := s.read.QueryContext(ctx, q, sinceTS, limit)
	if err != nil {
		return nil, fmt.Errorf("top domains: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]TopRow, 0, limit)
	for rows.Next() {
		var r TopRow
		if err := rows.Scan(&r.DeviceIP, &r.Hostname, &r.Domain, &r.Count); err != nil {
			return nil, fmt.Errorf("scan top: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
