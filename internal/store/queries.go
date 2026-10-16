package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// newEventSQL builds the unified dns/sni reader. includeNoise controls the
// dns-side noise filter (sni rows carry no noise flag — always included).
func newEventSQL(includeNoise bool) string {
	dnsWhere := ""
	if !includeNoise {
		dnsWhere = " WHERE COALESCE(noise, 0) = 0"
	}
	return `
SELECT kind, client_ip, name, ts, noise FROM (
    SELECT ? AS kind, client_ip, domain AS name, ts, COALESCE(noise,0) AS noise
      FROM dns_log` + dnsWhere + `
    UNION ALL
    SELECT ?, client_ip, sni AS name, ts, 0 AS noise FROM sni_log
)
`
}

// RecentEvents returns the newest clear (non-noise) events, newest first.
func (s *Store) RecentEvents(ctx context.Context, limit int) ([]Event, error) {
	q := fmt.Sprintf("%s ORDER BY ts DESC LIMIT %d", newEventSQL(false), limit) //nolint:gosec // limit is caller-bounded
	rows, err := s.db.QueryContext(ctx, q, EventDNS, EventSNI)
	if err != nil {
		return nil, fmt.Errorf("recent events: %w", err)
	}
	return scanEvents(rows)
}

// RecentEventsAll is RecentEvents without the noise filter (show=all view).
func (s *Store) RecentEventsAll(ctx context.Context, limit int) ([]Event, error) {
	q := fmt.Sprintf("%s ORDER BY ts DESC LIMIT %d", newEventSQL(true), limit) //nolint:gosec // limit is caller-bounded
	rows, err := s.db.QueryContext(ctx, q, EventDNS, EventSNI)
	if err != nil {
		return nil, fmt.Errorf("recent events all: %w", err)
	}
	return scanEvents(rows)
}

// NoisyEventsSince counts noise-flagged dns rows at or after sinceTS —
// the "hidden noise" counter under the clean feed.
func (s *Store) NoisyEventsSince(ctx context.Context, sinceTS int64) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM dns_log WHERE COALESCE(noise,0)=1 AND ts >= ?`, sinceTS).
		Scan(&n); err != nil {
		return 0, fmt.Errorf("noise count: %w", err)
	}
	return n, nil
}

// EventsSince returns events with ts > since (unix seconds), newest first
// (any noise flag — this feeds the JSON API for scripts).
func (s *Store) EventsSince(ctx context.Context, since int64, limit int) ([]Event, error) {
	q := fmt.Sprintf("%s WHERE ts > ? ORDER BY ts DESC LIMIT %d", newEventSQL(true), limit) //nolint:gosec // limit is caller-bounded
	rows, err := s.db.QueryContext(ctx, q, EventDNS, EventSNI, since)
	if err != nil {
		return nil, fmt.Errorf("events since %d: %w", since, err)
	}
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var noise int
		if err := rows.Scan(&e.Kind, &e.ClientIP, &e.Name, &e.TS, &noise); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		e.Noise = noise == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeviceByIP returns one device row or nil when unknown.
func (s *Store) DeviceByIP(ctx context.Context, ip string) (*DeviceRow, error) {
	var d DeviceRow
	err := s.db.QueryRowContext(ctx,
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
	q := fmt.Sprintf("%s WHERE client_ip = ? ORDER BY ts DESC LIMIT %d", newEventSQL(true), limit) //nolint:gosec // limit is caller-bounded
	rows, err := s.db.QueryContext(ctx, q, EventDNS, EventSNI, ip)
	if err != nil {
		return nil, fmt.Errorf("device events %s: %w", ip, err)
	}
	return scanEvents(rows)
}

// ListDevices returns the device table ordered by last_seen desc.
func (s *Store) ListDevices(ctx context.Context) ([]DeviceRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ip, COALESCE(mac,''), COALESCE(hostname,''), last_seen
		 FROM devices ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()
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
    FROM dns_log WHERE ts > ? AND COALESCE(noise,0)=0
    GROUP BY client_ip, domain
) t JOIN devices d ON d.ip = t.client_ip
ORDER BY d.ip, cnt DESC LIMIT ?`
	rows, err := s.db.QueryContext(ctx, q, sinceTS, limit)
	if err != nil {
		return nil, fmt.Errorf("top domains: %w", err)
	}
	defer rows.Close()
	var out []TopRow
	for rows.Next() {
		var r TopRow
		if err := rows.Scan(&r.DeviceIP, &r.Hostname, &r.Domain, &r.Count); err != nil {
			return nil, fmt.Errorf("scan top: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
