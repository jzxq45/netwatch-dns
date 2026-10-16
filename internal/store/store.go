package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Store wraps the SQLite handle. Writes are serialized on one conn because
// modernc.org/sqlite (pure Go) has no shared cache; WAL keeps readers live.
type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := ensureNoiseColumn(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate noise: %w", err)
	}
	return &Store{db: db}, nil
}

// ensureNoiseColumn adds dns_log.noise to databases created before the
// noise-filtering feature. Idempotent: no-op when the column exists.
func ensureNoiseColumn(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(dns_log)`)
	if err != nil {
		return fmt.Errorf("table_info: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return fmt.Errorf("scan table_info: %w", err)
		}
		if name == "noise" {
			return nil // column already there
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate table_info: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE dns_log ADD COLUMN noise INTEGER NOT NULL DEFAULT 0`); err != nil {
		return fmt.Errorf("add noise column: %w", err)
	}
	return nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}
	return nil
}

// UpsertDevice stores/refreshes a device row. nil mac/hostname keep the old value;
// lastSeen always refreshes (DNS feed passes nils, ARP path passes real values).
func (s *Store) UpsertDevice(ctx context.Context, ip string, mac, hostname *string, lastSeen int64) error {
	q := `INSERT INTO devices (ip, mac, hostname, last_seen)
	      VALUES (?, ?, ?, ?)
	      ON CONFLICT(ip) DO UPDATE SET
	          mac      = COALESCE(excluded.mac, devices.mac),
	          hostname = COALESCE(excluded.hostname, devices.hostname),
	          last_seen = excluded.last_seen`
	if _, err := s.db.ExecContext(ctx, q, ip, mac, hostname, lastSeen); err != nil {
		return fmt.Errorf("upsert device %s: %w", ip, err)
	}
	return nil
}

// RetentionTables whitelists targets for DeleteOld to keep caller input out of SQL.
var RetentionTables = map[string]bool{"dns_log": true, "sni_log": true, "flow_log": true}

// DeleteOld removes rows older than cutoff (unix seconds). Returns rows deleted.
func (s *Store) DeleteOld(table string, cutoff int64) (int64, error) {
	if !RetentionTables[table] {
		return 0, fmt.Errorf("unknown table %q", table)
	}
	q := fmt.Sprintf("DELETE FROM %s WHERE ts < ?", table) //nolint:gosec // table is whitelisted
	res, err := s.db.Exec(q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("retain %s: %w", table, err)
	}
	return res.RowsAffected()
}
