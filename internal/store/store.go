package store

import (
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
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}
	return nil
}

// retentionTables whitelists targets for DeleteOld to keep caller input out of SQL.
var retentionTables = map[string]bool{"dns_log": true, "sni_log": true, "flow_log": true}

// DeleteOld removes rows older than cutoff (unix seconds). Returns rows deleted.
func (s *Store) DeleteOld(table string, cutoff int64) (int64, error) {
	if !retentionTables[table] {
		return 0, fmt.Errorf("unknown table %q", table)
	}
	q := fmt.Sprintf("DELETE FROM %s WHERE ts < ?", table) //nolint:gosec // table is whitelisted
	res, err := s.db.Exec(q, cutoff)
	if err != nil {
		return 0, fmt.Errorf("retain %s: %w", table, err)
	}
	return res.RowsAffected()
}
