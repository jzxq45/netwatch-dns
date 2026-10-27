package store

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// Store owns the SQLite handles. SQLite WAL allows many concurrent readers;
// only writes conflict, so the writer is a dedicated single-connection pool
// and readers go through an independent read-only pool. Sharing one
// connection for both would make any UI query monopolize the data-plane
// writer (head-of-line blocking).
type Store struct {
	write *sql.DB // single conn: serialized writes (sink batches, upserts, retention)
	read  *sql.DB // read-only pool for UI/API queries
}

func Open(path string) (*Store, error) {
	wdsn := "file:" + path +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=cache_size(-64000)" + // 64MB page cache per connection
		"&_pragma=temp_store(MEMORY)"
	rdsn := "file:" + path +
		"?_pragma=busy_timeout(2000)" +
		"&_pragma=query_only(1)" +
		"&_pragma=cache_size(-64000)" +
		"&_pragma=temp_store(MEMORY)"

	write, err := sql.Open("sqlite", wdsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	write.SetMaxOpenConns(1) // writes must stay serialized (see Store doc)
	write.SetConnMaxLifetime(30 * time.Minute)
	write.SetConnMaxIdleTime(5 * time.Minute)

	read, err := sql.Open("sqlite", rdsn)
	if err != nil {
		_ = write.Close()
		return nil, fmt.Errorf("open db read pool: %w", err)
	}
	read.SetMaxOpenConns(4)
	read.SetMaxIdleConns(4)
	read.SetConnMaxLifetime(30 * time.Minute)
	read.SetConnMaxIdleTime(5 * time.Minute)

	if _, err := write.Exec(schemaSQL); err != nil {
		_ = write.Close()
		_ = read.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := ensureNoiseColumn(write); err != nil {
		_ = write.Close()
		_ = read.Close()
		return nil, fmt.Errorf("migrate noise: %w", err)
	}
	if err := read.PingContext(context.Background()); err != nil {
		_ = write.Close()
		_ = read.Close()
		return nil, fmt.Errorf("read pool ping: %w", err)
	}
	return &Store{write: write, read: read}, nil
}

// ensureNoiseColumn adds dns_log.noise to databases created before the
// noise-filtering feature. Idempotent: no-op when the column exists.
func ensureNoiseColumn(write *sql.DB) error {
	hasNoise, err := func() (bool, error) {
		rows, err := write.Query(`PRAGMA table_info(dns_log)`)
		if err != nil {
			return false, fmt.Errorf("table_info: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var cid int
			var name, typ string
			var notNull, pk int
			var dflt any
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				return false, fmt.Errorf("scan table_info: %w", err)
			}
			if name == "noise" {
				return true, nil
			}
		}
		if err := rows.Err(); err != nil {
			return false, fmt.Errorf("iterate table_info: %w", err)
		}
		return false, nil
	}()
	if err != nil {
		return err
	}
	if !hasNoise {
		if _, err := write.Exec(`ALTER TABLE dns_log ADD COLUMN noise INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add noise column: %w", err)
		}
	}
	if _, err := write.Exec(`CREATE INDEX IF NOT EXISTS idx_dns_noise_ts ON dns_log(noise, ts DESC)`); err != nil {
		return fmt.Errorf("create noise index: %w", err)
	}
	return nil
}

// DB returns the single writer handle. Reserved for the async sink and a few
// raw maintenance paths (tests); use the read methods for queries — never
// funnel read load through here or it starves the data plane.
func (s *Store) DB() *sql.DB { return s.write }

func (s *Store) Close() error {
	readErr := s.read.Close()
	if err := s.write.Close(); err != nil {
		return fmt.Errorf("close db: %w", err)
	}
	if readErr != nil {
		return fmt.Errorf("close db read pool: %w", readErr)
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
	if _, err := s.write.ExecContext(ctx, q, ip, mac, hostname, lastSeen); err != nil {
		return fmt.Errorf("upsert device %s: %w", ip, err)
	}
	return nil
}

// SetDeviceHostname updates or sets a human-friendly name for a device IP.
func (s *Store) SetDeviceHostname(ctx context.Context, ip, hostname string) error {
	q := `INSERT INTO devices (ip, hostname, last_seen) VALUES (?, ?, ?)
	      ON CONFLICT(ip) DO UPDATE SET hostname = excluded.hostname`
	if _, err := s.write.ExecContext(ctx, q, ip, hostname, time.Now().Unix()); err != nil {
		return fmt.Errorf("set hostname for %s: %w", ip, err)
	}
	return nil
}

// RetentionTables whitelists targets for DeleteOld to keep caller input out of SQL.
var RetentionTables = map[string]bool{"dns_log": true, "sni_log": true, "flow_log": true}

// deleteChunk caps the per-transaction DELETE so a big backlog (first sweep
// after downtime) never monopolizes the single writer connection for minutes.
const deleteChunk = 1000

// DeleteOld removes rows older than cutoff (unix seconds) in bounded chunks,
// cancelling between chunks via ctx. Returns rows deleted.
func (s *Store) DeleteOld(ctx context.Context, table string, cutoff int64) (int64, error) {
	if !RetentionTables[table] {
		return 0, fmt.Errorf("unknown table %q", table)
	}
	q := fmt.Sprintf(
		"DELETE FROM %s WHERE rowid IN (SELECT rowid FROM %s WHERE ts < ? LIMIT ?)", table, table) //nolint:gosec // table is whitelisted
	var total int64
	for {
		res, err := s.write.ExecContext(ctx, q, cutoff, deleteChunk)
		if err != nil {
			return total, fmt.Errorf("retain %s: %w", table, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("retain %s rows affected: %w", table, err)
		}
		total += n
		if n < deleteChunk {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
}
