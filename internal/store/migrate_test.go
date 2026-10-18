package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestNoiseColumnMigration: a legacy dns_log table without the noise column
// must gain it (NOT NULL DEFAULT 0) on Open, keeping old rows.
func TestNoiseColumnMigration(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "legacy.db")

	leg, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	if _, err := leg.Exec(`CREATE TABLE dns_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_ip TEXT, domain TEXT, qtype TEXT, ts INTEGER)`); err != nil {
		t.Fatalf("create legacy: %v", err)
	}
	if _, err := leg.Exec(`INSERT INTO dns_log (client_ip, domain, qtype, ts)
		VALUES ('192.168.1.7', 'old.site.', 'A', ?)`, time.Now().Unix()); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}
	if err := leg.Close(); err != nil {
		t.Fatalf("close legacy: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated: %v", err)
	}
	defer s.Close()

	rows, err := s.write.Query(`PRAGMA table_info(dns_log)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notNull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "noise" {
			found = true
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if !found {
		t.Fatal("noise column missing after Open")
	}

	var n int
	if err := s.write.QueryRow(`SELECT count(*) FROM dns_log WHERE COALESCE(noise,0)=0 AND domain='old.site.'`).Scan(&n); err != nil {
		t.Fatalf("legacy row query: %v", err)
	}
	if n != 1 {
		t.Fatalf("legacy row lost or bad noise default: %d", n)
	}
}
