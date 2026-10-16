package sni

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"monitor/internal/store"
)

type fakeSource struct {
	ch chan Frame
}

func (f fakeSource) Start(context.Context) (<-chan Frame, error) { return f.ch, nil }
func (f fakeSource) close()                                      { close(f.ch) }

func TestSnifferLogsSNI(t *testing.T) {
	t.Parallel()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var mu sync.Mutex
	var seen []string
	sn := New(db.DB(), nil)
	sn.OnRecord = func(clientIP, host string, ts int64) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, clientIP+"/"+host)
	}

	src := fakeSource{ch: make(chan Frame, 4)}
	sctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- sn.Start(sctx, src) }()

	src.ch <- Frame{ClientIP: "192.168.1.8", Payload: buildHello(sniExt("example.org"))}

	sdb := db.DB()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := sdb.QueryRow(`SELECT count(*) FROM sni_log WHERE client_ip=? AND sni=?`,
			"192.168.1.8", "example.org").Scan(&n); err == nil && n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond) // poll loop, not a fixed wait
	}
	var n int
	if err := sdb.QueryRow(`SELECT count(*) FROM sni_log WHERE client_ip=? AND sni=?`,
		"192.168.1.8", "example.org").Scan(&n); err != nil || n < 1 {
		t.Fatalf("row missing: err=%v n=%d", err, n)
	}
	mu.Lock()
	if len(seen) == 0 || seen[0] != "192.168.1.8/example.org" {
		t.Fatalf("OnRecord got %v", seen)
	}
	mu.Unlock()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("sniffer stop: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sniffer did not stop in time")
	}
}
