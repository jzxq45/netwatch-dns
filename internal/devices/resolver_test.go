package devices

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

type spyStore struct {
	mu     sync.Mutex
	calls  map[string]int64 // ip -> lastSeen
	failed map[string]error // ip -> injected error
}

func newSpy() *spyStore {
	return &spyStore{calls: map[string]int64{}, failed: map[string]error{}}
}

func (s *spyStore) UpsertDevice(_ context.Context, ip string, _, _ *string, lastSeen int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failed[ip]; err != nil {
		return err
	}
	s.calls[ip] = lastSeen
	return nil
}

func (s *spyStore) lastSeen(ip string) (int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.calls[ip]
	return v, ok
}

func TestUpsert(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		ip    string
		shows bool
	}{
		{"normal ip", "192.168.1.10", true},
		{"empty ip", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			spy := newSpy()
			r := New(spy, nil)
			r.upsert(context.Background(), Record{ClientIP: tt.ip, TS: 7})
			if tt.shows {
				if _, ok := spy.lastSeen(tt.ip); !ok {
					t.Fatalf("expected row for %q", tt.ip)
				}
				if v, _ := spy.lastSeen(tt.ip); v != 7 {
					t.Fatalf("lastSeen = %d, want 7", v)
				}
			}
		})
	}
}

func TestFeedDropsOnFullQueue(t *testing.T) {
	t.Parallel()
	spy := newSpy()
	r := New(spy, nil)
	// Fill the channel (no consumer running) — Feed must not block or panic.
	for range chanBuffer + 16 {
		r.Feed(Record{ClientIP: "10.0.0.1", TS: 1})
	}
}

func TestStartDrainsOnCancel(t *testing.T) {
	t.Parallel()
	spy := newSpy()
	r := New(spy, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Start(ctx) }()

	r.Feed(Record{ClientIP: "192.168.1.20", TS: 3})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start blocked after cancel")
	}
	if v, ok := spy.lastSeen("192.168.1.20"); !ok || v != 3 {
		t.Fatalf("drain lost sighting (got %v, ok=%v)", fmt.Sprint(v), ok)
	}
}
