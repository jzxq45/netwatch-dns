package devices

import (
	"context"
	"testing"
	"time"
)

type fakeDeviceSource struct {
	ch chan Event
}

func (f fakeDeviceSource) Start(context.Context) (<-chan Event, error) { return f.ch, nil }

func TestDeviceSourceUpserts(t *testing.T) {
	t.Parallel()
	spy := newSpy()
	src := fakeDeviceSource{ch: make(chan Event, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- Start(ctx, src, spy, nil) }()

	src.ch <- Event{IP: "192.168.1.30", MAC: "aa:bb:cc:dd:ee:01", Hostname: "android-x"}
	src.ch <- Event{IP: "192.168.1.30", MAC: "aa:bb:cc:dd:ee:01"} // hostname goes stale — must keep old

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := spy.lastSeen("192.168.1.30"); ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := spy.lastSeen("192.168.1.30"); !ok {
		t.Fatal("device row not written")
	}
	// hostname is nil (old one is empty), only UPDATED events count
	if ok1, ok2 := spy.has("192.168.1.30"), spy.has("10.0.0.99"); !ok1 || ok2 {
		t.Fatalf("unexpected persistence state: ok1=%v ok2=%v", ok1, ok2)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start blocked after cancel")
	}
}

func TestDeviceSourceEmptyIP(t *testing.T) {
	t.Parallel()
	spy := newSpy()
	src := fakeDeviceSource{ch: make(chan Event, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- Start(ctx, src, spy, nil) }()

	src.ch <- Event{} // no ip, nothing persisted

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("start: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start blocked after cancel")
	}
	if spy.has("192.168.1.30") {
		t.Fatalf("empty IP must not persist")
	}
}
