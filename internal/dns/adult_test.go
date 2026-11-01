package dns

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"monitor/internal/store"
)

func TestServerAdultBlockIntegration(t *testing.T) {
	t.Parallel()

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv := New(Config{
		Upstream:   "1.1.1.1:53",
		BlockAdult: true,
	}, db.DB(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snkDone := make(chan struct{})
	go func() {
		defer close(snkDone)
		_ = srv.snk.Start(ctx)
	}()

	rw := &testResponseWriter{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 54321},
	}

	// 1. Adult domain blocked with NXDOMAIN when BlockAdult is true
	reqPorn := new(dns.Msg)
	reqPorn.SetQuestion("www.pornhub.com.", dns.TypeA)
	srv.handle(rw, reqPorn)

	if rw.msg == nil {
		t.Fatal("expected reply for adult domain")
	}
	if rw.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN (RcodeNameError), got %s", dns.RcodeToString[rw.msg.Rcode])
	}

	// 2. Disable dynamically
	srv.SetBlockAdult(false)
	if srv.BlockAdult() {
		t.Fatal("expected BlockAdult to be false after toggle")
	}

	// Drain sink cleanly
	cancel()
	select {
	case <-snkDone:
	case <-time.After(2 * time.Second):
		t.Fatal("sink drain timed out")
	}
}

