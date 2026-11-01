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

type testResponseWriter struct {
	msg        *dns.Msg
	remoteAddr net.Addr
}

func (w *testResponseWriter) LocalAddr() net.Addr       { return &net.IPAddr{IP: net.ParseIP("127.0.0.1")} }
func (w *testResponseWriter) RemoteAddr() net.Addr      { return w.remoteAddr }
func (w *testResponseWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *testResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testResponseWriter) Close() error              { return nil }
func (w *testResponseWriter) TsigStatus() error         { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)       {}
func (w *testResponseWriter) Hijack()                   {}

func TestServerSafeSearchIntegration(t *testing.T) {
	t.Parallel()

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv := New(Config{
		Upstream:   "1.1.1.1:53",
		SafeSearch: true,
	}, db.DB(), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snkDone := make(chan struct{})
	go func() {
		defer close(snkDone)
		_ = srv.snk.Start(ctx)
	}()

	rw := &testResponseWriter{
		remoteAddr: &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
	}

	// 1. Google SafeSearch when enabled
	reqGoogle := new(dns.Msg)
	reqGoogle.SetQuestion("www.google.com.", dns.TypeA)
	srv.handle(rw, reqGoogle)

	if rw.msg == nil {
		t.Fatal("expected reply for www.google.com with SafeSearch enabled")
	}
	if len(rw.msg.Answer) != 2 {
		t.Fatalf("expected 2 answers (CNAME + A), got %d", len(rw.msg.Answer))
	}
	aRec, ok := rw.msg.Answer[1].(*dns.A)
	if !ok || aRec.A.String() != "216.239.38.120" {
		t.Fatalf("expected A 216.239.38.120, got %v", rw.msg.Answer[1])
	}

	// 2. Disable SafeSearch dynamically
	srv.SetSafeSearch(false)
	if srv.SafeSearch() {
		t.Fatal("expected SafeSearch to be false")
	}

	// Wait for sink flush on shutdown
	cancel()
	select {
	case <-snkDone:
	case <-time.After(2 * time.Second):
		t.Fatal("sink drain timed out")
	}
}
