package dns

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"

	"monitor/internal/store"
)

func TestClientIP(t *testing.T) {
	t.Parallel()
	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.5:5353", "192.168.1.5"},
		{"[fe80::1%eth0]:53", "fe80::1%eth0"},
		{"weird-addr-without-port", "weird-addr-without-port"},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			t.Parallel()
			if got := clientIP(addrFor(tt.addr)); got != tt.want {
				t.Fatalf("clientIP(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func addrFor(s string) net.Addr {
	if a, err := net.ResolveUDPAddr("udp", s); err == nil {
		return a
	}
	if a, err := net.ResolveTCPAddr("tcp", s); err == nil {
		return a
	}
	return addrStringer(s)
}

// addrStringer wraps a raw string for SplitHostPort fallback paths.
type addrStringer string

func (a addrStringer) Network() string { return "test" }
func (a addrStringer) String() string  { return string(a) }

var _ net.Addr = addrStringer("")

func startUpstream(t *testing.T, h dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	t.Cleanup(func() {
		if err := pc.Close(); err != nil {
			t.Errorf("close upstream: %v", err)
		}
	})
	usrv := &dns.Server{PacketConn: pc, Handler: h}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = usrv.ActivateAndServe()
	}()
	return pc.LocalAddr().String()
}

// poll runs fn every 10ms until it reports true or d elapses.
func poll(t *testing.T, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond) // poll loop, not a fixed wait
	}
	t.Fatal("condition not reached in time")
}

func TestServerLogsQuery(t *testing.T) {
	t.Parallel()
	up := startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.IPv4(93, 184, 216, 34).To4(),
		})
		if err := w.WriteMsg(m); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}))

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("db close: %v", err)
		}
	})

	// Grab a free TCP port (TCP bind is the strict side on Windows right
	// after release; UDP follows the same port fine).
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("probe close: %v", err)
	}

	srv := New(up, db.DB(), nil)
	serveErr := make(chan error, 1)
	sctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("server stop: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("server did not stop in time; goroutines:\n%s", func() string {
				buf := make([]byte, 1<<20)
				return string(buf[:runtime.Stack(buf, true)])
			}())
		}
	})
	go func() { serveErr <- srv.Start(sctx, addr) }()
	select {
	case err := <-serveErr:
		t.Fatalf("server exited immediately: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	c := &dns.Client{Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("client exchange: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want SUCCESS", resp.Rcode)
	}

	sdb := db.DB()
	poll(t, 2*time.Second, func() bool {
		var n int
		if err := sdb.QueryRow(`SELECT count(*) FROM dns_log WHERE client_ip=? AND domain=? AND qtype=?`,
			"127.0.0.1", "example.com.", "A").Scan(&n); err != nil {
			t.Logf("query: %v", err)
			return false
		}
		return n >= 1
	})
}
