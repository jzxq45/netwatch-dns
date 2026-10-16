package dns

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"monitor/internal/store"
)

func TestStripSuffixes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		in       string
		suffixes []string
		want     string
	}{
		{"search-domain form", "foo.IGD_Rostelecom.", []string{"IGD_Rostelecom"}, "foo."},
		{"case-insensitive", "foo.IGD_ROSTELECOM", []string{"IGD_Rostelecom"}, "foo."},
		{"plain name untouched", "vedomosti.ru.", []string{"IGD_Rostelecom"}, "vedomosti.ru."},
		{"suffix equal to name", "IGD_Rostelecom.", []string{"IGD_Rostelecom"}, "IGD_Rostelecom."},
		{"longest suffix wins", "a.bar.IGD_Rostelecom.",
			[]string{"IGD_Rostelecom", "bar.IGD_Rostelecom"}, "a."},
		{"no suffixes configured", "foo.IGD_Rostelecom.", nil, "foo.IGD_Rostelecom."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripSuffixes(tt.in, normalizeEntries(tt.suffixes)); got != tt.want {
				t.Fatalf("stripSuffixes(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestParseWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"10s", 10 * time.Second},
		{"", 10 * time.Second},  // empty -> default
		{"2s", 2 * time.Second}, // explicit override
		{"bogus", 10 * time.Second},
		{"-5s", 10 * time.Second},
	}
	for _, tt := range tests {
		if got := parseWindow(tt.in, 10*time.Second, slog.Default()); got != tt.want {
			t.Fatalf("parseWindow(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestBlockAggregator(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	t.Run("burst collapses into one line with count", func(t *testing.T) {
		buf.Reset()
		a := newBlockAggregator(slog.LevelDebug, log)
		for i := 0; i < 5; i++ {
			a.add("192.168.0.15", "dns.google.")
		}
		a.flush()
		out := buf.String()
		if n := strings.Count(out, "\n"); n != 1 {
			t.Fatalf("lines = %d, want 1; output:\n%s", n, out)
		}
		for _, sub := range []string{"msg=dns_blocked_doh", "192.168.0.15", "dns.google.", "count=5"} {
			if !strings.Contains(out, sub) {
				t.Fatalf("output missing %q:\n%s", sub, out)
			}
		}
	})

	t.Run("info level emits at INFO", func(t *testing.T) {
		buf.Reset()
		a := newBlockAggregator(slog.LevelInfo, log)
		a.add("c", "d")
		a.flush()
		if !strings.Contains(buf.String(), "level=INFO") {
			t.Fatalf("expected INFO line:\n%s", buf.String())
		}
	})

	t.Run("off level emits nothing", func(t *testing.T) {
		buf.Reset()
		a := newBlockAggregator(offLevel, log)
		a.add("c", "d")
		a.flush()
		if out := buf.String(); out != "" {
			t.Fatalf("level off produced output: %s", out)
		}
	})

	t.Run("flush resets counters", func(t *testing.T) {
		buf.Reset()
		a := newBlockAggregator(slog.LevelDebug, log)
		a.add("c1", "d1")
		a.flush()
		a.flush()
		if n := strings.Count(buf.String(), "\n"); n != 1 {
			t.Fatalf("second flush emitted again, lines=%d:\n%s", n, buf.String())
		}
	})
}

func TestSkipPTR(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("network bind test")
	}
	addr, db := startBlockTestServer(t, func(s *Server) { s.SkipPTR = true })

	c := &dns.Client{Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("1.0.0.127.in-addr.arpa.", dns.TypePTR)
	resp, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("exchange PTR: %v", err)
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 {
		t.Fatalf("PTR reply: rcode=%d answers=%d, want NOERROR/0", resp.Rcode, len(resp.Answer))
	}

	// Positive control: an A query must appear in dns_log (proves flushing
	// works), then the PTR query must be absent entirely.
	m2 := new(dns.Msg)
	m2.SetQuestion("example.com.", dns.TypeA)
	if _, _, err := c.Exchange(m2, addr); err != nil {
		t.Fatalf("exchange A: %v", err)
	}
	waitForLogRow(t, db, "SELECT count(*) FROM dns_log WHERE domain=?", "example.com.")

	var n int
	if err := db.DB().QueryRow(`SELECT count(*) FROM dns_log WHERE domain LIKE '%in-addr.arpa%'`).Scan(&n); err != nil {
		t.Fatalf("ptr query: %v", err)
	}
	if n != 0 {
		t.Fatalf("PTR rows leaked into dns_log: %d", n)
	}
}

func TestSearchSuffixLoggedClean(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("network bind test")
	}
	addr, db := startBlockTestServer(t, func(s *Server) {
		s.SearchSuffixes = []string{"IGD_Rostelecom"}
	})

	c := &dns.Client{Timeout: 3 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion("foo.IGD_Rostelecom.", dns.TypeA)
	if _, _, err := c.Exchange(m, addr); err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Logged under the cleaned name; the dirty form never lands in dns_log.
	waitForLogRow(t, db, "SELECT count(*) FROM dns_log WHERE domain=?", "foo.")

	var n int
	if err := db.DB().QueryRow(`SELECT count(*) FROM dns_log WHERE domain LIKE '%IGD_Rostelecom%'`).Scan(&n); err != nil {
		t.Fatalf("suffix query: %v", err)
	}
	if n != 0 {
		t.Fatalf("dirty name leaked into dns_log: %d rows", n)
	}
}

// waitForLogRow polls until the async batch writer commits a matching row.
func waitForLogRow(t *testing.T, db *store.Store, query string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var n int
		if err := db.DB().QueryRow(query, args...).Scan(&n); err != nil {
			t.Fatalf("log query: %v", err)
		}
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("row never appeared: %s %v", query, args)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
