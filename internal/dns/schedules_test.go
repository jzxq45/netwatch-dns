package dns

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"monitor/internal/store"
)

// mondayAt returns a local Monday inside the given year/week for stable
// weekday-mask assertions (2026-11-02 is a Monday).
func mondayAt(hour, min int) time.Time {
	return time.Date(2026, 11, 2, hour, min, 0, 0, time.Local)
}

func TestScheduleEngineServiceTargets(t *testing.T) {
	t.Parallel()
	e := NewScheduleEngine()
	e.SetSchedules([]store.Schedule{{
		Target: "youtube", DaysMask: 0, Enabled: true,
	}})
	now := mondayAt(23, 30)

	for _, domain := range []string{
		"youtube.com.", "www.youtube.com", "youtu.be", "r1---sn-abc.googlevideo.com",
	} {
		if !e.IsScheduledBlocked("192.168.1.10", domain, now) {
			t.Errorf("%q should match youtube service", domain)
		}
	}
	for _, domain := range []string{
		"notyoutube.com", "youtube.com.evil.example", "example.com",
	} {
		if e.IsScheduledBlocked("192.168.1.10", domain, now) {
			t.Errorf("%q must not match youtube service", domain)
		}
	}
}

func TestScheduleEngineDomainTargetAndClient(t *testing.T) {
	t.Parallel()
	e := NewScheduleEngine()
	e.SetSchedules([]store.Schedule{{
		ClientIP: "192.168.1.50", Target: "Games.Example.COM.",
		DaysMask: 0, Enabled: true,
	}})
	now := mondayAt(12, 0)

	if !e.IsScheduledBlocked("192.168.1.50", "games.example.com.", now) {
		t.Error("exact domain target should match (case/trailing dot insensitive)")
	}
	if !e.IsScheduledBlocked("192.168.1.50", "cdn.games.example.com", now) {
		t.Error("subdomain of a domain target should match")
	}
	if e.IsScheduledBlocked("192.168.1.50", "other.example.com", now) {
		t.Error("unrelated domain must not match")
	}
	if e.IsScheduledBlocked("192.168.1.51", "games.example.com", now) {
		t.Error("other clients must not be blocked")
	}

	// Empty ClientIP means every device.
	e.SetSchedules([]store.Schedule{{Target: "games.example.com", DaysMask: 0, Enabled: true}})
	if !e.IsScheduledBlocked("10.0.0.99", "games.example.com", now) {
		t.Error("empty client_ip should apply to all devices")
	}
}

func TestScheduleEngineWindowAndDays(t *testing.T) {
	t.Parallel()
	overnight := store.Schedule{
		Target: "youtube", StartHour: 22, EndHour: 7,
		DaysMask: 1 << uint(time.Monday), Enabled: true,
	}
	e := NewScheduleEngine()
	e.SetSchedules([]store.Schedule{overnight})

	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"before window", mondayAt(21, 59), false},
		{"window start", mondayAt(22, 0), true},
		{"midnight crossover", mondayAt(0, 30), true},
		{"last minute", mondayAt(6, 59), true},
		{"window end exclusive", mondayAt(7, 0), false},
		{"wrong weekday", time.Date(2026, 11, 3, 23, 0, 0, 0, time.Local), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := e.IsScheduledBlocked("192.168.1.10", "youtube.com", tt.now); got != tt.want {
				t.Errorf("blocked = %v, want %v at %v", got, tt.want, tt.now)
			}
		})
	}

	daytime := store.Schedule{
		Target: "youtube", StartHour: 9, EndHour: 17,
		DaysMask: 0, Enabled: true,
	}
	e.SetSchedules([]store.Schedule{daytime})
	if !e.IsScheduledBlocked("192.168.1.10", "youtube.com", mondayAt(12, 0)) {
		t.Error("same-day window should block at noon")
	}
	if e.IsScheduledBlocked("192.168.1.10", "youtube.com", mondayAt(17, 0)) {
		t.Error("same-day window end must be exclusive")
	}
	if !e.IsScheduledBlocked("192.168.1.10", "youtube.com", mondayAt(9, 0)) {
		t.Error("same-day window start is inclusive")
	}

	// start == end means all day, and mask 0 means every day.
	allDay := store.Schedule{Target: "youtube", StartHour: 0, EndHour: 0, DaysMask: 0, Enabled: true}
	e.SetSchedules([]store.Schedule{allDay})
	if !e.IsScheduledBlocked("192.168.1.10", "youtube.com", mondayAt(3, 17)) {
		t.Error("start == end should mean all day")
	}
}

func TestScheduleEngineDisabled(t *testing.T) {
	t.Parallel()
	e := NewScheduleEngine()
	e.SetSchedules([]store.Schedule{{
		Target: "youtube", DaysMask: 0, Enabled: false,
	}})
	if e.IsScheduledBlocked("192.168.1.10", "youtube.com", mondayAt(12, 0)) {
		t.Error("disabled schedule must not block")
	}
}

func TestServerScheduledBlockIntegration(t *testing.T) {
	t.Parallel()
	up := startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
			A:   net.ParseIP("1.2.3.4"),
		})
		_ = w.WriteMsg(m)
	}))

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("store open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv := New(Config{Upstream: up}, db.DB(), discardLogger())
	srv.SetSchedules([]store.Schedule{{
		ClientIP: "192.168.1.100",
		Target:   "youtube",
		// start == end → all day, independent of the test clock.
		DaysMask: 0,
		Enabled:  true,
	}})

	rec := make(chan Record, 2)
	srv.OnRecord = func(r Record) { rec <- r }

	blockedRW := &testResponseWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 5353}}
	req := new(dns.Msg)
	req.SetQuestion("www.youtube.com.", dns.TypeA)
	srv.handle(blockedRW, req)
	if blockedRW.msg == nil {
		t.Fatal("no response for scheduled block")
	}
	if blockedRW.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[blockedRW.msg.Rcode])
	}
	select {
	case r := <-rec:
		if !r.Noise {
			t.Error("scheduled block should be recorded as noise")
		}
	default:
		t.Error("scheduled block was not recorded")
	}

	// Same domain from another client must still resolve upstream.
	allowedRW := &testResponseWriter{remoteAddr: &net.UDPAddr{IP: net.ParseIP("192.168.1.101"), Port: 5354}}
	req2 := new(dns.Msg)
	req2.SetQuestion("www.youtube.com.", dns.TypeA)
	srv.handle(allowedRW, req2)
	if allowedRW.msg == nil || allowedRW.msg.Rcode != dns.RcodeSuccess {
		t.Fatalf("allowed client response = %+v", allowedRW.msg)
	}
	if len(allowedRW.msg.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(allowedRW.msg.Answer))
	}
}
