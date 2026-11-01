package web

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestMetricsEndpoint pins the public Prometheus exposition contract:
// exact Content-Type, one HELP/TYPE header per metric and a numeric sample.
func TestMetricsEndpoint(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	srv.RulesCount = func() int { return 42 }

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	const wantCT = "text/plain; version=0.0.4; charset=utf-8"
	if ct := rec.Header().Get("Content-Type"); ct != wantCT {
		t.Fatalf("Content-Type = %q, want %q", ct, wantCT)
	}
	body := rec.Body.String()

	required := [][3]string{
		{"netwatch_dns_queries_total", "Total DNS queries processed", "counter"},
		{"netwatch_dns_queries_blocked_total", "Total DNS queries blocked", "counter"},
		{"netwatch_dns_cache_hits_total", "Total DNS cache hits", "counter"},
		{"netwatch_dns_rules_count", "Total active blocklist rules", "gauge"},
		{"netwatch_uptime_seconds", "Server uptime in seconds", "gauge"},
	}
	for _, m := range required {
		for _, line := range []string{
			"# HELP " + m[0] + " " + m[1],
			"# TYPE " + m[0] + " " + m[2],
		} {
			if !strings.Contains(body, line+"\n") {
				t.Errorf("missing %q in:\n%s", line, body)
			}
		}
		if _, ok := metricValue(body, m[0]); !ok {
			t.Errorf("missing numeric sample for %s", m[0])
		}
	}

	if got, _ := metricValue(body, "netwatch_dns_rules_count"); got != 42 {
		t.Errorf("netwatch_dns_rules_count = %v, want 42", got)
	}
	if uptime, ok := metricValue(body, "netwatch_uptime_seconds"); !ok || uptime < 0 {
		t.Errorf("netwatch_uptime_seconds = %v (ok=%v), want >= 0", uptime, ok)
	}
	if !strings.HasSuffix(body, "\n") {
		t.Error("exposition must end with a newline")
	}
}

// TestMetricsPublicWithToken: Prometheus must be able to scrape /metrics
// without a web token, while normal routes stay protected.
func TestMetricsPublicWithToken(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	srv.Token = "secret"

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200 without token", rec.Code)
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/api/stats status = %d, want 401 without token", rec.Code)
	}
}

// TestMetricsLegacyAlias proves existing dashboards keep working with the
// legacy dns_* metric names after /metrics switched to netwatch_*.
func TestMetricsLegacyAlias(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics/prometheus", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "# TYPE dns_cache_hits_total counter\n") {
		t.Errorf("legacy metric missing:\n%s", body)
	}
}

func metricValue(body, name string) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+" ") {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(line, name+" ")), 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}
