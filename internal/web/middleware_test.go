package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"monitor/internal/store"
)

// fixtureErr is the stand-in for a flaky DB; its text must never reach clients.
var fixtureErr = errors.New("fixture error")

// failingStore fails every read: otherwise the stub for a broken DB.
type failingStore struct{}

func (failingStore) RecentEvents(context.Context, int) ([]store.Event, error) {
	return nil, fixtureErr
}
func (failingStore) RecentEventsAll(context.Context, int) ([]store.Event, error) {
	return nil, fixtureErr
}
func (failingStore) NoisyEventsSince(context.Context, int64) (int, error) {
	return 0, fixtureErr
}
func (failingStore) EventsSince(context.Context, int64, int) ([]store.Event, error) {
	return nil, fixtureErr
}
func (failingStore) DeviceByIP(context.Context, string) (*store.DeviceRow, error) {
	return nil, fixtureErr
}
func (failingStore) DeviceEvents(context.Context, string, int) ([]store.Event, error) {
	return nil, fixtureErr
}
func (failingStore) ListDevices(context.Context) ([]store.DeviceRow, error) {
	return nil, fixtureErr
}
func (failingStore) TopDomains(context.Context, int64, int) ([]store.TopRow, error) {
	return nil, fixtureErr
}

// TestRecovery: a handler panic must become a 500 — never a crashed process.
func TestRecovery(t *testing.T) {
	t.Parallel()
	srv := New(&failingStore{}, nil)
	h := srv.recovery(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !contains(rec.Body.String(), "internal server error") {
		t.Fatalf("body hides the generic message: %s", rec.Body)
	}
	if contains(rec.Body.String(), "boom") {
		t.Fatal("panic value leaked to client")
	}
}

// TestSecurityHeaders: every response (incl. open /healthz) carries the
// baseline browser protections.
func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	srv := New(&failingStore{}, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	for _, tt := range []struct{ h, want string }{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "no-referrer"},
	} {
		if got := rec.Header().Get(tt.h); got != tt.want {
			t.Errorf("%s = %q, want %q", tt.h, got, tt.want)
		}
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self': %q", rec.Header().Get("Content-Security-Policy"))
	}
}

// TestRateLimit: past the burst an IP gets 429, and /healthz is never
// limited so probes can't fail behind the limiter.
func TestRateLimit(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)
	srv.lim = newLimiter(0.001, 3) // deterministic: burst, then nothing

	do := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < 3; i++ {
		if rec := do("/api/events"); rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
	}
	if rec := do("/api/events"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("burst-excess status = %d, want 429", rec.Code)
	}
	if rec := do("/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("healthz limited: status = %d, want 200", rec.Code)
	}
}

// TestGenericErrorPage pins the no-information-disclosure contract: failing
// reads answer a generic 500, not the underlying error text.
func TestGenericErrorPage(t *testing.T) {
	t.Parallel()
	srv := New(&failingStore{}, nil)
	for _, path := range []string{"/", "/devices", "/top?period=1h", "/api/events"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("%s: status = %d, want 500", path, rec.Code)
		}
		if !contains(rec.Body.String(), "internal server error") {
			t.Fatalf("%s: body missing generic message: %s", path, rec.Body)
		}
		if contains(rec.Body.String(), fixtureErr.Error()) {
			t.Fatalf("%s: raw error leaked: %s", path, rec.Body)
		}
	}
}
