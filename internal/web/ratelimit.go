package web

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter tuning: the UI meta-refreshes every 5s (page + css + js ≈ 3 req per
// refresh per tab); generous bursts keep normal use smooth while bots and
// floods hit 429 fast.
const (
	rateLimitRPS   = 20.0            // sustained tokens per second per IP
	rateLimitBurst = 50              // instant burst per IP
	rateLimitTTL   = 5 * time.Minute // idle bucket lifetime
	maxBuckets     = 4096            // hard upper bound for bucket map
)

type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is a dependency-free per-IP token bucket, safe for concurrent use.
type limiter struct {
	rate, burst float64

	mu      sync.Mutex
	buckets map[string]bucket
}

func newLimiter(rate, burst float64) *limiter {
	return &limiter{rate: rate, burst: burst, buckets: make(map[string]bucket)}
}

// allow reports whether ip may pass now.
func (l *limiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) >= maxBuckets {
		l.sweep(now) // bound memory under IP-spoofing floods
		if len(l.buckets) >= maxBuckets {
			// If still full after sweep, reject new unseen IPs to prevent memory exhaustion
			if _, ok := l.buckets[ip]; !ok {
				return false
			}
		}
	}
	b, ok := l.buckets[ip]
	if !ok {
		l.buckets[ip] = bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens = min(l.burst, b.tokens+l.rate*now.Sub(b.last).Seconds())
	b.last = now
	if b.tokens < 1 {
		l.buckets[ip] = b
		return false
	}
	b.tokens--
	l.buckets[ip] = b
	return true
}

// sweep drops buckets idle longer than rateLimitTTL. Caller holds l.mu.
func (l *limiter) sweep(now time.Time) {
	for ip, b := range l.buckets {
		if now.Sub(b.last) > rateLimitTTL {
			delete(l.buckets, ip)
		}
	}
}

// clientIPFromRequest extracts client IP safely checking X-Forwarded-For and X-Real-IP first.
func clientIPFromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if r.RemoteAddr != "" {
			return r.RemoteAddr
		}
		return "unknown"
	}
	return ip
}

// rateLimit guards h with the limiter (429 when exhausted). /healthz stays
// unlimited so orchestrator probes never fail behind the limiter.
func rateLimit(l *limiter, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			ip := clientIPFromRequest(r)
			if !l.allow(ip, time.Now()) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
