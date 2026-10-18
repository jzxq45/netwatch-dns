// Package web serves the monitoring UI: live feed, devices, top domains and
// a small JSON API. stdlib only, server-rendered with html/template.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"monitor/internal/store"
)

// Store is the read surface the UI needs.
type Store interface {
	RecentEvents(ctx context.Context, limit int) ([]store.Event, error)
	RecentEventsAll(ctx context.Context, limit int) ([]store.Event, error)
	NoisyEventsSince(ctx context.Context, sinceTS int64) (int, error)
	EventsSince(ctx context.Context, since int64, limit int) ([]store.Event, error)
	DeviceByIP(ctx context.Context, ip string) (*store.DeviceRow, error)
	DeviceEvents(ctx context.Context, ip string, limit int) ([]store.Event, error)
	ListDevices(ctx context.Context) ([]store.DeviceRow, error)
	TopDomains(ctx context.Context, sinceTS int64, limit int) ([]store.TopRow, error)
}

const (
	feedLimit = 100
	apiLimit  = 500
)

func New(st Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	mux := http.NewServeMux()
	s := &Server{st: st, log: log, mux: mux, lim: newLimiter(rateLimitRPS, rateLimitBurst)}
	mux.HandleFunc("GET /{$}", s.feed)
	mux.HandleFunc("GET /devices", s.devices)
	mux.HandleFunc("GET /device", s.deviceLog)
	mux.HandleFunc("GET /top", s.top)
	mux.HandleFunc("GET /static/", s.static)
	mux.HandleFunc("GET /api/events", s.apiEvents)
	mux.HandleFunc("GET /healthz", s.healthz)
	// expvar counters/gauges (drops, in-flight, refused) — gated by token auth
	// when web_token is set, like every non-exception route.
	mux.Handle("GET /metrics", expvar.Handler())
	return s
}

type Server struct {
	st  Store
	log *slog.Logger
	mux *http.ServeMux
	lim *limiter

	// Token enables optional web_token auth when set (internal/web tests too).
	// Accepts X-Auth-Token header, ?token= query or auth_token cookie;
	// /healthz and /static/ stay open. Empty = no auth.
	Token string
}

// Handler exposes the router for tests.
func (s *Server) Handler() http.Handler { return s.route() }

// route chains the mux with, outermost first: security headers → panic
// recovery → per-IP rate limit → token auth.
func (s *Server) route() http.Handler {
	var h http.Handler = s.mux
	if s.Token == "" {
		return securityHeaders(s.recovery(rateLimit(s.lim, h)))
	}
	return securityHeaders(s.recovery(rateLimit(s.lim, s.tokenAuth(h))))
}

// tokenAuth guards h with the configured web token.
func (s *Server) tokenAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/static/") {
			h.ServeHTTP(w, r)
			return
		}
		tok := r.Header.Get("X-Auth-Token")
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if tok == "" {
			if c, err := r.Cookie("auth_token"); err == nil {
				tok = c.Value
			}
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("token") == s.Token {
			// First navigation via ?token=: persist for meta-refresh/links.
			// Secure is set for TLS requests only — on plain 127.0.0.1 the
			// cookie must work without HTTPS.
			http.SetCookie(w, &http.Cookie{
				Name: "auth_token", Value: s.Token, Path: "/",
				MaxAge: 30 * 24 * 3600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
				Secure: r.TLS != nil,
			})
		}
		h.ServeHTTP(w, r)
	})
}

// recovery converts handler panics into 500 responses instead of letting a
// panic kill the whole process.
func (s *Server) recovery(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("http panic", "path", r.URL.Path, "panic", p, "stack", string(debug.Stack()))
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

// securityHeaders sets baseline browser protections on every response.
func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hh := w.Header()
		hh.Set("X-Content-Type-Options", "nosniff")
		hh.Set("X-Frame-Options", "DENY")
		hh.Set("Referrer-Policy", "no-referrer")
		// 'unsafe-inline' for style-src covers the style="" attributes the
		// templates use; script-src 'self' covers /static/app.js.
		hh.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		h.ServeHTTP(w, r)
	})
}

// Start serves until ctx is done; returns after listeners closed.
func (s *Server) Start(ctx context.Context, addr string) error {
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           s.route(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second, // GET-only pages; covers slow clients
		WriteTimeout:      15 * time.Second, // caps stuck handler writes
		IdleTimeout:       60 * time.Second, // UI keep-alives refresh every 5s
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("web serve %s: %w", addr, err)
		}
		return nil
	case <-ctx.Done():
		if err := httpSrv.Shutdown(context.WithoutCancel(ctx)); err != nil {
			return fmt.Errorf("web shutdown %s: %w", addr, err)
		}
		return nil
	}
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

//go:embed static
var staticFS embed.FS

var funcMap = template.FuncMap{
	"tsfmt": func(ts int64) string { return time.Unix(ts, 0).Format("15:04:05") },
	// pct returns a safe bar width percentage for count/max.
	"pct": func(count, max int) int {
		if max <= 0 {
			return 0
		}
		return count * 100 / max
	},
}

// nav marks the current link in the top bar with class "on".
func nav(path, current string) string {
	if path == current {
		return "on"
	}
	return ""
}

const pageHead = `<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>monitor</title><link rel="stylesheet" href="/static/style.css">
<meta http-equiv="refresh" content="5">
<script src="/static/app.js" defer></script></head><body>
<header class="topbar">
  <span class="brand"><span class="dot"></span>monitor</span>
  <nav>
    <a href="/" class="{{nav "/" .Path}}">Лента</a>
    <a href="/devices" class="{{nav "/devices" .Path}}">Устройства</a>
    <a href="/top" class="{{nav "/top" .Path}}">Топ</a>
  </nav>
</header>
<main>`

const pageTail = `</main></body></html>`

const contentFeed = `
<h2>Лента <span class="sub">последние {{len .Data.Events}}</span></h2>
<p style="margin:.4rem 0">
  {{if .Data.ShowAll}}<a class="chip link" href="/">✓ обычные</a><span class="chip" style="border-color:var(--accent)">шум и DoH-попытки</span> <a class="chip link" href="/">скрыть шум</a>
  {{else}}<a class="chip link" href="/?show=all">показать шум</a>
  {{if gt .Data.Hidden 0}}<span class="chip" title="noise=1 строки за окно ленты">🚫 {{.Data.Hidden}} шумных скрыто</span>{{end}}{{end}}
</p>
{{if .Data.Events}}
<table>
  <thead><tr><th>Время</th><th></th><th>Устройство</th><th>Домен</th></tr></thead>
  <tbody>{{range .Data.Events}}<tr>
    <td class="time" data-ts="{{.TS}}">{{tsfmt .TS}}</td>
    <td><span class="badge {{.Kind}}">{{.Kind}}</span></td>
    <td><a class="chip link" href="/device?ip={{.ClientIP}}">{{.ClientIP}}</a></td>
    <td class="dom">{{.Name}}{{if $.Data.ShowAll}}{{if .Noise}} <span class="badge blocked">noise</span>{{end}}{{end}}</td></tr>{{end}}</tbody>
</table>
{{else}}<div class="empty">Пока тихо — запросы появятся здесь, когда устройства начнут резолвить домены.</div>{{end}}`

const contentDevices = `
<h2>Устройства <span class="sub">{{len .Data.Devices}} шт</span></h2>
{{if .Data.Devices}}
<div class="cards">{{range .Data.Devices}}
  <div class="dev-card">
    <a class="ip" href="/device?ip={{.IP}}">{{.IP}}</a>
    <div class="attrs">
      {{if .Hostname}}<span class="chip">{{.Hostname}}</span>{{end}}
      {{if .MAC}}<span class="chip">{{.MAC}}</span>{{end}}
    </div>
    <span class="seen">активность: <span data-ts="{{.LastSeen}}">{{tsfmt .LastSeen}}</span></span>
  </div>{{end}}
</div>
{{else}}<div class="empty">Устройств ещё нет. Они появятся, как только роутер начнёт слать DNS на этот ПК (см. TODO.txt).</div>{{end}}`

const contentDevice = `
<p><a class="backlink" href="/devices">← ко всем устройствам</a></p>
<div class="card">
  <div class="kv">
    <b>IP</b><span style="font-family:var(--mono)">{{.Data.Dev.IP}}</span>
    <b>MAC</b><span>{{if .Data.Dev.MAC}}{{.Data.Dev.MAC}}{{else}}<span class="mute">—</span>{{end}}</span>
    <b>Имя</b><span>{{if .Data.Dev.Hostname}}{{.Data.Dev.Hostname}}{{else}}<span class="mute">—</span>{{end}}</span>
    <b>Активность</b><span class="seen"><span data-ts="{{.Data.Dev.LastSeen}}">{{tsfmt .Data.Dev.LastSeen}}</span></span>
  </div>
</div>
<h2>История <span class="sub">последние {{len .Data.Events}}</span></h2>
{{if .Data.Events}}
<table>
  <thead><tr><th>Время</th><th></th><th>Домен</th></tr></thead>
  <tbody>{{range .Data.Events}}<tr>
    <td class="time" data-ts="{{.TS}}">{{tsfmt .TS}}</td>
    <td><span class="badge {{.Kind}}">{{.Kind}}</span></td>
    <td class="dom">{{.Name}}</td></tr>{{end}}</tbody>
</table>
{{else}}<div class="empty">Для этого IP записей пока нет.</div>{{end}}`

const contentTop = `
<h2>Топ доменов <span class="sub">за {{.Data.Period}}</span></h2>
<p><span class="mute">период:</span>
  <a class="chip link" href="/top?period=15m">15м</a>
  <a class="chip link" href="/top?period=1h">1ч</a>
  <a class="chip link" href="/top?period=6h">6ч</a>
  <a class="chip link" href="/top?period=24h">24ч</a>
  <a class="chip link" href="/top?period=7d">7д</a></p>
{{if .Data.Rows}}
<div class="card">
{{range .Data.Rows}}
  <div class="rowbar" style="padding:.35rem 0">
    <a class="chip link" href="/device?ip={{.DeviceIP}}">{{.DeviceIP}}</a>
    <div class="bar"><span style="width:{{pct .Count $.Data.Max}}%"></span></div>
    <span style="font-family:var(--mono);text-align:right">{{.Count}}</span>
  </div>
  <div class="dom" style="padding:0 0 .5rem">{{.Domain}}</div>
{{end}}
</div>
{{else}}<div class="empty">Нет данных за этот период.</div>{{end}}`

func page(content string) *template.Template {
	// nav rewrites funcMap via new template instance
	t := template.Must(template.New("p").Funcs(funcMap).Funcs(template.FuncMap{"nav": nav}).Parse(pageHead + content + pageTail))
	return t
}

// fail logs the real error and returns a generic 500 — raw error strings
// could leak DB or filesystem internals to the client.
func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// render executes a parsed page into a buffer first: a template error must
// not reach the client as a truncated 200-response.
func (s *Server) render(w http.ResponseWriter, status int, t *template.Template, path string, data any) {
	var buf bytes.Buffer
	inner := struct {
		Path string
		Data any
	}{path, data}
	if err := t.Execute(&buf, inner); err != nil {
		// The client gets nothing: a clean 500 beats half a page.
		s.log.Error("web render", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.Copy(w, &buf)
}

func (s *Server) feed(w http.ResponseWriter, r *http.Request) {
	showAll := r.URL.Query().Get("show") == "all"
	var (
		events []store.Event
		err    error
	)
	if showAll {
		events, err = s.st.RecentEventsAll(r.Context(), feedLimit)
	} else {
		events, err = s.st.RecentEvents(r.Context(), feedLimit)
	}
	if err != nil {
		s.fail(w, "feed events", err)
		return
	}
	// Hidden-noise counter: noise rows at or after the oldest shown row.
	hidden := 0
	if len(events) > 0 {
		if hidden, err = s.st.NoisyEventsSince(r.Context(), events[len(events)-1].TS); err != nil {
			s.fail(w, "feed noise count", err)
			return
		}
		if showAll {
			hidden = 0
		}
	}
	s.render(w, http.StatusOK, page(contentFeed), "/", struct {
		Events  []store.Event
		ShowAll bool
		Hidden  int
	}{events, showAll, hidden})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.st.ListDevices(r.Context())
	if err != nil {
		s.fail(w, "devices list", err)
		return
	}
	s.render(w, http.StatusOK, page(contentDevices), "/devices", struct {
		Devices []store.DeviceRow
	}{ds})
}

func (s *Server) deviceLog(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" || net.ParseIP(ip) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	dev, err := s.st.DeviceByIP(r.Context(), ip)
	if err != nil {
		s.fail(w, "device lookup", err)
		return
	}
	if dev == nil {
		// Unknown device (row appears after first query) — still show history.
		dev = &store.DeviceRow{IP: ip}
	}
	events, err := s.st.DeviceEvents(r.Context(), ip, feedLimit)
	if err != nil {
		s.fail(w, "device events", err)
		return
	}
	s.render(w, http.StatusOK, page(contentDevice), "/device", struct {
		Dev    *store.DeviceRow
		Events []store.Event
	}{dev, events})
}

func (s *Server) top(w http.ResponseWriter, r *http.Request) {
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "1h"
	}
	d, err := time.ParseDuration(period)
	if err != nil || d < time.Minute || d > 7*24*time.Hour {
		http.Error(w, "invalid period", http.StatusBadRequest)
		return
	}
	rows, err := s.st.TopDomains(r.Context(), time.Now().Add(-d).Unix(), feedLimit*10)
	if err != nil {
		s.fail(w, "top domains", err)
		return
	}
	max := 0
	for _, row := range rows {
		if row.Count > max {
			max = row.Count
		}
	}
	s.render(w, http.StatusOK, page(contentTop), "/top", struct {
		Rows   []store.TopRow
		Period string
		Max    int
	}{rows, period, max})
}

// static serves the embedded css/js without a filesystem dependency.
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		s.fail(w, "static fs", err)
		return
	}
	http.StripPrefix("/static/", http.FileServerFS(sub)).ServeHTTP(w, r)
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := int64(0)
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid since", http.StatusBadRequest)
			return
		}
		since = n
	}
	events, err := s.st.EventsSince(r.Context(), since, apiLimit)
	if err != nil {
		s.fail(w, "api events", err)
		return
	}
	if events == nil {
		events = []store.Event{} // JSON [] instead of null — the API contract
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(events); err != nil { //nolint:errcheck // client may vanish mid-write
		s.log.Debug("api events write", "err", err)
	}
}
