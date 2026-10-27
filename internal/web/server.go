// Package web serves the monitoring UI: live feed, devices, top domains and
// a small JSON API. stdlib only, server-rendered with html/template.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/csv"
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
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"monitor/internal/devices"
	"monitor/internal/metrics"
	"monitor/internal/store"
	"monitor/internal/sysnet"
)

// Store is the read surface the UI needs.
type Store interface {
	RecentEvents(ctx context.Context, limit int) ([]store.Event, error)
	RecentEventsAll(ctx context.Context, limit int) ([]store.Event, error)
	NoisyEventsSince(ctx context.Context, sinceTS int64) (int, error)
	EventsSince(ctx context.Context, since int64, limit int) ([]store.Event, error)
	HourlyActivity(ctx context.Context, sinceTS int64) ([]store.HourlyBucket, error)
	DeviceByIP(ctx context.Context, ip string) (*store.DeviceRow, error)
	DeviceEvents(ctx context.Context, ip string, limit int) ([]store.Event, error)
	ListDevices(ctx context.Context) ([]store.DeviceRow, error)
	TopDomains(ctx context.Context, sinceTS int64, limit int) ([]store.TopRow, error)
	SetDeviceHostname(ctx context.Context, ip string, hostname string) error
	ListCustomRules(ctx context.Context) ([]store.CustomRule, error)
	SetCustomRule(ctx context.Context, domain string, action string) error
	DeleteCustomRule(ctx context.Context, domain string) error
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
	s := &Server{
		st:     st,
		log:    log,
		mux:    mux,
		lim:    newLimiter(rateLimitRPS, rateLimitBurst),
		broker: newEventBroker(),
	}
	mux.HandleFunc("GET /{$}", s.feed)
	mux.HandleFunc("GET /devices", s.devices)
	mux.HandleFunc("GET /device", s.deviceLog)
	mux.HandleFunc("GET /top", s.top)
	mux.HandleFunc("GET /static/", s.static)
	mux.HandleFunc("GET /api/events", s.apiEvents)
	mux.HandleFunc("GET /api/events/stream", s.apiEventsStream)
	mux.HandleFunc("GET /api/export", s.apiExport)
	mux.HandleFunc("GET /api/activity", s.apiActivity)
	mux.HandleFunc("GET /api/rules", s.apiListRules)
	mux.HandleFunc("POST /api/rules", s.apiSetRule)
	mux.HandleFunc("DELETE /api/rules", s.apiDeleteRule)
	mux.HandleFunc("GET /api/network", s.apiNetwork)
	mux.HandleFunc("POST /api/local-dns", s.apiSetLocalDNS)
	mux.HandleFunc("POST /api/autostart", s.apiSetAutostart)
	mux.HandleFunc("POST /api/device/rename", s.apiRenameDevice)
	mux.HandleFunc("GET /download/netwatch.apk", s.downloadAPK)
	mux.HandleFunc("GET /healthz", s.healthz)
	// expvar counters/gauges (drops, in-flight, refused) — gated by token auth
	// when web_token is set, like every non-exception route.
	mux.Handle("GET /metrics", expvar.Handler())
	return s
}

type Server struct {
	st     Store
	log    *slog.Logger
	mux    *http.ServeMux
	lim    *limiter
	broker *eventBroker

	// Token enables optional web_token auth when set (internal/web tests too).
	// Accepts X-Auth-Token header, ?token= query or auth_token cookie; /healthz
	// and /static/ stay open. Empty = no auth.
	Token string

	// RulesCount reports active blocklist rules; nil means unavailable.
	RulesCount func() int

	// OnRuleChanged applies a saved/deleted custom rule to the live matcher.
	OnRuleChanged func(domain, action string, deleted bool)
}

func (s *Server) Broadcast(e store.Event) {
	if s.broker != nil {
		s.broker.broadcast(e)
	}
}

type eventBroker struct {
	mu      sync.RWMutex
	clients map[chan store.Event]struct{}
}

func newEventBroker() *eventBroker {
	return &eventBroker{clients: make(map[chan store.Event]struct{})}
}

func (b *eventBroker) subscribe() chan store.Event {
	ch := make(chan store.Event, 64)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *eventBroker) unsubscribe(ch chan store.Event) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
}

func (b *eventBroker) broadcast(e store.Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- e:
		default:
		}
	}
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
	"tsfmt":  func(ts int64) string { return time.Unix(ts, 0).Format("15:04:05") },
	"vendor": devices.VendorLookup,
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
<div class="card setup-card" id="setupCard" style="display:none;margin-bottom:1.2rem">
  <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:.8rem">
    <div style="display:flex;align-items:center;gap:.6rem;flex-wrap:wrap">
      <span style="font-weight:600">⚡ Мониторинг этого ПК:</span>
      <button class="chip" id="btnToggleLocalDns" style="cursor:pointer;padding:.2rem .75rem;font-weight:600">загрузка...</button>
      <button class="chip" id="btnToggleAutostart" style="cursor:pointer;padding:.2rem .75rem" title="Запускать приложение вместе с Windows">🚀 Автозапуск</button>
    </div>
    <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap">
      <span class="mute">Для всей сети:</span>
      <span class="chip" id="lblLanIp" title="Укажите этот IP в роутере как DNS">IP: ...</span>
      <button class="chip link" id="btnCopyIp" style="cursor:pointer">📋 Скопировать</button>
      <a class="chip link" id="btnOpenRouter" target="_blank" href="#">↗ Роутер</a>
      <button class="chip link" id="btnPhonePair" style="cursor:pointer">📱 Телефон</button>
      <div class="chip" id="lblBlockStats" title="Активная защита от рекламы и вредоносных доменов">🛡️ Защита: <span id="valBlockedQueries">0</span> угроз (<span id="valBlockedRules">0</span> правил)</div>
    </div>
  </div>
  <div id="localDnsError" style="color:#ff8080;font-size:.82rem;margin-top:.4rem;display:none"></div>
  <div id="phonePairCard" style="display:none;margin-top:.8rem;padding:.7rem .9rem;border:1px dashed var(--line);border-radius:var(--radius);font-size:.85rem">
    <b>📱 Мобильное приложение:</b> укажите адрес <span class="chip" id="phonePairAddr">http://...</span> в настройках Netwatch на телефоне (тот же Wi-Fi).
    <a class="chip link" href="/download/netwatch.apk" download style="margin-top:.4rem;display:inline-block">📥 Скачать NetWatch.apk</a>
  </div>
</div>
<h2>Лента <span class="sub">последние {{len .Data.Events}}</span></h2>
<p style="margin:.4rem 0">
  {{if .Data.ShowAll}}<a class="chip link" href="/">✓ обычные</a><span class="chip" style="border-color:var(--accent)">шум и DoH-попытки</span> <a class="chip link" href="/">скрыть шум</a>
  {{else}}<a class="chip link" href="/?show=all">показать шум</a>
  {{if gt .Data.Hidden 0}}<span class="chip" title="noise=1 строки за окно ленты">🚫 {{.Data.Hidden}} шумных скрыто</span>{{end}}{{end}}
  <span style="margin-left:.6rem;opacity:.6">|</span> <a class="chip link" href="/api/export?format=csv" download>📥 Экспорт CSV</a> <a class="chip link" href="/api/export?format=json" download>JSON</a>
</p>
{{if .Data.Events}}
<table>
  <thead><tr><th>Время</th><th></th><th>Устройство</th><th>Домен</th></tr></thead>
  <tbody>{{range .Data.Events}}<tr>
    <td class="time" data-ts="{{.TS}}">{{tsfmt .TS}}</td>
    <td><span class="badge {{.Kind}}">{{.Kind}}</span></td>
    <td><a class="chip link" href="/device?ip={{.ClientIP}}">{{.ClientIP}}</a></td>
    <td class="dom">{{.Name}}{{if $.Data.ShowAll}}{{if .Noise}} <span class="badge blocked">noise</span>{{end}}{{end}}<button class="chip btn-block-dom" data-dom="{{.Name}}" title="Заблокировать этот домен" style="cursor:pointer;padding:0 .35rem;margin-left:.35rem;font-size:.7rem">🚫</button></td></tr>{{end}}</tbody>
</table>
{{else}}<div class="empty">Пока тихо — запросы появятся здесь, когда устройства начнут резолвить домены.</div>{{end}}`

const contentDevices = `
<h2>Устройства <span class="sub">{{len .Data.Devices}} шт</span></h2>
{{if .Data.Devices}}
<div class="cards">{{range .Data.Devices}}
  <div class="dev-card">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <a class="ip" href="/device?ip={{.IP}}">{{.IP}}</a>
      {{$v := vendor .MAC}}{{if $v}}<span class="badge dns">{{$v}}</span>{{end}}
    </div>
    <div class="attrs">
      {{if .Hostname}}<span class="chip" style="color:var(--text);font-weight:600">{{.Hostname}}</span>{{end}}
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
    <b>MAC</b><span>{{if .Data.Dev.MAC}}{{.Data.Dev.MAC}}{{$v := vendor .Data.Dev.MAC}}{{if $v}} <span class="badge dns">{{$v}}</span>{{end}}{{else}}<span class="mute">—</span>{{end}}</span>
    <b>Имя</b><span id="devNameWrap"><span id="devNameVal">{{if .Data.Dev.Hostname}}{{.Data.Dev.Hostname}}{{else}}<span class="mute">—</span>{{end}}</span> <button class="chip link" id="btnRenameDev" style="cursor:pointer;margin-left:.4rem">✏️ изменить</button></span>
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
<div class="card" style="margin-bottom:1rem">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.6rem;flex-wrap:wrap;gap:.4rem">
    <b>Активность по часам</b>
    <span class="mute">24 ч · <span style="color:var(--accent)">обычные</span> / <span style="color:#ff8080">заблокированные</span></span>
  </div>
  <div class="chart-grid">
    {{range .Data.Activity}}
    <div class="chart-col" title="{{.Label}} — всего: {{.Total}}, заблокировано: {{.Blocked}}">
      <div class="chart-bar" style="height:{{.TotalPct}}%">
        <span class="chart-seg normal" style="height:{{.NormalPct}}%"></span>
        <span class="chart-seg blocked" style="height:{{.BlockedPct}}%;bottom:{{.NormalPct}}%"></span>
      </div>
      <span class="chart-label">{{.Label}}</span>
    </div>
    {{end}}
  </div>
</div>
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

// activityBar is one column of the 24h timeline chart.
type activityBar struct {
	Label      string
	Total      int
	Blocked    int
	TotalPct   int
	NormalPct  int
	BlockedPct int
}

// buildActivity fills missing hours with zero buckets and scales bar heights
// to the busiest hour so the chart always has exactly 24 columns.
func buildActivity(buckets []store.HourlyBucket, now time.Time) []activityBar {
	byTS := make(map[int64]store.HourlyBucket, len(buckets))
	for _, b := range buckets {
		byTS[b.TS] = b
	}
	endHour := now.Truncate(time.Hour).Unix()
	bars := make([]activityBar, 0, 24)
	max := 0
	for i := 23; i >= 0; i-- {
		ts := endHour - int64(i)*3600
		b := byTS[ts]
		if b.Total > max {
			max = b.Total
		}
		bars = append(bars, activityBar{
			Label:   time.Unix(ts, 0).Format("15:04"),
			Total:   b.Total,
			Blocked: b.Blocked,
		})
	}
	if max == 0 {
		return bars
	}
	for i := range bars {
		total := bars[i].Total * 100 / max
		blocked := bars[i].Blocked * 100 / max
		if bars[i].Total > 0 && total == 0 {
			total = 1
		}
		if bars[i].Blocked > 0 && blocked == 0 {
			blocked = 1
		}
		if blocked > total {
			blocked = total
		}
		bars[i].TotalPct = total
		bars[i].BlockedPct = blocked
		bars[i].NormalPct = total - blocked
	}
	return bars
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
	now := time.Now()
	rows, err := s.st.TopDomains(r.Context(), now.Add(-d).Unix(), feedLimit*10)
	if err != nil {
		s.fail(w, "top domains", err)
		return
	}
	buckets, err := s.st.HourlyActivity(r.Context(), now.Add(-24*time.Hour).Unix())
	if err != nil {
		s.fail(w, "top activity", err)
		return
	}
	max := 0
	for _, row := range rows {
		if row.Count > max {
			max = row.Count
		}
	}
	s.render(w, http.StatusOK, page(contentTop), "/top", struct {
		Rows     []store.TopRow
		Activity []activityBar
		Period   string
		Max      int
	}{rows, buildActivity(buckets, now), period, max})
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

// downloadAPK serves the built Android app from the server directory,
// checking the usual output locations in order.
func (s *Server) downloadAPK(w http.ResponseWriter, r *http.Request) {
	for _, path := range []string{
		"netwatch.apk",
		filepath.Join("android", "app-release.apk"),
		filepath.Join("android", "app", "build", "outputs", "apk", "debug", "app-debug.apk"),
	} {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			w.Header().Set("Content-Type", "application/vnd.android.package-archive")
			w.Header().Set("Content-Disposition", "attachment; filename=\"netwatch.apk\"")
			http.ServeFile(w, r, path)
			return
		}
	}
	http.Error(w, "APK not found", http.StatusNotFound)
}

// apiActivity returns hourly DNS totals for the last 24 hours (since is
// accepted as an optional unix-seconds override).
func (s *Server) apiActivity(w http.ResponseWriter, r *http.Request) {
	since := time.Now().Add(-24 * time.Hour).Unix()
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid since", http.StatusBadRequest)
			return
		}
		since = n
	}
	buckets, err := s.st.HourlyActivity(r.Context(), since)
	if err != nil {
		s.fail(w, "api activity", err)
		return
	}
	if buckets == nil {
		buckets = []store.HourlyBucket{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(buckets) //nolint:errcheck // client may vanish mid-write
}

// apiExport streams the DNS journal as CSV or JSON for audits and reports.
func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := time.Now().Add(-24 * time.Hour).Unix()
	if v := q.Get("since"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid since", http.StatusBadRequest)
			return
		}
		since = n
	}
	limit := 5000
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = n
	}
	if limit > 50000 {
		limit = 50000
	}
	events, err := s.st.EventsSince(r.Context(), since, limit)
	if err != nil {
		s.fail(w, "api export", err)
		return
	}
	if strings.EqualFold(q.Get("format"), "json") {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="dns_export.json"`)
		_ = json.NewEncoder(w).Encode(events) //nolint:errcheck // client may vanish mid-write
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="dns_export.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "time_iso", "client_ip", "kind", "domain", "noise"})
	for _, e := range events {
		noise := "0"
		if e.Noise {
			noise = "1"
		}
		_ = cw.Write([]string{
			strconv.FormatInt(e.TS, 10),
			time.Unix(e.TS, 0).Format(time.RFC3339),
			e.ClientIP,
			e.Kind,
			e.Name,
			noise,
		})
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		s.log.Error("api export csv", "err", err)
	}
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

func (s *Server) apiNetwork(w http.ResponseWriter, _ *http.Request) {
	rules := 0
	if s.RulesCount != nil {
		rules = s.RulesCount()
	}
	info := struct {
		sysnet.NetworkInfo
		BlockedQueries int64 `json:"blocked_queries"`
		BlockedRules   int   `json:"blocked_rules"`
	}{
		NetworkInfo:    sysnet.GetNetworkInfo(),
		BlockedQueries: metrics.DNSBlockedTotal.Value(),
		BlockedRules:   rules,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

func (s *Server) apiSetLocalDNS(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := sysnet.SetLocalDNS(body.Enabled); err != nil {
		s.log.Error("set local dns", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) apiSetAutostart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := sysnet.SetAutostart(body.Enabled); err != nil {
		s.log.Error("set autostart", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// apiListRules returns all custom block/allow overrides.
func (s *Server) apiListRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.st.ListCustomRules(r.Context())
	if err != nil {
		s.fail(w, "api list rules", err)
		return
	}
	if rules == nil {
		rules = []store.CustomRule{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rules) //nolint:errcheck // client may vanish mid-write
}

// apiSetRule stores a custom rule and applies it to the live matcher.
func (s *Server) apiSetRule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	domain := strings.TrimSpace(body.Domain)
	if domain == "" || (body.Action != store.RuleBlock && body.Action != store.RuleAllow) {
		http.Error(w, "invalid domain or action", http.StatusBadRequest)
		return
	}
	if err := s.st.SetCustomRule(r.Context(), domain, body.Action); err != nil {
		s.fail(w, "api set rule", err)
		return
	}
	if s.OnRuleChanged != nil {
		s.OnRuleChanged(domain, body.Action, false)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// apiDeleteRule removes a custom rule and its live matcher entry.
func (s *Server) apiDeleteRule(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}
	if err := s.st.DeleteCustomRule(r.Context(), domain); err != nil {
		s.fail(w, "api delete rule", err)
		return
	}
	if s.OnRuleChanged != nil {
		s.OnRuleChanged(domain, "", true)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) apiEventsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.broker.subscribe()
	defer s.broker.unsubscribe(ch)

	// Send initial comment to establish stream
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) apiRenameDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP   string `json:"ip"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.IP == "" || net.ParseIP(body.IP) == nil {
		http.Error(w, "invalid ip", http.StatusBadRequest)
		return
	}
	if err := s.st.SetDeviceHostname(r.Context(), body.IP, strings.TrimSpace(body.Name)); err != nil {
		s.fail(w, "set device hostname", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
