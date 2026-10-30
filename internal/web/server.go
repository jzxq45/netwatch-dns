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
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"unicode/utf8"

	"monitor/internal/devices"
	"monitor/internal/filter"
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
	DeviceActivity(ctx context.Context, sinceTS int64) (map[string]store.DeviceActivitySummary, error)
	TopDomains(ctx context.Context, sinceTS int64, limit int) ([]store.TopRow, error)
	Stats24h(ctx context.Context) (store.StatsSummary, error)
	SetDeviceHostname(ctx context.Context, ip string, hostname string) error
	ListCustomRules(ctx context.Context) ([]store.CustomRule, error)
	SetCustomRule(ctx context.Context, domain string, action string) error
	DeleteCustomRule(ctx context.Context, domain string) error
	ListRewrites(ctx context.Context) ([]store.DNSRewrite, error)
	SetRewrite(ctx context.Context, domain, ip string) error
	DeleteRewrite(ctx context.Context, domain string) error
}

const (
	feedLimit = 100
	apiLimit  = 500
)

// domainPattern limits rule domains to a conservative charset; further
// per-label checks remain the store's / matcher's responsibility.
var domainPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)

// maxDomainLen is the maximum length of a fully qualified domain name.
const maxDomainLen = 253

// maxDeviceNameLen caps user-provided device display names.
const maxDeviceNameLen = 64

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
	mux.HandleFunc("GET /api/devices/audit", s.apiDevicesAudit)
	mux.HandleFunc("GET /device", s.deviceLog)
	mux.HandleFunc("GET /top", s.top)
	mux.HandleFunc("GET /static/", s.static)
	mux.HandleFunc("GET /api/events", s.apiEvents)
	mux.HandleFunc("GET /api/stats", s.apiStats)
	mux.HandleFunc("GET /api/events/stream", s.apiEventsStream)
	mux.HandleFunc("GET /api/export", s.apiExport)
	mux.HandleFunc("GET /api/activity", s.apiActivity)
	mux.HandleFunc("GET /api/rules", s.apiListRules)
	mux.HandleFunc("POST /api/rules", s.apiSetRule)
	mux.HandleFunc("DELETE /api/rules", s.apiDeleteRule)
	mux.HandleFunc("GET /api/rewrites", s.apiListRewrites)
	mux.HandleFunc("POST /api/rewrites", s.apiSetRewrite)
	mux.HandleFunc("DELETE /api/rewrites", s.apiDeleteRewrite)
	mux.HandleFunc("GET /api/services", s.apiServices)
	mux.HandleFunc("POST /api/services/toggle", s.apiServiceToggle)
	mux.HandleFunc("GET /api/network", s.apiNetwork)
	mux.HandleFunc("GET /api/qr", s.apiQR)
	mux.HandleFunc("GET /api/apple.mobileconfig", s.appleMobileConfig)
	mux.HandleFunc("GET /netwatch.mobileconfig", s.appleMobileConfig)
	mux.HandleFunc("POST /api/local-dns", s.apiSetLocalDNS)
	mux.HandleFunc("POST /api/autostart", s.apiSetAutostart)
	mux.HandleFunc("POST /api/device/rename", s.apiRenameDevice)
	mux.HandleFunc("GET /download/netwatch.apk", s.downloadAPK)
	mux.HandleFunc("GET /healthz", s.healthz)
	// expvar counters/gauges (drops, in-flight, refused) — gated by token auth
	// when web_token is set, like every non-exception route.
	mux.Handle("GET /metrics", expvar.Handler())
	// Prometheus text exposition for the same counters (scrape-friendly =
	// no JSON parsing on the collector side).
	mux.HandleFunc("GET /metrics/prometheus", s.prometheusMetrics)
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

	// OnRewriteChanged applies a saved/deleted DNS rewrite to the live map.
	OnRewriteChanged func(domain, ip string, deleted bool)
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
      <div class="chip" id="lblCacheStats" title="Доля доменов, отвеченных из локального кэша за всё время">💾 Кэш: <span id="valCacheRatio">0</span>%</div>
      <div class="chip" id="lblStatStats" title="Доля заблокированных запросов за 24 часа (по /api/stats)">🚫 Блок: <span id="valBlockPct">0</span>%</div>
      <div class="chip" id="lblAIStats" title="Нейтрализованные ИИ угрозы нулевого дня (DGA, фишинг, спуфинг)">🤖 AI-Щит: <span id="valAIBlocked">0</span> угроз</div>
    </div>
  </div>
  <div id="localDnsError" style="color:#ff8080;font-size:.82rem;margin-top:.4rem;display:none"></div>
  <div id="servicesCard" style="display:none;margin-top:.8rem">
    <div style="display:flex;align-items:center;gap:.5rem;flex-wrap:wrap">
      <span style="font-weight:600">🎯 Быстрая блокировка:</span>
      <span id="servicesList"></span>
    </div>
  </div>
  <div id="rewritesCard" style="display:none;margin-top:.8rem">
    <b>🧭 Локальные DNS-записи (rewrites)</b>
    <div style="display:flex;gap:.5rem;margin-top:.5rem;flex-wrap:wrap;align-items:center">
      <input type="text" class="chip" id="rwDomain" placeholder="домен, напр. nas.lan" style="min-width:14rem">
      <input type="text" class="chip" id="rwIp" placeholder="IP, напр. 192.168.1.10" style="min-width:12rem">
      <button class="chip link" id="btnAddRewrite" style="cursor:pointer">➕ Добавить</button>
      <span id="rwError" style="color:#ff8080;font-size:.82rem;display:none"></span>
    </div>
    <table id="rwTable" style="margin-top:.5rem"><tbody></tbody></table>
  </div>
</div>
  <div id="phonePairCard" style="display:none;margin-top:.8rem;padding:.8rem .95rem;border:1px dashed var(--line);border-radius:var(--radius);font-size:.85rem">
    <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap">
      <div style="flex:0 0 auto;text-align:center">
        <img id="phonePairQR" alt="QR-код для мгновенного сопряжения" width="136" height="136"
             style="display:block;width:136px;height:136px;background:#fff;padding:6px;border-radius:8px">
        <span class="mute" style="font-size:.7rem">наведите камеру телефона</span>
      </div>
      <div style="flex:1 1 17rem;min-width:15rem">
        <b>📱 Мгновенное сопряжение</b>
        <div style="margin-top:.35rem">Адрес панели: <span class="chip" id="phonePairAddr">http://...</span></div>
        <div style="margin-top:.6rem">
          <b>📱 Android:</b>
          <a class="chip link" href="/download/netwatch.apk" download style="margin-left:.35rem">📥 Скачать NetWatch.apk</a>
        </div>
        <div style="margin-top:.6rem">
          <b>🍏 Apple (iPhone / iPad / Mac):</b>
          <a class="chip link" id="btnAppleProfile" href="/netwatch.mobileconfig" download style="margin-left:.35rem">🍏 Установить профиль iOS (.mobileconfig)</a>
          <div class="mute" style="font-size:.72rem;margin-top:.3rem">Safari → «Разрешить» → Настройки → Профиль загружен → Установить. Весь DNS-трафик пойдёт через NetWatch без сторонних приложений.</div>
        </div>
      </div>
    </div>
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
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:.5rem">
      <div style="display:flex;align-items:center;gap:.5rem;min-width:0">
        <span style="font-size:1.6rem;line-height:1">{{.Profile.Icon}}</span>
        <div style="min-width:0">
          <a class="ip" href="/device?ip={{.IP}}" style="display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{{if .Hostname}}{{.Hostname}}{{else}}{{.IP}}{{end}}</a>
          {{if .Profile.Vendor}}<span class="badge dns">{{.Profile.Vendor}}</span>{{end}}
        </div>
      </div>
      <span class="chip" style="font-family:var(--mono)">{{.IP}}</span>
    </div>
    <div class="attrs">
      {{if .MAC}}<span class="chip">{{.MAC}}</span>{{end}}
      <span class="chip">{{.Profile.Type}}</span>
    </div>
    <div style="margin-top:.55rem;display:flex;justify-content:space-between;align-items:center;gap:.5rem;flex-wrap:wrap">
      <span style="font-weight:600;color:{{.Privacy.GradeColor}}">{{.GradeIcon}} Рейтинг: {{.Privacy.Grade}} ({{.Privacy.Score}}/100)</span>
      <span class="mute" style="font-size:.8rem">{{.Advice}}</span>
    </div>
    <div class="bar" style="margin-top:.4rem;height:7px"><span style="width:{{.Privacy.Score}}%;background:{{.Privacy.GradeColor}}"></span></div>
    <div class="seen" style="display:block;margin-top:.45rem">Запросов: <b>{{.Total}}</b> · Обезврежено: <b>{{.Blocked}}</b> ({{.BlockPct}}%)</div>
    {{if .Privacy.LeakCategories}}<div class="attrs" style="margin-top:.5rem">{{range .Privacy.LeakCategories}}<span class="chip" style="font-size:.75rem">{{.}}</span>{{end}}</div>{{end}}
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

// deviceCardView is the privacy X-Ray card model for /devices.
type deviceCardView struct {
	store.DeviceRow
	Profile   devices.DeviceProfile
	Privacy   devices.PrivacyScore
	GradeIcon string
	Advice    string
	Total     int64
	Blocked   int64
	BlockPct  int
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.st.ListDevices(r.Context())
	if err != nil {
		s.fail(w, "devices list", err)
		return
	}
	since := time.Now().Add(-24 * time.Hour).Unix()
	act, err := s.st.DeviceActivity(r.Context(), since)
	if err != nil {
		s.fail(w, "device activity", err)
		return
	}
	views := make([]deviceCardView, 0, len(ds))
	for _, d := range ds {
		a := act[d.IP]
		prof := devices.ProfileDevice(d.MAC, d.Hostname)
		priv := devices.CalculatePrivacyScore(a.Total, a.Blocked, a.TopDomains)
		pct := 0
		if a.Total > 0 {
			pct = int(a.Blocked * 100 / a.Total)
		}
		views = append(views, deviceCardView{
			DeviceRow: d,
			Profile:   prof,
			Privacy:   priv,
			GradeIcon: devices.GradeIcon(priv.Grade),
			Advice:    devices.GradeAdvice(priv.Grade),
			Total:     a.Total,
			Blocked:   a.Blocked,
			BlockPct:  pct,
		})
	}
	s.render(w, http.StatusOK, page(contentDevices), "/devices", struct {
		Devices []deviceCardView
	}{views})
}

// auditProfile is the JSON identity of one client in /api/devices/audit.
type auditProfile struct {
	Type   string `json:"type"`
	Icon   string `json:"icon"`
	Vendor string `json:"vendor"`
}

// auditPrivacy is the JSON privacy X-ray block in /api/devices/audit.
type auditPrivacy struct {
	Score          int      `json:"score"`
	Grade          string   `json:"grade"`
	GradeColor     string   `json:"grade_color"`
	LeakCategories []string `json:"leak_categories"`
	Total          int64    `json:"total"`
	Blocked        int64    `json:"blocked"`
	BlockPct       float64  `json:"block_pct"`
}

// auditDevice is one row of the /api/devices/audit response.
type auditDevice struct {
	IP       string       `json:"ip"`
	MAC      string       `json:"mac"`
	Hostname string       `json:"hostname"`
	LastSeen int64        `json:"last_seen"`
	Profile  auditProfile `json:"profile"`
	Privacy  auditPrivacy `json:"privacy"`
}

func (s *Server) apiDevicesAudit(w http.ResponseWriter, r *http.Request) {
	ds, err := s.st.ListDevices(r.Context())
	if err != nil {
		s.fail(w, "devices list", err)
		return
	}
	since := time.Now().Add(-24 * time.Hour).Unix()
	act, err := s.st.DeviceActivity(r.Context(), since)
	if err != nil {
		s.fail(w, "device activity", err)
		return
	}
	out := make([]auditDevice, 0, len(ds))
	for _, d := range ds {
		a := act[d.IP]
		prof := devices.ProfileDevice(d.MAC, d.Hostname)
		priv := devices.CalculatePrivacyScore(a.Total, a.Blocked, a.TopDomains)
		cats := priv.LeakCategories
		if cats == nil {
			cats = []string{}
		}
		pct := 0.0
		if a.Total > 0 {
			pct = float64(a.Blocked) * 100 / float64(a.Total)
		}
		out = append(out, auditDevice{
			IP:       d.IP,
			MAC:      d.MAC,
			Hostname: d.Hostname,
			LastSeen: d.LastSeen,
			Profile:  auditProfile{Type: string(prof.Type), Icon: prof.Icon, Vendor: prof.Vendor},
			Privacy: auditPrivacy{
				Score:          priv.Score,
				Grade:          priv.Grade,
				GradeColor:     priv.GradeColor,
				LeakCategories: cats,
				Total:          a.Total,
				Blocked:        a.Blocked,
				BlockPct:       pct,
			},
		})
	}
	_ = json.NewEncoder(w).Encode(out) //nolint:errcheck // client may vanish mid-write
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

// apiStats serves the 24h summary (PI-hole-style dashboard numbers):
// total/blocked queries, block percentage, cache ratio from expvar
// counters and the active device count.
func (s *Server) apiStats(w http.ResponseWriter, r *http.Request) {
	sum, err := s.st.Stats24h(r.Context())
	if err != nil {
		s.fail(w, "api stats", err)
		return
	}
	blockPct := 0.0
	if sum.Total > 0 {
		blockPct = float64(sum.Blocked) * 100 / float64(sum.Total)
	}
	hits := metrics.DNSCacheHitsTotal.Value()
	misses := metrics.DNSCacheMissesTotal.Value()
	cacheRatio := 0.0
	if hits+misses > 0 {
		cacheRatio = float64(hits) * 100 / float64(hits+misses)
	}
	out := struct {
		store.StatsSummary
		BlockPct      float64 `json:"block_pct"`
		CacheHits     int64   `json:"cache_hits"`
		CacheMisses   int64   `json:"cache_misses"`
		CacheHitRatio float64 `json:"cache_hit_ratio"`
		AIBlocked     int64   `json:"ai_blocked"`
	}{
		StatsSummary:  sum,
		BlockPct:      blockPct,
		CacheHits:     hits,
		CacheMisses:   misses,
		CacheHitRatio: cacheRatio,
		AIBlocked:     metrics.DNSAIBlockedTotal.Value(),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out) //nolint:errcheck // client may vanish mid-write
}

// prometheusMetric is one exposition row of /metrics/prometheus.
type prometheusMetric struct {
	name  string
	help  string
	typ   string // "counter" | "gauge"
	value int64
}

// prometheusMetrics renders expvar counters in the Prometheus text format
// (# HELP / # TYPE per metric) so standard collectors need no custom query.
func (s *Server) prometheusMetrics(w http.ResponseWriter, _ *http.Request) {
	list := []prometheusMetric{
		{"dns_cache_hits_total", "DNS queries answered from local cache.", "counter", metrics.DNSCacheHitsTotal.Value()},
		{"dns_cache_misses_total", "DNS queries forwarded to an upstream resolver.", "counter", metrics.DNSCacheMissesTotal.Value()},
		{"dns_blocked_total", "DNS queries answered with NXDOMAIN by a blocklist match.", "counter", metrics.DNSBlockedTotal.Value()},
		{"dns_ai_blocked_total", "Zero-day DNS threats (DGA/phishing) answered NXDOMAIN by the local AI engine.", "counter", metrics.DNSAIBlockedTotal.Value()},
		{"dns_refused_total", "DNS queries refused (admission control / open-resolver ACL).", "counter", metrics.DNSRefusedTotal.Value()},
		{"dns_inflight", "DNS queries currently pending an upstream answer.", "gauge", metrics.DNSInflight.Value()},
		{"dns_log_rows_rejected_total", "Serve-path DNS rows dropped because the writer queue was full.", "counter", metrics.LogRowsRejectedTotal.Value()},
		{"dns_blocklog_capped_total", "Block-log window entries dropped by the per-window key cap.", "counter", metrics.BlockAggrCapTotal.Value()},
		{"devices_sightings_dropped_total", "Device sightings dropped because the resolver queue was full.", "counter", metrics.DevicesDroppedTotal.Value()},
		{"sink_rows_dropped_total", "Accepted log rows irreversibly lost to repeated DB failures.", "counter", metrics.SinkRowsDroppedTotal.Value()},
	}
	var buf bytes.Buffer
	for _, m := range list {
		fmt.Fprintf(&buf, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", m.name, m.help, m.name, m.typ, m.name, m.value)
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
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
	if domain == "" || len(domain) > maxDomainLen || !domainPattern.MatchString(domain) {
		http.Error(w, "invalid domain or action", http.StatusBadRequest)
		return
	}
	if body.Action != store.RuleBlock && body.Action != store.RuleAllow {
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

// serviceStatus is one /api/services row: the catalog entry plus whether the
// service is currently blocked (any of its domains has a block rule).
type serviceStatus struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Main    string   `json:"main"`
	Domains []string `json:"domains"`
	Blocked bool     `json:"blocked"`
}

// apiServices returns the built-in 1-click catalog with live block status.
func (s *Server) apiServices(w http.ResponseWriter, r *http.Request) {
	rules, err := s.st.ListCustomRules(r.Context())
	if err != nil {
		s.fail(w, "api services", err)
		return
	}
	blockedDomains := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if rule.Action == store.RuleBlock {
			blockedDomains[rule.Domain] = true
		}
	}
	out := make([]serviceStatus, 0, len(filter.Services))
	for _, svc := range filter.Services {
		blocked := false
		for _, d := range svc.Domains {
			if blockedDomains[d] {
				blocked = true
				break
			}
		}
		out = append(out, serviceStatus{
			ID:      svc.ID,
			Name:    svc.Name,
			Main:    svc.Domains[0],
			Domains: svc.Domains,
			Blocked: blocked,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out) //nolint:errcheck // client may vanish mid-write
}

// apiServiceToggle applies or removes (at once) every block rule of one
// catalog service. Store rows are written first, then the live matcher is
// updated — a partial DB failure never leaves the matcher disagreeing with
// what was attempted to persist.
func (s *Server) apiServiceToggle(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Blocked bool   `json:"blocked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	svc, ok := filter.ServiceByID(strings.TrimSpace(body.ID))
	if !ok {
		http.Error(w, "unknown service id", http.StatusBadRequest)
		return
	}
	for _, domain := range svc.Domains {
		if body.Blocked {
			if err := s.st.SetCustomRule(r.Context(), domain, store.RuleBlock); err != nil {
				s.fail(w, "api service toggle", err)
				return
			}
			if s.OnRuleChanged != nil {
				s.OnRuleChanged(domain, store.RuleBlock, false)
			}
		} else {
			if err := s.st.DeleteCustomRule(r.Context(), domain); err != nil {
				s.fail(w, "api service toggle", err)
				return
			}
			if s.OnRuleChanged != nil {
				s.OnRuleChanged(domain, "", true)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// apiListRewrites returns all local DNS rewrites as JSON.
func (s *Server) apiListRewrites(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListRewrites(r.Context())
	if err != nil {
		s.fail(w, "api list rewrites", err)
		return
	}
	if list == nil {
		list = []store.DNSRewrite{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list) //nolint:errcheck // client may vanish mid-write
}

// apiSetRewrite stores a local DNS override (domain -> IP) and applies it to
// the live map.
func (s *Server) apiSetRewrite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	domain := normalizeUserDomain(body.Domain)
	ip := strings.TrimSpace(body.IP)
	if domain == "" || len(domain) > maxDomainLen || !domainPattern.MatchString(domain) || net.ParseIP(ip) == nil {
		http.Error(w, "invalid domain or ip", http.StatusBadRequest)
		return
	}
	if err := s.st.SetRewrite(r.Context(), domain, ip); err != nil {
		s.fail(w, "api set rewrite", err)
		return
	}
	if s.OnRewriteChanged != nil {
		s.OnRewriteChanged(domain, ip, false)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// apiDeleteRewrite removes a local DNS override and its live map entry.
func (s *Server) apiDeleteRewrite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Domain string `json:"domain"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Domain == "" {
		body.Domain = r.URL.Query().Get("domain")
	}
	domain := normalizeUserDomain(body.Domain)
	if domain == "" {
		http.Error(w, "missing domain", http.StatusBadRequest)
		return
	}
	if err := s.st.DeleteRewrite(r.Context(), domain); err != nil {
		s.fail(w, "api delete rewrite", err)
		return
	}
	if s.OnRewriteChanged != nil {
		s.OnRewriteChanged(domain, "", true)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// normalizeUserDomain lowercases, trims and drops a trailing dot so both the
// store and the live DNS map see one canonical spelling.
func normalizeUserDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
}

func (s *Server) apiEventsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Disable WriteTimeout for the long-lived SSE streaming response
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.broker.subscribe()
	defer s.broker.unsubscribe(ch)

	// Send initial comment to establish stream
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	// Periodic keepalive prevents NAT/firewall and browser silent timeouts
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprintf(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
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
	name := strings.TrimSpace(body.Name)
	if utf8.RuneCountInString(name) > maxDeviceNameLen {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	if err := s.st.SetDeviceHostname(r.Context(), body.IP, name); err != nil {
		s.fail(w, "set device hostname", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
