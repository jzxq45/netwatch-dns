// Package web serves the monitoring UI: live feed, devices, top domains and
// a small JSON API. stdlib only, server-rendered with html/template.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
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
	s := &Server{st: st, log: log, mux: mux}
	mux.HandleFunc("GET /{$}", s.feed)
	mux.HandleFunc("GET /devices", s.devices)
	mux.HandleFunc("GET /device", s.deviceLog)
	mux.HandleFunc("GET /top", s.top)
	mux.HandleFunc("GET /static/", s.static)
	mux.HandleFunc("GET /api/events", s.apiEvents)
	mux.HandleFunc("GET /healthz", s.healthz)
	return s
}

type Server struct {
	st  Store
	log *slog.Logger
	mux *http.ServeMux
}

// Handler exposes the router for tests.
func (s *Server) Handler() http.Handler { return s.mux }

// Start serves until ctx is done; returns after listeners closed.
func (s *Server) Start(ctx context.Context, addr string) error {
	httpSrv := &http.Server{Addr: addr, Handler: s.mux, ReadHeaderTimeout: 5 * time.Second}
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

// render executes a parsed page. Path feeds the top-bar nav highlighting.
func render(w http.ResponseWriter, status int, t *template.Template, path string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	inner := struct {
		Path string
		Data any
	}{path, data}
	if err := t.Execute(w, inner); err != nil {
		slog.Error("web render", "err", err)
	}
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Hidden-noise counter: noise rows at or after the oldest shown row.
	hidden := 0
	if len(events) > 0 {
		if hidden, err = s.st.NoisyEventsSince(r.Context(), events[len(events)-1].TS); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if showAll {
			hidden = 0
		}
	}
	render(w, http.StatusOK, page(contentFeed), "/", struct {
		Events  []store.Event
		ShowAll bool
		Hidden  int
	}{events, showAll, hidden})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.st.ListDevices(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, page(contentDevices), "/devices", struct {
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if dev == nil {
		// Unknown device (row appears after first query) — still show history.
		dev = &store.DeviceRow{IP: ip}
	}
	events, err := s.st.DeviceEvents(r.Context(), ip, feedLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, page(contentDevice), "/device", struct {
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	max := 0
	for _, row := range rows {
		if row.Count > max {
			max = row.Count
		}
	}
	render(w, http.StatusOK, page(contentTop), "/top", struct {
		Rows   []store.TopRow
		Period string
		Max    int
	}{rows, period, max})
}

// static serves the embedded css/js without a filesystem dependency.
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		http.Error(w, "static fs: "+err.Error(), http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(events); err != nil { //nolint:errcheck // client may vanish mid-write
		s.log.Debug("api events write", "err", err)
	}
}
