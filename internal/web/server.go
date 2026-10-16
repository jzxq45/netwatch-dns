// Package web serves the monitoring UI: live feed, devices, top domains and
// a small JSON API. stdlib only, server-rendered with html/template.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
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

var funcMap = template.FuncMap{
	"tsfmt": func(ts int64) string { return time.Unix(ts, 0).Format("15:04:05") },
}

const pageHead = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>monitor</title>
<meta http-equiv="refresh" content="5">
<style>body{font-family:sans-serif;margin:1rem}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:2px 8px;text-align:left}nav a{margin-right:1rem}.mute{color:#888;font-size:.85em}</style>
</head><body>
<nav><a href="/">live</a><a href="/devices">devices</a><a href="/top">top</a></nav><hr>
`

const pageTail = `</body></html>`

const contentFeed = `
<h2>live feed (last {{len .Events}})</h2>
<table><tr><th>time</th><th>kind</th><th>device</th><th>domain</th></tr>
{{range .Events}}<tr><td>{{tsfmt .TS}}</td><td>{{.Kind}}</td><td><a href="/device?ip={{.ClientIP}}">{{.ClientIP}}</a></td><td>{{.Name}}</td></tr>{{end}}
</table>`

const contentDevices = `
<h2>devices</h2>
<table><tr><th>ip</th><th>mac</th><th>hostname</th><th>last seen</th></tr>
{{range .Devices}}<tr><td><a href="/device?ip={{.IP}}">{{.IP}}</a></td><td>{{.MAC}}</td><td>{{.Hostname}}</td><td>{{tsfmt .LastSeen}}</td></tr>{{end}}
</table>`

const contentDevice = `
<h2>device {{.Dev.IP}}</h2>
<p>mac: {{.Dev.MAC}} · hostname: {{.Dev.Hostname}} · last seen: {{tsfmt .Dev.LastSeen}}</p>
<h3>history (last {{len .Events}})</h3>
<table><tr><th>time</th><th>kind</th><th>query</th></tr>
{{range .Events}}<tr><td>{{tsfmt .TS}}</td><td>{{.Kind}}</td><td>{{.Name}}</td></tr>{{end}}
</table>`

const contentTop = `
<h2>top domains per device ({{.Period}})</h2>
<table><tr><th>device</th><th>hostname</th><th>domain</th><th>count</th></tr>
{{range .Rows}}<tr><td>{{.DeviceIP}}</td><td>{{.Hostname}}</td><td>{{.Domain}}</td><td>{{.Count}}</td></tr>{{end}}
</table>`

func page(content string) *template.Template {
	return template.Must(template.New("p").Funcs(funcMap).Parse(pageHead + content + pageTail))
}

func render(w http.ResponseWriter, status int, t *template.Template, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := t.Execute(w, data); err != nil {
		slog.Error("web render", "err", err)
	}
}

func (s *Server) feed(w http.ResponseWriter, r *http.Request) {
	events, err := s.st.RecentEvents(r.Context(), feedLimit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, page(contentFeed), struct {
		Events []store.Event
	}{events})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	ds, err := s.st.ListDevices(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	render(w, http.StatusOK, page(contentDevices), struct {
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
	render(w, http.StatusOK, page(contentDevice), struct {
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
	render(w, http.StatusOK, page(contentTop), struct {
		Rows   []store.TopRow
		Period string
	}{rows, period})
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
