//go:build windows

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	webview2 "github.com/jchv/go-webview2"

	"monitor/internal/app"
	"monitor/internal/config"
)

// netwatch.exe: the same monitor server, wrapped in a desktop window.
// Closing the window performs the graceful shutdown (DNS stops, sink flushes,
// DB closes) — there is no hidden background process left behind.
func main() {
	os.Exit(run())
}

func run() int {
	cfgPath := flag.String("config", "monitor.yaml", "path to config file")
	flag.Parse()

	logFile := openLogFile()
	slog.SetDefault(slog.New(slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		alert("netwatch-dns", "Config error:\n"+err.Error())
		return 1
	}
	webURL, err := localWebURL(cfg.WebListen)
	if err != nil {
		alert("netwatch-dns", "Bad web_listen: "+err.Error())
		return 1
	}
	if cfg.WebToken != "" {
		// First navigation mints the auth_token cookie ( Secure on TLS only);
		// meta-refresh and links keep working without typing the token again.
		webURL += "?token=" + url.QueryEscape(cfg.WebToken)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	appErr := make(chan error, 1)
	go func() { appErr <- app.Run(ctx, cfg) }()

	if err := waitWebUp(webURL, 5*time.Second, appErr); err != nil {
		alert("netwatch-dns", "Server failed to start:\n"+err.Error())
		return 1
	}

	// Desktop window. When it is closed → Run returns → ctx stops → every
	// component (DNS, sink flush, web, retention) shuts down before this
	// function returns.
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     false,
		DataPath:  filepath.Join(exeDir(), ".webview2"),
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "netwatch-dns — DNS monitor",
			Width:  1100,
			Height: 760,
			Center: true,
		},
	})
	if w == nil {
		// WebView2 runtime missing (rare on Win11, common trigger on old Win10).
		fallbackBrowser(webURL)
		alert("netwatch-dns",
			"WebView2 runtime not found — the interface opened in your browser instead.\n\n"+
				"Install it from https://aka.ms/webview2 to get the desktop window.\n"+
				"Servers keep running; Ctrl+C in a console session (or kill netwatch.exe) stops everything.")
		select {
		case err := <-appErr:
			if err != nil {
				alert("netwatch-dns", "Server error: "+err.Error())
				return 1
			}
		case <-ctx.Done():
			<-appErr
		}
		return 0
	}
	defer w.Destroy()
	w.Navigate(webURL)
	// Fatal app error (e.g. port grabbed between the health check and now)
	// must not leave a dead window on screen: terminate it immediately.
	go func() {
		select {
		case <-appErr:
			w.Terminate()
		case <-ctx.Done():
		}
	}()
	w.Run()

	// Window closed → graceful stop of the whole stack.
	stop()
	select {
	case err := <-appErr:
		if err != nil {
			alert("netwatch-dns", "Server stopped with error:\n"+err.Error())
			return 1
		}
	case <-time.After(10 * time.Second):
		alert("netwatch-dns", "Timeout: server did not stop in 10s (see netwatch.log).")
		return 1
	}
	return 0
}

// waitWebUp polls /healthz so the window never shows a blank page on a
// half-bound port; a fatal app error (e.g. DNS bind failure) fails fast.
func waitWebUp(webURL string, d time.Duration, appErr <-chan error) error {
	addr := strings.TrimSuffix(webURL, "/") + "/healthz"
	hc := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(d)
	for {
		resp, err := hc.Get(addr)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case err := <-appErr:
			return err
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("web UI on %s did not respond within %s", webURL, d)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// localWebURL maps the configured listener to the URL the local user opens.
// A wildcard ("0.0.0.0"/"::") listener must be reached as 127.0.0.1 here.
func localWebURL(webListen string) (string, error) {
	host, port, err := net.SplitHostPort(webListen)
	if err != nil {
		return "", fmt.Errorf("%q: %w", webListen, err)
	}
	if host == "0.0.0.0" || host == "::" || host == "" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port), nil
}

// fallbackBrowser opens the system default browser at the UI URL.
func fallbackBrowser(webURL string) {
	exec.Command("cmd", "/C", "start", "", webURL).Start() //nolint:errcheck // best effort
}

// exeDir returns the directory holding netwatch.exe — the default home for
// the log file and the WebView2 profile.
func exeDir() string {
	exe, err := os.Executable()
	if err == nil {
		if dir := filepath.Dir(exe); dir != "" {
			return dir
		}
	}
	dir, err := os.Getwd() // likely unwritable fallback if it ever happens
	if err != nil {
		return os.TempDir()
	}
	return dir
}

// openLogFile picks the first writable location: next to the exe (home style
// install), then the working dir, then %TEMP%. The console window is hidden
// (windowsgui), so the file is the only diagnostic surface.
func openLogFile() *os.File {
	locations := []string{
		filepath.Join(exeDir(), "netwatch.log"),
		"netwatch.log",
		filepath.Join(os.TempDir(), "netwatch.log"),
	}
	for _, path := range locations {
		// Truncate per run: a GUI binary has no log rotation, an append-only
		// file would grow forever. The tradeoff is "logs of the last run".
		f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err == nil {
			return f
		}
	}
	return os.Stdout // last resort
}

// alert shows a native MessageBox — the only reliable UI for fatal errors
// when there is no console and possibly no window.
func alert(title, msg string) {
	user32 := syscall.NewLazyDLL("user32.dll")
	mb := user32.NewProc("MessageBoxW")
	tp, _ := syscall.UTF16PtrFromString(title)
	mp, _ := syscall.UTF16PtrFromString(msg)
	//nolint:dogsled // winapi calling convention
	mb.Call(0, uintptr(unsafe.Pointer(mp)), uintptr(unsafe.Pointer(tp)), 0x10) // MB_ICONERROR
}
