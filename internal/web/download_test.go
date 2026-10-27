package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadAPK_NotFound(t *testing.T) {

	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	s := New(nil, nil)
	rec := httptest.NewRecorder()
	s.downloadAPK(rec, httptest.NewRequest(http.MethodGet, "/download/netwatch.apk", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d, body %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if body := rec.Body.String(); body != "APK not found\n" {
		t.Fatalf("body = %q", body)
	}
}

func TestDownloadAPK_ServesFile(t *testing.T) {

	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	payload := []byte{0x50, 0x4b, 0x03, 0x04, 0x00, 0xff}
	if err := os.WriteFile("netwatch.apk", payload, 0o644); err != nil {
		t.Fatalf("write apk: %v", err)
	}

	s := New(nil, nil)
	rec := httptest.NewRecorder()
	s.downloadAPK(rec, httptest.NewRequest(http.MethodGet, "/download/netwatch.apk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.android.package-archive" {
		t.Fatalf("content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="netwatch.apk"` {
		t.Fatalf("content-disposition = %q", cd)
	}
	if rec.Body.Bytes() == nil || len(rec.Body.Bytes()) != len(payload) {
		t.Fatalf("body len = %d, want %d", rec.Body.Len(), len(payload))
	}
}

func TestDownloadAPK_FallbackPaths(t *testing.T) {

	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(cwd) })

	// Only the debug build exists — handler must fall through to it.
	debugPath := filepath.Join("android", "app", "build", "outputs", "apk", "debug")
	if err := os.MkdirAll(debugPath, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(debugPath, "app-debug.apk"), []byte("debug"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	s := New(nil, nil)
	rec := httptest.NewRecorder()
	s.downloadAPK(rec, httptest.NewRequest(http.MethodGet, "/download/netwatch.apk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "debug" {
		t.Fatalf("body = %q", rec.Body.String())
	}
}
