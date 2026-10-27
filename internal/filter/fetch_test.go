package filter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestFetchURLAndCacheFallback(t *testing.T) {
	t.Parallel()
	const body = "0.0.0.0 ad.evil.test\n||tracker.evil.test^\n"
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fail.Load() {
			http.Error(w, "upstream down", http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprint(w, body)
	}))
	defer srv.Close()

	dir := t.TempDir()
	want := []string{"ad.evil.test", "tracker.evil.test"}

	got, err := FetchURL(context.Background(), srv.URL, dir, srv.Client())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	assertDomains(t, got, want)

	sum := sha256.Sum256([]byte(srv.URL))
	cachePath := filepath.Join(dir, hex.EncodeToString(sum[:]))
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache file missing: %v", err)
	}

	// HTTP failure must fall back to the cached copy.
	fail.Store(true)
	got, err = FetchURL(context.Background(), srv.URL, dir, srv.Client())
	if err != nil {
		t.Fatalf("offline fallback: %v", err)
	}
	assertDomains(t, got, want)

	// No cache + failure is still an error.
	if _, err := FetchURL(context.Background(), srv.URL, t.TempDir(), srv.Client()); err == nil {
		t.Fatal("expected error without cache")
	}
}
