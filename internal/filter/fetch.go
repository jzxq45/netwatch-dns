package filter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const maxFetchSize = 20 << 20 // 20 MiB

// FetchURL downloads a blocklist, caches the raw bytes on disk and returns the
// parsed domains. When the network or HTTP request fails, an existing cache
// file is used as an offline fallback. The cache file name is the SHA256 of
// rawURL, placed inside cacheDir.
func FetchURL(ctx context.Context, rawURL string, cacheDir string, client *http.Client) ([]string, error) {
	if client == nil {
		client = http.DefaultClient
	}
	cachePath := ""
	if cacheDir != "" {
		sum := sha256.Sum256([]byte(rawURL))
		cachePath = filepath.Join(cacheDir, hex.EncodeToString(sum[:]))
	}

	data, fetchErr := fetchBytes(ctx, rawURL, client)
	if fetchErr == nil {
		if cachePath != "" {
			_ = writeCache(cachePath, data) // download still usable if caching fails
		}
		return parseBytes(data)
	}

	if cachePath != "" {
		cached, err := os.ReadFile(cachePath)
		if err == nil {
			return parseBytes(cached)
		}
	}
	return nil, fetchErr
}

func fetchBytes(ctx context.Context, rawURL string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("blocklist request %s: %w", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("blocklist fetch %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("blocklist fetch %s: status %d", rawURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchSize+1))
	if err != nil {
		return nil, fmt.Errorf("blocklist read %s: %w", rawURL, err)
	}
	if len(data) > maxFetchSize {
		return nil, fmt.Errorf("blocklist %s: exceeds %d bytes", rawURL, maxFetchSize)
	}
	return data, nil
}

func parseBytes(data []byte) ([]string, error) {
	domains, err := Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("blocklist parse: %w", err)
	}
	return domains, nil
}

// writeCache persists data atomically (temp file + rename) so a crash never
// leaves a truncated blocklist behind.
func writeCache(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".blocklist-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
