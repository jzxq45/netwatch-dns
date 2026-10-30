package web

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// parseSVG validates the SVG as XML and returns the number of <rect> nodes.
func parseSVG(t *testing.T, svg string) int {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(svg))
	rects := 0
	root := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid SVG XML: %v\n%s", err, svg)
		}
		if se, ok := tok.(xml.StartElement); ok {
			switch se.Name.Local {
			case "svg":
				root = true
			case "rect":
				rects++
			}
		}
	}
	if !root {
		t.Fatal("SVG has no <svg> root")
	}
	return rects
}

func TestQRSVGValid(t *testing.T) {
	t.Parallel()
	const text = "http://192.168.1.15:8080/?token=abc"
	svg, err := qrSVG(text)
	if err != nil {
		t.Fatalf("qrSVG: %v", err)
	}
	if !strings.HasPrefix(svg, `<svg `) || !strings.HasSuffix(svg, `</svg>`) {
		t.Fatalf("unexpected SVG envelope: %.80s", svg)
	}
	if !strings.Contains(svg, `viewBox="0 0 `) {
		t.Error("SVG missing viewBox")
	}
	if rects := parseSVG(t, svg); rects < 2 {
		t.Errorf("rect nodes = %d, want background + modules", rects)
	}
	if again, _ := qrSVG(text); again != svg {
		t.Error("QR output is not deterministic")
	}
	if other, _ := qrSVG(text + "x"); other == svg {
		t.Error("different text produced identical SVG")
	}
}

func TestQRVersionSelection(t *testing.T) {
	t.Parallel()
	tests := []struct {
		n       int
		version int
	}{
		{10, 1},
		{14, 1},
		{15, 2},
		{30, 3},
		{60, 4},
		{100, 6},
		{150, 8},
		{qrMaxBytesM, 10},
	}
	for _, tt := range tests {
		q, err := encodeQR(strings.Repeat("a", tt.n))
		if err != nil {
			t.Fatalf("encode %d bytes: %v", tt.n, err)
		}
		if q.version != tt.version {
			t.Errorf("%d bytes → version %d, want %d", tt.n, q.version, tt.version)
		}
		if want := 17 + 4*tt.version; q.size != want {
			t.Errorf("size = %d, want %d", q.size, want)
		}
	}
	if _, err := encodeQR(strings.Repeat("a", qrMaxBytesM+1)); err == nil {
		t.Fatal("expected error for oversized text")
	}
}

func TestQRMatrixStructure(t *testing.T) {
	t.Parallel()
	q, err := encodeQR("HELLO")
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if q.size != 21 {
		t.Fatalf("size = %d, want 21 for version 1", q.size)
	}
	// Top-left finder: dark ring, light inner ring, dark 3x3 centre.
	checks := []struct {
		row, col int
		dark     bool
		name     string
	}{
		{0, 0, true, "finder outer corner"},
		{1, 1, false, "finder white ring"},
		{2, 2, true, "finder dark ring"},
		{3, 3, true, "finder centre"},
		{7, 7, false, "finder separator"},
		{q.size - 8, 8, true, "dark module"},
		{6, 8, true, "timing dark"},
		{6, 9, false, "timing light"},
	}
	for _, c := range checks {
		if got := q.modules[c.row][c.col]; got != c.dark {
			t.Errorf("%s at (%d,%d) = %v, want %v", c.name, c.row, c.col, got, c.dark)
		}
	}
	if !q.isFunc[q.size-8][8] {
		t.Error("dark module must be a function module")
	}
}

func TestAPIQR(t *testing.T) {
	t.Parallel()
	srv := New(seedStore(t), nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/qr?text="+"http%3A%2F%2F192.168.1.15%3A8080%2F", nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/svg+xml; charset=utf-8" {
		t.Fatalf("content-type = %q", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "<svg") || !strings.Contains(body, "</svg>") {
		t.Fatalf("body is not SVG: %.80s", body)
	}

	// No ?text: falls back to the request base URL.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://192.168.1.15:8080/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("default status = %d, want 200", rec.Code)
	}

	// Oversized payload: clean 400 instead of a broken image.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/qr?text="+strings.Repeat("a", qrMaxBytesM+10), nil)
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized status = %d, want 400", rec.Code)
	}
}
