package report

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeTinyPNG creates a valid 8x8 PNG at <dir>/shot.png and returns its path.
func writeTinyPNG(t *testing.T, dir string) string {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 8; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8(x * 32),
				G: uint8(y * 32),
				B: 255,
				A: 255,
			})
		}
	}

	path := filepath.Join(dir, "shot.png")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create png: %v", err)
	}
	defer f.Close()

	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return path
}

// requireValidPDF asserts that path exists, is non-empty, and starts with
// the PDF magic bytes "%PDF-".
func requireValidPDF(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pdf %q: %v", path, err)
	}
	if len(data) == 0 {
		t.Fatalf("pdf %q is empty", path)
	}
	const magic = "%PDF-"
	if len(data) < len(magic) || string(data[:len(magic)]) != magic {
		head := data
		if len(head) > 8 {
			head = head[:8]
		}
		t.Fatalf("pdf %q magic = %q, want prefix %q", path, head, magic)
	}
}

func TestWritePDFHappyPath(t *testing.T) {
	dir := t.TempDir()
	shot := writeTinyPNG(t, dir)
	ts := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	results := []Result{
		{
			IP:           "192.0.2.1",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Open test box",
			ScreenWidth:  800,
			ScreenHeight: 600,
			Screenshot:   shot,
			DurationMs:   42,
			Timestamp:    ts,
		},
		{
			IP:           "192.0.2.2",
			Port:         5901,
			Open:         true,
			RFB:          true,
			Passwordless: false,
			ServerName:   "Auth required",
			ScreenWidth:  1024,
			ScreenHeight: 768,
			DurationMs:   17,
			Timestamp:    ts.Add(time.Second),
		},
		{
			IP:         "192.0.2.3",
			Port:       5902,
			Open:       false,
			Error:      "connection refused",
			DurationMs: 5,
			Timestamp:  ts.Add(2 * time.Second),
		},
	}

	path := filepath.Join(dir, "out.pdf")
	if err := WritePDF(path, results); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}
	requireValidPDF(t, path)
}

func TestWritePDFEmptyResults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pdf")
	if err := WritePDF(path, nil); err != nil {
		t.Fatalf("WritePDF(nil): %v", err)
	}
	requireValidPDF(t, path)

	// Explicit empty slice must behave the same as nil.
	pathEmpty := filepath.Join(t.TempDir(), "out-empty.pdf")
	if err := WritePDF(pathEmpty, []Result{}); err != nil {
		t.Fatalf("WritePDF(empty): %v", err)
	}
	requireValidPDF(t, pathEmpty)
}

func TestWritePDFScreenshotMissingOrCorrupt(t *testing.T) {
	dir := t.TempDir()

	corruptPath := filepath.Join(dir, "corrupt.png")
	if err := os.WriteFile(corruptPath, []byte("this is not a png"), 0o644); err != nil {
		t.Fatalf("write corrupt png: %v", err)
	}
	missingPath := filepath.Join(dir, "missing.png")

	ts := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	results := []Result{
		{
			IP:           "192.0.2.10",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Missing shot",
			Screenshot:   missingPath,
			Timestamp:    ts,
		},
		{
			IP:           "192.0.2.11",
			Port:         5901,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Corrupt shot",
			Screenshot:   corruptPath,
			Timestamp:    ts,
		},
	}

	// A missing or undecodable screenshot must not fail the whole report.
	path := filepath.Join(dir, "out.pdf")
	if err := WritePDF(path, results); err != nil {
		t.Fatalf("WritePDF with bad screenshots: %v", err)
	}
	requireValidPDF(t, path)
}

func TestWritePDFUnicodeAndSpecialChars(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	results := []Result{
		{
			IP:           "192.0.2.20",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Sunucu-öçşiğüİÖÇŞĞÜ",
			ScreenWidth:  1280,
			ScreenHeight: 1024,
			Timestamp:    ts,
		},
		{
			IP:           "192.0.2.21",
			Port:         5901,
			Open:         true,
			RFB:          true,
			Passwordless: false,
			ServerName:   "<script>alert(1)</script>",
			Timestamp:    ts.Add(time.Second),
		},
	}

	path := filepath.Join(dir, "out.pdf")
	if err := WritePDF(path, results); err != nil {
		t.Fatalf("WritePDF with unicode/special server names: %v", err)
	}
	requireValidPDF(t, path)
}

func TestWritePDFUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "out.pdf")
	err := WritePDF(path, []Result{{IP: "192.0.2.1", Port: 5900, Open: true}})
	if err == nil {
		t.Fatal("WritePDF to missing directory: want error, got nil")
	}
}
