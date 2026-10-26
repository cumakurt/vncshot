package screenshot

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testTS = time.Date(2026, 10, 26, 15, 4, 5, 0, time.UTC)

func newTestImage(w, h int) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 32, A: 255})
		}
	}
	return img
}

func TestSaveWritesNamedPNG(t *testing.T) {
	dir := t.TempDir()
	img := newTestImage(8, 8)

	path, err := Save(img, dir, "192.0.2.10", 5900, testTS)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	wantName := "192.0.2.10_5900_20261026-150405.png"
	if got := filepath.Base(path); got != wantName {
		t.Errorf("file name = %q, want %q", got, wantName)
	}
	if got := filepath.Dir(path); got != dir {
		t.Errorf("file dir = %q, want %q", got, dir)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open saved png: %v", err)
	}
	defer f.Close()

	decoded, err := png.Decode(f)
	if err != nil {
		t.Fatalf("decode saved png: %v", err)
	}
	b := decoded.Bounds()
	if b.Dx() != 8 || b.Dy() != 8 {
		t.Errorf("decoded size = %dx%d, want 8x8", b.Dx(), b.Dy())
	}
}

func TestSaveSanitizesIPv6(t *testing.T) {
	dir := t.TempDir()
	img := newTestImage(4, 4)

	path, err := Save(img, dir, "2001:db8::1", 5900, testTS)
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	name := filepath.Base(path)
	if strings.Contains(name, ":") {
		t.Errorf("file name %q contains ':' (filesystem-unsafe)", name)
	}
	wantName := "2001_db8__1_5900_20261026-150405.png"
	if name != wantName {
		t.Errorf("file name = %q, want %q", name, wantName)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing: %v", err)
	}
}

func TestSaveNilImage(t *testing.T) {
	path, err := Save(nil, t.TempDir(), "192.0.2.1", 5900, testTS)
	if err == nil {
		t.Fatal("Save(nil image): want error, got nil")
	}
	if path != "" {
		t.Errorf("Save(nil image) path = %q, want empty", path)
	}
}

func TestSaveCreatesMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "shots")
	img := newTestImage(4, 4)

	path, err := Save(img, dir, "192.0.2.1", 5900, testTS)
	if err != nil {
		t.Fatalf("Save with missing dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("saved file missing after mkdir: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("directory not created: %v", err)
	}
}
