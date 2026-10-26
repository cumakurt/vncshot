package report

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestPNG writes a solid-ish w x h PNG to path, creating parent dirs.
func writeTestPNG(t *testing.T, path string, w, h int) {
	t.Helper()

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 17), G: uint8(y * 17), B: 64, A: 255})
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for test png: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create test png: %v", err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode test png: %v", err)
	}
}

func readHTML(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read html report: %v", err)
	}
	return string(raw)
}

func mustContain(t *testing.T, html, substr, why string) {
	t.Helper()
	if !strings.Contains(html, substr) {
		t.Errorf("html report missing %s; want substring %q", why, substr)
	}
}

func mustNotContain(t *testing.T, html, substr, why string) {
	t.Helper()
	if strings.Contains(html, substr) {
		t.Errorf("html report unexpectedly contains %s; substring %q", why, substr)
	}
}

func TestWriteHTMLSummaryNumbers(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.1", Port: 5900, Open: true, RFB: true, Passwordless: true, Screenshot: "a.png"},
		{IP: "192.0.2.2", Port: 5900, Open: true, RFB: true},
		{IP: "192.0.2.3", Port: 5901, Error: "dial timeout"},
		{IP: "192.0.2.4", Port: 5902, Open: true, Screenshot: "b.png", Error: "partial read"},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	wantStats := map[string]string{
		"Targets":      "4",
		"Open ports":   "3",
		"RFB services": "2",
		"Passwordless": "1",
		"Screenshots":  "2",
		"Errors":       "2",
	}
	for label, value := range wantStats {
		mustContain(t, html,
			fmt.Sprintf(`<div class="label">%s</div><div class="value">%s</div>`, label, value),
			fmt.Sprintf("summary stat %s", label))
	}
}

func TestWriteHTMLEmbedsPasswordlessScreenshot(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	ts := time.Date(2026, 10, 26, 15, 4, 5, 0, time.UTC)
	results := []Result{
		{
			IP:           "192.0.2.10",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Living room",
			ScreenWidth:  8,
			ScreenHeight: 8,
			Screenshot:   pngPath,
			Timestamp:    ts,
		},
	}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "data:image/png;base64,", "embedded screenshot data URI")
	mustContain(t, html, `class="card"`, "passwordless finding card")
	mustContain(t, html, "192.0.2.10:5900", "card address")
	mustContain(t, html, "no authentication", "passwordless badge")
}

func TestWriteHTMLMarkup(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	results := []Result{
		{
			IP:           "192.0.2.10",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			Screenshot:   pngPath,
		},
	}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, `id="filter"`, "filter input")
	mustContain(t, html, `id="modal"`, "modal container")
	mustContain(t, html, `data-filter="passwordless"`, "passwordless filter chip")
	mustContain(t, html, `data-search=`, "search index attribute")
}

func TestWriteHTMLMissingScreenshotStillRendersCard(t *testing.T) {
	results := []Result{
		{
			IP:           "192.0.2.50",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			Screenshot:   filepath.Join(t.TempDir(), "missing.png"),
		},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, `class="card"`, "card for missing capture")
	mustContain(t, html, "192.0.2.50:5900", "card address")
	mustContain(t, html, "no authentication", "passwordless badge")
	mustNotContain(t, html, "data:image/png;base64,", "base64 image when capture is missing")
}

func TestWriteHTMLClosedPortsOmittedFromTable(t *testing.T) {
	results := []Result{
		{IP: "203.0.113.10", Port: 5900, Open: true, RFB: true},
		{IP: "203.0.113.99", Port: 5901, Open: false},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	if rows := strings.Count(html, "<tr data-search="); rows != 1 {
		t.Errorf("open-endpoints table row count = %d, want 1 (only open ports)", rows)
	}

	tbodyStart := strings.Index(html, "<tbody>")
	tbodyEnd := strings.Index(html, "</tbody>")
	if tbodyStart < 0 || tbodyEnd < 0 || tbodyEnd < tbodyStart {
		t.Fatalf("html report has no well-formed <tbody> section")
	}
	tbody := html[tbodyStart:tbodyEnd]
	if strings.Contains(tbody, "203.0.113.99") {
		t.Errorf("closed port IP appears in open-endpoints table body:\n%s", tbody)
	}
	mustContain(t, tbody, "203.0.113.10", "open port IP in table body")
}

func TestWriteHTMLEscapesServerName(t *testing.T) {
	payload := "<script>alert(1)</script>"
	results := []Result{
		{
			IP:         "192.0.2.60",
			Port:       5900,
			Open:       true,
			RFB:        true,
			ServerName: payload,
		},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "&lt;script&gt;alert(1)&lt;/script&gt;", "escaped server name")
	mustNotContain(t, html, payload, "raw script payload")
}

func TestResizeNearestCapsWidth(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 640, 480))
	got := resizeNearest(src, thumbMaxWidth)

	b := got.Bounds()
	if b.Dx() != thumbMaxWidth {
		t.Errorf("resized width = %d, want %d", b.Dx(), thumbMaxWidth)
	}
	if b.Dy() != 240 {
		t.Errorf("resized height = %d, want 240", b.Dy())
	}
}

func TestResizeNearestKeepsSmallImages(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 100, 50))
	got := resizeNearest(src, thumbMaxWidth)

	b := got.Bounds()
	if b.Dx() != 100 || b.Dy() != 50 {
		t.Errorf("resized bounds = %v, want 100x50 unchanged", b)
	}
}

func TestResizeNearestMinimumHeight(t *testing.T) {
	src := image.NewRGBA(image.Rect(0, 0, 640, 1))
	got := resizeNearest(src, thumbMaxWidth)

	b := got.Bounds()
	if b.Dx() != thumbMaxWidth {
		t.Errorf("resized width = %d, want %d", b.Dx(), thumbMaxWidth)
	}
	if b.Dy() != 1 {
		t.Errorf("resized height = %d, want at least 1", b.Dy())
	}
}
