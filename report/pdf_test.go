package report

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

func TestSanitizePDFTextKeepsTurkish(t *testing.T) {
	const turkish = "İŞĞÜÖÇışğüöç"
	if got := sanitizePDFText(turkish); got != turkish {
		t.Fatalf("sanitizePDFText(%q) = %q, want unchanged", turkish, got)
	}

	got := sanitizePDFText("satır\nsonu\tve\rbaşlık\x01")
	want := "satır sonu ve başlık"
	if got != want {
		t.Fatalf("sanitizePDFText control chars = %q, want %q", got, want)
	}
}

func TestWritePDFRendersTurkishGlyphs(t *testing.T) {
	dir := t.TempDir()
	shot := writeTinyPNG(t, dir)
	ts := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	results := []Result{
		{
			IP:           "192.0.2.30",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Muhasebe Sunucusu — İstanbul Şube",
			ScreenWidth:  1280,
			ScreenHeight: 720,
			Screenshot:   shot,
			DurationMs:   23,
			Timestamp:    ts,
		},
	}

	path := filepath.Join(dir, "turkish.pdf")
	if err := WritePDF(path, results); err != nil {
		t.Fatalf("WritePDF with Turkish text: %v", err)
	}
	requireValidPDF(t, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pdf: %v", err)
	}
	// The embedded font subset alone exceeds this; an empty or truncated
	// document would fall below it.
	if info.Size() < 4096 {
		t.Fatalf("pdf size = %d bytes, want at least 4096", info.Size())
	}

	if !strings.Contains(legalNoticeTR, "YETKİLİ") || !strings.Contains(legalNoticeTR, "sorumluluk") {
		t.Fatalf("Turkish legal notice is missing required text: %q", legalNoticeTR)
	}
}

func TestWritePDFUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "out.pdf")
	err := WritePDF(path, []Result{{IP: "192.0.2.1", Port: 5900, Open: true}})
	if err == nil {
		t.Fatal("WritePDF to missing directory: want error, got nil")
	}
}

func TestWritePDFShowsWeakPassword(t *testing.T) {
	dir := t.TempDir()
	shot := writeTinyPNG(t, dir)
	ts := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	results := []Result{
		{
			IP:           "192.0.2.40",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Open test box",
			ScreenWidth:  800,
			ScreenHeight: 600,
			Screenshot:   shot,
			DurationMs:   12,
			Timestamp:    ts,
		},
		{
			IP:             "192.0.2.41",
			Port:           5901,
			Open:           true,
			RFB:            true,
			Password:       "hunter2",
			PasswordSource: "default",
			ServerName:     "Weak auth box",
			ScreenWidth:    1024,
			ScreenHeight:   768,
			Screenshot:     shot,
			DurationMs:     34,
			Timestamp:      ts.Add(time.Second),
		},
	}

	path := filepath.Join(dir, "weak.pdf")
	if err := WritePDF(path, results); err != nil {
		t.Fatalf("WritePDF with weak credentials: %v", err)
	}
	requireValidPDF(t, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pdf: %v", err)
	}
	if info.Size() < 4096 {
		t.Fatalf("pdf size = %d bytes, want at least 4096", info.Size())
	}

	// The PDF embeds a subset font and hexadecimal glyph runs, so the raw
	// bytes are not a reliable place to look for text. The strings the
	// renderer prints are asserted through the pure helpers instead.
	password, source := credentialParts(results[1])
	if password != "hunter2" || source != "(default list)" {
		t.Fatalf("credentialParts(weak) = %q, %q, want %q, %q", password, source, "hunter2", "(default list)")
	}
	if password, source := credentialParts(results[0]); password != "" || source != "" {
		t.Fatalf("credentialParts(passwordless) = %q, %q, want empty", password, source)
	}
	if got := authSummary(results[0]); got != "NONE / no credentials required" {
		t.Fatalf("authSummary(passwordless) = %q", got)
	}
	if got := authSummary(results[1]); got != "weak password" {
		t.Fatalf("authSummary(weak) = %q", got)
	}

	// A weak-password host must be listed in the findings section and in
	// the stat strip.
	findings := findingRows(results)
	if len(findings) != 2 {
		t.Fatalf("findingRows = %d entries, want 2", len(findings))
	}
	stats := coverStats(Summarize(results))
	var weak *statCell
	for i := range stats {
		if stats[i].label == "Weak creds" {
			weak = &stats[i]
		}
	}
	if weak == nil {
		t.Fatalf("coverStats has no %q counter", "Weak creds")
	}
	if weak.value != "1" {
		t.Fatalf("Weak creds = %q, want 1", weak.value)
	}
	if weak.color != colorWarning {
		t.Fatalf("Weak creds colour = %+v, want warning %+v", weak.color, colorWarning)
	}
}

func TestCredentialPartsSources(t *testing.T) {
	tests := []struct {
		name         string
		result       Result
		wantPassword string
		wantSource   string
	}{
		{name: "passwordless", result: Result{Passwordless: true}, wantPassword: "", wantSource: ""},
		{name: "default list", result: Result{Password: "hunter2", PasswordSource: "default"},
			wantPassword: "hunter2", wantSource: "(default list)"},
		{name: "word list", result: Result{Password: "Summer2024!", PasswordSource: "word-list"},
			wantPassword: "Summer2024!", wantSource: "(word list)"},
		{name: "unknown source", result: Result{Password: "pw", PasswordSource: "custom"},
			wantPassword: "pw", wantSource: "(custom)"},
		{name: "no source", result: Result{Password: "pw"}, wantPassword: "pw", wantSource: ""},
		{name: "long password", result: Result{Password: strings.Repeat("p", 60), PasswordSource: "default"},
			wantPassword: strings.Repeat("p", 29) + "...", wantSource: "(default list)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, source := credentialParts(tt.result)
			if password != tt.wantPassword || source != tt.wantSource {
				t.Fatalf("credentialParts() = %q, %q, want %q, %q",
					password, source, tt.wantPassword, tt.wantSource)
			}
		})
	}
}

func TestPasswordCell(t *testing.T) {
	if got := passwordCell(Result{}); got != "-" {
		t.Fatalf("passwordCell(empty) = %q, want -", got)
	}
	if got := passwordCell(Result{Password: "hunter2"}); got != "hunter2" {
		t.Fatalf("passwordCell(weak) = %q, want hunter2", got)
	}

	long := strings.Repeat("x", 40)
	got := passwordCell(Result{Password: long})
	if len([]rune(got)) > 18 {
		t.Fatalf("passwordCell(long) = %q, want at most 18 runes", got)
	}
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("passwordCell(long) = %q, want ellipsis", got)
	}
}

func TestSummaryWeakCredentialsCounted(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.50", Port: 5900, Open: true, Passwordless: true},
		{IP: "192.0.2.51", Port: 5901, Open: true, Password: "hunter2", PasswordSource: "default"},
		{IP: "192.0.2.52", Port: 5902, Open: true},
	}

	sum := Summarize(results)
	if sum.WeakCredentials != 1 {
		t.Fatalf("WeakCredentials = %d, want 1", sum.WeakCredentials)
	}
	if sum.Passwordless != 1 {
		t.Fatalf("Passwordless = %d, want 1", sum.Passwordless)
	}
}
