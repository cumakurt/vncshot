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

func TestSecuritySummary(t *testing.T) {
	tests := []struct {
		name  string
		types []string
		want  string
	}{
		{name: "none", types: nil, want: ""},
		{name: "vnc auth abbreviated", types: []string{"VNC authentication"}, want: "VNC auth"},
		{name: "multiple types", types: []string{"VeNCrypt", "VNC authentication"}, want: "VeNCrypt · VNC auth"},
		{name: "blank entries skipped", types: []string{"", "  ", "Tight"}, want: "Tight"},
		{name: "unknown type verbatim", types: []string{"RA2"}, want: "RA2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := securitySummary(tt.types); got != tt.want {
				t.Fatalf("securitySummary(%v) = %q, want %q", tt.types, got, tt.want)
			}
		})
	}
}

func TestTransportDescription(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{name: "no types", result: Result{}, want: ""},
		{name: "clear text", result: Result{SecurityTypes: []string{"VNC authentication"}},
			want: "VNC authentication (clear text)"},
		{name: "tls", result: Result{SecurityTypes: []string{"VeNCrypt"}, TLS: true},
			want: "VeNCrypt (TLS)"},
		{name: "tls without type", result: Result{TLS: true}, want: "TLS (encrypted)"},
		{name: "multiple types", result: Result{SecurityTypes: []string{"VeNCrypt", "VNC authentication"}},
			want: "VeNCrypt · VNC authentication (clear text)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := transportDescription(tt.result); got != tt.want {
				t.Fatalf("transportDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStateLabel(t *testing.T) {
	tests := []struct {
		name   string
		result Result
		want   string
	}{
		{name: "passwordless", result: Result{Open: true, RFB: true, Passwordless: true}, want: "no auth"},
		{name: "weak password", result: Result{Open: true, RFB: true, Password: "hunter2"}, want: "weak"},
		{name: "rfb", result: Result{Open: true, RFB: true}, want: "rfb"},
		{name: "plain open port", result: Result{Open: true}, want: "open"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stateLabel(tt.result); got != tt.want {
				t.Fatalf("stateLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDurationCellMarksRetries(t *testing.T) {
	if got := durationCell(Result{DurationMs: 42}); got != "42 ms" {
		t.Fatalf("durationCell(single attempt) = %q, want %q", got, "42 ms")
	}
	if got := durationCell(Result{DurationMs: 42, Attempts: 3}); got != "42 ms ×3" {
		t.Fatalf("durationCell(retried) = %q, want %q", got, "42 ms ×3")
	}
	if got := retrySuffix(Result{Attempts: 1}); got != "" {
		t.Fatalf("retrySuffix(1) = %q, want empty", got)
	}
	if got := retrySuffix(Result{Attempts: 2}); got != "retried ×2" {
		t.Fatalf("retrySuffix(2) = %q, want %q", got, "retried ×2")
	}
}

func TestOpenTableFitsContentWidth(t *testing.T) {
	if len(tableHeaders) != len(tableWidths) {
		t.Fatalf("table headers = %d, widths = %d; want equal", len(tableHeaders), len(tableWidths))
	}
	total := 0.0
	for _, w := range tableWidths {
		total += w
	}
	if total != contentWidth {
		t.Fatalf("table width total = %v mm, want content width %v mm", total, contentWidth)
	}
}

func TestWritePDFWithTransportSecurity(t *testing.T) {
	dir := t.TempDir()
	shot := writeTinyPNG(t, dir)
	ts := time.Date(2026, 10, 27, 8, 30, 0, 0, time.UTC)

	results := []Result{
		{
			IP:            "192.0.2.60",
			Port:          5900,
			Open:          true,
			RFB:           true,
			Passwordless:  true,
			SecurityTypes: []string{"VeNCrypt", "VNC authentication"},
			TLS:           true,
			Attempts:      2,
			ServerName:    "Encrypted but open",
			ScreenWidth:   1024,
			ScreenHeight:  768,
			Screenshot:    shot,
			DurationMs:    88,
			Timestamp:     ts,
		},
		{
			IP:            "192.0.2.61",
			Port:          5900,
			Open:          true,
			RFB:           true,
			Password:      "hunter2",
			SecurityTypes: []string{"VNC authentication"},
			ServerName:    "Clear text weak auth",
			DurationMs:    12,
			Timestamp:     ts.Add(time.Second),
		},
	}

	path := filepath.Join(dir, "security.pdf")
	if err := WritePDF(path, results); err != nil {
		t.Fatalf("WritePDF with transport security: %v", err)
	}
	requireValidPDF(t, path)

	stats := coverStats(Summarize(results))
	var tls *statCell
	for i := range stats {
		if stats[i].label == "TLS services" {
			tls = &stats[i]
		}
	}
	if tls == nil {
		t.Fatal(`coverStats has no "TLS services" counter`)
	}
	if tls.value != "1" {
		t.Fatalf("TLS services = %q, want 1", tls.value)
	}
	if tls.color != colorAccent {
		t.Fatalf("TLS services colour = %+v, want accent %+v", tls.color, colorAccent)
	}
}

func TestWritePDFWithDiff(t *testing.T) {
	dir := t.TempDir()
	shot := writeTinyPNG(t, dir)
	ts := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

	results := []Result{
		{
			IP:           "192.0.2.140",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			Screenshot:   shot,
			Timestamp:    ts,
		},
	}
	diff := &Diff{
		Baseline: "/var/lib/vncshot/runs/20261026-120000",
		New: []Result{
			{IP: "192.0.2.140", Port: 5900, Open: true, RFB: true, Passwordless: true},
		},
		Resolved: []Result{
			{IP: "192.0.2.141", Port: 5900, Open: true, RFB: true},
		},
		Changed: []Change{
			{
				Before: Result{IP: "192.0.2.142", Port: 5900, Open: true, RFB: true, Password: "hunter2"},
				After:  Result{IP: "192.0.2.142", Port: 5900, Open: true, RFB: true},
				Reason: "password no longer accepted",
			},
		},
	}

	path := filepath.Join(dir, "diff.pdf")
	if err := WritePDFWithDiff(path, results, diff); err != nil {
		t.Fatalf("WritePDFWithDiff: %v", err)
	}
	requireValidPDF(t, path)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat pdf: %v", err)
	}
	if info.Size() < 4096 {
		t.Fatalf("pdf size = %d bytes, want at least 4096", info.Size())
	}
}

func TestDiffTransition(t *testing.T) {
	tests := []struct {
		name   string
		before Result
		after  Result
		want   string
	}{
		{
			name:   "weak to rfb",
			before: Result{Open: true, RFB: true, Password: "hunter2"},
			after:  Result{Open: true, RFB: true},
			want:   "weak → rfb",
		},
		{
			name:   "passwordless to closed",
			before: Result{Open: true, RFB: true, Passwordless: true},
			after:  Result{Open: false},
			want:   "no auth → closed",
		},
		{
			name:   "rfb to plain open",
			before: Result{Open: true, RFB: true},
			after:  Result{Open: true},
			want:   "rfb → open",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffTransition(tt.before, tt.after)
			if got != tt.want {
				t.Fatalf("diffTransition() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCapDiffRows(t *testing.T) {
	entries := make([]Result, 60)
	for i := range entries {
		entries[i] = Result{IP: "192.0.2.1", Port: 5900 + i}
	}

	kept, hidden := capDiff(entries, pdfDiffRowLimit)
	if len(kept) != pdfDiffRowLimit || hidden != 60-pdfDiffRowLimit {
		t.Fatalf("capDiff(pdf limit) = %d kept, %d hidden; want %d, %d",
			len(kept), hidden, pdfDiffRowLimit, 60-pdfDiffRowLimit)
	}

	kept, hidden = capDiff(entries, htmlDiffRowLimit)
	if len(kept) != htmlDiffRowLimit || hidden != 60-htmlDiffRowLimit {
		t.Fatalf("capDiff(html limit) = %d kept, %d hidden; want %d, %d",
			len(kept), hidden, htmlDiffRowLimit, 60-htmlDiffRowLimit)
	}

	kept, hidden = capDiff(entries[:3], pdfDiffRowLimit)
	if len(kept) != 3 || hidden != 0 {
		t.Fatalf("capDiff(short) = %d kept, %d hidden; want 3, 0", len(kept), hidden)
	}

	kept, hidden = capDiff([]Result(nil), pdfDiffRowLimit)
	if kept != nil || hidden != 0 {
		t.Fatalf("capDiff(nil) = %v, %d; want nil, 0", kept, hidden)
	}
}

func TestBaselineSectionOnlyWithDiff(t *testing.T) {
	if hasBaselineSection(nil) {
		t.Fatal("hasBaselineSection(nil) = true, want false")
	}
	if normalizedDiff(nil) != nil {
		t.Fatal("normalizedDiff(nil) != nil")
	}
	if !hasBaselineSection(&Diff{}) {
		t.Fatal("hasBaselineSection(empty diff) = false, want true")
	}
	if !(&Diff{}).Empty() {
		t.Fatal("empty diff reports changes")
	}
}

func TestNormalizedDiffSortsAndReducesBaseline(t *testing.T) {
	diff := &Diff{
		Baseline: "/var/lib/vncshot/runs/20261026-120000",
		New: []Result{
			{IP: "192.0.2.10", Port: 5901},
			{IP: "192.0.2.9", Port: 5900},
			{IP: "192.0.2.10", Port: 5900},
		},
		Changed: []Change{
			{Before: Result{IP: "192.0.2.20", Port: 5900}, After: Result{IP: "192.0.2.20", Port: 5900}},
			{Before: Result{IP: "192.0.2.3", Port: 5901}, After: Result{IP: "192.0.2.3", Port: 5901}},
		},
	}

	got := normalizedDiff(diff)
	if got.Baseline != "20261026-120000" {
		t.Fatalf("Baseline = %q, want base name", got.Baseline)
	}
	wantNew := []string{"192.0.2.9:5900", "192.0.2.10:5900", "192.0.2.10:5901"}
	for i, want := range wantNew {
		if got.New[i].Addr() != want {
			t.Fatalf("New[%d] = %s, want %s", i, got.New[i].Addr(), want)
		}
	}
	if got.Changed[0].Before.Addr() != "192.0.2.3:5901" {
		t.Fatalf("Changed[0] = %s, want numeric IP order", got.Changed[0].Before.Addr())
	}
	// The helper must not reorder the caller's slices in place.
	if diff.New[0].Addr() != "192.0.2.10:5901" || diff.Baseline != "/var/lib/vncshot/runs/20261026-120000" {
		t.Fatal("normalizedDiff mutated its input")
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
