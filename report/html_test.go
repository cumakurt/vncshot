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
		"TLS services": "0",
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

func TestWriteHTMLTLSServicesCounter(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.80", Port: 5900, Open: true, RFB: true, TLS: true},
		{IP: "192.0.2.81", Port: 5900, Open: true, RFB: true},
		{IP: "192.0.2.82", Port: 5901, Open: true, RFB: true, TLS: true},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html,
		`<div class="label">TLS services</div><div class="value">2</div>`,
		"TLS services summary stat")
	// The counter is highlighted only when at least one service is encrypted.
	mustContain(t, html, `<div class="stat good"><div class="label">TLS services</div>`,
		"accent-coloured TLS services counter")
}

func TestWriteHTMLSecurityColumn(t *testing.T) {
	results := []Result{
		{
			IP:            "192.0.2.90",
			Port:          5900,
			Open:          true,
			RFB:           true,
			SecurityTypes: []string{"VeNCrypt", "VNC authentication"},
			TLS:           true,
		},
		{
			IP:   "192.0.2.91",
			Port: 5900,
			Open: true,
			RFB:  true,
		},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	tbodyStart := strings.Index(html, "<tbody>")
	tbodyEnd := strings.Index(html, "</tbody>")
	if tbodyStart < 0 || tbodyEnd < 0 || tbodyEnd < tbodyStart {
		t.Fatalf("html report has no well-formed <tbody> section")
	}
	tbody := html[tbodyStart:tbodyEnd]

	mustContain(t, tbody, "VeNCrypt · VNC auth", "security types in the endpoint table")
	mustContain(t, tbody, `class="tag tls"`, "TLS tag for an encrypted endpoint")
	mustContain(t, tbody, `<span class="no">—</span>`, "em dash for missing security types")
	mustContain(t, tbody, `data-search="192.0.2.90 5900 authenticated open  VeNCrypt · VNC auth tls"`,
		"security types in the row search index")
}

func TestWriteHTMLTLSTagOnlyWhenEncrypted(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.92", Port: 5900, Open: true, RFB: true, SecurityTypes: []string{"VNC authentication"}},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "VNC auth", "abbreviated security type")
	mustNotContain(t, html, `class="tag tls"`, "TLS tag on a clear-text endpoint")
}

func TestWriteHTMLRetriedMarker(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.93", Port: 5900, Open: true, RFB: true, Attempts: 2},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, `class="retried">retried ×2</span>`, "retried marker for a flaky host")
}

func TestWriteHTMLFindingTransportLine(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	results := []Result{
		{
			IP:            "192.0.2.94",
			Port:          5900,
			Open:          true,
			RFB:           true,
			Passwordless:  true,
			Screenshot:    pngPath,
			SecurityTypes: []string{"VNC authentication"},
		},
		{
			IP:            "192.0.2.95",
			Port:          5900,
			Open:          true,
			RFB:           true,
			Password:      "hunter2",
			Screenshot:    pngPath,
			SecurityTypes: []string{"VeNCrypt"},
			TLS:           true,
		},
	}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "VNC authentication (clear text)", "clear-text transport line on a finding card")
	mustContain(t, html, "VeNCrypt (TLS)", "encrypted transport line on a finding card")
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

func TestWriteHTMLShowsWeakPassword(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	results := []Result{
		{
			IP:             "192.0.2.20",
			Port:           5900,
			Open:           true,
			RFB:            true,
			Password:       "hunter2",
			PasswordSource: "default",
			ScreenWidth:    8,
			ScreenHeight:   8,
			Screenshot:     pngPath,
		},
	}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "hunter2", "weak password in report")
	mustContain(t, html, `<div class="label">Weak creds</div>`, "weak credentials summary stat")
	mustContain(t, html, "default list", "human-readable credential source")
}

func TestWriteHTMLWeakPasswordCard(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	results := []Result{
		{
			IP:             "192.0.2.21",
			Port:           5900,
			Open:           true,
			RFB:            true,
			Password:       "hunter2",
			PasswordSource: "default",
			ScreenWidth:    8,
			ScreenHeight:   8,
			Screenshot:     pngPath,
		},
	}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	start := strings.Index(html, `<figure class="card"`)
	if start < 0 {
		t.Fatalf("html report has no weak-password capture card")
	}
	end := strings.Index(html[start:], "</figure>")
	if end < 0 {
		t.Fatalf("weak-password capture card is not closed")
	}
	card := html[start : start+end]

	mustContain(t, card, "hunter2", "weak password inside the card")
	mustContain(t, card, `class="badge"`, "credential badge inside the card")
	mustContain(t, card, "default list", "credential source inside the card")
	mustNotContain(t, card, "no authentication", "passwordless badge on a weak-password card")
}

func TestWriteHTMLPasswordColumn(t *testing.T) {
	results := []Result{
		{
			IP:             "192.0.2.22",
			Port:           5900,
			Open:           true,
			RFB:            true,
			Password:       "hunter2",
			PasswordSource: "default",
		},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	tbodyStart := strings.Index(html, "<tbody>")
	tbodyEnd := strings.Index(html, "</tbody>")
	if tbodyStart < 0 || tbodyEnd < 0 || tbodyEnd < tbodyStart {
		t.Fatalf("html report has no well-formed <tbody> section")
	}
	tbody := html[tbodyStart:tbodyEnd]

	mustContain(t, tbody, "hunter2", "weak password in the endpoint table")
	mustContain(t, tbody, "default list", "credential source in the endpoint table")
	mustContain(t, tbody, `class="tag hot"`, "cracked-row tag in the endpoint table")
	mustContain(t, tbody, "weakpassword", "weak-password filter term in the row search index")
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

func TestWriteHTMLUsesLightTheme(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.70", Port: 5900, Open: true, RFB: true},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := strings.ToLower(readHTML(t, path))

	for _, token := range []string{"#0f1419", "#1a2332", "prefers-color-scheme: dark"} {
		mustNotContain(t, html, token, "dark theme token")
	}
	mustContain(t, html, "#fbfaf7", "light paper background token")
}

func TestWriteHTMLLegalNoticeKeepsTurkishCharacters(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.71", Port: 5900, Open: true, RFB: true},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	for _, want := range []string{"Yasal uyarı", "yalnızca", "sorumluluk"} {
		mustContain(t, html, want, "Turkish legal notice text")
	}
}

func TestWriteHTMLWithDiffRendersGroups(t *testing.T) {
	baseline := filepath.Join(t.TempDir(), "runs", "20261026-120000")
	diff := &Diff{
		Baseline: baseline,
		New: []Result{
			{IP: "192.0.2.120", Port: 5900, Open: true, RFB: true, Passwordless: true},
		},
		Resolved: []Result{
			{IP: "192.0.2.121", Port: 5900, Open: true, RFB: true},
		},
		Changed: []Change{
			{
				Before: Result{IP: "192.0.2.122", Port: 5900, Open: true, RFB: true, Password: "hunter2"},
				After:  Result{IP: "192.0.2.122", Port: 5900, Open: true, RFB: true},
				Reason: "password no longer accepted",
			},
		},
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTMLWithDiff(path, nil, diff); err != nil {
		t.Fatalf("WriteHTMLWithDiff: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "Changes since baseline", "baseline section heading")
	mustContain(t, html, "New (1)", "new-findings group heading")
	mustContain(t, html, "Resolved (1)", "resolved-findings group heading")
	mustContain(t, html, "Changed (1)", "changed-findings group heading")
	mustContain(t, html, "20261026-120000", "baseline run name")
	mustContain(t, html, "no auth", "new finding state tag")
	mustContain(t, html, "password no longer accepted", "change reason")
	mustContain(t, html, `class="diff-arrow">→</span>`, "before → after transition")
	mustContain(t, html, "192.0.2.122:5900", "changed finding address")
	mustContain(t, html, "data-search=", "searchable comparison rows")
	mustNotContain(t, html, baseline, "absolute baseline path")
	mustNotContain(t, html, filepath.Dir(baseline), "baseline parent directory")
}

func TestWriteHTMLWithDiffEmptyRendersMutedLine(t *testing.T) {
	diff := &Diff{Baseline: "/var/lib/vncshot/runs/20261026-120000"}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTMLWithDiff(path, nil, diff); err != nil {
		t.Fatalf("WriteHTMLWithDiff: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "No changes since the baseline run.", "empty-diff message")
	mustNotContain(t, html, `class="diff-row"`, "comparison rows for an empty diff")
	mustNotContain(t, html, "New (", "empty new-findings group")
}

func TestWriteHTMLWithDiffTruncatesLongGroups(t *testing.T) {
	diff := &Diff{Baseline: "20261026-120000"}
	for i := 0; i < 60; i++ {
		diff.New = append(diff.New, Result{
			IP:   fmt.Sprintf("192.0.2.%d", i+1),
			Port: 5900,
			Open: true,
			RFB:  true,
		})
	}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTMLWithDiff(path, nil, diff); err != nil {
		t.Fatalf("WriteHTMLWithDiff: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "New (60)", "full new-findings count")
	mustContain(t, html, "… and 10 more", "truncation marker")
	if rows := strings.Count(html, `class="diff-row"`); rows != htmlDiffRowLimit {
		t.Errorf("comparison rows = %d, want cap %d", rows, htmlDiffRowLimit)
	}
}

func TestWriteHTMLWithoutDiffHasNoBaselineSection(t *testing.T) {
	results := []Result{{IP: "192.0.2.130", Port: 5900, Open: true, RFB: true}}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	mustNotContain(t, readHTML(t, path), "Changes since baseline", "baseline section without -baseline")

	pathNil := filepath.Join(t.TempDir(), "report-nil.html")
	if err := WriteHTMLWithDiff(pathNil, results, nil); err != nil {
		t.Fatalf("WriteHTMLWithDiff(nil): %v", err)
	}
	mustNotContain(t, readHTML(t, pathNil), "Changes since baseline", "baseline section for a nil diff")
}

func TestWriteHTMLRedactsPassword(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	results := []Result{
		{
			IP:             "192.0.2.23",
			Port:           5900,
			Open:           true,
			RFB:            true,
			Password:       "hunter2",
			PasswordSource: "default",
			Screenshot:     pngPath,
		},
	}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTMLWithOptions(path, results, Options{Redact: true}); err != nil {
		t.Fatalf("WriteHTMLWithOptions: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, RedactedValue, "redaction marker in the report")
	mustNotContain(t, html, "hunter2", "real password")
	mustContain(t, html, `class="badge"`, "credential badge stays visible")
	mustContain(t, html, `class="tag hot"`, "weak-password tag stays visible")
	mustContain(t, html, "weakpassword", "weak-password filter term stays visible")
}

func TestWriteHTMLThumbnailOnly(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 64, 64)

	results := []Result{
		{
			IP:           "192.0.2.24",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			Screenshot:   pngPath,
		},
	}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTMLWithOptions(path, results, Options{ThumbnailOnly: true}); err != nil {
		t.Fatalf("WriteHTMLWithOptions: %v", err)
	}
	html := readHTML(t, path)

	if got := strings.Count(html, "data:image/png;base64,"); got != 1 {
		t.Errorf("embedded data URIs = %d, want 1 (thumbnail only)", got)
	}
	mustContain(t, html, `data-full=""`, "empty data-full attribute")
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

// TestWriteHTMLTimestampsAreLabelledUTC guards the report against ambiguous
// times: the JSON and PDF use UTC, the screenshot file names use the local
// clock, so the HTML must say which clock it shows.
func TestWriteHTMLTimestampsAreLabelledUTC(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	ts := time.Date(2026, 10, 26, 15, 4, 5, 0, time.UTC)
	results := []Result{{
		IP:           "192.0.2.10",
		Port:         5900,
		Open:         true,
		RFB:          true,
		Passwordless: true,
		Screenshot:   pngPath,
		Timestamp:    ts,
	}}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "2026-10-26 15:04:05 UTC", "UTC-labelled capture time")
}

// TestWriteHTMLHidesHostPaths guards the shareable report: it must not embed
// absolute local filesystem paths, which leak the operator's directory
// layout when the file is sent to a client.
func TestWriteHTMLHidesHostPaths(t *testing.T) {
	dir := t.TempDir()
	pngPath := filepath.Join(dir, "frame.png")
	writeTestPNG(t, pngPath, 8, 8)

	results := []Result{{
		IP:         "192.0.2.10",
		Port:       5900,
		Open:       true,
		RFB:        true,
		Screenshot: pngPath,
	}}

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustNotContain(t, html, dir, "absolute run directory in the HTML report")
	mustContain(t, html, "frame.png", "capture file name")
}
