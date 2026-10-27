// Golden files under testdata/golden are reviewed artifacts. They capture the
// rendered shape of every exporter, which substring assertions cannot guard.
// A failure therefore means one of two things: the render change was intended,
// in which case regenerate with -update and review the resulting diff, or the
// renderer regressed and the golden is the baseline that caught it.
package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// update rewrites the golden files instead of comparing against them.
var update = flag.Bool("update", false, "rewrite golden files")

// goldenDir is resolved during package initialisation because the golden tests
// switch the working directory to a scratch capture directory, which would
// otherwise make a testdata path relative to the wrong place.
var goldenDir = func() string {
	wd, err := os.Getwd()
	if err != nil {
		panic("report: resolve working directory for golden files: " + err.Error())
	}
	return filepath.Join(wd, "testdata", "golden")
}()

const goldenUpdateHint = `Intentional render change? Regenerate and review the diff:
    go test ./report -run TestGolden -update
The PDF invariant golden is covered by the same run when the pattern includes
TestPDFStructure:
    go test ./report -run 'TestGolden|TestPDFStructure' -update`

const (
	// goldenGeneratedAt replaces the volatile document timestamp in the JSON
	// golden so a re-run does not change the baseline.
	goldenGeneratedAt = "2026-10-26T12:00:00Z"

	// Capture paths stay relative because the test changes into the scratch
	// directory that holds the generated PNGs.
	passwordlessCapture = "captures/192.0.2.10-5900.png"
	weakCapture         = "captures/192.0.2.11-5900.png"
)

var (
	// htmlGeneratedAtRE matches only the masthead timestamp, not the fixed
	// per-capture timestamps that are part of the reviewed layout.
	htmlGeneratedAtRE = regexp.MustCompile(`(Generated</span><span class="meta-value mono">)[^<]*(</span>)`)
	// htmlDataURIRE matches any embedded PNG payload. Its length depends on
	// the encoder and thumbnailer, which is not a layout regression.
	htmlDataURIRE = regexp.MustCompile(`data:image/png;base64,[A-Za-z0-9+/=]+`)
)

// goldenResults is the single inventory exercised by every exporter: a
// passwordless host with a capture, a weak-password host with a capture, an
// authenticated host without one, a closed port, a self-signed TLS host, a
// host that requires a client certificate, and a host that needed a retry.
func goldenResults() []Result {
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	return []Result{
		{
			IP:            "192.0.2.10",
			Port:          5900,
			Open:          true,
			RFB:           true,
			Passwordless:  true,
			SecurityTypes: []string{"VNC authentication"},
			ServerName:    "Reception display",
			ScreenWidth:   96,
			ScreenHeight:  48,
			Screenshot:    passwordlessCapture,
			DurationMs:    118,
			Attempts:      1,
			Timestamp:     base,
		},
		{
			IP:             "192.0.2.11",
			Port:           5900,
			Open:           true,
			RFB:            true,
			Password:       "hunter2",
			PasswordSource: "word-list",
			SecurityTypes:  []string{"VNC authentication"},
			ServerName:     "Meeting room",
			ScreenWidth:    96,
			ScreenHeight:   48,
			Screenshot:     weakCapture,
			DurationMs:     204,
			Attempts:       1,
			Timestamp:      base.Add(1 * time.Minute),
		},
		{
			IP:            "198.51.100.20",
			Port:          5900,
			Open:          true,
			RFB:           true,
			SecurityTypes: []string{"VNC authentication"},
			ServerName:    "Build agent",
			ScreenWidth:   1280,
			ScreenHeight:  1024,
			DurationMs:    76,
			Timestamp:     base.Add(2 * time.Minute),
		},
		{
			IP:         "198.51.100.99",
			Port:       5901,
			Open:       false,
			Error:      "connection refused",
			DurationMs: 9,
			Timestamp:  base.Add(3 * time.Minute),
		},
		{
			IP:            "198.51.100.50",
			Port:          5900,
			Open:          true,
			RFB:           true,
			SecurityTypes: []string{"VeNCrypt", "VNC authentication"},
			TLS:           true,
			ServerName:    "vnc-console.example.net",
			ScreenWidth:   1024,
			ScreenHeight:  768,
			DurationMs:    143,
			Timestamp:     base.Add(4 * time.Minute),
			Certificate: &Certificate{
				Version:     "TLS 1.3",
				CipherSuite: "TLS_AES_256_GCM_SHA384",
				Subject:     "CN=vnc-console.example.net",
				Issuer:      "CN=vnc-console.example.net",
				NotBefore:   time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:    time.Date(2027, 10, 1, 0, 0, 0, 0, time.UTC),
				DNSNames: []string{
					"vnc-console.example.net",
					"vnc-console-alt.example.net",
				},
				Fingerprint: "3F:1A:9C:7E:5B:20:D4:88:11:6C:AF:02:E7:35:91:4B:" +
					"6D:08:C2:74:9E:15:AB:63:F0:2D:87:5C:19:B4:6E:40",
				SelfSigned: true,
			},
		},
		{
			IP:            "198.51.100.60",
			Port:          5900,
			Open:          true,
			RFB:           true,
			SecurityTypes: []string{"VeNCrypt"},
			TLS:           true,
			Note:          "client certificate required (VeNCrypt/X509Vnc)",
			DurationMs:    52,
			Timestamp:     base.Add(5 * time.Minute),
		},
		{
			IP:            "198.51.100.70",
			Port:          5900,
			Open:          true,
			RFB:           true,
			SecurityTypes: []string{"VNC authentication"},
			ServerName:    "Lab workstation",
			ScreenWidth:   800,
			ScreenHeight:  600,
			DurationMs:    311,
			Attempts:      2,
			Timestamp:     base.Add(6 * time.Minute),
		},
	}
}

// prepareGoldenWorkspace generates the capture PNGs referenced by
// goldenResults and changes into that scratch directory. The fixtures never
// read a checked-in image: the captures are produced here, and the relative
// paths keep machine-specific directories out of the goldens.
func prepareGoldenWorkspace(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	for _, name := range []string{passwordlessCapture, weakCapture} {
		writeGoldenPNG(t, filepath.Join(dir, name))
	}
	t.Chdir(dir)
	return dir
}

// writeGoldenPNG encodes a deterministic 96x48 desktop-like pattern.
func writeGoldenPNG(t *testing.T, path string) {
	t.Helper()

	const width, height = 96, 48
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{
				R: uint8(x * 2),
				G: uint8(y * 5),
				B: 0x60,
				A: 0xFF,
			})
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("create capture directory: %v", err)
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create capture png: %v", err)
	}
	defer file.Close()
	if err := png.Encode(file, img); err != nil {
		t.Fatalf("encode capture png: %v", err)
	}
}

// checkGolden compares got with testdata/golden/<name>.golden, or rewrites it
// when -update is set.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()

	path := filepath.Join(goldenDir, name+".golden")
	if *update {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("create golden directory: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v\n\n%s", path, err, goldenUpdateHint)
	}
	if bytes.Equal(want, got) {
		return
	}
	t.Fatalf("golden mismatch for %s\n\n%s\n\n%s", path, goldenLineDiff(want, got), goldenUpdateHint)
}

// goldenLineDiff prints the first differing line with a small context window
// so a layout change can be located without opening the whole golden.
func goldenLineDiff(want, got []byte) string {
	const contextLines = 3

	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(string(got), "\n")

	first := 0
	for first < len(wantLines) && first < len(gotLines) && wantLines[first] == gotLines[first] {
		first++
	}

	start := max(first-contextLines, 0)
	end := min(first+contextLines+1, max(len(wantLines), len(gotLines)))

	var diff strings.Builder
	fmt.Fprintf(&diff, "first difference at line %d (golden has %d lines, got %d)\n",
		first+1, len(wantLines), len(gotLines))
	for i := start; i < end; i++ {
		switch {
		case i < len(wantLines) && i < len(gotLines) && wantLines[i] == gotLines[i]:
			fmt.Fprintf(&diff, "  %5d | %s\n", i+1, wantLines[i])
		default:
			if i < len(wantLines) {
				fmt.Fprintf(&diff, "- %5d | %s\n", i+1, wantLines[i])
			}
			if i < len(gotLines) {
				fmt.Fprintf(&diff, "+ %5d | %s\n", i+1, gotLines[i])
			}
		}
	}
	return diff.String()
}

// normaliseJSON pins the volatile generation timestamp and re-marshals the
// document from a generic map. encoding/json sorts map keys, so the golden is
// stable even if struct field order changes; only the rendered values matter.
func normaliseJSON(t *testing.T, raw []byte) []byte {
	t.Helper()

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("unmarshal json report: %v", err)
	}
	document["generated_at"] = goldenGeneratedAt

	normalised, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatalf("marshal normalised json report: %v", err)
	}
	return append(normalised, '\n')
}

// normaliseHTML removes the two volatile inputs: the generation timestamp and
// the base64 payload of embedded captures. Captured timestamps are fixed
// fixtures and stay in the golden. CRLF is folded to LF for a text baseline.
func normaliseHTML(raw []byte) []byte {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = htmlGeneratedAtRE.ReplaceAllString(text, "${1}<GENERATED_AT>${2}")
	text = htmlDataURIRE.ReplaceAllString(text, "<DATA_URI>")
	return []byte(text)
}

// normalisePDF reports the structural invariants of a binary document as text,
// because raw PDF bytes contain creation dates and object offsets that are not
// meaningful to diff.
func normalisePDF(t *testing.T, data []byte) []byte {
	t.Helper()

	const (
		magic = "%PDF-"
		eof   = "%%EOF"
	)

	text := strings.TrimSpace(string(data))
	switch {
	case !strings.HasPrefix(text, magic):
		t.Fatalf("pdf does not start with %q", magic)
	case !strings.HasSuffix(text, eof):
		t.Fatalf("pdf does not end with %q", eof)
	}

	// The embedded font proves the report is self-contained rather than
	// relying on host fonts. fpdf registers UTF-8 fonts with a lowercase
	// "utf8" prefix, hence the spelling of the PostScript name.
	const fontName = "utf8liberation"
	if !strings.Contains(text, fontName) {
		t.Fatalf("pdf does not embed font %q", fontName)
	}

	var invariants strings.Builder
	fmt.Fprintf(&invariants, "magic: %s\n", magic)
	fmt.Fprintf(&invariants, "trailer: %s\n", eof)
	fmt.Fprintf(&invariants, "pages: %d\n", pdfPageCount(text))
	fmt.Fprintf(&invariants, "font: %s\n", fontName)
	return []byte(invariants.String())
}

// pdfPageCount counts page objects. The page tree node is typed /Pages, which
// shares the /Type /Page prefix, so those occurrences are subtracted.
func pdfPageCount(text string) int {
	return strings.Count(text, "/Type /Page") - strings.Count(text, "/Type /Pages")
}

func TestGoldenJSON(t *testing.T) {
	dir := prepareGoldenWorkspace(t)

	path := filepath.Join(dir, "report.json")
	if err := WriteJSON(path, goldenResults()); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json report: %v", err)
	}

	checkGolden(t, "report.json", normaliseJSON(t, raw))
}

func TestGoldenCSV(t *testing.T) {
	dir := prepareGoldenWorkspace(t)

	path := filepath.Join(dir, "report.csv")
	if err := WriteCSV(path, goldenResults()); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv report: %v", err)
	}

	// CSV has no volatile content once the timestamps are fixed, so the golden
	// is the file itself.
	checkGolden(t, "report.csv", raw)
}

func TestGoldenHTML(t *testing.T) {
	dir := prepareGoldenWorkspace(t)

	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, goldenResults()); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read html report: %v", err)
	}

	checkGolden(t, "report.html", normaliseHTML(raw))
}

func TestPDFStructure(t *testing.T) {
	dir := prepareGoldenWorkspace(t)

	path := filepath.Join(dir, "report.pdf")
	if err := WritePDF(path, goldenResults()); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read pdf report: %v", err)
	}

	checkGolden(t, "report.pdf", normalisePDF(t, raw))
}
