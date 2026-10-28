package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTrendRun creates a run folder whose JSON report carries the given
// results, the way a finished scan leaves it behind.
func writeTrendRun(t *testing.T, root, name string, results []Result) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create run dir: %v", err)
	}
	if err := WriteJSON(filepath.Join(dir, "vncshot_report.json"), results); err != nil {
		t.Fatalf("write run report: %v", err)
	}
}

func TestWriteHTMLRecentRunsSection(t *testing.T) {
	root := t.TempDir()
	writeTrendRun(t, root, "20261020-090000", []Result{
		{IP: "192.0.2.1", Port: 5900, Open: true, RFB: true, Passwordless: true},
		{IP: "192.0.2.2", Port: 5900, Open: true, RFB: true, Password: "hunter2"},
	})
	writeTrendRun(t, root, "20261021-090000", []Result{
		{IP: "192.0.2.3", Port: 5900, Error: "connection refused"},
	})
	// A plain file whose name parses as a timestamp is not a run folder.
	if err := os.WriteFile(filepath.Join(root, "20261019-090000"), []byte("junk"), 0o600); err != nil {
		t.Fatalf("write decoy file: %v", err)
	}
	current := filepath.Join(root, "20261022-100000")
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatalf("create current run dir: %v", err)
	}

	path := filepath.Join(current, "vncshot_report.html")
	if err := WriteHTML(path, nil); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, "Recent runs", "the trend section title")
	mustContain(t, html, ">20261021-090000<", "the newer sibling run")
	mustContain(t, html, ">20261020-090000<", "the older sibling run")
	if strings.Index(html, ">20261021-090000<") > strings.Index(html, ">20261020-090000<") {
		t.Error("recent runs are not sorted newest first")
	}
	mustNotContain(t, html, ">20261022-100000<", "the run being written must not list itself")
	mustNotContain(t, html, ">20261019-090000<", "a plain file is not a run folder")
	// Both insecure counters of the older run are highlighted.
	if got := strings.Count(html, `<td class="mono trend-hot">1</td>`); got != 2 {
		t.Errorf("highlighted counters = %d cells, want 2 (passwordless and weak)", got)
	}
}

func TestWriteHTMLOmitsRecentRunsWithoutSiblings(t *testing.T) {
	// An overridden output path is not inside a timestamped run folder, so
	// the section must stay out even with run folders nearby.
	root := t.TempDir()
	writeTrendRun(t, root, "20261020-090000", []Result{{IP: "192.0.2.1", Port: 5900}})
	path := filepath.Join(root, "vncshot_report.html")
	if err := WriteHTML(path, nil); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	mustNotContain(t, readHTML(t, path), "Recent runs", "an overridden output path")

	// A run folder without siblings must not gain the section either.
	lonely := t.TempDir()
	current := filepath.Join(lonely, "20261022-100000")
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatalf("create current run dir: %v", err)
	}
	path = filepath.Join(current, "vncshot_report.html")
	if err := WriteHTML(path, nil); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	mustNotContain(t, readHTML(t, path), "Recent runs", "a run without siblings")
}

func TestWriteHTMLRecentRunsBoundedToTen(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 12; i++ {
		writeTrendRun(t, root, fmt.Sprintf("20261001-%06d", i), []Result{
			{IP: "192.0.2.1", Port: 5900, Open: true, RFB: true, Passwordless: true},
		})
	}
	current := filepath.Join(root, "20261002-100000")
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatalf("create current run dir: %v", err)
	}

	path := filepath.Join(current, "vncshot_report.html")
	if err := WriteHTML(path, nil); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)
	mustNotContain(t, html, ">20261001-000000<", "the oldest run is outside the window")
	mustNotContain(t, html, ">20261001-000001<", "the second oldest run is outside the window")
	mustContain(t, html, ">20261001-000002<", "the third oldest run is inside the window")
	mustContain(t, html, ">20261001-000011<", "the newest run")
	if got := strings.Count(html, ">20261001-0"); got != 10 {
		t.Errorf("recent runs rows = %d, want 10", got)
	}
}

func TestWriteHTMLRecentRunsSkipsUnreadableReports(t *testing.T) {
	root := t.TempDir()
	writeTrendRun(t, root, "20261020-090000", []Result{
		{IP: "192.0.2.1", Port: 5900, Open: true, RFB: true, Passwordless: true},
	})
	broken := filepath.Join(root, "20261021-090000")
	if err := os.MkdirAll(broken, 0o700); err != nil {
		t.Fatalf("create broken run dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(broken, "vncshot_report.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt report: %v", err)
	}
	current := filepath.Join(root, "20261022-100000")
	if err := os.MkdirAll(current, 0o700); err != nil {
		t.Fatalf("create current run dir: %v", err)
	}

	path := filepath.Join(current, "vncshot_report.html")
	if err := WriteHTML(path, nil); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)
	mustNotContain(t, html, ">20261021-090000<", "the run with a damaged report")
	mustContain(t, html, ">20261020-090000<", "the readable sibling is still listed")
}
