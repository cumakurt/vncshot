package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vncshot/report"
	"vncshot/scanner"
	"vncshot/vnc"
)

func TestCredentialsDefaultsOnly(t *testing.T) {
	creds, err := Credentials(Config{})
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if len(creds) == 0 {
		t.Fatal("Credentials returned no candidates")
	}
	for _, c := range creds {
		if c.Source != vnc.SourceDefault {
			t.Errorf("candidate %q has source %q, want %q", c.Password, c.Source, vnc.SourceDefault)
		}
	}
}

func TestCredentialsDisabled(t *testing.T) {
	creds, err := Credentials(Config{NoPasswordCheck: true, WordList: "/nonexistent"})
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("Credentials returned %d candidates with NoPasswordCheck, want 0", len(creds))
	}
}

func TestCredentialsNoDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")
	if err := os.WriteFile(path, []byte("alpha\nbeta\n"), 0o600); err != nil {
		t.Fatalf("write word list: %v", err)
	}

	creds, err := Credentials(Config{NoDefaultPasswords: true, WordList: path})
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("Credentials returned %d candidates, want 2", len(creds))
	}
	for _, c := range creds {
		if c.Source != vnc.SourceWordList {
			t.Errorf("candidate %q has source %q, want %q", c.Password, c.Source, vnc.SourceWordList)
		}
	}
	if creds[0].Password != "alpha" || creds[1].Password != "beta" {
		t.Errorf("candidates = %q, %q; want alpha, beta", creds[0].Password, creds[1].Password)
	}
}

func TestReadWordListSkipsCommentsAndBlanksAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "words.txt")
	content := strings.Join([]string{
		"# operator word list",
		"",
		"  ",
		"alpha",
		"  beta  ",
		"alpha",
		"# trailing comment",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write word list: %v", err)
	}

	creds, err := Credentials(Config{NoDefaultPasswords: true, WordList: path})
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("Credentials returned %d candidates, want 2 (alpha, beta): %+v", len(creds), creds)
	}
	if creds[0].Password != "alpha" || creds[1].Password != "beta" {
		t.Errorf("candidates = %q, %q; want alpha, beta", creds[0].Password, creds[1].Password)
	}
}

func TestReadWordListRejectsMissingFile(t *testing.T) {
	if _, err := Credentials(Config{WordList: filepath.Join(t.TempDir(), "missing.txt")}); err == nil {
		t.Fatal("Credentials accepted a missing word list, want an error")
	}
}

func TestReadWordListRejectsDirectory(t *testing.T) {
	if _, err := Credentials(Config{WordList: t.TempDir()}); err == nil {
		t.Fatal("Credentials accepted a directory as a word list, want an error")
	}
}

func TestWordListLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "big.txt")
	var b strings.Builder
	for i := 0; i < maxWordListEntries+1; i++ {
		b.WriteString("candidate\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write word list: %v", err)
	}
	if _, err := Credentials(Config{NoDefaultPasswords: true, WordList: path}); err == nil {
		t.Fatal("Credentials accepted an oversized word list, want an error")
	}
}

func TestResolveArtifactPath(t *testing.T) {
	runDir := filepath.Join("/tmp", "run")

	if got := resolveArtifactPath("", runDir, "report.json"); got != filepath.Join(runDir, "report.json") {
		t.Errorf("default path = %q, want path inside the run directory", got)
	}
	if got := resolveArtifactPath("/var/tmp/report.json", runDir, "ignored.json"); got != "/var/tmp/report.json" {
		t.Errorf("absolute path = %q, want it kept as-is", got)
	}
	if got := resolveArtifactPath("sub/report.json", runDir, "ignored.json"); got != filepath.Join(runDir, "sub", "report.json") {
		t.Errorf("relative path = %q, want it resolved inside the run directory", got)
	}
}

func TestPrepareCreatesRunDirectoryAndResolvesArtifacts(t *testing.T) {
	base := t.TempDir()

	session, err := Prepare(Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		ConnectTimeout: 100 * time.Millisecond,
		VNCTimeout:     100 * time.Millisecond,
		Workers:        1,
		OutDir:         base,
		OutDirExplicit: true,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(session.Targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(session.Targets))
	}
	if filepath.Dir(session.RunDir) != base {
		t.Errorf("run dir %q is not inside %q", session.RunDir, base)
	}
	for _, path := range []string{session.JSONPath, session.HTMLPath, session.PDFPath, session.CSVPath} {
		if filepath.Dir(path) != session.RunDir {
			t.Errorf("artifact %q is not inside the run directory %q", path, session.RunDir)
		}
	}
	if filepath.Base(session.CSVPath) != "vncshot_report.csv" {
		t.Errorf("default csv path = %q, want vncshot_report.csv", session.CSVPath)
	}
	info, err := os.Stat(session.ShotDir)
	if err != nil {
		t.Fatalf("screenshot dir missing: %v", err)
	}
	if !info.IsDir() {
		t.Error("screenshot dir is not a directory")
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("screenshot dir permissions = %o, want owner-only", mode)
	}
	if warning := session.FallbackWarning(); warning != "" {
		t.Errorf("unexpected fallback warning: %s", warning)
	}
}

func TestPrepareKeepsAbsoluteCSVOverride(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "exports", "results.csv")
	session, err := Prepare(Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		OutDir:         t.TempDir(),
		OutDirExplicit: true,
		CSV:            custom,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if session.CSVPath != custom {
		t.Errorf("csv path = %q, want the absolute override %q", session.CSVPath, custom)
	}
}

func TestPrepareRejectsBrokenBaseline(t *testing.T) {
	cfg := Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		OutDir:         t.TempDir(),
		OutDirExplicit: true,
	}
	cfg.Baseline = t.TempDir()
	if _, err := Prepare(cfg); err == nil {
		t.Fatal("Prepare accepted a baseline directory without a report")
	}

	path := filepath.Join(t.TempDir(), "run.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	cfg.Baseline = path
	if _, err := Prepare(cfg); err == nil {
		t.Fatal("Prepare accepted a regular file as a baseline directory")
	}
}

// closedLocalPorts returns local ports that were just released, so a scan
// against them exercises the connection-refused path without needing RFB.
func closedLocalPorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	ports := make([]int, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve local port: %v", err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatalf("release local port: %v", err)
		}
	}
	return ports
}

func TestScanWritesCSVManifestAndDeterministicOrder(t *testing.T) {
	base := t.TempDir()
	ports := closedLocalPorts(t, 2)

	session, err := Prepare(Config{
		Target: "127.0.0.1",
		// Larger port first so the sorted output is observably different
		// from the requested order.
		Ports:          fmt.Sprintf("%d,%d", ports[1], ports[0]),
		ConnectTimeout: 200 * time.Millisecond,
		VNCTimeout:     200 * time.Millisecond,
		Workers:        2,
		OutDir:         base,
		OutDirExplicit: true,
		NoPDF:          true,
		Manifest:       true,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := session.Scan(ctx, nil)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(out.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(out.Results))
	}
	if out.CSV != session.CSVPath {
		t.Errorf("outcome csv = %q, want %q", out.CSV, session.CSVPath)
	}
	for _, path := range []string{out.JSON, out.HTML, out.CSV, out.Manifest} {
		if path == "" {
			t.Fatal("an expected artifact path is empty")
		}
		if _, err := os.Stat(path); err != nil {
			t.Errorf("artifact %q is missing: %v", path, err)
		}
	}
	if out.Manifest != filepath.Join(session.RunDir, ManifestFilename) {
		t.Errorf("manifest = %q, want it inside the run directory", out.Manifest)
	}
	if err := VerifyManifest(session.RunDir); err != nil {
		t.Errorf("VerifyManifest: %v", err)
	}

	sorted := append([]report.Result(nil), out.Results...)
	report.SortResults(sorted)

	data, err := os.ReadFile(out.JSON)
	if err != nil {
		t.Fatalf("read json report: %v", err)
	}
	var doc report.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse json report: %v", err)
	}
	if len(doc.Results) != len(sorted) {
		t.Fatalf("json results = %d, want %d", len(doc.Results), len(sorted))
	}
	for i := range sorted {
		if doc.Results[i].Addr() != sorted[i].Addr() {
			t.Fatalf("json row %d = %s, want %s", i, doc.Results[i].Addr(), sorted[i].Addr())
		}
	}

	file, err := os.Open(out.CSV)
	if err != nil {
		t.Fatalf("open csv report: %v", err)
	}
	records, err := csv.NewReader(file).ReadAll()
	file.Close()
	if err != nil {
		t.Fatalf("parse csv report: %v", err)
	}
	if len(records) != len(sorted)+1 {
		t.Fatalf("csv rows = %d, want header plus %d", len(records), len(sorted))
	}
	for i, r := range sorted {
		row := records[i+1]
		if len(row) < 2 {
			t.Fatalf("csv row %d is too short: %v", i+1, row)
		}
		if addr := row[0] + ":" + row[1]; addr != r.Addr() {
			t.Errorf("csv row %d = %s, want %s", i+1, addr, r.Addr())
		}
	}
}

func TestPrepareRejectsInvalidTargets(t *testing.T) {
	if _, err := Prepare(Config{Target: "", Ports: "5900", OutDir: t.TempDir()}); err == nil {
		t.Fatal("Prepare accepted an empty target, want an error")
	}
	if _, err := Prepare(Config{Target: "192.0.2.1", Ports: "notaport", OutDir: t.TempDir()}); err == nil {
		t.Fatal("Prepare accepted an invalid port list, want an error")
	}
}

func TestPrepareFallsBackWhenDefaultRootIsUnwritable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// A regular file cannot be turned into a directory, so MkdirAll fails
	// deterministically regardless of the privileges of the test user.
	blocker := filepath.Join(t.TempDir(), "blocked")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatalf("create blocker file: %v", err)
	}
	unwritable := filepath.Join(blocker, "nested")
	session, err := Prepare(Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		ConnectTimeout: 50 * time.Millisecond,
		VNCTimeout:     50 * time.Millisecond,
		Workers:        1,
		OutDir:         unwritable,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if session.FallbackWarning() == "" {
		t.Fatal("fallback was used but no warning was produced")
	}
	if !strings.HasPrefix(session.RunDir, filepath.Join(home, ".local", "share", "vncshot")) {
		t.Errorf("run dir %q is not inside the per-user fallback", session.RunDir)
	}
}

// A cancelled scan must still return the partial results it collected.
func TestScanCancelledReturnsPartialResults(t *testing.T) {
	base := t.TempDir()
	session, err := Prepare(Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		ConnectTimeout: 5 * time.Second,
		VNCTimeout:     5 * time.Second,
		Workers:        1,
		RatePerSec:     1,
		OutDir:         base,
		OutDirExplicit: true,
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out, err := session.Scan(ctx, nil)
	if err == nil {
		t.Fatal("Scan returned no error for a cancelled context")
	}
	if len(out.Results) > len(session.Targets) {
		t.Errorf("Scan returned %d results for %d targets", len(out.Results), len(session.Targets))
	}
	if out.RunDir != session.RunDir {
		t.Errorf("outcome run dir = %q, want %q", out.RunDir, session.RunDir)
	}
}

// TestCreateRunDirNeverCollides guards the data-loss path: two scans that
// start within the same second must not share a run folder, otherwise the
// second scan overwrites the first one's reports and screenshots.
func TestCreateRunDirNeverCollides(t *testing.T) {
	base := t.TempDir()

	first, err := createRunDir(base)
	if err != nil {
		t.Fatalf("createRunDir: %v", err)
	}
	// Mark the first run so an overwrite would be observable.
	if err := os.WriteFile(filepath.Join(first, "vncshot_report.json"), []byte("first"), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	second, err := createRunDir(base)
	if err != nil {
		t.Fatalf("createRunDir: %v", err)
	}
	if first == second {
		t.Fatalf("second scan reused %q; reports would be overwritten", first)
	}

	// The first run must be untouched, and both must keep the documented
	// timestamp layout so the GUI history and baseline comparison find them.
	data, err := os.ReadFile(filepath.Join(first, "vncshot_report.json"))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(data) != "first" {
		t.Errorf("first run marker = %q, want it unchanged", data)
	}
	for _, dir := range []string{first, second} {
		name := filepath.Base(dir)
		if _, err := time.ParseInLocation(RunTimestampLayout, name, time.Local); err != nil {
			t.Errorf("run folder %q does not match the timestamp layout: %v", name, err)
		}
	}
}

// TestCreateRunDirCreatesMissingBase covers a report root that does not exist
// yet: os.Mkdir on the run folder alone would fail with ENOENT.
func TestCreateRunDirCreatesMissingBase(t *testing.T) {
	base := filepath.Join(t.TempDir(), "nested", "reports")

	dir, err := createRunDir(base)
	if err != nil {
		t.Fatalf("createRunDir: %v", err)
	}
	if filepath.Dir(dir) != base {
		t.Errorf("run dir %q is not inside %q", dir, base)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat run dir: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("run dir permissions = %o, want owner-only", mode)
	}
}

// TestPrepareRejectsResourceExhaustionValues guards the shared validation:
// the GUI posts these values straight from a form, so an unbounded worker
// count used to spawn goroutines until the process ran out of sockets.
func TestPrepareRejectsResourceExhaustionValues(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"negative workers", Config{Workers: -1}},
		{"huge workers", Config{Workers: 1_000_000}},
		{"huge rate", Config{RatePerSec: 50_000_000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Target = "192.0.2.1"
			cfg.Ports = "5900"
			cfg.OutDir = t.TempDir()
			cfg.OutDirExplicit = true

			if _, err := Prepare(cfg); err == nil {
				t.Fatal("Prepare accepted an out-of-range value, want an error")
			}
		})
	}
}

// TestPrepareAllowsUpperBounds pins the accepted edge so the guard cannot
// drift into rejecting legitimate values.
func TestPrepareAllowsUpperBounds(t *testing.T) {
	cfg := Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		Workers:        scanner.MaxWorkers,
		RatePerSec:     scanner.MaxRate,
		OutDir:         t.TempDir(),
		OutDirExplicit: true,
	}
	if _, err := Prepare(cfg); err != nil {
		t.Fatalf("Prepare rejected the documented maximum: %v", err)
	}
}
