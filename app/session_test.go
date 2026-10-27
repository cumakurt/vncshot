package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	for _, path := range []string{session.JSONPath, session.HTMLPath, session.PDFPath} {
		if filepath.Dir(path) != session.RunDir {
			t.Errorf("artifact %q is not inside the run directory %q", path, session.RunDir)
		}
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
