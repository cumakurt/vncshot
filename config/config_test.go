package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newFlags builds a FlagSet shaped like the real CLI but small enough to
// reason about.
func newFlags() (*flag.FlagSet, *struct {
	outDir  string
	workers int
	timeout time.Duration
	shared  bool
}) {
	target := &struct {
		outDir  string
		workers int
		timeout time.Duration
		shared  bool
	}{outDir: "/usr/local/vncshot", workers: 150, timeout: time.Second, shared: true}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.StringVar(&target.outDir, "out-dir", target.outDir, "")
	fs.IntVar(&target.workers, "workers", target.workers, "")
	fs.DurationVar(&target.timeout, "timeout", target.timeout, "")
	fs.BoolVar(&target.shared, "shared", target.shared, "")
	return fs, target
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadEmptyPath(t *testing.T) {
	values, err := Load("   ")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(values) != 0 {
		t.Errorf("Load returned %d values for an empty path, want 0", len(values))
	}
}

func TestLoadJSON(t *testing.T) {
	path := writeFile(t, "config.json", `{"out-dir": "/srv/reports", "workers": 42, "shared": false}`)
	values, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := values["out-dir"]; got != "/srv/reports" {
		t.Errorf("out-dir = %v, want /srv/reports", got)
	}
	if got := values["workers"]; got != float64(42) {
		t.Errorf("workers = %v, want 42", got)
	}
	if got := values["shared"]; got != false {
		t.Errorf("shared = %v, want false", got)
	}
}

func TestLoadSimpleYAML(t *testing.T) {
	content := strings.Join([]string{
		"# scan defaults",
		"---",
		"out-dir: /srv/vncshot",
		"workers: 200",
		"timeout: 750ms",
		`shared: "false"`,
		"",
		"# trailing comment",
		"target: 10.0.0.0/24 # inline comment",
	}, "\n")
	values, err := Load(writeFile(t, "config.yml", content))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if values["out-dir"] != "/srv/vncshot" {
		t.Errorf("out-dir = %v", values["out-dir"])
	}
	if values["workers"] != int64(200) {
		t.Errorf("workers = %v (%T), want int64 200", values["workers"], values["workers"])
	}
	if values["timeout"] != "750ms" {
		t.Errorf("timeout = %v, want 750ms", values["timeout"])
	}
	if values["shared"] != "false" {
		t.Errorf("shared = %v, want the quoted string false", values["shared"])
	}
	if values["target"] != "10.0.0.0/24" {
		t.Errorf("target = %v, want the inline comment stripped", values["target"])
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yml")); err == nil {
		t.Fatal("Load accepted a missing file, want an error")
	}
}

func TestLoadMalformedLine(t *testing.T) {
	path := writeFile(t, "bad.yml", "this line has no separator\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a malformed line, want an error")
	}
}

func TestLoadRejectsDuplicateKey(t *testing.T) {
	path := writeFile(t, "dup.yml", "workers: 10\nworkers: 20\n")
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a duplicate key, want an error")
	}
}

func TestLoadRejectsMalformedJSON(t *testing.T) {
	if _, err := Load(writeFile(t, "bad.json", `{"workers": }`)); err == nil {
		t.Fatal("Load accepted malformed JSON, want an error")
	}
}

func TestApplyConfigValues(t *testing.T) {
	fs, target := newFlags()
	if err := Apply(fs, map[string]any{
		"out-dir": "/srv/reports",
		"workers": int64(30),
		"timeout": "2s",
		"shared":  false,
	}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if target.outDir != "/srv/reports" {
		t.Errorf("out-dir = %q", target.outDir)
	}
	if target.workers != 30 {
		t.Errorf("workers = %d", target.workers)
	}
	if target.timeout != 2*time.Second {
		t.Errorf("timeout = %v", target.timeout)
	}
	if target.shared {
		t.Error("shared = true, want false from config")
	}
}

func TestApplyRejectsUnknownKey(t *testing.T) {
	fs, _ := newFlags()
	err := Apply(fs, map[string]any{"nonsense": "x"})
	if err == nil {
		t.Fatal("Apply accepted an unknown key, want an error")
	}
	if !strings.Contains(err.Error(), "nonsense") {
		t.Errorf("error %q does not name the offending key", err)
	}
}

func TestApplyRejectsInvalidValue(t *testing.T) {
	fs, _ := newFlags()
	if err := Apply(fs, map[string]any{"workers": "many"}); err == nil {
		t.Fatal("Apply accepted a non-numeric worker count, want an error")
	}
}

func TestApplyPrecedenceCLIWins(t *testing.T) {
	fs, target := newFlags()
	if err := fs.Parse([]string{"-workers", "7"}); err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Setenv("VNCSHOT_WORKERS", "11")

	if err := Apply(fs, map[string]any{"workers": int64(99), "out-dir": "/from/file"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if target.workers != 7 {
		t.Errorf("workers = %d, want the CLI value 7", target.workers)
	}
	if target.outDir != "/from/file" {
		t.Errorf("out-dir = %q, want the config value where no flag was set", target.outDir)
	}
}

func TestApplyPrecedenceEnvBeatsConfig(t *testing.T) {
	fs, target := newFlags()
	t.Setenv("VNCSHOT_WORKERS", "11")

	if err := Apply(fs, map[string]any{"workers": int64(99)}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if target.workers != 11 {
		t.Errorf("workers = %d, want the environment value 11", target.workers)
	}
}

func TestApplyEnvironmentNameMapping(t *testing.T) {
	fs, target := newFlags()
	t.Setenv("VNCSHOT_OUT_DIR", "/env/reports")
	t.Setenv("VNCSHOT_SHARED", "false")

	if err := Apply(fs, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if target.outDir != "/env/reports" {
		t.Errorf("out-dir = %q, want the -/_ mapped environment value", target.outDir)
	}
	if target.shared {
		t.Error("shared = true, want false from VNCSHOT_SHARED")
	}
}

func TestApplyInvalidEnvironmentValue(t *testing.T) {
	fs, _ := newFlags()
	t.Setenv("VNCSHOT_WORKERS", "not-a-number")
	err := Apply(fs, nil)
	if err == nil {
		t.Fatal("Apply accepted an invalid environment value, want an error")
	}
	if !strings.Contains(err.Error(), "VNCSHOT_WORKERS") {
		t.Errorf("error %q does not name the environment variable", err)
	}
}

func TestFormatValueKeepsIntegralFloatsIntegral(t *testing.T) {
	got, err := formatValue(float64(200))
	if err != nil {
		t.Fatalf("formatValue: %v", err)
	}
	if got != "200" {
		t.Errorf("formatValue(200.0) = %q, want 200", got)
	}
}

func TestLoadAndApplyRoundTrip(t *testing.T) {
	path := writeFile(t, "config.yml", "workers: 12\nshared: false\n")

	values, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fs, target := newFlags()
	if err := Apply(fs, values); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if target.workers != 12 || target.shared {
		t.Errorf("target = %+v, want workers 12 and shared false", target)
	}
}
