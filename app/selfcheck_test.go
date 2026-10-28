package app

import (
	"os"
	"path/filepath"
	"testing"
)

// selfcheckNames is the fixed order SelfCheck must report.
var selfcheckNames = []string{
	"root",
	"report_root",
	"tls_roots",
	"browser",
	"clock",
	"loopback",
	"disk_space",
}

func TestSelfCheckNamesAndOrder(t *testing.T) {
	checks := SelfCheck(SelfCheckOptions{ReportRoot: t.TempDir()})
	if len(checks) != len(selfcheckNames) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(selfcheckNames), checks)
	}
	for i, want := range selfcheckNames {
		if checks[i].Name != want {
			t.Fatalf("check %d: name %q, want %q", i, checks[i].Name, want)
		}
		switch checks[i].Status {
		case StatusOK, StatusWarn, StatusFail:
		default:
			t.Fatalf("check %d (%s): unexpected status %q", i, checks[i].Name, checks[i].Status)
		}
		if checks[i].Detail == "" {
			t.Errorf("check %d (%s): empty detail", i, checks[i].Name)
		}
	}
}

// Determinism: two runs against the same root produce the same names in the
// same order.
func TestSelfCheckDeterministic(t *testing.T) {
	root := t.TempDir()
	first := SelfCheck(SelfCheckOptions{ReportRoot: root})
	second := SelfCheck(SelfCheckOptions{ReportRoot: root})
	if len(first) != len(second) {
		t.Fatalf("runs differ in length: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].Name != second[i].Name || first[i].Status != second[i].Status {
			t.Fatalf("run %d: got %s/%s then %s/%s",
				i, first[i].Name, first[i].Status, second[i].Name, second[i].Status)
		}
	}
}

func TestSelfCheckRootMatchesEuid(t *testing.T) {
	checks := SelfCheck(SelfCheckOptions{ReportRoot: t.TempDir()})
	check := findCheck(t, checks, "root")
	want := StatusFail
	if os.Geteuid() == 0 {
		want = StatusOK
	}
	if check.Status != want {
		t.Fatalf("root status %q, want %q for euid %d", check.Status, want, os.Geteuid())
	}
}

func TestSelfCheckReportRootWritable(t *testing.T) {
	root := t.TempDir()
	check := findCheck(t, SelfCheck(SelfCheckOptions{ReportRoot: root}), "report_root")
	if check.Status != StatusOK {
		t.Fatalf("report_root status %q (detail %q), want ok", check.Status, check.Detail)
	}

	// A report root that does not exist yet must be created, so the check
	// still passes against a deep missing path.
	missing := filepath.Join(t.TempDir(), "a", "b", "c")
	check = findCheck(t, SelfCheck(SelfCheckOptions{ReportRoot: missing}), "report_root")
	if check.Status != StatusOK {
		t.Fatalf("report_root on missing parent status %q (detail %q), want ok", check.Status, check.Detail)
	}
}

func TestSelfCheckReportRootNotADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Creating a directory under an existing file fails regardless of
	// privileges, so this exercises the fail path deterministically.
	check := findCheck(t, SelfCheck(SelfCheckOptions{ReportRoot: filepath.Join(file, "sub")}), "report_root")
	if check.Status != StatusFail {
		t.Fatalf("report_root status %q (detail %q), want fail", check.Status, check.Detail)
	}
}

func TestSelfCheckEmptyReportRoot(t *testing.T) {
	checks := SelfCheck(SelfCheckOptions{ReportRoot: ""})
	root := findCheck(t, checks, "report_root")
	if root.Status != StatusWarn {
		t.Fatalf("report_root status %q (detail %q), want warn for empty root", root.Status, root.Detail)
	}
	space := findCheck(t, checks, "disk_space")
	if space.Status != StatusWarn {
		t.Fatalf("disk_space status %q (detail %q), want warn for empty root", space.Status, space.Detail)
	}
}

// The writability probe must leave the report root exactly as it was.
func TestSelfCheckProbeFileCleanedUp(t *testing.T) {
	root := t.TempDir()
	SelfCheck(SelfCheckOptions{ReportRoot: root})
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("report root not empty after selfcheck: %d entries (%v)", len(entries), entries)
	}
}

func TestSelfCheckLoopbackOK(t *testing.T) {
	check := findCheck(t, SelfCheck(SelfCheckOptions{ReportRoot: t.TempDir()}), "loopback")
	if check.Status != StatusOK {
		t.Fatalf("loopback status %q (detail %q), want ok", check.Status, check.Detail)
	}
}

func TestSelfCheckTLSRootsNotFail(t *testing.T) {
	// Normal containers have either a system pool or none; neither is a
	// hard failure because scanning still works with self-signed peers.
	check := findCheck(t, SelfCheck(SelfCheckOptions{ReportRoot: t.TempDir()}), "tls_roots")
	if check.Status == StatusFail {
		t.Fatalf("tls_roots unexpectedly failed: %q", check.Detail)
	}
}

func TestSelfCheckDiskSpaceOnTempDir(t *testing.T) {
	check := findCheck(t, SelfCheck(SelfCheckOptions{ReportRoot: t.TempDir()}), "disk_space")
	// A temp filesystem is usually fine; a small tmpfs may legitimately warn.
	if check.Status == StatusFail {
		t.Fatalf("disk_space unexpectedly failed on temp dir: %q", check.Detail)
	}
}

func findCheck(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in %+v", name, checks)
	return Check{}
}
