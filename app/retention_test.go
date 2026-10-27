package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// runName returns the timestamp folder name for an arbitrary instant.
func runName(at time.Time) string {
	return at.Format(RunTimestampLayout)
}

// makeRun creates a run directory with the given name below root.
func makeRun(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create run directory %s: %v", dir, err)
	}
	return dir
}

// mustWrite writes content to path, creating parent directories.
func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("create parent of %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// runStart stamps deterministic, ordered run directory names.
func runStart() time.Time {
	return time.Date(2024, 1, 2, 3, 4, 5, 0, time.Local)
}

func TestListRunsNewestFirstAndSkipsNonRuns(t *testing.T) {
	root := t.TempDir()
	base := runStart()

	oldest := makeRun(t, root, runName(base))
	middle := makeRun(t, root, runName(base.Add(time.Minute)))
	newest := makeRun(t, root, runName(base.Add(2*time.Minute)))

	// Only regular files count towards size and file count.
	mustWrite(t, filepath.Join(newest, "report.json"), "hello")               // 5 bytes
	mustWrite(t, filepath.Join(newest, "screenshots", "shot.png"), "nested!") // 7 bytes
	if oldest == middle || middle == newest {
		t.Fatal("run directories must be distinct")
	}

	// A symlinked directory with a run-like name must be ignored, and a
	// symlinked file inside a run must not contribute to its usage.
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "big.bin"), string(make([]byte, 128)))
	if err := os.Symlink(outside, filepath.Join(root, runName(base.Add(3*time.Minute)))); err != nil {
		t.Fatalf("create symlinked run: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "big.bin"), filepath.Join(newest, "linked.bin")); err != nil {
		t.Fatalf("create symlinked file: %v", err)
	}

	// Unrelated directories, plain files and malformed names are ignored.
	makeRun(t, root, "unrelated")
	mustWrite(t, filepath.Join(root, "notes.txt"), "keep me")
	mustWrite(t, filepath.Join(root, "2024-01-02"), "not a run")

	runs, err := ListRuns(root)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	want := []string{filepath.Base(newest), filepath.Base(middle), filepath.Base(oldest)}
	if len(runs) != len(want) {
		t.Fatalf("ListRuns returned %d runs, want %d: %+v", len(runs), len(want), runs)
	}
	for i, name := range want {
		if runs[i].Name != name {
			t.Errorf("run %d = %q, want %q", i, runs[i].Name, name)
		}
	}
	if runs[0].Size != 12 || runs[0].Files != 2 {
		t.Errorf("newest run usage = %d bytes / %d files, want 12 / 2", runs[0].Size, runs[0].Files)
	}
	if runs[1].Size != 0 || runs[1].Files != 0 {
		t.Errorf("empty run usage = %d bytes / %d files, want 0 / 0", runs[1].Size, runs[1].Files)
	}
	if !runs[0].Started.After(runs[1].Started) || !runs[1].Started.After(runs[2].Started) {
		t.Errorf("runs are not newest first: %+v", runs)
	}
}

func TestListRunsMissingRootIsEmpty(t *testing.T) {
	runs, err := ListRuns(filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatalf("ListRuns on a missing root: %v", err)
	}
	if len(runs) != 0 {
		t.Errorf("ListRuns returned %d runs for a missing root, want 0", len(runs))
	}
}

func TestPruneRunsKeepsNewest(t *testing.T) {
	root := t.TempDir()
	base := runStart()
	oldest := makeRun(t, root, runName(base))
	middle := makeRun(t, root, runName(base.Add(time.Minute)))
	newest := makeRun(t, root, runName(base.Add(2*time.Minute)))
	unrelated := makeRun(t, root, "archive")
	mustWrite(t, filepath.Join(root, "notes.txt"), "keep me")
	mustWrite(t, filepath.Join(oldest, "vncshot_report.json"), "old")
	mustWrite(t, filepath.Join(unrelated, "index.json"), "unrelated")

	removed, err := PruneRuns(root, 2, false)
	if err != nil {
		t.Fatalf("PruneRuns: %v", err)
	}
	if len(removed) != 1 || removed[0].Name != filepath.Base(oldest) {
		t.Fatalf("removed = %+v, want only %q", removed, filepath.Base(oldest))
	}
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Errorf("oldest run %s still exists", oldest)
	}
	for _, dir := range []string{middle, newest, unrelated} {
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("directory %s was removed: %v", dir, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "notes.txt")); err != nil {
		t.Errorf("plain file was removed: %v", err)
	}
}

func TestPruneRunsDryRunDeletesNothing(t *testing.T) {
	root := t.TempDir()
	base := runStart()
	dirs := []string{
		makeRun(t, root, runName(base)),
		makeRun(t, root, runName(base.Add(time.Minute))),
		makeRun(t, root, runName(base.Add(2*time.Minute))),
	}

	dry, err := PruneRuns(root, 1, true)
	if err != nil {
		t.Fatalf("PruneRuns dry run: %v", err)
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("dry run removed %s: %v", dir, err)
		}
	}
	if len(dry) != 2 {
		t.Fatalf("dry run returned %d runs, want 2", len(dry))
	}

	real, err := PruneRuns(root, 1, false)
	if err != nil {
		t.Fatalf("PruneRuns: %v", err)
	}
	if len(real) != len(dry) {
		t.Fatalf("real prune returned %d runs, want %d", len(real), len(dry))
	}
	for i := range dry {
		if dry[i].Name != real[i].Name {
			t.Errorf("run %d = %q, want the dry run's %q", i, real[i].Name, dry[i].Name)
		}
	}
	runs, err := ListRuns(root)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].Name != filepath.Base(dirs[2]) {
		t.Fatalf("remaining runs = %+v, want only the newest", runs)
	}
}

func TestPruneRunsRejectsUnsafeRequests(t *testing.T) {
	root := t.TempDir()
	base := runStart()
	makeRun(t, root, runName(base))
	makeRun(t, root, runName(base.Add(time.Minute)))

	if _, err := PruneRuns(root, -1, false); err == nil {
		t.Error("PruneRuns accepted a negative keep, want an error")
	}
	if _, err := PruneRuns(root, 0, false); err == nil {
		t.Error("PruneRuns accepted keep 0, want an error")
	}
	if _, err := PruneRuns("/tmp", 1, true); err == nil {
		t.Error("PruneRuns accepted the /tmp root, want an error")
	}

	link := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatalf("create root symlink: %v", err)
	}
	if _, err := PruneRuns(link, 1, false); err == nil {
		t.Error("PruneRuns accepted a symlinked root, want an error")
	}
	if runs, err := ListRuns(root); err != nil || len(runs) != 2 {
		t.Errorf("symlinked root prune changed the runs: %d runs, err %v", len(runs), err)
	}
}

func TestPruneRunsNeverRemovesNonRunEntries(t *testing.T) {
	root := t.TempDir()
	base := runStart()
	newest := makeRun(t, root, runName(base.Add(time.Minute)))
	makeRun(t, root, runName(base))
	unrelated := makeRun(t, root, "unrelated")
	mustWrite(t, filepath.Join(root, "notes.txt"), "keep me")
	mustWrite(t, filepath.Join(unrelated, "data.txt"), "keep me too")

	if _, err := PruneRuns(root, 1, false); err != nil {
		t.Fatalf("PruneRuns: %v", err)
	}
	for _, path := range []string{unrelated, filepath.Join(root, "notes.txt"), filepath.Join(unrelated, "data.txt"), newest} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s was removed: %v", path, err)
		}
	}
}

func TestScanPrunesOlderRuns(t *testing.T) {
	base := t.TempDir()
	port := closedLocalPorts(t, 1)[0]

	cfg := Config{
		Target:         "127.0.0.1",
		Ports:          fmt.Sprintf("%d", port),
		ConnectTimeout: 200 * time.Millisecond,
		VNCTimeout:     200 * time.Millisecond,
		Workers:        1,
		OutDir:         base,
		OutDirExplicit: true,
		NoPDF:          true,
	}

	first, err := Prepare(cfg)
	if err != nil {
		t.Fatalf("Prepare first: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := first.Scan(ctx, nil); err != nil {
		t.Fatalf("Scan first: %v", err)
	}

	cfg.KeepRuns = 1
	second, err := Prepare(cfg)
	if err != nil {
		t.Fatalf("Prepare second: %v", err)
	}
	out, err := second.Scan(ctx, nil)
	if err != nil {
		t.Fatalf("Scan second: %v", err)
	}

	if out.Warning != "" {
		t.Errorf("unexpected retention warning: %s", out.Warning)
	}
	if _, err := os.Stat(first.RunDir); !os.IsNotExist(err) {
		t.Errorf("older run %s still exists", first.RunDir)
	}
	if _, err := os.Stat(second.RunDir); err != nil {
		t.Errorf("newest run %s is missing: %v", second.RunDir, err)
	}
	runs, err := ListRuns(second.ReportRoot())
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].Name != filepath.Base(second.RunDir) {
		t.Fatalf("remaining runs = %+v, want only %q", runs, filepath.Base(second.RunDir))
	}
	if len(out.RemovedRuns) != 1 || out.RemovedRuns[0].Name != filepath.Base(first.RunDir) {
		t.Errorf("RemovedRuns = %+v, want only %q", out.RemovedRuns, filepath.Base(first.RunDir))
	}
}
