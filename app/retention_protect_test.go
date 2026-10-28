package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPruneRunsProtectsResumeSource proves the resume source survives
// retention even though it is old enough to fall in the removed set. A
// resumed run keeps referencing the previous run's screenshots, so losing
// that directory would break the evidence chain.
func TestPruneRunsProtectsResumeSource(t *testing.T) {
	root := t.TempDir()
	base := runStart()
	oldest := makeRun(t, root, runName(base))
	middle := makeRun(t, root, runName(base.Add(time.Minute)))
	newest := makeRun(t, root, runName(base.Add(2*time.Minute)))

	// Protected by a full path, as the -resume flag supplies it.
	removed, err := PruneRuns(root, 2, false, oldest)
	if err != nil {
		t.Fatalf("PruneRuns: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %+v, want no run because keep=2 covers all", removed)
	}

	// keep=1 both removes the middle run and would remove the protected
	// oldest one; protection must keep the oldest and remove the middle.
	mustWrite(t, filepath.Join(oldest, "vncshot_report.json"), "old")
	removed, err = PruneRuns(root, 1, false, oldest)
	if err != nil {
		t.Fatalf("PruneRuns: %v", err)
	}
	if len(removed) != 1 || removed[0].Name != filepath.Base(middle) {
		t.Fatalf("removed = %+v, want only %q", removed, filepath.Base(middle))
	}
	if _, err := os.Stat(middle); !os.IsNotExist(err) {
		t.Errorf("middle run %s still exists", middle)
	}
	if _, err := os.Stat(oldest); err != nil {
		t.Errorf("protected run %s was removed: %v", oldest, err)
	}
	if _, err := os.Stat(newest); err != nil {
		t.Errorf("newest run %s was removed: %v", newest, err)
	}

	// Dry run with protection reports only unprotected stale runs.
	dry, err := PruneRuns(root, 1, true, oldest)
	if err != nil {
		t.Fatalf("PruneRuns dry run: %v", err)
	}
	if len(dry) != 0 {
		t.Fatalf("dry run removed = %+v, want only the protected run filtered out", dry)
	}
}

// TestPruneRunsProtectedByBaseName checks the bare run folder name form.
func TestPruneRunsProtectedByBaseName(t *testing.T) {
	root := t.TempDir()
	base := runStart()
	oldest := makeRun(t, root, runName(base))
	middle := makeRun(t, root, runName(base.Add(time.Minute)))

	removed, err := PruneRuns(root, 1, false, filepath.Base(oldest))
	if err != nil {
		t.Fatalf("PruneRuns: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %+v, want none because the stale run is protected", removed)
	}
	if _, err := os.Stat(oldest); err != nil {
		t.Errorf("protected run %s was removed: %v", oldest, err)
	}
	for _, dir := range []string{middle} {
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("directory %s was removed: %v", dir, err)
		}
	}
}
