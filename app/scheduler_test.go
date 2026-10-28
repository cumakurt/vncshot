package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// mustCreateRunDir makes a run directory whose name parses with the
// RunTimestampLayout, plus an optional report file inside it.
func mustCreateRunDir(t *testing.T, root, name string, withReport bool) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create run directory %s: %v", dir, err)
	}
	if withReport {
		if err := os.WriteFile(filepath.Join(dir, "vncshot_report.json"), []byte("{}"), 0o600); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}
	return dir
}

func TestPreviousRunEmptyRoot(t *testing.T) {
	dir, ok, err := PreviousRun(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("PreviousRun on missing root: %v", err)
	}
	if ok {
		t.Errorf("PreviousRun reported a run for an empty root: %s", dir)
	}
}

func TestPreviousRunIgnoresHalfWrittenAndForeignEntries(t *testing.T) {
	root := t.TempDir()
	mustCreateRunDir(t, root, "20260102-150401", true)
	// Newest run has no report yet: it must be skipped, not chosen.
	mustCreateRunDir(t, root, "20260102-150402", false)
	// Non-timestamp names are not run directories at all.
	if err := os.Mkdir(filepath.Join(root, "notes"), 0o700); err != nil {
		t.Fatalf("create foreign directory: %v", err)
	}

	dir, ok, err := PreviousRun(root)
	if err != nil {
		t.Fatalf("PreviousRun: %v", err)
	}
	if !ok {
		t.Fatal("PreviousRun did not find the completed run")
	}
	if want := filepath.Join(root, "20260102-150401"); dir != want {
		t.Errorf("PreviousRun = %s, want %s", dir, want)
	}
}

func TestPreviousRunNewestCompletedWins(t *testing.T) {
	root := t.TempDir()
	mustCreateRunDir(t, root, "20260102-150401", true)
	mustCreateRunDir(t, root, "20260102-150402", false)
	newest := mustCreateRunDir(t, root, "20260102-150403", true)

	dir, ok, err := PreviousRun(root)
	if err != nil {
		t.Fatalf("PreviousRun: %v", err)
	}
	if !ok || dir != newest {
		t.Errorf("PreviousRun = (%q, %v), want (%q, true)", dir, ok, newest)
	}
}

func TestPreviousRunNoCompletedRun(t *testing.T) {
	root := t.TempDir()
	mustCreateRunDir(t, root, "20260102-150401", false)
	if _, ok, err := PreviousRun(root); err != nil || ok {
		t.Errorf("PreviousRun = (ok %v, err %v), want (false, nil)", ok, err)
	}
}

func TestScheduleDelay(t *testing.T) {
	lastRound := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC)
	interval := 24 * time.Hour

	tests := []struct {
		name string
		now  time.Time
		want time.Duration
	}{
		{"mid interval", lastRound.Add(20 * time.Minute), interval - 20*time.Minute},
		{"exact boundary", lastRound.Add(interval), 0},
		{"overrun", lastRound.Add(25 * time.Hour), 0},
		{"long overrun", lastRound.Add(72 * time.Hour), 0},
		{"before last round", lastRound.Add(-time.Hour), interval + time.Hour},
		{"zero interval", lastRound, 0},
		{"negative interval", lastRound, 0},
	}
	for _, tc := range tests {
		var used time.Duration
		switch tc.name {
		case "zero interval":
			used = 0
		case "negative interval":
			used = -time.Minute
		default:
			used = interval
		}
		if got := ScheduleDelay(used, lastRound, tc.now); got != tc.want {
			t.Errorf("%s: ScheduleDelay = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestScheduleDelayStaysFixedFromRoundStart documents the fixed-schedule
// property: the delay compensates for the round duration, so round starts
// stay interval apart even when a round takes 20 minutes of a 24h interval.
func TestScheduleDelayStaysFixedFromRoundStart(t *testing.T) {
	interval := 24 * time.Hour
	lastRound := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	roundDuration := 20 * time.Minute

	now := lastRound.Add(roundDuration)
	delay := ScheduleDelay(interval, lastRound, now)
	if delay != interval-roundDuration {
		t.Fatalf("delay = %v, want %v", delay, interval-roundDuration)
	}
	if next := now.Add(delay); !next.Equal(lastRound.Add(interval)) {
		t.Errorf("next round start = %v, want %v", next, lastRound.Add(interval))
	}
}
