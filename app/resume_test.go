package app

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"vncshot/report"
	"vncshot/scanner"
)

func TestLoadCompletedReadsResults(t *testing.T) {
	dir := t.TempDir()
	results := []report.Result{
		{IP: "192.0.2.1", Port: 5900, Open: true, RFB: true},
		{IP: "192.0.2.2", Port: 5901},
	}
	if err := report.WriteJSONDocument(filepath.Join(dir, BaselineFilename), results, report.Options{}, report.DocumentOptions{}); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}

	loaded, err := LoadCompleted(dir)
	if err != nil {
		t.Fatalf("LoadCompleted: %v", err)
	}
	if len(loaded) != len(results) {
		t.Fatalf("loaded %d results, want %d", len(loaded), len(results))
	}
	for i := range results {
		if loaded[i].Addr() != results[i].Addr() {
			t.Errorf("result %d = %s, want %s", i, loaded[i].Addr(), results[i].Addr())
		}
	}
}

func TestLoadCompletedErrors(t *testing.T) {
	t.Run("missing report", func(t *testing.T) {
		if _, err := LoadCompleted(t.TempDir()); err == nil {
			t.Fatal("LoadCompleted accepted a directory without a report")
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, BaselineFilename), []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if _, err := LoadCompleted(dir); err == nil {
			t.Fatal("LoadCompleted accepted invalid JSON")
		}
	})

	t.Run("regular file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "run.json")
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if _, err := LoadCompleted(path); err == nil {
			t.Fatal("LoadCompleted accepted a regular file as a run directory")
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		if _, err := LoadCompleted(filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("LoadCompleted accepted a missing directory")
		}
	})
}

func TestResumePlan(t *testing.T) {
	scope := []scanner.Target{
		{IP: "192.0.2.1", Port: 5900},
		{IP: "192.0.2.2", Port: 5900},
		{IP: "192.0.2.3", Port: 5900},
	}

	cases := []struct {
		name      string
		previous  []report.Result
		remaining []string
		reused    []string
	}{
		{
			name: "only completed targets are skipped",
			previous: []report.Result{
				{IP: "192.0.2.1", Port: 5900},
				{IP: "192.0.2.3", Port: 5900},
			},
			remaining: []string{"192.0.2.2:5900"},
			reused:    []string{"192.0.2.1:5900", "192.0.2.3:5900"},
		},
		{
			name: "results outside the new scope are dropped",
			previous: []report.Result{
				{IP: "192.0.2.1", Port: 5900},
				{IP: "198.51.100.7", Port: 5900},
				{IP: "192.0.2.1", Port: 5901},
			},
			remaining: []string{"192.0.2.2:5900", "192.0.2.3:5900"},
			reused:    []string{"192.0.2.1:5900"},
		},
		{
			name: "fully completed scope has nothing remaining",
			previous: []report.Result{
				{IP: "192.0.2.1", Port: 5900},
				{IP: "192.0.2.2", Port: 5900},
				{IP: "192.0.2.3", Port: 5900},
			},
			remaining: nil,
			reused:    []string{"192.0.2.1:5900", "192.0.2.2:5900", "192.0.2.3:5900"},
		},
		{
			name:      "empty previous run scans everything",
			previous:  nil,
			remaining: []string{"192.0.2.1:5900", "192.0.2.2:5900", "192.0.2.3:5900"},
			reused:    nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			remaining, reused, err := ResumePlan(tc.previous, scope)
			if err != nil {
				t.Fatalf("ResumePlan: %v", err)
			}
			if got := addressesOfTargets(remaining); !equalStrings(got, tc.remaining) {
				t.Errorf("remaining = %v, want %v", got, tc.remaining)
			}
			if got := addressesOfResults(reused); !equalStrings(got, tc.reused) {
				t.Errorf("reused = %v, want %v", got, tc.reused)
			}
		})
	}
}

func TestResumePlanDeduplicatesPreviousResults(t *testing.T) {
	scope := []scanner.Target{{IP: "192.0.2.1", Port: 5900}}
	previous := []report.Result{
		{IP: "192.0.2.1", Port: 5900, Open: true},
		{IP: "192.0.2.1", Port: 5900, Open: false},
	}

	remaining, reused, err := ResumePlan(previous, scope)
	if err != nil {
		t.Fatalf("ResumePlan: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("remaining = %d, want 0", len(remaining))
	}
	if len(reused) != 1 {
		t.Fatalf("reused = %d results, want 1", len(reused))
	}
	if !reused[0].Open {
		t.Error("ResumePlan kept the later duplicate instead of the first observation")
	}
}

func TestPrepareRejectsResumeWithBaseline(t *testing.T) {
	cfg := Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		OutDir:         t.TempDir(),
		OutDirExplicit: true,
		ResumeDir:      t.TempDir(),
		Baseline:       t.TempDir(),
	}
	_, err := Prepare(cfg)
	if err == nil {
		t.Fatal("Prepare accepted -resume together with -baseline")
	}
	if !strings.Contains(err.Error(), "-resume") || !strings.Contains(err.Error(), "-baseline") {
		t.Errorf("error %q does not name both flags", err)
	}
}

func TestPrepareRejectsBrokenResumeBeforeCreatingRunDir(t *testing.T) {
	base := filepath.Join(t.TempDir(), "reports")
	cfg := Config{
		Target:         "192.0.2.1",
		Ports:          "5900",
		OutDir:         base,
		OutDirExplicit: true,
		ResumeDir:      t.TempDir(),
	}
	if _, err := Prepare(cfg); err == nil {
		t.Fatal("Prepare accepted a resume directory without a report")
	}
	if _, err := os.Stat(base); !os.IsNotExist(err) {
		t.Errorf("run root %q was created before the resume source was validated", base)
	}
}

// TestScanResumeReusesCompletedTargets runs one scan over three closed local
// ports and then resumes it with a scope that adds a fourth port, checking
// that only the missing target is probed and every artifact covers the full
// scope.
func TestScanResumeReusesCompletedTargets(t *testing.T) {
	ports := closedLocalPorts(t, 4)
	firstPorts := ports[:3]
	missingPort := ports[3]

	first, err := Prepare(Config{
		Target:         "127.0.0.1",
		Ports:          fmt.Sprintf("%d,%d,%d", firstPorts[0], firstPorts[1], firstPorts[2]),
		ConnectTimeout: 200 * time.Millisecond,
		VNCTimeout:     200 * time.Millisecond,
		Workers:        2,
		OutDir:         t.TempDir(),
		OutDirExplicit: true,
		NoPDF:          true,
	})
	if err != nil {
		t.Fatalf("Prepare first run: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	firstOut, err := first.Scan(ctx, nil)
	if err != nil {
		t.Fatalf("Scan first run: %v", err)
	}
	if len(firstOut.Results) != 3 {
		t.Fatalf("first run results = %d, want 3", len(firstOut.Results))
	}

	second, err := Prepare(Config{
		Target:         "127.0.0.1",
		Ports:          fmt.Sprintf("%d,%d,%d", firstPorts[0], firstPorts[1], missingPort),
		ConnectTimeout: 200 * time.Millisecond,
		VNCTimeout:     200 * time.Millisecond,
		Workers:        2,
		OutDir:         t.TempDir(),
		OutDirExplicit: true,
		NoPDF:          true,
		ResumeDir:      first.RunDir,
	})
	if err != nil {
		t.Fatalf("Prepare resumed run: %v", err)
	}
	if len(second.Targets) != 3 {
		t.Errorf("resumed session targets = %d, want the full scope of 3", len(second.Targets))
	}
	if got := second.ResumedTargets(); got != 2 {
		t.Errorf("ResumedTargets = %d, want 2", got)
	}
	if got := second.RemainingTargets(); got != 1 {
		t.Errorf("RemainingTargets = %d, want 1", got)
	}

	var progressSeen []Progress
	secondOut, err := second.Scan(ctx, func(p Progress) {
		progressSeen = append(progressSeen, p)
	})
	if err != nil {
		t.Fatalf("Scan resumed run: %v", err)
	}

	// Only the missing endpoint may be probed again.
	wantProbed := fmt.Sprintf("127.0.0.1:%d", missingPort)
	if len(progressSeen) != 1 {
		t.Fatalf("progress callbacks = %d, want 1 (only the missing target)", len(progressSeen))
	}
	if got := progressSeen[0].Result.Addr(); got != wantProbed {
		t.Errorf("probed target = %s, want %s", got, wantProbed)
	}
	// Progress is reported against the full scope, not just the tail.
	if progressSeen[0].Total != 3 || progressSeen[0].Done != 3 {
		t.Errorf("progress = %d/%d, want 3/3", progressSeen[0].Done, progressSeen[0].Total)
	}

	if secondOut.Resumed != 2 {
		t.Errorf("Outcome.Resumed = %d, want 2", secondOut.Resumed)
	}
	if secondOut.Remaining != 1 {
		t.Errorf("Outcome.Remaining = %d, want 1", secondOut.Remaining)
	}
	if len(secondOut.Results) != 3 {
		t.Fatalf("resumed results = %d, want all 3 of the scope", len(secondOut.Results))
	}
	if secondOut.Summary.Targets != 3 {
		t.Errorf("summary targets = %d, want 3", secondOut.Summary.Targets)
	}

	data, err := os.ReadFile(secondOut.JSON)
	if err != nil {
		t.Fatalf("read resumed json report: %v", err)
	}
	var doc report.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse resumed json report: %v", err)
	}
	if doc.ResumedFrom != filepath.Base(first.RunDir) {
		t.Errorf("resumed_from = %q, want %q", doc.ResumedFrom, filepath.Base(first.RunDir))
	}
	if len(doc.Results) != 3 {
		t.Fatalf("json results = %d, want 3", len(doc.Results))
	}
	wantAddrs := []string{
		fmt.Sprintf("127.0.0.1:%d", firstPorts[0]),
		fmt.Sprintf("127.0.0.1:%d", firstPorts[1]),
		wantProbed,
	}
	sort.Strings(wantAddrs)
	if got := addressesOfResults(doc.Results); !equalStrings(got, wantAddrs) {
		t.Errorf("json addresses = %v, want %v", got, wantAddrs)
	}
}

func addressesOfTargets(targets []scanner.Target) []string {
	addrs := make([]string, 0, len(targets))
	for _, t := range targets {
		addrs = append(addrs, t.IP+":"+fmt.Sprint(t.Port))
	}
	sort.Strings(addrs)
	return addrs
}

func addressesOfResults(results []report.Result) []string {
	addrs := make([]string, 0, len(results))
	for _, r := range results {
		addrs = append(addrs, r.Addr())
	}
	sort.Strings(addrs)
	return addrs
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
