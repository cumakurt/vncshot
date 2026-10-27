package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vncshot/report"
)

// reachableResult is a baseline finding: an open RFB service that requires a
// password.
func reachableResult(ip string, port int) report.Result {
	return report.Result{IP: ip, Port: port, Open: true, RFB: true}
}

func TestCompareChangeReasons(t *testing.T) {
	tests := []struct {
		name   string
		before report.Result
		after  report.Result
		want   string
	}{
		{
			name:   "became passwordless",
			before: reachableResult("10.0.0.1", 5900),
			after: func() report.Result {
				r := reachableResult("10.0.0.1", 5900)
				r.Passwordless = true
				return r
			}(),
			want: "became passwordless",
		},
		{
			name:   "weak password discovered",
			before: reachableResult("10.0.0.1", 5900),
			after: func() report.Result {
				r := reachableResult("10.0.0.1", 5900)
				r.Password = "placeholder"
				r.PasswordSource = "default"
				return r
			}(),
			want: "weak password discovered",
		},
		{
			name: "password no longer accepted",
			before: func() report.Result {
				r := reachableResult("10.0.0.1", 5900)
				r.Password = "placeholder"
				r.PasswordSource = "default"
				return r
			}(),
			after: reachableResult("10.0.0.1", 5900),
			want:  "password no longer accepted",
		},
		{
			name:   "no longer RFB",
			before: reachableResult("10.0.0.1", 5900),
			after:  report.Result{IP: "10.0.0.1", Port: 5900, Open: true},
			want:   "no longer RFB",
		},
		{
			name:   "became TLS",
			before: reachableResult("10.0.0.1", 5900),
			after: func() report.Result {
				r := reachableResult("10.0.0.1", 5900)
				r.TLS = true
				return r
			}(),
			want: "became TLS",
		},
		{
			name: "lost TLS",
			before: func() report.Result {
				r := reachableResult("10.0.0.1", 5900)
				r.TLS = true
				return r
			}(),
			after: reachableResult("10.0.0.1", 5900),
			want:  "lost TLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diff := Compare("baseline", []report.Result{tt.before}, []report.Result{tt.after})
			if len(diff.New) != 0 || len(diff.Resolved) != 0 {
				t.Fatalf("new = %d, resolved = %d; want 0, 0", len(diff.New), len(diff.Resolved))
			}
			if len(diff.Changed) != 1 {
				t.Fatalf("changed = %d, want 1", len(diff.Changed))
			}
			if diff.Changed[0].Reason != tt.want {
				t.Errorf("reason = %q, want %q", diff.Changed[0].Reason, tt.want)
			}
		})
	}
}

func TestCompareUnchangedRiskStateProducesNoChange(t *testing.T) {
	result := reachableResult("10.0.0.1", 5900)
	diff := Compare("baseline", []report.Result{result}, []report.Result{result})
	if len(diff.New) != 0 || len(diff.Resolved) != 0 || len(diff.Changed) != 0 {
		t.Errorf("diff = %+v, want every list empty", diff)
	}
}

// A host that starts accepting a weak password was already passwordless, so
// it must be one change rather than a new and a resolved finding.
func TestComparePasswordlessToWeakPasswordIsSingleChange(t *testing.T) {
	before := reachableResult("10.0.0.1", 5900)
	before.Passwordless = true

	after := reachableResult("10.0.0.1", 5900)
	after.Password = "placeholder"
	after.PasswordSource = "default"

	diff := Compare("baseline", []report.Result{before}, []report.Result{after})
	if len(diff.New) != 0 {
		t.Errorf("new = %d, want 0", len(diff.New))
	}
	if len(diff.Resolved) != 0 {
		t.Errorf("resolved = %d, want 0", len(diff.Resolved))
	}
	if len(diff.Changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(diff.Changed))
	}
	if diff.Changed[0].Reason != "weak password discovered" {
		t.Errorf("reason = %q, want %q", diff.Changed[0].Reason, "weak password discovered")
	}
}

func TestCompareClassifiesNewResolvedAndChanged(t *testing.T) {
	baseline := []report.Result{
		reachableResult("10.0.0.1", 5900),
		reachableResult("10.0.0.2", 5900),
	}
	nowPasswordless := reachableResult("10.0.0.1", 5900)
	nowPasswordless.Passwordless = true
	current := []report.Result{
		nowPasswordless,
		reachableResult("10.0.0.3", 5900),
	}

	diff := Compare("baseline", baseline, current)
	if len(diff.New) != 1 || diff.New[0].IP != "10.0.0.3" {
		t.Errorf("new = %+v, want 10.0.0.3", diff.New)
	}
	if len(diff.Resolved) != 1 || diff.Resolved[0].IP != "10.0.0.2" {
		t.Errorf("resolved = %+v, want 10.0.0.2", diff.Resolved)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].Reason != "became passwordless" {
		t.Errorf("changed = %+v, want one passwordless transition", diff.Changed)
	}
}

func TestCompareSortsDeterministically(t *testing.T) {
	// Numeric IP ordering, then port. Inputs are intentionally unsorted.
	current := []report.Result{
		reachableResult("10.0.0.10", 5900),
		reachableResult("10.0.0.9", 5901),
		reachableResult("10.0.0.9", 5900),
	}
	diff := Compare("baseline", nil, current)
	got := make([]string, len(diff.New))
	for i, r := range diff.New {
		got[i] = r.Addr()
	}
	want := []string{"10.0.0.9:5900", "10.0.0.9:5901", "10.0.0.10:5900"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("new order = %v, want %v", got, want)
		}
	}

	baseline := []report.Result{
		reachableResult("10.0.0.10", 5900),
		reachableResult("10.0.0.9", 5900),
	}
	changedCurrent := []report.Result{
		func() report.Result {
			r := reachableResult("10.0.0.10", 5900)
			r.Passwordless = true
			return r
		}(),
		func() report.Result {
			r := reachableResult("10.0.0.9", 5900)
			r.Passwordless = true
			return r
		}(),
	}
	changed := Compare("baseline", baseline, changedCurrent)
	if len(changed.Changed) != 2 {
		t.Fatalf("changed = %d, want 2", len(changed.Changed))
	}
	if changed.Changed[0].Before.IP != "10.0.0.9" || changed.Changed[1].Before.IP != "10.0.0.10" {
		t.Errorf("changed order = %s, %s; want 10.0.0.9 then 10.0.0.10",
			changed.Changed[0].Before.IP, changed.Changed[1].Before.IP)
	}

	resolvedBaseline := []report.Result{
		reachableResult("10.0.0.10", 5900),
		reachableResult("10.0.0.9", 5900),
	}
	resolved := Compare("baseline", resolvedBaseline, nil)
	if len(resolved.Resolved) != 2 {
		t.Fatalf("resolved = %d, want 2", len(resolved.Resolved))
	}
	if resolved.Resolved[0].IP != "10.0.0.9" || resolved.Resolved[1].IP != "10.0.0.10" {
		t.Errorf("resolved order = %s, %s; want 10.0.0.9 then 10.0.0.10",
			resolved.Resolved[0].IP, resolved.Resolved[1].IP)
	}
}

func TestLoadBaselineReadsDocument(t *testing.T) {
	dir := t.TempDir()
	doc := report.Document{
		Tool:    "vncshot",
		Results: []report.Result{reachableResult("10.0.0.1", 5900)},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, BaselineFilename), data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	results, err := LoadBaseline(dir)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(results) != 1 || results[0].Addr() != "10.0.0.1:5900" {
		t.Fatalf("results = %+v, want one finding for 10.0.0.1:5900", results)
	}
}

func TestLoadBaselineErrors(t *testing.T) {
	t.Run("missing report", func(t *testing.T) {
		dir := t.TempDir()
		_, err := LoadBaseline(dir)
		if err == nil {
			t.Fatal("LoadBaseline accepted a directory without a report")
		}
		if !strings.Contains(err.Error(), dir) {
			t.Errorf("error %q does not name the baseline path %q", err, dir)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "absent")
		if _, err := LoadBaseline(dir); err == nil {
			t.Fatal("LoadBaseline accepted a missing directory")
		}
	})

	t.Run("unparsable report", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, BaselineFilename)
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		_, err := LoadBaseline(dir)
		if err == nil {
			t.Fatal("LoadBaseline accepted invalid JSON")
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("error %q does not name the report path %q", err, path)
		}
	})

	t.Run("baseline is a file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "run.json")
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		if _, err := LoadBaseline(path); err == nil {
			t.Fatal("LoadBaseline accepted a regular file as a baseline directory")
		}
	})
}
