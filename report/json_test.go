package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteJSONRoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	results := []Result{
		{
			IP:           "192.0.2.1",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			ServerName:   "Test VNC",
			ScreenWidth:  1024,
			ScreenHeight: 768,
			Screenshot:   "/tmp/a.png",
			DurationMs:   42,
			Timestamp:    ts,
		},
		{
			IP:         "192.0.2.2",
			Port:       5901,
			Error:      "connection refused",
			DurationMs: 7,
			Timestamp:  ts.Add(time.Second),
		},
	}

	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteJSON(path, results); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}

	var got Document
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if got.Tool != "vncshot" {
		t.Errorf("tool = %q, want %q", got.Tool, "vncshot")
	}
	if got.GeneratedAt.IsZero() {
		t.Error("generated_at is zero, want a set timestamp")
	}
	if delta := time.Since(got.GeneratedAt); delta < -time.Minute || delta > time.Minute {
		t.Errorf("generated_at = %v, want approximately now", got.GeneratedAt)
	}

	wantSummary := Summarize(results)
	if got.Summary != wantSummary {
		t.Errorf("summary = %+v, want %+v", got.Summary, wantSummary)
	}

	if len(got.Results) != len(results) {
		t.Fatalf("len(results) = %d, want %d", len(got.Results), len(results))
	}
	for i, want := range results {
		g := got.Results[i]
		if g.IP != want.IP || g.Port != want.Port || g.Open != want.Open ||
			g.RFB != want.RFB || g.Passwordless != want.Passwordless ||
			g.ServerName != want.ServerName || g.ScreenWidth != want.ScreenWidth ||
			g.ScreenHeight != want.ScreenHeight || g.Screenshot != want.Screenshot ||
			g.Error != want.Error || g.DurationMs != want.DurationMs {
			t.Errorf("results[%d] = %+v, want %+v", i, g, want)
		}
		if !g.Timestamp.Equal(want.Timestamp) {
			t.Errorf("results[%d].timestamp = %v, want %v", i, g.Timestamp, want.Timestamp)
		}
	}
}

func TestWriteJSONIncludesDiff(t *testing.T) {
	diff := &Diff{
		Baseline: "/var/lib/vncshot/runs/20261026-120000",
		New: []Result{
			{IP: "192.0.2.30", Port: 5900, Open: true, RFB: true, Passwordless: true},
		},
		Resolved: []Result{
			{IP: "192.0.2.31", Port: 5900, Open: true, RFB: true},
		},
		Changed: []Change{
			{
				Before: Result{IP: "192.0.2.32", Port: 5900, Open: true, RFB: true, Password: "hunter2"},
				After:  Result{IP: "192.0.2.32", Port: 5900, Open: true, RFB: true},
				Reason: "password no longer accepted",
			},
		},
	}

	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteJSONWithOptions(path, nil, Options{Diff: diff}); err != nil {
		t.Fatalf("WriteJSONWithOptions: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var got Document
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if got.Diff == nil {
		t.Fatal("diff section is missing")
	}
	if got.Diff.Baseline != "20261026-120000" {
		t.Errorf("diff.baseline = %q, want display-safe run name", got.Diff.Baseline)
	}
	if len(got.Diff.New) != 1 {
		t.Errorf("len(diff.new) = %d, want 1", len(got.Diff.New))
	}
	if len(got.Diff.Resolved) != 1 {
		t.Errorf("len(diff.resolved) = %d, want 1", len(got.Diff.Resolved))
	}
	if len(got.Diff.Changed) != 1 {
		t.Fatalf("len(diff.changed) = %d, want 1", len(got.Diff.Changed))
	}

	change := got.Diff.Changed[0]
	if change.Addr != "192.0.2.32:5900" {
		t.Errorf("changed addr = %q, want 192.0.2.32:5900", change.Addr)
	}
	if change.Reason != "password no longer accepted" {
		t.Errorf("changed reason = %q, want the transition description", change.Reason)
	}
	if change.Before != "weak" || change.After != "rfb" {
		t.Errorf("changed states = %q -> %q, want %q -> %q",
			change.Before, change.After, "weak", "rfb")
	}
}

// TestWriteJSONRedactsPassword covers the redaction contract: the secret is
// replaced everywhere it can appear, while the source and the summary counter
// still report the finding.
func TestWriteJSONRedactsPassword(t *testing.T) {
	results := []Result{
		{IP: "192.0.2.40", Port: 5900, Open: true, RFB: true, Password: "hunter2", PasswordSource: "default"},
	}
	diff := &Diff{
		New: []Result{{IP: "192.0.2.41", Port: 5900, Open: true, RFB: true, Password: "letmein"}},
	}

	path := filepath.Join(t.TempDir(), "report.json")
	if err := WriteJSONWithOptions(path, results, Options{Diff: diff, Redact: true}); err != nil {
		t.Fatalf("WriteJSONWithOptions: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	var got Document
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}

	if len(got.Results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(got.Results))
	}
	if got.Results[0].Password != RedactedValue {
		t.Errorf("results[0].password = %q, want %q", got.Results[0].Password, RedactedValue)
	}
	if got.Results[0].PasswordSource != "default" {
		t.Errorf("results[0].password_source = %q, want unchanged %q", got.Results[0].PasswordSource, "default")
	}
	if got.Summary.WeakCredentials != 1 {
		t.Errorf("summary.weak_credentials = %d, want 1", got.Summary.WeakCredentials)
	}
	if got.Diff == nil || len(got.Diff.New) != 1 || got.Diff.New[0].Password != RedactedValue {
		t.Errorf("diff.new password was not redacted")
	}
}

func TestWriteJSONUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "report.json")
	err := WriteJSON(path, []Result{{IP: "192.0.2.1", Port: 5900, Open: true}})
	if err == nil {
		t.Fatal("WriteJSON to missing directory: want error, got nil")
	}
}

// TestWriteJSONEnforcesOwnerOnlyMode covers the case where -output points at
// a file that already exists with a wider mode: the report can contain weak
// credentials, so the documented 0600 contract must win.
func TestWriteJSONEnforcesOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod seed: %v", err)
	}

	if err := WriteJSON(path, []Result{{IP: "192.0.2.1", Port: 5900, Open: true, Password: "x"}}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat report: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("report mode = %o, want owner-only", mode)
	}
}
