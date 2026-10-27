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
