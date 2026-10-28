package scanner

import (
	"bytes"
	"context"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"vncshot/report"
)

func TestColoredProgressGrowsFromTheLeftOnly(t *testing.T) {
	var buf bytes.Buffer
	bar := newProgressBar(100, &buf, true)
	if err := bar.Add(40); err != nil {
		t.Fatalf("Add: %v", err)
	}

	plain := ansiPattern.ReplaceAllString(buf.String(), "")
	plain = strings.TrimRight(plain, "\r\n ")
	track := progressTrack(plain)
	if track == "" {
		t.Fatalf("rendered line %q has no track", plain)
	}
	if strings.Contains(track, "▐") || strings.Contains(track, "▌") {
		t.Fatalf("track %q still has filled end caps", track)
	}
	filled := strings.TrimRight(track, "░")
	empty := strings.TrimLeft(track, "█")
	if filled == "" || strings.Trim(filled, "█") != "" {
		t.Fatalf("track %q does not grow from the left", track)
	}
	if empty == "" || strings.Trim(empty, "░") != "" {
		t.Fatalf("track %q still has a filled cell at the unfilled end", track)
	}
	if strings.HasSuffix(track, "█") {
		t.Fatalf("track %q ends with a filled cell before the bar is complete", track)
	}
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func progressTrack(line string) string {
	start := strings.Index(line, "█")
	if start < 0 {
		start = strings.Index(line, "░")
	}
	if start < 0 {
		return ""
	}
	end := start
	for _, r := range line[start:] {
		if r != '█' && r != '░' {
			break
		}
		end += len(string(r))
	}
	return line[start:end]
}

func TestLiveFindingLine(t *testing.T) {
	var counts liveFindings
	if got := counts.line(); got != "open 0  rfb 0  passwordless 0  weak 0  screenshots 0  errors 0" {
		t.Fatalf("line = %q", got)
	}

	if !counts.observe(report.Result{Open: true, RFB: true, Passwordless: true, Screenshot: "captures/a.png"}) {
		t.Fatal("observe passwordless capture = false, want a change")
	}
	if counts.observe(report.Result{Open: true, Error: "banner rejected"}) != true {
		t.Fatal("observe error = false, want a change")
	}
	// A closed port is ordinary scan noise and must not redraw the row.
	if counts.observe(report.Result{IP: "192.0.2.1", Port: 5900}) {
		t.Fatal("observe closed port = true, want no change")
	}
	if counts.observe(report.Result{Password: "secret"}) != true {
		t.Fatal("observe weak credential = false, want a change")
	}

	got := counts.line()
	want := "open 2  rfb 1  passwordless 1  weak 1  screenshots 1  errors 1"
	if got != want {
		t.Fatalf("line = %q, want %q", got, want)
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "192.0.2.1") {
		t.Fatalf("line = %q, want counts only", got)
	}
}

func TestLiveFindingLineColored(t *testing.T) {
	var counts liveFindings
	counts.observe(report.Result{Open: true, RFB: true, Passwordless: true})
	got := counts.lineColored()
	if !strings.Contains(got, "\x1b[1;31m1\x1b[0m") {
		t.Fatalf("colored line = %q, want a bold red passwordless count", got)
	}
	if !strings.Contains(got, "passwordless") || !strings.Contains(got, "\x1b[2m0\x1b[0m") {
		t.Fatalf("colored line = %q, want labels and a dim zero", got)
	}
	if strings.Contains(counts.line(), "\x1b") {
		t.Fatalf("plain line = %q, want no colour", counts.line())
	}
}

func TestRunPaintsLiveFindingCounts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("port %q: %v", portText, err)
	}

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = Run(ctx, []Target{{IP: "127.0.0.1", Port: port}}, Options{
		ShowProgress:   true,
		ProgressWriter: &buf,
		Workers:        1,
		ConnectTimeout: 200 * time.Millisecond,
		VNCTimeout:     200 * time.Millisecond,
		SeedResults: []report.Result{{
			Open:         true,
			RFB:          true,
			Passwordless: true,
		}},
	})
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}

	out := buf.String()
	// The seeded passwordless host is on the row before the closed port
	// returns, and a closed port must not clear it.
	if !strings.Contains(out, "passwordless 1") {
		t.Fatalf("progress output %q missing seeded passwordless count", out)
	}
	if !strings.Contains(out, "open 1") || !strings.Contains(out, "errors 0") {
		t.Fatalf("progress output %q missing live counters", out)
	}
}
