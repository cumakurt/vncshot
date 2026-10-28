package app

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// TestNewConsoleDecision covers the colour gate: a terminal enables the
// palette, an explicit opt-out disables it and NO_COLOR always wins.
func TestNewConsoleDecision(t *testing.T) {
	tty := newFakeTerminal(t)
	pipe := &bytes.Buffer{}

	cases := []struct {
		name  string
		out   any
		allow bool
		noCol string
		want  bool
	}{
		{name: "terminal with colour allowed", out: tty, allow: true, want: true},
		{name: "explicit opt-out", out: tty, allow: false, want: false},
		{name: "pipe is never coloured", out: pipe, allow: true, want: false},
		{name: "NO_COLOR wins on a terminal", out: tty, allow: true, noCol: "1", want: false},
		{name: "NO_COLOR with empty value is ignored", out: tty, allow: true, noCol: "", want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", tc.noCol)
			var w = tc.out.(interface{ Write([]byte) (int, error) })
			got := NewConsole(w, tc.allow)
			if got.Color != tc.want {
				t.Errorf("Color = %v, want %v", got.Color, tc.want)
			}
		})
	}
}

// TestConsolePlainModeIsByteIdentical guards the compatibility promise: with
// colour off every helper must return its input unchanged, so a piped run
// emits exactly the bytes it always did.
func TestConsolePlainModeIsByteIdentical(t *testing.T) {
	plain := Console{}
	samples := []string{"", "0", "12", "warning: disk full", "=== summary ==="}

	for _, sample := range samples {
		if got := plain.Green(sample); got != sample {
			t.Errorf("Green(%q) = %q in plain mode", sample, got)
		}
		if got := plain.Red(sample); got != sample {
			t.Errorf("Red(%q) = %q in plain mode", sample, got)
		}
		if got := plain.Yellow(sample); got != sample {
			t.Errorf("Yellow(%q) = %q in plain mode", sample, got)
		}
		if got := plain.Cyan(sample); got != sample {
			t.Errorf("Cyan(%q) = %q in plain mode", sample, got)
		}
		if got := plain.Bold(sample); got != sample {
			t.Errorf("Bold(%q) = %q in plain mode", sample, got)
		}
	}
	for _, value := range []int{0, 1, 2, 99} {
		if got := plain.Count(value, true); got == "" || strings.Contains(got, "\x1b") {
			t.Errorf("Count(%d) = %q in plain mode, want digits only", value, got)
		}
	}
}

// TestConsoleColoredOutput checks the opposite direction: enabled colour must
// wrap the value and reset it, so a terminal does not leak the attribute.
func TestConsoleColoredOutput(t *testing.T) {
	c := Console{Color: true}

	if got := c.Red("3"); got != ansiRed+"3"+ansiReset {
		t.Errorf("Red = %q", got)
	}
	if got := c.Bold("summary"); got != ansiBold+"summary"+ansiReset {
		t.Errorf("Bold = %q", got)
	}
	// Zero counters stay monochrome even with colour on: a clean scan should
	// not look alarming.
	if got := c.Count(0, true); got != "0" {
		t.Errorf("Count(0) = %q, want plain zero", got)
	}
	if got := c.Count(2, true); got != ansiRed+"2"+ansiReset {
		t.Errorf("Count(2, insecure) = %q", got)
	}
	if got := c.Count(2, false); got != "2" {
		t.Errorf("Count(2, safe) = %q, want plain digits", got)
	}
	// Empty strings must not emit a dangling escape pair.
	if got := c.Red(""); got != "" {
		t.Errorf("Red(\"\") = %q, want empty", got)
	}
}

// TestIsTerminalRejectsBuffers documents that non-file writers are never
// treated as terminals, which is what suppresses the progress bar in tests.
func TestIsTerminalRejectsBuffers(t *testing.T) {
	if IsTerminal(&bytes.Buffer{}) {
		t.Error("a bytes.Buffer must not be reported as a terminal")
	}
}

// newFakeTerminal returns a character device to exercise the TTY branch.
// /dev/null is a character device on Linux (the only supported platform), so
// it reaches the same Stat mode check a real terminal does without requiring
// a pty in the test.
func newFakeTerminal(t *testing.T) interface{ Write([]byte) (int, error) } {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
