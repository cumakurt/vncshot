// Terminal presentation for the CLI: colour support detection and a small
// palette that degrades to plain text. The renderer is deliberately a pure
// function over an io.Writer so tests can assert byte-identical plain output.
package app

import (
	"io"
	"os"
	"strconv"
)

// ANSI escape sequences used by the CLI. Only the fixed chrome of the tool is
// coloured; captured data (server names, addresses, passwords) is never
// wrapped, so a terminal cannot mangle or highlight evidence.
const (
	ansiReset   = "\x1b[0m"
	ansiGreen   = "\x1b[32m"
	ansiCyan    = "\x1b[36m"
	ansiYellow  = "\x1b[33m"
	ansiRed     = "\x1b[31m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiBoldRed = "\x1b[1;31m"
	ansiBoldGrn = "\x1b[1;32m"
	ansiBoldYlw = "\x1b[1;33m"
	ansiBoldCyn = "\x1b[1;36m"
)

// Console renders terminal output with optional colour. A zero value prints
// plain text, which keeps the byte output identical for pipes and logs.
type Console struct {
	// Color enables the ANSI palette.
	Color bool
}

// NewConsole selects colour from the environment: colour is used only when
// out is a terminal, NO_COLOR is unset and the caller allows it. The caller
// passes allow=false for an explicit -no-color request.
func NewConsole(out io.Writer, allow bool) Console {
	if !allow {
		return Console{}
	}
	if os.Getenv("NO_COLOR") != "" {
		return Console{}
	}
	return Console{Color: IsTerminal(out)}
}

// IsTerminal reports whether w is attached to a character device (a TTY).
// Pipes, files and CI log collectors are not, which is what suppresses both
// the colour palette and the carriage-return progress redraws.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// paint wraps s in an escape sequence when colour is enabled. An empty code
// or a disabled Console returns s unchanged, so plain mode adds no bytes.
func (c Console) paint(code, s string) string {
	if !c.Color || code == "" || s == "" {
		return s
	}
	return code + s + ansiReset
}

// Green marks healthy values (TLS services, screenshots).
func (c Console) Green(s string) string { return c.paint(ansiGreen, s) }

// Cyan marks neutral progress values (the probe counter).
func (c Console) Cyan(s string) string { return c.paint(ansiCyan, s) }

// Yellow marks warnings.
func (c Console) Yellow(s string) string { return c.paint(ansiYellow, s) }

// Red marks failures and insecure findings.
func (c Console) Red(s string) string { return c.paint(ansiRed, s) }

// Bold marks section headings.
func (c Console) Bold(s string) string { return c.paint(ansiBold, s) }

// Dim marks secondary labels so the numbers stay the loudest part of a line.
func (c Console) Dim(s string) string { return c.paint(ansiDim, s) }

// Tone paints a positive count. Zero stays plain so a clean scan does not
// look like an alarm. tone is cyan, green, yellow or red.
func (c Console) Tone(value int, tone string) string {
	text := strconv.Itoa(value)
	if !c.Color || value == 0 {
		return text
	}
	switch tone {
	case "cyan":
		return c.paint(ansiBoldCyn, text)
	case "green":
		return c.paint(ansiBoldGrn, text)
	case "yellow":
		return c.paint(ansiBoldYlw, text)
	case "red":
		return c.paint(ansiBoldRed, text)
	default:
		return text
	}
}

// Count renders a summary counter value. Zero stays uncoloured so a clean
// scan reads as monochrome; a positive insecure count is highlighted.
func (c Console) Count(value int, insecure bool) string {
	text := strconv.Itoa(value)
	if !c.Color || value == 0 {
		return text
	}
	if insecure {
		return c.Red(text)
	}
	return text
}
