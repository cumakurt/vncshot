// vncshot — VNC security inventory scanner.
// Copyright (C) 2026 Cuma KURT
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// Command vncshot is a VNC security inventory scanner for authorized
// network assessments. It expands IP/CIDR/range targets, probes RFB
// endpoints, flags passwordless servers, captures their framebuffers and
// writes JSON/HTML/PDF reports.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vncshot/report"
	"vncshot/scanner"
)

const (
	appName = "vncshot"

	// runTimestampLayout names each scan run directory.
	runTimestampLayout = "20060102-150405"
)

// reportBaseDir is the root for timestamped run directories. install.sh
// overrides it at build time via -ldflags so the installed binary and the
// installed directory tree always agree.
var reportBaseDir = "/usr/local/vncshot"

// version is injected at build time (-ldflags "-X main.version=...").
var version = "dev"

type config struct {
	target        string
	file          string
	ports         string
	timeout       time.Duration
	vncTimeout    time.Duration
	workers       int
	rate          int
	outDir        string
	outDirSet     bool
	output        string
	html          string
	pdf           string
	noPDF         bool
	screenshotDir string
	shared        bool
	assumeYes     bool
}

func main() {
	// Running the tool without arguments is a request for usage, not a scan.
	if len(os.Args) == 1 {
		printUsage(os.Stdout)
		return
	}

	cfg := parseFlags()

	// Raw RFB probing and the shared report tree require root privileges;
	// fail fast instead of producing a half-working scan.
	if err := requireRoot(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if err := run(cfg); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "\nscan interrupted; partial results were written")
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config

	flag.StringVar(&cfg.target, "target", "", "single IP, CIDR or IPv4 range (e.g. 192.168.1.1, 192.168.1.0/24, 192.168.1.1-50)")
	flag.StringVar(&cfg.file, "file", "", "file with IPs/CIDRs/ranges, one per line (# comments allowed)")
	flag.StringVar(&cfg.ports, "ports", "5900", "ports to scan (list/ranges, e.g. 5900,5901-5910)")
	flag.DurationVar(&cfg.timeout, "timeout", 1*time.Second, "TCP connect timeout")
	flag.DurationVar(&cfg.vncTimeout, "vnc-timeout", 15*time.Second, "per-operation RFB handshake/capture timeout")
	flag.IntVar(&cfg.workers, "workers", 150, "concurrent scan workers")
	flag.IntVar(&cfg.rate, "rate", 200, "max new connections per second (0 = unlimited)")
	flag.StringVar(&cfg.outDir, "out-dir", reportBaseDir, "root directory for timestamped report folders")
	flag.StringVar(&cfg.output, "output", "", "JSON report path (default <run-dir>/"+appName+"_report.json)")
	flag.StringVar(&cfg.html, "html", "", "HTML report path (default <run-dir>/"+appName+"_report.html)")
	flag.StringVar(&cfg.pdf, "pdf", "", "PDF report path (default <run-dir>/"+appName+"_report.pdf)")
	flag.BoolVar(&cfg.noPDF, "no-pdf", false, "skip PDF generation")
	flag.StringVar(&cfg.screenshotDir, "screenshot-dir", "", "directory for PNG captures (default <run-dir>/screenshots)")
	flag.BoolVar(&cfg.shared, "shared", true, "request shared RFB session (does not kick active viewers)")
	flag.BoolVar(&cfg.assumeYes, "yes", false, "skip the interactive authorization confirmation")

	flag.Usage = func() { printUsage(flag.CommandLine.Output()) }
	flag.Parse()

	flag.Visit(func(f *flag.Flag) {
		if f.Name == "out-dir" {
			cfg.outDirSet = true
		}
	})

	return cfg
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "%s %s — VNC security inventory scanner\n\n", appName, version)
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  sudo %s -target <IP|CIDR|range> [flags]\n", appName)
	fmt.Fprintf(w, "  sudo %s -file <path> [flags]\n\n", appName)
	fmt.Fprintf(w, "Probes VNC/RFB endpoints, flags passwordless servers and captures\n")
	fmt.Fprintf(w, "their framebuffers. Each scan writes JSON, HTML and PDF reports plus\n")
	fmt.Fprintf(w, "PNG screenshots into a timestamped folder under -out-dir.\n\n")
	fmt.Fprintf(w, "%s must run as root (directly or via sudo).\n\n", appName)
	fmt.Fprintf(w, "Flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(w, "\nDeveloper: Cuma KURT <cumakurt@gmail.com>\n")
	fmt.Fprintf(w, "https://github.com/cumakurt/vncshot\n")
	fmt.Fprintf(w, "https://www.linkedin.com/in/cuma-kurt-34414917/\n")
}

func run(cfg config) error {
	if !cfg.assumeYes {
		ok, err := confirmAuthorization()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("authorization not confirmed; aborting")
		}
	}

	ports, err := scanner.ParsePorts(cfg.ports)
	if err != nil {
		return err
	}

	targets, err := scanner.ParseTargets(cfg.target, cfg.file, ports)
	if err != nil {
		return err
	}

	runDir, err := prepareRunDir(cfg)
	if err != nil {
		return err
	}

	cfg.output = resolveArtifactPath(cfg.output, runDir, appName+"_report.json")
	cfg.html = resolveArtifactPath(cfg.html, runDir, appName+"_report.html")
	cfg.pdf = resolveArtifactPath(cfg.pdf, runDir, appName+"_report.pdf")
	cfg.screenshotDir = resolveArtifactPath(cfg.screenshotDir, runDir, "screenshots")
	if err := os.MkdirAll(cfg.screenshotDir, 0o755); err != nil {
		return fmt.Errorf("create screenshot directory: %w", err)
	}

	fmt.Fprintf(os.Stderr, "targets: %d host:port pairs | ports: %s | workers: %d | rate: %s\n",
		len(targets), cfg.ports, cfg.workers, rateText(cfg.rate))
	fmt.Fprintf(os.Stderr, "report directory: %s\n", runDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	opts := scanner.Options{
		ConnectTimeout: cfg.timeout,
		VNCTimeout:     cfg.vncTimeout,
		Workers:        cfg.workers,
		RatePerSec:     cfg.rate,
		ScreenshotDir:  cfg.screenshotDir,
		Shared:         cfg.shared,
		ShowProgress:   true,
	}

	results, scanErr := scanner.Run(ctx, targets, opts)

	sum := report.Summarize(results)
	if err := report.WriteJSON(cfg.output, results); err != nil {
		return err
	}
	if err := report.WriteHTML(cfg.html, results); err != nil {
		return err
	}

	if !cfg.noPDF && cfg.pdf != "" {
		if err := report.WritePDF(cfg.pdf, results); err != nil {
			// PDF is a convenience artifact; a render failure must not
			// discard the scan itself.
			fmt.Fprintf(os.Stderr, "warning: pdf generation skipped: %v\n", err)
		}
	}

	fmt.Fprintf(os.Stderr, "\n=== summary ===\n")
	fmt.Fprintf(os.Stderr, "targets:      %d\n", sum.Targets)
	fmt.Fprintf(os.Stderr, "open:         %d\n", sum.Open)
	fmt.Fprintf(os.Stderr, "rfb services: %d\n", sum.RFB)
	fmt.Fprintf(os.Stderr, "passwordless: %d\n", sum.Passwordless)
	fmt.Fprintf(os.Stderr, "screenshots:  %d\n", sum.Screenshots)
	fmt.Fprintf(os.Stderr, "errors:       %d\n", sum.Errors)
	fmt.Fprintf(os.Stderr, "json:  %s\n", cfg.output)
	fmt.Fprintf(os.Stderr, "html:  %s\n", cfg.html)
	if !cfg.noPDF && cfg.pdf != "" {
		fmt.Fprintf(os.Stderr, "pdf:   %s\n", cfg.pdf)
	}

	return scanErr
}

// prepareRunDir creates the timestamped folder that holds every artifact of
// this scan. When the default base directory is not writable (for example
// when running from a source checkout without install.sh), it falls back to
// a per-user data directory so a scan is never lost to a permissions error.
func prepareRunDir(cfg config) (string, error) {
	runDir, err := createRunDir(cfg.outDir)
	if err == nil {
		return runDir, nil
	}
	if cfg.outDirSet {
		return "", err
	}

	fallback := fallbackReportBase()
	if fallback == "" {
		return "", err
	}
	runDir, fallbackErr := createRunDir(fallback)
	if fallbackErr != nil {
		return "", err
	}
	fmt.Fprintf(os.Stderr, "warning: %v; writing reports to %s\n", err, fallback)
	return runDir, nil
}

func createRunDir(base string) (string, error) {
	runDir := filepath.Join(base, time.Now().Format(runTimestampLayout))
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return "", fmt.Errorf("create report directory %s: %w", runDir, err)
	}
	return runDir, nil
}

func fallbackReportBase() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", appName)
}

// resolveArtifactPath keeps default artifacts inside the run directory while
// honouring explicit absolute paths and treating relative overrides as
// relative to the run directory.
func resolveArtifactPath(value, runDir, fallback string) string {
	if value == "" {
		return filepath.Join(runDir, fallback)
	}
	if filepath.IsAbs(value) {
		return value
	}
	return filepath.Join(runDir, value)
}

func rateText(rate int) string {
	if rate <= 0 {
		return "unlimited"
	}
	return fmt.Sprintf("%d/s", rate)
}

// requireRoot enforces privileged execution. Raw RFB probing and the shared
// report tree under /usr/local/vncshot both assume root, so running
// unprivileged would either fail halfway or silently write to a fallback
// location.
func requireRoot() error {
	if runtime.GOOS == "windows" {
		// Windows has no POSIX effective UID; installing and running there
		// already requires an elevated shell.
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required; re-run with sudo")
	}
	return nil
}

// confirmAuthorization makes the operator acknowledge that the scan is
// authorized before any packet leaves the host.
func confirmAuthorization() (bool, error) {
	stat, err := os.Stdin.Stat()
	if err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		// Non-interactive stdin (pipe/CI): require -yes explicitly.
		return false, fmt.Errorf("refusing to scan without confirmation in non-interactive mode; re-run with -yes after verifying authorization")
	}

	fmt.Fprint(os.Stderr, "Type 'yes' to confirm you are authorized to scan these targets: ")
	var answer string
	if _, err := fmt.Fscanln(os.Stdin, &answer); err != nil {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	return strings.EqualFold(strings.TrimSpace(answer), "yes"), nil
}
