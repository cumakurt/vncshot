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
// writes JSON/HTML/PDF reports. It is supported on Linux only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vncshot/app"
	configfile "vncshot/config"
	"vncshot/gui"
)

const appName = "vncshot"

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
	retries       int
	outDir        string
	outDirSet     bool
	output        string
	html          string
	pdf           string
	csv           string
	baseline      string
	manifest      bool
	webhook       string
	noPDF         bool
	screenshotDir string
	shared        bool
	wordList      string
	noDefaultPw   bool
	noPasswordChk bool
	assumeYes     bool
	gui           bool
	host          string
	port          int
	noBrowser     bool
	configPath    string
	showVersion   bool
}

func (c config) appConfig() app.Config {
	return app.Config{
		Target:             c.target,
		File:               c.file,
		Ports:              c.ports,
		ConnectTimeout:     c.timeout,
		VNCTimeout:         c.vncTimeout,
		Workers:            c.workers,
		RatePerSec:         c.rate,
		MaxRetries:         c.retries,
		Shared:             c.shared,
		NoPDF:              c.noPDF,
		WordList:           c.wordList,
		NoDefaultPasswords: c.noDefaultPw,
		NoPasswordCheck:    c.noPasswordChk,
		OutDir:             c.outDir,
		OutDirExplicit:     c.outDirSet,
		Output:             c.output,
		HTML:               c.html,
		PDF:                c.pdf,
		CSV:                c.csv,
		ScreenshotDir:      c.screenshotDir,
		Baseline:           c.baseline,
		WebhookURL:         c.webhook,
		Manifest:           c.manifest,
	}
}

func main() {
	// The app package builds outbound requests (webhook User-Agent), so it
	// needs the version that install.sh injected at build time.
	app.Version = version

	// Running the tool without arguments is a request for usage, not a scan.
	if len(os.Args) == 1 {
		printUsage(os.Stdout)
		return
	}

	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if cfg.showVersion {
		// Build information is harmless and must not require root.
		fmt.Println(versionText())
		return
	}

	// Raw RFB probing and the shared report tree under /usr/local/vncshot
	// require root; fail fast instead of producing a half-working scan.
	if err := requireRoot(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if cfg.gui {
		err = gui.Run(gui.Config{
			Scan:        cfg.appConfig(),
			Version:     version,
			Host:        cfg.host,
			Port:        cfg.port,
			OpenBrowser: !cfg.noBrowser,
			Reason:      "gui",
		})
	} else {
		err = runCLI(cfg)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "\nscan interrupted; partial results were written")
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags() (config, error) {
	var cfg config

	flag.BoolVar(&cfg.showVersion, "version", false, "print version information and exit")
	flag.StringVar(&cfg.target, "target", "", "single IP, CIDR or IPv4 range (e.g. 192.168.1.1, 192.168.1.0/24, 192.168.1.1-50)")
	flag.StringVar(&cfg.file, "file", "", "file with IPs/CIDRs/ranges, one per line (# comments allowed)")
	flag.StringVar(&cfg.ports, "ports", "5900", "ports to scan (list/ranges, e.g. 5900,5901-5910)")
	flag.DurationVar(&cfg.timeout, "timeout", 1*time.Second, "TCP connect timeout")
	flag.DurationVar(&cfg.vncTimeout, "vnc-timeout", 15*time.Second, "per-operation RFB handshake/capture timeout")
	flag.IntVar(&cfg.workers, "workers", 150, "concurrent scan workers")
	flag.IntVar(&cfg.rate, "rate", 200, "max new connections per second (0 = unlimited)")
	flag.IntVar(&cfg.retries, "retries", 1, "extra connect attempts for transient failures (0 = none)")
	flag.StringVar(&cfg.outDir, "out-dir", reportBaseDir, "root directory for timestamped report folders")
	flag.StringVar(&cfg.output, "output", "", "JSON report path (default <run-dir>/"+appName+"_report.json)")
	flag.StringVar(&cfg.html, "html", "", "HTML report path (default <run-dir>/"+appName+"_report.html)")
	flag.StringVar(&cfg.pdf, "pdf", "", "PDF report path (default <run-dir>/"+appName+"_report.pdf)")
	flag.StringVar(&cfg.csv, "csv", "", "CSV report path (default <run-dir>/"+appName+"_report.csv)")
	flag.StringVar(&cfg.baseline, "baseline", "", "previous run directory to compare against")
	flag.BoolVar(&cfg.manifest, "manifest", false, "write a SHA-256 checksum manifest for the run artifacts")
	flag.StringVar(&cfg.webhook, "webhook", "", "POST a JSON summary to this URL when the scan finishes with new findings or weak credentials")
	flag.StringVar(&cfg.configPath, "config", "", "config file with flag defaults (JSON or simple YAML)")
	flag.BoolVar(&cfg.noPDF, "no-pdf", false, "skip PDF generation")
	flag.StringVar(&cfg.screenshotDir, "screenshot-dir", "", "directory for PNG captures (default <run-dir>/screenshots)")
	flag.BoolVar(&cfg.shared, "shared", true, "request shared RFB session (does not kick active viewers)")
	flag.StringVar(&cfg.wordList, "word-list", "", "file with extra password candidates, one per line")
	flag.BoolVar(&cfg.noDefaultPw, "no-default-passwords", false, "do not try the built-in weak-password list")
	flag.BoolVar(&cfg.noPasswordChk, "no-password-check", false, "do not attempt any password, report passwordless hosts only")
	flag.BoolVar(&cfg.assumeYes, "yes", false, "skip the interactive authorization confirmation")

	flag.BoolVar(&cfg.gui, "gui", false, "start the local web GUI (all features incl. live progress)")
	flag.StringVar(&cfg.host, "gui-host", "127.0.0.1", "GUI listen address")
	flag.IntVar(&cfg.port, "gui-port", 0, "GUI listen port (0 = pick a free port)")
	flag.BoolVar(&cfg.noBrowser, "gui-no-browser", false, "do not open the GUI in a browser automatically")

	flag.Usage = func() { printUsage(flag.CommandLine.Output()) }
	flag.Parse()

	// -version must succeed even when a config file is broken or missing.
	if cfg.showVersion {
		return cfg, nil
	}

	configPath := cfg.configPath
	if configPath == "" {
		configPath = os.Getenv("VNCSHOT_CONFIG")
	}
	if configPath != "" {
		values, err := configfile.Load(configPath)
		if err != nil {
			return cfg, err
		}
		if err := configfile.Apply(flag.CommandLine, values); err != nil {
			return cfg, err
		}
	}

	// fs.Set, used for environment and config values, also records the flag
	// as visited, so this catches every explicit source, not just the CLI.
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "out-dir" {
			cfg.outDirSet = true
		}
	})

	return cfg, nil
}

func versionText() string {
	return fmt.Sprintf("%s %s (%s/%s, %s)", appName, version, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "%s %s — VNC security inventory scanner (Linux)\n\n", appName, version)
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  sudo %s -target <IP|CIDR|range> [flags]\n", appName)
	fmt.Fprintf(w, "  sudo %s -file <path> [flags]\n", appName)
	fmt.Fprintf(w, "  sudo %s -gui [flags]\n\n", appName)
	fmt.Fprintf(w, "Probes VNC/RFB endpoints, flags passwordless servers and captures\n")
	fmt.Fprintf(w, "their framebuffers. Each scan writes JSON, HTML and PDF reports plus\n")
	fmt.Fprintf(w, "PNG screenshots into a timestamped folder under -out-dir.\n\n")
	fmt.Fprintf(w, "-gui starts a local web interface with the same options and live\n")
	fmt.Fprintf(w, "progress. It listens on loopback only and requires root.\n\n")
	fmt.Fprintf(w, "Flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(w, "\nDeveloper: Cuma KURT <cumakurt@gmail.com>\n")
	fmt.Fprintf(w, "https://github.com/cumakurt/vncshot\n")
	fmt.Fprintf(w, "https://www.linkedin.com/in/cuma-kurt-34414917/\n")
}

func runCLI(cfg config) error {
	if !cfg.assumeYes {
		ok, err := confirmAuthorization()
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("authorization not confirmed; aborting")
		}
	}

	scanCfg := cfg.appConfig()
	scanCfg.ShowProgress = true

	session, err := app.Prepare(scanCfg)
	if err != nil {
		return err
	}
	if warning := session.FallbackWarning(); warning != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	fmt.Fprintf(os.Stderr, "targets: %d host:port pairs | ports: %s | workers: %d | rate: %s\n",
		len(session.Targets), cfg.ports, cfg.workers, rateText(cfg.rate))
	fmt.Fprintf(os.Stderr, "password candidates: %d\n", len(session.Credentials))
	fmt.Fprintf(os.Stderr, "report directory: %s\n", session.RunDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out, scanErr := session.Scan(ctx, nil)

	fmt.Fprintf(os.Stderr, "\n=== summary ===\n")
	fmt.Fprintf(os.Stderr, "targets:      %d\n", out.Summary.Targets)
	fmt.Fprintf(os.Stderr, "open:         %d\n", out.Summary.Open)
	fmt.Fprintf(os.Stderr, "rfb services: %d\n", out.Summary.RFB)
	fmt.Fprintf(os.Stderr, "passwordless: %d\n", out.Summary.Passwordless)
	fmt.Fprintf(os.Stderr, "weak creds:   %d\n", out.Summary.WeakCredentials)
	fmt.Fprintf(os.Stderr, "screenshots:  %d\n", out.Summary.Screenshots)
	fmt.Fprintf(os.Stderr, "errors:       %d\n", out.Summary.Errors)
	writeDiffSummary(os.Stderr, out.Diff)
	fmt.Fprintf(os.Stderr, "json:  %s\n", out.JSON)
	fmt.Fprintf(os.Stderr, "html:  %s\n", out.HTML)
	if out.PDF != "" {
		fmt.Fprintf(os.Stderr, "pdf:   %s\n", out.PDF)
	}
	if out.CSV != "" {
		fmt.Fprintf(os.Stderr, "csv:   %s\n", out.CSV)
	}
	if out.Manifest != "" {
		fmt.Fprintf(os.Stderr, "manifest: %s\n", out.Manifest)
	}
	if out.Warning != "" {
		fmt.Fprintf(os.Stderr, "warning: %s\n", out.Warning)
	}

	return scanErr
}

// writeDiffSummary reports baseline comparison counts when one was requested.
func writeDiffSummary(w io.Writer, diff *app.Diff) {
	if diff == nil {
		return
	}
	fmt.Fprintf(w, "baseline:     %s\n", diff.Baseline)
	fmt.Fprintf(w, "new findings: %d\n", len(diff.New))
	fmt.Fprintf(w, "resolved:     %d\n", len(diff.Resolved))
	fmt.Fprintf(w, "changed:      %d\n", len(diff.Changed))
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
