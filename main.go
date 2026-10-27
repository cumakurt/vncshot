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
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"vncshot/app"
	configfile "vncshot/config"
	"vncshot/gui"
	"vncshot/scanner"
)

const appName = "vncshot"

// reportBaseDir is the root for timestamped run directories. install.sh
// overrides it at build time via -ldflags so the installed binary and the
// installed directory tree always agree.
var reportBaseDir = "/usr/local/vncshot"

// version, commit and buildDate are injected at build time via -ldflags.
// They appear in -version so a bug report pins an exact build.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

type config struct {
	target        string
	file          string
	ports         string
	timeout       time.Duration
	vncTimeout    time.Duration
	workers       int
	rate          int
	retries       int
	sourceAddr    string
	outDir        string
	outDirSet     bool
	output        string
	html          string
	pdf           string
	csv           string
	baseline      string
	resume        string
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
	redact        bool
	thumbOnly     bool
	keepRuns      int
	prune         int
	pruneSet      bool
	pruneDryRun   bool
	dryRun        bool
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
		SourceAddr:         c.sourceAddr,
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
		ResumeDir:          c.resume,
		WebhookURL:         c.webhook,
		Manifest:           c.manifest,
		Redact:             c.redact,
		ThumbnailOnly:      c.thumbOnly,
		KeepRuns:           c.keepRuns,
		PruneDryRun:        c.pruneDryRun,
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

	// -prune is a maintenance command, not a scan: run it and exit so it can
	// be scheduled from cron without inventing a dummy target.
	// -prune with an explicit zero is a mistake worth reporting, so the flag
	// being *set* (not merely non-zero) selects the maintenance command.
	if cfg.pruneSet || cfg.pruneDryRun {
		if err := runPrune(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
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
	flag.IntVar(&cfg.retries, "retries", 1, "extra attempts on transient connect or handshake failures (0 = none, max 1)")
	flag.StringVar(&cfg.sourceAddr, "source-addr", "", "local IP to bind probes to (default: route table)")
	flag.StringVar(&cfg.outDir, "out-dir", reportBaseDir, "root directory for timestamped report folders")
	flag.StringVar(&cfg.output, "output", "", "JSON report path (default <run-dir>/"+appName+"_report.json)")
	flag.StringVar(&cfg.html, "html", "", "HTML report path (default <run-dir>/"+appName+"_report.html)")
	flag.StringVar(&cfg.pdf, "pdf", "", "PDF report path (default <run-dir>/"+appName+"_report.pdf)")
	flag.StringVar(&cfg.csv, "csv", "", "CSV report path (default <run-dir>/"+appName+"_report.csv)")
	flag.StringVar(&cfg.baseline, "baseline", "", "previous run directory to compare against")
	flag.StringVar(&cfg.resume, "resume", "", "continue a previously interrupted run; completed targets are reused")
	flag.BoolVar(&cfg.manifest, "manifest", false, "write a SHA-256 checksum manifest for the run artifacts")
	flag.BoolVar(&cfg.redact, "redact", false, "replace captured passwords with a placeholder (safe to share)")
	flag.BoolVar(&cfg.thumbOnly, "thumb-only", false, "embed only preview images in the HTML report (smaller file)")
	flag.IntVar(&cfg.keepRuns, "keep", 0, "keep only the newest N run folders after a scan (0 = keep all)")
	flag.IntVar(&cfg.prune, "prune", 0, "delete all but the newest N run folders and exit (0 = disabled)")
	flag.BoolVar(&cfg.pruneDryRun, "prune-dry-run", false, "with -prune or -keep, list what would be deleted")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "expand targets and report the scope without scanning")
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
		switch f.Name {
		case "out-dir":
			cfg.outDirSet = true
		case "prune":
			cfg.pruneSet = true
		}
	})

	return cfg, nil
}

func versionText() string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s/%s, %s)",
		appName, version, commit, buildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
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
	// A dry run only expands the scope locally, so it neither needs the
	// authorization prompt nor touches the network.
	if cfg.dryRun {
		return runDryRun(cfg)
	}

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
	if cfg.resume != "" {
		fmt.Fprintf(os.Stderr, "resuming: reused %d result(s) from %s, %d target(s) remaining\n",
			session.ResumedTargets(), filepath.Base(cfg.resume), session.RemainingTargets())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	out, scanErr := session.Scan(ctx, nil)

	fmt.Fprintf(os.Stderr, "\n=== summary ===\n")
	fmt.Fprintf(os.Stderr, "targets:      %d\n", out.Summary.Targets)
	if out.Resumed > 0 {
		fmt.Fprintf(os.Stderr, "resumed:      %d\n", out.Resumed)
	}
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
	if len(out.RemovedRuns) > 0 {
		fmt.Fprintf(os.Stderr, "retention:   removed %d old run(s)\n", len(out.RemovedRuns))
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

// runPrune deletes old run folders under the report root and prints what it
// did. It is deliberately separate from a scan so retention can be scheduled
// on its own.
func runPrune(cfg config) error {
	keep := cfg.prune
	if !cfg.pruneSet && cfg.pruneDryRun {
		// "-prune-dry-run" alone previews the -keep policy of a scan.
		keep = cfg.keepRuns
	}
	if keep <= 0 {
		return fmt.Errorf("-prune needs a positive run count, e.g. -prune 30")
	}

	root := cfg.outDir
	runs, err := app.ListRuns(root)
	if err != nil {
		return err
	}

	removed, err := app.PruneRuns(root, keep, cfg.pruneDryRun)
	if err != nil {
		return err
	}

	verb := "removed"
	if cfg.pruneDryRun {
		verb = "would remove"
	}
	fmt.Fprintf(os.Stderr, "report root: %s\n", root)
	fmt.Fprintf(os.Stderr, "runs found:  %d | keeping newest %d\n", len(runs), keep)
	fmt.Fprintf(os.Stderr, "%s: %d run folder(s)\n", verb, len(removed))
	for _, run := range removed {
		fmt.Fprintf(os.Stderr, "  %s  %s  %d file(s)  %s\n",
			run.Name, run.Started.Format("2006-01-02 15:04"), run.Files, humanBytes(run.Size))
	}
	return nil
}

// humanBytes renders a byte count for terminal output.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

// runDryRun expands the requested scope and reports it without sending a
// single packet, so a large CIDR or port list can be sanity-checked first.
func runDryRun(cfg config) error {
	ports, err := scanner.ParsePorts(cfg.ports)
	if err != nil {
		return err
	}
	cfgScan := cfg.appConfig()
	plan, err := app.DescribeScope(cfgScan, ports)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "dry run: nothing will be sent\n")
	fmt.Fprintf(os.Stderr, "targets:            %d host:port pairs\n", plan.Targets)
	fmt.Fprintf(os.Stderr, "unique hosts:       %d\n", plan.Hosts)
	fmt.Fprintf(os.Stderr, "ports:              %d (%s)\n", plan.Ports, cfg.ports)
	fmt.Fprintf(os.Stderr, "password candidates:%d\n", plan.Credentials)
	fmt.Fprintf(os.Stderr, "report root:        %s\n", cfg.outDir)
	fmt.Fprintf(os.Stderr, "workers:            %d | rate: %s\n", cfg.workers, rateText(cfg.rate))
	if plan.Targets > 0 {
		fmt.Fprintf(os.Stderr, "first target:       %s\n", plan.First)
		fmt.Fprintf(os.Stderr, "last target:        %s\n", plan.Last)
	}
	return nil
}
