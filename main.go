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
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
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
	"vncshot/report"
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
	target         string
	file           string
	ports          string
	timeout        time.Duration
	vncTimeout     time.Duration
	workers        int
	rate           int
	retries        int
	sourceAddr     string
	outDir         string
	outDirSet      bool
	output         string
	html           string
	pdf            string
	csv            string
	sarif          string
	baseline       string
	resume         string
	manifest       bool
	signKey        string
	verifyManifest string
	pubKey         string
	failOn         string
	// failOnCategories is the parsed and validated -fail-on value.
	failOnCategories []string
	accept           string
	exclude          string
	certWarnDays     int
	proxyURL         string
	slackURL         string
	mailServer       string
	mailFrom         string
	mailTo           string
	mailNoTLS        bool
	mailUser         string
	syslogAddr       string
	metricsAddr      string
	interval         time.Duration
	selfcheck        bool
	webhook          string
	noPDF            bool
	screenshotDir    string
	shared           bool
	wordList         string
	noDefaultPw      bool
	noPasswordChk    bool
	assumeYes        bool
	gui              bool
	host             string
	port             int
	noBrowser        bool
	configPath       string
	showVersion      bool
	redact           bool
	thumbOnly        bool
	noColor          bool
	keepRuns         int
	prune            int
	pruneSet         bool
	pruneDryRun      bool
	dryRun           bool
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
		SARIF:              c.sarif,
		ScreenshotDir:      c.screenshotDir,
		Baseline:           c.baseline,
		ResumeDir:          c.resume,
		WebhookURL:         c.webhook,
		Manifest:           c.manifest,
		Redact:             c.redact,
		ThumbnailOnly:      c.thumbOnly,
		KeepRuns:           c.keepRuns,
		PruneDryRun:        c.pruneDryRun,
		ExcludeFile:        c.exclude,
		AcceptFile:         c.accept,
		CertWarnDays:       c.certWarnDays,
		ProxyURL:           c.proxyURL,
		MetricsAddr:        c.metricsAddr,
		Interval:           c.interval,
		Notify:             c.notifyConfig(),
	}
}

// notifyConfig assembles the extra notification channels from the CLI flags.
// The SMTP password is read from the environment instead of a flag so it does
// not appear in the process list or shell history.
func (c config) notifyConfig() app.NotifyConfig {
	return app.NotifyConfig{
		SlackURL:     c.slackURL,
		SMTPAddr:     c.mailServer,
		SMTPFrom:     c.mailFrom,
		SMTPTo:       splitAddresses(c.mailTo),
		SMTPNoTLS:    c.mailNoTLS,
		SMTPUser:     c.mailUser,
		SMTPPassword: os.Getenv("VNCSHOT_MAIL_PASSWORD"),
		SyslogAddr:   c.syslogAddr,
	}
}

// splitAddresses breaks the comma-separated -mail-to value into envelope
// recipients and drops empty entries from sloppy input like "a@x, b@x,".
func splitAddresses(value string) []string {
	entries := strings.Split(value, ",")
	recipients := make([]string, 0, len(entries))
	for _, entry := range entries {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			recipients = append(recipients, trimmed)
		}
	}
	return recipients
}

func main() {
	// The app package builds outbound requests (webhook User-Agent) and the
	// SARIF driver descriptor, so both need the version that install.sh
	// injected at build time.
	app.Version = version
	report.SARIFDriverVersion = version

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

	// -selfcheck is a diagnostic, not a scan: it must run without root so it
	// can tell an unprivileged operator what is missing.
	if cfg.selfcheck {
		if err := runSelfCheck(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}

	// -verify-manifest is an offline evidence check, not a scan: it must
	// work on any machine without root and without the scan-time
	// environment, so it runs before the privilege check like -selfcheck.
	if cfg.verifyManifest != "" {
		if err := runVerifyManifest(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
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

	// The signing key is loaded (or generated) once, before any scan, so a
	// broken key file fails the invocation before any probe starts and the
	// GUI and CLI rounds share the same key.
	var signKey ed25519.PrivateKey
	if cfg.signKey != "" {
		key, generated, err := app.LoadOrCreateSignKey(cfg.signKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		if generated {
			fmt.Fprintf(os.Stderr, "sign-key: generated ed25519 key pair %s and %s\n", cfg.signKey, cfg.signKey+".pub")
		}
		signKey = key
	}

	if cfg.gui {
		scanCfg := cfg.appConfig()
		scanCfg.SignKey = signKey
		err = gui.Run(gui.Config{
			Scan:        scanCfg,
			Version:     version,
			Host:        cfg.host,
			Port:        cfg.port,
			OpenBrowser: !cfg.noBrowser,
			Reason:      "gui",
		})
	} else {
		err = runCLI(cfg, signKey)
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
	flag.StringVar(&cfg.sarif, "sarif", "", "SARIF 2.1.0 report path (default <run-dir>/"+appName+"_report.sarif when set)")
	flag.StringVar(&cfg.baseline, "baseline", "", "previous run directory to compare against")
	flag.StringVar(&cfg.resume, "resume", "", "continue a previously interrupted run; completed targets are reused")
	flag.BoolVar(&cfg.manifest, "manifest", false, "write a SHA-256 checksum manifest for the run artifacts")
	flag.StringVar(&cfg.signKey, "sign-key", "", "ed25519 PKCS#8 private key that signs the manifest; generated with mode 0600 when missing (requires -manifest)")
	flag.StringVar(&cfg.verifyManifest, "verify-manifest", "", "verify the signed manifest and every artifact of this run directory, then exit (no root needed)")
	flag.StringVar(&cfg.pubKey, "pub-key", "", "public key for -verify-manifest (default <sign-key>.pub)")
	flag.BoolVar(&cfg.redact, "redact", false, "replace captured passwords with a placeholder (safe to share)")
	flag.BoolVar(&cfg.thumbOnly, "thumb-only", false, "embed only preview images in the HTML report (smaller file)")
	flag.BoolVar(&cfg.noColor, "no-color", false, "disable ANSI colour in terminal output (NO_COLOR is also honoured)")
	flag.IntVar(&cfg.keepRuns, "keep", 0, "keep only the newest N run folders after a scan (0 = keep all)")
	flag.IntVar(&cfg.prune, "prune", 0, "delete all but the newest N run folders and exit (0 = disabled)")
	flag.BoolVar(&cfg.pruneDryRun, "prune-dry-run", false, "with -prune or -keep, list what would be deleted")
	flag.BoolVar(&cfg.dryRun, "dry-run", false, "expand targets and report the scope without scanning")
	flag.StringVar(&cfg.webhook, "webhook", "", "POST a JSON summary to this URL when the scan finishes with new findings or weak credentials")
	flag.StringVar(&cfg.slackURL, "slack-url", "", "send a formatted Slack message when the scan finishes (https incoming-webhook URL)")
	flag.StringVar(&cfg.mailServer, "mail-server", "", "SMTP relay as host:port for email notifications")
	flag.StringVar(&cfg.mailFrom, "mail-from", "", "envelope sender address for email notifications")
	flag.StringVar(&cfg.mailTo, "mail-to", "", "comma-separated recipient addresses for email notifications")
	flag.BoolVar(&cfg.mailNoTLS, "mail-no-tls", false, "allow plaintext SMTP without STARTTLS (discouraged)")
	flag.StringVar(&cfg.mailUser, "mail-user", "", "SMTP AUTH PLAIN user (password comes from the VNCSHOT_MAIL_PASSWORD environment variable)")
	flag.StringVar(&cfg.syslogAddr, "syslog", "", "send a CEF message to this syslog receiver (udp://host:port or tcp://host:port)")
	flag.StringVar(&cfg.accept, "accept", "", "file listing approved endpoints (ip:port [reason]) whose findings are not alarmed about")
	flag.StringVar(&cfg.exclude, "exclude", "", "file with IPs, CIDR ranges or ip:port entries that are never contacted")
	flag.StringVar(&cfg.failOn, "fail-on", "", "exit with code 3 when any of these finding categories match: new, resolved, changed, passwordless, weak, self-signed, cert-expiring (comma-separated)")
	flag.IntVar(&cfg.certWarnDays, "cert-warn", 30, "days ahead of expiry to flag TLS certificates (0 disables)")
	flag.StringVar(&cfg.proxyURL, "proxy", "", "outbound proxy for all probes, socks5://[user:pass@]host[:port] (socks5h resolves through the proxy)")
	flag.StringVar(&cfg.metricsAddr, "metrics-addr", "", "serve scan counters in Prometheus text exposition on this address (use 127.0.0.1:PORT)")
	flag.DurationVar(&cfg.interval, "interval", 0, "rescan forever with this pause between rounds, diffing against the previous round (e.g. 24h)")
	flag.BoolVar(&cfg.selfcheck, "selfcheck", false, "verify the environment (root, report root, TLS roots, browser) and exit")
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

	if cfg.certWarnDays < 0 {
		return cfg, fmt.Errorf("cert-warn must not be negative")
	}
	// -interval re-runs the same scope automatically, which contradicts a
	// resume (the scope already completed) and a fixed baseline (every
	// round would repeat the same stale comparison). The GUI drives its own
	// loop, so the two surfaces must not fight over the scheduler.
	if cfg.interval > 0 {
		if cfg.resume != "" {
			return cfg, fmt.Errorf("interval cannot be combined with -resume: a resumed run already completed part of its scope")
		}
		if cfg.baseline != "" {
			return cfg, fmt.Errorf("interval cannot be combined with -baseline: each round diffs against the previous round automatically")
		}
		if cfg.gui {
			return cfg, fmt.Errorf("interval cannot be combined with -gui: the GUI drives its own live loop")
		}
	}
	if err := validateNotificationFlags(cfg); err != nil {
		return cfg, err
	}

	// -fail-on drives the process exit code, so it only applies to the CLI
	// loop; the GUI owns its own lifecycle.
	if cfg.failOn != "" {
		categories, err := resolveFailOn(cfg.failOn, cfg.baseline, cfg.interval)
		if err != nil {
			return cfg, err
		}
		if cfg.gui {
			return cfg, fmt.Errorf("fail-on cannot be combined with -gui: the GUI does not control the process exit code")
		}
		cfg.failOnCategories = categories
	}
	// A signing key that only feeds -verify-manifest (to derive the public
	// key path) never signs anything, so -manifest is only required when a
	// scan will actually run.
	if cfg.signKey != "" && !cfg.manifest && cfg.verifyManifest == "" {
		return cfg, fmt.Errorf("sign-key requires -manifest: there is no manifest to sign")
	}
	if cfg.pubKey != "" && cfg.verifyManifest == "" {
		return cfg, fmt.Errorf("pub-key is only used together with -verify-manifest")
	}
	if cfg.verifyManifest != "" && cfg.pubKey == "" && cfg.signKey == "" {
		return cfg, fmt.Errorf("verify-manifest requires -pub-key or -sign-key to locate the public key")
	}

	return cfg, nil
}

// resolveFailOn parses and validates the -fail-on value. The baseline
// categories compare two runs, so they need either an explicit -baseline or
// the automatic per-round baseline of -interval.
func resolveFailOn(failOn, baseline string, interval time.Duration) ([]string, error) {
	categories, err := app.ParseFailOnCategories(failOn)
	if err != nil {
		return nil, err
	}
	var baselineOnly []string
	for _, category := range categories {
		if app.IsBaselineFailOnCategory(category) {
			baselineOnly = append(baselineOnly, category)
		}
	}
	if len(baselineOnly) == 0 {
		return categories, nil
	}
	if baseline == "" && interval <= 0 {
		return nil, fmt.Errorf("fail-on %s requires -baseline (or -interval, which diffs against the previous round)",
			strings.Join(baselineOnly, ","))
	}
	return categories, nil
}

// validateNotificationFlags rejects misconfigured notification endpoints at
// parse time. Failing at the first completed scan would discover a typo after
// a scan the operator may have waited an hour for. Proxy checks belong here
// for the same reason: a bad scheme would otherwise fail every single probe.
func validateNotificationFlags(cfg config) error {
	if cfg.proxyURL != "" {
		parsed, err := url.Parse(cfg.proxyURL)
		if err != nil || (parsed.Scheme != "socks5" && parsed.Scheme != "socks5h") || parsed.Host == "" {
			return fmt.Errorf("proxy must be socks5:// or socks5h://[user:pass@]host[:port]")
		}
	}
	if cfg.slackURL != "" {
		parsed, err := url.Parse(cfg.slackURL)
		// Slack incoming webhooks carry a secret token in the URL, so
		// plaintext http would leak it to the network.
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			return fmt.Errorf("slack-url must be an https:// incoming-webhook URL")
		}
	}
	if (cfg.mailFrom != "" || cfg.mailTo != "") && cfg.mailServer == "" {
		return fmt.Errorf("mail-from/mail-to require -mail-server")
	}
	if cfg.mailServer != "" && cfg.mailTo == "" {
		return fmt.Errorf("mail-server requires at least one -mail-to address")
	}
	if cfg.syslogAddr != "" {
		parsed, err := url.Parse(cfg.syslogAddr)
		if err != nil || (parsed.Scheme != "udp" && parsed.Scheme != "tcp") || parsed.Host == "" || parsed.Port() == "" {
			return fmt.Errorf("syslog must be udp://host:port or tcp://host:port")
		}
	}
	if cfg.metricsAddr != "" && !loopbackListenAddr(cfg.metricsAddr) {
		// Not fatal: an operator may deliberately expose counters to a
		// monitoring host. Say it loudly anyway, because the endpoint has
		// no authentication.
		fmt.Fprintln(os.Stderr, "warning: -metrics-addr is not loopback-bound; the endpoint has no authentication")
	}
	return nil
}

// loopbackListenAddr reports whether the address binds a loopback interface.
// The host may be an IP or a name; anything that does not clearly resolve to
// loopback is treated as exposed.
func loopbackListenAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func versionText() string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s/%s, %s)",
		appName, version, commit, buildDate, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "%s %s — VNC security inventory scanner (Linux)\n\n", appName, version)
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s -target <IP|CIDR|range> [flags]\n", appName)
	fmt.Fprintf(w, "  %s -file <path> [flags]\n", appName)
	fmt.Fprintf(w, "  %s -gui [flags]\n\n", appName)
	fmt.Fprintf(w, "Probes VNC/RFB endpoints, flags passwordless servers and captures\n")
	fmt.Fprintf(w, "their framebuffers. Each scan writes JSON, HTML and PDF reports plus\n")
	fmt.Fprintf(w, "PNG screenshots into a timestamped folder under -out-dir.\n\n")
	fmt.Fprintf(w, "-gui starts a local web interface with the same options and live\n")
	fmt.Fprintf(w, "progress. It listens on loopback only and does not require root.\n\n")
	fmt.Fprintf(w, "Flags:\n")
	flag.PrintDefaults()
	fmt.Fprintf(w, "\nDeveloper: Cuma KURT <cumakurt@gmail.com>\n")
	fmt.Fprintf(w, "https://github.com/cumakurt/vncshot\n")
	fmt.Fprintf(w, "https://www.linkedin.com/in/cuma-kurt-34414917/\n")
}

func runCLI(cfg config, signKey ed25519.PrivateKey) error {
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The metrics endpoint lives for the whole invocation and the counters
	// describe the most recent round, so -interval deployments expose a
	// live view of the inventory. Bind errors are fatal: the operator
	// explicitly asked for the endpoint.
	var metrics *app.Metrics
	if cfg.metricsAddr != "" {
		metrics = app.NewMetrics()
		go func() {
			// Shutdown and bind problems are already reported by the
			// validation and the readiness line; a serve error after a
			// successful bind must not abort a running scan.
			_ = metrics.Serve(ctx, cfg.metricsAddr)
		}()
	}

	round := 0
	var reportRoot string
	for {
		if cfg.interval > 0 {
			fmt.Fprintf(os.Stderr, "\n=== round %d ===\n", round+1)
		}
		roundStart := time.Now()
		out, err := runRound(ctx, cfg, signKey, round, reportRoot)
		if err != nil {
			return err
		}
		if out.RunDir != "" {
			// Later rounds diff against the previous round, so the baseline
			// search must look in the root this invocation actually writes
			// to, which may differ from -out-dir after a fallback.
			reportRoot = filepath.Dir(out.RunDir)
		}
		if metrics != nil {
			metrics.Publish(out)
		}
		// The exit-code decision is the last step of a completed round: the
		// reports are already on disk, because findings are data, not a
		// tool failure. With -interval a match stops the loop.
		if cfg.failOn != "" {
			if matches := app.EvaluateFailOn(out.Results, out.Diff, cfg.failOnCategories,
				time.Now().UTC(), certWarnWindow(cfg.certWarnDays)); len(matches) > 0 {
				fmt.Fprintf(os.Stderr, "fail-on matched: %s\n", failOnSummary(matches))
				os.Exit(3)
			}
		}
		if cfg.interval <= 0 {
			return nil
		}
		round++

		// The schedule is measured from round starts, so a slow round
		// cannot drift the cadence. An overrunning round runs the next one
		// immediately; there is no catch-up burst.
		delay := app.ScheduleDelay(cfg.interval, roundStart, time.Now())
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return nil
		}
	}
}

// runRound prepares and scans once. From the second round of an -interval
// invocation the previous round in the same report root is the diff baseline,
// which is what turns a repeated scan into a change feed. The signKey may be
// nil when -sign-key was not configured.
func runRound(ctx context.Context, cfg config, signKey ed25519.PrivateKey, round int, reportRoot string) (app.Outcome, error) {
	// Colour and the carriage-return progress bar are terminal affordances:
	// a pipe, a log file or a CI collector gets plain single-shot lines so
	// the captured output stays readable and byte-stable.
	console := app.NewConsole(os.Stderr, !cfg.noColor)
	scanCfg := cfg.appConfig()
	scanCfg.ShowProgress = console.Color
	scanCfg.SignKey = signKey
	if round > 0 && cfg.interval > 0 {
		if previous, ok, err := app.PreviousRun(reportRoot); err != nil {
			return app.Outcome{}, fmt.Errorf("choose baseline for round %d: %w", round+1, err)
		} else if ok {
			scanCfg.Baseline = previous
		}
	}

	session, err := app.Prepare(scanCfg)
	if err != nil {
		return app.Outcome{}, err
	}
	if warning := session.FallbackWarning(); warning != "" {
		fmt.Fprintf(os.Stderr, "%s\n", console.Yellow("warning: "+warning))
	}

	fmt.Fprintf(os.Stderr, "%s %s host:port pairs | %s %s | %s %s | %s %s\n",
		console.Bold("targets:"), console.Tone(len(session.Targets), "cyan"),
		console.Bold("ports:"), console.Cyan(cfg.ports),
		console.Bold("workers:"), console.Tone(cfg.workers, "cyan"),
		console.Bold("rate:"), console.Cyan(rateText(cfg.rate)))
	fmt.Fprintf(os.Stderr, "%s %s\n", console.Bold("password candidates:"), console.Tone(len(session.Credentials), "cyan"))
	if excluded := session.ExcludedTargets(); excluded > 0 {
		fmt.Fprintf(os.Stderr, "excluded: %d target(s) never contacted (%s)\n", excluded, cfg.exclude)
	}
	if session.AcceptanceFile() != "" {
		fmt.Fprintf(os.Stderr, "accepted endpoints: %s\n", session.AcceptanceFile())
	}
	fmt.Fprintf(os.Stderr, "report directory: %s\n", session.RunDir)
	if cfg.resume != "" {
		fmt.Fprintf(os.Stderr, "resuming: reused %d result(s) from %s, %d target(s) remaining\n",
			session.ResumedTargets(), filepath.Base(cfg.resume), session.RemainingTargets())
	}

	out, scanErr := session.Scan(ctx, nil)
	// Without a terminal there is no live bar, so one completion line keeps
	// a piped log meaningful; with a terminal the bar already said this.
	if !console.Color {
		fmt.Fprintf(os.Stderr, "scanning complete (%d/%d probes)\n",
			out.Summary.Targets, out.Summary.Targets)
	}

	fmt.Fprintf(os.Stderr, "\n%s\n", console.Bold("=== summary ==="))
	fmt.Fprintf(os.Stderr, "targets:      %s\n", console.Tone(out.Summary.Targets, "cyan"))
	if out.Resumed > 0 {
		fmt.Fprintf(os.Stderr, "resumed:      %s\n", console.Tone(out.Resumed, "cyan"))
	}
	fmt.Fprintf(os.Stderr, "open:         %s\n", console.Tone(out.Summary.Open, "cyan"))
	fmt.Fprintf(os.Stderr, "rfb services: %s\n", console.Tone(out.Summary.RFB, "cyan"))
	fmt.Fprintf(os.Stderr, "passwordless: %s\n", console.Tone(out.Summary.Passwordless, "red"))
	fmt.Fprintf(os.Stderr, "weak creds:   %s\n", console.Tone(out.Summary.WeakCredentials, "red"))
	fmt.Fprintf(os.Stderr, "screenshots:  %s\n", console.Tone(out.Summary.Screenshots, "green"))
	fmt.Fprintf(os.Stderr, "errors:       %s\n", console.Tone(out.Summary.Errors, "yellow"))
	writeDiffSummary(os.Stderr, out.Diff)
	fmt.Fprintf(os.Stderr, "json:  %s\n", console.Cyan(out.JSON))
	fmt.Fprintf(os.Stderr, "html:  %s\n", console.Cyan(out.HTML))
	if out.PDF != "" {
		fmt.Fprintf(os.Stderr, "pdf:   %s\n", console.Cyan(out.PDF))
	}
	if out.CSV != "" {
		fmt.Fprintf(os.Stderr, "csv:   %s\n", console.Cyan(out.CSV))
	}
	if out.SARIF != "" {
		fmt.Fprintf(os.Stderr, "sarif: %s\n", console.Cyan(out.SARIF))
	}
	if out.Manifest != "" {
		fmt.Fprintf(os.Stderr, "manifest: %s\n", console.Cyan(out.Manifest))
	}
	if out.Signature != "" {
		fmt.Fprintf(os.Stderr, "signature: %s\n", console.Cyan(out.Signature))
	}
	if len(out.RemovedRuns) > 0 {
		fmt.Fprintf(os.Stderr, "retention:   removed %s old run(s)\n", console.Tone(len(out.RemovedRuns), "yellow"))
	}
	if out.Summary.ExpiringSoon > 0 {
		fmt.Fprintf(os.Stderr, "expiring certs: %s\n", console.Tone(out.Summary.ExpiringSoon, "yellow"))
	}
	if out.Summary.AcceptedFindings > 0 {
		fmt.Fprintf(os.Stderr, "accepted findings: %s (see -accept list)\n", console.Tone(out.Summary.AcceptedFindings, "cyan"))
	}
	if out.Warning != "" {
		fmt.Fprintf(os.Stderr, "%s\n", console.Yellow("warning: "+out.Warning))
	}

	return out, scanErr
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

// certWarnWindow converts the -cert-warn day count into the duration the
// expiry checks use. Zero disables the window, matching the flag semantics.
func certWarnWindow(days int) time.Duration {
	return time.Duration(days) * 24 * time.Hour
}

// failOnSummary renders the matched categories for the exit-3 line, for
// example "passwordless (1 passwordless host(s)), new (3 new finding(s))".
func failOnSummary(matches []app.FailOnMatch) string {
	parts := make([]string, 0, len(matches))
	for _, match := range matches {
		parts = append(parts, fmt.Sprintf("%s (%s)", match.Category, match.Detail()))
	}
	return strings.Join(parts, ", ")
}

// runVerifyManifest checks the detached manifest signature and then every
// artifact digest of a run directory. It is deliberately offline: only the
// run directory and the public key are read, so an assessor can verify a
// copied evidence folder on any machine.
func runVerifyManifest(cfg config) error {
	publicPath := cfg.pubKey
	if publicPath == "" {
		publicPath = cfg.signKey + ".pub"
	}
	publicKey, err := app.LoadSignPublicKey(publicPath)
	if err != nil {
		return err
	}
	if err := app.VerifySignedManifest(cfg.verifyManifest, publicKey); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "manifest signature and artifacts verified: %s\n", cfg.verifyManifest)
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

// runSelfCheck prints the environment verdict of -selfcheck and fails the
// invocation only on a "fail" check; warnings are informational.
func runSelfCheck(cfg config) error {
	checks := app.SelfCheck(app.SelfCheckOptions{ReportRoot: cfg.outDir})
	failed := false
	for _, check := range checks {
		fmt.Printf("%-14s %s\n", check.Status+":", check.Name)
		if check.Detail != "" {
			fmt.Printf("               %s\n", check.Detail)
		}
		if check.Status == app.StatusFail {
			failed = true
		}
	}
	if failed {
		return fmt.Errorf("self-check failed; resolve the failures above before scanning")
	}
	return nil
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

	removed, err := app.PruneRuns(root, keep, cfg.pruneDryRun, cfg.resume)
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
	if plan.Excluded > 0 {
		fmt.Fprintf(os.Stderr, "excluded:           %d (never contacted)\n", plan.Excluded)
	}
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
