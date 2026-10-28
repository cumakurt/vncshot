// Package app holds the scan pipeline shared by the CLI and the GUI so both
// surfaces always validate, scan and report identically.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vncshot/report"
	"vncshot/scanner"
	"vncshot/vnc"
)

// RunTimestampLayout names each scan run directory.
const RunTimestampLayout = "20060102-150405"

// Config describes a single scan request. Values match the CLI flags.
type Config struct {
	Target         string
	File           string
	Ports          string
	ConnectTimeout time.Duration
	VNCTimeout     time.Duration
	Workers        int
	RatePerSec     int
	// MaxRetries is how many extra connection attempts a flaky target may
	// get (0 or 1). Zero disables retrying.
	MaxRetries      int
	HostConcurrency int
	Shared          bool
	NoPDF           bool

	// WordList is an optional file with extra password candidates.
	WordList string
	// NoDefaultPasswords disables the built-in weak-password list.
	NoDefaultPasswords bool
	// NoPasswordCheck disables password testing entirely.
	NoPasswordCheck bool
	// ShowProgress draws the terminal progress bar (CLI only).
	ShowProgress bool

	// OutDir is the root for timestamped run folders.
	OutDir string
	// OutDirExplicit disables the writable-directory fallback, because the
	// operator asked for that exact location.
	OutDirExplicit bool

	Output        string
	HTML          string
	PDF           string
	CSV           string
	ScreenshotDir string

	// Baseline points at a previous run directory; results are compared with
	// it so the report can show new and resolved findings.
	Baseline string
	// ResumeDir points at an interrupted run directory; already completed
	// targets are reused instead of being probed again.
	ResumeDir string
	// WebhookURL receives a POST when a completed scan contains new
	// findings or weak credentials.
	WebhookURL string
	// Manifest writes a checksum manifest for the run artifacts.
	Manifest bool

	// SourceAddr binds probes to a specific local address ("", "auto" or an
	// IP). It matters on multi-homed hosts where the route is ambiguous.
	SourceAddr string
	// Redact replaces captured credentials with a placeholder in every
	// artifact. Use it when a report is handed to a third party.
	Redact bool
	// ThumbnailOnly keeps the full-resolution captures out of the HTML
	// report, which keeps large inventories shareable as one file.
	ThumbnailOnly bool
	// KeepRuns bounds how many run folders stay below the report root after
	// a successful scan. Zero disables pruning.
	KeepRuns int
	// PruneDryRun reports the runs that retention would remove without
	// deleting them.
	PruneDryRun bool

	// ExcludeFile lists hosts or networks that must not be contacted at
	// all, for example a critical production segment. Targets matching an
	// entry are dropped before any connection attempt.
	ExcludeFile string
	// AcceptFile lists endpoints whose findings are known and approved.
	// Accepted results stay in the inventory but are not alarmed about.
	AcceptFile string
	// CertWarn is the certificate expiry window: peer certificates that
	// expire within this duration raise an expiring-soon posture. Zero
	// disables the check.
	CertWarnDays int
	// ProxyURL is an optional outbound proxy used for every probe, in
	// socks5:// or socks5h:// form. Empty connects directly.
	ProxyURL string
	// Notify configures the additional notification channels a completed
	// scan reports to. Zero fields keep the channel disabled.
	Notify NotifyConfig
	// MetricsAddr serves scan counters in Prometheus text exposition on
	// this address. Empty disables the endpoint.
	MetricsAddr string
	// Interval repeats the scan forever, sleeping that long between rounds
	// and using the previous round as the diff baseline. Zero runs once.
	Interval time.Duration
}

// NotifyConfig describes the extra notification channels a completed scan
// reports to, alongside the plain webhook. Zero fields keep a channel
// disabled.
type NotifyConfig struct {
	// SlackURL is a Slack incoming-webhook endpoint receiving a formatted
	// message. Only https endpoints are accepted.
	SlackURL string
	// SMTPAddr is the mail relay as host:port. Empty disables email.
	SMTPAddr string
	// SMTPFrom is the envelope sender address.
	SMTPFrom string
	// SMTPTo lists envelope recipient addresses.
	SMTPTo []string
	// SMTPNoTLS allows a plaintext SMTP session; by default a relay that
	// does not offer STARTTLS is refused, because the message carries
	// finding details.
	SMTPNoTLS bool
	// SMTPUser and SMTPPassword authenticate with AUTH PLAIN after
	// STARTTLS. Both or neither must be set.
	SMTPUser     string
	SMTPPassword string
	// SyslogAddr sends a CEF message over the network, in
	// "udp://host:port" or "tcp://host:port" form. Empty disables it.
	SyslogAddr string
}

// Progress reports scan advancement to a caller-supplied observer.
type Progress struct {
	Done   int
	Total  int
	Result report.Result
}

// Session is a prepared scan: targets parsed, run directory created and
// artifact paths resolved. Scanning happens separately so callers can
// announce the run before any probe starts.
type Session struct {
	Targets     []scanner.Target
	Credentials []vnc.Credential
	RunDir      string
	JSONPath    string
	HTMLPath    string
	PDFPath     string
	CSVPath     string
	ShotDir     string
	config      Config
	fallbacked  bool
	fallbackErr error

	// baseline holds the previous run's results when a comparison was
	// requested. It is loaded during Prepare so a broken baseline fails
	// before any probe starts.
	baseline    []report.Result
	baselineDir string
	sourceIP    net.IP

	// remaining is the subset of Targets that still needs a probe; the rest
	// was completed by the run named by resumeDir and is held in reused.
	remaining []scanner.Target
	reused    []report.Result
	resumeDir string
}

// Outcome is the result of a completed scan.
type Outcome struct {
	Results []report.Result
	Summary report.Summary
	RunDir  string
	JSON    string
	HTML    string
	PDF     string
	CSV     string
	// Manifest is the checksum manifest path, when one was requested.
	Manifest string
	ShotDir  string
	// Diff is the baseline comparison, nil when no baseline was requested.
	Diff *Diff
	// Warning carries non-fatal problems such as a failed webhook
	// notification or retention pass. Callers should surface it to the
	// operator, for example on stderr, without treating the scan as failed.
	Warning string
	// RemovedRuns lists the old run folders that retention deleted (or would
	// delete, when pruning is a dry run).
	RemovedRuns []RunInfo
	// Resumed is how many results came from the resume source instead of a
	// fresh probe. It is zero for a normal scan.
	Resumed int
	// Remaining is how many targets this run still had to probe after the
	// resume plan was applied. It equals Summary.Targets - Resumed.
	Remaining int
}

// Prepare validates the request, expands targets and creates the run folder.
func Prepare(cfg Config) (*Session, error) {
	// A resumed run reuses results from a different scope, so comparing it
	// against a baseline would report findings as new or resolved merely
	// because they were or were not probed.
	if cfg.ResumeDir != "" && cfg.Baseline != "" {
		return nil, fmt.Errorf("-resume cannot be combined with -baseline: a resumed run would compare a different scope")
	}

	ports, err := scanner.ParsePorts(cfg.Ports)
	if err != nil {
		return nil, err
	}
	targets, err := scanner.ParseTargets(cfg.Target, cfg.File, ports)
	if err != nil {
		return nil, err
	}

	// Bound the resource knobs here so the CLI and the GUI reject the same
	// values with the same message. A negative worker count would silently
	// fall back to the default and a huge one would exhaust sockets.
	if cfg.Workers < 0 {
		return nil, fmt.Errorf("workers must not be negative")
	}
	if cfg.Workers > scanner.MaxWorkers {
		return nil, fmt.Errorf("workers must be at most %d", scanner.MaxWorkers)
	}
	if cfg.RatePerSec > scanner.MaxRate {
		return nil, fmt.Errorf("rate must be at most %d connections per second", scanner.MaxRate)
	}

	creds, err := Credentials(cfg)
	if err != nil {
		return nil, err
	}

	// A baseline was explicitly requested, so a missing or broken report is
	// a hard error. Loading it before the run directory is created avoids
	// leaving an empty run behind.
	var baseline []report.Result
	if cfg.Baseline != "" {
		baseline, err = LoadBaseline(cfg.Baseline)
		if err != nil {
			return nil, fmt.Errorf("baseline comparison requested: %w", err)
		}
	}

	// Resume has the same fail-fast contract: a missing or broken report must
	// stop the scan before an empty run folder is created. Results outside
	// the requested scope are dropped so the merged report never describes
	// endpoints the operator did not ask for.
	remaining := targets
	var reused []report.Result
	if cfg.ResumeDir != "" {
		previous, err := LoadCompleted(cfg.ResumeDir)
		if err != nil {
			return nil, fmt.Errorf("resume requested: %w", err)
		}
		remaining, reused, err = ResumePlan(previous, targets)
		if err != nil {
			return nil, fmt.Errorf("resume requested: %w", err)
		}
	}

	runDir, fallbacked, fallbackErr := prepareRunDir(cfg)
	if runDir == "" {
		// fallbackErr carries the reason when no writable root could be
		// found; without a run directory there is nothing to report to.
		return nil, fallbackErr
	}

	s := &Session{
		Targets:     targets,
		Credentials: creds,
		RunDir:      runDir,
		JSONPath:    resolveArtifactPath(cfg.Output, runDir, "vncshot_report.json"),
		HTMLPath:    resolveArtifactPath(cfg.HTML, runDir, "vncshot_report.html"),
		PDFPath:     resolveArtifactPath(cfg.PDF, runDir, "vncshot_report.pdf"),
		CSVPath:     resolveArtifactPath(cfg.CSV, runDir, "vncshot_report.csv"),
		ShotDir:     resolveArtifactPath(cfg.ScreenshotDir, runDir, "screenshots"),
		config:      cfg,
		fallbacked:  fallbacked,
		fallbackErr: fallbackErr,
		baseline:    baseline,
		baselineDir: cfg.Baseline,
		remaining:   remaining,
		reused:      reused,
		resumeDir:   cfg.ResumeDir,
	}
	if addr := strings.TrimSpace(cfg.SourceAddr); addr != "" && !strings.EqualFold(addr, "auto") {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("source address %q is not a valid IP", addr)
		}
		s.sourceIP = ip
	}

	if err := os.MkdirAll(s.ShotDir, 0o700); err != nil {
		return nil, fmt.Errorf("create screenshot directory: %w", err)
	}
	return s, nil
}

// FallbackWarning explains why reports landed outside the configured root.
// Returns "" when the configured base directory was used.
func (s *Session) FallbackWarning() string {
	if !s.fallbacked {
		return ""
	}
	return fmt.Sprintf("%v; writing reports to %s", s.fallbackErr, filepath.Dir(s.RunDir))
}

// ReportRoot returns the directory that holds this session's run folder.
func (s *Session) ReportRoot() string {
	return filepath.Dir(s.RunDir)
}

// ResumedTargets returns how many targets are satisfied by results reused
// from the resume source instead of a fresh probe.
func (s *Session) ResumedTargets() int {
	return len(s.reused)
}

// RemainingTargets returns how many targets this session still has to probe.
// It equals len(Targets) - ResumedTargets().
func (s *Session) RemainingTargets() int {
	return len(s.remaining)
}

// Scan probes every target that still needs one and writes JSON, HTML, CSV
// and (optionally) PDF reports, plus an optional checksum manifest. Results
// reused from a resume source are merged into the same result set. A
// cancelled context returns partial results together with context.Canceled.
func (s *Session) Scan(ctx context.Context, progress func(Progress)) (Outcome, error) {
	cfg := s.config

	opts := scanner.Options{
		ConnectTimeout:  cfg.ConnectTimeout,
		VNCTimeout:      cfg.VNCTimeout,
		Workers:         cfg.Workers,
		RatePerSec:      cfg.RatePerSec,
		MaxRetries:      cfg.MaxRetries,
		HostConcurrency: cfg.HostConcurrency,
		ScreenshotDir:   s.ShotDir,
		Shared:          cfg.Shared,
		Passwords:       s.Credentials,
		LocalAddr:       s.sourceIP,
		ShowProgress:    cfg.ShowProgress,
	}
	if progress != nil {
		// Progress covers the full requested scope, not just the probes this
		// run still performs, so a resumed scan's bar starts at the reused
		// count instead of appearing to restart from zero.
		fullScope := len(s.reused) + len(s.remaining)
		opts.OnProgress = func(done int, total int, r report.Result) {
			progress(Progress{Done: len(s.reused) + done, Total: fullScope, Result: r})
		}
	}

	results, scanErr := scanner.Run(ctx, s.remaining, opts)
	// Reused results describe the rest of the requested scope, so they join
	// the fresh probes before sorting and reporting; every artifact then
	// covers the whole scope rather than only the resumed tail.
	results = append(results, s.reused...)
	// Sort once before any artifact is written so every report contains the
	// same deterministic order.
	report.SortResults(results)

	out := Outcome{
		Results: results,
		Summary: report.Summarize(results),
		RunDir:  s.RunDir,
		JSON:    s.JSONPath,
		HTML:    s.HTMLPath,
		CSV:     s.CSVPath,
		ShotDir: s.ShotDir,
		// Callers use the counters to explain what a resumed run did.
		Resumed:   len(s.reused),
		Remaining: len(s.remaining),
	}
	if s.baselineDir != "" {
		out.Diff = Compare(s.baselineDir, s.baseline, results)
	}

	// The baseline comparison is rendered into every report so the artifacts
	// stand on their own; it stays nil without -baseline.
	reportOpts := report.Options{
		Diff:          out.Diff.reportDiff(),
		Redact:        cfg.Redact,
		ThumbnailOnly: cfg.ThumbnailOnly,
	}

	// ResumedFrom records only the folder name so a report never carries an
	// absolute host path, matching how the baseline is recorded.
	resumedFrom := ""
	if s.resumeDir != "" {
		resumedFrom = filepath.Base(s.resumeDir)
	}

	if err := report.WriteJSONDocument(s.JSONPath, results, reportOpts, report.DocumentOptions{ResumedFrom: resumedFrom}); err != nil {
		return out, err
	}
	if err := report.WriteHTMLWithOptions(s.HTMLPath, results, reportOpts); err != nil {
		return out, err
	}
	if !cfg.NoPDF {
		if err := report.WritePDFWithOptions(s.PDFPath, results, reportOpts); err != nil {
			// PDF is a convenience artifact; a render failure must not
			// discard the scan itself.
			out.PDF = ""
			if scanErr == nil {
				scanErr = fmt.Errorf("pdf generation skipped: %w", err)
			}
		} else {
			out.PDF = s.PDFPath
		}
	}
	if err := report.WriteCSVWithOptions(s.CSVPath, results, reportOpts); err != nil {
		return out, err
	}

	if cfg.Manifest {
		manifestPath, err := WriteManifest(s.RunDir)
		if err != nil {
			return out, err
		}
		out.Manifest = manifestPath
	}

	// A receiver outage must never fail a completed scan or hide its
	// results, so a notification failure is reported as a warning. Partial
	// results from an interrupted scan are not announced.
	if cfg.WebhookURL != "" && shouldNotifyWebhook(out) && ctx.Err() == nil {
		if err := NotifyWebhook(ctx, cfg.WebhookURL, webhookPayload(out, Version)); err != nil {
			out.Warning = fmt.Sprintf("webhook notification failed: %v", err)
		}
	}

	// Retention runs only for a scan that produced complete artifacts. A
	// failed prune must not discard or fail the scan, so it becomes a
	// warning next to any webhook problem.
	if cfg.KeepRuns > 0 && ctx.Err() == nil {
		removed, err := s.RetainRuns()
		if err != nil {
			message := fmt.Sprintf("retention failed: %v", err)
			if out.Warning == "" {
				out.Warning = message
			} else {
				out.Warning += "; " + message
			}
		} else {
			out.RemovedRuns = removed
		}
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		return out, context.Canceled
	}
	return out, scanErr
}

// prepareRunDir creates the timestamped folder that holds every artifact of
// this scan. When the default base directory is not writable (for example
// when running from a source checkout without install.sh), it falls back to
// a per-user data directory so a scan is never lost to a permissions error.
func prepareRunDir(cfg Config) (runDir string, fallbacked bool, err error) {
	runDir, err = createRunDir(cfg.OutDir)
	if err == nil {
		return runDir, false, nil
	}
	if cfg.OutDirExplicit {
		return "", false, err
	}

	fallback := fallbackReportBase()
	if fallback == "" {
		return "", false, err
	}
	runDir, fallbackErr := createRunDir(fallback)
	if fallbackErr != nil {
		return "", false, err
	}
	return runDir, true, err
}

func createRunDir(base string) (string, error) {
	if err := os.MkdirAll(base, 0o700); err != nil {
		return "", fmt.Errorf("create report root %s: %w", base, err)
	}

	// os.Mkdir on the timestamp folder is atomic, so two scans that start in
	// the same second (two CLI runs, or a CLI run next to a GUI run) cannot
	// share a folder and silently overwrite each other's reports and
	// screenshots. The loser waits for the next second and retries with a
	// fresh timestamp, keeping the documented YYYYMMDD-HHMMSS layout that the
	// GUI history and the baseline comparison parse.
	for attempt := 0; attempt < 5; attempt++ {
		runDir := filepath.Join(base, time.Now().Format(RunTimestampLayout))
		// Runs hold captured desktops and credentials: keep them owner-only.
		err := os.Mkdir(runDir, 0o700)
		switch {
		case err == nil:
			return runDir, nil
		case errors.Is(err, fs.ErrExist):
			time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
		default:
			return "", fmt.Errorf("create report directory %s: %w", runDir, err)
		}
	}
	return "", fmt.Errorf("create report directory under %s: no unique timestamp available", base)
}

func fallbackReportBase() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".local", "share", "vncshot")
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

// Diff summarises how a run compares with a baseline run.
type Diff struct {
	// Baseline is the run directory that was compared against.
	Baseline string
	// New lists findings that were not present in the baseline.
	New []report.Result
	// Resolved lists baseline findings that no longer appear.
	Resolved []report.Result
	// Changed lists findings whose risk changed (for example a host that
	// now accepts a weak password).
	Changed []Change
}

// Change describes a finding whose state differs from the baseline.
type Change struct {
	Before report.Result
	After  report.Result
	Reason string
}
