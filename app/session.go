// Package app holds the scan pipeline shared by the CLI and the GUI so both
// surfaces always validate, scan and report identically.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	Shared         bool
	NoPDF          bool

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
	ScreenshotDir string
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
	ShotDir     string
	config      Config
	fallbacked  bool
	fallbackErr error
}

// Outcome is the result of a completed scan.
type Outcome struct {
	Results []report.Result
	Summary report.Summary
	RunDir  string
	JSON    string
	HTML    string
	PDF     string
	ShotDir string
}

// Prepare validates the request, expands targets and creates the run folder.
func Prepare(cfg Config) (*Session, error) {
	ports, err := scanner.ParsePorts(cfg.Ports)
	if err != nil {
		return nil, err
	}
	targets, err := scanner.ParseTargets(cfg.Target, cfg.File, ports)
	if err != nil {
		return nil, err
	}

	creds, err := Credentials(cfg)
	if err != nil {
		return nil, err
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
		ShotDir:     resolveArtifactPath(cfg.ScreenshotDir, runDir, "screenshots"),
		config:      cfg,
		fallbacked:  fallbacked,
		fallbackErr: fallbackErr,
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

// Scan probes every target and writes JSON, HTML and (optionally) PDF
// reports. A cancelled context returns partial results together with
// context.Canceled.
func (s *Session) Scan(ctx context.Context, progress func(Progress)) (Outcome, error) {
	cfg := s.config

	opts := scanner.Options{
		ConnectTimeout: cfg.ConnectTimeout,
		VNCTimeout:     cfg.VNCTimeout,
		Workers:        cfg.Workers,
		RatePerSec:     cfg.RatePerSec,
		ScreenshotDir:  s.ShotDir,
		Shared:         cfg.Shared,
		Passwords:      s.Credentials,
		ShowProgress:   cfg.ShowProgress,
	}
	if progress != nil {
		opts.OnProgress = func(done int, total int, r report.Result) {
			progress(Progress{Done: done, Total: total, Result: r})
		}
	}

	results, scanErr := scanner.Run(ctx, s.Targets, opts)
	out := Outcome{
		Results: results,
		Summary: report.Summarize(results),
		RunDir:  s.RunDir,
		JSON:    s.JSONPath,
		HTML:    s.HTMLPath,
		ShotDir: s.ShotDir,
	}

	if err := report.WriteJSON(s.JSONPath, results); err != nil {
		return out, err
	}
	if err := report.WriteHTML(s.HTMLPath, results); err != nil {
		return out, err
	}
	if !cfg.NoPDF {
		if err := report.WritePDF(s.PDFPath, results); err != nil {
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
	runDir := filepath.Join(base, time.Now().Format(RunTimestampLayout))
	// Runs hold captured desktops and credentials: keep them owner-only.
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return "", fmt.Errorf("create report directory %s: %w", runDir, err)
	}
	return runDir, nil
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
