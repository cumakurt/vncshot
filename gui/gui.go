// Package gui serves a local, loopback-only web interface for vncshot.
//
// The GUI is deliberately implemented as a web app: the scanner must run as
// root on Linux, so an in-browser front end avoids pulling a cgo/C library
// dependency into the static binary while still offering every CLI option,
// live progress and direct access to the generated reports.
package gui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vncshot/app"
	"vncshot/report"
)

//go:embed index.html
var assets embed.FS

// Config boots the GUI.
type Config struct {
	Scan app.Config
	// Redact and ThumbnailOnly are the launch-time report defaults. The scan
	// pipeline has no switch for them yet (app.Config owns those fields), so
	// the dashboard exposes them as fixed launch options instead of letting
	// the form silently override them.
	Redact        bool
	ThumbnailOnly bool
	Version       string
	Host          string
	Port          int
	OpenBrowser   bool
	Reason        string
}

// scanRequest is the JSON body posted by the form.
type scanRequest struct {
	Target         string `json:"target"`
	File           string `json:"file"`
	Ports          string `json:"ports"`
	TimeoutMs      int    `json:"timeout_ms"`
	VNCTimeoutMs   int    `json:"vnc_timeout_ms"`
	Workers        int    `json:"workers"`
	Rate           int    `json:"rate"`
	OutDir         string `json:"out_dir"`
	Output         string `json:"output"`
	HTML           string `json:"html"`
	PDF            string `json:"pdf"`
	NoPDF          bool   `json:"no_pdf"`
	ScreenshotDir  string `json:"screenshot_dir"`
	Shared         bool   `json:"shared"`
	WordList       string `json:"word_list"`
	NoDefaultPw    bool   `json:"no_default_passwords"`
	NoPasswordChk  bool   `json:"no_password_check"`
	Authorized     bool   `json:"authorized"`
	ScreenshotBase string `json:"screenshot_base"`

	// Run-level options shared with the CLI. Redact and ThumbnailOnly are
	// accepted for a stable form contract but cannot be applied yet: the scan
	// pipeline has no switch for them (see Config.Redact).
	Baseline      string `json:"baseline"`
	CSV           string `json:"csv"`
	Manifest      bool   `json:"manifest"`
	Webhook       string `json:"webhook"`
	Redact        bool   `json:"redact"`
	ThumbnailOnly bool   `json:"thumbnail_only"`
	KeepRuns      int    `json:"keep_runs"`
	PruneDryRun   bool   `json:"prune_dry_run"`
}

type event struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
}

type finding struct {
	IP            string   `json:"ip"`
	Port          int      `json:"port"`
	Addr          string   `json:"addr"`
	ServerName    string   `json:"server_name"`
	Dimensions    string   `json:"dimensions"`
	Passwordless  bool     `json:"passwordless"`
	Password      string   `json:"password,omitempty"`
	AuthLocked    bool     `json:"auth_locked,omitempty"`
	SecurityTypes []string `json:"security_types"`
	TLS           bool     `json:"tls"`
	Attempts      int      `json:"attempts"`
	Open          bool     `json:"open"`
	RFB           bool     `json:"rfb"`
	Error         string   `json:"error"`
	DurationMs    int64    `json:"duration_ms"`
	Screenshot    string   `json:"screenshot"`
	Timestamp     string   `json:"timestamp"`
}

// runInfo is one entry of the run history shown in the dashboard.
type runInfo struct {
	Name      string          `json:"name"`
	Started   string          `json:"started"`
	Files     []string        `json:"files"`
	HasHTML   bool            `json:"has_html"`
	HasPDF    bool            `json:"has_pdf"`
	HasJSON   bool            `json:"has_json"`
	Size      int64           `json:"size"`
	Summary   *report.Summary `json:"summary"`
	startedAt time.Time
}

type snapshot struct {
	Status      string         `json:"status"`
	Error       string         `json:"error"`
	Started     string         `json:"started"`
	Finished    string         `json:"finished"`
	Done        int            `json:"done"`
	Total       int            `json:"total"`
	ElapsedMs   int64          `json:"elapsed_ms"`
	Summary     report.Summary `json:"summary"`
	RunDir      string         `json:"run_dir"`
	Credentials int            `json:"credentials"`
	// On-disk paths stay server-side; the dashboard uses report_links.
	JSON         string            `json:"-"`
	HTML         string            `json:"-"`
	PDF          string            `json:"-"`
	Files        []string          `json:"files"`
	Findings     []finding         `json:"findings"`
	Events       []event           `json:"events"`
	Warning      string            `json:"warning"`
	Version      string            `json:"version"`
	Running      bool              `json:"running"`
	StartedScan  bool              `json:"started_scan"`
	ProgressRate float64           `json:"progress_rate"`
	ReportLinks  map[string]string `json:"report_links"`
	// RemovedRuns counts the old run folders retention deleted (or would
	// delete, for a dry run).
	RemovedRuns int `json:"removed_runs"`
	// Diff summarises the baseline comparison; nil without -baseline.
	Diff *diffSummary `json:"diff,omitempty"`
}

// diffSummary is the dashboard view of a baseline comparison. The full
// per-host lists live in the reports; the dashboard needs the counts and the
// compared run.
type diffSummary struct {
	Baseline string `json:"baseline"`
	New      int    `json:"new"`
	Resolved int    `json:"resolved"`
	Changed  int    `json:"changed"`
}

type runState struct {
	mu          sync.Mutex
	status      string
	errMsg      string
	started     time.Time
	finished    time.Time
	done        int
	total       int
	summary     report.Summary
	runDir      string
	credentials int
	jsonPath    string
	htmlPath    string
	pdfPath     string
	files       []string
	results     []report.Result
	findings    []finding
	events      []event
	warning     string
	diff        *diffSummary
	removedRuns int
	session     *app.Session
	cancel      context.CancelFunc
	subscribers map[chan snapshot]struct{}
	lastSent    time.Time
}

const (
	statusIdle      = "idle"
	statusRunning   = "running"
	statusCompleted = "completed"
	statusCancelled = "cancelled"
	statusFailed    = "failed"

	// defaultReportRoot matches the CLI default when no root was configured.
	defaultReportRoot = "/usr/local/vncshot"
	// maxRunHistory bounds the history payload so a long-lived report tree
	// cannot make the dashboard request arbitrarily expensive.
	maxRunHistory = 100
)

type server struct {
	token   string
	cfg     Config
	run     *runState
	version string
}

// Run starts the GUI and blocks until the process receives a signal.
func Run(cfg Config) error {
	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}
	if !isLoopback(host) {
		return fmt.Errorf("GUI must bind to a loopback address, got %q", host)
	}

	token, err := newToken()
	if err != nil {
		return fmt.Errorf("generate session token: %w", err)
	}

	srv := &server{
		token:   token,
		cfg:     cfg,
		version: cfg.Version,
		run: &runState{
			status:      statusIdle,
			subscribers: map[chan snapshot]struct{}{},
			warning:     preflightWarning(cfg.Scan),
		},
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return fmt.Errorf("listen for GUI: %w", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), token)

	httpSrv := &http.Server{
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: the SSE endpoint is a long-lived stream.
	}

	stopCh := make(chan os.Signal, 1)
	notifySignals(stopCh)
	go func() {
		<-stopCh
		srv.cancelRun()
		_ = httpSrv.Close()
	}()

	fmt.Fprintf(os.Stderr, "\n  vncshot GUI %s\n", cfg.Version)
	fmt.Fprintf(os.Stderr, "  url:      %s\n", url)
	fmt.Fprintf(os.Stderr, "  bind:     %s:%d (loopback only)\n", host, addr.Port)
	fmt.Fprintf(os.Stderr, "  token:    %s\n", token)
	fmt.Fprintf(os.Stderr, "  reports:  %s\n\n", cfg.Scan.OutDir)
	fmt.Fprintf(os.Stderr, "  Press Ctrl+C to stop the GUI.\n\n")

	if cfg.OpenBrowser {
		if err := openBrowser(url); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: could not open a browser (%v)\n", err)
			fmt.Fprintf(os.Stderr, "  open the URL above manually.\n\n")
		}
	}

	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("gui server: %w", err)
	}
	return nil
}

func preflightWarning(cfg app.Config) string {
	if cfg.OutDir == "" {
		return ""
	}
	info, err := os.Stat(cfg.OutDir)
	if err != nil || !info.IsDir() {
		return fmt.Sprintf("report root %s does not exist yet; it will be created on the first scan", cfg.OutDir)
	}
	if !isWritable(cfg.OutDir) {
		return fmt.Sprintf("report root %s is not writable by this process", cfg.OutDir)
	}
	return ""
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/state", s.guard(s.handleState))
	mux.HandleFunc("/api/scan", s.guard(s.handleScan))
	mux.HandleFunc("/api/cancel", s.guard(s.handleCancel))
	mux.HandleFunc("/api/runs", s.guard(s.handleRuns))
	mux.HandleFunc("/api/runs/open", s.guard(s.handleRunOpen))
	mux.HandleFunc("/api/events", s.guard(s.handleEvents))
	mux.HandleFunc("/files/", s.guard(s.handleFiles))
	return mux
}

// guard enforces the session token. The token arrives once as a query
// parameter, is stored in a SameSite=Strict cookie, and must also be echoed
// in a custom header for state-changing requests so a cross-site page cannot
// drive the scanner.
func (s *server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.acceptTokenQuery(w, r)

		cookie, err := r.Cookie("vncshot_token")
		if err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Vncshot-Token")), []byte(s.token)) != 1 {
				http.Error(w, "missing session token header", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

// acceptTokenQuery exchanges a valid ?t= token for the session cookie. The
// dashboard is opened with that URL, so the token has to work on "/" too.
func (s *server) acceptTokenQuery(w http.ResponseWriter, r *http.Request) {
	given := r.URL.Query().Get("t")
	if given == "" || subtle.ConstantTimeCompare([]byte(given), []byte(s.token)) != 1 {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "vncshot_token",
		Value:    s.token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	s.acceptTokenQuery(w, r)
	page, err := assets.ReadFile("index.html")
	if err != nil {
		http.Error(w, "gui assets unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	// The session token is delivered in the URL query string, so it must not
	// reach any other origin through the Referer header.
	w.Header().Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(page)
}

func (s *server) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.snapshot())
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !req.Authorized {
		http.Error(w, "authorization confirmation is required", http.StatusForbidden)
		return
	}

	s.run.mu.Lock()
	if s.run.status == statusRunning {
		s.run.mu.Unlock()
		http.Error(w, "a scan is already running", http.StatusConflict)
		return
	}
	s.run.mu.Unlock()

	scanCfg, err := s.scanConfig(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	session, err := app.Prepare(scanCfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	s.run.mu.Lock()
	s.run.status = statusRunning
	s.run.errMsg = ""
	s.run.started = time.Now()
	s.run.finished = time.Time{}
	s.run.done = 0
	s.run.total = len(session.Targets)
	s.run.summary = report.Summary{Targets: len(session.Targets)}
	s.run.runDir = session.RunDir
	s.run.credentials = len(session.Credentials)
	s.run.jsonPath = session.JSONPath
	s.run.htmlPath = session.HTMLPath
	s.run.pdfPath = session.PDFPath
	s.run.files = nil
	s.run.results = nil
	s.run.findings = nil
	s.run.events = nil
	s.run.warning = session.FallbackWarning()
	s.run.diff = nil
	s.run.removedRuns = 0
	s.run.session = session
	s.run.cancel = cancel
	s.run.mu.Unlock()

	s.pushEvent("scan", fmt.Sprintf("started scan of %d host:port pairs with %d password candidates",
		len(session.Targets), len(session.Credentials)))
	s.broadcast(true)

	go s.execute(ctx, session, cancel)

	writeJSON(w, s.snapshot())
}

func (s *server) execute(ctx context.Context, session *app.Session, cancel context.CancelFunc) {
	defer cancel()

	out, err := session.Scan(ctx, func(p app.Progress) {
		s.run.mu.Lock()
		s.run.done = p.Done
		s.run.results = append(s.run.results, p.Result)
		if p.Result.Open || p.Result.Passwordless || p.Result.Error != "" {
			s.run.findings = append(s.run.findings, toFinding(p.Result))
		}
		// Summarize recomputes from the collected results, which is cheap
		// at report scale and avoids drift between counters and rows.
		s.run.summary = report.Summarize(s.run.results)
		s.run.total = p.Total
		s.run.mu.Unlock()
		s.broadcast(false)
	})

	s.run.mu.Lock()
	s.run.done = out.Summary.Targets
	s.run.summary = out.Summary
	s.run.runDir = out.RunDir
	s.run.jsonPath = out.JSON
	s.run.htmlPath = out.HTML
	s.run.pdfPath = out.PDF
	s.run.finished = time.Now()
	// A webhook failure must not look like a clean run, and a baseline
	// comparison requested on the launch command line must be visible:
	// both were previously dropped on the floor by the GUI.
	if out.Warning != "" {
		if s.run.warning != "" {
			s.run.warning += "; " + out.Warning
		} else {
			s.run.warning = out.Warning
		}
	}
	if out.Diff != nil {
		s.run.diff = &diffSummary{
			Baseline: filepath.Base(out.Diff.Baseline),
			New:      len(out.Diff.New),
			Resolved: len(out.Diff.Resolved),
			Changed:  len(out.Diff.Changed),
		}
	}
	s.run.removedRuns = len(out.RemovedRuns)
	switch {
	case errors.Is(err, context.Canceled):
		s.run.status = statusCancelled
	case err != nil:
		s.run.status = statusFailed
		s.run.errMsg = err.Error()
	default:
		s.run.status = statusCompleted
	}
	s.run.mu.Unlock()

	s.collectFiles(session.RunDir)
	s.pushEvent("scan", fmt.Sprintf("finished: %d open, %d passwordless", out.Summary.Open, out.Summary.Passwordless))
	s.broadcast(true)
}

// collectFiles lists the artifacts of a finished run so the UI can link to
// them without guessing file names.
func (s *server) collectFiles(runDir string) {
	files := listRunFiles(runDir)
	s.run.mu.Lock()
	s.run.files = files
	s.run.mu.Unlock()
}

// listRunFiles returns every regular file below runDir as a slash-separated
// path relative to the run folder.
func listRunFiles(runDir string) []string {
	var files []string
	_ = filepath.WalkDir(runDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(runDir, path)
		if relErr != nil {
			return nil
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	return files
}

// reportRoot is the directory that holds timestamped run folders.
func (s *server) reportRoot() string {
	if s.cfg.Scan.OutDir != "" {
		return filepath.Clean(s.cfg.Scan.OutDir)
	}
	return defaultReportRoot
}

// handleRuns lists previous run folders, newest first.
func (s *server) handleRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, s.listRuns())
}

func (s *server) listRuns() []runInfo {
	root := s.reportRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		// A missing report root simply means there is no history yet.
		return []runInfo{}
	}

	runs := make([]runInfo, 0, len(entries))
	for _, entry := range entries {
		// Symlinked directories can point outside the report root, so they
		// are never treated as runs.
		if entry.Type()&fs.ModeSymlink != 0 || !entry.IsDir() {
			continue
		}
		started, err := time.ParseInLocation(app.RunTimestampLayout, entry.Name(), time.Local)
		if err != nil {
			continue
		}
		runs = append(runs, describeRun(filepath.Join(root, entry.Name()), entry.Name(), started))
	}

	sort.Slice(runs, func(i, j int) bool { return runs[i].startedAt.After(runs[j].startedAt) })
	if len(runs) > maxRunHistory {
		runs = runs[:maxRunHistory]
	}
	return runs
}

// describeRun inspects one run folder without following symlinks inside it.
func describeRun(dir, name string, started time.Time) runInfo {
	info := runInfo{
		Name:      name,
		Started:   started.Format(time.RFC3339),
		Files:     []string{},
		startedAt: started,
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return info
	}
	var preferredJSON, fallbackJSON string
	for _, entry := range entries {
		if entry.Type()&fs.ModeSymlink != 0 || entry.IsDir() {
			continue
		}
		info.Files = append(info.Files, entry.Name())
		if fileInfo, statErr := entry.Info(); statErr == nil {
			info.Size += fileInfo.Size()
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".html") {
			info.HasHTML = true
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".pdf") {
			info.HasPDF = true
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			switch {
			case entry.Name() == defaultJSONReport:
				preferredJSON = filepath.Join(dir, entry.Name())
			case !strings.EqualFold(entry.Name(), manifestFilename) && fallbackJSON == "":
				// A run written with -output may use another name, but the
				// evidence manifest is never the report.
				fallbackJSON = filepath.Join(dir, entry.Name())
			}
		}
	}
	jsonPath := preferredJSON
	if jsonPath == "" {
		jsonPath = fallbackJSON
	}
	info.HasJSON = jsonPath != ""
	if jsonPath == "" {
		return info
	}
	doc, err := readRunDocument(jsonPath)
	if err != nil {
		return info
	}
	summary := doc.Summary
	info.Summary = &summary
	return info
}

const (
	defaultJSONReport = "vncshot_report.json"
	manifestFilename  = "manifest.json"
)

// readRunDocument parses a finished run's JSON report. Reports written by
// this tool wrap the results in Document; a bare result array is accepted so
// runs from older or external producers still open.
func readRunDocument(path string) (report.Document, error) {
	var doc report.Document
	data, err := os.ReadFile(path)
	if err != nil {
		return doc, err
	}
	decodeErr := json.Unmarshal(data, &doc)
	if decodeErr == nil {
		return doc, nil
	}
	var results []report.Result
	if arrayErr := json.Unmarshal(data, &results); arrayErr != nil {
		return doc, fmt.Errorf("decode run report: %w", decodeErr)
	}
	return report.Document{
		Results: results,
		Summary: report.Summarize(results),
	}, nil
}

// validRunName rejects anything that is not a bare timestamp folder name.
func validRunName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") || filepath.IsAbs(name) {
		return false
	}
	_, err := time.ParseInLocation(app.RunTimestampLayout, name, time.Local)
	return err == nil
}

// handleRunOpen switches the dashboard to a previous run folder.
func (s *server) handleRunOpen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(req.Name)
	if !validRunName(name) {
		http.Error(w, "invalid run name", http.StatusBadRequest)
		return
	}

	root := s.reportRoot()
	dir := filepath.Join(root, name)
	if filepath.Dir(dir) != root {
		http.Error(w, "invalid run name", http.StatusBadRequest)
		return
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	s.run.mu.Lock()
	running := s.run.status == statusRunning
	s.run.mu.Unlock()
	if running {
		http.Error(w, "a scan is running", http.StatusConflict)
		return
	}

	jsonPath := filepath.Join(dir, defaultJSONReport)
	doc, err := readRunDocument(jsonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "run report not found", http.StatusNotFound)
			return
		}
		// The error may mention the filesystem path, which must not reach
		// the browser.
		http.Error(w, "run report is unreadable", http.StatusInternalServerError)
		return
	}

	started, _ := time.ParseInLocation(app.RunTimestampLayout, name, time.Local)
	finished := doc.GeneratedAt.Local()
	if finished.IsZero() {
		if info, statErr := os.Stat(jsonPath); statErr == nil {
			finished = info.ModTime()
		}
	}

	summary := report.Summarize(doc.Results)
	findings := make([]finding, 0, len(doc.Results))
	for _, result := range doc.Results {
		if result.Open || result.Passwordless || result.Error != "" {
			findings = append(findings, toFinding(result))
		}
	}

	s.run.mu.Lock()
	s.run.status = statusCompleted
	s.run.errMsg = ""
	s.run.started = started
	s.run.finished = finished
	s.run.done = summary.Targets
	s.run.total = summary.Targets
	s.run.summary = summary
	s.run.runDir = dir
	s.run.credentials = 0
	s.run.jsonPath = jsonPath
	s.run.htmlPath = runArtifact(dir, "vncshot_report.html", ".html")
	s.run.pdfPath = runArtifact(dir, "vncshot_report.pdf", ".pdf")
	s.run.files = listRunFiles(dir)
	s.run.results = doc.Results
	s.run.findings = findings
	s.run.events = []event{}
	s.run.warning = ""
	s.run.diff = nil
	s.run.removedRuns = 0
	s.run.session = nil
	s.run.cancel = nil
	s.run.mu.Unlock()

	s.broadcast(true)
	writeJSON(w, s.snapshot())
}

// runArtifact resolves a report artifact inside runDir, preferring the
// conventional file name and falling back to the first file with the wanted
// extension so overridden report names still resolve.
func runArtifact(dir, preferred, ext string) string {
	preferredPath := filepath.Join(dir, preferred)
	if info, err := os.Stat(preferredPath); err == nil && !info.IsDir() {
		return preferredPath
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 {
			continue
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ext) {
			return filepath.Join(dir, entry.Name())
		}
	}
	return ""
}

func (s *server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.cancelRun() {
		http.Error(w, "no scan is running", http.StatusConflict)
		return
	}
	s.pushEvent("cancel", "cancellation requested; finishing in-flight probes")
	s.broadcast(true)
	writeJSON(w, s.snapshot())
}

func (s *server) cancelRun() bool {
	s.run.mu.Lock()
	cancel := s.run.cancel
	running := s.run.status == statusRunning
	s.run.mu.Unlock()
	if !running || cancel == nil {
		return false
	}
	cancel()
	return true
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan snapshot, 16)
	s.run.mu.Lock()
	s.run.subscribers[ch] = struct{}{}
	initial := s.snapshotLocked()
	s.run.mu.Unlock()

	defer func() {
		s.run.mu.Lock()
		delete(s.run.subscribers, ch)
		s.run.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	writeEvent(w, initial)
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case snap := <-ch:
			writeEvent(w, snap)
			flusher.Flush()
		case <-ticker.C:
			// Heartbeat keeps proxies and browsers from closing the stream.
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func writeEvent(w http.ResponseWriter, snap snapshot) {
	data, err := json.Marshal(snap)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func (s *server) handleFiles(w http.ResponseWriter, r *http.Request) {
	s.run.mu.Lock()
	runDir := s.run.runDir
	s.run.mu.Unlock()
	if runDir == "" {
		http.NotFound(w, r)
		return
	}

	rel := strings.TrimPrefix(r.URL.Path, "/files/")
	clean := filepath.Clean(filepath.FromSlash(rel))
	full := filepath.Join(runDir, clean)

	// Compare resolved paths: a symlink inside the run folder must not be
	// able to serve a file from elsewhere on the host.
	rootReal, err := filepath.EvalSymlinks(runDir)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	fullReal, err := filepath.EvalSymlinks(full)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !strings.HasPrefix(fullReal, rootReal+string(os.PathSeparator)) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if info, err := os.Stat(fullReal); err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	full = fullReal

	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, full)
}

// broadcast pushes a snapshot to every SSE subscriber. Progress updates are
// throttled; terminal transitions are always delivered.
func (s *server) broadcast(force bool) {
	s.run.mu.Lock()
	if !force && time.Since(s.run.lastSent) < 150*time.Millisecond {
		s.run.mu.Unlock()
		return
	}
	s.run.lastSent = time.Now()
	snap := s.snapshotLocked()
	for ch := range s.run.subscribers {
		select {
		case ch <- snap:
		default:
			// Slow consumer: drop this frame rather than blocking the scan.
		}
	}
	s.run.mu.Unlock()
}

func (s *server) snapshot() snapshot {
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	return s.snapshotLocked()
}

func (s *server) snapshotLocked() snapshot {
	snap := snapshot{
		Status:      s.run.status,
		Error:       s.run.errMsg,
		Done:        s.run.done,
		Total:       s.run.total,
		Summary:     s.run.summary,
		RunDir:      s.run.runDir,
		Credentials: s.run.credentials,
		JSON:        s.run.jsonPath,
		HTML:        s.run.htmlPath,
		PDF:         s.run.pdfPath,
		Files:       append([]string(nil), s.run.files...),
		Findings:    s.sortedFindingsLocked(),
		Events:      append([]event(nil), s.run.events...),
		Warning:     s.run.warning,
		Version:     s.version,
		Running:     s.run.status == statusRunning,
		StartedScan: s.run.status != statusIdle,
		// Artifact paths are assigned when the scan starts, but the files
		// only exist once it settles. Linking them mid-scan would render
		// "Reports" buttons that answer 404.
		ReportLinks: s.reportLinksLocked(),
		RemovedRuns: s.run.removedRuns,
		Diff:        s.run.diff,
	}
	if !s.run.started.IsZero() {
		snap.Started = s.run.started.Format("2006-01-02 15:04:05")
	}
	if !s.run.finished.IsZero() {
		snap.Finished = s.run.finished.Format("2006-01-02 15:04:05")
		end := s.run.finished
		snap.ElapsedMs = end.Sub(s.run.started).Milliseconds()
	} else if !s.run.started.IsZero() {
		snap.ElapsedMs = time.Since(s.run.started).Milliseconds()
	}
	if snap.ElapsedMs > 0 && snap.Done > 0 {
		snap.ProgressRate = float64(snap.Done) / (float64(snap.ElapsedMs) / 1000)
	}
	if len(snap.Events) > 200 {
		snap.Events = snap.Events[len(snap.Events)-200:]
	}
	// Findings carry on-disk screenshot paths; expose them as URLs the
	// browser can fetch from the run folder instead.
	for i := range snap.Findings {
		snap.Findings[i].Screenshot = s.artifactLink(snap.Findings[i].Screenshot)
	}
	return snap
}

// reportLinksLocked returns the artifact URLs for the dashboard, or an empty
// map while a scan is still writing them.
func (s *server) reportLinksLocked() map[string]string {
	links := map[string]string{}
	if s.run.status == statusRunning {
		return links
	}
	links["json"] = s.artifactLink(s.run.jsonPath)
	links["html"] = s.artifactLink(s.run.htmlPath)
	links["pdf"] = s.artifactLink(s.run.pdfPath)
	return links
}

// artifactLink maps an on-disk artifact to its /files URL, returning "" when
// the file is outside the current run folder.
func (s *server) artifactLink(path string) string {
	if path == "" || s.run.runDir == "" {
		return ""
	}
	rel, err := filepath.Rel(s.run.runDir, path)
	if err != nil || strings.HasPrefix(rel, "..") {
		return ""
	}
	return "/files/" + filepath.ToSlash(rel)
}

// sortedFindingsLocked returns the findings in the same deterministic order
// the reports use (numeric IP, then port), so the dashboard never disagrees
// with the artifacts of the same run.
func (s *server) sortedFindingsLocked() []finding {
	out := append([]finding(nil), s.run.findings...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if cmp := compareNumericIP(a.IP, b.IP); cmp != 0 {
			return cmp < 0
		}
		return a.Port < b.Port
	})
	return out
}

// compareNumericIP orders addresses numerically, keeping non-IP entries
// last in lexical order.
func compareNumericIP(a, b string) int {
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	switch {
	case ipA != nil && ipB != nil:
		return bytes.Compare(ipA.To16(), ipB.To16())
	case ipA != nil:
		return -1
	case ipB != nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

func (s *server) pushEvent(kind, message string) {
	s.run.mu.Lock()
	s.run.events = append(s.run.events, event{At: time.Now(), Kind: kind, Message: message})
	s.run.mu.Unlock()
}

func (s *server) scanConfig(req scanRequest) (app.Config, error) {
	cfg := s.cfg.Scan

	if strings.TrimSpace(req.Target) == "" && strings.TrimSpace(req.File) == "" {
		return cfg, fmt.Errorf("either a target or a target file is required")
	}
	cfg.Target = strings.TrimSpace(req.Target)
	cfg.File = strings.TrimSpace(req.File)

	if req.Ports != "" {
		cfg.Ports = strings.TrimSpace(req.Ports)
	}
	if req.TimeoutMs > 0 {
		cfg.ConnectTimeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	if req.VNCTimeoutMs > 0 {
		cfg.VNCTimeout = time.Duration(req.VNCTimeoutMs) * time.Millisecond
	}
	if req.Workers > 0 {
		cfg.Workers = req.Workers
	}
	if req.Workers < 0 {
		return cfg, fmt.Errorf("workers must not be negative")
	}
	cfg.RatePerSec = req.Rate
	cfg.NoPDF = req.NoPDF
	cfg.Shared = req.Shared
	cfg.WordList = strings.TrimSpace(req.WordList)
	cfg.NoDefaultPasswords = req.NoDefaultPw
	cfg.NoPasswordCheck = req.NoPasswordChk

	if strings.TrimSpace(req.OutDir) != "" {
		cfg.OutDir = strings.TrimSpace(req.OutDir)
		cfg.OutDirExplicit = true
	} else {
		// Leaving the field empty keeps the compiled-in default and enables
		// the writable-directory fallback.
		cfg.OutDirExplicit = false
	}
	cfg.Output = strings.TrimSpace(req.Output)
	cfg.HTML = strings.TrimSpace(req.HTML)
	cfg.PDF = strings.TrimSpace(req.PDF)
	cfg.ScreenshotDir = strings.TrimSpace(req.ScreenshotDir)

	// The run-level options mirror the CLI flags. Empty strings keep the
	// launch-time defaults so a GUI started with -csv, -webhook or -baseline
	// does not silently lose them.
	if csvPath := strings.TrimSpace(req.CSV); csvPath != "" {
		cfg.CSV = csvPath
	}
	cfg.Manifest = req.Manifest

	if endpoint := strings.TrimSpace(req.Webhook); endpoint != "" {
		if err := validateWebhookURL(endpoint); err != nil {
			return cfg, err
		}
		cfg.WebhookURL = endpoint
	}

	if req.KeepRuns < 0 {
		return cfg, fmt.Errorf("keep_runs must not be negative")
	}
	cfg.KeepRuns = req.KeepRuns
	cfg.PruneDryRun = req.PruneDryRun

	// Redact and ThumbnailOnly remain launch-time options: app.Config has no
	// switch for them yet, so the request values stay accepted but unused
	// instead of pretending the dashboard can change report redaction.

	// The dashboard offers previous runs by folder name, while the pipeline
	// expects a directory, so resolve bare names against the report root that
	// this scan will write to.
	runRoot := cfg.OutDir
	if runRoot == "" {
		runRoot = s.reportRoot()
	}
	if name := strings.TrimSpace(req.Baseline); name != "" {
		if validRunName(name) {
			cfg.Baseline = filepath.Join(runRoot, name)
		} else {
			cfg.Baseline = name
		}
	}

	// Screenshots are served through /files/, which is rooted at the run
	// folder. A directory outside it would leave working findings with
	// thumbnails that 404 in the dashboard, so reject it before any probe
	// starts.
	if err := validateScreenshotDir(cfg.ScreenshotDir, runRoot); err != nil {
		return cfg, err
	}

	return cfg, nil
}

// validateWebhookURL accepts only the schemes the notifier can POST to. The
// server will send a request to this address, so anything else (file, ftp,
// unix) is rejected before the scan starts.
func validateWebhookURL(endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("webhook URL is invalid")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("webhook URL scheme %q is not supported; use http:// or https://", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("webhook URL must include a host")
	}
	return nil
}

// validateScreenshotDir keeps screenshots inside the report root so the
// /files/ route can serve them. Relative values are resolved against the run
// folder by the pipeline, so only a leading ".." can escape it.
func validateScreenshotDir(dir, runRoot string) error {
	if dir == "" {
		return nil
	}
	outside := fmt.Errorf("screenshot directory must be inside the run folder; remove -screenshot-dir or point it inside %s", runRoot)

	if !filepath.IsAbs(dir) {
		clean := filepath.Clean(dir)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
			return outside
		}
		return nil
	}

	rootAbs, err := filepath.Abs(runRoot)
	if err != nil {
		return outside
	}
	dirAbs, err := filepath.Abs(dir)
	if err != nil {
		return outside
	}
	rel, err := filepath.Rel(rootAbs, dirAbs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return outside
	}
	return nil
}

func toFinding(r report.Result) finding {
	dims := ""
	if r.ScreenWidth > 0 && r.ScreenHeight > 0 {
		dims = fmt.Sprintf("%dx%d", r.ScreenWidth, r.ScreenHeight)
	}
	return finding{
		IP:            r.IP,
		Port:          r.Port,
		Addr:          r.Addr(),
		ServerName:    r.ServerName,
		Dimensions:    dims,
		Passwordless:  r.Passwordless,
		Password:      r.Password,
		AuthLocked:    r.AuthLocked,
		SecurityTypes: append([]string(nil), r.SecurityTypes...),
		TLS:           r.TLS,
		Attempts:      r.Attempts,
		Open:          r.Open,
		RFB:           r.RFB,
		Error:         r.Error,
		DurationMs:    r.DurationMs,
		Screenshot:    r.Screenshot,
		Timestamp:     r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
	}
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(payload)
}

func newToken() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".vncshot-probe-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return true
}

func notifySignals(ch chan<- os.Signal) {
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
}

func openBrowser(url string) error {
	cmd := exec.Command("xdg-open", url)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
