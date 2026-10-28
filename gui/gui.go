// Package gui serves a local, loopback-only web interface for vncshot.
//
// The GUI is a local web app so the scanner stays a static binary: no cgo
// toolkit, every scan option, live progress and the generated reports.
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
	"io"
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
	// Certificate carries the peer certificate evidence for the transport
	// column; nil for clear-text or non-TLS findings.
	Certificate *certificateView `json:"certificate,omitempty"`
	Attempts    int              `json:"attempts"`
	Open        bool             `json:"open"`
	RFB         bool             `json:"rfb"`
	Error       string           `json:"error"`
	DurationMs  int64            `json:"duration_ms"`
	Screenshot  string           `json:"screenshot"`
	Timestamp   string           `json:"timestamp"`
}

// certificateView is the dashboard subset of report.Certificate. Only the
// fields the transport column and its tooltip render are carried, so the live
// SSE payload stays small during a scan.
type certificateView struct {
	Subject     string   `json:"subject"`
	Issuer      string   `json:"issuer"`
	NotBefore   string   `json:"not_before"`
	NotAfter    string   `json:"not_after"`
	Version     string   `json:"version"`
	Cipher      string   `json:"cipher"`
	DNSNames    []string `json:"dns_names,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	SelfSigned  bool     `json:"self_signed"`
	Expired     bool     `json:"expired"`
	Verified    bool     `json:"verified"`
}

// runInfo is one entry of the run history shown in the dashboard.
type runInfo struct {
	Name    string          `json:"name"`
	Started string          `json:"started"`
	Files   []string        `json:"files"`
	HasHTML bool            `json:"has_html"`
	HasPDF  bool            `json:"has_pdf"`
	HasJSON bool            `json:"has_json"`
	Size    int64           `json:"size"`
	Summary *report.Summary `json:"summary"`
	// GeneratedAt is the report's own generation timestamp (RFC 3339),
	// empty when the run has no readable report.
	GeneratedAt string `json:"generated_at,omitempty"`
	startedAt   time.Time
}

type snapshot struct {
	ID          string         `json:"id,omitempty"`
	Name        string         `json:"name,omitempty"`
	Seq         int64          `json:"seq,omitempty"`
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
	// SelfSigned counts findings whose established TLS session presented a
	// certificate that names itself as its issuer.
	SelfSigned int `json:"self_signed"`
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
	mu         sync.Mutex
	id         string
	name       string
	dropDir    bool
	reportRoot string
	seq        int64
	// accounted is read and written only while server.jobsMu is held.
	accounted   bool
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
	// request is the launch that started this scan. Pause keeps it so resume
	// can probe the unfinished targets with the same scope and pace.
	request scanRequest
	// pause is set when the operator freezes a running scan. The writer
	// reads it once, when the cancelled probe returns, and then clears it.
	pause bool
	// evidence lists run folders this scan already finished. Resume writes
	// a new folder and still has to serve screenshots from the earlier ones.
	evidence    []string
	subscribers map[chan snapshot]struct{}
	lastSent    time.Time
	// flushPending is set when a progress frame was coalesced. A timer
	// delivers that latest snapshot so a finding is not held until the
	// next probe happens to fall outside the throttle window.
	flushPending bool
}

const (
	statusIdle      = "idle"
	statusRunning   = "running"
	statusPaused    = "paused"
	statusCompleted = "completed"
	statusCancelled = "cancelled"
	statusFailed    = "failed"

	// defaultReportRoot matches the CLI default when no root was configured.
	defaultReportRoot = "/usr/local/vncshot"
	// maxRunHistory bounds the history payload so a long-lived report tree
	// cannot make the dashboard request arbitrarily expensive.
	maxRunHistory = 100
	// maxTargetFileBytes caps a file chosen from the operator's computer.
	// The browser cannot hand the scanner a real path, so the GUI stores a
	// private copy and the scan reads that copy.
	maxTargetFileBytes = 256 << 20
	// maxWordListBytes caps a word list picked in the browser. The scanner
	// already refuses more than 500 entries; this bound stops the upload
	// before that copy is written.
	maxWordListBytes = 1 << 20
	importDirName    = "imports"
	// maxTrendRuns bounds the trend strip window. The cap counts every
	// candidate folder, including ones whose report cannot be read, so the
	// payload size stays predictable even in a tree with damaged runs.
	maxTrendRuns = 50
	// maxRunReportBytes bounds the JSON report read into memory by
	// readRunDocument. Run reports hold per-result rows but no embedded
	// imagery, so anything beyond this limit is treated as unreadable
	// rather than stalling the history and trend endpoints.
	maxRunReportBytes = 32 << 20
)

type server struct {
	token   string
	cfg     Config
	run     *runState
	version string

	jobsMu  sync.Mutex
	jobs    map[string]*runState
	order   []string
	cards   map[string]jobCard
	running int

	feedMu   sync.Mutex
	feedSubs map[chan []byte]struct{}
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
		srv.cancelJobs()
		_ = httpSrv.Close()
	}()

	fmt.Fprintf(os.Stderr, "\n  vncshot GUI %s\n", cfg.Version)
	fmt.Fprintf(os.Stderr, "  url:      %s\n", url)
	fmt.Fprintf(os.Stderr, "  bind:     %s:%d (loopback only; use it only on your authorized network)\n", host, addr.Port)
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
	mux.HandleFunc("/api/runs/", s.guard(s.handleRunItem))
	mux.HandleFunc("/api/trends", s.guard(s.handleTrends))
	mux.HandleFunc("/api/diff", s.guard(s.handleDiff))
	mux.HandleFunc("/api/events", s.guard(s.handleEvents))
	mux.HandleFunc("/api/feed", s.guard(s.handleFeed))
	mux.HandleFunc("/api/target-file", s.guard(s.handleTargetFile))
	mux.HandleFunc("/api/word-list", s.guard(s.handleWordList))
	mux.HandleFunc("/api/scans", s.guard(s.handleScans))
	mux.HandleFunc("/api/scans/", s.guard(s.handleScanRoute))
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
	s.run.summary = session.LiveSummary()
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

	s.pushEvent(s.run, "scan", fmt.Sprintf("started scan of %d host:port pairs with %d password candidates",
		len(session.Targets), len(session.Credentials)))
	s.broadcast(s.run, true)

	go s.execute(ctx, s.run, session, cancel)

	writeJSON(w, s.snapshot())
}

func (s *server) execute(ctx context.Context, job *runState, session *app.Session, cancel context.CancelFunc) {
	defer cancel()

	out, err := session.Scan(ctx, func(p app.Progress) {
		job.mu.Lock()
		job.done = p.Done
		job.results = append(job.results, p.Result)
		if p.Result.Open || p.Result.Passwordless || p.Result.Password != "" || p.Result.Error != "" {
			job.findings = append(job.findings, toFinding(p.Result))
		}
		// Add is O(1). Rebuilding the summary from the whole slice on every
		// probe made a large scan stall the live counters.
		job.summary.Add(p.Result)
		job.summary.Targets = p.Total
		job.total = p.Total
		notable := p.Result.Passwordless || p.Result.Password != "" || p.Result.Screenshot != ""
		job.mu.Unlock()
		// A passwordless host, weak credential or screenshot is pushed
		// immediately. Open ports and errors ride the coalesced cadence.
		s.broadcast(job, notable)
	})

	job.mu.Lock()
	planned := job.total
	job.done = out.Summary.Targets
	job.summary = out.Summary
	job.runDir = out.RunDir
	job.jsonPath = out.JSON
	job.htmlPath = out.HTML
	job.pdfPath = out.PDF
	job.finished = time.Now()
	// A webhook failure must not look like a clean run, and a baseline
	// comparison requested on the launch command line must be visible:
	// both were previously dropped on the floor by the GUI.
	if out.Warning != "" {
		if job.warning != "" {
			job.warning += "; " + out.Warning
		} else {
			job.warning = out.Warning
		}
	}
	if out.Diff != nil {
		job.diff = &diffSummary{
			Baseline: filepath.Base(out.Diff.Baseline),
			New:      len(out.Diff.New),
			Resolved: len(out.Diff.Resolved),
			Changed:  len(out.Diff.Changed),
		}
	}
	job.removedRuns = len(out.RemovedRuns)
	pauseIt := job.pause
	job.pause = false
	switch {
	case errors.Is(err, context.Canceled) && pauseIt:
		job.status = statusPaused
		// The planned scope stays on the counter. A row whose only error is
		// the cancellation itself was not finished, so it does not count as
		// progress the next resume will keep.
		if planned > job.summary.Targets {
			job.summary.Targets = planned
		}
		kept := 0
		for _, result := range out.Results {
			if result.Error != context.Canceled.Error() {
				kept++
			}
		}
		job.done = kept
	case errors.Is(err, context.Canceled):
		job.status = statusCancelled
	case err != nil:
		job.status = statusFailed
		job.errMsg = err.Error()
	default:
		job.status = statusCompleted
	}
	status := job.status
	dropDir := job.dropDir
	runDir := job.runDir
	root := job.reportRoot
	evidence := append([]string(nil), job.evidence...)
	job.mu.Unlock()

	s.collectFiles(job, session.RunDir)
	if status == statusPaused {
		s.pushEvent(job, "pause", "paused; completed probes are kept")
	} else {
		s.pushEvent(job, "scan", fmt.Sprintf("finished: %d open, %d passwordless", out.Summary.Open, out.Summary.Passwordless))
	}
	s.broadcast(job, true)
	if dropDir {
		for _, dir := range evidence {
			_ = removeRunDir(root, dir)
		}
		_ = removeRunDir(root, runDir)
	}
}

// collectFiles lists the artifacts of a finished run so the UI can link to
// them without guessing file names.
func (s *server) collectFiles(job *runState, runDir string) {
	files := listRunFiles(runDir)
	job.mu.Lock()
	job.files = files
	job.mu.Unlock()
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

// importCopy describes one browser upload stored under the report root.
type importCopy struct {
	maxBytes int64
	fallback string
	tooLarge string
	invalid  string
	required string
	empty    string
	failed   string
}

// handleTargetFile stores a target list picked in the browser. The scan
// reads a filesystem path, and a browser file dialog does not provide one,
// so the bytes are copied under the report root and that path is returned.
func (s *server) handleTargetFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dest, name, err := s.saveImport(w, r, importCopy{
		maxBytes: maxTargetFileBytes,
		fallback: "targets.txt",
		tooLarge: "target file is larger than 256 MiB",
		invalid:  "target file is not a valid upload",
		required: "target file is required",
		empty:    "target file is empty",
		failed:   "target file could not be stored",
	})
	if err != nil {
		writeImportError(w, err)
		return
	}
	writeJSON(w, map[string]string{"path": dest, "name": name})
}

// handleWordList stores a word list picked in the browser and checks it with
// the same reader the scan uses, so an empty or oversized list is rejected
// before a path is handed back.
func (s *server) handleWordList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dest, name, err := s.saveImport(w, r, importCopy{
		maxBytes: maxWordListBytes,
		fallback: "wordlist.txt",
		tooLarge: "word list is larger than 1 MiB",
		invalid:  "word list is not a valid upload",
		required: "word list is required",
		empty:    "word list is empty",
		failed:   "word list could not be stored",
	})
	if err != nil {
		writeImportError(w, err)
		return
	}
	creds, readErr := app.Credentials(app.Config{NoDefaultPasswords: true, WordList: dest})
	if readErr != nil || len(creds) == 0 {
		_ = os.Remove(dest)
		if readErr != nil {
			if i := strings.Index(readErr.Error(), "exceeds the "); i >= 0 {
				http.Error(w, "word list "+readErr.Error()[i:], http.StatusBadRequest)
				return
			}
			http.Error(w, "word list could not be read", http.StatusBadRequest)
			return
		}
		http.Error(w, "word list is empty", http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"path": dest, "name": name})
}

type importFailure struct {
	status int
	msg    string
}

func (e *importFailure) Error() string { return e.msg }

func writeImportError(w http.ResponseWriter, err error) {
	var failure *importFailure
	if errors.As(err, &failure) {
		http.Error(w, failure.msg, failure.status)
		return
	}
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// saveImport copies one multipart file into the imports directory. The
// stored name is a timestamp plus a nonce, so the browser-supplied name
// cannot escape that directory.
func (s *server) saveImport(w http.ResponseWriter, r *http.Request, spec importCopy) (string, string, error) {
	r.Body = http.MaxBytesReader(w, r.Body, spec.maxBytes+1<<20)
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return "", "", &importFailure{status: http.StatusRequestEntityTooLarge, msg: spec.tooLarge}
		}
		return "", "", &importFailure{status: http.StatusBadRequest, msg: spec.invalid}
	}
	defer r.MultipartForm.RemoveAll()

	src, header, err := r.FormFile("file")
	if err != nil {
		return "", "", &importFailure{status: http.StatusBadRequest, msg: spec.required}
	}
	defer src.Close()

	root := s.reportRoot()
	dir := filepath.Join(root, importDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", &importFailure{status: http.StatusInternalServerError, msg: spec.failed}
	}
	stored := storedImportName(header.Filename, spec.fallback)
	dest := filepath.Join(dir, stored)
	rel, err := filepath.Rel(root, dest)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", "", &importFailure{status: http.StatusInternalServerError, msg: spec.failed}
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", "", &importFailure{status: http.StatusInternalServerError, msg: spec.failed}
	}
	written, copyErr := io.Copy(out, io.LimitReader(src, spec.maxBytes+1))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil || written == 0 || written > spec.maxBytes {
		_ = os.Remove(dest)
		if written > spec.maxBytes {
			return "", "", &importFailure{status: http.StatusRequestEntityTooLarge, msg: spec.tooLarge}
		}
		if written == 0 && copyErr == nil {
			return "", "", &importFailure{status: http.StatusBadRequest, msg: spec.empty}
		}
		return "", "", &importFailure{status: http.StatusInternalServerError, msg: spec.failed}
	}
	return dest, safeImportBase(header.Filename, spec.fallback), nil
}

// storedImportName builds a unique file name that stays inside the import
// directory. The operator's original name is only a suffix, never a path.
func storedImportName(original, fallback string) string {
	var nonce [4]byte
	_, _ = rand.Read(nonce[:])
	stamp := time.Now().UTC().Format("20060102-150405")
	return stamp + "-" + hex.EncodeToString(nonce[:]) + "-" + safeImportBase(original, fallback)
}

func safeImportBase(name, fallback string) string {
	base := filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	cleaned := strings.Trim(b.String(), "._")
	if cleaned == "" {
		return fallback
	}
	if len(cleaned) > 80 {
		cleaned = cleaned[:80]
	}
	return cleaned
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

// handleRunItem deletes one previous run folder. The name is a single
// timestamp segment; open stays on its own route.
func (s *server) handleRunItem(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/runs/"), "/")
	if name == "" || strings.Contains(name, "/") || !validRunName(name) {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.deleteHistoricalRun(name); err != nil {
		var status interface{ StatusCode() int }
		if errors.As(err, &status) {
			http.Error(w, err.Error(), status.StatusCode())
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteHistoricalRun removes a timestamp folder and every report file inside
// it. A folder a live scan is still writing is left in place.
func (s *server) deleteHistoricalRun(name string) error {
	dir, status, err := s.resolveRunDir(name)
	if err != nil {
		return runHTTPError{status: status, msg: err.Error()}
	}
	if s.runDirectoryBusy(dir) {
		return runHTTPError{status: http.StatusConflict, msg: "run is in use by a live scan"}
	}
	if err := removeRunDir(s.reportRoot(), dir); err != nil {
		return runHTTPError{status: http.StatusConflict, msg: "run could not be deleted"}
	}
	s.detachFinishedJobsAt(dir)
	s.releaseDisplayedRun(dir)
	return nil
}

type runHTTPError struct {
	status int
	msg    string
}

func (e runHTTPError) Error() string { return e.msg }

func (e runHTTPError) StatusCode() int { return e.status }

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}

func (s *server) runDirectoryBusy(dir string) bool {
	s.run.mu.Lock()
	legacy := s.run.status == statusRunning && samePath(s.run.runDir, dir)
	s.run.mu.Unlock()
	if legacy {
		return true
	}
	s.jobsMu.Lock()
	jobs := make([]*runState, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	s.jobsMu.Unlock()
	for _, job := range jobs {
		job.mu.Lock()
		busy := job.status == statusRunning && samePath(job.runDir, dir)
		job.mu.Unlock()
		if busy {
			return true
		}
	}
	return false
}

func (s *server) detachFinishedJobsAt(dir string) {
	s.jobsMu.Lock()
	jobs := make([]*runState, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	s.jobsMu.Unlock()
	var ids []string
	for _, job := range jobs {
		job.mu.Lock()
		id := job.id
		match := job.status != statusRunning && samePath(job.runDir, dir)
		job.mu.Unlock()
		if match && id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		s.detachJob(id)
	}
	s.publishMenu()
}

// releaseDisplayedRun clears the single-run slot when it is showing the
// folder that was just deleted, so a refresh does not keep serving it.
func (s *server) releaseDisplayedRun(dir string) {
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	if s.run.status == statusRunning || !samePath(s.run.runDir, dir) {
		return
	}
	s.run.id = ""
	s.run.name = ""
	s.run.status = statusIdle
	s.run.errMsg = ""
	s.run.started = time.Time{}
	s.run.finished = time.Time{}
	s.run.done = 0
	s.run.total = 0
	s.run.summary = report.Summary{}
	s.run.runDir = ""
	s.run.credentials = 0
	s.run.jsonPath = ""
	s.run.htmlPath = ""
	s.run.pdfPath = ""
	s.run.files = nil
	s.run.results = nil
	s.run.findings = nil
	s.run.events = nil
	s.run.warning = ""
	s.run.diff = nil
	s.run.session = nil
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
	if !doc.GeneratedAt.IsZero() {
		info.GeneratedAt = doc.GeneratedAt.UTC().Format(time.RFC3339)
	}
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
	// Bound the read so an oversized report cannot stall the endpoints that
	// parse every run folder (history and trends). A missing file must keep
	// reporting os.ErrNotExist for the callers that branch on it.
	if info, statErr := os.Stat(path); statErr != nil {
		return doc, statErr
	} else if info.Size() > maxRunReportBytes {
		return doc, fmt.Errorf("run report is larger than %d bytes", maxRunReportBytes)
	}
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

// resolveRunDir validates a bare run folder name against the report root and
// returns its directory. The status is the HTTP status to answer with when
// validation fails. Symlinks are rejected because a linked folder can point
// outside the report root.
func (s *server) resolveRunDir(name string) (string, int, error) {
	root := s.reportRoot()
	dir := filepath.Join(root, name)
	if filepath.Dir(dir) != root {
		return "", http.StatusBadRequest, errors.New("invalid run name")
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return "", http.StatusNotFound, errors.New("run not found")
	}
	return dir, 0, nil
}

// loadRunReport reads one run folder's JSON report with the same error
// contract as the run-open endpoint: 404 for a missing report, 500 for an
// unreadable one, so filesystem paths never reach the browser.
func (s *server) loadRunReport(dir string) (report.Document, int, error) {
	doc, err := readRunDocument(filepath.Join(dir, defaultJSONReport))
	if err == nil {
		return doc, 0, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return doc, http.StatusNotFound, errors.New("run report not found")
	}
	return doc, http.StatusInternalServerError, errors.New("run report is unreadable")
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

	dir, status, err := s.resolveRunDir(name)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	s.run.mu.Lock()
	running := s.run.status == statusRunning
	s.run.mu.Unlock()
	if running {
		http.Error(w, "a scan is running", http.StatusConflict)
		return
	}

	doc, status, err := s.loadRunReport(dir)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	started, _ := time.ParseInLocation(app.RunTimestampLayout, name, time.Local)
	jsonPath := filepath.Join(dir, defaultJSONReport)
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

	s.broadcast(s.run, true)
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

// trendPoint is one column of the dashboard trend strip: the summary
// counters of a single previous run.
type trendPoint struct {
	Name         string `json:"name"`
	GeneratedAt  string `json:"generated_at"`
	Targets      int    `json:"targets"`
	Open         int    `json:"open"`
	RFB          int    `json:"rfb"`
	TLS          int    `json:"tls"`
	Passwordless int    `json:"passwordless"`
	Weak         int    `json:"weak"`
	Screenshots  int    `json:"screenshots"`
	Errors       int    `json:"errors"`
}

// handleTrends serves the newest runs' summary counters for the dashboard
// trend strip. The window is capped at maxTrendRuns (including runs whose
// report cannot be read, which are skipped silently), and the underlying
// listing reuses the history scan with its bounded report reads.
func (s *server) handleTrends(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runs := s.listRuns()
	if len(runs) > maxTrendRuns {
		runs = runs[:maxTrendRuns]
	}
	trends := make([]trendPoint, 0, len(runs))
	for _, run := range runs {
		if run.Summary == nil {
			// No readable report: there is nothing to plot for this run,
			// but it still consumed a slot of the capped window.
			continue
		}
		summary := run.Summary
		trends = append(trends, trendPoint{
			Name:         run.Name,
			GeneratedAt:  run.GeneratedAt,
			Targets:      summary.Targets,
			Open:         summary.Open,
			RFB:          summary.RFB,
			TLS:          summary.TLS,
			Passwordless: summary.Passwordless,
			Weak:         summary.WeakCredentials,
			Screenshots:  summary.Screenshots,
			Errors:       summary.Errors,
		})
	}
	writeJSON(w, trends)
}

// diffEntry is the compact per-host view of one comparison entry: address,
// advertised security types and the server banner.
type diffEntry struct {
	Addr          string   `json:"addr"`
	SecurityTypes []string `json:"security_types,omitempty"`
	ServerName    string   `json:"server_name,omitempty"`
}

// diffChangeEntry is one risk-state transition, carrying the change reason.
type diffChangeEntry struct {
	Addr          string   `json:"addr"`
	Reason        string   `json:"reason"`
	SecurityTypes []string `json:"security_types,omitempty"`
	ServerName    string   `json:"server_name,omitempty"`
}

// diffResponse is the /api/diff payload. The three lists are always present
// so the dashboard can iterate without nil checks.
type diffResponse struct {
	New      []diffEntry       `json:"new"`
	Resolved []diffEntry       `json:"resolved"`
	Changed  []diffChangeEntry `json:"changed"`
}

// compactDiffEntry reduces a report result to the fields the diff panel
// renders.
func compactDiffEntry(r report.Result) diffEntry {
	return diffEntry{
		Addr:          r.Addr(),
		SecurityTypes: append([]string(nil), r.SecurityTypes...),
		ServerName:    r.ServerName,
	}
}

// handleDiff compares two previous runs with the same comparison logic the
// reports use. The base names the older run; the target the newer one. Only
// the run folders are read, so the dashboard state is untouched and the
// endpoint stays usable while a scan is running.
func (s *server) handleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Base   string `json:"base"`
		Target string `json:"target"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	base := strings.TrimSpace(req.Base)
	target := strings.TrimSpace(req.Target)
	if !validRunName(base) || !validRunName(target) {
		http.Error(w, "invalid run name", http.StatusBadRequest)
		return
	}
	baseDir, status, err := s.resolveRunDir(base)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	targetDir, status, err := s.resolveRunDir(target)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	baseDoc, status, err := s.loadRunReport(baseDir)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	targetDoc, status, err := s.loadRunReport(targetDir)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}

	comparison := app.Compare(base, baseDoc.Results, targetDoc.Results)
	resp := diffResponse{
		New:      []diffEntry{},
		Resolved: []diffEntry{},
		Changed:  []diffChangeEntry{},
	}
	for _, result := range comparison.New {
		resp.New = append(resp.New, compactDiffEntry(result))
	}
	for _, result := range comparison.Resolved {
		resp.Resolved = append(resp.Resolved, compactDiffEntry(result))
	}
	for _, change := range comparison.Changed {
		entry := compactDiffEntry(change.After)
		resp.Changed = append(resp.Changed, diffChangeEntry{
			Addr:          entry.Addr,
			Reason:        change.Reason,
			SecurityTypes: entry.SecurityTypes,
			ServerName:    entry.ServerName,
		})
	}
	writeJSON(w, resp)
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
	s.pushEvent(s.run, "cancel", "cancellation requested; finishing in-flight probes")
	s.broadcast(s.run, true)
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
	runDir, ok := s.fileRoot(r)
	if !ok || runDir == "" {
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

// progressFlushDelay is how long a non-urgent progress frame may wait so a
// fast scan does not flood the browser, while the latest counters still arrive.
const progressFlushDelay = 150 * time.Millisecond

// broadcast pushes a snapshot to every SSE subscriber. Urgent frames
// (scan start, finish, a new finding) go out immediately. Ordinary progress
// is coalesced: a dropped frame is delivered by a short timer instead of
// waiting for another probe.
func (s *server) broadcast(job *runState, force bool) {
	job.mu.Lock()
	if !force && time.Since(job.lastSent) < progressFlushDelay {
		if !job.flushPending {
			job.flushPending = true
			delay := progressFlushDelay - time.Since(job.lastSent)
			if delay < 0 {
				delay = 0
			}
			time.AfterFunc(delay, func() {
				job.mu.Lock()
				pending := job.flushPending
				job.mu.Unlock()
				if pending {
					s.broadcast(job, true)
				}
			})
		}
		job.mu.Unlock()
		return
	}
	job.lastSent = time.Now()
	job.flushPending = false
	snap := s.snapshotOf(job)
	subs := make([]chan snapshot, 0, len(job.subscribers))
	for ch := range job.subscribers {
		subs = append(subs, ch)
	}
	job.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- snap:
		default:
			// Slow consumer: drop this frame rather than blocking the scan.
		}
	}
	if job.id != "" {
		s.publishFeed(snap)
	}
}

func (s *server) snapshot() snapshot {
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	return s.snapshotOf(s.run)
}

// snapshotLocked is the lock-held view of the legacy single run. Callers
// that already hold s.run.mu use it; new scans call snapshotOf directly.
func (s *server) snapshotLocked() snapshot {
	return s.snapshotOf(s.run)
}

func (s *server) snapshotOf(job *runState) snapshot {
	if job.id != "" {
		job.seq++
	}
	snap := snapshot{
		ID:          job.id,
		Name:        job.name,
		Seq:         job.seq,
		Status:      job.status,
		Error:       job.errMsg,
		Done:        job.done,
		Total:       job.total,
		Summary:     job.summary,
		RunDir:      job.runDir,
		Credentials: job.credentials,
		SelfSigned:  countSelfSigned(job.findings),
		JSON:        job.jsonPath,
		HTML:        job.htmlPath,
		PDF:         job.pdfPath,
		Files:       append([]string(nil), job.files...),
		Findings:    sortedFindings(job),
		Events:      append([]event(nil), job.events...),
		Warning:     job.warning,
		Version:     s.version,
		Running:     job.status == statusRunning,
		StartedScan: job.status != statusIdle,
		// Artifact paths are assigned when the scan starts, but the files
		// only exist once it settles. Linking them mid-scan would render
		// "Reports" buttons that answer 404.
		ReportLinks: s.reportLinks(job),
		RemovedRuns: job.removedRuns,
		Diff:        job.diff,
	}
	if !job.started.IsZero() {
		snap.Started = job.started.Format("2006-01-02 15:04:05")
	}
	if !job.finished.IsZero() {
		snap.Finished = job.finished.Format("2006-01-02 15:04:05")
		end := job.finished
		snap.ElapsedMs = end.Sub(job.started).Milliseconds()
	} else if !job.started.IsZero() {
		snap.ElapsedMs = time.Since(job.started).Milliseconds()
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
		snap.Findings[i].Screenshot = s.artifactLink(job, snap.Findings[i].Screenshot)
	}
	return snap
}

// reportLinks returns the artifact URLs for one scan, or an empty map while
// that scan is still writing them.
func (s *server) reportLinks(job *runState) map[string]string {
	links := map[string]string{}
	if job.status == statusRunning {
		return links
	}
	links["json"] = s.artifactLink(job, job.jsonPath)
	links["html"] = s.artifactLink(job, job.htmlPath)
	links["pdf"] = s.artifactLink(job, job.pdfPath)
	return links
}

// artifactLink maps an on-disk artifact to its /files URL, returning "" when
// the file is outside that scan's run folders. A resumed scan keeps
// screenshots in the folder it paused in, so those paths stay reachable.
func (s *server) artifactLink(job *runState, path string) string {
	if path == "" {
		return ""
	}
	type folder struct {
		dir     string
		earlier bool
	}
	folders := make([]folder, 0, len(job.evidence)+1)
	for _, dir := range job.evidence {
		folders = append(folders, folder{dir: dir, earlier: true})
	}
	if job.runDir != "" {
		folders = append(folders, folder{dir: job.runDir})
	}
	for _, candidate := range folders {
		rel, err := filepath.Rel(candidate.dir, path)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			continue
		}
		link := "/files/" + filepath.ToSlash(rel)
		if job.id == "" {
			return link
		}
		query := url.Values{}
		query.Set("scan", job.id)
		if candidate.earlier {
			query.Set("run", filepath.Base(candidate.dir))
		}
		return link + "?" + query.Encode()
	}
	return ""
}

// fileRoot is the directory /files/ may read for this request. The run
// query selects an earlier folder of a resumed scan; anything else uses the
// scan's current folder.
func (s *server) fileRoot(r *http.Request) (string, bool) {
	if id := r.URL.Query().Get("scan"); id != "" {
		job := s.lookupJob(id)
		if job == nil {
			return "", false
		}
		job.mu.Lock()
		defer job.mu.Unlock()
		if runName := r.URL.Query().Get("run"); runName != "" {
			if !validRunName(runName) {
				return "", false
			}
			for _, dir := range job.evidence {
				if filepath.Base(dir) != runName {
					continue
				}
				if !dirInside(job.reportRoot, dir) {
					continue
				}
				return dir, true
			}
			return "", false
		}
		if job.runDir == "" {
			return "", false
		}
		return job.runDir, true
	}
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	if s.run.runDir == "" {
		return "", false
	}
	return s.run.runDir, true
}

// dirInside reports whether dir is a child of root. The report root itself
// is not a run folder, so it is rejected.
func dirInside(root, dir string) bool {
	if root == "" || dir == "" {
		return false
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return false
	}
	return true
}

// countSelfSigned returns how many findings carry a self-signed certificate.
func countSelfSigned(findings []finding) int {
	count := 0
	for _, f := range findings {
		if f.Certificate != nil && f.Certificate.SelfSigned {
			count++
		}
	}
	return count
}

// sortedFindings returns the findings in the same deterministic order the
// reports use (numeric IP, then port), so the dashboard never disagrees with
// the artifacts of the same run. The caller holds job.mu.
func sortedFindings(job *runState) []finding {
	out := append([]finding(nil), job.findings...)
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

func (s *server) pushEvent(job *runState, kind, message string) {
	job.mu.Lock()
	job.events = append(job.events, event{At: time.Now(), Kind: kind, Message: message})
	job.mu.Unlock()
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
	// NoPasswordCheck only skips password candidates. Passwordless detection
	// and the one-frame screenshot stay on for every scan; the request has
	// no field that can turn them off.
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

// notableFindings keeps the same rows the live progress feed shows, so a
// resumed scan can redraw what it already learned before the next probe.
func notableFindings(results []report.Result) []finding {
	var out []finding
	for _, r := range results {
		if r.Open || r.Passwordless || r.Password != "" || r.Error != "" {
			out = append(out, toFinding(r))
		}
	}
	return out
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
		Certificate:   certificateViewOf(r.Certificate),
		Attempts:      r.Attempts,
		Open:          r.Open,
		RFB:           r.RFB,
		Error:         r.Error,
		DurationMs:    r.DurationMs,
		Screenshot:    r.Screenshot,
		Timestamp:     r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
	}
}

// certificateViewOf projects the report certificate onto the dashboard view,
// keeping unset timestamps empty rather than emitting the zero value.
func certificateViewOf(cert *report.Certificate) *certificateView {
	if cert == nil {
		return nil
	}
	notBefore := ""
	if !cert.NotBefore.IsZero() {
		notBefore = cert.NotBefore.UTC().Format(time.RFC3339)
	}
	notAfter := ""
	if !cert.NotAfter.IsZero() {
		notAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	}
	return &certificateView{
		Subject:     cert.Subject,
		Issuer:      cert.Issuer,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		Version:     cert.Version,
		Cipher:      cert.CipherSuite,
		DNSNames:    append([]string(nil), cert.DNSNames...),
		Fingerprint: cert.Fingerprint,
		SelfSigned:  cert.SelfSigned,
		Expired:     cert.Expired,
		Verified:    cert.Verified,
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
