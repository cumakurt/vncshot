// Package gui serves a local, loopback-only web interface for vncshot.
//
// The GUI is deliberately implemented as a web app: the scanner must run as
// root on Linux, so an in-browser front end avoids pulling a cgo/C library
// dependency into the static binary while still offering every CLI option,
// live progress and direct access to the generated reports.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	Scan        app.Config
	Version     string
	Host        string
	Port        int
	OpenBrowser bool
	Reason      string
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
}

type event struct {
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
}

type finding struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Addr         string `json:"addr"`
	ServerName   string `json:"server_name"`
	Dimensions   string `json:"dimensions"`
	Passwordless bool   `json:"passwordless"`
	Password     string `json:"password,omitempty"`
	AuthLocked   bool   `json:"auth_locked,omitempty"`
	Open         bool   `json:"open"`
	RFB          bool   `json:"rfb"`
	Error        string `json:"error"`
	DurationMs   int64  `json:"duration_ms"`
	Screenshot   string `json:"screenshot"`
	Timestamp    string `json:"timestamp"`
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
	s.run.mu.Lock()
	s.run.files = files
	s.run.mu.Unlock()
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
	if !strings.HasPrefix(full, filepath.Clean(runDir)+string(os.PathSeparator)) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	if info, err := os.Stat(full); err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}

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
		Findings:    append([]finding(nil), s.run.findings...),
		Events:      append([]event(nil), s.run.events...),
		Warning:     s.run.warning,
		Version:     s.version,
		Running:     s.run.status == statusRunning,
		StartedScan: s.run.status != statusIdle,
		ReportLinks: map[string]string{
			"json": s.artifactLink(s.run.jsonPath),
			"html": s.artifactLink(s.run.htmlPath),
			"pdf":  s.artifactLink(s.run.pdfPath),
		},
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

	return cfg, nil
}

func toFinding(r report.Result) finding {
	dims := ""
	if r.ScreenWidth > 0 && r.ScreenHeight > 0 {
		dims = fmt.Sprintf("%dx%d", r.ScreenWidth, r.ScreenHeight)
	}
	return finding{
		IP:           r.IP,
		Port:         r.Port,
		Addr:         r.Addr(),
		ServerName:   r.ServerName,
		Dimensions:   dims,
		Passwordless: r.Passwordless,
		Password:     r.Password,
		AuthLocked:   r.AuthLocked,
		Open:         r.Open,
		RFB:          r.RFB,
		Error:        r.Error,
		DurationMs:   r.DurationMs,
		Screenshot:   r.Screenshot,
		Timestamp:    r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
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
