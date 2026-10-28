package gui

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"vncshot/app"
	"vncshot/report"
)

const maxConcurrentScans = 6

var (
	errJobNotFound = errors.New("scan not found")
	errNotRunning  = errors.New("scan is not running")
	errTooManyJobs = errors.New("too many scans are running")
)

// jobCard is the menu row for one scan. It is small enough to redraw on every
// progress frame without shipping that scan's findings to every listener.
type jobCard struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Status  string         `json:"status"`
	Done    int            `json:"done"`
	Total   int            `json:"total"`
	Summary report.Summary `json:"summary"`
	Started string         `json:"started,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type jobList struct {
	Jobs []jobCard `json:"jobs"`
}

// scanProfile is the editable pace of a new scan. Zero config values fall
// back to the same defaults as the CLI flags.
type scanProfile struct {
	Workers      int `json:"workers"`
	Rate         int `json:"rate"`
	TimeoutMs    int `json:"timeout_ms"`
	VNCTimeoutMs int `json:"vnc_timeout_ms"`
}

// feedFrame is one server-sent event for the scan menu. The first event
// carries every snapshot; later events carry the menu plus one scan.
type feedFrame struct {
	Version   string       `json:"version"`
	Warning   string       `json:"warning,omitempty"`
	Jobs      []jobCard    `json:"jobs"`
	Update    *snapshot    `json:"update,omitempty"`
	Snapshots []snapshot   `json:"snapshots,omitempty"`
	Profile   *scanProfile `json:"profile,omitempty"`
}

func (s *server) handleScans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, jobList{Jobs: s.listCards()})
	case http.MethodPost:
		req, ok := readAuthorizedScan(w, r)
		if !ok {
			return
		}
		snap, code, err := s.startJob(req)
		if err != nil {
			http.Error(w, err.Error(), code)
			return
		}
		writeJSON(w, snap)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleScanRoute(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/scans/"), "/")
	parts := strings.Split(rest, "/")
	if rest == "" || len(parts) > 2 || !validJobID(parts[0]) {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	if len(parts) == 2 {
		if parts[1] != "stop" || r.Method != http.MethodPost {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			http.NotFound(w, r)
			return
		}
		snap, err := s.stopJob(id)
		if err != nil {
			writeJobError(w, err)
			return
		}
		writeJSON(w, snap)
		return
	}
	switch r.Method {
	case http.MethodGet:
		snap, err := s.jobSnapshot(id)
		if err != nil {
			writeJobError(w, err)
			return
		}
		writeJSON(w, snap)
	case http.MethodDelete:
		if err := s.deleteJob(id); err != nil {
			writeJobError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func writeJobError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errJobNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, errNotRunning):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func readAuthorizedScan(w http.ResponseWriter, r *http.Request) (scanRequest, bool) {
	var req scanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return req, false
	}
	if !req.Authorized {
		http.Error(w, "authorization confirmation is required", http.StatusForbidden)
		return req, false
	}
	return req, true
}

func (s *server) startJob(req scanRequest) (snapshot, int, error) {
	scanCfg, err := s.scanConfig(req)
	if err != nil {
		return snapshot{}, http.StatusBadRequest, err
	}
	session, err := app.Prepare(scanCfg)
	if err != nil {
		return snapshot{}, http.StatusBadRequest, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	job := &runState{
		name:        scanName(req),
		status:      statusRunning,
		started:     time.Now(),
		total:       len(session.Targets),
		summary:     session.LiveSummary(),
		runDir:      session.RunDir,
		reportRoot:  filepath.Dir(session.RunDir),
		credentials: len(session.Credentials),
		jsonPath:    session.JSONPath,
		htmlPath:    session.HTMLPath,
		pdfPath:     session.PDFPath,
		warning:     session.FallbackWarning(),
		session:     session,
		cancel:      cancel,
		subscribers: map[chan snapshot]struct{}{},
	}

	s.jobsMu.Lock()
	s.ensureJobsLocked()
	if s.running >= maxConcurrentScans {
		s.jobsMu.Unlock()
		cancel()
		_ = removeRunDir(job.reportRoot, job.runDir)
		return snapshot{}, http.StatusTooManyRequests, errTooManyJobs
	}
	id, err := s.reserveJobIDLocked()
	if err != nil {
		s.jobsMu.Unlock()
		cancel()
		_ = removeRunDir(job.reportRoot, job.runDir)
		return snapshot{}, http.StatusInternalServerError, err
	}
	job.id = id
	job.accounted = true
	s.running++
	s.jobs[id] = job
	s.order = append(s.order, id)
	s.cards[id] = jobCard{
		ID:      id,
		Name:    job.name,
		Status:  job.status,
		Total:   job.total,
		Summary: job.summary,
	}
	s.jobsMu.Unlock()

	s.pushEvent(job, "scan", fmt.Sprintf("started scan of %d host:port pairs with %d password candidates",
		len(session.Targets), len(session.Credentials)))
	job.mu.Lock()
	snap := s.snapshotOf(job)
	job.mu.Unlock()

	s.jobsMu.Lock()
	s.cards[id] = cardFrom(snap)
	s.jobsMu.Unlock()

	s.broadcast(job, true)
	go s.execute(ctx, job, session, cancel)
	return snap, http.StatusOK, nil
}

func (s *server) stopJob(id string) (snapshot, error) {
	job := s.lookupJob(id)
	if job == nil {
		return snapshot{}, errJobNotFound
	}
	job.mu.Lock()
	cancel := job.cancel
	running := job.status == statusRunning
	job.mu.Unlock()
	if !running || cancel == nil {
		return snapshot{}, errNotRunning
	}
	cancel()
	s.pushEvent(job, "cancel", "cancellation requested; finishing in-flight probes")
	s.broadcast(job, true)
	job.mu.Lock()
	snap := s.snapshotOf(job)
	job.mu.Unlock()
	return snap, nil
}

// deleteJob drops a scan from the menu. A running scan is cancelled and its
// report folder is removed when the writer finishes; a finished scan is
// removed immediately. The folder is deleted only when it sits inside the
// report root recorded for that scan.
func (s *server) deleteJob(id string) error {
	job := s.lookupJob(id)
	if job == nil {
		return errJobNotFound
	}

	job.mu.Lock()
	running := job.status == statusRunning
	cancel := job.cancel
	runDir := job.runDir
	root := job.reportRoot
	if running {
		job.dropDir = true
	}
	job.mu.Unlock()

	if running {
		s.detachJob(id)
		if cancel != nil {
			cancel()
		}
		s.publishMenu()
		return nil
	}
	if err := removeRunDir(root, runDir); err != nil {
		return err
	}
	s.detachJob(id)
	s.publishMenu()
	return nil
}

func (s *server) jobSnapshot(id string) (snapshot, error) {
	job := s.lookupJob(id)
	if job == nil {
		return snapshot{}, errJobNotFound
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	return s.snapshotOf(job), nil
}

func (s *server) listCards() []jobCard {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	s.ensureJobsLocked()
	return s.cardsInOrderLocked()
}

func (s *server) lookupJob(id string) *runState {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	if s.jobs == nil {
		return nil
	}
	return s.jobs[id]
}

func (s *server) cancelJobs() {
	s.jobsMu.Lock()
	jobs := make([]*runState, 0, len(s.jobs))
	for _, job := range s.jobs {
		jobs = append(jobs, job)
	}
	s.jobsMu.Unlock()
	for _, job := range jobs {
		job.mu.Lock()
		cancel := job.cancel
		job.mu.Unlock()
		if cancel != nil {
			cancel()
		}
	}
}

func (s *server) ensureJobsLocked() {
	if s.jobs == nil {
		s.jobs = map[string]*runState{}
	}
	if s.cards == nil {
		s.cards = map[string]jobCard{}
	}
}

func (s *server) reserveJobIDLocked() (string, error) {
	for i := 0; i < 5; i++ {
		id, err := newJobID()
		if err != nil {
			return "", err
		}
		if s.jobs[id] == nil {
			return id, nil
		}
	}
	return "", errors.New("could not allocate a scan id")
}

func (s *server) detachJob(id string) {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	s.ensureJobsLocked()
	job := s.jobs[id]
	if job == nil {
		return
	}
	if job.accounted {
		job.accounted = false
		if s.running > 0 {
			s.running--
		}
	}
	delete(s.jobs, id)
	delete(s.cards, id)
	next := make([]string, 0, len(s.order))
	for _, existing := range s.order {
		if existing != id {
			next = append(next, existing)
		}
	}
	s.order = next
}

func (s *server) cardsInOrderLocked() []jobCard {
	out := make([]jobCard, 0, len(s.order))
	for _, id := range s.order {
		card, ok := s.cards[id]
		if ok {
			out = append(out, card)
		}
	}
	return out
}

func (s *server) publishFeed(snap snapshot) {
	if snap.ID == "" {
		return
	}
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	job := s.jobs[snap.ID]
	if job == nil {
		return
	}
	if job.accounted && snap.Status != statusRunning {
		job.accounted = false
		if s.running > 0 {
			s.running--
		}
	}
	if s.cards == nil {
		s.cards = map[string]jobCard{}
	}
	s.cards[snap.ID] = cardFrom(snap)
	s.sendFeedLocked(feedFrame{
		Version: s.version,
		Jobs:    s.cardsInOrderLocked(),
		Update:  &snap,
	})
}

func (s *server) publishMenu() {
	s.jobsMu.Lock()
	defer s.jobsMu.Unlock()
	s.ensureJobsLocked()
	s.sendFeedLocked(feedFrame{
		Version: s.version,
		Jobs:    s.cardsInOrderLocked(),
	})
}

func (s *server) sendFeedLocked(frame feedFrame) {
	payload, err := json.Marshal(frame)
	if err != nil {
		return
	}
	s.feedMu.Lock()
	subs := make([]chan []byte, 0, len(s.feedSubs))
	for ch := range s.feedSubs {
		subs = append(subs, ch)
	}
	s.feedMu.Unlock()
	for _, ch := range subs {
		select {
		case ch <- payload:
		default:
		}
	}
}

func (s *server) handleFeed(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan []byte, 8)
	s.feedMu.Lock()
	if s.feedSubs == nil {
		s.feedSubs = map[chan []byte]struct{}{}
	}
	s.feedSubs[ch] = struct{}{}
	s.feedMu.Unlock()
	defer func() {
		s.feedMu.Lock()
		delete(s.feedSubs, ch)
		s.feedMu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	writeFeed(w, s.feedInitial())
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case payload := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func (s *server) feedInitial() feedFrame {
	s.run.mu.Lock()
	warning := s.run.warning
	s.run.mu.Unlock()

	s.jobsMu.Lock()
	s.ensureJobsLocked()
	order := append([]string(nil), s.order...)
	jobs := make([]*runState, 0, len(order))
	for _, id := range order {
		if job := s.jobs[id]; job != nil {
			jobs = append(jobs, job)
		}
	}
	cards := s.cardsInOrderLocked()
	s.jobsMu.Unlock()

	snaps := make([]snapshot, 0, len(jobs))
	for _, job := range jobs {
		job.mu.Lock()
		snaps = append(snaps, s.snapshotOf(job))
		job.mu.Unlock()
	}
	profile := s.scanProfile()
	return feedFrame{
		Version:   s.version,
		Warning:   warning,
		Jobs:      cards,
		Snapshots: snaps,
		Profile:   &profile,
	}
}

// scanProfile reports the pace a new scan starts from. An unconfigured
// server uses the CLI defaults. An explicit -rate 0 stays unlimited.
func (s *server) scanProfile() scanProfile {
	cfg := s.cfg.Scan
	profile := scanProfile{
		Workers:      cfg.Workers,
		Rate:         cfg.RatePerSec,
		TimeoutMs:    int(cfg.ConnectTimeout / time.Millisecond),
		VNCTimeoutMs: int(cfg.VNCTimeout / time.Millisecond),
	}
	if profile.Workers <= 0 {
		profile.Workers = 150
	}
	if profile.TimeoutMs <= 0 {
		profile.TimeoutMs = 1000
	}
	if profile.VNCTimeoutMs <= 0 {
		profile.VNCTimeoutMs = 15000
	}
	if profile.Rate == 0 && cfg.Workers == 0 && cfg.ConnectTimeout == 0 && cfg.VNCTimeout == 0 {
		profile.Rate = 200
	}
	if profile.Rate < 0 {
		profile.Rate = 200
	}
	return profile
}

func writeFeed(w http.ResponseWriter, frame feedFrame) {
	data, err := json.Marshal(frame)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "data: %s\n\n", data)
}

func cardFrom(snap snapshot) jobCard {
	return jobCard{
		ID:      snap.ID,
		Name:    snap.Name,
		Status:  snap.Status,
		Done:    snap.Done,
		Total:   snap.Total,
		Summary: snap.Summary,
		Started: snap.Started,
		Error:   snap.Error,
	}
}

func scanName(req scanRequest) string {
	if target := strings.TrimSpace(req.Target); target != "" {
		return trimLabel(target, 64)
	}
	if file := strings.TrimSpace(req.File); file != "" {
		return trimLabel(filepath.Base(file), 64)
	}
	return "scan"
}

func trimLabel(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	if max <= 3 {
		return string(runes[:max])
	}
	return string(runes[:max-3]) + "..."
}

func newJobID() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

func validJobID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// removeRunDir deletes one timestamped run folder. root must be the parent
// recorded when the scan started; anything else is left untouched.
func removeRunDir(root, runDir string) error {
	if root == "" || runDir == "" {
		return errors.New("missing report path")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	runAbs, err := filepath.Abs(runDir)
	if err != nil {
		return err
	}
	info, err := os.Lstat(runAbs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("refusing to delete %s", runDir)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return err
	}
	runReal, err := filepath.EvalSymlinks(runAbs)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootReal, runReal)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to delete %s", runDir)
	}
	return os.RemoveAll(runAbs)
}
