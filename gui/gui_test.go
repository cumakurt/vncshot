package gui

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"vncshot/app"
	"vncshot/report"
)

const testToken = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T, cfg Config) (*server, *httptest.Server) {
	t.Helper()
	if cfg.Scan.Ports == "" {
		cfg.Scan.Ports = "5900"
	}
	srv := &server{
		token:   testToken,
		cfg:     cfg,
		version: "test",
		run: &runState{
			status:      statusIdle,
			subscribers: map[chan snapshot]struct{}{},
		},
	}
	ts := httptest.NewServer(srv.routes())
	t.Cleanup(ts.Close)
	return srv, ts
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar, Timeout: 30 * time.Second}
}

func doJSON(t *testing.T, client *http.Client, method, url string, payload any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, data
}

func TestIndexServesHTMLAndSetsCookie(t *testing.T) {
	_, ts := newTestServer(t, Config{})
	client := newClient(t)

	resp, body := doJSON(t, client, http.MethodGet, ts.URL+"/?t="+testToken, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "Scan control") {
		t.Error("index page does not contain the dashboard markup")
	}
	if strings.Contains(string(body), "Legal disclaimer") {
		t.Error("GUI page must not embed the legal notice block")
	}

	// The token query must have produced a cookie usable for the API.
	resp, _ = doJSON(t, client, http.MethodGet, ts.URL+"/api/state", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state status = %d after token exchange, want 200", resp.StatusCode)
	}
}

func TestAPIRequiresToken(t *testing.T) {
	_, ts := newTestServer(t, Config{})
	client := newClient(t)

	resp, _ := doJSON(t, client, http.MethodGet, ts.URL+"/api/state", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("state without cookie = %d, want 401", resp.StatusCode)
	}

	// Wrong token in the query must not establish a session.
	resp, _ = doJSON(t, client, http.MethodGet, ts.URL+"/?t=wrong", nil, nil)
	resp, _ = doJSON(t, client, http.MethodGet, ts.URL+"/api/state", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("state after wrong token = %d, want 401", resp.StatusCode)
	}
}

func TestStateChangingRequestsNeedTokenHeader(t *testing.T) {
	_, ts := newTestServer(t, Config{})
	client := newClient(t)
	doJSON(t, client, http.MethodGet, ts.URL+"/?t="+testToken, nil, nil)

	scan := map[string]any{"target": "127.0.0.1", "authorized": true}
	resp, _ := doJSON(t, client, http.MethodPost, ts.URL+"/api/scan", scan, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("scan without header = %d, want 403", resp.StatusCode)
	}
}

func TestScanRequiresAuthorizationConfirmation(t *testing.T) {
	_, ts := newTestServer(t, Config{})
	client := newClient(t)
	doJSON(t, client, http.MethodGet, ts.URL+"/?t="+testToken, nil, nil)
	auth := map[string]string{"X-Vncshot-Token": testToken}

	scan := map[string]any{"target": "127.0.0.1", "authorized": false}
	resp, _ := doJSON(t, client, http.MethodPost, ts.URL+"/api/scan", scan, auth)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("scan without confirmation = %d, want 403", resp.StatusCode)
	}
}

func TestScanRejectsMissingTarget(t *testing.T) {
	_, ts := newTestServer(t, Config{})
	client := newClient(t)
	doJSON(t, client, http.MethodGet, ts.URL+"/?t="+testToken, nil, nil)
	auth := map[string]string{"X-Vncshot-Token": testToken}

	resp, body := doJSON(t, client, http.MethodPost, ts.URL+"/api/scan",
		map[string]any{"authorized": true}, auth)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("scan without target = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(string(body), "target") {
		t.Errorf("error body %q does not explain the missing target", body)
	}
}

func TestFilesEndpointBlocksTraversal(t *testing.T) {
	srv, ts := newTestServer(t, Config{})
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, "report.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write report: %v", err)
	}
	srv.run.runDir = runDir

	client := newClient(t)
	doJSON(t, client, http.MethodGet, ts.URL+"/?t="+testToken, nil, nil)

	resp, _ := doJSON(t, client, http.MethodGet, ts.URL+"/files/report.json", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("existing artifact = %d, want 200", resp.StatusCode)
	}

	for _, path := range []string{
		"/files/../../../../etc/passwd",
		"/files/..%2f..%2fetc%2fpasswd",
		"/files/",
	} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("GET %s = 200, want the request to be rejected", path)
		}
	}
}

// fakePlainRFB serves a passwordless RFB session with a fixed frame.
func fakePlainRFB(t *testing.T, name string) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				conn.Write([]byte("RFB 003.008\n"))
				if _, err := io.ReadFull(conn, make([]byte, 12)); err != nil {
					return
				}
				conn.Write([]byte{1, 1}) // None
				if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
					return
				}
				conn.Write([]byte{0, 0, 0, 0}) // SecurityResult OK
				if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
					return
				}
				var init []byte
				init = append(init, 0, 2, 0, 2) // 2x2
				init = append(init, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0)
				init = append(init, 0, 0, 0, byte(len(name)))
				init = append(init, []byte(name)...)
				conn.Write(init)

				for {
					var typ [1]byte
					if _, err := io.ReadFull(conn, typ[:]); err != nil {
						return
					}
					switch typ[0] {
					case 0:
						io.ReadFull(conn, make([]byte, 19))
					case 2:
						var hdr [3]byte
						io.ReadFull(conn, hdr[:])
						n := int(hdr[2]) | int(hdr[1])<<8
						io.ReadFull(conn, make([]byte, n*4))
					case 3:
						io.ReadFull(conn, make([]byte, 9))
						frame := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 0}
						frame = append(frame, make([]byte, 2*2*4)...)
						conn.Write(frame)
						return
					default:
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestScanEndToEndThroughAPI(t *testing.T) {
	port := fakePlainRFB(t, "gui-desk")
	outDir := t.TempDir()

	srv, ts := newTestServer(t, Config{Scan: app.Config{OutDir: outDir}})
	client := newClient(t)
	doJSON(t, client, http.MethodGet, ts.URL+"/?t="+testToken, nil, nil)
	auth := map[string]string{"X-Vncshot-Token": testToken}

	scan := map[string]any{
		"target":         "127.0.0.1",
		"ports":          fmt.Sprint(port),
		"timeout_ms":     500,
		"vnc_timeout_ms": 3000,
		"workers":        2,
		"rate":           0,
		"out_dir":        outDir,
		"shared":         true,
		"no_pdf":         true,
		"authorized":     true,
	}
	resp, body := doJSON(t, client, http.MethodPost, ts.URL+"/api/scan", scan, auth)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("scan status = %d, body = %s", resp.StatusCode, body)
	}

	var state snapshot
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, raw := doJSON(t, client, http.MethodGet, ts.URL+"/api/state", nil, nil)
		if err := json.Unmarshal(raw, &state); err != nil {
			t.Fatalf("decode state: %v", err)
		}
		if state.Status != statusRunning {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if state.Status != statusCompleted {
		t.Fatalf("status = %q, want %q (error: %s)", state.Status, statusCompleted, state.Error)
	}

	if state.Summary.Targets != 1 || state.Summary.Passwordless != 1 {
		t.Errorf("summary = %+v, want 1 target and 1 passwordless", state.Summary)
	}
	if state.Summary.Screenshots != 1 {
		t.Errorf("screenshots = %d, want 1", state.Summary.Screenshots)
	}
	if len(state.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(state.Findings))
	}
	f := state.Findings[0]
	if !f.Passwordless || f.ServerName != "gui-desk" {
		t.Errorf("finding = %+v, want passwordless gui-desk", f)
	}
	if f.Screenshot == "" || !strings.HasPrefix(f.Screenshot, "/files/") {
		t.Errorf("screenshot link = %q, want a /files/ URL", f.Screenshot)
	}

	// The linked screenshot must be served as PNG.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+f.Screenshot, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch screenshot: %v", err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("screenshot status = %d, want 200", resp.StatusCode)
	}
	if len(data) < 8 || string(data[1:4]) != "PNG" {
		t.Error("served screenshot is not a PNG")
	}

	// Reports must exist on disk in the timestamped run directory.
	for _, name := range []string{"vncshot_report.json", "vncshot_report.html"} {
		path := filepath.Join(state.RunDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("report %q missing: %v", path, err)
		}
	}
	if state.ReportLinks["html"] == "" || state.ReportLinks["json"] == "" {
		t.Errorf("report links = %v, want html and json entries", state.ReportLinks)
	}
	if !strings.HasPrefix(state.RunDir, outDir) {
		t.Errorf("run dir %q is outside the configured root %q", state.RunDir, outDir)
	}

	// The scan must not have attempted any password against a
	// passwordless endpoint.
	if srv.run.credentials == 0 {
		t.Error("credentials were not prepared for the run")
	}
}

func TestScanConfigRejectsNegativeWorkers(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	if _, err := srv.scanConfig(scanRequest{Target: "192.0.2.1", Workers: -1}); err == nil {
		t.Fatal("scanConfig accepted negative workers, want an error")
	}
}

func TestScanConfigKeepsEmptyOutDirAsDefault(t *testing.T) {
	srv, _ := newTestServer(t, Config{Scan: app.Config{OutDir: "/usr/local/vncshot"}})
	cfg, err := srv.scanConfig(scanRequest{Target: "192.0.2.1"})
	if err != nil {
		t.Fatalf("scanConfig: %v", err)
	}
	if cfg.OutDirExplicit {
		t.Error("OutDirExplicit = true for an empty out_dir, want false (fallback allowed)")
	}
	if cfg.OutDir != "/usr/local/vncshot" {
		t.Errorf("OutDir = %q, want the configured default", cfg.OutDir)
	}
}

// TestSnapshotLinksAreURLs guards the browser payload: artifacts must be
// exposed as /files/ URLs rather than host paths.
func TestSnapshotLinksAreURLs(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	runDir := t.TempDir()
	srv.run.runDir = runDir
	srv.run.jsonPath = filepath.Join(runDir, "vncshot_report.json")
	srv.run.findings = []finding{{
		Addr:       "192.0.2.1:5900",
		Screenshot: filepath.Join(runDir, "screenshots", "shot.png"),
	}}

	snap := srv.snapshot()
	if !strings.HasPrefix(snap.Findings[0].Screenshot, "/files/") {
		t.Errorf("screenshot %q is not a /files/ URL", snap.Findings[0].Screenshot)
	}
	for key, link := range snap.ReportLinks {
		if link == "" {
			continue
		}
		if !strings.HasPrefix(link, "/files/") {
			t.Errorf("%s link %q is not a /files/ URL", key, link)
		}
	}
	for _, name := range snap.Files {
		if filepath.IsAbs(name) {
			t.Errorf("file entry %q is an absolute path", name)
		}
	}
}

func TestLoopbackEnforcement(t *testing.T) {
	for _, host := range []string{"0.0.0.0", "192.168.1.5", "example.com"} {
		if isLoopback(host) {
			t.Errorf("isLoopback(%q) = true, want false", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		if !isLoopback(host) {
			t.Errorf("isLoopback(%q) = false, want true", host)
		}
	}
}

func TestSummaryIsUpdatedDuringScan(t *testing.T) {
	// Guard the counters the dashboard renders: a weak credential must be
	// counted separately from a passwordless host.
	results := []report.Result{
		{IP: "192.0.2.1", Port: 5900, Open: true, RFB: true, Passwordless: true},
		{IP: "192.0.2.2", Port: 5900, Open: true, RFB: true, Password: "hunter2"},
	}
	sum := report.Summarize(results)
	if sum.Passwordless != 1 || sum.WeakCredentials != 1 {
		t.Errorf("summary = %+v, want 1 passwordless and 1 weak credential", sum)
	}
}

// login exchanges the session token for the guard cookie.
func login(t *testing.T, client *http.Client, baseURL string) {
	t.Helper()
	resp, _ := doJSON(t, client, http.MethodGet, baseURL+"/?t="+testToken, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange status = %d, want 200", resp.StatusCode)
	}
}

// writeRun creates a run folder with the artifacts the history endpoint
// inspects.
func writeRun(t *testing.T, root, name string, results []report.Result, withHTML, withPDF bool) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create run dir: %v", err)
	}
	if err := report.WriteJSON(filepath.Join(dir, "vncshot_report.json"), results); err != nil {
		t.Fatalf("write run json: %v", err)
	}
	if withHTML {
		if err := os.WriteFile(filepath.Join(dir, "vncshot_report.html"), []byte("<html></html>"), 0o600); err != nil {
			t.Fatalf("write run html: %v", err)
		}
	}
	if withPDF {
		if err := os.WriteFile(filepath.Join(dir, "vncshot_report.pdf"), []byte("%PDF-1.4\n"), 0o600); err != nil {
			t.Fatalf("write run pdf: %v", err)
		}
	}
	return dir
}

func TestRunsListsHistoryNewestFirst(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "20260101-010101", []report.Result{
		{IP: "192.0.2.1", Port: 5900, Open: true, RFB: true, Passwordless: true},
	}, true, false)
	writeRun(t, root, "20260202-020202", []report.Result{
		{IP: "192.0.2.2", Port: 5900, Open: true, RFB: true, Password: "hunter2", TLS: true},
		{IP: "192.0.2.3", Port: 5900, Open: true, RFB: true, TLS: true},
	}, true, true)

	// Non-run folders and symlinks must not show up in the history.
	if err := os.MkdirAll(filepath.Join(root, "notes"), 0o700); err != nil {
		t.Fatalf("create non-run dir: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "20260101-010101"), filepath.Join(root, "20260303-030303")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, ts := newTestServer(t, Config{Scan: app.Config{OutDir: root}})
	client := newClient(t)
	login(t, client, ts.URL)

	resp, body := doJSON(t, client, http.MethodGet, ts.URL+"/api/runs", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("runs status = %d, want 200 (%s)", resp.StatusCode, body)
	}
	var runs []runInfo
	if err := json.Unmarshal(body, &runs); err != nil {
		t.Fatalf("decode runs: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("runs = %d, want 2 (symlinks and non-run folders ignored)", len(runs))
	}
	if runs[0].Name != "20260202-020202" || runs[1].Name != "20260101-010101" {
		t.Fatalf("run order = %q, %q; want newest first", runs[0].Name, runs[1].Name)
	}
	if !runs[0].HasHTML || !runs[0].HasPDF || !runs[0].HasJSON {
		t.Errorf("newest run artifacts = %+v, want html, pdf and json", runs[0])
	}
	if runs[1].HasPDF {
		t.Errorf("oldest run reports a PDF it does not have")
	}
	if runs[0].Started == "" {
		t.Error("run has no start timestamp")
	}
	if _, err := time.Parse(time.RFC3339, runs[0].Started); err != nil {
		t.Errorf("started %q is not RFC3339: %v", runs[0].Started, err)
	}
	if runs[0].Size <= 0 {
		t.Errorf("size = %d, want a positive byte count", runs[0].Size)
	}
	if runs[0].Summary == nil {
		t.Fatal("newest run has no summary, want one parsed from JSON")
	}
	if runs[0].Summary.Targets != 2 || runs[0].Summary.WeakCredentials != 1 || runs[0].Summary.TLS != 2 {
		t.Errorf("summary = %+v, want 2 targets, 1 weak credential and 2 TLS services", *runs[0].Summary)
	}

	// The server must not expose the report root through the API.
	if strings.Contains(string(body), root) {
		t.Errorf("runs payload leaks the report root %q", root)
	}
}

func TestRunsIgnoresUnreadableJSON(t *testing.T) {
	root := t.TempDir()
	dir := writeRun(t, root, "20260101-010101", []report.Result{{IP: "192.0.2.1", Port: 5900}}, false, false)
	if err := os.WriteFile(filepath.Join(dir, "vncshot_report.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt report: %v", err)
	}
	_, ts := newTestServer(t, Config{Scan: app.Config{OutDir: root}})
	client := newClient(t)
	login(t, client, ts.URL)

	_, body := doJSON(t, client, http.MethodGet, ts.URL+"/api/runs", nil, nil)
	var runs []runInfo
	if err := json.Unmarshal(body, &runs); err != nil {
		t.Fatalf("decode runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(runs))
	}
	if runs[0].Summary != nil {
		t.Errorf("summary = %+v, want nil for an unreadable report", runs[0].Summary)
	}
	if runs[0].HasJSON != true {
		t.Error("has_json = false, want true because the file exists")
	}
}

func TestRunOpenSwitchesCurrentRun(t *testing.T) {
	root := t.TempDir()
	name := "20260202-020202"
	writeRun(t, root, name, []report.Result{
		{IP: "192.0.2.2", Port: 5900, Open: true, RFB: true, Password: "hunter2",
			SecurityTypes: []string{"VNC authentication"}, Attempts: 2},
	}, true, true)

	srv, ts := newTestServer(t, Config{Scan: app.Config{OutDir: root}})
	client := newClient(t)
	login(t, client, ts.URL)
	auth := map[string]string{"X-Vncshot-Token": testToken}

	resp, body := doJSON(t, client, http.MethodPost, ts.URL+"/api/runs/open",
		map[string]string{"name": name}, auth)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("open status = %d, want 200 (%s)", resp.StatusCode, body)
	}

	_, raw := doJSON(t, client, http.MethodGet, ts.URL+"/api/state", nil, nil)
	var state snapshot
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if state.Status != statusCompleted {
		t.Errorf("status = %q, want %q", state.Status, statusCompleted)
	}
	if state.Summary.Targets != 1 || state.Summary.WeakCredentials != 1 {
		t.Errorf("summary = %+v, want the parsed run summary", state.Summary)
	}
	if len(state.Findings) != 1 || state.Findings[0].Attempts != 2 {
		t.Fatalf("findings = %+v, want one finding with 2 attempts", state.Findings)
	}
	if state.RunDir != filepath.Join(root, name) {
		t.Errorf("run dir = %q, want the opened run folder", state.RunDir)
	}
	for _, key := range []string{"json", "html", "pdf"} {
		link := state.ReportLinks[key]
		if !strings.HasPrefix(link, "/files/") {
			t.Errorf("%s link = %q, want a /files/ URL", key, link)
		}
	}
	// The loaded run's artifacts must actually be servable.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+state.ReportLinks["html"], nil)
	fileResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch run html: %v", err)
	}
	fileResp.Body.Close()
	if fileResp.StatusCode != http.StatusOK {
		t.Errorf("run html status = %d, want 200", fileResp.StatusCode)
	}
	if srv.run.credentials != 0 {
		t.Errorf("credentials = %d, want 0 for a loaded run", srv.run.credentials)
	}
}

func TestRunOpenRejectsInvalidNames(t *testing.T) {
	root := t.TempDir()
	writeRun(t, root, "20260202-020202", []report.Result{{IP: "192.0.2.1", Port: 5900}}, false, false)
	// A run-shaped folder without a JSON report must not be openable.
	if err := os.MkdirAll(filepath.Join(root, "20250101-010101"), 0o700); err != nil {
		t.Fatalf("create empty run dir: %v", err)
	}

	_, ts := newTestServer(t, Config{Scan: app.Config{OutDir: root}})
	client := newClient(t)
	login(t, client, ts.URL)
	auth := map[string]string{"X-Vncshot-Token": testToken}

	for _, name := range []string{
		"../20260202-020202",
		"..",
		"/etc",
		"/etc/passwd",
		`..\20260202-020202`,
		"nested/20260202-020202",
		"20260202-020202/../../../etc",
		"notes",
	} {
		resp, body := doJSON(t, client, http.MethodPost, ts.URL+"/api/runs/open",
			map[string]string{"name": name}, auth)
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
			t.Errorf("open %q = %d, want 400 or 404", name, resp.StatusCode)
		}
		if strings.Contains(string(body), root) {
			t.Errorf("open %q error leaks the report root", name)
		}
	}

	resp, _ := doJSON(t, client, http.MethodPost, ts.URL+"/api/runs/open",
		map[string]string{"name": "20250102-030303"}, auth)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing run = %d, want 404", resp.StatusCode)
	}
	resp, _ = doJSON(t, client, http.MethodPost, ts.URL+"/api/runs/open",
		map[string]string{"name": "20250101-010101"}, auth)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("run without JSON = %d, want 404", resp.StatusCode)
	}
}

func TestRunOpenConflictsWithRunningScan(t *testing.T) {
	root := t.TempDir()
	name := "20260202-020202"
	writeRun(t, root, name, []report.Result{{IP: "192.0.2.1", Port: 5900}}, false, false)

	srv, ts := newTestServer(t, Config{Scan: app.Config{OutDir: root}})
	srv.run.status = statusRunning
	client := newClient(t)
	login(t, client, ts.URL)
	auth := map[string]string{"X-Vncshot-Token": testToken}

	resp, _ := doJSON(t, client, http.MethodPost, ts.URL+"/api/runs/open",
		map[string]string{"name": name}, auth)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("open during scan = %d, want 409", resp.StatusCode)
	}
}

func TestRunEndpointsRequireGuard(t *testing.T) {
	root := t.TempDir()
	_, ts := newTestServer(t, Config{Scan: app.Config{OutDir: root}})
	client := newClient(t)

	resp, _ := doJSON(t, client, http.MethodGet, ts.URL+"/api/runs", nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("runs without cookie = %d, want 401", resp.StatusCode)
	}

	login(t, client, ts.URL)
	resp, _ = doJSON(t, client, http.MethodPost, ts.URL+"/api/runs/open",
		map[string]string{"name": "20260202-020202"}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("open without token header = %d, want 403", resp.StatusCode)
	}
}

func TestSnapshotExposesTransportAndRetryData(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	srv.run.findings = []finding{toFinding(report.Result{
		IP:            "192.0.2.1",
		Port:          5900,
		Open:          true,
		RFB:           true,
		SecurityTypes: []string{"VNC authentication", "VeNCrypt"},
		TLS:           true,
		Attempts:      3,
	})}

	raw, err := json.Marshal(srv.snapshot())
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var decoded struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if len(decoded.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(decoded.Findings))
	}
	finding := decoded.Findings[0]
	for _, key := range []string{"security_types", "tls", "attempts"} {
		if _, ok := finding[key]; !ok {
			t.Errorf("finding JSON is missing %q", key)
		}
	}
	var tls bool
	if err := json.Unmarshal(finding["tls"], &tls); err != nil || !tls {
		t.Errorf("tls = %s, want true", finding["tls"])
	}
	var attempts int
	if err := json.Unmarshal(finding["attempts"], &attempts); err != nil || attempts != 3 {
		t.Errorf("attempts = %s, want 3", finding["attempts"])
	}
}

// TestDashboardElementIDsExist keeps the embedded script and markup in sync:
// every element the script looks up must exist on the page.
func TestDashboardElementIDsExist(t *testing.T) {
	page, err := assets.ReadFile("index.html")
	if err != nil {
		t.Fatalf("read embedded html: %v", err)
	}
	html := string(page)

	known := map[string]bool{}
	for _, match := range regexp.MustCompile(`id="([^"]+)"`).FindAllStringSubmatch(html, -1) {
		known[match[1]] = true
	}

	referenced := map[string]bool{}
	for _, pattern := range []string{`\$\("([^"]+)"\)`, `getElementById\("([^"]+)"\)`} {
		for _, match := range regexp.MustCompile(pattern).FindAllStringSubmatch(html, -1) {
			referenced[match[1]] = true
		}
	}
	if len(referenced) == 0 {
		t.Fatal("no element lookups found in index.html")
	}
	for id := range referenced {
		if !known[id] {
			t.Errorf("index.html references #%s but no element defines it", id)
		}
	}
}

// TestFindingsAreSortedDeterministically guards parity with the report
// artifacts: the dashboard must not show a different order than the JSON.
func TestFindingsAreSortedDeterministically(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	srv.run.findings = []finding{
		{IP: "10.0.0.10", Port: 5900},
		{IP: "10.0.0.9", Port: 5902},
		{IP: "10.0.0.9", Port: 5900},
		{IP: "host.example", Port: 5900},
	}

	got := srv.snapshot().Findings
	want := []struct {
		ip   string
		port int
	}{
		{"10.0.0.9", 5900},
		{"10.0.0.9", 5902},
		{"10.0.0.10", 5900},
		{"host.example", 5900},
	}
	if len(got) != len(want) {
		t.Fatalf("findings = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].IP != want[i].ip || got[i].Port != want[i].port {
			t.Errorf("finding[%d] = %s:%d, want %s:%d", i, got[i].IP, got[i].Port, want[i].ip, want[i].port)
		}
	}
}

// TestReportLinksHiddenWhileRunning guards the dashboard: artifact paths are
// known when a scan starts, but the files do not exist yet, so showing the
// links would produce 404s for the operator.
func TestReportLinksHiddenWhileRunning(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	runDir := t.TempDir()
	srv.run.runDir = runDir
	srv.run.jsonPath = filepath.Join(runDir, "vncshot_report.json")
	srv.run.htmlPath = filepath.Join(runDir, "vncshot_report.html")

	srv.run.status = statusRunning
	if links := srv.snapshot().ReportLinks; len(links) != 0 {
		t.Errorf("links while running = %v, want none", links)
	}

	srv.run.status = statusCompleted
	if links := srv.snapshot().ReportLinks; links["json"] == "" || links["html"] == "" {
		t.Errorf("links after completion = %v, want json and html entries", links)
	}
}

// TestManifestIsNotTreatedAsTheReport guards the history listing: a run
// folder that only holds manifest.json has no report to open.
func TestManifestIsNotTreatedAsTheReport(t *testing.T) {
	root := t.TempDir()
	runName := "20261027-120000"
	dir := filepath.Join(root, runName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"files":[]}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	started, err := time.ParseInLocation(app.RunTimestampLayout, runName, time.Local)
	if err != nil {
		t.Fatalf("parse run name: %v", err)
	}
	info := describeRun(dir, runName, started)
	if info.HasJSON {
		t.Error("HasJSON = true for a folder that only holds a manifest")
	}
	if info.Summary != nil {
		t.Errorf("Summary = %+v, want nil when there is no report", info.Summary)
	}
}

// TestFilesEndpointRejectsSymlinkEscape guards the artifact route: a symlink
// planted inside the run folder must not serve an arbitrary host file.
func TestFilesEndpointRejectsSymlinkEscape(t *testing.T) {
	srv, ts := newTestServer(t, Config{})
	runDir := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("host secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	if err := os.Symlink(secret, filepath.Join(runDir, "leak.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	srv.run.runDir = runDir

	client := newClient(t)
	doJSON(t, client, http.MethodGet, ts.URL+"/?t="+testToken, nil, nil)

	resp, body := doJSON(t, client, http.MethodGet, ts.URL+"/files/leak.txt", nil, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("symlink served host content: %s", body)
	}
	if strings.Contains(string(body), "host secret") {
		t.Fatal("symlink escape leaked file content")
	}
}

// TestIndexSetsReferrerPolicy guards token hygiene: the session token is in
// the URL, so the page must not leak it through Referer.
func TestIndexSetsReferrerPolicy(t *testing.T) {
	_, ts := newTestServer(t, Config{})
	resp, err := http.Get(ts.URL + "/?t=" + testToken)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if got := resp.Header.Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
}

// TestDashboardRendersFindingsInReportOrder guards UI/artifact parity: the
// findings table must not reverse the server order, otherwise the dashboard
// and the JSON report of the same run disagree.
func TestDashboardRendersFindingsInReportOrder(t *testing.T) {
	page, err := assets.ReadFile("index.html")
	if err != nil {
		t.Fatalf("read embedded page: %v", err)
	}
	body := string(page)
	if strings.Contains(body, "rows.slice().reverse()") {
		t.Error("findings are reversed before rendering; they must follow the report order")
	}
	if !strings.Contains(body, "rows.forEach(function (f)") {
		t.Error("findings renderer no longer iterates rows in server order")
	}
}

// TestSnapshotExposesWarningAndDiff guards the GUI parity with the CLI: a
// failing webhook and a requested baseline comparison must not disappear just
// because the scan was started from the dashboard.
func TestSnapshotExposesWarningAndDiff(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	srv.run.warning = "webhook notification failed: connection refused"
	srv.run.diff = &diffSummary{Baseline: "20261020-090000", New: 2, Resolved: 1, Changed: 3}

	snap := srv.snapshot()
	if snap.Warning == "" {
		t.Error("Warning is empty, want the webhook failure surfaced")
	}
	if snap.Diff == nil {
		t.Fatal("Diff is nil, want the baseline comparison exposed")
	}
	if snap.Diff.New != 2 || snap.Diff.Resolved != 1 || snap.Diff.Changed != 3 {
		t.Errorf("Diff = %+v, want 2 new / 1 resolved / 3 changed", snap.Diff)
	}
	if snap.Diff.Baseline != "20261020-090000" {
		t.Errorf("Diff.Baseline = %q, want the run folder name", snap.Diff.Baseline)
	}

	body, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if !strings.Contains(string(body), `"diff":`) {
		t.Error("snapshot JSON does not contain the diff object")
	}
}

// TestScanConfigMapsRunOptions guards the dashboard/CLI parity: the form must
// be able to start a baseline comparison, write a CSV and a manifest, notify a
// webhook and apply retention.
func TestScanConfigMapsRunOptions(t *testing.T) {
	root := t.TempDir()
	srv, _ := newTestServer(t, Config{Scan: app.Config{OutDir: root}})

	cfg, err := srv.scanConfig(scanRequest{
		Target:      "192.0.2.1",
		Baseline:    " 20261020-090000 ",
		CSV:         " audit.csv ",
		Webhook:     " https://hooks.example/vncshot ",
		Manifest:    true,
		KeepRuns:    5,
		PruneDryRun: true,
	})
	if err != nil {
		t.Fatalf("scanConfig: %v", err)
	}
	wantBaseline := filepath.Join(root, "20261020-090000")
	if cfg.Baseline != wantBaseline {
		t.Errorf("Baseline = %q, want %q resolved against the report root", cfg.Baseline, wantBaseline)
	}
	if cfg.CSV != "audit.csv" {
		t.Errorf("CSV = %q, want the trimmed override", cfg.CSV)
	}
	if cfg.WebhookURL != "https://hooks.example/vncshot" {
		t.Errorf("WebhookURL = %q, want the trimmed URL", cfg.WebhookURL)
	}
	if !cfg.Manifest {
		t.Error("Manifest = false, want true")
	}
	if cfg.KeepRuns != 5 {
		t.Errorf("KeepRuns = %d, want 5", cfg.KeepRuns)
	}
	if !cfg.PruneDryRun {
		t.Error("PruneDryRun = false, want true")
	}

	// An explicit path from the CLI-style field is kept verbatim.
	absolute := filepath.Join(t.TempDir(), "previous")
	cfg, err = srv.scanConfig(scanRequest{Target: "192.0.2.1", Baseline: absolute})
	if err != nil {
		t.Fatalf("scanConfig with absolute baseline: %v", err)
	}
	if cfg.Baseline != absolute {
		t.Errorf("Baseline = %q, want %q", cfg.Baseline, absolute)
	}
}

func TestScanConfigRejectsNegativeKeepRuns(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	if _, err := srv.scanConfig(scanRequest{Target: "192.0.2.1", KeepRuns: -1}); err == nil {
		t.Fatal("scanConfig accepted a negative keep_runs, want an error")
	}
}

// TestScanConfigRejectsNonHTTPWebhook guards the notifier: the server posts to
// the configured URL, so only http(s) endpoints are allowed.
func TestScanConfigRejectsNonHTTPWebhook(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	for _, endpoint := range []string{
		"file:///etc/passwd",
		"ftp://hooks.example/vncshot",
		"gopher://hooks.example/vncshot",
	} {
		_, err := srv.scanConfig(scanRequest{Target: "192.0.2.1", Webhook: endpoint})
		if err == nil {
			t.Fatalf("scanConfig accepted %q, want an error", endpoint)
		}
		scheme := endpoint[:strings.Index(endpoint, ":")]
		if !strings.Contains(err.Error(), scheme) {
			t.Errorf("error for %q = %q, want the scheme named", endpoint, err)
		}
	}
}

// TestScanConfigRejectsScreenshotDirOutsideRunRoot guards thumbnail
// visibility: /files/ only serves the run folder, so a screenshot directory
// elsewhere would produce findings whose images silently 404.
func TestScanConfigRejectsScreenshotDirOutsideRunRoot(t *testing.T) {
	root := t.TempDir()
	srv, _ := newTestServer(t, Config{Scan: app.Config{OutDir: root}})

	outside := t.TempDir()
	for _, dir := range []string{outside, "../screenshots", "shots/../../elsewhere"} {
		_, err := srv.scanConfig(scanRequest{Target: "192.0.2.1", ScreenshotDir: dir})
		if err == nil {
			t.Fatalf("scanConfig accepted screenshot dir %q outside the run root", dir)
		}
		if !strings.Contains(err.Error(), "screenshot directory must be inside the run folder") {
			t.Errorf("error for %q = %q, want the actionable message", dir, err)
		}
	}
}

func TestScanConfigAcceptsScreenshotDirInsideRunRoot(t *testing.T) {
	root := t.TempDir()
	srv, _ := newTestServer(t, Config{Scan: app.Config{OutDir: root}})

	for _, dir := range []string{"screenshots", "shots/2026", filepath.Join(root, "screenshots")} {
		cfg, err := srv.scanConfig(scanRequest{Target: "192.0.2.1", ScreenshotDir: dir})
		if err != nil {
			t.Fatalf("scanConfig rejected %q: %v", dir, err)
		}
		if cfg.ScreenshotDir != dir {
			t.Errorf("ScreenshotDir = %q, want %q", cfg.ScreenshotDir, dir)
		}
	}
}

// TestSnapshotExposesRemovedRuns guards the retention indicator: the dashboard
// shows how many old run folders the last scan removed.
func TestSnapshotExposesRemovedRuns(t *testing.T) {
	srv, _ := newTestServer(t, Config{})
	if snap := srv.snapshot(); snap.RemovedRuns != 0 {
		t.Errorf("RemovedRuns = %d before a retention pass, want 0", snap.RemovedRuns)
	}

	srv.run.removedRuns = 3
	raw, err := json.Marshal(srv.snapshot())
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	value, ok := decoded["removed_runs"]
	if !ok {
		t.Fatal("snapshot JSON is missing removed_runs")
	}
	var removed int
	if err := json.Unmarshal(value, &removed); err != nil || removed != 3 {
		t.Errorf("removed_runs = %s, want 3", value)
	}
}

// TestFormPersistsRunOptionsButNotAuthorization guards the dashboard contract:
// the new run-level controls survive a reload, while the authorization
// checkbox must be re-confirmed for every scan.
func TestFormPersistsRunOptionsButNotAuthorization(t *testing.T) {
	page, err := assets.ReadFile("index.html")
	if err != nil {
		t.Fatalf("read embedded html: %v", err)
	}
	html := string(page)

	match := regexp.MustCompile(`(?s)var formFields = \[(.*?)\]`).FindStringSubmatch(html)
	if match == nil {
		t.Fatal("index.html has no formFields list")
	}
	fields := match[1]
	for _, id := range []string{"baseline", "csv", "manifest", "webhook", "redact", "keep_runs", "prune_dry_run"} {
		if !strings.Contains(fields, `"`+id+`"`) {
			t.Errorf("formFields is missing %q, so the control does not persist", id)
		}
	}
	if strings.Contains(fields, `"authorized"`) {
		t.Error("formFields persists the authorization checkbox; it must be re-confirmed every time")
	}
	if !strings.Contains(html, "authorized.checked = false") {
		t.Error("loadForm no longer clears the authorization checkbox")
	}
}
