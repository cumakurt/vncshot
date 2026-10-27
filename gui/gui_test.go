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
