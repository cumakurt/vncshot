package app

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vncshot/report"
)

// metricsOutcome builds an Outcome whose summary carries the given targets
// count and one of every other counter, so gauge lines are distinguishable.
func metricsOutcome(targets int) Outcome {
	return Outcome{
		Summary: report.Summary{
			Targets:          targets,
			Open:             2,
			RFB:              2,
			Passwordless:     1,
			WeakCredentials:  1,
			TLS:              1,
			SelfSignedCerts:  1,
			ExpiringSoon:     4,
			AcceptedFindings: 5,
			Screenshots:      6,
			Errors:           7,
		},
	}
}

// scrapeGET issues a GET on handler and returns the body. For non-200
// responses it returns the status code with an empty body.
func scrapeGET(t *testing.T, handler http.Handler, path string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Code, w.Body.String()
}

// metricsBody scrapes path and requires a 200 response.
func metricsBody(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	code, body := scrapeGET(t, handler, path)
	if code != http.StatusOK {
		t.Fatalf("GET %s: status = %d, want 200", path, code)
	}
	return body
}

// containsPositiveFloat reports whether the line "<prefix><number>" exists
// with a number greater than zero.
func containsPositiveFloat(body, prefix string) bool {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimPrefix(line, prefix), 64)
		return err == nil && value > 0
	}
	return false
}

func TestMetricsHandlerEmptySnapshot(t *testing.T) {
	body := metricsBody(t, NewMetrics().Handler(), "/metrics")
	want := "# HELP vncshot_targets Targets in the last scan round.\n" +
		"# TYPE vncshot_targets gauge\n" +
		"vncshot_targets 0\n" +
		"# HELP vncshot_open Ports open in the last scan round.\n" +
		"# TYPE vncshot_open gauge\n" +
		"vncshot_open 0\n" +
		"# HELP vncshot_rfb_services RFB services found in the last scan round.\n" +
		"# TYPE vncshot_rfb_services gauge\n" +
		"vncshot_rfb_services 0\n" +
		"# HELP vncshot_passwordless RFB services reachable without a password in the last scan round.\n" +
		"# TYPE vncshot_passwordless gauge\n" +
		"vncshot_passwordless 0\n" +
		"# HELP vncshot_weak_credentials Endpoints accepting a weak credential in the last scan round.\n" +
		"# TYPE vncshot_weak_credentials gauge\n" +
		"vncshot_weak_credentials 0\n" +
		"# HELP vncshot_tls_services RFB services offering TLS in the last scan round.\n" +
		"# TYPE vncshot_tls_services gauge\n" +
		"vncshot_tls_services 0\n" +
		"# HELP vncshot_self_signed_certs TLS sessions whose certificate was self-signed in the last scan round.\n" +
		"# TYPE vncshot_self_signed_certs gauge\n" +
		"vncshot_self_signed_certs 0\n" +
		"# HELP vncshot_expiring_certs Certificates inside the expiry warning window in the last scan round.\n" +
		"# TYPE vncshot_expiring_certs gauge\n" +
		"vncshot_expiring_certs 0\n" +
		"# HELP vncshot_accepted_findings Findings approved through the acceptance list in the last scan round.\n" +
		"# TYPE vncshot_accepted_findings gauge\n" +
		"vncshot_accepted_findings 0\n" +
		"# HELP vncshot_screenshots Screenshots captured in the last scan round.\n" +
		"# TYPE vncshot_screenshots gauge\n" +
		"vncshot_screenshots 0\n" +
		"# HELP vncshot_errors Probe errors in the last scan round.\n" +
		"# TYPE vncshot_errors gauge\n" +
		"vncshot_errors 0\n" +
		"# HELP vncshot_scans_total Completed scan rounds published since process start.\n" +
		"# TYPE vncshot_scans_total counter\n" +
		"vncshot_scans_total 0\n" +
		"# HELP vncshot_last_scan_timestamp_seconds Completion time of the last scan round as a Unix timestamp in seconds.\n" +
		"# TYPE vncshot_last_scan_timestamp_seconds gauge\n" +
		"vncshot_last_scan_timestamp_seconds 0\n" +
		"# HELP vncshot_last_scan_duration_seconds Approximate duration of the last scan round; measured between publishes, so it includes scheduler idle time and is an upper bound.\n" +
		"# TYPE vncshot_last_scan_duration_seconds gauge\n" +
		"vncshot_last_scan_duration_seconds 0\n"
	if body != want {
		t.Fatalf("unexpected exposition\n got:\n%s\nwant:\n%s", body, want)
	}
}

func TestMetricsHandlerAfterPublish(t *testing.T) {
	m := NewMetrics()
	m.Publish(metricsOutcome(3))
	body := metricsBody(t, m.Handler(), "/metrics")
	for name, want := range map[string]string{
		"vncshot_targets":           "3",
		"vncshot_open":              "2",
		"vncshot_rfb_services":      "2",
		"vncshot_passwordless":      "1",
		"vncshot_weak_credentials":  "1",
		"vncshot_tls_services":      "1",
		"vncshot_self_signed_certs": "1",
		"vncshot_expiring_certs":    "4",
		"vncshot_accepted_findings": "5",
		"vncshot_screenshots":       "6",
		"vncshot_errors":            "7",
		"vncshot_scans_total":       "1",
	} {
		if line := name + " " + want; !strings.Contains(body, line+"\n") {
			t.Errorf("metric %s missing or wrong in:\n%s", name, body)
		}
	}
	if !containsPositiveFloat(body, "vncshot_last_scan_timestamp_seconds ") {
		t.Errorf("timestamp gauge missing or not positive in:\n%s", body)
	}
	if !strings.Contains(body, "vncshot_last_scan_duration_seconds 0\n") {
		t.Errorf("first publish should record a zero duration, body:\n%s", body)
	}
}

func TestMetricsPublishReplacesAndAccumulates(t *testing.T) {
	m := NewMetrics()
	m.Publish(metricsOutcome(10))
	m.Publish(metricsOutcome(4))
	body := metricsBody(t, m.Handler(), "/metrics")
	if !strings.Contains(body, "vncshot_targets 4\n") {
		t.Errorf("gauges must describe the last scan, not accumulate:\n%s", body)
	}
	if strings.Contains(body, "vncshot_targets 10\n") {
		t.Errorf("stale gauge value leaked:\n%s", body)
	}
	if !strings.Contains(body, "vncshot_scans_total 2\n") {
		t.Errorf("scans_total must accumulate across rounds:\n%s", body)
	}
	if !containsPositiveFloat(body, "vncshot_last_scan_duration_seconds ") {
		t.Errorf("duration between publishes missing or not positive:\n%s", body)
	}
}

func TestMetricsHandler404(t *testing.T) {
	handler := NewMetrics().Handler()
	code, body := scrapeGET(t, handler, "/secret123?x=1")
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
	if strings.Contains(body, "secret123") {
		t.Errorf("404 body must not echo the request path, got %q", body)
	}
}

// TestMetricsServe covers the exported Serve contract on a loopback port
// picked by an auxiliary listener: the endpoint answers, /metrics works and
// the server stops when the context is cancelled.
func TestMetricsServe(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick free port: %v", err)
	}
	addr := probe.Addr().String()
	probe.Close()

	m := NewMetrics()
	m.Publish(metricsOutcome(2))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- m.Serve(ctx, addr) }()

	// Retry the scrape briefly: Serve binds before returning from its
	// goroutine call, but the request races that bind.
	var body string
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, getErr := http.Get("http://" + addr + "/metrics")
		if getErr == nil {
			data, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil {
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d, want 200", resp.StatusCode)
				}
				body = string(data)
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("metrics endpoint never answered: %v", getErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(body, "vncshot_targets 2\n") {
		t.Errorf("served body missing gauge, got:\n%s", body)
	}

	cancel()
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatalf("Serve returned %v after cancellation, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}

	// A second scrape must now fail: the endpoint is really closed.
	if _, err := http.Get("http://" + addr + "/metrics"); err == nil {
		t.Error("endpoint still reachable after shutdown")
	}
}

// TestMetricsServeBindError checks that a taken address surfaces as a bind
// error from the exported Serve, not from inside the serving goroutine.
func TestMetricsServeBindError(t *testing.T) {
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind helper listener: %v", err)
	}
	defer held.Close()

	m := NewMetrics()
	if err := m.Serve(context.Background(), held.Addr().String()); err == nil {
		t.Fatal("Serve succeeded on an already bound address, want bind error")
	}
}

// TestMetricsConcurrentPublishAndScrape exercises the mutex under -race:
// publishers replace the snapshot while scrapers read it.
func TestMetricsConcurrentPublishAndScrape(t *testing.T) {
	m := NewMetrics()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					m.Publish(metricsOutcome(1))
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		code, _ := scrapeGET(t, m.Handler(), "/metrics")
		if code != http.StatusOK {
			t.Fatalf("scrape status = %d", code)
		}
	}
	close(stop)
	wg.Wait()
}
