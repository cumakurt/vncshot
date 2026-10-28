// This file implements the operational metrics endpoint: a plain Prometheus
// text exposition of the latest scan round plus a few scan-series counters.
// It intentionally depends only on the standard library.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics holds a thread-safe snapshot of the most recent scan Outcome plus
// accumulated scan-series counters. Gauges describe the LAST scan round
// (replace semantics, not accumulation); vncshot_scans_total counts every
// published round.
//
// No labels are exposed on purpose. The obvious label candidates (run
// directory names, target hosts) grow by one value per scan round or per
// probed endpoint, so cardinality would be unbounded and a long-running
// -interval deployment would slowly consume scraper memory. Counts without
// labels stay bounded and remain useful for operational alerting.
type Metrics struct {
	mu sync.Mutex

	// last is the summary of the most recent published Outcome. It reads
	// as zeros until the first Publish call.
	last reportSummary
	// scansTotal counts every published round since process start.
	scansTotal int
	// lastTimestamp is when the latest Outcome was published.
	lastTimestamp time.Time
	// lastDuration approximates the scan duration. The Outcome carries no
	// duration field, so it is measured as the wall time between two
	// consecutive Publish calls. This OVERSTATES the real scan time on an
	// -interval deployment, where the gap includes the scheduler sleep;
	// treat it as an upper bound, not a precise measurement.
	lastDuration time.Duration
	// hasPrevious records whether a previous Publish exists, so the first
	// Publish does not invent a duration from a zero time.
	hasPrevious bool
}

// reportSummary mirrors the counters of report.Summary. A separate type keeps
// this file independent of the report package's JSON struct tags.
type reportSummary struct {
	targets, open, rfb, passwordless, weakCredentials int
	tls, selfSignedCerts, expiringSoon                int
	acceptedFindings, screenshots, errors             int
}

// NewMetrics returns an empty metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{}
}

// Publish replaces the snapshot with out and advances the scan-series
// counters. It is safe for concurrent use.
func (m *Metrics) Publish(out Outcome) {
	s := reportSummary{
		targets:          out.Summary.Targets,
		open:             out.Summary.Open,
		rfb:              out.Summary.RFB,
		passwordless:     out.Summary.Passwordless,
		weakCredentials:  out.Summary.WeakCredentials,
		tls:              out.Summary.TLS,
		selfSignedCerts:  out.Summary.SelfSignedCerts,
		expiringSoon:     out.Summary.ExpiringSoon,
		acceptedFindings: out.Summary.AcceptedFindings,
		screenshots:      out.Summary.Screenshots,
		errors:           out.Summary.Errors,
	}

	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hasPrevious {
		// Approximate duration: wall time since the previous publish. It
		// includes scheduler idle time, so it is an upper bound only.
		m.lastDuration = now.Sub(m.lastTimestamp)
	}
	m.last = s
	m.scansTotal++
	m.lastTimestamp = now
	m.hasPrevious = true
}

// render produces the Prometheus text exposition for the current snapshot.
// The format is stable: HELP, TYPE, then the sample line, in a fixed metric
// order, so scrapers and diff tools see a deterministic body.
func (m *Metrics) render() string {
	m.mu.Lock()
	s := m.last
	scansTotal := m.scansTotal
	timestamp := m.lastTimestamp
	duration := m.lastDuration
	m.mu.Unlock()

	timestampSeconds := float64(0)
	if !timestamp.IsZero() {
		timestampSeconds = float64(timestamp.Unix())
	}
	durationSeconds := duration.Seconds()

	var b strings.Builder
	writeMetric := func(name, help, kind, value string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n%s %s\n", name, help, name, kind, name, value)
	}
	intValue := func(v int) string { return strconv.Itoa(v) }
	floatValue := func(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

	writeMetric("vncshot_targets", "Targets in the last scan round.", "gauge", intValue(s.targets))
	writeMetric("vncshot_open", "Ports open in the last scan round.", "gauge", intValue(s.open))
	writeMetric("vncshot_rfb_services", "RFB services found in the last scan round.", "gauge", intValue(s.rfb))
	writeMetric("vncshot_passwordless", "RFB services reachable without a password in the last scan round.", "gauge", intValue(s.passwordless))
	writeMetric("vncshot_weak_credentials", "Endpoints accepting a weak credential in the last scan round.", "gauge", intValue(s.weakCredentials))
	writeMetric("vncshot_tls_services", "RFB services offering TLS in the last scan round.", "gauge", intValue(s.tls))
	writeMetric("vncshot_self_signed_certs", "TLS sessions whose certificate was self-signed in the last scan round.", "gauge", intValue(s.selfSignedCerts))
	writeMetric("vncshot_expiring_certs", "Certificates inside the expiry warning window in the last scan round.", "gauge", intValue(s.expiringSoon))
	writeMetric("vncshot_accepted_findings", "Findings approved through the acceptance list in the last scan round.", "gauge", intValue(s.acceptedFindings))
	writeMetric("vncshot_screenshots", "Screenshots captured in the last scan round.", "gauge", intValue(s.screenshots))
	writeMetric("vncshot_errors", "Probe errors in the last scan round.", "gauge", intValue(s.errors))
	writeMetric("vncshot_scans_total", "Completed scan rounds published since process start.", "counter", intValue(scansTotal))
	writeMetric("vncshot_last_scan_timestamp_seconds", "Completion time of the last scan round as a Unix timestamp in seconds.", "gauge", floatValue(timestampSeconds))
	writeMetric("vncshot_last_scan_duration_seconds", "Approximate duration of the last scan round; measured between publishes, so it includes scheduler idle time and is an upper bound.", "gauge", floatValue(durationSeconds))
	return b.String()
}

// Handler returns the HTTP handler for the metrics endpoint. Only /metrics
// serves the exposition; every other path answers a plain 404 and never
// echoes the requested path, so the endpoint leaks nothing about the host
// layout. There is no authentication: this is an operational counters
// endpoint, and the operator is expected to bind it to a loopback or
// otherwise firewalled address.
func (m *Metrics) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		// The exposition is a snapshot per scrape; no caching layer sits
		// in front, so a plain text response is always current.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, m.render())
	})
	// Catch-all: a static 404 without reflecting the request path.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return mux
}

// Serve binds addr and serves the metrics endpoint until ctx is done. It
// returns the bind error when the address cannot be taken, the server error
// if the HTTP server stops unexpectedly before ctx is done, and nil after a
// graceful shutdown. addr may include a port of 0 (for example
// "127.0.0.1:0"), but the chosen port is not reported back; callers that
// need the actual address should pass a listener-derived port instead.
//
// Shutdown is bounded: when ctx is done the server stops accepting
// connections and in-flight requests get a fixed grace period before the
// call returns. Nothing is logged, not even request paths.
func (m *Metrics) Serve(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("bind metrics endpoint %s: %w", addr, err)
	}
	return m.serve(ctx, ln)
}

// serve runs the endpoint on an already-bound listener. Splitting it out of
// Serve lets tests bind 127.0.0.1:0 and learn the actual port.
func (m *Metrics) serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler: m.Handler(),
		// Bounded protocol timeouts: the endpoint serves one static
		// response and must never hold a connection indefinitely.
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Suppress all server-side logging, including error lines that
		// could carry request paths.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		// Bounded grace period: metrics responses are tiny, so five
		// seconds is generous and the CLI is never stuck on exit.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			srv.Close()
		}
		select {
		case err := <-serveErr:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-time.After(6 * time.Second):
			return nil
		}
	}
}
