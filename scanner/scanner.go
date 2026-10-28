package scanner

import (
	"context"
	"errors"
	"fmt"
	"image"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/schollz/progressbar/v3"

	"vncshot/report"
	"vncshot/screenshot"
	"vncshot/vnc"
)

// Options configures a scan run.
type Options struct {
	// ConnectTimeout bounds each TCP connect attempt.
	ConnectTimeout time.Duration
	// VNCTimeout bounds each RFB read/write inside a probe.
	VNCTimeout time.Duration
	// Workers is the number of concurrent probe goroutines.
	Workers int
	// RatePerSec caps new connection attempts per second; 0 disables.
	RatePerSec int
	// MaxRetries is how many times a transient connect failure is retried.
	// Only 0 (no retry) and 1 are supported; negative values are treated as
	// 0 and larger values are clamped to 1.
	MaxRetries int
	// RetryBackoff is the base delay before a retry; 0 uses 150ms. Actual
	// delays use exponential backoff with up to 50% jitter.
	RetryBackoff time.Duration
	// HostConcurrency caps how many probes run against the same target IP
	// at once; <= 0 uses 2. It complements the global worker pool so one
	// host is not hit by every worker at the same time.
	HostConcurrency int
	// ScreenshotDir is where passwordless captures are written.
	ScreenshotDir string
	// Shared requests a shared RFB session (does not kick active viewers).
	Shared bool
	// Passwords are weak-password candidates. Empty disables password
	// testing and keeps the scan to the passwordless check.
	Passwords []vnc.Credential
	// LocalAddr binds probes to a specific source address. Nil uses the
	// routing table's choice.
	LocalAddr net.IP
	// ProxyURL routes probes through a SOCKS5 proxy:
	// socks5://[user:pass@]host[:port] or socks5h://... (the proxy resolves
	// target hostnames). Empty connects directly.
	ProxyURL string
	// ShowProgress enables the terminal progress bar.
	ShowProgress bool
	// OnProgress, when set, is called once per completed probe. It runs on
	// the collecting goroutine, so implementations must not block for long.
	OnProgress func(done int, total int, r report.Result)
}

// Run probes every target and returns one Result per target, in
// completion order. Cancel ctx for a graceful shutdown: in-flight probes
// finish or abort and partial results are still returned.
func Run(ctx context.Context, targets []Target, opts Options) ([]report.Result, error) {
	if opts.Workers <= 0 {
		opts.Workers = DefaultWorkers
	}
	// Hard ceiling: every worker is a goroutine plus at least one socket, so
	// an accidentally huge value would exhaust file descriptors or memory
	// before the first probe completes.
	if opts.Workers > MaxWorkers {
		opts.Workers = MaxWorkers
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = time.Second
	}
	if opts.VNCTimeout <= 0 {
		opts.VNCTimeout = 15 * time.Second
	}

	limiter := NewRateLimiter(opts.RatePerSec)
	hostLimiter := newHostLimiter(opts.HostConcurrency)
	jobs := make(chan Target)
	results := make(chan report.Result)

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				if err := limiter.Wait(ctx); err != nil {
					// Context cancelled while waiting for a token.
					return
				}
				releaseHost, err := hostLimiter.acquire(ctx, t.IP)
				if err != nil {
					// Context cancelled while waiting for the host slot.
					return
				}
				res := probe(ctx, t, opts)
				releaseHost()
				results <- res
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, t := range targets {
			select {
			case jobs <- t:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out := make([]report.Result, 0, len(targets))

	var bar *progressbar.ProgressBar
	if opts.ShowProgress {
		bar = progressbar.NewOptions(len(targets),
			progressbar.OptionSetDescription("scanning"),
			progressbar.OptionShowCount(),
			progressbar.OptionSetWidth(30),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionOnCompletion(func() { fmt.Fprint(os.Stderr, "\n") }),
			progressbar.OptionSpinnerType(14),
			progressbar.OptionFullWidth(),
		)
	}

	for r := range results {
		out = append(out, r)
		if bar != nil {
			bar.Add(1)
		}
		if opts.OnProgress != nil {
			opts.OnProgress(len(out), len(targets), r)
		}
	}

	if bar != nil {
		bar.Finish()
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		return out, context.Canceled
	}
	return out, nil
}

// probe performs the RFB probe and, when the service allows a session, an
// optional screenshot. vnc.Probe owns the single TCP connection, so the
// scanner no longer dials once to test openness and again for the handshake.
func probe(ctx context.Context, t Target, opts Options) report.Result {
	return probeWith(ctx, t, opts, vnc.Probe)
}

// vncProbeFunc matches vnc.Probe. It is an unexported test seam so the retry
// policy can be exercised without a live network.
type vncProbeFunc func(context.Context, string, vnc.Options) (*vnc.Result, error)

func probeWith(ctx context.Context, t Target, opts Options, doProbe vncProbeFunc) (res report.Result) {
	start := time.Now()
	res = report.Result{
		IP:        t.IP,
		Port:      t.Port,
		Timestamp: start.UTC(),
	}
	defer func() {
		res.DurationMs = time.Since(start).Milliseconds()
	}()

	if err := ctx.Err(); err != nil {
		res.Error = err.Error()
		return res
	}

	maxRetries := opts.MaxRetries
	if maxRetries < 0 {
		maxRetries = 0
	}
	if maxRetries > 1 {
		maxRetries = 1
	}
	backoff := opts.RetryBackoff
	if backoff <= 0 {
		backoff = defaultRetryBackoff
	}

	addr := t.Addr()
	vncOpts := vnc.Options{
		Timeout:        opts.VNCTimeout,
		ConnectTimeout: opts.ConnectTimeout,
		Shared:         opts.Shared,
		Passwords:      opts.Passwords,
		LocalAddr:      opts.LocalAddr,
		ProxyURL:       opts.ProxyURL,
	}

	var vncRes *vnc.Result
	for attempt := 1; ; attempt++ {
		var err error
		vncRes, err = doProbe(ctx, addr, vncOpts)
		if err == nil {
			res.Attempts = attempt
			break
		}

		if !errors.Is(err, vnc.ErrConnect) {
			// The TCP connect succeeded, so the port is open. A reset or a
			// dropped handshake is often a transient server hiccup, so one
			// retry is allowed here too; a protocol error (malformed banner,
			// unsupported encoding) is definitive and is not retried.
			if ctx.Err() == nil && attempt <= maxRetries && isTransientHandshakeError(err) {
				if waitErr := sleepCtx(ctx, retryDelay(backoff, attempt)); waitErr == nil {
					continue
				}
			}

			res.Open = true
			res.Attempts = attempt
			if ctxErr := ctx.Err(); ctxErr != nil {
				// The probe was aborted mid-handshake by a cancellation.
				// Reporting the resulting socket deadline error ("i/o
				// timeout") would make an operator chase a phantom network
				// problem, so the real cause is recorded instead.
				res.Error = ctxErr.Error()
				return res
			}

			if vncRes != nil && vncRes.SawBanner {
				// The banner was parsed, so the endpoint definitely speaks
				// RFB: keep the partial evidence (security types, TLS
				// capability, server name) and record why the session could
				// not be established.
				res.RFB = true
				res.Note = vncRes.Note
				res.SecurityTypes = vncRes.SecurityTypeNames
				res.TLS = vncRes.TLS
				res.Passwordless = vncRes.Passwordless
				res.ServerName = vncRes.ServerName
				res.ScreenWidth = vncRes.Width
				res.ScreenHeight = vncRes.Height
				res.Certificate = certificateOf(vncRes)
			}
			res.Error = err.Error()
			return res
		}

		if ctx.Err() != nil {
			res.Error = ctx.Err().Error()
			if attempt > 1 {
				res.Attempts = attempt
			}
			return res
		}

		if attempt <= maxRetries && isTransientConnectError(err) {
			if waitErr := sleepCtx(ctx, retryDelay(backoff, attempt)); waitErr != nil {
				res.Error = waitErr.Error()
				res.Attempts = attempt
				return res
			}
			continue
		}

		// Closed/filtered ports are normal scan noise, not errors worth
		// surfacing in the report. A retry is still recorded so operators
		// can spot hosts that were flaky rather than definitively closed.
		if attempt > 1 {
			res.Attempts = attempt
		}
		return res
	}

	res.Open = true
	res.RFB = true
	res.Passwordless = vncRes.Passwordless
	res.Password = vncRes.Password
	res.PasswordSource = vncRes.PasswordSource
	res.AuthLocked = vncRes.AuthLocked
	res.Note = vncRes.Note
	res.SecurityTypes = vncRes.SecurityTypeNames
	res.TLS = vncRes.TLS
	res.Certificate = certificateOf(vncRes)
	res.ServerName = vncRes.ServerName
	res.ScreenWidth = vncRes.Width
	res.ScreenHeight = vncRes.Height

	// Capture whenever the session is established, whether it was open or
	// reached with a weak password. The client closes the session right
	// after reading this single frame.
	if (!vncRes.Passwordless && vncRes.Password == "") || vncRes.Frame == nil {
		return res
	}

	path, err := saveScreenshot(vncRes.Frame, opts.ScreenshotDir, t, res.Timestamp)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Screenshot = path
	return res
}

func saveScreenshot(img image.Image, dir string, t Target, ts time.Time) (string, error) {
	if dir == "" {
		dir = "screenshots"
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve screenshot directory: %w", err)
	}
	return screenshot.Save(img, abs, t.IP, t.Port, ts)
}

const (
	// DefaultWorkers is the worker pool size when the caller leaves it at 0.
	DefaultWorkers = 150
	// MaxWorkers caps the pool so a mistyped or hostile value cannot spawn
	// an unbounded number of goroutines and sockets.
	MaxWorkers = 4096
	// MaxRate caps new connections per second. Above this the computed
	// pacing interval rounds down to zero, which would silently disable the
	// limiter instead of honouring the requested rate.
	MaxRate = 100000
	// defaultHostConcurrency bounds simultaneous probes against one IP.
	defaultHostConcurrency = 2
	// defaultRetryBackoff is the base delay before a transient retry.
	defaultRetryBackoff = 150 * time.Millisecond
)

// isTransientConnectError reports whether a connect failure may succeed on a
// retry. A refused connection is definitive (nothing is listening), while
// timeouts, resets, broken pipes and unreachable hosts can be transient.
func isTransientConnectError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.EHOSTUNREACH)
}

// isTransientHandshakeError reports whether a failure that happened after the
// TCP connect can reasonably succeed on a retry: a dropped connection or a
// timeout. Anything else is a protocol-level answer and is not retried.
func isTransientHandshakeError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// retryDelay returns the jittered exponential backoff before the next
// attempt. attempt is 1-based, so the first retry waits
// [base, base*1.5].
func retryDelay(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = defaultRetryBackoff
	}
	if attempt < 1 {
		attempt = 1
	}
	delay := base
	for i := 1; i < attempt; i++ {
		// Overflow guard: no realistic scan reaches this, but a corrupted
		// retry count must not produce a negative delay.
		if delay > time.Duration(1<<62) {
			break
		}
		delay *= 2
	}
	// Up to 50% jitter keeps simultaneous retries from synchronising.
	jitter := time.Duration(rand.Int64N(int64(delay/2) + 1))
	return delay + jitter
}

// sleepCtx waits for d unless ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// certificateOf converts the client's TLS evidence into the report shape.
func certificateOf(res *vnc.Result) *report.Certificate {
	if res == nil || res.TLSInfo == nil {
		return nil
	}
	info := res.TLSInfo
	return &report.Certificate{
		Version:     info.Version,
		CipherSuite: info.CipherSuite,
		Subject:     info.Subject,
		Issuer:      info.Issuer,
		NotBefore:   info.NotBefore,
		NotAfter:    info.NotAfter,
		DNSNames:    append([]string(nil), info.DNSNames...),
		Fingerprint: info.Fingerprint,
		SelfSigned:  info.SelfSigned,
		Expired:     info.Expired,
		Verified:    info.Verified,
	}
}
