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
	"strconv"
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
	// ShowProgress enables the terminal progress bar and the live finding
	// counters drawn under it.
	ShowProgress bool
	// ProgressWriter is where the progress bar and live counters are drawn.
	// Nil uses stderr, which is where the rest of the CLI chrome goes.
	ProgressWriter io.Writer
	// SeedResults contribute to the live counters without being probed.
	// A resumed scan passes the reused results so the totals match the
	// final summary from the first paint.
	SeedResults []report.Result
	// OnProgress, when set, is called once per completed probe. It runs on
	// the collecting goroutine, so implementations must not block for long.
	OnProgress func(done int, total int, r report.Result)
}

// liveFindings is the running tally printed under the progress bar. The
// fields match the CLI summary so an operator can read partial counts
// without waiting for the scan to finish.
type liveFindings struct {
	open         int
	rfb          int
	passwordless int
	weak         int
	screenshots  int
	errors       int
}

// observe folds one result into the tally. It returns whether any counter
// changed, which is what throttles redraws while closed ports stream past.
func (c *liveFindings) observe(r report.Result) bool {
	before := *c
	if r.Open {
		c.open++
	}
	if r.RFB {
		c.rfb++
	}
	if r.Passwordless {
		c.passwordless++
	}
	if r.Password != "" {
		c.weak++
	}
	if r.Screenshot != "" {
		c.screenshots++
	}
	if r.Error != "" {
		c.errors++
	}
	return *c != before
}

// line renders the counters as one plain row. Values only: evidence
// (addresses, passwords, errors) stays in the report, not on this line.
func (c liveFindings) line() string {
	return fmt.Sprintf("open %d  rfb %d  passwordless %d  weak %d  screenshots %d  errors %d",
		c.open, c.rfb, c.passwordless, c.weak, c.screenshots, c.errors)
}

// lineColored is the terminal form of line. Zero counts stay dim; a positive
// count is bold in the same tone the summary uses, so a hit is visible
// without reading the final report.
func (c liveFindings) lineColored() string {
	return fmt.Sprintf("%s %s  %s %s  %s %s  %s %s  %s %s  %s %s",
		liveLabel("open"), liveCount(c.open, "36"),
		liveLabel("rfb"), liveCount(c.rfb, "36"),
		liveLabel("passwordless"), liveCount(c.passwordless, "31"),
		liveLabel("weak"), liveCount(c.weak, "31"),
		liveLabel("screenshots"), liveCount(c.screenshots, "32"),
		liveLabel("errors"), liveCount(c.errors, "33"))
}

func liveLabel(name string) string {
	return "\x1b[1m" + name + "\x1b[0m"
}

func liveCount(n int, color string) string {
	text := strconv.Itoa(n)
	if n == 0 {
		return "\x1b[2m" + text + "\x1b[0m"
	}
	return "\x1b[1;" + color + "m" + text + "\x1b[0m"
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

	var counts liveFindings
	var bar *progressbar.ProgressBar
	var lastPaint time.Time
	colorLive := false
	if opts.ShowProgress && len(targets) > 0 {
		for _, seeded := range opts.SeedResults {
			counts.observe(seeded)
		}
		writer := progressWriter(opts)
		colorLive = writerIsTerminal(writer)
		bar = newProgressBar(len(targets), writer, colorLive)
		// Paint the row before the first probe returns so the categories
		// are visible for the whole run, including a scan that finds nothing.
		paintFindings(bar, counts, colorLive)
		lastPaint = time.Now()
	}

	for r := range results {
		out = append(out, r)
		changed := counts.observe(r)
		if bar != nil {
			// Closed ports do not change the row. Open ports refresh at
			// the bar's cadence; a passwordless host, a weak credential
			// or a screenshot is painted immediately.
			notable := r.Passwordless || r.Password != "" || r.Screenshot != ""
			last := len(out) == len(targets)
			if last || (changed && (notable || time.Since(lastPaint) >= 100*time.Millisecond)) {
				paintFindings(bar, counts, colorLive)
				lastPaint = time.Now()
			}
			_ = bar.Add(1)
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

func progressWriter(opts Options) io.Writer {
	if opts.ProgressWriter != nil {
		return opts.ProgressWriter
	}
	return os.Stderr
}

// writerIsTerminal reports whether w is a character device. Colour is used
// only there; a buffer or a pipe keeps the plain counter line.
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// newProgressBar builds the CLI bar. The finding row is one detail line
// under the bar, rewritten in place, so the operator can read partial
// counts without the bar itself being squeezed off a narrow terminal.
// On a terminal the bar is a coloured block; a pipe stays monochrome.
//
// The width stays fixed and the predicted-time suffix stays off. Both change
// the line length on every paint, and the library's default refresh blanks
// the line before drawing it again, so the "scanning" label flashes. On a
// terminal the same paint is one carriage-return plus an erase-to-end, which
// replaces the line without that blank frame.
func newProgressBar(total int, w io.Writer, color bool) *progressbar.ProgressBar {
	desc := "scanning"
	options := []progressbar.Option{
		progressbar.OptionSetWriter(w),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(30),
		progressbar.OptionThrottle(100 * time.Millisecond),
		progressbar.OptionSetMaxDetailRow(1),
		progressbar.OptionOnCompletion(func() { fmt.Fprint(w, "\n") }),
		progressbar.OptionSetPredictTime(false),
	}
	if color {
		desc = "[cyan]scanning[reset]"
		options = append(options,
			progressbar.OptionUseANSICodes(true),
			progressbar.OptionEnableColorCodes(true),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        "[green]█[reset]",
				SaucerHead:    "[green]█[reset]",
				SaucerPadding: "[white]░[reset]",
				// End caps stay empty. A filled cap on the right is the same
				// glyph family as the saucer, so a bar at 0% looks like it is
				// already growing inward from both ends.
				BarStart: "",
				BarEnd:   "",
			}),
		)
	}
	options = append(options, progressbar.OptionSetDescription(desc))
	return progressbar.NewOptions(total, options...)
}

// paintFindings redraws the single finding row. The bar owns the cursor;
// once it has finished, the completion newline has already moved on and a
// late detail would land in the summary.
func paintFindings(bar *progressbar.ProgressBar, counts liveFindings, color bool) {
	if bar == nil || bar.IsFinished() {
		return
	}
	text := counts.line()
	if color {
		text = counts.lineColored()
	}
	_ = bar.AddDetail(text)
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
	// captureExtra counts reconnects used only because a session that
	// should have produced a screenshot timed out while reading pixels.
	// Those attempts get a longer RFB budget and run even when -retries is 0.
	captureExtra := 0
	for attempt := 1; ; attempt++ {
		attemptOpts := vncOpts
		if captureExtra > 0 {
			attemptOpts.Timeout = captureRetryTimeout(vncOpts.Timeout, captureExtra)
		}
		var err error
		vncRes, err = doProbe(ctx, addr, attemptOpts)
		if err == nil {
			res.Attempts = attempt
			break
		}

		if !errors.Is(err, vnc.ErrConnect) {
			// The TCP connect succeeded, so the port is open. A reset or a
			// dropped handshake is often a transient server hiccup, so one
			// retry is allowed here too; a protocol error (malformed banner,
			// unsupported encoding) is definitive and is not retried.
			//
			// When the server already authenticated (passwordless or a weak
			// password) but the framebuffer read timed out, reconnect with a
			// longer budget: the finding is known and the screenshot is the
			// missing piece. Manual viewers succeed in that situation.
			genericRetry := attempt <= maxRetries
			captureMiss := isCaptureMiss(vncRes)
			captureRetry := captureMiss && captureExtra < maxCaptureRetries
			if ctx.Err() == nil && isTransientHandshakeError(err) && (genericRetry || captureRetry) {
				if captureMiss {
					captureExtra++
				}
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
				// capability, server name, and any credential that already
				// authenticated before capture failed).
				res.RFB = true
				res.Note = vncRes.Note
				res.SecurityTypes = vncRes.SecurityTypeNames
				res.TLS = vncRes.TLS
				res.Passwordless = vncRes.Passwordless
				res.Password = vncRes.Password
				res.PasswordSource = vncRes.PasswordSource
				res.AuthLocked = vncRes.AuthLocked
				res.ServerName = vncRes.ServerName
				res.ProductHint = productHint(vncRes.RFBVersion, vncRes.ServerName)
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
	res.ProductHint = productHint(vncRes.RFBVersion, vncRes.ServerName)
	res.ScreenWidth = vncRes.Width
	res.ScreenHeight = vncRes.Height

	// A passwordless session always keeps this one frame. The same capture
	// runs after a weak password, including a blank VNC password (reported
	// as passwordless with PasswordSource set). The client closes the
	// session right after reading it. There is no option to skip the
	// passwordless screenshot.
	needShot := vncRes.Passwordless || vncRes.Password != "" || vncRes.PasswordSource != ""
	if !needShot || vncRes.Frame == nil {
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

const (
	// maxCaptureRetries is how many extra reconnects are spent specifically
	// on recovering a screenshot after a passwordless or authenticated
	// session timed out while reading pixels.
	maxCaptureRetries = 2
	// maxCaptureTimeout caps the stretched RFB budget used on those retries.
	maxCaptureTimeout = 60 * time.Second
)

// isCaptureMiss reports that the probe reached a session that should have
// produced a framebuffer, but the frame was never captured.
func isCaptureMiss(res *vnc.Result) bool {
	if res == nil || res.Frame != nil {
		return false
	}
	return res.Passwordless || res.Password != "" || res.PasswordSource != ""
}

// captureRetryTimeout stretches the RFB read budget for screenshot recovery
// attempts. retry is 1-based (the first capture retry uses 2× the base).
func captureRetryTimeout(base time.Duration, retry int) time.Duration {
	if base <= 0 {
		base = 15 * time.Second
	}
	if retry < 1 {
		return base
	}
	out := base
	for i := 0; i < retry; i++ {
		if out > maxCaptureTimeout/2 {
			return maxCaptureTimeout
		}
		out *= 2
	}
	if out > maxCaptureTimeout {
		return maxCaptureTimeout
	}
	return out
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
