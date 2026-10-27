package scanner

import (
	"context"
	"errors"
	"fmt"
	"image"
	"net"
	"os"
	"path/filepath"
	"sync"
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
	// ScreenshotDir is where passwordless captures are written.
	ScreenshotDir string
	// Shared requests a shared RFB session (does not kick active viewers).
	Shared bool
	// Passwords are weak-password candidates. Empty disables password
	// testing and keeps the scan to the passwordless check.
	Passwords []vnc.Credential
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
		opts.Workers = 150
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = time.Second
	}
	if opts.VNCTimeout <= 0 {
		opts.VNCTimeout = 15 * time.Second
	}

	limiter := NewRateLimiter(opts.RatePerSec)
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
				results <- probe(ctx, t, opts)
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

// probe performs the TCP connect and, when the port is open, the RFB
// handshake plus an optional screenshot.
func probe(ctx context.Context, t Target, opts Options) (res report.Result) {
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

	addr := t.Addr()
	dialer := net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil {
			res.Error = ctx.Err().Error()
		} else {
			// Closed/filtered ports are normal scan noise, not errors worth
			// surfacing in the report.
			res.Error = ""
		}
		return res
	}
	res.Open = true
	conn.Close()

	vncRes, err := vnc.Probe(ctx, addr, vnc.Options{
		Timeout:   opts.VNCTimeout,
		Shared:    opts.Shared,
		Passwords: opts.Passwords,
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}

	res.RFB = true
	res.Passwordless = vncRes.Passwordless
	res.Password = vncRes.Password
	res.PasswordSource = vncRes.PasswordSource
	res.AuthLocked = vncRes.AuthLocked
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
