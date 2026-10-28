package app

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Self-check status values reported in Check.Status.
const (
	StatusOK   = "ok"
	StatusWarn = "warn"
	StatusFail = "fail"
)

// minFreeReportBytes is the disk_space warn threshold: below this much free
// space on the report root's filesystem a full scan (PNG captures plus
// reports) may run out of room mid-run.
const minFreeReportBytes = 100 << 20 // 100 MiB

// clockMinTime and clockMaxTime bound the clock sanity check. Outside the
// window, certificate expiry math and retention timestamps would be nonsense.
var (
	clockMinTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	clockMaxTime = time.Date(2040, 12, 31, 23, 59, 59, 0, time.UTC)
)

// Check is one self-check result for -selfcheck output.
type Check struct {
	Name   string // stable machine-readable name, e.g. "root", "report_root"
	Status string // "ok", "warn", "fail"
	Detail string // one short line, English
}

// SelfCheckOptions configures SelfCheck.
type SelfCheckOptions struct {
	// ReportRoot is the directory reports are written to; it may not exist
	// yet. The caller should pass the resolved report base directory
	// (-out-dir or the build-time report base dir).
	ReportRoot string
}

// SelfCheck runs read-only environment checks. It never modifies anything
// except one documented writability probe: report_root creates a unique
// 0600 file named .selfcheck-<pid>-<rand> inside ReportRoot and removes it
// again immediately. It never contacts remote hosts; the only network
// activity is binding and closing a loopback listener (check "loopback").
//
// The returned slice is always the same seven checks in a fixed order, so
// callers can print or parse it deterministically.
func SelfCheck(opts SelfCheckOptions) []Check {
	return []Check{
		checkRoot(),
		checkReportRoot(opts.ReportRoot),
		checkTLSRoots(),
		checkBrowser(),
		checkClock(),
		checkLoopback(),
		checkDiskSpace(opts.ReportRoot),
	}
}

// checkRoot verifies privileged execution. Scanning privileged ports and
// raw RFB probing expect root, mirroring the CLI's root requirement.
func checkRoot() Check {
	if euid := os.Geteuid(); euid != 0 {
		return Check{Name: "root", Status: StatusFail,
			Detail: fmt.Sprintf("not running as root (euid %d); re-run with sudo", euid)}
	}
	return Check{Name: "root", Status: StatusOK, Detail: "running as root (euid 0)"}
}

// checkReportRoot verifies that the report root can be created and written
// by creating and immediately removing a unique 0600 probe file. An empty
// ReportRoot is a caller configuration gap, reported as a warning.
func checkReportRoot(root string) Check {
	const name = "report_root"
	if root == "" {
		return Check{Name: name, Status: StatusWarn,
			Detail: "no report root provided; skipping writability probe"}
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		return Check{Name: name, Status: StatusFail,
			Detail: fmt.Sprintf("cannot create report root %s: %v", root, err)}
	}

	// pid plus crypto randomness keeps concurrent self-checks from
	// colliding on the same probe name.
	nonce := make([]byte, 6)
	if _, err := rand.Read(nonce); err != nil {
		return Check{Name: name, Status: StatusFail,
			Detail: fmt.Sprintf("generate probe name: %v", err)}
	}
	probe := filepath.Join(root, fmt.Sprintf(".selfcheck-%d-%s", os.Getpid(), hex.EncodeToString(nonce)))

	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return Check{Name: name, Status: StatusFail, Detail: probeFailDetail(root, "create probe file", err)}
	}
	if _, err := f.WriteString("vncshot selfcheck probe\n"); err != nil {
		f.Close()
		os.Remove(probe) // best effort; the write failure is the real finding
		return Check{Name: name, Status: StatusFail, Detail: probeFailDetail(root, "write probe file", err)}
	}
	if err := f.Close(); err != nil {
		os.Remove(probe) // best effort; the close failure is the real finding
		return Check{Name: name, Status: StatusFail, Detail: probeFailDetail(root, "close probe file", err)}
	}
	if err := os.Remove(probe); err != nil {
		return Check{Name: name, Status: StatusFail, Detail: probeFailDetail(root, "remove probe file", err)}
	}
	return Check{Name: name, Status: StatusOK,
		Detail: fmt.Sprintf("writable (probe file created and removed in %s)", root)}
}

// probeFailDetail formats a probe failure, pointing out vanishing paths
// separately from other filesystem errors.
func probeFailDetail(root, step string, err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Sprintf("%s disappeared during writability probe (%s)", root, step)
	}
	return fmt.Sprintf("%s: %v", step, err)
}

// checkTLSRoots verifies that the system certificate pool is loadable and
// non-empty. Self-signed-only environments can still scan, so problems
// degrade to a warning rather than a failure.
func checkTLSRoots() Check {
	const name = "tls_roots"
	pool, err := x509.SystemCertPool()
	if err != nil {
		return Check{Name: name, Status: StatusWarn,
			Detail: fmt.Sprintf("cannot load system certificate pool: %v", err)}
	}
	subjects := pool.Subjects()
	if len(subjects) == 0 {
		return Check{Name: name, Status: StatusWarn,
			Detail: "system certificate pool is empty; TLS chain verification will degrade"}
	}
	return Check{Name: name, Status: StatusOK,
		Detail: fmt.Sprintf("system certificate pool loaded (%d root(s))", len(subjects))}
}

// checkBrowser verifies that xdg-open is available. The GUI uses it to open
// the browser automatically; a missing helper only disables that.
func checkBrowser() Check {
	const name = "browser"
	path, err := exec.LookPath("xdg-open")
	if err != nil {
		return Check{Name: name, Status: StatusWarn,
			Detail: "xdg-open not found in PATH; GUI auto-open will not work"}
	}
	return Check{Name: name, Status: StatusOK, Detail: "xdg-open found: " + path}
}

// checkClock verifies the system clock is inside a plausible window. A far
// off clock breaks certificate expiry math and retention timestamps.
func checkClock() Check {
	const name = "clock"
	now := time.Now().UTC()
	switch {
	case now.Before(clockMinTime):
		return Check{Name: name, Status: StatusWarn,
			Detail: fmt.Sprintf("system clock is before %s (%s); expiry math and timestamps would be nonsense",
				clockMinTime.Format(time.DateOnly), now.Format(time.RFC3339))}
	case now.After(clockMaxTime):
		return Check{Name: name, Status: StatusWarn,
			Detail: fmt.Sprintf("system clock is after %s (%s); expiry math and timestamps would be nonsense",
				clockMaxTime.Format(time.DateOnly), now.Format(time.RFC3339))}
	}
	return Check{Name: name, Status: StatusOK, Detail: "system clock plausible: " + now.Format(time.RFC3339)}
}

// checkLoopback verifies that local sockets work at all by binding a TCP
// listener on 127.0.0.1:0 and immediately closing it. No bytes are sent.
func checkLoopback() Check {
	const name = "loopback"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Check{Name: name, Status: StatusFail,
			Detail: fmt.Sprintf("cannot bind loopback TCP listener: %v", err)}
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		return Check{Name: name, Status: StatusWarn,
			Detail: fmt.Sprintf("loopback listener %s bound but close failed: %v", addr, err)}
	}
	return Check{Name: name, Status: StatusOK, Detail: "loopback TCP listener works (" + addr + ")"}
}

// checkDiskSpace reports the free space of the filesystem holding the
// report root. Below minFreeReportBytes (100 MiB) it warns; a Statfs error
// on an existing directory fails, while a missing directory only warns
// because the writability probe already covers that case.
func checkDiskSpace(root string) Check {
	const name = "disk_space"
	if root == "" {
		return Check{Name: name, Status: StatusWarn,
			Detail: "no report root provided; skipping disk space check"}
	}

	var st syscall.Statfs_t
	if err := syscall.Statfs(root, &st); err != nil {
		if _, dirErr := os.Stat(root); dirErr == nil {
			return Check{Name: name, Status: StatusFail,
				Detail: fmt.Sprintf("statfs failed on existing directory %s: %v", root, err)}
		}
		return Check{Name: name, Status: StatusWarn,
			Detail: fmt.Sprintf("statfs failed on %s (directory missing?): %v", root, err)}
	}

	// Bavail (blocks available to unprivileged users) is the conservative
	// choice: root can also use the Bfree reserve, but the tool should not
	// have to.
	free := st.Bavail * uint64(st.Bsize)
	if free < minFreeReportBytes {
		return Check{Name: name, Status: StatusWarn,
			Detail: fmt.Sprintf("only %d bytes free on %s filesystem (warn threshold %d bytes)",
				free, root, int64(minFreeReportBytes))}
	}
	return Check{Name: name, Status: StatusOK,
		Detail: fmt.Sprintf("%d bytes free on %s filesystem", free, root)}
}
