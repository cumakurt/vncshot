// This file holds the interval scheduling helpers: finding the previous
// completed run for the diff baseline and computing the delay before the
// next scheduled round.
package app

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// previousRunReportJSON is the artifact whose presence marks a run directory
// as completed. It matches the JSON report name Session writes.
const previousRunReportJSON = "vncshot_report.json"

// PreviousRun returns the newest run directory under root that contains a
// vncshot_report.json. It reuses ListRuns (newest first, timestamped names
// only, no symlinks) and skips directories whose report is missing, so a
// half-written folder left by an interrupted scan never becomes the diff
// baseline. ok is false when no completed run exists. An unreadable root is
// reported as an error; a run entry that cannot even be stat-ed is skipped
// rather than aborting the search.
//
// Intended for -interval: each round compares against the previous round,
// without the operator naming a baseline explicitly.
func PreviousRun(root string) (dir string, ok bool, err error) {
	runs, err := ListRuns(root)
	if err != nil {
		return "", false, err
	}
	for _, run := range runs {
		candidate := filepath.Join(root, run.Name)
		report := filepath.Join(candidate, previousRunReportJSON)
		_, statErr := os.Stat(report)
		switch {
		case statErr == nil:
			return candidate, true, nil
		case errors.Is(statErr, fs.ErrNotExist):
			continue
		default:
			return "", false, statErr
		}
	}
	return "", false, nil
}

// ScheduleDelay returns how long to sleep before starting the next scan
// round. The interval counts from the START of the previous round (lastRound),
// not from its end, so a fixed 24h interval stays 24h apart on the wall clock
// even when a round takes 20 minutes.
//
// If the previous round already overran the interval (now is at or past
// lastRound+interval), the delay is 0: the next round starts immediately.
// There is deliberately no burst catch-up for the missed interval — one
// late round is followed by one immediate round, never by a rapid-fire
// sequence of back-to-back scans.
//
// An interval of zero or less schedules nothing and always returns 0.
func ScheduleDelay(interval time.Duration, lastRound time.Time, now time.Time) time.Duration {
	if interval <= 0 {
		return 0
	}
	next := lastRound.Add(interval)
	delay := next.Sub(now)
	if delay <= 0 {
		return 0
	}
	return delay
}
