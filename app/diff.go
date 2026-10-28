package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vncshot/report"
)

// BaselineFilename is the report read from a baseline run directory.
const BaselineFilename = "vncshot_report.json"

// LoadBaseline reads the JSON report of a previous run directory so a later
// scan can be compared against it.
func LoadBaseline(dir string) ([]report.Result, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("read baseline directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("read baseline directory %s: not a directory", dir)
	}

	path := filepath.Join(dir, BaselineFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline report %s: %w", path, err)
	}
	var doc report.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse baseline report %s: %w", path, err)
	}
	return doc.Results, nil
}

// Compare classifies current findings against a baseline. Findings are keyed
// by IP:Port, so a host moving from one risk state to another is reported as
// a single change rather than as a new and a resolved finding.
func Compare(baselineRun string, baseline, current []report.Result) *Diff {
	diff := &Diff{Baseline: baselineRun}

	before := make(map[string]report.Result, len(baseline))
	for _, r := range baseline {
		before[r.Addr()] = r
	}

	seen := make(map[string]struct{}, len(current))
	for _, now := range current {
		key := now.Addr()
		seen[key] = struct{}{}

		previous, ok := before[key]
		if !ok {
			// An accepted finding is operator-approved: it stays in the
			// result set and summary, but it must not alarm, so it is not
			// reported as new.
			if now.Accepted {
				continue
			}
			diff.New = append(diff.New, now)
			continue
		}
		if reason := changeReason(previous, now); reason != "" {
			diff.Changed = append(diff.Changed, Change{
				Before: previous,
				After:  now,
				Reason: reason,
			})
		}
	}

	for _, previous := range baseline {
		if _, ok := seen[previous.Addr()]; !ok {
			diff.Resolved = append(diff.Resolved, previous)
		}
	}

	report.SortResults(diff.New)
	report.SortResults(diff.Resolved)
	sortChanges(diff.Changed)
	return diff
}

// changeReason returns a stable English description of the risk transition
// between two findings, or "" when the risk state is unchanged. Only the
// dominant transition is reported so one host yields one change entry.
func changeReason(before, after report.Result) string {
	switch {
	case before.RFB && !after.RFB:
		return "no longer RFB"
	case !before.Passwordless && after.Passwordless:
		return "became passwordless"
	case before.Password == "" && after.Password != "":
		return "weak password discovered"
	case before.Password != "" && after.Password == "":
		// This includes a host that stopped accepting its weak password.
		return "password no longer accepted"
	case before.Passwordless && !after.Passwordless:
		return "password no longer accepted"
	case !before.TLS && after.TLS:
		return "became TLS"
	case before.TLS && !after.TLS:
		return "lost TLS"
	default:
		return ""
	}
}

// sortChanges orders changes by the baseline finding they describe, reusing
// the report ordering (numeric IP, then port) without duplicating it.
func sortChanges(changes []Change) {
	if len(changes) < 2 {
		return
	}
	keys := make([]report.Result, len(changes))
	byKey := make(map[string]Change, len(changes))
	for i, c := range changes {
		keys[i] = c.Before
		byKey[c.Before.Addr()] = c
	}
	report.SortResults(keys)
	for i, r := range keys {
		changes[i] = byKey[r.Addr()]
	}
}

// reportDiff maps the scan-level comparison onto the report package's
// rendering type. Only the baseline base name is kept so reports never carry
// absolute host paths.
func (d *Diff) reportDiff() *report.Diff {
	if d == nil {
		return nil
	}
	out := &report.Diff{
		Baseline: filepath.Base(d.Baseline),
		New:      d.New,
		Resolved: d.Resolved,
	}
	for _, change := range d.Changed {
		out.Changed = append(out.Changed, report.Change{
			Before: change.Before,
			After:  change.After,
			Reason: change.Reason,
		})
	}
	return out
}
