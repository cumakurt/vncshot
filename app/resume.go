package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"vncshot/report"
	"vncshot/scanner"
)

// LoadCompleted reads the JSON report of an interrupted or finished run so a
// later scan can reuse the probes it already completed.
func LoadCompleted(dir string) ([]report.Result, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("read resume directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("read resume directory %s: not a directory", dir)
	}

	// Every run folder names its JSON report the same way, so the resume
	// source uses the constant documented for the baseline reader.
	path := filepath.Join(dir, BaselineFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read resume report %s: %w", path, err)
	}
	var doc report.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse resume report %s: %w", path, err)
	}
	return doc.Results, nil
}

// completedKeys indexes results by the endpoint address they describe.
func completedKeys(results []report.Result) map[string]struct{} {
	keys := make(map[string]struct{}, len(results))
	for _, r := range results {
		keys[r.Addr()] = struct{}{}
	}
	return keys
}

// ResumePlan splits a requested scope into the targets that still need a
// probe and the results that can be reused from a previous run. Results whose
// endpoint is no longer part of the requested scope are dropped: keeping them
// would make the resumed report claim findings for a scope it does not
// describe, and a later baseline comparison of that report would be
// meaningless.
func ResumePlan(previous []report.Result, targets []scanner.Target) (remaining []scanner.Target, reused []report.Result, err error) {
	inScope := make(map[string]struct{}, len(targets))
	for _, t := range targets {
		inScope[targetKey(t)] = struct{}{}
	}

	seen := make(map[string]struct{}, len(previous))
	reused = make([]report.Result, 0, len(previous))
	for _, r := range previous {
		key := r.Addr()
		if _, ok := inScope[key]; !ok {
			continue
		}
		// Any recorded probe error means the endpoint did not finish cleanly
		// (cancel, I/O timeout, dropped handshake). Reusing that row would
		// freeze a transient failure as the final answer on resume.
		if r.Error != "" {
			continue
		}
		// A passwordless or authenticated host without a screenshot did not
		// finish capture. Resume must probe it again even when Error was
		// cleared or never set.
		if incompleteCapture(r) {
			continue
		}
		// A duplicated address would produce two rows for one endpoint, so
		// only the first observation is reused.
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		reused = append(reused, r)
	}

	completed := completedKeys(reused)
	remaining = make([]scanner.Target, 0, len(targets))
	for _, t := range targets {
		if _, ok := completed[targetKey(t)]; ok {
			continue
		}
		remaining = append(remaining, t)
	}
	return remaining, reused, nil
}

// incompleteCapture reports that a previous result found an authenticated or
// passwordless session but never wrote a screenshot. Reusing that row would
// freeze a capture timeout or I/O failure as a permanent finding.
func incompleteCapture(r report.Result) bool {
	if r.Screenshot != "" {
		return false
	}
	return r.Passwordless || r.Password != "" || r.PasswordSource != ""
}

// targetKey renders a target in the same "ip:port" form as Result.Addr so a
// reused result can be matched against the requested scope.
func targetKey(t scanner.Target) string {
	return report.Result{IP: t.IP, Port: t.Port}.Addr()
}
