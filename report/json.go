package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Document is the on-disk JSON shape: metadata plus every probe result.
//
// Redaction contract: when Options.Redact is set, every result (top level,
// Diff.New and Diff.Resolved) carries RedactedValue in place of a captured
// password. The summary counters are computed from the unredacted results, so
// a redacted document still reports the same number of weak credentials.
type Document struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Tool        string        `json:"tool"`
	Summary     Summary       `json:"summary"`
	Results     []Result      `json:"results"`
	Diff        *diffDocument `json:"diff,omitempty"`
	// ResumedFrom names the run folder this scan continued, so a resumed
	// run stays traceable to the scan it was interrupted from.
	ResumedFrom string `json:"resumed_from,omitempty"`
}

// DocumentOptions carries the metadata a caller wants recorded alongside the
// results. It is separate from Options because it does not change rendering.
type DocumentOptions struct {
	ResumedFrom string
}

// diffDocument is the JSON-friendly view of a baseline comparison. New and
// resolved findings keep their full shape so a consumer can re-import them;
// changed entries are reduced to their address, reason and state labels,
// which keeps the comparison section small.
type diffDocument struct {
	Baseline string `json:"baseline,omitempty"`
	// The three lists are always present when a comparison ran, so a
	// pipeline can index them without nil checks.
	New      []Result             `json:"new"`
	Resolved []Result             `json:"resolved"`
	Changed  []diffChangeDocument `json:"changed"`
}

// diffChangeDocument is one risk-state transition. Before and After are the
// same display labels the human-readable reports use (for example "no auth",
// "weak", "closed"), not full Result objects.
type diffChangeDocument struct {
	Addr   string `json:"addr"`
	Reason string `json:"reason"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// WriteJSON saves the full result set to path.
func WriteJSON(path string, results []Result) error {
	return WriteJSONWithOptions(path, results, Options{})
}

// WriteJSONWithOptions saves the result set together with the optional
// baseline comparison, applying the redaction requested by opts.
func WriteJSONWithOptions(path string, results []Result, opts Options) error {
	return WriteJSONDocument(path, results, opts, DocumentOptions{})
}

// WriteJSONDocument writes the report with extra document metadata.
func WriteJSONDocument(path string, results []Result, opts Options, docOpts DocumentOptions) error {
	diff := normalizedDiff(opts.redactDiff(opts.Diff))

	doc := Document{
		GeneratedAt: time.Now().UTC(),
		Tool:        "vncshot",
		// Counters describe the findings that were actually observed, so
		// they are computed before redaction replaces the secret values.
		Summary:     Summarize(results),
		Results:     opts.apply(results),
		ResumedFrom: docOpts.ResumedFrom,
	}
	if diff != nil {
		doc.Diff = buildDiffDocument(diff)
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	data = append(data, '\n')

	// Reports may contain weak credentials and captured desktops, so they
	// are owner-readable only.
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	// WriteFile keeps the mode of an existing file, so an explicit -output
	// pointing at a world-readable path would leak the credentials. The
	// documented contract is owner-only, so enforce it.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict json report permissions: %w", err)
	}
	return nil
}

// buildDiffDocument converts a normalized comparison into its on-disk shape.
func buildDiffDocument(diff *Diff) *diffDocument {
	doc := &diffDocument{
		Baseline: diff.Baseline,
		// Copy so a nil slice still encodes as [] rather than null.
		New:      append([]Result{}, diff.New...),
		Resolved: append([]Result{}, diff.Resolved...),
		Changed:  []diffChangeDocument{},
	}
	for _, change := range diff.Changed {
		doc.Changed = append(doc.Changed, diffChangeDocument{
			Addr:   change.After.Addr(),
			Reason: change.Reason,
			Before: diffStateLabel(change.Before),
			After:  diffStateLabel(change.After),
		})
	}
	return doc
}
