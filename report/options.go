package report

// Options controls optional behaviour shared by every exporter.
//
// The zero value reproduces the historical output exactly, so existing
// callers keep working unchanged.
type Options struct {
	// Diff, when non-nil, is rendered into the human-readable reports and
	// serialised into the JSON document.
	Diff *Diff
	// Redact replaces captured credentials with a fixed marker. It is meant
	// for reports handed to a third party: the finding, its source and its
	// severity stay visible, the secret value does not.
	Redact bool
	// ThumbnailOnly embeds only the scaled preview in the HTML report instead
	// of the preview plus the full-resolution capture. It keeps the report
	// small for large inventories; the PNG files stay in the run folder.
	ThumbnailOnly bool
}

// RedactedValue is the placeholder written in place of a captured password.
const RedactedValue = "REDACTED"

// apply returns the result set with secrets removed when redaction is on.
// Counters are computed from the original results by the callers, so a
// redacted report still shows how many hosts were reachable.
func (o Options) apply(results []Result) []Result {
	if !o.Redact {
		return results
	}
	out := make([]Result, len(results))
	copy(out, results)
	for i := range out {
		if out[i].Password != "" {
			out[i].Password = RedactedValue
		}
	}
	return out
}

// redactDiff applies the same treatment to a baseline comparison.
func (o Options) redactDiff(diff *Diff) *Diff {
	if diff == nil || !o.Redact {
		return diff
	}
	out := &Diff{
		Baseline: diff.Baseline,
		New:      o.apply(diff.New),
		Resolved: o.apply(diff.Resolved),
		Changed:  make([]Change, len(diff.Changed)),
	}
	for i, change := range diff.Changed {
		out.Changed[i] = Change{
			Before: o.applyOne(change.Before),
			After:  o.applyOne(change.After),
			Reason: change.Reason,
		}
	}
	return out
}

func (o Options) applyOne(r Result) Result {
	if o.Redact && r.Password != "" {
		r.Password = RedactedValue
	}
	return r
}
