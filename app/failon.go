package app

import (
	"fmt"
	"strings"
	"time"

	"vncshot/report"
)

// Fail-on categories, in the order the flag help documents them. The first
// three are baseline-diff categories, the rest are per-scan findings.
const (
	FailOnNew          = "new"
	FailOnResolved     = "resolved"
	FailOnChanged      = "changed"
	FailOnPasswordless = "passwordless"
	FailOnWeak         = "weak"
	FailOnSelfSigned   = "self-signed"
	FailOnCertExpiring = "cert-expiring"
)

// failOnCategories is the accepted vocabulary for -fail-on.
var failOnCategories = []string{
	FailOnNew,
	FailOnResolved,
	FailOnChanged,
	FailOnPasswordless,
	FailOnWeak,
	FailOnSelfSigned,
	FailOnCertExpiring,
}

// failOnBaselineOnly reports whether a category is only meaningful together
// with a baseline comparison.
func failOnBaselineOnly(category string) bool {
	return category == FailOnNew || category == FailOnResolved || category == FailOnChanged
}

// IsBaselineFailOnCategory reports whether a -fail-on category compares two
// runs and therefore requires a baseline (explicit or the automatic
// per-round baseline of -interval).
func IsBaselineFailOnCategory(category string) bool {
	return failOnBaselineOnly(category)
}

// ParseFailOnCategories splits the comma-separated -fail-on value into
// unique, lower-case category names. Case is normalised, blank entries from
// sloppy input like "weak, passwordless," are skipped, and an empty value
// yields an empty list, which disables the exit-code check.
func ParseFailOnCategories(value string) ([]string, error) {
	parsed := make(map[string]bool)
	var categories []string
	for _, raw := range strings.Split(value, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		known := false
		for _, accepted := range failOnCategories {
			if name == accepted {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("fail-on: unknown category %q (accepted: %s)", name, strings.Join(failOnCategories, ", "))
		}
		if parsed[name] {
			continue
		}
		parsed[name] = true
		categories = append(categories, name)
	}
	return categories, nil
}

// FailOnMatch is one -fail-on category that actually matched: the scan has
// at least Count findings of that kind.
type FailOnMatch struct {
	Category string
	Count    int
}

// Detail renders the human-readable count shown in the CLI exit summary.
func (m FailOnMatch) Detail() string {
	switch m.Category {
	case FailOnPasswordless:
		return fmt.Sprintf("%d passwordless host(s)", m.Count)
	case FailOnWeak:
		return fmt.Sprintf("%d weak credential(s)", m.Count)
	case FailOnSelfSigned:
		return fmt.Sprintf("%d self-signed certificate(s)", m.Count)
	case FailOnCertExpiring:
		return fmt.Sprintf("%d certificate(s) expiring soon", m.Count)
	case FailOnNew:
		return fmt.Sprintf("%d new finding(s)", m.Count)
	case FailOnResolved:
		return fmt.Sprintf("%d resolved finding(s)", m.Count)
	case FailOnChanged:
		return fmt.Sprintf("%d changed finding(s)", m.Count)
	default:
		return fmt.Sprintf("%d finding(s)", m.Count)
	}
}

// EvaluateFailOn returns the requested categories that produced findings,
// in the order they were requested. diff may be nil when no baseline
// comparison ran; the baseline categories then simply never match. A
// non-positive certWarn disables the cert-expiring category, mirroring the
// -cert-warn window semantics.
func EvaluateFailOn(results []report.Result, diff *Diff, categories []string, now time.Time, certWarn time.Duration) []FailOnMatch {
	if len(categories) == 0 {
		return nil
	}
	counts := failOnCounts(results, diff, now, certWarn)

	matches := make([]FailOnMatch, 0, len(categories))
	for _, category := range categories {
		if count := counts[category]; count > 0 {
			matches = append(matches, FailOnMatch{Category: category, Count: count})
		}
	}
	return matches
}

// failOnCounts counts the findings of every category in one pass over the
// result set. The weak predicate matches the Summarize counter, so the exit
// decision can never disagree with the printed summary.
func failOnCounts(results []report.Result, diff *Diff, now time.Time, certWarn time.Duration) map[string]int {
	counts := make(map[string]int, len(failOnCategories))
	for _, r := range results {
		if r.Passwordless {
			counts[FailOnPasswordless]++
		}
		if r.Password != "" {
			counts[FailOnWeak]++
		}
		if r.Certificate != nil && r.Certificate.SelfSigned {
			counts[FailOnSelfSigned]++
		}
	}
	// Reuse the report-package expiry rule so the exit decision and the
	// expires-soon badges in the reports always agree.
	counts[FailOnCertExpiring] = report.CountExpiringSoon(results, now, certWarn)
	if diff != nil {
		counts[FailOnNew] = len(diff.New)
		counts[FailOnResolved] = len(diff.Resolved)
		counts[FailOnChanged] = len(diff.Changed)
	}
	return counts
}
