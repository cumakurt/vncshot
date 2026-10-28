package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vncshot/report"
)

// writeListFile creates a temporary list file (acceptance or exclusion) with
// the given content, for tests that exercise the file loaders.
func writeListFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	return path
}

func TestLoadAcceptancesParsesEntries(t *testing.T) {
	path := writeListFile(t, "accept.txt", `# known-approved endpoints
# (blank lines below)

192.0.2.10:5900 legacy appliance, ticket OPS-7 until:2026-12-31
192.0.2.2:* all ports on the jump host
192.0.2.30 bare host form
[2001:db8::15]:5900 core router
`)

	set, err := LoadAcceptances(path)
	if err != nil {
		t.Fatalf("LoadAcceptances: %v", err)
	}
	if set.Count() != 4 || set.Empty() {
		t.Fatalf("count = %d, empty = %v; want 4 entries", set.Count(), set.Empty())
	}

	wantReasons := map[string]string{
		"192.0.2.10:5900":     "legacy appliance, ticket OPS-7",
		"192.0.2.2:*":         "all ports on the jump host",
		"192.0.2.30":          "bare host form",
		"[2001:db8::15]:5900": "core router",
	}
	for _, entry := range set.entries {
		if entry.Reason != wantReasons[entry.Endpoint] {
			t.Errorf("entry %q reason = %q, want %q", entry.Endpoint, entry.Reason, wantReasons[entry.Endpoint])
		}
	}
}

func TestLoadAcceptancesUntilDate(t *testing.T) {
	path := writeListFile(t, "accept.txt", "192.0.2.1:5900 approved until:2026-12-31\n")
	set, err := LoadAcceptances(path)
	if err != nil {
		t.Fatalf("LoadAcceptances: %v", err)
	}
	want := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	if !set.entries[0].Until.Equal(want) {
		t.Errorf("until = %v, want %v", set.entries[0].Until, want)
	}
	if got := set.entries[0].Reason; got != "approved" {
		t.Errorf("reason = %q, want %q (the until token must be removed)", got, "approved")
	}
}

func TestLoadAcceptancesSortsDeterministically(t *testing.T) {
	// Lines are intentionally unsorted; the loaded set must not depend on
	// file order.
	path := writeListFile(t, "accept.txt", `10.0.0.9:5901 second
10.0.0.9:5900 first
10.0.0.10:5900 third
10.0.0.9:* every port sorts before exact ports
`)
	set, err := LoadAcceptances(path)
	if err != nil {
		t.Fatalf("LoadAcceptances: %v", err)
	}
	var got []string
	for _, entry := range set.entries {
		got = append(got, entry.Endpoint)
	}
	want := []string{"10.0.0.9:*", "10.0.0.9:5900", "10.0.0.9:5901", "10.0.0.10:5900"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestLoadAcceptancesIgnoresCommentsAndBlanks(t *testing.T) {
	path := writeListFile(t, "accept.txt", "# only comments\n\n   \n# and blanks\n")
	set, err := LoadAcceptances(path)
	if err != nil {
		t.Fatalf("LoadAcceptances: %v", err)
	}
	if !set.Empty() || set.Count() != 0 {
		t.Errorf("set = %d entries, want an empty set", set.Count())
	}
	if set.Apply(nil, time.Now()) != 0 {
		t.Error("empty set must not mark anything")
	}
}

func TestLoadAcceptancesMalformedLines(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantLine string
		wantIn   string
	}{
		{
			name:     "not an ip",
			content:  "# header\n10.0.0.1:5900 fine\nnot-a-host:5900 broken\n",
			wantLine: "accept.txt:3:",
			wantIn:   "not-a-host:5900",
		},
		{
			name:     "port out of range",
			content:  "10.0.0.1:70000 broken\n",
			wantLine: "accept.txt:1:",
			wantIn:   "70000",
		},
		{
			name:     "bad until date",
			content:  "10.0.0.1:5900 until:next-tuesday\n",
			wantLine: "accept.txt:1:",
			wantIn:   "until:next-tuesday",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeListFile(t, "accept.txt", tt.content)
			_, err := LoadAcceptances(path)
			if err == nil {
				t.Fatal("LoadAcceptances accepted a malformed line")
			}
			// The line number must be part of the error so the operator can
			// find the offending entry.
			if !strings.Contains(err.Error(), tt.wantLine) {
				t.Errorf("error %q does not name file and line %q", err, tt.wantLine)
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("error %q does not mention %q", err, tt.wantIn)
			}
		})
	}
}

func TestLoadAcceptancesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.txt")
	if _, err := LoadAcceptances(path); err == nil {
		t.Fatal("LoadAcceptances accepted a missing file")
	}
}

// acceptanceFixture covers every matching form plus one expired and one
// last-day entry.
func acceptanceFixture(t *testing.T) (AcceptanceSet, time.Time) {
	t.Helper()
	path := writeListFile(t, "accept.txt", `10.0.0.1:5900 exact
10.0.0.2:* wildcard
10.0.0.3 bare host
10.0.0.4:5900 expired last month until:2026-05-31
10.0.0.4:5901 valid through its own day until:2026-06-01
`)
	set, err := LoadAcceptances(path)
	if err != nil {
		t.Fatalf("LoadAcceptances: %v", err)
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	return set, now
}

func TestAcceptanceApplyMatches(t *testing.T) {
	set, now := acceptanceFixture(t)

	results := []report.Result{
		{IP: "10.0.0.1", Port: 5900}, // exact match
		{IP: "10.0.0.1", Port: 5901}, // different port, no match
		{IP: "10.0.0.2", Port: 5900}, // wildcard
		{IP: "10.0.0.2", Port: 22},   // wildcard on any port
		{IP: "10.0.0.3", Port: 5900}, // bare host
		{IP: "10.0.0.4", Port: 5900}, // expired until, must stay unaccepted
		{IP: "10.0.0.4", Port: 5901}, // until day itself is still covered
		{IP: "10.0.0.5", Port: 5900}, // not listed
	}

	got := set.Apply(results, now)
	if got != 5 {
		t.Fatalf("apply marked %d results, want 5", got)
	}

	for i, want := range []bool{true, false, true, true, true, false, true, false} {
		if results[i].Accepted != want {
			t.Errorf("result %s accepted = %v, want %v", results[i].Addr(), results[i].Accepted, want)
		}
	}
}

// An expired acceptance must not error: the approval simply lapses and the
// finding alarms again.
func TestAcceptanceApplyExpiredEntryIsNotAnError(t *testing.T) {
	path := writeListFile(t, "accept.txt", "10.0.0.1:5900 expired until:2026-01-01\n")
	set, err := LoadAcceptances(path)
	if err != nil {
		t.Fatalf("LoadAcceptances: %v", err)
	}
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	results := []report.Result{{IP: "10.0.0.1", Port: 5900}}
	if got := set.Apply(results, now); got != 0 {
		t.Errorf("apply marked %d results, want 0", got)
	}
	if results[0].Accepted {
		t.Error("expired acceptance must not mark the result")
	}
}

func TestAcceptanceApplyMatchesCanonicalIPv6(t *testing.T) {
	path := writeListFile(t, "accept.txt", "[2001:DB8::15]:5900 uppercase hex\n")
	set, err := LoadAcceptances(path)
	if err != nil {
		t.Fatalf("LoadAcceptances: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	results := []report.Result{{IP: "2001:db8::15", Port: 5900}}
	if got := set.Apply(results, now); got != 1 {
		t.Errorf("apply marked %d results, want 1", got)
	}
}
