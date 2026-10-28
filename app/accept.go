package app

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"vncshot/report"
)

// untilPrefix introduces the optional expiry token in an acceptance entry.
const untilPrefix = "until:"

// untilLayout is the date layout of the until: token.
const untilLayout = "2006-01-02"

// Acceptance is one operator-approved finding: the result on Endpoint is
// known and approved for the stated Reason, valid through Until (zero means
// no expiry).
type Acceptance struct {
	Endpoint string
	Reason   string
	Until    time.Time
}

// AcceptanceSet is a parsed acceptance list. Entries are sorted
// deterministically so repeated loads of the same file always yield the
// same set.
type AcceptanceSet struct {
	entries []acceptanceEntry
}

// acceptanceEntry pairs the operator-facing acceptance with the parsed
// matching key. port is 0 for "ip" and "ip:*" entries, meaning every port on
// the host.
type acceptanceEntry struct {
	Acceptance
	host string
	port int
}

// LoadAcceptances reads an acceptance list from path. Every non-comment
// line must parse; a malformed line is a hard error including the line
// number, because a silently ignored acceptance would keep alarming the
// operator about a finding they believe is approved.
//
// File format (one entry per line, '#' starts a comment):
//
//	# full-line comment
//	192.0.2.1:5900 legacy appliance, ticket OPS-7 until:2026-12-31
//	192.0.2.2:*    every port on this host
//	192.0.2.3      every port (bare host form)
//	[2001:db8::1]:5900
//
// The first whitespace-separated field is the endpoint ("ip:port", "ip:*"
// or bare "ip"); the remaining fields form a free-form reason. A token of
// the form until:YYYY-MM-DD anywhere in the trailing text records the expiry
// and is removed from the reason. The recorded day itself is still covered;
// the acceptance expires on the following UTC day. Because '#' starts a
// comment, a reason cannot contain that character.
//
// Address forms: bare "ip" and "ip:*" accept IPv6 written without brackets;
// an "ip:port" endpoint needs brackets for IPv6 ("[2001:db8::1]:5900"),
// because without them the port digits are part of the address itself.
func LoadAcceptances(path string) (AcceptanceSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return AcceptanceSet{}, fmt.Errorf("open acceptance list %s: %w", path, err)
	}
	defer f.Close()

	var entries []acceptanceEntry
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		entry, ok, err := parseAcceptanceLine(sc.Text())
		if err != nil {
			return AcceptanceSet{}, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if ok {
			entries = append(entries, entry)
		}
	}
	if err := sc.Err(); err != nil {
		return AcceptanceSet{}, fmt.Errorf("read acceptance list %s: %w", path, err)
	}
	sortAcceptances(entries)
	return AcceptanceSet{entries: entries}, nil
}

// parseAcceptanceLine parses one line, reporting ok=false for blank and
// comment-only lines.
func parseAcceptanceLine(line string) (acceptanceEntry, bool, error) {
	trimmed := stripListComment(line)
	if trimmed == "" {
		return acceptanceEntry{}, false, nil
	}

	fields := strings.Fields(trimmed)
	host, port, err := parseAcceptanceEndpoint(fields[0])
	if err != nil {
		return acceptanceEntry{}, false, err
	}
	entry := acceptanceEntry{
		Acceptance: Acceptance{Endpoint: fields[0]},
		host:       host,
		port:       port,
	}

	var reason []string
	for _, token := range fields[1:] {
		date, isUntil := strings.CutPrefix(token, untilPrefix)
		if !isUntil {
			reason = append(reason, token)
			continue
		}
		until, err := time.Parse(untilLayout, date)
		if err != nil {
			return acceptanceEntry{}, false, fmt.Errorf("invalid expiry %q (want until:YYYY-MM-DD)", token)
		}
		// Every until: token is validated, but the first one wins when a
		// line carries more than one.
		if entry.Until.IsZero() {
			entry.Until = until
		}
	}
	entry.Reason = strings.Join(reason, " ")
	return entry, true, nil
}

// parseAcceptanceEndpoint accepts "ip:port", "ip:*" and bare "ip" (bracketed
// IPv6 allowed) and returns the canonical host text plus port, where 0 means
// every port on that host.
func parseAcceptanceEndpoint(spec string) (string, int, error) {
	if hostText, ok := strings.CutSuffix(spec, ":*"); ok {
		host, err := parseIPText(hostText)
		if err != nil {
			return "", 0, fmt.Errorf("invalid endpoint %q: %w", spec, err)
		}
		return host, 0, nil
	}
	if ip := net.ParseIP(strings.Trim(spec, "[]")); ip != nil {
		return canonicalIP(ip), 0, nil
	}
	host, port, err := splitEndpointToken(spec)
	if err != nil {
		return "", 0, fmt.Errorf("invalid endpoint %q (want ip:port, ip:* or a bare IP)", spec)
	}
	return host, port, nil
}

// sortAcceptances orders entries by host, then port (all-ports entries
// first), then the raw endpoint text, so a file always loads to the same
// set.
func sortAcceptances(entries []acceptanceEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if cmp := compareHosts(entries[i].host, entries[j].host); cmp != 0 {
			return cmp < 0
		}
		if entries[i].port != entries[j].port {
			return entries[i].port < entries[j].port
		}
		return entries[i].Endpoint < entries[j].Endpoint
	})
}

// compareHosts orders two textual addresses numerically when both parse, so
// 10.0.0.9 sorts before 10.0.0.10, and falls back to lexical order for text
// that is not an address. This mirrors the report package's result
// ordering.
func compareHosts(a, b string) int {
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	switch {
	case ipA != nil && ipB != nil:
		return bytes.Compare(ipA.To16(), ipB.To16())
	case ipA != nil:
		return -1
	case ipB != nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}

// Count returns the number of acceptance entries.
func (a AcceptanceSet) Count() int {
	return len(a.entries)
}

// Empty reports whether the acceptance list has no entries.
func (a AcceptanceSet) Empty() bool {
	return len(a.entries) == 0
}

// Apply marks every result matching an acceptance entry as accepted and
// returns how many results were marked. Matching is by endpoint: an exact
// "ip:port" entry approves that endpoint, while "ip:*" and bare "ip"
// approve every port on the host.
//
// An entry whose Until day has passed is expired: it is skipped, and this is
// deliberately not an error, because an expired approval must simply let the
// finding alarm again. Accepted results stay in the full result set;
// acceptance only changes how findings are alarmed about.
func (a AcceptanceSet) Apply(results []report.Result, now time.Time) int {
	if len(a.entries) == 0 {
		return 0
	}
	marked := 0
	for i := range results {
		if a.matches(results[i], now) {
			results[i].Accepted = true
			marked++
		}
	}
	return marked
}

// matches reports whether one result is covered by a still-valid entry.
func (a AcceptanceSet) matches(r report.Result, now time.Time) bool {
	host := canonicalHost(r.IP)
	for _, entry := range a.entries {
		if entry.host != host {
			continue
		}
		if entry.port != 0 && entry.port != r.Port {
			continue
		}
		if acceptanceExpired(entry.Until, now) {
			continue
		}
		return true
	}
	return false
}

// acceptanceExpired reports whether the approval no longer covers now. The
// recorded day itself is still covered; the entry lapses on the following
// UTC day.
func acceptanceExpired(until, now time.Time) bool {
	if until.IsZero() {
		return false
	}
	today := now.UTC()
	today = time.Date(today.Year(), today.Month(), today.Day(), 0, 0, 0, 0, time.UTC)
	return today.After(until)
}

// HasUnacceptedAlarms reports whether any result still warrants waking an
// operator (passwordless access or a weak credential) after acceptance was
// applied. Accepted findings are known-approved and must not trigger the
// alarm. Intended for shouldNotifyWebhook in webhook.go.
func HasUnacceptedAlarms(results []report.Result) bool {
	for _, r := range results {
		if r.Accepted {
			continue
		}
		if r.Passwordless || r.Password != "" {
			return true
		}
	}
	return false
}
