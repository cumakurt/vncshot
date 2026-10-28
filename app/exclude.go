package app

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"vncshot/scanner"
)

// Exclusions lists addresses that must never be contacted. This is a safety
// boundary, not a reporting preference: matching targets are dropped before
// any connection is attempted, because a fragile or production-critical
// device must not receive even a probe. It differs from the acceptance
// list, which lets the scan touch an endpoint but treats the findings there
// as pre-approved.
type Exclusions struct {
	rules []exclusionRule
}

// exclusionRule is one parsed exclusion line.
type exclusionRule struct {
	kind exclusionKind
	// ip is the canonical address for exclusionIP and exclusionEndpoint.
	ip string
	// port is only meaningful for exclusionEndpoint.
	port int
	// network is only meaningful for exclusionCIDR.
	network *net.IPNet
}

type exclusionKind int

const (
	// exclusionIP matches every port on one address.
	exclusionIP exclusionKind = iota
	// exclusionCIDR matches every address inside a prefix.
	exclusionCIDR
	// exclusionEndpoint matches exactly one ip:port pair.
	exclusionEndpoint
)

// LoadExclusions reads an exclusion list from path. Every non-comment line
// must parse; a malformed line is a hard error including the line number,
// because a silently ignored exclusion would remove the operator's safety
// boundary without notice.
//
// File format (one rule per line, '#' starts a comment):
//
//	# full-line comment
//	192.0.2.1          single host, every port
//	192.0.2.0/24       whole prefix
//	192.0.2.1:5900     one endpoint
//	2001:db8::1        IPv6 host, every port
//	[2001:db8::2]:5900 IPv6 endpoint
func LoadExclusions(path string) (Exclusions, error) {
	f, err := os.Open(path)
	if err != nil {
		return Exclusions{}, fmt.Errorf("open exclusion list %s: %w", path, err)
	}
	defer f.Close()

	var rules []exclusionRule
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		rule, ok, err := parseExclusionLine(sc.Text())
		if err != nil {
			return Exclusions{}, fmt.Errorf("%s:%d: %w", path, lineNo, err)
		}
		if ok {
			rules = append(rules, rule)
		}
	}
	if err := sc.Err(); err != nil {
		return Exclusions{}, fmt.Errorf("read exclusion list %s: %w", path, err)
	}
	return Exclusions{rules: rules}, nil
}

// parseExclusionLine parses one line, reporting ok=false for blank and
// comment-only lines.
func parseExclusionLine(line string) (exclusionRule, bool, error) {
	trimmed := stripListComment(line)
	if trimmed == "" {
		return exclusionRule{}, false, nil
	}
	rule, err := parseExclusionRule(trimmed)
	if err != nil {
		return exclusionRule{}, false, err
	}
	return rule, true, nil
}

// stripListComment removes a '#' comment and surrounding whitespace. It
// returns "" for blank and comment-only lines.
func stripListComment(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if i := strings.IndexByte(trimmed, '#'); i >= 0 {
		trimmed = strings.TrimSpace(trimmed[:i])
	}
	return trimmed
}

// parseExclusionRule parses one rule: a CIDR, a bare IP, or an "ip:port"
// endpoint (bracketed IPv6 allowed). The bare-IP check runs before the
// endpoint split so "2001:db8::1" is a host rule rather than a broken
// endpoint.
func parseExclusionRule(spec string) (exclusionRule, error) {
	if strings.Contains(spec, "/") {
		_, network, err := net.ParseCIDR(spec)
		if err != nil {
			return exclusionRule{}, fmt.Errorf("invalid CIDR %q: %w", spec, err)
		}
		return exclusionRule{kind: exclusionCIDR, network: network}, nil
	}
	if ip := net.ParseIP(spec); ip != nil {
		return exclusionRule{kind: exclusionIP, ip: canonicalIP(ip)}, nil
	}
	host, port, err := splitEndpointToken(spec)
	if err != nil {
		return exclusionRule{}, fmt.Errorf("invalid exclusion %q (want an IP, CIDR or ip:port endpoint)", spec)
	}
	return exclusionRule{kind: exclusionEndpoint, ip: host, port: port}, nil
}

// Filter splits targets into the ones the scan may contact and the ones
// matching an exclusion rule. Matching targets are dropped before any
// connection is attempted; kept targets preserve their original order.
func (e Exclusions) Filter(targets []scanner.Target) (kept, dropped []scanner.Target) {
	for _, t := range targets {
		if e.excludes(t) {
			dropped = append(dropped, t)
			continue
		}
		kept = append(kept, t)
	}
	return kept, dropped
}

// excludes reports whether one target matches any rule. An ip:port rule
// matches only that endpoint; IP and CIDR rules match by address, on every
// port.
func (e Exclusions) excludes(t scanner.Target) bool {
	parsed := net.ParseIP(t.IP)
	host := canonicalHost(t.IP)
	for _, rule := range e.rules {
		switch rule.kind {
		case exclusionIP:
			if rule.ip == host {
				return true
			}
		case exclusionEndpoint:
			if rule.ip == host && rule.port == t.Port {
				return true
			}
		case exclusionCIDR:
			if parsed != nil && rule.network.Contains(parsed) {
				return true
			}
		}
	}
	return false
}

// --- Shared list-parsing helpers -------------------------------------------
//
// The acceptance and exclusion lists share the same textual conventions
// (line based, '#' comments, whitespace-separated fields) and the same
// address forms, so their parsing helpers live here and are reused by
// accept.go.

// canonicalIP renders ip in its canonical text form, collapsing IPv4-mapped
// addresses to dotted quad.
func canonicalIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// canonicalHost parses text as an IP address and returns its canonical form,
// or the input unchanged when it does not parse, so unexpected values still
// compare literally instead of silently never matching.
func canonicalHost(text string) string {
	ip := net.ParseIP(text)
	if ip == nil {
		return text
	}
	return canonicalIP(ip)
}

// parseIPText parses spec as a bare IP address (brackets around IPv6 are
// tolerated) and returns its canonical text form.
func parseIPText(spec string) (string, error) {
	ip := net.ParseIP(strings.Trim(spec, "[]"))
	if ip == nil {
		return "", fmt.Errorf("%q is not a valid IP address", spec)
	}
	return canonicalIP(ip), nil
}

// parseListPort parses one port number for the acceptance and exclusion
// lists.
func parseListPort(text string) (int, error) {
	port, err := strconv.Atoi(text)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("%q is not a valid port number (1-65535)", text)
	}
	return port, nil
}

// splitEndpointToken parses "ip:port" (bracketed IPv6 allowed) into the
// canonical host text and port number.
func splitEndpointToken(spec string) (string, int, error) {
	hostText, portText, err := net.SplitHostPort(spec)
	if err != nil {
		return "", 0, err
	}
	host, err := parseIPText(hostText)
	if err != nil {
		return "", 0, err
	}
	port, err := parseListPort(portText)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}
