package scanner

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

// Target is a single host:port pair handed to a scan worker.
type Target struct {
	IP   string
	Port int
}

func (t Target) Addr() string {
	return net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
}

// maxTargets guards against accidental expansions that would produce
// tens of millions of connection attempts. It bounds -target specs,
// ranges and host:port pairs when no target file is used.
const maxTargets = 1 << 20

// maxCIDRHostBits caps a single -target CIDR at 2^16 addresses (/16).
// Larger blocks must be split, or listed in -file, so a typo on the
// command line cannot allocate a gigabyte-scale host list.
const maxCIDRHostBits = 16

// maxFileCIDRHostBits caps one CIDR line from -file or stdin at 2^24
// addresses. That is an IPv4 /8, or an IPv6 prefix of /104.
const maxFileCIDRHostBits = 24

// maxFileHosts is the host and host:port budget for a -file or stdin
// list. It matches one full /8 so a file can name every prefix from
// /32 through /8 without being rejected by the narrower -target cap.
const maxFileHosts = 1 << maxFileCIDRHostBits

// stdinLabel is the user-facing name used for targets read from standard input.
const stdinLabel = "stdin"

// ParseTargets expands the CLI inputs into a concrete host:port list.
// target may be empty when a file is supplied; either input is enough.
// A file of "-" reads the target list from standard input.
func ParseTargets(target, file string, ports []int) ([]Target, error) {
	return parseTargets(target, file, ports, os.Stdin)
}

// parseTargets is the testable core of ParseTargets; stdin is the stream used
// when file is "-".
func parseTargets(target, file string, ports []int, stdin io.Reader) ([]Target, error) {
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports to scan")
	}

	var hosts []string
	if target != "" {
		expanded, err := expandSpec(target)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", target, err)
		}
		hosts = append(hosts, expanded...)
	}
	if file != "" {
		var (
			fromFile []string
			err      error
		)
		if file == "-" {
			fromFile, err = hostsFromReader(stdin, stdinLabel)
		} else {
			fromFile, err = hostsFromFile(file)
		}
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, fromFile...)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no targets: provide -target or -file")
	}

	hosts = dedupe(hosts)

	// A target file is an explicit inventory, so it may expand up to one
	// /8. A lone -target spec keeps the smaller cap: that path is where a
	// typo would otherwise schedule millions of probes.
	pairLimit := maxTargets
	if file != "" {
		pairLimit = maxFileHosts
	}
	total := len(hosts) * len(ports)
	if total > pairLimit {
		return nil, fmt.Errorf("refusing to scan %d host:port pairs (limit %d); narrow the range or port list", total, pairLimit)
	}

	targets := make([]Target, 0, total)
	for _, ip := range hosts {
		for _, p := range ports {
			targets = append(targets, Target{IP: ip, Port: p})
		}
	}
	return targets, nil
}

// ParsePorts accepts a comma separated list of ports and inclusive ranges,
// e.g. "5900", "5900,5901", "5900-5910", "5900,5901-5905,5999".
func ParsePorts(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty port specification")
	}

	seen := make(map[int]struct{})
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, ranged := strings.Cut(part, "-")
		lo = strings.TrimSpace(lo)
		hi = strings.TrimSpace(hi)
		start, err := parsePort(lo)
		if err != nil {
			return nil, fmt.Errorf("port %q: %w", part, err)
		}
		end := start
		if ranged {
			end, err = parsePort(hi)
			if err != nil {
				return nil, fmt.Errorf("port %q: %w", part, err)
			}
			if end < start {
				return nil, fmt.Errorf("port range %q is reversed", part)
			}
		}
		for p := start; p <= end; p++ {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports parsed from %q", spec)
	}
	return ports, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty port number")
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid port number %q", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range 1-65535", n)
	}
	return n, nil
}

func hostsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target file: %w", err)
	}
	defer f.Close()

	return hostsFromReader(f, path)
}

// hostsFromReader scans one target spec per line until EOF. label names the
// source in error messages ("stdin" or the file path). File lines may name
// an IPv4 prefix as short as /8; a -target spec stays at /16.
func hostsFromReader(r io.Reader, label string) ([]string, error) {
	return readHostLines(r, label, maxFileCIDRHostBits, maxFileHosts)
}

// readHostLines is the testable core of hostsFromReader. cidrHostBits is the
// per-CIDR width budget and hostBudget is the running total. A CIDR that
// would exceed either budget is rejected before its addresses are allocated.
func readHostLines(r io.Reader, label string, cidrHostBits, hostBudget int) ([]string, error) {
	var hosts []string
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow inline comments: "192.168.0.1  # gateway".
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		if err := cidrWidthError(line, cidrHostBits); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", label, lineNo, err)
		}
		// Reject an over-budget CIDR before expandCIDR allocates it. A /8
		// is 16,777,216 strings; the check has to happen first.
		if n, ok := prefixAddressCount(line); ok && len(hosts)+n > hostBudget {
			return nil, fmt.Errorf("refusing to read more than %d hosts from %s; narrow the input", hostBudget, label)
		}
		expanded, err := expandSpecBits(line, cidrHostBits)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", label, lineNo, err)
		}
		if len(hosts)+len(expanded) > hostBudget {
			return nil, fmt.Errorf("refusing to read more than %d hosts from %s; narrow the input", hostBudget, label)
		}
		hosts = append(hosts, expanded...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read targets from %s: %w", label, err)
	}
	return hosts, nil
}

// expandSpec turns one user-facing spec into a list of IP strings.
// Supported forms: single IP, CIDR, "a.b.c.d-e.f.g.h", "a.b.c.d-n" and
// IPv6 ranges ("2001:db8::1-2001:db8::a" or the shorthand
// "2001:db8::1-::a").
func expandSpec(spec string) ([]string, error) {
	return expandSpecBits(spec, maxCIDRHostBits)
}

// expandSpecBits is expandSpec with an explicit per-CIDR host-bit budget.
// -target uses maxCIDRHostBits (/16). File lines use maxFileCIDRHostBits (/8).
func expandSpecBits(spec string, cidrHostBits int) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty target")
	}

	if strings.Contains(spec, "/") {
		return expandCIDR(spec, cidrHostBits)
	}
	if strings.Contains(spec, "-") {
		return expandRange(spec)
	}
	ip := net.ParseIP(spec)
	if ip == nil {
		return nil, fmt.Errorf("not a valid IP address")
	}
	return []string{normalizeIP(ip)}, nil
}

// cidrWidthError reports a CIDR wider than maxHostBits. A non-CIDR spec and
// an unparseable CIDR return nil so the caller can surface the ordinary
// expand error instead of a width error.
func cidrWidthError(spec string, maxHostBits int) error {
	if !strings.Contains(spec, "/") {
		return nil
	}
	_, ipNet, err := net.ParseCIDR(spec)
	if err != nil {
		return nil
	}
	ones, bits := ipNet.Mask.Size()
	if bits-ones > maxHostBits {
		return cidrTooLarge(spec, bits, maxHostBits)
	}
	return nil
}

// prefixAddressCount returns the address count of a CIDR whose host portion
// fits in an int. ok is false for non-CIDRs, invalid specs and prefixes so
// wide that 1<<hostBits would overflow; those are rejected by cidrWidthError
// before any allocation.
func prefixAddressCount(spec string) (int, bool) {
	if !strings.Contains(spec, "/") {
		return 0, false
	}
	_, ipNet, err := net.ParseCIDR(strings.TrimSpace(spec))
	if err != nil {
		return 0, false
	}
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits < 0 || hostBits > 30 {
		return 0, false
	}
	return 1 << hostBits, true
}

func cidrTooLarge(spec string, bits, maxHostBits int) error {
	return fmt.Errorf("CIDR %s is too large (/%d or longer prefixes only; split bigger blocks into multiple specs)", spec, bits-maxHostBits)
}

func expandCIDR(spec string, maxHostBits int) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits > maxHostBits {
		return nil, cidrTooLarge(spec, bits, maxHostBits)
	}

	network := ip.Mask(ipNet.Mask)
	var hosts []string
	if network.To4() != nil {
		hosts = expandCIDR4(network.To4(), hostBits)
	} else {
		hosts = expandCIDR6(network, ipNet, hostBits)
	}
	// A /31 or single-address network may hold only the network address.
	// ParseCIDR already applied the mask, so the expansion covers every
	// address in the block, including broadcast.
	if len(hosts) == 0 {
		return nil, fmt.Errorf("CIDR %s expanded to zero addresses", spec)
	}
	return hosts, nil
}

// expandCIDR4 lists every IPv4 address in a prefix. hostBits is already
// bounded by the caller (at most 24), so the count fits in an int and the
// last address cannot wrap past the end of the uint32 space for a masked
// network base.
func expandCIDR4(start net.IP, hostBits int) []string {
	count := 1 << hostBits
	base := ipToUint32(start)
	hosts := make([]string, count)
	for i := 0; i < count; i++ {
		hosts[i] = normalizeIP(uint32ToIP(base + uint32(i)))
	}
	return hosts
}

// expandCIDR6 lists every IPv6 address in a prefix. hostBits is bounded by
// the same budget as IPv4, so the slice is allocated once.
func expandCIDR6(start net.IP, ipNet *net.IPNet, hostBits int) []string {
	count := 1 << hostBits
	hosts := make([]string, 0, count)
	for cur := start; ipNet.Contains(cur); cur = nextIP(cur) {
		hosts = append(hosts, normalizeIP(cur))
		if len(hosts) == count {
			break
		}
	}
	return hosts
}

func expandRange(spec string) ([]string, error) {
	left, right, ok := strings.Cut(spec, "-")
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if !ok || left == "" || right == "" {
		return nil, fmt.Errorf("invalid range %q (want a.b.c.d-e.f.g.h, a.b.c.d-n or 2001:db8::1-::a)", spec)
	}

	start := net.ParseIP(left)
	if start == nil {
		return nil, fmt.Errorf("invalid range start %q", left)
	}
	// 4-in-6 mapped addresses (::ffff:a.b.c.d) are treated as IPv4, the
	// same family decision the CIDR path makes through normalizeIP.
	if start4 := start.To4(); start4 != nil {
		return expandRange4(spec, start4, right)
	}
	return expandRange6(spec, start, right)
}

// expandRange4 expands an IPv4 range. right is a full IPv4 address or a
// last-octet number ("10.0.0.1-200").
func expandRange4(spec string, start4 net.IP, right string) ([]string, error) {
	var end net.IP
	if end = net.ParseIP(right); end == nil {
		n, err := strconv.Atoi(right)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("invalid range end %q", right)
		}
		end = net.IPv4(start4[0], start4[1], start4[2], byte(n)).To4()
	}
	end4 := end.To4()
	if end4 == nil {
		return nil, fmt.Errorf("range %q mixes IPv4 and IPv6 endpoints", spec)
	}

	startInt := ipToUint32(start4)
	endInt := ipToUint32(end4)
	if endInt < startInt {
		return nil, fmt.Errorf("range %q is reversed", spec)
	}
	if endInt-startInt > maxTargets {
		return nil, fmt.Errorf("range %q expands to more than %d addresses", spec, maxTargets)
	}

	hosts := make([]string, 0, endInt-startInt+1)
	for v := startInt; v <= endInt; v++ {
		hosts = append(hosts, normalizeIP(uint32ToIP(v)))
	}
	return hosts, nil
}

// expandRange6 expands an inclusive IPv6 range. right may be a full address
// or the trailing-group shorthand ("::a"), whose missing leading groups are
// taken from the start address. The expansion budget is the same
// address-count budget the IPv4 path enforces, and the same explicit error
// (no silent truncation) is produced when the range exceeds it.
func expandRange6(spec string, start net.IP, right string) ([]string, error) {
	start16 := start.To16()
	end, err := parseIPv6RangeEnd(spec, right, start16)
	if err != nil {
		return nil, err
	}

	// 128-bit big-endian arithmetic keeps the same per-range budget as IPv4
	// without overflowing on a typo spanning most of the address space.
	startInt := new(big.Int).SetBytes(start16)
	endInt := new(big.Int).SetBytes(end)
	if endInt.Cmp(startInt) < 0 {
		return nil, fmt.Errorf("range %q is reversed", spec)
	}
	diff := new(big.Int).Sub(endInt, startInt)
	if diff.Cmp(big.NewInt(maxTargets)) > 0 {
		return nil, fmt.Errorf("range %q expands to more than %d addresses", spec, maxTargets)
	}

	hosts := make([]string, 0, int(diff.Int64())+1)
	cur := make(net.IP, 16)
	copy(cur, start16)
	for {
		hosts = append(hosts, normalizeIP(cur))
		if bytes.Equal(cur, end) {
			return hosts, nil
		}
		incIP(cur)
	}
}

// parseIPv6RangeEnd parses the end of an IPv6 range. A value starting with
// "::" is shorthand: it carries only the trailing groups and the missing
// leading groups are copied from start, so "2001:db8::1-::a" ends at
// 2001:db8::a, not at the address ::a.
func parseIPv6RangeEnd(spec, value string, start net.IP) (net.IP, error) {
	if !strings.HasPrefix(value, "::") {
		end := net.ParseIP(value)
		if end == nil {
			return nil, fmt.Errorf("invalid range end %q", value)
		}
		if end.To4() != nil {
			return nil, fmt.Errorf("range %q mixes IPv4 and IPv6 endpoints", spec)
		}
		return end.To16(), nil
	}

	groups := strings.Split(value[2:], ":")
	if len(groups) > 8 {
		return nil, fmt.Errorf("invalid range end %q", value)
	}
	end := make(net.IP, 16)
	copy(end, start[:16-len(groups)*2])
	for i, g := range groups {
		// A bare "" (extra "::") or a group wider than 4 hex digits is not
		// valid shorthand; error instead of guessing the intent.
		if g == "" || len(g) > 4 {
			return nil, fmt.Errorf("invalid range end %q", value)
		}
		v, err := strconv.ParseUint(g, 16, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid range end %q", value)
		}
		end[16-len(groups)*2+2*i] = byte(v >> 8)
		end[16-len(groups)*2+2*i+1] = byte(v)
	}
	return end, nil
}

// incIP adds one to a big-endian address in place. Ranges are bounded by
// maxTargets long before the address space wraps, so the carry-out case
// cannot be reached by the callers.
func incIP(b []byte) {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return
		}
	}
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4()
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
