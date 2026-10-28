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
// tens of millions of connection attempts.
const maxTargets = 1 << 20

// maxCIDRHostBits caps a single CIDR spec at 2^16 addresses (/16).
// Larger blocks must be split into multiple specs so a typo cannot
// allocate a gigabyte-scale host list before the target cap applies.
const maxCIDRHostBits = 16

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

	total := len(hosts) * len(ports)
	if total > maxTargets {
		return nil, fmt.Errorf("refusing to scan %d host:port pairs (limit %d); narrow the range or port list", total, maxTargets)
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
// source in error messages ("stdin" or the file path).
func hostsFromReader(r io.Reader, label string) ([]string, error) {
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
		expanded, err := expandSpec(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", label, lineNo, err)
		}
		// Check before appending: a single line can expand to 2^16 hosts and
		// an endless stream must not grow the slice without bound.
		if len(hosts)+len(expanded) > maxTargets {
			return nil, fmt.Errorf("refusing to read more than %d hosts from %s; narrow the input", maxTargets, label)
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
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("empty target")
	}

	if strings.Contains(spec, "/") {
		return expandCIDR(spec)
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

func expandCIDR(spec string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(spec)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}
	ones, bits := ipNet.Mask.Size()
	if ip.To4() != nil {
		if bits-ones > maxCIDRHostBits {
			return nil, fmt.Errorf("CIDR %s is too large (/%d or longer prefixes only; split bigger blocks into multiple specs)", spec, 32-maxCIDRHostBits)
		}
	} else if bits-ones > maxCIDRHostBits {
		// IPv6: same address-count budget; /112 is 65536 addresses.
		return nil, fmt.Errorf("CIDR %s is too large (/%d or longer prefixes only; split bigger blocks into multiple specs)", spec, bits-maxCIDRHostBits)
	}

	var hosts []string
	for cur := ip.Mask(ipNet.Mask); ipNet.Contains(cur); cur = nextIP(cur) {
		hosts = append(hosts, normalizeIP(cur))
	}
	// A /31 or single-address network may hold only the network address
	// in the loop above; ParseCIDR already handled the mask correctly so
	// the loop covers every address in the block, including broadcast.
	if len(hosts) == 0 {
		return nil, fmt.Errorf("CIDR %s expanded to zero addresses", spec)
	}
	return hosts, nil
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
