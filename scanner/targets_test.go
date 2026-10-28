package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"vncshot/vnc"
)

func TestExpandSpecIPv6Ranges(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []string
		wantErr string
	}{
		{
			name: "full form range",
			spec: "2001:db8::a-2001:db8::c",
			want: []string{"2001:db8::a", "2001:db8::b", "2001:db8::c"},
		},
		{
			name: "shorthand range fills leading groups from the start",
			spec: "2001:db8::1-::3",
			want: []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"},
		},
		{
			name: "shorthand range with several groups",
			spec: "2001:db8::ff-::101",
			want: []string{"2001:db8::ff", "2001:db8::100", "2001:db8::101"},
		},
		{
			name: "shorthand end equals start",
			spec: "2001:db8::7-::7",
			want: []string{"2001:db8::7"},
		},
		{
			name:    "mixed endpoints ipv4 start ipv6 end",
			spec:    "192.168.1.1-2001:db8::1",
			wantErr: "mixes IPv4 and IPv6 endpoints",
		},
		{
			name:    "mixed endpoints ipv6 start ipv4 end",
			spec:    "2001:db8::1-192.168.1.1",
			wantErr: "mixes IPv4 and IPv6 endpoints",
		},
		{
			name:    "numeric last octet is ipv4 only",
			spec:    "2001:db8::1-10",
			wantErr: `invalid range end "10"`,
		},
		{
			name:    "reversed shorthand range",
			spec:    "2001:db8::5-::1",
			wantErr: "is reversed",
		},
		{
			name:    "shorthand with malformed group",
			spec:    "2001:db8::1-::zz",
			wantErr: `invalid range end "::zz"`,
		},
		{
			name:    "shorthand with too many groups",
			spec:    "2001:db8::1-::1:2:3:4:5:6:7:8:9",
			wantErr: `invalid range end`,
		},
		{
			name: "range over the budget is rejected",
			// 2^32-1 addresses between ::0 and ::ffff:ffff:ffff:ffff inside
			// one /64, far beyond the per-range budget.
			spec:    "2001:db8::-2001:db8:0:0:ffff:ffff:ffff:ffff",
			wantErr: "expands to more than 1048576 addresses",
		},
		{
			name: "range at the budget boundary expands",
			spec: "2001:db8::-2001:db8::3ff",
			want: nil, // checked by count below; the full list is asserted separately
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandSpec(tt.spec)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expandSpec(%q) error = nil, want error containing %q", tt.spec, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expandSpec(%q) error = %q, want it to contain %q", tt.spec, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandSpec(%q) error = %v", tt.spec, err)
			}
			if tt.want == nil {
				if len(got) != 0x400 {
					t.Fatalf("expandSpec(%q) = %d addresses, want 1024", tt.spec, len(got))
				}
				if got[0] != "2001:db8::" || got[len(got)-1] != "2001:db8::3ff" {
					t.Fatalf("expandSpec(%q) endpoints = %q..%q, want 2001:db8::..2001:db8::3ff", tt.spec, got[0], got[len(got)-1])
				}
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("expandSpec(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestExpandSpecIPv6RangeIsSortedAscending(t *testing.T) {
	got, err := expandSpec("2001:db8:0:0:0:0:0:9-2001:db8::b")
	if err != nil {
		t.Fatalf("expandSpec error = %v", err)
	}
	want := []string{"2001:db8::9", "2001:db8::a", "2001:db8::b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expandSpec = %v, want ascending %v", got, want)
	}
}

func TestParseTargetsDedupesIPv6Ranges(t *testing.T) {
	// The overlapping expansion is deduplicated in scan order, exactly like
	// the IPv4 path: first occurrence wins, order is stable.
	got, err := parseTargets("2001:db8::1-::3", "-", []int{5900}, strings.NewReader("2001:db8::2\n"))
	if err != nil {
		t.Fatalf("parseTargets error = %v", err)
	}
	want := []Target{
		{IP: "2001:db8::1", Port: 5900},
		{IP: "2001:db8::2", Port: 5900},
		{IP: "2001:db8::3", Port: 5900},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets = %v, want %v", got, want)
	}
}

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []int
		wantErr bool
	}{
		{name: "single", spec: "5900", want: []int{5900}},
		{name: "list", spec: "5900,5901", want: []int{5900, 5901}},
		{name: "range", spec: "5900-5903", want: []int{5900, 5901, 5902, 5903}},
		{name: "mixed", spec: "5900,5901-5902,5999", want: []int{5900, 5901, 5902, 5999}},
		{name: "dedupe", spec: "5900,5900", want: []int{5900}},
		{name: "spaces", spec: " 5900 , 5901 ", want: []int{5900, 5901}},
		{name: "empty", spec: "", wantErr: true},
		{name: "invalid", spec: "abc", wantErr: true},
		{name: "out of range", spec: "70000", wantErr: true},
		{name: "zero", spec: "0", wantErr: true},
		{name: "reversed range", spec: "5905-5901", wantErr: true},
		{name: "bad range end", spec: "5900-abc", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePorts(%q) error = nil, want error", tt.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePorts(%q) error = %v", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("ParsePorts(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestExpandSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    []string
		wantErr bool
	}{
		{name: "single ipv4", spec: "192.168.1.10", want: []string{"192.168.1.10"}},
		{name: "cidr /30", spec: "192.168.1.0/30", want: []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}},
		{name: "cidr /32", spec: "10.0.0.5/32", want: []string{"10.0.0.5"}},
		{name: "full range", spec: "192.168.1.1-192.168.1.3", want: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}},
		{name: "short range", spec: "192.168.1.1-3", want: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"}},
		{name: "ipv6 single", spec: "::1", want: []string{"::1"}},
		{name: "empty", spec: "  ", wantErr: true},
		{name: "garbage", spec: "not-an-ip", wantErr: true},
		{name: "huge cidr", spec: "10.0.0.0/8", wantErr: true},
		{name: "reversed range", spec: "192.168.1.5-192.168.1.1", wantErr: true},
		{name: "bad cidr", spec: "10.0.0.0/64", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandSpec(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expandSpec(%q) error = nil, want error", tt.spec)
				}
				return
			}
			if err != nil {
				t.Fatalf("expandSpec(%q) error = %v", tt.spec, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("expandSpec(%q) = %v, want %v", tt.spec, got, tt.want)
			}
		})
	}
}

func TestParseTargets(t *testing.T) {
	ports := []int{5900, 5901}

	got, err := ParseTargets("192.168.1.1-2", "", ports)
	if err != nil {
		t.Fatalf("ParseTargets error = %v", err)
	}
	want := []Target{
		{IP: "192.168.1.1", Port: 5900},
		{IP: "192.168.1.1", Port: 5901},
		{IP: "192.168.1.2", Port: 5900},
		{IP: "192.168.1.2", Port: 5901},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseTargets = %v, want %v", got, want)
	}
}

func TestParseTargetsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	content := `# comment line
192.168.1.1
10.0.0.0/30

10.0.0.9-10  # inline comment
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := ParseTargets("", path, []int{5900})
	if err != nil {
		t.Fatalf("ParseTargets error = %v", err)
	}
	want := []Target{
		{IP: "192.168.1.1", Port: 5900},
		{IP: "10.0.0.0", Port: 5900},
		{IP: "10.0.0.1", Port: 5900},
		{IP: "10.0.0.2", Port: 5900},
		{IP: "10.0.0.3", Port: 5900},
		{IP: "10.0.0.9", Port: 5900},
		{IP: "10.0.0.10", Port: 5900},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseTargets = %v, want %v", got, want)
	}
}

func TestParseTargetsErrors(t *testing.T) {
	if _, err := ParseTargets("", "", []int{5900}); err == nil {
		t.Fatal("expected error with no inputs")
	}
	if _, err := ParseTargets("192.168.1.1", "", nil); err == nil {
		t.Fatal("expected error with no ports")
	}
	if _, err := ParseTargets("", "/nonexistent/hosts.txt", []int{5900}); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestHostsFromReader(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		label   string
		want    []string
		wantErr string
	}{
		{
			name: "comments blank lines cidr and range",
			input: `# comment line
192.168.1.1
10.0.0.0/30  # inline comment

   # indented comment
10.0.0.9-10
`,
			label: "stdin",
			want: []string{
				"192.168.1.1",
				"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3",
				"10.0.0.9", "10.0.0.10",
			},
		},
		{
			name:  "empty input",
			input: "\n# only comments\n",
			label: "stdin",
			want:  nil,
		},
		{
			name:    "error names stdin and line",
			input:   "192.168.1.1\nnot-an-ip\n",
			label:   "stdin",
			wantErr: "stdin:2:",
		},
		{
			name:    "error names file label and line",
			input:   "not-an-ip\n",
			label:   "/tmp/hosts.txt",
			wantErr: "/tmp/hosts.txt:1:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hostsFromReader(strings.NewReader(tt.input), tt.label)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("hostsFromReader error = nil, want error containing %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("hostsFromReader error = %q, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("hostsFromReader error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("hostsFromReader = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadHostLinesRejectsBudgetOverflowBeforeExpanding(t *testing.T) {
	// The first /16 fills a one-block budget. The second must be refused
	// from its prefix length, before another 2^16 addresses are allocated.
	budget := 1 << 16
	input := "10.0.0.0/16\n10.1.0.0/16\n"

	_, err := readHostLines(strings.NewReader(input), "stdin", maxFileCIDRHostBits, budget)
	if err == nil {
		t.Fatal("readHostLines error = nil, want oversize error")
	}
	want := fmt.Sprintf("refusing to read more than %d hosts from stdin", budget)
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("readHostLines error = %q, want it to contain %q", err, want)
	}
}

func TestCIDRWidthBudget(t *testing.T) {
	tests := []struct {
		spec     string
		bits     int
		wantErr  string
		wantNone bool
	}{
		{spec: "10.0.0.0/8", bits: maxFileCIDRHostBits, wantNone: true},
		{spec: "10.0.0.0/7", bits: maxFileCIDRHostBits, wantErr: "/8 or longer"},
		{spec: "10.0.0.0/16", bits: maxCIDRHostBits, wantNone: true},
		{spec: "10.0.0.0/8", bits: maxCIDRHostBits, wantErr: "/16 or longer"},
		{spec: "2001:db8::/104", bits: maxFileCIDRHostBits, wantNone: true},
		{spec: "2001:db8::/103", bits: maxFileCIDRHostBits, wantErr: "/104 or longer"},
		{spec: "2001:db8::/112", bits: maxCIDRHostBits, wantNone: true},
		{spec: "2001:db8::/104", bits: maxCIDRHostBits, wantErr: "/112 or longer"},
	}
	for _, tt := range tests {
		err := cidrWidthError(tt.spec, tt.bits)
		if tt.wantNone {
			if err != nil {
				t.Errorf("cidrWidthError(%q, %d) = %v, want nil", tt.spec, tt.bits, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("cidrWidthError(%q, %d) = %v, want error containing %q", tt.spec, tt.bits, err, tt.wantErr)
		}
	}
}

func TestFileCIDRAllowsPrefixShorterThan16(t *testing.T) {
	// /15 is 131072 addresses, which a single -target spec rejects and a
	// file line must accept.
	if _, err := ParseTargets("10.2.0.0/15", "", []int{5900}); err == nil {
		t.Fatal("ParseTargets(-target /15) error = nil, want /16 cap")
	} else if !strings.Contains(err.Error(), "/16 or longer") {
		t.Fatalf("ParseTargets(-target /15) error = %v, want /16 cap", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "nets.txt")
	if err := os.WriteFile(path, []byte("10.2.0.0/15\n2001:db8::/120\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	got, err := ParseTargets("", path, []int{5900})
	if err != nil {
		t.Fatalf("ParseTargets(file /15) error = %v", err)
	}
	const want = (1 << 17) + (1 << 8)
	if len(got) != want {
		t.Fatalf("ParseTargets(file) = %d targets, want %d", len(got), want)
	}
}

func TestFileCIDRRejectsPrefixShorterThan8(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nets.txt")
	if err := os.WriteFile(path, []byte("10.0.0.0/7\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := ParseTargets("", path, []int{5900})
	if err == nil || !strings.Contains(err.Error(), "/8 or longer") {
		t.Fatalf("ParseTargets(file /7) error = %v, want /8 cap", err)
	}
}

func TestFilePairBudgetExceedsTargetCap(t *testing.T) {
	// 4096 hosts times 300 ports is past the -target pair cap (2^20) and
	// inside the file cap (2^24). File mode must scan it.
	dir := t.TempDir()
	path := filepath.Join(dir, "nets.txt")
	if err := os.WriteFile(path, []byte("10.4.0.0/20\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	ports := make([]int, 300)
	for i := range ports {
		ports[i] = i + 1
	}
	got, err := ParseTargets("", path, ports)
	if err != nil {
		t.Fatalf("ParseTargets(file) error = %v", err)
	}
	if len(got) != 4096*300 {
		t.Fatalf("ParseTargets(file) = %d targets, want %d", len(got), 4096*300)
	}
}

func TestParseTargetsFromStdin(t *testing.T) {
	input := `# gateway
192.168.1.1
10.0.0.0/31  # a pair

10.0.0.9-10
`
	got, err := parseTargets("", "-", []int{5900}, strings.NewReader(input))
	if err != nil {
		t.Fatalf("parseTargets error = %v", err)
	}
	want := []Target{
		{IP: "192.168.1.1", Port: 5900},
		{IP: "10.0.0.0", Port: 5900},
		{IP: "10.0.0.1", Port: 5900},
		{IP: "10.0.0.9", Port: 5900},
		{IP: "10.0.0.10", Port: 5900},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets = %v, want %v", got, want)
	}
}

func TestParseTargetsFromStdinCombinesWithTarget(t *testing.T) {
	got, err := parseTargets("192.168.1.2", "-", []int{5900}, strings.NewReader("192.168.1.1\n"))
	if err != nil {
		t.Fatalf("parseTargets error = %v", err)
	}
	want := []Target{
		{IP: "192.168.1.2", Port: 5900},
		{IP: "192.168.1.1", Port: 5900},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseTargets = %v, want %v", got, want)
	}
}

func TestParseTargetsFromStdinEmpty(t *testing.T) {
	if _, err := parseTargets("", "-", []int{5900}, strings.NewReader("# nothing\n")); err == nil {
		t.Fatal("expected error for empty stdin")
	}
}

func TestRateLimiter(t *testing.T) {
	// Unlimited limiter must not block.
	ul := NewRateLimiter(0)
	if err := ul.Wait(t.Context()); err != nil {
		t.Fatalf("unlimited Wait error = %v", err)
	}

	// A tight limiter should pace attempts without erroring while the
	// context stays live.
	rl := NewRateLimiter(1000) // 1ms interval
	for i := 0; i < 5; i++ {
		if err := rl.Wait(t.Context()); err != nil {
			t.Fatalf("Wait error = %v", err)
		}
	}

	// A cancelled context must surface the cancellation.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := rl.Wait(ctx); err == nil {
		t.Fatal("Wait on cancelled context error = nil, want error")
	}
}

// connectFailure builds the error shape vnc.Probe returns when the TCP dial
// fails: the ErrConnect sentinel joined with the underlying dial error.
func connectFailure(err error) error {
	return fmt.Errorf("connect: %w", errors.Join(vnc.ErrConnect, err))
}

func TestProbeAttemptsOnSuccess(t *testing.T) {
	calls := 0
	fn := func(context.Context, string, vnc.Options) (*vnc.Result, error) {
		calls++
		return &vnc.Result{
			Passwordless:      true,
			SecurityTypeNames: []string{"None"},
		}, nil
	}

	res := probeWith(context.Background(), Target{IP: "127.0.0.1", Port: 5900}, Options{}, fn)
	if calls != 1 {
		t.Errorf("probe calls = %d, want 1", calls)
	}
	if res.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", res.Attempts)
	}
	if !res.Open || !res.RFB {
		t.Errorf("Open=%v RFB=%v, want both true", res.Open, res.RFB)
	}
	if !reflect.DeepEqual(res.SecurityTypes, []string{"None"}) {
		t.Errorf("SecurityTypes = %v, want [None]", res.SecurityTypes)
	}
}

func TestProbeRetriesTransientConnectFailure(t *testing.T) {
	timeoutErr := connectFailure(&net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded})
	var calls atomic.Int32
	fn := func(context.Context, string, vnc.Options) (*vnc.Result, error) {
		if calls.Add(1) == 1 {
			return nil, timeoutErr
		}
		return &vnc.Result{}, nil
	}

	res := probeWith(context.Background(), Target{IP: "127.0.0.1", Port: 5900}, Options{
		MaxRetries:   1,
		RetryBackoff: time.Millisecond,
	}, fn)

	if got := calls.Load(); got != 2 {
		t.Errorf("probe calls = %d, want 2", got)
	}
	if res.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2", res.Attempts)
	}
	if !res.Open || !res.RFB {
		t.Errorf("Open=%v RFB=%v, want both true after the retry", res.Open, res.RFB)
	}
}

func TestProbeDoesNotRetryRefusedConnection(t *testing.T) {
	refused := connectFailure(&net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED})
	var calls atomic.Int32
	fn := func(context.Context, string, vnc.Options) (*vnc.Result, error) {
		calls.Add(1)
		return nil, refused
	}

	res := probeWith(context.Background(), Target{IP: "127.0.0.1", Port: 5900}, Options{
		MaxRetries:   1,
		RetryBackoff: time.Millisecond,
	}, fn)

	if got := calls.Load(); got != 1 {
		t.Errorf("probe calls = %d, want 1 (ECONNREFUSED is definitive)", got)
	}
	if res.Open {
		t.Error("Open = true, want false")
	}
	if res.Error != "" {
		t.Errorf("Error = %q, want empty for a closed port", res.Error)
	}
	if res.Attempts != 0 {
		t.Errorf("Attempts = %d, want 0 for a first-try closed port", res.Attempts)
	}
}

func TestProbeRecordsAttemptsWhenRetryStaysClosed(t *testing.T) {
	timeoutErr := connectFailure(&net.OpError{Op: "dial", Net: "tcp", Err: os.ErrDeadlineExceeded})
	var calls atomic.Int32
	fn := func(context.Context, string, vnc.Options) (*vnc.Result, error) {
		calls.Add(1)
		return nil, timeoutErr
	}

	res := probeWith(context.Background(), Target{IP: "127.0.0.1", Port: 5900}, Options{
		MaxRetries:   1,
		RetryBackoff: time.Millisecond,
	}, fn)

	if got := calls.Load(); got != 2 {
		t.Errorf("probe calls = %d, want 2", got)
	}
	if res.Open {
		t.Error("Open = true, want false")
	}
	if res.Error != "" {
		t.Errorf("Error = %q, want empty for a closed port", res.Error)
	}
	if res.Attempts != 2 {
		t.Errorf("Attempts = %d, want 2 so the retry is visible", res.Attempts)
	}
}

func TestProbeRecordsProductHint(t *testing.T) {
	fn := func(context.Context, string, vnc.Options) (*vnc.Result, error) {
		return &vnc.Result{
			Passwordless: true,
			RFBVersion:   "3.8",
			ServerName:   "node-7 (TigerVNC)",
		}, nil
	}

	res := probeWith(context.Background(), Target{IP: "127.0.0.1", Port: 5900}, Options{}, fn)
	if res.ProductHint != "TigerVNC" {
		t.Errorf("ProductHint = %q, want %q", res.ProductHint, "TigerVNC")
	}

	// Without volunteered data the hint stays empty and is omitted from JSON.
	fn2 := func(context.Context, string, vnc.Options) (*vnc.Result, error) {
		return &vnc.Result{}, nil
	}
	res2 := probeWith(context.Background(), Target{IP: "127.0.0.1", Port: 5900}, Options{}, fn2)
	if res2.ProductHint != "" {
		t.Errorf("ProductHint = %q, want empty", res2.ProductHint)
	}
}

func TestIsTransientConnectError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "timeout", err: connectFailure(&net.OpError{Op: "dial", Err: os.ErrDeadlineExceeded}), want: true},
		{name: "refused", err: connectFailure(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}), want: false},
		{name: "reset", err: connectFailure(&net.OpError{Op: "dial", Err: syscall.ECONNRESET}), want: true},
		{name: "broken pipe", err: connectFailure(&net.OpError{Op: "dial", Err: syscall.EPIPE}), want: true},
		{name: "host unreachable", err: connectFailure(&net.OpError{Op: "dial", Err: syscall.EHOSTUNREACH}), want: true},
		{name: "protocol error", err: errors.New("read protocol version: EOF"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isTransientConnectError(tt.err); got != tt.want {
				t.Errorf("isTransientConnectError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestRetryDelayBounds(t *testing.T) {
	const base = 100 * time.Millisecond
	tests := []struct {
		attempt int
		base    time.Duration
	}{
		{attempt: 1, base: base},
		{attempt: 2, base: 2 * base},
		{attempt: 3, base: 4 * base},
	}

	for _, tt := range tests {
		for i := 0; i < 100; i++ {
			got := retryDelay(base, tt.attempt)
			if got < tt.base || got > tt.base*3/2 {
				t.Fatalf("retryDelay(%v, %d) = %v, want within [%v, %v]",
					base, tt.attempt, got, tt.base, tt.base*3/2)
			}
		}
	}

	got := retryDelay(0, 1)
	if got < defaultRetryBackoff || got > defaultRetryBackoff*3/2 {
		t.Errorf("retryDelay(0, 1) = %v, want within [%v, %v]",
			got, defaultRetryBackoff, defaultRetryBackoff*3/2)
	}
}
