package app

import (
	"path/filepath"
	"strings"
	"testing"

	"vncshot/scanner"
)

// excludeTargets builds scanner.Targets from "ip:port" texts, preserving the
// given order.
func excludeTargets(t *testing.T, addrs ...string) []scanner.Target {
	t.Helper()
	out := make([]scanner.Target, 0, len(addrs))
	for _, a := range addrs {
		host, port, err := splitEndpointToken(a)
		if err != nil {
			t.Fatalf("test fixture %q: %v", a, err)
		}
		out = append(out, scanner.Target{IP: host, Port: port})
	}
	return out
}

// excludeAddrs renders targets back into their "ip:port" form so filtering
// results can be compared order-sensitively.
func excludeAddrs(ts []scanner.Target) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Addr())
	}
	return out
}

// sameAddrs reports whether two address lists are equal, order included.
func sameAddrs(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestLoadExclusionsParsesRules(t *testing.T) {
	path := writeListFile(t, "exclude.txt", `# never touch these
192.0.2.1
192.0.2.0/24
192.0.2.1:5900
2001:db8::1
[2001:db8::2]:5900
192.0.2.9  # inline comment
`)
	exclusions, err := LoadExclusions(path)
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	if len(exclusions.rules) != 6 {
		t.Fatalf("rules = %d, want 6", len(exclusions.rules))
	}
	if exclusions.rules[0].kind != exclusionIP ||
		exclusions.rules[1].kind != exclusionCIDR ||
		exclusions.rules[2].kind != exclusionEndpoint ||
		exclusions.rules[3].kind != exclusionIP ||
		exclusions.rules[4].kind != exclusionEndpoint ||
		exclusions.rules[5].kind != exclusionIP {
		t.Fatalf("rule kinds = %+v, want ip, cidr, endpoint, ip, endpoint, ip", exclusions.rules)
	}
}

func TestLoadExclusionsIgnoresCommentsAndBlanks(t *testing.T) {
	path := writeListFile(t, "exclude.txt", "# only comments\n\n   \n")
	exclusions, err := LoadExclusions(path)
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	if len(exclusions.rules) != 0 {
		t.Fatalf("rules = %d, want 0", len(exclusions.rules))
	}
}

func TestLoadExclusionsMalformedLines(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantLine string
		wantIn   string
	}{
		{
			name:     "hostname instead of ip",
			content:  "192.0.2.1\nexample.com\n",
			wantLine: "exclude.txt:2:",
			wantIn:   "example.com",
		},
		{
			name:     "endpoint port out of range",
			content:  "192.0.2.1:0\n",
			wantLine: "exclude.txt:1:",
			wantIn:   "0",
		},
		{
			name:     "bad cidr",
			content:  "192.0.2.0/33\n",
			wantLine: "exclude.txt:1:",
			wantIn:   "192.0.2.0/33",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeListFile(t, "exclude.txt", tt.content)
			_, err := LoadExclusions(path)
			if err == nil {
				t.Fatal("LoadExclusions accepted a malformed line")
			}
			if !strings.Contains(err.Error(), tt.wantLine) {
				t.Errorf("error %q does not name file and line %q", err, tt.wantLine)
			}
			if !strings.Contains(err.Error(), tt.wantIn) {
				t.Errorf("error %q does not mention %q", err, tt.wantIn)
			}
		})
	}
}

func TestLoadExclusionsMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.txt")
	if _, err := LoadExclusions(path); err == nil {
		t.Fatal("LoadExclusions accepted a missing file")
	}
}

func TestExclusionsFilterIP(t *testing.T) {
	path := writeListFile(t, "exclude.txt", "10.0.0.2\n")
	exclusions, err := LoadExclusions(path)
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	all := excludeTargets(t, "10.0.0.1:5900", "10.0.0.2:5900", "10.0.0.2:5901", "10.0.0.3:5900")

	kept, dropped := exclusions.Filter(all)
	// An IP rule matches every port on that host, and kept targets keep
	// their original order.
	if !sameAddrs(excludeAddrs(kept), []string{"10.0.0.1:5900", "10.0.0.3:5900"}) {
		t.Errorf("kept = %v, want 10.0.0.1 and 10.0.0.3 in original order", excludeAddrs(kept))
	}
	if !sameAddrs(excludeAddrs(dropped), []string{"10.0.0.2:5900", "10.0.0.2:5901"}) {
		t.Errorf("dropped = %v, want every port on 10.0.0.2", excludeAddrs(dropped))
	}
}

func TestExclusionsFilterCIDR(t *testing.T) {
	path := writeListFile(t, "exclude.txt", "192.0.2.0/24\n")
	exclusions, err := LoadExclusions(path)
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	all := excludeTargets(t, "192.0.2.5:5900", "192.0.3.1:5900", "192.0.2.250:5988")

	kept, dropped := exclusions.Filter(all)
	if !sameAddrs(excludeAddrs(kept), []string{"192.0.3.1:5900"}) {
		t.Errorf("kept = %v, want 192.0.3.1:5900", excludeAddrs(kept))
	}
	if !sameAddrs(excludeAddrs(dropped), []string{"192.0.2.5:5900", "192.0.2.250:5988"}) {
		t.Errorf("dropped = %v, want both 192.0.2.x targets", excludeAddrs(dropped))
	}
}

func TestExclusionsFilterEndpointMatchesSinglePort(t *testing.T) {
	path := writeListFile(t, "exclude.txt", "10.0.0.1:5900\n")
	exclusions, err := LoadExclusions(path)
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	all := excludeTargets(t, "10.0.0.1:5900", "10.0.0.1:5901", "10.0.0.2:5900")

	kept, dropped := exclusions.Filter(all)
	if !sameAddrs(excludeAddrs(kept), []string{"10.0.0.1:5901", "10.0.0.2:5900"}) {
		t.Errorf("kept = %v, want 10.0.0.1:5901 and 10.0.0.2:5900", excludeAddrs(kept))
	}
	if !sameAddrs(excludeAddrs(dropped), []string{"10.0.0.1:5900"}) {
		t.Errorf("dropped = %v, want 10.0.0.1:5900", excludeAddrs(dropped))
	}
}

func TestExclusionsFilterIPv6(t *testing.T) {
	path := writeListFile(t, "exclude.txt", "2001:db8::1\n[2001:db8::2]:5900\n")
	exclusions, err := LoadExclusions(path)
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	all := excludeTargets(t, "[2001:db8::1]:5900", "[2001:db8::1]:5901", "[2001:db8::2]:5900", "[2001:db8::2]:5901", "[2001:db8::3]:5900")

	kept, dropped := exclusions.Filter(all)
	// The bare IPv6 rule matches every port on that host; the endpoint
	// rule matches only its own port.
	if !sameAddrs(excludeAddrs(kept), []string{"[2001:db8::2]:5901", "[2001:db8::3]:5900"}) {
		t.Errorf("kept = %v, want the non-matching targets in order", excludeAddrs(kept))
	}
	if !sameAddrs(excludeAddrs(dropped), []string{"[2001:db8::1]:5900", "[2001:db8::1]:5901", "[2001:db8::2]:5900"}) {
		t.Errorf("dropped = %v, want the IPv6 rule matches", excludeAddrs(dropped))
	}
}

func TestExclusionsFilterEmptyListKeepsEverything(t *testing.T) {
	path := writeListFile(t, "exclude.txt", "# nothing excluded\n")
	exclusions, err := LoadExclusions(path)
	if err != nil {
		t.Fatalf("LoadExclusions: %v", err)
	}
	all := excludeTargets(t, "10.0.0.1:5900", "10.0.0.2:5900")

	kept, dropped := exclusions.Filter(all)
	if len(dropped) != 0 {
		t.Errorf("dropped = %v, want none", excludeAddrs(dropped))
	}
	if !sameAddrs(excludeAddrs(kept), excludeAddrs(all)) {
		t.Errorf("kept = %v, want the full target list in order", excludeAddrs(kept))
	}
}

func TestExclusionsFilterNoRulesLoaded(t *testing.T) {
	exclusions := Exclusions{}
	all := excludeTargets(t, "10.0.0.1:5900")
	kept, dropped := exclusions.Filter(all)
	if len(kept) != 1 || len(dropped) != 0 {
		t.Errorf("kept = %v, dropped = %v; want everything kept", excludeAddrs(kept), excludeAddrs(dropped))
	}
}
