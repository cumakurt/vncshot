package scanner

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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
