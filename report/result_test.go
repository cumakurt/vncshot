package report

import "testing"

func TestSummarizeMixedResults(t *testing.T) {
	results := []Result{
		{
			IP:           "192.0.2.1",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			Screenshot:   "/tmp/a.png",
		},
		{
			IP:   "192.0.2.2",
			Port: 5900,
			Open: true,
			RFB:  true,
		},
		{
			IP:    "192.0.2.3",
			Port:  5901,
			Error: "dial timeout",
		},
		{
			IP:         "192.0.2.4",
			Port:       5902,
			Open:       true,
			Screenshot: "/tmp/b.png",
			Error:      "partial read",
		},
	}

	want := Summary{
		Targets:      4,
		Open:         3,
		RFB:          2,
		Passwordless: 1,
		Screenshots:  2,
		Errors:       2,
	}

	if got := Summarize(results); got != want {
		t.Fatalf("Summarize(mixed) = %+v, want %+v", got, want)
	}
}

func TestSummarizeEmpty(t *testing.T) {
	want := Summary{}
	if got := Summarize(nil); got != want {
		t.Fatalf("Summarize(nil) = %+v, want %+v", got, want)
	}
	if got := Summarize([]Result{}); got != want {
		t.Fatalf("Summarize(empty) = %+v, want %+v", got, want)
	}
}

func TestResultAddr(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port int
		want string
	}{
		{name: "ipv4", ip: "192.0.2.1", port: 5900, want: "192.0.2.1:5900"},
		{name: "port zero", ip: "127.0.0.1", port: 0, want: "127.0.0.1:0"},
		{name: "negative port", ip: "10.0.0.1", port: -1, want: "10.0.0.1:-1"},
		// Addr joins with a single colon; IPv6 literals are not bracketed.
		{name: "ipv6 literal", ip: "2001:db8::1", port: 5900, want: "2001:db8::1:5900"},
		{name: "large port", ip: "192.0.2.9", port: 65535, want: "192.0.2.9:65535"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Result{IP: tt.ip, Port: tt.port}
			if got := r.Addr(); got != tt.want {
				t.Fatalf("Addr() = %q, want %q", got, tt.want)
			}
		})
	}
}
