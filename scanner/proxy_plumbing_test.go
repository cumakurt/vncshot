package scanner

import (
	"context"
	"testing"

	"vncshot/vnc"
)

// TestProbePlumbsProxyURLIntoVNCOptions verifies that Options.ProxyURL
// travels into the vnc.Options the probe builds, so the scanner needs no
// proxy awareness of its own.
func TestProbePlumbsProxyURLIntoVNCOptions(t *testing.T) {
	const want = "socks5h://127.0.0.1:1080"

	var got vnc.Options
	doProbe := func(_ context.Context, _ string, opts vnc.Options) (*vnc.Result, error) {
		got = opts
		return &vnc.Result{}, nil
	}

	res := probeWith(context.Background(), Target{IP: "127.0.0.1", Port: 5900}, Options{ProxyURL: want}, doProbe)
	if res.Error != "" {
		t.Fatalf("probeWith reported an error: %q", res.Error)
	}
	if got.ProxyURL != want {
		t.Errorf("vnc.Options.ProxyURL = %q, want %q", got.ProxyURL, want)
	}
}
