package app

import (
	"bufio"
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"vncshot/report"
)

// startFakeSyslogTCP accepts one connection, reads newline-framed lines and
// reports them. NotifyCEF closes the socket when it returns, which ends the
// read loop.
func startFakeSyslogTCP(t *testing.T) (string, <-chan []string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	received := make(chan []string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		var lines []string
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			lines = append(lines, scanner.Text())
		}
		received <- lines
	}()
	return listener.Addr().String(), received
}

func waitSyslogLines(t *testing.T, received <-chan []string) []string {
	t.Helper()
	select {
	case lines := <-received:
		return lines
	case <-time.After(3 * time.Second):
		t.Fatal("syslog receiver saw no events")
		return nil
	}
}

func TestNotifyCEFTCPDeliversFindingAndSummaryEvents(t *testing.T) {
	addr, received := startFakeSyslogTCP(t)
	nc := NotifyConfig{SyslogAddr: "tcp://" + addr}

	if err := NotifyCEF(context.Background(), nc, fixtureOutcome(), "9.9-test"); err != nil {
		t.Fatalf("NotifyCEF: %v", err)
	}

	lines := waitSyslogLines(t, received)
	if len(lines) != 4 {
		t.Fatalf("receiver saw %d lines, want 3 findings + 1 summary: %q", len(lines), lines)
	}

	headerPattern := regexp.MustCompile(`^<\d{3}>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2} [A-Za-z0-9._-]+ vncshot: CEF:0\|vncshot\|vncshot\|9\.9-test\|`)
	for _, line := range lines {
		if !headerPattern.MatchString(line) {
			t.Errorf("line does not start with an RFC 3164 header: %q", line)
		}
	}

	wants := []string{ //nolint:dupl // table of CEF key expectations
		"|VNC_WEAK_PASSWORD|Weak VNC password accepted|9|",
		"|VNC_PASSWORDLESS|VNC service without authentication|7|",
		"|VNC_CERT_EXPIRING|VNC certificate expiring soon|5|",
		"|VNC_SCAN_SUMMARY|vncshot scan summary|0|",
	}
	for _, want := range wants {
		found := false
		for _, line := range lines {
			if strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no CEF event carries %q; captured %q", want, lines)
		}
	}

	// Weak alarms are errors in the local0 facility, passwordless events are
	// warnings and the remainder are notices.
	for _, prefix := range []string{"<131>", "<132>", "<133>"} {
		found := false
		for _, line := range lines {
			if strings.HasPrefix(line, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no event has PRI prefix %q; captured %q", prefix, lines)
		}
	}
	const bs = string(rune(92))
	if !summarized(lines, "cs1Label=RunSummary cs1=passwordless"+bs+"=1"+bs+" weak"+bs+"=1"+bs+" expiring-certs"+bs+"=1") {
		t.Errorf("summary event misses the counters; captured %q", lines)
	}
}

func summarized(lines []string, want string) bool {
	for _, line := range lines {
		if strings.Contains(line, want) {
			return true
		}
	}
	return false
}

func TestNotifyCEFEscapesExtensionValues(t *testing.T) {
	addr, received := startFakeSyslogTCP(t)
	nc := NotifyConfig{SyslogAddr: "tcp://" + addr}

	// The fixture's certificate subject holds a space, an equals sign, a
	// backslash and a newline; every one must be escaped so the line stays
	// one CEF key/value pair per finding.
	if err := NotifyCEF(context.Background(), nc, fixtureOutcome(), "dev"); err != nil {
		t.Fatalf("NotifyCEF: %v", err)
	}

	lines := waitSyslogLines(t, received)
	const bs = string(rune(92))
	want := "CN" + bs + "=boom,eq" + bs + "=x" + bs + " back" + bs + bs + "slash" + bs + "n" + "second"
	if !summarized(lines, "cs2="+want) {
		t.Errorf("no event escapes the certificate subject as %q; captured %q", want, lines)
	}
	for _, line := range lines {
		if strings.Contains(line, "boom,eq=x") {
			t.Errorf("line carries an unescaped equals sign: %q", line)
		}
	}
	for _, secret := range []string{"hunter2", "\nsecond"} {
		for _, line := range lines {
			if strings.Contains(line, secret) {
				t.Errorf("line leaks %q: %q", secret, line)
			}
		}
	}
}

func TestNotifyCEFTruncatesLongEvents(t *testing.T) {
	addr, received := startFakeSyslogTCP(t)
	nc := NotifyConfig{SyslogAddr: "tcp://" + addr}

	out := fixtureOutcome()
	out.Results[2].Certificate.Subject = strings.Repeat("boomé", 1200) // 6000 bytes

	if err := NotifyCEF(context.Background(), nc, out, "dev"); err != nil {
		t.Fatalf("NotifyCEF: %v", err)
	}

	for _, line := range waitSyslogLines(t, received) {
		if len(line) > 1024 {
			t.Errorf("line is %d bytes, want at most 1024", len(line))
		}
		if !utf8.ValidString(line) {
			t.Errorf("truncation split a UTF-8 rune: %q", line)
		}
	}
}

func TestNotifyCEFUDPDeliversDatagrams(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { packet.Close() })
	nc := NotifyConfig{SyslogAddr: "udp://" + packet.LocalAddr().String()}

	if err := NotifyCEF(context.Background(), nc, fixtureOutcome(), "dev"); err != nil {
		t.Fatalf("NotifyCEF: %v", err)
	}

	// Read the four datagrams and then prove the sender does not rely on a
	// reply or a follow-up connection: a quiet window must carry no extra
	// event.
	count := 0
	buf := make([]byte, 2048)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_ = packet.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
		n, _, readErr := packet.ReadFrom(buf)
		if readErr != nil {
			if count == 4 {
				break
			}
			continue
		}
		datagram := string(buf[:n])
		if !strings.HasPrefix(datagram, "<13") {
			t.Errorf("datagram has no RFC 3164 PRI: %q", datagram)
		}
		count++
	}
	if count != 4 {
		t.Errorf("UDP receiver saw %d datagrams, want 3 findings + 1 summary", count)
	}
}

func TestNotifyCEFSkipsAcceptedFindings(t *testing.T) {
	addr, received := startFakeSyslogTCP(t)
	nc := NotifyConfig{SyslogAddr: "tcp://" + addr}

	out := outcomeWithAcceptedFinding()
	if err := NotifyCEF(context.Background(), nc, out, "dev"); err != nil {
		t.Fatalf("NotifyCEF: %v", err)
	}

	lines := waitSyslogLines(t, received)
	if len(lines) != 1 {
		t.Fatalf("accepted findings escaped into alarms: %q", lines)
	}
	if !strings.Contains(lines[0], "VNC_SCAN_SUMMARY") {
		t.Errorf("event is not the summary: %q", lines[0])
	}
}

func TestParseSyslogAddrRejectsBadTargets(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{name: "wrong scheme", addr: "http://collector.invalid:514"},
		{name: "socks5h", addr: "socks5h://collector.invalid:514"},
		{name: "no port", addr: "udp://collector.invalid"},
		{name: "no host", addr: "tcp://:514"},
		{name: "userinfo", addr: "udp://user:pass@collector.invalid:514"},
		{name: "bogus port", addr: "udp://collector.invalid:70000"},
		{name: "with path", addr: "udp://collector.invalid:514/path"},
		{name: "not a url", addr: "collector.invalid"},
		{name: "empty", addr: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, _, err := parseSyslogAddr(tt.addr); err == nil {
				t.Errorf("parseSyslogAddr accepted %q", tt.addr)
			}
		})
	}
}

func TestParseSyslogAddrAcceptsValidTargets(t *testing.T) {
	tests := []struct {
		addr    string
		network string
		host    string
		port    string
	}{
		{addr: "udp://collector.invalid:514", network: "udp", host: "collector.invalid", port: "514"},
		{addr: "tcp://127.0.0.1:601", network: "tcp", host: "127.0.0.1", port: "601"},
	}
	for _, tt := range tests {
		network, host, port, err := parseSyslogAddr(tt.addr)
		if err != nil {
			t.Fatalf("parseSyslogAddr(%q): %v", tt.addr, err)
		}
		if network != tt.network || host != tt.host || port != tt.port {
			t.Errorf("parseSyslogAddr(%q) = %q,%q,%q, want %q,%q,%q", tt.addr, network, host, port, tt.network, tt.host, tt.port)
		}
	}
}

// outcomeWithAcceptedFinding is a full run whose only alarming result is
// known-approved and therefore must not alarm any channel.
func outcomeWithAcceptedFinding() Outcome {
	result := report.Result{IP: "10.0.0.9", Port: 5900, Open: true, RFB: true, Passwordless: true}
	result.Accepted = true
	return Outcome{
		RunDir:  "/var/lib/vncshot/20260101-120000",
		Summary: report.Summary{Targets: 1, Open: 1, RFB: 1, Passwordless: 1, AcceptedFindings: 1},
		Results: []report.Result{result},
	}
}

func TestCEFExtensionEscaping(t *testing.T) {
	const bs = string(rune(92))
	if got := escapeCEFRuns("a b=c"+bs+"d\ne", false); got != "a"+bs+" b"+bs+"=c"+bs+bs+"d"+bs+"ne" {
		t.Errorf("extension escaping = %q", got)
	}
	if got := escapeCEFRuns("a|b"+bs+"c\nd", true); got != "a"+bs+"|b"+bs+bs+"c"+bs+"nd" {
		t.Errorf("header escaping = %q", got)
	}
}
