package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vncshot/report"
)

// fixtureOutcome builds an Outcome with one finding of each alarm kind: a
// passwordless host, a weak credential and an expiring TLS certificate. The
// secrets are decoys that must never travel to any notification channel.
func fixtureOutcome() Outcome {
	return Outcome{
		RunDir:  filepath.Join(string(filepath.Separator), "var", "lib", "vncshot", "20260101-120000"),
		Summary: report.Summary{Targets: 3, Open: 3, RFB: 3, Passwordless: 1, WeakCredentials: 1, ExpiringSoon: 1},
		Results: []report.Result{
			{
				IP:             "10.0.0.2",
				Port:           5900,
				Open:           true,
				RFB:            true,
				Password:       "hunter2",
				PasswordSource: "default-list",
			},
			{
				IP:           "10.0.0.1",
				Port:         5900,
				Open:         true,
				RFB:          true,
				Passwordless: true,
			},
			{
				IP:          "10.0.0.3",
				Port:        5901,
				Open:        true,
				RFB:         true,
				TLS:         true,
				ExpiresSoon: true,
				Certificate: &report.Certificate{
					// Boom, eq, backslash and markup: the escaping must
					// neutralize every one of these on the wire.
					Subject:     "CN=boom,eq=x back\\slash\nsecond",
					Fingerprint: "aa11bb22",
					NotAfter:    time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC),
					SelfSigned:  true,
				},
			},
		},
	}
}

func captureSlackServer(t *testing.T, status int) (*httptest.Server, <-chan string) {
	t.Helper()
	texts := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload slackPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("request body is not a Slack payload: %v", err)
		}
		texts <- payload.Text
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, texts
}

// trustTestServer swaps the Slack HTTP client for one that accepts the
// in-process test server's certificate and restores the original on cleanup.
func trustTestServer(t *testing.T, server *httptest.Server) {
	t.Helper()
	original := slackHTTPClient
	slackHTTPClient = server.Client()
	t.Cleanup(func() { slackHTTPClient = original })
}

func TestNotifySlackPostsEscapedMessage(t *testing.T) {
	server, texts := captureSlackServer(t, http.StatusOK)
	trustTestServer(t, server)

	err := NotifySlack(context.Background(), server.URL, fixtureOutcome(), "9.9-test")
	if err != nil {
		t.Fatalf("NotifySlack: %v", err)
	}

	text := <-texts
	for _, want := range []string{
		"vncshot 9.9-test run 20260101-120000",
		"passwordless=1 weak=1 expiring-certs=1",
		"new findings:",
		"10.0.0.1:5900 passwordless",
		"10.0.0.2:5900 weak",
		"10.0.0.3:5901 tls",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("message %q misses %q", text, want)
		}
	}
	// Findings are compact ip:port lines, alpha-sorted by that line.
	if strings.Index(text, "10.0.0.1:5900") > strings.Index(text, "10.0.0.2:5900") {
		t.Errorf("finding lines are not alpha-sorted: %q", text)
	}
	for _, secret := range []string{"hunter2", "CN=boom", "back\\slash", "second"} {
		if strings.Contains(text, secret) {
			t.Errorf("message leaks %q: %q", secret, text)
		}
	}
	// Server-selected text must never be able to form a link.
	if strings.Contains(text, "<") || strings.Contains(text, ">") {
		t.Errorf("message carries unescaped angle brackets: %q", text)
	}
}

func TestSlackMessageEscapesCurlyBooleans(t *testing.T) {
	got := escapeSlack("a&b" + "<" + "c>d")
	want := "a" + "&" + "a" + "m" + "p" + ";" + "b" + "&" + "l" + "t" + ";" + "c" + "&" + "g" + "t" + ";d"
	if got != want {
		t.Fatalf("escapeSlack = %q, want %q", got, want)
	}
}

func TestNotifySlackCapsFindings(t *testing.T) {
	out := Outcome{
		Summary: report.Summary{Passwordless: 14},
		Results: func() []report.Result {
			results := make([]report.Result, 0, 14)
			for i := 1; i <= 14; i++ {
				results = append(results, report.Result{
					IP:           "10.0.0." + itoaForTest(i),
					Port:         5900,
					Open:         true,
					RFB:          true,
					Passwordless: true,
				})
			}
			return results
		}(),
	}

	got := slackMessage(out, "dev")
	if !strings.Contains(got, "and 4 more") {
		t.Errorf("message %q should cap the findings list at 10", got)
	}
	if strings.Count(got, ":5900") != 10 {
		t.Errorf("message lists %d findings, want 10", strings.Count(got, ":5900"))
	}
}

// itoaForTest builds dotted quad IP strings for the finding-count test.
func itoaForTest(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return itoaForTest(n/10) + string(rune('0'+n%10))
}

func TestNotifySlackRequiresHTTPS(t *testing.T) {
	for _, endpoint := range []string{
		"http://127.0.0.1:1/hook",
		"not-a-url",
		"https:///missing-host",
		"localhost:9500/hook",
	} {
		err := NotifySlack(context.Background(), endpoint, Outcome{}, "dev")
		if err == nil {
			t.Errorf("NotifySlack accepted %q", endpoint)
		}
		if !strings.Contains(err.Error(), "https") {
			t.Errorf("error for %q does not explain the https requirement: %v", endpoint, err)
		}
	}
}

func TestNotifySlackHidesCredentialInURLErrors(t *testing.T) {
	// A non-2xx response: the body must not be echoed.
	server, _ := captureSlackServer(t, http.StatusInternalServerError)
	trustTestServer(t, server)

	err := NotifySlack(context.Background(), server.URL+"?token=slacktoken", Outcome{}, "dev")
	if err == nil {
		t.Fatal("NotifySlack accepted a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention the status", err)
	}
	for _, secret := range []string{"slacktoken", "internal"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks %q: %v", secret, err)
		}
	}
}

func TestNotifySlackHonoursContextDeadline(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(server.Close)
	trustTestServer(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := NotifySlack(ctx, server.URL, Outcome{}, "dev")
	if err == nil {
		t.Fatal("NotifySlack ignored the context deadline")
	}
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Errorf("NotifySlack blocked for %v, want it to stop near the 50ms deadline", elapsed)
	}
}

func TestDispatchNotificationsSendsToEveryChannel(t *testing.T) {
	// Slack: in-process https server.
	slackServer, texts := captureSlackServer(t, http.StatusOK)
	trustTestServer(t, slackServer)

	// Mail: fake relay with STARTTLS and no authentication.
	relay, mailAddr := newFakeSMTP(t, fakeSMTPConfig{advertiseSTARTTLS: true})
	relay.trust(t)

	// CEF: fake TCP syslog receiver.
	syslogAddr, received := startFakeSyslogTCP(t)

	nc := NotifyConfig{
		SlackURL:   slackServer.URL,
		SMTPAddr:   mailAddr,
		SMTPFrom:   "vncshot@corp.invalid",
		SMTPTo:     []string{"secops@corp.invalid"},
		SyslogAddr: "tcp://" + syslogAddr,
	}
	if err := dispatchNotifications(context.Background(), nc, fixtureOutcome()); err != nil {
		t.Fatalf("dispatchNotifications: %v", err)
	}

	if text := <-texts; !strings.Contains(text, "passwordless=1 weak=1 expiring-certs=1") {
		t.Errorf("Slack message misses the counts: %q", text)
	}
	// Mail and CEF each received the same completed scan.
	mail := waitForMail(t, relay)
	if !strings.Contains(mail.data, "Subject: vncshot findings: ") {
		t.Errorf("mail message misses the subject: %q", mail.data)
	}
	if !strings.Contains(mail.data, "10.0.0.1:5900 passwordless") {
		t.Errorf("mail message misses the findings: %q", mail.data)
	}
	if lines := waitSyslogLines(t, received); len(lines) != 4 {
		t.Errorf("syslog receiver saw %d events, want 4: %v", len(lines), lines)
	}
}

func TestDispatchNotificationsEmptyConfigIsNoop(t *testing.T) {
	if err := dispatchNotifications(context.Background(), NotifyConfig{}, Outcome{}); err != nil {
		t.Fatalf("dispatchNotifications returned an error for an empty config: %v", err)
	}
}

func TestDispatchNotificationsKeepsEveryChannelError(t *testing.T) {
	// Every channel fails at a different stage, so the combined error proves
	// no channel aborted the others.
	nc := NotifyConfig{
		SlackURL:   "https://127.0.0.1:1/hook",
		SMTPAddr:   "127.0.0.1:1",
		SyslogAddr: "tcp://127.0.0.1:1",
	}

	start := time.Now()
	err := dispatchNotifications(context.Background(), nc, fixtureOutcome())
	if err == nil {
		t.Fatal("dispatchNotifications ignored every channel failure")
	}
	if elapsed := time.Since(start); elapsed >= 10*time.Second {
		t.Errorf("dispatchNotifications blocked for %v, want fail-fast dials", elapsed)
	}

	for _, prefix := range []string{"slack: ", "mail: ", "syslog: "} {
		if !strings.Contains(err.Error(), prefix) {
			t.Errorf("combined error misses %q: %v", prefix, err)
		}
	}
	if strings.Contains(err.Error(), "hunter2") {
		// hunter2 is a finding password and must never be echoed by any
		// notification code path.
		t.Errorf("combined error leaks a finding password: %v", err)
	}
}
