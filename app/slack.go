package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"vncshot/report"
)

// maxFindingsPerMessage bounds how many individual findings a formatted
// notification lists before it falls back to an "and N more" line.
const maxFindingsPerMessage = 10

// dispatchNotifications sends the completed scan to every configured
// non-webhook channel. Each channel is independent: one failing channel must
// not prevent the others and every failure must be reported to the caller, so
// the scan can surface a combined warning. Secrets never appear in errors.
func dispatchNotifications(ctx context.Context, nc NotifyConfig, out Outcome) error {
	// Nothing configured means nothing to do, so a scan without notification
	// channels never sees an error from here.
	if nc.SlackURL == "" && nc.SMTPAddr == "" && nc.SyslogAddr == "" {
		return nil
	}

	// Channels run sequentially on purpose: their combined cost is small
	// compared to a scan, and a bounded, predictable sequence is far easier
	// to reason about than unbounded goroutines.
	var errs []error
	if nc.SlackURL != "" {
		if err := NotifySlack(ctx, nc.SlackURL, out, Version); err != nil {
			errs = append(errs, fmt.Errorf("slack: %w", err))
		}
	}
	if nc.SMTPAddr != "" {
		if err := NotifyMail(ctx, nc, out, Version); err != nil {
			errs = append(errs, fmt.Errorf("mail: %w", err))
		}
	}
	if nc.SyslogAddr != "" {
		if err := NotifyCEF(ctx, nc, out, Version); err != nil {
			errs = append(errs, fmt.Errorf("syslog: %w", err))
		}
	}
	return errors.Join(errs...)
}

// notification is the channel-neutral text of a completed-scan message. Each
// channel renders it into its own wire format (Slack mrkdwn, plain e-mail,
// CEF extensions) so untrusted-content escaping stays in one place per
// channel.
type notification struct {
	Header   string   // tool, version and run name
	Counters string   // passwordless/weak/expiring counts
	Findings []string // compact "<ip>:<port> <tag>" lines, alpha-sorted
	Hidden   int      // findings dropped from Findings because of the cap
}

// buildNotification renders out into the channel-neutral notification. The
// run directory is reduced to its base name so receivers never learn the
// local path.
func buildNotification(out Outcome, version string) notification {
	runName := "-"
	if out.RunDir != "" {
		runName = filepath.Base(out.RunDir)
	}
	header := fmt.Sprintf("vncshot %s run %s", version, runName)
	counters := fmt.Sprintf("passwordless=%d weak=%d expiring-certs=%d",
		out.Summary.Passwordless, out.Summary.WeakCredentials, out.Summary.ExpiringSoon)

	lines := make([]string, 0, len(out.Results))
	for _, r := range notificationFindings(out) {
		lines = append(lines, r.Addr()+" "+findingTag(r))
	}
	sort.Strings(lines)

	hidden := 0
	if len(lines) > maxFindingsPerMessage {
		hidden = len(lines) - maxFindingsPerMessage
		lines = lines[:maxFindingsPerMessage]
	}
	return notification{Header: header, Counters: counters, Findings: lines, Hidden: hidden}
}

// notificationFindings returns the results the notification channels alarm
// about: new findings when a baseline was compared, otherwise every probe
// result. Accepted endpoints are known-approved and are never alarmed about.
func notificationFindings(out Outcome) []report.Result {
	candidates := out.Results
	if out.Diff != nil {
		candidates = out.Diff.New
	}
	findings := make([]report.Result, 0, len(candidates))
	for _, r := range candidates {
		if r.Accepted {
			continue
		}
		if r.Passwordless || r.Password != "" || r.TLS || r.ExpiresSoon {
			findings = append(findings, r)
		}
	}
	return findings
}

// findingTag names a result inside a compact notification line, in alarm
// priority order: passwordless beats weak, which beats tls. An expiring
// certificate always rides on a TLS result.
func findingTag(r report.Result) string {
	switch {
	case r.Passwordless:
		return "passwordless"
	case r.Password != "":
		return "weak"
	case r.TLS, r.ExpiresSoon:
		return "tls"
	}
	return ""
}

// escapeSlack escapes text for Slack mrkdwn: &, < and > are escaped (as
// named entities) so server-supplied names can never break out of plain
// text or form a link.
func escapeSlack(text string) string {
	var b strings.Builder
	for _, r := range text {
		switch r {
		case '&':
			// Concatenating constants keeps the entity visible while the
			// source stays entity-injection-proof for reviewers.
			b.WriteString("&" + "amp;")
		case '<':
			b.WriteString("&" + "lt;")
		case '>':
			b.WriteString("&" + "gt;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// slackMessage renders the notification into a Slack mrkdwn "text" value.
// Every dynamic field is escaped because only verified content (ip:port
// pairs, configured run names) appears, and even those may contain
// operator-chosen text.
func slackMessage(out Outcome, version string) string {
	n := buildNotification(out, version)
	var b strings.Builder
	b.WriteString(escapeSlack(n.Header))
	b.WriteString(": ")
	b.WriteString(escapeSlack(n.Counters))
	if len(n.Findings) > 0 {
		b.WriteString("\nnew findings:")
		for _, line := range n.Findings {
			b.WriteString("\n")
			b.WriteString(escapeSlack(line))
		}
	}
	if n.Hidden > 0 {
		fmt.Fprintf(&b, "\nand %d more", n.Hidden)
	}
	return b.String()
}

// slackPayload is the Slack incoming-webhook body.
type slackPayload struct {
	Text string `json:"text"`
}

// slackHTTPClient POSTs to the Slack endpoint. It is a variable so tests can
// install a client that trusts the in-process test server's certificate.
var slackHTTPClient = &http.Client{Timeout: webhookTimeout}

// NotifySlack posts a formatted scan message to a Slack incoming webhook.
// Only https endpoints are accepted: Slack webhook URLs carry access tokens
// that must not travel over plaintext, and a plaintext endpoint would be
// spoofable. A non-2xx response is an error; receiver bodies are not echoed
// so a compromised Slack binding cannot inject text into our warnings.
func NotifySlack(ctx context.Context, endpoint string, out Outcome, version string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("invalid Slack webhook URL %s (only https:// is accepted)", redactEndpoint(endpoint))
	}
	safeEndpoint := redactEndpoint(endpoint)

	body, err := json.Marshal(slackPayload{Text: slackMessage(out, version)})
	if err != nil {
		return fmt.Errorf("encode Slack payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		// Do not wrap the cause: net/http includes the full URL, including
		// the query string, in its parse errors.
		return fmt.Errorf("build Slack request for %s: invalid request URL", safeEndpoint)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vncshot/"+version)

	resp, err := slackHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("post Slack message to %s: %w", safeEndpoint, redactedCause(err))
	}
	defer resp.Body.Close()

	// Drain a bounded amount so the connection can be reused without
	// trusting the receiver to keep its response small.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookResponseLimit))

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusMultipleChoices-1 {
		return fmt.Errorf("post Slack message to %s: unexpected status %s", safeEndpoint, resp.Status)
	}
	return nil
}

// notificationLocalHostname returns this machine's name for EHLO greetings
// and syslog headers, falling back to a neutral name when the hostname
// cannot be read.
func notificationLocalHostname() string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return "vncshot"
	}
	return sanitizeHostname(name)
}

// sanitizeHostname keeps characters that are valid in an RFC 3164 hostname
// and a HELO/EHLO name: spaces, symbols and non-ASCII text are dropped, so a
// odd machine name can never inject a second header line.
func sanitizeHostname(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "vncshot"
	}
	return b.String()
}
