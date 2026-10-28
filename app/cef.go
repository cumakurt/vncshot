package app

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"vncshot/report"
)

const (
	// syslogTimeout bounds per-send activity: dial (including DNS
	// resolution), write and, for TCP, the whole session.
	syslogTimeout = 5 * time.Second
	// syslogMaxLine truncates the whole syslog line, so it fits in the
	// traditional 1 KiB datagram that every collector accepts.
	syslogMaxLine = 1024
)

// NotifyCEF emits one CEF event per significant finding plus one summary
// event to the syslog receiver in nc.SyslogAddr ("udp://host:port" or
// "tcp://host:port"). UDP sends are datagrams and never wait for a reply.
// Hostnames are resolved per dial with the default resolver and connections
// are never proxied.
func NotifyCEF(ctx context.Context, nc NotifyConfig, out Outcome, version string) error {
	network, host, port, err := parseSyslogAddr(nc.SyslogAddr)
	if err != nil {
		return err
	}

	conn, err := (&net.Dialer{Timeout: syslogTimeout}).DialContext(ctx, network, net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("connect to syslog %s: dial %s: %v", nc.SyslogAddr, network, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(syslogTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	sessionDone := make(chan struct{})
	defer close(sessionDone)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-sessionDone:
		}
	}()

	// One connection carries every event: UDP writes one datagram per event,
	// TCP writes newline-framed lines per RFC 6587 non-transparent framing.
	events := cefEvents(out, version)
	for _, event := range events {
		if _, err := conn.Write([]byte(event + "\n")); err != nil {
			return fmt.Errorf("send CEF event: %w", err)
		}
	}
	return nil
}

// cefEvents renders one syslog line per significant finding plus one summary
// event, at the end, in finding order.
func cefEvents(out Outcome, version string) []string {
	hostname := notificationLocalHostname()
	lines := make([]string, 0, len(out.Results)+1)
	for _, r := range notificationFindings(out) {
		sig, name, severity, extensions, ok := cefFinding(r)
		if !ok {
			// A plain TLS session is evidence, not an alarm.
			continue
		}
		payload := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
			escapeCEFHeader("vncshot"), escapeCEFHeader("vncshot"), escapeCEFHeader(version),
			sig, escapeCEFHeader(name), severity, extensions)
		lines = append(lines, syslogLine(syslogPRI(severity), hostname, payload))
	}
	return append(lines, cefSummaryEvent(out, version, hostname))
}

// cefFinding classifies a result into one CEF event, most severe first: a
// weak password, then passwordless access, then an expiring certificate. A
// plain TLS session is not alarmed about. ok is false when the result carries
// no signal the SIEM should see.
func cefFinding(r report.Result) (sig string, name string, severity int, extensions string, ok bool) {
	switch {
	case r.Password != "":
		return "VNC_WEAK_PASSWORD", "Weak VNC password accepted", 9,
			cefEndpointExtensions(r) + " cs1Label=PasswordSource cs1=" + escapeCEFExtension(r.PasswordSource), true
	case r.Passwordless:
		return "VNC_PASSWORDLESS", "VNC service without authentication", 7, cefEndpointExtensions(r), true
	case r.ExpiresSoon:
		return "VNC_CERT_EXPIRING", "VNC certificate expiring soon", 5, cefCertificateExtensions(r), true
	}
	return "", "", 0, "", false
}

// cefEndpointExtensions carries the endpoint as ArcSight keys.
func cefEndpointExtensions(r report.Result) string {
	return "src=" + escapeCEFExtension(r.IP) + " dpt=" + strconv.Itoa(r.Port)
}

// cefCertificateExtensions carries the peer certificate identity: the
// subject string stays server-selected input and only appears escaped, while
// the fingerprint and expiry timestamp are objective anchors.
func cefCertificateExtensions(r report.Result) string {
	extensions := cefEndpointExtensions(r)
	if cert := r.Certificate; cert != nil {
		if cert.Subject != "" {
			extensions += " cs2Label=CertificateSubject cs2=" + escapeCEFExtension(cert.Subject)
		}
		if cert.Fingerprint != "" {
			extensions += " fileHash=" + escapeCEFExtension(cert.Fingerprint)
		}
		if !cert.NotAfter.IsZero() {
			extensions += " end=" + strconv.FormatInt(cert.NotAfter.Unix(), 10)
		}
	}
	return extensions
}

// cefSummaryEvent emits a single per-run counting event so a SIEM dashboard
// sees scan coverage even for runs without findings.
func cefSummaryEvent(out Outcome, version string, hostname string) string {
	n := buildNotification(out, version)
	extensions := "cs1Label=RunSummary cs1=" + escapeCEFExtension(n.Counters)
	payload := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d|%s",
		escapeCEFHeader("vncshot"), escapeCEFHeader("vncshot"), escapeCEFHeader(version),
		"VNC_SCAN_SUMMARY", "vncshot scan summary", 0, extensions)
	return syslogLine(syslogPRI(0), hostname, payload)
}

// syslogPRI maps a CEF severity to a syslog PRI value using the local0
// facility reserved for local tooling: CEF 8+ is an error, 6-7 a warning and
// below that a notice.
func syslogPRI(severity int) int {
	level := 5 // notice
	switch {
	case severity >= 8:
		level = 3 // err
	case severity >= 6:
		level = 4 // warning
	}
	return 16<<3 | level
}

// escapeCEFHeader escapes one CEF header field per ArcSight: backslash and
// pipe are the structural separators of the header, so both are escaped,
// and line breaks are written as literal sequences.
func escapeCEFHeader(value string) string {
	return escapeCEFRuns(value, true)
}

// escapeCEFExtension escapes one CEF extension value: backslash, equals and
// blanks are escaped so a server-supplied value cannot forge additional
// key=value pairs, and line breaks become literal sequences per ArcSight CEF.
func escapeCEFExtension(value string) string {
	return escapeCEFRuns(value, false)
}

// escapeCEFRuns writes the ArcSight CEF escaping of a value, working on bytes
// so UTF-8 runs pass through unchanged.
func escapeCEFRuns(value string, headerField bool) string {
	const backslash = 0x5c
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case backslash:
			b.WriteString(string([]byte{backslash, backslash}))
		case '|':
			if headerField {
				b.WriteString(string([]byte{backslash, '|'}))
			} else {
				b.WriteByte(c)
			}
		case '=':
			if headerField {
				b.WriteByte(c)
			} else {
				b.WriteString(string([]byte{backslash, '='}))
			}
		case ' ':
			if headerField {
				b.WriteByte(c)
			} else {
				b.WriteString(string([]byte{backslash, ' '}))
			}
		case '\n':
			b.WriteString(string([]byte{backslash, 'n'}))
		case '\r':
			b.WriteString(string([]byte{backslash, 'r'}))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// syslogLine frames one payload as RFC 3164, which every collector accepts:
// "<PRI>Mmm dd hh:mm:ss host vncshot: <payload>". It takes the PRI value so
// the mapping happens exactly once.
func syslogLine(pri int, hostname string, payload string) string {
	line := fmt.Sprintf("<%d>%s %s vncshot: %s",
		pri, time.Now().Format("Jan _2 15:04:05"), hostname, payload)
	return truncateSyslogLine(line)
}

// truncateSyslogLine cuts a line at whole runes so the whole syslog message
// stays within the traditional 1 KiB datagram bound.
func truncateSyslogLine(line string) string {
	if len(line) <= syslogMaxLine {
		return line
	}
	cut := syslogMaxLine
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut]
}

// parseSyslogAddr parses a strict "udp://host:port" or "tcp://host:port"
// syslog target: other schemes, credentials, paths or queries are refused,
// and the port is a required number.
func parseSyslogAddr(value string) (network, host, port string, err error) {
	parsed, parseErr := url.Parse(value)
	if parseErr != nil {
		return "", "", "", fmt.Errorf("invalid syslog address %q: %v", value, parseErr)
	}
	switch parsed.Scheme {
	case "udp", "tcp":
	default:
		return "", "", "", fmt.Errorf("invalid syslog address %q: only udp:// or tcp:// is supported", value)
	}
	if parsed.User != nil {
		return "", "", "", fmt.Errorf("invalid syslog address %q: user information is not supported", value)
	}
	if parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" {
		return "", "", "", fmt.Errorf("invalid syslog address %q: want a host and port only", value)
	}
	host, port = parsed.Hostname(), parsed.Port()
	if host == "" {
		return "", "", "", fmt.Errorf("invalid syslog address %q: host is missing", value)
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return "", "", "", fmt.Errorf("invalid syslog address %q: port is not a valid number", value)
	}
	return parsed.Scheme, host, port, nil
}
