package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// mailTimeout bounds one relay session: dial, STARTTLS handshake, AUTH and
// message delivery together stay under it, so a stalled relay cannot hang a
// scan a full default timeout short of forever.
const mailTimeout = 10 * time.Second

// newMailTLSConfig builds the STARTTLS verification configuration. It is a
// variable so tests can trust the in-process relay without ever weakening the
// production default, which is the system root pool.
var newMailTLSConfig = func(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}

// NotifyMail delivers the scan message as plain text to an SMTP relay. A
// relay that does not offer STARTTLS is refused unless nc.SMTPNoTLS is set,
// because the message carries finding details. Credentials are only sent
// after TLS is established: a relay without STARTTLS plus configured
// credentials is refused even with SMTPNoTLS. The password never appears in
// an error message.
func NotifyMail(ctx context.Context, nc NotifyConfig, out Outcome, version string) error {
	host, _, err := net.SplitHostPort(nc.SMTPAddr)
	if err != nil {
		return fmt.Errorf("mail relay %q is not a host:port address", nc.SMTPAddr)
	}
	if nc.SMTPFrom == "" {
		return errors.New("mail sender address is empty")
	}
	if len(nc.SMTPTo) == 0 {
		return errors.New("mail recipient addresses are empty")
	}

	// The dial timeout is set on the dialer before dialing, so DNS
	// resolution is bounded too, not just the TCP connect.
	conn, err := (&net.Dialer{Timeout: mailTimeout}).DialContext(ctx, "tcp", nc.SMTPAddr)
	if err != nil {
		return fmt.Errorf("connect to relay %s: %w", nc.SMTPAddr, err)
	}
	defer conn.Close()

	// Bound the whole session with one deadline and close the socket on
	// explicit cancellation, because net/smtp commands honor neither.
	deadline := time.Now().Add(mailTimeout)
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

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("connect to relay: %w", err)
	}
	defer client.Close()

	if err := client.Hello(notificationLocalHostname()); err != nil {
		return fmt.Errorf("greet relay: %w", err)
	}

	tlsEstablished := false
	supportedSTARTTLS, _ := client.Extension("STARTTLS")
	if supportedSTARTTLS {
		// RootCAs default to the system roots for relays with normal
		// certificates; the constructor is a variable so tests can trust the
		// in-process relay. ServerName comes from the configured relay
		// address, never from server greeting text.
		if err := client.StartTLS(newMailTLSConfig(host)); err != nil {
			return fmt.Errorf("start TLS with relay: %w", err)
		}
		tlsEstablished = true
	} else if !nc.SMTPNoTLS {
		return errors.New("relay does not offer STARTTLS; refusing to send findings in cleartext (set -smtp-no-tls to override)")
	}

	if nc.SMTPUser != "" || nc.SMTPPassword != "" {
		if !tlsEstablished {
			return errors.New("refusing to send mail credentials without TLS, even with -smtp-no-tls")
		}
		if err := client.Auth(smtp.PlainAuth("", nc.SMTPUser, nc.SMTPPassword, host)); err != nil {
			return fmt.Errorf("authenticate with relay: %w", err)
		}
	}

	if err := client.Mail(nc.SMTPFrom); err != nil {
		return fmt.Errorf("start message on relay: %w", err)
	}
	for _, recipient := range nc.SMTPTo {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("add mail recipient %s: %w", recipient, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("start message body: %w", err)
	}
	if _, err := writer.Write(mailMessage(nc, out, version)); err != nil {
		_ = writer.Close()
		return fmt.Errorf("write message body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("deliver message: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("finish mail session: %w", err)
	}
	return nil
}

// mailMessage renders the RFC 5322 message: a CRLF header block plus a plain
// text body mirroring the Slack message, without mrkdwn formatting. Header
// values and the body are stripped to printable ASCII and control characters
// are dropped, so no server-supplied name can smuggle in extra header lines
// and nothing needs RFC 2047 encoding.
func mailMessage(nc NotifyConfig, out Outcome, version string) []byte {
	n := buildNotification(out, version)
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", asciiSMTPField(nc.SMTPFrom))
	fmt.Fprintf(&b, "To: %s\r\n", asciiSMTPField(strings.Join(nc.SMTPTo, ", ")))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Subject: vncshot findings: %s\r\n", asciiSMTPField(n.Counters))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=us-ascii\r\n\r\n")

	b.WriteString(asciiSMTPField(n.Header))
	b.WriteString("\r\n")
	b.WriteString(asciiSMTPField(n.Counters))
	b.WriteString("\r\n")
	if len(n.Findings) > 0 {
		b.WriteString("\r\nNew findings:\r\n")
		for _, line := range n.Findings {
			b.WriteString(asciiSMTPField(line))
			b.WriteString("\r\n")
		}
	}
	// A trailing dot-stuffed lone "." line is written by net/smtp itself, so
	// the body must not end with one.
	if n.Hidden > 0 {
		fmt.Fprintf(&b, "\r\nand %d more\r\n", n.Hidden)
	}
	return b.Bytes()
}

// asciiSMTPField makes a value safe for an RFC 5322 header: printable ASCII
// only, with control characters, CR and LF dropped so a value can never add
// or terminate a header line early.
func asciiSMTPField(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= 0x20 && r <= 0x7e {
			b.WriteRune(r)
		}
	}
	return b.String()
}
