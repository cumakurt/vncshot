package app

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// receivedMail is the wire capture of one message as the fake relay sees it.
type receivedMail struct {
	from      string
	to        []string
	data      string
	tlsActive bool
}

// fakeSMTPConfig describes the session the fake relay accepts.
type fakeSMTPConfig struct {
	// advertiseSTARTTLS controls whether EHLO lists STARTTLS. When false the
	// relay stays plaintext forever and refuses the command.
	advertiseSTARTTLS bool
	// acceptUser and acceptPassword are the credentials the relay accepts;
	// empty acceptUser disables the AUTH capability.
	acceptUser     string
	acceptPassword string
}

// fakeSMTP is a minimal threaded SMTP relay speaking just enough of the
// protocol for NotifyMail: greeting, EHLO capabilities, optional STARTTLS
// upgrade, optional AUTH PLAIN, and one message per session.
type fakeSMTP struct {
	listener net.Listener
	// leaf is the self-signed certificate the relay presents, exposed so
	// tests can build a root pool for it.
	leaf     *x509.Certificate
	messages chan receivedMail
}

func newFakeSMTP(t *testing.T, cfg fakeSMTPConfig) (*fakeSMTP, string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	certificate := selfSignedCertificateRelay()
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("parse relay certificate: %v", err)
	}
	server := &fakeSMTP{listener: listener, leaf: leaf, messages: make(chan receivedMail, 1)}
	go server.serve(cfg, certificate)
	return server, listener.Addr().String()
}

// trust schedules NotifyMail to accept the fake relay's certificate.
func (s *fakeSMTP) trust(t *testing.T) {
	t.Helper()
	original := newMailTLSConfig
	pool := x509.NewCertPool()
	pool.AddCert(s.leaf)
	newMailTLSConfig = func(serverName string) *tls.Config {
		return &tls.Config{ServerName: serverName, RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	t.Cleanup(func() { newMailTLSConfig = original })
}

// addr turns the relay address into the NotifyConfig SMTPAddr form.
func (s *fakeSMTP) addr() string { return s.listener.Addr().String() }

func (s *fakeSMTP) serve(cfg fakeSMTPConfig, certificate tls.Certificate) {
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	plainConn := conn
	upgraded := false
	writeLine := func(line string) {
		_, _ = plainConn.Write([]byte(line + "\r\n"))
	}
	writeLine("220 test relay ready")

	reader := bufio.NewReader(plainConn)
	var mail receivedMail
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		command, argument, _ := strings.Cut(line, " ")
		switch strings.ToUpper(command) {
		case "EHLO", "HELO":
			capabilities := []string{"8BITMIME"}
			if cfg.advertiseSTARTTLS {
				capabilities = append(capabilities, "STARTTLS")
			}
			if cfg.acceptUser != "" {
				capabilities = append(capabilities, "AUTH PLAIN")
			}
			writeLine("250-test relay greets you")
			for index, capability := range capabilities {
				prefix := "250-"
				if index == len(capabilities)-1 {
					prefix = "250 "
				}
				writeLine(prefix + capability)
			}
		case "STARTTLS":
			if !cfg.advertiseSTARTTLS {
				writeLine("502 command not implemented")
				continue
			}
			writeLine("220 ready to start TLS")
			tlsConn := tls.Server(plainConn, &tls.Config{Certificates: []tls.Certificate{certificate}})
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			plainConn = tlsConn
			upgraded = true
			// A fresh reader: buffered plaintext left none behind here, but
			// the TLS stream must start reading from the new socket.
			reader = bufio.NewReader(plainConn)
		case "AUTH":
			if !upgraded {
				writeLine("538 encryption required for requested authentication mechanism")
				continue
			}
			token := strings.TrimSpace(strings.TrimPrefix(argument, "PLAIN "))
			decoded, decErr := base64.StdEncoding.DecodeString(token)
			if decErr != nil {
				writeLine("501 malformed authentication token")
				continue
			}
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				writeLine("501 malformed authentication token")
				continue
			}
			if parts[1] == cfg.acceptUser && parts[2] == cfg.acceptPassword {
				writeLine("235 authentication successful")
			} else {
				writeLine("535 authentication failed")
			}
		case "MAIL":
			mail.from = argument
			writeLine("250 ok")
		case "RCPT":
			mail.to = append(mail.to, argument)
			writeLine("250 ok")
		case "DATA":
			writeLine("354 end with a lone dot")
			mail.tlsActive = upgraded
			var lines []string
			for {
				bodyLine, bodyErr := reader.ReadString('\n')
				if bodyErr != nil {
					return
				}
				trimmed := strings.TrimRight(bodyLine, "\r\n")
				if trimmed == "." {
					break
				}
				lines = append(lines, trimmed)
			}
			mail.data = strings.Join(lines, "\r\n")
			writeLine("250 queued as 1")
			s.messages <- mail
		case "QUIT":
			writeLine("221 bye")
			return
		default:
			writeLine("500 unrecognized command")
		}
	}
}

// selfSignedCertificateRelay mints an in-memory certificate valid for the
// loopback address the fake relay binds.
func selfSignedCertificateRelay() tls.Certificate {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test relay"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func waitForMail(t *testing.T, server *fakeSMTP) receivedMail {
	t.Helper()
	select {
	case mail := <-server.messages:
		return mail
	case <-time.After(3 * time.Second):
		t.Fatal("relay never received a message")
		return receivedMail{}
	}
}

func mailNotifyConfig(addr string) NotifyConfig {
	return NotifyConfig{
		SMTPAddr: addr,
		SMTPFrom: "vncshot@corp.invalid",
		SMTPTo:   []string{"secops@corp.invalid", "audit@corp.invalid"},
	}
}

func TestNotifyMailDeliversFindingsOverSTARTTLS(t *testing.T) {
	const password = "mail-pass-1234"
	server, addr := newFakeSMTP(t, fakeSMTPConfig{
		advertiseSTARTTLS: true,
		acceptUser:        "scanner",
		acceptPassword:    password,
	})
	nc := mailNotifyConfig(addr)
	nc.SMTPUser = "scanner"
	nc.SMTPPassword = password
	server.trust(t)

	if err := NotifyMail(context.Background(), nc, fixtureOutcome(), "9.9-test"); err != nil {
		t.Fatalf("NotifyMail: %v", err)
	}

	mail := waitForMail(t, server)
	if !strings.Contains(mail.data, "Subject: vncshot findings: ") {
		t.Errorf("message misses the subject header: %q", mail.data)
	}
	if !strings.Contains(mail.data, "From: vncshot@corp.invalid\r\n") {
		t.Errorf("message misses the From header: %q", mail.data)
	}
	if !strings.Contains(mail.data, "To: secops@corp.invalid, audit@corp.invalid\r\n") {
		t.Errorf("message misses the To header: %q", mail.data)
	}
	if !strings.Contains(mail.data, "Date: ") {
		t.Errorf("message misses the Date header: %q", mail.data)
	}
	for _, want := range []string{
		"vncshot 9.9-test run 20260101-120000",
		"passwordless=1 weak=1 expiring-certs=1",
		"New findings:",
		"10.0.0.1:5900 passwordless",
	} {
		if !strings.Contains(mail.data, want) {
			t.Errorf("message body misses %q: %q", want, mail.data)
		}
	}
	for _, secret := range []string{password, "hunter2"} {
		if strings.Contains(mail.data, secret) {
			t.Errorf("message leaks %q: %q", secret, mail.data)
		}
	}
}

func TestNotifyMailRejectsRelayWithoutSTARTTLS(t *testing.T) {
	server, addr := newFakeSMTP(t, fakeSMTPConfig{})
	nc := mailNotifyConfig(addr)

	err := NotifyMail(context.Background(), nc, fixtureOutcome(), "dev")
	if err == nil {
		t.Fatal("NotifyMail delivered findings to a plaintext relay")
	}
	if !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("error %q does not explain why STARTTLS was required", err)
	}
	select {
	case mail := <-server.messages:
		t.Errorf("relay queued a message anyway: %+v", mail)
	default:
	}
}

func TestNotifyMailAllowsPlaintextRelayOnlyWhenOptedIn(t *testing.T) {
	server, addr := newFakeSMTP(t, fakeSMTPConfig{})
	nc := mailNotifyConfig(addr)
	nc.SMTPNoTLS = true

	if err := NotifyMail(context.Background(), nc, fixtureOutcome(), "dev"); err != nil {
		t.Fatalf("NotifyMail with explicit -smtp-no-tls: %v", err)
	}
	mail := waitForMail(t, server)
	if mail.tlsActive {
		t.Error("session used TLS although the relay never offered STARTTLS")
	}
}

func TestNotifyMailRefusesCredentialsWithoutTLS(t *testing.T) {
	const password = "mail-pass-1234"
	server, addr := newFakeSMTP(t, fakeSMTPConfig{})
	nc := mailNotifyConfig(addr)
	nc.SMTPNoTLS = true
	nc.SMTPUser = "scanner"
	nc.SMTPPassword = password

	err := NotifyMail(context.Background(), nc, fixtureOutcome(), "dev")
	if err == nil {
		t.Fatal("NotifyMail authenticated over plaintext")
	}
	if strings.Contains(err.Error(), password) {
		t.Errorf("error leaks the auth password: %v", err)
	}
	select {
	case mail := <-server.messages:
		t.Errorf("relay queued a message anyway: %+v", mail)
	default:
	}
}

func TestNotifyMailRejectsBadCredentials(t *testing.T) {
	server, addr := newFakeSMTP(t, fakeSMTPConfig{
		advertiseSTARTTLS: true,
		acceptUser:        "scanner",
		acceptPassword:    "correct",
	})
	nc := mailNotifyConfig(addr)
	nc.SMTPUser = "scanner"
	nc.SMTPPassword = "wrong-pass"
	server.trust(t)

	err := NotifyMail(context.Background(), nc, fixtureOutcome(), "dev")
	if err == nil {
		t.Fatal("NotifyMail accepted bad authentication")
	}
	if strings.Contains(err.Error(), "wrong-pass") {
		t.Errorf("error leaks the auth password: %v", err)
	}
	select {
	case mail := <-server.messages:
		t.Errorf("relay queued a message anyway: %+v", mail)
	default:
	}
}

func TestNotifyMailValidatesConfig(t *testing.T) {
	// These fail before any network activity, so no dial target matters.
	tests := []struct {
		name string
		nc   NotifyConfig
		want string
	}{
		{
			name: "relay address without port",
			nc:   NotifyConfig{SMTPAddr: "relay.invalid", SMTPFrom: "a@b.c", SMTPTo: []string{"d@e.f"}},
			want: "host:port",
		},
		{
			name: "missing sender",
			nc:   NotifyConfig{SMTPAddr: "127.0.0.1:1", SMTPTo: []string{"d@e.f"}},
			want: "sender",
		},
		{
			name: "missing recipients",
			nc:   NotifyConfig{SMTPAddr: "127.0.0.1:1", SMTPFrom: "a@b.c"},
			want: "recipient",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NotifyMail(context.Background(), tt.nc, Outcome{}, "dev")
			if err == nil {
				t.Fatal("NotifyMail accepted an incomplete configuration")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}
