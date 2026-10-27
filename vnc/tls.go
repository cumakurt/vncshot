package vnc

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSInfo describes the TLS session and the certificate a server presented.
//
// The probe records this information even when the certificate is not
// trusted: embedded VNC appliances routinely use self-signed certificates,
// and the purpose of the inventory is to report that fact, not to enforce
// trust. Verified therefore states the outcome of a separate validation
// against the system roots instead of hiding it behind InsecureSkipVerify.
type TLSInfo struct {
	// Version is the negotiated protocol version, e.g. "TLS 1.2".
	Version string
	// CipherSuite is the negotiated cipher suite name.
	CipherSuite string
	// Subject and Issuer are the textual distinguished names.
	Subject string
	Issuer  string
	// NotBefore and NotAfter bound the certificate's validity period.
	NotBefore time.Time
	NotAfter  time.Time
	// DNSNames lists the subject alternative names of type DNS.
	DNSNames []string
	// Fingerprint is the SHA-256 digest of the DER certificate, formatted
	// as uppercase hex bytes separated by colons.
	Fingerprint string
	// SelfSigned is true when the certificate's subject and issuer match.
	SelfSigned bool
	// Expired is true when the validity period has already ended.
	Expired bool
	// Verified is true only when the chain validated against the system
	// root pool. A self-signed certificate therefore reports false unless
	// the same certificate happens to be installed as a root.
	Verified bool
	// ServerName is the SNI/verification name used for the handshake, or
	// "" when the endpoint was an IP literal and no SNI was sent.
	ServerName string
}

// VeNCryptSubtypeName returns the human-readable name of a VeNCrypt subtype.
// SecurityTypeName deliberately stays limited to RFB wire security types,
// which are one byte wide and cannot represent these values.
func VeNCryptSubtypeName(t uint32) string {
	switch t {
	case 256:
		return "Plain"
	case vencryptSubtypeTLSNone:
		return "TLSNone"
	case vencryptSubtypeTLSVnc:
		return "TLSVnc"
	case 259:
		return "TLSPlain"
	case vencryptSubtypeX509None:
		return "X509None"
	case vencryptSubtypeX509Vnc:
		return "X509Vnc"
	case 262:
		return "X509Plain"
	case 263:
		return "TLSSASL"
	case 264:
		return "X509SASL"
	case 265:
		return "Ident"
	case 266:
		return "TLSIdent"
	case 267:
		return "X509Ident"
	default:
		return fmt.Sprintf("subtype %d", t)
	}
}

// tlsConfig builds the client configuration for a probe handshake.
//
// InsecureSkipVerify is always enabled, deliberately. The probe never relies
// on the encrypted channel for confidentiality or authenticity: it records
// the certificate, and Verified reports whether the chain would have passed
// validation against the system roots. Aborting on an untrusted certificate
// would make the common self-signed appliance unreportable, which defeats the
// purpose of the scan. Options.InsecureTLS is an explicit statement of that
// same intent; it does not weaken or strengthen this behaviour.
func tlsConfig(serverName string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // certificate is recorded, not trusted; see comment above
		ServerName:         serverName,
		// Old embedded appliances still negotiate TLS 1.0/1.1. The probe
		// reports the negotiated version, so accepting the handshake is
		// more useful than refusing to look at the endpoint.
		MinVersion: tls.VersionTLS10,
	}
}

// serverNameFromAddr returns the host part of addr when it is a DNS name,
// and "" for an IP literal. TLS forbids sending an IP address as SNI and the
// probe does not verify hostnames, so an IP yields no name.
func serverNameFromAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// upgradeTLS performs the TLS handshake on the current connection and replaces
// the buffered reader/writer with ones bound to the encrypted stream. All
// later RFB traffic, including a VNC authentication exchange, uses TLS.
func (c *client) upgradeTLS() error {
	// The protocol handshake that precedes TLS must be fully consumed: any
	// buffered plaintext here would otherwise be silently dropped and
	// desynchronise the encrypted stream.
	if n := c.r.Buffered(); n != 0 {
		return fmt.Errorf("TLS upgrade with %d buffered plaintext byte(s)", n)
	}

	tlsConn := tls.Client(c.conn, tlsConfig(c.serverName))
	// The handshake is network I/O and must be bounded like every other
	// read; the context callback installed in probeOnce also stays active.
	c.setDeadline()
	if err := tlsConn.HandshakeContext(c.ctx); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}

	c.adoptTLS(tlsConn)
	return nil
}

// errClientCertRequired means the server aborted the handshake because it
// demands a client certificate. It is a finding, not a scan failure: the
// server certificate it presented before aborting is still reported.
var errClientCertRequired = errors.New("server requires a client certificate")

// upgradeTLSForX509 is upgradeTLS for the VeNCrypt X509 subtypes. Their flows
// are identical to TLSNone/TLSVnc, except that the server may require a
// client certificate the probe does not have.
//
// The returned bool reports whether the server asked for a client
// certificate during the handshake. That matters because TLS 1.3 finishes the
// client side of the handshake before the server evaluates the (empty)
// client certificate, so a rejection there arrives as an alert on the first
// read rather than as a handshake error. The caller uses this flag to
// recognise that case without interpreting error text.
//
// A handshake that fails after the server has sent its own certificate is
// reported as errClientCertRequired when a peer certificate is present: the
// certificate arrives before the client-certificate check, so it is
// available even though the handshake failed.
func (c *client) upgradeTLSForX509() (bool, error) {
	if n := c.r.Buffered(); n != 0 {
		return false, fmt.Errorf("TLS upgrade with %d buffered plaintext byte(s)", n)
	}

	cfg := tlsConfig(c.serverName)
	clientCertRequested := false
	cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		clientCertRequested = true
		// No client certificate is available; an empty certificate is what
		// the TLS stack sends when no callback is configured.
		return &tls.Certificate{}, nil
	}

	tlsConn := tls.Client(c.conn, cfg)
	c.setDeadline()
	if err := tlsConn.HandshakeContext(c.ctx); err != nil {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			return false, fmt.Errorf("TLS handshake: %w", err)
		}
		// The handshake did not complete, so the stream is unusable, but
		// the certificate and cipher negotiated so far are evidence.
		c.result.TLSInfo = tlsInfoFromState(state, c.serverName)
		c.result.TLS = true
		return false, errClientCertRequired
	}

	c.adoptTLS(tlsConn)
	return clientCertRequested, nil
}

// adoptTLS installs a completed TLS handshake and records its posture.
func (c *client) adoptTLS(tlsConn *tls.Conn) {
	c.conn = tlsConn
	c.r = bufio.NewReaderSize(tlsConn, 64*1024)
	c.w = bufio.NewWriterSize(tlsConn, 32*1024)

	c.result.TLSInfo = tlsInfoFromState(tlsConn.ConnectionState(), c.serverName)
	c.result.TLS = true
}

// tlsInfoFromState converts a completed handshake into the reported posture.
// It never fails: missing certificate data is left zero-valued, and the
// verification outcome is expressed through Verified.
func tlsInfoFromState(state tls.ConnectionState, serverName string) *TLSInfo {
	info := &TLSInfo{
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ServerName:  serverName,
	}
	if len(state.PeerCertificates) == 0 {
		return info
	}

	cert := state.PeerCertificates[0]
	info.Subject = cert.Subject.String()
	info.Issuer = cert.Issuer.String()
	info.NotBefore = cert.NotBefore
	info.NotAfter = cert.NotAfter
	info.DNSNames = append([]string(nil), cert.DNSNames...)
	info.Fingerprint = certificateFingerprint(cert.Raw)
	info.SelfSigned = bytes.Equal(cert.RawSubject, cert.RawIssuer)
	info.Expired = !cert.NotAfter.IsZero() && time.Now().After(cert.NotAfter)
	info.Verified = certificateVerified(cert, state.PeerCertificates[1:])
	return info
}

// certificateFingerprint formats the SHA-256 digest of a DER certificate.
func certificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	var b strings.Builder
	b.Grow(len(sum)*3 - 1)
	for i, v := range sum {
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02X", v)
	}
	return b.String()
}

// certificateVerified validates the peer chain against the system roots.
// DNSName is left empty on purpose: the probe reports chain trust, not whether
// the certificate matches the scanned address. Intermediates come from the
// chain the server sent.
func certificateVerified(leaf *x509.Certificate, chain []*x509.Certificate) bool {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain {
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err == nil
}

// veNCryptSubtypes lists the subtypes the probe can attempt, strongest
// first. The X509 variants come last: they are the same flows, but a server
// may reject them for lack of a client certificate.
var veNCryptSubtypes = []uint32{
	vencryptSubtypeTLSNone,
	vencryptSubtypeTLSVnc,
	vencryptSubtypeX509None,
	vencryptSubtypeX509Vnc,
}

// chooseVeNCryptSubtype picks the strongest subtype the probe can complete.
// TLSNone is preferred because it needs neither a credential nor a client
// certificate and therefore yields a capture. TLSVnc follows when the server
// does not offer TLSNone, and the X509 variants are the last resort.
func chooseVeNCryptSubtype(offered []uint32) (uint32, bool) {
	for _, want := range veNCryptSubtypes {
		for _, got := range offered {
			if got == want {
				return want, true
			}
		}
	}
	return 0, false
}

// veNCryptHandshake performs the VeNCrypt subtype negotiation and then the
// subtype-specific authentication. The security type itself has already been
// selected by the caller.
//
// Version 0.2 (the only version worth targeting in practice) has the server
// send its version, then the client replies, then the server acknowledges and
// publishes the subtype list. Version 0.1 is handled as a best-effort
// fallback in which the client proposes the subtypes and the server chooses.
func (c *client) veNCryptHandshake() error {
	c.setDeadline()
	raw, err := readN(c.r, 2)
	if err != nil {
		return fmt.Errorf("read VeNCrypt version: %w", err)
	}
	serverMajor, serverMinor := raw[0], raw[1]
	if serverMajor != 0 || serverMinor == 0 {
		return fmt.Errorf("unsupported VeNCrypt version %d.%d", serverMajor, serverMinor)
	}
	minor := serverMinor
	if minor > 2 {
		minor = 2
	}

	if err := c.write([]byte{0, minor}); err != nil {
		return fmt.Errorf("write VeNCrypt version: %w", err)
	}
	c.setDeadline()
	ack, err := readU8(c.r)
	if err != nil {
		return fmt.Errorf("read VeNCrypt version ack: %w", err)
	}
	if ack != 0 {
		return fmt.Errorf("VeNCrypt version 0.%d rejected", minor)
	}

	var subtype uint32
	if minor == 1 {
		// 0.1: the client publishes its supported subtypes and the
		// server picks one.
		if err := c.write([]byte{byte(len(veNCryptSubtypes))}); err != nil {
			return fmt.Errorf("write VeNCrypt subtype list: %w", err)
		}
		for _, st := range veNCryptSubtypes {
			if err := writeU32(c.w, st); err != nil {
				return fmt.Errorf("write VeNCrypt subtype: %w", err)
			}
		}
		if err := c.w.Flush(); err != nil {
			return fmt.Errorf("write VeNCrypt subtype list: %w", err)
		}
		c.setDeadline()
		subtype, err = readU32(c.r)
		if err != nil {
			return fmt.Errorf("read VeNCrypt subtype: %w", err)
		}
	} else {
		c.setDeadline()
		n, err := readU8(c.r)
		if err != nil {
			return fmt.Errorf("read VeNCrypt subtype count: %w", err)
		}
		if n == 0 {
			return errStopProbe
		}
		offered := make([]uint32, 0, int(n))
		for i := 0; i < int(n); i++ {
			st, err := readU32(c.r)
			if err != nil {
				return fmt.Errorf("read VeNCrypt subtype list: %w", err)
			}
			offered = append(offered, st)
		}

		var ok bool
		subtype, ok = chooseVeNCryptSubtype(offered)
		if !ok {
			// The server only offers subtypes whose handshake this probe
			// does not implement (X509*, SASL, Plain, ...). Report the
			// posture and stop without attempting a guess.
			return errStopProbe
		}
		if err := writeU32(c.w, subtype); err != nil {
			return fmt.Errorf("write VeNCrypt subtype: %w", err)
		}
		if err := c.w.Flush(); err != nil {
			return fmt.Errorf("write VeNCrypt subtype: %w", err)
		}

		c.setDeadline()
		subAck, err := readU8(c.r)
		if err != nil {
			return fmt.Errorf("read VeNCrypt subtype ack: %w", err)
		}
		if subAck != 1 {
			return fmt.Errorf("VeNCrypt subtype %s rejected", VeNCryptSubtypeName(subtype))
		}
	}

	return c.completeVeNCrypt(subtype)
}

// completeVeNCrypt runs the handshake for an accepted TLS-based subtype.
func (c *client) completeVeNCrypt(subtype uint32) error {
	x509Subtype := subtype == vencryptSubtypeX509None || subtype == vencryptSubtypeX509Vnc
	switch subtype {
	case vencryptSubtypeTLSNone, vencryptSubtypeTLSVnc, vencryptSubtypeX509None, vencryptSubtypeX509Vnc:
	default:
		return errStopProbe
	}

	// This is a protocol fact independent of the subtype: the negotiated
	// session is encrypted even when the certificate is untrusted.
	c.result.SecurityTypeNames = append(c.result.SecurityTypeNames,
		"VeNCrypt/"+VeNCryptSubtypeName(subtype))
	c.result.TLS = true
	c.result.AuthRequired = true

	clientCertRequested := false
	if x509Subtype {
		requested, err := c.upgradeTLSForX509()
		if err != nil {
			if errors.Is(err, errClientCertRequired) {
				return c.stopForClientCertificate(subtype)
			}
			return err
		}
		clientCertRequested = requested
	} else if err := c.upgradeTLS(); err != nil {
		return err
	}

	err := c.finishVeNCrypt(subtype)
	if x509Subtype && clientCertRequested && isProtocolFailure(err) {
		// TLS 1.3: the client side of the handshake succeeded before the
		// server rejected our empty client certificate, so the alert
		// arrives on the first read. The server did ask for a
		// certificate, which makes this the same finding as a failed
		// handshake.
		return c.stopForClientCertificate(subtype)
	}
	return err
}

// stopForClientCertificate records the outcome of an X509 subtype whose
// server demands a client certificate. The certificate and cipher from the
// partial session are already in the result; the note explains the stop.
func (c *client) stopForClientCertificate(subtype uint32) error {
	c.result.AuthRequired = true
	c.result.Note = "client certificate required (VeNCrypt/" +
		VeNCryptSubtypeName(subtype) + ")"
	return errStopProbe
}

// isProtocolFailure reports whether err is a failure to exchange RFB
// messages, as opposed to the credential findings the probe reports without
// an error.
func isProtocolFailure(err error) bool {
	if err == nil {
		return false
	}
	return !errors.Is(err, errStopProbe) &&
		!errors.Is(err, errAuthRejected) &&
		!errors.Is(err, errAuthLocked)
}

// finishVeNCrypt runs the subtype-specific authentication after the
// encrypted channel is established.
func (c *client) finishVeNCrypt(subtype uint32) error {
	switch subtype {
	case vencryptSubtypeTLSNone, vencryptSubtypeX509None:
		// "None over TLS": no credential, so the probe can capture. Mirror
		// the plain None flow, including the 3.8 SecurityResult.
		c.result.AuthRequired = false
		c.result.Passwordless = true
		if c.version[0] == 3 && c.version[1] >= 8 {
			return c.readSecurityResult()
		}
		return nil
	default: // vencryptSubtypeTLSVnc, vencryptSubtypeX509Vnc
		if c.credential.Password == "" && c.credential.Source == "" {
			// Discovery connection: the certificate is recorded, but a
			// challenge cannot be answered without a candidate.
			return errStopProbe
		}
		return c.vncAuthenticate()
	}
}
