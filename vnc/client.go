package vnc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"image"
	"net"
	"strings"
	"time"
)

// Options controls a single RFB probe.
type Options struct {
	// Timeout bounds each network read/write. The caller is expected to
	// cancel ctx for an overall operation deadline.
	Timeout time.Duration
	// ConnectTimeout bounds the TCP connect attempt; 0 falls back to
	// Timeout. Keeping it separate lets a scan fail a dead host quickly
	// without shortening the budget for RFB reads on a live one.
	ConnectTimeout time.Duration
	// Shared requests a shared session so the probe does not disconnect
	// an existing viewer. Inventory scans should leave this enabled.
	Shared bool
	// Passwords are weak-password candidates tried against servers that
	// offer VNC authentication. Each candidate uses its own short-lived
	// connection so a server-side lockout is never triggered by hammering
	// one session, and the list stays under operator control.
	Passwords []Credential
	// LocalAddr binds the client socket to this source address. The zero
	// value leaves the choice to the operating system. It applies to every
	// dial the probe makes, including password-candidate connections. It
	// has no effect when a proxy is configured.
	LocalAddr net.IP
	// ProxyURL routes the probe through a SOCKS5 proxy:
	// socks5://[user:pass@]host[:port] or
	// socks5h://[user:pass@]host[:port]. With socks5:// the probe resolves
	// the target hostname locally and sends the resolved IP to the proxy;
	// with socks5h:// the proxy resolves the hostname, which matters when
	// the scanner cannot resolve internal DNS names. The port defaults to
	// 1080. Empty means direct connection.
	ProxyURL string
	// InsecureTLS states that certificate verification must not abort the
	// probe, which is also the default: the certificate is recorded and its
	// verification outcome is reported instead of being enforced. The field
	// exists so callers can express that intent explicitly; it does not
	// change the wire behaviour.
	InsecureTLS bool
	// skipEncrypted forces the clear-text security types. It is used for the
	// single retry after a failed encrypted negotiation, never by callers.
	skipEncrypted bool
}

// Result is what a probe learned about one endpoint.
type Result struct {
	// Passwordless is true when the server offered the "None" security
	// type and the session was established without credentials.
	Passwordless bool
	// AuthTypes lists the security types the server advertised, when the
	// protocol version provides a list (3.7+).
	AuthTypes []uint8
	// SecurityTypeNames is AuthTypes mapped through SecurityTypeName, in
	// the order the server advertised them.
	SecurityTypeNames []string
	// SecurityNotes explains the advertised types the probe cannot
	// complete, filled through SecurityTypeNote in advertisement order.
	// Types the probe supports, and types without a specific explanation,
	// are omitted, so this is usually shorter than SecurityTypeNames.
	SecurityNotes []string
	// Note is a stable, user-facing explanation for an otherwise
	// unexplained outcome, such as a server that demands a client
	// certificate or advertises only unsupported security types. It is
	// empty when the probe completed normally, and unlike Error it never
	// indicates a scan failure.
	Note string
	// TLS is true when at least one advertised security type provides an
	// encrypted channel. A server may offer both None and an encrypted
	// type; this stays true even though the probe prefers the weaker None.
	TLS bool
	// SawBanner is true once the RFB version banner was parsed. A probe that
	// fails later still proves the endpoint speaks RFB, which the reports
	// need in order to classify it as an RFB service with an error rather
	// than as a non-RFB port.
	SawBanner bool
	// TLSInfo describes the certificate and negotiated parameters when the
	// probe completed a TLS handshake, including for a VeNCrypt session. A
	// handshake that aborted because the server demands a client
	// certificate still records the certificate the server presented, so
	// this is non-nil for that partial handshake too. It is nil when no
	// server certificate was received at all.
	TLSInfo *TLSInfo
	// ServerName is the desktop name from ServerInit.
	ServerName string
	// RFBVersion is the version the server advertised in its banner, as
	// "major.minor" (for example "3.8"). This is the raw fingerprint input
	// before version selection, so a hint can tell a 3.3-era server from a
	// 3.8-era one even though both negotiate the same session version. It
	// is set as soon as the banner is parsed, including for probes that
	// fail later.
	RFBVersion string
	Width      int
	Height     int
	// AuthRequired is true when the server did not offer the "None"
	// security type.
	AuthRequired bool
	// Password is the weak password that authenticated the session, or ""
	// when authentication was not attempted or did not succeed.
	Password string
	// PasswordSource records where Password came from (SourceDefault or
	// SourceWordList).
	PasswordSource string
	// AuthLocked is true when the server rejected further attempts
	// (SecurityResult status 2). The caller must stop guessing.
	AuthLocked bool
	// Frame is the captured framebuffer. Nil when the server requires
	// authentication or capture failed.
	Frame image.Image
}

// errStopProbe signals that the probe learned everything it can without a
// valid credential. It is not a scan failure: the caller keeps the partial
// Result (RFB, auth types, server name).
var errStopProbe = errors.New("probe stopped before session init")

// ErrConnect marks a failure to establish the TCP connection, as opposed to
// a protocol error on an established connection. Callers can use
// errors.Is(err, ErrConnect) to tell a closed/filtered port from a service
// that answered with something unexpected.
var ErrConnect = errors.New("connect failed")

// connectError attaches ErrConnect to a dial error while preserving both the
// original error chain and its message. The message deliberately stays the
// dial error's text so it remains actionable, e.g.
// "connect: dial tcp 10.0.0.1:5900: i/o timeout".
type connectError struct{ err error }

func (e *connectError) Error() string { return e.err.Error() }

// Unwrap exposes both ErrConnect and the underlying dial error, so
// errors.Is/As can match either the sentinel or a syscall/net error.
func (e *connectError) Unwrap() []error { return []error{ErrConnect, e.err} }

// SecurityTypeName returns the human-readable name of an RFB security type.
// The numbers follow the IANA RFB security-type registry and the protocol
// specification's security handshake section:
// https://www.iana.org/assignments/rfb/
func SecurityTypeName(t uint8) string {
	switch t {
	case 1:
		return "None"
	case 2:
		return "VNC authentication"
	case 5:
		return "RA2"
	case 6:
		return "RA2ne"
	case 16:
		return "Tight"
	case 17:
		return "Ultra"
	case 18:
		return "TLS"
	case 19:
		return "VeNCrypt"
	case 20:
		return "SASL"
	case 21:
		return "MD5"
	case 22:
		return "xvp"
	case 30:
		return "Apple Remote Desktop"
	case 113:
		return "MSLogon II"
	default:
		return fmt.Sprintf("type %d", t)
	}
}

// SecurityTypeNote returns a short, stable explanation for a security type
// the probe cannot complete. It is empty for the types the probe supports
// (None, VNC authentication, TLS and VeNCrypt) and for values it has no
// specific explanation for, so callers can omit empty entries.
//
// The strings end up in reports; keep them short and do not reword them
// without treating that as a user-visible change.
func SecurityTypeNote(t uint8) string {
	switch t {
	case 5, 6:
		return "proprietary authentication (RealVNC)"
	case 16, 17:
		return "Tight/Ultra tunneling"
	case 20:
		return "SASL authentication"
	case 21:
		return "MD5 authentication (RealVNC)"
	case 22:
		return "xvp authentication"
	case 30:
		return "Apple Remote Desktop authentication"
	case 113:
		return "MSLogon II (UltraVNC)"
	default:
		return ""
	}
}

// securityTypeProvidesTLS reports whether the security type is defined to
// establish, or able to negotiate, an encrypted channel.
//
// Tight (16) and Ultra (17) are included on purpose: both can tunnel the RFB
// session inside TLS as a negotiated capability, so a server advertising them
// can offer confidentiality. The flag describes that capability, not a
// guarantee that every session actually uses TLS. SASL (20) is included for
// the same reason: its negotiated security layer can provide confidentiality.
func securityTypeProvidesTLS(t uint8) bool {
	switch t {
	case 5, 16, 17, 18, 19, 20:
		return true
	default:
		return false
	}
}

// errAuthRejected means the server refused the credential for this
// connection. It is the expected outcome for most word-list entries.
var errAuthRejected = errors.New("authentication rejected")

// errAuthLocked means the server has blocked further attempts.
var errAuthLocked = errors.New("authentication locked out")

// Probe dials addr, performs the RFB handshake and, when the server allows
// unauthenticated access (or a weak password is discovered), captures the
// current framebuffer. It never sends input, clipboard or power events: the
// session is read-only by construction and is closed as soon as the frame
// has been read.
//
// A server that requires authentication is reported through Result with
// Passwordless=false and a nil Frame; that is not an error.
func Probe(ctx context.Context, addr string, opts Options) (*Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = opts.Timeout
	}

	// Discovery attempt: learn the security types without sending any
	// credential. This keeps an inventory scan from looking like an attack
	// against hosts that are not in scope for password testing.
	attemptOpts := opts
	discovery, err := probeOnce(ctx, addr, attemptOpts, Credential{})
	if err != nil && errors.Is(err, ErrConnect) {
		return nil, err
	}
	if err != nil && len(discoveryTypes(discovery)) > 0 {
		// The security types were advertised but the encrypted negotiation
		// failed. Some appliances advertise VeNCrypt or TLS but cannot
		// complete it, or expect a subtype this client does not implement.
		// Retry once over the clear-text types so the host is still
		// inventoried, and use the same path for the password candidates.
		// A failure before the type list (dropped connection, truncated
		// banner) is left to the caller's own retry policy instead.
		retry, retryErr := probeOnce(ctx, addr, opts.withSkipEncrypted(), Credential{})
		if retryErr != nil {
			if retry != nil && retry.SawBanner && (discovery == nil || !discovery.SawBanner) {
				return retry, retryErr
			}
			return discovery, err
		}
		// The clear-text retry succeeded: the earlier failure is resolved.
		discovery, attemptOpts, err = retry, opts.withSkipEncrypted(), nil
	}
	if err != nil {
		// The handshake never reached a usable session state. Return the
		// partial result so the caller can still see the banner and the
		// advertised types alongside the error.
		return discovery, err
	}
	if discovery.Passwordless || !discovery.AuthRequired || len(opts.Passwords) == 0 {
		return discovery, nil
	}

	for _, cred := range opts.Passwords {
		if err := ctx.Err(); err != nil {
			return discovery, err
		}
		res, err := probeOnce(ctx, addr, attemptOpts, cred)
		if err != nil {
			// A network-level failure ends the attempt loop; the discovery
			// result still describes the endpoint.
			return discovery, nil
		}
		if res.Password != "" {
			return res, nil
		}
		if res.AuthLocked {
			// Surface the lockout: operators need to know the server is
			// blocking further attempts.
			discovery.AuthLocked = true
			break
		}
	}
	return discovery, nil
}

// probeOnce runs one complete RFB session. An empty credential means the
// caller only wants the security-type discovery step.
func probeOnce(ctx context.Context, addr string, opts Options, cred Credential) (*Result, error) {
	conn, err := dialTarget(ctx, addr, opts)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", &connectError{err: err})
	}
	defer conn.Close()

	// Fail the whole probe if the caller cancels, even while blocked in I/O.
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Now())
	})
	defer stop()

	c := &client{
		conn:       conn,
		r:          bufio.NewReaderSize(conn, 64*1024),
		w:          bufio.NewWriterSize(conn, 32*1024),
		opts:       opts,
		credential: cred,
		ctx:        ctx,
		serverName: serverNameFromAddr(addr),
		result:     &Result{},
	}

	if err := c.handshake(); err != nil {
		switch {
		case errors.Is(err, errStopProbe), errors.Is(err, errAuthRejected):
			// Not a scan failure: the endpoint is RFB but the credential
			// did not work (or none was sent).
			return c.result, nil
		case errors.Is(err, errAuthLocked):
			c.result.AuthLocked = true
			return c.result, nil
		default:
			// Keep whatever was learned (banner, security types) so the
			// caller can still classify the endpoint.
			return c.result, err
		}
	}
	return c.result, nil
}

// dialTarget establishes the probe's TCP connection, either directly or
// through the SOCKS5 proxy configured in opts.ProxyURL. With no proxy the
// behaviour is byte-for-byte the previous direct dial, including the
// LocalAddr binding.
func dialTarget(ctx context.Context, addr string, opts Options) (net.Conn, error) {
	if opts.ProxyURL != "" {
		// Note: LocalAddr does not apply to the proxy path; the source
		// address binding only concerns direct dials.
		return dialProxy(ctx, opts.ProxyURL, "tcp", addr, opts.ConnectTimeout)
	}
	dialer := net.Dialer{Timeout: opts.ConnectTimeout}
	if opts.LocalAddr != nil {
		dialer.LocalAddr = &net.TCPAddr{IP: opts.LocalAddr}
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

// discoveryTypes returns the advertised security types learned so far.
func discoveryTypes(res *Result) []uint8 {
	if res == nil {
		return nil
	}
	return res.AuthTypes
}

// withSkipEncrypted returns a copy of the options that forces the clear-text
// security types.
func (o Options) withSkipEncrypted() Options {
	o.skipEncrypted = true
	return o
}

type client struct {
	conn       net.Conn
	r          *bufio.Reader
	w          *bufio.Writer
	opts       Options
	credential Credential
	// skipEncrypted disables the TLS/VeNCrypt paths. It is used for a single
	// retry when an encrypted negotiation fails, so a server that advertises
	// TLS but cannot actually complete it is still inventoried over the
	// plain-text security type it also offers.
	skipEncrypted bool
	ctx           context.Context
	// serverName is the SNI name derived from the dial address, "" for an
	// IP literal.
	serverName string

	result      *Result
	version     [2]int
	pixelFormat pixelFormat
}

func (c *client) setDeadline() {
	c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
}

func (c *client) handshake() error {
	// 1. ProtocolVersion exchange.
	c.setDeadline()
	banner, err := readN(c.r, 12)
	if err != nil {
		return fmt.Errorf("read protocol version: %w", err)
	}
	sMajor, sMinor, err := parseVersion(banner)
	if err != nil {
		return err
	}
	major, minor := selectVersion(sMajor, sMinor)
	c.version = [2]int{major, minor}
	c.result.SawBanner = true
	c.result.RFBVersion = fmt.Sprintf("%d.%d", sMajor, sMinor)

	if err := c.write(formatVersion(major, minor)); err != nil {
		return fmt.Errorf("write protocol version: %w", err)
	}

	// 2. Security handshake. errStopProbe means "we know the security
	// posture but cannot continue without a valid credential"; that is a
	// finding, not a failure.
	if err := c.securityHandshake(); err != nil {
		if errors.Is(err, errStopProbe) {
			return err
		}
		return err
	}

	// 3. ClientInit / ServerInit.
	if err := c.initSession(); err != nil {
		return err
	}

	// 4. Capture the current framebuffer, then close. The only client
	// messages ever sent are SetPixelFormat, SetEncodings and
	// FramebufferUpdateRequest; no input, clipboard or control messages
	// are emitted, so the remote desktop cannot be altered.
	return c.capture()
}

func (c *client) write(b []byte) error {
	c.setDeadline()
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	return c.w.Flush()
}

// readSecurityTypes reads the security-type advertisement for the
// negotiated protocol version. RFB 3.3 announces exactly one U32 type;
// 3.7+ sends a counted list.
func (c *client) readSecurityTypes() ([]uint8, error) {
	major, minor := c.version[0], c.version[1]

	c.setDeadline()
	if major == 3 && minor <= 3 {
		raw, err := readU32(c.r)
		if err != nil {
			return nil, fmt.Errorf("read security type: %w", err)
		}
		if raw == uint32(secTypeInvalid) {
			return nil, c.readFailure("security negotiation")
		}
		if raw > 0xFF {
			return nil, fmt.Errorf("unsupported security type %d", raw)
		}
		return []uint8{uint8(raw)}, nil
	}

	n, err := readU8(c.r)
	if err != nil {
		return nil, fmt.Errorf("read security types: %w", err)
	}
	if n == 0 {
		return nil, c.readFailure("security negotiation")
	}
	types, err := readN(c.r, int(n))
	if err != nil {
		return nil, fmt.Errorf("read security type list: %w", err)
	}
	return types, nil
}

// securityHandshake selects a security type. It prefers "None" (the
// passwordless finding) and otherwise performs VNC authentication with the
// credential supplied for this connection.
func (c *client) securityHandshake() error {
	types, err := c.readSecurityTypes()
	if err != nil {
		return err
	}
	c.result.AuthTypes = append([]uint8(nil), types...)
	// Record the advertised capabilities before selecting a type: the
	// report must show that TLS was available even when the probe takes the
	// weaker None path.
	c.result.SecurityTypeNames = make([]string, len(types))
	for i, t := range types {
		c.result.SecurityTypeNames[i] = SecurityTypeName(t)
		if note := SecurityTypeNote(t); note != "" {
			c.result.SecurityNotes = append(c.result.SecurityNotes, note)
		}
		if securityTypeProvidesTLS(t) {
			c.result.TLS = true
		}
	}

	hasNone, hasVNC, hasVeNCrypt, hasTLS := false, false, false, false
	for _, t := range types {
		switch t {
		case secTypeNone:
			hasNone = true
		case secTypeVNCAuth:
			hasVNC = true
		case secTypeVeNCrypt:
			hasVeNCrypt = true
		case secTypeTLS:
			hasTLS = true
		}
	}
	if c.opts.skipEncrypted {
		// The encrypted negotiation already failed once for this endpoint;
		// fall back to the clear-text types it also advertises.
		hasVeNCrypt, hasTLS = false, false
	}

	// A server that offers both None and auth is treated as passwordless:
	// that is the weaker configuration and the one worth reporting.
	if hasNone {
		if err := c.selectSecurityType(secTypeNone); err != nil {
			return err
		}
		c.result.Passwordless = true
		return nil
	}

	c.result.AuthRequired = true

	// Encrypted transports are preferred over plain authentication: both
	// yield either a passwordless capture or a certificate that identifies
	// the endpoint, which plain VNC authentication cannot provide.
	switch {
	case hasVeNCrypt:
		if err := c.selectSecurityType(secTypeVeNCrypt); err != nil {
			return err
		}
		return c.veNCryptHandshake()

	case hasTLS:
		// Security type 18 is "None over TLS": no credential is needed
		// once the encrypted channel is established.
		if err := c.selectSecurityType(secTypeTLS); err != nil {
			return err
		}
		if err := c.upgradeTLS(); err != nil {
			return err
		}
		c.result.Passwordless = true
		// 3.8 sends SecurityResult for the None-equivalent flow; 3.3 and
		// 3.7 go straight to ClientInit.
		if c.version[0] == 3 && c.version[1] >= 8 {
			return c.readSecurityResult()
		}
		return nil

	case hasVNC:
		// Discovery connection: report the posture without sending a
		// password guess.
		if c.credential.Password == "" && c.credential.Source == "" {
			return errStopProbe
		}
		if err := c.selectSecurityType(secTypeVNCAuth); err != nil {
			return err
		}
		if err := c.vncAuthenticate(); err != nil {
			return err
		}
		return nil

	default:
		// Nothing on offer can be completed. Explain why, so the report
		// does not show an unexplained stop after the type list.
		c.result.Note = joinSecurityNotes(c.result.SecurityNotes)
		return errStopProbe
	}
}

// joinSecurityNotes renders the advertised explanations as one report note.
// Identical notes collapse so a server that advertises RA2 and RA2ne does not
// repeat the same sentence.
func joinSecurityNotes(notes []string) string {
	unique := make([]string, 0, len(notes))
	for _, note := range notes {
		seen := false
		for _, existing := range unique {
			if existing == note {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, note)
		}
	}
	return strings.Join(unique, ", ")
}

// selectSecurityType sends the chosen type, which only RFB 3.7+ expects,
// and consumes the SecurityResult that 3.8 always sends.
func (c *client) selectSecurityType(secType uint8) error {
	major, minor := c.version[0], c.version[1]
	legacy := major == 3 && minor <= 3

	if !legacy {
		if err := c.write([]byte{secType}); err != nil {
			return fmt.Errorf("select security type: %w", err)
		}
	}

	// Only RFB 3.8 sends SecurityResult for the None type. In 3.3 and 3.7
	// the server goes straight from the type selection to ClientInit, so
	// reading a result there blocks until the deadline expires and a
	// passwordless 3.7 server would be reported as a probe error.
	// VNC authentication always receives a challenge next, and its
	// SecurityResult is consumed by vncAuthenticate after the response.
	if secType != secTypeNone {
		return nil
	}
	if major == 3 && minor < 8 {
		return nil
	}
	return c.readSecurityResult()
}

// readSecurityResult consumes the U32 status. Status 1 is a wrong password
// (normal during a word-list run); status 2 means the server has locked the
// account out and the caller must stop guessing.
func (c *client) readSecurityResult() error {
	c.setDeadline()
	status, err := readU32(c.r)
	if err != nil {
		return fmt.Errorf("read security result: %w", err)
	}
	switch status {
	case 0:
		return nil
	case 1:
		// 3.8 may send a reason string after a failure; drain it so the
		// connection stays usable for a follow-up attempt on this socket.
		if c.version[1] >= 8 {
			c.drainFailureReason()
		}
		return errAuthRejected
	case 2:
		return errAuthLocked
	default:
		return fmt.Errorf("security result returned unknown status %d", status)
	}
}

// drainFailureReason reads and discards an optional failure reason. Errors
// are ignored on purpose: the rejection itself is the outcome we report.
func (c *client) drainFailureReason() {
	c.setDeadline()
	length, err := readU32(c.r)
	if err != nil || length > 4096 {
		return
	}
	_, _ = readN(c.r, int(length))
}

// vncAuthenticate performs the DES challenge-response exchange with the
// password bound to this connection.
func (c *client) vncAuthenticate() error {
	c.setDeadline()
	challenge, err := readN(c.r, 16)
	if err != nil {
		return fmt.Errorf("read authentication challenge: %w", err)
	}
	response, err := vncResponse(c.credential.Password, challenge)
	if err != nil {
		return err
	}
	if err := c.write(response); err != nil {
		return fmt.Errorf("write authentication response: %w", err)
	}
	if err := c.readSecurityResult(); err != nil {
		return err
	}
	c.result.Password = c.credential.Password
	c.result.PasswordSource = c.credential.Source
	return nil
}

// readFailure reads the server's failure reason (a U32 length followed by
// that many bytes) and turns it into an error.
func (c *client) readFailure(stage string) error {
	c.setDeadline()
	length, err := readU32(c.r)
	if err != nil {
		return fmt.Errorf("%s failed (no reason available)", stage)
	}
	// Reason strings are small; cap the allocation.
	if length > 4096 {
		return fmt.Errorf("%s failed (server reason too long)", stage)
	}
	reason, err := readN(c.r, int(length))
	if err != nil {
		return fmt.Errorf("%s failed (truncated reason)", stage)
	}
	return fmt.Errorf("%s failed: %s", stage, string(reason))
}

func (c *client) initSession() error {
	sharedFlag := byte(0)
	if c.opts.Shared {
		sharedFlag = 1
	}
	if err := c.write([]byte{sharedFlag}); err != nil {
		return fmt.Errorf("write ClientInit: %w", err)
	}

	c.setDeadline()
	width, err := readU16(c.r)
	if err != nil {
		return fmt.Errorf("read ServerInit width: %w", err)
	}
	height, err := readU16(c.r)
	if err != nil {
		return fmt.Errorf("read ServerInit height: %w", err)
	}
	pfRaw, err := readN(c.r, 16)
	if err != nil {
		return fmt.Errorf("read ServerInit pixel format: %w", err)
	}
	nameLen, err := readU32(c.r)
	if err != nil {
		return fmt.Errorf("read ServerInit name length: %w", err)
	}
	if nameLen > 1<<20 {
		return fmt.Errorf("server name length %d is unreasonable", nameLen)
	}
	name, err := readN(c.r, int(nameLen))
	if err != nil {
		return fmt.Errorf("read ServerInit name: %w", err)
	}

	if width == 0 || height == 0 {
		return fmt.Errorf("server reported empty framebuffer %dx%d", width, height)
	}
	if width > maxFramebufferSide || height > maxFramebufferSide {
		return fmt.Errorf("framebuffer %dx%d exceeds limit %d", width, height, maxFramebufferSide)
	}

	c.result.Width = int(width)
	c.result.Height = int(height)
	c.result.ServerName = string(name)

	// Keep the native format around only for diagnostics; capture uses
	// the format we explicitly request below.
	_ = parsePixelFormat(pfRaw)
	return nil
}

func parsePixelFormat(b []byte) pixelFormat {
	return pixelFormat{
		BitsPerPixel: b[0],
		Depth:        b[1],
		BigEndian:    b[2] != 0,
		TrueColor:    b[3] != 0,
		RedMax:       uint16(b[4])<<8 | uint16(b[5]),
		GreenMax:     uint16(b[6])<<8 | uint16(b[7]),
		BlueMax:      uint16(b[8])<<8 | uint16(b[9]),
		RedShift:     b[10],
		GreenShift:   b[11],
		BlueShift:    b[12],
	}
}

// capture requests a full raw frame and decodes it into an RGBA image.
func (c *client) capture() error {
	c.pixelFormat = desiredPixelFormat()

	// SetPixelFormat.
	pfBytes := c.pixelFormat.bytes()
	msg := make([]byte, 0, 20)
	msg = append(msg, msgSetPixelFormat, 0, 0, 0)
	msg = append(msg, pfBytes[:]...)
	if err := c.write(msg); err != nil {
		return fmt.Errorf("send SetPixelFormat: %w", err)
	}

	// SetEncodings: raw only.
	enc := make([]byte, 0, 8)
	enc = append(enc, msgSetEncodings, 0)
	enc = append(enc, 0, 1) // one encoding
	enc = append(enc, 0, 0, 0, byte(encRaw))
	if err := c.write(enc); err != nil {
		return fmt.Errorf("send SetEncodings: %w", err)
	}

	// FramebufferUpdateRequest: non-incremental, full screen.
	req := make([]byte, 0, 10)
	req = append(req, msgFramebufferUpdateRequest, 0) // 0 = full frame
	req = append(req, 0, 0, 0, 0)                     // x, y
	req = append(req, byte(c.result.Width>>8), byte(c.result.Width))
	req = append(req, byte(c.result.Height>>8), byte(c.result.Height))
	if err := c.write(req); err != nil {
		return fmt.Errorf("send FramebufferUpdateRequest: %w", err)
	}

	img := image.NewRGBA(image.Rect(0, 0, c.result.Width, c.result.Height))
	if err := c.readUpdate(img); err != nil {
		return err
	}
	c.result.Frame = img
	return nil
}

// readUpdate consumes server messages until one complete
// FramebufferUpdate has been decoded into img.
func (c *client) readUpdate(img *image.RGBA) error {
	for {
		c.setDeadline()
		msgType, err := readU8(c.r)
		if err != nil {
			return fmt.Errorf("read server message: %w", err)
		}

		switch msgType {
		case msgFramebufferUpdate:
			if err := c.readFramebufferUpdate(img); err != nil {
				return err
			}
			return nil

		case msgSetColorMapEntries:
			if err := skipColorMapEntries(c.r); err != nil {
				return fmt.Errorf("skip SetColorMapEntries: %w", err)
			}

		case msgBell:
			// No payload.

		case msgServerCutText:
			if err := skipServerCutText(c.r); err != nil {
				return fmt.Errorf("skip ServerCutText: %w", err)
			}

		default:
			return fmt.Errorf("unexpected server message type %d", msgType)
		}
	}
}

func (c *client) readFramebufferUpdate(img *image.RGBA) error {
	if _, err := readU8(c.r); err != nil { // padding
		return fmt.Errorf("read FramebufferUpdate padding: %w", err)
	}
	nRects, err := readU16(c.r)
	if err != nil {
		return fmt.Errorf("read rectangle count: %w", err)
	}

	gotPixels := false
	for i := 0; i < int(nRects); i++ {
		x, err := readU16(c.r)
		if err != nil {
			return fmt.Errorf("read rectangle x: %w", err)
		}
		y, err := readU16(c.r)
		if err != nil {
			return fmt.Errorf("read rectangle y: %w", err)
		}
		w, err := readU16(c.r)
		if err != nil {
			return fmt.Errorf("read rectangle width: %w", err)
		}
		h, err := readU16(c.r)
		if err != nil {
			return fmt.Errorf("read rectangle height: %w", err)
		}
		enc, err := readI32(c.r)
		if err != nil {
			return fmt.Errorf("read rectangle encoding: %w", err)
		}

		switch enc {
		case encRaw:
			if err := c.readRawRect(img, int(x), int(y), int(w), int(h)); err != nil {
				return err
			}
			gotPixels = true

		case encDesktopSize:
			// Pseudo-rectangle: no pixel payload. Dimensions already
			// constrain the image, so a mid-update resize is ignored.

		case encLastRect:
			// Signals the end of the rectangle list.
			i = int(nRects)

		case encCopyRect:
			return fmt.Errorf("server used CopyRect encoding; raw was the only requested encoding")

		default:
			return fmt.Errorf("unsupported rectangle encoding %d", enc)
		}
	}

	if !gotPixels {
		return fmt.Errorf("framebuffer update contained no pixel data")
	}
	return nil
}

func (c *client) readRawRect(img *image.RGBA, x, y, w, h int) error {
	if w < 0 || h < 0 || x < 0 || y < 0 {
		return fmt.Errorf("invalid rectangle %d,%d %dx%d", x, y, w, h)
	}
	if x+w > img.Bounds().Dx() || y+h > img.Bounds().Dy() {
		return fmt.Errorf("rectangle %d,%d %dx%d exceeds framebuffer %v", x, y, w, h, img.Bounds())
	}

	bpp := c.pixelFormat.bytesPerPixel()
	if bpp < 3 {
		return fmt.Errorf("refusing to decode %d-byte pixels", bpp)
	}
	size := w * h * bpp
	if size < 0 || (w != 0 && size/w/bpp != h) {
		return fmt.Errorf("rectangle %dx%d overflows size calculation", w, h)
	}

	buf, err := readN(c.r, size)
	if err != nil {
		return fmt.Errorf("read raw pixels %dx%d: %w", w, h, err)
	}

	// Pixels follow the format we requested in SetPixelFormat: 32bpp
	// 0x00RRGGBB little-endian, so the wire bytes are B,G,R,pad.
	srcBpp := bpp
	stride := img.Stride
	for row := 0; row < h; row++ {
		srcOff := row * w * srcBpp
		dstOff := (y+row)*stride + x*4
		for col := 0; col < w; col++ {
			s := srcOff + col*srcBpp
			d := dstOff + col*4
			img.Pix[d+0] = buf[s+2] // R
			img.Pix[d+1] = buf[s+1] // G
			img.Pix[d+2] = buf[s+0] // B
			img.Pix[d+3] = 255
		}
	}
	return nil
}

func skipColorMapEntries(r *bufio.Reader) error {
	if _, err := readU8(r); err != nil { // padding
		return err
	}
	if _, err := readU16(r); err != nil { // first colour
		return err
	}
	n, err := readU16(r)
	if err != nil {
		return err
	}
	// Each colour is 3x U16.
	_, err = readN(r, int(n)*6)
	return err
}

func skipServerCutText(r *bufio.Reader) error {
	if _, err := readN(r, 3); err != nil { // padding
		return err
	}
	n, err := readU32(r)
	if err != nil {
		return err
	}
	if n > 1<<20 {
		return fmt.Errorf("clipboard text length %d is unreasonable", n)
	}
	_, err = readN(r, int(n))
	return err
}
