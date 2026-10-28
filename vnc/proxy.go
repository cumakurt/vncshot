package vnc

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SOCKS5 protocol constants (RFC 1928, RFC 1929).
const (
	socksVersion    = 5
	socksCmdConnect = 1
	socksAuthNone   = 0x00
	// socksAuthPassword is the RFC 1929 username/password subnegotiation.
	socksAuthPassword = 0x02
	// socksAuthNoAcceptable is the server's refusal to pick a method.
	socksAuthNoAcceptable = 0xFF

	socksATypIPv4   = 1
	socksATypDomain = 3
	socksATypIPv6   = 4

	// socksDefaultPort is a named constant so the default-port behaviour
	// is greppable.
	socksDefaultPort = "1080"
	// authVersion is the RFC 1929 username/password subnegotiation version.
	authVersion = 1
)

// proxyConfig is the parsed form of a socks5:// or socks5h:// proxy URL.
type proxyConfig struct {
	// addr is the proxy server as host:port, ready for a TCP dial.
	addr string
	// username and password are the RFC 1929 credentials; both empty when
	// no userinfo was supplied.
	username string
	password string
	// remoteResolve is true for socks5h:// and means the proxy resolves
	// the target hostname. socks5:// resolves locally instead.
	remoteResolve bool
}

// parseProxyURL parses exactly one of the accepted proxy URL forms:
//
//	socks5://[user:pass@]host[:port]
//	socks5h://[user:pass@]host[:port]
//
// socks5:// resolves the target hostname locally and sends the resolved IP
// to the proxy; socks5h:// asks the proxy to resolve, which matters when the
// scanner cannot resolve internal DNS names. The port defaults to 1080.
// Anything in the URL besides scheme, userinfo, host and port is rejected,
// so credential-looking pieces cannot hide behind a path or query string.
// Parse errors never echo the password.
func parseProxyURL(raw string) (proxyConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return proxyConfig{}, fmt.Errorf("parse proxy URL: %w", err)
	}

	var cfg proxyConfig
	switch strings.ToLower(u.Scheme) {
	case "socks5":
	case "socks5h":
		cfg.remoteResolve = true
	default:
		return proxyConfig{}, fmt.Errorf("unsupported proxy scheme %q: want socks5:// or socks5h://", u.Scheme)
	}

	// Only userinfo may carry credentials. A path, query or fragment is
	// neither on the accepted wire form nor safe to interpret.
	if u.Path != "" && u.Path != "/" {
		return proxyConfig{}, errors.New("proxy URL must not contain a path")
	}
	if u.RawQuery != "" {
		return proxyConfig{}, errors.New("proxy URL must not contain a query")
	}
	if u.Fragment != "" {
		return proxyConfig{}, errors.New("proxy URL must not contain a fragment")
	}

	host := u.Hostname()
	if host == "" {
		return proxyConfig{}, errors.New("proxy URL is missing a host")
	}

	port := u.Port()
	if port == "" {
		port = socksDefaultPort
	} else if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		// url.Parse accepts non-numeric ports; reject them here.
		return proxyConfig{}, fmt.Errorf("invalid proxy port %q", port)
	}
	cfg.addr = net.JoinHostPort(host, port)

	if u.User != nil && u.User.Username() != "" {
		cfg.username = u.User.Username()
		cfg.password, _ = u.User.Password()
	}
	return cfg, nil
}

// dialProxy connects to targetAddr through a SOCKS5 proxy and returns the
// established tunnel as a raw net.Conn. proxyURL must be socks5:// or
// socks5h:// (see parseProxyURL); network is the dial network for reaching
// the proxy itself, usually "tcp"; timeout bounds both reaching the proxy
// and the whole SOCKS5 handshake, which is the connect phase of the probe.
//
// On success the returned connection has no deadline set: the caller
// re-applies per-operation deadlines exactly as it does after a direct
// dial. On error the connection is closed.
func dialProxy(ctx context.Context, proxyURL, network, targetAddr string, timeout time.Duration) (net.Conn, error) {
	cfg, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, network, cfg.addr)
	if err != nil {
		return nil, fmt.Errorf("connect to proxy: %w", err)
	}

	// Fail the handshake when the caller cancels while we are blocked in
	// I/O, mirroring probeOnce's deadline discipline. The connect timeout
	// applies to the handshake too, bounded by any earlier ctx deadline.
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctxDeadline, ok := ctx.Deadline(); ok && (deadline.IsZero() || ctxDeadline.Before(deadline)) {
		deadline = ctxDeadline
	}
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Now())
	})
	defer stop()

	if err := cfg.handshake(conn, targetAddr, deadline); err != nil {
		conn.Close()
		return nil, err
	}

	// Clear the connect-phase deadline so later protocol deadlines govern
	// again, exactly like a direct dial leaves the connection deadline-free.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy handshake: %w", err)
	}
	return conn, nil
}

// handshake runs the SOCKS5 method negotiation, optional password
// authentication and the CONNECT request against a proxy connection whose
// socket already carries deadline (set by dialProxy).
func (cfg proxyConfig) handshake(conn net.Conn, targetAddr string, deadline time.Time) error {
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("proxy handshake: %w", err)
	}

	// Greeting: offer no-auth, plus username/password only when the URL has
	// credentials. Sending both lets the server choose between them; the
	// no-auth preference is expressed by offering it either way and by
	// honouring whatever the server picks.
	methods := []uint8{socksAuthNone, socksAuthPassword}
	if cfg.username == "" && cfg.password == "" {
		methods = methods[:1]
	}
	greeting := make([]byte, 0, 2+len(methods))
	greeting = append(greeting, socksVersion, byte(len(methods)))
	greeting = append(greeting, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("proxy greeting: %w", err)
	}

	r := bufio.NewReader(conn)

	ver, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("proxy greeting: %w", err)
	}
	if ver != socksVersion {
		return fmt.Errorf("proxy greeting: unexpected protocol version %d", ver)
	}
	chosen, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("proxy greeting: %w", err)
	}
	switch chosen {
	case socksAuthNone:
	case socksAuthPassword:
		if cfg.username == "" && cfg.password == "" {
			return errors.New("proxy requires authentication but no credentials were configured")
		}
		if err := cfg.authenticate(conn, r); err != nil {
			return err
		}
	default:
		return fmt.Errorf("proxy rejected every authentication method (server picked 0x%02x)", chosen)
	}

	if err := cfg.connect(conn, targetAddr); err != nil {
		return err
	}
	return cfg.connectReply(r)
}

// authenticate performs the RFC 1929 username/password subnegotiation. The
// password lives only on the wire: errors mention the outcome, never the
// credential.
func (cfg proxyConfig) authenticate(conn net.Conn, r *bufio.Reader) error {
	// RFC 1929 caps both fields at 255 bytes; exceeding them means the
	// request cannot be expressed, so fail instead of truncating.
	if len(cfg.username) > 255 || len(cfg.password) > 255 {
		return errors.New("proxy username or password exceeds 255 bytes")
	}
	req := make([]byte, 0, 3+len(cfg.username)+len(cfg.password))
	req = append(req, authVersion, byte(len(cfg.username)))
	req = append(req, cfg.username...)
	req = append(req, byte(len(cfg.password)))
	req = append(req, cfg.password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("proxy authentication: %w", err)
	}

	ver, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("proxy authentication: %w", err)
	}
	if ver != authVersion {
		return fmt.Errorf("proxy authentication: unexpected subnegotiation version %d", ver)
	}
	status, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("proxy authentication: %w", err)
	}
	if status != 0 {
		return errors.New("proxy authentication rejected")
	}
	return nil
}

// connect sends the CONNECT request. The target address is sent as an IP
// literal when known: socks5:// resolves hostnames locally so the proxy only
// sees an IP, socks5h:// sends the hostname as a domain for the proxy to
// resolve, and a hostname that cannot be resolved locally falls back to the
// domain form for the proxy to try.
func (cfg proxyConfig) connect(conn net.Conn, targetAddr string) error {
	host, portS, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("proxy connect: %w", err)
	}
	port, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return fmt.Errorf("proxy connect: invalid target port %q", portS)
	}

	payload, err := cfg.targetPayload(host)
	if err != nil {
		return fmt.Errorf("proxy connect: %w", err)
	}

	req := make([]byte, 0, 8+len(payload))
	req = append(req, socksVersion, socksCmdConnect, 0)
	req = append(req, payload...)
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("proxy connect: %w", err)
	}
	return nil
}

// targetPayload returns the ATYP byte and the address that follows it.
func (cfg proxyConfig) targetPayload(host string) ([]byte, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ipPayload(ip)
	}

	if cfg.remoteResolve {
		return domainPayload(host)
	}

	// socks5:// resolves locally; an unresolvable hostname falls back to
	// the domain form so the proxy can try its own resolver.
	ips, err := net.DefaultResolver.LookupIPAddr(context.Background(), host)
	if err != nil || len(ips) == 0 {
		return domainPayload(host)
	}
	// Prefer an IPv4 when the resolver offers both: a DNS64-synthesised
	// AAAA would make the proxy NAT64 the target instead of using plain
	// IPv4, which is rarely what the operator dialled from a scanner.
	for _, candidate := range ips {
		if candidate.IP.To4() != nil {
			return ipPayload(candidate.IP)
		}
	}
	return ipPayload(ips[0].IP)
}

// ipPayload encodes a Go IP for the ATYP=IPv4 / ATYP=IPv6 forms.
func ipPayload(ip net.IP) ([]byte, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return append([]byte{socksATypIPv4}, ip4...), nil
	}
	ip6 := ip.To16()
	if ip6 == nil {
		return nil, errors.New("invalid target address")
	}
	return append([]byte{socksATypIPv6}, ip6...), nil
}

// domainPayload encodes a hostname for ATYP=domain.
func domainPayload(host string) ([]byte, error) {
	if host == "" {
		return nil, errors.New("empty target hostname")
	}
	if len(host) > 255 {
		return nil, errors.New("target hostname exceeds 255 bytes")
	}
	payload := make([]byte, 0, 2+len(host))
	payload = append(payload, socksATypDomain, byte(len(host)))
	return append(payload, host...), nil
}

// connectReply reads the CONNECT reply and maps the server's response code
// onto a clear error.
func (cfg proxyConfig) connectReply(r *bufio.Reader) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return fmt.Errorf("proxy connect: %w", err)
	}
	if head[0] != socksVersion {
		return fmt.Errorf("proxy connect: unexpected protocol version %d", head[0])
	}
	// The bound address/port is protocol metadata needed only to stay
	// byte-aligned; the tunnel's endpoint is not needed to use it.
	if err := skipBoundAddr(r, head[3]); err != nil {
		return fmt.Errorf("proxy connect: %w", err)
	}
	if rep := head[1]; rep != 0 {
		return fmt.Errorf("proxy connect failed: %s", socksConnectErrorText(rep))
	}
	return nil
}

// socksConnectErrorText turns a SOCKS5 reply code into a stable message.
func socksConnectErrorText(rep uint8) string {
	switch rep {
	case 1:
		return "general SOCKS server failure"
	case 2:
		return "connection not allowed by ruleset"
	case 3:
		return "network unreachable"
	case 4:
		return "host unreachable"
	case 5:
		return "connection refused"
	case 6:
		return "TTL expired"
	case 7:
		return "command not supported"
	case 8:
		return "address type not supported"
	default:
		return fmt.Sprintf("unknown reply 0x%02x", rep)
	}
}

// skipBoundAddr consumes the BND.ADDR/SRV.PORT that follows a reply.
func skipBoundAddr(r *bufio.Reader, atyp uint8) error {
	switch atyp {
	case socksATypIPv4:
		_, err := io.ReadFull(r, make([]byte, 6)) // 4 addr + 2 port
		return err
	case socksATypIPv6:
		_, err := io.ReadFull(r, make([]byte, 18)) // 16 addr + 2 port
		return err
	case socksATypDomain:
		ln, err := r.ReadByte()
		if err != nil {
			return err
		}
		_, err = io.ReadFull(r, make([]byte, int(ln)+2)) // host + 2 port
		return err
	default:
		return fmt.Errorf("unknown address type %d in reply", atyp)
	}
}
