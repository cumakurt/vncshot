package vnc

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"image"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const proxyTestTimeout = 2 * time.Second

// socksSpec configures the in-process SOCKS5 server.
type socksSpec struct {
	// method is what the server picks during method selection:
	// socksAuthNone, socksAuthPassword or socksAuthNoAcceptable.
	method uint8
	// expectedUser and expectedPass are the answer sheet for the password
	// subnegotiation; the server rejects any other pair.
	expectedUser, expectedPass string
	// rep is the CONNECT reply code; 0 makes the server relay to the
	// route target, anything else makes it report the error and close.
	rep uint8
	// stall keeps the connection open but silent after the greeting, to
	// exercise the handshake deadline.
	stall bool
	// route maps a CONNECT target host to a backend "host:port" the
	// server relays to.
	route map[string]string
}

// socksRecord holds what the fake proxy observed. The handler goroutine
// writes it; tests read it only after waitSocksDone, so plain fields are
// race-free.
type socksRecord struct {
	done chan struct{}

	greetingMethods []byte
	authSent        bool
	authUser        string
	authAccepted    bool
	atyp            uint8
	targetHost      string
	targetPort      uint16
	// tunnelPrefix holds the first sniffLen bytes the tunnel carried from
	// the client towards the target. For an RFB 3.8 session those are the
	// 12-byte ProtocolVersion reply, the security-type selection byte and
	// the ClientInit shared flag.
	tunnelPrefix []byte
}

// sniffLen covers the client's RFB version reply, the security-type
// selection and the ClientInit: the bytes the tests want to inspect.
const sniffLen = 16

// sniffReader records the first sniffLen bytes that pass through while
// forwarding everything unchanged.
type sniffReader struct {
	src io.Reader
	buf [sniffLen]byte
	n   int
}

func (s *sniffReader) Read(p []byte) (int, error) {
	n, err := s.src.Read(p)
	if n > 0 {
		if free := len(s.buf) - s.n; free > 0 {
			take := n
			if take > free {
				take = free
			}
			copy(s.buf[s.n:], p[:take])
			s.n += take
		}
	}
	return n, err
}

func (s *sniffReader) prefix() []byte { return s.buf[:s.n] }

// startFakeSOCKS starts a loopback SOCKS5 server that handles one accepted
// connection per use (tests use one probe per server) and returns its dial
// address plus the observation record.
func startFakeSOCKS(t *testing.T, spec socksSpec) (addr string, rec *socksRecord) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	rec = &socksRecord{done: make(chan struct{})}

	t.Cleanup(func() {
		ln.Close()
		select {
		case <-rec.done:
		case <-time.After(proxyTestTimeout + time.Second):
			t.Error("fake SOCKS server did not finish")
		}
	})

	go func() {
		defer close(rec.done)

		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(proxyTestTimeout * 3))
		r := bufio.NewReader(conn)

		// RFC 1928 section 3: greeting.
		ver, _ := r.ReadByte()
		nMethods, _ := r.ReadByte()
		methods, _ := readN(r, int(nMethods))
		if ver != socksVersion {
			return
		}
		rec.greetingMethods = append([]byte(nil), methods...)
		if _, err := conn.Write([]byte{socksVersion, spec.method}); err != nil {
			return
		}

		if spec.stall {
			// Stay silent so the client's handshake deadline fires. Keep
			// the wait short enough for the cleanup deadline.
			time.Sleep(proxyTestTimeout)
			return
		}

		// RFC 1929 section 2: username/password, when selected.
		if spec.method == socksAuthPassword {
			ver, _ := r.ReadByte()
			ulen, _ := r.ReadByte()
			userBytes, _ := readN(r, int(ulen))
			plen, _ := r.ReadByte()
			passBytes, _ := readN(r, int(plen))
			accept := ver == authVersion &&
				string(userBytes) == spec.expectedUser &&
				string(passBytes) == spec.expectedPass
			status := byte(1)
			if accept {
				status = 0
			}
			rec.authSent = true
			rec.authUser = string(userBytes)
			rec.authAccepted = accept
			if _, err := conn.Write([]byte{authVersion, status}); err != nil || !accept {
				return
			}
		}

		// RFC 1928 section 4: CONNECT.
		head := make([]byte, 4)
		if _, err := io.ReadFull(r, head); err != nil {
			return
		}
		if head[0] != socksVersion || head[1] != socksCmdConnect {
			return
		}
		rec.atyp = head[3]
		switch head[3] {
		case socksATypIPv4:
			b := make([]byte, 4)
			_, _ = io.ReadFull(r, b)
			rec.targetHost = net.IP(b).String()
		case socksATypIPv6:
			b := make([]byte, 16)
			_, _ = io.ReadFull(r, b)
			rec.targetHost = net.IP(b).String()
		case socksATypDomain:
			nameLen, _ := r.ReadByte()
			b := make([]byte, nameLen)
			_, _ = io.ReadFull(r, b)
			rec.targetHost = string(b)
		default:
			return
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(r, portBytes); err != nil {
			return
		}
		rec.targetPort = binary.BigEndian.Uint16(portBytes)

		// Reply. The bound address contents are irrelevant to the client;
		// a fixed 127.0.0.1:0 keeps the reply frame legal.
		bound := []byte{socksVersion, spec.rep, 0, socksATypIPv4, 127, 0, 0, 1, 0, 0}
		if _, err := conn.Write(bound); err != nil || spec.rep != 0 {
			return
		}

		// Success: relay to the routed backend through a sniffer so the tests
		// can inspect the tunnelled handshake bytes while data flows freely.
		backend, ok := spec.route[rec.targetHost]
		if !ok {
			return
		}
		targetConn, err := net.DialTimeout("tcp", backend, proxyTestTimeout)
		if err != nil {
			return
		}
		defer targetConn.Close()
		_ = targetConn.SetDeadline(time.Now().Add(proxyTestTimeout * 3))

		sniffer := &sniffReader{src: conn}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = io.Copy(conn, targetConn) }()
		go func() {
			defer wg.Done()
			if _, err := io.Copy(targetConn, sniffer); err == nil {
				// The client hung up: half-close so backends relying on
				// EOF (like the echo target) can finish and close too.
				if tc, ok := targetConn.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
			}
		}()
		wg.Wait()
		rec.tunnelPrefix = sniffer.prefix()
	}()

	return ln.Addr().String(), rec
}

// waitSocksDone blocks until the fake proxy handler finished, so record
// reads are synchronised with the handler goroutine.
func waitSocksDone(t *testing.T, rec *socksRecord) {
	t.Helper()
	select {
	case <-rec.done:
	case <-time.After(proxyTestTimeout + time.Second):
		t.Error("fake SOCKS server did not finish")
	}
}

// startRFBTarget runs a minimal RFB 3.8 server flow on loopback: banner,
// None-only security types, SecurityResult, ClientInit, ServerInit, the
// capture messages and one solid red 4x3 raw frame. It returns its address.
func startRFBTarget(t *testing.T, name string) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		select {
		case <-done:
		case <-time.After(proxyTestTimeout + time.Second):
			t.Error("fake RFB target did not finish")
		}
	})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(proxyTestTimeout * 3))
		r := bufio.NewReader(conn)
		w := bufio.NewWriter(conn)

		write := func(b []byte) bool {
			if _, err := w.Write(b); err != nil {
				return false
			}
			return w.Flush() == nil
		}
		u16 := func(v uint16) []byte {
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], v)
			return b[:]
		}

		if !write([]byte("RFB 003.008\n")) {
			return
		}
		if _, err := io.ReadFull(r, make([]byte, 12)); err != nil { // client version
			return
		}
		// Security types: None only; then the selection, the SecurityResult
		// RFB 3.8 always sends for None, and the ClientInit.
		if !write([]byte{1, 1}) {
			return
		}
		if sel, err := r.ReadByte(); err != nil || sel != 1 {
			return
		}
		if !write([]byte{0, 0, 0, 0}) { // SecurityResult OK
			return
		}
		if _, err := io.ReadFull(r, make([]byte, 1)); err != nil { // ClientInit
			return
		}
		init := make([]byte, 0, 2+2+16+4+len(name))
		init = append(init, u16(4)...)
		init = append(init, u16(3)...)
		init = append(init, make([]byte, 16)...) // pixel format placeholder
		var nameLen [4]byte
		binary.BigEndian.PutUint32(nameLen[:], uint32(len(name)))
		init = append(init, nameLen[:]...)
		init = append(init, name...)
		if !write(init) {
			return
		}
		// Capture: SetPixelFormat (20 bytes), SetEncodings (8),
		// FramebufferUpdateRequest (10).
		if _, err := io.ReadFull(r, make([]byte, 20+8+10)); err != nil {
			return
		}
		frame := make([]byte, 0, 2+2+12+4*3*4)
		frame = append(frame, 0, 0) // FramebufferUpdate + padding
		frame = append(frame, u16(1)...)
		frame = append(frame, u16(0)...)
		frame = append(frame, u16(0)...)
		frame = append(frame, u16(4)...)
		frame = append(frame, u16(3)...)
		frame = append(frame, 0, 0, 0, 0) // raw encoding
		for i := 0; i < 4*3; i++ {
			frame = append(frame, 0, 0, 255, 0) // B,G,R,pad: red
		}
		_ = write(frame)
	}()

	return ln.Addr().String()
}

// startEchoTarget accepts one connection and echoes everything back until
// the client disconnects.
func startEchoTarget(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		ln.Close()
		select {
		case <-done:
		case <-time.After(proxyTestTimeout + time.Second):
			t.Error("echo target did not finish")
		}
	})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(proxyTestTimeout * 3))
		_, _ = io.Copy(conn, conn)
	}()

	return ln.Addr().String()
}

// assertSolidRedFrame checks that img is a 4x3 image whose pixels are
// opaque red, the frame startRFBTarget sends.
func assertSolidRedFrame(t *testing.T, img image.Image) {
	t.Helper()
	if img == nil {
		t.Fatal("frame is nil")
	}
	b := img.Bounds()
	if b.Dx() != 4 || b.Dy() != 3 {
		t.Fatalf("frame bounds = %v, want 4x3", b)
	}
	r, g, bl, a := img.At(0, 0).RGBA()
	if r != 0xFFFF || g != 0 || bl != 0 || a != 0xFFFF {
		t.Fatalf("frame.At(0,0) = (%#x, %#x, %#x, %#x), want opaque red", r, g, bl, a)
	}
}

func TestParseProxyURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    proxyConfig
		wantErr string
	}{
		{
			name:  "socks5 default port",
			input: "socks5://10.0.0.5",
			want:  proxyConfig{addr: "10.0.0.5:1080"},
		},
		{
			name:  "socks5 explicit host and port",
			input: "socks5://10.0.0.5:9050",
			want:  proxyConfig{addr: "10.0.0.5:9050"},
		},
		{
			name:  "socks5h requests remote resolution",
			input: "socks5h://proxy.corp.example:9150",
			want:  proxyConfig{addr: "proxy.corp.example:9150", remoteResolve: true},
		},
		{
			name:  "userinfo",
			input: "socks5://operator:s3cret@proxy.example:1080",
			want:  proxyConfig{addr: "proxy.example:1080", username: "operator", password: "s3cret"},
		},
		{
			name:  "case-insensitive scheme",
			input: "SOCKS5H://proxy.example",
			want:  proxyConfig{addr: "proxy.example:1080", remoteResolve: true},
		},
		{
			name:  "trailing slash ignored",
			input: "socks5://proxy.example:1080/",
			want:  proxyConfig{addr: "proxy.example:1080"},
		},
		{
			name:  "IPv6 literal",
			input: "socks5://[2001:db8::1]:9050",
			want:  proxyConfig{addr: "[2001:db8::1]:9050"},
		},
		{
			name:    "unsupported scheme",
			input:   "http://proxy.example:8080",
			want:    proxyConfig{},
			wantErr: "unsupported proxy scheme",
		},
		{
			name:    "no scheme",
			input:   "proxy.example:1080",
			want:    proxyConfig{},
			wantErr: "unsupported proxy scheme",
		},
		{
			name:    "missing host",
			input:   "socks5://",
			want:    proxyConfig{},
			wantErr: "missing a host",
		},
		{
			name:    "path rejected",
			input:   "socks5://user:s3cret@proxy.example/bleh",
			want:    proxyConfig{},
			wantErr: "must not contain a path",
		},
		{
			name:    "query rejected",
			input:   "socks5://proxy.example?cred=user:pass",
			want:    proxyConfig{},
			wantErr: "must not contain a query",
		},
		{
			name:    "fragment rejected",
			input:   "socks5://proxy.example#s3cret",
			want:    proxyConfig{},
			wantErr: "must not contain a fragment",
		},
		{
			name:    "non-numeric port",
			input:   "socks5://proxy.example:notaport",
			want:    proxyConfig{},
			wantErr: "invalid port",
		},
		{
			name:    "port out of range",
			input:   "socks5://proxy.example:70000",
			want:    proxyConfig{},
			wantErr: "invalid proxy port",
		},
		{
			name: "userinfo without username is treated as no credentials",
			want: proxyConfig{addr: "proxy.example:1080"},
			// Empty userinfo; url.Parse keeps User non-nil with no username.
			input: "socks5://@proxy.example",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseProxyURL(tt.input)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseProxyURL(%q) = %+v, nil; want error containing %q", tt.input, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("parseProxyURL(%q) error = %q, want it to contain %q", tt.input, err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseProxyURL(%q) error = %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("parseProxyURL(%q) = %+v, want %+v", tt.input, got, tt.want)
			}
		})
	}
}

// TestDialProxyEcho exercises the tunnel directly: the CONNECT target is an
// IP literal with an explicit port, and data written into the tunnel comes
// back from the echo server behind the proxy.
func TestDialProxyEcho(t *testing.T) {
	echoAddr := startEchoTarget(t)
	echoHost, echoPortS, err := net.SplitHostPort(echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	echoPortNum, err := strconv.ParseUint(echoPortS, 10, 16)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr, rec := startFakeSOCKS(t, socksSpec{
		method: socksAuthNone,
		route:  map[string]string{echoHost: echoAddr},
	})

	ctx := context.Background()
	conn, err := dialProxy(ctx, "socks5://"+proxyAddr, "tcp", echoAddr, proxyTestTimeout)
	if err != nil {
		t.Fatalf("dialProxy error: %v", err)
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(proxyTestTimeout)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("echo got %q, want %q", got, "ping")
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The record is final once the handler's relay has ended.
	waitSocksDone(t, rec)
	if rec.atyp != socksATypIPv4 {
		t.Errorf("CONNECT atyp = %d, want %d (IPv4)", rec.atyp, socksATypIPv4)
	}
	if rec.targetHost != echoHost {
		t.Errorf("CONNECT host = %q, want %q", rec.targetHost, echoHost)
	}
	if rec.targetPort != uint16(echoPortNum) {
		t.Errorf("CONNECT port = %d, want %d", rec.targetPort, echoPortNum)
	}
}

func TestProbeThroughProxyNoAuth(t *testing.T) {
	rfbAddr := startRFBTarget(t, "proxy-desktop")
	_, rfbPort, err := net.SplitHostPort(rfbAddr)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr, rec := startFakeSOCKS(t, socksSpec{
		method: socksAuthNone,
		route:  map[string]string{"127.0.0.1": rfbAddr},
	})

	result, err := Probe(context.Background(), rfbAddr, Options{
		Timeout:        proxyTestTimeout,
		ConnectTimeout: proxyTestTimeout,
		Shared:         true,
		ProxyURL:       "socks5://" + proxyAddr,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	waitSocksDone(t, rec)

	if !result.Passwordless {
		t.Error("Passwordless = false, want true")
	}
	if result.ServerName != "proxy-desktop" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "proxy-desktop")
	}
	assertSolidRedFrame(t, result.Frame)

	if want := []byte{socksAuthNone}; len(rec.greetingMethods) != len(want) || rec.greetingMethods[0] != want[0] {
		t.Errorf("greeting methods = %v, want %v", rec.greetingMethods, want)
	}
	if rec.atyp != socksATypIPv4 {
		t.Errorf("CONNECT atyp = %d, want %d (IPv4)", rec.atyp, socksATypIPv4)
	}
	if rec.targetHost != "127.0.0.1" {
		t.Errorf("CONNECT host = %q, want %q", rec.targetHost, "127.0.0.1")
	}
	if wantPort := parseTargetPort(t, rfbPort); rec.targetPort != wantPort {
		t.Errorf("CONNECT port = %d, want %d", rec.targetPort, wantPort)
	}
	if len(rec.tunnelPrefix) < 14 {
		t.Fatalf("tunnel prefix = %d bytes, want at least the 14 handshake bytes", len(rec.tunnelPrefix))
	}
	if rec.tunnelPrefix[12] != 1 { // security-type None
		t.Errorf("tunnelled security selection = %d, want 1 (None)", rec.tunnelPrefix[12])
	}
	if rec.tunnelPrefix[13] != 1 {
		t.Errorf("tunnelled ClientInit shared flag = %d, want 1 (shared session)", rec.tunnelPrefix[13])
	}
}

// TestProxySendsDomainNames checks when the CONNECT request carries the
// DOMAINNAME form instead of a resolved IP: always for socks5h, and for an
// unresolvable hostname with socks5.
func TestProxySendsDomainNames(t *testing.T) {
	const internalName = "vnc.invalid.example"

	router := func(t *testing.T, scheme string) (proxyURL, rfbAddr string, rec *socksRecord) {
		rfbAddr = startRFBTarget(t, "domain-desktop")
		_, port, err := net.SplitHostPort(rfbAddr)
		if err != nil {
			t.Fatal(err)
		}
		// The fake proxy routes the invented name to the real loopback RFB
		// server, keeping the whole test in-process.
		pAddr, r := startFakeSOCKS(t, socksSpec{
			method: socksAuthNone,
			route:  map[string]string{internalName: "127.0.0.1:" + port},
		})
		return scheme + "://" + pAddr, internalName + ":" + port, r
	}

	t.Run("socks5h always sends the hostname", func(t *testing.T) {
		proxyURL, addr, rec := router(t, "socks5h")
		result, err := Probe(context.Background(), addr, Options{
			Timeout:        proxyTestTimeout,
			ConnectTimeout: proxyTestTimeout,
			ProxyURL:       proxyURL,
		})
		if err != nil {
			t.Fatalf("Probe error: %v", err)
		}
		waitSocksDone(t, rec)

		if rec.atyp != socksATypDomain {
			t.Errorf("CONNECT atyp = %d, want %d (domain)", rec.atyp, socksATypDomain)
		}
		if rec.targetHost != internalName {
			t.Errorf("CONNECT host = %q, want the hostname %q, not a resolved IP", rec.targetHost, internalName)
		}
		if !result.Passwordless || result.ServerName != "domain-desktop" {
			t.Errorf("result = %+v, want a passwordless domain-desktop capture", result)
		}
	})

	t.Run("socks5 falls back to the hostname when it cannot be resolved", func(t *testing.T) {
		proxyURL, addr, rec := router(t, "socks5")
		result, err := Probe(context.Background(), addr, Options{
			Timeout:        proxyTestTimeout,
			ConnectTimeout: proxyTestTimeout,
			ProxyURL:       proxyURL,
		})
		if err != nil {
			t.Fatalf("Probe error: %v", err)
		}
		waitSocksDone(t, rec)

		if rec.atyp != socksATypDomain {
			t.Errorf("CONNECT atyp = %d, want %d (domain fallback)", rec.atyp, socksATypDomain)
		}
		if rec.targetHost != internalName {
			t.Errorf("CONNECT host = %q, want %q", rec.targetHost, internalName)
		}
		if !result.Passwordless || result.ServerName != "domain-desktop" {
			t.Errorf("result = %+v, want a passwordless domain-desktop capture", result)
		}
	})
}

func TestProbeThroughProxyAuthSuccess(t *testing.T) {
	const user, password = "scanner", "vnc-probe-2026"
	rfbAddr := startRFBTarget(t, "auth-desktop")
	_, port, err := net.SplitHostPort(rfbAddr)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr, rec := startFakeSOCKS(t, socksSpec{
		method:       socksAuthPassword,
		expectedUser: user,
		expectedPass: password,
		route:        map[string]string{"127.0.0.1": "127.0.0.1:" + port},
	})

	result, err := Probe(context.Background(), rfbAddr, Options{
		Timeout:        proxyTestTimeout,
		ConnectTimeout: proxyTestTimeout,
		Shared:         true,
		ProxyURL:       "socks5://" + user + ":" + password + "@" + proxyAddr,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	waitSocksDone(t, rec)

	if len(rec.greetingMethods) != 2 {
		t.Fatalf("greeting methods = %v, want both no-auth and password", rec.greetingMethods)
	}
	if rec.greetingMethods[0] != socksAuthNone || rec.greetingMethods[1] != socksAuthPassword {
		t.Errorf("greeting methods = %v, want [%d, %d]", rec.greetingMethods, socksAuthNone, socksAuthPassword)
	}
	if !rec.authSent || !rec.authAccepted {
		t.Errorf("authSent = %v, authAccepted = %v, want a successful subnegotiation", rec.authSent, rec.authAccepted)
	}
	if !result.Passwordless || result.ServerName != "auth-desktop" {
		t.Errorf("result = %+v, want a passwordless auth-desktop capture", result)
	}
	assertSolidRedFrame(t, result.Frame)
}

func TestProbeThroughProxyBadAuth(t *testing.T) {
	const (
		user          = "scanner"
		wrongPassword = "wr0ng-pw"
		rightPassword = "r1ght-pw"
	)
	rfbAddr := startRFBTarget(t, "should-not-be-reached")
	_, port, err := net.SplitHostPort(rfbAddr)
	if err != nil {
		t.Fatal(err)
	}

	// The proxy must not leak the password into the error, whichever side
	// of the exchange it leaked from.
	proxyAddr, rec := startFakeSOCKS(t, socksSpec{
		method:       socksAuthPassword,
		expectedUser: user,
		expectedPass: rightPassword,
		route:        map[string]string{"127.0.0.1": "127.0.0.1:" + port},
	})

	_, err = Probe(context.Background(), rfbAddr, Options{
		Timeout:        proxyTestTimeout,
		ConnectTimeout: proxyTestTimeout,
		ProxyURL:       "socks5://" + user + ":" + wrongPassword + "@" + proxyAddr,
	})
	if err == nil {
		t.Fatal("Probe = nil error, want an authentication rejection")
	}
	waitSocksDone(t, rec)

	if !rec.authSent || rec.authAccepted {
		t.Errorf("authSent = %v, authAccepted = %v, want a rejected subnegotiation", rec.authSent, rec.authAccepted)
	}
	if rec.authUser != user {
		t.Errorf("auth username = %q, want %q (no password was echoed)", rec.authUser, user)
	}
	if !errors.Is(err, ErrConnect) {
		t.Errorf("Probe error = %v, want errors.Is(err, ErrConnect)", err)
	}
	if want := "proxy authentication rejected"; !strings.Contains(err.Error(), want) {
		t.Errorf("Probe error = %q, want it to contain %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), wrongPassword) || strings.Contains(err.Error(), rightPassword) {
		t.Errorf("Probe error = %q, must not contain the password", err.Error())
	}
}

// TestProxyConnectErrorCodes checks that the server's response codes are
// mapped onto their RFC 1928 messages.
func TestProxyConnectErrorCodes(t *testing.T) {
	tests := []struct {
		name string
		rep  uint8
		want string
	}{
		{name: "ruleset refusal", rep: 2, want: "connection not allowed by ruleset"},
		{name: "network unreachable", rep: 3, want: "network unreachable"},
		{name: "host unreachable", rep: 4, want: "host unreachable"},
		{name: "connection refused", rep: 5, want: "connection refused"},
		{name: "command not supported", rep: 7, want: "command not supported"},
		{name: "unknown reply", rep: 0x55, want: "unknown reply 0x55"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxyAddr, rec := startFakeSOCKS(t, socksSpec{method: socksAuthNone, rep: tt.rep})

			_, err := Probe(context.Background(), "127.0.0.1:52333", Options{
				Timeout:        proxyTestTimeout,
				ConnectTimeout: proxyTestTimeout,
				ProxyURL:       "socks5://" + proxyAddr,
			})
			if err == nil {
				t.Fatal("Probe = nil error, want a proxy connect failure")
			}
			waitSocksDone(t, rec)
			if !errors.Is(err, ErrConnect) {
				t.Errorf("Probe error = %v, want errors.Is(err, ErrConnect)", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Probe error = %q, want it to contain %q", err.Error(), tt.want)
			}
		})
	}
}

// TestProxyNoAcceptableMethod covers a proxy that refuses every offered
// authentication method.
func TestProxyNoAcceptableMethod(t *testing.T) {
	proxyAddr, rec := startFakeSOCKS(t, socksSpec{method: socksAuthNoAcceptable})

	_, err := Probe(context.Background(), "127.0.0.1:52333", Options{
		Timeout:        proxyTestTimeout,
		ConnectTimeout: proxyTestTimeout,
		ProxyURL:       "socks5://" + proxyAddr,
	})
	if err == nil {
		t.Fatal("Probe = nil error, want an authentication-method failure")
	}
	waitSocksDone(t, rec)
	if want := "proxy rejected every authentication method"; !strings.Contains(err.Error(), want) {
		t.Errorf("Probe error = %q, want it to contain %q", err.Error(), want)
	}
}

// TestProbeThroughProxyHandshakeDeadline verifies the handshake deadline: a
// proxy that accepts TCP but never answers the CONNECT request must fail
// within the connect timeout, not the full probe timeout.
func TestProbeThroughProxyHandshakeDeadline(t *testing.T) {
	rfbAddr := startRFBTarget(t, "unreachable")
	_, port, err := net.SplitHostPort(rfbAddr)
	if err != nil {
		t.Fatal(err)
	}

	proxyAddr, rec := startFakeSOCKS(t, socksSpec{
		method: socksAuthNone,
		stall:  true,
		route:  map[string]string{"127.0.0.1": "127.0.0.1:" + port},
	})

	start := time.Now()
	_, err = Probe(context.Background(), rfbAddr, Options{
		// A much larger RFB timeout proves the separate connect deadline is
		// what aborted the handshake.
		Timeout:        4 * proxyTestTimeout,
		ConnectTimeout: 300 * time.Millisecond,
		ProxyURL:       "socks5://" + proxyAddr,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Probe = nil error, want a handshake deadline failure")
	}
	waitSocksDone(t, rec)
	if elapsed > proxyTestTimeout {
		t.Errorf("Probe took %v, want roughly the 300ms connect deadline", elapsed)
	}
	if !errors.Is(err, ErrConnect) {
		t.Errorf("Probe error = %v, want errors.Is(err, ErrConnect)", err)
	}
}

// parseTargetPort parses the "port" half of a host:port string.
func parseTargetPort(t *testing.T, s string) uint16 {
	t.Helper()
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		t.Fatalf("parse port %q: %v", s, err)
	}
	return uint16(v)
}
