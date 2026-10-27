package vnc_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"image"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	"vncshot/vnc"
)

const probeTimeout = 2 * time.Second

// rfbServer is a minimal in-process RFB endpoint for Probe tests.
type rfbServer struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func (s *rfbServer) mustRead(n int) []byte {
	s.t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		s.t.Errorf("fake server: read %d bytes: %v", n, err)
	}
	return buf
}

func (s *rfbServer) mustWrite(b []byte) {
	s.t.Helper()
	if _, err := s.w.Write(b); err != nil {
		s.t.Errorf("fake server: write %d bytes: %v", len(b), err)
		return
	}
	if err := s.w.Flush(); err != nil {
		s.t.Errorf("fake server: flush: %v", err)
	}
}

func (s *rfbServer) mustWriteU16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	s.mustWrite(b[:])
}

func (s *rfbServer) mustWriteU32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	s.mustWrite(b[:])
}

// serveRFB starts a loopback listener and runs handler against the first
// accepted connection. The dial address is returned. Cleanup closes the
// listener and waits for the handler goroutine to finish.
func serveRFB(t *testing.T, handler func(s *rfbServer)) string {
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
		case <-time.After(probeTimeout + time.Second):
			t.Error("fake RFB server handler did not finish")
		}
	})

	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(probeTimeout + time.Second))
		handler(&rfbServer{
			t:    t,
			conn: conn,
			r:    bufio.NewReader(conn),
			w:    bufio.NewWriter(conn),
		})
	}()

	return ln.Addr().String()
}

// sendBanner writes the server version banner and consumes the client reply.
func (s *rfbServer) sendBanner(banner string) {
	s.t.Helper()
	if len(banner) != 12 {
		s.t.Errorf("fake server: banner %q must be 12 bytes", banner)
		return
	}
	s.mustWrite([]byte(banner))
	s.mustRead(12) // client ProtocolVersion reply
}

// sendServerInit writes a ServerInit message with the given geometry and name.
func (s *rfbServer) sendServerInit(width, height uint16, name string) {
	s.t.Helper()
	s.mustWriteU16(width)
	s.mustWriteU16(height)
	// Pixel format: any 16 bytes are acceptable; the client requests its
	// own format via SetPixelFormat before capture.
	s.mustWrite(make([]byte, 16))
	s.mustWriteU32(uint32(len(name)))
	s.mustWrite([]byte(name))
}

// readCaptureMessages consumes SetPixelFormat, SetEncodings and a
// FramebufferUpdateRequest issued during capture.
func (s *rfbServer) readCaptureMessages() {
	s.t.Helper()
	if got := s.mustRead(20); got[0] != 0 {
		s.t.Errorf("fake server: SetPixelFormat type = %d, want 0", got[0])
	}
	if got := s.mustRead(8); got[0] != 2 {
		s.t.Errorf("fake server: SetEncodings type = %d, want 2", got[0])
	}
	if got := s.mustRead(10); got[0] != 3 {
		s.t.Errorf("fake server: FramebufferUpdateRequest type = %d, want 3", got[0])
	}
}

// sendSolidRawRect sends one raw rectangle covering w*h solid pixels.
// Pixels use the 32bpp little-endian B,G,R,pad layout the client requests.
func (s *rfbServer) sendSolidRawRect(w, h int, r8, g8, b8 uint8) {
	s.t.Helper()
	s.mustWrite([]byte{0, 0}) // FramebufferUpdate + padding
	s.mustWriteU16(1)         // one rectangle

	s.mustWriteU16(0) // x
	s.mustWriteU16(0) // y
	s.mustWriteU16(uint16(w))
	s.mustWriteU16(uint16(h))
	s.mustWriteU32(0) // raw encoding

	pix := make([]byte, w*h*4)
	for i := 0; i < w*h; i++ {
		pix[i*4+0] = b8
		pix[i*4+1] = g8
		pix[i*4+2] = r8
		pix[i*4+3] = 0
	}
	s.mustWrite(pix)
}

// writeFailureReason sends an RFB security failure reason string.
func (s *rfbServer) writeFailureReason(reason string) {
	s.t.Helper()
	s.mustWriteU32(uint32(len(reason)))
	s.mustWrite([]byte(reason))
}

// assertRedPixel checks that img is a 4x3 image whose (0,0) pixel is solid red.
func assertRedPixel(t *testing.T, frame image.Image) {
	t.Helper()
	if frame == nil {
		t.Fatal("Frame is nil")
	}
	b := frame.Bounds()
	if b.Dx() != 4 || b.Dy() != 3 {
		t.Fatalf("Frame bounds = %v, want 4x3", b)
	}
	r, g, bl, a := frame.At(0, 0).RGBA()
	if r != 0xFFFF || g != 0 || bl != 0 || a != 0xFFFF {
		t.Fatalf("Frame.At(0,0) = (%#x, %#x, %#x, %#x), want opaque red", r, g, bl, a)
	}
	// Spot-check a second pixel to catch stride/layout mistakes.
	r2, g2, b2, a2 := frame.At(3, 2).RGBA()
	if r2 != 0xFFFF || g2 != 0 || b2 != 0 || a2 != 0xFFFF {
		t.Fatalf("Frame.At(3,2) = (%#x, %#x, %#x, %#x), want opaque red", r2, g2, b2, a2)
	}
}

func TestProbePasswordlessWithCapture(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")

		// Security types: None (1) and VNC auth (2).
		s.mustWrite([]byte{2, 1, 2})
		sel := s.mustRead(1)
		if sel[0] != 1 {
			s.t.Errorf("fake server: security selection = %d, want 1 (None)", sel[0])
		}

		// SecurityResult: OK.
		s.mustWriteU32(0)

		// ClientInit shared flag.
		_ = s.mustRead(1)

		s.sendServerInit(4, 3, "test-desktop")
		s.readCaptureMessages()
		s.sendSolidRawRect(4, 3, 255, 0, 0)
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result == nil {
		t.Fatal("Probe returned nil result")
	}
	if !result.Passwordless {
		t.Error("Passwordless = false, want true")
	}
	if result.ServerName != "test-desktop" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "test-desktop")
	}
	if result.Width != 4 || result.Height != 3 {
		t.Errorf("geometry = %dx%d, want 4x3", result.Width, result.Height)
	}
	if len(result.AuthTypes) == 0 {
		t.Fatal("AuthTypes is empty")
	}
	foundNone := false
	for _, typ := range result.AuthTypes {
		if typ == 1 {
			foundNone = true
		}
	}
	if !foundNone {
		t.Errorf("AuthTypes = %v, want to contain 1 (None)", result.AuthTypes)
	}
	assertRedPixel(t, result.Frame)
}

func TestProbeRequiresAuth(t *testing.T) {
	// With no credentials the probe must stop right after the security-type
	// list: sending ClientInit without authenticating would be a protocol
	// violation, and the desktop name is only available post-auth.
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 2}) // only VNC authentication

		// Anything the client writes from here on is a bug.
		if extra, err := io.ReadAll(io.LimitReader(s.conn, 1)); err == nil && len(extra) > 0 {
			s.t.Errorf("fake server: client sent %d unexpected byte(s) before authenticating", len(extra))
		}
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result == nil {
		t.Fatal("Probe returned nil result")
	}
	if result.Passwordless {
		t.Error("Passwordless = true, want false")
	}
	if !result.AuthRequired {
		t.Error("AuthRequired = false, want true")
	}
	if len(result.AuthTypes) != 1 || result.AuthTypes[0] != 2 {
		t.Errorf("AuthTypes = %v, want [2]", result.AuthTypes)
	}
	if result.Frame != nil {
		t.Error("Frame is non-nil, want nil when auth is required")
	}
	if result.Password != "" {
		t.Errorf("Password = %q, want empty when no credentials were supplied", result.Password)
	}
	if result.ServerName != "" {
		t.Errorf("ServerName = %q, want empty before authentication", result.ServerName)
	}
}

func TestExportedSecurityTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{typ: 1, want: "None"},
		{typ: 2, want: "VNC authentication"},
		{typ: 5, want: "RA2"},
		{typ: 6, want: "RA2ne"},
		{typ: 16, want: "Tight"},
		{typ: 17, want: "Ultra"},
		{typ: 18, want: "TLS"},
		{typ: 19, want: "VeNCrypt"},
		{typ: 20, want: "SASL"},
		{typ: 21, want: "MD5"},
		{typ: 22, want: "xvp"},
		{typ: 30, want: "Apple Remote Desktop"},
		{typ: 113, want: "MSLogon II"},
		{typ: 0, want: "type 0"},
		{typ: 200, want: "type 200"},
	}

	for _, tt := range tests {
		if got := vnc.SecurityTypeName(tt.typ); got != tt.want {
			t.Errorf("SecurityTypeName(%d) = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestSecurityTypeNote(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{typ: 0, want: ""},
		{typ: 1, want: ""}, // None
		{typ: 2, want: ""}, // VNC authentication
		{typ: 5, want: "proprietary authentication (RealVNC)"},
		{typ: 6, want: "proprietary authentication (RealVNC)"},
		{typ: 16, want: "Tight/Ultra tunneling"},
		{typ: 17, want: "Tight/Ultra tunneling"},
		{typ: 18, want: ""}, // TLS
		{typ: 19, want: ""}, // VeNCrypt
		{typ: 20, want: "SASL authentication"},
		{typ: 21, want: "MD5 authentication (RealVNC)"},
		{typ: 22, want: "xvp authentication"},
		{typ: 30, want: "Apple Remote Desktop authentication"},
		{typ: 113, want: "MSLogon II (UltraVNC)"},
		{typ: 200, want: ""}, // unknown
	}

	for _, tt := range tests {
		if got := vnc.SecurityTypeNote(tt.typ); got != tt.want {
			t.Errorf("SecurityTypeNote(%d) = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestUnsupportedOnlyTypesProduceNotes(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 30}) // Apple Remote Desktop only

		// The probe must not select a type it cannot complete.
		if extra, err := io.ReadAll(io.LimitReader(s.conn, 1)); err == nil && len(extra) > 0 {
			s.t.Errorf("fake server: client sent %d unexpected byte(s)", len(extra))
		}
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result == nil {
		t.Fatal("Probe returned nil result")
	}
	want := []string{"Apple Remote Desktop authentication"}
	if !reflect.DeepEqual(result.SecurityNotes, want) {
		t.Errorf("SecurityNotes = %v, want %v", result.SecurityNotes, want)
	}
	if result.Note != want[0] {
		t.Errorf("Note = %q, want %q", result.Note, want[0])
	}
	if !result.AuthRequired {
		t.Error("AuthRequired = false, want true")
	}
	if result.Frame != nil {
		t.Error("Frame is non-nil, want nil when no supported type is offered")
	}
}

func TestProbeReportsEncryptedSecurityTypes(t *testing.T) {
	// VeNCrypt (19) plus VNC authentication (2): the probe takes no
	// credential and does not perform TLS authentication, but the report must
	// still show that an encrypted channel was on offer. The server offers
	// only the X509Plain subtype, which the probe does not implement, so the
	// negotiation stops after the subtype list.
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{2, 19, 2})
		if sel := s.mustRead(1); sel[0] != 19 {
			s.t.Errorf("fake server: security selection = %d, want 19 (VeNCrypt)", sel[0])
		}
		s.mustWrite([]byte{0, 2}) // VeNCrypt server version
		s.mustRead(2)             // client version
		s.mustWrite([]byte{0})    // version ack
		s.mustWrite([]byte{1})    // one subtype
		s.mustWriteU32(262)       // X509Plain, not implemented
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result == nil {
		t.Fatal("Probe returned nil result")
	}
	if !result.TLS {
		t.Error("TLS = false, want true for VeNCrypt")
	}
	if result.TLSInfo != nil {
		t.Error("TLSInfo is non-nil, want nil when no TLS handshake happened")
	}
	want := []string{"VeNCrypt", "VNC authentication"}
	if !reflect.DeepEqual(result.SecurityTypeNames, want) {
		t.Errorf("SecurityTypeNames = %v, want %v", result.SecurityTypeNames, want)
	}
	if !result.AuthRequired {
		t.Error("AuthRequired = false, want true")
	}
}

func TestProbeReportsPlainSecurityTypes(t *testing.T) {
	t.Run("None only", func(t *testing.T) {
		addr := serveRFB(t, func(s *rfbServer) {
			s.sendBanner("RFB 003.008\n")
			s.mustWrite([]byte{1, 1}) // None only
			_ = s.mustRead(1)         // security selection
			s.mustWriteU32(0)         // SecurityResult: OK
			_ = s.mustRead(1)         // ClientInit
			s.sendServerInit(4, 3, "plain-desktop")
			s.readCaptureMessages()
			s.sendSolidRawRect(4, 3, 255, 0, 0)
		})

		result, err := vnc.Probe(t.Context(), addr, vnc.Options{Timeout: probeTimeout})
		if err != nil {
			t.Fatalf("Probe error: %v", err)
		}
		if result.TLS {
			t.Error("TLS = true, want false for None")
		}
		if want := []string{"None"}; !reflect.DeepEqual(result.SecurityTypeNames, want) {
			t.Errorf("SecurityTypeNames = %v, want %v", result.SecurityTypeNames, want)
		}
	})

	t.Run("VNC authentication only", func(t *testing.T) {
		addr := serveRFB(t, func(s *rfbServer) {
			s.sendBanner("RFB 003.008\n")
			s.mustWrite([]byte{1, 2})
		})

		result, err := vnc.Probe(t.Context(), addr, vnc.Options{Timeout: probeTimeout})
		if err != nil {
			t.Fatalf("Probe error: %v", err)
		}
		if result.TLS {
			t.Error("TLS = true, want false for VNC authentication")
		}
		if want := []string{"VNC authentication"}; !reflect.DeepEqual(result.SecurityTypeNames, want) {
			t.Errorf("SecurityTypeNames = %v, want %v", result.SecurityTypeNames, want)
		}
	})
}

func TestProbeRFB33Passwordless(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.003\n")

		// RFB 3.3 announces a single security type as a U32 and sends no
		// SecurityResult after selecting None.
		s.mustWriteU32(1) // None

		_ = s.mustRead(1) // ClientInit
		s.sendServerInit(4, 3, "legacy-desktop")
		s.readCaptureMessages()
		s.sendSolidRawRect(4, 3, 255, 0, 0)
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result == nil {
		t.Fatal("Probe returned nil result")
	}
	if !result.Passwordless {
		t.Error("Passwordless = false, want true")
	}
	if len(result.AuthTypes) != 1 || result.AuthTypes[0] != 1 {
		t.Errorf("AuthTypes = %v, want [1]", result.AuthTypes)
	}
	if result.ServerName != "legacy-desktop" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "legacy-desktop")
	}
	if result.Width != 4 || result.Height != 3 {
		t.Errorf("geometry = %dx%d, want 4x3", result.Width, result.Height)
	}
	assertRedPixel(t, result.Frame)
}

func TestProbeSecurityFailureReason(t *testing.T) {
	const reason = "too many authentication failures"
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")

		// n = 0 signals failure and is followed by a reason string.
		s.mustWrite([]byte{0})
		s.writeFailureReason(reason)
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err == nil {
		t.Fatalf("Probe = (%+v, nil), want error containing %q", result, reason)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("Probe error = %q, want it to contain %q", err.Error(), reason)
	}
}

func TestProbeConnectRefused(t *testing.T) {
	// Bind and immediately close to obtain an address nothing listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{Timeout: probeTimeout})
	if err == nil {
		t.Fatalf("Probe = (%+v, nil), want connect error", result)
	}
	if !errors.Is(err, vnc.ErrConnect) {
		t.Errorf("Probe error = %v, want errors.Is(err, vnc.ErrConnect)", err)
	}
	if !strings.HasPrefix(err.Error(), "connect: ") {
		t.Errorf("Probe error = %q, want a %q prefix", err.Error(), "connect: ")
	}
}

func TestProbeMalformedBanner(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.mustWrite([]byte("HTP 001.000\n"))
	})

	_, err := vnc.Probe(t.Context(), addr, vnc.Options{Timeout: probeTimeout})
	if err == nil {
		t.Fatal("Probe = (nil, nil), want malformed banner error")
	}
}

func TestProbeEmptyFramebufferRejected(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{2, 1, 2})
		_ = s.mustRead(1) // None
		s.mustWriteU32(0)
		_ = s.mustRead(1) // ClientInit
		s.sendServerInit(0, 3, "empty-width")
	})

	_, err := vnc.Probe(t.Context(), addr, vnc.Options{Timeout: probeTimeout})
	if err == nil {
		t.Fatal("Probe = (nil, nil), want empty framebuffer error")
	}
}

func TestProbeContextCancel(t *testing.T) {
	// A server that sends the banner and then stalls exercises cancellation:
	// Probe must give up when the context expires rather than block on I/O.
	addr := serveRFB(t, func(s *rfbServer) {
		s.mustWrite([]byte("RFB 003.008\n"))
		_ = s.mustRead(12) // client ProtocolVersion
		// Keep the connection open until the client disconnects. Errors are
		// expected here because Probe cancels mid-handshake.
		_, _ = io.Copy(io.Discard, s.r)
	})

	ctx, cancel := context.WithTimeout(t.Context(), probeTimeout/4)
	defer cancel()

	_, err := vnc.Probe(ctx, addr, vnc.Options{Timeout: probeTimeout})
	if err == nil {
		t.Fatal("Probe = (nil, nil), want error after context cancellation")
	}
}

// TestProbeRFB37Passwordless covers the RFB 3.7 wire flow: the server
// announces a security-type list and, unlike 3.8, sends no SecurityResult
// after the None type. Reading one there would block until the deadline and
// hide every 3.7 passwordless host behind a probe error.
func TestProbeRFB37Passwordless(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.007\n")

		s.mustWrite([]byte{1, 1}) // one type: None
		if sel := s.mustRead(1); sel[0] != 1 {
			s.t.Errorf("fake server: security selection = %d, want 1 (None)", sel[0])
		}

		// No SecurityResult for None in 3.7: the next client byte is
		// ClientInit.
		shared := s.mustRead(1)
		if shared[0] != 1 {
			s.t.Errorf("fake server: shared flag = %d, want 1", shared[0])
		}
		s.sendServerInit(4, 3, "legacy-37")
		s.readCaptureMessages()
		s.sendSolidRawRect(4, 3, 255, 0, 0)
	})

	start := time.Now()
	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > probeTimeout {
		t.Errorf("probe took %v, want well under the %v deadline", elapsed, probeTimeout)
	}
	if !result.Passwordless {
		t.Error("Passwordless = false, want true")
	}
	if result.ServerName != "legacy-37" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "legacy-37")
	}
	if result.Frame == nil {
		t.Fatal("Frame is nil, want a capture for a 3.7 passwordless host")
	}
	assertRedPixel(t, result.Frame)
}

// TestProbeRFB38NoneReadsSecurityResult is the counterpart guard: 3.8 does
// send SecurityResult for None, so the client must consume it. A server that
// sends it and then the frame must be handled without desync.
func TestProbeRFB38NoneReadsSecurityResult(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 1})
		if sel := s.mustRead(1); sel[0] != 1 {
			s.t.Errorf("fake server: security selection = %d, want 1", sel[0])
		}
		s.mustWriteU32(0) // SecurityResult OK, required in 3.8
		_ = s.mustRead(1) // ClientInit
		s.sendServerInit(4, 3, "modern-38")
		s.readCaptureMessages()
		s.sendSolidRawRect(4, 3, 255, 0, 0)
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{Timeout: probeTimeout, Shared: true})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !result.Passwordless || result.ServerName != "modern-38" {
		t.Errorf("result = %+v, want a passwordless modern-38 capture", result)
	}
	assertRedPixel(t, result.Frame)
}
