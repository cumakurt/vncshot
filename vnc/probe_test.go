package vnc_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"image"
	"io"
	"net"
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
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")

		// Only VNC authentication is offered; the client must not select
		// None and must not attempt a capture.
		s.mustWrite([]byte{1, 2})

		// The client still completes ClientInit/ServerInit so the endpoint
		// is recorded as RFB, then stops without credentials.
		shared := s.mustRead(1)
		if shared[0] != 1 {
			s.t.Errorf("fake server: shared flag = %d, want 1", shared[0])
		}
		s.sendServerInit(8, 6, "locked-desktop")
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
	if len(result.AuthTypes) != 1 || result.AuthTypes[0] != 2 {
		t.Errorf("AuthTypes = %v, want [2]", result.AuthTypes)
	}
	if result.Frame != nil {
		t.Error("Frame is non-nil, want nil when auth is required")
	}
	if result.ServerName != "locked-desktop" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "locked-desktop")
	}
	if result.Width != 8 || result.Height != 6 {
		t.Errorf("geometry = %dx%d, want 8x6", result.Width, result.Height)
	}
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
