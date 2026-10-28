package vnc_test

import (
	"bufio"
	"bytes"
	"crypto/des"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vncshot/vnc"
)

// challenge is the fixed server challenge used by the authentication fakes.
var challenge = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
}

// authFake is a loopback RFB 3.8 server that only offers VNC
// authentication. It accepts repeated connections so the probe's
// discovery-then-guess sequence can be exercised.
type authFake struct {
	ln net.Listener

	// password is the credential that must succeed.
	password string
	// lockOnAttempt, when > 0, makes the server answer SecurityResult 2
	// on that (1-based) rejected attempt, simulating a lockout.
	lockOnAttempt int32
	// width and height configure the served framebuffer.
	width, height uint16

	conns    atomic.Int32
	attempts atomic.Int32
	rejected atomic.Int32

	wg sync.WaitGroup
}

func startAuthFake(t *testing.T, password string, lockOnAttempt int32) *authFake {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &authFake{
		ln:            ln,
		password:      password,
		lockOnAttempt: lockOnAttempt,
		width:         4,
		height:        3,
	}

	t.Cleanup(func() {
		ln.Close()
		s.wg.Wait()
	})

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serve(conn)
			}()
		}
	}()
	return s
}

func (s *authFake) addr() string { return s.ln.Addr().String() }

func (s *authFake) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	s.conns.Add(1)

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}
	if _, err := io.ReadFull(r, make([]byte, 12)); err != nil {
		return
	}

	// Security types: VNC authentication only.
	if _, err := conn.Write([]byte{1, 2}); err != nil {
		return
	}
	sel := make([]byte, 1)
	if _, err := io.ReadFull(r, sel); err != nil {
		return
	}
	if sel[0] != 2 {
		return
	}

	if _, err := conn.Write(challenge); err != nil {
		return
	}
	got := make([]byte, 16)
	if _, err := io.ReadFull(r, got); err != nil {
		return
	}

	attempt := s.attempts.Add(1)
	want := expectedResponse(s.password)
	if !bytes.Equal(got, want) {
		s.rejected.Add(1)
		if s.lockOnAttempt > 0 && attempt >= s.lockOnAttempt {
			writeU32BE(w, 2) // too many attempts
		} else {
			writeU32BE(w, 1) // failed
			reason := []byte("invalid password")
			writeU32BE(w, uint32(len(reason)))
			w.Write(reason)
		}
		w.Flush()
		return
	}

	writeU32BE(w, 0)
	w.Flush()

	// ClientInit then ServerInit.
	if _, err := io.ReadFull(r, make([]byte, 1)); err != nil {
		return
	}
	var init bytes.Buffer
	binary.Write(&init, binary.BigEndian, s.width)
	binary.Write(&init, binary.BigEndian, s.height)
	init.Write([]byte{
		32, 24, 0, 1,
		0, 255, 0, 255, 0, 255,
		16, 8, 0,
		0, 0, 0,
	})
	name := []byte("locked-desktop")
	binary.Write(&init, binary.BigEndian, uint32(len(name)))
	init.Write(name)
	if _, err := conn.Write(init.Bytes()); err != nil {
		return
	}

	// Consume SetPixelFormat / SetEncodings until the update request.
	for {
		var typ [1]byte
		if _, err := io.ReadFull(r, typ[:]); err != nil {
			return
		}
		switch typ[0] {
		case 0:
			if _, err := io.ReadFull(r, make([]byte, 19)); err != nil {
				return
			}
		case 2:
			var hdr [3]byte
			if _, err := io.ReadFull(r, hdr[:]); err != nil {
				return
			}
			count := binary.BigEndian.Uint16(hdr[1:3])
			if _, err := io.ReadFull(r, make([]byte, int(count)*4)); err != nil {
				return
			}
		case 3:
			if _, err := io.ReadFull(r, make([]byte, 9)); err != nil {
				return
			}
			s.sendFrame(conn)
			return
		default:
			return
		}
	}
}

func (s *authFake) sendFrame(conn net.Conn) {
	w, h := int(s.width), int(s.height)
	pixels := make([]byte, 0, w*h*4)
	for i := 0; i < w*h; i++ {
		pixels = append(pixels, 0x40, 0x30, 0x20, 0) // B,G,R,pad
	}

	var buf bytes.Buffer
	buf.WriteByte(0)
	buf.WriteByte(0)
	binary.Write(&buf, binary.BigEndian, uint16(1))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(w))
	binary.Write(&buf, binary.BigEndian, uint16(h))
	binary.Write(&buf, binary.BigEndian, int32(0))
	buf.Write(pixels)
	conn.Write(buf.Bytes())
}

func writeU32BE(w *bufio.Writer, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.Write(b[:])
}

// expectedResponse derives the VNC response with an independent key
// construction, so the client implementation is checked rather than
// mirrored.
func expectedResponse(password string) []byte {
	var key [8]byte
	for i := 0; i < 8 && i < len(password); i++ {
		b := password[i]
		var rev byte
		for bit := 0; bit < 8; bit++ {
			rev <<= 1
			rev |= b & 1
			b >>= 1
		}
		key[i] = rev
	}
	block, err := des.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out
}

func TestProbeAuthenticatesWithWeakPasswordAndCaptures(t *testing.T) {
	srv := startAuthFake(t, "hunter2", 0)

	result, err := vnc.Probe(t.Context(), srv.addr(), vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
		Passwords: []vnc.Credential{
			{Password: "wrong-one", Source: vnc.SourceWordList},
			{Password: "wrong-two", Source: vnc.SourceWordList},
			{Password: "hunter2", Source: vnc.SourceWordList},
		},
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result.Passwordless {
		t.Error("Passwordless = true, want false")
	}
	if !result.AuthRequired {
		t.Error("AuthRequired = false, want true")
	}
	if result.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", result.Password, "hunter2")
	}
	if result.PasswordSource != vnc.SourceWordList {
		t.Errorf("PasswordSource = %q, want %q", result.PasswordSource, vnc.SourceWordList)
	}
	if result.ServerName != "locked-desktop" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "locked-desktop")
	}
	if result.Frame == nil {
		t.Fatal("Frame is nil, want a capture after successful authentication")
	}
	if result.Frame.Bounds().Dx() != 4 || result.Frame.Bounds().Dy() != 3 {
		t.Errorf("frame bounds = %v, want 4x3", result.Frame.Bounds())
	}

	// Discovery + blank password + three listed candidates: the blank
	// attempt is always first, then the probe stops on the first hit.
	if got := srv.conns.Load(); got != 5 {
		t.Errorf("server saw %d connections, want 5 (1 discovery + blank + 3 candidates)", got)
	}
	if got := srv.attempts.Load(); got != 4 {
		t.Errorf("server saw %d password attempts, want 4", got)
	}
}

func TestProbeEmptyPasswordStopsFurtherGuesses(t *testing.T) {
	srv := startAuthFake(t, "", 0)

	result, err := vnc.Probe(t.Context(), srv.addr(), vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
		Passwords: []vnc.Credential{
			{Password: "password", Source: vnc.SourceWordList},
			{Password: "admin", Source: vnc.SourceWordList},
			{Password: "hunter2", Source: vnc.SourceWordList},
		},
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !result.Passwordless {
		t.Error("Passwordless = false, want true for a blank VNC password")
	}
	if result.Password != "" {
		t.Errorf("Password = %q, want empty", result.Password)
	}
	if result.PasswordSource != vnc.SourceDefault {
		t.Errorf("PasswordSource = %q, want %q", result.PasswordSource, vnc.SourceDefault)
	}
	if result.Frame == nil {
		t.Fatal("Frame is nil, want a capture after the blank password")
	}
	// Discovery + one blank attempt: no later candidates may be tried.
	if got := srv.conns.Load(); got != 2 {
		t.Errorf("server saw %d connections, want 2 (discovery + blank)", got)
	}
	if got := srv.attempts.Load(); got != 1 {
		t.Errorf("server saw %d password attempts, want 1", got)
	}
	if got := srv.rejected.Load(); got != 0 {
		t.Errorf("server saw %d rejections, want 0", got)
	}
}

func TestProbeStopsOnAuthenticationLockout(t *testing.T) {
	srv := startAuthFake(t, "correct-horse", 1)

	result, err := vnc.Probe(t.Context(), srv.addr(), vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
		Passwords: []vnc.Credential{
			{Password: "first-wrong", Source: vnc.SourceWordList},
			{Password: "second-wrong", Source: vnc.SourceWordList},
			{Password: "correct-horse", Source: vnc.SourceWordList},
		},
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result.Password != "" {
		t.Errorf("Password = %q, want empty", result.Password)
	}
	if !result.AuthLocked {
		t.Error("AuthLocked = false, want true")
	}
	if result.Frame != nil {
		t.Error("Frame is non-nil, want nil without authentication")
	}

	// Discovery + exactly one rejected attempt: the lockout must stop the
	// loop instead of continuing to guess a locked account.
	if got := srv.attempts.Load(); got != 1 {
		t.Errorf("server saw %d attempts, want 1 (stop at lockout)", got)
	}
}

func TestProbeWithoutCredentialsSendsNoPassword(t *testing.T) {
	srv := startAuthFake(t, "hunter2", 0)

	result, err := vnc.Probe(t.Context(), srv.addr(), vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !result.AuthRequired {
		t.Error("AuthRequired = false, want true")
	}
	if result.Password != "" {
		t.Errorf("Password = %q, want empty", result.Password)
	}
	if result.Frame != nil {
		t.Error("Frame is non-nil, want nil")
	}
	if got := srv.conns.Load(); got != 1 {
		t.Errorf("server saw %d connections, want 1 (discovery only)", got)
	}
	if got := srv.attempts.Load(); got != 0 {
		t.Errorf("server saw %d password attempts, want 0", got)
	}
}

// TestProbeNeverSendsInputMessages asserts the client's wire traffic after
// a successful authentication contains no input, clipboard or control
// messages: only SetPixelFormat (0), SetEncodings (2) and
// FramebufferUpdateRequest (3) are permitted.
func TestProbeNeverSendsInputMessages(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	allowed := map[byte]bool{0: true, 2: true, 3: true}
	seenUnexpected := make(chan byte, 4)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)

		conn.Write([]byte("RFB 003.008\n"))
		io.ReadFull(r, make([]byte, 12))
		conn.Write([]byte{1, 1}) // None security type
		io.ReadFull(r, make([]byte, 1))
		conn.Write([]byte{0, 0, 0, 0})  // SecurityResult: OK
		io.ReadFull(r, make([]byte, 1)) // ClientInit
		conn.Write([]byte{
			0, 4, 0, 3,
			32, 24, 0, 1,
			0, 255, 0, 255, 0, 255,
			16, 8, 0,
			0, 0, 0,
			0, 0, 0, 0,
		})
		for {
			var typ [1]byte
			if _, err := io.ReadFull(r, typ[:]); err != nil {
				return
			}
			if !allowed[typ[0]] {
				seenUnexpected <- typ[0]
				return
			}
			switch typ[0] {
			case 0:
				io.ReadFull(r, make([]byte, 19))
			case 2:
				var hdr [3]byte
				io.ReadFull(r, hdr[:])
				count := binary.BigEndian.Uint16(hdr[1:3])
				io.ReadFull(r, make([]byte, int(count)*4))
			case 3:
				io.ReadFull(r, make([]byte, 9))
				// One 4x3 raw frame.
				var buf bytes.Buffer
				buf.Write([]byte{0, 0, 0, 1})
				buf.Write(make([]byte, 8))
				buf.Write([]byte{0, 0, 0, 0})
				buf.Write(make([]byte, 4*3*4))
				conn.Write(buf.Bytes())
			}
		}
	}()

	result, err := vnc.Probe(t.Context(), ln.Addr().String(), vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
	})
	wg.Wait()
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result.Frame == nil {
		t.Fatal("Frame is nil, want a capture")
	}
	select {
	case typ := <-seenUnexpected:
		t.Fatalf("client sent forbidden message type %d; only framebuffer reads are allowed", typ)
	default:
	}

}
