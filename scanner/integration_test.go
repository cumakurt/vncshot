package scanner_test

import (
	"bytes"
	"context"
	"crypto/des"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image/color"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"vncshot/report"
	"vncshot/scanner"
	"vncshot/vnc"
)

// fakeRFB is a minimal in-process RFB 3.8 server used to exercise the
// scanner pipeline without any external network or real VNC software.
type fakeRFB struct {
	ln net.Listener

	// name is the desktop name announced in ServerInit.
	name string
	// passwordless offers security type None (1); otherwise only VNC
	// authentication (2) is advertised.
	passwordless bool
	width        int
	height       int
	// fill is the solid colour served as a single raw rectangle.
	fill color.RGBA

	wg sync.WaitGroup
}

// startFakeRFB binds 127.0.0.1:0, serves RFB clients until the test ends,
// and returns the running server.
func startFakeRFB(t *testing.T, name string, passwordless bool, width, height int, fill color.RGBA) *fakeRFB {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeRFB{
		ln:           ln,
		name:         name,
		passwordless: passwordless,
		width:        width,
		height:       height,
		fill:         fill,
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
				return // listener closed by cleanup
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				s.serveConn(conn)
			}()
		}
	}()
	return s
}

func (s *fakeRFB) port() int {
	return s.ln.Addr().(*net.TCPAddr).Port
}

func (s *fakeRFB) target() scanner.Target {
	return scanner.Target{IP: "127.0.0.1", Port: s.port()}
}

// serveConn speaks one RFB 3.8 session. The scanner uses a single TCP
// connection per probe (vnc.Probe owns the dial), so every accepted
// connection is the real handshake; short-lived failures still have to exit
// cleanly on EOF.
func (s *fakeRFB) serveConn(conn net.Conn) {
	defer conn.Close()
	// Bound every exchange so a wedged client cannot hang the test.
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. ProtocolVersion: server banner, then client's 12-byte reply.
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}
	var clientVer [12]byte
	if _, err := io.ReadFull(conn, clientVer[:]); err != nil {
		return
	}

	// 2. Security handshake (RFB 3.8 list form).
	if s.passwordless {
		// one type: None
		if _, err := conn.Write([]byte{1, 1}); err != nil {
			return
		}
		var selected [1]byte
		if _, err := io.ReadFull(conn, selected[:]); err != nil {
			return
		}
		// SecurityResult: 0 == OK (3.8 sends this even for None).
		if err := writeU32(conn, 0); err != nil {
			return
		}
	} else {
		// one type: VNC authentication. The inventory client does not
		// select a type or complete the challenge; it continues with
		// ClientInit so ServerInit is still collected for the report.
		if _, err := conn.Write([]byte{1, 2}); err != nil {
			return
		}
	}

	// 3. ClientInit: one shared-flag byte.
	var shared [1]byte
	if _, err := io.ReadFull(conn, shared[:]); err != nil {
		return
	}

	// 4. ServerInit.
	if err := s.writeServerInit(conn); err != nil {
		return
	}

	if !s.passwordless {
		// Authenticated path stops here: no framebuffer capture.
		return
	}

	// 5. Serve one full-frame raw update after the client requests it.
	if !s.awaitFramebufferUpdateRequest(conn) {
		return
	}
	s.writeSolidUpdate(conn)
}

func (s *fakeRFB) writeServerInit(conn net.Conn) error {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, uint16(s.width)); err != nil {
		return err
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(s.height)); err != nil {
		return err
	}
	// Pixel format: 32bpp little-endian true colour (B,G,R,pad on the wire).
	buf.Write([]byte{
		32, 24, // bits-per-pixel, depth
		0, 1, // little-endian, true-colour
		0, 255, 0, 255, 0, 255, // red/green/blue maxima
		16, 8, 0, // red/green/blue shifts
		0, 0, 0, // padding
	})
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(s.name))); err != nil {
		return err
	}
	buf.WriteString(s.name)
	_, err := conn.Write(buf.Bytes())
	return err
}

// awaitFramebufferUpdateRequest consumes client messages until the
// full-frame update request that vnc.client.capture always sends.
func (s *fakeRFB) awaitFramebufferUpdateRequest(conn net.Conn) bool {
	for {
		var typ [1]byte
		if _, err := io.ReadFull(conn, typ[:]); err != nil {
			return false
		}
		switch typ[0] {
		case 0: // SetPixelFormat: 3 padding + 16 pixel-format bytes
			if _, err := io.ReadFull(conn, make([]byte, 19)); err != nil {
				return false
			}
		case 2: // SetEncodings: 1 padding + U16 count + 4*count bytes
			var hdr [3]byte
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return false
			}
			count := binary.BigEndian.Uint16(hdr[1:3])
			if _, err := io.ReadFull(conn, make([]byte, int(count)*4)); err != nil {
				return false
			}
		case 3: // FramebufferUpdateRequest: 9 payload bytes
			if _, err := io.ReadFull(conn, make([]byte, 9)); err != nil {
				return false
			}
			return true
		default:
			return false
		}
	}
}

func (s *fakeRFB) writeSolidUpdate(conn net.Conn) {
	w, h := s.width, s.height
	pixels := make([]byte, 0, w*h*4)
	for i := 0; i < w*h; i++ {
		pixels = append(pixels, s.fill.B, s.fill.G, s.fill.R, 0)
	}

	var buf bytes.Buffer
	buf.WriteByte(0)                                    // FramebufferUpdate
	buf.WriteByte(0)                                    // padding
	_ = binary.Write(&buf, binary.BigEndian, uint16(1)) // one rectangle
	_ = binary.Write(&buf, binary.BigEndian, uint16(0)) // x
	_ = binary.Write(&buf, binary.BigEndian, uint16(0)) // y
	_ = binary.Write(&buf, binary.BigEndian, uint16(w))
	_ = binary.Write(&buf, binary.BigEndian, uint16(h))
	_ = binary.Write(&buf, binary.BigEndian, int32(0)) // encoding: Raw
	buf.Write(pixels)
	_, _ = conn.Write(buf.Bytes())
}

func writeU32(w io.Writer, v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

// closedPort returns a 127.0.0.1 port that nothing is listening on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve closed port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release closed port: %v", err)
	}
	return port
}

func closedPorts(t *testing.T, n int) []int {
	t.Helper()
	ports := make([]int, 0, n)
	for i := 0; i < n; i++ {
		ports = append(ports, closedPort(t))
	}
	return ports
}

func resultsByPort(results []report.Result) map[int]report.Result {
	byPort := make(map[int]report.Result, len(results))
	for _, r := range results {
		byPort[r.Port] = r
	}
	return byPort
}

func TestScanPipelineEndToEnd(t *testing.T) {
	t.Run("passwordless authenticated and closed targets", func(t *testing.T) {
		// Solid-colour desktop: distinctive RGB so the capture path is real.
		fill := color.RGBA{R: 0x20, G: 0x40, B: 0x60, A: 0xff}
		serverA := startFakeRFB(t, "desk-A", true, 4, 3, fill)
		serverB := startFakeRFB(t, "desk-B", false, 2, 2, fill)
		closed := closedPort(t)

		targets := []scanner.Target{
			serverA.target(),
			serverB.target(),
			{IP: "127.0.0.1", Port: closed},
		}

		screenshotDir := t.TempDir()
		results, err := scanner.Run(context.Background(), targets, scanner.Options{
			ConnectTimeout: 2 * time.Second,
			VNCTimeout:     2 * time.Second,
			Workers:        4,
			RatePerSec:     0,
			ScreenshotDir:  screenshotDir,
			Shared:         true,
			ShowProgress:   false,
		})
		if err != nil {
			t.Fatalf("Run error = %v", err)
		}
		if len(results) != 3 {
			t.Fatalf("Run returned %d results, want 3", len(results))
		}

		byPort := resultsByPort(results)

		// Server A: passwordless capture with a file on disk.
		ra, ok := byPort[serverA.port()]
		if !ok {
			t.Fatalf("missing result for passwordless server (port %d)", serverA.port())
		}
		if !ra.Open {
			t.Error("server A: Open = false, want true")
		}
		if !ra.RFB {
			t.Error("server A: RFB = false, want true")
		}
		if !ra.Passwordless {
			t.Error("server A: Passwordless = false, want true")
		}
		if ra.ServerName != "desk-A" {
			t.Errorf("server A: ServerName = %q, want %q", ra.ServerName, "desk-A")
		}
		if ra.ScreenWidth != 4 || ra.ScreenHeight != 3 {
			t.Errorf("server A: screen = %dx%d, want 4x3", ra.ScreenWidth, ra.ScreenHeight)
		}
		if want := []string{"None"}; !reflect.DeepEqual(ra.SecurityTypes, want) {
			t.Errorf("server A: SecurityTypes = %v, want %v", ra.SecurityTypes, want)
		}
		if ra.TLS {
			t.Error("server A: TLS = true, want false for None")
		}
		if ra.Attempts != 1 {
			t.Errorf("server A: Attempts = %d, want 1", ra.Attempts)
		}
		if ra.Screenshot == "" {
			t.Error("server A: Screenshot is empty, want a file path")
		} else {
			info, err := os.Stat(ra.Screenshot)
			if err != nil {
				t.Errorf("server A: screenshot file missing: %v", err)
			} else if info.Size() == 0 {
				t.Error("server A: screenshot file is empty")
			}
		}

		// Server B: open RFB endpoint that requires authentication.
		rb, ok := byPort[serverB.port()]
		if !ok {
			t.Fatalf("missing result for authenticated server (port %d)", serverB.port())
		}
		if !rb.Open {
			t.Error("server B: Open = false, want true")
		}
		if !rb.RFB {
			t.Error("server B: RFB = false, want true")
		}
		if rb.Passwordless {
			t.Error("server B: Passwordless = true, want false")
		}
		if rb.Screenshot != "" {
			t.Errorf("server B: Screenshot = %q, want empty", rb.Screenshot)
		}
		if want := []string{"VNC authentication"}; !reflect.DeepEqual(rb.SecurityTypes, want) {
			t.Errorf("server B: SecurityTypes = %v, want %v", rb.SecurityTypes, want)
		}
		if rb.TLS {
			t.Error("server B: TLS = true, want false for VNC authentication")
		}
		if rb.Attempts != 1 {
			t.Errorf("server B: Attempts = %d, want 1", rb.Attempts)
		}

		// Closed port: no service, no screenshot.
		rc, ok := byPort[closed]
		if !ok {
			t.Fatalf("missing result for closed port %d", closed)
		}
		if rc.Open {
			t.Error("closed port: Open = true, want false")
		}
		if rc.RFB {
			t.Error("closed port: RFB = true, want false")
		}
		if rc.Screenshot != "" {
			t.Errorf("closed port: Screenshot = %q, want empty", rc.Screenshot)
		}
		if rc.Attempts != 0 {
			t.Errorf("closed port: Attempts = %d, want 0 (no retry needed)", rc.Attempts)
		}

		// Report exporters: JSON and HTML artifacts must be written.
		outDir := t.TempDir()
		jsonPath := filepath.Join(outDir, "report.json")
		htmlPath := filepath.Join(outDir, "report.html")

		if err := report.WriteJSON(jsonPath, results); err != nil {
			t.Fatalf("WriteJSON error = %v", err)
		}
		if err := report.WriteHTML(htmlPath, results); err != nil {
			t.Fatalf("WriteHTML error = %v", err)
		}

		jsonInfo, err := os.Stat(jsonPath)
		if err != nil {
			t.Fatalf("JSON report missing: %v", err)
		}
		if jsonInfo.Size() == 0 {
			t.Error("JSON report is empty")
		}

		htmlInfo, err := os.Stat(htmlPath)
		if err != nil {
			t.Fatalf("HTML report missing: %v", err)
		}
		if htmlInfo.Size() == 0 {
			t.Error("HTML report is empty")
		}

		htmlBody, err := os.ReadFile(htmlPath)
		if err != nil {
			t.Fatalf("read HTML report: %v", err)
		}
		if !bytes.Contains(htmlBody, []byte("desk-A")) {
			t.Error("HTML report does not contain server name desk-A")
		}

		jsonBody, err := os.ReadFile(jsonPath)
		if err != nil {
			t.Fatalf("read JSON report: %v", err)
		}
		var doc report.Document
		if err := json.Unmarshal(jsonBody, &doc); err != nil {
			t.Fatalf("JSON report does not parse: %v", err)
		}
		if doc.Summary.Targets != 3 {
			t.Errorf("JSON summary targets = %d, want 3", doc.Summary.Targets)
		}
		if doc.Summary.Passwordless != 1 {
			t.Errorf("JSON summary passwordless = %d, want 1", doc.Summary.Passwordless)
		}
	})

	t.Run("context cancellation stops a large scan gracefully", func(t *testing.T) {
		const n = 50
		ports := closedPorts(t, n)
		targets := make([]scanner.Target, 0, n)
		for _, p := range ports {
			targets = append(targets, scanner.Target{IP: "127.0.0.1", Port: p})
		}

		// Cancel while the run is in flight. A 1-attempt-per-second limit
		// keeps the job queue from draining before cancellation lands, so
		// the returned set is deterministically partial.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			time.Sleep(50 * time.Millisecond)
			cancel()
		}()

		results, err := scanner.Run(ctx, targets, scanner.Options{
			ConnectTimeout: 2 * time.Second,
			VNCTimeout:     2 * time.Second,
			Workers:        4,
			RatePerSec:     1,
			ScreenshotDir:  t.TempDir(),
			Shared:         true,
			ShowProgress:   false,
		})

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v, want context.Canceled", err)
		}
		if len(results) >= n {
			t.Fatalf("Run returned %d results, want partial (< %d)", len(results), n)
		}

		// Results that did complete must still be well-formed.
		for i, r := range results {
			if r.IP != "127.0.0.1" {
				t.Errorf("result[%d].IP = %q, want 127.0.0.1", i, r.IP)
			}
			if r.Port <= 0 {
				t.Errorf("result[%d].Port = %d, want > 0", i, r.Port)
			}
		}
	})
}

// fakeAuthRFB is a multi-connection RFB 3.8 server that only offers VNC
// authentication, so the scanner's weak-password path can be exercised
// without any external software.
type fakeAuthRFB struct {
	ln       net.Listener
	password string
	name     string
	fill     color.RGBA
	// lockOnReject answers SecurityResult 2 instead of 1, simulating a
	// server that blocks further attempts.
	lockOnReject bool
	wg           sync.WaitGroup
}

func startFakeAuthRFB(t *testing.T, password, name string) *fakeAuthRFB {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeAuthRFB{ln: ln, password: password, name: name, fill: color.RGBA{R: 0x10, G: 0x70, B: 0x30, A: 0xff}}
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

func (s *fakeAuthRFB) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeAuthRFB) serve(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, 12)); err != nil {
		return
	}
	if _, err := conn.Write([]byte{1, 2}); err != nil { // VNC auth only
		return
	}
	sel := make([]byte, 1)
	if _, err := io.ReadFull(conn, sel); err != nil || sel[0] != 2 {
		return
	}

	challenge := bytes.Repeat([]byte{0x42}, 16)
	if _, err := conn.Write(challenge); err != nil {
		return
	}
	got := make([]byte, 16)
	if _, err := io.ReadFull(conn, got); err != nil {
		return
	}

	if !bytes.Equal(got, fakeVNCResponse(s.password, challenge)) {
		if s.lockOnReject {
			_ = writeU32(conn, 2)
			return
		}
		_ = writeU32(conn, 1)
		reason := []byte("invalid password")
		_ = writeU32(conn, uint32(len(reason)))
		_, _ = conn.Write(reason)
		return
	}
	if err := writeU32(conn, 0); err != nil {
		return
	}

	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil { // ClientInit
		return
	}
	if err := s.writeServerInit(conn); err != nil {
		return
	}
	if !s.awaitFramebufferUpdateRequest(conn) {
		return
	}
	s.writeSolidUpdate(conn)
}

func (s *fakeAuthRFB) writeServerInit(conn net.Conn) error {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(6))
	_ = binary.Write(&buf, binary.BigEndian, uint16(5))
	buf.Write([]byte{
		32, 24, 0, 1,
		0, 255, 0, 255, 0, 255,
		16, 8, 0,
		0, 0, 0,
	})
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(s.name)))
	buf.WriteString(s.name)
	_, err := conn.Write(buf.Bytes())
	return err
}

func (s *fakeAuthRFB) awaitFramebufferUpdateRequest(conn net.Conn) bool {
	for {
		var typ [1]byte
		if _, err := io.ReadFull(conn, typ[:]); err != nil {
			return false
		}
		switch typ[0] {
		case 0:
			if _, err := io.ReadFull(conn, make([]byte, 19)); err != nil {
				return false
			}
		case 2:
			var hdr [3]byte
			if _, err := io.ReadFull(conn, hdr[:]); err != nil {
				return false
			}
			count := binary.BigEndian.Uint16(hdr[1:3])
			if _, err := io.ReadFull(conn, make([]byte, int(count)*4)); err != nil {
				return false
			}
		case 3:
			if _, err := io.ReadFull(conn, make([]byte, 9)); err != nil {
				return false
			}
			return true
		default:
			return false
		}
	}
}

func (s *fakeAuthRFB) writeSolidUpdate(conn net.Conn) {
	const w, h = 6, 5
	pixels := make([]byte, 0, w*h*4)
	for i := 0; i < w*h; i++ {
		pixels = append(pixels, s.fill.B, s.fill.G, s.fill.R, 0)
	}
	var buf bytes.Buffer
	buf.WriteByte(0)
	buf.WriteByte(0)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(w))
	_ = binary.Write(&buf, binary.BigEndian, uint16(h))
	_ = binary.Write(&buf, binary.BigEndian, int32(0))
	buf.Write(pixels)
	_, _ = conn.Write(buf.Bytes())
}

// fakeVNCResponse computes the DES response independently of the client
// implementation under test.
func fakeVNCResponse(password string, challenge []byte) []byte {
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

func TestScanWeakPasswordCaptureAndReport(t *testing.T) {
	server := startFakeAuthRFB(t, "hunter2", "finance-desktop")
	screenshotDir := t.TempDir()

	results, err := scanner.Run(context.Background(),
		[]scanner.Target{{IP: "127.0.0.1", Port: server.port()}},
		scanner.Options{
			ConnectTimeout: 2 * time.Second,
			VNCTimeout:     2 * time.Second,
			Workers:        2,
			RatePerSec:     0,
			ScreenshotDir:  screenshotDir,
			Shared:         true,
			Passwords: []vnc.Credential{
				{Password: "nope", Source: vnc.SourceWordList},
				{Password: "hunter2", Source: vnc.SourceWordList},
			},
		})
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Run returned %d results, want 1", len(results))
	}

	r := results[0]
	if !r.Open || !r.RFB {
		t.Errorf("Open=%v RFB=%v, want both true", r.Open, r.RFB)
	}
	if r.Passwordless {
		t.Error("Passwordless = true, want false for an authenticated server")
	}
	if r.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", r.Password, "hunter2")
	}
	if r.PasswordSource != vnc.SourceWordList {
		t.Errorf("PasswordSource = %q, want %q", r.PasswordSource, vnc.SourceWordList)
	}
	if r.ServerName != "finance-desktop" {
		t.Errorf("ServerName = %q, want %q", r.ServerName, "finance-desktop")
	}
	if r.ScreenWidth != 6 || r.ScreenHeight != 5 {
		t.Errorf("screen = %dx%d, want 6x5", r.ScreenWidth, r.ScreenHeight)
	}
	if r.Screenshot == "" {
		t.Fatal("Screenshot is empty, want a capture after authenticated login")
	}
	info, err := os.Stat(r.Screenshot)
	if err != nil {
		t.Fatalf("screenshot file missing: %v", err)
	}
	if info.Size() == 0 {
		t.Error("screenshot file is empty")
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("screenshot permissions = %o, want owner-only", mode)
	}

	sum := report.Summarize(results)
	if sum.WeakCredentials != 1 {
		t.Errorf("WeakCredentials = %d, want 1", sum.WeakCredentials)
	}
	if sum.Passwordless != 0 {
		t.Errorf("Passwordless = %d, want 0", sum.Passwordless)
	}
	if sum.Screenshots != 1 {
		t.Errorf("Screenshots = %d, want 1", sum.Screenshots)
	}

	// Reports must carry the credential so the operator can act on it.
	jsonPath := filepath.Join(t.TempDir(), "report.json")
	if err := report.WriteJSON(jsonPath, results); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	body, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	var doc report.Document
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("JSON does not parse: %v", err)
	}
	if len(doc.Results) != 1 || doc.Results[0].Password != "hunter2" {
		t.Errorf("JSON report password = %q, want %q", doc.Results[0].Password, "hunter2")
	}
	if doc.Summary.WeakCredentials != 1 {
		t.Errorf("JSON summary weak_credentials = %d, want 1", doc.Summary.WeakCredentials)
	}

	htmlPath := filepath.Join(t.TempDir(), "report.html")
	if err := report.WriteHTML(htmlPath, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatalf("read HTML: %v", err)
	}
	if !bytes.Contains(html, []byte("hunter2")) {
		t.Error("HTML report does not contain the discovered password")
	}

	pdfPath := filepath.Join(t.TempDir(), "report.pdf")
	if err := report.WritePDF(pdfPath, results); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}
	pdfInfo, err := os.Stat(pdfPath)
	if err != nil {
		t.Fatalf("PDF report missing: %v", err)
	}
	if pdfInfo.Size() == 0 {
		t.Error("PDF report is empty")
	}
}

func TestScanRecordsAuthenticationLockout(t *testing.T) {
	server := startFakeAuthRFB(t, "s3cret", "guarded-desktop")
	server.lockOnReject = true

	results, err := scanner.Run(context.Background(),
		[]scanner.Target{{IP: "127.0.0.1", Port: server.port()}},
		scanner.Options{
			ConnectTimeout: 2 * time.Second,
			VNCTimeout:     2 * time.Second,
			Workers:        1,
			ScreenshotDir:  t.TempDir(),
			Shared:         true,
			Passwords: []vnc.Credential{
				{Password: "wrong", Source: vnc.SourceDefault},
				{Password: "s3cret", Source: vnc.SourceDefault},
			},
		})
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Run returned %d results, want 1", len(results))
	}

	r := results[0]
	if !r.AuthLocked {
		t.Error("AuthLocked = false, want true when the server blocks attempts")
	}
	if r.Password != "" {
		t.Errorf("Password = %q, want empty after a lockout", r.Password)
	}
	if r.Screenshot != "" {
		t.Errorf("Screenshot = %q, want empty after a lockout", r.Screenshot)
	}
	if !r.RFB || !r.Open {
		t.Errorf("Open=%v RFB=%v, want both true", r.Open, r.RFB)
	}

	jsonPath := filepath.Join(t.TempDir(), "report.json")
	if err := report.WriteJSON(jsonPath, results); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	body, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read JSON: %v", err)
	}
	if !bytes.Contains(body, []byte(`"auth_locked": true`)) {
		t.Errorf("JSON report does not record the lockout:\n%s", body)
	}
}

// TestScanReportsEncryptedSecurityTypes checks the end-to-end path from the
// advertised RFB security types to the report: a server offering VeNCrypt
// must be marked TLS even though the scanner sends no credential.
func TestScanReportsEncryptedSecurityTypes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, _ = conn.Write([]byte("RFB 003.008\n"))
			_, _ = io.ReadFull(conn, make([]byte, 12))
			// Two types: VNC authentication and VeNCrypt.
			_, _ = conn.Write([]byte{2, 2, 19})
			conn.Close()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		wg.Wait()
	})

	results, err := scanner.Run(context.Background(),
		[]scanner.Target{{IP: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}},
		scanner.Options{
			ConnectTimeout: 2 * time.Second,
			VNCTimeout:     2 * time.Second,
			Workers:        1,
			ScreenshotDir:  t.TempDir(),
			Shared:         true,
		})
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Run returned %d results, want 1", len(results))
	}

	r := results[0]
	if !r.Open || !r.RFB {
		t.Errorf("Open=%v RFB=%v, want both true", r.Open, r.RFB)
	}
	if !r.TLS {
		t.Error("TLS = false, want true when VeNCrypt is advertised")
	}
	want := []string{"VNC authentication", "VeNCrypt"}
	if !reflect.DeepEqual(r.SecurityTypes, want) {
		t.Errorf("SecurityTypes = %v, want %v", r.SecurityTypes, want)
	}
	if r.Attempts != 1 {
		t.Errorf("Attempts = %d, want 1", r.Attempts)
	}
}

// TestHostConcurrencyCap asserts the per-IP semaphore keeps several open
// ports on one host from being probed by more workers than configured.
func TestHostConcurrencyCap(t *testing.T) {
	const (
		portCount       = 8
		hostConcurrency = 2
		probeHoldTime   = 50 * time.Millisecond
	)

	var (
		mu          sync.Mutex
		inFlight    int
		maxInFlight int
	)

	listeners := make([]net.Listener, 0, portCount)
	targets := make([]scanner.Target, 0, portCount)

	var servers sync.WaitGroup
	for i := 0; i < portCount; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		listeners = append(listeners, ln)
		targets = append(targets, scanner.Target{
			IP:   "127.0.0.1",
			Port: ln.Addr().(*net.TCPAddr).Port,
		})

		servers.Add(1)
		go func(ln net.Listener) {
			defer servers.Done()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}

				mu.Lock()
				inFlight++
				if inFlight > maxInFlight {
					maxInFlight = inFlight
				}
				mu.Unlock()

				// Hold the connection so overlapping probes are observable.
				// The decrement happens before Close: the scanner cannot
				// dial the next target until this probe sees the close, so
				// the counter can never be inflated by a stale connection.
				time.Sleep(probeHoldTime)

				mu.Lock()
				inFlight--
				mu.Unlock()

				conn.Close()
			}
		}(ln)
	}
	t.Cleanup(func() {
		for _, ln := range listeners {
			ln.Close()
		}
		servers.Wait()
	})

	results, err := scanner.Run(context.Background(), targets, scanner.Options{
		ConnectTimeout:  2 * time.Second,
		VNCTimeout:      2 * time.Second,
		Workers:         portCount,
		HostConcurrency: hostConcurrency,
		ScreenshotDir:   t.TempDir(),
		Shared:          true,
	})
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if len(results) != portCount {
		t.Fatalf("Run returned %d results, want %d", len(results), portCount)
	}

	mu.Lock()
	observed := maxInFlight
	mu.Unlock()

	if observed > hostConcurrency {
		t.Errorf("max probes in flight = %d, want <= %d", observed, hostConcurrency)
	}
	if observed < hostConcurrency {
		t.Errorf("max probes in flight = %d, want the cap of %d to be used", observed, hostConcurrency)
	}
}

// TestCancelledProbeReportsCancellationNotTimeout guards the diagnostic path:
// aborting a handshake must not be reported as a network timeout, otherwise
// an operator chases a phantom connectivity problem while the port is simply
// an unverified open service.
func TestCancelledProbeReportsCancellationNotTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				// Announce RFB, then stall forever so the probe is still in
				// flight when the context is cancelled.
				_, _ = io.ReadFull(conn, make([]byte, 12))
				_, _ = conn.Write([]byte("RFB 003.008\n"))
				buf := make([]byte, 1)
				_, _ = io.ReadFull(conn, buf)
				time.Sleep(10 * time.Second)
			}()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	results, err := scanner.Run(ctx,
		[]scanner.Target{{IP: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}},
		scanner.Options{
			ConnectTimeout: 2 * time.Second,
			VNCTimeout:     5 * time.Second,
			Workers:        1,
			ScreenshotDir:  t.TempDir(),
		})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v, want context.Canceled", err)
	}
	if len(results) != 1 {
		t.Fatalf("Run returned %d results, want 1", len(results))
	}
	if got := results[0].Error; !strings.Contains(got, "context canceled") {
		t.Errorf("Error = %q, want it to name the cancellation", got)
	}
	if strings.Contains(results[0].Error, "i/o timeout") {
		t.Error("Error still reports a misleading i/o timeout for a cancelled probe")
	}
}

// TestRunClampsWorkerPool pins the hard ceiling so a mistyped or hostile
// worker count cannot spawn unbounded goroutines and sockets.
func TestRunClampsWorkerPool(t *testing.T) {
	results, err := scanner.Run(context.Background(),
		[]scanner.Target{{IP: "127.0.0.1", Port: closedPort(t)}},
		scanner.Options{
			ConnectTimeout: 200 * time.Millisecond,
			VNCTimeout:     200 * time.Millisecond,
			Workers:        1_000_000,
			ScreenshotDir:  t.TempDir(),
		})
	if err != nil {
		t.Fatalf("Run error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Run returned %d results, want 1", len(results))
	}
}
