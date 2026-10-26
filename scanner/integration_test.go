package scanner_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image/color"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"vncshot/report"
	"vncshot/scanner"
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

// serveConn speaks one RFB 3.8 session. The scanner dials twice per probe
// (a TCP openness check that closes immediately, then the real handshake),
// so short-lived connections must exit cleanly on EOF.
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
