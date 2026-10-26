package vnc

import (
	"bufio"
	"context"
	"fmt"
	"image"
	"net"
	"time"
)

// Options controls a single RFB probe.
type Options struct {
	// Timeout bounds each network read/write. The caller is expected to
	// cancel ctx for an overall operation deadline.
	Timeout time.Duration
	// Shared requests a shared session so the probe does not disconnect
	// an existing viewer. Inventory scans should leave this enabled.
	Shared bool
}

// Result is what a probe learned about one endpoint.
type Result struct {
	// Passwordless is true when the server offered the "None" security
	// type and the session was established without credentials.
	Passwordless bool
	// AuthTypes lists the security types the server advertised, when the
	// protocol version provides a list (3.7+).
	AuthTypes []uint8
	// ServerName is the desktop name from ServerInit.
	ServerName string
	Width      int
	Height     int
	// Frame is the captured framebuffer. Nil when the server requires
	// authentication or capture failed.
	Frame image.Image
}

// Probe dials addr, performs the RFB handshake and, when the server
// allows unauthenticated access, captures the current framebuffer.
//
// A server that requires authentication is reported through Result with
// Passwordless=false and a nil Frame; that is not an error.
func Probe(ctx context.Context, addr string, opts Options) (*Result, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}

	dialer := net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	// Fail the whole probe if the caller cancels, even while blocked in I/O.
	stop := context.AfterFunc(ctx, func() {
		conn.SetDeadline(time.Now())
	})
	defer stop()

	c := &client{
		conn:   conn,
		r:      bufio.NewReaderSize(conn, 64*1024),
		w:      bufio.NewWriterSize(conn, 32*1024),
		opts:   opts,
		result: &Result{},
	}

	if err := c.handshake(); err != nil {
		return nil, err
	}
	// The handshake succeeded: this endpoint speaks RFB. Auth refusal is
	// a finding, not a probe failure.
	return c.result, nil
}

type client struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	opts Options

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

	if err := c.write(formatVersion(major, minor)); err != nil {
		return fmt.Errorf("write protocol version: %w", err)
	}

	// 2. Security handshake.
	passwordless, err := c.securityHandshake()
	if err != nil {
		return err
	}
	c.result.Passwordless = passwordless

	// 3. ClientInit / ServerInit.
	if err := c.initSession(); err != nil {
		return err
	}
	if !passwordless {
		// Authenticated servers are still inventory findings, but we have
		// no credentials and cannot continue.
		return nil
	}

	// 4. Capture the current framebuffer.
	return c.capture()
}

func (c *client) write(b []byte) error {
	c.setDeadline()
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	return c.w.Flush()
}

// securityHandshake selects the "None" security type when offered and
// reports whether the session is therefore passwordless.
func (c *client) securityHandshake() (bool, error) {
	major, minor := c.version[0], c.version[1]

	// RFB 3.3 announces a single security type as U32.
	if major == 3 && minor <= 3 {
		c.setDeadline()
		raw, err := readU32(c.r)
		if err != nil {
			return false, fmt.Errorf("read security type: %w", err)
		}
		if raw == uint32(secTypeInvalid) {
			return false, c.readFailure("security negotiation")
		}
		// 3.3 only uses the low byte of the type in practice, but the
		// field is a full U32; reject anything outside the known range.
		secType := uint8(raw)
		if raw > 0xFF {
			return false, fmt.Errorf("unsupported security type %d", raw)
		}
		c.result.AuthTypes = []uint8{secType}
		if secType != secTypeNone {
			return false, nil
		}
		// 3.3 + None: no SecurityResult, proceed to ClientInit.
		return true, nil
	}

	// RFB 3.7/3.8: a list of security types.
	c.setDeadline()
	n, err := readU8(c.r)
	if err != nil {
		return false, fmt.Errorf("read security types: %w", err)
	}
	if n == 0 {
		return false, c.readFailure("security negotiation")
	}
	types, err := readN(c.r, int(n))
	if err != nil {
		return false, fmt.Errorf("read security type list: %w", err)
	}
	c.result.AuthTypes = append([]uint8(nil), types...)

	hasNone := false
	for _, t := range types {
		if t == secTypeNone {
			hasNone = true
			break
		}
	}
	if !hasNone {
		return false, nil
	}

	if err := c.write([]byte{secTypeNone}); err != nil {
		return false, fmt.Errorf("select security type: %w", err)
	}

	// 3.8 sends SecurityResult for every security type, including None.
	if minor >= 8 {
		c.setDeadline()
		status, err := readU32(c.r)
		if err != nil {
			return false, fmt.Errorf("read security result: %w", err)
		}
		if status != 0 {
			return false, c.readFailure("security result")
		}
	}
	return true, nil
}

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
