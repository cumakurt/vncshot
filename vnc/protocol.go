package vnc

import (
	"encoding/binary"
	"fmt"
	"io"
)

// RFB security types we care about for inventory purposes.
const (
	secTypeInvalid uint8 = 0
	secTypeNone    uint8 = 1
	secTypeVNCAuth uint8 = 2
)

// Encoding types. Only Raw is requested; the pseudo-encodings below may
// still appear in an update and must be understood to stay in sync.
const (
	encRaw         int32 = 0
	encCopyRect    int32 = 1
	encDesktopSize int32 = -223
	encLastRect    int32 = -224
)

// Server -> client message types.
const (
	msgFramebufferUpdate      uint8 = 0
	msgSetColorMapEntries     uint8 = 1
	msgBell                   uint8 = 2
	msgServerCutText          uint8 = 3
	msgEndOfContinuousUpdates uint8 = 155
)

// Client -> server message types.
const (
	msgSetPixelFormat           uint8 = 0
	msgSetEncodings             uint8 = 2
	msgFramebufferUpdateRequest uint8 = 3
)

// maxFramebufferSide caps a declared framebuffer dimension so a hostile
// or broken server cannot make us allocate an unbounded image.
const maxFramebufferSide = 8192

type pixelFormat struct {
	BitsPerPixel uint8
	Depth        uint8
	BigEndian    bool
	TrueColor    bool
	RedMax       uint16
	GreenMax     uint16
	BlueMax      uint16
	RedShift     uint8
	GreenShift   uint8
	BlueShift    uint8
}

// desiredPixelFormat requests 32bpp little-endian true colour
// (0x00RRGGBB), which decodes to raw bytes as B,G,R,padding.
func desiredPixelFormat() pixelFormat {
	return pixelFormat{
		BitsPerPixel: 32,
		Depth:        24,
		BigEndian:    false,
		TrueColor:    true,
		RedMax:       255,
		GreenMax:     255,
		BlueMax:      255,
		RedShift:     16,
		GreenShift:   8,
		BlueShift:    0,
	}
}

func (p pixelFormat) bytes() [16]byte {
	var b [16]byte
	b[0] = p.BitsPerPixel
	b[1] = p.Depth
	if p.BigEndian {
		b[2] = 1
	}
	if p.TrueColor {
		b[3] = 1
	}
	binary.BigEndian.PutUint16(b[4:], p.RedMax)
	binary.BigEndian.PutUint16(b[6:], p.GreenMax)
	binary.BigEndian.PutUint16(b[8:], p.BlueMax)
	b[10] = p.RedShift
	b[11] = p.GreenShift
	b[12] = p.BlueShift
	// b[13:16] is padding and stays zero.
	return b
}

// bytesPerPixel returns the wire size of one pixel, rounded up to whole bytes.
func (p pixelFormat) bytesPerPixel() int {
	return int(p.BitsPerPixel+7) / 8
}

func readU8(r io.Reader) (uint8, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func readU16(r io.Reader) (uint16, error) {
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func readI32(r io.Reader) (int32, error) {
	v, err := readU32(r)
	return int32(v), err
}

func readN(r io.Reader, n int) ([]byte, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative read length %d", n)
	}
	buf := make([]byte, n)
	if n == 0 {
		return buf, nil
	}
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeU8(w io.Writer, v uint8) error {
	_, err := w.Write([]byte{v})
	return err
}

func writeU16(w io.Writer, v uint16) error {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	_, err := w.Write(b[:])
	return err
}

func writeU32(w io.Writer, v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, err := w.Write(b[:])
	return err
}

// parseVersion reads a 12-byte "RFB xxx.yyy\n" banner.
func parseVersion(b []byte) (major, minor int, err error) {
	if len(b) != 12 {
		return 0, 0, fmt.Errorf("unexpected protocol banner length %d", len(b))
	}
	if string(b[:4]) != "RFB " || b[11] != '\n' {
		return 0, 0, fmt.Errorf("malformed protocol banner %q", b)
	}
	if _, err := fmt.Sscanf(string(b[4:11]), "%03d.%03d", &major, &minor); err != nil {
		return 0, 0, fmt.Errorf("malformed protocol version %q: %w", b[4:11], err)
	}
	return major, minor, nil
}

// formatVersion renders the 12-byte banner for a negotiated version.
func formatVersion(major, minor int) []byte {
	return []byte(fmt.Sprintf("RFB %03d.%03d\n", major, minor))
}

// selectVersion picks the highest RFB version both sides support.
// The client implements 3.3, 3.7 and 3.8.
func selectVersion(serverMajor, serverMinor int) (major, minor int) {
	if serverMajor > 3 || (serverMajor == 3 && serverMinor >= 8) {
		return 3, 8
	}
	if serverMajor == 3 && serverMinor == 7 {
		return 3, 7
	}
	return 3, 3
}

func securityTypeName(t uint8) string {
	switch t {
	case secTypeNone:
		return "None"
	case secTypeVNCAuth:
		return "VNC Authentication"
	default:
		return fmt.Sprintf("type %d", t)
	}
}
