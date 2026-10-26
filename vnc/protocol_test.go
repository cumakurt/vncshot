package vnc

import (
	"bytes"
	"io"
	"testing"
)

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name      string
		banner    string
		wantMajor int
		wantMinor int
		wantErr   bool
	}{
		{
			name:      "RFB 3.8",
			banner:    "RFB 003.008\n",
			wantMajor: 3,
			wantMinor: 8,
		},
		{
			name:      "RFB 3.7",
			banner:    "RFB 003.007\n",
			wantMajor: 3,
			wantMinor: 7,
		},
		{
			name:      "RFB 3.3",
			banner:    "RFB 003.003\n",
			wantMajor: 3,
			wantMinor: 3,
		},
		{
			name:      "RFB 4.1",
			banner:    "RFB 004.001\n",
			wantMajor: 4,
			wantMinor: 1,
		},
		{
			name:    "too short",
			banner:  "RFB 003.008",
			wantErr: true,
		},
		{
			name:    "too long",
			banner:  "RFB 003.008\n\n",
			wantErr: true,
		},
		{
			name:    "bad prefix",
			banner:  "RFB0 003.008\n",
			wantErr: true,
		},
		{
			name:    "missing newline",
			banner:  "RFB 003.008 ",
			wantErr: true,
		},
		{
			name:    "non-numeric version",
			banner:  "RFB abc.def\n",
			wantErr: true,
		},
		{
			name:    "empty version",
			banner:  "RFB ....... \n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor, err := parseVersion([]byte(tt.banner))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseVersion(%q) = (%d, %d), want error", tt.banner, major, minor)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseVersion(%q) error: %v", tt.banner, err)
			}
			if major != tt.wantMajor || minor != tt.wantMinor {
				t.Fatalf("parseVersion(%q) = (%d, %d), want (%d, %d)",
					tt.banner, major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestFormatVersionRoundTrip(t *testing.T) {
	versions := []struct{ major, minor int }{
		{3, 3},
		{3, 7},
		{3, 8},
		{4, 1},
		{3, 10},
	}

	for _, v := range versions {
		got := formatVersion(v.major, v.minor)
		if len(got) != 12 {
			t.Fatalf("formatVersion(%d, %d) length = %d, want 12", v.major, v.minor, len(got))
		}
		if got[11] != '\n' {
			t.Fatalf("formatVersion(%d, %d) = %q, want trailing newline", v.major, v.minor, got)
		}
		major, minor, err := parseVersion(got)
		if err != nil {
			t.Fatalf("parseVersion(formatVersion(%d, %d)) error: %v", v.major, v.minor, err)
		}
		if major != v.major || minor != v.minor {
			t.Fatalf("round trip = (%d, %d), want (%d, %d)", major, minor, v.major, v.minor)
		}
	}
}

func TestFormatVersionExactBytes(t *testing.T) {
	got := formatVersion(3, 8)
	want := []byte("RFB 003.008\n")
	if !bytes.Equal(got, want) {
		t.Fatalf("formatVersion(3, 8) = %q, want %q", got, want)
	}
}

func TestSelectVersion(t *testing.T) {
	tests := []struct {
		name                     string
		serverMajor, serverMinor int
		wantMajor, wantMinor     int
	}{
		{name: "server 3.8", serverMajor: 3, serverMinor: 8, wantMajor: 3, wantMinor: 8},
		{name: "server 3.7", serverMajor: 3, serverMinor: 7, wantMajor: 3, wantMinor: 7},
		{name: "server 3.3", serverMajor: 3, serverMinor: 3, wantMajor: 3, wantMinor: 3},
		{name: "server 3.5 negotiates down to 3.3", serverMajor: 3, serverMinor: 5, wantMajor: 3, wantMinor: 3},
		{name: "server 3.0 negotiates down to 3.3", serverMajor: 3, serverMinor: 0, wantMajor: 3, wantMinor: 3},
		{name: "server 4.1 negotiates down to 3.8", serverMajor: 4, serverMinor: 1, wantMajor: 3, wantMinor: 8},
		{name: "server 3.9 negotiates down to 3.8", serverMajor: 3, serverMinor: 9, wantMajor: 3, wantMinor: 8},
		{name: "server 2.9 negotiates down to 3.3", serverMajor: 2, serverMinor: 9, wantMajor: 3, wantMinor: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			major, minor := selectVersion(tt.serverMajor, tt.serverMinor)
			if major != tt.wantMajor || minor != tt.wantMinor {
				t.Fatalf("selectVersion(%d, %d) = (%d, %d), want (%d, %d)",
					tt.serverMajor, tt.serverMinor, major, minor, tt.wantMajor, tt.wantMinor)
			}
		})
	}
}

func TestDesiredPixelFormat(t *testing.T) {
	p := desiredPixelFormat()
	if p.BitsPerPixel != 32 {
		t.Errorf("BitsPerPixel = %d, want 32", p.BitsPerPixel)
	}
	if p.Depth != 24 {
		t.Errorf("Depth = %d, want 24", p.Depth)
	}
	if p.BigEndian {
		t.Error("BigEndian = true, want false (little-endian)")
	}
	if !p.TrueColor {
		t.Error("TrueColor = false, want true")
	}
	if p.RedMax != 255 || p.GreenMax != 255 || p.BlueMax != 255 {
		t.Errorf("channel maxima = (%d, %d, %d), want (255, 255, 255)",
			p.RedMax, p.GreenMax, p.BlueMax)
	}
	if p.RedShift != 16 || p.GreenShift != 8 || p.BlueShift != 0 {
		t.Errorf("channel shifts = (%d, %d, %d), want (16, 8, 0)",
			p.RedShift, p.GreenShift, p.BlueShift)
	}
}

func TestPixelFormatBytes(t *testing.T) {
	p := desiredPixelFormat()
	b := p.bytes()

	want := [16]byte{
		0:  32,  // bits-per-pixel
		1:  24,  // depth
		2:  0,   // little-endian
		3:  1,   // true colour
		4:  0,   // red-max hi
		5:  255, // red-max lo
		6:  0,   // green-max hi
		7:  255, // green-max lo
		8:  0,   // blue-max hi
		9:  255, // blue-max lo
		10: 16,  // red-shift
		11: 8,   // green-shift
		12: 0,   // blue-shift
		13: 0,   // padding
		14: 0,   // padding
		15: 0,   // padding
	}
	if b != want {
		t.Fatalf("bytes() = %v, want %v", b, want)
	}
}

func TestPixelFormatBytesFlagsAndEndian(t *testing.T) {
	p := pixelFormat{
		BitsPerPixel: 16,
		Depth:        16,
		BigEndian:    true,
		TrueColor:    false,
		RedMax:       0x1F,
		GreenMax:     0x3F,
		BlueMax:      0x1F,
		RedShift:     11,
		GreenShift:   5,
		BlueShift:    0,
	}
	b := p.bytes()

	want := [16]byte{
		0:  16,
		1:  16,
		2:  1,
		3:  0,
		4:  0x00,
		5:  0x1F,
		6:  0x00,
		7:  0x3F,
		8:  0x00,
		9:  0x1F,
		10: 11,
		11: 5,
		12: 0,
	}
	if b != want {
		t.Fatalf("bytes() = %v, want %v", b, want)
	}
}

func TestBytesPerPixel(t *testing.T) {
	tests := []struct {
		bpp  uint8
		want int
	}{
		{bpp: 32, want: 4},
		{bpp: 24, want: 3},
		{bpp: 16, want: 2},
		{bpp: 8, want: 1},
		{bpp: 1, want: 1},
		{bpp: 9, want: 2}, // rounds up to whole bytes
	}

	for _, tt := range tests {
		p := pixelFormat{BitsPerPixel: tt.bpp}
		if got := p.bytesPerPixel(); got != tt.want {
			t.Errorf("bitsPerPixel(%d) = %d, want %d", tt.bpp, got, tt.want)
		}
	}
}

func TestReadU8(t *testing.T) {
	r := bytes.NewReader([]byte{0x00, 0xAB, 0xFF})
	for _, want := range []uint8{0x00, 0xAB, 0xFF} {
		got, err := readU8(r)
		if err != nil {
			t.Fatalf("readU8 error: %v", err)
		}
		if got != want {
			t.Fatalf("readU8 = %#02x, want %#02x", got, want)
		}
	}
	if _, err := readU8(r); err != io.EOF {
		t.Fatalf("readU8 on empty reader = %v, want io.EOF", err)
	}
}

func TestReadU16(t *testing.T) {
	r := bytes.NewReader([]byte{0x12, 0x34, 0x00, 0x00, 0xFF, 0xFF})
	for _, want := range []uint16{0x1234, 0x0000, 0xFFFF} {
		got, err := readU16(r)
		if err != nil {
			t.Fatalf("readU16 error: %v", err)
		}
		if got != want {
			t.Fatalf("readU16 = %#04x, want %#04x", got, want)
		}
	}
	if _, err := readU16(r); err != io.EOF {
		t.Fatalf("readU16 on empty reader = %v, want io.EOF", err)
	}
}

func TestReadU16ShortBuffer(t *testing.T) {
	r := bytes.NewReader([]byte{0x12})
	if _, err := readU16(r); err == nil {
		t.Fatal("readU16 on 1-byte reader = nil, want error")
	}
}

func TestReadU32(t *testing.T) {
	r := bytes.NewReader([]byte{
		0xDE, 0xAD, 0xBE, 0xEF,
		0x00, 0x00, 0x00, 0x00,
		0xFF, 0xFF, 0xFF, 0xFF,
	})
	for _, want := range []uint32{0xDEADBEEF, 0, 0xFFFFFFFF} {
		got, err := readU32(r)
		if err != nil {
			t.Fatalf("readU32 error: %v", err)
		}
		if got != want {
			t.Fatalf("readU32 = %#08x, want %#08x", got, want)
		}
	}
	if _, err := readU32(r); err != io.EOF {
		t.Fatalf("readU32 on empty reader = %v, want io.EOF", err)
	}
}

func TestReadI32(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int32
	}{
		{name: "zero", in: []byte{0, 0, 0, 0}, want: 0},
		{name: "positive raw encoding", in: []byte{0, 0, 0, 0}, want: 0},
		{name: "CopyRect encoding", in: []byte{0, 0, 0, 1}, want: 1},
		{name: "DesktopSize pseudo-encoding", in: []byte{0xFF, 0xFF, 0xFF, 0x21}, want: -223},
		{name: "LastRect pseudo-encoding", in: []byte{0xFF, 0xFF, 0xFF, 0x20}, want: -224},
		{name: "negative one", in: []byte{0xFF, 0xFF, 0xFF, 0xFF}, want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readI32(bytes.NewReader(tt.in))
			if err != nil {
				t.Fatalf("readI32 error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("readI32 = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestReadN(t *testing.T) {
	t.Run("reads exact bytes", func(t *testing.T) {
		r := bytes.NewReader([]byte{1, 2, 3, 4, 5})
		got, err := readN(r, 3)
		if err != nil {
			t.Fatalf("readN error: %v", err)
		}
		if !bytes.Equal(got, []byte{1, 2, 3}) {
			t.Fatalf("readN = %v, want [1 2 3]", got)
		}
		rest, err := readN(r, 2)
		if err != nil {
			t.Fatalf("readN rest error: %v", err)
		}
		if !bytes.Equal(rest, []byte{4, 5}) {
			t.Fatalf("readN rest = %v, want [4 5]", rest)
		}
	})

	t.Run("zero length returns empty slice", func(t *testing.T) {
		r := bytes.NewReader([]byte{1})
		got, err := readN(r, 0)
		if err != nil {
			t.Fatalf("readN(0) error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("readN(0) = %v, want empty", got)
		}
		// The unread byte must remain available.
		if b, err := readU8(r); err != nil || b != 1 {
			t.Fatalf("byte after readN(0) = (%d, %v), want (1, nil)", b, err)
		}
	})

	t.Run("negative length errors", func(t *testing.T) {
		if _, err := readN(bytes.NewReader(nil), -1); err == nil {
			t.Fatal("readN(-1) = nil, want error")
		}
	})

	t.Run("short reader errors", func(t *testing.T) {
		if _, err := readN(bytes.NewReader([]byte{1, 2}), 5); err == nil {
			t.Fatal("readN past end = nil, want error")
		}
	})
}

func TestWriteU8(t *testing.T) {
	var buf bytes.Buffer
	if err := writeU8(&buf, 0xAB); err != nil {
		t.Fatalf("writeU8 error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0xAB}) {
		t.Fatalf("writeU8 wrote %v, want [0xab]", buf.Bytes())
	}
}

func TestWriteU16(t *testing.T) {
	var buf bytes.Buffer
	if err := writeU16(&buf, 0x1234); err != nil {
		t.Fatalf("writeU16 error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0x12, 0x34}) {
		t.Fatalf("writeU16 wrote %v, want [0x12 0x34]", buf.Bytes())
	}
}

func TestWriteU32(t *testing.T) {
	var buf bytes.Buffer
	if err := writeU32(&buf, 0xDEADBEEF); err != nil {
		t.Fatalf("writeU32 error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("writeU32 wrote %v, want [0xde 0xad 0xbe 0xef]", buf.Bytes())
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeU8(&buf, 0x01); err != nil {
		t.Fatalf("writeU8 error: %v", err)
	}
	if err := writeU16(&buf, 0x0203); err != nil {
		t.Fatalf("writeU16 error: %v", err)
	}
	if err := writeU32(&buf, 0x04050607); err != nil {
		t.Fatalf("writeU32 error: %v", err)
	}

	u8, err := readU8(&buf)
	if err != nil || u8 != 0x01 {
		t.Fatalf("readU8 = (%#02x, %v), want (0x01, nil)", u8, err)
	}
	u16, err := readU16(&buf)
	if err != nil || u16 != 0x0203 {
		t.Fatalf("readU16 = (%#04x, %v), want (0x0203, nil)", u16, err)
	}
	u32, err := readU32(&buf)
	if err != nil || u32 != 0x04050607 {
		t.Fatalf("readU32 = (%#08x, %v), want (0x04050607, nil)", u32, err)
	}
}

func TestSecurityTypeName(t *testing.T) {
	tests := []struct {
		typ  uint8
		want string
	}{
		{typ: secTypeNone, want: "None"},
		{typ: secTypeVNCAuth, want: "VNC Authentication"},
		{typ: secTypeInvalid, want: "type 0"},
		{typ: 16, want: "type 16"},
	}

	for _, tt := range tests {
		if got := securityTypeName(tt.typ); got != tt.want {
			t.Errorf("securityTypeName(%d) = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestParsePixelFormat(t *testing.T) {
	raw := [16]byte{
		0:  32,
		1:  24,
		2:  1,
		3:  1,
		4:  0x01,
		5:  0x02,
		6:  0x03,
		7:  0x04,
		8:  0x05,
		9:  0x06,
		10: 16,
		11: 8,
		12: 0,
	}
	p := parsePixelFormat(raw[:])

	if p.BitsPerPixel != 32 {
		t.Errorf("BitsPerPixel = %d, want 32", p.BitsPerPixel)
	}
	if p.Depth != 24 {
		t.Errorf("Depth = %d, want 24", p.Depth)
	}
	if !p.BigEndian {
		t.Error("BigEndian = false, want true")
	}
	if !p.TrueColor {
		t.Error("TrueColor = false, want true")
	}
	if p.RedMax != 0x0102 || p.GreenMax != 0x0304 || p.BlueMax != 0x0506 {
		t.Errorf("maxima = (%#x, %#x, %#x), want (0x102, 0x304, 0x506)",
			p.RedMax, p.GreenMax, p.BlueMax)
	}
	if p.RedShift != 16 || p.GreenShift != 8 || p.BlueShift != 0 {
		t.Errorf("shifts = (%d, %d, %d), want (16, 8, 0)",
			p.RedShift, p.GreenShift, p.BlueShift)
	}
}
