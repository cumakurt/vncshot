package vnc

import (
	"bytes"
	"crypto/des"
	"testing"
)

// TestVNCDESKeyBitReversal pins the bit-reversal quirk of VNC
// authentication. The expected bytes are written out literally so a change
// to the transformation is caught.
func TestVNCDESKeyBitReversal(t *testing.T) {
	cases := []struct {
		password string
		want     [8]byte
	}{
		// '1'=0x31 -> 0x8C, '2'=0x32 -> 0x4C, '3'=0x33 -> 0xCC, '4'=0x34 -> 0x2C
		{"1234", [8]byte{0x8C, 0x4C, 0xCC, 0x2C, 0, 0, 0, 0}},
		{"", [8]byte{}},
		// Longer than eight bytes is truncated.
		{"123456789", [8]byte{0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C}},
	}
	for _, tc := range cases {
		if got := vncDESKey(tc.password); got != tc.want {
			t.Errorf("vncDESKey(%q) = % x, want % x", tc.password, got, tc.want)
		}
	}
}

func TestReverseBits(t *testing.T) {
	for in, want := range map[byte]byte{
		0x00: 0x00,
		0xFF: 0xFF,
		0x01: 0x80,
		0x80: 0x01,
		0xF0: 0x0F,
		0xA5: 0xA5,
	} {
		if got := reverseBits(in); got != want {
			t.Errorf("reverseBits(%#02x) = %#02x, want %#02x", in, got, want)
		}
	}
}

// TestVNCAuthenticationResponseMatchesStandardDES checks the response
// against an independent DES computation using the same key schedule the
// RFB specification mandates.
func TestVNCAuthenticationResponseMatchesStandardDES(t *testing.T) {
	challenge := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}
	key := [8]byte{0x8C, 0x4C, 0xCC, 0x2C, 0, 0, 0, 0} // "1234"
	block, err := des.NewCipher(key[:])
	if err != nil {
		t.Fatalf("des.NewCipher: %v", err)
	}
	want := make([]byte, 16)
	block.Encrypt(want[0:8], challenge[0:8])
	block.Encrypt(want[8:16], challenge[8:16])

	got, err := vncResponse("1234", challenge)
	if err != nil {
		t.Fatalf("vncResponse: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("vncResponse = % x, want % x", got, want)
	}
}

func TestVNCAuthenticationResponseRejectsBadChallengeLength(t *testing.T) {
	if _, err := vncResponse("x", make([]byte, 8)); err == nil {
		t.Fatal("vncResponse accepted an 8-byte challenge, want an error")
	}
}

func TestDefaultCredentialsAreUsableAndUnique(t *testing.T) {
	creds := DefaultCredentials()
	if len(creds) == 0 {
		t.Fatal("DefaultCredentials returned no candidates")
	}

	seen := make(map[string]struct{}, len(creds))
	for _, c := range creds {
		if c.Source != SourceDefault {
			t.Errorf("credential %q has source %q, want %q", c.Password, c.Source, SourceDefault)
		}
		if _, dup := seen[c.Password]; dup {
			t.Errorf("duplicate default credential %q", c.Password)
		}
		seen[c.Password] = struct{}{}
	}

	for _, required := range []string{"", "password", "admin"} {
		if _, ok := seen[required]; !ok {
			t.Errorf("default credential list is missing %q", required)
		}
	}
}
