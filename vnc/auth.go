package vnc

import (
	"crypto/des"
	"fmt"
)

// Credential is one password candidate. Source records where the candidate
// came from so reports can distinguish the built-in weak-password list from
// an operator-supplied word list.
type Credential struct {
	Password string
	Source   string
}

// Credential sources used in reports.
const (
	SourceDefault  = "default"
	SourceWordList = "word-list"
)

// vncDESKey derives the VNC authentication key from a password: the first
// eight bytes, zero-padded, with the bits of every byte reversed. This
// quirk is part of the RFB specification and is required for
// interoperability.
func vncDESKey(password string) [8]byte {
	var key [8]byte
	for i := 0; i < len(key) && i < len(password); i++ {
		key[i] = reverseBits(password[i])
	}
	return key
}

func reverseBits(b byte) byte {
	var out byte
	for i := 0; i < 8; i++ {
		out <<= 1
		out |= b & 1
		b >>= 1
	}
	return out
}

// vncResponse computes the 16-byte challenge response for a password.
// Exported behaviour is covered by the package tests through Probe.
func vncResponse(password string, challenge []byte) ([]byte, error) {
	if len(challenge) != 16 {
		return nil, fmt.Errorf("challenge must be 16 bytes, got %d", len(challenge))
	}
	key := vncDESKey(password)
	block, err := des.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("create DES cipher: %w", err)
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out, nil
}

// DefaultCredentials is the built-in weak-password list. It intentionally
// stays small: VNC servers commonly have no lockout, but a compact list
// keeps an inventory scan unobtrusive. Operators can extend it with
// -word-list.
//
// The list is data, not policy: it only ever produces a read-only capture
// of the framebuffer, exactly like the passwordless path.
func DefaultCredentials() []Credential {
	passwords := []string{
		"",
		"password",
		"Password",
		"password1",
		"password123",
		"123456",
		"12345678",
		"123456789",
		"1234",
		"12345",
		"1234567890",
		"qwerty",
		"qwerty123",
		"abc123",
		"admin",
		"administrator",
		"root",
		"toor",
		"guest",
		"test",
		"vnc",
		"vncpass",
		"changeme",
		"secret",
		"letmein",
		"welcome",
		"default",
		"raspberry",
		"ubuntu",
		"kali",
	}

	out := make([]Credential, 0, len(passwords))
	for _, p := range passwords {
		// The empty string is a real candidate: some servers accept a blank
		// password while still advertising VNC authentication.
		out = append(out, Credential{Password: p, Source: SourceDefault})
	}
	return out
}
