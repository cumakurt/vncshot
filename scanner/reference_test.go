package scanner_test

// The reference inventory is a fixed matrix of known-good and known-bad RFB
// behaviours with committed expected outcomes. Every case is served by an
// in-process fake server on loopback and driven through the real scanner.Run
// pipeline, then compared field by field with testdata/reference/expected.json.
//
// The accuracy line printed by this test is agreement with that answer key for
// this fixed matrix. It is not a real-world prevalence, detection-rate or
// coverage claim: the matrix is deliberately small and every case is synthetic.

import (
	"bytes"
	"context"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"vncshot/report"
	"vncshot/scanner"
	"vncshot/vnc"
)

const (
	// referenceSchemaVersion guards accidental key format changes.
	referenceSchemaVersion = 1
	// referenceAnswerKey is relative to the scanner package directory, which
	// is the working directory of `go test`.
	referenceAnswerKey = "../testdata/reference/expected.json"
	// referenceServerDeadline bounds every fake-server exchange so a wedged
	// client cannot hang the test or its cleanup.
	referenceServerDeadline = 5 * time.Second
	// referenceProbeTimeout bounds one scanner probe. It is generous compared
	// with loopback latency so a slow CI machine does not flake.
	referenceProbeTimeout = 2 * time.Second
)

// referenceExpectation is the answer-key shape for one case. Password, Note,
// Screenshot and Error are presence flags, not values: the key asserts that
// the field is populated, not what its exact content is.
type referenceExpectation struct {
	Open           bool   `json:"open"`
	RFB            bool   `json:"rfb"`
	Passwordless   bool   `json:"passwordless"`
	Password       bool   `json:"password"`
	PasswordSource string `json:"password_source"`
	AuthLocked     bool   `json:"auth_locked"`
	TLS            bool   `json:"tls"`
	SelfSigned     bool   `json:"self_signed"`
	Note           bool   `json:"note"`
	// NoteContains narrows a presence check to a required substring. It is
	// empty for cases where any note is acceptable.
	NoteContains string `json:"note_contains,omitempty"`
	Screenshot   bool   `json:"screenshot"`
	Error        bool   `json:"error"`
}

type referenceKey struct {
	SchemaVersion int                             `json:"schema_version"`
	Cases         map[string]referenceExpectation `json:"cases"`
}

// referenceCase is one row of the matrix plus the server that implements it.
type referenceCase struct {
	id          string
	description string
	expected    referenceExpectation
	passwords   []vnc.Credential
	target      scanner.Target
}

func TestReferenceInventory(t *testing.T) {
	key := loadReferenceKey(t)
	cases := referenceMatrix(t)
	validateReferenceKey(t, cases, key)

	matched := 0
	for _, c := range cases {
		// A separate directory per case makes the "no capture on a negative
		// case" assertion unambiguous.
		screenshotDir := t.TempDir()

		results, err := scanner.Run(context.Background(),
			[]scanner.Target{c.target},
			scanner.Options{
				ConnectTimeout: referenceProbeTimeout,
				VNCTimeout:     referenceProbeTimeout,
				Workers:        4,
				RatePerSec:     0,
				MaxRetries:     0,
				ScreenshotDir:  screenshotDir,
				Shared:         true,
				Passwords:      c.passwords,
			})
		if err != nil {
			t.Fatalf("case %q: scanner.Run error = %v", c.id, err)
		}
		if len(results) != 1 {
			t.Fatalf("case %q: scanner.Run returned %d results, want 1", c.id, len(results))
		}

		r := results[0]
		if compareReferenceCase(t, c, r) {
			matched++
		}
		assertNegativeCase(t, c, r, screenshotDir)
	}

	total := len(cases)
	// Integer division truncates; the value is still exactly matched/total,
	// never an estimate.
	percent := matched * 100 / total
	t.Logf("reference inventory: %d/%d cases matched (%d%%)", matched, total, percent)
}

// loadReferenceKey reads the committed answer key and validates its schema.
func loadReferenceKey(t *testing.T) referenceKey {
	t.Helper()

	raw, err := os.ReadFile(referenceAnswerKey)
	if err != nil {
		t.Fatalf("read reference answer key %s: %v", referenceAnswerKey, err)
	}
	var key referenceKey
	if err := json.Unmarshal(raw, &key); err != nil {
		t.Fatalf("parse reference answer key %s: %v", referenceAnswerKey, err)
	}
	if key.SchemaVersion != referenceSchemaVersion {
		t.Fatalf("reference answer key schema_version = %d, want %d",
			key.SchemaVersion, referenceSchemaVersion)
	}
	if len(key.Cases) == 0 {
		t.Fatalf("reference answer key %s contains no cases", referenceAnswerKey)
	}
	return key
}

// validateReferenceKey fails when the matrix and the answer key drift apart in
// either direction. A missing entry would silently skip a case and an unknown
// entry would describe a server that no longer exists.
func validateReferenceKey(t *testing.T, cases []*referenceCase, key referenceKey) {
	t.Helper()

	matrix := make(map[string]referenceExpectation, len(cases))
	for _, c := range cases {
		if _, exists := matrix[c.id]; exists {
			t.Fatalf("reference matrix contains duplicate case id %q", c.id)
		}
		matrix[c.id] = c.expected
	}

	for _, c := range cases {
		want, ok := key.Cases[c.id]
		if !ok {
			t.Fatalf("reference answer key is missing case %q (%s)", c.id, c.description)
		}
		if !reflect.DeepEqual(want, matrix[c.id]) {
			t.Fatalf("reference answer key drifted for case %q: key = %+v, matrix = %+v",
				c.id, want, matrix[c.id])
		}
	}
	for id := range key.Cases {
		if _, ok := matrix[id]; !ok {
			t.Fatalf("reference answer key contains unknown case %q", id)
		}
	}
}

// compareReferenceCase checks the result against the matrix expectation and
// reports every differing field. It returns true only when the whole case
// matches.
func compareReferenceCase(t *testing.T, c *referenceCase, r report.Result) bool {
	t.Helper()

	actual := referenceExpectation{
		Open:           r.Open,
		RFB:            r.RFB,
		Passwordless:   r.Passwordless,
		Password:       r.Password != "",
		PasswordSource: r.PasswordSource,
		AuthLocked:     r.AuthLocked,
		TLS:            r.TLS,
		SelfSigned:     r.Certificate != nil && r.Certificate.SelfSigned,
		Note:           r.Note != "",
		Screenshot:     r.Screenshot != "",
		Error:          r.Error != "",
	}

	matched := true
	check := func(field string, want, got any) {
		if reflect.DeepEqual(want, got) {
			return
		}
		matched = false
		t.Errorf("case %q: field %s: expected %v, got %v (%s)",
			c.id, field, want, got, c.description)
	}

	check("open", c.expected.Open, actual.Open)
	check("rfb", c.expected.RFB, actual.RFB)
	check("passwordless", c.expected.Passwordless, actual.Passwordless)
	check("password", c.expected.Password, actual.Password)
	check("password_source", c.expected.PasswordSource, actual.PasswordSource)
	check("auth_locked", c.expected.AuthLocked, actual.AuthLocked)
	check("tls", c.expected.TLS, actual.TLS)
	check("self_signed", c.expected.SelfSigned, actual.SelfSigned)
	check("note", c.expected.Note, actual.Note)
	check("screenshot", c.expected.Screenshot, actual.Screenshot)
	check("error", c.expected.Error, actual.Error)

	if c.expected.NoteContains != "" && !strings.Contains(r.Note, c.expected.NoteContains) {
		matched = false
		t.Errorf("case %q: note_contains: expected substring %q, got %q (%s)",
			c.id, c.expected.NoteContains, r.Note, c.description)
	}

	if !matched {
		t.Logf("case %q actual: %+v (note %q, error %q)", c.id, actual, r.Note, r.Error)
	}
	return matched
}

// assertNegativeCase makes a false positive fail loudly. The closed and
// non-RFB cases must not produce a password or any capture file; the same
// assertion is applied to every case whose key says there is no screenshot.
func assertNegativeCase(t *testing.T, c *referenceCase, r report.Result, screenshotDir string) {
	t.Helper()

	if c.expected.Password || c.expected.Screenshot {
		return
	}
	if r.Password != "" {
		t.Errorf("case %q: false positive password %q for a case that must not authenticate", c.id, r.Password)
	}
	if r.Screenshot != "" {
		t.Errorf("case %q: false positive screenshot %q for a case that must not capture", c.id, r.Screenshot)
	}

	entries, err := os.ReadDir(screenshotDir)
	if err != nil {
		t.Fatalf("case %q: read screenshot directory: %v", c.id, err)
	}
	if len(entries) != 0 {
		t.Errorf("case %q: expected no screenshot files, found %d in %s", c.id, len(entries), screenshotDir)
	}
}

// ---------------------------------------------------------------------------
// Matrix definition
// ---------------------------------------------------------------------------

func referenceMatrix(t *testing.T) []*referenceCase {
	t.Helper()

	cert := newReferenceCertificate(t)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	// The X509 case pins TLS 1.2 so the missing client certificate aborts the
	// handshake deterministically. Under TLS 1.3 the client half can complete
	// first, and the probe may stop before the rejection is observed.
	x509Config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAnyClientCert,
	}

	return []*referenceCase{
		referenceServerCase(t, "plain-38",
			"RFB 3.8 advertising only None: passwordless capture",
			referenceExpectation{Open: true, RFB: true, Passwordless: true, Screenshot: true},
			nil, referencePlain38),

		referenceServerCase(t, "plain-37",
			"RFB 3.7 advertising only None without a SecurityResult",
			referenceExpectation{Open: true, RFB: true, Passwordless: true, Screenshot: true},
			nil, referencePlain37),

		referenceServerCase(t, "plain-33",
			"RFB 3.3 announcing one U32 None type",
			referenceExpectation{Open: true, RFB: true, Passwordless: true, Screenshot: true},
			nil, referencePlain33),

		referenceServerCase(t, "weak-default",
			"VNC authentication whose password is in the built-in list",
			referenceExpectation{Open: true, RFB: true, Password: true, PasswordSource: vnc.SourceDefault, Screenshot: true},
			vnc.DefaultCredentials(),
			func(c *refConn) { referenceVNC8Session(c, "password", "ref-weak-default", false) }),

		referenceServerCase(t, "weak-wordlist",
			"VNC authentication whose password is only in the supplied word list",
			referenceExpectation{Open: true, RFB: true, Password: true, PasswordSource: vnc.SourceWordList, Screenshot: true},
			[]vnc.Credential{
				{Password: "not-in-any-list", Source: vnc.SourceWordList},
				{Password: "hunter2", Source: vnc.SourceWordList},
			},
			func(c *refConn) { referenceVNC8Session(c, "hunter2", "ref-weak-wordlist", false) }),

		referenceServerCase(t, "strong",
			"VNC authentication with no candidate matching",
			referenceExpectation{Open: true, RFB: true},
			[]vnc.Credential{
				{Password: "definitely-wrong", Source: vnc.SourceDefault},
				{Password: "also-wrong", Source: vnc.SourceWordList},
			},
			func(c *refConn) { referenceVNC8Session(c, "correct-horse-battery-staple", "ref-strong", false) }),

		referenceServerCase(t, "locked",
			"VNC authentication answering SecurityResult 2, which stops the loop",
			referenceExpectation{Open: true, RFB: true, AuthLocked: true},
			[]vnc.Credential{
				{Password: "wrong", Source: vnc.SourceDefault},
				{Password: "would-have-worked", Source: vnc.SourceWordList},
			},
			func(c *refConn) { referenceVNC8Session(c, "would-have-worked", "ref-locked", true) }),

		referenceServerCase(t, "tls18",
			"Security type 18 (None over TLS) with a self-signed certificate",
			referenceExpectation{Open: true, RFB: true, Passwordless: true, TLS: true, SelfSigned: true, Screenshot: true},
			nil,
			func(c *refConn) { referenceTLS18(c, tlsConfig) }),

		referenceServerCase(t, "vencrypt-257",
			"VeNCrypt TLSNone with a self-signed certificate",
			referenceExpectation{Open: true, RFB: true, Passwordless: true, TLS: true, SelfSigned: true, Screenshot: true},
			nil,
			func(c *refConn) { referenceVeNCrypt(c, tlsConfig, 257) }),

		referenceServerCase(t, "vencrypt-258",
			"VeNCrypt TLSVnc accepting a word-list password",
			referenceExpectation{Open: true, RFB: true, Password: true, PasswordSource: vnc.SourceWordList, TLS: true, SelfSigned: true, Screenshot: true},
			[]vnc.Credential{
				{Password: "not-in-any-list", Source: vnc.SourceWordList},
				{Password: "hunter2", Source: vnc.SourceWordList},
			},
			func(c *refConn) { referenceVeNCryptVnc(c, tlsConfig, "hunter2") }),

		referenceServerCase(t, "client-cert",
			"VeNCrypt X509Vnc requiring a client certificate the probe does not have",
			referenceExpectation{Open: true, RFB: true, TLS: true, SelfSigned: true, Note: true, NoteContains: "client certificate"},
			nil,
			func(c *refConn) { referenceVeNCryptClientCert(c, x509Config) }),

		referenceServerCase(t, "ard-only",
			"RFB advertising only Apple Remote Desktop authentication (type 30)",
			referenceExpectation{Open: true, RFB: true, Note: true, NoteContains: "Apple Remote Desktop"},
			nil, referenceARDOnly),

		referenceServerCase(t, "non-rfb",
			"TCP service that accepts a connection but never speaks RFB",
			referenceExpectation{Open: true, Error: true},
			nil, referenceNonRFB),

		{
			id:          "closed",
			description: "nothing listening on the port",
			target:      scanner.Target{IP: "127.0.0.1", Port: referenceClosedPort(t)},
		},
	}
}

func referenceServerCase(t *testing.T, id, description string, expected referenceExpectation, passwords []vnc.Credential, handler func(*refConn)) *referenceCase {
	t.Helper()
	return &referenceCase{
		id:          id,
		description: description,
		expected:    expected,
		passwords:   passwords,
		target:      startReferenceServer(t, handler),
	}
}

func referenceClosedPort(t *testing.T) int {
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

// ---------------------------------------------------------------------------
// Fake RFB servers
// ---------------------------------------------------------------------------

// refConn is one accepted connection. Reads and writes go straight to the
// socket so a TLS upgrade never loses plaintext buffered in userspace; the
// protocol exchanges are strictly lockstep, so no read-ahead is needed.
type refConn struct {
	conn net.Conn
}

type refServer struct {
	ln net.Listener
	wg sync.WaitGroup
}

func startReferenceServer(t *testing.T, handler func(*refConn)) scanner.Target {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &refServer{ln: ln}

	t.Cleanup(func() {
		s.ln.Close()
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
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(referenceServerDeadline))
				handler(&refConn{conn: conn})
			}()
		}
	}()

	return scanner.Target{IP: "127.0.0.1", Port: ln.Addr().(*net.TCPAddr).Port}
}

func (c *refConn) readN(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *refConn) write(b []byte) error {
	_, err := c.conn.Write(b)
	return err
}

func (c *refConn) writeU32(v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return c.write(b[:])
}

func (c *refConn) sendBanner(banner string) error {
	if err := c.write([]byte(banner)); err != nil {
		return err
	}
	_, err := c.readN(12)
	return err
}

func (c *refConn) sendServerInit(width, height int, name string) error {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(width))
	_ = binary.Write(&buf, binary.BigEndian, uint16(height))
	// 16 bytes of pixel format; the client requests its own format before
	// capture, so the native values are irrelevant here.
	buf.Write(make([]byte, 16))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(name)))
	buf.WriteString(name)
	return c.write(buf.Bytes())
}

// readCaptureMessages consumes SetPixelFormat, SetEncodings and
// FramebufferUpdateRequest in the order the client sends them.
func (c *refConn) readCaptureMessages() error {
	if _, err := c.readN(20); err != nil {
		return err
	}
	if _, err := c.readN(8); err != nil {
		return err
	}
	_, err := c.readN(10)
	return err
}

func (c *refConn) sendSolidUpdate(width, height int) error {
	var buf bytes.Buffer
	buf.WriteByte(0) // FramebufferUpdate
	buf.WriteByte(0) // padding
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(width))
	_ = binary.Write(&buf, binary.BigEndian, uint16(height))
	_ = binary.Write(&buf, binary.BigEndian, int32(0)) // raw encoding
	pixels := make([]byte, width*height*4)
	for i := 0; i < width*height; i++ {
		pixels[i*4+0] = 0x60 // B
		pixels[i*4+1] = 0x40 // G
		pixels[i*4+2] = 0x20 // R
	}
	buf.Write(pixels)
	return c.write(buf.Bytes())
}

func (c *refConn) startTLS(cfg *tls.Config) error {
	tlsConn := tls.Server(c.conn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	c.conn = tlsConn
	return nil
}

// referenceCaptureSession completes a session that is already authenticated
// (or needs no authentication) with one solid raw frame.
func referenceCaptureSession(c *refConn, name string) {
	if err := c.sendServerInit(4, 3, name); err != nil {
		return
	}
	if err := c.readCaptureMessages(); err != nil {
		return
	}
	_ = c.sendSolidUpdate(4, 3)
}

func referencePlain38(c *refConn) {
	if err := c.sendBanner("RFB 003.008\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 1}); err != nil { // one type: None
		return
	}
	if _, err := c.readN(1); err != nil { // security selection
		return
	}
	if err := c.writeU32(0); err != nil { // SecurityResult OK
		return
	}
	if _, err := c.readN(1); err != nil { // ClientInit
		return
	}
	referenceCaptureSession(c, "ref-plain-38")
}

func referencePlain37(c *refConn) {
	if err := c.sendBanner("RFB 003.007\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 1}); err != nil {
		return
	}
	if _, err := c.readN(1); err != nil { // security selection
		return
	}
	// RFB 3.7 sends no SecurityResult for None: ClientInit follows directly.
	if _, err := c.readN(1); err != nil {
		return
	}
	referenceCaptureSession(c, "ref-plain-37")
}

func referencePlain33(c *refConn) {
	if err := c.sendBanner("RFB 003.003\n"); err != nil {
		return
	}
	if err := c.writeU32(1); err != nil { // single U32 type: None
		return
	}
	// RFB 3.3 has no security selection message.
	if _, err := c.readN(1); err != nil { // ClientInit
		return
	}
	referenceCaptureSession(c, "ref-plain-33")
}

// referenceVNC8Session implements RFB 3.8 VNC authentication. It also serves
// the discovery connection, which reads the type list and closes without
// selecting a type.
func referenceVNC8Session(c *refConn, password, name string, lockOnReject bool) {
	if err := c.sendBanner("RFB 003.008\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 2}); err != nil { // one type: VNC authentication
		return
	}
	sel, err := c.readN(1)
	if err != nil || sel[0] != 2 {
		return
	}

	challenge := bytes.Repeat([]byte{0x42}, 16)
	if err := c.write(challenge); err != nil {
		return
	}
	response, err := c.readN(16)
	if err != nil {
		return
	}
	if !bytes.Equal(response, referenceVNCResponse(password, challenge)) {
		if lockOnReject {
			// Status 2 means "too many attempts": the client must stop.
			_ = c.writeU32(2)
			return
		}
		_ = c.writeU32(1)
		reason := []byte("invalid password")
		_ = c.writeU32(uint32(len(reason)))
		_ = c.write(reason)
		return
	}

	if err := c.writeU32(0); err != nil { // SecurityResult OK
		return
	}
	if _, err := c.readN(1); err != nil { // ClientInit
		return
	}
	referenceCaptureSession(c, name)
}

func referenceTLS18(c *refConn, cfg *tls.Config) {
	if err := c.sendBanner("RFB 003.008\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 18}); err != nil { // one type: TLS
		return
	}
	sel, err := c.readN(1)
	if err != nil || sel[0] != 18 {
		return
	}
	if err := c.startTLS(cfg); err != nil {
		return
	}
	if err := c.writeU32(0); err != nil { // SecurityResult OK, None over TLS
		return
	}
	if _, err := c.readN(1); err != nil { // ClientInit
		return
	}
	referenceCaptureSession(c, "ref-tls18")
}

// referenceVeNCryptNegotiate performs the version 0.2 negotiation and accepts
// exactly the offered subtype.
func referenceVeNCryptNegotiate(c *refConn, subtype uint32) error {
	if err := c.write([]byte{0, 2}); err != nil { // server version 0.2
		return err
	}
	if _, err := c.readN(2); err != nil { // client version
		return err
	}
	if err := c.write([]byte{0}); err != nil { // version accepted
		return err
	}
	if err := c.write([]byte{1}); err != nil { // one subtype
		return err
	}
	if err := c.writeU32(subtype); err != nil {
		return err
	}
	if _, err := c.readN(4); err != nil { // selected subtype
		return err
	}
	return c.write([]byte{1}) // subtype accepted
}

func referenceVeNCrypt(c *refConn, cfg *tls.Config, subtype uint32) {
	if err := c.sendBanner("RFB 003.008\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 19}); err != nil { // one type: VeNCrypt
		return
	}
	sel, err := c.readN(1)
	if err != nil || sel[0] != 19 {
		return
	}
	if err := referenceVeNCryptNegotiate(c, subtype); err != nil {
		return
	}
	if err := c.startTLS(cfg); err != nil {
		return
	}
	if err := c.writeU32(0); err != nil { // SecurityResult OK (TLSNone)
		return
	}
	if _, err := c.readN(1); err != nil { // ClientInit
		return
	}
	referenceCaptureSession(c, "ref-vencrypt-tlsnone")
}

func referenceVeNCryptVnc(c *refConn, cfg *tls.Config, password string) {
	if err := c.sendBanner("RFB 003.008\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 19}); err != nil {
		return
	}
	sel, err := c.readN(1)
	if err != nil || sel[0] != 19 {
		return
	}
	if err := referenceVeNCryptNegotiate(c, 258); err != nil { // TLSVnc
		return
	}
	if err := c.startTLS(cfg); err != nil {
		return
	}

	challenge := bytes.Repeat([]byte{0x24}, 16)
	if err := c.write(challenge); err != nil {
		return
	}
	// The discovery connection closes right after the TLS handshake,
	// before answering the challenge, so a read error is expected here.
	response, err := c.readN(16)
	if err != nil {
		return
	}
	if !bytes.Equal(response, referenceVNCResponse(password, challenge)) {
		_ = c.writeU32(1)
		reason := []byte("invalid password")
		_ = c.writeU32(uint32(len(reason)))
		_ = c.write(reason)
		return
	}

	if err := c.writeU32(0); err != nil {
		return
	}
	if _, err := c.readN(1); err != nil { // ClientInit
		return
	}
	referenceCaptureSession(c, "ref-vencrypt-vnc")
}

func referenceVeNCryptClientCert(c *refConn, cfg *tls.Config) {
	if err := c.sendBanner("RFB 003.008\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 19}); err != nil {
		return
	}
	sel, err := c.readN(1)
	if err != nil || sel[0] != 19 {
		return
	}
	if err := referenceVeNCryptNegotiate(c, 261); err != nil { // X509Vnc
		return
	}
	// The probe has no client certificate, so the handshake is expected to
	// fail. Either way the fake server is done after it.
	_ = c.startTLS(cfg)
}

func referenceARDOnly(c *refConn) {
	if err := c.sendBanner("RFB 003.008\n"); err != nil {
		return
	}
	if err := c.write([]byte{1, 30}); err != nil { // one type: Apple Remote Desktop
		return
	}
	// The client records the advertised type and closes without selecting it.
	_, _ = c.readN(1)
}

func referenceNonRFB(c *refConn) {
	// A service that accepts TCP but answers with a non-RFB protocol.
	_ = c.write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
}

// newReferenceCertificate creates a throwaway self-signed certificate in
// memory. The tests must not depend on host certificates or files.
func newReferenceCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vncshot-reference", Organization: []string{"vncshot tests"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"reference.vncshot.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        parsed,
	}
}

// referenceVNCResponse computes the DES challenge response independently of
// the client implementation under test.
func referenceVNCResponse(password string, challenge []byte) []byte {
	var key [8]byte
	for i := 0; i < len(key) && i < len(password); i++ {
		b := password[i]
		var reversed byte
		for bit := 0; bit < 8; bit++ {
			reversed <<= 1
			reversed |= b & 1
			b >>= 1
		}
		key[i] = reversed
	}
	block, err := des.NewCipher(key[:])
	if err != nil {
		panic(fmt.Sprintf("create DES cipher: %v", err))
	}
	out := make([]byte, 16)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out
}
