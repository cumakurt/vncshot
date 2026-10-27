package vnc_test

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"vncshot/vnc"
)

// newSelfSignedCertificate builds a throwaway certificate in memory. Tests
// must never depend on certificates or files from the host.
func newSelfSignedCertificate(t *testing.T, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vnc-test", Organization: []string{"vncshot tests"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"vnc-test.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert := newSelfSignedCertificate(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// bufferedConn makes a listener socket readable through the bufio.Reader the
// plaintext handshake used, so bytes already read ahead are not lost when the
// server switches to TLS.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }

// startTLS upgrades the fake server side of the connection.
func (s *rfbServer) startTLS(cfg *tls.Config) {
	s.t.Helper()
	tlsConn := tls.Server(&bufferedConn{Conn: s.conn, r: s.r}, cfg)
	if err := tlsConn.Handshake(); err != nil {
		s.t.Errorf("fake server: TLS handshake: %v", err)
		return
	}
	s.conn = tlsConn
	s.r = bufio.NewReader(tlsConn)
	s.w = bufio.NewWriter(tlsConn)
}

// readN is the non-fatal counterpart of mustRead: for the discovery
// connection the client may close as soon as it has the certificate.
func (s *rfbServer) readN(n int) ([]byte, error) {
	s.t.Helper()
	buf := make([]byte, n)
	_, err := io.ReadFull(s.r, buf)
	return buf, err
}

// veNCryptNegotiate runs the version/subtype exchange for version 0.2 and
// accepts exactly one offered subtype.
func (s *rfbServer) veNCryptNegotiate(subtype uint32) {
	s.t.Helper()

	s.mustWrite([]byte{0, 2}) // server version
	if got := s.mustRead(2); !bytes.Equal(got, []byte{0, 2}) {
		s.t.Errorf("fake server: VeNCrypt version reply = %v, want [0 2]", got)
	}
	s.mustWrite([]byte{0}) // version accepted
	s.mustWrite([]byte{1}) // one subtype
	s.mustWriteU32(subtype)
	got := s.mustRead(4)
	if binary.BigEndian.Uint32(got) != subtype {
		s.t.Errorf("fake server: selected subtype = %d, want %d", binary.BigEndian.Uint32(got), subtype)
	}
	s.mustWrite([]byte{1}) // subtype accepted
}

// serveRFBConns serves every accepted connection. The probe uses one
// connection for discovery and one per password candidate on encrypted
// servers, so these tests need a listener that stays open.
func serveRFBConns(t *testing.T, handler func(s *rfbServer)) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(probeTimeout + time.Second))
				handler(&rfbServer{
					t:    t,
					conn: conn,
					r:    bufio.NewReader(conn),
					w:    bufio.NewWriter(conn),
				})
			}()
		}
	}()

	t.Cleanup(func() {
		ln.Close()
		<-done
		wg.Wait()
	})
	return ln.Addr().String()
}

func TestProbeTLSAnonymous(t *testing.T) {
	cfg := testTLSConfig(t)
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 18}) // TLS only
		if sel := s.mustRead(1); sel[0] != 18 {
			s.t.Errorf("fake server: security selection = %d, want 18 (TLS)", sel[0])
		}

		s.startTLS(cfg)
		s.mustWriteU32(0) // SecurityResult: OK, None-over-TLS
		_ = s.mustRead(1) // ClientInit
		s.sendServerInit(4, 3, "tls-desktop")
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
		t.Error("Passwordless = false, want true for TLS (18)")
	}
	if !result.TLS {
		t.Error("TLS = false, want true")
	}
	if result.Frame == nil {
		t.Fatal("Frame is nil, want a capture over TLS")
	}
	assertRedPixel(t, result.Frame)
	if result.ServerName != "tls-desktop" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "tls-desktop")
	}
	if result.Width != 4 || result.Height != 3 {
		t.Errorf("geometry = %dx%d, want 4x3", result.Width, result.Height)
	}

	info := result.TLSInfo
	if info == nil {
		t.Fatal("TLSInfo is nil, want the server certificate")
	}
	if !info.SelfSigned {
		t.Error("TLSInfo.SelfSigned = false, want true for a self-signed certificate")
	}
	if info.Verified {
		t.Error("TLSInfo.Verified = true, want false for an untrusted self-signed certificate")
	}
	if info.Fingerprint == "" {
		t.Error("TLSInfo.Fingerprint is empty")
	}
	if got := len(bytes.Split([]byte(info.Fingerprint), []byte(":"))); got != 32 {
		t.Errorf("fingerprint has %d groups, want 32 SHA-256 bytes", got)
	}
	if info.NotAfter.IsZero() {
		t.Error("TLSInfo.NotAfter is zero")
	}
	if info.Subject == "" || info.Issuer == "" || info.Version == "" || info.CipherSuite == "" {
		t.Errorf("TLSInfo = %+v, want subject, issuer, version and cipher suite", info)
	}
}

func TestProbeVeNCryptTLSNone(t *testing.T) {
	cfg := testTLSConfig(t)
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 19}) // VeNCrypt only
		if sel := s.mustRead(1); sel[0] != 19 {
			s.t.Errorf("fake server: security selection = %d, want 19 (VeNCrypt)", sel[0])
		}
		s.veNCryptNegotiate(257) // TLSNone
		s.startTLS(cfg)
		s.mustWriteU32(0) // SecurityResult: OK
		_ = s.mustRead(1) // ClientInit
		s.sendServerInit(4, 3, "vencrypt-none")
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
	if !result.Passwordless {
		t.Error("Passwordless = false, want true for VeNCrypt/TLSNone")
	}
	if result.AuthRequired {
		t.Error("AuthRequired = true, want false for VeNCrypt/TLSNone")
	}
	if result.Frame == nil {
		t.Fatal("Frame is nil, want a capture over VeNCrypt/TLSNone")
	}
	assertRedPixel(t, result.Frame)
	if result.ServerName != "vencrypt-none" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "vencrypt-none")
	}
	if result.TLSInfo == nil {
		t.Fatal("TLSInfo is nil, want the server certificate")
	}
	if !result.TLSInfo.SelfSigned || result.TLSInfo.Verified {
		t.Errorf("TLSInfo = %+v, want a self-signed, unverified certificate", result.TLSInfo)
	}

	found := false
	for _, name := range result.SecurityTypeNames {
		if name == "VeNCrypt/TLSNone" {
			found = true
		}
	}
	if !found {
		t.Errorf("SecurityTypeNames = %v, want it to contain %q", result.SecurityTypeNames, "VeNCrypt/TLSNone")
	}
}

func TestProbeVeNCryptTLSVncAcceptsPassword(t *testing.T) {
	cfg := testTLSConfig(t)
	addr := serveRFBConns(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 19})
		if sel := s.mustRead(1); sel[0] != 19 {
			s.t.Errorf("fake server: security selection = %d, want 19", sel[0])
		}
		s.veNCryptNegotiate(258) // TLSVnc
		s.startTLS(cfg)

		s.mustWrite(challenge)
		// The discovery connection closes right after the TLS handshake,
		// before answering the challenge; that is expected.
		got, err := s.readN(16)
		if err != nil {
			return
		}
		if !bytes.Equal(got, expectedResponse("hunter2")) {
			s.mustWriteU32(1) // failure
			s.writeFailureReason("invalid password")
			return
		}

		s.mustWriteU32(0) // SecurityResult: OK
		_ = s.mustRead(1) // ClientInit
		s.sendServerInit(4, 3, "vencrypt-vnc")
		s.readCaptureMessages()
		s.sendSolidRawRect(4, 3, 255, 0, 0)
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout: probeTimeout,
		Shared:  true,
		Passwords: []vnc.Credential{
			{Password: "wrong-one", Source: vnc.SourceWordList},
			{Password: "hunter2", Source: vnc.SourceWordList},
		},
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if result.Password != "hunter2" {
		t.Errorf("Password = %q, want %q", result.Password, "hunter2")
	}
	if result.PasswordSource != vnc.SourceWordList {
		t.Errorf("PasswordSource = %q, want %q", result.PasswordSource, vnc.SourceWordList)
	}
	if result.Frame == nil {
		t.Fatal("Frame is nil, want a capture after TLSVnc authentication")
	}
	assertRedPixel(t, result.Frame)
	if result.ServerName != "vencrypt-vnc" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "vencrypt-vnc")
	}
	if result.TLSInfo == nil {
		t.Fatal("TLSInfo is nil, want the server certificate")
	}
	if result.TLSInfo.Verified {
		t.Error("TLSInfo.Verified = true, want false for a self-signed certificate")
	}
}

func TestProbeVeNCryptUnsupportedSubtype(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 19})
		if sel := s.mustRead(1); sel[0] != 19 {
			s.t.Errorf("fake server: security selection = %d, want 19", sel[0])
		}
		s.mustWrite([]byte{0, 2}) // server version
		s.mustRead(2)             // client version
		s.mustWrite([]byte{0})    // version accepted
		s.mustWrite([]byte{1})    // one subtype
		s.mustWriteU32(260)       // X509None: not implemented
		// The client must stop without selecting a subtype.
		_, _ = io.Copy(io.Discard, s.r)
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
	if !result.AuthRequired {
		t.Error("AuthRequired = false, want true")
	}
	if !result.TLS {
		t.Error("TLS = false, want true for an offered VeNCrypt subtype")
	}
	if result.TLSInfo != nil {
		t.Error("TLSInfo is non-nil, want nil when the subtype is not implemented")
	}
	if result.Frame != nil {
		t.Error("Frame is non-nil, want nil without a completed session")
	}
}

func TestProbeBindsLocalAddress(t *testing.T) {
	addr := serveRFB(t, func(s *rfbServer) {
		s.sendBanner("RFB 003.008\n")
		s.mustWrite([]byte{1, 1}) // None only
		s.mustRead(1)             // security selection
		s.mustWriteU32(0)         // SecurityResult: OK
		s.mustRead(1)             // ClientInit
		s.sendServerInit(4, 3, "bound-desktop")
		s.readCaptureMessages()
		s.sendSolidRawRect(4, 3, 255, 0, 0)
	})

	result, err := vnc.Probe(t.Context(), addr, vnc.Options{
		Timeout:   probeTimeout,
		Shared:    true,
		LocalAddr: net.ParseIP("127.0.0.1"),
	})
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !result.Passwordless {
		t.Error("Passwordless = false, want true")
	}
	if result.ServerName != "bound-desktop" {
		t.Errorf("ServerName = %q, want %q", result.ServerName, "bound-desktop")
	}
}
