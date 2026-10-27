package vnc

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"
)

func TestTLSInfoFromState(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour)
	subject := []byte("CN=expired-test")
	expired := &x509.Certificate{
		Raw:        []byte{0x01, 0x02, 0x03},
		RawSubject: subject,
		RawIssuer:  subject,
		Subject:    pkix.Name{CommonName: "expired-test"},
		Issuer:     pkix.Name{CommonName: "expired-test"},
		NotBefore:  past.Add(-time.Hour),
		NotAfter:   past,
		DNSNames:   []string{"expired.test"},
	}

	state := tls.ConnectionState{
		Version:          tls.VersionTLS12,
		CipherSuite:      tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{expired},
	}
	info := tlsInfoFromState(state, "expired.test")
	if info == nil {
		t.Fatal("tlsInfoFromState returned nil")
	}
	if !info.Expired {
		t.Error("Expired = false, want true")
	}
	if !info.SelfSigned {
		t.Error("SelfSigned = false, want true when subject == issuer")
	}
	if info.Verified {
		t.Error("Verified = true, want false for a certificate outside the system roots")
	}
	if info.Version != "TLS 1.2" {
		t.Errorf("Version = %q, want %q", info.Version, "TLS 1.2")
	}
	if info.ServerName != "expired.test" {
		t.Errorf("ServerName = %q, want %q", info.ServerName, "expired.test")
	}
	if info.Fingerprint == "" {
		t.Error("Fingerprint is empty")
	}
	if !info.NotAfter.Equal(past) {
		t.Errorf("NotAfter = %v, want %v", info.NotAfter, past)
	}

	// A separate issuer must not be reported as self-signed.
	other := *expired
	other.RawIssuer = []byte("CN=test-ca")
	other.Issuer = pkix.Name{CommonName: "test-ca"}
	info = tlsInfoFromState(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{&other},
	}, "")
	if info.SelfSigned {
		t.Error("SelfSigned = true, want false when issuer differs")
	}
	if info.ServerName != "" {
		t.Errorf("ServerName = %q, want empty", info.ServerName)
	}
}

func TestTLSInfoFromStateWithoutCertificate(t *testing.T) {
	info := tlsInfoFromState(tls.ConnectionState{Version: tls.VersionTLS12}, "")
	if info == nil {
		t.Fatal("tlsInfoFromState returned nil")
	}
	if info.Fingerprint != "" || info.Verified {
		t.Errorf("TLSInfo = %+v, want empty certificate fields", info)
	}
}
