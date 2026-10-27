package report

import "time"

// Result is the outcome of probing a single host:port pair.
type Result struct {
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Open         bool   `json:"open"`
	RFB          bool   `json:"rfb"`
	Passwordless bool   `json:"passwordless"`
	// Password is the weak credential that granted access, if any. Reports
	// containing it are sensitive and are written with owner-only permissions.
	Password       string `json:"password,omitempty"`
	PasswordSource string `json:"password_source,omitempty"`
	// AuthLocked records that the server refused further authentication
	// attempts, so the operator knows the word list was cut short.
	AuthLocked bool `json:"auth_locked,omitempty"`
	// SecurityTypes lists the RFB security types the server advertised, as
	// human-readable names (for example "VNC authentication", "VeNCrypt").
	SecurityTypes []string `json:"security_types,omitempty"`
	// TLS is true when the server offers an encrypted security type, i.e.
	// the session can be confidential rather than clear-text.
	TLS bool `json:"tls,omitempty"`
	// Certificate summarises the peer certificate when a TLS session was
	// actually established. Nil for clear-text RFB.
	Certificate *Certificate `json:"certificate,omitempty"`
	// Attempts is how many TCP connection attempts were needed, which
	// exposes flaky hosts that only answered after a retry.
	Attempts     int       `json:"attempts,omitempty"`
	ServerName   string    `json:"server_name,omitempty"`
	ScreenWidth  int       `json:"screen_width,omitempty"`
	ScreenHeight int       `json:"screen_height,omitempty"`
	Screenshot   string    `json:"screenshot,omitempty"`
	Error        string    `json:"error,omitempty"`
	DurationMs   int64     `json:"duration_ms"`
	Timestamp    time.Time `json:"timestamp"`
}

// Certificate is the evidence collected from a VNC server's TLS certificate.
// The probe records the certificate instead of trusting it: embedded VNC
// appliances almost always use self-signed certificates, and an inventory
// should report that rather than fail the connection.
type Certificate struct {
	Version     string    `json:"tls_version,omitempty"`
	CipherSuite string    `json:"cipher_suite,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	DNSNames    []string  `json:"dns_names,omitempty"`
	// Fingerprint is the SHA-256 digest of the DER certificate.
	Fingerprint string `json:"sha256_fingerprint,omitempty"`
	// SelfSigned is true when the certificate names itself as its issuer.
	SelfSigned bool `json:"self_signed,omitempty"`
	// Expired is true when NotAfter is in the past at scan time.
	Expired bool `json:"expired,omitempty"`
	// Verified is true only when the chain validated against the system
	// roots, so a self-signed certificate reports false.
	Verified bool `json:"verified,omitempty"`
}

// Summary aggregates the counters shown at the top of the reports.
type Summary struct {
	Targets      int `json:"targets"`
	Open         int `json:"open"`
	RFB          int `json:"rfb"`
	Passwordless int `json:"passwordless"`
	// WeakCredentials counts hosts reached with a weak password.
	WeakCredentials int `json:"weak_credentials"`
	// TLS counts RFB services that offer an encrypted security type.
	TLS         int `json:"tls_services"`
	Screenshots int `json:"screenshots"`
	Errors      int `json:"errors"`
}

// Summarize counts the outcomes in results.
func Summarize(results []Result) Summary {
	s := Summary{Targets: len(results)}
	for _, r := range results {
		if r.Open {
			s.Open++
		}
		if r.RFB {
			s.RFB++
		}
		if r.Passwordless {
			s.Passwordless++
		}
		if r.Password != "" {
			s.WeakCredentials++
		}
		if r.TLS {
			s.TLS++
		}
		if r.Screenshot != "" {
			s.Screenshots++
		}
		if r.Error != "" {
			s.Errors++
		}
	}
	return s
}

// Addr returns the conventional "ip:port" form.
func (r Result) Addr() string {
	return r.IP + ":" + itoa(r.Port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
