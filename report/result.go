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
	AuthLocked   bool      `json:"auth_locked,omitempty"`
	ServerName   string    `json:"server_name,omitempty"`
	ScreenWidth  int       `json:"screen_width,omitempty"`
	ScreenHeight int       `json:"screen_height,omitempty"`
	Screenshot   string    `json:"screenshot,omitempty"`
	Error        string    `json:"error,omitempty"`
	DurationMs   int64     `json:"duration_ms"`
	Timestamp    time.Time `json:"timestamp"`
}

// Summary aggregates the counters shown at the top of the reports.
type Summary struct {
	Targets      int `json:"targets"`
	Open         int `json:"open"`
	RFB          int `json:"rfb"`
	Passwordless int `json:"passwordless"`
	// WeakCredentials counts hosts reached with a weak password.
	WeakCredentials int `json:"weak_credentials"`
	Screenshots     int `json:"screenshots"`
	Errors          int `json:"errors"`
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
