package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCountExpiringSoon pins the counting semantics of the expiry warning:
// the window is the closed interval [0, within] over the remaining validity
// NotAfter.Sub(now), evaluated against the caller's clock.
func TestCountExpiringSoon(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	window := 30 * 24 * time.Hour

	certExpiringIn := func(d time.Duration) *Certificate {
		return &Certificate{NotAfter: now.Add(d)}
	}

	tests := []struct {
		name    string
		results []Result
		now     time.Time
		within  time.Duration
		want    int
	}{
		{
			name:    "empty results",
			results: nil,
			now:     now,
			within:  window,
			want:    0,
		},
		{
			name:    "no certificate",
			results: []Result{{IP: "192.0.2.1", Open: true, RFB: true}},
			now:     now,
			within:  window,
			want:    0,
		},
		{
			name: "nil certificate",
			results: []Result{
				{IP: "192.0.2.2", Certificate: nil},
			},
			now:    now,
			within: window,
			want:   0,
		},
		{
			name: "certificate without NotAfter",
			results: []Result{
				{IP: "192.0.2.3", Certificate: &Certificate{}},
			},
			now:    now,
			within: window,
			want:   0,
		},
		{
			name: "inside the window",
			results: []Result{
				{IP: "192.0.2.4", Certificate: certExpiringIn(10 * 24 * time.Hour)},
			},
			now:    now,
			within: window,
			want:   1,
		},
		{
			name: "boundary inclusive at the window edge",
			results: []Result{
				{IP: "192.0.2.5", Certificate: certExpiringIn(window)},
			},
			now:    now,
			within: window,
			want:   1,
		},
		{
			name: "boundary inclusive at the report clock",
			results: []Result{
				{IP: "192.0.2.6", Certificate: certExpiringIn(0)},
			},
			now:    now,
			within: window,
			want:   1,
		},
		{
			name: "one nanosecond beyond the window",
			results: []Result{
				{IP: "192.0.2.7", Certificate: certExpiringIn(window + 1)},
			},
			now:    now,
			within: window,
			want:   0,
		},
		{
			// An already-expired certificate is the expired state, not
			// "expiring soon"; it is counted elsewhere.
			name: "already expired",
			results: []Result{
				{IP: "192.0.2.8", Certificate: certExpiringIn(-1)},
			},
			now:    now,
			within: window,
			want:   0,
		},
		{
			name: "zero window disables the count",
			results: []Result{
				{IP: "192.0.2.9", Certificate: certExpiringIn(1)},
			},
			now:    now,
			within: 0,
			want:   0,
		},
		{
			name: "negative window disables the count",
			results: []Result{
				{IP: "192.0.2.10", Certificate: certExpiringIn(10 * 24 * time.Hour)},
			},
			now:    now,
			within: -time.Hour,
			want:   0,
		},
		{
			name: "counts several hosts and skips clear text",
			results: []Result{
				{IP: "192.0.2.11", Certificate: certExpiringIn(3 * 24 * time.Hour)},
				{IP: "192.0.2.12", Certificate: certExpiringIn(400 * 24 * time.Hour)},
				{IP: "192.0.2.13"},
				{IP: "192.0.2.14", Certificate: certExpiringIn(-time.Second)},
				{IP: "192.0.2.15", Certificate: certExpiringIn(window - time.Second)},
			},
			now:    now,
			within: window,
			want:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountExpiringSoon(tt.results, tt.now, tt.within); got != tt.want {
				t.Fatalf("CountExpiringSoon() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestCountExpiringSoonGoldenFixture ties the golden fixture to the counting
// helper: the fixture host 198.51.100.80 expires 20 days after the fixed
// golden clock, exactly the condition the caller turns into ExpiresSoon, and
// the other fixtures fall outside the default 30-day window.
func TestCountExpiringSoonGoldenFixture(t *testing.T) {
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	const certWarnWindow = 30 * 24 * time.Hour

	if got := CountExpiringSoon(goldenResults(), base, certWarnWindow); got != 1 {
		t.Fatalf("CountExpiringSoon(goldenResults) = %d, want 1 (the 198.51.100.80 fixture)", got)
	}
}

// TestResultCertificateTagsExpiringSoon covers the badge list that the HTML
// and PDF renderers share: the expiring marker joins the existing trust tags
// without replacing them and stays absent without the caller's flag.
func TestResultCertificateTagsExpiringSoon(t *testing.T) {
	t.Run("appended to the trust tags", func(t *testing.T) {
		r := Result{
			ExpiresSoon: true,
			Certificate: &Certificate{SelfSigned: true},
		}

		tags := resultCertificateTags(r)
		want := []certificateTag{
			{"self-signed", "tag hot"},
			{"expires soon", "tag hot"},
		}
		if len(tags) != len(want) {
			t.Fatalf("resultCertificateTags() = %v, want %v", tags, want)
		}
		for i, tag := range want {
			if tags[i] != tag {
				t.Errorf("tag %d = %v, want %v", i, tags[i], tag)
			}
		}
	})

	t.Run("absent without the flag", func(t *testing.T) {
		r := Result{Certificate: &Certificate{Verified: true}}

		tags := resultCertificateTags(r)
		for _, tag := range tags {
			if tag.Label == "expires soon" {
				t.Fatalf("resultCertificateTags() contains %q without ExpiresSoon", tag.Label)
			}
		}
	})

	t.Run("no certificate", func(t *testing.T) {
		if tags := resultCertificateTags(Result{ExpiresSoon: true}); len(tags) != 0 {
			t.Fatalf("resultCertificateTags() = %v, want empty for a nil certificate", tags)
		}
	})
}

// TestWriteHTMLExpiringSoonMarker renders the certificate section for an
// expiring certificate and checks the shared badge appears in the HTML.
func TestWriteHTMLExpiringSoonMarker(t *testing.T) {
	results := []Result{{
		IP:          "192.0.2.240",
		Port:        5900,
		Open:        true,
		RFB:         true,
		TLS:         true,
		ExpiresSoon: true,
		Certificate: &Certificate{
			Subject:    "CN=soon.local",
			Issuer:     "CN=soon.local",
			NotBefore:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:   time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
			SelfSigned: true,
		},
	}}

	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, results); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	html := readHTML(t, path)

	mustContain(t, html, `>expires soon<`, "expiring-soon badge on the certificate entry")
	mustContain(t, html, "CN=soon.local", "certificate section entry")
}

// TestWritePDFExpiringSoonTag renders a PDF whose certificate entry carries
// the expiring marker, mainly to exercise the shared tag path end to end.
func TestWritePDFExpiringSoonTag(t *testing.T) {
	results := []Result{{
		IP:          "192.0.2.241",
		Port:        5900,
		Open:        true,
		RFB:         true,
		TLS:         true,
		ExpiresSoon: true,
		Certificate: &Certificate{
			Subject:  "CN=soon.local",
			Issuer:   "CN=soon.local",
			NotAfter: time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC),
		},
	}}

	path := filepath.Join(t.TempDir(), "report.pdf")
	if err := WritePDF(path, results); err != nil {
		t.Fatalf("WritePDF: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("stat pdf: %v", err)
	}
	requireValidPDF(t, path)
}
