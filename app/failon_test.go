package app

import (
	"strings"
	"testing"
	"time"

	"vncshot/report"
)

func TestParseFailOnCategories(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    []string
		wantErr string
	}{
		{name: "empty disables the check", value: "", want: nil},
		{name: "blank disables the check", value: "   ", want: nil},
		{name: "single category", value: "passwordless", want: []string{"passwordless"}},
		{name: "case is normalised", value: "Passwordless,Weak", want: []string{"passwordless", "weak"}},
		{name: "duplicates are deduplicated", value: "new,NEW,passwordless", want: []string{"new", "passwordless"}},
		{name: "blank entries are skipped", value: " weak,,passwordless, ", want: []string{"weak", "passwordless"}},
		{name: "all categories", value: "new,resolved,changed,passwordless,weak,self-signed,cert-expiring",
			want: []string{"new", "resolved", "changed", "passwordless", "weak", "self-signed", "cert-expiring"}},
		{name: "unknown category is rejected", value: "passwordless,broken",
			wantErr: `fail-on: unknown category "broken"`},
		{name: "typo is rejected with the accepted list", value: "certs",
			wantErr: "accepted: new, resolved, changed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFailOnCategories(tt.value)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ParseFailOnCategories(%q) error = %v, want containing %q", tt.value, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseFailOnCategories(%q): %v", tt.value, err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("ParseFailOnCategories(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// failOnFixture covers every predicate: one passwordless host, one weak
// host, one self-signed TLS host with a certificate inside the expiry
// window, one valid CA-signed TLS host, one closed port and one result that
// has no findings at all.
func failOnFixture(now time.Time) []report.Result {
	return []report.Result{
		{IP: "10.0.0.5", Port: 5900, Open: true, RFB: true, Passwordless: true},
		{IP: "10.0.0.6", Port: 5900, Open: true, RFB: true, Password: "hunter2", PasswordSource: "word-list"},
		{
			IP: "10.0.0.7", Port: 5900, Open: true, RFB: true, TLS: true,
			Certificate: &report.Certificate{
				SelfSigned: true,
				NotAfter:   now.Add(10 * 24 * time.Hour),
			},
		},
		{
			IP: "10.0.0.8", Port: 5900, Open: true, RFB: true, TLS: true,
			Certificate: &report.Certificate{
				SelfSigned: false,
				NotAfter:   now.Add(365 * 24 * time.Hour),
			},
		},
		{IP: "10.0.0.9", Port: 5900, Open: false, Error: "connection refused"},
	}
}

func TestEvaluateFailOnFindingCategories(t *testing.T) {
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	results := failOnFixture(now)

	tests := []struct {
		name       string
		categories []string
		certWarn   time.Duration
		want       []FailOnMatch
	}{
		{
			name:       "passwordless matches",
			categories: []string{"passwordless"},
			want:       []FailOnMatch{{Category: "passwordless", Count: 1}},
		},
		{
			name:       "weak matches word-list source",
			categories: []string{"weak"},
			want:       []FailOnMatch{{Category: "weak", Count: 1}},
		},
		{
			name:       "self-signed matches only the self-signed certificate",
			categories: []string{"self-signed"},
			want:       []FailOnMatch{{Category: "self-signed", Count: 1}},
		},
		{
			name:       "cert-expiring uses the warning window",
			categories: []string{"cert-expiring"},
			certWarn:   30 * 24 * time.Hour,
			want:       []FailOnMatch{{Category: "cert-expiring", Count: 1}},
		},
		{
			name:       "disabled warning window never matches",
			categories: []string{"cert-expiring"},
			certWarn:   0,
			want:       nil,
		},
		{
			name:       "clean categories never match",
			categories: []string{"new", "resolved", "changed"},
			want:       nil,
		},
		{
			name:       "request order is preserved",
			categories: []string{"weak", "passwordless", "self-signed"},
			want: []FailOnMatch{
				{Category: "weak", Count: 1},
				{Category: "passwordless", Count: 1},
				{Category: "self-signed", Count: 1},
			},
		},
		{
			name:       "multiple matches report per-category counts",
			categories: []string{"passwordless", "weak", "self-signed", "cert-expiring"},
			certWarn:   30 * 24 * time.Hour,
			want: []FailOnMatch{
				{Category: "passwordless", Count: 1},
				{Category: "weak", Count: 1},
				{Category: "self-signed", Count: 1},
				{Category: "cert-expiring", Count: 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateFailOn(results, nil, tt.categories, now, tt.certWarn)
			if len(got) != len(tt.want) {
				t.Fatalf("EvaluateFailOn = %+v, want %+v", got, tt.want)
			}
			for i, match := range got {
				if match != tt.want[i] {
					t.Errorf("match %d = %+v, want %+v", i, match, tt.want[i])
				}
			}
		})
	}
}

func TestEvaluateFailOnBaselineCategories(t *testing.T) {
	diff := &Diff{
		New:      []report.Result{{IP: "10.0.0.5", Port: 5900, Passwordless: true}},
		Resolved: []report.Result{{IP: "10.0.0.6", Port: 5900}},
		Changed:  []Change{{Reason: "became passwordless"}},
	}

	tests := []struct {
		name       string
		diff       *Diff
		categories []string
		want       []FailOnMatch
	}{
		{name: "new findings match", diff: diff, categories: []string{"new"},
			want: []FailOnMatch{{Category: "new", Count: 1}}},
		{name: "resolved findings match", diff: diff, categories: []string{"resolved"},
			want: []FailOnMatch{{Category: "resolved", Count: 1}}},
		{name: "changed findings match", diff: diff, categories: []string{"changed"},
			want: []FailOnMatch{{Category: "changed", Count: 1}}},
		{name: "nil diff never matches baseline categories", diff: nil, categories: []string{"new", "resolved", "changed"},
			want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			now := time.Now()
			got := EvaluateFailOn(nil, tt.diff, tt.categories, now, 0)
			if len(got) != len(tt.want) {
				t.Fatalf("EvaluateFailOn = %+v, want %+v", got, tt.want)
			}
			for i, match := range got {
				if match != tt.want[i] {
					t.Errorf("match %d = %+v, want %+v", i, match, tt.want[i])
				}
			}
		})
	}
}

func TestFailOnMatchDetail(t *testing.T) {
	tests := []struct {
		match FailOnMatch
		want  string
	}{
		{FailOnMatch{Category: "passwordless", Count: 2}, "2 passwordless host(s)"},
		{FailOnMatch{Category: "weak", Count: 3}, "3 weak credential(s)"},
		{FailOnMatch{Category: "self-signed", Count: 1}, "1 self-signed certificate(s)"},
		{FailOnMatch{Category: "cert-expiring", Count: 4}, "4 certificate(s) expiring soon"},
		{FailOnMatch{Category: "new", Count: 5}, "5 new finding(s)"},
		{FailOnMatch{Category: "resolved", Count: 6}, "6 resolved finding(s)"},
		{FailOnMatch{Category: "changed", Count: 7}, "7 changed finding(s)"},
	}
	for _, tt := range tests {
		t.Run(tt.match.Category, func(t *testing.T) {
			if got := tt.match.Detail(); got != tt.want {
				t.Errorf("Detail() = %q, want %q", got, tt.want)
			}
		})
	}
}
