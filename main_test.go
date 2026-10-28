package main

import (
	"strings"
	"testing"
	"time"
)

func TestResolveFailOn(t *testing.T) {
	tests := []struct {
		name     string
		failOn   string
		baseline string
		interval time.Duration
		want     []string
		wantErr  string
	}{
		{
			name:   "empty value disables the check",
			failOn: "",
			want:   nil,
		},
		{
			name:   "finding categories need no baseline",
			failOn: "passwordless,weak",
			want:   []string{"passwordless", "weak"},
		},
		{
			name:     "baseline categories with -baseline",
			failOn:   "new,resolved",
			baseline: "20261020-090000",
			want:     []string{"new", "resolved"},
		},
		{
			name:     "baseline categories with -interval",
			failOn:   "new",
			interval: 24 * time.Hour,
			want:     []string{"new"},
		},
		{
			name:    "baseline categories without a baseline are rejected",
			failOn:  "new",
			wantErr: "fail-on new requires -baseline",
		},
		{
			name:    "mixed categories still require a baseline",
			failOn:  "weak,changed",
			wantErr: "fail-on changed requires -baseline",
		},
		{
			name:    "unknown category is rejected",
			failOn:  "passwordless,broken",
			wantErr: `unknown category "broken"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveFailOn(tt.failOn, tt.baseline, tt.interval)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("resolveFailOn(%q, %q, %v) error = %v, want containing %q",
						tt.failOn, tt.baseline, tt.interval, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveFailOn(%q, %q, %v): %v", tt.failOn, tt.baseline, tt.interval, err)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("resolveFailOn(%q, %q, %v) = %v, want %v", tt.failOn, tt.baseline, tt.interval, got, tt.want)
			}
		})
	}
}
