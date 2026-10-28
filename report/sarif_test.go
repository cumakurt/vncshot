package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sarifFixture mirrors the golden inventory: every finding class is present
// exactly once, and the input order is deliberately unsorted to prove that
// the SARIF output is ordered by host and port.
func sarifFixture() []Result {
	base := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	return []Result{
		{
			IP:        "192.0.2.11",
			Port:      5900,
			Open:      true,
			RFB:       true,
			Password:  "hunter2",
			Timestamp: base,
		},
		{
			IP:           "192.0.2.10",
			Port:         5900,
			Open:         true,
			RFB:          true,
			Passwordless: true,
			Timestamp:    base,
		},
		{
			IP:          "198.51.100.80",
			Port:        5900,
			Open:        true,
			RFB:         true,
			TLS:         true,
			Timestamp:   base,
			ExpiresSoon: true,
			Certificate: &Certificate{
				SelfSigned: true,
				NotAfter:   base.Add(20 * 24 * time.Hour),
			},
		},
		{
			IP:        "198.51.100.20",
			Port:      5900,
			Open:      true,
			RFB:       true,
			Timestamp: base,
		},
		{
			IP:        "198.51.100.99",
			Port:      5901,
			Open:      false,
			Error:     "connection refused",
			Timestamp: base,
		},
	}
}

func TestWriteSARIFStructure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.sarif")
	if err := WriteSARIF(path, sarifFixture()); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat sarif report: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("sarif mode = %o, want 600", mode)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sarif report: %v", err)
	}
	var log struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name           string `json:"name"`
					Version        string `json:"version"`
					InformationURI string `json:"informationUri"`
					Rules          []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("parse sarif report: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if !strings.HasSuffix(log.Schema, "sarif-schema-2.1.0.json") {
		t.Errorf("$schema = %q, want the official SARIF 2.1.0 schema URL", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	driver := log.Runs[0].Tool.Driver
	if driver.Name != "vncshot" {
		t.Errorf("driver name = %q, want vncshot", driver.Name)
	}
	if driver.Version == "" {
		t.Error("driver version is empty")
	}
	if driver.InformationURI != "https://github.com/cumakurt/vncshot" {
		t.Errorf("informationUri = %q", driver.InformationURI)
	}

	// One result per finding: the fixture has a passwordless host, a weak
	// host, and a TLS host that is both self-signed and expiring.
	results := log.Runs[0].Results
	if len(results) != 4 {
		t.Fatalf("results = %d, want 4: %+v", len(results), results)
	}

	wantOrder := []string{
		"192.0.2.10:5900",
		"192.0.2.11:5900",
		"198.51.100.80:5900",
		"198.51.100.80:5900",
	}
	for i, want := range wantOrder {
		if got := results[i].Locations[0].PhysicalLocation.ArtifactLocation.URI; got != want {
			t.Errorf("result %d uri = %q, want %q (ordering)", i, got, want)
		}
	}

	if results[0].RuleID != SARIFRulePasswordless || results[0].Level != "error" {
		t.Errorf("result 0 = %s/%s, want passwordless-vnc/error", results[0].RuleID, results[0].Level)
	}
	wantMessage := "VNC endpoint 192.0.2.10:5900 accepts connections without authentication (security type None)"
	if results[0].Message.Text != wantMessage {
		t.Errorf("passwordless message = %q, want %q", results[0].Message.Text, wantMessage)
	}
	if results[1].RuleID != SARIFRuleWeak || results[1].Level != "error" {
		t.Errorf("result 1 = %s/%s, want weak-credentials/error", results[1].RuleID, results[1].Level)
	}
	if results[2].RuleID != SARIFRuleSelfSigned || results[2].Level != "warning" {
		t.Errorf("result 2 = %s/%s, want tls-self-signed/warning", results[2].RuleID, results[2].Level)
	}
	if results[3].RuleID != SARIFRuleExpiring || results[3].Level != "warning" {
		t.Errorf("result 3 = %s/%s, want certificate-expiring/warning", results[3].RuleID, results[3].Level)
	}

	// ruleIndex must point into the rules array at the matching rule id, and
	// every referenced rule must carry a description.
	ruleByID := make(map[string]string, len(driver.Rules))
	for _, rule := range driver.Rules {
		ruleByID[rule.ID] = rule.ShortDescription.Text
	}
	for _, result := range results {
		description, ok := ruleByID[result.RuleID]
		if !ok {
			t.Errorf("result ruleId %q has no rule descriptor", result.RuleID)
			continue
		}
		if description == "" {
			t.Errorf("rule %q has an empty description", result.RuleID)
		}
		if result.RuleIndex < 0 || result.RuleIndex >= len(driver.Rules) {
			t.Errorf("result %q ruleIndex %d out of range", result.RuleID, result.RuleIndex)
			continue
		}
		if driver.Rules[result.RuleIndex].ID != result.RuleID {
			t.Errorf("result %q ruleIndex %d points at %q",
				result.RuleID, result.RuleIndex, driver.Rules[result.RuleIndex].ID)
		}
	}

	// Only the rules actually referenced are described.
	if len(driver.Rules) != 4 {
		t.Errorf("rules = %d, want 4", len(driver.Rules))
	}
}

func TestWriteSARIFEmptyScanIsValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.sarif")
	if err := WriteSARIF(path, nil); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sarif report: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("parse sarif report: %v", err)
	}
	runs, ok := document["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("runs = %v, want one run", document["runs"])
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("run = %v, want an object", runs[0])
	}
	if results, ok := run["results"].([]any); !ok || len(results) != 0 {
		t.Errorf("results = %v, want an empty array (not null)", run["results"])
	}
	driver := run["tool"].(map[string]any)["driver"].(map[string]any)
	if driver["name"] != "vncshot" {
		t.Errorf("driver name = %v, want vncshot", driver["name"])
	}
}

func TestSARIFWeakMessageNeverCarriesThePassword(t *testing.T) {
	results := []Result{{
		IP:             "10.0.0.5",
		Port:           5900,
		Open:           true,
		RFB:            true,
		Password:       "hunter2",
		PasswordSource: "word-list",
	}}
	findings := sarifFindings(results[0])
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if strings.Contains(findings[0].message, "hunter2") {
		t.Errorf("message %q contains the captured password", findings[0].message)
	}
	if !strings.Contains(findings[0].message, "source: word-list") {
		t.Errorf("message %q does not name the password source", findings[0].message)
	}
}
