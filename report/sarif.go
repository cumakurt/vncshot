package report

import (
	"encoding/json"
	"fmt"
	"os"
)

// SARIFDriverVersion is the tool version reported in the SARIF driver
// descriptor. The CLI sets it from the build information; "dev" is the
// fallback for builds without -ldflags injection.
var SARIFDriverVersion = "dev"

// SARIF 2.1.0 constants. The schema URI is the official OASIS schema for
// SARIF 2.1.0, so editors and pipelines can validate the output directly.
const (
	sarifVersion   = "2.1.0"
	sarifSchemaURI = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	// sarifInformationURI is the project repository rendered as the tool's
	// information URI.
	sarifInformationURI = "https://github.com/cumakurt/vncshot"
)

// SARIF rule identifiers and levels. The mapping is stable so downstream
// CI pipelines can key on the rule ids.
const (
	SARIFRulePasswordless = "passwordless-vnc"
	SARIFRuleWeak         = "weak-credentials"
	SARIFRuleSelfSigned   = "tls-self-signed"
	SARIFRuleExpiring     = "certificate-expiring"

	sarifLevelError   = "error"
	sarifLevelWarning = "warning"
)

// sarifRule describes one finding class emitted by WriteSARIF.
type sarifRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     sarifText   `json:"shortDescription"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifRuleSpec is the static definition of one emitted rule.
type sarifRuleSpec struct {
	id    string
	name  string
	text  string
	level string
}

// sarifRuleSpecs is the single source for both the rule descriptors and the
// result levels, so a rule id can never drift from its definition.
var sarifRuleSpecs = map[string]sarifRuleSpec{
	SARIFRulePasswordless: {
		id:    SARIFRulePasswordless,
		name:  "PasswordlessVNC",
		text:  "A VNC endpoint accepts connections without authentication (security type None).",
		level: sarifLevelError,
	},
	SARIFRuleWeak: {
		id:    SARIFRuleWeak,
		name:  "WeakCredentials",
		text:  "A VNC endpoint accepts a weak or well-known password.",
		level: sarifLevelError,
	},
	SARIFRuleSelfSigned: {
		id:    SARIFRuleSelfSigned,
		name:  "TLSSelfSigned",
		text:  "A VNC endpoint presents a self-signed TLS certificate.",
		level: sarifLevelWarning,
	},
	SARIFRuleExpiring: {
		id:    SARIFRuleExpiring,
		name:  "CertificateExpiring",
		text:  "A VNC endpoint uses a TLS certificate that expires within the configured warning window.",
		level: sarifLevelWarning,
	},
}

// sarifFinding is one SARIF result before the rule index is resolved.
type sarifFinding struct {
	ruleID  string
	message string
}

// sarifFindings maps one scan result onto the SARIF findings it represents.
// A single result can carry several findings: a host can accept a weak
// password and present an expiring self-signed certificate at the same time.
// The message never contains the captured password itself, only its source.
func sarifFindings(r Result) []sarifFinding {
	var findings []sarifFinding
	if r.Passwordless {
		findings = append(findings, sarifFinding{
			ruleID: SARIFRulePasswordless,
			message: fmt.Sprintf("VNC endpoint %s accepts connections without authentication (security type None)",
				r.Addr()),
		})
	}
	if r.Password != "" {
		source := r.PasswordSource
		if source == "" {
			source = "default list"
		}
		findings = append(findings, sarifFinding{
			ruleID: SARIFRuleWeak,
			message: fmt.Sprintf("VNC endpoint %s accepts a weak password (source: %s)",
				r.Addr(), source),
		})
	}
	if r.Certificate == nil {
		return findings
	}
	if r.Certificate.SelfSigned {
		findings = append(findings, sarifFinding{
			ruleID: SARIFRuleSelfSigned,
			message: fmt.Sprintf("VNC endpoint %s presents a self-signed TLS certificate",
				r.Addr()),
		})
	}
	if r.ExpiresSoon {
		findings = append(findings, sarifFinding{
			ruleID: SARIFRuleExpiring,
			message: fmt.Sprintf("VNC endpoint %s presents a TLS certificate that expires soon",
				r.Addr()),
		})
	}
	return findings
}

// WriteSARIF exports the results as a SARIF 2.1.0 log: one result per
// finding, with stable rule ids and deterministic ordering (rows sorted by
// IP and port, findings per row in rule-definition order). The file is
// written owner-only for consistency with the other report artifacts, even
// though finding messages never carry the captured passwords.
func WriteSARIF(path string, results []Result) error {
	log := buildSARIF(results)

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif report: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write sarif report: %w", err)
	}
	// WriteFile keeps the mode of an existing file, so enforce the
	// owner-only contract explicitly.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict sarif report permissions: %w", err)
	}
	return nil
}

// buildSARIF renders the result set into the SARIF document structure.
func buildSARIF(results []Result) sarifLog {
	sorted := make([]Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	driver := sarifDriver{
		Name:           "vncshot",
		Version:        SARIFDriverVersion,
		InformationURI: sarifInformationURI,
		Rules:          []sarifRule{},
	}
	run := sarifRun{Results: []sarifResult{}}
	ruleIndexes := make(map[string]int)

	for _, r := range sorted {
		for _, finding := range sarifFindings(r) {
			index, ok := ruleIndexes[finding.ruleID]
			if !ok {
				spec := sarifRuleSpecs[finding.ruleID]
				index = len(driver.Rules)
				ruleIndexes[finding.ruleID] = index
				driver.Rules = append(driver.Rules, sarifRule{
					ID:                   spec.id,
					Name:                 spec.name,
					ShortDescription:     sarifText{Text: spec.text},
					DefaultConfiguration: sarifConfig{Level: spec.level},
				})
			}
			run.Results = append(run.Results, sarifResult{
				RuleID:    finding.ruleID,
				RuleIndex: index,
				Level:     sarifRuleSpecs[finding.ruleID].level,
				Message:   sarifText{Text: finding.message},
				Locations: []sarifLocation{{PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifact{URI: r.Addr()},
				}}},
			})
		}
	}

	return sarifLog{
		Version: sarifVersion,
		Schema:  sarifSchemaURI,
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: run.Results}},
	}
}
