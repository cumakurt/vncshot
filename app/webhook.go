package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"time"
)

// Version is the tool version reported to webhook receivers. The CLI and GUI
// set it from their build-time version; it stays "dev" for source builds.
var Version = "dev"

const (
	webhookTimeout       = 10 * time.Second
	webhookResponseLimit = 4 << 10
)

// NotifyWebhook POSTs payload as JSON to endpoint. A non-2xx response is an
// error. Error messages never include the endpoint's query string or userinfo
// because those can carry access tokens.
func NotifyWebhook(ctx context.Context, endpoint string, payload any) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("invalid webhook URL %s", redactEndpoint(endpoint))
	}
	safeEndpoint := redactEndpoint(endpoint)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		// Do not wrap the cause: net/http includes the full URL, including
		// the query string, in its parse errors.
		return fmt.Errorf("build webhook request for %s: invalid request URL", safeEndpoint)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "vncshot/"+Version)

	client := &http.Client{Timeout: webhookTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post webhook %s: %w", safeEndpoint, redactedCause(err))
	}
	defer resp.Body.Close()

	// Drain a bounded amount so the connection can be reused without
	// trusting the receiver to keep its response small.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, webhookResponseLimit))

	if resp.StatusCode < http.StatusOK || resp.StatusCode > http.StatusMultipleChoices-1 {
		return fmt.Errorf("post webhook %s: unexpected status %s", safeEndpoint, resp.Status)
	}
	return nil
}

// redactedCause strips the request URL from transport errors, which would
// otherwise expose the query string.
func redactedCause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// redactEndpoint returns endpoint without query, fragment or userinfo. Text
// that does not parse as a URL is replaced entirely rather than echoed.
func redactEndpoint(endpoint string) string {
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" {
		return "<webhook endpoint>"
	}
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.User = nil
	return parsed.String()
}

// webhookFinding is the redacted form of a result sent to a webhook receiver:
// it deliberately has no password field.
type webhookFinding struct {
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	Open           bool   `json:"open"`
	RFB            bool   `json:"rfb"`
	Passwordless   bool   `json:"passwordless"`
	PasswordSource string `json:"password_source,omitempty"`
	TLS            bool   `json:"tls"`
	ServerName     string `json:"server_name,omitempty"`
	Error          string `json:"error,omitempty"`
	Accepted       bool   `json:"accepted,omitempty"`
}

// webhookWeakCredential names a host reached with a weak password without
// disclosing the password itself.
type webhookWeakCredential struct {
	IP             string `json:"ip"`
	Port           int    `json:"port"`
	PasswordSource string `json:"password_source"`
	// Accepted records that the operator has already approved this finding,
	// so a receiver can separate new risk from known-approved noise.
	Accepted bool `json:"accepted,omitempty"`
}

// webhookCertEntry mirrors the trust posture of one TLS peer. Only the
// subject SHA-256 fingerprint travels: the subject text itself is
// server-selected input that must not be echoed wholesale.
type webhookCertEntry struct {
	IP            string `json:"ip"`
	Port          int    `json:"port"`
	SubjectSHA256 string `json:"subject_sha256"`
	SelfSigned    bool   `json:"self_signed"`
	Expired       bool   `json:"expired"`
	// ExpiresAt is the certificate not-after time, RFC3339 UTC.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// webhookPayload builds the JSON body for a completed scan. The run directory
// is reduced to its base name so the receiver never learns the local path.
func webhookPayload(out Outcome, version string) map[string]any {
	newFindings := make([]webhookFinding, 0)
	if out.Diff != nil {
		for _, r := range out.Diff.New {
			newFindings = append(newFindings, webhookFinding{
				IP:             r.IP,
				Port:           r.Port,
				Open:           r.Open,
				RFB:            r.RFB,
				Passwordless:   r.Passwordless,
				PasswordSource: r.PasswordSource,
				TLS:            r.TLS,
				ServerName:     r.ServerName,
				Error:          r.Error,
				Accepted:       r.Accepted,
			})
		}
	}

	weakCredentials := make([]webhookWeakCredential, 0)
	for _, r := range out.Results {
		if r.Password == "" {
			continue
		}
		weakCredentials = append(weakCredentials, webhookWeakCredential{
			IP:             r.IP,
			Port:           r.Port,
			PasswordSource: r.PasswordSource,
			Accepted:       r.Accepted,
		})
	}

	certificates := make([]webhookCertEntry, 0)
	for _, r := range out.Results {
		if !r.TLS || r.Certificate == nil {
			continue
		}
		entry := webhookCertEntry{
			IP:            r.IP,
			Port:          r.Port,
			SubjectSHA256: r.Certificate.Fingerprint,
			SelfSigned:    r.Certificate.SelfSigned,
			Expired:       r.Certificate.Expired,
		}
		if !r.Certificate.NotAfter.IsZero() {
			entry.ExpiresAt = r.Certificate.NotAfter.UTC().Format(time.RFC3339)
		}
		certificates = append(certificates, entry)
	}

	return map[string]any{
		"tool":             "vncshot",
		"version":          version,
		"generated_at":     time.Now().UTC().Format(time.RFC3339),
		"run_dir":          filepath.Base(out.RunDir),
		"summary":          out.Summary,
		"new_findings":     newFindings,
		"weak_credentials": weakCredentials,
		"certificates":     certificates,
	}
}

// shouldNotifyWebhook reports whether a run carries something worth waking an
// operator for.
func shouldNotifyWebhook(out Outcome) bool {
	if out.Diff != nil && len(out.Diff.New) > 0 {
		return true
	}
	return out.Summary.Passwordless > 0 || out.Summary.WeakCredentials > 0
}
