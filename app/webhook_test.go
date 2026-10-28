package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vncshot/report"
)

type capturedRequest struct {
	method      string
	contentType string
	userAgent   string
	body        []byte
}

func captureServer(t *testing.T, status int) (*httptest.Server, <-chan capturedRequest) {
	t.Helper()
	requests := make(chan capturedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- capturedRequest{
			method:      r.Method,
			contentType: r.Header.Get("Content-Type"),
			userAgent:   r.Header.Get("User-Agent"),
			body:        body,
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, requests
}

func TestNotifyWebhookPostsJSON(t *testing.T) {
	server, requests := captureServer(t, http.StatusOK)
	payload := map[string]any{"hello": "world"}

	if err := NotifyWebhook(context.Background(), server.URL, payload); err != nil {
		t.Fatalf("NotifyWebhook: %v", err)
	}

	request := <-requests
	if request.method != http.MethodPost {
		t.Errorf("method = %q, want POST", request.method)
	}
	if request.contentType != "application/json" {
		t.Errorf("content type = %q, want application/json", request.contentType)
	}
	if request.userAgent != "vncshot/"+Version {
		t.Errorf("user agent = %q, want vncshot/%s", request.userAgent, Version)
	}
	var decoded map[string]any
	if err := json.Unmarshal(request.body, &decoded); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if decoded["hello"] != "world" {
		t.Errorf("body = %s, want the payload", request.body)
	}
}

func TestNotifyWebhookAcceptsSuccessStatuses(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, _ := captureServer(t, status)
			if err := NotifyWebhook(context.Background(), server.URL, map[string]any{"ok": true}); err != nil {
				t.Fatalf("NotifyWebhook rejected status %d: %v", status, err)
			}
		})
	}
}

func TestNotifyWebhookRejectsErrorStatus(t *testing.T) {
	server, _ := captureServer(t, http.StatusInternalServerError)
	err := NotifyWebhook(context.Background(), server.URL, map[string]any{})
	if err == nil {
		t.Fatal("NotifyWebhook accepted a 500 response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not mention the status code", err)
	}
}

func TestNotifyWebhookHidesQueryStringInErrors(t *testing.T) {
	const token = "supersecret-token"
	server, _ := captureServer(t, http.StatusInternalServerError)

	err := NotifyWebhook(context.Background(), server.URL+"/hook?token="+token, map[string]any{})
	if err == nil {
		t.Fatal("NotifyWebhook accepted a 500 response")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaks the webhook token: %v", err)
	}

	// A transport failure must be redacted the same way.
	unreachable := "http://127.0.0.1:1/hook?token=" + token
	err = NotifyWebhook(context.Background(), unreachable, map[string]any{})
	if err == nil {
		t.Fatal("NotifyWebhook succeeded against an unreachable endpoint")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("transport error leaks the webhook token: %v", err)
	}
}

func TestNotifyWebhookHonoursContextDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := NotifyWebhook(ctx, server.URL, map[string]any{})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("NotifyWebhook ignored the context deadline")
	}
	if elapsed >= time.Second {
		t.Errorf("NotifyWebhook blocked for %v, want it to stop near the 50ms deadline", elapsed)
	}
}

func TestWebhookPayloadShape(t *testing.T) {
	out := Outcome{
		RunDir:  filepath.Join(string(filepath.Separator)+"var", "lib", "vncshot", "20260101-120000"),
		Summary: report.Summary{Targets: 2, Open: 2, RFB: 2, Passwordless: 1, WeakCredentials: 1},
		Results: []report.Result{
			{IP: "10.0.0.1", Port: 5900, Open: true, RFB: true, Passwordless: true},
			{IP: "10.0.0.2", Port: 5900, Open: true, RFB: true, Password: "do-not-leak", PasswordSource: "wordlist"},
		},
		Diff: &Diff{
			New: []report.Result{
				{IP: "10.0.0.2", Port: 5900, Open: true, RFB: true, Password: "do-not-leak", PasswordSource: "wordlist"},
			},
		},
	}

	data, err := json.Marshal(webhookPayload(out, "1.2.3"))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if strings.Contains(string(data), "do-not-leak") {
		t.Fatalf("payload leaks a password: %s", data)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	assertNoPasswordKey(t, decoded)

	if decoded["run_dir"] != "20260101-120000" {
		t.Errorf("run_dir = %v, want the run directory base name", decoded["run_dir"])
	}
	if decoded["version"] != "1.2.3" {
		t.Errorf("version = %v, want 1.2.3", decoded["version"])
	}
	if generatedAt, ok := decoded["generated_at"].(string); !ok {
		t.Errorf("generated_at = %v, want an RFC3339 string", decoded["generated_at"])
	} else if _, err := time.Parse(time.RFC3339, generatedAt); err != nil {
		t.Errorf("generated_at %q is not RFC3339: %v", generatedAt, err)
	}

	newFindings, ok := decoded["new_findings"].([]any)
	if !ok || len(newFindings) != 1 {
		t.Fatalf("new_findings = %v, want one entry", decoded["new_findings"])
	}
	finding, ok := newFindings[0].(map[string]any)
	if !ok {
		t.Fatalf("new_findings[0] = %v, want an object", newFindings[0])
	}
	if finding["ip"] != "10.0.0.2" || finding["password_source"] != "wordlist" {
		t.Errorf("new finding = %v, want the redacted result", finding)
	}

	weak, ok := decoded["weak_credentials"].([]any)
	if !ok || len(weak) != 1 {
		t.Fatalf("weak_credentials = %v, want one entry", decoded["weak_credentials"])
	}
	credential, ok := weak[0].(map[string]any)
	if !ok {
		t.Fatalf("weak_credentials[0] = %v, want an object", weak[0])
	}
	expected := map[string]any{"ip": "10.0.0.2", "port": float64(5900), "password_source": "wordlist"}
	for key, value := range expected {
		if credential[key] != value {
			t.Errorf("weak credential %s = %v, want %v", key, credential[key], value)
		}
	}
}

func TestWebhookPayloadWithoutBaselineUsesEmptyList(t *testing.T) {
	data, err := json.Marshal(webhookPayload(Outcome{}, "dev"))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	list, ok := decoded["new_findings"].([]any)
	if !ok {
		t.Fatalf("new_findings = %v, want an empty array", decoded["new_findings"])
	}
	if len(list) != 0 {
		t.Errorf("new_findings = %v, want an empty array", list)
	}
}

func TestWebhookPayloadCertificatesAndAccepted(t *testing.T) {
	expires := time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC)
	out := Outcome{
		Summary: report.Summary{Targets: 3, Open: 3, RFB: 3, TLS: 2},
		Results: []report.Result{
			{
				IP: "10.0.0.1", Port: 5900, Open: true, RFB: true, TLS: true,
				Certificate: &report.Certificate{
					Fingerprint: "00aa11",
					SelfSigned:  true,
					Expired:     false,
					NotAfter:    expires,
				},
			},
			{
				IP: "10.0.0.2", Port: 5900, Open: true, RFB: true, TLS: true,
				Password:    "hunter2",
				Accepted:    true,
				Certificate: &report.Certificate{Fingerprint: "bb22cc", Expired: true},
			},
			// Clear-text peer: no TLS, hence no certificates entry.
			{IP: "10.0.0.3", Port: 5900, Open: true, RFB: true},
		},
	}

	data, err := json.Marshal(webhookPayload(out, "1.4.5"))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	certificates, ok := decoded["certificates"].([]any)
	if !ok || len(certificates) != 2 {
		t.Fatalf("certificates = %v, want two entries for the TLS peers", decoded["certificates"])
	}
	certificate, _ := certificates[0].(map[string]any)
	for key, value := range map[string]any{
		"ip":             "10.0.0.1",
		"port":           float64(5900),
		"subject_sha256": "00aa11",
		"self_signed":    true,
		"expired":        false,
		"expires_at":     "2026-12-31T12:00:00Z",
	} {
		if certificate[key] != value {
			t.Errorf("certificate entry %s = %v, want %v", key, certificate[key], value)
		}
	}
	if _, ok := certificates[1].(map[string]any)["expires_at"]; ok {
		t.Error("a peer with an unset not-after time got an expires_at")
	}
}

func TestWebhookPayloadFindingShowsAccepted(t *testing.T) {
	accepted := report.Result{
		IP: "10.0.0.9", Port: 5900, Open: true, RFB: true, Passwordless: true, Accepted: true,
	}
	out := Outcome{Diff: &Diff{New: []report.Result{accepted}}}

	data, err := json.Marshal(webhookPayload(out, "dev"))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if !strings.Contains(string(data), `"accepted":true`) {
		t.Errorf("accepted finding is not marked on the payload: %s", data)
	}
}

func TestShouldNotifyWebhook(t *testing.T) {
	tests := []struct {
		name string
		out  Outcome
		want bool
	}{
		{name: "quiet run", out: Outcome{}, want: false},
		// The alarm predicate reads the results, not the summary counters,
		// so accepted findings can be excluded from the alarm.
		{name: "passwordless host", out: Outcome{Results: []report.Result{{IP: "10.0.0.1", Port: 5900, Passwordless: true}}}, want: true},
		{name: "weak credential", out: Outcome{Results: []report.Result{{IP: "10.0.0.2", Port: 5900, Password: "hunter2"}}}, want: true},
		// Accepted findings are known-approved and must never alarm again.
		{name: "accepted passwordless only", out: Outcome{Results: []report.Result{{IP: "10.0.0.3", Port: 5900, Passwordless: true, Accepted: true}}}, want: false},
		{name: "accepted weak password only", out: Outcome{Results: []report.Result{{IP: "10.0.0.4", Port: 5900, Password: "hunter2", Accepted: true}}}, want: false},
		{name: "mixed accepted and unaccepted", out: Outcome{Results: []report.Result{
			{IP: "10.0.0.5", Port: 5900, Passwordless: true, Accepted: true},
			{IP: "10.0.0.6", Port: 5900, Passwordless: true},
		}}, want: true},
		{name: "new finding", out: Outcome{Diff: &Diff{New: []report.Result{{IP: "10.0.0.1", Port: 5900}}}}, want: true},
		{name: "no new findings", out: Outcome{Diff: &Diff{}}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldNotifyWebhook(tt.out); got != tt.want {
				t.Errorf("shouldNotifyWebhook = %v, want %v", got, tt.want)
			}
		})
	}
}

// assertNoPasswordKey walks a decoded JSON value and fails when any object
// carries a "password" key. "passwordless" and "password_source" are fine.
func assertNoPasswordKey(t *testing.T, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		if _, ok := typed["password"]; ok {
			t.Fatalf("payload contains a password field: %v", typed)
		}
		for _, child := range typed {
			assertNoPasswordKey(t, child)
		}
	case []any:
		for _, child := range typed {
			assertNoPasswordKey(t, child)
		}
	}
}
