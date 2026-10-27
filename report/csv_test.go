package report

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// readCSV parses a rendered export into records.
func readCSV(t *testing.T, path string) [][]string {
	t.Helper()

	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open csv: %v", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	return records
}

func TestWriteCSVHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, nil); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	records := readCSV(t, path)
	if len(records) != 1 {
		t.Fatalf("csv records = %d, want header only", len(records))
	}

	want := []string{
		"ip", "port", "open", "rfb", "passwordless", "weak_password",
		"password_source", "tls", "security_types", "server_name",
		"screen_width", "screen_height", "screenshot", "error",
		"duration_ms", "attempts",
		"tls_version", "cipher_suite", "cert_subject", "cert_issuer",
		"cert_not_before", "cert_not_after", "cert_dns_names", "cert_sha256",
		"cert_self_signed", "cert_expired", "cert_verified",
		"timestamp",
	}
	if !reflect.DeepEqual(records[0], want) {
		t.Fatalf("csv header = %v, want %v", records[0], want)
	}
}

func TestWriteCSVRowMapping(t *testing.T) {
	ts := time.Date(2026, 10, 27, 9, 15, 30, 0, time.UTC)
	results := []Result{
		{
			IP:             "192.0.2.10",
			Port:           5900,
			Open:           true,
			RFB:            true,
			Passwordless:   false,
			Password:       "hunter2",
			PasswordSource: "default",
			SecurityTypes:  []string{"VeNCrypt", "VNC authentication"},
			TLS:            true,
			ServerName:     "Lab box",
			ScreenWidth:    1920,
			ScreenHeight:   1080,
			Screenshot:     "/captures/lab.png",
			DurationMs:     123,
			Attempts:       2,
			Timestamp:      ts,
		},
		{
			IP:        "192.0.2.11",
			Port:      5901,
			Open:      false,
			Error:     "connection refused",
			Timestamp: ts.Add(time.Minute),
		},
	}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	records := readCSV(t, path)
	if len(records) != 3 {
		t.Fatalf("csv records = %d, want header + 2 rows", len(records))
	}

	weak := records[1]
	wantWeak := []string{
		"192.0.2.10", "5900", "yes", "yes", "no", "yes", "default", "yes",
		"VeNCrypt;VNC authentication", "Lab box", "1920", "1080",
		"/captures/lab.png", "", "123", "2",
		"", "", "", "", "", "", "", "", "", "", "",
		"2026-10-27T09:15:30Z",
	}
	if !reflect.DeepEqual(weak, wantWeak) {
		t.Fatalf("csv weak row = %v, want %v", weak, wantWeak)
	}

	closed := records[2]
	if closed[2] != "no" || closed[3] != "no" || closed[4] != "no" ||
		closed[5] != "no" || closed[7] != "no" {
		t.Fatalf("csv closed row booleans = %v, want all no", closed)
	}
	if closed[8] != "" {
		t.Fatalf("csv closed row security_types = %q, want empty", closed[8])
	}
	if closed[27] != "2026-10-27T09:16:30Z" {
		t.Fatalf("csv closed row timestamp = %q, want RFC 3339 UTC", closed[27])
	}
}

func TestWriteCSVSecurityTypesUseSemicolons(t *testing.T) {
	results := []Result{
		{
			IP:            "192.0.2.12",
			Port:          5900,
			Open:          true,
			SecurityTypes: []string{"VeNCrypt", "VNC authentication", "Tight"},
		},
	}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if strings.Contains(string(raw), `"VeNCrypt;VNC`) {
		t.Fatalf("security types should stay in one unquoted field:\n%s", raw)
	}

	records := readCSV(t, path)
	if got := records[1][8]; got != "VeNCrypt;VNC authentication;Tight" {
		t.Fatalf("security_types = %q, want semicolon-joined list", got)
	}
}

func TestWriteCSVSortsNumericallyByIP(t *testing.T) {
	results := []Result{
		{IP: "10.0.0.10", Port: 5901},
		{IP: "192.0.2.1", Port: 5900},
		{IP: "10.0.0.9", Port: 5902},
		{IP: "10.0.0.10", Port: 5900},
	}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	records := readCSV(t, path)
	var got []string
	for _, record := range records[1:] {
		got = append(got, record[0]+":"+record[1])
	}
	want := []string{"10.0.0.9:5902", "10.0.0.10:5900", "10.0.0.10:5901", "192.0.2.1:5900"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("csv order = %v, want %v", got, want)
	}

	// The caller's slice must not be reordered as a side effect.
	if results[0].IP != "10.0.0.10" || results[2].IP != "10.0.0.9" {
		t.Fatalf("WriteCSV reordered the caller's slice: %v", results)
	}
}

func TestSortResultsHandlesNonIPAddresses(t *testing.T) {
	results := []Result{
		{IP: "host-b", Port: 5900},
		{IP: "10.0.0.2", Port: 5900},
		{IP: "host-a", Port: 5901},
		{IP: "10.0.0.10", Port: 5900},
	}

	SortResults(results)
	var got []string
	for _, r := range results {
		got = append(got, r.Addr())
	}
	want := []string{"10.0.0.2:5900", "10.0.0.10:5900", "host-a:5901", "host-b:5900"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SortResults = %v, want %v", got, want)
	}
}

func TestWriteCSVEscapesServerName(t *testing.T) {
	const name = `ACME, Inc. "Lab"`
	results := []Result{
		{IP: "192.0.2.13", Port: 5900, Open: true, ServerName: name},
	}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if !strings.Contains(string(raw), `"ACME, Inc. ""Lab"""`) {
		t.Fatalf("csv does not quote/escape the server name:\n%s", raw)
	}

	records := readCSV(t, path)
	if got := records[1][9]; got != name {
		t.Fatalf("round-tripped server_name = %q, want %q", got, name)
	}
}

func TestWriteCSVTimestampIsRFC3339UTC(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*60*60)
	results := []Result{
		{IP: "192.0.2.14", Port: 5900, Timestamp: time.Date(2026, 10, 27, 12, 0, 0, 0, zone)},
	}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	records := readCSV(t, path)
	if got, want := records[1][27], "2026-10-27T09:00:00Z"; got != want {
		t.Fatalf("timestamp = %q, want %q", got, want)
	}
}

func TestWriteCSVFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, []Result{{IP: "192.0.2.15", Port: 5900}}); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat csv: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("csv permissions = %o, want 600", perm)
	}
}

func TestWriteCSVEndsWithNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, []Result{{IP: "192.0.2.16", Port: 5900}}); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read csv: %v", err)
	}
	if len(raw) == 0 || raw[len(raw)-1] != '\n' {
		t.Fatalf("csv does not end with a newline: %q", raw)
	}
}

// TestWriteCSVRedactionChangesNothing guards the schema: the CSV records only
// the weak_password flag and the credential source, never the secret, so a
// redacted export must be byte-identical to a normal one.
func TestWriteCSVRedactionChangesNothing(t *testing.T) {
	results := []Result{{
		IP:             "192.0.2.17",
		Port:           5900,
		Open:           true,
		RFB:            true,
		Password:       "hunter2",
		PasswordSource: "default",
	}}

	plainPath := filepath.Join(t.TempDir(), "plain.csv")
	redactedPath := filepath.Join(t.TempDir(), "redacted.csv")
	if err := WriteCSV(plainPath, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}
	if err := WriteCSVWithOptions(redactedPath, results, Options{Redact: true}); err != nil {
		t.Fatalf("WriteCSVWithOptions: %v", err)
	}

	plain, err := os.ReadFile(plainPath)
	if err != nil {
		t.Fatalf("read plain csv: %v", err)
	}
	redacted, err := os.ReadFile(redactedPath)
	if err != nil {
		t.Fatalf("read redacted csv: %v", err)
	}
	if string(plain) != string(redacted) {
		t.Errorf("redacted CSV differs from plain CSV:\nplain:\n%s\nredacted:\n%s", plain, redacted)
	}
	if strings.Contains(string(redacted), "hunter2") {
		t.Error("CSV contains the secret password")
	}
}

func TestWriteCSVUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "out.csv")
	if err := WriteCSV(path, nil); err == nil {
		t.Fatal("WriteCSV to missing directory: want error, got nil")
	}
}

// certificateFieldIndexes maps the certificate evidence columns to their
// position in the documented schema, so the tests fail loudly if the order
// drifts rather than silently comparing the wrong fields.
var certificateFieldIndexes = map[string]int{
	"tls_version":      16,
	"cipher_suite":     17,
	"cert_subject":     18,
	"cert_issuer":      19,
	"cert_not_before":  20,
	"cert_not_after":   21,
	"cert_dns_names":   22,
	"cert_sha256":      23,
	"cert_self_signed": 24,
	"cert_expired":     25,
	"cert_verified":    26,
}

// TestWriteCSVCertificateColumnsEmptyWithoutCertificate guards the clear-text
// case: the certificate columns must be empty strings, not "no", so a consumer
// can tell "no certificate" from "certificate that is not self-signed".
func TestWriteCSVCertificateColumnsEmptyWithoutCertificate(t *testing.T) {
	results := []Result{{
		IP:            "192.0.2.20",
		Port:          5900,
		Open:          true,
		RFB:           true,
		SecurityTypes: []string{"VNC authentication"},
	}}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	record := readCSV(t, path)[1]
	if len(record) != len(csvHeader) {
		t.Fatalf("row has %d fields, want %d", len(record), len(csvHeader))
	}
	for name, index := range certificateFieldIndexes {
		if got := record[index]; got != "" {
			t.Errorf("%s = %q without a certificate, want empty", name, got)
		}
	}
}

// TestWriteCSVCertificateColumnsFillsEvidence guards the self-signed case that
// dominates VNC appliances: every certificate column carries its evidence in
// the documented format.
func TestWriteCSVCertificateColumnsFillsEvidence(t *testing.T) {
	zone := time.FixedZone("UTC+3", 3*60*60)
	cert := &Certificate{
		Version:     "TLS 1.3",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Subject:     "CN=vnc-appliance",
		Issuer:      "CN=vnc-appliance",
		NotBefore:   time.Date(2026, 1, 2, 12, 0, 0, 0, zone),
		NotAfter:    time.Date(2027, 1, 2, 12, 0, 0, 0, zone),
		DNSNames:    []string{"vnc.lab.example", "vnc-appliance.local"},
		Fingerprint: "AA:BB:CC:DD",
		SelfSigned:  true,
		Expired:     false,
		Verified:    false,
	}
	results := []Result{{
		IP:          "192.0.2.21",
		Port:        5901,
		Open:        true,
		RFB:         true,
		TLS:         true,
		Certificate: cert,
		Timestamp:   time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC),
	}}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	record := readCSV(t, path)[1]
	want := map[string]string{
		"tls_version":      "TLS 1.3",
		"cipher_suite":     "TLS_AES_128_GCM_SHA256",
		"cert_subject":     "CN=vnc-appliance",
		"cert_issuer":      "CN=vnc-appliance",
		"cert_not_before":  "2026-01-02T09:00:00Z",
		"cert_not_after":   "2027-01-02T09:00:00Z",
		"cert_dns_names":   "vnc.lab.example;vnc-appliance.local",
		"cert_sha256":      "AA:BB:CC:DD",
		"cert_self_signed": "yes",
		"cert_expired":     "no",
		"cert_verified":    "no",
	}
	for name, wantValue := range want {
		if got := record[certificateFieldIndexes[name]]; got != wantValue {
			t.Errorf("%s = %q, want %q", name, got, wantValue)
		}
	}
}

// TestWriteCSVVerifiedCertificateFlags guards the trusted-certificate case:
// the flags must report the certificate as verified but not self-signed.
func TestWriteCSVVerifiedCertificateFlags(t *testing.T) {
	results := []Result{{
		IP:   "192.0.2.22",
		Port: 5902,
		Certificate: &Certificate{
			Subject:    "CN=trusted.example",
			Issuer:     "CN=Lab CA",
			SelfSigned: false,
			Verified:   true,
		},
	}}

	path := filepath.Join(t.TempDir(), "out.csv")
	if err := WriteCSV(path, results); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	record := readCSV(t, path)[1]
	if got := record[certificateFieldIndexes["cert_self_signed"]]; got != "no" {
		t.Errorf("cert_self_signed = %q, want no", got)
	}
	if got := record[certificateFieldIndexes["cert_verified"]]; got != "yes" {
		t.Errorf("cert_verified = %q, want yes", got)
	}
	if got := record[certificateFieldIndexes["cert_expired"]]; got != "no" {
		t.Errorf("cert_expired = %q, want no", got)
	}
}
