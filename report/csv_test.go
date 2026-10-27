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
		"duration_ms", "attempts", "timestamp",
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
		"/captures/lab.png", "", "123", "2", "2026-10-27T09:15:30Z",
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
	if closed[16] != "2026-10-27T09:16:30Z" {
		t.Fatalf("csv closed row timestamp = %q, want RFC 3339 UTC", closed[16])
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
	if got, want := records[1][16], "2026-10-27T09:00:00Z"; got != want {
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

func TestWriteCSVUnwritablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist", "out.csv")
	if err := WriteCSV(path, nil); err == nil {
		t.Fatal("WriteCSV to missing directory: want error, got nil")
	}
}
