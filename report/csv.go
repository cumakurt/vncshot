package report

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// csvHeader is the deterministic column order of the export. Fields are
// kept stable so spreadsheets and downstream scripts can rely on the schema.
var csvHeader = []string{
	"ip",
	"port",
	"open",
	"rfb",
	"passwordless",
	"weak_password",
	"password_source",
	"tls",
	"security_types",
	"server_name",
	"screen_width",
	"screen_height",
	"screenshot",
	"error",
	"duration_ms",
	"attempts",
	"timestamp",
}

// WriteCSV exports the results as RFC 4180 CSV. Rows are sorted by IP and
// port so the output is deterministic regardless of the caller's order, and
// the file is written owner-only because it can contain weak credentials.
func WriteCSV(path string, results []Result) error {
	sorted := make([]Result, len(results))
	copy(sorted, results)
	SortResults(sorted)

	// The explicit mode is subject to the process umask; the chmod below
	// makes the owner-only guarantee independent of it.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create csv report: %w", err)
	}

	writer := csv.NewWriter(file)
	if err := writer.Write(csvHeader); err != nil {
		file.Close()
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, r := range sorted {
		if err := writer.Write(csvRecord(r)); err != nil {
			file.Close()
			return fmt.Errorf("write csv row for %s: %w", r.Addr(), err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		file.Close()
		return fmt.Errorf("flush csv report: %w", err)
	}
	// csv.Writer emits a newline after every record, including the last, so
	// the file always ends with a line terminator.
	if err := file.Close(); err != nil {
		return fmt.Errorf("close csv report: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict csv report permissions: %w", err)
	}
	return nil
}

// csvRecord maps one result to the header order. Booleans use yes/no rather
// than true/false for spreadsheet friendliness, and security types are joined
// with ";" so the list stays inside a single CSV field.
func csvRecord(r Result) []string {
	return []string{
		r.IP,
		strconv.Itoa(r.Port),
		yesNo(r.Open),
		yesNo(r.RFB),
		yesNo(r.Passwordless),
		yesNo(r.Password != ""),
		r.PasswordSource,
		yesNo(r.TLS),
		strings.Join(r.SecurityTypes, ";"),
		r.ServerName,
		strconv.Itoa(r.ScreenWidth),
		strconv.Itoa(r.ScreenHeight),
		r.Screenshot,
		r.Error,
		strconv.FormatInt(r.DurationMs, 10),
		strconv.Itoa(r.Attempts),
		r.Timestamp.UTC().Format(time.RFC3339),
	}
}

// SortResults orders results by IP and then port. Numeric IP ordering is used
// when both addresses parse, so 10.0.0.9 sorts before 10.0.0.10; otherwise
// the addresses are compared as plain strings.
func SortResults(results []Result) {
	sort.SliceStable(results, func(i, j int) bool {
		return compareResults(results[i], results[j]) < 0
	})
}

func compareResults(a, b Result) int {
	if cmp := compareIP(a.IP, b.IP); cmp != 0 {
		return cmp
	}
	switch {
	case a.Port < b.Port:
		return -1
	case a.Port > b.Port:
		return 1
	default:
		return 0
	}
}

// compareIP compares two textual addresses numerically. Mixed families are
// ordered deterministically by their 16-byte representations, and text that
// is not an IP address falls back to lexical ordering.
func compareIP(a, b string) int {
	ipA, ipB := net.ParseIP(a), net.ParseIP(b)
	switch {
	case ipA != nil && ipB != nil:
		return bytes.Compare(ipA.To16(), ipB.To16())
	case ipA != nil:
		return -1
	case ipB != nil:
		return 1
	default:
		return strings.Compare(a, b)
	}
}
