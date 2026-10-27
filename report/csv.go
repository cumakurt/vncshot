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
//
// The schema is append-only: existing columns keep their names and relative
// order, and new evidence columns are added as a block before the trailing
// timestamp so the timestamp stays the last field. Downstream scripts index
// columns by position, so a column must never be renamed, removed or moved.
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
	"tls_version",
	"cipher_suite",
	"cert_subject",
	"cert_issuer",
	"cert_not_before",
	"cert_not_after",
	"cert_dns_names",
	"cert_sha256",
	"cert_self_signed",
	"cert_expired",
	"cert_verified",
	"timestamp",
}

// certificateColumnCount is the number of certificate evidence columns. A
// result without a certificate still renders this many empty fields so every
// row keeps the header width.
const certificateColumnCount = 11

// WriteCSV exports the results as RFC 4180 CSV. Rows are sorted by IP and
// port so the output is deterministic regardless of the caller's order, and
// the file is written owner-only because it can contain weak credentials.
func WriteCSV(path string, results []Result) error {
	return WriteCSVWithOptions(path, results, Options{})
}

// WriteCSVWithOptions exports the results as RFC 4180 CSV.
//
// The CSV schema deliberately holds no secret value: it records only whether a
// weak password was found (weak_password) and where it came from
// (password_source), never the credential itself. Redaction therefore has
// nothing to change here, and opts is accepted only to keep the exporter API
// uniform.
func WriteCSVWithOptions(path string, results []Result, opts Options) error {
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
	record := []string{
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
	}
	record = append(record, certificateColumns(r.Certificate)...)
	return append(record, r.Timestamp.UTC().Format(time.RFC3339))
}

// certificateColumns renders the certificate evidence. Every column is empty
// when no certificate was presented: the boolean flags stay empty rather than
// "no" so a consumer can tell clear-text from a certificate that is simply not
// self-signed, expired or verified.
func certificateColumns(cert *Certificate) []string {
	if cert == nil {
		return make([]string, certificateColumnCount)
	}
	return []string{
		cert.Version,
		cert.CipherSuite,
		cert.Subject,
		cert.Issuer,
		certTime(cert.NotBefore),
		certTime(cert.NotAfter),
		strings.Join(cert.DNSNames, ";"),
		cert.Fingerprint,
		yesNo(cert.SelfSigned),
		yesNo(cert.Expired),
		yesNo(cert.Verified),
	}
}

// certTime formats a certificate timestamp in UTC, keeping an unset time
// empty instead of emitting the zero value.
func certTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
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
