package report

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// thumbMaxWidth bounds embedded card previews so a large report stays
// usable in a browser.
const thumbMaxWidth = 320

// htmlDiffRowLimit caps each baseline group so a large comparison stays a
// compact summary; the remaining count is rendered as a single line.
const htmlDiffRowLimit = 50

// Diff describes how the current scan compares with a baseline run. It mirrors
// the scan pipeline's comparison without importing the application package,
// which already depends on report.
type Diff struct {
	// Baseline names the compared run. Reports render only its base name so
	// the scanner's filesystem layout never leaks into an artifact.
	Baseline string
	// New lists findings that were not present in the baseline.
	New []Result
	// Resolved lists baseline findings that are absent from the current run.
	Resolved []Result
	// Changed lists findings whose risk state differs from the baseline.
	Changed []Change
}

// Change is one finding whose risk state differs from the baseline run.
// Reason is the operator-facing description of the transition, for example
// "became passwordless".
type Change struct {
	Before Result
	After  Result
	Reason string
}

// Empty reports whether the comparison found no differences. A nil diff is
// treated as empty, which keeps callers free of nil checks.
func (d *Diff) Empty() bool {
	return d == nil || (len(d.New) == 0 && len(d.Resolved) == 0 && len(d.Changed) == 0)
}

// hasBaselineSection reports whether a diff should produce a baseline section
// at all. A nil diff means no baseline was requested, so the report stays
// identical to a scan without -baseline.
func hasBaselineSection(diff *Diff) bool {
	return diff != nil
}

// normalizedDiff returns a copy of diff with the baseline reduced to a display
// safe name and every group in canonical order (numeric IP, then port). The
// caller's slices are never modified. Entries are already sorted by the scan
// pipeline; re-sorting here keeps hand-built diffs stable as well.
func normalizedDiff(diff *Diff) *Diff {
	if diff == nil {
		return nil
	}
	out := &Diff{
		Baseline: baselineName(diff.Baseline),
		New:      append([]Result(nil), diff.New...),
		Resolved: append([]Result(nil), diff.Resolved...),
		Changed:  append([]Change(nil), diff.Changed...),
	}
	SortResults(out.New)
	SortResults(out.Resolved)
	sort.SliceStable(out.Changed, func(i, j int) bool {
		return compareResults(out.Changed[i].Before, out.Changed[j].Before) < 0
	})
	return out
}

// baselineName reduces a run reference to its base name so reports never
// contain an absolute filesystem path.
func baselineName(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	base := filepath.Base(filepath.Clean(ref))
	if base == "." || base == string(filepath.Separator) {
		return ""
	}
	return base
}

// diffStateLabel names the endpoint state used by the baseline comparison.
// Closed ports are shown explicitly because a resolved finding frequently
// means the service is simply gone.
func diffStateLabel(r Result) string {
	if !r.Open {
		return "closed"
	}
	return stateLabel(r)
}

// diffTagClass picks the compact state tag style. Weak and unauthenticated
// endpoints keep the warning treatment; other RFB services use the accent
// variant, and plain/closed ports stay muted.
func diffTagClass(r Result) string {
	switch {
	case r.Passwordless || r.Password != "":
		return "tag hot"
	case r.RFB:
		return "tag ok"
	default:
		return "tag"
	}
}

// diffSearchIndex extends the endpoint search index with the change reason so
// the existing report filter also matches baseline rows by their description.
func diffSearchIndex(r Result, reason string) string {
	index := searchIndex(r)
	if reason != "" {
		index += " " + reason
	}
	return index
}

// capDiff keeps at most limit entries and reports how many were dropped.
// A non-positive limit means no cap.
func capDiff[T any](entries []T, limit int) ([]T, int) {
	if limit <= 0 || len(entries) <= limit {
		return entries, 0
	}
	return entries[:limit], len(entries) - limit
}

type cardData struct {
	IP             string
	Port           string
	Addr           string
	ServerName     string
	Dimensions     string
	CapturedAt     string
	DurationMs     string
	Passwordless   bool
	Authenticated  bool
	AuthLocked     bool
	Password       string
	PasswordSource string
	Transport      string
	Attempts       int
	ThumbURL       template.URL
	FullURL        template.URL
	SearchIndex    string
}

type rowData struct {
	IP             string
	Port           string
	Open           bool
	RFB            bool
	Passwordless   bool
	Authenticated  bool
	AuthLocked     bool
	Password       string
	PasswordSource string
	Security       string
	TLS            bool
	CertState      string
	CertStateClass string
	CertValidity   string
	ServerName     string
	Dimensions     string
	Screenshot     string
	Error          string
	DurationMs     string
	Attempts       int
	Timestamp      string
	SearchIndex    string
}

// certificateEntryData is one dossier entry in the certificate section.
type certificateEntryData struct {
	Addr        string
	Subject     string
	Issuer      string
	Window      string
	Fingerprint string
	TLS         string
	Cipher      string
	Tags        []certificateTag
	SearchIndex string
}

type htmlData struct {
	GeneratedAt  string
	Summary      Summary
	Cards        []cardData
	Rows         []rowData
	Certificates []certificateEntryData
	Diff         *htmlDiffData
}

// diffRowData is one line of a baseline comparison group.
type diffRowData struct {
	Addr        string
	Tag         string
	TagClass    string
	Reason      string
	Before      string
	BeforeClass string
	After       string
	AfterClass  string
	SearchIndex string
}

// diffGroupData is one group of the baseline section: New, Resolved or
// Changed. More counts entries omitted by the row cap.
type diffGroupData struct {
	Count int
	Rows  []diffRowData
	More  int
}

// htmlDiffData is the template-facing view of a baseline comparison.
type htmlDiffData struct {
	Baseline string
	Empty    bool
	New      diffGroupData
	Resolved diffGroupData
	Changed  diffGroupData
}

// WriteHTML renders a self-contained HTML report to path. Thumbnails and
// full-size captures are embedded as data URIs so the file can be shared
// as a single artifact.
func WriteHTML(path string, results []Result) error {
	return WriteHTMLWithOptions(path, results, Options{})
}

// WriteHTMLWithDiff renders the report together with a baseline comparison.
// A nil diff keeps the output identical to WriteHTML.
func WriteHTMLWithDiff(path string, results []Result, diff *Diff) error {
	return WriteHTMLWithOptions(path, results, Options{Diff: diff})
}

// WriteHTMLWithOptions renders the report with the requested redaction and
// thumbnail policy. Redaction replaces the captured password on the cards and
// in the endpoint table while the weak / passwordless state stays visible.
// ThumbnailOnly drops the full-resolution data URI so the report carries one
// embedded image per card; the PNG files themselves stay in the run folder.
func WriteHTMLWithOptions(path string, results []Result, opts Options) error {
	diff := normalizedDiff(opts.redactDiff(opts.Diff))

	doc := htmlData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		// Counters describe the observed findings, before redaction hides
		// the secret values.
		Summary: Summarize(results),
	}
	if hasBaselineSection(diff) {
		doc.Diff = buildHTMLDiff(diff)
	}

	for _, r := range opts.apply(results) {
		dims := ""
		if r.ScreenWidth > 0 && r.ScreenHeight > 0 {
			dims = fmt.Sprintf("%dx%d", r.ScreenWidth, r.ScreenHeight)
		}

		if (r.Passwordless || r.Password != "") && r.Screenshot != "" {
			thumb, full, err := embedScreenshot(r.Screenshot)
			if err != nil {
				// A missing/corrupt capture should not drop the finding
				// from the report; keep the card without imagery.
				thumb, full = "", ""
			}
			if opts.ThumbnailOnly {
				// The template only opens the modal when data-full is set,
				// so emptying it also disables the enlarged view.
				full = ""
			}
			doc.Cards = append(doc.Cards, cardData{
				IP:         r.IP,
				Port:       fmt.Sprintf("%d", r.Port),
				Addr:       r.Addr(),
				ServerName: r.ServerName,
				Dimensions: dims,
				// Report timestamps are UTC; label them so they are not
				// confused with the local-clock screenshot file names.
				CapturedAt:     r.Timestamp.UTC().Format("2006-01-02 15:04:05") + " UTC",
				DurationMs:     fmt.Sprintf("%d", r.DurationMs),
				Passwordless:   r.Passwordless,
				Authenticated:  r.Password != "",
				AuthLocked:     r.AuthLocked,
				Password:       r.Password,
				PasswordSource: credentialSourceLabel(r.PasswordSource),
				Transport:      transportDescription(r),
				Attempts:       r.Attempts,
				ThumbURL:       template.URL(thumb),
				FullURL:        template.URL(full),
				SearchIndex:    searchIndex(r),
			})
		}

		// Certificates are evidence from an established TLS session, so they
		// are listed even when the port is not otherwise reported as open.
		if cert := r.Certificate; cert != nil {
			doc.Certificates = append(doc.Certificates, certificateEntryData{
				Addr:        r.Addr(),
				Subject:     certificateFieldValue(cert.Subject),
				Issuer:      certificateFieldValue(cert.Issuer),
				Window:      certificateWindow(cert),
				Fingerprint: certificateFieldValue(certificateFingerprint(cert)),
				TLS:         certificateFieldValue(cert.Version),
				Cipher:      certificateFieldValue(cert.CipherSuite),
				Tags:        resultCertificateTags(r),
				SearchIndex: r.Addr() + " certificate " + certificateFieldValue(cert.Subject),
			})
		}

		// Closed ports are summarised in the counters; listing every one
		// would drown the table on large ranges.
		if !r.Open {
			continue
		}
		doc.Rows = append(doc.Rows, rowData{
			IP:             r.IP,
			Port:           fmt.Sprintf("%d", r.Port),
			Open:           r.Open,
			RFB:            r.RFB,
			Passwordless:   r.Passwordless,
			Authenticated:  r.Password != "",
			AuthLocked:     r.AuthLocked,
			Password:       r.Password,
			PasswordSource: credentialSourceLabel(r.PasswordSource),
			Security:       securitySummary(r.SecurityTypes),
			TLS:            r.TLS,
			CertState:      certificateStateLabel(r.Certificate),
			CertStateClass: certificateStateClass(r.Certificate),
			CertValidity:   certificateValidityLine(r.Certificate),
			ServerName:     r.ServerName,
			Dimensions:     dims,
			// The HTML report is shareable, so it shows only the capture
			// file name rather than the absolute host path.
			Screenshot:  filepath.Base(r.Screenshot),
			Error:       r.Error,
			DurationMs:  fmt.Sprintf("%d", r.DurationMs),
			Attempts:    r.Attempts,
			Timestamp:   r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
			SearchIndex: searchIndex(r),
		})
	}

	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, doc); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	// Reports may contain weak credentials and captured desktops, so they
	// are owner-readable only.
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write html report: %w", err)
	}
	// WriteFile keeps the mode of an existing file, so an explicit -html
	// pointing at a world-readable path would leak the credentials. The
	// documented contract is owner-only, so enforce it.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict html report permissions: %w", err)
	}
	return nil
}

func searchIndex(r Result) string {
	status := "closed"
	switch {
	case r.Passwordless:
		status = "passwordless open"
	case r.RFB:
		status = "authenticated open"
	case r.Open:
		status = "open non-rfb"
	}
	index := fmt.Sprintf("%s %d %s %s", r.IP, r.Port, status, r.ServerName)
	if security := securitySummary(r.SecurityTypes); security != "" {
		index += " " + security
	}
	if r.TLS {
		index += " tls"
	}
	// The "weak password" chip matches by substring, so the term is kept
	// as a single token even though it reads as two words.
	if r.Password != "" {
		index += " weakpassword"
	}
	return index
}

// securityTypeAbbreviations keeps the endpoint table compact without
// inventing names for security types the scanner did not recognise.
var securityTypeAbbreviations = map[string]string{
	"VNC authentication": "VNC auth",
}

// securityTypeLabel abbreviates a single RFB security type for tabular
// output. Unknown types are shown verbatim.
func securityTypeLabel(name string) string {
	name = strings.TrimSpace(name)
	if short, ok := securityTypeAbbreviations[name]; ok {
		return short
	}
	return name
}

// securitySummary joins the advertised security types into one compact cell
// value, for example "VNC auth · VeNCrypt". It returns "" when the server
// advertised none.
func securitySummary(types []string) string {
	labels := make([]string, 0, len(types))
	for _, name := range types {
		if label := securityTypeLabel(name); label != "" {
			labels = append(labels, label)
		}
	}
	return strings.Join(labels, " · ")
}

// transportDescription renders the transport posture in prose, using the
// full security type names: "VeNCrypt (TLS)" or "VNC authentication (clear
// text)". An empty result means the server advertised no security types.
func transportDescription(r Result) string {
	names := make([]string, 0, len(r.SecurityTypes))
	for _, name := range r.SecurityTypes {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	switch {
	case len(names) == 0 && r.TLS:
		return "TLS (encrypted)"
	case len(names) == 0:
		return ""
	case r.TLS:
		return strings.Join(names, " · ") + " (TLS)"
	default:
		return strings.Join(names, " · ") + " (clear text)"
	}
}

// credentialSourceLabel renders the scanner's machine-readable credential
// source as human-readable text for reports.
func credentialSourceLabel(source string) string {
	switch source {
	case "default":
		return "default list"
	case "word-list":
		return "word list"
	default:
		return source
	}
}

// embedScreenshot loads the PNG, produces a thumbnail, and returns both
// as "data:image/png;base64,..." URIs.
func embedScreenshot(path string) (thumbURL, fullURL string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	// Full-size URI from the file bytes: no re-encode needed.
	fullURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(data)

	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		// Keep the full image even if we cannot make a thumbnail.
		return fullURL, fullURL, nil
	}

	thumb := resizeNearest(img, thumbMaxWidth)
	var tb bytes.Buffer
	if err := png.Encode(&tb, thumb); err != nil {
		return fullURL, fullURL, nil
	}
	thumbURL = "data:image/png;base64," + base64.StdEncoding.EncodeToString(tb.Bytes())
	return thumbURL, fullURL, nil
}

// resizeNearest scales img so its width is at most maxWidth, preserving
// the aspect ratio. Nearest-neighbour is enough for inventory previews.
func resizeNearest(img image.Image, maxWidth int) image.Image {
	b := img.Bounds()
	srcW, srcH := b.Dx(), b.Dy()
	if srcW <= maxWidth || srcW == 0 {
		return img
	}
	dstW := maxWidth
	dstH := srcH * dstW / srcW
	if dstH < 1 {
		dstH = 1
	}

	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	for y := 0; y < dstH; y++ {
		sy := b.Min.Y + y*srcH/dstH
		for x := 0; x < dstW; x++ {
			sx := b.Min.X + x*srcW/dstW
			dst.Set(x, y, img.At(sx, sy))
		}
	}
	return dst
}

// buildHTMLDiff converts a normalized comparison into the template view.
func buildHTMLDiff(diff *Diff) *htmlDiffData {
	data := &htmlDiffData{Baseline: diff.Baseline, Empty: diff.Empty()}
	if data.Empty {
		return data
	}

	newRows, newMore := capDiff(diff.New, htmlDiffRowLimit)
	for _, r := range newRows {
		data.New.Rows = append(data.New.Rows, htmlDiffRow(r, ""))
	}
	data.New.Count, data.New.More = len(diff.New), newMore

	resolvedRows, resolvedMore := capDiff(diff.Resolved, htmlDiffRowLimit)
	for _, r := range resolvedRows {
		data.Resolved.Rows = append(data.Resolved.Rows, htmlDiffRow(r, ""))
	}
	data.Resolved.Count, data.Resolved.More = len(diff.Resolved), resolvedMore

	changedRows, changedMore := capDiff(diff.Changed, htmlDiffRowLimit)
	for _, c := range changedRows {
		row := htmlDiffRow(c.After, c.Reason)
		row.Before = diffStateLabel(c.Before)
		row.BeforeClass = diffTagClass(c.Before)
		row.After = diffStateLabel(c.After)
		row.AfterClass = diffTagClass(c.After)
		data.Changed.Rows = append(data.Changed.Rows, row)
	}
	data.Changed.Count, data.Changed.More = len(diff.Changed), changedMore

	return data
}

// htmlDiffRow renders the shared address and state columns of a comparison
// row. Changed rows add the reason and transition fields on top.
func htmlDiffRow(r Result, reason string) diffRowData {
	return diffRowData{
		Addr:        r.Addr(),
		Tag:         diffStateLabel(r),
		TagClass:    diffTagClass(r),
		Reason:      reason,
		SearchIndex: diffSearchIndex(r, reason),
	}
}

var htmlTmpl = template.Must(template.New("report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>vncshot · VNC security inventory</title>
<style>
:root {
  --paper: #FBFAF7;
  --panel: #FFFFFF;
  --ink: #17242B;
  --ink-soft: #41525B;
  --muted: #6F8089;
  --rule: #DCD5C9;
  --hairline: #EFEAE1;
  --accent: #0E6E62;
  --accent-soft: #E4F1EE;
  --warning: #B45309;
  --warning-soft: #FDF2E3;
  --danger: #A3312A;
  --danger-soft: #FBEDEB;
  --serif: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, serif;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
}
* { box-sizing: border-box; }
html { background: var(--paper); }
body {
  margin: 0;
  background: var(--paper);
  color: var(--ink);
  font: 15px/1.6 var(--sans);
  -webkit-font-smoothing: antialiased;
}
.page {
  max-width: 1120px;
  margin: 0 auto;
  padding: 0 36px 72px;
}
/* Masthead ------------------------------------------------------------- */
.masthead {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 48px;
  padding: 56px 0 26px;
  border-bottom: 2px solid var(--ink);
}
.eyebrow {
  display: block;
  margin: 0;
  font: 600 10px/1.4 var(--sans);
  letter-spacing: .18em;
  text-transform: uppercase;
  color: var(--accent);
}
h1 {
  margin: 14px 0 10px;
  font-family: var(--serif);
  font-size: clamp(34px, 5vw, 52px);
  font-weight: 500;
  line-height: 1.05;
  letter-spacing: -.015em;
  color: var(--ink);
}
.dek {
  margin: 0;
  max-width: 50ch;
  color: var(--ink-soft);
  font-size: 15px;
}
.masthead-meta {
  flex: 0 0 auto;
  min-width: 246px;
  padding-left: 22px;
  border-left: 1px solid var(--rule);
}
.meta-row {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  padding: 5px 0;
}
.meta-key {
  font: 600 9.5px/1.6 var(--sans);
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--muted);
  white-space: nowrap;
}
.meta-value {
  color: var(--ink-soft);
  font-size: 12px;
  text-align: right;
}
/* Stat strip ----------------------------------------------------------- */
.stat-strip {
  display: grid;
  grid-template-columns: repeat(9, 1fr);
  border-bottom: 1px solid var(--rule);
}
.stat {
  padding: 22px 20px;
  border-left: 1px solid var(--hairline);
}
.stat:first-child {
  padding-left: 0;
  border-left: 0;
}
.stat .label {
  font: 600 9.5px/1.35 var(--sans);
  letter-spacing: .16em;
  text-transform: uppercase;
  color: var(--muted);
}
.stat .value {
  margin-top: 8px;
  font-family: var(--serif);
  font-size: 34px;
  font-weight: 500;
  line-height: 1.1;
  font-variant-numeric: tabular-nums;
  color: var(--ink);
}
.stat.alert .value { color: var(--warning); }
.stat.good .value { color: var(--accent); }
/* Toolbar -------------------------------------------------------------- */
.toolbar {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  justify-content: space-between;
  gap: 18px 28px;
  padding: 22px 0;
  border-bottom: 1px solid var(--hairline);
}
.search-wrap { flex: 1 1 280px; }
.search-wrap .eyebrow {
  margin-bottom: 7px;
  color: var(--muted);
  letter-spacing: .14em;
}
input[type="search"] {
  width: 100%;
  padding: 8px 2px;
  border: 0;
  border-bottom: 1px solid var(--rule);
  border-radius: 0;
  background: transparent;
  color: var(--ink);
  font: 15px/1.4 var(--sans);
  outline: none;
  transition: border-color .15s ease;
}
input[type="search"]::placeholder { color: var(--muted); opacity: .85; }
input[type="search"]:focus { border-bottom-color: var(--accent); }
input[type="search"]::-webkit-search-cancel-button { -webkit-appearance: none; }
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.chip {
  padding: 6px 10px;
  border: 1px solid transparent;
  border-radius: 2px;
  background: transparent;
  color: var(--muted);
  font: 600 10px/1.4 var(--sans);
  letter-spacing: .12em;
  text-transform: uppercase;
  cursor: pointer;
  user-select: none;
  transition: color .15s ease, background-color .15s ease;
}
.chip:hover { color: var(--ink); background: var(--accent-soft); }
.chip.active {
  color: var(--accent);
  background: var(--accent-soft);
  border-color: var(--accent-soft);
}
.chip:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
/* Sections ------------------------------------------------------------- */
.section { padding-top: 46px; }
.section-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 20px;
  margin-bottom: 22px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--rule);
}
h2 {
  margin: 0;
  font-family: var(--serif);
  font-size: 24px;
  font-weight: 500;
  letter-spacing: -.01em;
  color: var(--ink);
}
.section-note {
  font: 600 9.5px/1.4 var(--sans);
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--muted);
  text-align: right;
}
/* Capture cards -------------------------------------------------------- */
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 30px 24px;
}
.card {
  margin: 0;
  padding: 10px;
  border: 1px solid var(--rule);
  border-radius: 2px;
  background: var(--panel);
  cursor: pointer;
  transition: border-color .15s ease;
}
.card:hover { border-color: var(--ink-soft); }
.card:focus-visible { outline: 2px solid var(--accent); outline-offset: 3px; }
.frame {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 168px;
  overflow: hidden;
  border: 1px solid var(--hairline);
  background: var(--paper);
}
.card img {
  display: block;
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: top left;
}
.frame-missing {
  padding: 0 12px;
  font: 600 9.5px/1.6 var(--sans);
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--muted);
  text-align: center;
}
.card .meta { padding: 12px 2px 2px; }
.card .addr {
  font-family: var(--mono);
  font-size: 14px;
  letter-spacing: -.01em;
  color: var(--ink);
}
.card .line {
  margin-top: 4px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.5;
  word-break: break-word;
}
.badge {
  display: inline-block;
  margin-top: 10px;
  padding: 3px 8px;
  border: 1px solid var(--warning);
  border-radius: 2px;
  background: var(--warning-soft);
  color: var(--warning);
  font: 600 9px/1.4 var(--sans);
  letter-spacing: .14em;
  text-transform: uppercase;
}
.empty {
  padding: 28px;
  border: 1px solid var(--hairline);
  background: var(--panel);
  color: var(--muted);
  font-size: 14px;
}
/* Credential tags ------------------------------------------------------ */
.tag {
  display: inline-block;
  padding: 1px 6px;
  border: 1px solid var(--rule);
  border-radius: 2px;
  font: 600 9px/1.4 var(--sans);
  letter-spacing: .12em;
  text-transform: uppercase;
  white-space: nowrap;
  color: var(--muted);
}
.tag.hot {
  border-color: #F0D3AB;
  background: var(--warning-soft);
  color: var(--warning);
}
.tag.tls {
  border-color: var(--accent-soft);
  background: var(--accent-soft);
  color: var(--accent);
}
.tag.ok {
  border-color: var(--accent-soft);
  background: var(--accent-soft);
  color: var(--accent);
}
.tag.danger {
  border-color: #EBC6C2;
  background: var(--danger-soft);
  color: var(--danger);
}
/* Certificate evidence ------------------------------------------------- */
.cert-list {
  border-top: 1px solid var(--hairline);
}
.cert-entry {
  padding: 18px 0;
  border-bottom: 1px solid var(--hairline);
}
.cert-head {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  justify-content: space-between;
  gap: 6px 18px;
}
.cert-addr {
  font-family: var(--mono);
  font-size: 13px;
  letter-spacing: -.01em;
  color: var(--ink);
}
.cert-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.cert-facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 6px 28px;
  margin: 11px 0 0;
}
.cert-fact {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin: 0;
}
.cert-fact dt,
.cert-key {
  flex: 0 0 62px;
  font: 600 9px/1.5 var(--sans);
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--muted);
}
.cert-fact dd {
  margin: 0;
  min-width: 0;
  color: var(--ink-soft);
  font-size: 12.5px;
  word-break: break-word;
}
.cert-hash-row {
  display: flex;
  align-items: baseline;
  gap: 10px;
  margin-top: 7px;
}
.cert-hash {
  min-width: 0;
  color: var(--ink-soft);
  word-break: break-all;
}
.cert-line {
  margin-top: 4px;
}
.cert-validity {
  color: var(--muted);
  font-size: 11px;
  white-space: nowrap;
}
/* Baseline comparison -------------------------------------------------- */
.diff-groups {
  display: grid;
  gap: 26px;
}
.diff-group-head {
  padding-bottom: 8px;
  border-bottom: 1px solid var(--hairline);
}
.diff-label {
  font: 600 9.5px/1.4 var(--sans);
  letter-spacing: .14em;
  text-transform: uppercase;
  color: var(--ink-soft);
}
.diff-row {
  display: grid;
  grid-template-columns: minmax(120px, 180px) minmax(0, 1fr);
  gap: 8px 18px;
  align-items: baseline;
  padding: 9px 0;
  border-bottom: 1px solid var(--hairline);
}
.diff-row:last-child { border-bottom: 0; }
.diff-addr {
  font-family: var(--mono);
  font-size: 12px;
  letter-spacing: -.01em;
  color: var(--ink);
}
.diff-detail {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 4px 10px;
  color: var(--ink-soft);
  font-size: 12.5px;
}
.diff-reason { color: var(--ink); }
.diff-transition {
  display: inline-flex;
  align-items: baseline;
  gap: 6px;
  white-space: nowrap;
}
.diff-arrow { color: var(--muted); }
.diff-more {
  margin: 8px 0 0;
  color: var(--muted);
  font-size: 12px;
}
.diff-empty {
  margin: 0;
  padding: 4px 0 2px;
  color: var(--muted);
  font-size: 13.5px;
}
.retried {
  color: var(--muted);
  font-family: var(--sans);
  font-size: 11px;
  white-space: nowrap;
}
.cred-source {
  color: var(--muted);
  font-size: 11px;
  white-space: nowrap;
}
/* Endpoint table ------------------------------------------------------- */
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--rule);
  background: var(--panel);
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th, td {
  padding: 11px 14px;
  border-bottom: 1px solid var(--hairline);
  text-align: left;
  vertical-align: top;
}
th {
  position: sticky;
  top: 0;
  border-bottom: 1px solid var(--rule);
  background: var(--panel);
  color: var(--muted);
  font: 600 9px/1.5 var(--sans);
  letter-spacing: .15em;
  text-transform: uppercase;
  white-space: nowrap;
}
tbody tr:last-child td { border-bottom: 0; }
tbody tr:hover td { background: #FAF7F1; }
td { color: var(--ink-soft); }
.mono {
  font-family: var(--mono);
  font-size: 12px;
  letter-spacing: -.01em;
}
.yes { color: var(--accent); font-weight: 600; }
.no { color: var(--muted); }
.err {
  max-width: 260px;
  color: var(--danger);
  word-break: break-word;
}
/* Screenshot modal ----------------------------------------------------- */
#modal {
  position: fixed;
  inset: 0;
  z-index: 50;
  display: none;
  align-items: center;
  justify-content: center;
  padding: 28px;
  background: rgba(23, 36, 43, .62);
}
#modal.open { display: flex; }
#modal .panel {
  display: flex;
  flex-direction: column;
  width: min(1100px, 96vw);
  max-height: 92vh;
  overflow: hidden;
  border: 1px solid var(--rule);
  border-radius: 2px;
  background: var(--panel);
}
#modal .panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--rule);
  background: var(--paper);
}
#modal .title {
  font-family: var(--mono);
  font-size: 13px;
  color: var(--ink);
}
#modal .panel-head button {
  padding: 5px 12px;
  border: 1px solid var(--rule);
  border-radius: 2px;
  background: transparent;
  color: var(--ink-soft);
  font: 600 9.5px/1.4 var(--sans);
  letter-spacing: .14em;
  text-transform: uppercase;
  cursor: pointer;
}
#modal .panel-head button:hover {
  border-color: var(--ink-soft);
  color: var(--ink);
}
#modal .panel-body {
  overflow: auto;
  background: var(--paper);
}
#modal img {
  display: block;
  width: 100%;
  height: auto;
  max-height: calc(92vh - 56px);
  object-fit: contain;
}
/* Colophon ------------------------------------------------------------- */
footer {
  margin-top: 64px;
  padding-top: 26px;
  border-top: 2px solid var(--ink);
  color: var(--muted);
  font-size: 11.5px;
  line-height: 1.7;
}
footer strong { color: var(--ink-soft); font-weight: 600; }
.legal-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 26px 44px;
}
footer h3 {
  margin: 0 0 8px;
  color: var(--ink-soft);
  font: 600 9.5px/1.4 var(--sans);
  letter-spacing: .16em;
  text-transform: uppercase;
}
footer p { margin: 0; }
footer .evidence-note {
  margin-top: 20px;
  padding-top: 14px;
  border-top: 1px solid var(--hairline);
}
.colophon {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 14px;
  margin-top: 14px;
  padding-top: 14px;
  border-top: 1px solid var(--hairline);
  font-size: 11px;
}
footer a {
  color: var(--accent);
  text-decoration: none;
  border-bottom: 1px solid var(--accent-soft);
}
footer a:hover { border-bottom-color: var(--accent); }
/* Responsive ----------------------------------------------------------- */
@media (max-width: 880px) {
  .masthead {
    flex-direction: column;
    align-items: flex-start;
    gap: 24px;
  }
  .masthead-meta {
    width: 100%;
    padding: 12px 0 0;
    border-left: 0;
    border-top: 1px solid var(--hairline);
  }
  .stat-strip { grid-template-columns: repeat(3, 1fr); }
  .stat { padding-left: 16px; border-left: 1px solid var(--hairline); }
  .stat:nth-child(3n+1) { padding-left: 0; border-left: 0; }
  .legal-grid { grid-template-columns: 1fr; }
}
@media (max-width: 560px) {
  .page { padding: 0 18px 48px; }
  .stat-strip { grid-template-columns: repeat(2, 1fr); }
  .stat:nth-child(3n+1) { padding-left: 16px; border-left: 1px solid var(--hairline); }
  .stat:nth-child(2n+1) { padding-left: 0; border-left: 0; }
  .section-head { flex-direction: column; align-items: flex-start; gap: 6px; }
  .section-note { text-align: left; }
}
@media print {
  body { background: var(--panel); }
  .toolbar, #modal { display: none; }
  .card { break-inside: avoid; }
}
</style>
</head>
<body>
<div class="page">

<header class="masthead">
  <div class="masthead-main">
    <span class="eyebrow">Technical dossier · Network exposure</span>
    <h1>VNC Security Inventory</h1>
    <p class="dek">Framebuffer captures and authentication posture across the probed address range.</p>
  </div>
  <div class="masthead-meta">
    <div class="meta-row"><span class="meta-key">Generated</span><span class="meta-value mono">{{.GeneratedAt}}</span></div>
    <div class="meta-row"><span class="meta-key">Probes</span><span class="meta-value mono">{{.Summary.Targets}}</span></div>
    <div class="meta-row"><span class="meta-key">Use</span><span class="meta-value">Authorized assessments only</span></div>
  </div>
</header>

<section class="stat-strip" aria-label="Scan summary">
  <div class="stat"><div class="label">Targets</div><div class="value">{{.Summary.Targets}}</div></div>
  <div class="stat"><div class="label">Open ports</div><div class="value">{{.Summary.Open}}</div></div>
  <div class="stat"><div class="label">RFB services</div><div class="value">{{.Summary.RFB}}</div></div>
  <div class="stat{{if .Summary.TLS}} good{{end}}"><div class="label">TLS services</div><div class="value">{{.Summary.TLS}}</div></div>
  <div class="stat"><div class="label">Self-signed certs</div><div class="value">{{.Summary.SelfSignedCerts}}</div></div>
  <div class="stat alert"><div class="label">Passwordless</div><div class="value">{{.Summary.Passwordless}}</div></div>
  <div class="stat{{if .Summary.WeakCredentials}} alert{{end}}"><div class="label">Weak creds</div><div class="value">{{.Summary.WeakCredentials}}</div></div>
  <div class="stat good"><div class="label">Screenshots</div><div class="value">{{.Summary.Screenshots}}</div></div>
  <div class="stat"><div class="label">Errors</div><div class="value">{{.Summary.Errors}}</div></div>
</section>

<div class="toolbar">
  <div class="search-wrap">
    <label class="eyebrow" for="filter">Filter records</label>
    <input id="filter" type="search" placeholder="IP address, port, status or server name" autocomplete="off">
  </div>
  <div class="chips" role="group" aria-label="Filter records">
    <div class="chip active" data-filter="">All records</div>
    <div class="chip" data-filter="passwordless">Passwordless</div>
    <div class="chip" data-filter="weak">Weak password</div>
    <div class="chip" data-filter="authenticated">Authenticated</div>
    <div class="chip" data-filter="open">Open</div>
  </div>
</div>

<main>
  <section class="section">
    <div class="section-head">
      <h2>Unauthenticated and weak-password captures</h2>
      <span class="section-note">Frames collected without authentication or with cracked credentials</span>
    </div>
    {{if .Cards}}
    <div class="cards" id="cards">
      {{range .Cards}}
      <figure class="card" data-search="{{.SearchIndex}}" data-full="{{.FullURL}}" data-title="{{.Addr}}" tabindex="0" role="button" aria-label="Enlarge capture of {{.Addr}}">
        <div class="frame">
          {{if .ThumbURL}}<img src="{{.ThumbURL}}" alt="Framebuffer captured from {{.Addr}}">{{else}}<span class="frame-missing">No capture available</span>{{end}}
        </div>
        <figcaption class="meta">
          <div class="addr">{{.Addr}}</div>
          <div class="line">{{if .Dimensions}}<span class="mono">{{.Dimensions}}</span>{{end}}{{if .ServerName}}{{if .Dimensions}} · {{end}}{{.ServerName}}{{end}}</div>
          {{if .Transport}}<div class="line">{{.Transport}}</div>{{end}}
          <div class="line"><span class="mono">{{.CapturedAt}}</span> · <span class="mono">{{.DurationMs}}</span> ms{{if gt .Attempts 1}} · <span class="retried">retried ×{{.Attempts}}</span>{{end}}</div>
          {{if .Passwordless}}<div class="badge">no authentication</div>{{else if .Authenticated}}<div class="badge">password: <span class="mono">{{.Password}}</span>{{if .PasswordSource}} · {{.PasswordSource}}{{end}}</div>{{end}}
        </figcaption>
      </figure>
      {{end}}
    </div>
    {{else}}
    <div class="empty" id="cards">No unauthenticated or weak-password VNC endpoints with captures were found.</div>
    {{end}}
  </section>

  {{with .Diff}}
  <section class="section" aria-label="Changes since baseline">
    <div class="section-head">
      <h2>Changes since baseline</h2>
      {{if .Baseline}}<span class="section-note">Compared with <span class="mono">{{.Baseline}}</span></span>{{else}}<span class="section-note">Baseline comparison</span>{{end}}
    </div>
    {{if .Empty}}
    <p class="diff-empty">No changes since the baseline run.</p>
    {{else}}
    <div class="diff-groups">
      {{if .New.Count}}
      <div class="diff-group">
        <div class="diff-group-head"><span class="diff-label">New ({{.New.Count}})</span></div>
        {{range .New.Rows}}
        <div class="diff-row" data-search="{{.SearchIndex}}">
          <span class="diff-addr">{{.Addr}}</span>
          <span class="diff-detail"><span class="{{.TagClass}}">{{.Tag}}</span></span>
        </div>
        {{end}}
        {{if .New.More}}<p class="diff-more">… and {{.New.More}} more</p>{{end}}
      </div>
      {{end}}
      {{if .Resolved.Count}}
      <div class="diff-group">
        <div class="diff-group-head"><span class="diff-label">Resolved ({{.Resolved.Count}})</span></div>
        {{range .Resolved.Rows}}
        <div class="diff-row" data-search="{{.SearchIndex}}">
          <span class="diff-addr">{{.Addr}}</span>
          <span class="diff-detail"><span class="{{.TagClass}}">{{.Tag}}</span></span>
        </div>
        {{end}}
        {{if .Resolved.More}}<p class="diff-more">… and {{.Resolved.More}} more</p>{{end}}
      </div>
      {{end}}
      {{if .Changed.Count}}
      <div class="diff-group">
        <div class="diff-group-head"><span class="diff-label">Changed ({{.Changed.Count}})</span></div>
        {{range .Changed.Rows}}
        <div class="diff-row" data-search="{{.SearchIndex}}">
          <span class="diff-addr">{{.Addr}}</span>
          <span class="diff-detail">
            <span class="diff-reason">{{.Reason}}</span>
            <span class="diff-transition"><span class="{{.BeforeClass}}">{{.Before}}</span><span class="diff-arrow">→</span><span class="{{.AfterClass}}">{{.After}}</span></span>
          </span>
        </div>
        {{end}}
        {{if .Changed.More}}<p class="diff-more">… and {{.Changed.More}} more</p>{{end}}
      </div>
      {{end}}
    </div>
    {{end}}
  </section>
  {{end}}

  {{if .Certificates}}
  <section class="section" aria-label="Certificate evidence">
    <div class="section-head">
      <h2>Certificates</h2>
      <span class="section-note">Peer certificate evidence from established TLS sessions</span>
    </div>
    <div class="cert-list">
      {{range .Certificates}}
      <div class="cert-entry" data-search="{{.SearchIndex}}">
        <div class="cert-head">
          <span class="cert-addr">{{.Addr}}</span>
          <span class="cert-tags">{{range .Tags}}<span class="{{.Class}}">{{.Label}}</span>{{end}}</span>
        </div>
        <dl class="cert-facts">
          <div class="cert-fact"><dt>Subject</dt><dd>{{.Subject}}</dd></div>
          <div class="cert-fact"><dt>Issuer</dt><dd>{{.Issuer}}</dd></div>
          <div class="cert-fact"><dt>Valid</dt><dd class="mono">{{.Window}}</dd></div>
          <div class="cert-fact"><dt>TLS</dt><dd>{{.TLS}}</dd></div>
          <div class="cert-fact"><dt>Cipher</dt><dd>{{.Cipher}}</dd></div>
        </dl>
        <div class="cert-hash-row"><span class="cert-key">SHA-256</span><span class="cert-hash mono">{{.Fingerprint}}</span></div>
      </div>
      {{end}}
    </div>
  </section>
  {{end}}

  <section class="section">
    <div class="section-head">
      <h2>Open endpoints</h2>
      <span class="section-note">Closed ports omitted</span>
    </div>
    {{if .Rows}}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">IP</th><th scope="col">Port</th><th scope="col">RFB</th><th scope="col">Passwordless</th><th scope="col">Security</th><th scope="col">Password</th><th scope="col">Server</th>
            <th scope="col">Screen</th><th scope="col">Screenshot</th><th scope="col">Error</th><th scope="col">Duration</th><th scope="col">Time</th>
          </tr>
        </thead>
        <tbody>
          {{range .Rows}}
          <tr data-search="{{.SearchIndex}}">
            <td class="mono">{{.IP}}</td>
            <td class="mono">{{.Port}}</td>
            <td class="{{if .RFB}}yes{{else}}no{{end}}">{{if .RFB}}yes{{else}}no{{end}}</td>
            <td class="{{if .Passwordless}}yes{{else}}no{{end}}">{{if .Passwordless}}yes{{else}}no{{end}}</td>
            <td>{{if .Security}}{{.Security}}{{else}}<span class="no">—</span>{{end}}{{if .TLS}} <span class="tag tls">tls</span>{{end}}{{if .CertState}}<div class="cert-line"><span class="{{.CertStateClass}}">{{.CertState}}</span>{{if .CertValidity}} <span class="cert-validity">{{.CertValidity}}</span>{{end}}</div>{{end}}</td>
            <td>{{if .Password}}<span class="tag hot">weak</span> <span class="mono">{{.Password}}</span> <span class="cred-source">{{.PasswordSource}}</span>{{else if .AuthLocked}}<span class="tag">locked out</span>{{else}}<span class="no">—</span>{{end}}</td>
            <td>{{.ServerName}}</td>
            <td class="mono">{{.Dimensions}}</td>
            <td class="mono">{{.Screenshot}}</td>
            <td class="err">{{.Error}}</td>
            <td class="mono">{{.DurationMs}} ms{{if gt .Attempts 1}} <span class="retried">retried ×{{.Attempts}}</span>{{end}}</td>
            <td class="mono">{{.Timestamp}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{else}}
    <div class="empty">No open TCP ports were found in the scanned set.</div>
    {{end}}
  </section>
</main>

<div id="modal" role="dialog" aria-modal="true" aria-label="Screenshot viewer" aria-hidden="true">
  <div class="panel">
    <div class="panel-head">
      <div class="title" id="modal-title"></div>
      <button type="button" id="modal-close">Close</button>
    </div>
    <div class="panel-body">
      <img id="modal-img" alt="Enlarged framebuffer">
    </div>
  </div>
</div>

<footer>
  <div class="legal-grid">
    <div>
      <h3>Legal notice</h3>
      <p>This tool is published for authorized security testing only. Scan only networks you own or have explicit written permission to test. Unauthorized access to computer systems is a criminal offence in most jurisdictions. <strong>The developer (Cuma KURT) accepts no liability whatsoever</strong> for any damage, loss, legal claim, penalty or other consequence arising from use, misuse or inability to use this software. The software is provided "AS IS", without warranty of any kind.</p>
    </div>
    <div>
      <h3>Yasal uyarı</h3>
      <p>Bu araç yalnızca yetkili güvenlik testleri için yayımlanmıştır. Yalnızca sahibi olduğunuz ya da açık yazılı yetkiniz bulunan ağları tarayın. <strong>Geliştirici (Cuma KURT), kullanım veya kötüye kullanım sonucu doğabilecek hiçbir zarar, kayıp, hukuki talep veya ceza için sorumluluk kabul etmez.</strong> Yazılım "olduğu gibi", hiçbir garanti olmaksızın sunulur.</p>
    </div>
  </div>
  <p class="evidence-note">Handle captured desktops as sensitive evidence. Report findings only to owners of the tested network.</p>
  <div class="colophon">
    <span>Developer: <strong>Cuma KURT</strong></span>
    <span><a href="mailto:cumakurt@gmail.com">cumakurt@gmail.com</a></span>
    <span><a href="https://github.com/cumakurt/vncshot">github.com/cumakurt/vncshot</a></span>
    <span><a href="https://www.linkedin.com/in/cuma-kurt-34414917/">linkedin.com/in/cuma-kurt-34414917</a></span>
    <span>License: GPL-3.0</span>
  </div>
</footer>

</div>

<script>
(function () {
  var filter = document.getElementById('filter');
  var chips = Array.prototype.slice.call(document.querySelectorAll('.chip'));
  var activeChip = '';

  function applyFilter() {
    var q = (filter.value || '').trim().toLowerCase();
    var nodes = document.querySelectorAll('[data-search]');
    Array.prototype.forEach.call(nodes, function (el) {
      var hay = (el.getAttribute('data-search') || '').toLowerCase();
      var okQuery = !q || hay.indexOf(q) !== -1;
      var okChip = !activeChip || hay.indexOf(activeChip) !== -1;
      el.style.display = (okQuery && okChip) ? '' : 'none';
    });
  }

  filter.addEventListener('input', applyFilter);
  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      chips.forEach(function (c) { c.classList.remove('active'); });
      chip.classList.add('active');
      activeChip = chip.getAttribute('data-filter') || '';
      applyFilter();
    });
  });

  var modal = document.getElementById('modal');
  var modalImg = document.getElementById('modal-img');
  var modalTitle = document.getElementById('modal-title');

  function openModal(src, title) {
    modalImg.src = src;
    modalTitle.textContent = title;
    modal.classList.add('open');
    modal.setAttribute('aria-hidden', 'false');
  }
  function closeModal() {
    modal.classList.remove('open');
    modal.setAttribute('aria-hidden', 'true');
    modalImg.src = '';
  }

  document.addEventListener('click', function (e) {
    var card = e.target.closest ? e.target.closest('.card') : null;
    if (card && card.getAttribute('data-full')) {
      openModal(card.getAttribute('data-full'), card.getAttribute('data-title') || '');
    }
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeModal();
      return;
    }
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var card = e.target.closest ? e.target.closest('.card') : null;
    if (card && card.getAttribute('data-full')) {
      e.preventDefault();
      openModal(card.getAttribute('data-full'), card.getAttribute('data-title') || '');
    }
  });
  document.getElementById('modal-close').addEventListener('click', closeModal);
  modal.addEventListener('click', function (e) {
    if (e.target === modal) closeModal();
  });
})();
</script>
</body>
</html>
`))
