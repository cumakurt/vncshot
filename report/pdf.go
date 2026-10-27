package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// The report embeds Liberation Sans so the PDF is independent of host fonts
// and carries real Turkish glyphs (Latin Extended-A) instead of ASCII
// transliterations. Font files and their license live under fonts/.
//
//go:embed fonts/LiberationSans-Regular.ttf
var liberationRegular []byte

//go:embed fonts/LiberationSans-Bold.ttf
var liberationBold []byte

const (
	fontFamily   = "Liberation"
	pageWidth    = 210.0
	pageHeight   = 297.0
	marginX      = 16.0
	contentWidth = pageWidth - 2*marginX
	topY         = 22.0
	// bottomBreak keeps body text clear of the footer colophon.
	bottomBreak = 24.0
)

// pdfColor keeps the dossier palette in one place so the PDF and the HTML
// report share the same visual language.
type pdfColor struct{ r, g, b int }

func (c pdfColor) text(pdf *pdfType) { pdf.SetTextColor(c.r, c.g, c.b) }
func (c pdfColor) fill(pdf *pdfType) { pdf.SetFillColor(c.r, c.g, c.b) }
func (c pdfColor) draw(pdf *pdfType) { pdf.SetDrawColor(c.r, c.g, c.b) }

var (
	colorInk         = pdfColor{0x17, 0x24, 0x2B}
	colorInkSoft     = pdfColor{0x41, 0x52, 0x5B}
	colorMuted       = pdfColor{0x6F, 0x80, 0x89}
	colorRule        = pdfColor{0xDC, 0xD5, 0xC9}
	colorHairline    = pdfColor{0xEF, 0xEA, 0xE1}
	colorAccent      = pdfColor{0x0E, 0x6E, 0x62}
	colorAccentSoft  = pdfColor{0xE4, 0xF1, 0xEE}
	colorWarning     = pdfColor{0xB4, 0x53, 0x09}
	colorWarningSoft = pdfColor{0xFD, 0xF2, 0xE3}
	colorDanger      = pdfColor{0xA3, 0x31, 0x2A}
	colorZebra       = pdfColor{0xFB, 0xFA, 0xF7}
)

const (
	legalNoticeEN = "This tool is published for authorized security testing only. " +
		"Scan only networks you own or have explicit written permission to test. " +
		"The developer (Cuma KURT) accepts no liability for any damage, loss, legal claim " +
		"or other consequence arising from use or misuse of this software."

	legalNoticeTR = "YALNIZCA YETKİLİ KULLANIM — Yalnızca sahibi olduğunuz veya yazılı yetkiniz bulunan ağları tarayın. " +
		"Geliştirici (Cuma KURT) bu aracın kullanımından veya kötüye kullanımından doğabilecek " +
		"hiçbir zarar, kayıp veya hukuki sonuç için sorumluluk kabul etmez."
)

// WritePDF renders the scan results as a PDF report. Generation is done
// entirely in-process: no browser, no external tools.
func WritePDF(path string, results []Result) error {
	return WritePDFWithOptions(path, results, Options{})
}

// WritePDFWithDiff renders the report together with a baseline comparison.
// A nil diff keeps the output identical to WritePDF.
func WritePDFWithDiff(path string, results []Result, diff *Diff) error {
	return WritePDFWithOptions(path, results, Options{Diff: diff})
}

// WritePDFWithOptions renders the report with the requested redaction. A
// redacted report replaces the captured password with the marker in the
// findings and in the endpoint table while the weak / passwordless state and
// the summary counters stay intact.
func WritePDFWithOptions(path string, results []Result, opts Options) error {
	diff := normalizedDiff(opts.redactDiff(opts.Diff))
	// Counters describe the observed findings, before redaction hides the
	// secret values.
	sum := Summarize(results)
	results = opts.apply(results)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(marginX, topY, marginX)
	pdf.SetAutoPageBreak(true, bottomBreak)
	pdf.SetTitle("vncshot — VNC security inventory", true)
	pdf.SetAuthor("vncshot — Cuma KURT", true)
	pdf.SetCreator("vncshot", false)
	pdf.SetSubject("VNC security inventory", true)

	pdf.AddUTF8FontFromBytes(fontFamily, "", liberationRegular)
	pdf.AddUTF8FontFromBytes(fontFamily, "B", liberationBold)
	pdf.SetFooterFunc(func() { drawFooter(pdf) })
	pdf.AliasNbPages("{nb}")

	writeCover(pdf, results, sum)
	if hasBaselineSection(diff) {
		writeDiff(pdf, diff)
	}
	writeFindings(pdf, results)
	writeOpenTable(pdf, results)

	if err := pdf.OutputFileAndClose(path); err != nil {
		return fmt.Errorf("write pdf report: %w", err)
	}
	// Reports may contain weak credentials and captured desktops, so they
	// are owner-readable only. fpdf creates files with the process umask.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict pdf report permissions: %w", err)
	}
	return nil
}

// statCell is one column of the cover stat strip.
type statCell struct {
	label string
	value string
	color pdfColor
}

// coverStats builds the stat strip cells. Warning and danger colours are
// conditional so a clean scan stays monochrome and only actual findings
// stand out.
func coverStats(sum Summary) []statCell {
	weakColor := colorInk
	if sum.WeakCredentials > 0 {
		weakColor = colorWarning
	}
	errorColor := colorInk
	if sum.Errors > 0 {
		errorColor = colorDanger
	}
	tlsColor := colorInk
	if sum.TLS > 0 {
		tlsColor = colorAccent
	}

	return []statCell{
		{"Targets", itoa(sum.Targets), colorInk},
		{"Open ports", itoa(sum.Open), colorInk},
		{"RFB services", itoa(sum.RFB), colorInk},
		{"TLS services", itoa(sum.TLS), tlsColor},
		{"Passwordless", itoa(sum.Passwordless), colorWarning},
		{"Weak creds", itoa(sum.WeakCredentials), weakColor},
		{"Screenshots", itoa(sum.Screenshots), colorAccent},
		{"Errors", itoa(sum.Errors), errorColor},
	}
}

// writeCover renders the editorial front page: masthead, metadata block,
// stat strip, legal notice and a short dossier index.
func writeCover(pdf *pdfType, results []Result, sum Summary) {
	pdf.AddPage()

	pdf.SetFont(fontFamily, "B", 7)
	colorAccent.text(pdf)
	pdf.SetXY(marginX, topY)
	pdf.CellFormat(contentWidth, 4, letterSpace("VNC SECURITY INVENTORY"), "", 0, "L", false, 0, "")

	// Masthead.
	pdf.SetFont(fontFamily, "B", 28)
	colorInk.text(pdf)
	pdf.SetXY(marginX, 29)
	pdf.CellFormat(96, 12, "vncshot", "", 0, "L", false, 0, "")

	// The masthead rule stops at the metadata column so it never strikes
	// through the right-hand values.
	const metaX = 130.0
	metaW := pageWidth - marginX - metaX

	colorRule.draw(pdf)
	pdf.SetLineWidth(0.3)
	pdf.Line(marginX, 45, metaX-6, 45)

	pdf.SetFont(fontFamily, "", 9.4)
	colorInkSoft.text(pdf)
	pdf.SetXY(marginX, 49)
	pdf.MultiCell(104, 4.8,
		"Framebuffer captures and authentication posture across the probed address range.",
		"", "L", false)

	// Right-aligned metadata block, separated by a hairline.
	colorHairline.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Line(metaX-6, topY, metaX-6, 68)

	metaRows := []struct{ label, value string }{
		{"GENERATED", time.Now().UTC().Format("2006-01-02 15:04 UTC")},
		{"TARGETS", itoa(sum.Targets) + " probes"},
		{"PREPARED BY", "vncshot · Cuma KURT"},
	}
	for i, row := range metaRows {
		y := topY + float64(i)*15
		pdf.SetFont(fontFamily, "B", 6.2)
		colorMuted.text(pdf)
		pdf.SetXY(metaX, y)
		pdf.CellFormat(metaW, 3.5, letterSpace(row.label), "", 0, "R", false, 0, "")

		pdf.SetFont(fontFamily, "", 8)
		colorInkSoft.text(pdf)
		pdf.SetXY(metaX, y+5)
		pdf.CellFormat(metaW, 4, sanitizePDFText(row.value), "", 0, "R", false, 0, "")
	}

	// Stat strip: plain columns with hairline separators, not cards.
	const stripY = 82.0
	colorRule.draw(pdf)
	pdf.SetLineWidth(0.3)
	pdf.Line(marginX, stripY, pageWidth-marginX, stripY)

	stats := coverStats(sum)
	statW := contentWidth / float64(len(stats))
	for i, stat := range stats {
		x := marginX + float64(i)*statW
		if i > 0 {
			colorHairline.draw(pdf)
			pdf.SetLineWidth(0.2)
			pdf.Line(x, stripY+2, x, stripY+22)
		}

		pad := 0.0
		if i > 0 {
			pad = 4
		}
		pdf.SetFont(fontFamily, "", 6.6)
		colorMuted.text(pdf)
		pdf.SetXY(x+pad, stripY+6)
		pdf.CellFormat(statW-pad, 3.5, strings.ToUpper(sanitizePDFText(stat.label)), "", 0, "L", false, 0, "")

		pdf.SetFont(fontFamily, "B", 16)
		stat.color.text(pdf)
		pdf.SetXY(x+pad, stripY+11)
		pdf.CellFormat(statW-pad, 8, stat.value, "", 0, "L", false, 0, "")
	}

	colorRule.draw(pdf)
	pdf.SetLineWidth(0.3)
	pdf.Line(marginX, stripY+24, pageWidth-marginX, stripY+24)

	noticeBottom := drawLegalNotice(pdf, 120)

	// Dossier index keeps the lower white space purposeful.
	indexY := noticeBottom + 18
	if indexY > 205 {
		indexY = 205
	}
	pdf.SetFont(fontFamily, "B", 6.5)
	colorMuted.text(pdf)
	pdf.SetXY(marginX, indexY)
	pdf.CellFormat(contentWidth, 4, letterSpace("CONTENTS"), "", 0, "L", false, 0, "")

	indexRows := []struct{ number, title, meta string }{
		{"01", "Authentication findings",
			fmt.Sprintf("%d findings", sum.Passwordless+sum.WeakCredentials)},
		{"02", "Open endpoints", fmt.Sprintf("%d of %d targets open", sum.Open, sum.Targets)},
	}
	y := indexY + 8
	for _, row := range indexRows {
		pdf.SetFont(fontFamily, "B", 8)
		colorAccent.text(pdf)
		pdf.SetXY(marginX, y)
		pdf.CellFormat(9, 5, row.number, "", 0, "L", false, 0, "")

		pdf.SetFont(fontFamily, "", 10.5)
		colorInk.text(pdf)
		pdf.SetXY(marginX+10, y)
		pdf.CellFormat(90, 5, row.title, "", 0, "L", false, 0, "")

		pdf.SetFont(fontFamily, "", 8)
		colorMuted.text(pdf)
		pdf.SetXY(marginX, y)
		pdf.CellFormat(contentWidth, 5, row.meta, "", 0, "R", false, 0, "")

		colorHairline.draw(pdf)
		pdf.SetLineWidth(0.2)
		pdf.Line(marginX, y+7, pageWidth-marginX, y+7)
		y += 13
	}
}

// drawLegalNotice paints the warning-soft panel and returns its bottom edge.
func drawLegalNotice(pdf *pdfType, y float64) float64 {
	const (
		padX     = 6.0
		innerW   = contentWidth - 2*padX
		lineH    = 4.4
		bodySize = 8.2
	)

	pdf.SetFont(fontFamily, "", bodySize)
	enLines := len(pdf.SplitLines([]byte(legalNoticeEN), innerW))
	trLines := len(pdf.SplitLines([]byte(legalNoticeTR), innerW))
	height := 21.5 + float64(enLines+trLines)*lineH

	colorWarningSoft.fill(pdf)
	colorRule.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Rect(marginX, y, contentWidth, height, "DF")

	colorWarning.fill(pdf)
	pdf.Rect(marginX, y, 1.0, height, "F")

	pdf.SetFont(fontFamily, "B", 7)
	colorWarning.text(pdf)
	pdf.SetXY(marginX+padX, y+5)
	pdf.CellFormat(innerW, 4, letterSpace("LEGAL NOTICE / YASAL UYARI"), "", 0, "L", false, 0, "")

	pdf.SetFont(fontFamily, "", bodySize)
	colorInkSoft.text(pdf)
	pdf.SetXY(marginX+padX, y+12)
	pdf.MultiCell(innerW, lineH, legalNoticeEN, "", "L", false)

	// MultiCell leaves the cursor at the left margin, so advance a line
	// first and then restore the panel padding for the Turkish paragraph.
	pdf.Ln(2)
	pdf.SetX(marginX + padX)
	colorInk.text(pdf)
	pdf.MultiCell(innerW, lineH, legalNoticeTR, "", "L", false)

	return y + height
}

// diffTransition renders the compact before → after state description used
// by the PDF comparison rows.
func diffTransition(before, after Result) string {
	return diffStateLabel(before) + " → " + diffStateLabel(after)
}

// pdfDiffRowLimit caps each baseline group. A comparison over a large range
// must stay a summary rather than a second copy of the endpoint table.
const pdfDiffRowLimit = 25

const (
	diffAddrW  = 38.0
	diffGap    = 2.0
	diffStateW = 17.0
	diffArrowW = 7.0
)

// writeDiff renders the baseline comparison as a page-break safe section:
// group headings and rows move to a continuation page when they no longer
// fit above the footer.
func writeDiff(pdf *pdfType, diff *Diff) {
	pdf.AddPage()

	note := "No baseline differences were recorded."
	if diff.Baseline != "" {
		note = "Compared with " + sanitizePDFText(diff.Baseline) + "."
	}
	y := sectionHeader(pdf, "BASELINE COMPARISON", "Changes since baseline", note)

	if diff.Empty() {
		pdf.SetFont(fontFamily, "", 9.5)
		colorMuted.text(pdf)
		pdf.SetXY(marginX, y+2)
		pdf.CellFormat(contentWidth, 6, "No changes since the baseline run.", "", 0, "L", false, 0, "")
		return
	}

	y = writeDiffResultGroup(pdf, y, "New", diff.New)
	y = writeDiffResultGroup(pdf, y, "Resolved", diff.Resolved)
	writeDiffChangedGroup(pdf, y, "Changed", diff.Changed)
}

// writeDiffResultGroup renders one New or Resolved group and returns the y
// coordinate below it.
func writeDiffResultGroup(pdf *pdfType, y float64, title string, results []Result) float64 {
	if len(results) == 0 {
		return y
	}
	if y+18 > 270 {
		pdf.AddPage()
		y = continuationHeader(pdf, "BASELINE COMPARISON / CONTINUED",
			"Changes since baseline / continued")
	}
	y = drawDiffGroupHead(pdf, y, title, len(results))

	rows, hidden := capDiff(results, pdfDiffRowLimit)
	for _, r := range rows {
		if y+7.4 > 270 {
			pdf.AddPage()
			y = continuationHeader(pdf, "BASELINE COMPARISON / CONTINUED",
				"Changes since baseline / continued")
			y = drawDiffGroupHead(pdf, y, title, len(results))
		}
		drawDiffResultRow(pdf, r, y)
		y += 7.0
	}
	if hidden > 0 {
		y = drawDiffMore(pdf, y, hidden)
	}
	return y + 8
}

// writeDiffChangedGroup renders risk transitions for findings that exist in
// both runs but changed state.
func writeDiffChangedGroup(pdf *pdfType, y float64, title string, changes []Change) float64 {
	if len(changes) == 0 {
		return y
	}
	if y+18 > 270 {
		pdf.AddPage()
		y = continuationHeader(pdf, "BASELINE COMPARISON / CONTINUED",
			"Changes since baseline / continued")
	}
	y = drawDiffGroupHead(pdf, y, title, len(changes))

	rows, hidden := capDiff(changes, pdfDiffRowLimit)
	for _, c := range rows {
		if y+7.4 > 270 {
			pdf.AddPage()
			y = continuationHeader(pdf, "BASELINE COMPARISON / CONTINUED",
				"Changes since baseline / continued")
			y = drawDiffGroupHead(pdf, y, title, len(changes))
		}
		drawDiffChangedRow(pdf, c, y)
		y += 7.0
	}
	if hidden > 0 {
		y = drawDiffMore(pdf, y, hidden)
	}
	return y + 8
}

// drawDiffGroupHead renders the bold group label and its hairline rule.
func drawDiffGroupHead(pdf *pdfType, y float64, title string, count int) float64 {
	pdf.SetFont(fontFamily, "B", 7.2)
	colorInk.text(pdf)
	pdf.SetXY(marginX, y)
	pdf.CellFormat(contentWidth, 5,
		sanitizePDFText(fmt.Sprintf("%s (%d)", title, count)), "", 0, "L", false, 0, "")

	colorHairline.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Line(marginX, y+5.6, pageWidth-marginX, y+5.6)

	return y + 8.5
}

// drawDiffResultRow renders one address and its current state tag.
func drawDiffResultRow(pdf *pdfType, r Result, y float64) {
	pdf.SetFont(fontFamily, "B", 8)
	colorInk.text(pdf)
	pdf.SetXY(marginX, y)
	addr := sanitizePDFText(r.Addr())
	pdf.CellFormat(diffAddrW, 4.4, fitCellText(pdf, addr, diffAddrW-1), "", 0, "L", false, 0, "")

	drawDiffState(pdf, marginX+diffAddrW+diffGap, y, diffStateW, diffStateLabel(r))

	colorHairline.draw(pdf)
	pdf.SetLineWidth(0.1)
	pdf.Line(marginX, y+6.6, pageWidth-marginX, y+6.6)
}

// drawDiffChangedRow renders the address, the before → after transition and
// the change reason on a single aligned row.
func drawDiffChangedRow(pdf *pdfType, c Change, y float64) {
	pdf.SetFont(fontFamily, "B", 8)
	colorInk.text(pdf)
	pdf.SetXY(marginX, y)
	addr := sanitizePDFText(c.After.Addr())
	pdf.CellFormat(diffAddrW, 4.4, fitCellText(pdf, addr, diffAddrW-1), "", 0, "L", false, 0, "")

	x := marginX + diffAddrW + diffGap
	drawDiffState(pdf, x, y, diffStateW, diffStateLabel(c.Before))

	x += diffStateW
	pdf.SetFont(fontFamily, "", 7.6)
	colorMuted.text(pdf)
	pdf.SetXY(x, y)
	pdf.CellFormat(diffArrowW, 4.4, "→", "", 0, "C", false, 0, "")

	x += diffArrowW
	drawDiffState(pdf, x, y, diffStateW, diffStateLabel(c.After))

	x += diffStateW + diffGap
	reasonW := pageWidth - marginX - x
	pdf.SetFont(fontFamily, "", 7.8)
	colorInkSoft.text(pdf)
	pdf.SetXY(x, y)
	reason := sanitizePDFText(c.Reason)
	pdf.CellFormat(reasonW, 4.4, fitCellText(pdf, reason, reasonW-1), "", 0, "L", false, 0, "")

	colorHairline.draw(pdf)
	pdf.SetLineWidth(0.1)
	pdf.Line(marginX, y+6.6, pageWidth-marginX, y+6.6)
}

// drawDiffState paints a compact state label with the severity colour used by
// the endpoint table.
func drawDiffState(pdf *pdfType, x, y, w float64, label string) {
	pdf.SetFont(fontFamily, "B", 7.4)
	diffStateColor(label).text(pdf)
	pdf.SetXY(x, y)
	pdf.CellFormat(w, 4.4, sanitizePDFText(label), "", 0, "L", false, 0, "")
}

// diffStateColor maps a comparison state to the dossier palette.
func diffStateColor(label string) pdfColor {
	switch label {
	case "no auth", "weak":
		return colorWarning
	case "closed":
		return colorMuted
	default:
		return colorAccent
	}
}

// drawDiffMore renders the muted count of entries omitted by the row cap.
func drawDiffMore(pdf *pdfType, y float64, hidden int) float64 {
	pdf.SetFont(fontFamily, "", 7.4)
	colorMuted.text(pdf)
	pdf.SetXY(marginX, y)
	pdf.CellFormat(contentWidth, 4,
		sanitizePDFText(fmt.Sprintf("and %d more", hidden)), "", 0, "L", false, 0, "")
	return y + 5.5
}

func writeFindings(pdf *pdfType, results []Result) {
	findings := findingRows(results)

	pdf.AddPage()
	y := sectionHeader(pdf,
		"SECTION 01 / AUTHENTICATION EXPOSURE",
		fmt.Sprintf("Passwordless and weak-credential endpoints (%d)", len(findings)),
		"Framebuffer evidence and weak credentials collected during probing. Handle as sensitive material.")

	if len(findings) == 0 {
		pdf.SetFont(fontFamily, "", 9.5)
		colorMuted.text(pdf)
		pdf.SetXY(marginX, y+4)
		pdf.CellFormat(contentWidth, 6,
			"No passwordless or weak-credential VNC endpoints were recorded in this scan.",
			"", 0, "L", false, 0, "")
		return
	}

	for i, r := range findings {
		if y+66 > 270 {
			pdf.AddPage()
			y = continuationHeader(pdf, "AUTHENTICATION EXPOSURE / CONTINUED",
				fmt.Sprintf("Continued from finding %d of %d", i+1, len(findings)))
		}
		drawFindingEntry(pdf, r, i+1, y)
		y += 70
	}
}

// findingRows selects the hosts that appear in the findings section: hosts
// that needed no credentials and hosts whose weak password was accepted.
func findingRows(results []Result) []Result {
	var findings []Result
	for _, r := range results {
		if r.Passwordless || r.Password != "" {
			findings = append(findings, r)
		}
	}
	return findings
}

// passwordSourceLabel turns the recorded credential source into prose for
// the report. Unknown sources are shown verbatim so a future source value is
// still visible to the reader.
func passwordSourceLabel(source string) string {
	switch source {
	case "":
		return ""
	case "default":
		return "default list"
	case "word-list":
		return "word list"
	default:
		return sanitizePDFText(source)
	}
}

// credentialParts splits the credential line so the renderer can emphasise
// the password and keep the source muted. Both values are already sanitised.
// Passwordless hosts yield empty strings; the caller then omits the row.
func credentialParts(r Result) (password, source string) {
	password = sanitizePDFText(truncate(r.Password, 32))
	if label := passwordSourceLabel(r.PasswordSource); label != "" {
		source = "(" + label + ")"
	}
	return password, source
}

// authSummary describes how the endpoint was reached.
func authSummary(r Result) string {
	if r.Password != "" {
		return "weak password"
	}
	if r.AuthLocked {
		return "VNC authentication / locked out after failures"
	}
	return "NONE / no credentials required"
}

// continuationHeader labels a page that resumes a long section and returns
// the y coordinate of the first entry.
func continuationHeader(pdf *pdfType, eyebrow, note string) float64 {
	pdf.SetFont(fontFamily, "B", 6.4)
	colorMuted.text(pdf)
	pdf.SetXY(marginX, topY)
	pdf.CellFormat(contentWidth, 4, letterSpace(eyebrow), "", 0, "L", false, 0, "")

	pdf.SetFont(fontFamily, "", 7.6)
	pdf.SetXY(marginX, topY)
	pdf.CellFormat(contentWidth, 4, note, "", 0, "R", false, 0, "")

	colorHairline.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Line(marginX, topY+6, pageWidth-marginX, topY+6)

	return topY + 12
}

// findingRow is one line of the definition list next to a finding's capture.
// suffix carries a muted trailing note, currently the credential source or a
// retry marker; emphasis selects bold ink for the value itself.
type findingRow struct {
	label    string
	value    string
	suffix   string
	warning  bool
	emphasis bool
}

// drawFindingEntry renders one dossier entry: framed capture on the left,
// finding label, address and definition list on the right.
func drawFindingEntry(pdf *pdfType, r Result, idx int, y float64) {
	const (
		frameW = 72.0
		frameH = 50.0
	)

	frameX := marginX
	colorRule.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Rect(frameX, y, frameW, frameH, "D")

	drawn := false
	if r.Screenshot != "" {
		drawn = drawScreenshot(pdf, r.Screenshot, frameX+1.5, y+1.5, frameW-3, frameH-3)
	}
	if !drawn {
		colorAccentSoft.fill(pdf)
		pdf.Rect(frameX+1.5, y+1.5, frameW-3, frameH-3, "F")
		colorMuted.text(pdf)
		pdf.SetFont(fontFamily, "", 7.5)
		message := "screenshot unavailable"
		if r.Screenshot == "" {
			message = "no screenshot captured"
		}
		pdf.SetXY(frameX, y+frameH/2-2)
		pdf.CellFormat(frameW, 4, message, "", 0, "C", false, 0, "")
	}

	caption := fmt.Sprintf("CAPTURE %02d", idx)
	if r.ScreenWidth > 0 && r.ScreenHeight > 0 {
		caption += fmt.Sprintf(" · %dx%d", r.ScreenWidth, r.ScreenHeight)
	}
	pdf.SetFont(fontFamily, "", 6.4)
	colorMuted.text(pdf)
	pdf.SetXY(frameX, y+frameH+2)
	pdf.CellFormat(frameW, 4, letterSpace(caption), "", 0, "L", false, 0, "")

	// Right column.
	tx := frameX + frameW + 8
	tw := pageWidth - marginX - tx

	pdf.SetFont(fontFamily, "B", 6.8)
	colorWarning.text(pdf)
	pdf.SetXY(tx, y)
	pdf.CellFormat(tw, 4, letterSpace(fmt.Sprintf("FINDING %02d", idx)), "", 0, "L", false, 0, "")

	pdf.SetFont(fontFamily, "B", 13)
	colorInk.text(pdf)
	pdf.SetXY(tx, y+5)
	pdf.CellFormat(tw, 7, sanitizePDFText(truncate(r.Addr(), 26)), "", 0, "L", false, 0, "")

	colorHairline.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Line(tx, y+14, pageWidth-marginX, y+14)

	serverName := "-"
	if r.ServerName != "" {
		serverName = sanitizePDFText(truncate(r.ServerName, 38))
	}
	dims := "unknown"
	if r.ScreenWidth > 0 && r.ScreenHeight > 0 {
		dims = fmt.Sprintf("%d × %d px", r.ScreenWidth, r.ScreenHeight)
	}
	captured := "-"
	if !r.Timestamp.IsZero() {
		captured = r.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	evidence := "none"
	if r.Screenshot != "" {
		evidence = sanitizePDFText(truncate(filepath.Base(r.Screenshot), 34))
	}

	rows := []findingRow{
		{"Server", serverName, "", false, false},
		{"Screen", dims, "", false, false},
		{"Captured", captured, retrySuffix(r), false, false},
		{"Authentication", authSummary(r), "", true, false},
		{"Transport", transportValue(r), "", false, false},
	}
	if r.Password != "" {
		password, source := credentialParts(r)
		rows = append(rows, findingRow{"Credential", password, source, false, true})
	}
	rows = append(rows, findingRow{"Evidence", evidence, "", false, false})

	rowY := y + 17
	const labelW = 28.0
	for _, row := range rows {
		pdf.SetFont(fontFamily, "B", 6.2)
		colorMuted.text(pdf)
		pdf.SetXY(tx, rowY)
		pdf.CellFormat(labelW, 4, letterSpace(row.label), "", 0, "L", false, 0, "")

		valueX := tx + labelW + 1
		valueLimit := tw - labelW - 1
		switch {
		case row.warning:
			pdf.SetFont(fontFamily, "B", 8.4)
			colorWarning.text(pdf)
		case row.emphasis:
			// The credential is the most sensitive value on the page, so it
			// is set in bold ink while its source stays muted.
			pdf.SetFont(fontFamily, "B", 8.4)
			colorInk.text(pdf)
		default:
			pdf.SetFont(fontFamily, "", 8.4)
			colorInkSoft.text(pdf)
		}

		suffixW := 0.0
		if row.suffix != "" {
			pdf.SetFont(fontFamily, "", 7.4)
			suffixW = pdf.GetStringWidth(row.suffix) + 2
			pdf.SetFont(fontFamily, "B", 8.4)
		}

		pdf.SetXY(valueX, rowY)
		fitted := fitCellText(pdf, row.value, valueLimit-suffixW)
		pdf.CellFormat(valueLimit, 4, fitted, "", 0, "L", false, 0, "")

		if row.suffix != "" {
			valueW := pdf.GetStringWidth(fitted)
			pdf.SetFont(fontFamily, "", 7.4)
			colorMuted.text(pdf)
			pdf.SetXY(valueX+valueW+2, rowY)
			pdf.CellFormat(valueLimit-valueW-2, 4, row.suffix, "", 0, "L", false, 0, "")
		}
		rowY += 5.6
	}

	colorHairline.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Line(marginX, y+frameH+10, pageWidth-marginX, y+frameH+10)
}

// drawScreenshot loads a PNG and paints it into the given box, preserving
// the aspect ratio. Returns false when the file cannot be decoded.
func drawScreenshot(pdf *pdfType, path string, x, y, w, h float64) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return false
	}

	b := img.Bounds()
	srcW, srcH := float64(b.Dx()), float64(b.Dy())
	if srcW <= 0 || srcH <= 0 {
		return false
	}

	scale := w / srcW
	if srcH*scale > h {
		scale = h / srcH
	}
	drawW := srcW * scale
	drawH := srcH * scale
	offX := x + (w-drawW)/2
	offY := y + (h-drawH)/2

	// fpdf reads images through a name-keyed registry; use a per-file
	// counter so repeated paths stay unique and cached.
	imageSeq++
	name := fmt.Sprintf("shot-%d", imageSeq)

	opts := fpdf.ImageOptions{ImageType: "PNG", ReadDpi: false}
	if pdf.RegisterImageOptionsReader(name, opts, bytes.NewReader(data)) == nil {
		return false
	}
	pdf.ImageOptions(name, offX, offY, drawW, drawH, false, opts, 0, "")
	return true
}

// imageSeq gives every embedded screenshot a unique registry key. PDF
// generation is single-threaded, so a plain counter is sufficient.
var imageSeq int

// The endpoint table trades two columns for transport visibility: RFB and
// Passwordless collapse into one STATE column ("no auth", "weak", "rfb", or
// "open") and SECURITY carries the advertised security types. The widths sum
// to contentWidth, so the table still fits the page exactly.
var (
	tableHeaders = []string{"IP", "PORT", "STATE", "PASSWORD", "SECURITY", "SERVER", "SCREEN", "DURATION", "TIME"}
	tableWidths  = []float64{26, 10, 16, 22, 33, 28, 16, 14, 13}
)

func writeOpenTable(pdf *pdfType, results []Result) {
	var open []Result
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}

	pdf.AddPage()
	y := sectionHeader(pdf, "SECTION 02 / EXPOSED PORTS", "Open endpoints",
		fmt.Sprintf("%d of %d probed targets accepted a TCP connection.", len(open), len(results)))

	if len(open) == 0 {
		pdf.SetFont(fontFamily, "", 9.5)
		colorMuted.text(pdf)
		pdf.SetXY(marginX, y+4)
		pdf.CellFormat(contentWidth, 6, "No open TCP ports were found in the scanned set.",
			"", 0, "L", false, 0, "")
		return
	}

	y = drawTableHeader(pdf, y)
	for i, r := range open {
		if y+7.6 > 270 {
			pdf.AddPage()
			y = continuationHeader(pdf, "OPEN ENDPOINTS / CONTINUED",
				fmt.Sprintf("Rows %d–%d of %d", i+1, len(open), len(open)))
			y = drawTableHeader(pdf, y)
		}

		if i%2 == 1 {
			colorZebra.fill(pdf)
			pdf.Rect(marginX, y, contentWidth, 7.6, "F")
		}
		drawTableRow(pdf, r, y)

		colorHairline.draw(pdf)
		pdf.SetLineWidth(0.1)
		pdf.Line(marginX, y+7.6, pageWidth-marginX, y+7.6)
		y += 7.6
	}
}

// drawTableHeader renders the accent micro-label header row and returns the
// y coordinate of the first data row.
func drawTableHeader(pdf *pdfType, y float64) float64 {
	pdf.SetFont(fontFamily, "B", 6.4)
	colorAccent.text(pdf)

	x := marginX
	for i, header := range tableHeaders {
		pdf.SetXY(x, y)
		// Table headers are already uppercase and short; letter-spacing them
		// would overflow the narrow numeric columns.
		pdf.CellFormat(tableWidths[i], 6, header, "", 0, "L", false, 0, "")
		x += tableWidths[i]
	}

	colorRule.draw(pdf)
	pdf.SetLineWidth(ptToMM(0.4))
	pdf.Line(marginX, y+6.4, pageWidth-marginX, y+6.4)

	return y + 8.2
}

func drawTableRow(pdf *pdfType, r Result, y float64) {
	dims := "-"
	if r.ScreenWidth > 0 && r.ScreenHeight > 0 {
		dims = fmt.Sprintf("%dx%d", r.ScreenWidth, r.ScreenHeight)
	}

	security := sanitizePDFText(securitySummary(r.SecurityTypes))
	if security == "" {
		security = "-"
	}

	cells := []string{
		sanitizePDFText(r.IP),
		itoa(r.Port),
		stateLabel(r),
		passwordCell(r),
		security,
		sanitizePDFText(truncate(r.ServerName, 24)),
		dims,
		durationCell(r),
		r.Timestamp.UTC().Format("15:04:05"),
	}

	x := marginX
	for i, cell := range cells {
		pdf.SetXY(x, y+1.6)
		switch {
		case (i == 2 && (r.Passwordless || r.Password != "")) || (i == 3 && r.Password != ""):
			pdf.SetFont(fontFamily, "B", 7.8)
			colorWarning.text(pdf)
		case i == 2 || i == 3 || i == 4 || i == 7 || i == 8:
			pdf.SetFont(fontFamily, "", 7.8)
			colorMuted.text(pdf)
		default:
			pdf.SetFont(fontFamily, "", 7.8)
			colorInk.text(pdf)
		}
		if i == 3 || i == 4 || i == 5 || i == 7 {
			// Passwords, server names and security lists vary wildly in glyph
			// width; fit the cell to the column instead of trusting a fixed
			// character count.
			cell = fitCellText(pdf, cell, tableWidths[i]-1)
		}
		pdf.CellFormat(tableWidths[i], 4.4, cell, "", 0, "L", false, 0, "")
		x += tableWidths[i]
	}
}

// stateLabel collapses the RFB and passwordless flags into one table cell,
// which frees the width the security column needs.
func stateLabel(r Result) string {
	switch {
	case r.Passwordless:
		return "no auth"
	case r.Password != "":
		return "weak"
	case r.RFB:
		return "rfb"
	default:
		return "open"
	}
}

// durationCell appends the connection attempt count when a host only
// answered after a retry, so flaky endpoints stand out in the table.
func durationCell(r Result) string {
	cell := fmt.Sprintf("%d ms", r.DurationMs)
	if r.Attempts > 1 {
		cell += fmt.Sprintf(" ×%d", r.Attempts)
	}
	return cell
}

// retrySuffix is the muted variant of the retry marker used in findings.
func retrySuffix(r Result) string {
	if r.Attempts <= 1 {
		return ""
	}
	return fmt.Sprintf("retried ×%d", r.Attempts)
}

// transportValue renders the transport line for findings, falling back to a
// dash when the server advertised no security types at all.
func transportValue(r Result) string {
	if transport := transportDescription(r); transport != "" {
		return sanitizePDFText(transport)
	}
	return "-"
}

// fitCellText shortens s until it fits width at the currently selected
// font, adding an ellipsis when characters are dropped.
func fitCellText(pdf *pdfType, s string, width float64) string {
	if pdf.GetStringWidth(s) <= width {
		return s
	}
	runes := []rune(s)
	for n := len(runes) - 1; n > 0; n-- {
		candidate := truncate(s, n)
		if pdf.GetStringWidth(candidate) <= width {
			return candidate
		}
	}
	return ""
}

// passwordCell renders the last accepted credential for the endpoint table,
// or a dash when the host required a password that was not recovered.
func passwordCell(r Result) string {
	if r.Password == "" {
		return "-"
	}
	return sanitizePDFText(truncate(r.Password, 18))
}

// drawFooter is the running colophon and page counter. It runs for every
// page, including the cover, via SetFooterFunc.
func drawFooter(pdf *pdfType) {
	y := pageHeight - 16

	colorRule.draw(pdf)
	pdf.SetLineWidth(0.2)
	pdf.Line(marginX, y, pageWidth-marginX, y)

	pdf.SetFont(fontFamily, "", 6.5)
	colorMuted.text(pdf)
	pdf.SetXY(marginX, y+1.6)
	pdf.CellFormat(138, 3.4,
		"vncshot / Cuma KURT / cumakurt@gmail.com / github.com/cumakurt/vncshot / GPL-3.0",
		"", 0, "L", false, 0, "")

	pdf.SetXY(pageWidth-marginX-40, y+1.6)
	pdf.CellFormat(40, 3.4, fmt.Sprintf("Page %d of {nb}", pdf.PageNo()), "", 0, "R", false, 0, "")

	pdf.SetXY(marginX, y+5.4)
	pdf.CellFormat(contentWidth, 3.4,
		"Handle captured desktops as sensitive evidence. Report findings only to the owners of the tested network.",
		"", 0, "L", false, 0, "")
}

// sectionHeader draws the uppercase micro-label, bold title and hairline
// rule, and returns the y coordinate where section content can start.
func sectionHeader(pdf *pdfType, eyebrow, title, note string) float64 {
	y := topY

	pdf.SetFont(fontFamily, "B", 6.6)
	colorAccent.text(pdf)
	pdf.SetXY(marginX, y)
	pdf.CellFormat(contentWidth, 4, letterSpace(eyebrow), "", 0, "L", false, 0, "")

	y += 6
	pdf.SetFont(fontFamily, "B", 18)
	colorInk.text(pdf)
	pdf.SetXY(marginX, y)
	pdf.CellFormat(contentWidth, 8, sanitizePDFText(title), "", 0, "L", false, 0, "")

	y += 10
	colorRule.draw(pdf)
	pdf.SetLineWidth(0.3)
	pdf.Line(marginX, y, pageWidth-marginX, y)

	y += 4
	if note != "" {
		pdf.SetFont(fontFamily, "", 8.2)
		colorMuted.text(pdf)
		pdf.SetXY(marginX, y)
		pdf.CellFormat(contentWidth, 4, sanitizePDFText(note), "", 0, "L", false, 0, "")
		y += 6
	}

	return y + 4
}

// pdfType aliases the concrete type from go-pdf/fpdf so signatures above
// stay readable without importing the third-party name everywhere.
type pdfType = fpdf.Fpdf

// sanitizePDFText normalises characters that cannot travel through the PDF
// text operators. Printable Unicode, including Turkish letters, is preserved
// because the report embeds a font with the required coverage.
func sanitizePDFText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || (r >= 0x7F && r <= 0x9F):
			// Drop remaining control characters.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// letterSpace widens a short uppercase label so it reads as a micro-label.
func letterSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s) * 2)
	first := true
	wordGap := false
	for _, r := range s {
		if r == ' ' {
			wordGap = true
			continue
		}
		if !first {
			if wordGap {
				b.WriteString("   ")
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteRune(r)
		first = false
		wordGap = false
	}
	return b.String()
}

// ptToMM converts PDF points to the millimetre unit used by the document.
func ptToMM(pt float64) float64 {
	return pt * 25.4 / 72
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	if n <= 3 {
		return string(runes[:n])
	}
	return string(runes[:n-3]) + "..."
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
