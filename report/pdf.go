package report

import (
	"bytes"
	"fmt"
	"image/png"
	"os"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// WritePDF renders the scan results as a PDF report. Generation is done
// entirely in-process: no browser, no external tools.
func WritePDF(path string, results []Result) error {
	sum := Summarize(results)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 18)
	pdf.SetMargins(14, 14, 14)
	pdf.SetTitle("vncshot report", false)
	pdf.SetAuthor("vncshot — Cuma KURT", false)
	pdf.SetCreator("vncshot", false)

	writeCover(pdf, sum)
	writePasswordless(pdf, results)
	writeOpenTable(pdf, results)

	if err := pdf.OutputFileAndClose(path); err != nil {
		return fmt.Errorf("write pdf report: %w", err)
	}
	return nil
}

// Brand colours shared with the HTML report theme.
const (
	colAccentR, colAccentG, colAccentB = 61, 139, 253
	colWarnR, colWarnG, colWarnB       = 217, 119, 6
	colOkR, colOkG, colOkB             = 47, 158, 107
	colInkR, colInkG, colInkB          = 23, 32, 48
	colMutedR, colMutedG, colMutedB    = 100, 116, 139
	colRuleR, colRuleG, colRuleB       = 203, 213, 225
	colPanelR, colPanelG, colPanelB    = 241, 245, 249
)

func writeCover(pdf *pdfType, sum Summary) {
	pdf.AddPage()

	// Header band.
	pdf.SetFillColor(colInkR, colInkG, colInkB)
	pdf.Rect(0, 0, 210, 34, "F")

	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 20)
	pdf.SetXY(14, 10)
	pdf.Cell(120, 8, "vncshot report")

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(14, 21)
	pdf.Cell(120, 5, "VNC security inventory — authorized assessments only")

	pdf.SetXY(14, 26)
	pdf.SetTextColor(147, 197, 253)
	pdf.Cell(120, 5, "Developer: Cuma KURT  ·  cumakurt@gmail.com  ·  github.com/cumakurt/vncshot")

	// Timestamp on the right of the band.
	pdf.SetTextColor(203, 213, 225)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(130, 12)
	pdf.CellFormat(66, 5, "Generated "+time.Now().UTC().Format("2006-01-02 15:04 UTC"), "", 0, "R", false, 0, "")
	pdf.SetXY(130, 18)
	pdf.CellFormat(66, 5, "Target count: "+itoa(sum.Targets), "", 0, "R", false, 0, "")

	pdf.SetY(42)

	// Summary cards.
	labels := []struct {
		label   string
		value   string
		r, g, b int
	}{
		{"Targets", itoa(sum.Targets), colInkR, colInkG, colInkB},
		{"Open ports", itoa(sum.Open), colInkR, colInkG, colInkB},
		{"RFB services", itoa(sum.RFB), colInkR, colInkG, colInkB},
		{"Passwordless", itoa(sum.Passwordless), colWarnR, colWarnG, colWarnB},
		{"Screenshots", itoa(sum.Screenshots), colOkR, colOkG, colOkB},
		{"Errors", itoa(sum.Errors), colInkR, colInkG, colInkB},
	}

	const cardW = 29.0
	const gap = 3.0
	x := 14.0
	y := pdf.GetY()
	for _, c := range labels {
		pdf.SetFillColor(colPanelR, colPanelG, colPanelB)
		pdf.RoundedRect(x, y, cardW, 20, 2, "1234", "F")

		pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetXY(x+2, y+3)
		pdf.Cell(cardW-4, 4, sanitizePDFText(c.label))

		pdf.SetTextColor(c.r, c.g, c.b)
		pdf.SetFont("Helvetica", "B", 16)
		pdf.SetXY(x+2, y+8)
		pdf.Cell(cardW-4, 8, c.value)

		x += cardW + gap
	}

	pdf.SetY(y + 28)

	// Legal notice.
	pdf.SetFillColor(254, 243, 199)
	pdf.SetDrawColor(245, 158, 11)
	pdf.RoundedRect(14, pdf.GetY(), 182, 16, 2, "1234", "DF")
	pdf.SetTextColor(120, 53, 15)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(18, pdf.GetY()+3)
	pdf.MultiCell(174, 4,
		"AUTHORIZED USE ONLY / YALNIZCA YETKILI KULLANIM — Scan only networks you own or have explicit written permission to test. "+
			"The developer (Cuma KURT) accepts no liability for any damage, loss or legal consequence arising from use or misuse of this tool. "+
			"Araci yalnizca sahibi oldugunuz veya yazili yetkiniz bulunan aglarda kullanin. Gelistirici hicbir sorumluluk kabul etmez.",
		"", "L", false)
}

func writePasswordless(pdf *pdfType, results []Result) {
	var findings []Result
	for _, r := range results {
		if r.Passwordless {
			findings = append(findings, r)
		}
	}

	pdf.AddPage()
	sectionTitle(pdf, fmt.Sprintf("Passwordless VNC endpoints (%d)", len(findings)))

	if len(findings) == 0 {
		pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
		pdf.SetFont("Helvetica", "I", 10)
		pdf.Cell(182, 8, "No unauthenticated VNC endpoints were found.")
		return
	}

	for i, r := range findings {
		drawFindingCard(pdf, r, i+1)
	}
}

func drawFindingCard(pdf *pdfType, r Result, idx int) {
	const cardH = 62.0
	if pdf.GetY()+cardH > 277 {
		pdf.AddPage()
	}

	x := 14.0
	y := pdf.GetY()

	pdf.SetFillColor(255, 255, 255)
	pdf.SetDrawColor(colRuleR, colRuleG, colRuleB)
	pdf.RoundedRect(x, y, 182, cardH, 2, "1234", "DF")

	// Left: screenshot (or placeholder).
	imgX := x + 4
	imgY := y + 4
	imgW := 74.0

	if r.Screenshot != "" {
		if drawn := drawScreenshot(pdf, r.Screenshot, imgX, imgY, imgW, 54); !drawn {
			pdf.SetFillColor(colPanelR, colPanelG, colPanelB)
			pdf.Rect(imgX, imgY, imgW, 54, "F")
			pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
			pdf.SetFont("Helvetica", "", 8)
			pdf.SetXY(imgX, imgY+25)
			pdf.CellFormat(imgW, 5, "screenshot unavailable", "", 0, "C", false, 0, "")
		}
	} else {
		pdf.SetFillColor(colPanelR, colPanelG, colPanelB)
		pdf.Rect(imgX, imgY, imgW, 54, "F")
		pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetXY(imgX, imgY+25)
		pdf.CellFormat(imgW, 5, "no screenshot", "", 0, "C", false, 0, "")
	}

	// Right: metadata.
	tx := imgX + imgW + 6
	pdf.SetXY(tx, imgY+2)

	pdf.SetTextColor(colWarnR, colWarnG, colWarnB)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.Cell(30, 5, fmt.Sprintf("FINDING #%d", idx))

	pdf.SetTextColor(colInkR, colInkG, colInkB)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetXY(tx, imgY+8)
	pdf.Cell(90, 7, sanitizePDFText(r.Addr()))

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
	pdf.SetXY(tx, imgY+18)
	meta := fmt.Sprintf("Screen: %dx%d", r.ScreenWidth, r.ScreenHeight)
	if r.ServerName != "" {
		meta += "  ·  " + sanitizePDFText(truncate(r.ServerName, 48))
	}
	pdf.Cell(90, 5, meta)

	pdf.SetXY(tx, imgY+25)
	pdf.Cell(90, 5, "Captured: "+r.Timestamp.UTC().Format("2006-01-02 15:04:05 UTC"))

	pdf.SetXY(tx, imgY+32)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetTextColor(colWarnR, colWarnG, colWarnB)
	pdf.Cell(90, 5, "Authentication: NONE")

	if r.Screenshot != "" {
		pdf.SetXY(tx, imgY+40)
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
		pdf.Cell(90, 5, "Evidence: "+sanitizePDFText(truncate(r.Screenshot, 56)))
	}

	pdf.SetY(y + cardH + 4)
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

func writeOpenTable(pdf *pdfType, results []Result) {
	var open []Result
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}

	pdf.AddPage()
	sectionTitle(pdf, fmt.Sprintf("Open endpoints (%d of %d targets)", len(open), len(results)))

	if len(open) == 0 {
		pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
		pdf.SetFont("Helvetica", "I", 10)
		pdf.Cell(182, 8, "No open TCP ports were found in the scanned set.")
		writeColophon(pdf)
		return
	}

	// Column widths (mm) — total 182.
	widths := []float64{34, 14, 12, 18, 40, 24, 20, 20}

	headers := []string{"IP", "Port", "RFB", "Passwordless", "Server", "Screen", "Duration", "Time"}

	pdf.SetFillColor(colInkR, colInkG, colInkB)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 8)
	x := 14.0
	for i, h := range headers {
		pdf.SetXY(x, pdf.GetY())
		pdf.CellFormat(widths[i], 8, h, "", 0, "L", true, 0, "")
		x += widths[i]
	}
	pdf.Ln(-1)

	pdf.SetFont("Helvetica", "", 7.5)
	for i, r := range open {
		if pdf.GetY() > 275 {
			pdf.AddPage()
			// Repeat the header on overflow pages.
			pdf.SetFillColor(colInkR, colInkG, colInkB)
			pdf.SetTextColor(255, 255, 255)
			pdf.SetFont("Helvetica", "B", 8)
			x = 14.0
			for j, h := range headers {
				pdf.SetXY(x, pdf.GetY())
				pdf.CellFormat(widths[j], 8, h, "", 0, "L", true, 0, "")
				x += widths[j]
			}
			pdf.Ln(-1)
			pdf.SetFont("Helvetica", "", 7.5)
		}

		if i%2 == 0 {
			pdf.SetFillColor(colPanelR, colPanelG, colPanelB)
			pdf.Rect(14, pdf.GetY(), 182, 7, "F")
		}

		dims := "-"
		if r.ScreenWidth > 0 && r.ScreenHeight > 0 {
			dims = fmt.Sprintf("%dx%d", r.ScreenWidth, r.ScreenHeight)
		}
		cells := []string{
			r.IP,
			itoa(r.Port),
			yesNo(r.RFB),
			yesNo(r.Passwordless),
			sanitizePDFText(truncate(r.ServerName, 30)),
			dims,
			fmt.Sprintf("%dms", r.DurationMs),
			r.Timestamp.UTC().Format("15:04:05"),
		}

		x = 14.0
		for j, c := range cells {
			pdf.SetTextColor(colInkR, colInkG, colInkB)
			if j == 3 && r.Passwordless {
				pdf.SetTextColor(colWarnR, colWarnG, colWarnB)
				pdf.SetFont("Helvetica", "B", 7.5)
			}
			pdf.SetXY(x, pdf.GetY())
			pdf.CellFormat(widths[j], 7, c, "", 0, "L", false, 0, "")
			if j == 3 {
				pdf.SetFont("Helvetica", "", 7.5)
			}
			x += widths[j]
		}
		pdf.Ln(-1)
	}

	writeColophon(pdf)
}

func writeColophon(pdf *pdfType) {
	pdf.SetY(-22)
	pdf.SetDrawColor(colRuleR, colRuleG, colRuleB)
	pdf.Line(14, pdf.GetY(), 196, pdf.GetY())
	pdf.SetTextColor(colMutedR, colMutedG, colMutedB)
	pdf.SetFont("Helvetica", "", 7)
	pdf.SetXY(14, pdf.GetY()+2)
	pdf.Cell(182, 4, "vncshot — Cuma KURT · cumakurt@gmail.com · github.com/cumakurt/vncshot · License: GPL-3.0")
	pdf.SetXY(14, pdf.GetY()+4)
	pdf.Cell(182, 4, "DISCLAIMER: The developer accepts no liability for use or misuse of this tool. Handle captured desktops as sensitive evidence.")
}

func sectionTitle(pdf *pdfType, title string) {
	pdf.SetTextColor(colAccentR, colAccentG, colAccentB)
	pdf.SetFont("Helvetica", "B", 13)
	pdf.Cell(182, 8, sanitizePDFText(title))
	pdf.Ln(10)
}

// pdfType aliases the concrete type from go-pdf/fpdf so signatures above
// stay readable without importing the third-party name everywhere.
type pdfType = fpdf.Fpdf

// sanitizePDFText maps text to the Latin-1 range used by the built-in
// core fonts and replaces anything that would not render.
func sanitizePDFText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteByte(' ')
		case r >= 0x20 && r <= 0x7E:
			b.WriteRune(r)
		case r >= 0xA0 && r <= 0xFF:
			b.WriteRune(r)
		default:
			if repl, ok := translit[r]; ok {
				b.WriteString(repl)
			} else {
				b.WriteByte('?')
			}
		}
	}
	return b.String()
}

// translit folds common non-Latin letters to ASCII so Turkish desktop
// names remain readable in the PDF without embedding a TTF.
var translit = map[rune]string{
	'ı': "i", 'İ': "I", 'ş': "s", 'Ş': "S",
	'ğ': "g", 'Ğ': "G", 'ü': "u", 'Ü': "U",
	'ö': "o", 'Ö': "O", 'ç': "c", 'Ç': "C",
	'â': "a", 'Â': "A", 'î': "i", 'Î': "I",
	'û': "u", 'Û': "U", 'ä': "a", 'Ä': "A",
	'ß': "ss", 'æ': "ae", 'Æ': "AE",
	'œ': "oe", 'Œ': "OE", 'ø': "o", 'Ø': "O",
	'å': "a", 'Å': "A", 'é': "e", 'è': "e",
	'ê': "e", 'ë': "e", 'á': "a", 'à': "a",
	'ó': "o", 'ò': "o", 'ú': "u",
	'ù': "u", 'ñ': "n", 'Ñ': "N",
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
