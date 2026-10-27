package report

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"image"
	"image/png"
	"os"
	"time"
)

// thumbMaxWidth bounds embedded card previews so a large report stays
// usable in a browser.
const thumbMaxWidth = 320

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
	ServerName     string
	Dimensions     string
	Screenshot     string
	Error          string
	DurationMs     string
	Timestamp      string
	SearchIndex    string
}

type htmlData struct {
	GeneratedAt string
	Summary     Summary
	Cards       []cardData
	Rows        []rowData
}

// WriteHTML renders a self-contained HTML report to path. Thumbnails and
// full-size captures are embedded as data URIs so the file can be shared
// as a single artifact.
func WriteHTML(path string, results []Result) error {
	doc := htmlData{
		GeneratedAt: time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
		Summary:     Summarize(results),
	}

	for _, r := range results {
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
			doc.Cards = append(doc.Cards, cardData{
				IP:             r.IP,
				Port:           fmt.Sprintf("%d", r.Port),
				Addr:           r.Addr(),
				ServerName:     r.ServerName,
				Dimensions:     dims,
				CapturedAt:     r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
				DurationMs:     fmt.Sprintf("%d", r.DurationMs),
				Passwordless:   r.Passwordless,
				Authenticated:  r.Password != "",
				AuthLocked:     r.AuthLocked,
				Password:       r.Password,
				PasswordSource: credentialSourceLabel(r.PasswordSource),
				ThumbURL:       template.URL(thumb),
				FullURL:        template.URL(full),
				SearchIndex:    searchIndex(r),
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
			ServerName:     r.ServerName,
			Dimensions:     dims,
			Screenshot:     r.Screenshot,
			Error:          r.Error,
			DurationMs:     fmt.Sprintf("%d", r.DurationMs),
			Timestamp:      r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
			SearchIndex:    searchIndex(r),
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
	// The "weak password" chip matches by substring, so the term is kept
	// as a single token even though it reads as two words.
	if r.Password != "" {
		index += " weakpassword"
	}
	return index
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
  grid-template-columns: repeat(7, 1fr);
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
          <div class="line"><span class="mono">{{.CapturedAt}}</span> · <span class="mono">{{.DurationMs}}</span> ms</div>
          {{if .Passwordless}}<div class="badge">no authentication</div>{{else if .Authenticated}}<div class="badge">password: <span class="mono">{{.Password}}</span>{{if .PasswordSource}} · {{.PasswordSource}}{{end}}</div>{{end}}
        </figcaption>
      </figure>
      {{end}}
    </div>
    {{else}}
    <div class="empty" id="cards">No unauthenticated or weak-password VNC endpoints with captures were found.</div>
    {{end}}
  </section>

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
            <th scope="col">IP</th><th scope="col">Port</th><th scope="col">RFB</th><th scope="col">Passwordless</th><th scope="col">Password</th><th scope="col">Server</th>
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
            <td>{{if .Password}}<span class="tag hot">weak</span> <span class="mono">{{.Password}}</span> <span class="cred-source">{{.PasswordSource}}</span>{{else if .AuthLocked}}<span class="tag">locked out</span>{{else}}<span class="no">—</span>{{end}}</td>
            <td>{{.ServerName}}</td>
            <td class="mono">{{.Dimensions}}</td>
            <td class="mono">{{.Screenshot}}</td>
            <td class="err">{{.Error}}</td>
            <td class="mono">{{.DurationMs}} ms</td>
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
