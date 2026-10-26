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
	IP          string
	Port        string
	Addr        string
	ServerName  string
	Dimensions  string
	CapturedAt  string
	DurationMs  string
	ThumbURL    template.URL
	FullURL     template.URL
	SearchIndex string
}

type rowData struct {
	IP           string
	Port         string
	Open         bool
	RFB          bool
	Passwordless bool
	ServerName   string
	Dimensions   string
	Screenshot   string
	Error        string
	DurationMs   string
	Timestamp    string
	SearchIndex  string
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

		if r.Passwordless && r.Screenshot != "" {
			thumb, full, err := embedScreenshot(r.Screenshot)
			if err != nil {
				// A missing/corrupt capture should not drop the finding
				// from the report; keep the card without imagery.
				thumb, full = "", ""
			}
			doc.Cards = append(doc.Cards, cardData{
				IP:          r.IP,
				Port:        fmt.Sprintf("%d", r.Port),
				Addr:        r.Addr(),
				ServerName:  r.ServerName,
				Dimensions:  dims,
				CapturedAt:  r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
				DurationMs:  fmt.Sprintf("%d", r.DurationMs),
				ThumbURL:    template.URL(thumb),
				FullURL:     template.URL(full),
				SearchIndex: searchIndex(r),
			})
		}

		// Closed ports are summarised in the counters; listing every one
		// would drown the table on large ranges.
		if !r.Open {
			continue
		}
		doc.Rows = append(doc.Rows, rowData{
			IP:           r.IP,
			Port:         fmt.Sprintf("%d", r.Port),
			Open:         r.Open,
			RFB:          r.RFB,
			Passwordless: r.Passwordless,
			ServerName:   r.ServerName,
			Dimensions:   dims,
			Screenshot:   r.Screenshot,
			Error:        r.Error,
			DurationMs:   fmt.Sprintf("%d", r.DurationMs),
			Timestamp:    r.Timestamp.UTC().Format("2006-01-02 15:04:05"),
			SearchIndex:  searchIndex(r),
		})
	}

	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, doc); err != nil {
		return fmt.Errorf("render html report: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
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
	return fmt.Sprintf("%s %d %s %s", r.IP, r.Port, status, r.ServerName)
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
<title>vncshot report</title>
<style>
:root {
  --bg: #0f1419;
  --panel: #1a2332;
  --panel-2: #243044;
  --text: #e7ecf3;
  --muted: #8b9bb4;
  --accent: #3d8bfd;
  --ok: #2f9e6b;
  --warn: #d97706;
  --danger: #dc2626;
  --border: #2c3a4f;
  --radius: 10px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
}
header {
  padding: 24px 28px 8px;
  border-bottom: 1px solid var(--border);
  background: linear-gradient(180deg, #162033, var(--bg));
}
h1 { margin: 0 0 4px; font-size: 22px; letter-spacing: 0.2px; }
.sub { color: var(--muted); margin-bottom: 18px; }
.stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 18px;
}
.stat {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
}
.stat .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.stat .value { font-size: 24px; font-weight: 650; margin-top: 2px; }
.stat.alert .value { color: var(--warn); }
.stat.good .value { color: var(--ok); }
.toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  margin-bottom: 22px;
}
input[type="search"] {
  flex: 1 1 260px;
  background: var(--panel);
  border: 1px solid var(--border);
  color: var(--text);
  border-radius: 8px;
  padding: 10px 12px;
  outline: none;
}
input[type="search"]:focus { border-color: var(--accent); }
.chips { display: flex; gap: 8px; flex-wrap: wrap; }
.chip {
  border: 1px solid var(--border);
  background: var(--panel-2);
  color: var(--muted);
  border-radius: 999px;
  padding: 6px 12px;
  cursor: pointer;
  font-size: 12px;
}
.chip.active, .chip:hover { color: var(--text); border-color: var(--accent); }
main { padding: 8px 28px 48px; }
h2 {
  font-size: 15px;
  text-transform: uppercase;
  letter-spacing: .06em;
  color: var(--muted);
  margin: 28px 0 12px;
}
.cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 16px;
}
.card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  cursor: pointer;
  transition: transform .12s ease, border-color .12s ease;
}
.card:hover { transform: translateY(-2px); border-color: var(--accent); }
.card img {
  width: 100%;
  height: 160px;
  object-fit: cover;
  display: block;
  background: #000;
}
.card .meta { padding: 12px 14px; }
.card .addr { font-weight: 650; font-size: 15px; }
.card .line { color: var(--muted); font-size: 12px; margin-top: 3px; }
.badge {
  display: inline-block;
  background: rgba(217, 119, 6, .15);
  color: var(--warn);
  border: 1px solid rgba(217, 119, 6, .35);
  border-radius: 999px;
  padding: 2px 8px;
  font-size: 11px;
  margin-top: 8px;
}
.empty {
  color: var(--muted);
  padding: 24px;
  border: 1px dashed var(--border);
  border-radius: var(--radius);
}
table {
  width: 100%;
  border-collapse: collapse;
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}
th, td {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
th {
  background: var(--panel-2);
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .04em;
  position: sticky;
  top: 0;
}
tr:last-child td { border-bottom: 0; }
tr:hover td { background: rgba(61, 139, 253, .06); }
.yes { color: var(--ok); font-weight: 600; }
.no { color: var(--muted); }
.err { color: var(--danger); max-width: 280px; word-break: break-word; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
#modal {
  position: fixed; inset: 0;
  background: rgba(5, 8, 12, .82);
  display: none;
  align-items: center;
  justify-content: center;
  padding: 24px;
  z-index: 50;
}
#modal.open { display: flex; }
#modal .panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  max-width: min(1100px, 96vw);
  max-height: 92vh;
  overflow: auto;
}
#modal img { display: block; width: 100%; height: auto; background: #000; }
#modal .caption {
  padding: 14px 18px;
  display: flex;
  justify-content: space-between;
  gap: 12px;
  align-items: center;
}
#modal .caption .title { font-weight: 650; }
#modal .caption button {
  background: var(--panel-2);
  color: var(--text);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 6px 12px;
  cursor: pointer;
}
footer {
  color: var(--muted);
  padding: 18px 28px 32px;
  border-top: 1px solid var(--border);
  font-size: 12px;
}
@media (max-width: 640px) {
  header, main, footer { padding-left: 16px; padding-right: 16px; }
}
</style>
</head>
<body>
<header>
  <h1>VNC security inventory</h1>
  <div class="sub">Generated by vncshot on {{.GeneratedAt}} · authorized assessments only</div>
  <div class="stats">
    <div class="stat"><div class="label">Targets</div><div class="value">{{.Summary.Targets}}</div></div>
    <div class="stat"><div class="label">Open ports</div><div class="value">{{.Summary.Open}}</div></div>
    <div class="stat"><div class="label">RFB services</div><div class="value">{{.Summary.RFB}}</div></div>
    <div class="stat alert"><div class="label">Passwordless</div><div class="value">{{.Summary.Passwordless}}</div></div>
    <div class="stat good"><div class="label">Screenshots</div><div class="value">{{.Summary.Screenshots}}</div></div>
    <div class="stat"><div class="label">Errors</div><div class="value">{{.Summary.Errors}}</div></div>
  </div>
  <div class="toolbar">
    <input id="filter" type="search" placeholder="Filter by IP, port, status, server name…">
    <div class="chips">
      <div class="chip active" data-filter="">All</div>
      <div class="chip" data-filter="passwordless">Passwordless</div>
      <div class="chip" data-filter="authenticated">Authenticated</div>
      <div class="chip" data-filter="open">Open</div>
    </div>
  </div>
</header>

<main>
  <h2>Passwordless VNC — captured frames</h2>
  {{if .Cards}}
  <div class="cards" id="cards">
    {{range .Cards}}
    <div class="card" data-search="{{.SearchIndex}}" data-full="{{.FullURL}}" data-title="{{.Addr}}">
      {{if .ThumbURL}}<img src="{{.ThumbURL}}" alt="framebuffer of {{.Addr}}">{{else}}<img alt="no screenshot">{{end}}
      <div class="meta">
        <div class="addr">{{.Addr}}</div>
        <div class="line">{{.Dimensions}}{{if .ServerName}} · {{.ServerName}}{{end}}</div>
        <div class="line">captured {{.CapturedAt}} · {{.DurationMs}} ms</div>
        <div class="badge">no authentication</div>
      </div>
    </div>
    {{end}}
  </div>
  {{else}}
  <div class="empty" id="cards">No passwordless VNC endpoints with captures were found.</div>
  {{end}}

  <h2>Open endpoints</h2>
  {{if .Rows}}
  <div style="overflow-x:auto">
  <table>
    <thead>
      <tr>
        <th>IP</th><th>Port</th><th>RFB</th><th>Passwordless</th><th>Server</th>
        <th>Screen</th><th>Screenshot</th><th>Error</th><th>Duration</th><th>Time</th>
      </tr>
    </thead>
    <tbody>
      {{range .Rows}}
      <tr data-search="{{.SearchIndex}}">
        <td class="mono">{{.IP}}</td>
        <td>{{.Port}}</td>
        <td class="{{if .RFB}}yes{{else}}no{{end}}">{{if .RFB}}yes{{else}}no{{end}}</td>
        <td class="{{if .Passwordless}}yes{{else}}no{{end}}">{{if .Passwordless}}yes{{else}}no{{end}}</td>
        <td>{{.ServerName}}</td>
        <td class="mono">{{.Dimensions}}</td>
        <td class="mono">{{.Screenshot}}</td>
        <td class="err">{{.Error}}</td>
        <td>{{.DurationMs}} ms</td>
        <td class="mono">{{.Timestamp}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  </div>
  {{else}}
  <div class="empty">No open TCP ports were found in the scanned set.</div>
  {{end}}
</main>

<div id="modal" aria-hidden="true">
  <div class="panel">
    <img id="modal-img" alt="enlarged framebuffer">
    <div class="caption">
      <div class="title" id="modal-title"></div>
      <button type="button" id="modal-close">Close</button>
    </div>
  </div>
</div>

<footer>
  <div><strong>Legal disclaimer / Yasal uyarı:</strong> This tool is published for authorized security testing only. Scan only networks you own or have explicit written permission to test. Unauthorized access to computer systems is a criminal offence in most jurisdictions. <strong>The developer (Cuma KURT) accepts no liability whatsoever</strong> for any damage, loss, legal claim, penalty or other consequence arising from use, misuse or inability to use this software. The software is provided "AS IS", without warranty of any kind.</div>
  <div style="margin-top:8px">Bu araç yalnızca yetkili güvenlik testleri için yayımlanmıştır. Yalnızca sahibi olduğunuz ya da açık yazılı yetkiniz bulunan ağları tarayın. <strong>Geliştirici (Cuma KURT), kullanım veya kötüye kullanım sonucu doğabilecek hiçbir zarar, kayıp, hukuki talep veya cezadan sorumlu tutulamaz.</strong> Yazılım "olduğu gibi", hiçbir garanti olmaksızın sunulur.</div>
  <div style="margin-top:8px">Handle captured desktops as sensitive evidence. Report findings only to owners of the tested network.</div>
  <div style="margin-top:8px">
    Developer: <strong>Cuma KURT</strong>
    · <a href="mailto:cumakurt@gmail.com">cumakurt@gmail.com</a>
    · <a href="https://github.com/cumakurt/vncshot">github.com/cumakurt/vncshot</a>
    · <a href="https://www.linkedin.com/in/cuma-kurt-34414917/">linkedin.com/in/cuma-kurt-34414917</a>
    · License: GPL-3.0
  </div>
</footer>

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
  document.getElementById('modal-close').addEventListener('click', closeModal);
  modal.addEventListener('click', function (e) {
    if (e.target === modal) closeModal();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeModal();
  });
})();
</script>
</body>
</html>
`))
