# vncshot

[English](README.md) | [Türkçe](README.tr.md)

VNC security inventory scanner. Discovers RFB/VNC endpoints, flags
passwordless and weak-password servers, and captures their current
framebuffer as PNG evidence for authorized security assessments.

`vncshot` supports Linux only and requires root privileges.

```
Use only on networks you own or have explicit written permission to test.
```

## Developer

**Cuma KURT**
- Email: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/vncshot](https://github.com/cumakurt/vncshot)

## Features

- Linux only; both the CLI and the GUI must run as root
- Scan single IPs, CIDR blocks, IPv4 ranges, or a file of targets
- Concurrent worker pool with configurable rate limiting
- RFB 3.3 / 3.7 / 3.8 handshake, passwordless (`None`) detection and
  weak-password detection
- Framebuffer capture to PNG for passwordless and weak-password endpoints
- Read-only probing: one frame is requested and the session is closed
- JSON + self-contained HTML report (base64 thumbnails, filter, modal)
- In-process PDF report export (no external tools required)
- CSV export with a stable column order for spreadsheets and pipelines
- Security-type inventory: every finding records the advertised
  `security_types` and a `tls` flag
- Baseline comparison against a previous run (new, resolved and changed findings)
- SHA-256 manifest of every run artifact (`-manifest`) for evidence integrity
- Optional webhook notification when a run has new findings or exposed hosts
- Flag defaults from a config file (`-config`) and `VNCSHOT_*` environment variables
- Deterministic, sorted results so repeated scans can be compared directly
- One TCP connection per target and bounded per-host concurrency
- Local web GUI (`-gui`) with live progress, report links and a previous-run history
- `-version` prints build information without requiring root
- Graceful Ctrl+C shutdown with partial results

## Build

```bash
# one-shot bootstrap + static build + install to /usr/local/bin
./install.sh

# or build directly
go build -o vncshot .

# install.sh options
./install.sh -y               # non-interactive
./install.sh --build-only     # skip dependency installation
./install.sh --no-install-bin # build only; do not install system-wide
```

`install.sh` detects the Linux distribution's package manager (apt, dnf,
yum, pacman, apk, zypper), installs missing tools only when needed,
and produces a stripped **statically linked** Linux binary. It refuses to
run on any other operating system. By default it also:

* installs the binary to `/usr/local/bin/vncshot` (using `sudo` when required)
  so it can be run from any directory, and
* creates `/usr/local/vncshot`, the root directory for scan output.

Both locations can be changed with `INSTALL_PREFIX` and `REPORT_DIR`:

```bash
INSTALL_PREFIX="$HOME/.local/bin" REPORT_DIR="$HOME/vncshot" ./install.sh -y
```

The report root is compiled into the binary, so the installed binary and the
installed directory always agree. There are no runtime external dependencies
beyond the Go toolchain used for building.

## Privileges

`vncshot` refuses to run without root privileges, in both CLI and GUI mode:

```bash
sudo vncshot -target 192.168.1.0/24
```

This is enforced at startup; the tool exits with an actionable error instead
of producing a partially working scan. The only exception is `-version`, which
prints build information and exits before the root check.

## Usage

```bash
sudo vncshot -target 192.168.1.0/24 -ports 5900,5901-5910
sudo vncshot -file hosts.txt -workers 100 -rate 150 -timeout 800ms
sudo vncshot -target 10.0.0.1-50 -out-dir /root/assessments
sudo vncshot -target 192.168.1.0/24 -word-list /root/passwords.txt
sudo vncshot -target 192.168.1.0/24 -baseline /usr/local/vncshot/20261020-090000
sudo vncshot -target 10.0.0.0/24 -manifest -webhook https://hooks.example.test/vncshot
sudo vncshot -target 192.168.1.0/24 -config /root/vncshot.conf
sudo vncshot -gui
vncshot -version
```

Running the tool without arguments prints the usage text and exits without
scanning. `-version` prints the tool name, build version, GOOS/GOARCH and Go
runtime version, for example `vncshot dev (linux/amd64, go1.27.2)`; `install.sh`
injects the release version at build time.

| Flag | Default | Description |
|------|---------|-------------|
| `-version` | `false` | Print build information and exit (does not require root) |
| `-target` | | Single IP, CIDR, or range (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | File with IPs/CIDRs/ranges, one per line (`#` comments allowed) |
| `-ports` | `5900` | Port list/ranges (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP connect timeout |
| `-vnc-timeout` | `15s` | RFB handshake/capture timeout |
| `-workers` | `150` | Concurrent scan workers |
| `-rate` | `200` | Max new connections per second (`0` = unlimited) |
| `-retries` | `1` | Extra connect attempts for transient failures (`0` = none) |
| `-out-dir` | `/usr/local/vncshot` | Root directory for timestamped scan folders |
| `-output` | `<run-dir>/vncshot_report.json` | JSON report path |
| `-html` | `<run-dir>/vncshot_report.html` | HTML report path |
| `-pdf` | `<run-dir>/vncshot_report.pdf` | PDF report path (generated in-process) |
| `-csv` | `<run-dir>/vncshot_report.csv` | CSV report path |
| `-baseline` | | Previous run directory; findings are compared with it |
| `-manifest` | `false` | Write `<run-dir>/manifest.json` with SHA-256 digests of every artifact |
| `-webhook` | | POST a JSON summary to this URL when a run has new findings or exposed hosts |
| `-config` | | Config file with flag defaults (JSON or flat `key: value` YAML) |
| `-no-pdf` | `false` | Skip PDF generation |
| `-screenshot-dir` | `<run-dir>/screenshots` | Directory for PNG captures |
| `-shared` | `true` | Request shared RFB session (does not kick active viewers) |
| `-word-list` | | Extra password candidates, one per line (`#` comments and blank lines ignored, max 500 entries) |
| `-no-default-passwords` | `false` | Do not try the built-in weak-password list |
| `-no-password-check` | `false` | Do not attempt any password; report passwordless hosts only |
| `-yes` | `false` | Skip the interactive authorization confirmation |
| `-gui` | `false` | Start the local web GUI instead of a CLI scan |
| `-gui-host` | `127.0.0.1` | GUI listen address (loopback only) |
| `-gui-port` | `0` | GUI listen port (`0` = pick a free port) |
| `-gui-no-browser` | `false` | Do not open the GUI in a browser automatically |

The `-gui-*` flags only apply together with `-gui`.

### Configuration and precedence

Every scan flag can also be supplied by a `VNCSHOT_*` environment variable or
by a config file. The precedence, highest first, is:

```
command-line flag > environment variable > config file > built-in default
```

An explicit command-line flag always wins; environment values only apply to
flags that were not set on the command line, and config-file values only apply
to flags that were not set by either of the other two sources.

Environment variable names are the upper-case flag name with every `-`
replaced by `_`: `-out-dir` becomes `VNCSHOT_OUT_DIR`, `-vnc-timeout` becomes
`VNCSHOT_VNC_TIMEOUT`, and so on. Empty environment values are ignored.

A config file is loaded with `-config <path>` or, when that flag is absent,
from `VNCSHOT_CONFIG`. A `.json` file is parsed as a flat JSON object; any
other extension is parsed as the flat `key: value` YAML subset, which rejects
nesting, lists, block scalars, duplicate keys and unknown keys instead of
silently ignoring them. Keys are the exact flag names:

```yaml
# /root/vncshot.conf
out-dir: /root/assessments
ports: 5900,5901-5910
workers: 200
rate: 150
timeout: 2s
vnc-timeout: 20s
shared: true
no-pdf: false
```

The JSON form is equivalent:

```json
{
  "out-dir": "/root/assessments",
  "workers": 200,
  "timeout": "2s"
}
```

`-version` is evaluated before environment, config-file and root checks are
applied, so a broken or missing config never hides the build information and
the flag itself must come from the command line.

## Password testing

Password testing is enabled by default. Every RFB endpoint first gets a
discovery connection that reads the advertised security types without
sending a credential:

* If the server offers the `None` security type, the host is reported as
  passwordless and its framebuffer is captured.
* If the server requires VNC authentication, each candidate password is tried
  on its own short-lived connection. The first accepted password is recorded,
  and the host is captured exactly like a passwordless one.
* Servers that offer only other security types (for example TLS or VeNCrypt)
  are reported as RFB services without a password attempt.

Candidates come from the built-in weak-password list (about 30 common VNC
passwords, including the empty password) plus, optionally, `-word-list`.
`-no-default-passwords` removes the built-in list, and `-no-password-check`
skips the attempt phase entirely so only passwordless hosts are reported.
Discovery itself never sends a password, so an out-of-scope host is not
attacked just because it was scanned.

### Read-only by design

After a successful login — passwordless or weak password — the client sends
only `SetPixelFormat`, `SetEncodings` and a single `FramebufferUpdateRequest`,
reads exactly one framebuffer update and then disconnects. It never sends
keyboard or mouse input, clipboard data or control messages, never requests
continuous updates, and never modifies the remote desktop. A capture is a
snapshot of the current screen, nothing more.

### Candidate limits

* Every candidate uses a new connection; a session is never reused to hammer
  one server.
* A `SecurityResult` status of `2` (too many attempts / locked out) stops the
  remaining candidates for that host and is recorded as `auth_locked` in the
  JSON report and as a "locked out" marker in the HTML/PDF reports.
* The built-in list is intentionally small so an inventory scan stays
  unobtrusive.
* `-word-list` accepts at most 500 entries and is rejected when the path is
  missing or points to a directory.

### Handling sensitive output

Reports contain weak credentials and screenshots contain captured desktops.
Run directories are created `0700`, screenshots `0600`, and the JSON, HTML, PDF,
CSV reports and the manifest `0600`, so only the owner can read them. Treat a
run directory as sensitive evidence: do not copy it to shared storage or attach
it to a ticket without redaction.

## Connection and transport

### Security types and TLS

Every result records the RFB security types the server advertised, in
advertisement order, as human-readable names in `security_types` (for example
`["VNC authentication", "VeNCrypt"]`). The names follow the IANA RFB security
type registry, so entries such as `None`, `VNC authentication`, `Tight`,
`Ultra`, `TLS`, `VeNCrypt`, `SASL`, `MSLogon II` and `Apple Remote Desktop`
appear as their protocol names, and unknown numbers appear as `type <n>`.

A result also carries a `tls` flag, which is set when at least one advertised
type is defined to establish or negotiate an encrypted channel. The following
types count as encrypted: `RA2`, `Tight`, `Ultra`, `TLS`, `VeNCrypt` and
`SASL`. `Tight`, `Ultra` and `SASL` are included because they can negotiate
confidentiality, so the flag describes the offered capability rather than a
guarantee that every session uses TLS. `None`, `VNC authentication` and the
other types are treated as clear text. A server that advertises both `None`
and an encrypted type still gets `tls: true`, even though the probe takes the
weaker `None` path.

The summary includes a `tls_services` counter (JSON key `tls_services`, HTML
and PDF label `TLS services`, GUI counter `TLS services`). The HTML endpoint
table adds a Security column, the PDF endpoint table adds a `SECURITY` column
and a `Transport` row in each finding card, and the GUI findings table adds a
Transport column. Both `security_types` and `tls` are omitted from JSON when
empty or false.

### Retry and per-host limits

* A probe uses exactly one TCP connection: the dial that establishes the
  connectivity result is the same connection that performs the RFB handshake
  and the single frame capture. There is no separate openness dial followed by
  a second handshake dial.
* Password candidates are the exception: each candidate is tried on its own
  short-lived connection, as described under password testing.
* The scanner's retry policy allows at most one retry of a transient connect
  failure, with jittered exponential backoff starting at 150 ms (the first
  retry waits 150–225 ms). Timeouts, `ECONNRESET`, `EPIPE` and `EHOSTUNREACH`
  are treated as transient; `ECONNREFUSED` is definitive and never retried.
  The default budget is one retry; `-retries 0` makes a default scan use a
  single connection attempt per target.
* `attempts` in the JSON result, the CSV column and the report markers records
  how many TCP connection attempts were needed. A successful first attempt is
  `1`; a target that never connected reports `0`; a retried host shows the
  higher count and is marked as retried in the HTML/PDF/GUI output.
* Per-host concurrency is capped at 2 simultaneous probes per target IP, so a
  server with many scanned ports is not hit by every worker at once. The
  global `-workers` and `-rate` limits still apply.

## GUI

```bash
sudo vncshot -gui
```

This starts a local web interface on loopback and prints its session URL to
the terminal. The form exposes the scan options: target or target file, ports,
workers, rate, connect and RFB timeouts, report root, JSON/HTML/PDF path
overrides, screenshot directory, skip PDF and shared session. The run-level
options `-baseline`, `-manifest`, `-webhook`, `-csv` and `-config` are not part
of the form; values passed on the launch command line are inherited by scans
started from the GUI.

The "Passwords" panel holds the word list path and the two skip toggles
(built-in weak-password list, password testing). The status line shows how
many password candidates the current run will try, and the findings table
marks hosts reached with a weak credential.

The summary strip includes a `TLS services` counter, and the findings table
has a Transport column that lists the advertised security types (joined with
`·`) and adds a `tls` tag for encrypted endpoints.

The "Previous runs" panel lists the run folders under the report root
(`GET /api/runs`, newest first, limited to the 100 most recent). Selecting a
run reloads its JSON report into the dashboard (`POST /api/runs/open`) so an
older run can be reviewed without starting a scan; the request is rejected
with `409 Conflict` while a scan is running. Run names are validated as bare
timestamp folder names, so a crafted name cannot escape the report root.

Form values survive a page reload in `localStorage` (target, ports, timeouts,
output paths, password options and the other form fields). The authorization
checkbox is deliberately never persisted and must be ticked again for every
scan.

A scan cannot start until the authorization checkbox is ticked; this is the
GUI equivalent of `-yes`. Progress, counters, findings and screenshots update
live over Server-Sent Events. A running scan can be cancelled, and a finished
run links to its HTML, PDF and JSON artifacts.

Security properties:

* A non-loopback `-gui-host` value is rejected at startup.
* Each launch generates a 24-byte random session token. It is delivered once
  as a URL query parameter, stored in an HttpOnly, SameSite=Strict cookie,
  and must also be sent in the `X-Vncshot-Token` header for state-changing
  requests.
* The `/files/` endpoint only serves files inside the current run folder.
* The GUI also runs as root, so anyone with the printed URL can drive the
  scanner. Treat the URL and token as credentials.
* For remote access, keep the loopback bind and forward the port over SSH
  (`ssh -L 8080:127.0.0.1:<port> ...`) rather than exposing it on a public
  interface.

Use `-gui-port` to pin the port and `-gui-no-browser` to suppress the
automatic `xdg-open` call.

## Output

Every scan writes into its own timestamped folder under `-out-dir`, so runs
never overwrite each other. The default, `/usr/local/vncshot`, is compiled
into the binary by `install.sh`, which also creates the directory:

```
/usr/local/vncshot/20261026-205304/
├── screenshots/{ip}_{port}_{timestamp}.png
├── manifest.json                  (with -manifest)
├── vncshot_report.csv
├── vncshot_report.json
├── vncshot_report.html
└── vncshot_report.pdf
```

* `screenshots/` — framebuffer captures of passwordless and weak-password servers
* `vncshot_report.json` — full result set
* `vncshot_report.html` — self-contained report (embedded thumbnails, filter, modal)
* `vncshot_report.pdf` — PDF report generated in-process from scan results
* `vncshot_report.csv` — flat export of the same result set
* `manifest.json` — SHA-256 digests of the run artifacts, written only with `-manifest`

Results are sorted once before any artifact is written: numerically by IP
address, then by port. JSON, HTML, PDF, CSV and the terminal summary therefore
always list endpoints in the same order, and repeated scans of an unchanged
network produce directly comparable files. Hosts whose address is not a valid
IP (for example a hostname) sort after numeric addresses, in lexical order.

Each result in the JSON report carries `password` and `password_source`
(`default` or `word-list`) when a weak credential was accepted, and the
summary includes a `weak_credentials` counter. The HTML and PDF reports show
the same counter as a "Weak creds" stat and display the credential with its
source in the finding cards and the endpoint table.

A run directory holds credentials and captured desktops, so it is created
`0700` and every screenshot and report file `0600`.

Relative paths passed to `-output`, `-html`, `-pdf`, `-csv` or
`-screenshot-dir` are resolved inside the run folder; absolute paths are used
as given. If the compiled-in default is not writable, the scan falls back to
`~/.local/share/vncshot`; an explicitly set `-out-dir` is always used as given.

The HTML and PDF reports use a light "technical dossier" theme. The PDF embeds
the Liberation Sans font (SIL Open Font License), so Turkish and other
non-ASCII characters render correctly.

### CSV format

The CSV report is always written, uses standard CSV quoting with
comma-separated fields, and has a fixed column order:

```
ip,port,open,rfb,passwordless,weak_password,password_source,tls,security_types,server_name,screen_width,screen_height,screenshot,error,duration_ms,attempts,timestamp
```

Booleans are written as `yes` or `no`. `security_types` joins the advertised
type names with `;` so the whole list stays inside one field. `timestamp` is
RFC 3339 in UTC. Rows are sorted by IP and port, exactly like the other
artifacts.

### Manifest

`-manifest` writes `<run-dir>/manifest.json` after every other artifact, so
the digests describe the final files:

```json
{
  "generated_at": "2026-10-26T20:53:04Z",
  "algorithm": "sha256",
  "root": "20261026-205304",
  "files": [
    {"path": "vncshot_report.csv", "size": 8192, "sha256": "..."}
  ]
}
```

`generated_at` is RFC 3339 in UTC, `algorithm` is `sha256`, `root` is the run
folder's base name (never the full local path), and `files` is sorted by the
slash-separated path relative to the run directory. Only regular files are
hashed; symbolic links are skipped, so a link pointing outside the run folder
cannot pull foreign content into the manifest. The manifest excludes itself,
so re-running it produces the same file list, and it is written
`0600` because the run folder holds credentials and captured desktops. It is
intended for evidence integrity: a reviewer can re-hash the folder and compare
each size and digest against this file.

### Baseline comparison

`-baseline <dir>` names a previous run directory; the tool reads its
`vncshot_report.json` and compares findings by `ip:port`. A missing directory,
a path that is not a directory, an unreadable report or invalid JSON is a hard
error before any probe runs, so a failed comparison never leaves an empty run
folder behind.

The comparison is reported in three groups:

* **new** — endpoints present in this run but not in the baseline
* **resolved** — baseline endpoints that no longer appear
* **changed** — endpoints whose risk state changed, with a reason

The reason strings are stable English text:

| Reason | Meaning |
|--------|---------|
| `no longer RFB` | The port answered before but no longer speaks RFB |
| `became passwordless` | The endpoint now offers the `None` security type |
| `weak password discovered` | A weak credential is now accepted |
| `password no longer accepted` | The previous weak password no longer works |
| `became TLS` | An encrypted security type is now advertised |
| `lost TLS` | No encrypted security type is advertised any more |

A host that changes state appears once under changed, not as both a new and a
resolved finding. The counts are printed in the CLI summary (baseline, new
findings, resolved, changed), rendered as a "Changes since baseline" section
in the HTML and PDF reports, and included in the webhook payload described
below. The JSON and CSV artifacts always contain the current run only. New
findings are also the trigger for the webhook.

### Webhook notifications

`-webhook <url>` POSTs a JSON document to an HTTP or HTTPS endpoint after a
completed scan, but only when `-baseline` produced at least one new finding or
the run found a passwordless or weak-password endpoint. Interrupted scans are
never announced. The request has a 10 second timeout and a `vncshot/<version>`
User-Agent; a non-2xx response counts as a failure.

The payload is:

```json
{
  "tool": "vncshot",
  "version": "1.0.0",
  "generated_at": "2026-10-26T20:53:04Z",
  "run_dir": "20261026-205304",
  "summary": { "targets": 254, "open": 3, "rfb": 2, "passwordless": 1,
               "weak_credentials": 1, "tls_services": 1, "screenshots": 2,
               "errors": 0 },
  "new_findings": [
    { "ip": "192.0.2.10", "port": 5900, "open": true, "rfb": true,
      "passwordless": false, "password_source": "word-list", "tls": false,
      "server_name": "lab-pc" }
  ],
  "weak_credentials": [
    { "ip": "192.0.2.10", "port": 5900, "password_source": "word-list" }
  ]
}
```

The password value is never included: webhook entries carry only
`password_source` (`default` or `word-list`). `run_dir` is the run folder's
base name, so the receiver never learns the local filesystem path, and error
messages redact the endpoint's query string and userinfo because those can
carry access tokens. `new_findings` is empty when no baseline was requested.

A delivery failure is a warning, not a failed scan: the CLI prints
`warning: webhook notification failed: ...` on stderr after the summary, the
artifacts remain intact, and the exit status still reflects the scan itself.

## Package layout

```
main.go        CLI flags, root check, GUI bootstrap
app/           scan session, artifact layout, baseline diff, manifest, webhook
config/        flag defaults from a config file and VNCSHOT_* environment variables
gui/           embedded web UI (index.html + HTTP server)
scanner/       target expansion, worker pool, rate limiting, retry and per-host limits
vnc/           RFB 3.3/3.7/3.8 client, None-auth and weak-password auth, raw capture
screenshot/    PNG persistence
report/        Result model, JSON/HTML/PDF/CSV exporters
```

## Dependencies

| Module | Purpose |
|--------|---------|
| `github.com/go-pdf/fpdf` | PDF report generation |
| `github.com/schollz/progressbar/v3` | Terminal progress bar |

Everything else uses the Go standard library.

## Development

```bash
go test ./...          # unit + integration tests
go vet ./...
gofmt -l .
```

CI runs on Linux (`.github/workflows/ci.yml`) for every push to `main`, every
pull request and manual dispatches. It checks `gofmt -l .`, runs `go vet ./...`,
`go build ./...` and `go test -race -count=1 ./...`, and lints `install.sh`
with shellcheck (severity warning, with `SC2034` excluded for two known
informational findings).

## Legal Disclaimer / Terms of Use

**Authorized use only.** This software is published for authorized
security testing, defensive security research and education. You must
scan only networks and systems you own or for which you hold explicit
written authorization.

Unauthorized access to, or interception of, computer systems is a
criminal offence in most jurisdictions. Ensuring that your use complies
with all applicable local, national and international law is **solely
and exclusively your responsibility**.

**No liability of the developer.** The developer (**Cuma KURT**) shall
**not** be held liable, under any circumstances and to the maximum
extent permitted by applicable law, for any damage, loss of data, loss
of profit, business interruption, legal claim, administrative or
criminal proceeding, penalty, fine, or any other direct, indirect,
incidental, special, consequential or punitive liability arising out of
or in connection with the use, misuse, inability to use, or reliance
upon this software — even if the developer has been advised of the
possibility of such damages.

**No warranty.** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF
THE SOFTWARE IS WITH YOU.

By running this tool you are deemed to have read, understood and
accepted this disclaimer.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

Copyright (C) 2026 Cuma KURT

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

Use responsibly and only with authorization.