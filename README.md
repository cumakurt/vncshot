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
- Local web GUI (`-gui`) with every CLI option, live progress and report links
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
of producing a partially working scan.

## Usage

```bash
sudo vncshot -target 192.168.1.0/24 -ports 5900,5901-5910
sudo vncshot -file hosts.txt -workers 100 -rate 150 -timeout 800ms
sudo vncshot -target 10.0.0.1-50 -out-dir /root/assessments
sudo vncshot -target 192.168.1.0/24 -word-list /root/passwords.txt
sudo vncshot -gui
```

Running the tool without arguments prints the usage text and exits without
scanning.

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Single IP, CIDR, or range (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | File with IPs/CIDRs/ranges, one per line (`#` comments allowed) |
| `-ports` | `5900` | Port list/ranges (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP connect timeout |
| `-vnc-timeout` | `15s` | RFB handshake/capture timeout |
| `-workers` | `150` | Concurrent scan workers |
| `-rate` | `200` | Max new connections per second (`0` = unlimited) |
| `-out-dir` | `/usr/local/vncshot` | Root directory for timestamped scan folders |
| `-output` | `<run-dir>/vncshot_report.json` | JSON report path |
| `-html` | `<run-dir>/vncshot_report.html` | HTML report path |
| `-pdf` | `<run-dir>/vncshot_report.pdf` | PDF report path (generated in-process) |
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
Run directories are created `0700`, screenshots `0600`, and the JSON, HTML and
PDF reports `0600`, so only the owner can read them. Treat a run directory as
sensitive evidence: do not copy it to shared storage or attach it to a ticket
without redaction.

## GUI

```bash
sudo vncshot -gui
```

This starts a local web interface on loopback and prints its session URL to
the terminal. The form exposes every CLI option: target or target file,
ports, workers, rate, connect and RFB timeouts, report root, JSON/HTML/PDF
path overrides, screenshot directory, skip PDF and shared session.

The "Passwords" panel holds the word list path and the two skip toggles
(built-in weak-password list, password testing). The status line shows how
many password candidates the current run will try, and the findings table
marks hosts reached with a weak credential.

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
├── vncshot_report.json
├── vncshot_report.html
└── vncshot_report.pdf
```

* `screenshots/` — framebuffer captures of passwordless and weak-password servers
* `vncshot_report.json` — full result set
* `vncshot_report.html` — self-contained report (embedded thumbnails, filter, modal)
* `vncshot_report.pdf` — PDF report generated in-process from scan results

Each result in the JSON report carries `password` and `password_source`
(`default` or `word-list`) when a weak credential was accepted, and the
summary includes a `weak_credentials` counter. The HTML and PDF reports show
the same counter as a "Weak creds" stat and display the credential with its
source in the finding cards and the endpoint table.

A run directory holds credentials and captured desktops, so it is created
`0700` and every screenshot and report file `0600`.

Relative paths passed to `-output`, `-html`, `-pdf` or `-screenshot-dir` are
resolved inside the run folder; absolute paths are used as given. If the
compiled-in default is not writable, the scan falls back to
`~/.local/share/vncshot`; an explicitly set `-out-dir` is always used as given.

The HTML and PDF reports use a light "technical dossier" theme. The PDF embeds
the Liberation Sans font (SIL Open Font License), so Turkish and other
non-ASCII characters render correctly.

## Package layout

```
main.go        CLI flags, root check, GUI bootstrap
app/           scan session and artifact layout shared by CLI and GUI
gui/           embedded web UI (index.html + HTTP server)
scanner/       target expansion, worker pool, rate limiting
vnc/           RFB 3.3/3.7/3.8 client, None-auth and weak-password auth, raw capture
screenshot/    PNG persistence
report/        Result model, JSON/HTML/PDF exporters
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