# vncshot

[English](README.md) | [Türkçe](README.tr.md)

VNC security inventory scanner. Discovers RFB/VNC endpoints, flags
passwordless and weak-password servers, and captures their current
framebuffer as PNG evidence for authorized security assessments.

`vncshot` supports Linux only and requires root privileges.

```
Use only on networks you own or have explicit written permission to test.
```

![vncshot GUI dashboard](docs/screenshots/gui-dashboard.png)

*The local GUI: live counters, transport column, captured frames and the
previous-run history, all on loopback.*

## Table of contents

- [Developer](#developer)
- [Features](#features)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Build and install](#build-and-install)
- [Privileges](#privileges)
- [Usage](#usage)
  - [Configuration and precedence](#configuration-and-precedence)
- [Password testing](#password-testing)
  - [Read-only by design](#read-only-by-design)
  - [Candidate limits](#candidate-limits)
  - [Handling sensitive output](#handling-sensitive-output)
- [Connection and transport](#connection-and-transport)
  - [Security types and TLS](#security-types-and-tls)
  - [Retry and per-host limits](#retry-and-per-host-limits)
- [How a scan works](#how-a-scan-works)
  - [Target expansion](#target-expansion)
  - [Probe pipeline](#probe-pipeline)
- [GUI](#gui)
  - [GUI HTTP API](#gui-http-api)
- [Output](#output)
  - [JSON schema](#json-schema)
  - [CSV format](#csv-format)
  - [SARIF output](#sarif-output)
  - [Manifest](#manifest)
  - [Manifest signing and verification](#manifest-signing-and-verification)
  - [Baseline comparison](#baseline-comparison)
  - [Failing on findings (-fail-on)](#failing-on-findings--fail-on)
  - [Webhook notifications](#webhook-notifications)
  - [Acceptance and exclusion lists](#acceptance-and-exclusion-lists)
  - [Certificate expiry tracking](#certificate-expiry-tracking)
  - [Continuous monitoring](#continuous-monitoring)
  - [Maintenance and retention](#maintenance-and-retention)
- [Running behind a proxy](#running-behind-a-proxy)
- [Self-check](#self-check)
- [Exit codes](#exit-codes)
- [Performance tuning](#performance-tuning)
- [Troubleshooting](#troubleshooting)
- [Package layout](#package-layout)
- [Dependencies](#dependencies)
- [Development](#development)
- [Legal Disclaimer / Terms of Use](#legal-disclaimer--terms-of-use)
- [License](#license)

## Developer

**Cuma KURT**
- Email: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/vncshot](https://github.com/cumakurt/vncshot)

## Features

- Linux only; both the CLI and the GUI must run as root
- Scan single IPs, CIDR blocks, IPv4 ranges, a file of targets, or a target
  list from standard input (`-file -`)
- `-dry-run` prints the expanded scope without sending a packet
- Concurrent worker pool with configurable rate limiting and per-host caps
- RFB 3.3 / 3.7 / 3.8 handshake, passwordless (`None`) detection and
  weak-password detection
- TLS and VeNCrypt probing (`TLSNone`, `TLSVnc`, `X509None`, `X509Vnc`) with
  peer certificate evidence for every established encrypted session
- Framebuffer capture to PNG for passwordless and weak-password endpoints
- Read-only probing: one frame is requested and the session is closed
- JSON + self-contained HTML report (base64 thumbnails, filter, modal)
- In-process PDF report export (no external tools required)
- CSV export with a stable column order for spreadsheets and pipelines
- SARIF 2.1.0 output (`-sarif`) for CI/SAST dashboards, with stable rule ids
  and deterministic ordering
- Report redaction (`-redact`) and preview-only HTML (`-thumb-only`) for
  sharing evidence without the secrets or the full-resolution frames
- Run retention (`-keep`, `-prune`) with guarded deletion and a dry-run mode
- Security-type inventory: every finding records the advertised
  `security_types` and a `tls` flag
- Baseline comparison against a previous run (new, resolved and changed findings)
- SHA-256 manifest of every run artifact (`-manifest`) for evidence integrity
- Manifest signing (`-sign-key`) and offline verification
  (`-verify-manifest`) with ed25519, so copied evidence folders stay
  provable on any machine
- CI exit-code control (`-fail-on`): fail the run with code 3 when any
  requested finding category is present
- Optional notifications on completion: webhook, Slack, SMTP e-mail and
  syslog CEF events (`-webhook`, `-slack-url`, `-mail-server`, `-syslog`)
- Acceptance list for known findings (`-accept`) and exclusion list for
  segments that are never contacted (`-exclude`)
- Certificate expiry tracking (`-cert-warn`) with expires-soon badges and
  summary counters
- Scheduled scanning (`-interval`) with automatic per-round baselines and a
  Prometheus metrics endpoint (`-metrics-addr`)
- Optional systemd timer installed by `install.sh --systemd`, with all scan
  options in `/etc/vncshot/scan.conf`
- SOCKS5 proxy support (`-proxy`) for reaching isolated segments through a
  jumphost
- Environment self-check (`-selfcheck`) for new deployments
- Flag defaults from a config file (`-config`) and `VNCSHOT_*` environment variables
- Deterministic, sorted results so repeated scans can be compared directly
- One TCP connection per attempt and bounded per-host concurrency
- Local web GUI (`-gui`) with live progress, report links and a previous-run history
- `-version` prints build information without requiring root
- Graceful Ctrl+C shutdown with partial results

## Requirements

| Area | Requirement |
|------|-------------|
| Operating system | Linux (the binary and `install.sh` refuse other systems) |
| Privileges | root, directly or via `sudo`, for CLI and GUI scans |
| Build toolchain | Go 1.22 or newer, only when building from source |
| Runtime | none; the binary is statically linked |
| Network | TCP reachability to the scanned VNC ports |

The tool has no runtime dependency on a desktop environment, X11, a browser or
external utilities. The GUI is a local web page, and `xdg-open` is used only to
open a browser automatically (`-gui-no-browser` disables it).

## Quick start

```bash
# 1. Build and install (creates /usr/local/vncshot for scan output)
git clone https://github.com/cumakurt/vncshot.git
cd vncshot
./install.sh

# 2. Verify the binary and review the options
vncshot -version
vncshot -h

# 3. Scan an authorized range and capture evidence
sudo vncshot -target 192.168.1.0/24 -ports 5900,5901-5910

# 4. Open the generated report
sudo find /usr/local/vncshot -name vncshot_report.html
```

Every run lands in its own timestamped folder, so consecutive scans never
overwrite each other. The terminal summary ends with the exact paths.

## Build and install

```bash
# one-shot bootstrap + static build + install to /usr/local/bin
./install.sh

# or build directly
go build -o vncshot .

# install.sh options
./install.sh -y               # non-interactive
./install.sh --build-only     # skip dependency installation
./install.sh --no-install-bin # build only; do not install system-wide
./install.sh --systemd        # also install and enable the daily systemd timer
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

`GO_VERSION` pins the Go release downloaded when no suitable toolchain is
present, and `VERSION` sets the version string embedded in the binary and
printed by `-version`. The report root is compiled into the binary, so the
installed binary and the installed directory always agree. There are no
runtime external dependencies beyond the Go toolchain used for building.

### Uninstall

```bash
sudo ./install.sh --uninstall          # removes the binary, keeps reports
sudo ./install.sh --uninstall --purge-reports   # also deletes $REPORT_DIR
```

Manual removal is still possible:

```bash
sudo rm -f /usr/local/bin/vncshot
sudo rm -rf /usr/local/vncshot     # deletes every captured report and screenshot
```

Remove `~/.cache/vncshot-install` as well if you want to drop the cached Go
tarball downloaded by `install.sh`.

### Scheduled scanning with systemd

`install.sh --systemd` turns the scan into a systemd timer. After the usual
build and install it writes `/etc/systemd/system/vncshot.service`,
`/etc/systemd/system/vncshot.timer` and an example configuration at
`/etc/vncshot/scan.conf`, then enables the timer:

```bash
sudo ./install.sh --systemd                   # daily at 03:30
sudo ./install.sh --systemd 'Mon..Fri 04:00'  # custom OnCalendar expression
```

All scan options come from `/etc/vncshot/scan.conf`, an environment file the
service loads with `EnvironmentFile=`. Every `VNCSHOT_*` variable maps to a
flag (`-target` becomes `VNCSHOT_TARGET`, `-ports` becomes
`VNCSHOT_PORTS`, `-word-list` becomes `VNCSHOT_WORD_LIST`); the generated
file ships with commented examples, and `VNCSHOT_ARGS` passes extra
command-line arguments through verbatim. The unit runs the scan with
`-yes`, which skips the interactive authorization confirmation — make sure
the configured targets are authorized before enabling the timer. The timer
uses `Persistent=true`, so a missed run (host powered off) is started on
the next boot.

Next steps:

```bash
sudoedit /etc/vncshot/scan.conf        # set VNCSHOT_TARGET and friends
systemctl restart vncshot.timer        # pick up configuration changes
systemctl list-timers vncshot.timer    # check the next scheduled run
```

The operation is idempotent: re-running `--systemd` regenerates the unit
files and never overwrites an existing non-empty `scan.conf`. A malformed
`OnCalendar` expression is rejected up front when `systemd-analyze` is
available, and a failing `systemctl` call only warns — the units stay in
place and the timer can be enabled manually. The systemd paths can be
redirected for staged installs with `SYSTEMD_UNIT_DIR` and
`VNCSHOT_CONF_DIR`.

To stop the timer and remove the generated units (the binary, the reports
and `/etc/vncshot/scan.conf` are kept):

```bash
sudo ./install.sh --systemd-uninstall
```

`--uninstall` also removes the units when they are present.

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
sudo vncshot -target 10.0.0.0/16 -dry-run
cat hosts.txt | sudo vncshot -file - -ports 5900
sudo vncshot -target 192.168.1.0/24 -redact -thumb-only
sudo vncshot -target 10.0.0.0/16 -source-addr 10.1.2.3
sudo vncshot -target 192.168.1.0/24 -baseline /usr/local/vncshot/20261020-090000
sudo vncshot -target 10.0.0.0/24 -manifest -webhook https://hooks.example.test/vncshot
sudo vncshot -target 192.168.1.0/24 -config /root/vncshot.conf
sudo vncshot -target 192.168.1.0/24 -keep 30
sudo vncshot -prune 30 -prune-dry-run
sudo vncshot -gui
vncshot -version
```

Running the tool without arguments prints the usage text and exits without
scanning. `-version` prints the tool name, build version, GOOS/GOARCH and Go
runtime version, for example `vncshot dev (linux/amd64, go1.27.2)`; `install.sh`
injects the release version at build time.

![vncshot console output](docs/screenshots/console.png)

*Console output of a scan against lab fixtures: progress, summary and the
generated report files.*

| Flag | Default | Description |
|------|---------|-------------|
| `-version` | `false` | Print build information and exit (does not require root) |
| `-target` | | Single IP, CIDR, or range (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | File with IPs/CIDRs/ranges, one per line (`#` comments allowed); `-` reads standard input |
| `-ports` | `5900` | Port list/ranges (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP connect timeout |
| `-vnc-timeout` | `15s` | RFB handshake/capture timeout |
| `-workers` | `150` | Concurrent scan workers (maximum 4096) |
| `-rate` | `200` | Max new connections per second (`0` = unlimited, maximum 100000) |
| `-retries` | `1` | Extra attempts for transient failures, before and after the TCP connect (`0` = none) |
| `-source-addr` | `""` | Local IP to bind probes to; empty or `auto` uses the route table |
| `-out-dir` | `/usr/local/vncshot` | Root directory for timestamped scan folders |
| `-output` | `<run-dir>/vncshot_report.json` | JSON report path |
| `-html` | `<run-dir>/vncshot_report.html` | HTML report path |
| `-pdf` | `<run-dir>/vncshot_report.pdf` | PDF report path (generated in-process) |
| `-csv` | `<run-dir>/vncshot_report.csv` | CSV report path |
| `-sarif` | | SARIF 2.1.0 report path (default `<run-dir>/vncshot_report.sarif` when set) |
| `-baseline` | | Previous run directory; findings are compared with it |
| `-manifest` | `false` | Write `<run-dir>/manifest.json` with SHA-256 digests of every artifact |
| `-sign-key` | | ed25519 PKCS#8 private key that signs the manifest; generated with mode `0600` when missing (requires `-manifest`) |
| `-fail-on` | | Exit with code 3 when any of these finding categories match: `new`, `resolved`, `changed`, `passwordless`, `weak`, `self-signed`, `cert-expiring` (comma-separated) |
| `-redact` | `false` | Replace captured passwords with `REDACTED` in JSON/HTML/PDF |
| `-thumb-only` | `false` | Embed only the preview image, not the full-resolution capture, in HTML |
| `-keep` | `0` | Keep only the newest n run folders after a scan (`0` = keep all) |
| `-prune` | `0` | Delete all but the newest n run folders and exit (`0` = disabled) |
| `-prune-dry-run` | `false` | With `-prune` (or with `-keep` alone) list what would be removed and delete nothing |
| `-dry-run` | `false` | Expand the scope, print targets/hosts/ports/password candidates and exit without sending a packet |
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
| `-proxy` | | SOCKS5 proxy for every probe, `socks5://` (local resolution) or `socks5h://` (proxy resolves); default port 1080 |
| `-exclude` | | File with IPs, CIDR ranges or `ip:port` entries that are never contacted |
| `-accept` | | File listing approved endpoints (`ip:port [reason]`, optional `until:YYYY-MM-DD`) whose findings stop alarming |
| `-cert-warn` | `30` | Days ahead of certificate expiry to flag TLS certificates (`0` disables) |
| `-slack-url` | | Slack incoming-webhook URL (https only) receiving a formatted message |
| `-mail-server` | | SMTP relay `host:port` for e-mail notifications (STARTTLS mandatory unless `-mail-no-tls`) |
| `-mail-from` / `-mail-to` | | Envelope sender / comma-separated recipients for e-mail |
| `-mail-no-tls` | `false` | Allow plaintext SMTP without STARTTLS (credentials are still never sent without TLS) |
| `-mail-user` | | SMTP AUTH PLAIN user; password comes from `VNCSHOT_MAIL_PASSWORD` |
| `-syslog` | | Syslog receiver (`udp://host:port` or `tcp://host:port`) receiving CEF events |
| `-metrics-addr` | | Serve Prometheus text metrics on this address (use loopback) |
| `-interval` | `0s` | Rescan forever with this pause between rounds, diffing against the previous round |
| `-selfcheck` | `false` | Verify the environment (root, report root, TLS roots, browser, clock, loopback, disk) and exit |
| `-verify-manifest` | | Verify the signed manifest and every artifact of this run directory, then exit (no root needed) |
| `-pub-key` | | Public key for `-verify-manifest` (default `<sign-key>.pub`) |

The `-gui-*` flags only apply together with `-gui`.

`-prune` turns the invocation into a maintenance command: it needs no target,
deletes all but the newest n run folders below `-out-dir` and exits, so it can be
scheduled on its own. The root check still applies, because the default report
root is `/usr/local/vncshot`, but no authorization prompt is shown for a prune
or a dry run. `-prune-dry-run` either previews that command (with `-prune`, or
alone together with `-keep`) or, in the GUI, previews the retention pass of the
next scan. On its own, without a positive `-prune` or `-keep` value, it exits
with an error because there is no policy to preview. Both `-keep 0` and
`-prune 0` mean "disabled"; an explicitly given `-prune 0` is rejected as a
mistake rather than silently ignored.

`-dry-run` expands the target and port inputs, prints the scope and exits before
any packet is sent or any directory is created. It neither prompts for
authorization nor needs `-yes`, but the startup root check still applies.

`-h` prints the same flag reference and exits `0`. An unknown flag prints
`flag provided but not defined: <name>` followed by the usage text and exits `2`.

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

* If the server offers the `None` security type, or the `TLS` type (18, which
  is `None` over TLS), the host is reported as passwordless and its framebuffer
  is captured.
* If the server requires VNC authentication — directly or through the VeNCrypt
  `TLSVnc` subtype — each candidate password is tried on its own short-lived
  connection. The first accepted password is recorded, and the host is captured
  exactly like a passwordless one.
* Servers that offer only security types this client does not implement (for
  example `SASL`, `Plain`, or a VeNCrypt `X509*` subtype) are reported as RFB
  services without a password attempt.

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

The whole RFB client is about 1,100 lines and can be audited in one sitting:
`vnc/protocol.go` holds the wire constants and encoders, `vnc/auth.go` the
authentication, and `vnc/client.go` the handshake and capture flow.

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
* Candidates longer than eight bytes are truncated to eight by the RFB
  authentication scheme itself; the report records what was accepted.

### Handling sensitive output

Reports contain weak credentials and screenshots contain captured desktops.
Run directories are created `0700`, screenshots `0600`, and the JSON, HTML, PDF,
CSV reports and the manifest `0600`, so only the owner can read them. Treat a
run directory as sensitive evidence: do not copy it to shared storage or attach
it to a ticket without redaction.

`-redact` removes the secret value before the JSON, HTML and PDF artifacts are
written: every captured password becomes `REDACTED`, while the finding, its
`password_source` and the weak-credential counters stay visible. The CSV export
has no password column, so it is unaffected, and certificate evidence is not a
secret and is kept. `-thumb-only` complements it by embedding only the preview
image in the HTML report, which keeps a large inventory shareable as one file;
the full-resolution PNGs stay in the run folder.

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

The probe completes an encrypted session on three paths:

| Path | Security type | Credential |
|------|---------------|------------|
| `TLS` | type 18, defined as `None` over TLS | none |
| VeNCrypt `TLSNone` | subtype 257 | none |
| VeNCrypt `TLSVnc` | subtype 258 | VNC authentication inside TLS |

An encrypted path is preferred over plain VNC authentication: both yield either
a passwordless capture or a certificate that identifies the endpoint, which
plain VNC authentication cannot provide. TLS 1.0 and 1.1 handshakes are accepted
so old appliances can still be inventoried; `tls_version` reports what was
actually negotiated.

Other VeNCrypt subtypes are not implemented: `Plain`, `TLSPlain`, the `X509*`
family, `TLSSASL`, `X509SASL` and the `Ident` family. When a server offers only
those, the posture is recorded and no session is attempted, so the endpoint
appears as an RFB service without a capture or certificate.

Some appliances advertise TLS or VeNCrypt but cannot complete the encrypted
negotiation, or expect a subtype this client does not implement. When the
security-type list was already read, the probe retries once over the clear-text
types the server also advertises, and any password candidates use that
clear-text path. A failure before the type list is left to the retry policy
described below.

When a TLS session is established, the result carries a `certificate` object:

| Field | Meaning |
|-------|---------|
| `tls_version` | Negotiated protocol version, for example `TLS 1.2` |
| `cipher_suite` | Negotiated cipher suite name |
| `subject`, `issuer` | Textual distinguished names |
| `not_before`, `not_after` | Validity boundaries in UTC |
| `dns_names` | DNS subject alternative names |
| `sha256_fingerprint` | SHA-256 of the DER certificate, colon-separated hex |
| `self_signed` | Subject and issuer are identical |
| `expired` | `not_after` is in the past at scan time |
| `verified` | The chain validated against the system roots |

The probe records the certificate instead of trusting it: the TLS client runs
with `InsecureSkipVerify`, so an appliance certificate never aborts the scan.
`verified` is computed independently against the system roots and covers chain
trust only, not whether the certificate matches the scanned address. A
self-signed appliance certificate therefore reports `self_signed: true` and
`verified: false`; that is evidence about the endpoint's trust posture, not a
failed probe. An unverified certificate that is not self-signed is rendered as
`untrusted` in the reports.

The summary includes a `tls_services` counter (JSON key `tls_services`, HTML
and PDF label `TLS services`, GUI counter `TLS services`) and a
`self_signed_certs` counter (HTML, PDF and GUI label `Self-signed certs`) that
counts established TLS sessions whose peer certificate names itself as its
issuer. The HTML endpoint table adds a Security column with the certificate
state, the PDF endpoint table adds a `SECURITY` column and a `Transport` row in
each finding card, and the GUI findings table adds a Transport column with a
certificate marker. Both `security_types` and `tls` are omitted from JSON when
empty or false, and `certificate` is omitted when no TLS session was
established.

### Retry and per-host limits

* A probe uses one TCP connection per attempt: the dial that establishes the
  connectivity result is the same connection that performs the RFB handshake
  and the single frame capture. There is no separate openness dial followed by
  a second handshake dial; a retry is a new attempt with a new connection.
* Password candidates are the exception: each candidate is tried on its own
  short-lived connection, as described under password testing.
* The scanner's retry policy allows at most one retry, with jittered
  exponential backoff starting at 150 ms (the first retry waits 150–225 ms).
  The same `-retries` budget covers both sides of the TCP connect:
  * Before the connect, timeouts, `ECONNRESET`, `EPIPE` and `EHOSTUNREACH` are
    transient; `ECONNREFUSED` is definitive and never retried.
  * After the connect, a timeout, `ECONNRESET`, `EPIPE`, `EOF` or a truncated
    read is retried once. A protocol-level answer — a malformed or non-RFB
    banner, an unsupported encoding, a rejected negotiation — is definitive and
    is never retried.
  The default budget is one retry; `-retries 0` makes a default scan use a
  single connection attempt per target.
* A probe that parsed the RFB banner but failed the security negotiation is
  still reported as an RFB service: `open` and `rfb` are `true`, `error`
  carries the failure and the evidence collected so far (security types, TLS
  capability, certificate, server name and geometry) is kept. A port that
  answered without a parsable banner stays `open: true`, `rfb: false`.
* `attempts` in the JSON result, the CSV column and the report markers records
  how many connection attempts were needed. A successful first attempt is
  `1`; a target that never connected reports `0`; a retried host shows the
  higher count and is marked as retried in the HTML/PDF/GUI output.
* Per-host concurrency is capped at 2 simultaneous probes per target IP, so a
  server with many scanned ports is not hit by every worker at once. The
  global `-workers` and `-rate` limits still apply.
* `-workers` and `-rate` have hard upper bounds (4096 and 100000). A worker is
  a goroutine plus at least one socket, and beyond 100000 connections per
  second the pacing interval would round to zero, so both limits are rejected
  instead of being silently ignored.

`-source-addr` binds every probe dial to the given local address, including the
connections used for password candidates. It matters on a multi-homed host
where the route table would otherwise pick an address outside the assessed
network. An invalid value is rejected before the run starts; `auto` or an empty
value keeps the route table's choice.

A cancelled probe is recorded with the cancellation reason, not with the
socket deadline error it triggers: an operator reading `i/o timeout` would
otherwise look for a nonexistent network fault.

## How a scan works

### Target expansion

`-target` accepts a single address, a CIDR block, an inclusive last-octet
range (`10.0.0.10-20`), an IPv6 address/CIDR or an IPv6 range
(`2001:db8::1-2001:db8::a`, or the shorthand `2001:db8::1-::a`, where the
missing leading groups of the right endpoint are filled in from the left
one). Range endpoints must belong to the same family (both IPv4 or both
IPv6); 4-in-6 mapped addresses (`::ffff:a.b.c.d`) count as IPv4. `-file`
reads the same syntax one entry per line, with `#` comments and blank lines
ignored, and `-file -` reads the list from standard input instead of a file.
Both sources can be combined and duplicates are removed. `-ports` accepts a
comma-separated list of ports and inclusive ranges.

Expansion is bounded so a typo cannot start a massive scan:

| Limit | Value | Behaviour |
|-------|-------|-----------|
| Host:port pairs per run | 1,048,576 (2^20) | Rejected with a message to narrow the target or port list |
| Hosts per single CIDR spec | 65,536 (2^16, i.e. `/16` or longer) | Rejected; split larger blocks into several specs |
| Hosts read from a file or stdin stream | 1,048,576 (2^20) | Rejected; the stream is not buffered beyond the cap |
| Hosts per single range spec (IPv4 and IPv6) | 1,048,576 (2^20) | Rejected; split larger ranges into several specs |
| Word-list entries | 500 | Rejected |

Targets are expanded before any packet is sent, so an invalid input fails
immediately with no partial scan. `-dry-run` uses the same expansion and prints
the number of host:port pairs, the unique host count, the port specification,
the password-candidate count, the report root, the worker/rate settings and the
first and last target in scan order, then exits without creating a directory or
opening a socket.

### Probe pipeline

For every `host:port` pair the worker performs:

1. **Dial** with `-timeout`. A refused or timed-out connect marks the port as
   closed (or retries once when the failure is transient).
2. **Protocol banner** — read `RFB xxx.yyy`, reply with the best version both
   sides support (3.3, 3.7 or 3.8).
3. **Security negotiation** — read the advertised types. `None` continues
   immediately; the `TLS` type and the VeNCrypt `TLSNone` subtype establish an
   encrypted session without a credential; VNC authentication and VeNCrypt
   `TLSVnc` trigger the candidate loop; anything else stops after recording the
   posture. A failed encrypted negotiation is retried once over the clear-text
   types the server also advertises.
4. **Session init** — `ClientInit`/`ServerInit` yields the desktop name and
   framebuffer geometry (capped at 8192x8192 per side).
5. **Capture** — request the 32-bit true-colour pixel format, raw encoding,
   one full-frame update, then close the connection.
6. **Persist** — write the PNG for passwordless/weak-password hosts and add
   the result to the in-memory set.

Results stream back to the collector, which drives the progress bar, the GUI
event stream and the final sorted artifact set. Ctrl+C cancels the context;
in-flight probes abort and the partial results are still written.

## GUI

```bash
sudo vncshot -gui
```

This starts a local web interface on loopback and prints its session URL to
the terminal. The form exposes the scan options: target or target file, ports,
workers, rate, connect and RFB timeouts, report root, JSON/HTML/PDF/CSV path
overrides, screenshot directory, skip PDF, shared session, manifest, webhook URL
and a keep-runs count with a prune dry-run toggle. `-config` is not part of the
form; values passed on the launch command line are inherited by scans started
from the GUI.

The "Comparison" panel holds a "Previous run" selector. It lists the run folders
under the report root and selects one as the baseline for the next scan, with
"No comparison" as the default. A run folder removed by retention silently
falls back to "No comparison" instead of leaving a baseline that cannot be read.

The "Passwords" panel holds the word list path and the two skip toggles
(built-in weak-password list, password testing). The status line shows how
many password candidates the current run will try, and the findings table
marks hosts reached with a weak credential.

The summary strip includes `TLS services` and `Self-signed certs` counters. The
findings table has a Transport column that lists the advertised security types
(joined with `·`), adds a `tls` tag for encrypted endpoints, and renders a
certificate marker when a TLS session was established: `self-signed`,
`expired` and `verified` as applicable, followed by the expiry date when the
certificate reports one. Hovering the marker shows the subject, issuer and
SHA-256 fingerprint; certificates that carry none of those markers are labelled
`certificate`. After a scan with retention, the dashboard shows
`Removed N old run(s)` when the pass deleted (or, in a dry run, would delete)
one or more folders.

Redaction stays a launch-time option: the "Delivery" panel keeps a redaction
checkbox as a saved preference, but the scan pipeline only honours `-redact`
given when the GUI was started. Start `sudo vncshot -gui -redact` to redact the
reports of every scan launched from that dashboard.

The "Previous runs" panel lists the run folders under the report root
(`GET /api/runs`, newest first, limited to the 100 most recent). Selecting a
run reloads its JSON report into the dashboard (`POST /api/runs/open`) so an
older run can be reviewed without starting a scan; the request is rejected
with `409 Conflict` while a scan is running. Run names are validated as bare
timestamp folder names, so a crafted name cannot escape the report root.

A "Run trend" strip under the counters plots the newest runs
(`GET /api/trends`, up to 50): one column per run with stacked bars for the
passwordless and weak-password counts, highlighted and scaled against the
busiest run. Clicking a column opens that run through the same flow as the
history list; runs without a readable report are skipped. Each non-current
run in the history panel also offers a "compare" action: it diffs that run
against the run the dashboard is serving (`POST /api/diff`) and opens a
`Baseline <base> → <target>` panel above the findings with the new, resolved
and changed endpoints. The panel has a close button and is hidden whenever
another run becomes current.

The dashboard follows the operating system colour scheme: the light "paper"
theme has an automatic dark variant driven by a `prefers-color-scheme` block
over the same CSS token set, with no toggle and no JavaScript. Findings
thumbnails open an in-page lightbox (Esc, backdrop click or the Close button
dismisses it; focus returns to the thumbnail) instead of navigating to the raw
file, and the lightbox keeps a "open full size" link for copy/download use.
Keyboard focus rings are drawn for every control, the status pill and the
activity feed announce changes with `aria-live`, and activity lines are
coloured by event severity.

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
* A screenshot directory outside the run folder is rejected before any probe
  starts, with an error that points at the report root. `/files/` is rooted at
  the run folder, so captures written elsewhere would render as broken
  thumbnails; remove the override or point it inside the run folder.
* The GUI also runs as root, so anyone with the printed URL can drive the
  scanner. Treat the URL and token as credentials.
* For remote access, keep the loopback bind and forward the port over SSH
  (`ssh -L 8080:127.0.0.1:<port> ...`) rather than exposing it on a public
  interface.

Use `-gui-port` to pin the port and `-gui-no-browser` to suppress the
automatic `xdg-open` call.

![Findings table and run history](docs/screenshots/gui-findings.png)

*Findings carry the transport, the credential source and a thumbnail of the
captured frame; the left rail keeps the previous runs one click away.*

### GUI HTTP API

The dashboard is a thin client over a small JSON API. Every endpoint except
the HTML page itself is protected by the session cookie and, for
state-changing requests, the `X-Vncshot-Token` header.

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/` | Dashboard page (accepts `?t=<token>` to establish the session) |
| `GET` | `/api/state` | Current run snapshot: status, counters, findings, artifact links |
| `GET` | `/api/events` | Server-Sent Events stream of the same snapshot |
| `POST` | `/api/scan` | Start a scan (requires `authorized: true`) |
| `POST` | `/api/cancel` | Cancel the running scan |
| `GET` | `/api/runs` | Previous runs under the report root, newest first |
| `POST` | `/api/runs/open` | Load a previous run into the dashboard |
| `GET` | `/api/trends` | Summary counters of the newest runs (up to 50) for the trend strip |
| `POST` | `/api/diff` | Compare two previous runs: `{base, target}` → `{new, resolved, changed}` |
| `GET` | `/files/<path>` | Serve an artifact of the current run folder |

Error responses use the standard HTTP status codes: `400` for invalid input,
`401` without a session, `403` without the token header or authorization,
`404` for a missing run or artifact, `409` when a scan is already running, and
`405` for a wrong method.

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

`-redact` is applied when the artifacts are written: JSON, HTML and PDF replace
every captured password with `REDACTED` while keeping the finding, its
`password_source` and the counters. The CSV export never contained the secret,
so it is identical with or without the flag, and certificate evidence is not a
secret and is kept. `-thumb-only` affects the HTML report only: cards keep the
preview image and the full-resolution data URI is dropped, so a large inventory
stays shareable as one file; the PNG files, the PDF and the JSON are unchanged.

Certificate evidence appears in the JSON `certificate` object, in the HTML
"Certificates" section and in the PDF "Certificate evidence" section (subject,
issuer, validity window, TLS version, cipher and SHA-256 fingerprint), while
the endpoint tables show the compact trust state and expiry date. The CSV
records only the `tls` flag and the `security_types` list, because it has a
fixed flat schema.

When the HTML report is written into a timestamped run folder, it also carries
a small "Recent runs" trend table: the run name, generation timestamp, an
inline SVG sparkline (red = passwordless, amber = weak passwords, scaled
against the busiest run in the set), and the numeric passwordless,
weak-password and error counts of up to the 10 sibling runs written before it,
newest first. The section is omitted entirely when the
output path is not inside a run folder or no sibling runs have a readable
report, so a single-run or offline report is unaffected.

The folder name is the local scan start time in `YYYYMMDD-HHMMSS` form (the
GUI and the baseline comparison rely on this layout). Screenshot names use the
capture timestamp in the same form, so a run folder is self-describing.

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

![HTML report](docs/screenshots/html-report.png)

*The self-contained HTML report: stat strip, captured frames with the
authentication badge, the baseline diff and the open-endpoint table.*

![PDF report cover](docs/screenshots/pdf-report.png)

*The PDF report is generated in-process; no browser or external tool is used.*

![Captured framebuffer](docs/screenshots/framebuffer-capture.png)

*A saved capture. The tool requests exactly one frame and disconnects, so the
evidence is a snapshot and never a live session.*

### JSON schema

`vncshot_report.json` is a single object:

```json
{
  "generated_at": "2026-10-26T20:53:04.512Z",
  "tool": "vncshot",
  "summary": {
    "targets": 254,
    "open": 3,
    "rfb": 2,
    "passwordless": 1,
    "weak_credentials": 1,
    "tls_services": 1,
    "self_signed_certs": 1,
    "screenshots": 2,
    "errors": 0
  },
  "results": [
    {
      "ip": "192.0.2.10",
      "port": 5900,
      "open": true,
      "rfb": true,
      "passwordless": true,
      "security_types": ["VeNCrypt"],
      "tls": true,
      "certificate": {
        "tls_version": "TLS 1.2",
        "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "subject": "CN=lab-pc",
        "issuer": "CN=lab-pc",
        "not_before": "2025-03-04T00:00:00Z",
        "not_after": "2027-03-04T00:00:00Z",
        "dns_names": ["lab-pc"],
        "sha256_fingerprint": "5C:1A:...:9F",
        "self_signed": true,
        "expired": false,
        "verified": false
      },
      "attempts": 1,
      "server_name": "lab-pc",
      "product_hint": "RealVNC",
      "screen_width": 1920,
      "screen_height": 1080,
      "screenshot": "/usr/local/vncshot/20261026-205304/screenshots/192.0.2.10_5900_20261026-205304.png",
      "duration_ms": 84,
      "timestamp": "2026-10-26T20:53:04.428Z"
    }
  ]
}
```

The summary always carries every counter, including `tls_services` and
`self_signed_certs`; `self_signed_certs` counts established TLS sessions whose
peer certificate is self-signed, not certificate failures.

Result fields:

| Field | Type | Notes |
|-------|------|-------|
| `ip`, `port` | string, int | Target endpoint |
| `open` | bool | TCP connect succeeded |
| `rfb` | bool | RFB banner parsed and session init succeeded; `true` with `error` for a partial finding |
| `passwordless` | bool | Server offered `None` (or `None` over TLS) and accepted it |
| `password` | string | Omitted unless a weak credential was accepted; sensitive; `REDACTED` with `-redact` |
| `password_source` | string | `default` (built-in list) or `word-list` |
| `auth_locked` | bool | Omitted unless the server blocked further attempts |
| `security_types` | []string | Advertised type names, omitted when empty |
| `tls` | bool | Omitted when false |
| `certificate` | object | Peer certificate evidence from an established TLS session, omitted otherwise |
| `attempts` | int | Connection attempts used, omitted when zero |
| `server_name` | string | Desktop name from `ServerInit`, omitted when empty |
| `product_hint` | string | Best-effort triage hint derived only from volunteered data (desktop name and RFB banner version), e.g. `RealVNC` or `legacy RFB 3.3 (older or embedded stack)`. Heuristic, not identification: it may be wrong or empty and is never an active probe. Omitted when unknown |
| `screen_width`, `screen_height` | int | Framebuffer geometry, omitted when unknown |
| `screenshot` | string | Absolute path of the PNG, omitted when no capture |
| `error` | string | Omitted for closed ports; present for partial failures |
| `duration_ms` | int | Probe duration in milliseconds |
| `timestamp` | string | RFC 3339 in UTC |

The `certificate` fields are `tls_version`, `cipher_suite`, `subject`, `issuer`,
`not_before`, `not_after`, `dns_names`, `sha256_fingerprint`, `self_signed`,
`expired` and `verified`; see [Security types and TLS](#security-types-and-tls)
for their meaning.

### CSV format

The CSV report is always written, uses standard CSV quoting with
comma-separated fields, and has a fixed column order:

```
ip,port,open,rfb,passwordless,weak_password,password_source,tls,security_types,server_name,screen_width,screen_height,screenshot,error,duration_ms,attempts,timestamp
```

Booleans are written as `yes` or `no`. `security_types` joins the advertised
type names with `;` so the whole list stays inside one field. `timestamp` is
RFC 3339 in UTC. Rows are sorted by IP and port, exactly like the other
artifacts. The file is written `0600` because it records which endpoints accept
a weak credential.

### SARIF output

`-sarif <path>` writes a [SARIF](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
2.1.0 JSON log, so findings can be ingested by CI dashboards, GitHub code
scanning integrations and SAST tooling. Relative paths are created inside the
run directory; the default file name is `vncshot_report.sarif`. The file is
written before the manifest, so `-manifest` covers it.

Findings are mapped to stable rule ids:

| Rule id | Level | Condition |
|---------|-------|-----------|
| `passwordless-vnc` | `error` | The endpoint accepts connections without authentication (security type `None`) |
| `weak-credentials` | `error` | The endpoint accepts a weak or word-list password |
| `tls-self-signed` | `warning` | The established TLS session presents a self-signed certificate |
| `certificate-expiring` | `warning` | The peer certificate expires within the `-cert-warn` window |

One SARIF result is emitted per finding, so an endpoint that is both
self-signed and expiring produces two results. Messages name the endpoint
(e.g. `VNC endpoint 10.0.0.5:5900 accepts connections without authentication
(security type None)`) but never the captured password itself. The
`runs[].tool.driver` block records the tool name `vncshot`, the build version
and the project URL; `rules[]` describes every referenced rule. Results are
sorted by host and port, so repeated scans produce byte-stable logs for a
given result set. A clean scan produces valid SARIF with an empty `results`
array.

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

A verification helper exists in the code (`app.VerifyManifest`) for tooling
that re-hashes a run folder and reports the first missing, extra or modified
file; it is not exposed as a CLI flag.

### Manifest signing and verification

`-sign-key <path>` signs the manifest with ed25519. The key must be a PEM
PKCS#8 private key; when the file does not exist, a key pair is generated on
the spot: the private key is written to `<path>` with mode `0600` and the
public key to `<path>.pub`, and a notice is printed. Signing happens after
the manifest is finalized, so `<run-dir>/manifest.sig` always covers the
exact `manifest.json` bytes as written — a base64-encoded ed25519 signature.

`-sign-key` requires `-manifest`, because there is otherwise no manifest to
sign. The signature file is written `0600` like every other artifact.

`-verify-manifest <run-dir>` is an offline command (like `-prune`, it exits
without scanning and does not require root): it verifies the ed25519
signature over `manifest.json` and then re-hashes every artifact listed in
it. The public key comes from `-pub-key <path>`, defaulting to
`<sign-key>.pub` when `-sign-key` is given. It reads nothing but the run
directory and the key file, so an assessor can verify a copied evidence
folder on any machine, long after the scan environment is gone. Exit is `0`
on success and `1` on any failure, with the first failing artifact named on
stderr:

```bash
sudo vncshot -target 192.168.1.0/24 -manifest -sign-key /root/vncshot-signing.pem
# hand the public key to the reviewer, who needs no root on this host:
sudo cat /root/vncshot-signing.pem.pub > vncshot-signing.pem.pub
vncshot -verify-manifest /usr/local/vncshot/20261028-120000 -pub-key vncshot-signing.pem.pub
# -> manifest signature and artifacts verified: /usr/local/vncshot/20261028-120000
```

Keep the private key on the scanning host and hand the `.pub` file to
reviewers: with it, anyone can prove that neither the manifest nor a single
artifact byte was altered after the scan.

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
below. The JSON artifact keeps the current results at the top level and adds a
`diff` object; the CSV artifact always contains the current run only. New
findings are also the trigger for the webhook.

The `diff` object carries the compared run folder name, the full results under
`new` and `resolved`, and the changed endpoints as
`{addr, reason, before, after}`. The three lists are always present as arrays
when a comparison ran — an empty list is written as `[]`, never `null` — so a
pipeline can index them without nil checks. `before` and `after` use the same
display labels as the reports: `no auth`, `weak`, `rfb`, `open` and `closed`.

```json
"diff": {
  "baseline": "20261020-090000",
  "new": [],
  "resolved": [],
  "changed": [
    { "addr": "192.0.2.10:5900", "reason": "became passwordless",
      "before": "weak", "after": "no auth" }
  ]
}
```

### Failing on findings (-fail-on)

Findings are data, not tool failures: a completed scan always exits `0` so its
reports and notifications are produced first. Pipelines that need a hard
signal can add one with `-fail-on`, a comma-separated list of finding
categories that makes the run exit with code `3` after every report has been
written:

```bash
sudo vncshot -target 192.168.1.0/24 -fail-on passwordless,new -yes
```

Accepted categories (case-insensitive, duplicates are ignored):

| Category | Matches when |
|----------|--------------|
| `passwordless` | Any result with `passwordless: true` |
| `weak` | Any result with a weak (built-in list or `-word-list`) password |
| `self-signed` | Any TLS result whose peer certificate is self-signed |
| `cert-expiring` | Any certificate expiring within the `-cert-warn` window |
| `new` | The baseline comparison reports new findings (requires `-baseline`) |
| `resolved` | The baseline comparison reports resolved findings (requires `-baseline`) |
| `changed` | The baseline comparison reports changed findings (requires `-baseline`) |

`new`, `resolved` and `changed` compare two runs, so they require `-baseline`
(or `-interval`, which diffs against the previous round automatically);
without either, the flag combination is rejected at parse time before any
packet is sent. When one or more categories match, a summary line such as

```
fail-on matched: passwordless (2 passwordless host(s)), new (3 new finding(s))
```

is printed on stderr and the process exits `3`. With `-interval` the check is
evaluated per round: the first matching round stops the loop and exits `3`.
Note that `-interval` cannot be combined with `-baseline`, so its baseline
categories rely on the automatic per-round diff.

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
               "weak_credentials": 1, "tls_services": 1, "self_signed_certs": 1,
               "screenshots": 2, "errors": 0 },
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
Endpoints approved through `-accept` (below) carry `"accepted": true` and
leave the alarm checks; results with an established TLS session also carry a
`certificates` block (`ip`, `port`, `subject_sha256`, `self_signed`,
`expired`, `expires_at`).

A delivery failure is a warning, not a failed scan: the CLI prints
`warning: webhook notification failed: ...` on stderr after the summary, the
artifacts remain intact, and the exit status still reflects the scan itself.

### Acceptance and exclusion lists

Two lists answer two different questions.

`-accept <file>` marks endpoints whose findings are known and approved. The
scan still probes them and they stay in every report, but they stop
triggering notifications and leave the baseline diff's *new findings*
section, so an accepted host does not page the operator on every run:

```
# accept.txt — ip:port [reason]; a bare IP or ip:* covers all ports
192.0.2.10:5900 reception TV, approved by operations
192.0.2.11       lab subnet, ticket #123, until:2027-06-30
[2001:db8::10]:5900 IPv6 endpoint
```

`until:YYYY-MM-DD` expires the approval: after that date the finding alarms
again (no error, the entry simply stops applying). A malformed line is a hard
error with the line number, because a silently ignored acceptance would keep
alarming.

`-exclude <file>` is a safety boundary instead: listed addresses are dropped
from the scope before any connection is attempted and never contacted at
all:

```
# exclude.txt — IP, CIDR range, or ip:port for a single endpoint
192.0.2.0/24
10.9.9.9:5900
[2001:db8::1]:5900
```

Use `-exclude` for critical production segments that must not receive even a
TCP probe, and `-accept` for findings that are real but already handled.
Both lists load with the same fail-fast contract as `-baseline`: a broken
file stops the scan before a run folder is created. A scope that is excluded
entirely is refused. `-dry-run` shows how many pairs the exclusion list
dropped.

### Certificate expiry tracking

`-cert-warn <days>` (default 30, `0` disables) flags peer certificates whose
validity ends inside the window. Flagged results carry `expires_soon`, the
summary counter `expiring_soon` counts them, HTML and PDF render an
*expires soon* badge next to the existing self-signed/expired markers, the
CSV export has the full certificate columns, and the Slack and webhook
notifications include the count. The check runs against the clock at report
time; a certificate that is already expired is reported as expired, not as
expiring.

### Continuous monitoring

`-interval <duration>` turns a scan into a recurring job without cron: the
scanner repeats the same scope forever, sleeps the given pause between
rounds (measured from round starts, so a slow round cannot drift the
cadence), and diffs every round against the previous one automatically. The
first round uses `-baseline` if given, later rounds pick the newest run
folder in the report root themselves.

```bash
sudo vncshot -file /root/scope.txt -interval 24h -keep 30 \
  -slack-url https://hooks.slack.com/services/T000/B000/XXXX \
  -cert-warn 30
```

Round 1 reports without a diff, round 2 prints the first baseline comparison,
and so on — a change feed. `-interval` rejects `-resume` (the resumed scope
is already partially complete) and `-baseline` (it would compare every round
against the same stale run).

For dashboards, `-metrics-addr 127.0.0.1:9100` serves the last round's
counters in Prometheus text exposition: `vncshot_targets`, `vncshot_open`,
`vncshot_rfb_services`, `vncshot_passwordless`, `vncshot_weak_credentials`,
`vncshot_tls_services`, `vncshot_self_signed_certs`,
`vncshot_expiring_certs`, `vncshot_accepted_findings`, `vncshot_screenshots`,
`vncshot_errors`, plus the series gauges `vncshot_scans_total`,
`vncshot_last_scan_timestamp_seconds` and
`vncshot_last_scan_duration_seconds`. The metrics have no labels on purpose:
run directories or hosts as label values would grow without bound. The
endpoint has no authentication, so bind loopback and scrape through a local
exporter; binding a non-loopback address prints a warning.

Notifications go to more channels than the webhook:

* `-slack-url <https-url>` posts a compact message (summary plus up to ten
  findings) to a Slack incoming webhook. Only `https://` is accepted,
  because the webhook URL carries a secret token.
* `-mail-server host:port -mail-from you@example.com -mail-to a@x,b@x`
  sends a plain-text mail. STARTTLS is mandatory unless `-mail-no-tls` is
  passed, and credentials are never sent without TLS even then. Set
  `-mail-user` and the `VNCSHOT_MAIL_PASSWORD` environment variable for
  AUTH PLAIN; the password is read from the environment so it never appears
  in the process list.
* `-syslog udp://collector:514` (or `tcp://`) sends ArcSight CEF events: one
  per passwordless (`VNC_PASSWORDLESS`, severity 7), weak password
  (`VNC_WEAK_PASSWORD`, severity 9) or expiring certificate
  (`VNC_CERT_EXPIRING`, severity 5) finding, plus one summary event
  (`VNC_SCAN_SUMMARY`). Accepted findings are not sent. Lines are
  RFC 3164 framed and truncated to 1024 bytes.

Every channel is independent: one receiver being down never silences the
others and never fails the scan. Failures are collected in the same
`warning:` line as the webhook and retention problems.

### Maintenance and retention

Run folders hold credentials and captured desktops, so unused history should not
accumulate on the assessment host. `-keep n` applies retention to the report
root after a successful scan: it keeps the newest n run folders (the run that
just finished included) and deletes the rest. `-prune n` does the same as a
standalone maintenance command and exits, so it can run without a target.

```bash
# keep the 30 newest runs, nightly
0 3 * * * /usr/local/bin/vncshot -prune 30 -yes >/dev/null 2>&1
```

```bash
# preview the nightly prune without deleting anything
sudo vncshot -prune 30 -prune-dry-run

# apply the policy after every scan of a range
sudo vncshot -target 10.0.0.0/24 -keep 30
```

Deletion is deliberately narrow and fails safe:

* A count of zero or less never deletes anything: `-keep 0` disables retention
  for scans, and an explicit `-prune 0` is rejected instead of being read as
  "delete everything". A negative `-keep` also disables retention, while
  `-prune` rejects any non-positive count.
* Dangerous report roots are refused: `/`, `/root`, `/home`, `/tmp`, `/usr`,
  `/var` and the current user's home directory.
* A symlinked report root is refused rather than followed.
* Only directories directly below the report root whose name parses as a run
  folder (`YYYYMMDD-HHMMSS`) are candidates. Plain files, unrelated directories
  and symlinked entries in the report root are never treated as runs, and
  linked content is not measured or counted.
* The `-resume` source directory is protected: a continued run references the
  previous run's screenshots, so that folder survives retention even when it
  is old enough to fall in the removed set.
* A retention failure is reported as `warning: retention failed: ...` and does
  not turn a completed scan into a failed one; the artifacts and exit status
  still describe the scan.

With `-prune-dry-run` the command prints `would remove` and the same per-run
listing (name, start time, file count, size) without deleting anything. After a
scan, the CLI prints `retention: removed N old run(s)` when the policy deleted
folders. In the GUI, the keep-runs count and the prune dry-run toggle apply to
scans started from the dashboard, and the dashboard shows
`Removed N old run(s)` after the pass.

## Running behind a proxy

`-proxy socks5://[user:pass@]host[:port]` routes every probe through a SOCKS5
proxy — useful when the assessment host reaches isolated segments only through
a jumphost. `socks5h://` additionally asks the proxy to resolve hostnames,
which matters when internal names are not resolvable locally. Without a port
the default 1080 applies. Credentials live in the URL userinfo only and never
appear in error messages. The SOCKS5 handshake honours the same connect
deadline as direct dials, and proxy failures are classified as connect
errors, so `-retries` keeps working.

```bash
sudo vncshot -file scope.txt -proxy socks5h://127.0.0.1:1080
```

## Self-check

`sudo vncshot -selfcheck` verifies the environment without scanning or
changing anything and exits 0 only when every check passes (warnings do not
fail): root privileges, report-root writability, the system TLS root pool,
`xdg-open` (GUI auto-open), clock sanity, loopback sockets and free disk
space (warn below 100 MiB). Use it when a scan behaves unexpectedly, or in
new deployments before the first scan.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, help printed, or `-version` printed |
| `1` | Configuration, authorization, target, I/O or report error |
| `2` | Unknown command-line flag (flag package usage error) |
| `3` | `-fail-on` matched at least one requested finding category; all reports were written first |
| `130` | Interrupted with Ctrl+C or SIGTERM; partial results were written |

A completed scan that found exposed hosts still exits `0` unless `-fail-on`
was requested: findings are data, not a tool failure. Use `-fail-on`, the
JSON summary or the webhook if a pipeline needs to fail on findings.

## Performance tuning

The defaults target a `/24` with one port in a few seconds. For other shapes:

| Situation | Adjustment |
|-----------|------------|
| Many ports per host | Lower `-workers`; per-host concurrency stays at 2 |
| Large ranges | Raise `-rate` and `-workers` together, watch loss |
| WAN or lossy links | Raise `-timeout` to `2s`–`5s`, keep `-retries 1` |
| Slow or embedded VNC servers | Raise `-vnc-timeout` to `30s` |
| Untrusted or monitored networks | Lower `-rate` (e.g. `20`) to stay unobtrusive |
| Very large word list | Trim it; each candidate is a separate connection |

Memory use is dominated by captured frames: one RGBA buffer per in-flight
capture (up to `-workers`) plus the thumbnails embedded in the HTML report.
Scanning tens of thousands of ports with `-workers 500` is possible but the
HTML report grows quickly because every capture is base64-embedded; use
`-thumb-only` to keep only the previews, `-no-pdf` and lower worker counts for
very large inventories. `-redact` does not change the size.

## Troubleshooting

**`error: root privileges required; re-run with sudo`**
Run the command through `sudo`. `-version` and `-h` are the only exceptions.

**`create report directory /usr/local/vncshot/...: permission denied`**
The compiled-in report root is not writable. Run as root, or pass an explicit
`-out-dir` you own.

**Reports are in `/root/.local/share/vncshot` instead of `/usr/local/vncshot`**
The default root was not writable and no `-out-dir` was given, so the scan fell
back to the per-user directory. The CLI prints a warning with the reason.

**`refusing to scan N host:port pairs (limit 1048576)`**
Narrow the range, split the CIDR, or reduce the port list.

**`CIDR ... is too large (… /16 or longer prefixes only …)`**
`vncshot` expands at most 65,536 hosts per CIDR spec; split a `/8` into `/16`
blocks or use `-file` with the subnets you actually own.

**A host shows `open: true`, `rfb: false`**
The TCP port answered but the service did not complete an RFB handshake. It is
reported with the protocol error in `error` so a non-VNC service on 5900 is
visible rather than silently treated as closed.

**A host shows `rfb: true` together with `error`**
The RFB banner was parsed, so the endpoint is an RFB service, but the session
could not be established. `error` carries the reason and the evidence collected
before the failure (security types, TLS capability, certificate) is kept. Check
the advertised security types: a VeNCrypt subtype this probe does not implement
(for example `X509Vnc`) is reported as posture only, without a session attempt.

**`auth_locked: true`**
The server returned `SecurityResult` status 2. Remaining candidates were
abandoned to avoid locking the account further; investigate manually.

**The GUI URL opens but the dashboard stays empty**
The token is in the URL query string; if you copied only the host and port the
cookie was never set. Reopen the full printed URL.

**`warning: webhook notification failed`**
The scan and all artifacts are intact; only the notification failed. Check DNS,
TLS trust and the receiver, then replay from the stored JSON if needed.

**`warning: retention failed: ...`**
The scan and its artifacts are intact; only the old-run cleanup failed. The
message names the refused root or the directory that could not be removed.
Common causes are a report root on a read-only mount, a symlinked root, or a
root from the refused list (`/`, `/root`, `/home`, `/tmp`, `/usr`, `/var`).
Fix the root, or run the retention again with `-prune`.

**`refusing to prune report root ...` / `report root ... does not exist`**
`-prune` only works on a report root that exists and is a real directory. Pass
the same `-out-dir` the scans used, and do not point it at a system directory.

**`screenshot directory must be inside the run folder`**
The GUI rejects a `-screenshot-dir` (or form value) outside the run folder,
because `/files/` cannot serve it. Remove the override or point it inside the
report root.

**HTML report is huge**
Every capture is embedded as base64. Use `-thumb-only` to embed only the
previews, add `-no-pdf`, and lower the worker count or split the scan into
smaller runs.

## Package layout

```
main.go        CLI flags, root check, GUI bootstrap
app/           scan session, artifact layout, baseline diff, manifest, signing, fail-on, retention, webhook
config/        flag defaults from a config file and VNCSHOT_* environment variables
gui/           embedded web UI (index.html + HTTP server)
scanner/       target expansion, worker pool, rate limiting, retry and per-host limits
vnc/           RFB 3.3/3.7/3.8 client, None-auth and weak-password auth, TLS/VeNCrypt, raw capture
screenshot/    PNG persistence
report/        Result model, JSON/HTML/PDF/CSV/SARIF exporters, certificate evidence, embedded PDF font
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
go test -race ./...    # concurrency checks
go vet ./...
gofmt -l .
go build ./...
shellcheck -S warning install.sh
```

The test suite runs entirely offline: RFB endpoints are simulated in-process,
so no VNC server or network access is required. Coverage includes the
handshake for RFB 3.3/3.7/3.8, DES authentication against an independent
implementation, passwordless and weak-password capture, lockout handling, TLS
and VeNCrypt sessions with certificate evidence and the clear-text fallback, a
wire-level assertion that no input or clipboard messages are ever sent, target
input from files and standard input, the retention guards, redaction and
thumbnail policy, the GUI API and its token/traversal guards,
CSV/manifest/baseline/webhook behaviour, and the report renderers.

CI runs on Linux (`.github/workflows/ci.yml`) for every push to `main`, every
pull request and manual dispatches. It checks `gofmt -l .`, runs `go vet ./...`,
`go build ./...` and `go test -race -count=1 ./...`, and lints `install.sh`
with shellcheck (severity warning, with `SC2034` excluded for two known
informational findings).

When adding a flag, update `README.md` **and** `README.tr.md`; both files are
kept in sync and reviewed together.

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
