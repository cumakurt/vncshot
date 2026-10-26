# vncshot

[English](README.md) | [Türkçe](README.tr.md)

VNC security inventory scanner. Discovers RFB/VNC endpoints, flags
passwordless servers and captures their current framebuffer as PNG
evidence for authorized security assessments.

```
Use only on networks you own or have explicit written permission to test.
```

## Developer

**Cuma KURT**
- Email: [cumakurt@gmail.com](mailto:cumakurt@gmail.com)
- LinkedIn: [cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/)
- GitHub: [cumakurt/vncshot](https://github.com/cumakurt/vncshot)

## Features

- Scan single IPs, CIDR blocks, IPv4 ranges, or a file of targets
- Concurrent worker pool with configurable rate limiting
- RFB 3.3 / 3.7 / 3.8 handshake and passwordless (`None`) detection
- Framebuffer capture to PNG for unauthenticated endpoints
- JSON + self-contained HTML report (base64 thumbnails, filter, modal)
- In-process PDF report export (no external tools required)
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

`install.sh` detects the operating system and package manager (apt, dnf,
yum, pacman, apk, zypper, brew), installs missing tools only when needed,
and produces a stripped **statically linked** binary. By default it also
installs the binary to `/usr/local/bin/vncshot` (using `sudo` when required)
so it can be run from any directory. Set `INSTALL_PREFIX` to install
somewhere else.

```bash
INSTALL_PREFIX="$HOME/.local/bin" ./install.sh -y
```

There are no runtime external dependencies beyond the Go toolchain used
for building.

## Usage

```bash
vncshot -target 192.168.1.0/24 -ports 5900,5901-5910
vncshot -file hosts.txt -workers 100 -rate 150 -timeout 800ms
vncshot -target 10.0.0.1-50 -pdf report.pdf
```

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Single IP, CIDR, or range (`192.168.1.1`, `192.168.1.0/24`, `192.168.1.1-50`) |
| `-file` | | File with IPs/CIDRs/ranges, one per line (`#` comments allowed) |
| `-ports` | `5900` | Port list/ranges (`5900,5901-5910`) |
| `-timeout` | `1s` | TCP connect timeout |
| `-vnc-timeout` | `15s` | Overall RFB handshake/capture budget |
| `-workers` | `150` | Concurrent scan workers |
| `-rate` | `200` | Max new connections per second (`0` = unlimited) |
| `-output` | `vncshot_report.json` | JSON report path |
| `-html` | `vncshot_report.html` | HTML report path |
| `-pdf` | `vncshot_report.pdf` | PDF report path (generated in-process) |
| `-no-pdf` | `false` | Skip PDF generation |
| `-screenshot-dir` | `screenshots` | Directory for PNG captures |
| `-shared` | `true` | Request shared RFB session (does not kick active viewers) |
| `-yes` | `false` | Skip the interactive authorization confirmation |

## Output

* `screenshots/{ip}_{port}_{timestamp}.png` — framebuffer of passwordless servers
* `vncshot_report.json` — full result set
* `vncshot_report.html` — self-contained report (embedded thumbnails, filter, modal)
* `vncshot_report.pdf` — PDF report generated in-process from scan results

## Package layout

```
main.go        CLI wiring + authorization notice
scanner/       target expansion, worker pool, rate limiting
vnc/           RFB 3.3/3.7/3.8 client, None-auth detection, raw capture
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