# Reference inventory

This document describes the project's detection answer key: a fixed set of
known-good and known-bad RFB server behaviours with committed expected
outcomes, plus an optional real-server deployment for manual checks.

The goal is to make statements such as "passwordless detection works" testable.
Every change to the scanner is checked against the same answer key instead of
against an operator's memory of what the scanner used to do.

## What is and is not measured

Measured:

- Agreement between `scanner.Run` and the committed answer key in
  `testdata/reference/expected.json` for the fixed matrix in
  `scanner/reference_test.go`.
- Passwordless detection, capture, weak-password detection and its source,
  lockout handling, TLS/VeNCrypt handling, certificate evidence, and the
  negative side (closed and non-RFB services produce no password and no
  screenshot).
- Stability of the same matrix across repeated runs (`-count=3`).

Not measured:

- Real-world prevalence or a "detection rate" in any population of hosts.
- Accuracy on server implementations outside the matrix.
- Live network scanning. The harness binds only to loopback and needs neither
  Docker nor internet access.
- Performance, throughput or rate-limiter behaviour.
- Whether a discovered password is the *only* valid credential; the key only
  records presence and source.

The printed accuracy line (`reference inventory: 14/14 cases matched (100%)`)
is simply the number of cases that agree with the committed key divided by the
size of this fixed matrix. It is not an estimate or a rounded statistic.

## Running the offline harness

From the repository root:

```sh
go test ./scanner -run TestReference -v -count=1
```

Expected output includes:

```text
=== RUN   TestReferenceInventory
    reference_test.go:...: reference inventory: 14/14 cases matched (100%)
--- PASS: TestReferenceInventory (0.0s)
PASS
```

Run it repeatedly to check determinism:

```sh
go test ./scanner -run TestReference -count=3
```

Each case starts its own loopback listener, uses one target, `Workers: 4`,
`RatePerSec: 0`, `MaxRetries: 0`, fixed generous deadlines, and screenshots in
a `t.TempDir()` directory. The test never needs Docker or external network
access.

### The case matrix

| Case | Fake-server behaviour | Expected outcome |
| --- | --- | --- |
| `plain-38` | RFB 3.8, security type None | passwordless, RFB, capture |
| `plain-37` | RFB 3.7, None with no SecurityResult | passwordless, RFB, capture |
| `plain-33` | RFB 3.3, single U32 None | passwordless, RFB, capture |
| `weak-default` | VNC auth, password in the built-in list | password, source `default`, capture |
| `weak-wordlist` | VNC auth, password only in the supplied list | password, source `word-list`, capture |
| `strong` | VNC auth, no candidate works | RFB, no password, no capture |
| `locked` | VNC auth answering SecurityResult 2 | `auth_locked`, loop stops, no capture |
| `tls18` | Security type 18 with a self-signed certificate | passwordless, TLS, self-signed, capture |
| `vencrypt-257` | VeNCrypt TLSNone, self-signed certificate | passwordless, TLS, self-signed, capture |
| `vencrypt-258` | VeNCrypt TLSVnc, password accepted | password, source `word-list`, TLS, capture |
| `client-cert` | VeNCrypt X509Vnc requiring a client certificate | RFB, note mentions client certificate, no capture |
| `ard-only` | Only type 30 (Apple Remote Desktop) is advertised | RFB, note mentions Apple Remote Desktop, no session |
| `non-rfb` | TCP accepts but answers with a non-RFB protocol | open, not RFB, error recorded, no capture |
| `closed` | Nothing listening | not open, no error text, no capture |

## How the answer key is compared

`testdata/reference/expected.json` contains:

- `schema_version`: currently `1`, checked against the constant in the test.
- `cases`: a map from case id to the expected fields (`open`, `rfb`,
  `passwordless`, password presence, `password_source`, `auth_locked`, `tls`,
  `self_signed`, note presence, optional `note_contains`, screenshot presence,
  error presence).

The test performs three checks:

1. **Drift check (both directions).** Every matrix id must exist in the key and
   every key id must exist in the matrix. A missing entry, an unknown entry, a
   duplicate id or a field difference fails before any probe runs.
2. **Result comparison.** Each `report.Result` is reduced to the same shape as
   the key (for example `password: true` means the field is non-empty, and
   `self_signed` is read from `Certificate.SelfSigned`). Every field is compared
   explicitly; a mismatch reports the case id, the field, the expected and
   actual values, and the case description.
3. **Negative assertion.** For `closed`, `non-rfb` and every case whose key says
   there is no screenshot, the test additionally asserts that no password was
   found and that the per-case screenshot directory is empty. This turns a
   false positive into a failure rather than a silently better-looking score.

A failed case prints a line such as:

```text
case "plain-37": field passwordless: expected true, got false (RFB 3.7 advertising only None without a SecurityResult)
```

### Inspecting or regenerating a mismatch

Capture the verbose output:

```sh
go test ./scanner -run '^TestReferenceInventory$' -v -count=1 2>&1 | tee /tmp/reference-inventory.log
```

The test also logs the reduced actual result for every failing case, so the
mismatch can be diagnosed without rerunning under a debugger.

If the new behaviour is intentional and correct, update the matching entry in
`testdata/reference/expected.json` and rerun the test. The drift check forces
the matrix and the key to be updated together, so the key cannot silently
describe a server that no longer exists. Do not edit the key merely to make a
regression pass.

### Adding a case

1. Add the fake server behaviour to `scanner/reference_test.go` (an
   `func(*refConn)` handler plus any small helpers it needs).
2. Add a row to `referenceMatrix` with a unique id, a description, the expected
   fields, the password candidates, and the handler.
3. Add the same id and expected fields to
   `testdata/reference/expected.json`.
4. Run `go test ./scanner -run TestReference -v -count=1` and confirm the
   accuracy line covers the new total.

## Real-server reference deployment

`deploy/reference/docker-compose.yml` holds one runnable x11vnc service and two
commented TigerVNC templates.

- `x11vnc` uses `theasp/novnc`, pinned by digest. That image runs
  `x11vnc -forever -shared` (no password) on container port 5900, published as
  `127.0.0.1:5902`. The pinned digest is linux/amd64; substitute the digest for
  your platform if needed.
- The TigerVNC services (one `-SecurityTypes None`, one
  `-SecurityTypes VncAuth -PasswordFile`) are templates on purpose: no widely
  used image with a reliably pinned tag is known to this project for that exact
  command line. Supply an image you have verified, pin it by tag and digest,
  then uncomment the service. Do not run an unverified reference just to make
  the file non-empty.

Bring it up (after filling in the TigerVNC templates if you want those cases):

```sh
# Throwaway VncAuth credential; keep it outside the repository.
mkdir -p /tmp/vncshot-reference
vncpasswd -f > /tmp/vncshot-reference/passwd
chmod 600 /tmp/vncshot-reference/passwd

docker compose -f deploy/reference/docker-compose.yml up -d
docker compose -f deploy/reference/docker-compose.yml ps
```

Point vncshot at the loopback ports:

```sh
./vncshot -target 127.0.0.1 -ports 5900,5901,5902 \
  -word-list /tmp/vncshot-reference/wordlist \
  -yes -retries 0
```

Use a word-list file that contains the same throwaway password you gave
`vncpasswd`, or set a built-in candidate such as `password` to exercise the
`default` source. Never put a real credential in the repository or the word
list.

Inspect the JSON report fields that the answer key describes:

```sh
jq '.results[] | {
  port,
  open,
  rfb,
  passwordless,
  password_source,
  tls,
  self_signed: (.certificate.self_signed // false),
  screenshot
}' <run-dir>/vncshot_report.json
```

This manual deployment is a smoke check against independent server
implementations. It is deliberately *not* compared automatically with
`testdata/reference/expected.json`: the key describes the synthetic matrix and
its ports and per-case behaviours, while the deployment's image, geometry and
credentials are operator choices. The committed key remains the authoritative
regression check and runs entirely offline.
