#!/usr/bin/env bash
#
# install.sh — dependency bootstrap and static build for vncshot.
#
# Linux only. Detects the host distribution and package manager, installs
# any missing toolchain pieces exactly once (existing installs are reused),
# then produces a stripped static Linux binary.
#
# Usage:
#   ./install.sh              interactive install + build + system-wide install
#   ./install.sh -y           non-interactive
#   ./install.sh --build-only skip dependency installation
#   ./install.sh --no-install-bin
#                             build only, do not install into the binary prefix
#   ./install.sh --uninstall remove the installed binary (reports are kept)
#   ./install.sh --uninstall --purge-reports
#                             also delete the report directory and its reports
#   ./install.sh --systemd [calendar]
#                             install the systemd units and enable the timer
#   ./install.sh --systemd-uninstall
#                             remove the systemd units (scan.conf is kept)
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------

if [[ -t 1 && "${NO_COLOR:-}" == "" && "${TERM:-dumb}" != "dumb" ]]; then
  C_RESET=$'\033[0m'
  C_BOLD=$'\033[1m'
  C_DIM=$'\033[2m'
  C_RED=$'\033[31m'
  C_GREEN=$'\033[32m'
  C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'
  C_MAGENTA=$'\033[35m'
  C_CYAN=$'\033[36m'
  C_WHITE=$'\033[37m'
  C_BG_BLUE=$'\033[44m'
else
  C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW=""
  C_BLUE="" C_MAGENTA="" C_CYAN="" C_WHITE="" C_BG_BLUE=""
fi

readonly RULE="────────────────────────────────────────────────────────────────"

step()    { printf "\n  ${C_BOLD}${C_BLUE}[%s/%s]${C_RESET} ${C_BOLD}%s${C_RESET}\n" "$1" "$2" "$3"; }
detail()  { printf "      ${C_DIM}%s${C_RESET}\n" "$*"; }
ok()      { printf "      ${C_GREEN}✓${C_RESET} %s\n" "$*"; }
warn()    { printf "      ${C_YELLOW}!${C_RESET} %s\n" "$*"; }
err()     { printf "      ${C_RED}✗${C_RESET} %s\n" "$*" >&2; }
fail()    { err "$*"; exit 1; }

banner() {
  printf "\n"
  printf "  ${C_BG_BLUE}${C_WHITE}${C_BOLD}  vncshot  ${C_RESET}  ${C_DIM}security inventory toolkit${C_RESET}\n"
  printf "  ${C_CYAN}%s${C_RESET}\n" "$RULE"
  printf "  ${C_DIM}Cuma KURT  ·  cumakurt@gmail.com  ·  github.com/cumakurt/vncshot${C_RESET}\n"
}

kv() {
  local label="$1" value="$2"
  printf "    ${C_DIM}%-12s${C_RESET} %s\n" "$label" "$value"
}

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

ASSUME_YES=0
BUILD_ONLY=0
INSTALL_BIN=1
UNINSTALL=0
PURGE_REPORTS=0
SYSTEMD=0
SYSTEMD_CALENDAR=""
SYSTEMD_UNINSTALL=0
SYSTEMD_DONE=0
SYSTEMD_CALENDAR_USED=""

usage() {
  cat <<EOF
Usage: ./install.sh [options]

Builds vncshot on Linux, installs the binary into /usr/local/bin and
creates the /usr/local/vncshot report directory so scans can be run from
any directory. vncshot supports Linux only.

Options:
  -y, --yes          non-interactive; assume yes on prompts
  --build-only       skip dependency installation, just compile
  --no-install-bin   build only; do not install binary or report directory
  --install-bin      keep the binary install step (default; accepted for compatibility)
  --uninstall        remove the installed binary; report directories are kept
  --purge-reports    together with --uninstall: also delete REPORT_DIR and the
                     reports inside it (asks for confirmation unless -y is set)
  --systemd [cal]    additionally install vncshot.service/vncshot.timer and
                     enable the timer; cal is an OnCalendar expression
                     (default: daily at 03:30); requires root
  --systemd-uninstall
                     stop/disable vncshot.timer and remove the systemd units;
                     /etc/vncshot/scan.conf is kept unless it is empty
  -h, --help         show this help

Environment:
  GO_VERSION         preferred Go release (default: 1.22 or newer required)
  INSTALL_PREFIX     binary install prefix (default: /usr/local/bin)
  REPORT_DIR         root for timestamped report folders (default: /usr/local/vncshot)
  SYSTEMD_UNIT_DIR   systemd unit directory (default: /etc/systemd/system)
  VNCSHOT_CONF_DIR   directory holding scan.conf (default: /etc/vncshot)
  NO_COLOR           disable coloured output
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)        ASSUME_YES=1 ;;
    --build-only)    BUILD_ONLY=1 ;;
    --install-bin)   INSTALL_BIN=1 ;;
    --no-install-bin) INSTALL_BIN=0 ;;
    --uninstall)     UNINSTALL=1 ;;
    --purge-reports) PURGE_REPORTS=1 ;;
    --systemd)
      SYSTEMD=1
      # The optional calendar argument is only consumed when present and not
      # another option, so "--systemd --uninstall" still parses correctly.
      if [[ $# -ge 2 && "$2" != -* ]]; then
        SYSTEMD_CALENDAR="$2"
        shift
      fi
      ;;
    --systemd-uninstall) SYSTEMD_UNINSTALL=1 ;;
    -h|--help)       usage; exit 0 ;;
    *)               printf 'unknown option: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
  shift
done

# Flag combinations that make no sense together are rejected before any work.
if [[ "$PURGE_REPORTS" -eq 1 && "$UNINSTALL" -eq 0 ]]; then
  printf '%s\n' '--purge-reports requires --uninstall' >&2
  usage
  exit 1
fi
if [[ "$UNINSTALL" -eq 1 ]]; then
  if [[ "$BUILD_ONLY" -eq 1 ]]; then
    printf '%s\n' '--uninstall cannot be combined with --build-only' >&2
    usage
    exit 1
  fi
  if [[ "$INSTALL_BIN" -eq 0 ]]; then
    printf '%s\n' '--uninstall cannot be combined with --no-install-bin' >&2
    usage
    exit 1
  fi
fi

if [[ "$SYSTEMD" -eq 1 ]]; then
  if [[ "$UNINSTALL" -eq 1 || "$SYSTEMD_UNINSTALL" -eq 1 ]]; then
    printf '%s\n' '--systemd cannot be combined with --uninstall or --systemd-uninstall' >&2
    usage
    exit 1
  fi
  if [[ "$BUILD_ONLY" -eq 1 ]]; then
    printf '%s\n' '--systemd cannot be combined with --build-only' >&2
    usage
    exit 1
  fi
  # The timer unit points at the installed binary, so the install step must run.
  if [[ "$INSTALL_BIN" -eq 0 ]]; then
    printf '%s\n' '--systemd cannot be combined with --no-install-bin' >&2
    usage
    exit 1
  fi
fi

if [[ "$SYSTEMD_UNINSTALL" -eq 1 ]]; then
  if [[ "$BUILD_ONLY" -eq 1 ]]; then
    printf '%s\n' '--systemd-uninstall cannot be combined with --build-only' >&2
    usage
    exit 1
  fi
  if [[ "$INSTALL_BIN" -eq 0 ]]; then
    printf '%s\n' '--systemd-uninstall cannot be combined with --no-install-bin' >&2
    usage
    exit 1
  fi
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CACHE_DIR="${XDG_CACHE_HOME:-$HOME/.cache}/vncshot-install"
GO_MIN_VERSION="1.22"

OS_NAME=""
OS_ARCH=""
PKG_MGR=""
PKG_INSTALL=""
GO_BIN=""
GO_VERSION_STR=""
BINARY_PATH="$SCRIPT_DIR/vncshot"
BINARY_SIZE=""
REPORT_DIR="${REPORT_DIR:-/usr/local/vncshot}"
# Systemd integration paths. Overridable so staged (packaging) installs and
# dry runs can redirect the generated files, mirroring INSTALL_PREFIX/REPORT_DIR.
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
VNCSHOT_CONF_DIR="${VNCSHOT_CONF_DIR:-/etc/vncshot}"
SYSTEMD_SERVICE_NAME="vncshot.service"
SYSTEMD_TIMER_NAME="vncshot.timer"
DEFAULT_SYSTEMD_CALENDAR="*-*-* 03:30:00"
DEPS_INSTALLED=()
DEPS_PRESENT=()

# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------

detect_os() {
  OS_ARCH="$(uname -m)"
  OS_NAME="Linux"

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_NAME="Linux (${ID:-unknown})"
  fi
}

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    PKG_MGR="apt"; PKG_INSTALL="apt-get install -y"
  elif command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"; PKG_INSTALL="dnf install -y"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"; PKG_INSTALL="yum install -y"
  elif command -v pacman >/dev/null 2>&1; then
    PKG_MGR="pacman"; PKG_INSTALL="pacman -S --noconfirm --needed"
  elif command -v apk >/dev/null 2>&1; then
    PKG_MGR="apk"; PKG_INSTALL="apk add --no-cache"
  elif command -v zypper >/dev/null 2>&1; then
    PKG_MGR="zypper"; PKG_INSTALL="zypper --non-interactive install"
  else
    PKG_MGR=""
  fi
}

run_pkg() {
  if [[ "$PKG_MGR" == "apt" ]]; then
    if [[ "$(id -u)" -eq 0 ]]; then
      apt-get update -qq >/dev/null 2>&1 || true
      $PKG_INSTALL "$@" >/dev/null 2>&1
    else
      sudo apt-get update -qq >/dev/null 2>&1 || true
      sudo $PKG_INSTALL "$@" >/dev/null 2>&1
    fi
  elif [[ "$(id -u)" -eq 0 ]]; then
    $PKG_INSTALL "$@" >/dev/null 2>&1
  else
    sudo $PKG_INSTALL "$@" >/dev/null 2>&1
  fi
}

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

version_ge() {
  # Compare dotted versions: returns 0 when $1 >= $2.
  [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

check_go() {
  local candidate=""
  if have_cmd go; then
    candidate="$(command -v go)"
  elif [[ -x /usr/local/go/bin/go ]]; then
    candidate="/usr/local/go/bin/go"
  elif [[ -x "$HOME/go/bin/go" ]]; then
    candidate="$HOME/go/bin/go"
  elif [[ -x "$HOME/.local/go/bin/go" ]]; then
    candidate="$HOME/.local/go/bin/go"
  fi

  if [[ -n "$candidate" ]]; then
    GO_VERSION_STR="$("$candidate" env GOVERSION 2>/dev/null | sed 's/^go//')"
    if [[ -n "$GO_VERSION_STR" ]] && version_ge "$GO_VERSION_STR" "$GO_MIN_VERSION"; then
      GO_BIN="$candidate"
      return 0
    fi
    warn "found go${GO_VERSION_STR:-unknown} at $candidate (need >= ${GO_MIN_VERSION})"
    return 1
  fi
  return 1
}

install_go_from_tarball() {
  local ver="${GO_VERSION:-1.22.10}"
  local arch_tar
  case "$(uname -m)" in
    x86_64)          arch_tar="amd64" ;;
    aarch64|arm64)   arch_tar="arm64" ;;
    armv7l)          arch_tar="armv6l" ;;
    *)               fail "unsupported architecture for Go tarball: $(uname -m) (supported: x86_64, aarch64/arm64, armv7l)" ;;
  esac

  local tarball="go${ver}.linux-${arch_tar}.tar.gz"
  local url="https://go.dev/dl/${tarball}"
  local dest="$CACHE_DIR/$tarball"
  local prefix="$HOME/.local/go"

  mkdir -p "$CACHE_DIR"

  if [[ -x "$prefix/bin/go" ]]; then
    GO_BIN="$prefix/bin/go"
    GO_VERSION_STR="$("$GO_BIN" env GOVERSION 2>/dev/null | sed 's/^go//')"
    if [[ -n "$GO_VERSION_STR" ]] && version_ge "$GO_VERSION_STR" "$GO_MIN_VERSION"; then
      detail "reusing Go ${GO_VERSION_STR} already installed in $prefix"
      return 0
    fi
  fi

  if [[ ! -f "$dest" ]]; then
    detail "downloading ${tarball}"
    if have_cmd curl; then
      curl -fsSL --retry 3 -o "$dest.partial" "$url" && mv "$dest.partial" "$dest"
    elif have_cmd wget; then
      wget -q -O "$dest.partial" "$url" && mv "$dest.partial" "$dest"
    else
      fail "neither curl nor wget is available to download Go"
    fi
  else
    detail "reusing cached $tarball"
  fi

  rm -rf "$prefix"
  mkdir -p "$prefix"
  tar -C "$prefix" --strip-components=1 -xzf "$dest"
  GO_BIN="$prefix/bin/go"
  GO_VERSION_STR="$("$GO_BIN" env GOVERSION | sed 's/^go//')"
}

ensure_go() {
  if check_go; then
    ok "Go ${GO_VERSION_STR} at $GO_BIN (satisfied)"
    DEPS_PRESENT+=("Go ${GO_VERSION_STR}")
    return
  fi

  if [[ "$BUILD_ONLY" -eq 1 ]]; then
    fail "Go >= ${GO_MIN_VERSION} is required and --build-only was requested"
  fi

  if [[ -n "$PKG_MGR" ]]; then
    local pkg_name="go"
    if [[ "$PKG_MGR" == "apt" ]]; then pkg_name="golang-go"; fi
    detail "installing Go via $PKG_MGR ($pkg_name)"
    if run_pkg "$pkg_name"; then
      if check_go; then
        ok "Go ${GO_VERSION_STR} installed via $PKG_MGR"
        DEPS_INSTALLED+=("Go ${GO_VERSION_STR} (via $PKG_MGR)")
        return
      fi
      warn "package manager Go did not meet version requirement; falling back to official tarball"
    else
      warn "$PKG_MGR install failed; falling back to official tarball"
    fi
  fi

  install_go_from_tarball
  ok "Go ${GO_VERSION_STR} installed to $HOME/.local/go (official tarball)"
  DEPS_INSTALLED+=("Go ${GO_VERSION_STR} (official tarball)")
  export PATH="$HOME/.local/go/bin:$HOME/go/bin:$PATH"
}

ensure_build_essentials() {
  # Go needs a C toolchain only for cgo; the build below is static with
  # CGO_ENABLED=0, so we only need basic shell utilities and tar/curl.
  local missing=()
  have_cmd tar  || missing+=("tar")
  have_cmd curl || have_cmd wget || missing+=("curl")
  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "archive/download tools present"
    DEPS_PRESENT+=("tar/curl")
    return
  fi
  if [[ "$BUILD_ONLY" -eq 1 || -z "$PKG_MGR" ]]; then
    warn "missing tools: ${missing[*]} (continuing anyway)"
    return
  fi
  detail "installing ${missing[*]} via $PKG_MGR"
  if run_pkg "${missing[@]}"; then
    ok "installed ${missing[*]}"
    DEPS_INSTALLED+=("${missing[*]}")
  else
    warn "could not install ${missing[*]} — build may fail"
  fi
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

human_size() {
  local bytes="$1"
  if   (( bytes >= 1048576 )); then printf '%d.%d MB' "$((bytes / 1048576))" "$(( (bytes % 1048576) * 10 / 1048576 ))"
  elif (( bytes >= 1024 ));    then printf '%d KB' "$((bytes / 1024))"
  else                              printf '%d B' "$bytes"
  fi
}

build_static() {
  # The values are single-quoted inside the ldflags string: without quoting,
  # a path containing a space splits the -X assignment and `go build` fails
  # with a linker usage dump. Values must not contain a single quote.
  # The commit and build time make -version identify an exact build.
  local commit build_date
  commit="$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local ldflags="-s -w -X 'main.version=${VERSION:-dev}' -X 'main.commit=${commit}' -X 'main.buildDate=${build_date}' -X 'main.reportBaseDir=${REPORT_DIR}'"
  # CGO off + explicit GOOS + -trimpath yields a portable static Linux binary.
  if ! CGO_ENABLED=0 GOOS=linux "$GO_BIN" build \
      -trimpath \
      -ldflags "$ldflags" \
      -o "$BINARY_PATH" . ; then
    fail "go build failed"
  fi

  if have_cmd file && file "$BINARY_PATH" | grep -qi 'statically linked\|static-pie'; then
    :
  fi

  local sz
  sz="$(wc -c < "$BINARY_PATH" | tr -d ' ')"
  BINARY_SIZE="$(human_size "$sz")"

  if have_cmd ldd >/dev/null 2>&1; then
    if ldd "$BINARY_PATH" >/dev/null 2>&1; then
      warn "binary links dynamic libraries; static build not fully achieved"
    else
      ok "statically linked binary produced"
    fi
  else
    ok "binary produced"
  fi
  ok "built $BINARY_PATH (${BINARY_SIZE})"
}

INSTALLED_BINARY=""
INSTALLED_ON_PATH=0

# run_privileged runs a command as root directly when possible, otherwise
# through sudo. Returns non-zero when no privileged path is available.
run_privileged() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif have_cmd sudo && [[ -t 0 ]]; then
    sudo "$@"
  elif have_cmd sudo && sudo -n true >/dev/null 2>&1; then
    sudo -n "$@"
  else
    return 1
  fi
}

install_binary() {
  local prefix="${INSTALL_PREFIX:-/usr/local/bin}"
  local target="$prefix/vncshot"

  # Try the unprivileged path first and let the OS decide: probing only the
  # immediate parent wrongly rejects nested prefixes such as
  # /opt/tools/bin/vnc when /opt/tools does not exist yet but is writable.
  if mkdir -p "$prefix" 2>/dev/null && install -m 0755 "$BINARY_PATH" "$target" 2>/dev/null; then
    :
  elif run_privileged mkdir -p "$prefix" && run_privileged install -m 0755 "$BINARY_PATH" "$target"; then
    detail "installed with elevated permissions"
  else
    err "cannot write $target (no write access; sudo is unavailable or needs a password)"
    detail "re-run with sudo or set INSTALL_PREFIX to a writable directory"
    return 1
  fi

  if [[ ! -x "$target" ]]; then
    err "installation verification failed: $target is not executable"
    return 1
  fi

  INSTALLED_BINARY="$target"
  ok "installed $target"
  if printf '%s' ":$PATH:" | grep -q ":$prefix:"; then
    INSTALLED_ON_PATH=1
  else
    warn "$prefix is not on PATH; add it to your shell profile to run vncshot directly"
  fi
}

prepare_report_dir() {
  if [[ -d "$REPORT_DIR" ]]; then
    ok "report directory $REPORT_DIR"
    return 0
  fi
  # Attempt the unprivileged path first so a multi-level REPORT_DIR under a
  # writable ancestor works without sudo; only then fall back to privilege.
  if mkdir -p "$REPORT_DIR" 2>/dev/null; then
    chmod 0755 "$REPORT_DIR" 2>/dev/null || true
    ok "created report directory $REPORT_DIR"
    return 0
  fi
  if run_privileged mkdir -p "$REPORT_DIR" && run_privileged chmod 0755 "$REPORT_DIR"; then
    ok "created report directory $REPORT_DIR"
    return 0
  fi
  err "cannot create $REPORT_DIR (no write access; sudo is unavailable or needs a password)"
  detail "re-run with sudo or set REPORT_DIR to a writable directory"
  return 1
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------

# do_uninstall removes the installed binary using the same prefix logic as
# install_binary. Report directories are kept by default because reports
# contain scan evidence; --purge-reports opts into deleting them. The
# systemd units are removed as well so nothing schedules a binary that is
# about to disappear.
do_uninstall() {
  local prefix="${INSTALL_PREFIX:-/usr/local/bin}"
  local target="$prefix/vncshot"

  # Units first: failure here must never abort the binary removal below.
  remove_systemd_units

  if [[ ! -e "$target" && ! -L "$target" ]]; then
    ok "already uninstalled: no binary at $target"
  elif [[ ! -f "$target" && ! -L "$target" ]]; then
    fail "refusing to remove $target: not a regular file"
  else
    # Try the unprivileged removal first (user-writable prefixes such as
    # ~/.local/bin need no sudo), then fall back to privilege.
    if rm -f -- "$target" 2>/dev/null || run_privileged rm -f -- "$target"; then
      ok "removed $target"
    else
      fail "cannot remove $target (no write access; sudo is unavailable or needs a password)"
    fi
  fi

  if [[ "$PURGE_REPORTS" -eq 1 ]]; then
    purge_report_dir || exit 1
  else
    ok "reports preserved: $REPORT_DIR kept (reports contain scan evidence)"
  fi
}

# purge_report_dir deletes REPORT_DIR itself, including every report inside
# it. Reports hold scan evidence, so this is opt-in and guarded: dangerous
# paths are rejected, and deletion needs interactive confirmation unless -y
# was given (or stdin is not a terminal, in which case the purge is refused).
purge_report_dir() {
  local dir="$REPORT_DIR"

  if [[ -z "$dir" ]]; then
    err "REPORT_DIR is empty; refusing to purge an unknown directory"
    return 1
  fi

  # Compare against dangerous targets without trailing slashes so "///" and
  # "$HOME/" are judged the same as "/" and "$HOME".
  local norm="$dir"
  while [[ "$norm" == */ && "$norm" != "/" ]]; do
    norm="${norm%/}"
  done

  if [[ -z "$norm" || "$norm" == "/" ]]; then
    err "refusing to purge REPORT_DIR=$dir: the filesystem root is not a valid target"
    return 1
  fi
  if [[ -n "$HOME" && "$norm" == "$HOME" ]]; then
    err "refusing to purge REPORT_DIR=$dir: it equals the home directory"
    return 1
  fi

  if [[ ! -d "$dir" ]]; then
    ok "no report directory at $dir; nothing to purge"
    return 0
  fi

  warn "this permanently deletes EVERY report under $dir — scan evidence cannot be recovered"

  if [[ "$ASSUME_YES" -ne 1 ]]; then
    if ! [[ -t 0 ]]; then
      err "purging reports needs confirmation, but stdin is not a terminal"
      detail "re-run interactively, or pass -y to confirm non-interactively"
      return 1
    fi
    local answer=""
    read -r answer || answer=""
    if [[ "$answer" != "yes" ]]; then
      warn "confirmation not received; reports kept and nothing deleted"
      return 1
    fi
  fi

  # Try the unprivileged removal first, then fall back to privilege.
  if rm -rf -- "$dir" 2>/dev/null || run_privileged rm -rf -- "$dir"; then
    ok "removed report directory $dir and all reports inside it"
  else
    err "failed to remove $dir (no write access; sudo is unavailable or needs a password)"
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Systemd
# ---------------------------------------------------------------------------

# check_systemd_requirements refuses the systemd setup on hosts where it
# cannot succeed: systemctl needs root to talk to PID 1, and without it the
# generated units would never be scheduled.
check_systemd_requirements() {
  if [[ "$(id -u)" -ne 0 ]]; then
    err "--systemd must run as root (systemctl enable needs root)"
    detail "re-run with sudo"
    return 1
  fi
  if ! have_cmd systemctl; then
    err "systemctl was not found; systemd is not available on this host"
    return 1
  fi
  return 0
}

# validate_calendar rejects a malformed OnCalendar expression up front when
# systemd-analyze is present; otherwise the error would only surface when the
# timer is (re)started. Without systemd-analyze the expression is passed
# through and systemd itself reports the problem.
validate_calendar() {
  local calendar="$1"
  if ! have_cmd systemd-analyze; then
    return 0
  fi
  if ! systemd-analyze calendar "$calendar" >/dev/null 2>&1; then
    err "invalid OnCalendar expression: $calendar"
    detail "examples: '*-*-* 03:30:00', 'Mon..Fri 04:00:00', 'daily'"
    return 1
  fi
  return 0
}

# write_scan_conf creates the environment-file style config the service unit
# loads with EnvironmentFile=. A non-empty file is operator data and is never
# overwritten; an empty one is regenerated.
write_scan_conf() {
  local conf="$VNCSHOT_CONF_DIR/scan.conf"

  if [[ -s "$conf" ]]; then
    ok "keeping existing $conf"
    return 0
  fi

  mkdir -p "$VNCSHOT_CONF_DIR"
  # VNCSHOT_ARGS must reach the file verbatim, so it is escaped below;
  # every other VNCSHOT_* name is a literal example.
  cat >"$conf" <<EOF
# $conf — environment file loaded by $SYSTEMD_SERVICE_NAME.
#
# Every VNCSHOT_* variable maps to a vncshot flag: the flag name in
# upper case with dashes replaced by underscores (-target -> VNCSHOT_TARGET).
# See the README section "Configuration and precedence" for the full list.
# Commented and empty values are ignored.

# Targets: single IP, CIDR block, IPv4 range, or a file of targets.
#VNCSHOT_TARGET=192.168.1.0/24

# Ports to probe (list/ranges; the tool default is 5900).
#VNCSHOT_PORTS=5900,5901-5910

# Extra password candidates, one per line.
#VNCSHOT_WORD_LIST=/etc/vncshot/wordlist.txt

# Extra command-line arguments passed through by the unit (word-split on
# spaces, e.g. -json -manifest).
#VNCSHOT_ARGS=

# The timer runs unattended, so the unit passes -yes and skips the
# interactive authorization confirmation. Make sure the configured targets
# are authorized before enabling the timer.
EOF
  chmod 0644 "$conf"
  ok "wrote $conf"
}

# write_systemd_units (re)writes the oneshot service and the timer. Running
# the setup again simply overwrites the units, which keeps the operation
# idempotent.
write_systemd_units() {
  local calendar="$1"
  local bin="$INSTALLED_BINARY"
  local service="$SYSTEMD_UNIT_DIR/$SYSTEMD_SERVICE_NAME"
  local timer="$SYSTEMD_UNIT_DIR/$SYSTEMD_TIMER_NAME"

  mkdir -p "$SYSTEMD_UNIT_DIR"

  # \$VNCSHOT_ARGS must stay literal: systemd expands it into extra
  # ExecStart arguments (word-split on whitespace), not the shell here.
  cat >"$service" <<EOF
[Unit]
Description=vncshot VNC security inventory scan
Documentation=https://github.com/cumakurt/vncshot
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=$VNCSHOT_CONF_DIR/scan.conf
# -yes skips the interactive authorization confirmation; scheduled runs are
# unattended by definition.
ExecStart=$bin -yes \$VNCSHOT_ARGS
EOF

  cat >"$timer" <<EOF
[Unit]
Description=Run $SYSTEMD_SERVICE_NAME on a schedule

[Timer]
OnCalendar=$calendar
Persistent=true
Unit=$SYSTEMD_SERVICE_NAME

[Install]
WantedBy=timers.target
EOF
  chmod 0644 "$service" "$timer"
  ok "wrote $service"
  ok "wrote $timer"
}

# install_systemd writes the config and the units, then enables the timer.
# A failing systemctl call only warns: the units are in place and the
# operator can enable the timer manually.
install_systemd() {
  check_systemd_requirements || return 1

  local calendar="${SYSTEMD_CALENDAR:-$DEFAULT_SYSTEMD_CALENDAR}"
  validate_calendar "$calendar" || return 1

  write_scan_conf || return 1
  write_systemd_units "$calendar" || return 1

  SYSTEMD_DONE=1
  SYSTEMD_CALENDAR_USED="$calendar"

  detail "running systemctl daemon-reload"
  if ! systemctl daemon-reload; then
    warn "systemctl daemon-reload failed; run it manually before using the timer"
  fi

  detail "enabling $SYSTEMD_TIMER_NAME (OnCalendar=$calendar)"
  if systemctl enable --now "$SYSTEMD_TIMER_NAME"; then
    ok "$SYSTEMD_TIMER_NAME enabled (next run: systemctl list-timers $SYSTEMD_TIMER_NAME)"
  else
    warn "systemctl enable --now $SYSTEMD_TIMER_NAME failed; check 'systemctl status $SYSTEMD_TIMER_NAME'"
  fi

  detail "next steps: review $VNCSHOT_CONF_DIR/scan.conf, then: systemctl restart $SYSTEMD_TIMER_NAME"
}

# remove_systemd_units stops and disables the timer and deletes the generated
# unit files. It backs --systemd-uninstall and also runs during --uninstall,
# so a removed binary is never scheduled again. Removal is deliberately
# tolerant: a missing systemctl or a failing call only warns, because the
# file removal still leaves the host clean. scan.conf holds operator
# configuration and is kept unless it is empty.
remove_systemd_units() {
  local service="$SYSTEMD_UNIT_DIR/$SYSTEMD_SERVICE_NAME"
  local timer="$SYSTEMD_UNIT_DIR/$SYSTEMD_TIMER_NAME"
  local conf="$VNCSHOT_CONF_DIR/scan.conf"
  local removed=0

  if have_cmd systemctl && [[ -e "$timer" ]]; then
    detail "stopping and disabling $SYSTEMD_TIMER_NAME"
    if ! run_privileged systemctl disable --now "$SYSTEMD_TIMER_NAME"; then
      warn "could not stop/disable $SYSTEMD_TIMER_NAME via systemctl (continuing)"
    fi
  fi

  if [[ ! -e "$service" && ! -e "$timer" ]]; then
    ok "no systemd units found in $SYSTEMD_UNIT_DIR"
  fi

  local unit
  for unit in "$timer" "$service"; do
    [[ -e "$unit" ]] || continue
    if rm -f -- "$unit" 2>/dev/null || run_privileged rm -f -- "$unit"; then
      ok "removed $unit"
      removed=1
    else
      warn "cannot remove $unit (no write access; sudo is unavailable or needs a password)"
    fi
  done

  if [[ "$removed" -eq 1 ]] && have_cmd systemctl; then
    run_privileged systemctl daemon-reload \
      || warn "systemctl daemon-reload failed; run it manually to refresh unit state"
  fi

  if [[ ! -e "$conf" ]]; then
    ok "no scan.conf at $conf"
  elif [[ -s "$conf" ]]; then
    ok "kept $conf (operator configuration; delete it manually if unwanted)"
  else
    if rm -f -- "$conf" 2>/dev/null || run_privileged rm -f -- "$conf"; then
      rmdir "$VNCSHOT_CONF_DIR" 2>/dev/null || true
      ok "removed empty $conf"
    else
      warn "cannot remove empty $conf (no write access; sudo is unavailable or needs a password)"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  local status="${1:-success}"
  local color="$C_GREEN"
  [[ "$status" != "success" ]] && color="$C_YELLOW"

  printf "\n"
  if [[ "$status" == "success" ]]; then
    printf "  ${color}${C_BOLD}Installation complete${C_RESET}\n"
  else
    printf "  ${color}${C_BOLD}Installation %s${C_RESET}\n" "$(echo "$status" | tr '[:lower:]' '[:upper:]')"
  fi

  kv "Binary"    "${INSTALLED_BINARY:-$BINARY_PATH}"
  kv "Reports"   "$REPORT_DIR"
  if [[ "$SYSTEMD_DONE" -eq 1 ]]; then
    kv "Timer"   "$SYSTEMD_TIMER_NAME (OnCalendar=$SYSTEMD_CALENDAR_USED)"
  fi
  kv "Size"      "${BINARY_SIZE:-n/a}"
  kv "Go"        "${GO_VERSION_STR:-not found}"
  kv "OS"        "$OS_NAME / $OS_ARCH"
  if [[ ${#DEPS_INSTALLED[@]} -gt 0 ]]; then
    local list
    list="$(printf '%s, ' "${DEPS_INSTALLED[@]}")"
    kv "Installed" "${list%, }"
  fi
  if [[ ${#DEPS_PRESENT[@]} -gt 0 ]]; then
    local present
    present="$(printf '%s, ' "${DEPS_PRESENT[@]}")"
    kv "Reused"    "${present%, }"
  fi

  printf "\n"
  if [[ -n "$INSTALLED_BINARY" && "$INSTALLED_ON_PATH" -eq 1 ]]; then
    printf "  ${C_DIM}Run:${C_RESET} ${C_BOLD}sudo vncshot -target 192.168.1.0/24${C_RESET}\n"
  elif [[ -n "$INSTALLED_BINARY" ]]; then
    printf "  ${C_DIM}Run:${C_RESET} ${C_BOLD}sudo %s -target 192.168.1.0/24${C_RESET}\n" "$INSTALLED_BINARY"
  else
    printf "  ${C_DIM}Run:${C_RESET} ${C_BOLD}sudo ./vncshot -target 192.168.1.0/24${C_RESET}\n"
  fi
  printf "  ${C_DIM}vncshot requires root privileges for raw RFB probing.${C_RESET}\n"
  if [[ "$SYSTEMD_DONE" -eq 1 ]]; then
    printf "  ${C_DIM}Schedule:${C_RESET} ${C_BOLD}edit %s/scan.conf, then: systemctl restart %s${C_RESET}\n" "$VNCSHOT_CONF_DIR" "$SYSTEMD_TIMER_NAME"
  fi
  printf "  ${C_DIM}%s${C_RESET}\n" "$RULE"
  printf "  ${C_DIM}Developer: Cuma KURT  ·  cumakurt@gmail.com${C_RESET}\n"
  printf "  ${C_DIM}github.com/cumakurt/vncshot  ·  linkedin.com/in/cuma-kurt-34414917${C_RESET}\n\n"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  banner

  if [[ "$(uname -s)" != "Linux" ]]; then
    err "unsupported operating system: $(uname -s) (vncshot supports Linux only)"
    exit 1
  fi

  # Fail before the build when the systemd setup could never succeed; a full
  # compile must not be paid for an operation that is refused anyway.
  if [[ "$SYSTEMD" -eq 1 ]]; then
    check_systemd_requirements || exit 1
  fi

  if [[ "$UNINSTALL" -eq 1 ]]; then
    do_uninstall
    return
  fi

  if [[ "$SYSTEMD_UNINSTALL" -eq 1 ]]; then
    remove_systemd_units
    return
  fi

  local total=3
  if [[ "$INSTALL_BIN" -eq 1 ]]; then
    total=5
  fi
  # --systemd always ships with the binary install step, so it can only
  # extend the five-step flow.
  if [[ "$SYSTEMD" -eq 1 ]]; then
    total=6
  fi

  step 1 "$total" "Detecting operating system"
  detect_os
  detect_package_manager
  ok "$OS_NAME / $OS_ARCH"
  detail "package manager: ${PKG_MGR:-none detected}"

  if [[ "$BUILD_ONLY" -eq 0 ]]; then
    step 2 "$total" "Checking build prerequisites"
    ensure_build_essentials
    ensure_go
  else
    step 2 "$total" "Checking Go toolchain"
    ensure_go
  fi

  step 3 "$total" "Building static binary"

  if [[ -z "$GO_BIN" ]]; then
    print_summary "failed"
    fail "no usable Go toolchain"
  fi

  # Make sure module downloads are quiet unless they fail.
  if ! "$GO_BIN" mod download >/dev/null 2>&1; then
    warn "go mod download reported issues; retrying verbosely"
    "$GO_BIN" mod tidy
  fi

  build_static

  if [[ "$INSTALL_BIN" -eq 1 ]]; then
    step 4 "$total" "Installing binary"
    install_binary || fail "binary installation failed"

    step 5 "$total" "Preparing report directory"
    prepare_report_dir || fail "report directory setup failed"
  fi

  if [[ "$SYSTEMD" -eq 1 ]]; then
    step 6 "$total" "Installing systemd timer"
    install_systemd || fail "systemd setup failed"
  fi

  print_summary "success"
}

main "$@"