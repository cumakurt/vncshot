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
  -h, --help         show this help

Environment:
  GO_VERSION         preferred Go release (default: 1.22 or newer required)
  INSTALL_PREFIX     binary install prefix (default: /usr/local/bin)
  REPORT_DIR         root for timestamped report folders (default: /usr/local/vncshot)
  NO_COLOR           disable coloured output
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)        ASSUME_YES=1 ;;
    --build-only)    BUILD_ONLY=1 ;;
    --install-bin)   INSTALL_BIN=1 ;;
    --no-install-bin) INSTALL_BIN=0 ;;
    -h|--help)       usage; exit 0 ;;
    *)               printf 'unknown option: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
  shift
done

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
  local ldflags="-s -w -X main.version=${VERSION:-dev} -X main.reportBaseDir=${REPORT_DIR}"
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

  if [[ -w "$prefix" || ( ! -e "$prefix" && -w "$(dirname -- "$prefix")" ) ]]; then
    mkdir -p "$prefix"
    install -m 0755 "$BINARY_PATH" "$target"
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
  local parent
  parent="$(dirname -- "$REPORT_DIR")"
  if [[ "$(id -u)" -eq 0 || ( -d "$parent" && -w "$parent" ) ]]; then
    if mkdir -p "$REPORT_DIR" && chmod 0755 "$REPORT_DIR"; then
      ok "created report directory $REPORT_DIR"
      return 0
    fi
  elif run_privileged mkdir -p "$REPORT_DIR" && run_privileged chmod 0755 "$REPORT_DIR"; then
    ok "created report directory $REPORT_DIR"
    return 0
  fi
  err "cannot create $REPORT_DIR (no write access; sudo is unavailable or needs a password)"
  detail "re-run with sudo or set REPORT_DIR to a writable directory"
  return 1
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

  local total=3
  if [[ "$INSTALL_BIN" -eq 1 ]]; then
    total=5
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

  print_summary "success"
}

main "$@"