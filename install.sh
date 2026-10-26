#!/usr/bin/env bash
#
# install.sh — dependency bootstrap and static build for vncshot.
#
# Detects the host operating system and package manager, installs any
# missing toolchain pieces exactly once (existing installs are reused),
# then produces a stripped static binary.
#
# Usage:
#   ./install.sh              interactive install + build
#   ./install.sh -y           non-interactive
#   ./install.sh --build-only skip dependency installation
#   ./install.sh --install-bin also copy the binary into /usr/local/bin
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

info()    { printf "  ${C_CYAN}•${C_RESET} %s\n" "$*"; }
step()    { printf "\n  ${C_BOLD}${C_BLUE}[%s/%s]${C_RESET} ${C_BOLD}%s${C_RESET}\n" "$1" "$2" "$3"; }
detail()  { printf "      ${C_DIM}%s${C_RESET}\n" "$*"; }
ok()      { printf "      ${C_GREEN}✓${C_RESET} %s\n" "$*"; }
warn()    { printf "      ${C_YELLOW}!${C_RESET} %s\n" "$*"; }
err()     { printf "      ${C_RED}✗${C_RESET} %s\n" "$*" >&2; }
fail()    { err "$*"; exit 1; }

banner() {
  printf "\n"
  printf "  ${C_BG_BLUE}${C_WHITE}${C_BOLD}  vncshot  ${C_RESET}  ${C_DIM}security inventory toolkit${C_RESET}\n"
  printf "  ${C_DIM}%s${C_RESET}\n" "$RULE"
  printf "  ${C_DIM}Cuma KURT  ·  cumakurt@gmail.com  ·  github.com/cumakurt/vncshot${C_RESET}\n"
}

box_top()    { printf "  ${C_CYAN}┌%s┐${C_RESET}\n" "$RULE"; }
box_bottom() { printf "  ${C_CYAN}└%s┘${C_RESET}\n" "$RULE"; }
box_rule()   { printf "  ${C_CYAN}├%s┤${C_RESET}\n" "$RULE"; }
box_row() {
  # Fixed-width columns keep the right border aligned with the rule.
  local label="$1" value="$2"
  printf "  ${C_CYAN}│${C_RESET} ${C_BOLD}%-13s${C_RESET} ${C_DIM}│${C_RESET} %-46s ${C_CYAN}│${C_RESET}\n" "$label" "$value"
}

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

ASSUME_YES=0
BUILD_ONLY=0
INSTALL_BIN=0

usage() {
  cat <<EOF
Usage: ./install.sh [options]

Options:
  -y, --yes          non-interactive; assume yes on prompts
  --build-only       skip dependency installation, just compile
  --install-bin      copy the built binary to /usr/local/bin
  -h, --help         show this help

Environment:
  GO_VERSION         preferred Go release (default: 1.22 or newer required)
  INSTALL_PREFIX     binary prefix for --install-bin (default: /usr/local/bin)
  NO_COLOR           disable coloured output
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)        ASSUME_YES=1 ;;
    --build-only)    BUILD_ONLY=1 ;;
    --install-bin)   INSTALL_BIN=1 ;;
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
DEPS_INSTALLED=()
DEPS_PRESENT=()

# ---------------------------------------------------------------------------
# System detection
# ---------------------------------------------------------------------------

detect_os() {
  OS_ARCH="$(uname -m)"
  case "$(uname -s)" in
    Linux)  OS_NAME="Linux" ;;
    Darwin) OS_NAME="macOS" ;;
    MINGW*|MSYS*|CYGWIN*) OS_NAME="Windows" ;;
    *)      OS_NAME="$(uname -s)" ;;
  esac

  if [[ "$OS_NAME" == "Linux" ]] && [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_NAME="Linux (${ID:-unknown})"
  fi
}

detect_package_manager() {
  if [[ "$OS_NAME" == "macOS" ]] && command -v brew >/dev/null 2>&1; then
    PKG_MGR="brew"; PKG_INSTALL="brew install"
    return
  fi
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
  elif [[ "$(id -u)" -eq 0 ]] || [[ "$PKG_MGR" == "brew" ]]; then
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
  local os_lc arch_tar goos goarch
  os_lc="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$(uname -m)" in
    x86_64)          arch_tar="amd64" ;;
    aarch64|arm64)   arch_tar="arm64" ;;
    armv7l)          arch_tar="armv6l" ;;
    *)               fail "unsupported architecture for Go tarball: $(uname -m)" ;;
  esac
  case "$os_lc" in
    linux)  goos="linux" ;;
    darwin) goos="darwin" ;;
    *)      fail "unsupported OS for Go tarball: $os_lc" ;;
  esac

  local tarball="go${ver}.${goos}-${arch_tar}.tar.gz"
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
    if [[ "$PKG_MGR" == "brew" ]]; then pkg_name="go"; fi
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
  local ldflags="-s -w -X main.version=${VERSION:-dev}"
  # CGO off + -trimpath yields a portable static binary.
  if ! CGO_ENABLED=0 "$GO_BIN" build \
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

install_binary() {
  local prefix="${INSTALL_PREFIX:-/usr/local/bin}"
  if [[ ! -d "$prefix" ]]; then
    warn "$prefix does not exist; skipping --install-bin"
    return
  fi
  if [[ -w "$prefix" ]]; then
    cp "$BINARY_PATH" "$prefix/vncshot"
  else
    detail "elevated permissions required to write $prefix"
    sudo cp "$BINARY_PATH" "$prefix/vncshot"
  fi
  ok "installed $prefix/vncshot"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  local status="${1:-success}"
  local color="$C_GREEN"
  [[ "$status" != "success" ]] && color="$C_YELLOW"

  printf "\n"
  box_top
  printf "  ${C_CYAN}│${C_RESET} ${C_BOLD}%-62s${C_RESET} ${C_CYAN}│${C_RESET}\n" "vncshot installation summary"
  box_rule
  box_row "OS"        "$OS_NAME / $OS_ARCH"
  box_row "Go"        "${GO_VERSION_STR:-not found}"
  box_row "Package"   "${PKG_MGR:-none}"
  box_row "Binary"    "${BINARY_PATH}"
  box_row "Size"      "${BINARY_SIZE:-n/a}"
  if [[ ${#DEPS_INSTALLED[@]} -gt 0 ]]; then
    local list
    list="$(printf '%s, ' "${DEPS_INSTALLED[@]}")"
    box_row "Installed" "${list%, }"
  else
    box_row "Installed" "nothing — all requirements already satisfied"
  fi
  if [[ ${#DEPS_PRESENT[@]} -gt 0 ]]; then
    local present
    present="$(printf '%s, ' "${DEPS_PRESENT[@]}")"
    box_row "Reused"    "${present%, }"
  fi
  box_rule
  printf "  ${C_CYAN}│${C_RESET} ${C_BOLD}%-13s${C_RESET} ${C_DIM}│${C_RESET} ${color}${C_BOLD}%-46s${C_RESET} ${C_CYAN}│${C_RESET}\n" "Status" "$(echo "$status" | tr '[:lower:]' '[:upper:]')"
  box_bottom

  printf "\n  ${C_DIM}Run it with:${C_RESET} ${C_BOLD}./vncshot -h${C_RESET}\n"
  printf "  ${C_DIM}Developer: Cuma KURT  ·  cumakurt@gmail.com${C_RESET}\n"
  printf "  ${C_DIM}github.com/cumakurt/vncshot  ·  linkedin.com/in/cuma-kurt-34414917${C_RESET}\n"
  printf "  ${C_DIM}Authorized use only — scan networks you own or have written permission to test.${C_RESET}\n\n"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  banner

  local total=3

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
    install_binary
  fi

  print_summary "success"
}

main "$@"