#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

BOARD_CONFIG="${ODTS_BOOTSTRAP_BOARD_CONFIG:-j152fap}"
PYENV_ROOT="${PYENV_ROOT:-$HOME/.pyenv}"
BREW_PACKAGES=(
  pyenv
  libusb
  libirecovery
  openssl@1.1
  readline
  xz
  pkg-config
)
LEGACY_PYTHON_VERSION="2.7.18"
LEGACY_EXPORT_FILE="$PROJECT_ROOT/.odts-legacy-python.env"
LEGACY_RUNTIME_JSON="$PROJECT_ROOT/legacy-runtime-check.json"
PREFLIGHT_JSON="$PROJECT_ROOT/preflight-bootstrap-check.json"

log() {
  printf '[bootstrap] %s\n' "$*"
}

fail() {
  printf '[bootstrap] ERROR: %s\n' "$*" >&2
  exit 1
}

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || fail "This bootstrap is supported on macOS only."
  log "macOS version: $(sw_vers -productVersion)"
  log "architecture: $(uname -m)"
}

ensure_homebrew() {
  if command -v brew >/dev/null 2>&1; then
    log "Homebrew present: $(command -v brew)"
    return
  fi
  log "Installing Homebrew"
  NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
  command -v brew >/dev/null 2>&1 || fail "Homebrew installation did not make brew available on PATH."
}

ensure_brew_on_path() {
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
}

ensure_brew_packages() {
  for pkg in "${BREW_PACKAGES[@]}"; do
    if brew list --versions "$pkg" >/dev/null 2>&1; then
      log "brew package present: $pkg"
    else
      log "Installing brew package: $pkg"
      brew install "$pkg"
    fi
  done
}

ensure_pyenv() {
  export PYENV_ROOT
  export PATH="$PYENV_ROOT/bin:$PATH"
  command -v pyenv >/dev/null 2>&1 || fail "pyenv not available after brew installation."
  eval "$(pyenv init -)"
}

ensure_python27() {
  local openssl_prefix readline_prefix xz_prefix
  openssl_prefix="$(brew --prefix openssl@1.1)"
  readline_prefix="$(brew --prefix readline)"
  xz_prefix="$(brew --prefix xz)"

  export CPPFLAGS="-I${openssl_prefix}/include -I${readline_prefix}/include -I${xz_prefix}/include"
  export LDFLAGS="-L${openssl_prefix}/lib -L${readline_prefix}/lib -L${xz_prefix}/lib"
  export PKG_CONFIG_PATH="${openssl_prefix}/lib/pkgconfig:${readline_prefix}/lib/pkgconfig:${xz_prefix}/lib/pkgconfig"

  if pyenv versions --bare | grep -qx "$LEGACY_PYTHON_VERSION"; then
    log "pyenv Python present: $LEGACY_PYTHON_VERSION"
  else
    log "Installing Python $LEGACY_PYTHON_VERSION via pyenv"
    pyenv install -s "$LEGACY_PYTHON_VERSION"
  fi

  export ODTS_LEGACY_PYTHON="$PYENV_ROOT/versions/$LEGACY_PYTHON_VERSION/bin/python2.7"
  [[ -x "$ODTS_LEGACY_PYTHON" ]] || fail "Expected interpreter not found at $ODTS_LEGACY_PYTHON"
  printf 'export ODTS_LEGACY_PYTHON=%s\n' "$ODTS_LEGACY_PYTHON" > "$LEGACY_EXPORT_FILE"
  log "Persisted legacy runtime export to $LEGACY_EXPORT_FILE"
}

ensure_python3_venv() {
  local python3_bin
  python3_bin="$(command -v python3 || true)"
  [[ -n "$python3_bin" ]] || fail "python3 is required to create the repo virtualenv."
  if [[ ! -x "$PROJECT_ROOT/venv/bin/python" ]]; then
    log "Creating Python 3 virtualenv"
    "$python3_bin" -m venv "$PROJECT_ROOT/venv"
  fi
  log "Upgrading Python 3 packaging tools"
  "$PROJECT_ROOT/venv/bin/python" -m pip install --upgrade pip setuptools wheel
  log "Installing Python 3 requirements"
  "$PROJECT_ROOT/venv/bin/python" -m pip install -r "$PROJECT_ROOT/requirements.txt"
}

ensure_python2_pip() {
  if "$ODTS_LEGACY_PYTHON" -m pip --version >/dev/null 2>&1; then
    log "Python 2 pip present"
    return
  fi
  log "Installing pip for Python 2.7"
  local get_pip="$PROJECT_ROOT/.tmp-get-pip.py"
  curl -fsSL https://bootstrap.pypa.io/pip/2.7/get-pip.py -o "$get_pip"
  "$ODTS_LEGACY_PYTHON" "$get_pip" "pip<21" "setuptools<45" "wheel"
  rm -f "$get_pip"
}

ensure_python2_deps() {
  ensure_python2_pip
  log "Installing Python 2 runtime dependencies"
  "$ODTS_LEGACY_PYTHON" -m pip install --upgrade "pip<21" "setuptools<45" "wheel"
  "$ODTS_LEGACY_PYTHON" -m pip install "pyusb==1.0.2"
}

verify_libusb() {
  if brew list --versions libusb >/dev/null 2>&1; then
    log "libusb brew package present"
  else
    fail "libusb brew package is missing after bootstrap."
  fi
}

run_validations() {
  log "Running non-destructive legacy runtime check"
  "$PROJECT_ROOT/venv/bin/python" odts.py --check-legacy-pwn-runtime --json > "$LEGACY_RUNTIME_JSON"
  log "Running non-destructive preflight with board config $BOARD_CONFIG"
  "$PROJECT_ROOT/venv/bin/python" odts.py --preflight --board-config "$BOARD_CONFIG" --json > "$PREFLIGHT_JSON"
}

print_summary() {
  "$PROJECT_ROOT/venv/bin/python" - <<'PY' "$LEGACY_RUNTIME_JSON" "$PREFLIGHT_JSON" "$LEGACY_EXPORT_FILE"
import json
import sys
from pathlib import Path

runtime_path = Path(sys.argv[1])
preflight_path = Path(sys.argv[2])
export_path = Path(sys.argv[3])
runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
preflight = json.loads(preflight_path.read_text(encoding="utf-8"))

print("[bootstrap] Summary")
print(f"[bootstrap] legacy export file: {export_path}")
print(f"[bootstrap] preview_clean_runtime_boundary: {runtime['preview_clean_runtime_boundary']}")
print(f"[bootstrap] interpreter_ready: {runtime['interpreter_ready']}")
print(f"[bootstrap] module_import_ready: {runtime['module_import_ready']}")
print(f"[bootstrap] libusb_backend_ready: {runtime['libusb_backend_ready']}")
print(f"[bootstrap] vendored_libusbfinder_ready: {runtime['vendored_libusbfinder_ready']}")
print(f"[bootstrap] runtime issues: {[issue['classification'] for issue in runtime['issues']]}")
print(f"[bootstrap] preflight blockers: {preflight['blockers']}")
print(f"[bootstrap] readiness level: {preflight['readiness']['level']}")
print(f"[bootstrap] next export: {runtime['suggested_export']}")
PY
}

main() {
  require_macos
  ensure_brew_on_path
  ensure_homebrew
  ensure_brew_on_path
  ensure_brew_packages
  ensure_pyenv
  ensure_python27
  ensure_python3_venv
  ensure_python2_deps
  verify_libusb
  run_validations
  print_summary
}

main "$@"
