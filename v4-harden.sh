#!/usr/bin/env bash
################################################################################
# VPS HARDENING SCRIPT v4.0 - BASH BOOTSTRAP WRAPPER
#
# Purpose: Ensure Python 3 + python3-distro are available, then hand off to
#          the Python orchestrator (v4-harden.py).
#
# This wrapper is intentionally minimal. All logic lives in Python.
################################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_MAIN="${SCRIPT_DIR}/v4-harden.py"

# ---- Help / version shortcuts ----
case "${1:-}" in
    --version|-v)
        echo "VPS Hardening Script v4.0.0"
        exit 0
        ;;
    --help|-h)
        cat <<'EOF'
VPS Hardening Script v4.0

Usage: sudo bash v4-harden.sh [options]

Options are passed through to the Python orchestrator:
  --dry-run              Preview all actions without making changes
  --skip-luks            Skip LUKS module
  --skip-wireguard       Skip WireGuard module
  --skip-docker          Skip Docker hardening module
  --skip-telegram        Skip Telegram bot setup
  --verbose              Verbose debug output
  --help, -h             Show this help
  --version, -v          Show version

Environment:
  V4_NO_BOOTSTRAP=1      Skip dependency installation (assumes deps present)
EOF
        exit 0
        ;;
esac

# ---- Root check ----
if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)." >&2
    exit 1
fi

# ---- Locate or install Python 3 ----
PYTHON_BIN=""
for candidate in python3 python3.12 python3.11 python3.10 python3.9 python3.8; do
    if command -v "${candidate}" >/dev/null 2>&1; then
        PYTHON_BIN="$(command -v "${candidate}")"
        break
    fi
done

if [[ -z "${PYTHON_BIN}" ]]; then
    echo "[bootstrap] Python 3 not found. Attempting to install..." >&2
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq python3
        PYTHON_BIN="$(command -v python3)"
    else
        echo "ERROR: Cannot install Python 3 automatically. Please install it manually." >&2
        exit 1
    fi
fi

PY_VERSION="$("${PYTHON_BIN}" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
echo "[bootstrap] Using Python ${PY_VERSION} at ${PYTHON_BIN}"

# ---- Ensure python3-distro is available ----
if [[ "${V4_NO_BOOTSTRAP:-0}" != "1" ]]; then
    if ! "${PYTHON_BIN}" -c 'import distro' >/dev/null 2>&1; then
        echo "[bootstrap] Installing python3-distro..." >&2
        if command -v apt-get >/dev/null 2>&1; then
            export DEBIAN_FRONTEND=noninteractive
            apt-get install -y -qq python3-distro || true
        fi
    fi
fi

if ! "${PYTHON_BIN}" -c 'import distro' >/dev/null 2>&1; then
    echo "[bootstrap] WARNING: python3-distro not available; falling back to /etc/os-release parsing." >&2
fi

# ---- Hand off to Python orchestrator ----
if [[ ! -f "${PY_MAIN}" ]]; then
    echo "ERROR: ${PY_MAIN} not found. Ensure both files are in the same directory." >&2
    exit 1
fi

exec "${PYTHON_BIN}" "${PY_MAIN}" "$@"
