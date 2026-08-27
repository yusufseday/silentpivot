#!/usr/bin/env bash
#
# SilentPivot installer for Linux (Kali / Debian / Ubuntu).
#
# Brings up everything the tool needs on a fresh machine:
#   1. Python 3 (installed via apt if missing)
#   2. pipx
#   3. the `silentpivot` command, installed globally & editable (git pull updates it)
#   4. a .env from the template
# and reports which optional recon tools (nmap, nuclei, ...) are present.
#
# Usage:   bash install.sh
#
set -euo pipefail

info() { printf '\033[1;36m[*]\033[0m %s\n' "$1"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[-]\033[0m %s\n' "$1" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# sudo only if we're not already root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi
fi

# ---- 1. Python 3 ----------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    info "Python 3 not found — installing..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update
        $SUDO apt-get install -y python3 python3-pip python3-venv
    else
        err "No apt-get on this system. Install Python 3.8+ manually, then re-run."
        exit 1
    fi
fi
ok "Python: $(python3 --version 2>&1)"

# ---- 2. pipx --------------------------------------------------------------
if ! command -v pipx >/dev/null 2>&1 && ! python3 -m pipx --version >/dev/null 2>&1; then
    info "Installing pipx..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get install -y pipx || python3 -m pip install --user pipx
    else
        python3 -m pip install --user pipx
    fi
fi
# ensurepath adds pipx's bin dir to PATH (takes effect in new shells).
python3 -m pipx ensurepath >/dev/null 2>&1 || pipx ensurepath >/dev/null 2>&1 || true
ok "pipx ready"

# ---- 3. Install SilentPivot (editable → tracks git pull) ------------------
info "Installing silentpivot (global, editable)..."
if python3 -m pipx --version >/dev/null 2>&1; then
    python3 -m pipx install --editable . --force
else
    pipx install --editable . --force
fi
ok "silentpivot installed"

# ---- 4. .env --------------------------------------------------------------
if [ ! -f .env ]; then
    cp .env.example .env
    warn "Created .env from template — add your AI_API_KEY to enable AI features."
else
    ok ".env already present"
fi

# ---- 5. Optional external tools ------------------------------------------
info "Optional recon tools (the hybrid modules use them when present):"
for t in nmap nuclei subfinder ffuf gobuster searchsploit; do
    if command -v "$t" >/dev/null 2>&1; then
        ok "  $t"
    else
        warn "  $t missing (optional — a pure-Python fallback is used where possible)"
    fi
done

echo
ok "Done. Open a NEW terminal (so PATH refreshes), then run:  silentpivot"
