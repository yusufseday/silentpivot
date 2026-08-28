<#
    SilentPivot installer for Windows (PowerShell).

    Brings up everything the tool needs on a fresh machine:
      1. Python 3 (installed via winget if missing)
      2. pipx
      3. the `silentpivot` command, installed globally and editable (git pull updates it)
      4. a .env from the template
    and reports which optional recon tools (nmap, nuclei, ...) are present.

    Usage (from the project folder):
        powershell -ExecutionPolicy Bypass -File .\install.ps1

    NOTE: this file is intentionally pure ASCII. Windows PowerShell 5.1 reads .ps1
    files as ANSI when there is no BOM, so non-ASCII punctuation would corrupt parsing.
#>
$ErrorActionPreference = 'Stop'

function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Err($m)  { Write-Host "[-] $m" -ForegroundColor Red }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# ---- 1. Find (or install) Python 3 ---------------------------------------
$PyExe = $null
$PyPre = @()
if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 --version *> $null
    if ($LASTEXITCODE -eq 0) { $PyExe = 'py'; $PyPre = @('-3') }
}
if (-not $PyExe -and (Get-Command python -ErrorAction SilentlyContinue)) {
    $v = & python --version 2>&1
    if ($v -match 'Python 3') { $PyExe = 'python' }
}

if (-not $PyExe) {
    Info "Python 3 not found - attempting install via winget..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install -e --id Python.Python.3.13 --accept-source-agreements --accept-package-agreements
        Warn "Python installed. CLOSE this window, open a NEW PowerShell, and re-run .\install.ps1"
        exit 0
    } else {
        Err "winget is unavailable. Install Python 3.8+ from https://www.python.org/downloads/"
        Err "(tick 'Add python.exe to PATH' during setup), then re-run this script."
        exit 1
    }
}
$ver = & $PyExe @PyPre --version 2>&1
Ok "Python found: $ver"

# ---- 2. pipx --------------------------------------------------------------
Info "Ensuring pipx..."
& $PyExe @PyPre -m pip install --user --upgrade --quiet --disable-pip-version-check pipx
# ensurepath writes an informational note to stderr when PATH is already configured.
# Under ErrorActionPreference=Stop, redirecting a native command's stderr raises a
# NativeCommandError, so soften the preference just for this tolerant, idempotent call.
$eap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $PyExe @PyPre -m pipx ensurepath 2>&1 | Out-Null
$ErrorActionPreference = $eap
Ok "pipx ready"

# ---- 3. Install SilentPivot (editable, so it tracks git pull) -------------
Info "Installing silentpivot (global, editable)..."
& $PyExe @PyPre -m pipx install --editable . --force --quiet
Ok "silentpivot installed"

# ---- 4. .env --------------------------------------------------------------
if (-not (Test-Path .env)) {
    Copy-Item .env.example .env
    Warn "Created .env from template - add your AI_API_KEY to enable AI features."
} else {
    Ok ".env already present"
}

# ---- 5. Optional external tools ------------------------------------------
Info "Optional recon tools (the hybrid modules use them when present):"
foreach ($t in 'nmap', 'nuclei', 'subfinder', 'ffuf', 'gobuster') {
    if (Get-Command $t -ErrorAction SilentlyContinue) {
        Ok "  $t"
    } else {
        Warn "  $t missing (optional - a pure-Python fallback is used where possible)"
    }
}

Write-Host ""
Ok "Done. Open a NEW terminal (so PATH refreshes), then run:  silentpivot"
