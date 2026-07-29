"""Shared UI layer: a single Console instance, colors and common output helpers.
Both the CLI and the interactive panel are fed from here (no duplicated code)."""
import os
import sys
import subprocess
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# Prevent UTF-8 crashes on legacy Windows consoles (cp1252 etc.); skip if unsupported.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# emoji=False so ':word:' patterns in scanned content (e.g. the "root:x:0:0:" line of
# /etc/passwd) aren't mangled into emojis by rich's shortcode replacement.
console = Console(emoji=False)

# CVSS severity -> rich style
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}

BANNER = r"""[bold green]
   _____ _ _            _   ____  _            _
  / ____(_) |          | | |  _ \(_)          | |
 | (___  _| | ___ _ __ | |_| |_) |___   _____ | |_
  \___ \| | |/ _ \ '_ \| __|  __/| \ \ / / _ \| __|
  ____) | | |  __/ | | | |_| |   | |\ V / (_) | |_
 |_____/|_|_|\___|_| |_|\__|_|   |_| \_/ \___/ \__|
[/bold green][dim]        AI-powered recon & vulnerability command center[/dim]"""


def print_banner():
    console.print(BANNER)


def _worst_cve(cves):
    """Pick the most critical CVE: KEV first, then CVSS, then severity."""
    from modules.reporter import _worst_cve as wc
    return wc(cves)


def print_summary_table(results, title="Scan Summary"):
    """Render open ports and the highest verified CVE risk in a colored table."""
    table = Table(title=title, show_lines=False)
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Service", style="white")
    table.add_column("Version", style="white")
    table.add_column("CVEs", justify="right")
    table.add_column("Top Risk")
    table.add_column("KEV")

    for r in results:
        cves = r.get("cves", []) or []
        worst = _worst_cve(cves)
        if worst:
            sev = worst.get("severity", "UNKNOWN")
            risk = f"[{SEVERITY_COLORS.get(sev, 'dim')}]{sev} ({worst.get('cvss')})[/]"
            kev = "[bold red]ACTIVE[/]" if any(c.get("kev") for c in cves) else "[dim]-[/dim]"
        else:
            risk, kev = "[dim]-[/dim]", "[dim]-[/dim]"
        table.add_row(
            str(r.get("port", "?")),
            r.get("service", "?"),
            r.get("version", "?"),
            str(len(cves)),
            risk,
            kev,
        )
    console.print(table)


def file_link(path):
    """rich markup for a local file. Shows the ABSOLUTE path as the visible text so it
    is copy/paste-ready (and auto-detected) even in terminals without OSC-8 support,
    while still being a real file:// hyperlink in terminals that do support it."""
    abs_path = os.path.abspath(path).replace("\\", "/")
    return f"[link=file:///{abs_path.lstrip('/')}]{abs_path}[/link]"


def open_path(path):
    """Open a file with the OS default app, swallowing the launched app's own console
    noise (e.g. Chrome's harmless GPU/VAAPI warnings on Linux VMs). Returns True on ok."""
    path = os.path.abspath(path)
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: E501  (Windows-only)
        else:
            opener = "open" if sys.platform == "darwin" else "xdg-open"
            subprocess.Popen([opener, path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False


def cve_link(cve_id):
    """rich clickable link from a CVE id to its NVD detail page."""
    return f"[link=https://nvd.nist.gov/vuln/detail/{cve_id}]{cve_id}[/link]"


def normalize_url(raw):
    """Validate + normalize a user-entered URL. Returns a clean URL or None.
    Guards against malformed input (spaces, stray '[', missing host) that would
    otherwise throw a cryptic error deep inside urlparse."""
    raw = (raw or "").strip()
    if not raw or " " in raw or "[" in raw:
        return None
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    return raw if parsed.netloc else None


def info(msg):
    console.print(f"[bold cyan][*][/bold cyan] {msg}")


def success(msg):
    console.print(f"[bold green][+][/bold green] {msg}")


def warn(msg):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def error(msg):
    console.print(f"[bold red][-][/bold red] {msg}")
