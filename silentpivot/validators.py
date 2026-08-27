"""Input validation — one place for every "is this safe to act on?" check.

Targets typed by the operator end up as arguments to external tools (nmap, subfinder,
nuclei) and as URLs. python-nmap in particular shlex-splits the host string, so an
unvalidated target like "-oN /tmp/x" would turn into nmap *flags*. Everything the user
types is validated here before it reaches a scanner.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# A hostname label: letters/digits/hyphen, not starting or ending with a hyphen.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})*\.?$")

MAX_PORTS = 65535


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_network(value: str) -> bool:
    """CIDR range such as 10.0.2.0/24."""
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def is_hostname(value: str) -> bool:
    return bool(value) and len(value) <= 253 and bool(_HOSTNAME_RE.match(value))


def valid_target(value: str | None) -> str | None:
    """Normalized scan target (IP, CIDR or hostname), or None if unusable.
    Rejects anything with whitespace/flags/quotes that a tool could read as an argument."""
    value = (value or "").strip()
    if not value or any(c in value for c in ' \t\n\r"\';|&$`\\') or value.startswith("-"):
        return None
    # Accept a URL by taking its host part, so "http://host/path" works as a target.
    if "://" in value:
        host = urlparse(value).hostname
        value = host or ""
    value = value.rstrip(".")
    if is_ip(value) or is_network(value) or is_hostname(value):
        return value
    return None


def valid_domain(value: str | None) -> str | None:
    """Domain for OSINT/subdomain work: a hostname, never an IP or CIDR."""
    value = (value or "").strip().lower().lstrip("*.")
    if "://" in value:
        value = urlparse(value).hostname or ""
    value = value.split("/")[0].rstrip(".")
    if not value or is_ip(value) or not is_hostname(value):
        return None
    return value if "." in value else None      # a bare label isn't a domain


def valid_url(raw: str | None) -> str | None:
    """Validate + normalize a user-entered URL (defaults to https://). None if unusable.
    Only http/https are accepted — a 'javascript:' or 'file:' string is not a web target."""
    raw = (raw or "").strip()
    if not raw or any(c in raw for c in ' \t\n\r"\'<>|'):
        return None
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    try:
        _ = parsed.port      # property access raises ValueError on a junk port
    except ValueError:
        return None
    host = parsed.hostname
    if not (is_ip(host) or is_hostname(host)):
        return None
    return raw


def parse_ports(spec: str | None, max_ports: int = MAX_PORTS) -> list[int] | None:
    """'22,80' / '1-1024' / 'top' -> sorted port list (None = use the caller's default).
    Returns None for 'top'/empty, [] when nothing valid was given. Never raises, and
    never expands an absurd range into memory."""
    spec = (spec or "").strip().lower()
    if not spec or spec == "top":
        return None
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if not (lo.strip().isdigit() and hi.strip().isdigit()):
                continue                      # malformed range -> skip, don't crash
            lo, hi = int(lo), int(hi)
            if lo > hi:
                lo, hi = hi, lo
            # Clamp before expanding so '1-99999999' can't blow up memory.
            lo, hi = max(lo, 1), min(hi, max_ports)
            ports.update(range(lo, hi + 1))
        elif part.isdigit():
            p = int(part)
            if 0 < p <= max_ports:
                ports.add(p)
    return sorted(ports)
