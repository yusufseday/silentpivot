"""Security regression tests — the hardening from the audit passes must not regress.

Covers: input validation (nmap argument injection, URL/domain/port parsing), the ReDoS
time budget on target-scanning regexes, and report-filename path-traversal defence.
"""
import re
import time

import pytest

from silentpivot import validators as v
from silentpivot.ai_engine import SilentAI
from silentpivot.leakfinder import _EXPOSED_PATHS
from silentpivot.pathtraversal import _SIGNATURES
from silentpivot.reporter import _fs_safe, default_filename
from silentpivot.webprobe import _TITLE_RE


# ---------------- input validation ----------------
@pytest.mark.parametrize("target,expected", [
    ("10.0.2.9", "10.0.2.9"),
    ("10.0.2.0/24", "10.0.2.0/24"),
    ("scanme.nmap.org", "scanme.nmap.org"),
    ("-oN /tmp/x", None),           # nmap flag injection
    ("a b", None),                  # whitespace
    ("a;whoami", None),             # shell metachar
    ("$(id)", None),                # command substitution
    ("--script=vuln", None),        # leading-dash flag
])
def test_valid_target(target, expected):
    assert v.valid_target(target) == expected


@pytest.mark.parametrize("url,expected", [
    ("javascript:alert(1)", None),
    ("file:///etc/passwd", None),
    ("x.com", "https://x.com"),
])
def test_valid_url(url, expected):
    assert v.valid_url(url) == expected


def test_valid_domain_rejects_ip_and_bare_label():
    assert v.valid_domain("10.0.2.9") is None
    assert v.valid_domain("localhost") is None


def test_parse_ports_never_crashes_and_clamps():
    assert v.parse_ports("a-b") == []                 # malformed -> empty, no crash
    assert v.parse_ports("top") is None               # sentinel default
    assert len(v.parse_ports("1-99999999") or []) == 65535   # clamped, no memory blow-up


# ---------------- filename path-traversal defence ----------------
@pytest.mark.parametrize("hostile", ["..\\..\\..\\evil", "../../../evil", "10.0.2.0/24", "a\\b", "x/y"])
def test_fs_safe_strips_separators_and_leading_dots(hostile):
    out = _fs_safe(hostile)
    assert "/" not in out and "\\" not in out
    assert not out.startswith(".")


def test_default_filename_safe_for_cidr_and_none():
    fn = default_filename({"resolved_ip": "10.0.2.9", "target": "10.0.2.0/24"}, "md")
    assert "/" not in fn and "\\" not in fn and not fn.startswith(".")
    fn2 = default_filename({"target": None}, "json")
    assert fn2 and not fn2.startswith(".")


# ---------------- ReDoS time budget ----------------
# Each of these regexes scans raw target/AI response bodies and previously exhibited
# O(n^2) backtracking (multi-minute hangs) on adversarial input before being bounded.
_BUDGET_S = 5.0


def _elapsed(fn):
    t0 = time.time()
    fn()
    return time.time() - t0


def test_pathtraversal_signature_fast_on_adversarial():
    evil = "root:" * 500_000
    assert _elapsed(lambda: [rx.search(evil) for _n, rx in _SIGNATURES]) < _BUDGET_S


def test_webprobe_title_fast_on_adversarial():
    def run():
        _TITLE_RE.search("<title " + "a=1 " * 200_000)
        _TITLE_RE.search("<title" * 200_000)
    assert _elapsed(run) < _BUDGET_S


def test_ai_payload_bracket_scan_fast_on_adversarial():
    evil = "text " + "[" * 2_000_000
    assert _elapsed(lambda: SilentAI._parse_payload_list(evil, 12)) < _BUDGET_S


def test_leakfinder_script_src_fast_on_adversarial():
    rx = re.compile(r'<script[^>]{1,500}src=["\']([^"\']{1,2000})["\']', re.I)
    assert _elapsed(lambda: rx.search("<script" * 500_000)) < _BUDGET_S


def test_leakfinder_htpasswd_fast_on_adversarial():
    rx = re.compile(dict(_EXPOSED_PATHS)["/.htpasswd"])
    assert _elapsed(lambda: rx.search("a" * 5_000_000)) < _BUDGET_S
