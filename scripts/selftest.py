"""SilentPivot self-test — proves every module works against real sources.

Run from the project root:
    python scripts/selftest.py

No API keys and no nmap required. Uses only known-safe public endpoints and the
canonical legal test host scanme.nmap.org. Prints PASS/FAIL per check.
"""
import os
import sys
import time

# Make the project root importable when run as `python scripts/selftest.py`
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console

console = Console()
PASS = "[bold green]PASS[/bold green]"
FAIL = "[bold red]FAIL[/bold red]"
results = []


def check(name, fn):
    console.print(f"[cyan]>>[/cyan] {name} ...")
    t0 = time.time()
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, f"exception: {e}"
    dt = time.time() - t0
    console.print(f"   {PASS if ok else FAIL}  [dim]{dt:.1f}s[/dim]  {detail}\n")
    results.append((name, ok))


# ---------------- Checks ----------------
def c_kev():
    from modules.kev import KevCatalog
    hit = KevCatalog().lookup("CVE-2021-44228")  # Log4Shell, always in KEV
    return bool(hit), f"Log4Shell KEV -> {hit.get('name') if hit else None}"


def c_epss():
    from modules.exploits import ExploitIntel
    epss = ExploitIntel()._epss_batch(["CVE-2021-44228"])
    v = epss.get("CVE-2021-44228", {}).get("epss")
    return (v is not None and v > 0.5), f"Log4Shell EPSS = {v}"


def c_poc():
    from modules.exploits import ExploitIntel
    _, data = ExploitIntel()._poc_one("CVE-2021-44228")
    # A reachable service returns a count (>0 expected for Log4Shell).
    return (data["count"] > 0), f"public PoCs found = {data['count']}"


def c_exploit_full():
    from modules.exploits import ExploitIntel
    sample = [{"port": 443, "service": "https", "cves": [
        {"id": "CVE-2021-44228", "cvss": 10.0, "severity": "CRITICAL", "kev": True},
    ]}]
    ExploitIntel().enrich(sample)
    c = sample[0]["cves"][0]
    return ("epss" in c), f"enriched -> EPSS={c.get('epss')} PoC={c.get('poc')} EDB={c.get('exploitdb')}"


def c_nvd():
    from modules.vuln_checker import VulnChecker
    vc = VulnChecker()
    data = vc._request({"cpeName": vc._normalize_cpe("cpe:/a:apache:http_server:2.4.49"),
                        "resultsPerPage": 3})
    n = len(data.get("vulnerabilities", [])) if data else 0
    return (n > 0), f"NVD returned {n} CVEs for Apache 2.4.49"


def c_subdomain():
    from modules.subdomain import SubdomainScanner
    s = SubdomainScanner()
    sub_sources = s._gather_passive("nmap.org")
    working = [k for k, v in s._passive_counts.items() if v > 0]
    return (len(sub_sources) > 0), f"{len(sub_sources)} subs (passive) | working sources: {working}"


def c_portcheck():
    from modules.portcheck import PortChecker
    # scanme.nmap.org is Nmap's official legal scan target; 22 and 80 are open.
    res = PortChecker(timeout=3.0).scan("scanme.nmap.org", ports=[22, 80, 443], only_open=True)
    if res is None:
        return False, "DNS resolution failed"
    open_ports = [r["port"] for r in res]
    return (len(open_ports) > 0), f"open ports on scanme.nmap.org: {open_ports}"


def c_webprobe():
    from modules.webprobe import WebProber
    res = WebProber(timeout=10).probe_host("wordpress.com", ports=[443])
    if not res:
        return False, "no web endpoint reachable"
    r = res[0]
    return (r["status"] == 200 and bool(r["tech"])), \
        f"wordpress.com -> [{r['status']}] tech={r['tech']} waf={r['waf']}"


def c_nuclei():
    from modules.nuclei import NucleiScanner
    # Parsing is deterministic and always testable; the binary is optional.
    sample = ('{"template-id":"x","info":{"name":"n","severity":"high"},'
              '"matched-at":"https://t/a"}')
    parsed = NucleiScanner.parse_jsonl(sample)
    ok = len(parsed) == 1 and parsed[0]["severity"] == "HIGH"
    avail = "installed" if NucleiScanner().available else "NOT installed (optional)"
    return ok, f"JSONL parse OK | nuclei binary: {avail}"


def c_bypass403():
    from modules.bypass403 import Bypass403
    attempts = Bypass403()._build_attempts("https://host/admin")
    techniques = {a[0].split()[0] for a in attempts}  # header / path / method
    ok = len(attempts) > 20 and {"header", "path", "method"} <= techniques
    return ok, f"{len(attempts)} bypass techniques generated ({', '.join(sorted(techniques))})"


def c_leakfinder():
    from modules.leakfinder import _COMPILED, _PLACEHOLDER
    sample = 'a="AKIAIOSFODNN7EXAMPLE" b="AKIA1234567890ABCDEF" c="ghp_' + "z" * 36 + '"'
    hits = []
    for name, (pat, _c) in _COMPILED.items():
        for m in pat.finditer(sample):
            if not _PLACEHOLDER.search(m.group(0)):
                hits.append(name)
    # must catch the real AWS + GitHub token, skip the EXAMPLE placeholder
    ok = "AWS Access Key" in hits and "GitHub Token" in hits and len(hits) == 2
    return ok, f"caught {hits} (placeholder skipped)"


def c_pathtraversal():
    from modules.pathtraversal import PathTraversal
    pt = PathTraversal()
    hit = pt._check("root:x:0:0:root:/root:/bin/bash", "x")
    clean = pt._check("<html>welcome</html>", "x")
    ok = hit and hit[0] == "Linux /etc/passwd" and clean is None
    return ok, f"passwd signature -> {hit[0] if hit else None}, clean page -> {clean}"


def c_ssrf():
    from modules.ssrf import SSRFScanner
    # Real AWS metadata response tokens (not present in the payloads)
    real = SSRFScanner._check('{"AccessKeyId":"AKIA...","SecretAccessKey":"x"}', "http://169.254.169.254/")
    # Reflected payload must NOT trigger (the guard): body echoes the payload path
    reflected = SSRFScanner._check("Warning: include(http://169.254.169.254/latest/meta-data/iam/)",
                                   "http://169.254.169.254/latest/meta-data/iam/")
    clean = SSRFScanner._check("<html>welcome</html>", "x")
    ok = real and real[0] == "AWS metadata" and reflected is None and clean is None
    return ok, f"real->{real[0] if real else None}, reflected->{reflected}, clean->{clean}"


def c_ai_payload_parse():
    from modules.ai_engine import SilentAI
    got = SilentAI._parse_payload_list('text ["http://127.0.0.1/","gopher://x"] tail', 12)
    return len(got) == 2, f"parsed {got} (bad input -> {SilentAI._parse_payload_list('none', 12)})"


def c_validators():
    from modules import validators as v
    checks = [
        # (result, expected, label)
        (v.valid_target("10.0.2.9"), "10.0.2.9", "ip ok"),
        (v.valid_target("-oN /tmp/x"), None, "nmap flag injection rejected"),
        (v.valid_target("a b"), None, "whitespace rejected"),
        (v.valid_url("javascript:alert(1)"), None, "js scheme rejected"),
        (v.valid_url("x.com"), "https://x.com", "bare host normalized"),
        (v.valid_domain("10.0.2.9"), None, "ip is not a domain"),
        (v.parse_ports("a-b"), [], "malformed range survives"),
        (v.parse_ports("top"), None, "'top' -> default"),
        (len(v.parse_ports("1-99999999") or []), 65535, "huge range clamped"),
    ]
    bad = [label for got, want, label in checks if got != want]
    return not bad, ("all input checks pass" if not bad else f"FAILED: {bad}")


def c_contentdisco():
    from modules.contentdisco import ContentDiscovery, BUILTIN_WORDLIST
    # ffuf base64-encodes FUZZ values in JSON output — the parser must decode them.
    ffuf = ('{"input":{"FUZZ":"admin"},"url":"http://t/admin","status":200,"length":12}\n'
            '{"input":{"FUZZ":"cGhwTXlBZG1pbg=="},"status":301,"length":9}\n'
            '{"input":{"FUZZ":"a"},"status":"abc"}\n'
            'not json')
    gob = "/admin  (Status: 301) [Size: 234] [--> /admin/]\nnoise"
    f = ContentDiscovery.parse_ffuf(ffuf)
    g = ContentDiscovery.parse_gobuster(gob)
    paths = [x["path"] for x in f]
    ok = (paths == ["/admin", "/phpMyAdmin"]          # decoded, bad row skipped
          and f[0]["status"] == 200
          and len(g) == 1 and g[0]["status"] == 301 and g[0]["redirect"] == "/admin/"
          and len(BUILTIN_WORDLIST) > 100)
    tool = ContentDiscovery.detect_tool() or "none (python fallback)"
    return ok, f"ffuf+gobuster parsers OK | {len(BUILTIN_WORDLIST)} builtin words | tool: {tool}"


def c_tasktree():
    import shutil
    from modules.tasktree import TaskTree, DONE
    test_dir = os.path.join("data", "engagements")
    had_dir = os.path.isdir(test_dir)
    t = TaskTree("_selftest_target")
    t.ingest(nuclei=[{"template_id": "CVE-X", "name": "Test Finding",
                      "severity": "CRITICAL", "matched_at": "h:1"}])
    n1 = len(t.leads)
    t.save()
    lead_id = next(iter(t.leads))
    t.set_status(lead_id, DONE, note="tested")   # set_status persists on its own now

    # Reload fresh — must survive a "restart".
    t2 = TaskTree("_selftest_target")
    persisted = t2.leads.get(lead_id, {}).get("status") == DONE

    # Re-ingest the same finding — must not duplicate or reopen the done lead.
    t2.ingest(nuclei=[{"template_id": "CVE-X", "name": "Test Finding",
                       "severity": "CRITICAL", "matched_at": "h:1"}])
    idempotent = len(t2.leads) == n1 and t2.leads[lead_id]["status"] == DONE

    # Cleanup: remove only the file we created, not the whole directory.
    try:
        os.remove(t.path)
        if not had_dir and not os.listdir(test_dir):
            os.rmdir(test_dir)
    except OSError:
        pass

    ok = n1 == 1 and persisted and idempotent
    return ok, f"1 lead created, persisted across reload: {persisted}, rescan idempotent: {idempotent}"


def c_redos_guard():
    """Adversarial-input timing guard for the regexes that scan raw target/AI
    output. These three previously exhibited O(n^2) backtracking (multi-minute
    hangs on hostile input) before being bounded — this pins that fix."""
    import re
    import time
    from modules.pathtraversal import _SIGNATURES
    from modules.webprobe import _TITLE_RE
    from modules.ai_engine import SilentAI
    from modules.leakfinder import _EXPOSED_PATHS

    budget = 5.0
    cases = []

    t0 = time.time()
    evil = "root:" * 500000
    for _name, rx in _SIGNATURES:
        rx.search(evil)
    cases.append(("pathtraversal /etc/passwd signature", time.time() - t0))

    t0 = time.time()
    _TITLE_RE.search("<title " + "a=1 " * 200000)
    _TITLE_RE.search("<title" * 200000)
    cases.append(("webprobe title regex", time.time() - t0))

    t0 = time.time()
    SilentAI._parse_payload_list("text " + "[" * 2000000, 12)
    cases.append(("ai_engine payload bracket scan", time.time() - t0))

    script_rx = re.compile(r'<script[^>]{1,500}src=["\']([^"\']{1,2000})["\']', re.I)
    t0 = time.time()
    script_rx.search("<script" * 500000)
    cases.append(("leakfinder script-src regex", time.time() - t0))

    htpasswd_rx = dict(_EXPOSED_PATHS)["/.htpasswd"]
    t0 = time.time()
    re.compile(htpasswd_rx).search("a" * 5000000)
    cases.append(("leakfinder htpasswd signature", time.time() - t0))

    slow = [f"{n} ({dt:.2f}s)" for n, dt in cases if dt > budget]
    detail = ", ".join(f"{n}={dt:.3f}s" for n, dt in cases)
    return not slow, (detail if not slow else f"SLOW (>{budget}s): {slow}")


def main():
    console.print("\n[bold green]=== SilentPivot Self-Test ===[/bold green]\n")
    check("CISA KEV catalog", c_kev)
    check("EPSS score (FIRST.org)", c_epss)
    check("Public PoC lookup (GitHub)", c_poc)
    check("Exploit intel end-to-end", c_exploit_full)
    check("NVD CVE query (CPE-based)", c_nvd)
    check("Subdomain multi-source", c_subdomain)
    check("Native port check", c_portcheck)
    check("Web probe & fingerprint", c_webprobe)
    check("Nuclei wrapper (parse)", c_nuclei)
    check("403 bypass techniques", c_bypass403)
    check("Leak/secret regex core", c_leakfinder)
    check("Path traversal signatures", c_pathtraversal)
    check("SSRF signatures", c_ssrf)
    check("AI payload JSON parse", c_ai_payload_parse)
    check("Input validation", c_validators)
    check("Content discovery parsers", c_contentdisco)
    check("Task tree persistence", c_tasktree)
    check("ReDoS guard (adversarial input timing)", c_redos_guard)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    color = "green" if passed == total else ("yellow" if passed else "red")
    console.print(f"[bold {color}]RESULT: {passed}/{total} checks passed[/bold {color}]")
    for name, ok in results:
        mark = "[green][OK][/green]" if ok else "[red][X][/red]"
        console.print(f"  {mark} {name}")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
