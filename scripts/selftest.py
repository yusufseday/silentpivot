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
    hit = SSRFScanner._check("ami-id\ninstance-id\niam/security-credentials/")
    clean = SSRFScanner._check("<html>welcome</html>")
    ok = hit and hit[0] == "AWS metadata" and clean is None
    return ok, f"AWS-metadata signature -> {hit[0] if hit else None}, clean -> {clean}"


def c_ai_payload_parse():
    from modules.ai_engine import SilentAI
    got = SilentAI._parse_payload_list('text ["http://127.0.0.1/","gopher://x"] tail', 12)
    return len(got) == 2, f"parsed {got} (bad input -> {SilentAI._parse_payload_list('none', 12)})"


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
