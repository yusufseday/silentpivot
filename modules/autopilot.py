"""Autopilot — the full engagement pipeline in one command.

Chains: Nmap -> CVE/KEV/EPSS/Exploit -> Web probe -> Nuclei -> AI -> unified report.
Each stage is isolated in its own try/except so one failure degrades gracefully
instead of aborting the whole run.
"""
from modules.scanner import NetworkScanner
from modules.vuln_checker import VulnChecker
from modules.webprobe import WebProber, WEB_PORTS
from modules.nuclei import NucleiScanner
from modules.ai_engine import SilentAI
from modules import reporter

SCAN_LABELS = {
    "1": "Fast (Top 100)",
    "2": "Standard (1-1000 + version)",
    "3": "Deep (All ports + OS)",
}


def run_autopilot(target, scan_type="2", use_ai=True, use_nuclei=True,
                  nuclei_severities=("medium", "high", "critical"), log=None):
    """Run the full pipeline against a single target. Returns a unified report dict,
    or None if the target has no open ports / is down."""
    log = log or (lambda m: None)

    # [1] Nmap
    log("[1/5] Nmap scan...")
    try:
        results = NetworkScanner().scan_target(target, scan_type)
    except Exception as e:
        log(f"nmap failed: {e}")
        results = []
    if not results:
        return None

    # [2] CVE / KEV / EPSS / exploit intel (VulnChecker chains ExploitIntel internally)
    log("[2/5] CVE / KEV / EPSS / exploit enrichment...")
    try:
        enriched = VulnChecker().check_vulnerabilities(results)
    except Exception as e:
        log(f"vulnerability enrichment failed: {e}")
        enriched = results

    # [3] Web probe on the open web ports found by nmap
    log("[3/5] Web probing...")
    web = []
    web_ports = [r["port"] for r in enriched if r.get("port") in WEB_PORTS]
    if web_ports:
        try:
            web = WebProber().probe_host(target, ports=web_ports)
        except Exception as e:
            log(f"web probe failed: {e}")
    else:
        log("      no web ports open — skipping web probe")

    # [4] Nuclei on the discovered web endpoints
    log("[4/5] Nuclei active scan...")
    nuclei, nuclei_meta = [], {}
    ns = NucleiScanner()
    if not use_nuclei:
        log("      nuclei disabled")
    elif not ns.available:
        log("      nuclei not installed — skipping (install for active scanning)")
    elif not web:
        log("      no web endpoints — skipping nuclei")
    else:
        try:
            urls = [w["url"] for w in web]
            nuclei = ns.scan(urls, severities=nuclei_severities) or []
            nuclei_meta = ns.meta
        except Exception as e:
            log(f"nuclei failed: {e}")

    # [5] AI engagement analysis over everything
    analysis = None
    if use_ai:
        log("[5/5] AI analysis...")
        try:
            analysis = SilentAI().analyze_engagement(enriched, web, nuclei)
        except Exception as e:
            log(f"AI analysis failed: {e}")
    else:
        log("[5/5] AI analysis skipped")

    return reporter.build_report_data(
        target, SCAN_LABELS.get(scan_type, scan_type), enriched, analysis,
        web=web, nuclei=nuclei, nuclei_meta=nuclei_meta,
    )
