"""Live end-to-end checks against real data sources — opt-in.

Skipped by default (the `live` marker is excluded in pyproject's addopts) so the
standard `pytest` run stays offline and deterministic. Run them explicitly with:

    pytest -m live

They need network connectivity; a firewalled/guest network can make them fail for
reasons unrelated to the code (this is why they are not in CI).
"""
import pytest

pytestmark = pytest.mark.live


def test_kev_catalog_has_log4shell():
    from silentpivot.kev import KevCatalog
    hit = KevCatalog().lookup("CVE-2021-44228")
    assert hit and hit.get("name")


def test_epss_score_for_log4shell():
    from silentpivot.exploits import ExploitIntel
    epss = ExploitIntel()._epss_batch(["CVE-2021-44228"])
    v = epss.get("CVE-2021-44228", {}).get("epss")
    assert v is not None and v > 0.5


def test_public_poc_lookup():
    from silentpivot.exploits import ExploitIntel
    _, data = ExploitIntel()._poc_one("CVE-2021-44228")
    assert data["count"] > 0


def test_nvd_cve_query():
    from silentpivot.vuln_checker import VulnChecker
    vc = VulnChecker()
    data = vc._request({"cpeName": vc._normalize_cpe("cpe:/a:apache:http_server:2.4.49"),
                        "resultsPerPage": 3})
    assert data and len(data.get("vulnerabilities", [])) > 0


def test_subdomain_passive_sources():
    from silentpivot.subdomain import SubdomainScanner
    s = SubdomainScanner()
    subs = s._gather_passive("nmap.org")
    assert len(subs) > 0


def test_web_probe_fingerprint():
    from silentpivot.webprobe import WebProber
    res = WebProber(timeout=10).probe_host("wordpress.com", ports=[443])
    assert res and res[0]["status"] == 200 and res[0]["tech"]
