import os
import time
import requests

from modules.kev import KevCatalog
from modules.exploits import ExploitIntel


class VulnChecker:
    def __init__(self):
        # NIST NVD (National Vulnerability Database) Public API
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # Optional NVD API key: raises the rate limit from 5/30s to 50/30s.
        self.api_key = os.getenv("NVD_API_KEY", "")
        # Simple cache so the same service+version is not queried twice.
        self._cache = {}
        # CISA KEV: used to flag actively exploited CVEs.
        self.kev = KevCatalog()
        # EPSS / PoC / ExploitDB enrichment.
        self.intel = ExploitIntel()

    def _request(self, params):
        """Rate-limit-friendly, retrying request to NVD."""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        # Without a key NVD recommends 1 request / 6s; with one we can go faster.
        delay = 0.7 if self.api_key else 6.0

        for attempt in range(3):
            time.sleep(delay)
            try:
                resp = requests.get(
                    self.base_url, params=params, headers=headers, timeout=15
                )
            except requests.RequestException:
                continue

            if resp.status_code == 200:
                return resp.json()
            # 403/429 -> rate limit; back off and retry.
            if resp.status_code in (403, 429):
                time.sleep(delay * (attempt + 2))
                continue
            break
        return None

    def _parse_cves(self, data, limit=3):
        """Extract CVE id + CVSS score + severity from an NVD response."""
        cves = []
        for item in data.get("vulnerabilities", [])[:limit]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "?")
            score, severity = self._extract_cvss(cve.get("metrics", {}))
            kev_info = self.kev.lookup(cve_id)
            cves.append({
                "id": cve_id,
                "cvss": score,
                "severity": severity,
                # Present in CISA KEV -> actively exploited (the strongest signal)
                "kev": bool(kev_info),
                "ransomware": kev_info.get("ransomware") if kev_info else None,
            })
        return cves

    @staticmethod
    def _extract_cvss(metrics):
        """Find score and severity in order: CVSS v3.1 > v3.0 > v2."""
        for key in ("cvssMetricV31", "cvssMetricV30"):
            if metrics.get(key):
                d = metrics[key][0]["cvssData"]
                return d.get("baseScore"), d.get("baseSeverity", "UNKNOWN")
        if metrics.get("cvssMetricV2"):
            m = metrics["cvssMetricV2"][0]
            return m["cvssData"].get("baseScore"), m.get("baseSeverity", "UNKNOWN")
        return None, "UNKNOWN"

    def check_vulnerabilities(self, scan_results):
        enriched_results = []

        for result in scan_results:
            cpe = result.get("cpe", "")
            service = result.get("service", "")
            version = result.get("version", "")

            # 1) Query by CPE first (most accurate method).
            # 2) If no CPE, fall back to service+version keyword search.
            if cpe:
                cache_key = cpe
                params = {"cpeName": self._normalize_cpe(cpe), "resultsPerPage": 3}
            elif version and version != "unknown":
                cache_key = f"{service} {version}"
                params = {"keywordSearch": cache_key, "resultsPerPage": 3}
            else:
                result["cve_data"] = "Version/CPE unknown, vulnerability scan skipped."
                result["cves"] = []
                enriched_results.append(result)
                continue

            if cache_key in self._cache:
                cves = self._cache[cache_key]
            else:
                data = self._request(params)
                cves = self._parse_cves(data) if data else None
                self._cache[cache_key] = cves

            if cves is None:
                result["cve_data"] = "Could not reach the vulnerability database."
                result["cves"] = []
            elif cves:
                summary = ", ".join(
                    f"{c['id']} (CVSS {c['cvss']}/{c['severity']}"
                    + (", ACTIVELY EXPLOITED/KEV" if c.get("kev") else "")
                    + ")"
                    for c in cves
                )
                result["cve_data"] = f"VERIFIED VULNERABILITIES: {summary}"
                result["cves"] = cves
            else:
                result["cve_data"] = "No known CVE found."
                result["cves"] = []

            enriched_results.append(result)

        # Add exploit intelligence (EPSS probability, public PoCs, ExploitDB).
        self.intel.enrich(enriched_results)
        return enriched_results

    @staticmethod
    def _normalize_cpe(cpe):
        """Nmap gives 'cpe:/a:apache:http_server:2.4.49'; NVD wants the 2.3 format.
        cpe:/a:apache:http_server:2.4.49 -> cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
        """
        if cpe.startswith("cpe:2.3:"):
            return cpe
        if cpe.startswith("cpe:/"):
            body = cpe[len("cpe:/"):]
            parts = body.split(":")
            # cpe 2.3 expects exactly 11 fields; pad the missing ones with '*'.
            while len(parts) < 11:
                parts.append("*")
            return "cpe:2.3:" + ":".join(parts)
        return cpe
