import os
import time
import requests


class VulnChecker:
    def __init__(self):
        # NIST NVD (National Vulnerability Database) Public API
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        # Opsiyonel NVD API anahtarı: varsa rate limit 5/30sn -> 50/30sn olur.
        self.api_key = os.getenv("NVD_API_KEY", "")
        # Aynı servis+versiyon tekrar sorgulanmasın diye basit önbellek.
        self._cache = {}

    def _request(self, params):
        """NVD'ye rate-limit'e saygılı, tekrar denemeli istek."""
        headers = {"apiKey": self.api_key} if self.api_key else {}
        # Anahtar yoksa NVD 6 saniyede 1 istek önerir; varsa daha sık sorulabilir.
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
            # 403/429 -> rate limit; artan bekleme ile tekrar dene.
            if resp.status_code in (403, 429):
                time.sleep(delay * (attempt + 2))
                continue
            break
        return None

    def _parse_cves(self, data, limit=3):
        """NVD yanıtından CVE id + CVSS skoru + severity çıkar."""
        cves = []
        for item in data.get("vulnerabilities", [])[:limit]:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "?")
            score, severity = self._extract_cvss(cve.get("metrics", {}))
            cves.append({"id": cve_id, "cvss": score, "severity": severity})
        return cves

    @staticmethod
    def _extract_cvss(metrics):
        """CVSS v3.1 > v3.0 > v2 sırasıyla skoru ve severity'yi bul."""
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

            # 1) Önce CPE ile sorgula (en isabetli yöntem).
            # 2) CPE yoksa servis+versiyon anahtar araması (fallback).
            if cpe:
                cache_key = cpe
                params = {"cpeName": self._normalize_cpe(cpe), "resultsPerPage": 3}
            elif version and version != "Bilinmiyor":
                cache_key = f"{service} {version}"
                params = {"keywordSearch": cache_key, "resultsPerPage": 3}
            else:
                result["cve_data"] = "Versiyon/CPE bilinmediği için zafiyet taraması yapılamadı."
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
                result["cve_data"] = "Zafiyet veritabanına erişilemedi."
                result["cves"] = []
            elif cves:
                summary = ", ".join(
                    f"{c['id']} (CVSS {c['cvss']}/{c['severity']})" for c in cves
                )
                result["cve_data"] = f"DOĞRULANMIŞ ZAFİYETLER: {summary}"
                result["cves"] = cves
            else:
                result["cve_data"] = "Bilinen bir CVE bulunamadı."
                result["cves"] = []

            enriched_results.append(result)

        return enriched_results

    @staticmethod
    def _normalize_cpe(cpe):
        """Nmap 'cpe:/a:apache:http_server:2.4.49' verir; NVD 2.3 formatı ister.
        cpe:/a:apache:http_server:2.4.49 -> cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
        """
        if cpe.startswith("cpe:2.3:"):
            return cpe
        if cpe.startswith("cpe:/"):
            body = cpe[len("cpe:/"):]
            parts = body.split(":")
            # cpe 2.3 tam 11 alan bekler; eksikleri '*' ile doldur.
            while len(parts) < 11:
                parts.append("*")
            return "cpe:2.3:" + ":".join(parts)
        return cpe
