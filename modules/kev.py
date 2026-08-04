import os
import json
import time
import requests

# CISA Known Exploited Vulnerabilities (KEV) — the official catalog of CVEs
# actively exploited in the wild. No key required, a single JSON file.
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# The catalog updates once a day; treat the local cache as fresh for 24 hours.
_CACHE_TTL = 24 * 3600


class KevCatalog:
    """Downloads the CISA KEV catalog, caches it locally, and offers CVE lookup."""

    def __init__(self, cache_dir="data"):
        self.cache_path = os.path.join(cache_dir, ".kev_cache.json")
        self._index = None  # cve_id -> {ransomware, date_added, name}

    def _load(self):
        if self._index is not None:
            return self._index

        catalog = self._read_cache() or self._fetch()
        self._index = {}
        if catalog:
            for v in catalog.get("vulnerabilities", []):
                cve_id = v.get("cveID")
                if cve_id:
                    self._index[cve_id] = {
                        "date_added": v.get("dateAdded", ""),
                        "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
                        "name": v.get("vulnerabilityName", ""),
                    }
        return self._index

    def _read_cache(self):
        try:
            if os.path.exists(self.cache_path):
                age = time.time() - os.path.getmtime(self.cache_path)
                if age < _CACHE_TTL:
                    with open(self.cache_path, "r", encoding="utf-8") as f:
                        return json.load(f)
        except Exception:
            pass
        return None

    def _fetch(self):
        try:
            resp = requests.get(KEV_URL, timeout=20)
            if resp.status_code == 200:
                data = resp.json()
                try:
                    os.makedirs(os.path.dirname(self.cache_path), exist_ok=True)
                    with open(self.cache_path, "w", encoding="utf-8") as f:
                        json.dump(data, f)
                except Exception:
                    pass  # if the cache can't be written, fine — keep it in memory
                return data
        except requests.RequestException:
            pass
        return None

    def lookup(self, cve_id):
        """Return a detail dict if the CVE is actively exploited, else None."""
        return self._load().get(cve_id)
