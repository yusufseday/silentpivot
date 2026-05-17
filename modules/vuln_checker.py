import requests
import time


class VulnChecker:
    def __init__(self):
        # NIST NVD (National Vulnerability Database) Public API
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def check_vulnerabilities(self, scan_results):
        enriched_results = []

        for result in scan_results:
            service = result.get('service', '')
            version = result.get('version', '')

            # Versiyon bilinmiyorsa veritabanını yormaya gerek yok
            if version == "Bilinmiyor" or not version:
                result['cve_data'] = "Versiyon bilinmediği için zafiyet taraması yapılamadı."
                enriched_results.append(result)
                continue

            keyword = f"{service} {version}"
            params = {
                "keywordSearch": keyword,
                "resultsPerPage": 3  # En kritik 3 zafiyeti al
            }

            try:
                # API hız sınırına (rate limit) takılmamak için 1 saniye bekleme
                time.sleep(1)
                response = requests.get(self.base_url, params=params, timeout=10)

                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulnerabilities", [])

                    if vulns:
                        cve_list = []
                        for item in vulns:
                            cve_id = item["cve"]["id"]
                            cve_list.append(cve_id)
                        result['cve_data'] = f"DOĞRULANMIŞ ZAFİYETLER: {', '.join(cve_list)}"
                    else:
                        result['cve_data'] = "Bilinen bir CVE bulunamadı."
                else:
                    result['cve_data'] = "Zafiyet veritabanına erişilemedi."
            except Exception as e:
                result['cve_data'] = "Zafiyet sorgusunda hata oluştu."

            enriched_results.append(result)

        return enriched_results