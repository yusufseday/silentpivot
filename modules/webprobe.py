"""Web layer probing — HTTP fingerprinting for open web ports.

For each web port it captures: status code, page title, redirect chain, Server /
X-Powered-By headers, content length, detected technologies, and any WAF/CDN.
Pure Python (requests); TLS verification is disabled on purpose because pentest
targets frequently use self-signed certificates.
"""
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ports we treat as web, mapped to the scheme we try first.
WEB_PORTS = {
    80: "http", 8080: "http", 8000: "http", 8081: "http", 8888: "http",
    3000: "http", 5000: "http", 8008: "http",
    443: "https", 8443: "https", 4443: "https",
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

# Technology signatures. Each: name -> {headers, cookies, body}.
# headers: {header_name: regex}, cookies: [cookie_name...], body: [regex...]
TECH_SIGNATURES = {
    "WordPress": {"body": [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress'],
                  "cookies": ["wordpress_", "wp-settings"]},
    "Drupal": {"body": [r"Drupal.settings", r"/sites/all/", r'name="Generator" content="Drupal'],
               "headers": {"X-Generator": r"Drupal"}},
    "Joomla": {"body": [r"/media/jui/", r"joomla", r"/templates/"]},
    "Magento": {"body": [r"/skin/frontend/", r"Mage\.Cookies", r"/static/version\d"]},
    "Laravel": {"cookies": ["laravel_session", "XSRF-TOKEN"]},
    "Django": {"cookies": ["csrftoken", "django"]},
    "PHP": {"headers": {"X-Powered-By": r"PHP"}, "cookies": ["PHPSESSID"]},
    "ASP.NET": {"headers": {"X-Powered-By": r"ASP\.NET", "X-AspNet-Version": r".*"},
                "cookies": ["ASP.NET_SessionId", "ASPSESSIONID"]},
    "Java": {"cookies": ["JSESSIONID"]},
    "Next.js": {"body": [r"__NEXT_DATA__", r"/_next/"], "headers": {"X-Powered-By": r"Next\.js"}},
    "Nuxt.js": {"body": [r"__NUXT__", r"/_nuxt/"]},
    "React": {"body": [r"data-reactroot", r"react\.production\.min\.js"]},
    "Angular": {"body": [r"ng-version=", r"ng-app"]},
    "Vue.js": {"body": [r"data-v-[0-9a-f]{8}", r"vue\.min\.js"]},
    "Express": {"headers": {"X-Powered-By": r"Express"}},
    "Flask/Werkzeug": {"headers": {"Server": r"Werkzeug"}},
    "Nginx": {"headers": {"Server": r"nginx"}},
    "Apache": {"headers": {"Server": r"Apache"}},
    "IIS": {"headers": {"Server": r"IIS|Microsoft-IIS"}},
    "OpenResty": {"headers": {"Server": r"openresty"}},
    "Tomcat": {"headers": {"Server": r"Tomcat|Coyote"}},
}

# WAF / CDN signatures (header name -> regex, or cookie/body markers).
WAF_SIGNATURES = {
    "Cloudflare": {"headers": {"Server": r"cloudflare", "CF-RAY": r".*"}, "cookies": ["__cfduid", "__cf_bm"]},
    "AWS CloudFront": {"headers": {"Via": r"CloudFront", "X-Amz-Cf-Id": r".*"}},
    "Akamai": {"headers": {"Server": r"AkamaiGHost", "X-Akamai-Transformed": r".*"}},
    "Sucuri": {"headers": {"Server": r"Sucuri", "X-Sucuri-ID": r".*"}},
    "Imperva/Incapsula": {"headers": {"X-Iinfo": r".*"}, "cookies": ["incap_ses", "visid_incap"]},
    "F5 BIG-IP": {"cookies": ["BIGipServer", "TS01"]},
    "Fastly": {"headers": {"X-Served-By": r"cache-.*", "Fastly-Debug-Digest": r".*"}},
    "Barracuda": {"cookies": ["barra_counter_session"]},
}


class WebProber:
    def __init__(self, timeout=8):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SilentPivot/1.0",
        })

    def probe_host(self, host, ports=None):
        """Probe web ports on a host. Returns one dict per reachable web endpoint."""
        ports = ports if ports else list(WEB_PORTS.keys())
        results = []
        for port in ports:
            primary = WEB_PORTS.get(port, "http")
            alternate = "https" if primary == "http" else "http"
            for scheme in (primary, alternate):
                r = self._probe_url(f"{scheme}://{host}:{port}")
                if r is not None:
                    results.append(r)
                    break  # one working scheme per port is enough
        return results

    def detect_waf(self, host, ports):
        """Lightweight WAF/CDN check on web ports via response headers.
        Catches WAFs (e.g. Imperva Incapsula) even when nmap sees few ports,
        because it reads the actual response fingerprint, not the port count."""
        wafs = set()
        for r in self.probe_host(host, ports=ports):
            for w in r.get("waf") or []:
                wafs.add(w)
        return sorted(wafs)

    def _probe_url(self, url):
        try:
            resp = self.session.get(
                url, timeout=self.timeout, verify=False, allow_redirects=True
            )
        except requests.RequestException:
            return None

        body = resp.text if resp.encoding else ""
        return {
            "url": url,
            "final_url": resp.url if resp.url != url else None,
            "status": resp.status_code,
            "title": self._title(body),
            "server": resp.headers.get("Server", ""),
            "powered_by": resp.headers.get("X-Powered-By", ""),
            "content_length": len(resp.content),
            "tech": self._match(TECH_SIGNATURES, resp, body),
            "waf": self._match(WAF_SIGNATURES, resp, body),
        }

    @staticmethod
    def _title(body):
        m = _TITLE_RE.search(body or "")
        if not m:
            return ""
        return re.sub(r"\s+", " ", m.group(1)).strip()[:80]

    @staticmethod
    def _match(signatures, resp, body):
        """Return the list of signature names whose markers appear in the response."""
        found = []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookie_names = list(resp.cookies.keys())
        set_cookie = headers.get("set-cookie", "")

        for name, sig in signatures.items():
            hit = False
            for hname, pattern in sig.get("headers", {}).items():
                val = headers.get(hname.lower())
                if val is not None and re.search(pattern, val, re.IGNORECASE):
                    hit = True
                    break
            if not hit:
                for cname in sig.get("cookies", []):
                    if any(cname.lower() in c.lower() for c in cookie_names) \
                            or cname.lower() in set_cookie.lower():
                        hit = True
                        break
            if not hit and body:
                for pattern in sig.get("body", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        hit = True
                        break
            if hit:
                found.append(name)
        return found
