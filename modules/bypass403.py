"""403/401 bypass — try well-known access-control bypass techniques against a
forbidden URL and report which ones return a success/redirect instead.

Techniques: header spoofing (X-Forwarded-For, X-Original-URL, ...), path mutations
(trailing chars, encodings, `..;/`, case), and HTTP method changes. All requests are
active — run only against authorized targets. TLS verification is disabled because
pentest targets often use self-signed certificates.
"""
import concurrent.futures
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Headers that back-ends / proxies sometimes trust for access decisions.
_IP_HEADERS = [
    "X-Forwarded-For", "X-Forwarded-Host", "X-Originating-IP", "X-Remote-IP",
    "X-Remote-Addr", "X-Client-IP", "X-Real-IP", "X-Host", "X-Custom-IP-Authorization",
    "X-Forwarded-Server", "X-Forwarded-Scheme",
]
# Path suffixes/prefixes and mutations that can slip past path-based rules.
_PATH_SUFFIXES = ["/", "/.", "//", "/./", "/..;/", "/;/", "%20", "%09", "?", "#",
                  ".json", "/~", "/*", "%2e", "..%2f"]
_PATH_PREFIXES = ["//", "/./", "/%2e/"]
_METHODS = ["POST", "PUT", "HEAD", "OPTIONS", "PATCH", "TRACE"]


class Bypass403:
    def __init__(self, timeout=8, max_workers=20):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 SilentPivot"})

    def _req(self, method, url, headers=None):
        try:
            resp = self.session.request(
                method, url, headers=headers, timeout=self.timeout,
                verify=False, allow_redirects=False,
            )
            return resp.status_code, len(resp.content)
        except requests.RequestException:
            return None

    def _build_attempts(self, url):
        """Yield (technique, method, url, headers) tuples to try."""
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        path = p.path or "/"
        attempts = []

        # 1) Header spoofing (value 127.0.0.1 = pretend to be localhost/internal)
        for h in _IP_HEADERS:
            attempts.append((f"header {h}: 127.0.0.1", "GET", url, {h: "127.0.0.1"}))
        # URL-rewrite headers: request the site root but point the header at the path
        for h in ("X-Original-URL", "X-Rewrite-URL"):
            attempts.append((f"header {h}: {path}", "GET", base + "/", {h: path}))
        attempts.append(("header Referer: <url>", "GET", url, {"Referer": url}))

        # 2) Path mutations
        for s in _PATH_SUFFIXES:
            attempts.append((f"path {path}{s}", "GET", base + path + s, None))
        for pre in _PATH_PREFIXES:
            attempts.append((f"path {pre}{path.lstrip('/')}", "GET",
                             base + pre + path.lstrip("/"), None))
        if path.lower() != path.upper():
            attempts.append(("path UPPERCASE", "GET", base + path.upper(), None))

        # 3) HTTP method changes
        for m in _METHODS:
            attempts.append((f"method {m}", m, url, None))

        return attempts

    def _try(self, attempt):
        technique, method, url, headers = attempt
        r = self._req(method, url, headers)
        if r is None:
            return None
        status, length = r
        # A bypass = a success/redirect (< 400) where the baseline was forbidden.
        if status < 400:
            return {"technique": technique, "method": method, "url": url,
                    "status": status, "length": length}
        return None

    def run(self, url):
        """Returns {url, baseline, applicable, hits}. `hits` = techniques that got
        a < 400 response. `applicable` is False if the URL isn't 401/403 to begin with."""
        base = self._req("GET", url)
        baseline = base[0] if base else None
        if baseline not in (401, 403):
            return {"url": url, "baseline": baseline, "applicable": False, "hits": []}

        hits = []
        attempts = self._build_attempts(url)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for res in ex.map(self._try, attempts):
                if res:
                    hits.append(res)
        hits.sort(key=lambda h: h["status"])
        return {"url": url, "baseline": baseline, "applicable": True, "hits": hits}
