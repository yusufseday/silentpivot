"""Leak / secret finder (OSINT) — deterministic, evidence-based.

Two capabilities:
  1. Secret scan  — fetch the page + its same-origin JS, regex-hunt for exposed
     API keys / tokens / private keys (well-known provider formats).
  2. Exposed files — probe common sensitive paths (/.git/config, /.env, backups…)
     and confirm real hits by content signature or a difference from the 404 baseline.

Every finding is backed by concrete evidence (a matched pattern / a real file), never
a guess. An optional AI false-positive filter can be layered on top later.
"""
import re
import concurrent.futures
from urllib.parse import urlparse, urljoin

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# provider-format tokens are distinctive (low false-positive); "Generic" is broad (low confidence).
_SECRET_PATTERNS = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "high"),
    "Google API Key": (r"AIza[0-9A-Za-z_\-]{35}", "high"),
    "Slack Token": (r"xox[baprs]-[0-9A-Za-z-]{10,48}", "high"),
    "Slack Webhook": (r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "high"),
    "GitHub Token": (r"gh[pousr]_[0-9A-Za-z]{36,}", "high"),
    "GitLab Token": (r"glpat-[0-9A-Za-z_\-]{20}", "high"),
    "Stripe Key": (r"[sr]k_live_[0-9A-Za-z]{20,}", "high"),
    "Twilio SID": (r"AC[0-9a-f]{32}", "high"),
    "Mailgun Key": (r"key-[0-9a-f]{32}", "high"),
    "Private Key": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "high"),
    "JWT": (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", "medium"),
    "Generic Secret": (r"(?i)(?:api[_-]?key|secret|passwd|password|token)"
                       r"['\"]?\s*[:=]\s*['\"][0-9A-Za-z_\-]{12,}['\"]", "low"),
}
_COMPILED = {n: (re.compile(p), c) for n, (p, c) in _SECRET_PATTERNS.items()}
# skip obvious non-secrets (documentation placeholders)
_PLACEHOLDER = re.compile(r"(?i)example|xxxx+|your[_-]?|placeholder|sample|dummy|changeme|<[a-z]")

# (path, signature-regex or None). None => confirmed via difference from the 404 baseline.
_EXPOSED_PATHS = [
    ("/.git/config", r"\[core\]|repositoryformatversion"),
    ("/.git/HEAD", r"ref:\s*refs/"),
    ("/.env", r"(?m)^[A-Z0-9_]{2,}="),
    ("/.htpasswd", r"[^:\s]+:[^:\s]+"),
    ("/.svn/entries", r"svn|^\d+$"),
    ("/.DS_Store", r"Bud1|\x00"),
    ("/server-status", r"Apache Server Status"),
    ("/phpinfo.php", r"PHP Version|phpinfo\(\)"),
    ("/config.php.bak", None),
    ("/config.php~", None),
    ("/wp-config.php.bak", None),
    ("/backup.zip", None),
    ("/backup.tar.gz", None),
    ("/db.sql", None),
    ("/database.sql", None),
    ("/dump.sql", None),
    ("/.aws/credentials", r"aws_access_key_id|\[default\]"),
]


class LeakFinder:
    def __init__(self, timeout=8, max_workers=15):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 SilentPivot"})

    # ---------- helpers ----------
    def _get(self, url):
        try:
            return self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
        except requests.RequestException:
            return None

    @staticmethod
    def _mask(value):
        v = value.strip()
        if len(v) <= 12:
            return v[:2] + "****"
        return f"{v[:6]}…{v[-4:]}"

    # ---------- secret scan ----------
    def scan_secrets(self, url):
        resp = self._get(url)
        if resp is None:
            return []
        origin = urlparse(url)
        contents = [(url, resp.text)]

        # collect same-origin JS files referenced by the page
        js = set()
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.I):
            ju = urljoin(url, m.group(1))
            if urlparse(ju).netloc == origin.netloc:
                js.add(ju)
        js = list(js)[:25]
        if js:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
                for ju, r in zip(js, ex.map(self._get, js)):
                    if r is not None:
                        contents.append((ju, r.text))

        findings, seen = [], set()
        for src, text in contents:
            for name, (pat, conf) in _COMPILED.items():
                for m in pat.finditer(text or ""):
                    val = m.group(0)
                    if _PLACEHOLDER.search(val):
                        continue
                    key = (name, val)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({"type": name, "value": self._mask(val),
                                     "confidence": conf, "source": src})
        return findings

    # ---------- exposed files ----------
    def scan_exposed_files(self, url):
        origin = urlparse(url)
        base = f"{origin.scheme}://{origin.netloc}"
        # baseline: a random path to learn the server's "not found" behaviour
        baseline = self._get(base + "/silentpivot_nope_" + "x9z8q7")
        base_status = baseline.status_code if baseline else None
        base_len = len(baseline.content) if baseline else -1

        def probe(entry):
            path, sig = entry
            r = self._get(base + path)
            if r is None or r.status_code != 200:
                return None
            body = r.text
            if sig:
                if not re.search(sig, body):
                    return None
                conf = "high"
            else:
                # No signature: only a hit if it differs from the catch-all 404 page.
                if base_status == 200 and abs(len(r.content) - base_len) < 32:
                    return None
                conf = "medium"
            return {"path": path, "url": base + path, "size": len(r.content),
                    "confidence": conf}

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            for res in ex.map(probe, _EXPOSED_PATHS):
                if res:
                    results.append(res)
        return results

    def run(self, url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return {"url": url, "secrets": self.scan_secrets(url),
                "exposed": self.scan_exposed_files(url)}
