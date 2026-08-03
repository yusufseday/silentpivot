"""OPSEC profile — central control over the tool's footprint.

Red-team work is judged as much by *not being caught* as by what is found. This module
holds one shared profile that every other module consults, so timing, proxying and
user-agent behaviour stay consistent across nmap, HTTP probing, nuclei and the active
scanners.

Profiles:
  normal   — default; today's behaviour, unchanged (fast, direct).
  stealth  — slow nmap timing, randomized delay (jitter) between HTTP requests,
             rotating browser user-agents, optional proxy.
  passive  — no packets to the target at all: only public OSINT sources are used.

Proxy comes from the OPSEC profile or the standard HTTP(S)_PROXY / SP_PROXY env vars.
"""
import os
import time
import random

import urllib3

# fetch() sends verify=False (pentest targets routinely use self-signed certs), so the
# matching warning is silenced here rather than in every calling module.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Realistic browser UAs, rotated in stealth mode so requests don't share one signature.
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36",
]
_DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) SilentPivot/1.0"

NORMAL, STEALTH, PASSIVE = "normal", "stealth", "passive"

# Hard cap on how much of a response body we read. Recon never needs more, and a
# hostile host (or a defensive tarpit) can otherwise stream data until we run out of
# memory. Applied by fetch() below, which every HTTP module goes through.
MAX_BODY_BYTES = 5_000_000




class OpsecProfile:
    """Shared, mutable profile. Import the module-level `profile` singleton."""

    def __init__(self):
        self.mode = NORMAL
        # Proxy honoured in every mode when set (env vars are picked up automatically).
        self.proxy = os.getenv("SP_PROXY") or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY") or ""
        # Jitter bounds (seconds) applied between HTTP requests in stealth mode.
        self.jitter = (1.5, 4.0)
        self.max_workers_stealth = 3   # low concurrency = low noise

    # ---------- state ----------
    @property
    def is_stealth(self):
        return self.mode == STEALTH

    @property
    def is_passive(self):
        return self.mode == PASSIVE

    def set_mode(self, mode):
        if mode in (NORMAL, STEALTH, PASSIVE):
            self.mode = mode

    def set_proxy(self, proxy):
        self.proxy = (proxy or "").strip()

    def proxy_problem(self, candidate=None):
        """Return a human-readable problem with a proxy value, or None if it's fine.
        Pass `candidate` to validate a value BEFORE assigning it, so a rejected or
        interrupted entry can never leave a broken proxy configured.
        Catches the common trap: a socks:// proxy without the PySocks dependency, which
        would otherwise fail mid-scan with a confusing requests error."""
        proxy = self.proxy if candidate is None else (candidate or "").strip()
        if not proxy:
            return None
        if not proxy.startswith(("http://", "https://", "socks4://", "socks5://",
                                 "socks5h://")):
            return ("Proxy must start with http://, https:// or socks5:// "
                    f"(got: {proxy})")
        if proxy.startswith("socks"):
            try:
                import socks  # noqa: F401  (PySocks, pulled in by requests[socks])
            except ImportError:
                return ("SOCKS proxy needs PySocks — install it with: "
                        "pip install 'requests[socks]'")
        return None

    def summary(self):
        """One-line status for the panel."""
        proxy = self.proxy if self.proxy else "direct"
        return f"{self.mode} · proxy: {proxy}"

    # ---------- behaviour the other modules ask for ----------
    def proxies(self):
        """requests-style proxies dict (empty when no proxy configured)."""
        return {"http": self.proxy, "https": self.proxy} if self.proxy else {}

    def user_agent(self):
        return random.choice(_USER_AGENTS) if self.is_stealth else _DEFAULT_UA

    def workers(self, normal_workers):
        """Cap concurrency in stealth mode — parallel bursts are what IDS notices."""
        return min(normal_workers, self.max_workers_stealth) if self.is_stealth else normal_workers

    def wait(self):
        """Random delay between requests (stealth only); no-op otherwise."""
        if self.is_stealth:
            time.sleep(random.uniform(*self.jitter))

    def nmap_timing(self):
        """Nmap timing template: -T1 (sneaky) in stealth, -T4 (fast) normally."""
        return "-T1" if self.is_stealth else "-T4"

    def nmap_extra(self):
        """Extra nmap flags for a quieter scan profile / proxy compatibility."""
        flags = []
        if self.is_stealth:
            # Keep the packet rate low and space out probes.
            flags.append("--max-rate 50 --scan-delay 500ms")
        if self.proxy:
            # Raw SYN scans cannot be proxied. -sT (TCP connect) is the only mode that
            # works when the user wraps the tool in proxychains, so prefer it whenever a
            # proxy is configured — otherwise the scan would silently bypass the proxy.
            flags.append("-sT")
        return " ".join(flags)

    # Proxying nmap is NOT possible from inside this process: nmap opens its own raw
    # sockets, so a requests-level proxy never sees that traffic.
    def covers_nmap(self):
        """Whether the configured proxy also covers nmap traffic. It does not —
        unless the whole tool is launched under proxychains."""
        return bool(os.getenv("PROXYCHAINS_CONF_FILE") or os.getenv("LD_PRELOAD", "").find("proxychains") >= 0)

    def nmap_proxy_warning(self):
        """Explain the nmap/proxy gap, or None when there's nothing to warn about."""
        if not self.proxy or self.covers_nmap():
            return None
        return ("Proxy applies to HTTP modules only — nmap sends its own packets and "
                "would reveal your real IP. To proxy everything, launch the tool with "
                "proxychains:  proxychains4 python silentpivot.py")

    def fetch(self, session, url, **kwargs):
        """GET with a bounded body. Returns a requests.Response whose .text/.content
        hold at most MAX_BODY_BYTES, so a hostile host (or a defensive tarpit) can't
        stream data until we run out of memory. Raises the usual requests exceptions."""
        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("verify", False)     # pentest targets often use self-signed certs
        resp = session.get(url, stream=True, **kwargs)
        body = bytearray()
        try:
            for chunk in resp.iter_content(65536):
                body.extend(chunk)
                if len(body) >= MAX_BODY_BYTES:
                    break
        finally:
            resp.close()
        # Hand the capped bytes back to requests so .text / .content behave normally.
        resp._content = bytes(body)
        resp._content_consumed = True
        return resp

    def apply_to_session(self, session):
        """Configure a requests.Session with the current proxy + user-agent."""
        if self.proxy:
            session.proxies.update(self.proxies())
        session.headers.update({"User-Agent": self.user_agent()})
        return session


# Single shared instance used across the whole tool.
profile = OpsecProfile()
