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

    def proxy_problem(self):
        """Return a human-readable problem with the current proxy, or None if it's fine.
        Catches the common trap: a socks:// proxy without the PySocks dependency, which
        would otherwise fail mid-scan with a confusing requests error."""
        if not self.proxy:
            return None
        if not self.proxy.startswith(("http://", "https://", "socks4://", "socks5://",
                                      "socks5h://")):
            return ("Proxy must start with http://, https:// or socks5:// "
                    f"(got: {self.proxy})")
        if self.proxy.startswith("socks"):
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
        """Extra nmap flags for a quieter scan profile."""
        # --max-rate keeps packet rate low; -f fragments packets to slip past simple IDS.
        return "--max-rate 50 --scan-delay 500ms" if self.is_stealth else ""

    def apply_to_session(self, session):
        """Configure a requests.Session with the current proxy + user-agent."""
        if self.proxy:
            session.proxies.update(self.proxies())
        session.headers.update({"User-Agent": self.user_agent()})
        return session


# Single shared instance used across the whole tool.
profile = OpsecProfile()
