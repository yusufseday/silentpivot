"""Subdomain discovery — hybrid engine.

Strategy (best result on any machine, no keys required):
  1. If an external tool (subfinder / amass) is on PATH, run it — these aggregate
     dozens of sources and are the industry standard (common on Kali).
  2. In parallel, always query several keyless passive OSINT sources and merge:
     crt.sh, certspotter, AlienVault OTX, HackerTarget, Anubis (jldc).
  3. Deduplicate, then resolve via DNS to flag which subdomains are live.

Everything is passive (no packets sent to the target) except the final DNS
resolution, which is optional.
"""
import shutil
import socket
import subprocess
import concurrent.futures

import requests

# External tools tried in order of preference (cleaner output first).
EXTERNAL_TOOLS = ("subfinder", "amass")
TOOL_TIMEOUT = 120  # seconds


class SubdomainScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SilentPivot"})
        # Populated after scan(): {"method": ..., "sources": {name: count}}
        self.stats = {"method": None, "sources": {}}

    # ---------- Public API ----------
    def scan(self, domain, resolve=True):
        """Full flow: gather from all sources -> merge -> (optional) DNS resolve."""
        domain = self._clean_domain(domain)
        found = self._gather(domain)
        subs = sorted(found)
        if not subs:
            return []
        if not resolve:
            return [{"host": s, "ip": None, "live": None} for s in subs]
        return self.resolve_all(subs)

    # ---------- Gathering / merging ----------
    def _gather(self, domain):
        """Run the external tool (if any) and all passive sources concurrently."""
        sources = {
            "crt.sh": self._src_crtsh,
            "certspotter": self._src_certspotter,
            "otx": self._src_otx,
            "hackertarget": self._src_hackertarget,
            "anubis": self._src_anubis,
        }
        tool = self.detect_tool()

        merged = set()
        counts = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(fn, domain): name for name, fn in sources.items()}
            if tool:
                futures[ex.submit(self._run_external, tool, domain)] = tool
            for fut in concurrent.futures.as_completed(futures):
                name = futures[fut]
                try:
                    subs = fut.result() or set()
                except Exception:
                    subs = set()
                # Keep only names that actually belong to the target domain.
                subs = {s for s in subs if s == domain or s.endswith("." + domain)}
                counts[name] = len(subs)
                merged |= subs

        self.stats = {
            "method": tool if tool else "passive-only",
            "tool": tool,
            "sources": counts,
            "total": len(merged),
        }
        return merged

    # ---------- External tools ----------
    @staticmethod
    def detect_tool():
        for name in EXTERNAL_TOOLS:
            if shutil.which(name):
                return name
        return None

    def _run_external(self, tool, domain):
        if tool == "subfinder":
            cmd = [tool, "-d", domain, "-silent"]
        else:  # amass passive enumeration
            cmd = [tool, "enum", "-passive", "-d", domain]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT
            )
        except (subprocess.TimeoutExpired, OSError):
            return set()
        out = set()
        for line in proc.stdout.splitlines():
            line = line.strip().lower().lstrip("*.")
            if line and "@" not in line:
                out.add(line)
        return out

    # ---------- Passive OSINT sources (keyless) ----------
    def _get(self, url, **kw):
        kw.setdefault("timeout", 25)
        return self.session.get(url, **kw)

    def _src_crtsh(self, domain):
        out = set()
        resp = self._get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
        if resp.status_code == 200 and resp.text.strip():
            for entry in resp.json():
                for name in entry.get("name_value", "").splitlines():
                    out.add(name.strip().lower().lstrip("*."))
        return out

    def _src_certspotter(self, domain):
        out = set()
        url = "https://api.certspotter.com/v1/issuances"
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        resp = self._get(url, params=params)
        if resp.status_code == 200:
            for cert in resp.json():
                for name in cert.get("dns_names", []):
                    out.add(name.strip().lower().lstrip("*."))
        return out

    def _src_otx(self, domain):
        out = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        resp = self._get(url)
        if resp.status_code == 200:
            for rec in resp.json().get("passive_dns", []):
                host = rec.get("hostname", "").strip().lower()
                if host:
                    out.add(host)
        return out

    def _src_hackertarget(self, domain):
        out = set()
        resp = self._get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
        # Returns "host,ip" lines; on rate limit it returns an error message instead.
        if resp.status_code == 200 and "," in resp.text and "API" not in resp.text:
            for line in resp.text.splitlines():
                host = line.split(",", 1)[0].strip().lower()
                if host:
                    out.add(host)
        return out

    def _src_anubis(self, domain):
        out = set()
        resp = self._get(f"https://jldc.me/anubis/subdomains/{domain}")
        if resp.status_code == 200:
            for name in resp.json():
                out.add(str(name).strip().lower().lstrip("*."))
        return out

    # ---------- DNS resolution ----------
    @staticmethod
    def _resolve(host):
        try:
            return host, socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError):
            return host, None

    def resolve_all(self, hosts, max_workers=50):
        """Resolve the subdomain list via parallel DNS; flag the live ones."""
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for host, ip in ex.map(self._resolve, hosts):
                results.append({"host": host, "ip": ip, "live": ip is not None})
        return sorted(results, key=lambda r: r["host"])

    # ---------- Helpers ----------
    @staticmethod
    def _clean_domain(domain):
        domain = domain.strip().lower()
        for prefix in ("http://", "https://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0].lstrip("*.")
