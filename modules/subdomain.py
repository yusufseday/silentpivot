"""Subdomain discovery — deep research engine.

Combines every angle into one pass:
  * Passive OSINT (keyless): crt.sh, certspotter, AlienVault OTX, HackerTarget, Anubis
  * External tools if present: subfinder / amass (industry standard, common on Kali)
  * Active DNS brute-force: a built-in wordlist (or a custom one), with wildcard-DNS
    detection so a catch-all record doesn't create false positives
  * Enrichment: DNS resolution (IP) + HTTP status for every subdomain
  * Subdomain takeover detection: HTTP-fingerprints dangling services (S3, GitHub
    Pages, Heroku, Fastly, Shopify, ...) that can be claimed by an attacker

Passive sources send no packets to the target; brute-force + enrichment are active.
Run against authorized targets only.
"""
import random
import shutil
import socket
import subprocess
import concurrent.futures

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EXTERNAL_TOOLS = ("subfinder", "amass")
TOOL_TIMEOUT = 120

# Built-in brute-force wordlist (common subdomain names). A custom list can be passed.
DEFAULT_WORDLIST = """
www mail ftp localhost webmail smtp pop pop3 imap ns ns1 ns2 ns3 ns4 dns dns1 dns2
mx mx1 email cpanel whm autodiscover autoconfig admin administrator test dev staging
stage prod production api api1 api2 apis app apps mobile m portal vpn remote secure
sso auth login signin account accounts my dashboard panel cpan host server web web1
web2 blog shop store cdn static assets img images media video files download uploads
docs doc wiki support help helpdesk status monitor grafana kibana jenkins gitlab git
svn jira confluence nexus sonar registry docker k8s kube internal intranet extranet
corp office ldap ad exchange owa lync sip voip pbx crm erp hr finance payroll billing
payment pay checkout cart new old beta alpha demo sandbox uat qa preprod backup db
database sql mysql postgres redis mongo elastic search solr proxy gateway gw router
firewall fw vps cloud aws azure gcp s3 storage bucket data analytics stats metrics
grafana prometheus alerts logs log syslog splunk soc ns5 smtp2 mail2 mx2 relay news
forum community events careers jobs partners partner reseller affiliate track click
link go redirect short url api-dev api-staging dev-api staging-api test-api adminpanel
""".split()

# service -> substrings that appear when the pointed-to service is unclaimed.
TAKEOVER_FINGERPRINTS = {
    "AWS S3": ["NoSuchBucket", "The specified bucket does not exist"],
    "GitHub Pages": ["There isn't a GitHub Pages site here"],
    "Heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "Fastly": ["Fastly error: unknown domain"],
    "Shopify": ["Sorry, this shop is currently unavailable"],
    "Tumblr": ["Whatever you were looking for doesn't currently exist"],
    "Bitbucket": ["Repository not found"],
    "Ghost": ["The thing you were looking for is no longer here"],
    "Surge.sh": ["project not found"],
    "Zendesk": ["Help Center Closed"],
    "Pantheon": ["The gods are wise, but do not know of the site which you seek"],
    "Netlify": ["Not Found - Request ID"],
    "Wordpress": ["Do you want to register"],
}


class SubdomainScanner:
    def __init__(self, http_timeout=6):
        self.http_timeout = http_timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 SilentPivot"})
        self.stats = {}
        self._wildcard = False

    # ---------- Public API ----------
    def scan(self, domain, active=True, wordlist=None):
        """Deep flow: passive + external + active brute -> merge -> enrich (IP/HTTP)
        -> takeover check. Returns a rich list of subdomain dicts."""
        domain = self._clean_domain(domain)

        sub_sources = self._gather_passive(domain)          # {sub: set(source names)}
        active_subs = self.brute_force(domain, wordlist) if active else set()

        merged = {}
        for sub, srcs in sub_sources.items():
            merged[sub] = {"sources": set(srcs), "origin": {"passive"}}
        for sub in active_subs:
            e = merged.setdefault(sub, {"sources": set(), "origin": set()})
            e["sources"].add("dns-brute")
            e["origin"].add("active")

        if not merged:
            self._finalize_stats([], set())
            return []

        results = self._enrich(merged)
        self._finalize_stats(results, active_subs)
        return results

    # ---------- Enrichment (resolve + HTTP + takeover) ----------
    def _enrich(self, merged, max_workers=40):
        def one(item):
            host, meta = item
            _, ip = self._resolve(host)
            # Probe HTTP even when the A-record lookup failed: CDN/IPv6-only hosts can
            # still answer over HTTP. Unresolved hosts get a short timeout so a long
            # list of dead names doesn't slow the scan down.
            status, takeover, url = self._http_probe(host, timeout=None if ip else 3)
            origin = meta["origin"]
            origin_str = "both" if origin == {"passive", "active"} else next(iter(origin))
            return {
                "host": host, "ip": ip, "resolved": ip is not None,
                "http_status": status, "takeover": takeover, "url": url,
                "origin": origin_str, "sources": sorted(meta["sources"]),
            }

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for r in ex.map(one, list(merged.items())):
                results.append(r)
        # Most actionable first: takeover candidates, then live HTTP, then resolved,
        # then the rest — alphabetical within each group.
        return sorted(results, key=lambda r: (
            not r.get("takeover"), r.get("http_status") is None, not r["resolved"], r["host"]
        ))

    def _http_probe(self, host, timeout=None):
        """Returns (status, takeover, url) — url is the scheme that actually answered,
        so the UI can link to a URL that really works."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                r = self.session.get(url, timeout=timeout or self.http_timeout,
                                     verify=False, allow_redirects=True)
                return r.status_code, self._match_takeover(r.text[:8000]), url
            except requests.RequestException:
                continue
        return None, None, None

    @staticmethod
    def _match_takeover(body):
        for service, sigs in TAKEOVER_FINGERPRINTS.items():
            if any(sig.lower() in body.lower() for sig in sigs):
                return service
        return None

    # ---------- Active DNS brute-force ----------
    def brute_force(self, domain, wordlist=None, max_workers=80):
        words = wordlist or DEFAULT_WORDLIST
        # Wildcard detection: if a random host resolves, the zone is a catch-all.
        rand = f"sp{random.randint(10**8, 10**9)}"
        _, wildcard_ip = self._resolve(f"{rand}.{domain}")
        self._wildcard = wildcard_ip is not None

        def check(word):
            host = f"{word}.{domain}"
            _, ip = self._resolve(host)
            if ip and ip != wildcard_ip:
                return host
            return None

        found = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            for res in ex.map(check, words):
                if res:
                    found.add(res)
        return found

    # ---------- Passive gather ----------
    def _gather_passive(self, domain):
        sources = {
            "crt.sh": self._src_crtsh,
            "certspotter": self._src_certspotter,
            "otx": self._src_otx,
            "hackertarget": self._src_hackertarget,
            "anubis": self._src_anubis,
        }
        tool = self.detect_tool()
        self._tool = tool
        counts = {}
        sub_sources = {}
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
                subs = {s for s in subs if s == domain or s.endswith("." + domain)}
                counts[name] = len(subs)
                for s in subs:
                    sub_sources.setdefault(s, set()).add(name)
        self._passive_counts = counts
        return sub_sources

    def _finalize_stats(self, results, active_subs):
        self.stats = {
            "method": self._tool if getattr(self, "_tool", None) else "passive+active",
            "passive_sources": getattr(self, "_passive_counts", {}),
            "active_found": len(active_subs),
            "wildcard": self._wildcard,
            "total": len(results),
            "resolved": sum(1 for r in results if r["resolved"]),
            "takeovers": sum(1 for r in results if r.get("takeover")),
        }

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
        else:
            cmd = [tool, "enum", "-passive", "-d", domain]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT)
        except (subprocess.TimeoutExpired, OSError):
            return set()
        return {ln.strip().lower().lstrip("*.") for ln in proc.stdout.splitlines()
                if ln.strip() and "@" not in ln}

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

    # ---------- Helpers ----------
    @staticmethod
    def _resolve(host):
        try:
            return host, socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError):
            return host, None

    @staticmethod
    def _clean_domain(domain):
        domain = domain.strip().lower()
        for prefix in ("http://", "https://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0].lstrip("*.")
