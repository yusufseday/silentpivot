"""Content discovery — find hidden paths, panels, backups and API endpoints.

Hybrid, like the rest of the toolkit:
  * ffuf or gobuster if they are on PATH (fast, battle-tested, common on Kali)
  * otherwise a pure-Python threaded fuzzer with a built-in high-value wordlist

Accuracy comes from baselining: many servers answer 200 (or a friendly 404 page) for
*every* path, so the scanner first learns what "not found" looks like on this host and
discards anything that matches it. A hit is a response that genuinely differs.

Active testing — authorized targets only.
"""
import os
import json
import base64
import binascii
import shutil
import tempfile
import subprocess
import concurrent.futures
from urllib.parse import urljoin, urlparse

import requests

from modules.opsec import profile as opsec

EXTERNAL_TOOLS = ("ffuf", "gobuster")
TOOL_TIMEOUT = 600

# Wordlists shipped with Kali / common distros, best first.
SYSTEM_WORDLISTS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
]

# Compact built-in list: the paths that actually matter on a first pass.
BUILTIN_WORDLIST = """
admin administrator login signin signup register dashboard panel cpanel wp-admin
wp-login.php wp-content wp-includes phpmyadmin pma adminer manager console
api api/v1 api/v2 api-docs swagger swagger-ui openapi graphql graphiql rest
backup backups bak old new test testing dev develop staging stage prod uat demo
config configuration settings setup install installer upgrade update
db database sql dump dumps data export exports import
logs log debug trace error errors status health healthz metrics actuator
actuator/health actuator/env server-status server-info
uploads upload files file download downloads media images img assets static
tmp temp cache private secret secrets internal hidden
.git .git/config .git/HEAD .svn .hg .env .env.local .env.production .htaccess
.htpasswd .DS_Store .aws .ssh id_rsa web.config composer.json package.json
robots.txt sitemap.xml crossdomain.xml security.txt .well-known/security.txt
readme readme.md changelog license phpinfo.php info.php test.php shell.php
user users account accounts profile members member customer clients
mail webmail email roundcube squirrelmail
jenkins gitlab git jira confluence grafana kibana prometheus nagios zabbix
solr elasticsearch redis mongo kafka rabbitmq
cgi-bin cgi-bin/test-cgi scripts includes lib vendor node_modules
portal intranet extranet vpn remote citrix owa exchange autodiscover
""".split()

# Extensions worth appending to word stems in the Python fallback.
DEFAULT_EXTENSIONS = ["", ".php", ".bak", ".old", ".txt", ".zip", ".json"]

# Statuses worth reporting; 404 is noise, 5xx usually is too.
INTERESTING = {200, 201, 202, 203, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Safety rails for the pure-Python fuzzer. External tools (ffuf/gobuster) are built for
# huge lists, but Python is not: a 220k-word list (Kali's dirbuster medium) times the
# extension set would be over a million requests and a runaway scan. Cap and warn.
MAX_WORDLIST_LINES = 50_000
MAX_PYTHON_REQUESTS = 10_000


class ContentDiscovery:
    def __init__(self, timeout=8, max_workers=20):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        opsec.apply_to_session(self.session)
        self.stats = {}

    # ---------- external tools ----------
    @staticmethod
    def detect_tool():
        for name in EXTERNAL_TOOLS:
            if shutil.which(name):
                return name
        return None

    @staticmethod
    def system_wordlist():
        for path in SYSTEM_WORDLISTS:
            if os.path.isfile(path):
                return path
        return None

    @staticmethod
    def _ffuf_path(item, base_url=""):
        """Recover the real path from an ffuf result.

        ffuf's JSON output base64-encodes the values in `input`, so FUZZ comes back as
        e.g. 'cGhwTXlBZG1pbg==' for 'phpMyAdmin'. The result `url` is authoritative when
        present; otherwise decode the input, falling back to the raw value.
        """
        url = str(item.get("url") or "")
        if url:
            path = urlparse(url).path or "/"
            if base_url:
                prefix = urlparse(base_url).path.rstrip("/")
                if prefix and path.startswith(prefix):
                    path = path[len(prefix):] or "/"
            return path if path.startswith("/") else "/" + path

        inp = item.get("input")
        raw = inp.get("FUZZ", "") if isinstance(inp, dict) else ""
        raw = str(raw)
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8", "strict")
            raw = decoded
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass          # not base64 (older ffuf) — use the value as-is
        return "/" + raw.lstrip("/")

    @staticmethod
    def _as_int(value, default=0):
        """Tolerant int(): tool output varies between versions, so a surprising type
        must never abort the whole parse."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def parse_ffuf(stdout, base_url=""):
        """ffuf -json prints one JSON object per result line. Written defensively —
        unexpected shapes are skipped rather than raising."""
        out = []
        for line in (stdout or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if not isinstance(obj, dict):
                continue
            # ffuf wraps results differently across versions; accept both shapes.
            items = obj.get("results") if isinstance(obj.get("results"), list) else [obj]
            for it in items:
                if not isinstance(it, dict) or "status" not in it:
                    continue
                status = ContentDiscovery._as_int(it.get("status"), 0)
                if not status:
                    continue
                out.append({
                    "path": ContentDiscovery._ffuf_path(it, base_url),
                    "url": str(it.get("url") or ""),
                    "status": status,
                    "size": ContentDiscovery._as_int(it.get("length"), 0),
                    "redirect": str(it.get("redirectlocation") or ""),
                })
        return out

    @staticmethod
    def parse_gobuster(stdout):
        """gobuster -q prints: /admin  (Status: 301) [Size: 234] [--> /admin/]"""
        import re
        rx = re.compile(r"^(?P<path>/\S*)\s+\(Status:\s*(?P<status>\d+)\)"
                        r"(?:\s*\[Size:\s*(?P<size>\d+)\])?"
                        r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?")
        out = []
        for line in (stdout or "").splitlines():
            m = rx.match(line.strip())
            if m:
                out.append({
                    "path": m.group("path"),
                    "url": "",
                    "status": int(m.group("status")),
                    "size": int(m.group("size") or 0),
                    "redirect": (m.group("redirect") or "").strip(),
                })
        return out

    def _run_external(self, tool, base_url, wordlist):
        if tool == "ffuf":
            cmd = [tool, "-u", base_url.rstrip("/") + "/FUZZ", "-w", wordlist,
                   "-json", "-s", "-t", str(opsec.workers(self.max_workers)),
                   "-mc", "200,201,202,203,204,301,302,307,308,401,403,405,500"]
        else:  # gobuster
            cmd = [tool, "dir", "-u", base_url, "-w", wordlist, "-q", "-k",
                   "-t", str(opsec.workers(self.max_workers))]
        if opsec.proxy:
            cmd += (["-x", opsec.proxy] if tool == "ffuf" else ["-p", opsec.proxy])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TOOL_TIMEOUT)
        except (subprocess.TimeoutExpired, OSError):
            return []
        return (self.parse_ffuf(proc.stdout, base_url) if tool == "ffuf"
                else self.parse_gobuster(proc.stdout))

    # ---------- python fallback ----------
    def _baseline(self, base_url):
        """Learn what a definitely-missing path looks like (status + body size), so
        catch-all/soft-404 servers don't produce a wall of false hits."""
        samples = []
        for probe in ("sp_no_such_path_9x8z7", "sp_missing_4k2j1/", "sp_none_1a2b3.php"):
            try:
                r = opsec.fetch(self.session, urljoin(base_url + "/", probe),
                                timeout=self.timeout, allow_redirects=False)
                samples.append((r.status_code, len(r.content)))
            except requests.RequestException:
                continue
        if not samples:
            return None
        statuses = {s for s, _ in samples}
        sizes = [n for _, n in samples]
        return {
            "status": samples[0][0] if len(statuses) == 1 else None,
            "size": sum(sizes) // len(sizes),
            "size_varies": max(sizes) - min(sizes) > 64,
        }

    def _probe(self, args):
        base_url, path, baseline = args
        opsec.wait()                                   # stealth pacing
        url = urljoin(base_url + "/", path.lstrip("/"))
        try:
            r = opsec.fetch(self.session, url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None
        if r.status_code not in INTERESTING:
            return None
        size = len(r.content)
        # Soft-404 filter: same status as the baseline AND a near-identical body.
        if baseline and baseline["status"] == r.status_code and not baseline["size_varies"]:
            if abs(size - baseline["size"]) < 64:
                return None
        return {
            "path": "/" + path.lstrip("/"),
            "url": url,
            "status": r.status_code,
            "size": size,
            "redirect": r.headers.get("Location", ""),
        }

    @staticmethod
    def plan_size(words, extensions):
        """How many requests a Python run would need — lets the caller warn *before*
        starting instead of silently testing only part of the list."""
        total = 0
        for w in words:
            total += 1 if ("." in w or "/" in w) else len(extensions)
        return total

    def _run_python(self, base_url, words, extensions):
        baseline = self._baseline(base_url)
        planned = self.plan_size(words, extensions)
        seen, tasks = set(), []
        truncated = False
        for w in words:
            # Words that already look like a file/path are used as-is.
            variants = [w] if ("." in w or "/" in w) else [w + ext for ext in extensions]
            for c in variants:
                if c in seen:
                    continue
                seen.add(c)
                tasks.append((base_url, c, baseline))
                # Hard stop: Python can't sanely fuzz a million paths, and doing so
                # would hammer the target as much as ourselves.
                if len(tasks) >= MAX_PYTHON_REQUESTS:
                    truncated = True
                    break
            if truncated:
                break
        self._truncated = truncated
        self._tested = len(tasks)
        self._planned = planned

        results = []
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=opsec.workers(self.max_workers)) as ex:
            for res in ex.map(self._probe, tasks):
                if res:
                    results.append(res)
        return results

    # ---------- public API ----------
    def run(self, base_url, wordlist_path=None, extensions=None, use_external=True):
        """Discover content under base_url. Returns findings sorted by status.
        Uses ffuf/gobuster when available (with a system or temporary wordlist),
        otherwise the built-in Python fuzzer."""
        base_url = base_url.rstrip("/")
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return []

        extensions = extensions if extensions is not None else DEFAULT_EXTENSIONS
        words = BUILTIN_WORDLIST
        wordlist_truncated = False
        if wordlist_path and os.path.isfile(wordlist_path):
            words = []
            with open(wordlist_path, encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        words.append(line)
                    if len(words) >= MAX_WORDLIST_LINES:   # don't load a giant file whole
                        # Anything after this point is never tested — the caller must
                        # say so, otherwise "nothing found" reads as "nothing is there".
                        wordlist_truncated = any(ln.strip() for ln in fh)
                        break

        tool = self.detect_tool() if use_external else None
        results, method = [], "python"
        if tool:
            # External tools need a file; fall back to writing the built-in list out.
            path = wordlist_path or self.system_wordlist()
            tmp = None
            if not path:
                tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                                  encoding="utf-8")
                tmp.write("\n".join(BUILTIN_WORDLIST))
                tmp.close()
                path = tmp.name
            try:
                results = self._run_external(tool, base_url, path)
                method = f"{tool} ({os.path.basename(path)})"
            finally:
                if tmp:
                    try:
                        os.unlink(tmp.name)
                    except OSError:
                        pass
        if not results:
            self._truncated = False
            results = self._run_python(base_url, words, extensions)
            method = f"python ({len(words)} words)"

        # De-duplicate by path, most interesting status first.
        uniq = {}
        for r in results:
            uniq.setdefault(r["path"], r)
        results = sorted(uniq.values(), key=lambda r: (r["status"], r["path"]))
        # Coverage is reported explicitly: a truncated run that finds nothing must not
        # be mistaken for "there is nothing here".
        self.stats = {
            "method": method,
            "total": len(results),
            "wordlist": len(words),
            "wordlist_truncated": wordlist_truncated,
            "tested": getattr(self, "_tested", None),
            "planned": getattr(self, "_planned", None),
            "truncated": bool(getattr(self, "_truncated", False)) or wordlist_truncated,
            "complete": not (getattr(self, "_truncated", False) or wordlist_truncated),
        }
        return results
