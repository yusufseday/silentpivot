"""Active vulnerability scanning via nuclei (ProjectDiscovery).

Hybrid wrapper: if `nuclei` is on PATH we run it and parse its JSONL output;
otherwise the caller is told it is unavailable and can degrade gracefully.
nuclei ships thousands of community templates (CVEs, misconfigurations, exposed
panels, default creds, secrets), which is what turns recon into real findings.
"""
import os
import re
import json
import shutil
import tempfile
import subprocess

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": -1}
_TEMPLATES_RE = re.compile(r"Templates loaded for current scan:\s*(\d+)")


class NucleiScanner:
    def __init__(self):
        self.path = shutil.which("nuclei")
        self.available = self.path is not None
        # Populated after scan(): {"returncode", "templates", "errors"}
        self.meta = {}

    def scan(self, targets, severities=("medium", "high", "critical"), timeout=1800):
        """Run nuclei against one or more targets. Returns a sorted findings list,
        or None if nuclei is not installed. Run diagnostics land in self.meta so the
        caller can tell a genuine 'no findings' from an error / missing templates."""
        if not self.available:
            return None
        if isinstance(targets, str):
            targets = [targets]
        targets = [t.strip() for t in targets if t and t.strip()]
        if not targets:
            return []

        tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        )
        try:
            tmp.write("\n".join(targets))
            tmp.close()
            # NOTE: no -silent, so nuclei's INF/ERR logs reach stderr where we parse
            # the loaded-template count and detect fatal errors. Findings (JSONL) go
            # to stdout. -disable-update-check only skips the version nag.
            cmd = [self.path, "-l", tmp.name, "-jsonl", "-disable-update-check"]
            if severities:
                cmd += ["-severity", ",".join(severities)]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            self.meta = self._parse_meta(proc.returncode, proc.stderr)
            return self.parse_jsonl(proc.stdout)
        except subprocess.TimeoutExpired:
            self.meta = {"returncode": None, "templates": None, "errors": ["timeout"]}
            return []
        except (subprocess.SubprocessError, OSError) as e:
            self.meta = {"returncode": None, "templates": None, "errors": [str(e)]}
            return []
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @staticmethod
    def _parse_meta(returncode, stderr):
        stderr = stderr or ""
        m = _TEMPLATES_RE.search(stderr)
        templates = int(m.group(1)) if m else None
        errors = [ln.strip() for ln in stderr.splitlines()
                  if "[FTL]" in ln or "[ERR]" in ln]
        return {"returncode": returncode, "templates": templates, "errors": errors[-3:]}

    @staticmethod
    def parse_jsonl(text):
        """Parse nuclei JSONL (one JSON object per line) into structured findings,
        deduplicated so the same template+location doesn't spam identical rows."""
        findings, seen = [], set()
        for line in (text or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            info = obj.get("info", {}) or {}
            # matcher-name / extracted-results say WHICH thing matched (e.g. which weak
            # credential or missing header) — turns duplicate-looking rows into signal.
            extracted = obj.get("extracted-results") or []
            detail = obj.get("matcher-name", "") or ", ".join(map(str, extracted))
            matched_at = obj.get("matched-at") or obj.get("matched", "")
            template_id = obj.get("template-id") or obj.get("templateID", "")

            key = (template_id, matched_at, detail)
            if key in seen:  # collapse truly identical hits
                continue
            seen.add(key)

            findings.append({
                "template_id": template_id,
                "name": info.get("name", ""),
                "matcher_name": detail,
                "severity": (info.get("severity") or "unknown").upper(),
                "tags": info.get("tags") or [],
                "matched_at": matched_at,
                "host": obj.get("host", ""),
                "type": obj.get("type", ""),
                "description": (info.get("description") or "").strip(),
                "reference": info.get("reference") or [],
            })
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], -1), reverse=True)
        return findings
