"""Active vulnerability scanning via nuclei (ProjectDiscovery).

Hybrid wrapper: if `nuclei` is on PATH we run it and parse its JSONL output;
otherwise the caller is told it is unavailable and can degrade gracefully.
nuclei ships thousands of community templates (CVEs, misconfigurations, exposed
panels, default creds, secrets), which is what turns recon into real findings.
"""
import os
import json
import shutil
import tempfile
import subprocess

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": -1}


class NucleiScanner:
    def __init__(self):
        self.path = shutil.which("nuclei")
        self.available = self.path is not None

    def scan(self, targets, severities=("medium", "high", "critical"), timeout=900):
        """Run nuclei against one or more targets. Returns a sorted findings list,
        or None if nuclei is not installed."""
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
            cmd = [self.path, "-l", tmp.name, "-jsonl", "-silent", "-disable-update-check"]
            if severities:
                cmd += ["-severity", ",".join(severities)]
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return self.parse_jsonl(proc.stdout)
        except (subprocess.SubprocessError, OSError):
            return []
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

    @staticmethod
    def parse_jsonl(text):
        """Parse nuclei JSONL (one JSON object per line) into structured findings."""
        findings = []
        for line in (text or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            info = obj.get("info", {}) or {}
            findings.append({
                "template_id": obj.get("template-id") or obj.get("templateID", ""),
                "name": info.get("name", ""),
                "severity": (info.get("severity") or "unknown").upper(),
                "tags": info.get("tags") or [],
                "matched_at": obj.get("matched-at") or obj.get("matched", ""),
                "host": obj.get("host", ""),
                "type": obj.get("type", ""),
                "description": (info.get("description") or "").strip(),
                "reference": info.get("reference") or [],
            })
        findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], -1), reverse=True)
        return findings
