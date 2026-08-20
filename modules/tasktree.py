"""Engagement task tree — a persistent, per-target list of what's done and what's
still open.

A long engagement produces far more leads (CVEs, weak creds, readable files, forbidden
paths) than a human tracks in their head, and the co-pilot loses everything the moment
the session ends. This module turns every module's output into tracked "leads" —
findings worth acting on — with a status (open / done / no-result), stored on disk per
target so the tree survives closing and reopening the tool.

Design: entries are content-addressed (target + kind + a stable key derived from the
finding) so re-running a scan updates existing leads instead of duplicating them, and
marking a lead 'done' persists across rescans.
"""
import os
import re
import json
import hashlib
from datetime import datetime, timezone

ENGAGEMENTS_DIR = os.path.join("data", "engagements")

OPEN, DONE, NO_RESULT = "open", "done", "no_result"

# Priority just orders the display; it's a hint, not a score.
PRIORITY = {
    "kev": 0, "backdoor": 0, "confirmed_vuln": 1, "high_epss": 1,
    "default_creds": 2, "exposed_file": 2, "content": 3, "cve": 3,
    "nuclei": 3, "subdomain": 4, "service": 5,
}


def _slug(target):
    """Filesystem-safe file name for a target (IP or hostname)."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", target.strip())[:200] or "target"


def _key(kind, *parts):
    """Stable id for a lead: same finding -> same id across rescans."""
    raw = kind + "|" + "|".join(str(p) for p in parts)
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:12]


class TaskTree:
    def __init__(self, target):
        self.target = target
        self.path = os.path.join(ENGAGEMENTS_DIR, _slug(target) + ".json")
        self.leads = {}          # id -> lead dict
        self.created = None
        self._load()

    # ---------- persistence ----------
    def _load(self):
        if os.path.isfile(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    data = json.load(f)
                self.leads = data.get("leads", {})
                self.created = data.get("created")
            except (OSError, ValueError):
                self.leads = {}
        if self.created is None:
            self.created = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def save(self):
        os.makedirs(ENGAGEMENTS_DIR, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"target": self.target, "created": self.created,
                      "leads": self.leads}, f, indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)   # atomic — a crash mid-write can't corrupt the file

    @staticmethod
    def exists(target):
        return os.path.isfile(os.path.join(ENGAGEMENTS_DIR, _slug(target) + ".json"))

    @staticmethod
    def list_engagements():
        if not os.path.isdir(ENGAGEMENTS_DIR):
            return []
        return sorted(f[:-5] for f in os.listdir(ENGAGEMENTS_DIR) if f.endswith(".json"))

    # ---------- adding / updating leads ----------
    def _add(self, kind, key, title, evidence, priority=None, status=OPEN):
        """Insert a new lead, or refresh an existing one's evidence without touching
        its status — a rescan must not silently un-complete work you already did."""
        existing = self.leads.get(key)
        if existing:
            existing["evidence"] = evidence
            existing["seen"] = existing.get("seen", 0) + 1
            existing["last_seen"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            return
        self.leads[key] = {
            "kind": kind, "title": title, "evidence": evidence,
            "priority": PRIORITY.get(priority or kind, 5),
            "status": status, "seen": 1, "note": "",
            "first_seen": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "last_seen": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }

    def ingest(self, findings=None, nuclei=None, web=None, subdomains=None,
              leak=None, vulns=None, content=None):
        """Turn a batch of module output into leads. Safe to call repeatedly (e.g.
        after every tool) — it only adds what's new or updates evidence."""
        for r in findings or []:
            port, svc = r.get("port"), r.get("service", "?")
            for c in r.get("cves") or []:
                cid = c.get("id", "?")
                pr = "kev" if c.get("kev") else ("high_epss" if (c.get("epss") or 0) > 0.3 else "cve")
                exploit = "ExploitDB" if c.get("exploitdb") else ("PoC" if c.get("poc") else "")
                self._add("cve", _key("cve", port, cid),
                          f"{cid} on {port}/{svc}",
                          f"CVSS {c.get('cvss')} {c.get('severity')}"
                          + (" · ACTIVELY EXPLOITED (KEV)" if c.get("kev") else "")
                          + (f" · {exploit}" if exploit else ""),
                          priority=pr)

        for f in nuclei or []:
            if f.get("severity") not in ("CRITICAL", "HIGH", "MEDIUM"):
                continue
            blob = f"{f.get('template_id','')} {f.get('name','')}".lower()
            pr = "backdoor" if "backdoor" in blob else ("default_creds" if "default" in blob or "empty-password" in blob else "nuclei")
            self._add("nuclei", _key("nuclei", f.get("template_id"), f.get("matched_at")),
                      f"{f.get('name') or f.get('template_id')} ({f.get('severity')})",
                      f"{f.get('template_id')} at {f.get('matched_at')}"
                      + (f" — {f['matcher_name']}" if f.get("matcher_name") else ""),
                      priority=pr)

        for w in web or []:
            if w.get("waf"):
                self._add("service", _key("waf", w.get("url")),
                          f"WAF/CDN: {', '.join(w['waf'])}", w.get("url"), priority="service")

        for s in subdomains or []:
            if s.get("takeover"):
                self._add("subdomain", _key("takeover", s.get("host")),
                          f"Subdomain takeover: {s['host']}", s.get("takeover"),
                          priority="kev")

        if leak:
            for s in leak.get("secrets") or []:
                self._add("exposed_file", _key("secret", s.get("type"), s.get("value")),
                          f"Leaked secret: {s.get('type')}",
                          f"{s.get('value')} ({s.get('confidence')}) at {s.get('source')}",
                          priority="default_creds")
            for e in leak.get("exposed") or []:
                self._add("exposed_file", _key("exposed", e.get("path")),
                          f"Exposed file: {e.get('path')}",
                          f"{e.get('size')}B, confidence {e.get('confidence')}",
                          priority="exposed_file")

        for v in vulns or []:
            self._add("confirmed_vuln", _key("vuln", v.get("type"), v.get("url")),
                      f"Confirmed {v.get('type')}: {v.get('url')}",
                      "; ".join(str(h) for h in (v.get("hits") or [])[:2]),
                      priority="confirmed_vuln")

        for c in content or []:
            if c.get("status") in (401, 403):
                self._add("content", _key("forbidden", c.get("path")),
                          f"Forbidden path: {c['path']}",
                          f"status {c['status']} — try 403 bypass", priority="content")
            elif c.get("status") == 200 and any(t in c.get("path", "")
                                                for t in (".bash_history", ".git", ".env",
                                                          "backup", ".sql", "phpinfo")):
                self._add("content", _key("interesting", c.get("path")),
                          f"Interesting file: {c['path']}",
                          f"status 200, {c.get('size')}B", priority="exposed_file")

    # ---------- status changes ----------
    def set_status(self, lead_id, status, note=None):
        """Update a lead's status and persist immediately — a status change is the one
        thing in this module that must never be lost to a forgotten save() call."""
        lead = self.leads.get(lead_id)
        if not lead:
            return False
        lead["status"] = status
        if note is not None:
            lead["note"] = note
        self.save()
        return True

    def find(self, prefix):
        """Resolve a short id prefix (what the user types) to a full lead id."""
        matches = [k for k in self.leads if k.startswith(prefix)]
        return matches[0] if len(matches) == 1 else None

    # ---------- views ----------
    def open_leads(self):
        return sorted((dict(id=k, **v) for k, v in self.leads.items() if v["status"] == OPEN),
                     key=lambda x: (x["priority"], -x["seen"]))

    def summary(self):
        counts = {OPEN: 0, DONE: 0, NO_RESULT: 0}
        for v in self.leads.values():
            counts[v["status"]] = counts.get(v["status"], 0) + 1
        return counts
