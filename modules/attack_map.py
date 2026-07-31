"""MITRE ATT&CK mapping — translate findings into adversary language.

Red-team reports speak ATT&CK: instead of "port 3389 is open", the finding becomes
"T1021.001 Remote Services: RDP". The mapping here is deterministic (service/port and
finding type -> technique), so it stays accurate and reproducible; the AI layer only
narrates the resulting chain, it never invents technique IDs.

Reference: https://attack.mitre.org/techniques/enterprise/
"""

# Kill-chain order used for sorting/grouping in reports.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]


def _t(tid, name, tactic):
    return {"id": tid, "name": name, "tactic": tactic}


# --- service/port based (exposed services an adversary can use) ---
SERVICE_TECHNIQUES = {
    "ssh": _t("T1021.004", "Remote Services: SSH", "Lateral Movement"),
    "rdp": _t("T1021.001", "Remote Services: RDP", "Lateral Movement"),
    "ms-wbt-server": _t("T1021.001", "Remote Services: RDP", "Lateral Movement"),
    "vnc": _t("T1021.005", "Remote Services: VNC", "Lateral Movement"),
    "smb": _t("T1021.002", "Remote Services: SMB/Admin Shares", "Lateral Movement"),
    "microsoft-ds": _t("T1021.002", "Remote Services: SMB/Admin Shares", "Lateral Movement"),
    "netbios-ssn": _t("T1021.002", "Remote Services: SMB/Admin Shares", "Lateral Movement"),
    "telnet": _t("T1021", "Remote Services", "Lateral Movement"),
    "ftp": _t("T1071.002", "Application Layer Protocol: File Transfer", "Command and Control"),
    "mysql": _t("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "postgresql": _t("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "ms-sql-s": _t("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "mongodb": _t("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "redis": _t("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "smtp": _t("T1566", "Phishing", "Initial Access"),
    "http": _t("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "https": _t("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "http-proxy": _t("T1090", "Proxy", "Command and Control"),
    "domain": _t("T1590.002", "Gather Victim Network Info: DNS", "Reconnaissance"),
    "ldap": _t("T1087.002", "Account Discovery: Domain Account", "Discovery"),
    "kerberos-sec": _t("T1558", "Steal or Forge Kerberos Tickets", "Credential Access"),
    "nfs": _t("T1039", "Data from Network Shared Drive", "Collection"),
    "rpcbind": _t("T1135", "Network Share Discovery", "Discovery"),
    "java-rmi": _t("T1210", "Exploitation of Remote Services", "Lateral Movement"),
    "ajp13": _t("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "irc": _t("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"),
    "bindshell": _t("T1059", "Command and Scripting Interpreter", "Execution"),
    "x11": _t("T1113", "Screen Capture", "Collection"),
}

# --- module finding types ---
FINDING_TECHNIQUES = {
    "cve": _t("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "cve_kev": _t("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "LFI": _t("T1005", "Data from Local System", "Collection"),
    "path_traversal": _t("T1083", "File and Directory Discovery", "Discovery"),
    "SSRF": _t("T1090", "Proxy / Internal Service Access", "Command and Control"),
    "ssrf_cloud_creds": _t("T1552.005", "Unsecured Credentials: Cloud Instance Metadata",
                           "Credential Access"),
    "403-bypass": _t("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    "secret": _t("T1552.001", "Unsecured Credentials: Credentials In Files",
                 "Credential Access"),
    "exposed_file": _t("T1083", "File and Directory Discovery", "Discovery"),
    "git_exposed": _t("T1213.003", "Data from Information Repositories: Code Repositories",
                      "Collection"),
    "subdomain": _t("T1590.005", "Gather Victim Network Info: IP Addresses",
                    "Reconnaissance"),
    "takeover": _t("T1584.001", "Compromise Infrastructure: Domains", "Resource Development"),
    "default_creds": _t("T1078.001", "Valid Accounts: Default Accounts", "Initial Access"),
    "cloud_creds": _t("T1078.004", "Valid Accounts: Cloud Accounts", "Initial Access"),
    "waf": _t("T1090.003", "Proxy: Multi-hop / CDN in path", "Defense Evasion"),
}

# nuclei template-id / name keywords -> finding type (checked in order)
_NUCLEI_KEYWORDS = [
    ("default-login", "default_creds"),
    ("default-cred", "default_creds"),
    ("weak-credential", "default_creds"),
    ("empty-password", "default_creds"),
    ("rce", "cve"),
    ("traversal", "path_traversal"),
    ("lfi", "LFI"),
    ("ssrf", "SSRF"),
    ("exposure", "exposed_file"),
    ("exposed", "exposed_file"),
    ("git", "git_exposed"),
    ("takeover", "takeover"),
]


def _add(bucket, tech, evidence):
    """Group evidence under a technique id."""
    if not tech:
        return
    entry = bucket.setdefault(tech["id"], {**tech, "evidence": []})
    if evidence and evidence not in entry["evidence"]:
        entry["evidence"].append(evidence)


def map_findings(findings=None, nuclei=None, web=None, subdomains=None,
                 leak=None, vulns=None, scan_meta=None):
    """Map everything we know into ATT&CK techniques.
    Returns a list of {id, name, tactic, evidence[]} sorted by kill-chain order."""
    bucket = {}

    # Open services
    for r in findings or []:
        svc = (r.get("service") or "").lower()
        port = r.get("port")
        tech = SERVICE_TECHNIQUES.get(svc)
        if tech:
            _add(bucket, tech, f"port {port}/{svc}")
        # CVEs on that service
        for c in r.get("cves") or []:
            key = "cve_kev" if c.get("kev") else "cve"
            label = f"{c['id']} on {port}/{svc}" + (" (KEV)" if c.get("kev") else "")
            _add(bucket, FINDING_TECHNIQUES[key], label)

    # Nuclei findings
    for f in nuclei or []:
        blob = f"{f.get('template_id','')} {f.get('name','')}".lower()
        ftype = next((t for kw, t in _NUCLEI_KEYWORDS if kw in blob), None)
        if ftype:
            _add(bucket, FINDING_TECHNIQUES[ftype],
                 f"{f.get('template_id')} ({f.get('severity')})")

    # Web layer / WAF
    for w in web or []:
        if w.get("waf"):
            _add(bucket, FINDING_TECHNIQUES["waf"], f"{', '.join(w['waf'])} in front of {w.get('url')}")

    # Subdomains + takeover
    subs = subdomains or []
    live = [s for s in subs if s.get("resolved")]
    if live:
        _add(bucket, FINDING_TECHNIQUES["subdomain"], f"{len(live)} live subdomains")
    for s in subs:
        if s.get("takeover"):
            _add(bucket, FINDING_TECHNIQUES["takeover"], f"{s['host']} → {s['takeover']}")

    # Leaked secrets / exposed files
    if leak:
        for s in leak.get("secrets") or []:
            ftype = "cloud_creds" if "AWS" in s.get("type", "") else "secret"
            _add(bucket, FINDING_TECHNIQUES[ftype], f"{s.get('type')} ({s.get('confidence')})")
        for e in leak.get("exposed") or []:
            ftype = "git_exposed" if ".git" in e.get("path", "") else "exposed_file"
            _add(bucket, FINDING_TECHNIQUES[ftype], e.get("path"))

    # Confirmed vulns from the active modules
    for v in vulns or []:
        vtype = v.get("type")
        if vtype == "SSRF":
            # Cloud-metadata SSRF is a credential-access problem, not just proxying.
            sigs = " ".join(h.get("signature", "") for h in v.get("hits", []))
            key = "ssrf_cloud_creds" if "metadata" in sigs.lower() else "SSRF"
        else:
            key = vtype if vtype in FINDING_TECHNIQUES else None
        if key:
            _add(bucket, FINDING_TECHNIQUES[key], f"{vtype} at {v.get('url')}")

    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    return sorted(bucket.values(), key=lambda t: (order.get(t["tactic"], 99), t["id"]))


def tactic_summary(techniques):
    """{tactic: [technique ids]} for a compact coverage view."""
    out = {}
    for t in techniques:
        out.setdefault(t["tactic"], []).append(t["id"])
    return out
