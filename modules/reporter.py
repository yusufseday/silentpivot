import os
import json
import socket
from datetime import datetime


def _severity_rank(sev):
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    return order.get(sev, 0)


def _worst_cve(cves):
    if not cves:
        return None
    # KEV (actively exploited) first, then CVSS score, then severity.
    return max(
        cves,
        key=lambda c: (
            1 if c.get("kev") else 0,
            c["cvss"] if isinstance(c.get("cvss"), (int, float)) else -1,
            _severity_rank(c.get("severity", "UNKNOWN")),
        ),
    )


def build_report_data(target, scan_type, results, analysis=None,
                      web=None, nuclei=None, nuclei_meta=None):
    """The single structured data model every output format is built from."""
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        ip = None

    kev_count = sum(
        1 for r in results for c in (r.get("cves") or []) if c.get("kev")
    )
    return {
        "target": target,
        "resolved_ip": ip,
        "scan_type": scan_type,
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "open_ports": len(results),
        "kev_count": kev_count,
        "findings": results,
        "web": web or [],
        "nuclei": nuclei or [],
        "nuclei_meta": nuclei_meta or {},
        "ai_analysis": analysis,
    }


def _md_cell(value):
    """Escape a value for a Markdown table cell (pipes, newlines)."""
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def to_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False)


def to_markdown(report):
    lines = [
        "# SilentPivot Pentest Report",
        "",
        f"- **Target:** {report['target']}",
        f"- **Resolved IP:** {report.get('resolved_ip') or 'unknown'}",
        f"- **Scan Type:** {report['scan_type']}",
        f"- **Date:** {report['timestamp']}",
        f"- **Open Ports:** {report['open_ports']}  |  **Actively Exploited (KEV):** {report['kev_count']}",
        "",
        "## Findings",
        "",
        "| Port | Service | Version | CVEs | Top Risk | EPSS | KEV | Exploit |",
        "|------|---------|---------|------|----------|------|-----|---------|",
    ]
    for r in report["findings"]:
        cves = r.get("cves") or []
        worst = _worst_cve(cves)
        if worst:
            risk = f"{worst.get('severity')} ({worst.get('cvss')})"
            epss = worst.get("epss")
            epss_str = f"{epss * 100:.1f}%" if isinstance(epss, (int, float)) else "-"
            kev = "YES" if any(c.get("kev") for c in cves) else "-"
            if any(c.get("exploitdb") for c in cves):
                exploit = "ExploitDB"
            elif any(c.get("poc") for c in cves):
                exploit = "PoC"
            else:
                exploit = "-"
        else:
            risk, epss_str, kev, exploit = "-", "-", "-", "-"
        lines.append(
            f"| {r.get('port')} | {r.get('service')} | {r.get('version')} "
            f"| {len(cves)} | {risk} | {epss_str} | {kev} | {exploit} |"
        )

    # Web fingerprint section
    if report.get("web"):
        lines += [
            "", "## Web Fingerprint", "",
            "| URL | Code | Title | Server | Tech | WAF/CDN |",
            "|-----|------|-------|--------|------|---------|",
        ]
        for w in report["web"]:
            lines.append(
                f"| {_md_cell(w.get('url'))} | {w.get('status')} "
                f"| {_md_cell(w.get('title') or '-')} | {_md_cell(w.get('server') or '-')} "
                f"| {_md_cell(', '.join(w.get('tech') or []) or '-')} "
                f"| {_md_cell(', '.join(w.get('waf') or []) or '-')} |"
            )

    # Nuclei findings section
    if report.get("nuclei"):
        counts = {}
        for f in report["nuclei"]:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        summary = ", ".join(
            f"{s}: {counts[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            if counts.get(s)
        )
        lines += [
            "", "## Nuclei Findings", "",
            f"_{len(report['nuclei'])} findings — {summary}_", "",
            "| Severity | Template | Name | Detail | Matched At |",
            "|----------|----------|------|--------|------------|",
        ]
        for f in report["nuclei"]:
            lines.append(
                f"| {f.get('severity')} | {_md_cell(f.get('template_id'))} "
                f"| {_md_cell(f.get('name') or '-')} | {_md_cell(f.get('matcher_name') or '-')} "
                f"| {_md_cell(f.get('matched_at') or '-')} |"
            )

    if report.get("ai_analysis"):
        lines += ["", "---", "", "## AI Analysis", "", report["ai_analysis"]]
    return "\n".join(lines)


def default_filename(report, ext):
    ip = report.get("resolved_ip") or "target"
    safe_target = report["target"].replace("/", "_").replace(":", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    return f"{ip}({safe_target})_{stamp}.{ext}"


def save_report(report, fmt="md", output_path=None, out_dir="data"):
    """Write the report to disk in the requested format and return the path."""
    fmt = fmt.lower()
    renderers = {"json": to_json, "md": to_markdown, "markdown": to_markdown}
    if fmt not in renderers:
        raise ValueError(f"Unsupported format: {fmt}")

    content = renderers[fmt](report)
    ext = "json" if fmt == "json" else "md"

    if output_path is None:
        os.makedirs(out_dir, exist_ok=True)
        output_path = os.path.join(out_dir, default_filename(report, ext))
    else:
        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path
