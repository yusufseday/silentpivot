import os
import re
import html
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
                      web=None, nuclei=None, nuclei_meta=None, scan_meta=None):
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
        "scan_meta": scan_meta or {},
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
    ]

    # Scan notes: multi-IP + protected-target context (nothing escapes the reader).
    sm = report.get("scan_meta") or {}
    notes = []
    if len(sm.get("ips") or []) > 1:
        others = [ip for ip in sm["ips"] if ip != sm.get("scanned_ip")]
        notes.append(f"Target resolves to {len(sm['ips'])} IPs (scanned "
                     f"{sm.get('scanned_ip')}; others: {', '.join(others)}).")
    if sm.get("protected"):
        notes.append(f"{sm.get('total_open')} ports responded but only "
                     f"{sm.get('confirmed')} confirmed — likely WAF/anti-scan device; "
                     f"unconfirmed ports may be decoys.")
    if sm.get("waf"):
        notes.append(f"WAF/CDN detected via headers: {', '.join(sm['waf'])}.")
    if notes:
        lines += ["", "> **Scan Notes:** " + " ".join(notes)]

    lines += [
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


# ---------------- HTML report ----------------
_HTML_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin:0; font-family: -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  background:#f4f5f7; color:#1a1d23; line-height:1.5; }
.wrap { max-width:1040px; margin:0 auto; padding:0 20px 60px; }
header.top { background:#12161f; color:#e8eaed; padding:28px 20px; }
header.top .wrap { padding-bottom:0; }
header.top h1 { margin:0; font-size:22px; letter-spacing:.5px; }
header.top h1 .g { color:#3ddc84; }
header.top .meta { margin-top:6px; font-size:13px; color:#9aa0aa; }
header.top .meta code { color:#e8eaed; background:#1e2430; padding:1px 6px; border-radius:4px; }
.cards { display:flex; flex-wrap:wrap; gap:14px; margin:22px 0; }
.card { flex:1 1 150px; background:#fff; border:1px solid #e3e6ea; border-radius:10px;
  padding:16px 18px; box-shadow:0 1px 2px rgba(0,0,0,.04); }
.card .n { font-size:26px; font-weight:700; }
.card .l { font-size:12px; text-transform:uppercase; letter-spacing:.6px; color:#6b7280; margin-top:2px; }
.note { background:#fff8e1; border:1px solid #f6e2a8; border-left:4px solid #e6a700;
  border-radius:8px; padding:12px 16px; margin:18px 0; font-size:14px; }
h2.sec { font-size:16px; margin:34px 0 12px; padding-bottom:8px; border-bottom:2px solid #e3e6ea; }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid #e3e6ea;
  border-radius:8px; overflow:hidden; font-size:13.5px; }
th,td { text-align:left; padding:9px 12px; border-bottom:1px solid #eef0f2; vertical-align:top; }
th { background:#f0f2f5; font-size:12px; text-transform:uppercase; letter-spacing:.4px; color:#4b5563; }
tr:last-child td { border-bottom:none; }
tbody tr:hover { background:#fafbfc; }
code,.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
.badge { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px;
  font-weight:700; letter-spacing:.3px; color:#fff; }
.sev-critical{background:#c62828;} .sev-high{background:#ef6c00;}
.sev-medium{background:#f9a825;color:#1a1d23;} .sev-low{background:#2e7d32;}
.sev-info{background:#78849a;} .sev-unknown{background:#9aa0aa;}
.kev { color:#c62828; font-weight:700; }
.ai { background:#fff; border:1px solid #e3e6ea; border-radius:10px; padding:6px 24px 20px; }
.ai h1,.ai h2,.ai h3 { border-bottom:1px solid #eef0f2; padding-bottom:6px; }
.ai table { margin:12px 0; } .ai code { background:#f0f2f5; padding:1px 5px; border-radius:4px; }
footer { text-align:center; color:#9aa0aa; font-size:12px; margin-top:40px; }
@media (prefers-color-scheme: dark) {
  body{background:#0d1017;color:#d5d8de;} .card,table,.ai{background:#161b24;border-color:#262d3a;}
  th{background:#1b212c;color:#aab2c0;} td{border-color:#222834;} tbody tr:hover{background:#1b212c;}
  .note{background:#231f10;border-color:#4a3d12;} h2.sec{border-color:#262d3a;}
  header.top .meta code{background:#0d1017;} .ai code{background:#0d1017;}
}
"""


def _sev_badge(sev):
    sev = (sev or "UNKNOWN").upper()
    return f'<span class="badge sev-{sev.lower()}">{html.escape(sev)}</span>'


def _inline_md(text):
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def _md_to_html(md):
    """Minimal Markdown -> HTML for the AI prose (headers, lists, tables, bold, code)."""
    lines = (md or "").split("\n")
    out, i, n, lst = [], 0, len((md or "").split("\n")), None

    def close():
        nonlocal lst
        if lst:
            out.append(f"</{lst}>")
            lst = None

    while i < n:
        s = lines[i].strip()
        # Table block
        if s.startswith("|") and i + 1 < n and set(lines[i + 1].strip()) <= set("|-: "):
            close()
            heads = [c.strip() for c in s.strip("|").split("|")]
            i += 2
            body = ""
            while i < n and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                body += "<tr>" + "".join(f"<td>{_inline_md(c)}</td>" for c in cells) + "</tr>"
                i += 1
            head = "".join(f"<th>{_inline_md(h)}</th>" for h in heads)
            out.append(f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
            continue
        if not s:
            close(); i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", s)
        if m:
            close(); lvl = len(m.group(1))
            out.append(f"<h{lvl}>{_inline_md(m.group(2))}</h{lvl}>"); i += 1; continue
        if s in ("---", "***", "___"):
            close(); out.append("<hr>"); i += 1; continue
        m = re.match(r"^[-*]\s+(.*)$", s)
        if m:
            if lst != "ul": close(); out.append("<ul>"); lst = "ul"
            out.append(f"<li>{_inline_md(m.group(1))}</li>"); i += 1; continue
        m = re.match(r"^\d+\.\s+(.*)$", s)
        if m:
            if lst != "ol": close(); out.append("<ol>"); lst = "ol"
            out.append(f"<li>{_inline_md(m.group(1))}</li>"); i += 1; continue
        close(); out.append(f"<p>{_inline_md(s)}</p>"); i += 1
    close()
    return "\n".join(out)


def _html_table(headers, rows):
    head = "".join(f"<th>{html.escape(str(h))}</th>" for h in headers)
    body = ""
    for row in rows:
        body += "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def to_html(report):
    esc = html.escape
    sm = report.get("scan_meta") or {}
    nuclei = report.get("nuclei") or []
    web = report.get("web") or []

    # Stat cards
    ncrit = sum(1 for f in nuclei if f.get("severity") in ("CRITICAL", "HIGH"))
    waf = ", ".join(sm.get("waf") or []) or "—"
    cards = [
        ("Open Ports", report.get("open_ports", 0)),
        ("KEV (Active)", report.get("kev_count", 0)),
        ("Nuclei", f"{len(nuclei)}" + (f" ({ncrit}!)" if ncrit else "")),
        ("WAF/CDN", waf),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="n">{esc(str(v))}</div><div class="l">{esc(l)}</div></div>'
        for l, v in cards
    )

    # Scan notes
    notes = []
    if len(sm.get("ips") or []) > 1:
        notes.append(f"Target resolves to {len(sm['ips'])} IPs (scanned "
                     f"{esc(str(sm.get('scanned_ip')))}).")
    if sm.get("protected"):
        notes.append(f"{sm.get('total_open')} ports responded but only "
                     f"{sm.get('confirmed')} confirmed — likely WAF/anti-scan; unconfirmed "
                     f"ports may be decoys.")
    if sm.get("waf"):
        notes.append(f"WAF/CDN detected via headers: {esc(', '.join(sm['waf']))}.")
    notes_html = f'<div class="note"><strong>Scan Notes:</strong> {" ".join(notes)}</div>' if notes else ""

    # Findings table
    frows = []
    for r in report["findings"]:
        cves = r.get("cves") or []
        worst = _worst_cve(cves)
        if worst:
            risk = f'{_sev_badge(worst.get("severity"))} {esc(str(worst.get("cvss")))}'
            epss = worst.get("epss")
            epss_s = f"{epss * 100:.1f}%" if isinstance(epss, (int, float)) else "—"
            kev = '<span class="kev">YES</span>' if any(c.get("kev") for c in cves) else "—"
            if any(c.get("exploitdb") for c in cves):
                exp = "ExploitDB"
            elif any(c.get("poc") for c in cves):
                exp = "PoC"
            else:
                exp = "—"
        else:
            risk, epss_s, kev, exp = "—", "—", "—", "—"
        frows.append([f'<span class="mono">{esc(str(r.get("port")))}</span>',
                      esc(str(r.get("service"))), esc(str(r.get("version"))),
                      len(cves), risk, epss_s, kev, exp])
    findings_html = _html_table(
        ["Port", "Service", "Version", "CVEs", "Top Risk", "EPSS", "KEV", "Exploit"], frows)

    # Web table
    web_html = ""
    if web:
        wrows = [[f'<span class="mono">{esc(w["url"])}</span>', esc(str(w.get("status"))),
                  esc(w.get("server") or "—"), esc(", ".join(w.get("tech") or []) or "—"),
                  esc(", ".join(w.get("waf") or []) or "—")] for w in web]
        web_html = ('<h2 class="sec">Web Fingerprint</h2>'
                    + _html_table(["URL", "Code", "Server", "Tech", "WAF/CDN"], wrows))

    # Nuclei table
    nuclei_html = ""
    if nuclei:
        nrows = [[_sev_badge(f.get("severity")), f'<span class="mono">{esc(f.get("template_id") or "")}</span>',
                  esc(f.get("name") or "—"), esc(f.get("matcher_name") or "—"),
                  f'<span class="mono">{esc(f.get("matched_at") or "—")}</span>'] for f in nuclei]
        nuclei_html = (f'<h2 class="sec">Nuclei Findings ({len(nuclei)})</h2>'
                       + _html_table(["Severity", "Template", "Name", "Detail", "Matched At"], nrows))

    # AI analysis
    ai_html = ""
    if report.get("ai_analysis"):
        ai_html = ('<h2 class="sec">AI Analysis</h2><div class="ai">'
                   + _md_to_html(report["ai_analysis"]) + "</div>")

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SilentPivot Report — {esc(report['target'])}</title>
<style>{_HTML_CSS}</style></head><body>
<header class="top"><div class="wrap">
<h1>Silent<span class="g">Pivot</span> — Pentest Report</h1>
<div class="meta">Target <code>{esc(report['target'])}</code>
&nbsp; IP <code>{esc(str(report.get('resolved_ip') or '—'))}</code>
&nbsp; Scan <code>{esc(str(report['scan_type']))}</code>
&nbsp; {esc(report['timestamp'])}</div>
</div></header>
<div class="wrap">
<div class="cards">{cards_html}</div>
{notes_html}
<h2 class="sec">Findings</h2>
{findings_html}
{web_html}
{nuclei_html}
{ai_html}
<footer>Generated by SilentPivot · for authorized security testing only</footer>
</div></body></html>"""


def default_filename(report, ext):
    ip = report.get("resolved_ip") or "target"
    safe_target = report["target"].replace("/", "_").replace(":", "_")
    stamp = datetime.now().strftime("%Y%m%d_%H%M")
    return f"{ip}({safe_target})_{stamp}.{ext}"


def save_report(report, fmt="md", output_path=None, out_dir="data"):
    """Write the report to disk in the requested format and return the path."""
    fmt = fmt.lower()
    renderers = {"json": to_json, "md": to_markdown, "markdown": to_markdown, "html": to_html}
    if fmt not in renderers:
        raise ValueError(f"Unsupported format: {fmt}")

    content = renderers[fmt](report)
    ext = {"json": "json", "html": "html"}.get(fmt, "md")

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
