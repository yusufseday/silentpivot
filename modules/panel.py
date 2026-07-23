"""SilentPivot command center — interactive terminal panel.
Launched when the program is run without arguments; drives every tool from one menu."""
import os
import glob

from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.panel import Panel as RichPanel
from rich.markdown import Markdown

from modules import ui
from modules.ui import console
from modules.scanner import NetworkScanner, SCAN_LABELS
from modules.vuln_checker import VulnChecker
from modules.ai_engine import SilentAI
from modules.subdomain import SubdomainScanner
from modules.portcheck import PortChecker
from modules.webprobe import WebProber, WEB_PORTS
from modules.nuclei import NucleiScanner
from modules.bypass403 import Bypass403
from modules.leakfinder import LeakFinder
from modules.pathtraversal import PathTraversal
from modules.autopilot import run_autopilot
from modules import reporter


class CommandCenter:
    def __init__(self):
        # The last nmap scan is kept here so follow-up tools can chain off it.
        self.last_target = None
        self.last_scan_type = None
        self.last_results = None  # findings enriched with CVE data
        self.last_nuclei = None   # last nuclei findings
        self.last_web = []        # last web-probe fingerprints
        self.last_scan_meta = {}  # multi-IP / protected-target context

    # ---------- Menu loop ----------
    def run(self):
        ui.print_banner()
        while True:
            self._show_menu()
            choice = Prompt.ask("\n[bold cyan]Choice[/bold cyan]", default="0").strip().lower()
            action = self.MENU.get(choice)
            if action is None:
                ui.warn("Invalid choice.")
                continue
            if action == "exit":
                console.print("\n[bold green]See you. Stay safe.[/bold green]\n")
                break
            try:
                getattr(self, action)()
            except KeyboardInterrupt:
                ui.warn("Cancelled, returning to menu.")
            except Exception as e:
                ui.error(f"Unexpected error: {e}")
            console.print()

    MENU = {
        "a": "tool_autopilot",
        "?": "tool_copilot",
        "1": "tool_nmap",
        "2": "tool_subdomain",
        "3": "tool_portcheck",
        "4": "tool_webprobe",
        "5": "tool_nuclei",
        "6": "tool_vuln",
        "7": "tool_ai_report",
        "8": "tool_reports",
        "9": "tool_bypass403",
        "l": "tool_leak",
        "p": "tool_pathtraversal",
        "0": "exit",
    }

    def _show_menu(self):
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style="bold cyan", justify="right")
        t.add_column()
        t.add_row("A", "[bold green]Autopilot / Full Engagement[/bold green] [dim](runs the whole pipeline)[/dim]")
        t.add_row("?", "[bold magenta]AI Co-pilot[/bold magenta]             [dim](what should I do next?)[/dim]")
        t.add_row("", "")
        t.add_row("1", "Nmap Port Scan          [dim](service/version detection)[/dim]")
        t.add_row("2", "Subdomain Discovery     [dim](crt.sh passive OSINT + DNS)[/dim]")
        t.add_row("3", "Quick Port Check        [dim](open/closed — no nmap needed)[/dim]")
        t.add_row("4", "Web Probe & Fingerprint [dim](HTTP tech/WAF detection)[/dim]")
        t.add_row("5", "Nuclei Vuln Scan        [dim](active templated scanning)[/dim]")
        t.add_row("6", "CVE + KEV Vuln Analysis [dim](on the last scan)[/dim]")
        t.add_row("7", "Generate AI Report      [dim](on the last scan)[/dim]")
        t.add_row("8", "Saved Reports")
        t.add_row("9", "403 Bypass              [dim](forbidden-path bypass techniques)[/dim]")
        t.add_row("L", "Leak / Secret Finder    [dim](exposed keys, tokens, .git/.env)[/dim]")
        t.add_row("P", "Path Traversal / LFI    [dim](parameter file-read fuzzing)[/dim]")
        t.add_row("0", "[red]Exit[/red]")
        status = self._status_line()
        console.print(RichPanel(t, title="[bold]Command Center[/bold]", subtitle=status,
                                border_style="green"))

    def _status_line(self):
        if self.last_results is None:
            return "[dim]no active scan[/dim]"
        return (f"[dim]last target:[/dim] [cyan]{self.last_target}[/cyan] "
                f"[dim]| {len(self.last_results)} open ports[/dim]")

    # ---------- Tools ----------
    def tool_copilot(self):
        if not self.last_results and not self.last_nuclei:
            ui.warn("Run a scan first ([A] Autopilot or [1] Nmap) so the co-pilot has "
                    "something to reason about.")
            return
        ui.info("Co-pilot reviewing the current recon state...")
        advice = SilentAI().copilot(
            findings=self.last_results or [],
            web=self.last_web,
            nuclei=self.last_nuclei or [],
            scan_meta=self.last_scan_meta,
            target=self.last_target,
        )
        console.print(RichPanel.fit("[bold magenta]AI CO-PILOT — NEXT MOVES[/bold magenta]"))
        console.print(Markdown(advice))
        console.print("[dim]Suggestions only — verify each against your authorized scope.[/dim]")

    def tool_autopilot(self):
        target = Prompt.ask("Target IP/domain", default=self.last_target or "").strip()
        if not target:
            return
        console.print("[1] Fast  [2] Standard  [3] Deep")
        scan_type = Prompt.ask("Nmap scan type", choices=["1", "2", "3"], default="2")
        use_ai = Confirm.ask("Generate AI report?", default=True)

        console.rule("[bold green]AUTOPILOT[/bold green]")
        report = run_autopilot(target, scan_type, use_ai=use_ai, log=ui.info)
        if report is None:
            ui.warn("No open ports found, or the host is down.")
            return

        # Remember for follow-up tools
        self.last_target = target
        self.last_scan_type = scan_type
        self.last_results = report["findings"]
        self.last_nuclei = report["nuclei"]
        self.last_web = report["web"]

        console.print()
        ui.print_summary_table(report["findings"])
        if report["web"]:
            self._print_web_table(report["web"])
        if report["nuclei"]:
            crit_high = sum(1 for f in report["nuclei"] if f["severity"] in ("CRITICAL", "HIGH"))
            ui.info(f"Nuclei: {len(report['nuclei'])} findings ({crit_high} critical/high)")
        if report.get("ai_analysis"):
            console.print(RichPanel.fit("[bold cyan]ENGAGEMENT REPORT[/bold cyan]"))
            console.print(Markdown(report["ai_analysis"]))

        fmt = Prompt.ask("Save report format", choices=["md", "json", "html"], default="md")
        path = reporter.save_report(report, fmt=fmt)
        ui.success(f"Unified report saved: {path}")

    def tool_nmap(self):
        target = Prompt.ask("Target IP/domain").strip()
        if not target:
            return
        console.print("[1] Fast  [2] Standard  [3] Deep")
        scan_type = Prompt.ask("Scan type", choices=["1", "2", "3"], default="2")

        # If the host resolves to multiple IPs, let the user pin one (or scan all).
        scan_targets = self._select_scan_targets(target)

        raw_all, metas = [], {}
        for tgt in scan_targets:
            ui.info(f"Scanning {tgt} ({SCAN_LABELS[scan_type]})...")
            scanner = NetworkScanner()
            res = scanner.scan_target(tgt, scan_type)
            for r in res:
                r["ip"] = tgt
            raw_all.extend(res)
            metas[tgt] = scanner.scan_meta

        if not raw_all:
            # Distinguish "reachable but firewalled" from "genuinely down/no services".
            if any(m.get("blocked") for m in metas.values()):
                ui.warn("Host is reachable but every scanned port is filtered/closed.")
                console.print("[dim]    A firewall is blocking the scan — often your own "
                              "network (restricted/guest Wi-Fi). Try a different network.[/dim]")
            else:
                ui.warn("No open ports found, or the host is down.")
            return

        # Auto-enrich the aggregate with CVE + KEV (single flow, no extra clicks)
        ui.info("Verifying vulnerabilities against NVD + CISA KEV...")
        enriched = VulnChecker().check_vulnerabilities(raw_all)
        self.last_target, self.last_scan_type, self.last_results = target, scan_type, enriched
        self.last_scan_meta = metas[scan_targets[0]] if len(scan_targets) == 1 else {}

        # Display per scanned target so multi-IP results stay clear.
        for tgt in scan_targets:
            subset = [r for r in enriched if r.get("ip") == tgt]
            if len(scan_targets) > 1:
                console.rule(f"[cyan]{tgt}[/cyan]")
            self._show_scan_context(metas[tgt])
            self._check_waf(tgt, subset, metas[tgt])
            self._show_scan_results(subset, metas[tgt])
        ui.success("Scan complete. Press [7] for an AI report, [6] for CVE details.")

    def _print_web_table(self, results, title="Web Fingerprint"):
        """Render web-fingerprint results as a table (shared by webprobe + autopilot)."""
        t = Table(title=title)
        t.add_column("URL", style="cyan", no_wrap=False)
        t.add_column("Code", justify="right")
        t.add_column("Title")
        t.add_column("Server")
        t.add_column("Tech")
        t.add_column("WAF/CDN")
        for r in results:
            code = r.get("status", 0)
            code_style = "green" if code < 400 else ("yellow" if code < 500 else "red")
            waf = r.get("waf") or []
            t.add_row(
                r.get("url", "-"),
                f"[{code_style}]{code}[/]",
                r.get("title") or "[dim]-[/dim]",
                r.get("server") or "[dim]-[/dim]",
                ", ".join(r.get("tech") or []) or "[dim]-[/dim]",
                ("[bold magenta]" + ", ".join(waf) + "[/]") if waf else "[dim]-[/dim]",
            )
        console.print(t)

    def _check_waf(self, host, results, meta):
        """Header-based WAF/CDN detection on open web ports (reliable in any mode)."""
        web_ports = [r["port"] for r in results if r["port"] in WEB_PORTS]
        if not web_ports:
            return
        try:
            wafs = WebProber().detect_waf(host, web_ports)
        except Exception:
            wafs = []
        if wafs:
            meta["waf"] = wafs
            ui.warn(f"WAF/CDN detected: [bold magenta]{', '.join(wafs)}[/bold magenta] "
                    f"— responses are likely filtered/challenged, treat with care")

    def _select_scan_targets(self, target):
        """Return the list of hosts to scan. Prompts only when a domain resolves
        to more than one IP (single-IP / IP targets scan straight through)."""
        ips = NetworkScanner.resolve_all(target)
        # Drop IPv6 addresses if this machine has no IPv6 route — otherwise those
        # scans just time out. Works on any network (auto-detected), not just ours.
        v6 = [ip for ip in ips if ":" in ip]
        if v6 and not NetworkScanner.has_ipv6():
            ips = [ip for ip in ips if ":" not in ip]
            ui.info(f"Skipping {len(v6)} IPv6 address(es) — no IPv6 connectivity here")
        if len(ips) <= 1:
            return ips or [target]
        console.print(f"\n[yellow]{target} resolves to {len(ips)} IPs:[/yellow]")
        for i, ip in enumerate(ips, 1):
            console.print(f"  [cyan]{i}[/cyan]  {ip}")
        console.print("  [cyan]A[/cyan]  Scan all sequentially")
        choice = Prompt.ask("Which to scan", default="1").strip().lower()
        if choice == "a":
            return ips
        if choice.isdigit() and 1 <= int(choice) <= len(ips):
            return [ips[int(choice) - 1]]
        return [ips[0]]

    def _show_scan_context(self, meta):
        """Surface the important context so nothing escapes the user's eye."""
        ips = meta.get("ips") or []
        if len(ips) > 1:
            others = [ip for ip in ips if ip != meta.get("scanned_ip")]
            ui.warn(f"Target resolves to {len(ips)} IPs; scanned "
                    f"[bold]{meta.get('scanned_ip')}[/bold]. "
                    f"Others: {', '.join(others)}")
            console.print("[dim]    (scan an IP directly to pin a specific node)[/dim]")
        if meta.get("protected"):
            ui.warn(f"{meta.get('total_open')} ports responded but only "
                    f"{meta.get('confirmed')} could be confirmed — target likely behind "
                    f"a WAF / anti-scan device. Treat these results as deceptive.")

    def _show_scan_results(self, enriched, meta):
        """Layered view: confirmed services up front; noise collapsed but not lost."""
        confirmed = [r for r in enriched if r.get("confirmed")]
        unconfirmed = [r for r in enriched if not r.get("confirmed")]

        if meta.get("protected"):
            # Deceptive target: show only confirmed, collapse the phantom ports.
            if confirmed:
                ui.print_summary_table(confirmed, title="Confirmed Services")
            else:
                ui.info("No services could be confirmed on this host.")
            if unconfirmed:
                console.print(f"[dim]+ {len(unconfirmed)} unconfirmed ports hidden "
                              f"(no service banner, likely decoy) — full list is saved "
                              f"in the report[/dim]")
        else:
            # Normal target: show everything (unconfirmed just lack a version).
            ui.print_summary_table(enriched)

    def tool_subdomain(self):
        domain = Prompt.ask("Target domain (e.g. example.com)").strip()
        if not domain:
            return
        active = Confirm.ask("Include active DNS brute-force? (deeper, slower)", default=True)
        scanner = SubdomainScanner()
        engine = scanner.detect_tool() or "passive OSINT"
        ui.info(f"Deep research on {domain}: passive ({engine}) + "
                f"{'active brute + ' if active else ''}enrichment + takeover check...")
        ui.info("This can take up to a minute...")
        results = scanner.scan(domain, active=active)
        if not results:
            ui.warn("No subdomains found, or sources did not respond.")
            return

        st = scanner.stats
        contrib = ", ".join(f"{k}:{v}" for k, v in st.get("passive_sources", {}).items() if v)
        ui.info(f"Engine: [bold]{st.get('method')}[/bold]  |  passive -> {contrib}  |  "
                f"active brute -> {st.get('active_found')}"
                + ("  [yellow](wildcard DNS)[/yellow]" if st.get("wildcard") else ""))

        resolved = [r for r in results if r["resolved"]]
        t = Table(title=f"{domain} — {len(results)} subdomains, {len(resolved)} resolved")
        t.add_column("Subdomain", style="cyan", no_wrap=False)
        t.add_column("IP")
        t.add_column("HTTP", justify="right")
        t.add_column("Origin")
        t.add_column("Takeover")
        # Show resolved ones (the actionable set); note the rest.
        for r in resolved:
            code = r.get("http_status")
            http = f"{code}" if code else "[dim]-[/dim]"
            origin = {"both": "[green]active+passive[/]", "active": "[yellow]active[/]",
                      "passive": "[cyan]passive[/]"}.get(r["origin"], r["origin"])
            takeover = f"[bold red]{r['takeover']}[/]" if r.get("takeover") else "[dim]-[/dim]"
            t.add_row(r["host"], r["ip"], http, origin, takeover)
        console.print(t)

        unresolved = len(results) - len(resolved)
        if unresolved:
            console.print(f"[dim]+ {unresolved} subdomain(s) found but not currently resolving[/dim]")
        takeovers = [r for r in results if r.get("takeover")]
        if takeovers:
            ui.error(f"⚠ {len(takeovers)} POTENTIAL SUBDOMAIN TAKEOVER(S):")
            for r in takeovers:
                console.print(f"    [bold red]{r['host']}[/] → {r['takeover']} (dangling)")
        ui.success(f"{len(resolved)} resolved subdomains ({len(results)} total discovered).")

    def tool_portcheck(self):
        host = Prompt.ask("Target IP/host").strip()
        if not host:
            return
        spec = Prompt.ask("Ports ('top', '22,80,443' or '1-1024')", default="top")
        ports = PortChecker.parse_ports(spec)
        ui.info(f"Checking ports on {host}...")
        results = PortChecker().scan(host, ports=ports, only_open=True)
        if results is None:
            ui.error("Target could not be resolved via DNS.")
            return
        if not results:
            ui.warn("No open ports found.")
            return
        t = Table(title=f"{host} — Open Ports")
        t.add_column("Port", justify="right", style="cyan")
        t.add_column("Service")
        t.add_column("State")
        for r in results:
            t.add_row(str(r["port"]), r["service"], "[green]OPEN[/green]")
        console.print(t)
        ui.success(f"{len(results)} open ports found.")

    def tool_webprobe(self):
        default = self.last_target or ""
        host = Prompt.ask("Target host/domain", default=default).strip()
        if not host:
            return

        # If we scanned this host with nmap, probe exactly the open web ports found.
        ports = None
        if host == self.last_target and self.last_results:
            web = [r["port"] for r in self.last_results if r["port"] in WEB_PORTS]
            if web:
                ports = web
                ui.info(f"Using open web ports from the last scan: {web}")

        ui.info(f"Probing web services on {host}...")
        results = WebProber().probe_host(host, ports=ports)
        if not results:
            ui.warn("No reachable web services found.")
            return
        self.last_web = results

        self._print_web_table(results, title=f"{host} — Web Fingerprint")
        ui.success(f"{len(results)} web endpoint(s) fingerprinted.")

    def tool_nuclei(self):
        scanner = NucleiScanner()
        if not scanner.available:
            ui.warn("nuclei is not installed / not on PATH.")
            console.print("[dim]Install: https://github.com/projectdiscovery/nuclei "
                          "(or `apt install nuclei` on Kali)[/dim]")
            return
        default = self.last_target or ""
        target = Prompt.ask("Target URL/host", default=default).strip()
        if not target:
            return
        sev = Prompt.ask("Severities (comma-separated)", default="medium,high,critical").strip()
        severities = [s.strip().lower() for s in sev.split(",") if s.strip()]

        ui.info(f"Running nuclei against {target} [sev: {sev}] — this can take a while...")
        findings = scanner.scan(target, severities=severities)
        if findings is None:
            ui.warn("nuclei became unavailable.")
            return
        self.last_nuclei = findings
        meta = scanner.meta
        tmpl = meta.get("templates")

        # Distinguish a genuine "no findings" from an error / missing templates.
        if tmpl == 0:
            ui.error("nuclei loaded 0 templates. Install them first: "
                     "[bold]nuclei -update-templates[/bold]")
            return
        if not findings and meta.get("errors"):
            ui.error(f"nuclei reported errors (exit {meta.get('returncode')}):")
            for e in meta["errors"]:
                console.print(f"  [red]{e}[/red]")
            return

        tmpl_note = f" [dim]({tmpl} templates ran)[/dim]" if tmpl else ""
        if not findings:
            ui.success(f"nuclei finished — no findings at the selected severities.{tmpl_note}")
            return
        console.print(f"[dim]{tmpl} templates ran[/dim]" if tmpl else "")

        t = Table(title=f"{target} — Nuclei Findings ({len(findings)})")
        t.add_column("Severity")
        t.add_column("Template", style="cyan")
        t.add_column("Name")
        t.add_column("Detail")
        t.add_column("Matched At")
        for f in findings:
            sv = f["severity"]
            t.add_row(
                f"[{ui.SEVERITY_COLORS.get(sv, 'dim')}]{sv}[/]",
                f["template_id"],
                f["name"] or "[dim]-[/dim]",
                f.get("matcher_name") or "[dim]-[/dim]",
                f["matched_at"] or "[dim]-[/dim]",
            )
        console.print(t)
        crit_high = sum(1 for f in findings if f["severity"] in ("CRITICAL", "HIGH"))
        ui.success(f"{len(findings)} findings ({crit_high} critical/high).")

    def tool_vuln(self):
        if not self.last_results:
            ui.warn("Run an Nmap scan first via [1].")
            return
        t = Table(title=f"{self.last_target} — Vulnerability Detail")
        t.add_column("Port", justify="right", style="cyan")
        t.add_column("Service")
        t.add_column("CVE")
        t.add_column("CVSS")
        t.add_column("EPSS")
        t.add_column("KEV")
        t.add_column("Exploit")
        any_cve = False
        for r in self.last_results:
            for c in (r.get("cves") or []):
                any_cve = True
                sev = c.get("severity", "UNKNOWN")
                epss = c.get("epss")
                epss_str = f"{epss * 100:.1f}%" if isinstance(epss, (int, float)) else "[dim]-[/dim]"
                # Exploit availability: ExploitDB > public PoC > none
                if c.get("exploitdb"):
                    exp = f"[bold red]EDB:{','.join(map(str, c['exploitdb'][:2]))}[/]"
                elif c.get("poc"):
                    exp = f"[yellow]PoC x{c.get('poc_count')}[/]"
                else:
                    exp = "[dim]-[/dim]"
                t.add_row(
                    str(r["port"]), r["service"], c["id"],
                    f"[{ui.SEVERITY_COLORS.get(sev, 'dim')}]{c.get('cvss')} {sev}[/]",
                    epss_str,
                    "[bold red]ACTIVE[/]" if c.get("kev") else "[dim]-[/dim]",
                    exp,
                )
        if not any_cve:
            ui.warn("No verified CVEs found.")
            return
        console.print(t)
        console.print("[dim]EDB = ExploitDB ID · PoC = public GitHub exploit · "
                      "EPSS = exploitation probability[/dim]")

    def tool_ai_report(self):
        if not self.last_results:
            ui.warn("Run an Nmap scan first via [1].")
            return
        ui.info("Sending data to AI analysis...")
        analysis = SilentAI().analyze_results(self.last_results)
        console.print(RichPanel.fit("[bold cyan]PENTEST REPORT[/bold cyan]"))
        console.print(Markdown(analysis))

        fmt = Prompt.ask("Report format", choices=["md", "json", "html"], default="md")
        report = reporter.build_report_data(
            self.last_target, SCAN_LABELS.get(self.last_scan_type, "?"),
            self.last_results, analysis, scan_meta=self.last_scan_meta,
        )
        path = reporter.save_report(report, fmt=fmt)
        ui.success(f"Report saved: {path}")

    def tool_bypass403(self):
        url = Prompt.ask("Forbidden URL (e.g. https://host/admin)").strip()
        if not url:
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        ui.info(f"Trying 403/401 bypass techniques on {url} ...")
        result = Bypass403().run(url)
        if result["baseline"] is None:
            ui.error("Could not reach the URL.")
            return
        if not result["applicable"]:
            ui.warn(f"URL returned {result['baseline']} (not 401/403) — nothing to bypass.")
            return
        hits = result["hits"]
        if not hits:
            ui.success(f"Baseline {result['baseline']} — no bypass found "
                       f"(access control looks solid).")
            return
        t = Table(title=f"{url} — Bypass Hits (baseline {result['baseline']})")
        t.add_column("Status", justify="right")
        t.add_column("Technique", style="cyan")
        t.add_column("Method")
        t.add_column("Length", justify="right")
        for h in hits:
            code_style = "green" if h["status"] < 300 else "yellow"
            t.add_row(f"[{code_style}]{h['status']}[/]", h["technique"],
                      h["method"], str(h["length"]))
        console.print(t)
        ui.warn(f"{len(hits)} potential bypass(es) — verify manually (a 200 can still "
                f"be a login/redirect page).")

    def tool_leak(self):
        default = self.last_target or ""
        url = Prompt.ask("Target URL/host", default=default).strip()
        if not url:
            return
        ui.info(f"Hunting for secrets and exposed files on {url} ...")
        result = LeakFinder().run(url)
        secrets, exposed = result["secrets"], result["exposed"]

        if secrets:
            t = Table(title=f"Exposed Secrets ({len(secrets)})")
            t.add_column("Type", style="cyan")
            t.add_column("Value")
            t.add_column("Confidence")
            t.add_column("Source")
            conf_color = {"high": "bold red", "medium": "yellow", "low": "dim"}
            for s in secrets:
                t.add_row(s["type"], s["value"],
                          f"[{conf_color.get(s['confidence'], 'dim')}]{s['confidence']}[/]",
                          s["source"])
            console.print(t)

        if exposed:
            t = Table(title=f"Exposed Files ({len(exposed)})")
            t.add_column("Path", style="cyan")
            t.add_column("Size", justify="right")
            t.add_column("Confidence")
            for e in exposed:
                cc = "bold red" if e["confidence"] == "high" else "yellow"
                t.add_row(e["path"], str(e["size"]), f"[{cc}]{e['confidence']}[/]")
            console.print(t)

        if not secrets and not exposed:
            ui.success("No exposed secrets or sensitive files found.")
        else:
            ui.warn(f"{len(secrets)} secret(s), {len(exposed)} exposed file(s) — "
                    f"verify (low-confidence hits may be false positives).")

    def tool_pathtraversal(self):
        console.print("[dim]Tip: include a parameter, e.g. https://host/view.php?file=welcome[/dim]")
        url = Prompt.ask("Target URL").strip()
        if not url:
            return
        ui.info(f"Fuzzing {url} for path traversal / LFI ...")
        result = PathTraversal().run(url)
        if result["used_common_params"]:
            ui.info(f"No query parameter in the URL — trying common names: "
                    f"{', '.join(result['params'][:6])}...")
        hits = result["hits"]
        if not hits:
            ui.success("No path traversal / LFI found (no file-read evidence).")
            return
        t = Table(title=f"{result['url']} — Path Traversal / LFI Hits")
        t.add_column("Param", style="cyan")
        t.add_column("Signature", style="bold red")
        t.add_column("Status", justify="right")
        t.add_column("Payload")
        for h in hits:
            payload = h["payload"] if len(h["payload"]) < 45 else h["payload"][:42] + "..."
            t.add_row(h["param"], h["signature"], str(h["status"]), payload)
        console.print(t)
        ui.error(f"⚠ {len(hits)} confirmed file-read(s) — evidence found in the response.")
        for h in hits[:3]:
            console.print(f"    [dim]{h['param']}:[/dim] [green]{h['evidence']}[/green]")

    def tool_reports(self):
        files = sorted(glob.glob(os.path.join("data", "*.md")) +
                       glob.glob(os.path.join("data", "*.json")) +
                       glob.glob(os.path.join("data", "*.html")),
                       key=os.path.getmtime, reverse=True)
        if not files:
            ui.warn("No saved reports yet.")
            return
        t = Table(title="Saved Reports")
        t.add_column("#", justify="right", style="cyan")
        t.add_column("File")
        t.add_column("Size", justify="right")
        for i, f in enumerate(files[:20], 1):
            t.add_row(str(i), os.path.basename(f), f"{os.path.getsize(f)} B")
        console.print(t)
        sel = Prompt.ask("View # (blank to skip)", default="").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(files):
            path = files[int(sel) - 1]
            if path.endswith(".html"):
                # Raw HTML in a terminal is noise; point to the browser instead.
                ui.info(f"Open in a browser: [cyan]{path}[/cyan]  "
                        f"[dim](e.g. xdg-open / firefox {path})[/dim]")
            else:
                with open(path, encoding="utf-8") as fh:
                    console.print(RichPanel(fh.read(), border_style="dim"))
