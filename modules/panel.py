"""SilentPivot command center — interactive terminal panel.
Launched when the program is run without arguments; drives every tool from one menu."""
import os
import glob

from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel as RichPanel

from modules import ui
from modules.ui import console
from modules.scanner import NetworkScanner
from modules.vuln_checker import VulnChecker
from modules.ai_engine import SilentAI
from modules.subdomain import SubdomainScanner
from modules.portcheck import PortChecker
from modules import reporter

SCAN_LABELS = {
    "1": "Fast (Top 100)",
    "2": "Standard (1-1000 + version)",
    "3": "Deep (All ports + OS)",
}


class CommandCenter:
    def __init__(self):
        # The last nmap scan is kept here so follow-up tools can chain off it.
        self.last_target = None
        self.last_scan_type = None
        self.last_results = None  # findings enriched with CVE data

    # ---------- Menu loop ----------
    def run(self):
        ui.print_banner()
        while True:
            self._show_menu()
            choice = Prompt.ask("\n[bold cyan]Choice[/bold cyan]", default="0").strip()
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
        "1": "tool_nmap",
        "2": "tool_subdomain",
        "3": "tool_portcheck",
        "4": "tool_vuln",
        "5": "tool_ai_report",
        "6": "tool_reports",
        "0": "exit",
    }

    def _show_menu(self):
        t = Table(show_header=False, box=None, padding=(0, 2))
        t.add_column(style="bold cyan", justify="right")
        t.add_column()
        t.add_row("1", "Nmap Port Scan          [dim](service/version detection)[/dim]")
        t.add_row("2", "Subdomain Discovery     [dim](crt.sh passive OSINT + DNS)[/dim]")
        t.add_row("3", "Quick Port Check        [dim](open/closed — no nmap needed)[/dim]")
        t.add_row("4", "CVE + KEV Vuln Analysis [dim](on the last scan)[/dim]")
        t.add_row("5", "Generate AI Report      [dim](on the last scan)[/dim]")
        t.add_row("6", "Saved Reports")
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
    def tool_nmap(self):
        target = Prompt.ask("Target IP/domain").strip()
        if not target:
            return
        console.print("[1] Fast  [2] Standard  [3] Deep")
        scan_type = Prompt.ask("Scan type", choices=["1", "2", "3"], default="2")

        ui.info(f"Scanning {target} ({SCAN_LABELS[scan_type]})...")
        results = NetworkScanner().scan_target(target, scan_type)
        if not results:
            ui.warn("No open ports found, or the host is down.")
            return

        # Auto-enrich with CVE + KEV (single flow, no extra clicks)
        ui.info("Verifying vulnerabilities against NVD + CISA KEV...")
        enriched = VulnChecker().check_vulnerabilities(results)
        self.last_target, self.last_scan_type, self.last_results = target, scan_type, enriched

        console.print()
        ui.print_summary_table(enriched)
        ui.success("Scan complete. Press [5] for an AI report, [4] for CVE details.")

    def tool_subdomain(self):
        domain = Prompt.ask("Target domain (e.g. example.com)").strip()
        if not domain:
            return
        scanner = SubdomainScanner()
        tool = scanner._detect_tool()
        engine = tool if tool else "passive OSINT (crt.sh, certspotter, OTX, ...)"
        ui.info(f"Enumerating {domain} via {engine}...")
        results = scanner.scan(domain, resolve=True)
        if not results:
            ui.warn("No subdomains found, or sources did not respond.")
            return

        # Show which sources contributed (transparency + trust)
        st = scanner.stats
        contrib = ", ".join(f"{k}:{v}" for k, v in st.get("sources", {}).items() if v)
        ui.info(f"Engine: [bold]{st.get('method')}[/bold]  |  sources -> {contrib}")

        live = [r for r in results if r["live"]]
        t = Table(title=f"{domain} — {len(results)} subdomains, {len(live)} live")
        t.add_column("Subdomain", style="cyan")
        t.add_column("IP")
        t.add_column("State")
        for r in results:
            if r["live"]:
                t.add_row(r["host"], r["ip"], "[green]LIVE[/green]")
            else:
                t.add_row(r["host"], "[dim]-[/dim]", "[dim]unresolved[/dim]")
        console.print(t)
        ui.success(f"{len(live)} live subdomains detected.")

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
        from rich.markdown import Markdown
        console.print(Markdown(analysis))

        fmt = Prompt.ask("Report format", choices=["md", "json"], default="md")
        report = reporter.build_report_data(
            self.last_target, SCAN_LABELS.get(self.last_scan_type, "?"),
            self.last_results, analysis,
        )
        path = reporter.save_report(report, fmt=fmt)
        ui.success(f"Report saved: {path}")

    def tool_reports(self):
        files = sorted(glob.glob(os.path.join("data", "*.md")) +
                       glob.glob(os.path.join("data", "*.json")),
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
            with open(files[int(sel) - 1], encoding="utf-8") as fh:
                console.print(RichPanel(fh.read(), border_style="dim"))
