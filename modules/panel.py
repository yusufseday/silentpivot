"""SilentPivot command center — interactive terminal panel.
Launched when the program is run without arguments; drives every tool from one menu."""
import os
import glob
from urllib.parse import urlparse

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
from modules.ssrf import SSRFScanner
from modules.contentdisco import ContentDiscovery
from modules import contentdisco
from modules.autopilot import run_autopilot
from modules.opsec import profile as opsec, NORMAL, STEALTH, PASSIVE
from modules import attack_map
from modules import validators
from modules import reporter
from modules.tasktree import TaskTree, OPEN, DONE, NO_RESULT


# Tools whose output should feed the persistent task tree. Kept as one explicit list
# (rather than scattering _sync_tree() calls across ten methods) so it's obvious at a
# glance which tools are tracked and none can be silently missed.
_TREE_SYNC_ACTIONS = {
    "tool_autopilot", "tool_nmap", "tool_subdomain", "tool_webprobe", "tool_nuclei",
    "tool_leak", "tool_pathtraversal", "tool_ssrf", "tool_bypass403", "tool_content",
}


class CommandCenter:
    def __init__(self):
        # The last nmap scan is kept here so follow-up tools can chain off it.
        self.last_target = None
        self.last_scan_type = None
        self.last_results = None  # findings enriched with CVE data
        self.last_nuclei = None   # last nuclei findings
        self.last_nuclei_meta = {}
        self.last_web = []        # last web-probe fingerprints
        self.last_scan_meta = {}  # multi-IP / protected-target context
        # Extra recon state so the co-pilot can reason after ANY tool, not just nmap.
        self.last_subdomains = []
        self.last_ports = []
        self.last_leak = None
        self.last_vulns = []      # confirmed hits from active modules (403/LFI/SSRF)
        self.last_content = []    # discovered paths
        self.last_attack = []     # mapped ATT&CK techniques
        self.last_attack_story = None
        self.tree = None          # persistent per-target TaskTree (see _sync_tree)

    # ---------- Menu loop ----------
    def run(self):
        ui.print_banner()
        # The full menu is drawn once; afterwards a single compact line keeps the
        # terminal readable so scan output stays visible instead of being pushed away
        # by a 20-line menu after every action. 'h' brings the full menu back.
        self._show_menu()
        while True:
            choice = self._ask_choice()
            action = self.MENU.get(choice)
            if action is None:
                ui.warn("Invalid choice — press [bold]h[/bold] for the full menu.")
                continue
            if action == "exit":
                console.print("\n[bold green]See you. Stay safe.[/bold green]\n")
                break
            if action == "help":
                self._show_menu()
                continue
            try:
                getattr(self, action)()
                # Every finding-producing tool feeds the persistent task tree here,
                # in one place, so no tool can forget to — and a tool that only reads
                # state (co-pilot, ATT&CK map, task tree itself) just no-ops (nothing
                # new to ingest, or it already synced internally).
                if action in _TREE_SYNC_ACTIONS:
                    self._sync_tree()
            except KeyboardInterrupt:
                ui.warn("Cancelled, returning to menu.")
            except Exception as e:
                ui.error(f"Something went wrong: {e}")
                console.print("[dim]    (returning to the menu — nothing was saved)[/dim]")
            console.print()

    def _ask_choice(self):
        """Compact prompt: one dim hint line (+ status only when there's state),
        instead of redrawing the full menu after every action."""
        console.print("[dim]A auto · ? co-pilot · 1-9/L/P/S tools · C content · "
                      "T tasks · M att&ck · O opsec · h menu · 0 exit[/dim]")
        if self.last_results or self.last_target or opsec.mode != NORMAL or opsec.proxy:
            console.print(f"[dim]{self._status_line()}[/dim]")
        return Prompt.ask("[bold cyan]›[/bold cyan]", default="0").strip().lower()

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
        "s": "tool_ssrf",
        "c": "tool_content",
        "t": "tool_tasktree",
        "m": "tool_attack_map",
        "o": "tool_opsec",
        "h": "help",
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
        t.add_row("S", "SSRF Scan               [dim](reflected SSRF + AI payloads)[/dim]")
        t.add_row("C", "Content Discovery       [dim](hidden paths, panels, backups)[/dim]")
        t.add_row("", "")
        t.add_row("T", "[bold]Task Tree[/bold]               [dim](persistent leads — survives restarts)[/dim]")
        t.add_row("M", "[bold]ATT&CK Map[/bold]              [dim](techniques + AI kill-chain narrative)[/dim]")
        t.add_row("O", "OPSEC Profile           [dim](stealth / passive / proxy)[/dim]")
        t.add_row("h", "[dim]Show this menu again[/dim]")
        t.add_row("0", "[red]Exit[/red]")
        status = self._status_line()
        console.print(RichPanel(t, title="[bold]Command Center[/bold]", subtitle=status,
                                border_style="green"))

    def _status_line(self):
        # OPSEC is only called out when it's not the default, so normal runs stay clean.
        ops = "" if opsec.mode == NORMAL and not opsec.proxy else \
            f"[bold yellow]OPSEC: {opsec.summary()}[/] [dim]|[/dim] "
        if self.last_results is None:
            return f"{ops}[dim]no active scan[/dim]"
        return (f"{ops}[dim]last target:[/dim] [cyan]{self.last_target}[/cyan] "
                f"[dim]| {len(self.last_results)} open ports[/dim]")

    # ---------- Tools ----------
    def _remember_target(self, host_or_url):
        """Set last_target from a host or URL, normalized to a bare host. Every tool
        that can run standalone (without nmap having run first) calls this, so its
        findings always land in the SAME per-target task tree — a URL and a bare
        hostname for the same box must not fragment into two separate tree files."""
        if self.last_target:
            return
        host = urlparse(host_or_url).hostname if "://" in host_or_url else host_or_url
        self.last_target = host or host_or_url

    def _sync_tree(self):
        """Feed everything gathered this session into the persistent per-target task
        tree and save it. Called after every tool that can produce a finding, so the
        tree is never more than one action stale — and survives closing the tool."""
        if not self.last_target:
            return None
        if self.tree is None or self.tree.target != self.last_target:
            self.tree = TaskTree(self.last_target)
        self.tree.ingest(
            findings=self.last_results or [], nuclei=self.last_nuclei or [],
            web=self.last_web, subdomains=self.last_subdomains,
            leak=self.last_leak, vulns=self.last_vulns, content=self.last_content,
        )
        self.tree.save()
        return self.tree

    def tool_tasktree(self):
        target = validators.valid_target(
            Prompt.ask("Target (blank = current)", default=self.last_target or ""))
        if not target:
            saved = TaskTree.list_engagements()
            if not saved:
                ui.warn("No engagement history yet — run some recon first.")
                return
            ui.error(f"Invalid or missing target. Known engagements: {', '.join(saved)}")
            return
        self.last_target = self.last_target or target
        tree = self.tree if (self.tree and self.tree.target == target) else TaskTree(target)
        self.tree = tree
        self._sync_tree()

        summary = tree.summary()
        console.print(RichPanel.fit(
            f"[bold]{target}[/bold] — [green]{summary[DONE]} done[/] · "
            f"[yellow]{summary[OPEN]} open[/] · [dim]{summary[NO_RESULT]} no-result[/] "
            f"[dim](started {tree.created[:10]})[/dim]"))

        open_leads = tree.open_leads()
        if not open_leads:
            ui.success("No open leads — everything found so far is resolved or noted.")
        else:
            t = Table(title="Open Leads (highest priority first)")
            t.add_column("ID", style="dim")
            t.add_column("Lead", style="cyan")
            t.add_column("Evidence")
            t.add_column("Seen", justify="right")
            for lead in open_leads:
                t.add_row(lead["id"], ui.safe(lead["title"]), ui.safe(lead["evidence"]),
                          str(lead["seen"]))
            console.print(t)

        console.print("[dim]Enter a lead ID to mark it: d=done, n=no-result "
                      "(blank to skip)[/dim]")
        sel = Prompt.ask("Lead ID", default="").strip()
        if not sel:
            return
        lead_id = tree.find(sel)
        if not lead_id:
            ui.error("No unique lead matches that ID.")
            return
        status = Prompt.ask("Mark as", choices=["d", "n"], default="d")
        note = Prompt.ask("Note (optional)", default="").strip()
        tree.set_status(lead_id, DONE if status == "d" else NO_RESULT, note=note or None)
        ui.success(f"Lead {lead_id} marked {'done' if status == 'd' else 'no-result'}.")

    def _map_attack(self):
        """Map everything gathered this session into ATT&CK techniques."""
        return attack_map.map_findings(
            findings=self.last_results or [], nuclei=self.last_nuclei or [],
            web=self.last_web, subdomains=self.last_subdomains,
            leak=self.last_leak, vulns=self.last_vulns, scan_meta=self.last_scan_meta,
        )

    def tool_attack_map(self):
        techniques = self._map_attack()
        if not techniques:
            ui.warn("Nothing mapped yet — run some recon first ([A], [1], [2], [5], [L]...).")
            return

        t = Table(title=f"MITRE ATT&CK — {self.last_target or 'current session'} "
                        f"({len(techniques)} techniques)")
        t.add_column("Tactic", style="magenta")
        t.add_column("Technique", style="cyan")
        t.add_column("Name")
        t.add_column("Evidence")
        for tech in techniques:
            ev = ", ".join(tech["evidence"][:3])
            if len(tech["evidence"]) > 3:
                ev += f" (+{len(tech['evidence']) - 3})"
            tid = (f"[link=https://attack.mitre.org/techniques/"
                   f"{tech['id'].replace('.', '/')}/]{tech['id']}[/link]")
            t.add_row(tech["tactic"], tid, tech["name"], ui.safe(ev))
        console.print(t)

        # Coverage line: which kill-chain stages we already touch.
        summary = attack_map.tactic_summary(techniques)
        ui.info("Kill-chain coverage: " +
                " · ".join(f"{k} ({len(v)})" for k, v in summary.items()))

        if Confirm.ask("Generate the AI attack narrative?", default=True):
            ui.info("Building the adversary kill-chain story...")
            story = SilentAI().attack_narrative(techniques, target=self.last_target)
            console.print(RichPanel.fit("[bold red]ADVERSARY KILL-CHAIN[/bold red]"))
            console.print(Markdown(story))
            self.last_attack_story = story
        self.last_attack = techniques

    def tool_opsec(self):
        """Set the footprint profile every module obeys (timing, proxy, passive)."""
        console.print(RichPanel.fit(
            f"[bold]Current:[/bold] {opsec.summary()}", border_style="yellow"))
        console.print("[bold]1[/bold]  normal   [dim]fast, direct — default behaviour[/dim]")
        console.print("[bold]2[/bold]  stealth  [dim]slow nmap (-T1), request jitter, "
                      "low concurrency, rotating user-agents[/dim]")
        console.print("[bold]3[/bold]  passive  [dim]no packets to the target — OSINT only[/dim]")
        mode = Prompt.ask("Mode", choices=["1", "2", "3"],
                          default={NORMAL: "1", STEALTH: "2", PASSIVE: "3"}[opsec.mode])
        opsec.set_mode({"1": NORMAL, "2": STEALTH, "3": PASSIVE}[mode])

        cur = opsec.proxy or ""
        proxy = Prompt.ask("Proxy (e.g. socks5://127.0.0.1:9050, blank = none)",
                           default=cur).strip()
        # Validate BEFORE assigning: a rejected (or Ctrl+C'd) entry must never leave a
        # broken proxy configured behind it.
        problem = opsec.proxy_problem(proxy)
        if problem:
            ui.error(problem)
            try:
                keep = Confirm.ask("Keep this proxy anyway?", default=False)
            except KeyboardInterrupt:
                keep = False
                console.print()
            if not keep:
                proxy = ""
        opsec.set_proxy(proxy)

        ui.success(f"OPSEC profile: {opsec.summary()}")
        nmap_warn = opsec.nmap_proxy_warning()
        if nmap_warn:
            ui.warn(nmap_warn)
        if opsec.is_stealth:
            ui.info("Stealth is much slower by design — scans may take many minutes.")
        if opsec.is_passive:
            ui.info("Passive mode: port scans and active fuzzers are disabled; "
                    "OSINT tools (subdomain sources, CVE/KEV lookups) still work.")

    def _blocked_by_passive(self, what):
        """Guard for tools that send traffic to the target."""
        if opsec.is_passive:
            ui.warn(f"{what} is disabled in OPSEC passive mode (it would touch the target). "
                    f"Switch profile with [O].")
            return True
        return False

    def tool_copilot(self):
        # Build extra context from whatever tools have been run this session.
        extra = {}
        if self.last_subdomains:
            extra["subdomains"] = [{k: s.get(k) for k in ("host", "ip", "http_status")}
                                   for s in self.last_subdomains if s.get("resolved")][:40]
        if self.last_ports:
            extra["open_ports"] = [{"port": p["port"], "service": p.get("service")}
                                   for p in self.last_ports][:40]
        if self.last_leak:
            extra["leaks"] = {
                "secrets": [s["type"] for s in self.last_leak.get("secrets", [])],
                "exposed_files": [e["path"] for e in self.last_leak.get("exposed", [])],
            }
        if self.last_vulns:
            extra["confirmed_vulns"] = self.last_vulns[-10:]

        # Task tree: what's already been resolved (so the co-pilot doesn't propose it
        # again) and what's still open — including leads from a PRIOR session that
        # in-memory state above doesn't cover, since the tree survives restarts.
        tree = self._sync_tree()
        if tree:
            done = [l for l in tree.leads.values() if l["status"] != OPEN]
            if done:
                extra["already_handled"] = [f"{l['title']} ({l['status']})" for l in done][:20]
            open_leads = tree.open_leads()
            if open_leads:
                extra["untried_leads"] = [l["title"] for l in open_leads][:20]

        if not any([self.last_results, self.last_nuclei, self.last_web, extra]):
            ui.warn("Run any recon first (e.g. [1] Nmap, [2] Subdomain, [4] Web Probe, "
                    "[L] Leak, [P]/[S]/[9]) so the co-pilot has something to reason about.")
            return
        ui.info("Co-pilot reviewing the current recon state...")
        advice = SilentAI().copilot(
            findings=self.last_results or [],
            web=self.last_web,
            nuclei=self.last_nuclei or [],
            scan_meta=self.last_scan_meta,
            target=self.last_target,
            extra=extra,
        )
        console.print(RichPanel.fit("[bold magenta]AI CO-PILOT — NEXT MOVES[/bold magenta]"))
        console.print(Markdown(advice))
        console.print("[dim]Suggestions only — verify each against your authorized scope.[/dim]")

    def tool_autopilot(self):
        if self._blocked_by_passive("Autopilot"):
            return
        target = validators.valid_target(Prompt.ask("Target IP/domain",
                                                    default=self.last_target or ""))
        if not target:
            ui.error("Invalid target — expected an IP, CIDR or hostname (e.g. 10.0.2.9).")
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
        ui.success(f"Unified report saved: {ui.file_link(path)}")

    def tool_nmap(self):
        if self._blocked_by_passive("Nmap scanning"):
            return
        target = validators.valid_target(Prompt.ask("Target IP/domain"))
        if not target:
            ui.error("Invalid target — expected an IP, CIDR or hostname (e.g. 10.0.2.9).")
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
            url = r.get("url", "")
            t.add_row(
                f"[link={url}]{ui.safe(url)}[/link]" if url else "-",
                f"[{code_style}]{code}[/]",
                ui.safe(r.get("title")),
                ui.safe(r.get("server")),
                ui.safe(", ".join(r.get("tech") or [])),
                ("[bold magenta]" + ui.safe(", ".join(waf)) + "[/]") if waf else "[dim]-[/dim]",
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
        domain = validators.valid_domain(Prompt.ask("Target domain (e.g. example.com)"))
        if not domain:
            ui.error("Invalid domain — expected something like example.com.")
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
        self.last_subdomains = results
        self.last_target = self.last_target or domain

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
        # Show every discovered subdomain (resolved first); unresolved ones are still
        # useful intel (old/internal names), so they are listed rather than hidden.
        for r in results:
            code = r.get("http_status")
            if code:
                style = "green" if code < 400 else ("yellow" if code < 500 else "red")
                http = f"[{style}]{code}[/]"
            elif r["resolved"]:
                http = "[dim]no HTTP[/dim]"
            else:
                http = "[dim]-[/dim]"
            ip = r["ip"] if r["resolved"] else "[dim]unresolved[/dim]"
            origin = {"both": "[green]active+passive[/]", "active": "[yellow]active[/]",
                      "passive": "[cyan]passive[/]"}.get(r["origin"], r["origin"])
            takeover = f"[bold red]{ui.safe(r['takeover'])}[/]" if r.get("takeover") else "[dim]-[/dim]"
            # Show the full URL as the visible text: terminals that support OSC-8 get a
            # real hyperlink, and the ones that don't still auto-detect the plain URL.
            url = r.get("url") or "https://" + r["host"]
            t.add_row(f"[link={url}]{ui.safe(url)}[/link]", ui.safe(ip), http, origin, takeover)
        console.print(t)
        takeovers = [r for r in results if r.get("takeover")]
        if takeovers:
            ui.error(f"⚠ {len(takeovers)} POTENTIAL SUBDOMAIN TAKEOVER(S):")
            for r in takeovers:
                link = r.get("url") or "https://" + r["host"]
                console.print(f"    [link={link}][bold red]{r['host']}[/][/link] "
                              f"→ {r['takeover']} (dangling)")
        ui.success(f"{len(resolved)} resolved subdomains ({len(results)} total discovered).")

    def tool_portcheck(self):
        if self._blocked_by_passive("Port checking"):
            return
        host = validators.valid_target(Prompt.ask("Target IP/host"))
        if not host:
            ui.error("Invalid host — expected an IP or hostname.")
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
        self.last_ports = results
        self.last_target = self.last_target or host
        t = Table(title=f"{host} — Open Ports")
        t.add_column("Port", justify="right", style="cyan")
        t.add_column("Service")
        t.add_column("State")
        for r in results:
            t.add_row(str(r["port"]), ui.safe(r["service"]), "[green]OPEN[/green]")
        console.print(t)
        ui.success(f"{len(results)} open ports found.")

    def tool_webprobe(self):
        if self._blocked_by_passive("Web probing"):
            return
        default = self.last_target or ""
        host = validators.valid_target(Prompt.ask("Target host/domain", default=default))
        if not host:
            ui.error("Invalid host — expected an IP or hostname.")
            return
        self._remember_target(host)

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
        if self._blocked_by_passive("Nuclei scanning"):
            return
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
        self.last_nuclei_meta = meta
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
                ui.safe(f["template_id"]),
                ui.safe(f["name"]),
                ui.safe(f.get("matcher_name")),
                ui.safe(f["matched_at"]),
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
                # Exploit availability (clickable): ExploitDB > public PoC > none
                if c.get("exploitdb"):
                    edb = c["exploitdb"][0]
                    ids = ",".join(map(str, c["exploitdb"][:2]))
                    exp = (f"[link=https://www.exploit-db.com/exploits/{edb}]"
                           f"[bold red]EDB:{ids}[/][/link]")
                elif c.get("poc"):
                    url = (c.get("poc_urls") or [None])[0]
                    label = f"[yellow]PoC x{c.get('poc_count')}[/]"
                    exp = f"[link={url}]{label}[/link]" if url else label
                else:
                    exp = "[dim]-[/dim]"
                t.add_row(
                    str(r["port"]), ui.safe(r["service"]), ui.cve_link(ui.safe(c["id"])),
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
            web=self.last_web, nuclei=self.last_nuclei or [],
            nuclei_meta=self.last_nuclei_meta,
            attack=self.last_attack or self._map_attack(),
            attack_story=self.last_attack_story,
        )
        path = reporter.save_report(report, fmt=fmt)
        ui.success(f"Report saved: {ui.file_link(path)}")

    def tool_bypass403(self):
        if self._blocked_by_passive("403 bypass testing"):
            return
        url = ui.normalize_url(Prompt.ask("Forbidden URL (e.g. https://host/admin)"))
        if not url:
            ui.error("Invalid URL — enter something like http://host/admin")
            return
        self._remember_target(url)
        # Check first, ask later: no point generating payloads for a URL that isn't
        # actually forbidden.
        scanner = Bypass403()
        ui.info(f"Checking {url} ...")
        baseline = scanner.baseline_status(url)
        if baseline is None:
            ui.error("Could not reach the URL.")
            return
        if baseline not in (401, 403):
            ui.warn(f"URL returned {baseline} (not 401/403) — nothing to bypass.")
            return
        ui.info(f"Baseline {baseline} — bypass techniques apply.")

        extra = self._ai_payloads("403 bypass path variants")
        ui.info(f"Trying 403/401 bypass techniques on {url} ...")
        result = scanner.run(url, extra_payloads=extra, baseline=baseline)
        hits = result["hits"]
        if not hits:
            ui.success(f"Baseline {result['baseline']} — no bypass found "
                       f"(access control looks solid).")
            return
        # TRACE-style findings are weaknesses, not access bypasses — count them apart
        # so the summary never claims a bypass that didn't happen.
        real = [h for h in hits if h.get("bypass", True)]
        other = [h for h in hits if not h.get("bypass", True)]
        if real:
            self.last_vulns.append({"type": "403-bypass", "url": url,
                                    "hits": [{"technique": h["technique"],
                                              "status": h["status"]} for h in real[:5]]})
        title = "Bypass Hits" if real else "Findings (no bypass)"
        t = Table(title=f"{url} — {title} (baseline {result['baseline']})")
        t.add_column("Status", justify="right")
        t.add_column("Technique", style="cyan")
        t.add_column("Method")
        t.add_column("Length", justify="right")
        for h in hits:
            code_style = "green" if h["status"] < 300 else "yellow"
            t.add_row(f"[{code_style}]{h['status']}[/]", ui.safe(h["technique"]),
                      ui.safe(h["method"]), str(h["length"]))
        console.print(t)
        if real:
            ui.warn(f"{len(real)} potential bypass(es) — verify manually (a 200 can "
                    f"still be a login/redirect page).")
        else:
            ui.success(f"Baseline {result['baseline']} — no bypass found. "
                       f"[dim]{len(other)} related weakness(es) listed above.[/dim]")

    def tool_leak(self):
        if self._blocked_by_passive("Leak scanning"):
            return
        default = self.last_target or ""
        url = ui.normalize_url(Prompt.ask("Target URL/host", default=default))
        if not url:
            ui.error("Invalid URL — enter something like http://host")
            return
        ui.info(f"Hunting for secrets and exposed files on {url} ...")
        result = LeakFinder().run(url)
        self.last_leak = result
        self._remember_target(url)
        secrets, exposed = result["secrets"], result["exposed"]

        if secrets:
            t = Table(title=f"Exposed Secrets ({len(secrets)})")
            t.add_column("Type", style="cyan")
            t.add_column("Value")
            t.add_column("Confidence")
            t.add_column("Source")
            conf_color = {"high": "bold red", "medium": "yellow", "low": "dim"}
            for s in secrets:
                t.add_row(ui.safe(s["type"]), ui.safe(s["value"]),
                          f"[{conf_color.get(s['confidence'], 'dim')}]{s['confidence']}[/]",
                          ui.safe(s["source"]))
            console.print(t)

        if exposed:
            t = Table(title=f"Exposed Files ({len(exposed)})")
            t.add_column("Path", style="cyan")
            t.add_column("Size", justify="right")
            t.add_column("Confidence")
            for e in exposed:
                cc = "bold red" if e["confidence"] == "high" else "yellow"
                t.add_row(ui.safe(e["path"]), str(e["size"]), f"[{cc}]{e['confidence']}[/]")
            console.print(t)

        if not secrets and not exposed:
            ui.success("No exposed secrets or sensitive files found.")
        else:
            ui.warn(f"{len(secrets)} secret(s), {len(exposed)} exposed file(s) — "
                    f"verify (low-confidence hits may be false positives).")

    def tool_pathtraversal(self):
        if self._blocked_by_passive("LFI fuzzing"):
            return
        console.print("[dim]Tip: include a parameter, e.g. https://host/view.php?file=welcome[/dim]")
        url = ui.normalize_url(Prompt.ask("Target URL"))
        if not url:
            ui.error("Invalid URL — enter something like http://host/path?param=x")
            return
        self._remember_target(url)
        extra = self._ai_payloads("path traversal / LFI")
        ui.info(f"Fuzzing {url} for path traversal / LFI ...")
        result = PathTraversal().run(url, extra_payloads=extra)
        if result["used_common_params"]:
            ui.info(f"No query parameter in the URL — trying common names: "
                    f"{', '.join(result['params'][:6])}...")
        hits = result["hits"]
        if not hits:
            ui.success("No path traversal / LFI found (no file-read evidence).")
            return
        self.last_vulns.append({"type": "LFI", "url": result["url"],
                                "hits": [{"param": h["param"], "signature": h["signature"]}
                                         for h in hits[:5]]})
        t = Table(title=f"{result['url']} — Path Traversal / LFI Hits")
        t.add_column("Param", style="cyan")
        t.add_column("Signature", style="bold red")
        t.add_column("Status", justify="right")
        t.add_column("Payload")
        for h in hits:
            payload = h["payload"] if len(h["payload"]) < 45 else h["payload"][:42] + "..."
            t.add_row(ui.safe(h["param"]), ui.safe(h["signature"]), str(h["status"]),
                      ui.safe(payload))
        console.print(t)
        ui.error(f"⚠ {len(hits)} confirmed file-read(s) — evidence found in the response.")
        for h in hits[:3]:
            console.print(f"    [dim]{ui.safe(h['param'])}:[/dim] "
                          f"[green]{ui.safe(h['evidence'])}[/green]")

    def _ai_payloads(self, kind):
        """Shared AI-payload helper for the active modules (ssrf / lfi / 403).
        Uses the last web fingerprint as context; the calling module still verifies
        every suggested payload by evidence, so AI never decides 'vulnerable'."""
        if not Confirm.ask("Use AI to add stack-specific payloads?", default=False):
            return []
        ctx = {"web": [{k: w.get(k) for k in ("server", "tech", "waf")}
                       for w in (self.last_web or [])]}
        ui.info(f"Asking AI for target-tailored {kind} payloads...")
        extra = SilentAI().suggest_payloads(ctx, kind)
        if extra:
            ui.info(f"AI proposed {len(extra)} extra payload(s) — testing them too.")
        else:
            ui.warn("AI returned no usable payloads (check AI_* config in .env).")
        return extra

    def tool_ssrf(self):
        if self._blocked_by_passive("SSRF fuzzing"):
            return
        console.print("[dim]Tip: include a URL-taking parameter, e.g. ?url=https://x[/dim]")
        url = ui.normalize_url(Prompt.ask("Target URL"))
        if not url:
            ui.error("Invalid URL — enter something like http://host/path?param=x")
            return
        self._remember_target(url)
        extra = self._ai_payloads("ssrf")
        ui.info(f"Scanning {url} for reflected SSRF ...")
        result = SSRFScanner().run(url, extra_payloads=extra)
        hits = result["hits"]
        if not hits:
            ui.success(f"No reflected SSRF found ({result['payloads_tried']} payloads). "
                       f"[dim]Blind SSRF needs OOB — use [5] Nuclei.[/dim]")
            return
        self.last_vulns.append({"type": "SSRF", "url": result["url"],
                                "hits": [{"param": h["param"], "signature": h["signature"]}
                                         for h in hits[:5]]})
        t = Table(title=f"{result['url']} — SSRF Hits")
        t.add_column("Param", style="cyan")
        t.add_column("Signature", style="bold red")
        t.add_column("Status", justify="right")
        t.add_column("Evidence")
        for h in hits:
            t.add_row(ui.safe(h["param"]), ui.safe(h["signature"]), str(h["status"]),
                      ui.safe(h["evidence"]))
        console.print(t)
        ui.error(f"⚠ {len(hits)} SSRF hit(s) — internal/metadata content reflected!")

    @staticmethod
    def _report_coverage(stats):
        """State plainly whether the wordlist was fully covered. A capped run that
        found nothing must never read as 'the target is clean'."""
        if stats.get("complete", True):
            return
        tested, planned = stats.get("tested"), stats.get("planned")
        detail = (f"{tested:,} of {planned:,} candidates tested"
                  if tested and planned else "the wordlist was truncated")
        ui.warn(f"INCOMPLETE SCAN — {detail}. Untested paths may still exist.")
        console.print("[dim]    Use ffuf/gobuster (sudo apt install ffuf) or a smaller "
                      "wordlist for full coverage.[/dim]")

    def tool_content(self):
        if self._blocked_by_passive("Content discovery"):
            return
        default = ""
        if self.last_web:
            default = self.last_web[0].get("url", "")
        elif self.last_target:
            default = f"http://{self.last_target}"
        url = ui.normalize_url(Prompt.ask("Base URL", default=default))
        if not url:
            ui.error("Invalid URL — enter something like http://host")
            return
        self._remember_target(url)
        wl = Prompt.ask("Wordlist path (blank = auto)", default="").strip() or None
        if wl and not os.path.isfile(wl):
            ui.warn(f"Wordlist not found: {wl} — using the built-in list.")
            wl = None

        scanner = ContentDiscovery()
        tool = scanner.detect_tool()

        # Without an external tool the Python fuzzer is capped, so warn BEFORE the run:
        # a partial scan that reports "nothing found" would be misleading.
        if not tool and wl:
            try:
                with open(wl, encoding="utf-8", errors="ignore") as fh:
                    n_words = sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))
                planned = n_words * len(contentdisco.DEFAULT_EXTENSIONS)
                if planned > contentdisco.MAX_PYTHON_REQUESTS:
                    ui.warn(f"This wordlist needs ~{planned:,} requests but the built-in "
                            f"fuzzer stops at {contentdisco.MAX_PYTHON_REQUESTS:,} — the "
                            f"scan would be PARTIAL.")
                    console.print("[dim]    Install ffuf for full coverage: "
                                  "sudo apt install ffuf[/dim]")
                    if not Confirm.ask("Run the partial scan anyway?", default=False):
                        return
            except OSError:
                pass

        engine = tool or "built-in python fuzzer"
        ui.info(f"Discovering content on {url} via {engine} — this can take a while...")
        results = scanner.run(url, wordlist_path=wl)
        self.last_content = results
        st = scanner.stats
        ui.info(f"Engine: [bold]{st.get('method')}[/bold]")
        self._report_coverage(st)
        if not results:
            if st.get("complete"):
                ui.success("No extra content discovered.")
            else:
                ui.warn("Nothing found in the part that was scanned — the scan was "
                        "incomplete, so this does NOT mean the target is clean.")
            return

        t = Table(title=f"{url} — Discovered Content ({len(results)})")
        t.add_column("Status", justify="right")
        t.add_column("Path", style="cyan")
        t.add_column("Size", justify="right")
        t.add_column("Redirect")
        for r in results:
            code = r["status"]
            style = ("green" if code < 300 else "cyan" if code < 400
                     else "yellow" if code < 500 else "red")
            t.add_row(f"[{style}]{code}[/]", ui.safe(r["path"]), str(r["size"]),
                      ui.safe(r.get("redirect")))
        console.print(t)

        # Chain hints: what the operator should do with these paths next.
        forbidden = [r["path"] for r in results if r["status"] in (401, 403)]
        if forbidden:
            ui.warn(f"{len(forbidden)} forbidden path(s) — try [9] 403 Bypass on: "
                    f"{ui.safe(', '.join(forbidden[:3]))}")
        if st.get("complete", True):
            ui.success(f"{len(results)} paths discovered.")
        else:
            ui.warn(f"{len(results)} paths discovered so far — scan was incomplete "
                    f"(see the coverage note above).")

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
            # Clickable file link on the name — click opens the report directly.
            abs_f = os.path.abspath(f).replace("\\", "/")
            name = f"[link=file:///{abs_f.lstrip('/')}]{ui.safe(os.path.basename(f))}[/link]"
            t.add_row(str(i), name, f"{os.path.getsize(f)} B")
        console.print(t)
        console.print("[dim]Enter a # to open (HTML opens in browser), or e<#> to "
                      "export (e.g. 'e2') to HTML/MD[/dim]")
        sel = Prompt.ask("Open / export # (blank to skip)", default="").strip().lower()

        # Export: re-render a saved report to another format from its JSON — no re-scan.
        if sel.startswith("e") and sel[1:].isdigit():
            idx = int(sel[1:])
            if not (1 <= idx <= len(files)):
                return
            base = os.path.splitext(files[idx - 1])[0]
            json_path = base + ".json"
            if not os.path.exists(json_path):
                ui.warn("No JSON data for this report — can't re-export (re-run the scan).")
                return
            fmt = Prompt.ask("Export to", choices=["html", "md"], default="html")
            new_path = reporter.export_saved(json_path, fmt)
            ui.success(f"Exported: {ui.file_link(new_path)}")
            return

        if sel.isdigit() and 1 <= int(sel) <= len(files):
            path = files[int(sel) - 1]
            if path.endswith(".html"):
                # Open in the default app; its console output is suppressed so the
                # terminal stays clean (browser GPU warnings, etc.).
                if ui.open_path(path):
                    ui.success(f"Opened: {os.path.basename(path)}")
                else:
                    ui.info(f"Open manually: {ui.file_link(path)}")
            else:
                with open(path, encoding="utf-8") as fh:
                    console.print(RichPanel(fh.read(), border_style="dim"))
