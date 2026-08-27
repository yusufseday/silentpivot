import argparse
import sys

from rich.markdown import Markdown

from silentpivot import reporter, ui, validators
from silentpivot.ai_engine import SilentAI
from silentpivot.scanner import SCAN_LABELS, NetworkScanner
from silentpivot.ui import console, print_summary_table
from silentpivot.vuln_checker import VulnChecker

# Scan type: usable by both number (1/2/3) and name.
SCAN_ALIASES = {
    "1": "1", "fast": "1", "quick": "1",
    "2": "2", "standard": "2", "std": "2",
    "3": "3", "deep": "3", "full": "3",
}


def run_scan(target, scan_type, use_ai=True, quiet=False):
    """Scan -> CVE enrichment -> (optional) AI. Returns structured data."""
    scanner = NetworkScanner()
    results = scanner.scan_target(target, scan_type)
    if not results:
        return None, None

    if not quiet:
        ui.info("Verifying vulnerabilities against NVD + CISA KEV...")
    enriched = VulnChecker().check_vulnerabilities(results)

    if not quiet:
        console.print()
        print_summary_table(enriched)

    analysis = None
    if use_ai:
        if not quiet:
            ui.info("Sending data to AI analysis...")
        analysis = SilentAI().analyze_results(enriched)
        if not quiet:
            console.print("\n[bold cyan]--- PENTEST REPORT ---[/bold cyan]\n")
            console.print(Markdown(analysis))

    return enriched, analysis


def build_parser():
    p = argparse.ArgumentParser(
        prog="silentpivot",
        description="SilentPivot — AI-powered recon and vulnerability analysis tool.",
        epilog="With no arguments, the interactive command center (panel) opens.",
    )
    p.add_argument("-t", "--target", help="Target IP or domain")
    p.add_argument("-s", "--scan-type", default="2",
                   help="Scan type: 1/fast, 2/standard, 3/deep (default: 2)")
    p.add_argument("--auto", action="store_true",
                   help="Autopilot: full engagement pipeline (nmap+web+nuclei+CVE+AI)")
    p.add_argument("--no-ai", action="store_true", help="Skip AI analysis (scan + CVE only)")
    p.add_argument("-o", "--output", help="Report file path (default: auto under data/)")
    p.add_argument("-f", "--format", default="md", choices=["md", "json", "html"],
                   help="Report format (default: md)")
    p.add_argument("-q", "--quiet", action="store_true", help="Reduce terminal output")
    p.add_argument("--no-save", action="store_true", help="Do not save the report to disk")
    return p


def run_cli(args):
    target = args.target
    scan_type = SCAN_ALIASES.get(str(args.scan_type).lower())
    if scan_type is None:
        ui.error(f"Invalid scan type: {args.scan_type}")
        sys.exit(2)

    enriched, analysis = run_scan(target, scan_type, use_ai=not args.no_ai, quiet=args.quiet)
    if enriched is None:
        ui.error("No open ports found, or the host is down.")
        sys.exit(1)

    report = reporter.build_report_data(
        target, SCAN_LABELS.get(scan_type, scan_type), enriched, analysis
    )
    if not args.no_save:
        path = reporter.save_report(report, fmt=args.format, output_path=args.output)
        ui.success(f"Report saved: {ui.file_link(path)}")


def run_autopilot_cli(args):
    from silentpivot.autopilot import run_autopilot
    scan_type = SCAN_ALIASES.get(str(args.scan_type).lower())
    if scan_type is None:
        ui.error(f"Invalid scan type: {args.scan_type}")
        sys.exit(2)

    log = (lambda m: None) if args.quiet else ui.info
    report = run_autopilot(args.target, scan_type, use_ai=not args.no_ai, log=log)
    if report is None:
        ui.error("No open ports found, or the host is down.")
        sys.exit(1)

    if not args.quiet:
        console.print()
        print_summary_table(report["findings"])
        # Stage transparency: show what web + nuclei produced (details in the report file)
        ui.info(f"Web endpoints probed: {len(report['web'])}")
        for w in report["web"]:
            tech = ", ".join(w.get("tech") or []) or "-"
            waf = ", ".join(w.get("waf") or []) or "-"
            console.print(f"    [cyan]{ui.safe(w['url'])}[/cyan] [{w['status']}] "
                          f"tech={ui.safe(tech)} waf={ui.safe(waf)}")
        crit_high = sum(1 for f in report["nuclei"] if f["severity"] in ("CRITICAL", "HIGH"))
        ui.info(f"Nuclei findings: {len(report['nuclei'])} ({crit_high} critical/high)")
        if report.get("ai_analysis"):
            console.print("\n[bold cyan]--- ENGAGEMENT REPORT ---[/bold cyan]\n")
            console.print(Markdown(report["ai_analysis"]))

    if not args.no_save:
        path = reporter.save_report(report, fmt=args.format, output_path=args.output)
        ui.success(f"Unified report saved: {ui.file_link(path)}")


def main():
    args = build_parser().parse_args()
    # Validate the target here, once, for every CLI path. python-nmap shlex-splits the
    # host string, so an unvalidated target like "-oN /tmp/x" would be read as nmap
    # *flags*. The interactive panel already validates; the CLI must not be a bypass.
    if args.target:
        clean = validators.valid_target(args.target)
        if clean is None:
            ui.error(f"Invalid target: {args.target!r} "
                     "(expected an IP, CIDR or hostname — no flags, spaces or quotes).")
            sys.exit(2)
        args.target = clean
    if args.auto:
        if not args.target:
            ui.error("--auto requires a target (-t).")
            sys.exit(2)
        run_autopilot_cli(args)
    elif args.target:
        run_cli(args)  # arguments given -> automation/CLI mode
    else:
        # No arguments -> interactive command center
        from silentpivot.panel import CommandCenter
        try:
            CommandCenter().run()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Exiting...[/dim]")


if __name__ == "__main__":
    main()
