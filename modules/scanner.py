import nmap
import sys
import socket
import ipaddress
import functools

from modules.opsec import profile as opsec

# Single source of truth for scan-type labels (shared by panel, autopilot, CLI).
SCAN_LABELS = {
    "1": "Fast (Top 100)",
    "2": "Standard (1-1000 + version)",
    "3": "Deep (All ports + OS)",
}


@functools.lru_cache(maxsize=1)
def _ipv6_available():
    """True only if this machine has a real IPv6 route. UDP 'connect' sends no
    packets — it just checks whether the OS can route to a global IPv6 address —
    so on IPv4-only networks (e.g. many corporate guest Wi-Fis) this returns False
    instantly and we can avoid dead IPv6 scans for any user, on any network."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("2001:4860:4860::8888", 53))  # Google public IPv6 DNS
        s.close()
        return True
    except OSError:
        return False


class NetworkScanner:
    def __init__(self):
        # Populated after scan_target(): IPs, scanned IP, confirmed/unconfirmed
        # counts and a "protected" (WAF/anti-scan) heuristic flag.
        self.scan_meta = {}
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("Error: Nmap not found on the system. Make sure Nmap is installed.")
            sys.exit(1)

    @staticmethod
    def resolve_all(target):
        """All A/AAAA addresses a host resolves to (round-robin awareness).
        IPv4 is listed first so the default choice never lands on an IPv6 address
        the host may not even be reachable over."""
        ips = set()
        try:
            for res in socket.getaddrinfo(target, None):
                ips.add(res[4][0])
        except socket.gaierror:
            pass
        return sorted(ips, key=lambda ip: (":" in ip, ip))

    @staticmethod
    def _is_ipv6(host):
        try:
            return isinstance(ipaddress.ip_address(host), ipaddress.IPv6Address)
        except ValueError:
            return False

    @staticmethod
    def has_ipv6():
        """Whether this machine can actually reach IPv6 targets."""
        return _ipv6_available()

    def scan_target(self, target, scan_type="2"):
        # Passive mode sends nothing to the target — an active port scan is exactly
        # the kind of footprint it exists to avoid.
        if opsec.is_passive:
            print("[!] OPSEC passive mode — port scanning skipped (no packets to target).")
            self.scan_meta = {"ips": self.resolve_all(target), "scanned_ip": None,
                              "skipped": "passive"}
            return []

        # -Pn: don't skip a host that blocks ping — essential behind a WAF/firewall
        # where ICMP/discovery is filtered but ports may still be open.
        # -6: required for IPv6 targets (otherwise nmap can hang/misbehave).
        base = '-Pn -6' if self._is_ipv6(target) else '-Pn'
        # --host-timeout caps how long a single host can take, so a dead/unreachable
        # address (e.g. IPv6 with no route) can't hang the scan indefinitely.
        cap = '--host-timeout 10m'
        # Timing/rate come from the OPSEC profile (-T4 normally, -T1 + rate caps in stealth).
        tmg = f"{opsec.nmap_timing()} {opsec.nmap_extra()}".strip()
        if scan_type == "1":
            print(f"[!] Starting Fast Scan (Top 100 ports) on {target}...")
            nmap_args = f'{base} {cap} -F {tmg}'
        elif scan_type == "3":
            print(f"[!] Starting Deep Scan (All ports) on {target} (this may take a while!)...")
            # Deep is expected to be long, so no host cap here.
            nmap_args = f'{base} -p- -sV -O {tmg}'
        else:
            print(f"[!] Starting Standard Scan (Top 1000 ports + services) on {target}...")
            # --top-ports 1000 = the 1000 statistically most common ports (spread across
            # the whole range), so high-value services like RDP(3389), MySQL(3306),
            # web-alt(8080/8443) are covered — unlike a sequential -p 1-1000.
            nmap_args = f'{base} {cap} --top-ports 1000 -sV {tmg}'
        if opsec.is_stealth:
            print("[!] OPSEC stealth — slow timing, this will take considerably longer.")
        # A proxy set in the profile does NOT cover nmap's own packets — say so loudly,
        # because silently scanning from the real IP is an OPSEC failure.
        warn = opsec.nmap_proxy_warning()
        if warn:
            print(f"[!] OPSEC WARNING: {warn}")

        all_ips = self.resolve_all(target)
        try:
            self.nm.scan(target, arguments=nmap_args)
        except nmap.PortScannerError as e:
            print(f"[!] Scan error: {e}")
            self.scan_meta = {"ips": all_ips, "scanned_ip": None}
            return []
        except Exception as e:
            print(f"[!] Could not scan target ({target}): {e}")
            self.scan_meta = {"ips": all_ips, "scanned_ip": None}
            return []

        scan_results = []
        state_counts = {}  # open/closed/filtered tallies across scanned ports
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    service = self.nm[host][proto][port]
                    st = service.get('state', 'unknown')
                    state_counts[st] = state_counts.get(st, 0) + 1
                    # Noise filter: only open ports make it into the report.
                    if st != 'open':
                        continue
                    # Nmap -sV often returns CPE and product name too;
                    # these are far more accurate than version for CVE matching.
                    cpe = service.get('cpe', '')
                    product = service.get('product', '')
                    version = service.get('version', '')
                    name = service.get('name', 'unknown')
                    # "Confirmed" = nmap actually identified the service (real banner),
                    # not just a port-table guess or an ssl-wrapped "?" response. This is
                    # the key to filtering out WAF/decoy phantom ports without hiding them.
                    confirmed = bool(product) or bool(version)
                    scan_results.append({
                        "port": port,
                        "service": name if name else 'unknown',
                        "product": product if product else 'unknown',
                        "version": version if version else 'unknown',
                        "cpe": cpe if cpe else '',
                        "state": service.get('state', 'unknown'),
                        "tunnel": service.get('tunnel', ''),
                        "confirmed": confirmed,
                    })

        self.scan_meta = self._build_meta(all_ips, scan_results, state_counts)
        return scan_results

    def _build_meta(self, all_ips, scan_results, state_counts=None):
        state_counts = state_counts or {}
        scanned_ip = self.nm.all_hosts()[0] if self.nm.all_hosts() else None
        total = len(scan_results)
        confirmed = sum(1 for r in scan_results if r["confirmed"])
        ratio = (confirmed / total) if total else 1.0
        # Many open ports but almost nothing identifiable => likely a security
        # appliance / CDN answering every port (anti-recon), results are deceptive.
        protected = total >= 15 and ratio < 0.2
        # If the host answered on some ports (closed = got an RST) but nothing is
        # open, the target is reachable and something is filtering — often a
        # firewall or the user's own (guest/corporate) network.
        blocked = total == 0 and (state_counts.get("closed", 0) > 0
                                  or state_counts.get("filtered", 0) > 0)
        return {
            "ips": all_ips,
            "scanned_ip": scanned_ip,
            "total_open": total,
            "confirmed": confirmed,
            "unconfirmed": total - confirmed,
            "protected": protected,
            "state_counts": state_counts,
            "blocked": blocked,
        }
