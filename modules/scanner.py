import nmap
import sys
import socket


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
    def _resolve_all(target):
        """All A/AAAA addresses a host resolves to (round-robin awareness)."""
        ips = set()
        try:
            for res in socket.getaddrinfo(target, None):
                ips.add(res[4][0])
        except socket.gaierror:
            pass
        return sorted(ips)

    def scan_target(self, target, scan_type="2"):
        # Choose Nmap arguments based on the selected scan type.
        if scan_type == "1":
            print(f"[!] Starting Fast Scan (Top 100 ports) on {target}...")
            nmap_args = '-F -T4'
        elif scan_type == "3":
            print(f"[!] Starting Deep Scan (All ports) on {target} (this may take a while!)...")
            nmap_args = '-p- -sV -O -T4'
        else:
            print(f"[!] Starting Standard Scan (Top 1000 ports + services) on {target}...")
            nmap_args = '-p 1-1000 -sV -T4'

        all_ips = self._resolve_all(target)
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
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    service = self.nm[host][proto][port]
                    # Noise filter: only open ports make it into the report.
                    if service.get('state') != 'open':
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

        self.scan_meta = self._build_meta(all_ips, scan_results)
        return scan_results

    def _build_meta(self, all_ips, scan_results):
        scanned_ip = self.nm.all_hosts()[0] if self.nm.all_hosts() else None
        total = len(scan_results)
        confirmed = sum(1 for r in scan_results if r["confirmed"])
        ratio = (confirmed / total) if total else 1.0
        # Many open ports but almost nothing identifiable => likely a security
        # appliance / CDN answering every port (anti-recon), results are deceptive.
        protected = total >= 15 and ratio < 0.2
        return {
            "ips": all_ips,
            "scanned_ip": scanned_ip,
            "total_open": total,
            "confirmed": confirmed,
            "unconfirmed": total - confirmed,
            "protected": protected,
        }
