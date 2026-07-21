import nmap
import sys


class NetworkScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("Error: Nmap not found on the system. Make sure Nmap is installed.")
            sys.exit(1)

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

        try:
            self.nm.scan(target, arguments=nmap_args)
        except nmap.PortScannerError as e:
            print(f"[!] Scan error: {e}")
            return []
        except Exception as e:
            print(f"[!] Could not scan target ({target}): {e}")
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
                    scan_results.append({
                        "port": port,
                        "service": service.get('name', 'unknown'),
                        "product": product if product else 'unknown',
                        "version": service.get('version', 'unknown'),
                        "cpe": cpe if cpe else '',
                        "state": service.get('state', 'unknown')
                    })
        return scan_results
