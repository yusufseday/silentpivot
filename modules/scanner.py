import nmap
import sys


class NetworkScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("Hata: Nmap sistemde bulunamadı. Lütfen Nmap'in kurulu olduğundan emin ol.")
            sys.exit(1)

    def scan_target(self, target):
        print(f"[!] {target} üzerinde tarama başlatılıyor (Bu işlem birkaç dakika sürebilir)...")
        # -sV: Versiyon tespiti, -T4: Hızlı tarama
        self.nm.scan(target, arguments='-p 1-1000 -sV -T4')

        scan_results = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    service = self.nm[host][proto][port]
                    scan_results.append({
                        "port": port,
                        "service": service.get('name', 'Bilinmiyor'),
                        "version": service.get('version', 'Bilinmiyor'),
                        "state": service.get('state', 'Bilinmiyor')
                    })
        return scan_results