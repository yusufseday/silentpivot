import nmap
import sys


class NetworkScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("Hata: Nmap sistemde bulunamadı. Lütfen Nmap'in kurulu olduğundan emin ol.")
            sys.exit(1)

    def scan_target(self, target, scan_type="2"):
        # Seçime göre Nmap parametrelerini belirliyoruz
        if scan_type == "1":
            print(f"[!] {target} üzerinde Hızlı Tarama (Top 100 Port) başlatılıyor...")
            nmap_args = '-F -T4'
        elif scan_type == "3":
            print(f"[!] {target} üzerinde Derin Tarama (Tüm Portlar) başlatılıyor (Bu işlem uzun sürebilir!)...")
            nmap_args = '-p- -sV -O -T4'
        else:
            print(f"[!] {target} üzerinde Standart Tarama (Top 1000 Port + Servisler) başlatılıyor...")
            nmap_args = '-p 1-1000 -sV -T4'

        try:
            self.nm.scan(target, arguments=nmap_args)
        except nmap.PortScannerError as e:
            print(f"[!] Tarama hatası: {e}")
            return []
        except Exception as e:
            print(f"[!] Hedef taranamadı ({target}): {e}")
            return []

        scan_results = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    service = self.nm[host][proto][port]
                    # Nmap -sV çoğu zaman CPE ve ürün adını da döndürür;
                    # bunlar CVE eşleştirmesinde versiyondan çok daha isabetlidir.
                    cpe = service.get('cpe', '')
                    product = service.get('product', '')
                    scan_results.append({
                        "port": port,
                        "service": service.get('name', 'Bilinmiyor'),
                        "product": product if product else 'Bilinmiyor',
                        "version": service.get('version', 'Bilinmiyor'),
                        "cpe": cpe if cpe else '',
                        "state": service.get('state', 'Bilinmiyor')
                    })
        return scan_results