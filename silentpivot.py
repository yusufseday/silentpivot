import os
import socket
from datetime import datetime
from modules.scanner import NetworkScanner
from modules.ai_engine import SilentAI
from modules.vuln_checker import VulnChecker
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

console = Console()

# CVSS severity -> renk eşlemesi (rich stilleri)
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "UNKNOWN": "dim",
}


def print_summary_table(results):
    """Açık portları ve doğrulanmış en yüksek CVE riskini renkli tabloda göster."""
    table = Table(title="Tarama Özeti", show_lines=False)
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Servis", style="white")
    table.add_column("Versiyon", style="white")
    table.add_column("CVE Sayısı", justify="right")
    table.add_column("En Yüksek Risk")

    for r in results:
        cves = r.get("cves", []) or []
        if cves:
            worst = max(
                cves,
                key=lambda c: c["cvss"] if isinstance(c.get("cvss"), (int, float)) else -1,
            )
            sev = worst.get("severity", "UNKNOWN")
            risk = f"[{SEVERITY_COLORS.get(sev, 'dim')}]{sev} ({worst.get('cvss')})[/]"
        else:
            risk = "[dim]—[/dim]"
        table.add_row(
            str(r.get("port", "?")),
            r.get("service", "?"),
            r.get("version", "?"),
            str(len(cves)),
            risk,
        )
    console.print(table)


def main():
    # Senin belirlediğin özel yeşil başlık formatı
    console.print("\n[bold green]=== SilentPivot ===[/bold green]\n")
    target = input("Hedef IP veya Domain girin (Örn: scanme.nmap.org): ")

    # Menü Tasarımı
    console.print("\n[bold cyan]Tarama Türünü Seçin:[/bold cyan]")
    console.print("[1] Hızlı Tarama (En popüler 100 port - Versiyon tespiti yok)")
    console.print("[2] Standart Tarama (1-1000 arası portlar + Versiyon tespiti)")
    console.print("[3] Derin Tarama (Tüm 65535 port + OS/Versiyon tespiti - Uzun sürer)")

    scan_type = input("\nSeçiminiz (1/2/3) [Varsayılan: 2]: ")
    if scan_type not in ["1", "2", "3"]:
        scan_type = "2"

    # 1. Nmap Tarama Aşaması
    scanner = NetworkScanner()
    results = scanner.scan_target(target, scan_type)

    if not results:
        console.print("[bold red]Hedefte açık port bulunamadı veya hedef ayakta değil.[/bold red]")
        return

    # 2. CVE Veritabanı Sorgulama Aşaması
    console.print("\n[bold yellow]NVD Veritabanında bilinen zafiyetler (CVE) aranıyor...[/bold yellow]")
    vuln_checker = VulnChecker()
    enriched_results = vuln_checker.check_vulnerabilities(results)

    # Doğrulanmış bulguları AI'dan önce hızlı bir özet tablosunda göster
    console.print()
    print_summary_table(enriched_results)

    # 3. AI Analiz Aşaması
    console.print("[bold yellow]Veriler yapay zeka analizine gönderiliyor...[/bold yellow]\n")
    ai = SilentAI()
    analysis = ai.analyze_results(enriched_results)

    # 4. Sonuç Raporu (Senin belirlediğin özel cyan başlık formatı)
    console.print("\n[bold cyan]--- PENTEST RAPORU ---[/bold cyan]\n")
    console.print(Markdown(analysis))

    # 5. Raporu Kaydetme
    console.print("[yellow]Rapor dosyaya kaydediliyor...[/yellow]")
    try:
        ip_address = socket.gethostbyname(target)
        domain_name = target if target != ip_address else "Direct-IP"
    except Exception:
        ip_address = "Bilinmiyor"
        domain_name = target

    if not os.path.exists("data"):
        os.makedirs("data")

    zaman = datetime.now().strftime("%Y%m%d_%H%M")
    dosya_adi = f"{ip_address}({domain_name})_{zaman}.md"
    dosya_yolu = os.path.join("data", dosya_adi)

    with open(dosya_yolu, "w", encoding="utf-8") as dosya:
        dosya.write(f"# SilentPivot Pentest Raporu\n")
        dosya.write(f"**Hedef:** {target}\n")
        dosya.write(f"**Tarama Türü:** Seviye {scan_type}\n")
        dosya.write(f"**Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        dosya.write("---\n\n")
        dosya.write(analysis)

    console.print(f"\n[bold green][+] Rapor başarıyla data/ klasörüne kaydedildi: {dosya_adi}[/bold green]\n")


if __name__ == "__main__":
    main()