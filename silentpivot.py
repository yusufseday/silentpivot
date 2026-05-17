import os
import socket
from datetime import datetime
from modules.scanner import NetworkScanner
from modules.ai_engine import SilentAI
from rich.console import Console
from rich.markdown import Markdown

console = Console()


def main():
    console.print("\n[bold green]=== silentpivot ===[/bold green]\n")
    target = input("Hedef IP veya Domain girin (Örn: scanme.nmap.org): ")

    # Menü Tasarımı
    console.print("\n[bold cyan]Tarama Türünü Seçin:[/bold cyan]")
    console.print("[1] Hızlı Tarama (En popüler 100 port - Versiyon tespiti yok)")
    console.print("[2] Standart Tarama (1-1000 arası portlar + Versiyon tespiti)")
    console.print("[3] Derin Tarama (Tüm 65535 port + OS/Versiyon tespiti - Uzun sürer)")

    scan_type = input("\nSeçiminiz (1/2/3) [Varsayılan: 2]: ")
    if scan_type not in ["1", "2", "3"]:
        scan_type = "2"  # Yanlış girişte varsayılan olarak 2'yi seç

    # 1. Tarama Aşaması
    scanner = NetworkScanner()
    results = scanner.scan_target(target, scan_type)

    if not results:
        console.print("[bold red]Hedefte açık port bulunamadı veya hedef ayakta değil.[/bold red]")
        return

    # 2. AI Analiz Aşaması
    console.print("\n[bold yellow]Tarama tamamlandı! Veriler AI analizine gönderiliyor...[/bold yellow]\n")
    ai = SilentAI()
    analysis = ai.analyze_results(results)

    # 3. Sonuç Raporu (Ekrana Yazdırma)
    console.print("\n[bold cyan]--- PENTEST RAPORU ---[/bold cyan]\n")
    console.print(Markdown(analysis))

    # 4. Raporu Kaydetme
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
        dosya.write(f"# silentpivot Pentest Raporu\n")
        dosya.write(f"**Hedef:** {target}\n")
        dosya.write(f"**Tarama Türü:** Seviye {scan_type}\n")
        dosya.write(f"**Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        dosya.write("---\n\n")
        dosya.write(analysis)

    console.print(f"\n[bold green][+] Rapor başarıyla data/ klasörüne kaydedildi: {dosya_adi}[/bold green]\n")


if __name__ == "__main__":
    main()