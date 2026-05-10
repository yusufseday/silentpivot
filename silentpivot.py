import os
import socket
from datetime import datetime
from modules.scanner import NetworkScanner
from modules.ai_engine import SilentAI
from rich.console import Console
from rich.markdown import Markdown

console = Console()


def main():
    console.print("\n[bold green]=== SilentPivot ===[/bold green]\n")
    target = input("Hedef IP veya Domain girin (Örn: scanme.nmap.org): ")

    # 1. Tarama Aşaması
    scanner = NetworkScanner()
    results = scanner.scan_target(target)

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

    # 4. Raporu Kaydetme (Loglama Aşaması)
    console.print("[yellow]Rapor dosyaya kaydediliyor...[/yellow]")
    try:
        # socket ile girilen adresin IP'sini çözelim
        ip_address = socket.gethostbyname(target)
        # Eğer girilen adres IP ile aynı değilse (yani bir domain girildiyse) domaini al
        domain_name = target if target != ip_address else "Direct-IP"
    except Exception:
        # Eğer adres çözülemezse hata vermemesi için:
        ip_address = "Bilinmiyor"
        domain_name = target

    # Klasör yoksa oluştur (güvenlik önlemi)
    if not os.path.exists("data"):
        os.makedirs("data")

    # Dosya adını oluşturma: Örn: 45.33.32.156(scanme.nmap.org)_20260510_2105.md
    zaman = datetime.now().strftime("%Y%m%d_%H%M")
    dosya_adi = f"{ip_address}({domain_name})_{zaman}.md"
    dosya_yolu = os.path.join("data", dosya_adi)

    # Markdown dosyasını oluştur ve içine AI analizini yaz (Türkçe karakterler için utf-8 önemli)
    with open(dosya_yolu, "w", encoding="utf-8") as dosya:
        # Dosyanın en üstüne bir başlık ve meta veri ekleyelim
        dosya.write(f"# SilentPivot Pentest Raporu\n")
        dosya.write(f"**Hedef:** {target}\n")
        dosya.write(f"**Tarih:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        dosya.write("---\n\n")
        dosya.write(analysis)

    console.print(f"\n[bold green][+] Rapor başarıyla data/ klasörüne kaydedildi: {dosya_adi}[/bold green]\n")


if __name__ == "__main__":
    main()