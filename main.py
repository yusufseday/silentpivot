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

    # 3. Sonuç Raporu
    console.print("\n[bold cyan]--- PENTEST RAPORU ---[/bold cyan]\n")
    console.print(Markdown(analysis))


if __name__ == "__main__":
    main()