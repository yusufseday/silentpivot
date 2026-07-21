import os
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


class SilentAI:
    def __init__(self):
        self.client = OpenAI(
            base_url="https://api.groq.com/openai/v1",
            api_key=os.getenv("AI_API_KEY")
        )

    def analyze_results(self, scan_data):
        # Groq üzerindeki hızlı ve yetenekli modellerden biri
        model_name = "llama-3.3-70b-versatile"

        prompt = f"""
        Sen bir Senior Penetration Tester'sın. Aşağıdaki Nmap tarama verisi ve
        NVD (NIST) veritabanından DOĞRULANMIŞ CVE listesi verilmiştir:
        {json.dumps(scan_data, indent=2, ensure_ascii=False)}

        ÖNEMLİ KURALLAR:
        - 'cve_data' ve 'cves' alanlarındaki CVE'ler gerçek ve doğrulanmıştır.
          SADECE bu doğrulanmış CVE'leri referans al; kendin yeni CVE numarası UYDURMA.
        - Doğrulanmış CVE yoksa bunu açıkça belirt ve servis/versiyona göre
          genel risk değerlendirmesi yap (spesifik CVE numarası verme).

        Raporu şu başlıklarla, Türkçe ve Markdown formatında hazırla:
        1. **Yönetici Özeti** — En kritik bulgular ve genel risk seviyesi (CVSS'e göre).
        2. **Bulgular** — Her açık port için: servis/versiyon, doğrulanmış CVE'ler,
           CVSS skoru ve pratikteki risk açıklaması.
        3. **Exploit Stratejisi** — Önceliklendirilmiş, kullanılabilecek araçlar
           (Metasploit, searchsploit vb.) ve saldırı vektörleri.
        4. **Sertleştirme (Hardening) Önerileri** — Somut, uygulanabilir çözümler.
        """

        try:
            response = self.client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"AI Analizi sırasında hata oluştu: {str(e)}"