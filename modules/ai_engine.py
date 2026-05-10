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
        Sen bir Senior Penetration Tester'sın. Aşağıdaki Nmap tarama verisini incele:
        {json.dumps(scan_data, indent=2)}

        Şu analizi yap:
        1. Açık portların risklerini ve olası zafiyetleri (CVE'ler) belirt.
        2. Bu hedefe sızmak için kullanılabilecek araçları (Metasploit vb.) ve exploit stratejisini yaz.
        3. Sistemin güvenliğini artırmak için çözüm önerileri sun.

        Yanıtı profesyonel bir siber güvenlik raporu formatında, Türkçe ve Markdown kullanarak ver.
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