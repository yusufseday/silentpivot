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
        # One of the fast, capable models on Groq
        model_name = "llama-3.3-70b-versatile"

        prompt = f"""
        You are a Senior Penetration Tester. Below is Nmap scan data together with a
        list of VERIFIED CVEs from the NVD (NIST) database:
        {json.dumps(scan_data, indent=2, ensure_ascii=False)}

        IMPORTANT RULES:
        - The CVEs in the 'cve_data' and 'cves' fields are real and verified.
          Reference ONLY these verified CVEs; do NOT invent new CVE numbers.
        - If there are no verified CVEs, state this clearly and give a general risk
          assessment based on the service/version (do not cite specific CVE numbers).

        Produce the report in English, in Markdown, with these sections:
        1. **Executive Summary** — the most critical findings and overall risk level (per CVSS).
        2. **Findings** — for each open port: service/version, verified CVEs,
           CVSS score, and the practical risk explanation.
        3. **Exploitation Strategy** — prioritized, usable tools
           (Metasploit, searchsploit, etc.) and attack vectors.
        4. **Hardening Recommendations** — concrete, actionable fixes.
        """

        try:
            response = self.client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"An error occurred during AI analysis: {str(e)}"
