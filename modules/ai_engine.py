import os
import re
import json
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# Provider-agnostic defaults. Any OpenAI-compatible endpoint works by setting these
# in .env — Groq (fast, free), OpenAI/Claude (strongest reasoning), Ollama (local &
# private — keeps sensitive scan data on your machine), OpenRouter (many models).
DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "llama-3.3-70b-versatile"


class SilentAI:
    def __init__(self):
        # api_key can be a dummy value for local providers (e.g. Ollama).
        self.client = OpenAI(
            base_url=os.getenv("AI_BASE_URL", DEFAULT_BASE_URL),
            api_key=os.getenv("AI_API_KEY") or "not-needed",
        )
        self.model = os.getenv("AI_MODEL", DEFAULT_MODEL)

    def analyze_results(self, scan_data):
        prompt = f"""
        You are a Senior Penetration Tester. Below is Nmap scan data together with a
        list of VERIFIED CVEs from the NVD (NIST) database:
        {json.dumps(scan_data, indent=2, ensure_ascii=False)}

        IMPORTANT RULES:
        - The CVEs in the 'cve_data' and 'cves' fields are real and verified.
          Reference ONLY these verified CVEs; do NOT invent new CVE numbers.
        - Prioritize using these signals per CVE: 'kev' true = actively exploited in
          the wild (highest priority), 'epss' = exploitation probability (0-1),
          'exploitdb'/'poc' = a public exploit already exists.
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

        return self._complete(prompt)

    @staticmethod
    def _build_context(findings, web, nuclei):
        """Compact, prompt-friendly view of the recon state (shared by report + co-pilot)."""
        slim_services = []
        for r in findings:
            cves = [{k: c.get(k) for k in
                     ("id", "cvss", "severity", "kev", "epss", "poc", "exploitdb")}
                    for c in (r.get("cves") or [])]
            slim_services.append({
                "port": r.get("port"), "service": r.get("service"),
                "product": r.get("product"), "version": r.get("version"),
                "cves": cves,
            })
        sev_counts = {}
        for f in nuclei:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        notable = [
            {k: f.get(k) for k in ("template_id", "name", "severity", "matcher_name", "matched_at")}
            for f in nuclei if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")
        ][:30]
        return {
            "services": slim_services,
            "web_fingerprint": [
                {k: w.get(k) for k in ("url", "status", "title", "server", "tech", "waf")}
                for w in web
            ],
            "nuclei_summary": sev_counts,
            "nuclei_notable": notable,
        }

    def analyze_engagement(self, findings, web=None, nuclei=None):
        """Engagement-level analysis that sees services+CVEs, web fingerprints and
        nuclei findings together, and prioritizes by real exploitability."""
        context = self._build_context(findings, web or [], nuclei or [])

        prompt = f"""
        You are a Senior Penetration Tester writing an engagement report. Below is the
        full recon data: open services with VERIFIED CVEs (NVD), web fingerprints, and
        active nuclei findings.
        {json.dumps(context, indent=2, ensure_ascii=False)}

        RULES:
        - Only reference the verified CVEs given; never invent CVE numbers.
        - Prioritize by real exploitability: 'kev' true = actively exploited (top
          priority), high 'epss' = likely exploited, 'exploitdb'/'poc' = public exploit
          exists. nuclei CRITICAL/HIGH findings are confirmed live issues.
        - Be concise and actionable; do not pad with generic advice.

        Write the report in English, in Markdown, with these sections:
        1. **Executive Summary** — overall risk posture and the top 3-5 things to fix first.
        2. **Attack Surface** — services, web technologies, and any WAF/CDN observed.
        3. **Key Findings** — prioritized issues (CVEs + nuclei), each with why it matters.
        4. **Exploitation Path** — the most realistic route in, with tools (Metasploit,
           searchsploit, etc.).
        5. **Remediation** — concrete fixes, most important first.
        """
        return self._complete(prompt)

    def copilot(self, findings=None, web=None, nuclei=None, scan_meta=None, target=None,
                extra=None):
        """Advisory 'what should I do next?' — reads the current recon state and
        recommends prioritized, concrete next actions (tools/commands/endpoints/CVEs).
        `extra` carries results from any other tool (subdomains, ports, leaks, confirmed
        vulns) so the co-pilot works after ANY operation, not just nmap."""
        context = self._build_context(findings or [], web or [], nuclei or [])
        context["target"] = target
        context["waf"] = (scan_meta or {}).get("waf")
        if extra:
            context.update(extra)
        # Drop empty sections so the prompt stays focused on what we actually have.
        context = {k: v for k, v in context.items() if v}

        prompt = f"""
        You are a Senior Penetration Tester acting as a hands-on co-pilot. Given the
        current recon state below, tell the operator the highest-value NEXT ACTIONS.
        {json.dumps(context, indent=2, ensure_ascii=False)}

        RULES:
        - Reference only the verified CVEs shown; never invent CVE numbers.
        - Be specific and practical: name the exact tool, command, endpoint or CVE to
          try, tied to what was actually found (e.g. "Jenkins on 8080 -> try /script
          console, CVE-XXXX with metasploit module Y").
        - Prioritize by real exploitability: KEV / high EPSS / public exploit, then
          confirmed nuclei CRITICAL/HIGH, then everything else.
        - If a WAF/CDN is present, account for it (evasion or note it may block).
        - This is authorized testing; the operator will verify every suggestion, so be
          direct. Do NOT claim anything is confirmed vulnerable without evidence.

        Output concise Markdown (max ~8 concrete moves):
        ## Next Moves (prioritized)
        1. **action** — why it matters + the exact command/tool
        ## Quick Wins
        ## Watch Out
        (WAF, rate-limits, or things likely to be false positives)
        """
        return self._complete(prompt)

    def suggest_payloads(self, context, kind, n=12):
        """Generate up to `n` target-tailored payloads for an active module (ssrf / lfi
        / 403). AI only PROPOSES candidates; the calling module still tests each one and
        confirms by evidence, so a bogus payload simply produces no finding."""
        prompt = f"""You are a penetration tester generating test payloads for AUTHORIZED
        testing. Target context (from recon):
        {json.dumps(context, ensure_ascii=False)}

        Generate up to {n} '{kind}' payloads tailored to this exact stack (OS, web server,
        framework, cloud provider, WAF). Prefer variants the generic lists miss.
        Return ONLY a JSON array of raw payload strings — no prose, no markdown."""
        return self._parse_payload_list(self._complete(prompt), n)

    @staticmethod
    def _parse_payload_list(raw, cap):
        """Safely pull a JSON string-array out of the model's reply."""
        if not raw:
            return []
        m = re.search(r"\[.*\]", raw, re.DOTALL)
        if not m:
            return []
        try:
            arr = json.loads(m.group(0))
        except ValueError:
            return []
        out = [x.strip() for x in arr
               if isinstance(x, str) and x.strip() and len(x) < 300]
        return out[:cap]

    def _complete(self, prompt):
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.5
            )
            return response.choices[0].message.content
        except Exception as e:
            return (f"AI analysis is unavailable right now: {e}\n\n"
                    f"Check AI_API_KEY / AI_BASE_URL / AI_MODEL in your .env "
                    f"(the rest of the scan data above is still valid).")
