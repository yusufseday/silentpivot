<p align="center">
  <img src="assets/banner.svg" alt="SilentPivot — AI-powered recon & vulnerability command center" width="600">
</p>

# SilentPivot

![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)

**SilentPivot** is an AI-powered reconnaissance and vulnerability-analysis **command
center** for penetration testing and red-team work. It drives many tools from a single
terminal panel, verifies findings against authoritative sources (NVD, CISA KEV, EPSS),
and turns everything into a professional report — in one command.

Its guiding principle: **surface everything that matters, drown the user in nothing.**
Signal over noise, verified data over guesses, graceful behaviour on any network.

> ⚠️ For **authorized** security testing only. Always have explicit, written permission
> before scanning any system.

---

## ✨ Features

**Recon**
- **Nmap scanning** — service/version detection with sane defaults (`-Pn`, top-1000, IPv6-aware, host-timeout).
- **Subdomain discovery** — hybrid engine: uses `subfinder`/`amass` if installed, always merges keyless passive sources (crt.sh, certspotter, AlienVault OTX, HackerTarget, Anubis).
- **Native port check** — fast TCP open/closed test in pure Python, no nmap needed.
- **Web fingerprinting** — HTTP probe with technology detection (WordPress, Nginx, ASP.NET…) and WAF/CDN detection (Cloudflare, Imperva Incapsula, Akamai…).

**Vulnerability intelligence**
- **CVE matching** — CPE-based queries against the NIST **NVD** database.
- **CISA KEV** — flags CVEs **actively exploited in the wild**.
- **EPSS** — exploitation-probability score per CVE.
- **Exploit mapping** — public GitHub PoCs + **ExploitDB** (via `searchsploit`).
- **Nuclei** — active templated scanning (thousands of community templates).

**Analysis & reporting**
- **AI analysis** — an LLM writes a senior-pentester report, grounded strictly on verified CVEs (no hallucinated CVE numbers).
- **Autopilot** — the whole pipeline in one command.
- **Reports** — Markdown, JSON, or a polished self-contained **HTML** report.

**Smart behaviour**
- **Layered disclosure** — confirmed services shown first; WAF/decoy phantom ports collapsed but saved in full to the report.
- **WAF / firewall awareness** — tells you when a target is behind a WAF or when your own network is blocking the scan.
- **Network-adaptive** — auto-detects IPv6 connectivity and multi-IP (round-robin) targets, and lets you pick which IP to scan.

---

## 🧭 How it works (Autopilot pipeline)

```
Target
  │
  ├─ 1. Nmap            → open ports + services
  ├─ 2. CVE/KEV/EPSS    → verified vulns + real exploitability
  ├─ 3. Web probe       → tech stack + WAF/CDN
  ├─ 4. Nuclei          → active vulnerability scan
  ├─ 5. AI analysis     → prioritized expert report
  └─ 6. Report          → one unified MD / JSON / HTML file
```

Each stage is isolated — if one fails, the pipeline degrades gracefully instead of aborting.

---

## 🛠️ Prerequisites

- **Python 3.8+**
- **Nmap** on your PATH — for the nmap scan module. ([Download](https://nmap.org/download.html))
- **AI API key** (OpenAI-compatible) — only for the AI report module.
- **Optional** (unlock the hybrid tools, e.g. on Kali): `nuclei`, `subfinder`/`amass`, `searchsploit` (exploitdb).

---

## 📦 Installation

```bash
git clone https://github.com/yusufseday/SilentPivot.git
cd SilentPivot
python3 -m venv venv
source venv/bin/activate          # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # then add your key
```

`.env`:
```ini
AI_API_KEY=your_api_key_here
NVD_API_KEY=            # optional — speeds up CVE queries
```

Verify everything works against the real data sources:
```bash
python scripts/selftest.py         # expect all checks to pass
```

---

## 🎯 Usage

**Interactive panel (default):**
```bash
python silentpivot.py
```

```
 A   Autopilot / Full Engagement   (runs the whole pipeline)
 1   Nmap Port Scan                (service/version detection)
 2   Subdomain Discovery           (passive OSINT + DNS)
 3   Quick Port Check              (open/closed — no nmap needed)
 4   Web Probe & Fingerprint       (HTTP tech/WAF detection)
 5   Nuclei Vuln Scan              (active templated scanning)
 6   CVE + KEV Vuln Analysis       (on the last scan)
 7   Generate AI Report            (on the last scan)
 8   Saved Reports
 0   Exit
```
After an Nmap scan, the findings stay in memory — CVE analysis, Nuclei and the AI
report all chain off that scan.

**Autopilot — full engagement in one command:**
```bash
python silentpivot.py -t target.com --auto -f html
```

**CLI / automation:**
```bash
python silentpivot.py -t scanme.nmap.org -s deep -f json -o report.json
python silentpivot.py -t 10.0.0.5 -s fast --no-ai --quiet
```

| Flag | Description |
|------|-------------|
| `-t, --target` | Target IP/domain |
| `-s, --scan-type` | `1/fast`, `2/standard`, `3/deep` |
| `--auto` | Autopilot: full engagement pipeline |
| `--no-ai` | Skip AI analysis |
| `-f, --format` | `md`, `json`, or `html` |
| `-o, --output` | Report file path |
| `-q, --quiet` | Quiet mode |

Reports are saved under `data/`. Open an HTML report in any browser:
```bash
xdg-open data/*.html      # or: firefox data/*.html
```

---

## 📂 Project structure

```
silentpivot/
├── silentpivot.py         # Entry point (panel + CLI)
├── modules/
│   ├── panel.py           # Interactive command center
│   ├── ui.py              # Shared UI (console, colors, tables)
│   ├── autopilot.py       # Full-engagement orchestrator
│   ├── scanner.py         # Nmap integration + scan context
│   ├── subdomain.py       # Hybrid subdomain discovery
│   ├── portcheck.py       # Native TCP port check
│   ├── webprobe.py        # HTTP fingerprinting + WAF detection
│   ├── nuclei.py          # Nuclei wrapper
│   ├── vuln_checker.py    # NVD (CPE) + CVSS matching
│   ├── kev.py             # CISA KEV catalog
│   ├── exploits.py        # EPSS + PoC + ExploitDB intel
│   ├── ai_engine.py       # LLM analysis engine
│   └── reporter.py        # MD / JSON / HTML reports
├── scripts/selftest.py    # Live self-test of every module
└── data/                  # Auto-generated reports (gitignored)
```

---

## ⚠️ Legal disclaimer

This tool is for **educational purposes and authorized penetration testing only**.
Always obtain **explicit, written permission** from the system owner before scanning.
The developer assumes no liability for misuse.
