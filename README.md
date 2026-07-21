# SilentPivot

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)

**SilentPivot** is an AI-powered recon and vulnerability analysis **command center**
built for penetration testing and red team work. It drives multiple tools from a single
terminal panel, verifies scan results against NVD + CISA KEV, and turns them into a
professional report with the help of a Large Language Model.

## 🚀 Features

* **One panel, many tools:** Drive every module from the interactive command center (menu).
* **Nmap scanning:** Fast / Standard / Deep port + service/version detection.
* **Subdomain discovery:** Passive OSINT via crt.sh (Certificate Transparency) + live DNS resolution.
* **Quick port check:** Native, parallel open/closed test in pure Python — no nmap required.
* **CVE + CISA KEV:** CPE-based NVD queries; flags and prioritizes vulnerabilities that are
  **actively exploited in the wild**.
* **AI analysis:** Expert report grounded strictly on verified CVEs (no hallucinated CVE numbers).
* **Structured output:** Markdown or JSON reports, saved automatically.
* **Two modes:** Interactive panel *and* a scriptable CLI (for automation/pipelines).

## 🛠️ Prerequisites

* **Python 3.8+**
* **Nmap** (on PATH) — only for the nmap scan module. ([Download](https://nmap.org/download.html))
* **AI API key** — only for the AI report module.

## 📦 Installation

```bash
git clone https://github.com/yusufseday/silentpivot.git
cd silentpivot
pip install -r requirements.txt
cp .env.example .env    # then put your key inside .env
```

`.env` contents:
```
AI_API_KEY=your_api_key_here
NVD_API_KEY=            # optional, speeds up CVE queries
```

## 🎯 Usage

**Interactive panel (default):**
```bash
python3 silentpivot.py
```
Pick the tool you want from the menu. After an nmap scan the findings are kept in memory;
CVE analysis and the AI report chain off that scan.

**CLI / automation mode:**
```bash
python3 silentpivot.py -t scanme.nmap.org -s deep -f json -o report.json
python3 silentpivot.py -t 10.0.0.5 -s fast --no-ai --quiet
```

| Flag | Description |
|------|-------------|
| `-t, --target` | Target IP/domain |
| `-s, --scan-type` | `1/fast`, `2/standard`, `3/deep` |
| `--no-ai` | Skip AI analysis |
| `-f, --format` | `md` or `json` |
| `-o, --output` | Report file path |
| `-q, --quiet` | Quiet mode |

## 📂 Project Structure

```
silentpivot/
├── silentpivot.py        # Entry point (panel + CLI)
├── modules/
│   ├── panel.py          # Interactive command center (menu)
│   ├── ui.py             # Shared UI (Console, colors, tables)
│   ├── scanner.py        # Nmap integration
│   ├── subdomain.py      # crt.sh subdomain discovery
│   ├── portcheck.py      # Native TCP port check
│   ├── vuln_checker.py   # NVD (CPE) + CVSS vulnerability verification
│   ├── kev.py            # CISA KEV (actively exploited) catalog
│   ├── ai_engine.py      # LLM analysis engine
│   └── reporter.py       # JSON / Markdown report generation
└── data/                 # Auto-generated reports (gitignored)
```

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes and authorized penetration testing only**.
Always make sure you have **explicit, written permission** from the system owner before
scanning any system. The developer assumes no liability for misuse.
