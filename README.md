# SilentPivot

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)

**SilentPivot** is an AI-powered reconnaissance and vulnerability analysis tool designed for modern penetration testing. It seamlessly automates the initial network scanning phase and leverages Large Language Models (LLMs) to analyze results, score risks, and suggest actionable exploit vectors.

## 🚀 Features

* **Automated Reconnaissance:** Deep integration with Nmap for fast, reliable port, service, and OS version detection.
* **AI-Driven Analysis:** Utilizes advanced LLMs to analyze scan results with the mindset of a senior penetration tester.
* **Actionable Insights:** Automatically predicts CVEs, suggests exploit tools (e.g., Metasploit, Searchsploit), and maps out potential attack vectors.
* **Auto-Logging:** Generates and saves detailed Markdown reports locally for every scan, complete with target resolution and timestamps for evidence tracking.

## 🛠️ Prerequisites

Before you begin, ensure you have met the following requirements:
* **Python 3.8+**
* **Nmap:** Must be installed and added to your system's PATH. ([Download Nmap](https://nmap.org/download.html))
* **API Key:** An API key.

## 📦 Installation

1. Clone the repository:
```bash
git clone [https://github.com/yusufseday/silentpivot.git](https://github.com/yusufseday/silentpivot.git)
cd silentpivot
Install the required Python dependencies:

Bash
pip install -r requirements.txt
Set up your environment variables:
Rename .env.example to .env and insert your API key:

Kod snippet'i
AI_API_KEY=your_api_key_here
🎯 Usage
Run the tool via the command line. You can input either an IP address or a Domain name.

Bash
python3 silentpivot.py
Follow the on-screen prompts to enter your target. The tool will automatically resolve domains, perform the scan, process the AI analysis, and save the final report in the data/ directory.

📂 Project Structure
Plaintext
silentpivot/
├── modules/
│   ├── scanner.py       # Nmap integration and data parsing
│   └── ai_engine.py     # LLM integration
├── data/                # Auto-generated Markdown scan reports
├── .env.example         # Template for environment variables
├── requirements.txt     # Python dependencies
└── silentpivot.py       # Main executable script
⚠️ Legal Disclaimer
This tool is designed strictly for educational purposes and authorized penetration testing only. The developer assumes no liability and is not responsible for any misuse, damage, or illegal activities caused by this program. Always ensure you have explicit, written permission from the system owner before scanning any network or system.

Developed for the cybersecurity community.
