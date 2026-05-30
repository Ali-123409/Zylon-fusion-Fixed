<div align="center">

# ZYLON FUSION

**Advanced Security Reconnaissance & Vulnerability Platform**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Version](https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge)](https://github.com/Ali-123409/zylon-fusion)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Termux](https://img.shields.io/badge/Termux-Non--Root-00C853?style=for-the-badge&logo=android)]

```
 ███████╗██╗██████╗  ██████╗ ███████╗
 ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
   ███╔╝ ██║██████╔╝██║   ██║███████╗
  ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
 ███████╗██║██║     ╚██████╔╝███████║
 ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝
```

*Fused from **omino** + **wizard** + Zylon Custom Techniques*

*Built for **Android Termux (Non-Root)** — No sudo required*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-scan-modules) • [AI Integration](#-ai-integration) • [Contributing](#-contributing)

</div>

---

## 🌟 Overview

**ZYLON FUSION** is an enterprise-grade offensive security platform that combines the best of two legendary tools — **omino** (advanced recon/vuln suite) and **wizard** (Python security framework) — with brand new custom Zylon techniques, all rebuilt from scratch to run on **Android Termux without root access**.

|  🔥 22+ Scans  |  📱 Termux Ready  |  🤖 AI Ready  |  🎯 10+ Data Sources  |  🔒 Non-Root  |
|:-:|:-:|:-:|:-:|:-:|

---

## ✨ Features

### Fused from omino
- Multi-source subdomain discovery (10 sources: crt.sh, bufferover.run, rapiddns, etc.)
- Full reconnaissance pipeline (OSINT → DNS → Ports → Vulns)
- Workspace and loot management concepts
- Nuclear scan mode (everything combined)

### Fused from wizard
- Python-based engine with Rich UI
- SQL Injection & XSS scanners
- WordPress security scanning
- WHOIS, Geo-IP, DNS enumeration
- API key management with encryption
- JSON/HTML/PDF reporting

### Zylon Custom Techniques (NEW)
- CORS Misconfiguration Detector
- Open Redirect Detector
- CRLF Injection Scanner
- Cookie Security Analyzer
- JavaScript Sensitive Data Extractor (API keys, AWS keys, JWTs, etc.)
- Cloud Storage Bucket Detector (AWS S3, GCS, Azure Blob)
- WAF Detector & Fingerprinter (7 WAF signatures)
- Technology Stack Fingerprinter (15+ technologies)
- SSL/TLS Deep Analysis
- AI-Powered Vulnerability Analysis Bridge

---

## 📱 Installation

### Termux (Android Non-Root) — One Command Install

```bash
# Clone the repo
git clone https://github.com/Ali-123409/zylon-fusion.git
cd zylon-fusion

# Run the installer
bash install_termux.sh

# Launch
zylon
```

### Manual Install (Any Platform)

```bash
git clone https://github.com/Ali-123409/zylon-fusion.git
cd zylon-fusion
pip3 install -r requirements.txt
python3 zylon.py
```

### Prerequisites

- Python 3.8+
- pip3
- Internet connection

> **No root required!** All scanning uses API-based and connect-scan methods.

---

## 🚀 Usage

### Interactive Mode

```bash
python3 zylon.py
```

```
ZYLON > example.com          # Set target + choose scan
ZYLON > help                 # Show all commands
ZYLON > 0                    # Full Reconnaissance
ZYLON > 22                   # NUCLEAR SCAN (all modules)
ZYLON > ai                   # AI vulnerability analysis
ZYLON > config               # Manage API keys
ZYLON > exit                 # Quit
```

### Quick Start

1. Launch ZYLON: `python3 zylon.py`
2. Enter your target domain
3. Select scan type (0-22)
4. View results in terminal
5. Reports auto-saved to `~/.zylon/reports/`

---

## 🎯 Scan Modules

| # | Module | Source | Description |
|---|---|---|---|
| 0 | **Full Recon** | omino + wizard | OSINT, DNS, Subdomains, Headers, CMS, Cloudflare |
| 1 | **WHOIS** | wizard | Domain registration lookup |
| 2 | **Geo-IP** | wizard | Server geolocation |
| 3 | **DNS Enum** | omino + wizard | A, AAAA, MX, NS, TXT, CNAME, SOA, DMARC |
| 4 | **Subdomain Discovery** | omino | 10 sources: crt.sh, bufferover, rapiddns, etc. |
| 5 | **Port Scanner** | wizard + fix | Connect scan (NO ROOT needed) |
| 6 | **Banner Grab** | omino + wizard | Service fingerprinting |
| 7 | **Security Headers** | wizard + enhanced | 10 headers scored with recommendations |
| 8 | **SSL/TLS Analysis** | Zylon Custom | Certificate, protocol, cipher, expiry |
| 9 | **SQL Injection** | wizard + enhanced | Error, Time, Boolean-based detection |
| 10 | **XSS Scanner** | wizard + enhanced | Reflected XSS + Template Injection |
| 11 | **Directory Brute** | wizard + enhanced | 70+ common paths + smart detection |
| 12 | **WordPress Scan** | wizard + enhanced | 12 WP checks + REST API user enum |
| 13 | **CORS Detector** | Zylon Custom | 6 origin tests with risk scoring |
| 14 | **Open Redirect** | Zylon Custom | 12 params × 6 payloads |
| 15 | **CRLF Injection** | Zylon Custom | Header injection testing |
| 16 | **Cookie Security** | Zylon Custom | Secure, HttpOnly, SameSite analysis |
| 17 | **JS Secrets** | Zylon Custom | API keys, AWS keys, JWTs, DB connections |
| 18 | **Cloud Buckets** | Zylon Custom | AWS S3, GCS, Azure Blob, DO Spaces |
| 19 | **WAF Detector** | Zylon Custom | 7 WAF signatures with confidence |
| 20 | **Tech Fingerprint** | Zylon Custom | 15+ technologies detected |
| 21 | **Full Vuln Scan** | omino + wizard | All vulnerability scanners combined |
| 22 | **NUCLEAR SCAN** | omino nuke mode | **ALL 22 modules combined** |

---

## 🤖 AI Integration

ZYLON FUSION includes an AI bridge module ready for LLM integration:

1. Set your API key: `config` → `ai_api_key`
2. Run any scan
3. Type `ai` to get AI-powered analysis

Supports OpenAI-compatible endpoints. Future versions will include:
- Automated exploit chain identification
- Priority-based remediation suggestions
- Natural language report generation
- Continuous monitoring with AI alerts

---

## 🏗️ Architecture

```
zylon-fusion/
├── zylon.py              # Main engine + interactive UI
├── core/
│   ├── var.py            # Constants, payloads, signatures
│   ├── recon.py          # Reconnaissance engine
│   ├── vuln.py           # Vulnerability scanner engine
│   ├── network.py        # Network scanning engine
│   ├── web.py            # Web security engine
│   ├── reports.py        # HTML/JSON report generator
│   └── ai_bridge.py      # AI integration module
├── install_termux.sh     # Termux one-command installer
└── requirements.txt      # Python dependencies
```

---

## 🔑 Termux Non-Root Compatibility

| Feature | PC Tools | ZYLON FUSION |
|---|---|---|
| Port Scanning | SYN scan (root) | Connect scan (no root) |
| Subdomain Enum | Binary tools (amass, subfinder) | API-based (10 sources) |
| Installation | apt-get + sudo | pkg (Termux native) |
| File Paths | /usr/share/ | $HOME/.zylon/ |
| Dependencies | Many system packages | Python only |
| Nmap | Required | Optional (built-in scanner) |

---

## 📊 Comparison with Source Tools

| Feature | omino | wizard | ZYLON FUSION |
|---|---|---|---|
| Language | Bash | Python 3 | Python 3 |
| Root Required | Yes | No | No |
| Termux Compatible | No | Partial | **Full** |
| Subdomain Sources | 8+ (binaries) | 1 | **10 (API-based)** |
| Vulnerability Scans | External tools | 3 | **8+** |
| Custom Techniques | 0 | 0 | **8+** |
| AI Integration | No | No | **Yes** |
| Non-Root Port Scan | No | No | **Yes** |
| Rich UI | Bash colors | Rich | **Rich** |

---

## ⚖️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any target. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

## 🤝 Contributing

Contributions are welcome! Feel free to:
1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Open a Pull Request

---

<div align="center">

**Built by Zylon | Hackathon Edition**

*omino + wizard + Zylon Custom Techniques = ZYLON FUSION*

</div>
