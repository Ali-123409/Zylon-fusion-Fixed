<div align="center">

# ZYLON FUSION

**Advanced Security Reconnaissance & Vulnerability Platform**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Version](https://img.shields.io/badge/Version-2.0.0-red?style=for-the-badge)](https://github.com/Ali-123409/zylon-fusion)
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

**v2.0 NUCLEAR** — Fused from **omino** + **wizard** + Zylon Custom Techniques + V2.0 Nuclear Modules + Origin IP Finder

*Built for **Android Termux (Non-Root)** — No sudo required*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-scan-modules) • [AI Integration](#-ai-integration) • [Architecture](#-architecture) • [Contributing](#-contributing)

</div>

---

## 🌟 Overview

**ZYLON FUSION v2.0 NUCLEAR** is an enterprise-grade offensive security platform that combines the best of two legendary tools — **omino** (advanced recon/vuln suite) and **wizard** (Python security framework) — with brand new custom Zylon techniques, V2.0 Nuclear modules, and a powerful Origin IP Finder engine, all rebuilt from scratch to run on **Android Termux without root access**.

|  🔥 57+ Scans  |  📱 Termux Ready  |  🤖 AI Ready  |  🎯 10+ Data Sources  |  🔒 Non-Root  |
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

### Zylon Custom Techniques (NEW in v1.0)
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

### V2.0 Nuclear Modules (NEW in v2.0)
- **Deep Web Crawler** — Recursive URL discovery, form extraction, API endpoint detection
- **Parameter Mining** — Discover hidden parameters with reflection testing
- **Wayback Machine** — Historical URL and parameter discovery
- **Google Dorking** — Automated Google search queries for sensitive data
- **GitHub Secret Dorking** — Find leaked secrets on GitHub repositories
- **Deep JS Analysis** — Advanced JavaScript analysis for endpoints, secrets, hidden params
- **Subdomain Takeover** — Detect vulnerable subdomain takeover (20+ services)
- **SSRF Scanner** — Server-Side Request Forgery detection
- **SSTI Scanner** — Server-Side Template Injection detection
- **LFI / Path Traversal** — Local File Inclusion with 20+ payloads
- **XXE Scanner** — XML External Entity injection detection
- **IDOR Scanner** — Insecure Direct Object Reference testing
- **Race Condition** — Concurrent request race condition testing
- **Prototype Pollution** — Client-side and server-side prototype pollution
- **Cache Poisoning** — HTTP cache poisoning detection
- **Request Smuggling** — HTTP request smuggling (CL.TE / TE.CL)
- **Host Header Injection** — Host header manipulation testing
- **JWT Vulnerability Scanner** — JWT none algorithm, weak secret, key confusion
- **Broken Authentication** — Brute force, default creds, session issues
- **API Fuzzer** — REST API endpoint fuzzing with error detection
- **Rate Limit Tester** — API rate limiting and throttling analysis
- **Sensitive File Scanner** — Exposed config files, backups, .env, .git
- **Email Enumeration** — User enumeration via registration/login flows
- **Broken Link Checker** — Dead link detection with status codes
- **Tech CVE Lookup** — Technology version to CVE correlation

### Origin IP Finder (NEW in v2.0)
- **22 Advanced Techniques** to discover the real origin IP behind CDN/Cloudflare/WAF
- IP Classification System — Labels each IP as `origin`, `mail`, `spf`, `dns`, or `cdn`
- CDN/Cloud IP Range Filtering — AWS, GCP, Azure, Cloudflare, and 70+ ranges
- Mail Provider Detection — Google (1e100.net), Mailchimp, SendGrid, and 20+ patterns
- Quick Find — Fast 8-technique scan for rapid results
- Full Find — All 22 techniques for comprehensive discovery
- CDN Detection — Identify CDN provider with confidence scoring
- DNS & Certificate Hunting — DNS records + crt.sh certificate search
- Subdomain Origin — Scan all subdomains for non-CDN IPs
- IP Verification — HTTP verification with host header routing

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
ZYLON > 22                   # NUCLEAR SCAN (all base modules)
ZYLON > 42                   # Bug Bounty Recon
ZYLON > 43                   # Bug Bounty Vuln Scan
ZYLON > 50                   # Origin IP Quick Find
ZYLON > 55                   # IP Verification
ZYLON > 99                   # MEGA SCAN (everything)
ZYLON > ai                   # AI vulnerability analysis
ZYLON > config               # Manage API keys
ZYLON > exit                 # Quit
```

### Quick Start

1. Launch ZYLON: `python3 zylon.py`
2. Enter your target domain
3. Select scan type (0-55, 99)
4. View results in terminal
5. Reports auto-saved to `~/.zylon/reports/`

---

## 🎯 Scan Modules

### Core Reconnaissance (0-8)

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

### Vulnerability Scanners (9-12)

| # | Module | Source | Description |
|---|---|---|---|
| 9 | **SQL Injection** | wizard + enhanced | Error, Time, Boolean-based detection |
| 10 | **XSS Scanner** | wizard + enhanced | Reflected XSS + Template Injection |
| 11 | **Directory Brute** | wizard + enhanced | 70+ common paths + smart detection |
| 12 | **WordPress Scan** | wizard + enhanced | 12 WP checks + REST API user enum |

### Web Security (13-20)

| # | Module | Source | Description |
|---|---|---|---|
| 13 | **CORS Detector** | Zylon Custom | 6 origin tests with risk scoring |
| 14 | **Open Redirect** | Zylon Custom | 12 params × 6 payloads |
| 15 | **CRLF Injection** | Zylon Custom | Header injection testing |
| 16 | **Cookie Security** | Zylon Custom | Secure, HttpOnly, SameSite analysis |
| 17 | **JS Secrets** | Zylon Custom | API keys, AWS keys, JWTs, DB connections |
| 18 | **Cloud Buckets** | Zylon Custom | AWS S3, GCS, Azure Blob, DO Spaces |
| 19 | **WAF Detector** | Zylon Custom | 7 WAF signatures with confidence |
| 20 | **Tech Fingerprint** | Zylon Custom | 15+ technologies detected |

### Combined Scans (21-22)

| # | Module | Source | Description |
|---|---|---|---|
| 21 | **Full Vuln Scan** | omino + wizard | All vulnerability scanners combined |
| 22 | **NUCLEAR SCAN** | omino nuke mode | **ALL base modules combined** |

### Bug Bounty Arsenal (23-41)

| # | Module | Source | Description |
|---|---|---|---|
| 23 | **Deep Crawler** | Zylon V2 | Recursive URL, form, API, JS discovery |
| 24 | **Parameter Mining** | Zylon V2 | Hidden parameter discovery with reflection |
| 25 | **Wayback URLs** | Zylon V2 | Historical URL and parameter discovery |
| 26 | **Google Dork** | Zylon V2 | Automated Google search queries |
| 27 | **GitHub Dork** | Zylon V2 | Leaked secrets on GitHub repositories |
| 28 | **Deep JS Analysis** | Zylon V2 | Endpoints, secrets, hidden params in JS |
| 29 | **Subdomain Takeover** | Zylon V2 | 20+ service takeover detection |
| 30 | **SSRF Scanner** | Zylon V2 | Server-Side Request Forgery detection |
| 31 | **SSTI Scanner** | Zylon V2 | Server-Side Template Injection |
| 32 | **LFI / Path Traversal** | Zylon V2 | 20+ payloads for Local File Inclusion |
| 33 | **XXE Scanner** | Zylon V2 | XML External Entity injection |
| 34 | **IDOR Scanner** | Zylon V2 | Insecure Direct Object Reference |
| 35 | **Race Condition** | Zylon V2 | Concurrent request race testing |
| 36 | **Prototype Pollution** | Zylon V2 | Client & server-side pollution |
| 37 | **Cache Poisoning** | Zylon V2 | HTTP cache poisoning detection |
| 38 | **Request Smuggling** | Zylon V2 | CL.TE / TE.CL smuggling |
| 39 | **Host Header Injection** | Zylon V2 | Host header manipulation |
| 40 | **JWT Vulnerability** | Zylon V2 | None algo, weak secret, key confusion |
| 41 | **Broken Auth** | Zylon V2 | Brute force, default creds, sessions |

### Bug Bounty Workflows (42-43)

| # | Module | Source | Description |
|---|---|---|---|
| 42 | **Bounty Recon** | Zylon V2 | Automated recon workflow for bug bounty |
| 43 | **Bounty Vuln** | Zylon V2 | Automated vulnerability workflow |

### V2.0 Nuclear Modules (44-49)

| # | Module | Source | Description |
|---|---|---|---|
| 44 | **API Fuzzer** | Zylon V2 | REST API endpoint fuzzing with error detection |
| 45 | **Rate Limit Test** | Zylon V2 | API rate limiting and throttling analysis |
| 46 | **Sensitive Files** | Zylon V2 | Exposed .env, .git, config, backup files |
| 47 | **Email Enum** | Zylon V2 | User enumeration via registration/login |
| 48 | **Broken Links** | Zylon V2 | Dead link detection with status codes |
| 49 | **Tech CVE Lookup** | Zylon V2 | Technology version to CVE correlation |

### Origin IP Finder (50-55)

| # | Module | Source | Description |
|---|---|---|---|
| 50 | **Origin IP Quick** | Zylon V2 | Fast 8-technique scan for origin IP |
| 51 | **Origin IP Full** | Zylon V2 | All 22 techniques for comprehensive discovery |
| 52 | **CDN Detection** | Zylon V2 | CDN provider identification with confidence |
| 53 | **DNS & Cert Hunt** | Zylon V2 | DNS records + crt.sh certificate search |
| 54 | **Subdomain Origin** | Zylon V2 | Scan subdomains for non-CDN IPs |
| 55 | **IP Verification** | Zylon V2 | HTTP verification with host header routing |

### Mega Scan

| # | Module | Source | Description |
|---|---|---|---|
| 99 | **MEGA SCAN** | All | **Every single module combined** |

---

## 🔍 Origin IP Finder — 22 Techniques

The Origin IP Finder uses 22 advanced techniques to discover the real IP address behind CDN/Cloudflare/WAF:

| Category | Techniques |
|---|---|
| **DNS Record Mining** | A, AAAA, MX, NS, TXT, SOA records |
| **Historical Data** | SecurityTrails, Netcraft, ViewDNS |
| **Certificate Search** | crt.sh, Censys certificate search |
| **SPF/DKIM/DMARC** | SPF includes, DKIM selectors, DMARC reports |
| **Subdomain Resolution** | Subdomain A/AAAA record lookup |
| **Cloud Metadata** | AWS, GCP, Azure IP range matching |
| **HTTP Verification** | Host header routing, status code validation |
| **IP Classification** | origin / mail / spf / dns / cdn labeling |

**Key Features:**
- 🔒 **False Positive Prevention** — MX/SPF/DNS infrastructure IPs are classified, not shown as origin
- ☁️ **Cloud IP Filtering** — 70+ AWS, GCP, Azure, Cloudflare IP ranges detected
- 📧 **Mail Provider Detection** — Google (1e100.net), Mailchimp, SendGrid, and 20+ patterns
- ✅ **HTTP Verification** — Only 200/301/302 responses count as verified (403/5xx rejected)

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
├── zylon.py                  # Main engine + interactive UI (2,199 lines)
├── core/
│   ├── __init__.py           # Package init
│   ├── var.py                # Constants, payloads, signatures, CDN ranges (725 lines)
│   ├── recon.py              # Reconnaissance engine (704 lines)
│   ├── vuln.py               # Vulnerability scanner engine (526 lines)
│   ├── network.py            # Network scanning engine (411 lines)
│   ├── web.py                # Web security engine (368 lines)
│   ├── reports.py            # HTML/JSON report generator (242 lines)
│   ├── ai_bridge.py          # AI integration module (196 lines)
│   ├── advanced_recon.py     # Advanced recon: Deep Crawl, Params, Wayback, Dorks (759 lines)
│   ├── advanced_web.py       # Advanced web: Takeover, SSRF, SSTI, LFI, XXE, IDOR (605 lines)
│   ├── injections.py         # Injection scanners: Race, ProtoPollution, Cache, Smuggle (845 lines)
│   ├── bounty_workflow.py    # Bug bounty workflow automation (516 lines)
│   ├── v2_recon.py           # V2 Recon: API Fuzzer, Rate Limit, Sensitive Files (404 lines)
│   ├── v2_vuln.py            # V2 Vuln: Email Enum, Broken Links, Tech CVE (364 lines)
│   └── origin_ip.py          # Origin IP Finder Engine — 22 techniques (2,178 lines)
├── install_termux.sh         # Termux one-command installer
└── requirements.txt          # Python dependencies
```

**Total Codebase:** 11,000+ lines of Python

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
| Origin IP Discovery | Manual techniques | 22 automated techniques |

---

## 📊 Comparison with Source Tools

| Feature | omino | wizard | ZYLON FUSION v2.0 |
|---|---|---|---|
| Language | Bash | Python 3 | Python 3 |
| Root Required | Yes | No | No |
| Termux Compatible | No | Partial | **Full** |
| Subdomain Sources | 8+ (binaries) | 1 | **10 (API-based)** |
| Vulnerability Scans | External tools | 3 | **20+** |
| Custom Techniques | 0 | 0 | **8+** |
| V2 Nuclear Modules | 0 | 0 | **19+** |
| Origin IP Finder | 0 | 0 | **22 techniques** |
| AI Integration | No | No | **Yes** |
| Non-Root Port Scan | No | No | **Yes** |
| Rich UI | Bash colors | Rich | **Rich** |
| Total Scan Methods | ~10 | ~5 | **57+** |

---

## 📦 Dependencies

### Python Packages
| Package | Purpose |
|---|---|
| `requests` | HTTP requests for all web scanning |
| `rich` | Terminal UI with colors, tables, progress bars |
| `colorama` | Cross-platform colored output |
| `beautifulsoup4` | HTML parsing and extraction |
| `dnspython` | DNS queries and enumeration |
| `python-whois` | WHOIS domain lookups |
| `lxml` | Fast XML/HTML processing |
| `cryptography` | SSL/TLS certificate analysis |
| `aiohttp` | Async HTTP for parallel scanning |
| `pyfiglet` | ASCII art banner generation |

### Optional (for enhanced features)
| Package | Purpose |
|---|---|
| `nmap` | Advanced port scanning (optional) |

### API Keys (Optional — all modules work without them)
| Key | Purpose |
|---|---|
| `shodan_api_key` | Enhanced port/service data |
| `virustotal_api_key` | Domain/IP reputation |
| `hunter_api_key` | Email discovery |
| `securitytrails_api_key` | Historical DNS data for Origin IP Finder |
| `censys_api_id` + `censys_api_secret` | Certificate search for Origin IP Finder |
| `ai_api_key` | AI-powered vulnerability analysis |

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

*omino + wizard + Zylon Custom Techniques + V2.0 Nuclear Modules + Origin IP Finder = ZYLON FUSION v2.0 NUCLEAR*

</div>
