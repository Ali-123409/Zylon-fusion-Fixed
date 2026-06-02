<div align="center">

# ZYLON FUSION

**Advanced Security Reconnaissance & Vulnerability Platform**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Version](https://img.shields.io/badge/Version-6.2.0-red?style=for-the-badge)](https://github.com/Ali-123409/zylon-fusion)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Termux](https://img.shields.io/badge/Termux-Non--Root-00C853?style=for-the-badge&logo=android)]
[![Scans](https://img.shields.io/badge/Scans-428-orange?style=for-the-badge)]

```
 ███████╗██╗██████╗  ██████╗ ███████╗
 ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
   ███╔╝ ██║██████╔╝██║   ██║███████╗
  ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
 ███████╗██║██║     ╚██████╔╝███████║
 ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝
```

**v6.2.0 ULTIMATE** — Fused from **omino** + **wizard** + Zylon Custom + V2-V6 Engines + 87 Engine Files + 428 Scan Types + 55 Groups

*Built for **Android Termux (Non-Root)** — No sudo required*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Scan-Groups](#-scan-groups-55-groups) • [Modules](#-scan-modules) • [AI Integration](#-ai-integration) • [Performance](#-performance-engine) • [Wordlists](#-built-in-wordlists) • [Architecture](#-architecture) • [Branches](#-branches)

</div>

---

## 🌟 Overview

**ZYLON FUSION v6.2.0 ULTIMATE** is an enterprise-grade offensive security platform that combines the best of two legendary tools — **omino** and **wizard** — with brand new Zylon techniques, V2-V6 engines, 87 engine files, 428 scan types, 55 groups, built-in wordlists, Gemini AI integration, thread-safe parallel scanning, and a **Performance Engine** that makes scans 3-5x faster.

| 🔥 428 Scans | 📱 Termux Ready | 🤖 Gemini AI | 🧠 55 Groups | ⚡ 87 Engines | 🔒 Non-Root |
|:-:|:-:|:-:|:-:|:-:|:-:|

---

## ✨ What's New in v6.2.0 ULTIMATE

### 🚀 8-Phase Unleash Plan (P1-P8)

| Phase | What | Impact |
|---|---|---|
| P1 | **Thread Safety** | Fixed all race conditions in parallel scanning |
| P2 | **Orphaned Engines** | Wired 12 disconnected engines to scan_map |
| P3 | **Performance Integration** | DNS cache + connection pool + adaptive threading |
| P4 | **Scan Map Expansion** | 428 scan types across 55 groups |
| P5 | **Python 3.13 Compat** | Fixed yaml, urllib3, telnetlib import errors |
| P6 | **Duplicate Removal** | Cleaned duplicate scan_map entries |
| P7 | **Safe Import System** | Graceful fallback for all module imports |
| P8 | **Full Audit** | 88 files, 87 engines, zero import failures |

### ⚡ Performance Engine (V6)
- **DNS Cache** — Thread-safe DNS caching with TTL, saves 2-5s per repeated lookup
- **HTTP Connection Pooling** — Reuses TCP connections across all modules (100 pool size)
- **Adaptive Threading** — Auto-adjusts thread count based on CPU, error rate, and WAF detection
- **Smart Rate Limiter** — Exponential backoff on 429 responses, prevents WAF bans
- **Adaptive Timeouts** — Adjusts timeouts based on observed response times
- **Performance Stats** — `perf` command shows DNS cache hit rate, thread stats, request count

### 🧵 Thread-Safe Parallel Scanning
- All group scans run in **parallel** using ThreadPoolExecutor
- Thread-safe result collection with locks
- Safe save/restore of shared state
- Serial mode available for sensitive targets (`G1-S`)

### 🤖 Gemini AI Integration
- **X-goog-api-key Header** — More secure than URL parameter authentication
- **gemini-flash-latest Model** — Always uses the latest Flash model, with auto-fallback
- **AI Vulnerability Triage** (Scan 87) — Classifies findings, identifies false positives
- **AI Recon Advisor** (Scan 88) — Suggests recon strategy based on partial results
- **AI Payload Generator** (`aipayload`) — Context-aware payload crafting
- **AI Connection Test** (`aitest`) — Verify Gemini API connectivity

### 📚 Expanded Wordlists
- **Directories**: 431 → 1,176 entries
- **Subdomains**: 452 → 1,176 entries
- **API Paths**: 550+ API endpoint paths
- **File Extensions**: 225+ file extensions
- **JWT Secrets**: 224+ secrets
- **Total**: 9 built-in wordlists, 3,815+ entries

---

## 📱 Installation

### Termux (Android Non-Root) — One Command Install

```bash
git clone https://github.com/Ali-123409/zylon-fusion.git
cd zylon-fusion
bash install_termux.sh
zylon
```

### Manual Install (Any Platform)

```bash
git clone https://github.com/Ali-123409/zylon-fusion.git
cd zylon-fusion
pip3 install -r requirements.txt
python3 zylon.py
```

> **No root required!** All scanning uses API-based and connect-scan methods.

---

## 🚀 Usage

```bash
python3 zylon.py
```

```
ZYLON > example.com          # Set target + choose scan
ZYLON > help                 # Show all commands
ZYLON > 0                    # Full Reconnaissance
ZYLON > 22                   # NUCLEAR SCAN (all base modules)
ZYLON > 42                   # Bug Bounty Recon
ZYLON > 50                   # Origin IP Quick Find
ZYLON > 86                   # AI Smart Scan (Gemini-Guided)
ZYLON > 87                   # AI Vulnerability Triage
ZYLON > 88                   # AI Recon Advisor
ZYLON > 99                   # MEGA SCAN (everything)
ZYLON > groups               # Group-based scanning mode
ZYLON > GALL                 # Run ALL groups (428 scans) PARALLEL
ZYLON > G1+G2+G5             # Multiple groups — PARALLEL
ZYLON > ai                   # AI Chat (Gemini Security Assistant)
ZYLON > aianalyze            # AI Analyze last scan results
ZYLON > aipayload            # AI Generate custom payloads
ZYLON > aitest               # Test Gemini API connection
ZYLON > perf                 # Performance statistics
ZYLON > search xss           # Search scans by keyword
ZYLON > config               # Manage API keys
ZYLON > exit                 # Quit
```

---

## 🎯 Scan Groups (55 Groups)

| Group | Category | Scans |
|---|---|---|
| G1 | SQL Injection | 14 |
| G2 | XSS | 14 |
| G3 | LFI/RFI | 8 |
| G4 | SSRF | 8 |
| G5 | Authentication | 10 |
| G6 | CORS | 6 |
| G7 | Open Redirect | 4 |
| G8 | JWT | 6 |
| G9 | CSRF | 4 |
| G10 | Subdomain Takeover | 6 |
| G11 | XXE | 4 |
| G12 | SSTI | 6 |
| G13 | IDOR | 4 |
| G14 | Race Condition | 4 |
| G15 | Prototype Pollution | 6 |
| G16 | Cache Poisoning | 6 |
| G17 | Request Smuggling | 6 |
| G18 | WebSocket | 4 |
| G19 | GraphQL | 4 |
| G20 | API Security | 8 |
| G21 | Reconnaissance | 12 |
| G22 | OSINT | 10 |
| G23 | DNS Security | 6 |
| G24 | Cloud Security | 8 |
| G25 | Container Security | 6 |
| G26 | Mobile Security | 4 |
| G27 | Crypto/Hash | 6 |
| G28 | WAF Bypass | 8 |
| G29 | Credential Testing | 6 |
| G30 | Directory Brute | 6 |
| G31 | Subdomain Enum | 8 |
| G32 | Technology Detection | 6 |
| G33 | Origin IP | 8 |
| G34 | Wordlist/Brute | 6 |
| G35 | Nuclei-Style | 6 |
| G36 | Dalfox/XSStrike | 6 |
| G37 | SQLMap/Hakuin | 6 |
| G38 | Commix/CMDi | 6 |
| G39 | CMS Detection | 8 |
| G40 | Deserialization | 6 |
| G41 | Business Logic | 6 |
| G42 | Session Security | 6 |
| G43 | Shell/Reverse | 6 |
| G44 | OAST/Callback | 6 |
| G45 | DDoS Testing | 4 |
| G46 | Stealth Scanning | 6 |
| G47 | Payload Database | 6 |
| G48 | Bounty Workflow | 8 |
| G49 | Bounty Management | 6 |
| G50 | Performance | 6 |
| G51 | Battle/Academy | 6 |
| G52 | HTTP C2 | 4 |
| G53 | Metadata/OPSEC | 6 |
| G54 | Path Traversal | 6 |
| G55 | Web Fuzzer | 6 |

### Group Commands

```
ZYLON > groups           # Enter group scanning mode
  GALL                   # Run ALL groups (428 scans) — PARALLEL
  G1+G2+G5              # Multiple groups — PARALLEL
  G1-S                   # Run group in SERIAL mode (safe, one-by-one)
```

---

## 🎯 Scan Modules

### Core Reconnaissance (0-8)
| # | Module | Description |
|---|---|---|
| 0 | **Full Recon** | OSINT, DNS, Subdomains, Headers, CMS, Cloudflare |
| 1 | **WHOIS** | Domain registration lookup |
| 2 | **Geo-IP** | Server geolocation |
| 3 | **DNS Enum** | A, AAAA, MX, NS, TXT, CNAME, SOA, DMARC |
| 4 | **Subdomain Discovery** | 10 sources: crt.sh, bufferover, rapiddns, etc. |
| 5 | **Port Scanner** | Connect scan (NO ROOT needed) |
| 6 | **Banner Grab** | Service fingerprinting |
| 7 | **Security Headers** | 10 headers scored with recommendations |
| 8 | **SSL/TLS Analysis** | Certificate, protocol, cipher, expiry |

### Vulnerability Scanners (9-12)
| # | Module | Description |
|---|---|---|
| 9 | **SQL Injection** | Error, Time, Boolean-based detection |
| 10 | **XSS Scanner** | Reflected XSS + Template Injection |
| 11 | **Directory Brute** | 1,176+ paths from built-in wordlist |
| 12 | **WordPress Scan** | 12 WP checks + REST API user enum |

### Web Security (13-20)
| # | Module | Description |
|---|---|---|
| 13 | **CORS Detector** | 6 origin tests with risk scoring |
| 14 | **Open Redirect** | 12 params × 6 payloads |
| 15 | **CRLF Injection** | Header injection testing |
| 16 | **Cookie Security** | Secure, HttpOnly, SameSite analysis |
| 17 | **JS Secrets** | API keys, AWS keys, JWTs, DB connections |
| 18 | **Cloud Buckets** | AWS S3, GCS, Azure Blob, DO Spaces |
| 19 | **WAF Detector** | 7 WAF signatures with confidence |
| 20 | **Tech Fingerprint** | 15+ technologies detected |

### Bug Bounty Arsenal (23-41)
| # | Module | Description |
|---|---|---|
| 23 | **Deep Crawler** | Recursive URL, form, API, JS discovery |
| 24 | **Parameter Mining** | Hidden parameter discovery |
| 25 | **Wayback URLs** | Historical URL discovery |
| 26 | **Google Dork** | Automated Google search queries |
| 27 | **GitHub Dork** | Leaked secrets on GitHub |
| 28 | **Deep JS Analysis** | Endpoints, secrets, hidden params |
| 29 | **Subdomain Takeover** | 20+ service takeover detection |
| 30 | **SSRF Scanner** | Server-Side Request Forgery |
| 31 | **SSTI Scanner** | Template Injection |
| 32 | **LFI / Path Traversal** | 20+ payloads |
| 33 | **XXE Scanner** | XML External Entity injection |
| 34 | **IDOR Scanner** | Insecure Direct Object Reference |
| 35 | **Race Condition** | Concurrent request race testing |
| 36 | **Prototype Pollution** | Client & server-side pollution |
| 37 | **Cache Poisoning** | HTTP cache poisoning |
| 38 | **Request Smuggling** | CL.TE / TE.CL smuggling |
| 39 | **Host Header Injection** | Host header manipulation |
| 40 | **JWT Vulnerability** | None algo, weak secret, key confusion |
| 41 | **Broken Auth** | Brute force, default creds, sessions |

### V2 Nuclear Modules (44-49)
| # | Module | Description |
|---|---|---|
| 44 | **API Fuzzer** | REST API endpoint fuzzing |
| 45 | **Rate Limit Test** | API rate limiting analysis |
| 46 | **Sensitive Files** | Exposed .env, .git, config, backups |
| 47 | **Email Enum** | User enumeration |
| 48 | **Broken Links** | Dead link detection |
| 49 | **Tech CVE Lookup** | Version to CVE correlation |

### Origin IP Finder (50-55)
| # | Module | Description |
|---|---|---|
| 50 | **Origin IP Quick** | Fast 8-technique scan |
| 51 | **Origin IP Full** | All 22 techniques |
| 52 | **CDN Detection** | CDN provider identification |
| 53 | **DNS & Cert Hunt** | DNS + crt.sh certificate search |
| 54 | **Subdomain Origin** | Scan subdomains for non-CDN IPs |
| 55 | **IP Verification** | HTTP verification with host header |

### V3 Security Engine (56-75)
| # | Module | Description |
|---|---|---|
| 56-75 | **20 Modules** | GraphQL, DOM XSS, Reverse IP, Zone Transfer, Cache Deception, Clickjacking, CSP, Account Takeover, OAuth, HTTP Method, Shodan, Favicon, Pastebin, URL Shortener, Security.txt, Blind XSS, WebSocket, 2FA Bypass, Mixed Content, Info Disclosure |

### V4 Hunting Engine (76-83)
| # | Module | Description |
|---|---|---|
| 76 | **Username Enum** | Differential error analysis |
| 77 | **Email Security** | DMARC/DKIM/SPF + spoofing risk |
| 78 | **CSRF Detection** | Token detection + login CSRF + PoC |
| 79 | **Framework Detection** | Framework-specific attacks |
| 80 | **JS Library Vulns** | Library version → CVE lookup |
| 81 | **403 Bypass** | 7 bypass categories |
| 82 | **Cross-Domain** | Sibling domain discovery |
| 83 | **CVE-to-Exploit** | NVD + CIRCL API exploitability |

### V5 Async Engine + AI (84-88)
| # | Module | Description |
|---|---|---|
| 84 | **Subdomain Brute Force** | Active DNS + 1,176 wordlist |
| 85 | **Directory Brute (Async)** | Async high-speed with aiohttp |
| 86 | **AI Smart Scan** | Gemini-Guided auto recon |
| 87 | **AI Vuln Triage** | Classify, prioritize, identify false positives |
| 88 | **AI Recon Advisor** | Strategy suggestions based on recon data |

### Mega Scan
| # | Module | Description |
|---|---|---|
| 99 | **MEGA SCAN** | **Every single module combined** |

---

## ⚡ Performance Engine

The V6 Performance Engine addresses the #1 complaint: **"the toolkit is slow"**. Key optimizations:

| Component | Before | After v6.2.0 | Speedup |
|---|---|---|---|
| DNS Resolution | Every lookup is fresh | Thread-safe cache with 5-min TTL | 3-5x |
| HTTP Connections | New connection per request | Connection pool (100 connections) | 2-3x |
| Thread Count | Fixed at 50 | Adaptive 20-200 based on CPU | Variable |
| WAF Handling | No rate limit handling | Smart rate limiter + exponential backoff | Reliable |
| Timeouts | Fixed 10s | Adaptive based on response patterns | Faster |
| Group Scanning | Sequential | Parallel with ThreadPoolExecutor | 2-4x |

### Performance Commands
```
ZYLON > perf     # Show DNS cache stats, thread stats, request counts
ZYLON > aitest   # Test Gemini AI connection and latency
```

---

## 🤖 AI Integration

ZYLON v6.2.0 includes deep Gemini AI integration using `X-goog-api-key` header authentication:

| Command | Description |
|---|---|
| `ai` | Interactive AI security chat |
| `aianalyze` | AI analysis of last scan results |
| `aireport` | AI-generated bug bounty report |
| `aipayload` | AI-generated custom payloads |
| `aitriage` | AI vulnerability classification (Scan 87) |
| `aitest` | Test Gemini API connection |
| Scan 86 | AI Smart Scan — auto recon + AI recommendations |
| Scan 87 | AI Vulnerability Triage — classify & prioritize |
| Scan 88 | AI Recon Advisor — strategy suggestions |

### AI Configuration
```python
# API key is pre-configured in var.py
# Override with config command:
ZYLON > config
# Set: gemini_api_key = YOUR_KEY
```

---

## 📚 Built-in Wordlists

| Wordlist | Entries | Description |
|---|---|---|
| `directories.txt` | 1,176 | Admin panels, APIs, config files, backups, CI/CD, cloud, CMS |
| `subdomains.txt` | 1,176 | Common services, dev/staging, monitoring, databases, cloud |
| `api_paths.txt` | 550 | REST endpoints, auth, admin, health, GraphQL, actuator |
| `file_extensions.txt` | 225 | Backup, config, archive, code, log, cert, database |
| `jwt_secrets.txt` | 224 | Framework defaults, base64 secrets, HMAC keys |
| `lfi_payloads.txt` | 118 | Linux/Windows path traversal payloads |
| `ssrf_payloads.txt` | 116 | Cloud metadata, internal services, protocols |
| `usernames.txt` | 215 | Common usernames for enumeration |
| `passwords.txt` | 165 | Common passwords for brute force |
| **Total** | **3,815** | **9 built-in wordlists** |

---

## 🏗️ Architecture

```
zylon-fusion/
├── zylon.py                    # Main engine + UI (10,900+ lines)
├── core/
│   ├── var.py                  # Constants, payloads, wordlists (730+ lines)
│   ├── performance.py          # V6 Performance Engine - DNS cache, connection pool
│   ├── ai_bridge.py            # Gemini AI integration with X-goog-api-key header
│   ├── recon.py                # Reconnaissance engine
│   ├── vuln.py                 # Vulnerability scanner engine
│   ├── network.py              # Network scanning engine
│   ├── web.py                  # Web security engine
│   ├── reports.py              # HTML/JSON report generator
│   ├── advanced_recon.py       # Deep Crawl, Params, Wayback, Dorks
│   ├── advanced_web.py         # Takeover, SSRF, SSTI, LFI, XXE, IDOR
│   ├── injections.py           # Race, ProtoPollution, Cache, Smuggle
│   ├── bounty_workflow.py      # Bug bounty workflow automation
│   ├── v2_recon.py             # API Fuzzer, Rate Limit, Sensitive Files
│   ├── v2_vuln.py              # Email Enum, Broken Links, Tech CVE
│   ├── origin_ip.py            # Origin IP Finder — 22 techniques
│   ├── v3_security.py          # V3 Security Engine — 20 modules
│   ├── v4_hunting.py           # V4 Hunting Engine — 8 modules
│   ├── v5_async_engine.py      # V5 Async Engine — wordlists + AI smart scan
│   └── [69 more engine files]  # 87 total engines
├── data/wordlists/             # 9 built-in wordlists (3,815+ entries)
├── install_termux.sh           # Termux installer
└── requirements.txt            # Python dependencies
```

**Total Codebase:** 20,000+ lines of Python | 428 Scan Types | 55 Groups | 87 Engines | 9 Built-in Wordlists | Gemini AI | Performance Engine | Thread-Safe Parallel Scanning

---

## 🔀 Branches

| Branch | Version | Description |
|---|---|---|
| `main` | v6.2.0 | **ZYLON FUSION ULTIMATE** — Classic numbered menu (you are here) |
| `experimental/ai-powered` | v7.0.0-ai | 🎸 **ROCKER** — AI-Powered Chat Pentesting |
| `experimental/phone-farm` | v6.2.0 | Phone Farm (coming soon) |
| `experimental/stealth-ops` | v6.2.0 | Stealth Operations (coming soon) |
| `experimental/api-hunter` | v6.2.0 | API Hunter (coming soon) |
| `experimental/auto-exploit` | v6.2.0 | Auto Exploit (coming soon) |
| `experimental/mass-scale` | v6.2.0 | Mass Scale (coming soon) |

---

## 🔑 Termux Non-Root Compatibility

| Feature | PC Tools | ZYLON FUSION |
|---|---|---|
| Port Scanning | SYN scan (root) | Connect scan (no root) |
| Subdomain Enum | Binary tools | API-based (10 sources) + 1,176 wordlist |
| Directory Brute | External wordlists | Built-in 1,176 wordlist |
| AI Analysis | Manual | Built-in Gemini AI |
| Performance | No optimization | DNS cache + connection pool + adaptive threads |
| Group Scanning | Sequential | Parallel with ThreadPoolExecutor |
| Installation | apt-get + sudo | pkg (Termux native) |

---

## 📊 Comparison

| Feature | omino | wizard | ZYLON FUSION v6.2.0 |
|---|---|---|---|
| Language | Bash | Python 3 | Python 3 |
| Root Required | Yes | No | **No** |
| Termux Compatible | No | Partial | **Full** |
| Scan Types | ~10 | ~5 | **428** |
| Scan Groups | 0 | 0 | **55** |
| Engine Files | 0 | 1 | **87** |
| Built-in Wordlists | 0 | 0 | **9 (3,815 entries)** |
| AI Integration | No | No | **Gemini AI** |
| Performance Engine | No | No | **DNS Cache + Pooling** |
| Thread Safety | No | No | **Full** |
| Origin IP Finder | 0 | 0 | **22 techniques** |
| Parallel Groups | No | No | **55 groups parallel** |

---

## ⚖️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Always obtain proper authorization before scanning any target. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

---

<div align="center">

**Built by Zylon**

*omino + wizard + Zylon Custom + V2 Nuclear + Origin IP + V3 Security + V4 Hunting + V5 Async + V6 Performance + Gemini AI = ZYLON FUSION v6.2.0 ULTIMATE*

</div>
