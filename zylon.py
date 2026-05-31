#!/usr/bin/env python3
"""
 ███████╗██╗██████╗  ██████╗ ███████╗
 ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
   ███╔╝ ██║██████╔╝██║   ██║███████╗
  ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
 ███████╗██║██║     ╚██████╔╝███████║
 ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝

 ZYLON FUSION v2.0 - Advanced Security Reconnaissance & Vulnerability Platform
 Fused from omino + wizard + custom Zylon techniques + V2.0 Nuclear Modules
 Termux Non-Root Compatible | AI-Ready Architecture

 Coded by: Zylon | Hackathon Edition
 License: MIT
"""

import os
import sys
import time
import json
import socket
import random
import threading
import signal
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================================
# DETECT TERMUX ENVIRONMENT
# ============================================================================

def is_termux():
    """Detect if running in Termux"""
    return os.path.exists('/data/data/com.termux')

def get_prefix():
    """Get the appropriate prefix path"""
    if is_termux():
        return '/data/data/com.termux/files/usr'
    return '/usr'

def get_home():
    """Get home directory"""
    return os.environ.get('HOME', os.path.expanduser('~'))

# ============================================================================
# AUTO-INSTALL DEPENDENCIES (TERMUX-AWARE)
# ============================================================================

def install_requirements():
    """Auto-install required packages with Termux awareness"""
    required = {
        'requests': 'requests',
        'rich': 'rich',
        'colorama': 'colorama',
        'beautifulsoup4': 'bs4',
        'dnspython': 'dns',
        'whois': 'whois',
        'lxml': 'lxml',
        'cryptography': 'cryptography',
        'aiohttp': 'aiohttp',
    }
    
    missing = []
    for package, module in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[*] Installing missing packages: {', '.join(missing)}")
        pip_cmd = 'pip3' if os.system('which pip3 > /dev/null 2>&1') == 0 else 'pip'
        for package in missing:
            os.system(f"{pip_cmd} install {package} --quiet 2>/dev/null")
        print("[+] All packages installed!\n")
        time.sleep(1)

# Install on first run
install_requirements()

# ============================================================================
# THIRD-PARTY IMPORTS
# ============================================================================

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from colorama import Fore, Back, Style, init as colorama_init
from bs4 import BeautifulSoup
import dns.resolver
from urllib.parse import urlparse, urljoin, parse_qs

# Optional imports with graceful fallback
try:
    import whois as pythonwhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import ssl
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False

try:
    import aiohttp
    import asyncio
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# Initialize colorama
colorama_init(autoreset=True)
console = Console()

# ============================================================================
# IMPORT ZYLON MODULES
# ============================================================================

from core.var import *
from core.recon import ReconEngine
from core.vuln import VulnEngine
from core.network import NetworkEngine
from core.web import WebEngine
from core.reports import ReportEngine
from core.ai_bridge import AIBridge
from core.advanced_recon import AdvancedRecon
from core.injections import InjectionArsenal
from core.advanced_web import AdvancedWebAttacks
from core.bounty_workflow import BugBountyWorkflow
from core.v2_recon import V2ReconEngine
from core.v2_vuln import V2VulnEngine
from core.origin_ip import OriginIPEngine
from core.v3_security import V3SecurityEngine
from core.v4_hunting import V4HuntingEngine
from core.v5_async_engine import V5AsyncEngine
from core.performance import (
    dns_cache, optimized_session, adaptive_threads,
    rate_limiter, smart_timeout, parallel_scanner,
    get_performance_stats
)

# ============================================================================
# SIGNAL HANDLER
# ============================================================================

def signal_handler(sig, frame):
    console.print("\n[bold yellow][!] ZYLON shutting down gracefully...[/bold yellow]")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ============================================================================
# BANNER & UI
# ============================================================================

class ZylonUI:
    """ZYLON terminal UI engine"""
    
    @staticmethod
    def display_banner():
        """Display the ZYLON fusion banner"""
        console.clear()
        
        # Animated intro
        with console.status("[bold red]Initializing ZYLON FUSION...[/bold red]", spinner="dots"):
            time.sleep(0.8)
        
        banner = f"""
[bold red]
    ███████╗██╗██████╗  ██████╗ ███████╗
    ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
      ███╔╝ ██║██████╔╝██║   ██║███████╗
     ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
    ███████╗██║██║     ╚██████╔╝███████║
    ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝
[/bold red]
[bold yellow]    FUSION v2.3 NUCLEAR - Advanced Security & Bug Bounty Platform[/bold yellow]
[bold cyan]    omino + wizard + Zylon Custom + V2 Nuclear + V4 Hunting + V5 Async + V6 Perf | Gemini AI | Termux Non-Root[/bold cyan]
"""
        console.print(Panel(banner, border_style="bright_red", box=box.HEAVY))
        
        # Info table
        info = Table(box=box.ROUNDED, border_style="bright_yellow", show_header=False,
                     title="[bold yellow] System Info[/bold yellow]")
        info.add_column("Key", style="cyan")
        info.add_column("Value", style="green")
        info.add_row(" Version", ZYLON_VERSION)
        info.add_row(" Codename", ZYLON_CODENAME)
        info.add_row(" Environment", "Termux" if is_termux() else f"{platform.system()} {platform.release()}")
        info.add_row(" Python", platform.python_version())
        info.add_row(" Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            is_root = False
        info.add_row(" Root Access", "No (Non-Root Mode)" if not is_root else "Yes")
        console.print(info)
        console.print()
    
    @staticmethod
    def display_help():
        """Display help menu"""
        help_table = Table(
            title="[bold yellow] ZYLON FUSION - Commands & Scan Types[/bold yellow]",
            box=box.DOUBLE, border_style="bright_magenta"
        )
        help_table.add_column("Command", style="bold cyan")
        help_table.add_column("Description", style="white")
        
        commands = [
            ("help", "Show this help menu"),
            ("0", "Full Reconnaissance (OSINT + DNS + Subdomains + Headers)"),
            ("1", "WHOIS Domain Lookup"),
            ("2", "Geo-IP Location"),
            ("3", "DNS Records Enumeration"),
            ("4", "Subdomain Discovery (Multi-Source)"),
            ("5", "Port Scanner (Connect Scan - No Root)"),
            ("6", "Banner Grabbing & Fingerprinting"),
            ("7", "HTTP Security Headers Analysis"),
            ("8", "SSL/TLS Certificate Analysis"),
            ("9", "SQL Injection Scanner"),
            ("10", "XSS (Cross-Site Scripting) Scanner"),
            ("11", "Directory & File Brute Force"),
            ("12", "WordPress Security Scan"),
            ("13", "CORS Misconfiguration Detector"),
            ("14", "Open Redirect Detector"),
            ("15", "CRLF Injection Scanner"),
            ("16", "Cookie Security Analyzer"),
            ("17", "JavaScript Sensitive Data Extractor"),
            ("18", "Cloud Storage Bucket Detector"),
            ("19", "WAF Detector & Fingerprinter"),
            ("20", "Technology Stack Fingerprinter"),
            ("21", "Full Vulnerability Assessment"),
            ("22", "Nuclear Scan (Core Modules)"),
            # === BUG BOUNTY ARSENAL ===
            ("23", "Deep Web Crawler (URL Discovery)"),
            ("24", "Parameter Miner (Hidden Params)"),
            ("25", "Wayback URL Discovery"),
            ("26", "Google Dorking"),
            ("27", "GitHub Secret Dorking"),
            ("28", "Deep JS Analysis"),
            ("29", "Subdomain Takeover Check"),
            ("30", "SSRF Scanner"),
            ("31", "SSTI (Template Injection) Scanner"),
            ("32", "Path Traversal / LFI Scanner"),
            ("33", "XXE (XML Entity) Scanner"),
            ("34", "IDOR Detector"),
            ("35", "Race Condition Tester"),
            ("36", "Prototype Pollution Scanner"),
            ("37", "Web Cache Poisoning"),
            ("38", "HTTP Request Smuggling"),
            ("39", "Host Header Injection"),
            ("40", "JWT Vulnerability Scanner"),
            ("41", "Broken Authentication Detector"),
            # V2.0 Nuclear Modules
            ("44", "API Endpoint Discovery + Fuzzer"),
            ("45", "Rate Limit Tester"),
            ("46", "Sensitive File Deep Scanner"),
            ("47", "Email Enumeration"),
            ("48", "Broken Link Hijacker"),
            ("49", "Tech Version + CVE Lookup"),
            # Origin IP Finder
            ("50", "Origin IP Finder (Quick - Top Techniques)"),
            ("51", "Origin IP Finder (Full - All 22 Techniques)"),
            ("52", "CDN/WAF Detection & Fingerprinting"),
            ("53", "DNS History + Cert Transparency IP Hunt"),
            ("54", "Subdomain Resolution + CDN IP Filter"),
            ("55", "Direct IP Verification (Host Header)"),
            ("42", "Bug Bounty Full Recon Pipeline"),
            ("43", "Bug Bounty Full Vuln Pipeline"),
            # V4.0 Hunting Modules
            ("76", "Username Enumeration Scanner"),
            ("77", "DMARC/DKIM/SPF Email Security Checker"),
            ("78", "CSRF Token Detection & Login CSRF Tester"),
            ("79", "Framework Detection + Specific Attacks"),
            ("80", "Client-Side JS Library Vulnerability Scanner"),
            ("81", "403 Bypass Tester"),
            ("82", "Cross-Domain Discovery"),
            ("83", "CVE-to-Exploit Lookup Engine"),
            # V5.0 Async Engine Modules
            ("84", "Subdomain Brute Force (Active DNS + Wordlist)"),
            ("85", "Directory Brute Force (Async High-Speed)"),
            ("86", "AI Smart Scan (Gemini-Guided Auto Recon)"),
            ("87", "AI Vulnerability Triage (Classify & Prioritize)"),
            ("88", "AI Recon Advisor (Strategy Suggestions)"),
            ("99", "MEGA SCAN (Every Single Module)"),
            ("ai", "AI Chat (Gemini-Powered Security Assistant)"),
            ("aianalyze", "AI Analyze Last Scan Results"),
            ("aireport", "AI Generate Bug Bounty Report"),
            ("aipayload", "AI Generate Custom Payloads"),
            ("aitriage", "AI Triage Findings (Prioritize & Classify)"),
            ("aitest", "AI Test Connection to Gemini API"),
            ("smart", "AI Smart Scan (Quick Recon + AI Recommendations)"),
            ("wordlists", "Show Built-in Wordlist Stats"),
            ("scope", "Set/Check Bug Bounty Scope"),
            ("poc", "Generate PoC for Last Finding"),
            ("config", "Configuration Manager (API Keys)"),
            ("report", "View/Export Previous Scan Reports"),
            ("perf", "Performance Stats (DNS Cache, Threads, Speed)"),
            ("update", "Check for Updates"),
            ("fix", "Install Missing Dependencies"),
            ("exit/quit/q", "Exit ZYLON FUSION"),
        ]
        for cmd, desc in commands:
            help_table.add_row(cmd, desc)
        
        console.print(help_table)
    
    @staticmethod
    def display_scan_progress(module_name, target):
        """Display scanning progress indicator"""
        return console.status(
            f"[bold cyan][*] Running {module_name} on {target}...[/bold cyan]",
            spinner="dots"
        )
    
    @staticmethod
    def display_result_table(title, columns, rows):
        """Display results in a formatted table"""
        table = Table(
            title=f"[bold yellow]{title}[/bold yellow]",
            box=box.ROUNDED, border_style="bright_magenta"
        )
        for col in columns:
            table.add_column(col, style="cyan")
        for row in rows:
            table.add_row(*[str(item) for item in row])
        console.print(table)


# ============================================================================
# ZYLON FUSION MAIN ENGINE
# ============================================================================

class ZylonFusion:
    """ZYLON FUSION - Main Engine combining omino + wizard + custom techniques"""
    
    def __init__(self):
        self.version = ZYLON_VERSION
        self.target = None
        self.parsed_target = None
        self.protocol = "https://"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS)
        })
        self.session.verify = False
        self.results = {}
        self.scan_history = []
        
        # Initialize sub-engines
        self.recon = ReconEngine(self.session)
        self.vuln = VulnEngine(self.session)
        self.network = NetworkEngine(self.session)
        self.web = WebEngine(self.session)
        self.reports = ReportEngine()
        self.ai = AIBridge()
        self.ui = ZylonUI()
        
        # Bug Bounty Arsenal engines
        self.adv_recon = AdvancedRecon(self.session)
        self.injections = InjectionArsenal(self.session)
        self.adv_web = AdvancedWebAttacks(self.session)
        self.bounty = BugBountyWorkflow()
        
        # V2.0 Engines
        self.v2_recon = V2ReconEngine(self.session)
        self.v2_vuln = V2VulnEngine(self.session)
        
        # Origin IP Finder Engine
        self.origin_ip = OriginIPEngine(self.session)

        # V3.0 Security Engine (20 New Modules)
        self.v3_security = V3SecurityEngine(self.session)

        # V4.0 Hunting Engine (8 New Modules)
        self.v4_hunting = V4HuntingEngine(self.session)

        # V5.0 Async Engine (High-Performance + Wordlists + AI Smart Scan)
        self.v5_async = V5AsyncEngine(self.session)

        # Initialize Gemini API key (hardcoded default + config file)
        self._init_gemini()

        # Performance Engine
        self.dns_cache = dns_cache
        self.perf_session = optimized_session
        self.adaptive_threads = adaptive_threads
        self.rate_limiter = rate_limiter

    def _init_gemini(self):
        """Initialize Gemini API key - hardcoded default, env var overrides"""
        # Use hardcoded key from var.py as default
        if GEMINI_API_KEY:
            self.ai.set_gemini_key(GEMINI_API_KEY)

        # Environment variable can override
        env_key = os.environ.get('GEMINI_API_KEY', '')
        if env_key:
            self.ai.set_gemini_key(env_key)
    
    def set_target(self, target):
        """Validate and set target"""
        target = target.strip()
        # Remove protocol if user included it
        if '://' in target:
            target = target.split('://', 1)[1]
        target = target.rstrip('/')
        
        if '.' not in target:
            return False, "Invalid target - must contain a domain or IP"
        
        self.target = target
        self.parsed_target = urlparse(f"https://{target}")
        return True, f"Target set: {target}"
    
    def run_scan(self, scan_type):
        """Run a specific scan type"""
        if not self.target:
            console.print("[bold red][!] No target set![/bold red]")
            return
        
        self.results = {'target': self.target, 'scan_type': scan_type, 
                       'timestamp': datetime.now().isoformat(), 'findings': {}}
        
        scan_map = {
            '0': self._scan_full_recon,
            '1': self._scan_whois,
            '2': self._scan_geoip,
            '3': self._scan_dns,
            '4': self._scan_subdomains,
            '5': self._scan_ports,
            '6': self._scan_banners,
            '7': self._scan_headers,
            '8': self._scan_ssl,
            '9': self._scan_sqli,
            '10': self._scan_xss,
            '11': self._scan_dirbrute,
            '12': self._scan_wordpress,
            '13': self._scan_cors,
            '14': self._scan_openredirect,
            '15': self._scan_crlf,
            '16': self._scan_cookies,
            '17': self._scan_javascript,
            '18': self._scan_cloudbuckets,
            '19': self._scan_waf,
            '20': self._scan_techstack,
            '21': self._scan_fullvuln,
            '22': self._scan_nuclear,
            # Bug Bounty Arsenal
            '23': self._scan_deep_crawl,
            '24': self._scan_param_mining,
            '25': self._scan_wayback,
            '26': self._scan_google_dork,
            '27': self._scan_github_dork,
            '28': self._scan_deep_js,
            '29': self._scan_takeover,
            '30': self._scan_ssrf,
            '31': self._scan_ssti,
            '32': self._scan_lfi,
            '33': self._scan_xxe,
            '34': self._scan_idor,
            '35': self._scan_race,
            '36': self._scan_proto_pollution,
            '37': self._scan_cache_poison,
            '38': self._scan_smuggling,
            '39': self._scan_host_header,
            '40': self._scan_jwt,
            '41': self._scan_broken_auth,
            # V2.0 Nuclear Modules
            '44': self._scan_api_fuzzer,
            '45': self._scan_rate_limit,
            '46': self._scan_sensitive_files,
            '47': self._scan_email_enum,
            '48': self._scan_broken_links,
            '49': self._scan_tech_cve,
            # Origin IP Finder
            '50': self._scan_origin_ip_quick,
            '51': self._scan_origin_ip_full,
            '52': self._scan_cdn_detection,
            '53': self._scan_dns_cert_hunt,
            '54': self._scan_subdomain_origin,
            '55': self._scan_ip_verify,
            '42': self._scan_bounty_recon,
            '43': self._scan_bounty_vuln,
            # V3.0 Security Modules (56-75)
            '56': self._scan_graphql,
            '57': self._scan_dom_xss,
            '58': self._scan_reverse_ip,
            '59': self._scan_dns_zone_transfer,
            '60': self._scan_cache_deception,
            '61': self._scan_clickjacking,
            '62': self._scan_csp,
            '63': self._scan_account_takeover,
            '64': self._scan_oauth,
            '65': self._scan_http_method,
            '66': self._scan_shodan_internetdb,
            '67': self._scan_favicon_hash,
            '68': self._scan_pastebin_dork,
            '69': self._scan_url_shortener,
            '70': self._scan_security_robots,
            '71': self._scan_blind_xss,
            '72': self._scan_websocket,
            '73': self._scan_2fa_bypass,
            '74': self._scan_mixed_content,
            '75': self._scan_info_disclosure,
            # V4.0 Hunting Modules (76-83)
            '76': self._scan_username_enum,
            '77': self._scan_email_security,
            '78': self._scan_csrf,
            '79': self._scan_framework,
            '80': self._scan_js_libraries,
            '81': self._scan_403_bypass,
            '82': self._scan_cross_domain,
            '83': self._scan_cve_lookup,
            # V5.0 Async Engine Modules (84-86)
            '84': self._scan_subdomain_brute,
            '85': self._scan_dir_brute_async,
            '86': self._scan_smart,
            '87': self._scan_ai_triage,
            '88': self._scan_ai_recon_advisor,
            '99': self._scan_mega,
        }
        
        scan_func = scan_map.get(scan_type)
        if scan_func:
            try:
                scan_func()
                # Auto-save results
                self.reports.save_json(self.results, self.target)
                console.print(f"\n[bold green][+] Scan complete! Results saved.[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] Scan error: {str(e)}[/bold red]")
        else:
            console.print(f"[bold red][!] Unknown scan type: {scan_type}[/bold red]")
    
    # ========================================================================
    # SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_full_recon(self):
        """Full Reconnaissance - omino's recon + wizard's basic recon combined"""
        console.print(f"\n[bold cyan][*] Full Reconnaissance on {self.target}[/bold cyan]")
        
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Gathering intelligence...[/bold cyan]"):
            # Phase 1: Basic info
            title = self.recon.get_title(url)
            ip = self.network.resolve_ip(self.target)
            geo = self.network.get_geolocation(ip) if ip else None
            cms = self.recon.detect_cms(url)
            cloudflare = self.recon.check_cloudflare(ip, url) if ip else False
            robots = self.recon.analyze_robots(url)
            headers = self.web.analyze_security_headers(url)
            dns_records = self.network.dns_lookup(self.target)
            
        self.results['findings']['recon'] = {
            'title': title,
            'ip': ip,
            'geolocation': geo,
            'cms': cms,
            'cloudflare': cloudflare,
            'robots_txt': robots,
            'security_headers': headers,
            'dns_records': dns_records
        }
        
        # Display results
        recon_table = Table(title=f"[bold]Reconnaissance Results: {self.target}[/bold]",
                          box=box.ROUNDED, border_style="bright_cyan")
        recon_table.add_column("Property", style="yellow")
        recon_table.add_column("Value", style="green")
        
        recon_table.add_row("Page Title", str(title))
        recon_table.add_row("IP Address", str(ip))
        recon_table.add_row("CMS", str(cms))
        recon_table.add_row("Cloudflare", "Yes" if cloudflare else "No")
        if geo:
            recon_table.add_row("Country", geo.get('country', 'Unknown'))
            recon_table.add_row("City", geo.get('city', 'Unknown'))
            recon_table.add_row("ISP", geo.get('isp', 'Unknown'))
        
        console.print(recon_table)
        
        # DNS Records
        if dns_records and 'error' not in dns_records:
            dns_table = Table(title="DNS Records", box=box.ROUNDED, border_style="cyan")
            dns_table.add_column("Type", style="yellow")
            dns_table.add_column("Value", style="green")
            for rtype, values in dns_records.items():
                if isinstance(values, list):
                    for val in values[:5]:
                        dns_table.add_row(rtype, val)
            console.print(dns_table)
        
        # Security Headers
        if headers:
            h_table = Table(title="Security Headers", box=box.ROUNDED, border_style="red")
            h_table.add_column("Header", style="yellow")
            h_table.add_column("Status", style="green")
            h_table.add_column("Score Impact", style="red")
            for hname, hval in headers.get('security_headers', {}).items():
                status = "Present" if hval.get('value') != 'Missing' else "Missing"
                impact = f"-{hval.get('weight', 0)}pts"
                h_table.add_row(hname, status, impact)
            console.print(h_table)
            console.print(f"[bold yellow]Security Header Score: {headers.get('security_score', 0)}/100[/bold yellow]")
    
    def _scan_whois(self):
        """WHOIS Domain Lookup"""
        console.print(f"\n[bold cyan][*] WHOIS Lookup on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Querying WHOIS records...[/bold cyan]"):
            result = self.recon.whois_lookup(self.target)
        
        self.results['findings']['whois'] = result
        
        if result and 'error' not in result:
            w_table = Table(title="WHOIS Information", box=box.ROUNDED, border_style="cyan")
            w_table.add_column("Field", style="yellow")
            w_table.add_column("Value", style="green")
            for key, val in result.items():
                if val and key not in ['raw']:
                    w_table.add_row(key, str(val)[:80])
            console.print(w_table)
        else:
            console.print(f"[bold yellow][!] WHOIS lookup failed: {result.get('error', 'Unknown error')}[/bold yellow]")
    
    def _scan_geoip(self):
        """Geo-IP Location"""
        console.print(f"\n[bold cyan][*] Geo-IP Lookup on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Locating server...[/bold cyan]"):
            ip = self.network.resolve_ip(self.target)
            geo = self.network.get_geolocation(ip) if ip else None
        
        self.results['findings']['geoip'] = {'ip': ip, 'geo': geo}
        
        if geo:
            g_table = Table(title="Geo-IP Information", box=box.ROUNDED, border_style="green")
            g_table.add_column("Property", style="yellow")
            g_table.add_column("Value", style="green")
            g_table.add_row("IP", str(ip))
            g_table.add_row("Country", geo.get('country', 'Unknown'))
            g_table.add_row("City", geo.get('city', 'Unknown'))
            g_table.add_row("Region", geo.get('regionName', 'Unknown'))
            g_table.add_row("ISP", geo.get('isp', 'Unknown'))
            g_table.add_row("Organization", geo.get('org', 'Unknown'))
            g_table.add_row("Latitude", str(geo.get('lat', 'N/A')))
            g_table.add_row("Longitude", str(geo.get('lon', 'N/A')))
            g_table.add_row("Timezone", geo.get('timezone', 'Unknown'))
            console.print(g_table)
        else:
            console.print("[bold red][!] Geo-IP lookup failed[/bold red]")
    
    def _scan_dns(self):
        """DNS Records Enumeration"""
        console.print(f"\n[bold cyan][*] DNS Enumeration on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Querying DNS records...[/bold cyan]"):
            dns_records = self.network.dns_lookup(self.target)
        
        self.results['findings']['dns'] = dns_records
        
        if dns_records and 'error' not in dns_records:
            d_table = Table(title="DNS Records", box=box.DOUBLE, border_style="bright_cyan")
            d_table.add_column("Type", style="bold yellow")
            d_table.add_column("Value", style="green")
            for rtype, values in dns_records.items():
                if isinstance(values, list):
                    for val in values:
                        d_table.add_row(rtype, val)
            console.print(d_table)
    
    def _scan_subdomains(self):
        """Multi-Source Subdomain Discovery"""
        console.print(f"\n[bold cyan][*] Subdomain Discovery on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Discovering subdomains (crt.sh, dns.bufferover.run, rapiddns)...[/bold cyan]"):
            subdomains = self.recon.discover_subdomains(self.target)
        
        self.results['findings']['subdomains'] = subdomains
        
        if subdomains:
            s_table = Table(title=f"Subdomains Found: {len(subdomains)}", box=box.ROUNDED, border_style="green")
            s_table.add_column("#", style="dim")
            s_table.add_column("Subdomain", style="cyan")
            s_table.add_column("Source", style="yellow")
            for i, sub in enumerate(sorted(subdomains)[:100], 1):
                source = subdomains[sub] if isinstance(subdomains, dict) else 'multi'
                s_table.add_row(str(i), sub, str(source))
            console.print(s_table)
            if len(subdomains) > 100:
                console.print(f"[yellow]... and {len(subdomains) - 100} more subdomains[/yellow]")
        else:
            console.print("[bold yellow][!] No subdomains found[/bold yellow]")
    
    def _scan_ports(self):
        """Port Scanner - Connect Scan (No Root Required)"""
        console.print(f"\n[bold cyan][*] Port Scanning {self.target}[/bold cyan]")
        
        ip = self.network.resolve_ip(self.target)
        if not ip:
            console.print("[bold red][!] Cannot resolve target[/bold red]")
            return
        
        with console.status("[bold cyan]Scanning ports (connect scan - no root needed)...[/bold cyan]"):
            open_ports = self.network.port_scan(ip)
        
        self.results['findings']['ports'] = open_ports
        
        if open_ports:
            p_table = Table(title=f"Open Ports: {len(open_ports)}", box=box.ROUNDED, border_style="red")
            p_table.add_column("Port", style="bold red")
            p_table.add_column("Service", style="cyan")
            p_table.add_column("State", style="green")
            for port, info in sorted(open_ports.items()):
                p_table.add_row(str(port), info.get('service', 'unknown'), 'open')
            console.print(p_table)
        else:
            console.print("[bold yellow][!] No open ports found (target may be firewalled)[/bold yellow]")
    
    def _scan_banners(self):
        """Banner Grabbing"""
        console.print(f"\n[bold cyan][*] Banner Grabbing on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Grabbing banners...[/bold cyan]"):
            banners = self.network.banner_grab(self.target)
        
        self.results['findings']['banners'] = banners
        
        if banners:
            b_table = Table(title="Service Banners", box=box.ROUNDED, border_style="cyan")
            b_table.add_column("Port", style="yellow")
            b_table.add_column("Banner", style="green")
            for port, banner in banners.items():
                b_table.add_row(str(port), str(banner)[:100])
            console.print(b_table)
    
    def _scan_headers(self):
        """HTTP Security Headers Analysis"""
        console.print(f"\n[bold cyan][*] Security Headers Analysis on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Analyzing HTTP headers...[/bold cyan]"):
            result = self.web.analyze_security_headers(url)
        
        self.results['findings']['headers'] = result
        
        if result:
            h_table = Table(title="Security Headers Analysis", box=box.DOUBLE, border_style="red")
            h_table.add_column("Header", style="yellow")
            h_table.add_column("Status", style="bold")
            h_table.add_column("Value/Recommendation", style="cyan")
            for hname, hval in result.get('security_headers', {}).items():
                status = "[green]Present[/green]" if hval.get('value') != 'Missing' else "[red]Missing[/red]"
                val = str(hval.get('value', ''))[:60] if hval.get('value') != 'Missing' else hval.get('recommended', '')
                h_table.add_row(hname, status, val)
            console.print(h_table)
            console.print(f"\n[bold]Security Header Score: [yellow]{result.get('security_score', 0)}/100[/yellow][/bold]")
            
            recs = result.get('recommendations', [])
            if recs:
                console.print("\n[bold red]Recommendations:[/bold red]")
                for rec in recs:
                    console.print(f"  [red]*[/red] {rec}")
    
    def _scan_ssl(self):
        """SSL/TLS Certificate Analysis"""
        console.print(f"\n[bold cyan][*] SSL/TLS Analysis on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Analyzing SSL certificate...[/bold cyan]"):
            result = self.network.ssl_analyze(self.target)
        
        self.results['findings']['ssl'] = result
        
        if result:
            s_table = Table(title="SSL/TLS Analysis", box=box.ROUNDED, border_style="green")
            s_table.add_column("Property", style="yellow")
            s_table.add_column("Value", style="green")
            for key, val in result.items():
                if key != 'raw_cert':
                    s_table.add_row(key, str(val)[:80])
            console.print(s_table)
            
            if result.get('issues'):
                console.print("\n[bold red]SSL Issues Found:[/bold red]")
                for issue in result['issues']:
                    console.print(f"  [red]*[/red] {issue}")
    
    def _scan_sqli(self):
        """SQL Injection Scanner"""
        console.print(f"\n[bold cyan][*] SQL Injection Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for SQL injection vulnerabilities...[/bold cyan]"):
            result = self.vuln.scan_sqli(url)
        
        self.results['findings']['sqli'] = result
        
        if result and result.get('vulnerable'):
            v_table = Table(title="SQL Injection Vulnerabilities Found!", box=box.HEAVY, border_style="bold red")
            v_table.add_column("URL", style="red")
            v_table.add_column("Parameter", style="yellow")
            v_table.add_column("Payload", style="cyan")
            v_table.add_column("Evidence", style="green")
            for finding in result.get('findings', []):
                v_table.add_row(
                    finding.get('url', '')[:50],
                    finding.get('parameter', ''),
                    finding.get('payload', '')[:40],
                    finding.get('evidence', '')[:40]
                )
            console.print(v_table)
        else:
            console.print("[bold green][+] No SQL injection vulnerabilities detected[/bold green]")
    
    def _scan_xss(self):
        """XSS Scanner"""
        console.print(f"\n[bold cyan][*] XSS Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for XSS vulnerabilities...[/bold cyan]"):
            result = self.vuln.scan_xss(url)
        
        self.results['findings']['xss'] = result
        
        if result and result.get('vulnerable'):
            x_table = Table(title="XSS Vulnerabilities Found!", box=box.HEAVY, border_style="bold red")
            x_table.add_column("URL", style="red")
            x_table.add_column("Parameter", style="yellow")
            x_table.add_column("Payload", style="cyan")
            for finding in result.get('findings', []):
                x_table.add_row(
                    finding.get('url', '')[:50],
                    finding.get('parameter', ''),
                    finding.get('payload', '')[:40]
                )
            console.print(x_table)
        else:
            console.print("[bold green][+] No XSS vulnerabilities detected[/bold green]")
    
    def _scan_dirbrute(self):
        """Directory Brute Force"""
        console.print(f"\n[bold cyan][*] Directory Brute Force on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Brute forcing directories...[/bold cyan]"):
            result = self.web.directory_bruteforce(url)
        
        self.results['findings']['directories'] = result
        
        if result:
            d_table = Table(title=f"Discovered Paths: {len(result)}", box=box.ROUNDED, border_style="cyan")
            d_table.add_column("Path", style="yellow")
            d_table.add_column("Status", style="green")
            d_table.add_column("Size", style="cyan")
            for path, info in sorted(result.items()):
                status_color = "green" if info.get('status') == 200 else "yellow" if info.get('status') in [301, 302, 403] else "red"
                d_table.add_row(path, f"[{status_color}]{info.get('status')}[/{status_color}]", str(info.get('size', '')))
            console.print(d_table)
    
    def _scan_wordpress(self):
        """WordPress Security Scan"""
        console.print(f"\n[bold cyan][*] WordPress Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Scanning WordPress installation...[/bold cyan]"):
            result = self.vuln.scan_wordpress(url)
        
        self.results['findings']['wordpress'] = result
        
        if result:
            w_table = Table(title="WordPress Scan Results", box=box.ROUNDED, border_style="cyan")
            w_table.add_column("Check", style="yellow")
            w_table.add_column("Result", style="green")
            for check, val in result.items():
                w_table.add_row(check, str(val)[:80])
            console.print(w_table)
    
    def _scan_cors(self):
        """CORS Misconfiguration Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] CORS Misconfiguration Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing CORS configurations...[/bold cyan]"):
            result = self.vuln.scan_cors(url)
        
        self.results['findings']['cors'] = result
        
        if result and result.get('misconfigured'):
            console.print("[bold red][!] CORS Misconfiguration Detected![/bold red]")
            c_table = Table(title="CORS Issues", box=box.HEAVY, border_style="red")
            c_table.add_column("Origin", style="yellow")
            c_table.add_column("ACAO Header", style="cyan")
            c_table.add_column("Risk", style="red")
            for finding in result.get('findings', []):
                c_table.add_row(
                    finding.get('origin', ''),
                    finding.get('acao', ''),
                    finding.get('risk', '')
                )
            console.print(c_table)
        else:
            console.print("[bold green][+] CORS configuration appears secure[/bold green]")
    
    def _scan_openredirect(self):
        """Open Redirect Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Open Redirect Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for open redirects...[/bold cyan]"):
            result = self.vuln.scan_open_redirect(url)
        
        self.results['findings']['open_redirect'] = result
        
        if result and result.get('vulnerable'):
            console.print("[bold red][!] Open Redirect Vulnerability Detected![/bold red]")
            for finding in result.get('findings', []):
                console.print(f"  [red]*[/red] URL: {finding.get('url', '')}")
                console.print(f"  [red]*[/red] Redirects to: {finding.get('redirects_to', '')}")
        else:
            console.print("[bold green][+] No open redirect vulnerabilities detected[/bold green]")
    
    def _scan_crlf(self):
        """CRLF Injection Scanner - Zylon Custom"""
        console.print(f"\n[bold cyan][*] CRLF Injection Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for CRLF injection...[/bold cyan]"):
            result = self.vuln.scan_crlf(url)
        
        self.results['findings']['crlf'] = result
        
        if result and result.get('vulnerable'):
            console.print("[bold red][!] CRLF Injection Detected![/bold red]")
            for finding in result.get('findings', []):
                console.print(f"  [red]*[/red] URL: {finding.get('url', '')}")
        else:
            console.print("[bold green][+] No CRLF injection vulnerabilities detected[/bold green]")
    
    def _scan_cookies(self):
        """Cookie Security Analyzer - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Cookie Security Analysis on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Analyzing cookie security...[/bold cyan]"):
            result = self.web.analyze_cookies(url)
        
        self.results['findings']['cookies'] = result
        
        if result:
            c_table = Table(title="Cookie Analysis", box=box.ROUNDED, border_style="yellow")
            c_table.add_column("Cookie", style="yellow")
            c_table.add_column("Secure", style="green")
            c_table.add_column("HttpOnly", style="green")
            c_table.add_column("SameSite", style="green")
            c_table.add_column("Issues", style="red")
            for cookie, info in result.items():
                issues = ', '.join(info.get('issues', []))
                c_table.add_row(
                    cookie,
                    "Yes" if info.get('secure') else "[red]No[/red]",
                    "Yes" if info.get('httponly') else "[red]No[/red]",
                    info.get('samesite', 'N/A'),
                    issues if issues else "None"
                )
            console.print(c_table)
    
    def _scan_javascript(self):
        """JavaScript Sensitive Data Extractor - Zylon Custom"""
        console.print(f"\n[bold cyan][*] JavaScript Sensitive Data Extraction on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Extracting sensitive data from JavaScript...[/bold cyan]"):
            result = self.web.extract_js_secrets(url)
        
        self.results['findings']['javascript'] = result
        
        if result:
            j_table = Table(title="Sensitive Data in JavaScript", box=box.ROUNDED, border_style="red")
            j_table.add_column("Type", style="yellow")
            j_table.add_column("Value", style="red")
            j_table.add_column("Source", style="cyan")
            for finding in result.get('findings', []):
                j_table.add_row(
                    finding.get('type', ''),
                    finding.get('value', '')[:60],
                    finding.get('source', '')[:50]
                )
            console.print(j_table)
        else:
            console.print("[bold green][+] No sensitive data found in JavaScript files[/bold green]")
    
    def _scan_cloudbuckets(self):
        """Cloud Storage Bucket Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Cloud Storage Bucket Scan on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Checking for exposed cloud storage...[/bold cyan]"):
            result = self.recon.detect_cloud_buckets(self.target)
        
        self.results['findings']['cloud_buckets'] = result
        
        if result and result.get('exposed'):
            console.print("[bold red][!] Exposed Cloud Storage Detected![/bold red]")
            b_table = Table(title="Exposed Buckets", box=box.HEAVY, border_style="red")
            b_table.add_column("Provider", style="yellow")
            b_table.add_column("Bucket URL", style="cyan")
            b_table.add_column("Status", style="red")
            for finding in result.get('findings', []):
                b_table.add_row(
                    finding.get('provider', ''),
                    finding.get('url', ''),
                    finding.get('status', '')
                )
            console.print(b_table)
        else:
            console.print("[bold green][+] No exposed cloud storage buckets detected[/bold green]")
    
    def _scan_waf(self):
        """WAF Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] WAF Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Detecting Web Application Firewall...[/bold cyan]"):
            result = self.recon.detect_waf(url)
        
        self.results['findings']['waf'] = result
        
        if result and result.get('detected'):
            console.print(f"[bold yellow][*] WAF Detected: {result.get('name', 'Unknown')}[/bold yellow]")
            w_table = Table(title="WAF Information", box=box.ROUNDED, border_style="yellow")
            w_table.add_column("Property", style="yellow")
            w_table.add_column("Value", style="green")
            for key, val in result.items():
                w_table.add_row(key, str(val)[:80])
            console.print(w_table)
        else:
            console.print("[bold green][+] No WAF detected[/bold green]")
    
    def _scan_techstack(self):
        """Technology Stack Fingerprinter - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Technology Fingerprinting on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Fingerprinting technology stack...[/bold cyan]"):
            result = self.recon.fingerprint_tech(url)
        
        self.results['findings']['tech_stack'] = result
        
        if result:
            t_table = Table(title="Technology Stack", box=box.DOUBLE, border_style="bright_cyan")
            t_table.add_column("Category", style="yellow")
            t_table.add_column("Technology", style="green")
            t_table.add_column("Confidence", style="cyan")
            for tech in result.get('technologies', []):
                t_table.add_row(
                    tech.get('category', ''),
                    tech.get('name', ''),
                    f"{tech.get('confidence', 0)}%"
                )
            console.print(t_table)
    
    def _scan_fullvuln(self):
        """Full Vulnerability Assessment - All vulnerability scanners combined"""
        console.print(f"\n[bold red][*] Full Vulnerability Assessment on {self.target}[/bold red]")
        console.print("[bold yellow][*] This will run: SQLi + XSS + CORS + Open Redirect + CRLF + WordPress + WAF + Headers + SSL + Cookies[/bold yellow]")
        
        self._scan_headers()
        self._scan_ssl()
        self._scan_sqli()
        self._scan_xss()
        self._scan_cors()
        self._scan_openredirect()
        self._scan_crlf()
        self._scan_cookies()
        self._scan_waf()
        self._scan_wordpress()
    
    def _scan_nuclear(self):
        """NUCLEAR SCAN - Everything combined (omino's nuke mode + wizard's full scan)"""
        console.print(f"\n[bold red][!!!] NUCLEAR SCAN INITIATED on {self.target}[/bold red]")
        console.print("[bold yellow][*] Running ALL modules... This may take a while.[/bold yellow]")
        
        # Run every single scan module
        self._scan_full_recon()
        self._scan_whois()
        self._scan_geoip()
        self._scan_dns()
        self._scan_subdomains()
        self._scan_ports()
        self._scan_banners()
        self._scan_headers()
        self._scan_ssl()
        self._scan_sqli()
        self._scan_xss()
        self._scan_dirbrute()
        self._scan_wordpress()
        self._scan_cors()
        self._scan_openredirect()
        self._scan_crlf()
        self._scan_cookies()
        self._scan_javascript()
        self._scan_cloudbuckets()
        self._scan_waf()
        self._scan_techstack()
        
        # Generate comprehensive report
        self.reports.generate_html_report(self.results, self.target)
        console.print(f"\n[bold green][+] NUCLEAR SCAN COMPLETE! Full report generated.[/bold green]")
    
    # ========================================================================
    # BUG BOUNTY ARSENAL - NEW SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_deep_crawl(self):
        """Deep web crawler for URL discovery"""
        console.print(f"\n[bold cyan][*] Deep Crawling {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Spidering website...[/bold cyan]"):
            result = self.adv_recon.deep_crawl(url)
        self.results['findings']['deep_crawl'] = result
        console.print(f"[green][+] Discovered: {result['total_discovered']} URLs, {len(result['forms'])} forms, {len(result['api_endpoints'])} API endpoints, {len(result['js_files'])} JS files")
        if result.get('parameters'):
            p_table = Table(title="Discovered Parameters", box=box.ROUNDED, border_style="yellow")
            p_table.add_column("Parameter", style="yellow")
            p_table.add_column("Found In URLs", style="cyan")
            for param, urls in list(result['parameters'].items())[:20]:
                p_table.add_row(param, str(len(urls)))
            console.print(p_table)
    
    def _scan_param_mining(self):
        """Parameter mining for hidden parameters"""
        console.print(f"\n[bold cyan][*] Parameter Mining on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Mining hidden parameters...[/bold cyan]"):
            result = self.adv_recon.mine_parameters(url)
        self.results['findings']['param_mining'] = result
        if 'error' in result:
            console.print(f"[bold red][!] {result['error']}[/bold red]")
            return
        console.print(f"[green][+] Tested {result.get('tested', 0)} parameters, found {len(result.get('discovered', {}))} active, {len(result.get('reflected', []))} reflected")
        if result.get('discovered'):
            d_table = Table(title="Active Parameters", box=box.ROUNDED, border_style="yellow")
            d_table.add_column("Parameter", style="yellow")
            d_table.add_column("Hint", style="red")
            for param, info in result['discovered'].items():
                d_table.add_row(param, info.get('hint', ''))
            console.print(d_table)
    
    def _scan_wayback(self):
        """Wayback URL discovery"""
        console.print(f"\n[bold cyan][*] Wayback URL Discovery for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Querying Wayback Machine...[/bold cyan]"):
            result = self.adv_recon.wayback_urls(self.target)
        self.results['findings']['wayback'] = result
        console.print(f"[green][+] Found {result['total']} historical URLs, {len(result.get('unique_params', []))} unique parameters")
    
    def _scan_google_dork(self):
        """Google dorking"""
        console.print(f"\n[bold cyan][*] Google Dorking {self.target}[/bold cyan]")
        with console.status("[bold cyan]Generating dork queries...[/bold cyan]"):
            result = self.adv_recon.google_dork(self.target)
        self.results['findings']['google_dork'] = result
        if result.get('findings'):
            g_table = Table(title=f"Google Dorks: {result['total']}", box=box.ROUNDED, border_style="yellow")
            g_table.add_column("Category", style="cyan")
            g_table.add_column("Severity", style="red")
            g_table.add_column("Dork", style="green")
            for f in result['findings'][:20]:
                g_table.add_row(f['category'], f['severity'], f['dork'][:60])
            console.print(g_table)
    
    def _scan_github_dork(self):
        """GitHub secret dorking"""
        console.print(f"\n[bold cyan][*] GitHub Secret Dorking for {self.target}[/bold cyan]")
        config_file = os.path.join(get_home(), '.zylon', 'config.json')
        api_token = None
        if os.path.exists(config_file):
            with open(config_file) as f:
                config = json.load(f)
            api_token = config.get('github_api_key', '')
        with console.status("[bold cyan]Searching GitHub for leaked secrets...[/bold cyan]"):
            result = self.adv_recon.github_dork(self.target, api_token)
        self.results['findings']['github_dork'] = result
        if result.get('findings'):
            console.print(f"[bold red][!] Found {result['total']} potential secret leaks on GitHub![/bold red]")
            for f in result['findings'][:10]:
                console.print(f"  [red]*[/red] {f.get('file', '')} in {f.get('repo', '')} - Severity: {f.get('severity', '')}")
        else:
            console.print("[green][+] No leaked secrets found on GitHub[/green]")
    
    def _scan_deep_js(self):
        """Deep JS analysis"""
        console.print(f"\n[bold cyan][*] Deep JS Analysis on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing JavaScript files...[/bold cyan]"):
            result = self.adv_recon.analyze_js_files(url)
        self.results['findings']['deep_js'] = result
        console.print(f"[green][+] Analyzed {result.get('files_analyzed', 0)} JS files")
        console.print(f"  Endpoints: {len(result.get('endpoints', []))}")
        console.print(f"  Secrets: {len(result.get('secrets', []))}")
        console.print(f"  Hidden Params: {len(result.get('hidden_params', []))}")
    
    def _scan_takeover(self):
        """Subdomain takeover check"""
        console.print(f"\n[bold cyan][*] Subdomain Takeover Check on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Discovering subdomains first...[/bold cyan]"):
            subs = self.recon.discover_subdomains(self.target)
        subdomain_list = list(subs.keys()) if isinstance(subs, dict) else list(subs)
        with console.status(f"[bold cyan]Checking {len(subdomain_list)} subdomains for takeover...[/bold cyan]"):
            result = self.adv_recon.check_subdomain_takeover(subdomain_list[:50])
        self.results['findings']['takeover'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!] {len(result['vulnerable'])} subdomains vulnerable to takeover![/bold red]")
            for v in result['vulnerable']:
                console.print(f"  [red]*[/red] {v['subdomain']} -> {v['service']} ({v['severity']})")
        else:
            console.print(f"[green][+] No subdomain takeover vulnerabilities ({result['total_tested']} checked)[/green]")
    
    def _scan_ssrf(self):
        """SSRF Scanner"""
        console.print(f"\n[bold red][*] SSRF Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for SSRF...[/bold cyan]"):
            result = self.injections.scan_ssrf(url)
        self.results['findings']['ssrf'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] SSRF Vulnerability Detected![/bold red]")
            for f in result['findings'][:10]:
                console.print(f"  [red]*[/red] Param: {f['parameter']} | Payload: {f['payload'][:40]} | Severity: {f.get('severity', '')}")
        else:
            console.print(f"[green][+] No SSRF detected ({result['tested_params']} params tested)[/green]")
    
    def _scan_ssti(self):
        """SSTI Scanner"""
        console.print(f"\n[bold red][*] SSTI Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Template Injection...[/bold cyan]"):
            result = self.injections.scan_ssti(url)
        self.results['findings']['ssti'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!] SSTI Detected! Engine: {result.get('engine', 'Unknown')}[/bold red]")
            for f in result['findings'][:5]:
                console.print(f"  [red]*[/red] {f['engine']} via param '{f['parameter']}' ({f['method']})")
        else:
            console.print(f"[green][+] No SSTI detected ({result['tested']} tests)[/green]")
    
    def _scan_lfi(self):
        """Path Traversal / LFI Scanner"""
        console.print(f"\n[bold red][*] Path Traversal / LFI Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Path Traversal...[/bold cyan]"):
            result = self.injections.scan_path_traversal(url)
        self.results['findings']['lfi'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Path Traversal / LFI Detected![/bold red]")
            for f in result['findings'][:10]:
                console.print(f"  [red]*[/red] Param: {f['parameter']} | Payload: {f['payload'][:40]}")
        else:
            console.print(f"[green][+] No LFI detected ({result['tested']} tests)[/green]")
    
    def _scan_xxe(self):
        """XXE Scanner"""
        console.print(f"\n[bold red][*] XXE Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for XXE...[/bold cyan]"):
            result = self.injections.scan_xxe(url)
        self.results['findings']['xxe'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] XXE Vulnerability Detected![/bold red]")
        else:
            console.print(f"[green][+] No XXE detected ({result['tested']} tests)[/green]")
    
    def _scan_idor(self):
        """IDOR Detector"""
        console.print(f"\n[bold red][*] IDOR Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for IDOR...[/bold cyan]"):
            result = self.injections.scan_idor(url)
        self.results['findings']['idor'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] IDOR Vulnerability Detected![/bold red]")
        else:
            console.print(f"[green][+] No IDOR detected ({result['tested']} tests)[/green]")
    
    def _scan_race(self):
        """Race Condition Tester"""
        console.print(f"\n[bold red][*] Race Condition Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Sending burst requests...[/bold cyan]"):
            result = self.injections.scan_race_condition(url)
        self.results['findings']['race_condition'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Race Condition Detected![/bold red]")
        else:
            console.print(f"[green][+] No race condition detected ({result['requests_sent']} requests)[/green]")
    
    def _scan_proto_pollution(self):
        """Prototype Pollution Scanner"""
        console.print(f"\n[bold cyan][*] Prototype Pollution Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Prototype Pollution...[/bold cyan]"):
            result = self.injections.scan_prototype_pollution(url)
        self.results['findings']['prototype_pollution'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Prototype Pollution Detected![/bold red]")
        else:
            console.print(f"[green][+] No prototype pollution detected[/green]")
    
    def _scan_cache_poison(self):
        """Web Cache Poisoning"""
        console.print(f"\n[bold red][*] Cache Poisoning Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Cache Poisoning...[/bold cyan]"):
            result = self.adv_web.scan_cache_poisoning(url)
        self.results['findings']['cache_poisoning'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Cache Poisoning Detected![/bold red]")
        else:
            console.print(f"[green][+] No cache poisoning detected ({result['tested']} tests)[/green]")
    
    def _scan_smuggling(self):
        """HTTP Request Smuggling"""
        console.print(f"\n[bold red][*] Request Smuggling Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Request Smuggling...[/bold cyan]"):
            result = self.adv_web.scan_request_smuggling(url)
        self.results['findings']['request_smuggling'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Request Smuggling Detected![/bold red]")
        else:
            console.print(f"[green][+] No request smuggling detected ({result['tested']} tests)[/green]")
    
    def _scan_host_header(self):
        """Host Header Injection"""
        console.print(f"\n[bold red][*] Host Header Injection Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing Host Header Injection...[/bold cyan]"):
            result = self.adv_web.scan_host_header(url)
        self.results['findings']['host_header'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Host Header Injection Detected![/bold red]")
        else:
            console.print(f"[green][+] No host header injection detected ({result['tested']} tests)[/green]")
    
    def _scan_jwt(self):
        """JWT Vulnerability Scanner"""
        console.print(f"\n[bold red][*] JWT Vulnerability Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing JWT tokens...[/bold cyan]"):
            result = self.adv_web.scan_jwt(url)
        self.results['findings']['jwt'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] JWT Vulnerability Detected![/bold red]")
        if result.get('jwt_count', 0) == 0:
            console.print("[yellow][!] No JWT tokens found - try scanning an authenticated endpoint[/yellow]")
        else:
            console.print(f"[green][+] Analyzed {result['jwt_count']} JWT tokens ({result['tested']} tests)[/green]")
    
    def _scan_broken_auth(self):
        """Broken Authentication Detector"""
        console.print(f"\n[bold red][*] Broken Authentication Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing authentication mechanisms...[/bold cyan]"):
            result = self.adv_web.scan_broken_auth(url)
        self.results['findings']['broken_auth'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Broken Authentication Detected![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Medium')
            console.print(f"  [{'red' if sev == 'Critical' else 'yellow'}]*[/{'red' if sev == 'Critical' else 'yellow'}] {f.get('type', '')}: {f.get('note', '')}")
    
    # ========================================================================
    # ORIGIN IP FINDER SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_origin_ip_quick(self):
        """Origin IP Finder - Quick scan with top techniques"""
        console.print(f"\n[bold magenta][*] Origin IP Finder (Quick) on {self.target}[/bold magenta]")
        console.print("[dim]Running top 7 techniques: DNS Mining, Subdomain Resolve, Cert Transparency, DNS History, Error Page Leak, CNAME Chain, CDN Detection[/dim]")
        
        with console.status("[bold magenta]Hunting for origin IP behind CDN/WAF...[/bold magenta]"):
            result = self.origin_ip.quick_find(self.target)
        
        self.results['findings']['origin_ip'] = result
        
        # Display CDN detection
        cdn = result.get('cdn_detection', {})
        if cdn.get('behind_cdn'):
            console.print(f"\n[bold yellow][*] CDN Detected: {cdn.get('cdn_provider', 'Unknown')}[/bold yellow]")
            for evidence in cdn.get('evidence', []):
                console.print(f"  [yellow]*[/yellow] {evidence}")
        else:
            console.print("\n[bold green][+] Target does not appear to be behind a CDN[/bold green]")
        
        # Display found origin IPs
        origin_ips = result.get('origin_ips', [])
        if origin_ips:
            ip_table = Table(
                title=f"[bold]Origin IP Candidates: {len(origin_ips)}[/bold]",
                box=box.HEAVY, border_style="bold magenta"
            )
            ip_table.add_column("IP", style="bold red")
            ip_table.add_column("Confidence", style="yellow")
            ip_table.add_column("Sources", style="cyan")
            ip_table.add_column("Type", style="magenta")
            ip_table.add_column("Verified", style="green")
            
            for candidate in origin_ips[:20]:
                confidence = candidate.get('confidence', 'low')
                conf_color = "green" if confidence == 'high' else "yellow" if confidence == 'medium' else "red"
                sources = ', '.join(candidate.get('sources', [])[:3])
                verified = candidate.get('verification', {}).get('verified', False)
                ip_type = candidate.get('ip_type', 'origin')
                ver_str = "[green]YES[/green]" if verified else "[red]NO[/red]"
                type_str = "ORIGIN" if ip_type == 'origin' else f"[dim]{ip_type}[/dim]"
                ip_table.add_row(
                    candidate.get('ip', ''),
                    f"[{conf_color}]{confidence}[/{conf_color}]",
                    sources[:60],
                    type_str,
                    ver_str
                )
            console.print(ip_table)
        else:
            console.print("[bold yellow][!] No verified origin IPs found[/bold yellow]")
        
        # Display infrastructure IPs (mail/DNS/SPF) for reference
        infra_ips = result.get('infrastructure_ips', [])
        if infra_ips:
            infra_table = Table(
                title=f"[dim]Infrastructure IPs (NOT origin): {len(infra_ips)}[/dim]",
                box=box.SIMPLE, border_style="dim"
            )
            infra_table.add_column("IP", style="dim")
            infra_table.add_column("Type", style="dim yellow")
            infra_table.add_column("Note", style="dim")
            for inf in infra_ips[:10]:
                infra_table.add_row(
                    inf.get('ip', ''),
                    inf.get('ip_type', ''),
                    inf.get('note', 'Infrastructure')
                )
            console.print(infra_table)
    
    def _scan_origin_ip_full(self):
        """Origin IP Finder - Full scan with all 22 techniques"""
        console.print(f"\n[bold magenta][*] Origin IP Finder (Full - 22 Techniques) on {self.target}[/bold magenta]")
        console.print("[dim]Running all 22 advanced origin IP discovery techniques...[/dim]")
        
        with console.status("[bold magenta]Running all 22 origin IP techniques... (this may take a minute)[/bold magenta]"):
            result = self.origin_ip.find_origin_ip(self.target)
        
        self.results['findings']['origin_ip'] = result
        
        # Display CDN detection
        cdn = result.get('cdn_detection', {})
        if cdn.get('behind_cdn'):
            console.print(f"\n[bold yellow][*] CDN Detected: {cdn.get('cdn_provider', 'Unknown')}[/bold yellow]")
            for evidence in cdn.get('evidence', []):
                console.print(f"  [yellow]*[/yellow] {evidence}")
        else:
            console.print("\n[bold green][+] Target does not appear to be behind a CDN[/bold green]")
        
        # Display technique results summary
        techniques = result.get('all_techniques', {})
        tech_table = Table(
            title="[bold]Technique Results Summary[/bold]",
            box=box.ROUNDED, border_style="cyan"
        )
        tech_table.add_column("Technique", style="yellow")
        tech_table.add_column("Status", style="green")
        tech_table.add_column("Findings", style="cyan")
        
        technique_names = {
            'dns_mining': 'DNS Record Mining',
            'cname_chain': 'CNAME Chain Following',
            'multi_resolver': 'Multi-Resolver Validation',
            'spf_dkim_dmarc': 'SPF/DKIM/DMARC Extract',
            'zone_transfer': 'DNS Zone Transfer (AXFR)',
            'dns_history': 'DNS Historical Records',
            'cert_transparency': 'Certificate Transparency',
            'subdomain_resolution': 'Subdomain Resolution',
            'web_archive': 'Web Archive History',
            'shodan': 'Shodan Search',
            'censys': 'Censys Search',
            'favicon_hash': 'Favicon Hash',
            'email_headers': 'Email Header IP Extract',
            'error_page_leak': 'Error Page IP Leak',
            'server_status': 'Server Status Mining',
            'sitemap_parse': 'Sitemap IP Parsing',
            'resource_leak': 'Resource IP Leak',
            'cloud_metadata': 'Cloud Metadata Detection',
            'asn_prefix': 'ASN/Prefix Lookup',
        }
        
        for tech_key, tech_name in technique_names.items():
            tech_data = techniques.get(tech_key, {})
            if isinstance(tech_data, dict) and 'error' in tech_data:
                status = "[red]Failed[/red]"
                findings = tech_data['error']
            elif isinstance(tech_data, list):
                status = "[green]Complete[/green]"
                findings = f"{len(tech_data)} results"
            elif isinstance(tech_data, dict):
                status = "[green]Complete[/green]"
                ip_count = len(tech_data.get('ips', tech_data.get('found_ips', tech_data.get('matching_hosts', []))))
                findings = f"{ip_count} IPs found" if ip_count > 0 else "No IPs found"
            else:
                status = "[dim]N/A[/dim]"
                findings = "-"
            tech_table.add_row(tech_name, status, str(findings)[:50])
        
        console.print(tech_table)
        
        # Display CDN IPs found
        cdn_ips = result.get('cdn_ips', [])
        if cdn_ips:
            console.print(f"\n[bold yellow]CDN/Proxy IPs Found: {len(cdn_ips)}[/bold yellow]")
            for cdn_ip in cdn_ips[:5]:
                console.print(f"  [yellow]*[/yellow] {cdn_ip.get('ip', '')} -> {cdn_ip.get('cdn_provider', 'Unknown')}")
        
        # Display verified origin IPs
        origin_ips = result.get('origin_ips', [])
        if origin_ips:
            ip_table = Table(
                title=f"[bold red]VERIFIED ORIGIN IP CANDIDATES: {len(origin_ips)}[/bold red]",
                box=box.HEAVY, border_style="bold red"
            )
            ip_table.add_column("IP", style="bold red")
            ip_table.add_column("Confidence", style="yellow")
            ip_table.add_column("Sources", style="cyan")
            ip_table.add_column("Type", style="magenta")
            ip_table.add_column("Verified", style="bold green")
            ip_table.add_column("Match Score", style="magenta")
            
            for candidate in origin_ips[:20]:
                confidence = candidate.get('confidence', 'low')
                conf_color = "green" if confidence == 'high' else "yellow" if confidence == 'medium' else "red"
                sources = ', '.join(candidate.get('sources', [])[:4])
                verified = candidate.get('verification', {}).get('verified', False)
                ver_str = "[bold green]VERIFIED[/bold green]" if verified else "[dim]Unverified[/dim]"
                match_score = candidate.get('verification', {}).get('response_similarity', 0)
                score_str = f"{match_score}%" if match_score else "N/A"
                ip_type = candidate.get('ip_type', 'origin')
                type_str = "[green]ORIGIN[/green]" if ip_type == 'origin' else f"[dim]{ip_type}[/dim]"
                ip_table.add_row(
                    candidate.get('ip', ''),
                    f"[{conf_color}]{confidence}[/{conf_color}]",
                    sources[:60],
                    type_str,
                    ver_str,
                    score_str
                )
            console.print(ip_table)
        else:
            console.print("[bold yellow][!] No verified origin IPs discovered (target may be well-protected)[/bold yellow]")
        
        # Display infrastructure IPs for reference
        infra_ips = result.get('infrastructure_ips', [])
        if infra_ips:
            console.print(f"\n[bold dim]Infrastructure IPs (NOT origin): {len(infra_ips)}[/bold dim]")
            for inf in infra_ips[:8]:
                console.print(f"  [dim]*[/dim] {inf.get('ip', '')} | {inf.get('ip_type', '')} | {inf.get('note', 'Infrastructure')}")
        
        # Display header fingerprint matches
        fp = result.get('header_fingerprint', {})
        if fp.get('ip_matches'):
            console.print(f"\n[bold cyan]Header Fingerprint Matches: {len(fp['ip_matches'])}[/bold cyan]")
            for match in fp['ip_matches']:
                console.print(f"  [cyan]*[/cyan] IP: {match.get('ip', '')} | Score: {match.get('match_score', 0)} | Details: {', '.join(match.get('details', []))}")
        
        # Display all candidate IPs
        all_candidates = result.get('all_candidate_ips', [])
        if all_candidates and len(all_candidates) > len(origin_ips):
            console.print(f"\n[bold dim]All Non-CDN IP Candidates: {len(all_candidates)} (showing top 10)[/bold dim]")
            for candidate in all_candidates[:10]:
                console.print(f"  [dim]*[/dim] {candidate.get('ip', '')} | {candidate.get('confidence', '')} | {len(candidate.get('sources', []))} sources")
    
    def _scan_cdn_detection(self):
        """CDN/WAF Detection & Fingerprinting"""
        console.print(f"\n[bold yellow][*] CDN/WAF Detection on {self.target}[/bold yellow]")
        
        with console.status("[bold yellow]Detecting CDN/WAF protection...[/bold yellow]"):
            result = self.origin_ip.detect_cdn(self.target)
        
        self.results['findings']['cdn_detection'] = result
        
        cdn_table = Table(
            title="CDN/WAF Detection Results",
            box=box.ROUNDED, border_style="yellow"
        )
        cdn_table.add_column("Property", style="yellow")
        cdn_table.add_column("Value", style="cyan")
        
        cdn_table.add_row("Behind CDN", "[red]YES[/red]" if result.get('behind_cdn') else "[green]NO[/green]")
        cdn_table.add_row("CDN Provider", result.get('cdn_provider', 'None detected'))
        cdn_table.add_row("Current IP", str(result.get('current_ip', 'Unknown')))
        
        console.print(cdn_table)
        
        if result.get('evidence'):
            console.print("\n[bold yellow]Evidence:[/bold yellow]")
            for evidence in result['evidence']:
                console.print(f"  [yellow]*[/yellow] {evidence}")
        
        if not result.get('behind_cdn'):
            console.print("\n[bold green][+] Target is NOT behind a CDN - the resolved IP is likely the origin[/bold green]")
        else:
            console.print("\n[bold red][!] Target IS behind CDN - use scan 50/51 to find the real origin IP[/bold red]")
    
    def _scan_dns_cert_hunt(self):
        """DNS History + Certificate Transparency IP Hunt"""
        console.print(f"\n[bold magenta][*] DNS History + Cert Transparency Hunt on {self.target}[/bold magenta]")
        
        with console.status("[bold magenta]Querying DNS history and certificate transparency logs...[/bold magenta]"):
            dns_history = self.origin_ip.dns_history_lookup(self.target)
            cert_results = self.origin_ip.cert_transparency_search(self.target)
        
        self.results['findings']['dns_cert_hunt'] = {
            'dns_history': dns_history,
            'cert_transparency': cert_results
        }
        
        # DNS History results
        if dns_history:
            h_table = Table(
                title="DNS History - Previous IPs",
                box=box.ROUNDED, border_style="magenta"
            )
            h_table.add_column("IP", style="red")
            h_table.add_column("Source", style="cyan")
            h_table.add_column("Details", style="yellow")
            for entry in dns_history[:20]:
                ip = entry.get('ip', '')
                source = entry.get('source', '')
                details = entry.get('first_seen', '') or entry.get('hostname', '')
                cdn = self.origin_ip._is_cdn_ip(ip)
                ip_display = f"{ip} [dim](CDN: {cdn})[/dim]" if cdn else f"[bold red]{ip}[/bold red]"
                h_table.add_row(ip_display, source, str(details)[:40])
            console.print(h_table)
        else:
            console.print("[bold yellow][!] No historical DNS records found[/bold yellow]")
        
        # Certificate Transparency results
        non_cdn_cert = [r for r in cert_results if not self.origin_ip._is_cdn_ip(r.get('ip', ''))]
        if non_cdn_cert:
            c_table = Table(
                title="Cert Transparency - Non-CDN IPs",
                box=box.ROUNDED, border_style="magenta"
            )
            c_table.add_column("IP", style="red")
            c_table.add_column("Hostname", style="cyan")
            c_table.add_column("Source", style="yellow")
            for entry in non_cdn_cert[:20]:
                c_table.add_row(
                    entry.get('ip', ''),
                    entry.get('hostname', ''),
                    entry.get('source', '')
                )
            console.print(c_table)
        else:
            console.print("[bold yellow][!] No non-CDN IPs found via certificate transparency[/bold yellow]")
    
    def _scan_subdomain_origin(self):
        """Subdomain Resolution + CDN IP Filtering"""
        console.print(f"\n[bold magenta][*] Subdomain Origin IP Hunt on {self.target}[/bold magenta]")
        
        with console.status("[bold magenta]Resolving subdomains and filtering CDN IPs...[/bold magenta]"):
            result = self.origin_ip.subdomain_resolution(self.target)
        
        self.results['findings']['subdomain_origin'] = result
        
        console.print(f"\n[bold cyan]Total subdomains discovered: {result.get('total_subdomains', 0)}[/bold cyan]")
        
        # Display non-CDN IPs (likely origin)
        non_cdn = result.get('non_cdn_ips', [])
        if non_cdn:
            s_table = Table(
                title=f"Non-CDN Origin IP Candidates: {len(non_cdn)}",
                box=box.HEAVY, border_style="bold magenta"
            )
            s_table.add_column("Subdomain", style="cyan")
            s_table.add_column("IP", style="bold red")
            for entry in non_cdn[:30]:
                s_table.add_row(entry.get('subdomain', ''), entry.get('ip', ''))
            console.print(s_table)
        else:
            console.print("[bold yellow][!] All resolved subdomains point to CDN IPs[/bold yellow]")
    
    def _scan_ip_verify(self):
        """Direct IP Verification with Host Header"""
        console.print(f"\n[bold magenta][*] Direct IP Verification on {self.target}[/bold magenta]")
        
        # First, get any known non-CDN IPs
        with console.status("[bold magenta]Quick scanning for candidate IPs first...[/bold magenta]"):
            quick = self.origin_ip.quick_find(self.target)
        
        candidates = quick.get('origin_ips', [])
        if not candidates:
            console.print("[bold yellow][!] No candidate IPs found to verify. Run scan 50 first.[/bold yellow]")
            return
        
        # Verify top candidates
        verified_results = []
        for candidate in candidates[:10]:
            ip = candidate.get('ip', '')
            if not ip:
                continue
            console.print(f"  [cyan]*[/cyan] Verifying {ip}...")
            verification = self.origin_ip.verify_origin_ip(self.target, ip)
            verified_results.append(verification)
        
        self.results['findings']['ip_verification'] = verified_results
        
        # Display results
        v_table = Table(
            title="IP Verification Results",
            box=box.ROUNDED, border_style="magenta"
        )
        v_table.add_column("IP", style="bold red")
        v_table.add_column("Verified", style="bold green")
        v_table.add_column("Match Score", style="yellow")
        v_table.add_column("Methods", style="cyan")
        v_table.add_column("Evidence", style="dim")
        
        for v in verified_results:
            verified = v.get('verified', False)
            ver_str = "[bold green]YES[/bold green]" if verified else "[red]NO[/red]"
            score = v.get('response_similarity', 0)
            methods = ', '.join(v.get('methods', []))
            evidence = '; '.join(v.get('evidence', []))[:60]
            v_table.add_row(
                v.get('ip', ''),
                ver_str,
                f"{score}%",
                methods,
                evidence
            )
        
        console.print(v_table)
        
        verified = [v for v in verified_results if v.get('verified')]
        if verified:
            console.print(f"\n[bold green][+] {len(verified)} VERIFIED ORIGIN IP(S) FOUND![/bold green]")
            for v in verified:
                console.print(f"  [bold green]*[/bold green] {v.get('ip', '')} (Match: {v.get('response_similarity', 0)}%)")
        else:
            console.print("[bold yellow][!] No IPs could be verified as origin[/bold yellow]")
    
    def _scan_bounty_recon(self):
        """Bug Bounty Full Recon Pipeline - All recon modules"""
        console.print(f"\n[bold yellow][*] BUG BOUNTY RECON PIPELINE on {self.target}[/bold yellow]")
        self._scan_full_recon()
        self._scan_deep_crawl()
        self._scan_param_mining()
        self._scan_wayback()
        self._scan_google_dork()
        self._scan_github_dork()
        self._scan_deep_js()
        self._scan_takeover()
        console.print(f"\n[bold green][+] Bug Bounty Recon Pipeline Complete![/bold green]")
    
    def _scan_bounty_vuln(self):
        """Bug Bounty Full Vulnerability Pipeline - All vuln modules"""
        console.print(f"\n[bold red][*] BUG BOUNTY VULN PIPELINE on {self.target}[/bold red]")
        self._scan_sqli()
        self._scan_xss()
        self._scan_ssrf()
        self._scan_ssti()
        self._scan_lfi()
        self._scan_xxe()
        self._scan_idor()
        self._scan_cors()
        self._scan_openredirect()
        self._scan_crlf()
        self._scan_race()
        self._scan_jwt()
        self._scan_broken_auth()
        self._scan_cache_poison()
        self._scan_host_header()
        console.print(f"\n[bold green][+] Bug Bounty Vuln Pipeline Complete![/bold green]")
    
    # ========================================================================
    # V2.0 NUCLEAR MODULE SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_api_fuzzer(self):
        """API Endpoint Discovery + Fuzzer (V2.0)"""
        console.print(f"\n[bold magenta][*] API Endpoint Discovery + Fuzzer on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Discovering and fuzzing API endpoints...[/bold magenta]"):
            result = self.v2_vuln.discover_api_endpoints(url)
        
        self.results['findings']['api_fuzzer'] = result
        
        if result and result.get('discovered_endpoints'):
            e_table = Table(title=f"API Endpoints Discovered: {result['total_endpoints']}", 
                          box=box.DOUBLE, border_style="bright_magenta")
            e_table.add_column("Endpoint", style="cyan")
            e_table.add_column("Status", style="green")
            e_table.add_column("Type", style="yellow")
            e_table.add_column("Vulns", style="red")
            
            for ep in result['discovered_endpoints']:
                is_api = "Yes" if ep.get('is_api') else "No"
                vuln_count = len(ep.get('vulnerabilities', []))
                status_color = "green" if ep['status_code'] == 200 else "yellow"
                e_table.add_row(
                    ep['path'],
                    f"[{status_color}]{ep['status_code']}[/{status_color}]",
                    is_api,
                    str(vuln_count) if vuln_count > 0 else "-"
                )
            console.print(e_table)
            
            if result.get('swagger_docs'):
                console.print("\n[bold red][!] API Documentation Exposed:[/bold red]")
                for doc in result['swagger_docs']:
                    console.print(f"  [red]*[/red] {doc['path']} (Status: {doc['status_code']})")
            
            if result.get('vulnerabilities'):
                v_table = Table(title=f"API Vulnerabilities Found: {result['total_vulns']}", 
                              box=box.HEAVY, border_style="bold red")
                v_table.add_column("Type", style="red")
                v_table.add_column("Endpoint", style="cyan")
                v_table.add_column("Severity", style="yellow")
                v_table.add_column("Description", style="white")
                for v in result['vulnerabilities']:
                    v_table.add_row(
                        v.get('type', ''),
                        v.get('endpoint', ''),
                        v.get('severity', ''),
                        v.get('description', '')[:60]
                    )
                console.print(v_table)
        else:
            console.print("[bold yellow][!] No API endpoints discovered[/bold yellow]")
    
    def _scan_rate_limit(self):
        """Rate Limit Tester (V2.0)"""
        console.print(f"\n[bold magenta][*] Rate Limit Testing on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Sending rapid requests to test rate limiting...[/bold magenta]"):
            result = self.v2_vuln.test_rate_limiting(url)
        
        self.results['findings']['rate_limit'] = result
        
        if result and result.get('missing_rate_limit'):
            console.print(f"\n[bold red][!] {result['total_missing']} endpoints missing rate limiting![/bold red]")
            r_table = Table(title="Missing Rate Limiting", box=box.HEAVY, border_style="bold red")
            r_table.add_column("Endpoint", style="cyan")
            r_table.add_column("Severity", style="red")
            r_table.add_column("Details", style="yellow")
            for ep in result['missing_rate_limit']:
                r_table.add_row(
                    ep['endpoint'],
                    f"[red]{ep['severity']}[/red]",
                    ep['description'][:60]
                )
            console.print(r_table)
        else:
            console.print("[bold green][+] Rate limiting appears to be in place on tested endpoints[/bold green]")
        
        # Show summary of all tested endpoints
        if result and result.get('endpoints_tested'):
            s_table = Table(title="Rate Limit Test Summary", box=box.ROUNDED, border_style="cyan")
            s_table.add_column("Endpoint", style="cyan")
            s_table.add_column("Sent", style="yellow")
            s_table.add_column("Success", style="green")
            s_table.add_column("Verdict", style="bold")
            for ep in result['endpoints_tested']:
                verdict_color = "red" if 'NO' in ep.get('verdict', '') else "green" if 'RATE' in ep.get('verdict', '') else "dim"
                s_table.add_row(
                    ep['endpoint'],
                    str(ep['requests_sent']),
                    str(ep['successful']),
                    f"[{verdict_color}]{ep.get('verdict', 'N/A')}[/{verdict_color}]"
                )
            console.print(s_table)
    
    def _scan_sensitive_files(self):
        """Sensitive File Deep Scanner (V2.0)"""
        console.print(f"\n[bold magenta][*] Sensitive File Deep Scan on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Scanning for 100+ sensitive file patterns...[/bold magenta]"):
            result = self.v2_vuln.scan_sensitive_files(url)
        
        self.results['findings']['sensitive_files'] = result
        
        if result and result.get('found_files'):
            # Critical exposures first
            if result.get('critical_exposures'):
                console.print(f"\n[bold red][!!!] {result['total_critical']} CRITICAL EXPOSURES FOUND![/bold red]")
                for exp in result['critical_exposures']:
                    console.print(f"  [bold red]*[/bold red] {exp['url']} - {exp.get('severity', '').upper()}")
                    if exp.get('contains_secrets'):
                        console.print(f"    [red]Contains secrets/passwords![/red]")
                    if exp.get('git_exposed'):
                        console.print(f"    [red]Git repository exposed![/red]")
                    if exp.get('db_dump_exposed'):
                        console.print(f"    [red]Database dump exposed![/red]")
            
            f_table = Table(title=f"Sensitive Files Found: {result['total_found']}", 
                          box=box.DOUBLE, border_style="bright_red")
            f_table.add_column("Path", style="cyan")
            f_table.add_column("Status", style="green")
            f_table.add_column("Size", style="yellow")
            f_table.add_column("Severity", style="bold")
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_files = sorted(result['found_files'], 
                                key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
            
            for f in sorted_files[:50]:
                sev = f.get('severity', 'info')
                sev_color = "red" if sev == 'critical' else "yellow" if sev == 'high' else "green" if sev == 'medium' else "dim"
                f_table.add_row(
                    f['path'],
                    str(f['status_code']),
                    str(f.get('size', '')),
                    f"[{sev_color}]{sev}[/{sev_color}]"
                )
            console.print(f_table)
            if result['total_found'] > 50:
                console.print(f"[yellow]... and {result['total_found'] - 50} more files[/yellow]")
        else:
            console.print("[bold green][+] No sensitive files detected[/bold green]")
    
    def _scan_email_enum(self):
        """Email Enumeration (V2.0)"""
        console.print(f"\n[bold magenta][*] Email Enumeration on {self.target}[/bold magenta]")
        domain = self.target.replace('www.', '')
        
        with console.status("[bold magenta]Enumerating email addresses...[/bold magenta]"):
            result = self.v2_recon.enumerate_emails(domain)
        
        self.results['findings']['email_enum'] = result
        
        if result and result.get('emails'):
            e_table = Table(title=f"Emails Found: {result['total_found']}", 
                          box=box.DOUBLE, border_style="bright_cyan")
            e_table.add_column("#", style="dim")
            e_table.add_column("Email", style="cyan")
            e_table.add_column("Source", style="yellow")
            
            for i, email in enumerate(result['emails'][:50], 1):
                source = 'multi'
                for src, emails in result.get('sources', {}).items():
                    if email in emails:
                        source = src
                        break
                if any(email.startswith(p.split('@')[0]) for p in result.get('patterns_generated', [])):
                    source = 'pattern-generated'
                e_table.add_row(str(i), email, source)
            console.print(e_table)
        else:
            console.print("[bold yellow][!] No emails found[/bold yellow]")
        
        if result and result.get('mx_records'):
            console.print(f"\n[cyan]MX Records:[/cyan] {', '.join(result['mx_records'])}")
    
    def _scan_broken_links(self):
        """Broken Link Hijacker (V2.0)"""
        console.print(f"\n[bold magenta][*] Broken Link Hijacking Scan on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Crawling page and checking external links...[/bold magenta]"):
            result = self.v2_recon.check_broken_links(url)
        
        self.results['findings']['broken_links'] = result
        
        console.print(f"\n[cyan]Total links on page:[/cyan] {result.get('total_links', 0)}")
        console.print(f"[cyan]External links:[/cyan] {result.get('external_links', 0)}")
        console.print(f"[cyan]Broken links:[/cyan] {result.get('total_broken', 0)}")
        
        if result and result.get('hijackable'):
            console.print(f"\n[bold red][!] {result['total_hijackable']} HIJACKABLE broken links found![/bold red]")
            h_table = Table(title="Hijackable Domains", box=box.HEAVY, border_style="bold red")
            h_table.add_column("Broken URL", style="red")
            h_table.add_column("Domain", style="cyan")
            h_table.add_column("Status", style="yellow")
            for link in result['hijackable']:
                h_table.add_row(
                    link['url'][:60],
                    link['domain'],
                    str(link['status_code'])
                )
            console.print(h_table)
        elif result and result.get('broken_links'):
            b_table = Table(title=f"Broken Links: {result['total_broken']}", 
                          box=box.ROUNDED, border_style="yellow")
            b_table.add_column("URL", style="red")
            b_table.add_column("Status", style="yellow")
            b_table.add_column("Server", style="dim")
            for link in result['broken_links']:
                b_table.add_row(
                    link['url'][:60],
                    str(link['status_code']),
                    link.get('server', '')[:30]
                )
            console.print(b_table)
        else:
            console.print("[bold green][+] No broken external links found[/bold green]")
    
    def _scan_tech_cve(self):
        """Technology Version + CVE Lookup (V2.0)"""
        console.print(f"\n[bold magenta][*] Tech Version + CVE Lookup on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Detecting technology versions and looking up CVEs...[/bold magenta]"):
            result = self.v2_recon.detect_tech_versions(url)
        
        self.results['findings']['tech_cve'] = result
        
        if result and result.get('technologies'):
            t_table = Table(title=f"Technologies with Versions: {result['total_techs']}", 
                          box=box.DOUBLE, border_style="bright_cyan")
            t_table.add_column("Technology", style="cyan")
            t_table.add_column("Version", style="green")
            t_table.add_column("Source", style="yellow")
            t_table.add_column("CVEs", style="red")
            
            for tech in result['technologies']:
                cve_count = len(tech.get('cves', []))
                t_table.add_row(
                    tech['name'],
                    tech['version'],
                    tech.get('source', ''),
                    str(cve_count) if cve_count > 0 else "-"
                )
            console.print(t_table)
            
            # Show CVEs
            if result.get('cves'):
                risk = result.get('risk_summary', {})
                console.print(f"\n[bold red]CVE Risk Summary:[/bold red] "
                            f"[red]Critical: {risk.get('critical', 0)}[/red] | "
                            f"[yellow]High: {risk.get('high', 0)}[/yellow] | "
                            f"[cyan]Medium: {risk.get('medium', 0)}[/cyan] | "
                            f"[green]Low: {risk.get('low', 0)}[/green]")
                
                c_table = Table(title=f"CVEs Found: {result['total_cves']}", 
                              box=box.HEAVY, border_style="bold red")
                c_table.add_column("CVE ID", style="red")
                c_table.add_column("Technology", style="cyan")
                c_table.add_column("CVSS", style="yellow")
                c_table.add_column("Severity", style="bold")
                c_table.add_column("Summary", style="white")
                
                for tech in result['technologies']:
                    for cve in tech.get('cves', []):
                        sev = cve.get('severity', 'medium')
                        sev_color = "red" if sev == 'critical' else "yellow" if sev == 'high' else "green"
                        c_table.add_row(
                            cve.get('id', ''),
                            tech['name'],
                            str(cve.get('cvss', 0)),
                            f"[{sev_color}]{sev}[/{sev_color}]",
                            cve.get('summary', '')[:50]
                        )
                console.print(c_table)
        else:
            console.print("[bold yellow][!] No technology versions detected[/bold yellow]")
    
    def _scan_mega(self):
        """MEGA SCAN - Every single module"""
        console.print(f"\n[bold red][!!!] MEGA SCAN INITIATED on {self.target}[/bold red]")
        console.print("[bold yellow][*] Running ALL 40+ modules... Grab some coffee.[/bold yellow]")
        # Original modules
        self._scan_full_recon()
        self._scan_whois()
        self._scan_geoip()
        self._scan_dns()
        self._scan_subdomains()
        self._scan_ports()
        self._scan_banners()
        self._scan_headers()
        self._scan_ssl()
        self._scan_sqli()
        self._scan_xss()
        self._scan_dirbrute()
        self._scan_wordpress()
        self._scan_cors()
        self._scan_openredirect()
        self._scan_crlf()
        self._scan_cookies()
        self._scan_javascript()
        self._scan_cloudbuckets()
        self._scan_waf()
        self._scan_techstack()
        # Bug Bounty Arsenal
        self._scan_deep_crawl()
        self._scan_param_mining()
        self._scan_wayback()
        self._scan_google_dork()
        self._scan_github_dork()
        self._scan_deep_js()
        self._scan_takeover()
        self._scan_ssrf()
        self._scan_ssti()
        self._scan_lfi()
        self._scan_xxe()
        self._scan_idor()
        self._scan_race()
        self._scan_proto_pollution()
        self._scan_cache_poison()
        self._scan_smuggling()
        self._scan_host_header()
        self._scan_jwt()
        self._scan_broken_auth()
        # V2.0 Nuclear Modules
        self._scan_api_fuzzer()
        self._scan_rate_limit()
        self._scan_sensitive_files()
        self._scan_email_enum()
        self._scan_broken_links()
        self._scan_tech_cve()
        # Origin IP Finder
        self._scan_origin_ip_quick()
        # V3.0 Security Modules
        self._scan_graphql()
        self._scan_dom_xss()
        self._scan_clickjacking()
        self._scan_csp()
        self._scan_http_method()
        self._scan_shodan_internetdb()
        self._scan_security_robots()
        self._scan_mixed_content()
        self._scan_info_disclosure()
        # V4.0 Hunting Modules
        self._scan_username_enum()
        self._scan_email_security()
        self._scan_csrf()
        self._scan_framework()
        self._scan_js_libraries()
        self._scan_403_bypass()
        self._scan_cross_domain()
        self._scan_cve_lookup()
        # Generate mega report
        self.reports.generate_html_report(self.results, self.target)
        console.print(f"\n[bold green][+] MEGA SCAN COMPLETE! Full report generated.[/bold green]")

    # ========================================================================
    # V3.0 SECURITY MODULE SCAN IMPLEMENTATIONS (56-75)
    # ========================================================================

    def _scan_graphql(self):
        """Scan 56: GraphQL Security Tester"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] GraphQL Security Scan on {self.target}[/bold cyan]")
        with console.status("[bold magenta]Testing GraphQL endpoints...[/bold magenta]"):
            result = self.v3_security.scan_graphql(url)
        self.results['findings']['graphql'] = result
        if result.get('graphql_found'):
            console.print(f"[bold yellow][*] GraphQL endpoint found![/bold yellow]")
            for ep in result.get('endpoints', []):
                console.print(f"  [cyan]Endpoint: {ep}[/cyan]")
            for f in result.get('findings', []):
                sev = f.get('severity', 'Info')
                color = 'red' if sev in ['Critical', 'High'] else 'yellow' if sev == 'Medium' else 'cyan'
                console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
                console.print(f"      {f.get('note', '')}")
        else:
            console.print("[green][+] No GraphQL endpoints detected[/green]")

    def _scan_dom_xss(self):
        """Scan 57: DOM-based XSS Scanner"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold red][*] DOM XSS Scan on {self.target}[/bold red]")
        with console.status("[bold magenta]Analyzing JavaScript for DOM XSS patterns...[/bold magenta]"):
            result = self.v3_security.scan_dom_xss(url)
        self.results['findings']['dom_xss'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] DOM XSS Vulnerability Detected![/bold red]")
            for f in result.get('findings', []):
                sev = f.get('severity', 'Medium')
                color = 'red' if sev in ['Critical', 'High'] else 'yellow'
                console.print(f"  [{color}]*[/{color}] {f['type']}: {f.get('pattern', '')} ({sev})")
                if f.get('js_file'):
                    console.print(f"      JS: {f['js_file'][:80]}")
        else:
            console.print(f"[green][+] No DOM XSS detected ({result.get('tested', 0)} JS files analyzed)[/green]")

    def _scan_reverse_ip(self):
        """Scan 58: Reverse IP Lookup"""
        console.print(f"\n[bold cyan][*] Reverse IP Lookup for {self.target}[/bold cyan]")
        with console.status("[bold magenta]Finding domains on same IP...[/bold magenta]"):
            result = self.v3_security.reverse_ip_lookup(self.target)
        self.results['findings']['reverse_ip'] = result
        if result.get('ip'):
            console.print(f"  [cyan]IP: {result['ip']}[/cyan]")
        if result.get('domains'):
            console.print(f"  [green]Found {result['total']} domains on same IP:[/green]")
            for domain in result['domains'][:20]:
                console.print(f"    - {domain}")
            if result['total'] > 20:
                console.print(f"    ... and {result['total'] - 20} more")
        else:
            console.print("[yellow][!] No co-hosted domains found[/yellow]")

    def _scan_dns_zone_transfer(self):
        """Scan 59: DNS Zone Transfer Test"""
        console.print(f"\n[bold red][*] DNS Zone Transfer Test on {self.target}[/bold red]")
        with console.status("[bold magenta]Testing AXFR on nameservers...[/bold magenta]"):
            result = self.v3_security.test_dns_zone_transfer(self.target)
        self.results['findings']['dns_zone_transfer'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!!!] DNS ZONE TRANSFER VULNERABLE![/bold red]")
            console.print(f"  [red]Dumped {result.get('total_records', 0)} DNS records![/red]")
            for rec in result.get('records', [])[:15]:
                console.print(f"    {rec.get('name', '')} [{rec.get('type', '')}] -> {str(rec.get('value', ''))[:60]}")
        else:
            console.print(f"[green][+] Zone transfer properly denied ({result.get('tested', 0)} nameservers tested)[/green]")
            for ns in result.get('nameservers', []):
                console.print(f"    NS: {ns}")

    def _scan_cache_deception(self):
        """Scan 60: Web Cache Deception"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold red][*] Web Cache Deception Test on {self.target}[/bold red]")
        with console.status("[bold magenta]Testing cache deception variations...[/bold magenta]"):
            result = self.v3_security.scan_cache_deception(url)
        self.results['findings']['cache_deception'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Web Cache Deception Detected![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]*[/red] {f['type']}: {f.get('test_url', '')[:80]}")
                console.print(f"      Similarity: {f.get('similarity', '')} | Severity: {f.get('severity', '')}")
        else:
            console.print(f"[green][+] No cache deception detected ({result.get('tested', 0)} tests)[/green]")

    def _scan_clickjacking(self):
        """Scan 61: Clickjacking Detector"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] Clickjacking Test on {self.target}[/bold cyan]")
        with console.status("[bold magenta]Testing framing protections...[/bold magenta]"):
            result = self.v3_security.scan_clickjacking(url)
        self.results['findings']['clickjacking'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Clickjacking Vulnerability Detected![/bold red]")
            for f in result.get('findings', []):
                if 'PoC' in f.get('type', ''):
                    console.print(f"  [yellow]*[/yellow] {f['type']} - save as HTML and test")
                else:
                    console.print(f"  [red]*[/red] {f['type']} - {f.get('note', '')}")
        else:
            console.print("[green][+] Clickjacking properly protected[/green]")

    def _scan_csp(self):
        """Scan 62: CSP Analyzer"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] CSP Analysis on {self.target}[/bold cyan]")
        with console.status("[bold magenta]Analyzing Content-Security-Policy...[/bold magenta]"):
            result = self.v3_security.analyze_csp(url)
        self.results['findings']['csp'] = result
        if result.get('findings'):
            console.print("[bold yellow][*] CSP Issues Found:[/bold yellow]")
            for f in result.get('findings', []):
                sev = f.get('severity', 'Medium')
                color = 'red' if sev in ['Critical', 'High'] else 'yellow' if sev == 'Medium' else 'cyan'
                console.print(f"  [{color}]*[/{color}] {f['type']} - {f.get('note', '')}")
        else:
            console.print("[green][+] CSP is properly configured[/green]")

    def _scan_account_takeover(self):
        """Scan 63: Account Takeover Suite"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold red][*] Account Takeover Test on {self.target}[/bold red]")
        with console.status("[bold magenta]Testing ATO vectors...[/bold magenta]"):
            result = self.v3_security.scan_account_takeover(url)
        self.results['findings']['account_takeover'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Account Takeover Vector Detected![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Medium')
            color = 'red' if sev in ['Critical', 'High'] else 'yellow'
            console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
            console.print(f"      {f.get('note', '')}")

    def _scan_oauth(self):
        """Scan 64: OAuth/SSO Misconfig Scanner"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold red][*] OAuth/SSO Misconfig Scan on {self.target}[/bold red]")
        with console.status("[bold magenta]Testing OAuth implementations...[/bold magenta]"):
            result = self.v3_security.scan_oauth_misconfig(url)
        self.results['findings']['oauth'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] OAuth Misconfiguration Detected![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Info')
            color = 'red' if sev in ['Critical', 'High'] else 'yellow' if sev == 'Medium' else 'cyan'
            console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
            console.print(f"      {f.get('note', '')}")

    def _scan_http_method(self):
        """Scan 65: HTTP Method Tampering"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] HTTP Method Tampering Test on {self.target}[/bold cyan]")
        with console.status("[bold magenta]Testing HTTP methods...[/bold magenta]"):
            result = self.v3_security.scan_http_method_tampering(url)
        self.results['findings']['http_method'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] HTTP Method Tampering Detected![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Info')
            color = 'red' if sev in ['Critical', 'High'] else 'yellow' if sev == 'Medium' else 'cyan'
            console.print(f"  [{color}]*[/{color}] {f['type']}")
            if f.get('method'):
                console.print(f"      Method: {f.get('method', '')} | Status: {f.get('status', '')}")
            if f.get('note'):
                console.print(f"      {f['note']}")
        if not result.get('vulnerable') and not result.get('findings'):
            console.print(f"[green][+] No HTTP method tampering detected ({result.get('tested', 0)} tested)[/green]")

    def _scan_shodan_internetdb(self):
        """Scan 66: Shodan InternetDB Lookup"""
        console.print(f"\n[bold cyan][*] Shodan InternetDB Lookup for {self.target}[/bold cyan]")
        with console.status("[bold magenta]Querying Shodan InternetDB...[/bold magenta]"):
            result = self.v3_security.lookup_shodan_internetdb(self.target)
        self.results['findings']['shodan_internetdb'] = result
        if result.get('error'):
            console.print(f"[red][!] {result['error']}[/red]")
        else:
            if result.get('ip'):
                console.print(f"  [cyan]IP: {result['ip']}[/cyan]")
            if result.get('ports'):
                console.print(f"  [yellow]Open Ports: {', '.join(str(p) for p in result['ports'])}[/yellow]")
            if result.get('vulns'):
                console.print(f"  [red]Known Vulnerabilities ({len(result['vulns'])}):[/red]")
                for v in result['vulns'][:10]:
                    console.print(f"    - {v}")
            if result.get('hostnames'):
                console.print(f"  [cyan]Hostnames: {', '.join(result['hostnames'][:5])}[/cyan]")
            if result.get('cpes'):
                console.print(f"  [yellow]Software: {', '.join(result['cpes'][:5])}[/yellow]")

    def _scan_favicon_hash(self):
        """Scan 67: Favicon Hash Discovery"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] Favicon Hash Discovery for {self.target}[/bold cyan]")
        with console.status("[bold magenta]Calculating favicon hash...[/bold magenta]"):
            result = self.v3_security.discover_favicon_hash(url)
        self.results['findings']['favicon_hash'] = result
        if result.get('hash'):
            console.print(f"  [cyan]Hash: {result['hash']} ({result.get('hash_type', '')})[/cyan]")
            console.print(f"  [cyan]MD5: {result.get('md5', 'N/A')}[/cyan]")
            if result.get('favicon_url'):
                console.print(f"  [cyan]Favicon URL: {result['favicon_url']}[/cyan]")
            if result.get('related_domains'):
                console.print(f"  [yellow]Related Domains ({len(result['related_domains'])}):[/yellow]")
                for d in result['related_domains'][:10]:
                    console.print(f"    - {d}")
        else:
            console.print(f"[yellow][!] {result.get('error', 'Could not calculate favicon hash')}[/yellow]")

    def _scan_pastebin_dork(self):
        """Scan 68: Pastebin Dorking"""
        console.print(f"\n[bold cyan][*] Pastebin Dorking for {self.target}[/bold cyan]")
        with console.status("[bold magenta]Searching for leaked data...[/bold magenta]"):
            result = self.v3_security.dork_pastebin(self.target)
        self.results['findings']['pastebin_dork'] = result
        if result.get('findings'):
            console.print(f"[bold red][!] Found {result['total']} leaked entries![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]*[/red] {f.get('url', '')}")
                if f.get('sensitive_types'):
                    console.print(f"      Sensitive: {', '.join(f['sensitive_types'])} | Severity: {f.get('severity', '')}")
        else:
            console.print(f"[green][+] No leaked data found on paste sites[/green]")
        for source, count in result.get('sources', {}).items():
            console.print(f"  [cyan]Source {source}: {count} results[/cyan]")

    def _scan_url_shortener(self):
        """Scan 69: URL Shortener Discovery"""
        console.print(f"\n[bold cyan][*] URL Shortener Discovery for {self.target}[/bold cyan]")
        with console.status("[bold magenta]Finding shortened URLs...[/bold magenta]"):
            result = self.v3_security.discover_url_shorteners(self.target)
        self.results['findings']['url_shortener'] = result
        if result.get('expanded_urls'):
            console.print(f"  [green]Found {result['total_expanded']} shortened URLs pointing to target:[/green]")
            for item in result['expanded_urls'][:10]:
                console.print(f"    {item['short']} -> {item['expanded']}")
        if result.get('hidden_paths'):
            console.print(f"  [yellow]Hidden Paths Discovered ({len(result['hidden_paths'])}):[/yellow]")
            for path in result['hidden_paths'][:10]:
                console.print(f"    {path}")
        if not result.get('expanded_urls'):
            console.print("[green][+] No shortened URLs found[/green]")

    def _scan_security_robots(self):
        """Scan 70: Security.txt & Robots.txt & Sitemap Parser"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] Security.txt / Robots.txt / Sitemap for {self.target}[/bold cyan]")
        with console.status("[bold magenta]Parsing security files...[/bold magenta]"):
            result = self.v3_security.parse_security_robots_sitemap(url)
        self.results['findings']['security_robots'] = result
        # Security.txt
        if result.get('security_txt', {}).get('found'):
            console.print(f"  [green]security.txt: Found[/green]")
            for key in ['Contact', 'Expires', 'Preferred-Languages', 'Canonical']:
                if result['security_txt'].get(key):
                    console.print(f"    {key}: {result['security_txt'][key]}")
        else:
            console.print(f"  [yellow]security.txt: Not found[/yellow]")
        # Robots.txt
        if result.get('robots_txt', {}).get('found'):
            disallowed = result['robots_txt'].get('disallowed', [])
            console.print(f"  [green]robots.txt: Found ({len(disallowed)} disallowed paths)[/green]")
            for path in disallowed[:10]:
                console.print(f"    Disallow: {path}")
        else:
            console.print(f"  [yellow]robots.txt: Not found[/yellow]")
        # Sitemap
        if result.get('sitemap', {}).get('found'):
            total = result['sitemap'].get('total', 0)
            console.print(f"  [green]sitemap.xml: Found ({total} URLs)[/green]")
        else:
            console.print(f"  [yellow]sitemap.xml: Not found[/yellow]")
        # Findings
        for f in result.get('findings', []):
            console.print(f"  [yellow]*[/yellow] {f['type']} - {f.get('note', '')}")

    def _scan_blind_xss(self):
        """Scan 71: Blind XSS Scanner"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold red][*] Blind XSS Scan on {self.target}[/bold red]")
        with console.status("[bold magenta]Injecting blind XSS payloads...[/bold magenta]"):
            result = self.v3_security.scan_blind_xss(url)
        self.results['findings']['blind_xss'] = result
        if result.get('findings'):
            console.print(f"[bold yellow][*] Blind XSS Payloads Submitted ({result.get('tested', 0)} tests)[/bold yellow]")
            for f in result.get('findings', []):
                sev = f.get('severity', 'Medium')
                color = 'red' if sev == 'High' else 'yellow'
                console.print(f"  [{color}]*[/{color}] {f['type']} ({f.get('method', '')} to {f.get('url', '')[:60]})")
                console.print(f"      {f.get('note', '')}")
        else:
            console.print(f"[green][+] No forms found for blind XSS injection[/green]")

    def _scan_websocket(self):
        """Scan 72: WebSocket Security Tester"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] WebSocket Security Test on {self.target}[/bold cyan]")
        with console.status("[bold magenta]Testing WebSocket endpoints...[/bold magenta]"):
            result = self.v3_security.scan_websocket(url)
        self.results['findings']['websocket'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] WebSocket Vulnerability Detected![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Info')
            color = 'red' if sev in ['Critical', 'High'] else 'yellow' if sev == 'Medium' else 'cyan'
            console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
            console.print(f"      {f.get('note', '')}")

    def _scan_2fa_bypass(self):
        """Scan 73: 2FA Bypass Tester"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold red][*] 2FA Bypass Test on {self.target}[/bold red]")
        with console.status("[bold magenta]Testing 2FA bypass vectors...[/bold magenta]"):
            result = self.v3_security.scan_2fa_bypass(url)
        self.results['findings']['2fa_bypass'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] 2FA Bypass Possible![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Info')
            color = 'red' if sev in ['Critical', 'High'] else 'yellow' if sev == 'Medium' else 'cyan'
            console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
            console.print(f"      {f.get('note', '')}")

    def _scan_mixed_content(self):
        """Scan 74: Mixed Content Scanner"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] Mixed Content Scan on {self.target}[/bold cyan]")
        with console.status("[bold magenta]Checking for mixed content...[/bold magenta]"):
            result = self.v3_security.scan_mixed_content(url)
        self.results['findings']['mixed_content'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Mixed Content Detected![/bold red]")
            for f in result.get('active', []):
                console.print(f"  [red]*[/red] Active: {f.get('tag', '')} -> {f.get('url', '')[:60]}")
            for f in result.get('passive', []):
                console.print(f"  [yellow]*[/yellow] Passive: {f.get('tag', '')} -> {f.get('url', '')[:60]}")
        else:
            total = result.get('total_passive', 0) + result.get('total_active', 0)
            console.print(f"[green][+] No mixed content issues ({total} found)[/green]")

    def _scan_info_disclosure(self):
        """Scan 75: Information Disclosure Hunter"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold red][*] Information Disclosure Scan on {self.target}[/bold red]")
        with console.status("[bold magenta]Hunting for information disclosure...[/bold magenta]"):
            result = self.v3_security.scan_info_disclosure(url)
        self.results['findings']['info_disclosure'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Information Disclosure Detected![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Medium')
            color = 'red' if sev in ['Critical', 'High'] else 'yellow' if sev == 'Medium' else 'cyan'
            console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
            if f.get('url'):
                console.print(f"      URL: {f['url'][:80]}")
            if f.get('header'):
                console.print(f"      {f['header']}: {f.get('value', '')}")
            if f.get('note'):
                console.print(f"      {f['note']}")
        if not result.get('vulnerable') and not result.get('findings'):
            console.print(f"[green][+] No information disclosure detected ({result.get('tested', 0)} tests)[/green]")

    # ========================================================================
    # V4.0 HUNTING MODULE SCAN IMPLEMENTATIONS (76-83)
    # ========================================================================

    def _scan_username_enum(self):
        """Scan 76: Username Enumeration Scanner"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] Username Enumeration Scan on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Testing for username enumeration vulnerabilities...[/bold cyan]"):
            result = self.v4_hunting.scan_username_enum(url)
        self.results['findings']['username_enum'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Username Enumeration Detected![/bold red]")
            e_table = Table(title="Confirmed Valid Usernames", box=box.HEAVY, border_style="red")
            e_table.add_column("Username", style="red")
            e_table.add_column("Evidence", style="yellow")
            for finding in result.get('findings', []):
                e_table.add_row(
                    finding.get('username', ''),
                    finding.get('evidence', '')[:60]
                )
            console.print(e_table)
        else:
            console.print(f"[green][+] No username enumeration detected ({result.get('tested', 0)} usernames tested)[/green]")

    def _scan_email_security(self):
        """Scan 77: DMARC/DKIM/SPF Email Security Checker"""
        console.print(f"\n[bold cyan][*] Email Security (DMARC/DKIM/SPF) Check on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Checking email security records...[/bold cyan]"):
            result = self.v4_hunting.scan_email_security(self.target)
        self.results['findings']['email_security'] = result

        # Display DMARC
        dmarc = result.get('dmarc', {})
        dmarc_status = dmarc.get('status', 'unknown')
        console.print(f"\n[bold]DMARC:[/bold] {'[red]MISSING[/red]' if dmarc_status == 'missing' else '[green]' + dmarc_status + '[/green]'}")
        if dmarc.get('policy'):
            console.print(f"  Policy: {dmarc['policy']}")

        # Display SPF
        spf = result.get('spf', {})
        spf_status = spf.get('status', 'unknown')
        console.print(f"[bold]SPF:[/bold] {'[red]MISSING[/red]' if spf_status == 'missing' else '[green]' + spf_status + '[/green]'}")
        if spf.get('all_mechanism'):
            console.print(f"  All Mechanism: {spf['all_mechanism']}")

        # Display DKIM
        dkim = result.get('dkim', {})
        dkim_found = dkim.get('selectors_found', [])
        console.print(f"[bold]DKIM:[/bold] {len(dkim_found)} selectors found ({dkim.get('tested', 0)} tested)")

        # Risk score
        risk = result.get('risk_score', 0)
        risk_color = 'red' if risk >= 70 else 'yellow' if risk >= 40 else 'green'
        console.print(f"\n[bold]Email Spoofing Risk Score: [{risk_color}]{risk}/100[/{risk_color}][/bold]")
        console.print(f"[bold]Risk Level: [{risk_color}]{result.get('risk_level', 'Unknown')}[/{risk_color}][/bold]")

    def _scan_csrf(self):
        """Scan 78: CSRF Token Detection & Login CSRF Tester"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] CSRF Detection on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Testing for CSRF vulnerabilities...[/bold cyan]"):
            result = self.v4_hunting.scan_csrf(url)
        self.results['findings']['csrf'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] CSRF Vulnerability Detected![/bold red]")
            for f in result.get('findings', []):
                sev = f.get('severity', 'Medium')
                color = 'red' if sev in ['Critical', 'High'] else 'yellow'
                console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
                if f.get('note'):
                    console.print(f"      {f['note']}")
            if result.get('poc_html'):
                console.print("\n[bold yellow][!] CSRF PoC HTML generated - saved in report[/bold yellow]")
        else:
            console.print(f"[green][+] No CSRF vulnerabilities detected ({result.get('tested', 0)} forms tested)[/green]")

    def _scan_framework(self):
        """Scan 79: Framework Detection + Specific Attacks"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] Framework Detection on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Detecting frameworks and testing framework-specific attacks...[/bold cyan]"):
            result = self.v4_hunting.scan_framework(url)
        self.results['findings']['framework'] = result

        # Display detected frameworks
        framework_names = result.get('detected_frameworks', result.get('frameworks_detected', []))
        framework_details = result.get('framework_details', {})
        if framework_names:
            fw_table = Table(title="Detected Frameworks", box=box.ROUNDED, border_style="cyan")
            fw_table.add_column("Framework", style="cyan")
            fw_table.add_column("Version", style="yellow")
            fw_table.add_column("Evidence", style="green")
            for fw_name in framework_names:
                detail = framework_details.get(fw_name, {})
                fw_table.add_row(
                    fw_name,
                    detail.get('version', 'Unknown'),
                    ', '.join(detail.get('detection_methods', ['detected']))[:60]
                )
            console.print(fw_table)
        else:
            console.print("[yellow][!] No frameworks detected on main page (try scan on login portals)[/yellow]")

        # Display framework-specific findings
        findings = result.get('findings', [])
        if findings:
            console.print("\n[bold red]Framework-Specific Findings:[/bold red]")
            for f in findings:
                sev = f.get('severity', 'Medium')
                color = 'red' if sev in ['Critical', 'High'] else 'yellow'
                console.print(f"  [{color}]*[/{color}] {f['type']} - {f.get('note', '')[:80]}")

    def _scan_js_libraries(self):
        """Scan 80: Client-Side JS Library Vulnerability Scanner"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] Client-Side JS Library Vulnerability Scan on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Scanning JavaScript libraries for known vulnerabilities...[/bold cyan]"):
            result = self.v4_hunting.scan_js_libraries(url)
        self.results['findings']['js_libraries'] = result

        # Display detected libraries
        libs = result.get('libraries_found', result.get('libraries_detected', []))
        if libs:
            lib_table = Table(title="Detected JS Libraries", box=box.ROUNDED, border_style="cyan")
            lib_table.add_column("Library", style="cyan")
            lib_table.add_column("Version", style="yellow")
            lib_table.add_column("Status", style="green")
            for lib in libs:
                status = "[red]Vulnerable[/red]" if lib.get('vulnerable') else "[green]OK[/green]"
                lib_table.add_row(lib.get('name', ''), lib.get('version', '?'), status)
            console.print(lib_table)

        # Display vulnerabilities
        if result.get('vulnerable'):
            console.print("\n[bold red]Vulnerable JS Libraries Found![/bold red]")
            for f in result.get('findings', []):
                sev = f.get('severity', 'Medium')
                color = 'red' if sev in ['Critical', 'High'] else 'yellow'
                console.print(f"  [{color}]*[/{color}] {f['type']} - Severity: {sev}")
                console.print(f"      {f.get('note', '')[:80]}")
        else:
            console.print(f"[green][+] No vulnerable JS libraries detected ({result.get('tested', 0)} checked)[/green]")

    def _scan_403_bypass(self):
        """Scan 81: 403 Bypass Tester"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] 403 Bypass Test on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Testing 403 bypass techniques...[/bold cyan]"):
            result = self.v4_hunting.scan_403_bypass(url)
        self.results['findings']['403_bypass'] = result

        if result.get('bypassed'):
            console.print("[bold red][!] 403 Bypass Found![/bold red]")
            b_table = Table(title="Successful 403 Bypasses", box=box.HEAVY, border_style="red")
            b_table.add_column("Technique", style="red")
            b_table.add_column("Status", style="yellow")
            b_table.add_column("Size", style="cyan")
            for f in result.get('findings', []):
                b_table.add_row(
                    f.get('technique', ''),
                    str(f.get('status', '')),
                    str(f.get('size', ''))
                )
            console.print(b_table)
        else:
            console.print(f"[green][+] No 403 bypass found ({result.get('tested', 0)} techniques tested)[/green]")

    def _scan_cross_domain(self):
        """Scan 82: Cross-Domain Discovery"""
        console.print(f"\n[bold cyan][*] Cross-Domain Discovery on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Finding sibling domains on same IP...[/bold cyan]"):
            result = self.v4_hunting.scan_cross_domain(self.target)
        self.results['findings']['cross_domain'] = result

        domains = result.get('domains', [])
        if domains:
            cd_table = Table(title=f"Domains on Same IP ({result.get('ip', '')})", box=box.ROUNDED, border_style="yellow")
            cd_table.add_column("Domain", style="cyan")
            cd_table.add_column("Title", style="yellow")
            cd_table.add_column("Server", style="green")
            for d in domains:
                cd_table.add_row(
                    d.get('domain', ''),
                    d.get('title', '')[:40],
                    d.get('server', '')[:30]
                )
            console.print(cd_table)
        else:
            console.print(f"[yellow][!] No sibling domains found ({result.get('tested', 0)} checked)[/yellow]")

        if result.get('findings'):
            console.print("\n[bold red]Cross-Domain Findings:[/bold red]")
            for f in result['findings']:
                console.print(f"  [red]*[/red] {f.get('type', '')} - {f.get('note', '')[:80]}")

    def _scan_cve_lookup(self):
        """Scan 83: CVE-to-Exploit Lookup Engine"""
        url = f"{self.protocol}{self.target}"
        console.print(f"\n[bold cyan][*] CVE-to-Exploit Lookup on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Looking up CVEs and exploits...[/bold cyan]"):
            result = self.v4_hunting.scan_cve_lookup(url)
        self.results['findings']['cve_lookup'] = result

        cve_groups = result.get('cve_groups', {})
        techs = result.get('technologies', [])

        if techs:
            console.print(f"\n[bold]Detected Technologies for CVE Lookup:[/bold]")
            for t in techs:
                console.print(f"  [cyan]*[/cyan] {t.get('name', '')} {t.get('version', '')}")

        total_cves = result.get('total_cves', 0)
        if total_cves > 0:
            console.print(f"\n[bold red]Total CVEs Found: {total_cves}[/bold red]")

            for severity in ['Critical', 'High', 'Medium', 'Low']:
                cves = cve_groups.get(severity, [])
                if cves:
                    color = 'red' if severity in ['Critical', 'High'] else 'yellow'
                    console.print(f"\n[bold {color}]{severity} ({len(cves)} CVEs):[/{color}]")
                    for cve in cves[:10]:
                        cve_id = cve.get('id', '')
                        cvss = cve.get('cvss', 'N/A')
                        desc = cve.get('description', '')[:80]
                        exploitable = '[red]EXPLOIT[/red]' if cve.get('exploitable') else ''
                        console.print(f"  [{color}]*[/{color}] {cve_id} (CVSS: {cvss}) {exploitable}")
                        console.print(f"      {desc}")
        else:
            console.print("[green][+] No critical CVEs found for detected technologies[/green]")

    # ====================================================================
    # V5.0 ASYNC ENGINE SCAN IMPLEMENTATIONS
    # ====================================================================

    def _scan_subdomain_brute(self):
        """Scan 84: Subdomain Brute Force (Active DNS + Wordlist)"""
        console.print(f"\n[bold cyan][*] Subdomain Brute Force on {self.target}[/bold cyan]")

        # Show wordlist stats
        wl_stats = self.v5_async.get_wordlist_stats()
        subdomain_count = wl_stats.get('subdomains', 0)
        console.print(f"[cyan]    Wordlist: {subdomain_count} subdomain names loaded[/cyan]")

        with console.status(f"[bold cyan]Resolving {subdomain_count} subdomains via DNS...[/bold cyan]"):
            result = self.v5_async.scan_subdomain_bruteforce(self.target)

        self.results['findings']['subdomain_brute'] = result

        found = result.get('found', [])
        if found:
            s_table = Table(
                title=f"[bold green]Subdomains Found: {len(found)}[/bold green] ({result.get('time_taken', 0)}s)",
                box=box.ROUNDED, border_style="green"
            )
            s_table.add_column("#", style="dim")
            s_table.add_column("Subdomain", style="cyan")
            s_table.add_column("IP", style="yellow")
            s_table.add_column("Reverse DNS", style="green")
            for i, sub in enumerate(found, 1):
                s_table.add_row(str(i), sub['subdomain'], sub['ip'],
                               sub.get('reverse_dns', '')[:40])
            console.print(s_table)
            console.print(f"\n[cyan]Tested: {result['tested']} | Resolved: {result['resolved']} | "
                         f"Time: {result['time_taken']}s[/cyan]")
        else:
            console.print(f"[yellow][!] No subdomains resolved from {subdomain_count} names[/yellow]")
            console.print(f"[cyan]    Tested: {result['tested']} | Time: {result['time_taken']}s[/cyan]")

    def _scan_dir_brute_async(self):
        """Scan 85: Directory Brute Force (Async High-Speed)"""
        console.print(f"\n[bold cyan][*] Async Directory Brute Force on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"

        # Show wordlist stats
        wl_stats = self.v5_async.get_wordlist_stats()
        dir_count = wl_stats.get('directories', 0)
        console.print(f"[cyan]    Wordlist: {dir_count} paths loaded | Async mode[/cyan]")

        with console.status(f"[bold cyan]Scanning {dir_count} paths at high speed...[/bold cyan]"):
            result = self.v5_async.scan_dir_bruteforce_async(url)

        self.results['findings']['dir_brute_async'] = result

        found = result.get('found', [])
        if found:
            d_table = Table(
                title=f"[bold]Paths Found: {len(found)}[/bold] ({result.get('time_taken', 0)}s)",
                box=box.ROUNDED, border_style="cyan"
            )
            d_table.add_column("#", style="dim")
            d_table.add_column("Path", style="yellow")
            d_table.add_column("Status", style="green")
            d_table.add_column("Size", style="cyan")
            for i, item in enumerate(found[:150], 1):
                status = item.get('status', 0)
                status_color = "green" if status == 200 else "yellow" if status in [301, 302] else "red"
                size = str(item.get('size', ''))
                d_table.add_row(str(i), item.get('path', ''),
                               f"[{status_color}]{status}[/{status_color}]", size)
            console.print(d_table)
            if len(found) > 150:
                console.print(f"[yellow]... and {len(found) - 150} more paths[/yellow]")
            console.print(f"\n[cyan]Scanned: {result['tested']} | Found: {len(found)} | "
                         f"Time: {result['time_taken']}s[/cyan]")
        else:
            console.print(f"[yellow][!] No accessible paths found[/yellow]")
            console.print(f"[cyan]    Scanned: {result['tested']} | Time: {result['time_taken']}s[/cyan]")

    def _scan_smart(self):
        """Scan 86: AI Smart Scan (Gemini-Guided Auto Recon)"""
        console.print(f"\n[bold magenta][*] AI Smart Scan on {self.target}[/bold magenta]")

        gemini_configured = bool(self.ai.gemini_api_key)
        if gemini_configured:
            console.print("[magenta]    Gemini AI: Connected[/magenta]")
        else:
            console.print("[yellow]    Gemini AI: Not configured (use 'config' to set key)[/yellow]")
            console.print("[yellow]    Running basic smart scan without AI...[/yellow]")

        with console.status("[bold magenta]Running AI-guided smart scan...[/bold magenta]"):
            result = self.v5_async.scan_smart(
                self.target,
                ai_bridge=self.ai if gemini_configured else None
            )

        self.results['findings']['smart_scan'] = result

        # Display Phase 1: Quick Recon results
        phases = result.get('phases', [])
        for phase in phases:
            findings = phase.get('findings', {})
            if findings:
                p_table = Table(
                    title=f"[bold]{phase['name']} Results[/bold]",
                    box=box.ROUNDED, border_style="cyan"
                )
                p_table.add_column("Property", style="yellow")
                p_table.add_column("Value", style="green")
                for key, val in findings.items():
                    if isinstance(val, (str, int, float, bool)):
                        p_table.add_row(key, str(val))
                    elif isinstance(val, list) and len(val) < 10:
                        p_table.add_row(key, ', '.join(str(v) for v in val))
                    elif isinstance(val, dict):
                        p_table.add_row(key, f"{len(val)} items")
                console.print(p_table)

        # Display AI Recommendations
        ai_recs = result.get('ai_recommendations')
        if ai_recs:
            console.print(Panel(
                ai_recs,
                title="[bold magenta]AI Recommendations[/bold magenta]",
                border_style="magenta"
            ))

        # Display recommended next scans
        recs = result.get('summary', {}).get('recommended_next_scans', [])
        if recs:
            r_table = Table(
                title="[bold yellow]Recommended Next Scans[/bold yellow]",
                box=box.ROUNDED, border_style="yellow"
            )
            r_table.add_column("Scan ID", style="cyan")
            r_table.add_column("Name", style="green")
            r_table.add_column("Reason", style="yellow")
            for rec in recs:
                r_table.add_row(rec['scan_id'], rec['name'], rec['reason'][:60])
            console.print(r_table)

    # ========================================================================
    # SCAN 87: AI VULNERABILITY TRIAGE
    # ========================================================================

    def _scan_ai_triage(self):
        """Scan 87: AI Vulnerability Triage - Classify & Prioritize findings"""
        console.print(f"\n[bold magenta][*] AI Vulnerability Triage on {self.target}[/bold magenta]")

        if not self.ai.gemini_api_key:
            console.print("[bold yellow][!] Gemini API key not configured. Use 'config' command.[/bold yellow]")
            return

        if not self.results or not self.results.get('findings'):
            console.print("[bold yellow][!] Run some scans first to generate findings for triage[/bold yellow]")
            console.print("[cyan]    Tip: Run scans 0, 7, 9, 10, 11 first, then use scan 87[/cyan]")
            return

        findings_list = []
        for category, data in self.results.get('findings', {}).items():
            findings_list.append({'category': category, 'data': str(data)[:500]})

        with console.status("[bold magenta]Gemini AI is triaging vulnerabilities...[/bold magenta]"):
            triage_result = self.ai.ai_triage(self.target, findings_list)

        if triage_result:
            self.results['findings']['ai_triage'] = triage_result
            console.print(Panel(
                triage_result,
                title="[bold magenta]AI Triage Results[/bold magenta]",
                border_style="magenta"
            ))
        else:
            console.print("[bold yellow][!] AI triage unavailable - check API key[/bold yellow]")

    # ========================================================================
    # SCAN 88: AI RECON ADVISOR
    # ========================================================================

    def _scan_ai_recon_advisor(self):
        """Scan 88: AI Recon Advisor - Strategy suggestions based on recon data"""
        console.print(f"\n[bold magenta][*] AI Recon Advisor for {self.target}[/bold magenta]")

        if not self.ai.gemini_api_key:
            console.print("[bold yellow][!] Gemini API key not configured. Use 'config' command.[/bold yellow]")
            return

        # Run quick recon first
        recon_data = {}
        with console.status("[bold cyan]Gathering recon data for AI analysis...[/bold cyan]"):
            try:
                import socket
                ip = socket.gethostbyname(self.target)
                recon_data['ip'] = ip
            except Exception:
                pass

            try:
                resp = self.session.get(f"https://{self.target}", timeout=10, verify=False)
                recon_data['status'] = resp.status_code
                recon_data['server'] = resp.headers.get('Server', 'Unknown')
                recon_data['headers'] = dict(list(resp.headers.items())[:20])
                
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, 'html.parser')
                title = soup.find('title')
                if title:
                    recon_data['title'] = title.string or ''
                js_files = [s.get('src', '') for s in soup.find_all('script', src=True)]
                recon_data['js_count'] = len(js_files)
            except Exception as e:
                recon_data['http_error'] = str(e)[:100]

            # Quick DNS
            try:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                a_records = resolver.resolve(self.target, 'A')
                recon_data['dns_a'] = [str(r) for r in a_records]
            except Exception:
                pass

        # Get AI advice
        with console.status("[bold magenta]Gemini AI is analyzing recon strategy...[/bold magenta]"):
            advisor_result = self.ai.ai_recon_advisor(self.target, recon_data)

        if advisor_result:
            self.results['findings']['ai_recon_advisor'] = advisor_result
            console.print(Panel(
                advisor_result,
                title="[bold magenta]AI Recon Strategy[/bold magenta]",
                border_style="magenta"
            ))
        else:
            console.print("[bold yellow][!] AI advisor unavailable - check API key[/bold yellow]")

    # ========================================================================
    # AI COMMAND HANDLERS
    # ========================================================================

    def _ai_payload_gen(self):
        """AI-powered payload generation"""
        if not self.ai.gemini_api_key:
            console.print("[bold yellow][!] Gemini API key not configured. Use 'config' command.[/bold yellow]")
            return

        vuln_type = Prompt.ask("[bold cyan]Vulnerability type (sqli/xss/ssrf/ssti/lfi/rce/etc)[/bold cyan]")
        context = Prompt.ask("[bold cyan]Context (URL, tech stack, etc.)[/bold cyan]", default=self.target or "")

        console.print(f"\n[bold magenta][*] Generating {vuln_type} payloads...[/bold magenta]")
        with console.status("[bold magenta]Gemini AI is crafting payloads...[/bold magenta]"):
            result = self.ai.ai_generate_payload(vuln_type, context)

        if result:
            console.print(Panel(
                result,
                title=f"[bold magenta]AI-Generated {vuln_type.upper()} Payloads[/bold magenta]",
                border_style="magenta"
            ))
        else:
            console.print("[bold yellow][!] Payload generation unavailable[/bold yellow]")

    def _ai_triage_cmd(self):
        """AI triage command handler"""
        self._scan_ai_triage()

    def _ai_test(self):
        """Test Gemini API connection"""
        console.print("\n[bold cyan][*] Testing Gemini API connection...[/bold cyan]")
        success, message = self.ai.test_connection()
        if success:
            console.print(f"[bold green][+] {message}[/bold green]")
        else:
            console.print(f"[bold red][!] Connection failed: {message}[/bold red]")

    def _show_perf_stats(self):
        """Display performance statistics"""
        console.print("\n[bold cyan][*] Performance Statistics[/bold cyan]")

        stats = get_performance_stats()

        perf_table = Table(
            title="Performance Engine Stats",
            box=box.DOUBLE, border_style="cyan"
        )
        perf_table.add_column("Component", style="yellow")
        perf_table.add_column("Metric", style="cyan")
        perf_table.add_column("Value", style="green")

        # DNS Cache
        dns = stats.get('dns_cache', {})
        perf_table.add_row("DNS Cache", "Entries", str(dns.get('entries', 0)))
        perf_table.add_row("DNS Cache", "Hit Rate", str(dns.get('hit_rate', '0%')))
        perf_table.add_row("DNS Cache", "Hits", str(dns.get('hits', 0)))
        perf_table.add_row("DNS Cache", "Misses", str(dns.get('misses', 0)))

        # Session
        perf_table.add_row("HTTP Session", "Total Requests", str(stats.get('session_requests', 0)))

        # Threading
        threading_stats = stats.get('threading', {})
        perf_table.add_row("Threading", "Current Threads", str(threading_stats.get('current_threads', 0)))
        perf_table.add_row("Threading", "Success Count", str(threading_stats.get('success_count', 0)))
        perf_table.add_row("Threading", "Error Count", str(threading_stats.get('error_count', 0)))
        perf_table.add_row("Threading", "Avg Response", str(threading_stats.get('avg_response_time', 'N/A')))

        # Timeout
        timeout_stats = stats.get('timeout', {})
        perf_table.add_row("Timeout", "Current", str(timeout_stats.get('current_timeout', '10s')))
        perf_table.add_row("Timeout", "Samples", str(timeout_stats.get('samples', 0)))

        console.print(perf_table)

        # AI Status
        ai_status = self.ai.get_status()
        ai_table = Table(
            title="AI Bridge Status",
            box=box.ROUNDED, border_style="magenta"
        )
        ai_table.add_column("Property", style="yellow")
        ai_table.add_column("Value", style="green")

        ai_table.add_row("Provider", ai_status.get('provider', 'N/A'))
        ai_table.add_row("Model", ai_status.get('model', 'N/A'))
        ai_table.add_row("Fallback Model", ai_status.get('fallback_model', 'N/A'))
        ai_table.add_row("API Key Set", "Yes" if ai_status.get('api_key_set') else "No")
        ai_table.add_row("Total AI Requests", str(ai_status.get('total_requests', 0)))
        ai_table.add_row("Last Error", str(ai_status.get('last_error', 'None')))

        console.print(ai_table)

    def run_ai_analysis(self):
        """AI-powered vulnerability analysis"""
        if not self.results or not self.results.get('findings'):
            console.print("[bold yellow][!] Run a scan first before AI analysis[/bold yellow]")
            return

        gemini_configured = bool(self.ai.gemini_api_key)
        if not gemini_configured:
            console.print("[bold yellow][!] Gemini API key not configured. Use 'config' command to set it.[/bold yellow]")
            console.print("[cyan]    Set key: gemini_api_key = YOUR_KEY[/cyan]")

        console.print("\n[bold magenta][*] AI-Powered Vulnerability Analysis[/bold magenta]")
        with console.status("[bold magenta]Gemini AI is analyzing scan results...[/bold magenta]"):
            analysis = self.ai.analyze_results(self.results)

        if analysis:
            console.print(Panel(
                analysis.get('summary', 'No analysis available'),
                title="[bold magenta]Gemini AI Analysis[/bold magenta]",
                border_style="magenta"
            ))
        else:
            console.print("[bold yellow][!] AI analysis unavailable - check API key configuration[/bold yellow]")
    
    def run(self):
        """Main ZYLON FUSION loop"""
        self.ui.display_banner()
        
        while True:
            try:
                console.print("\n[bold red]ZYLON[/bold red] [bold yellow]>[/bold yellow] ", end="")
                user_input = input().strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['exit', 'quit', 'q']:
                    console.print("[bold red][*] ZYLON FUSION signing off... Stay sharp![/bold red]")
                    break
                
                elif user_input.lower() == 'help':
                    self.ui.display_help()
                
                elif user_input.lower() == 'fix':
                    install_requirements()
                
                elif user_input.lower() == 'update':
                    console.print("[cyan][*] Checking for updates...[/cyan]")
                
                elif user_input.lower() == 'config':
                    self._config_menu()
                
                elif user_input.lower() == 'report':
                    self._report_menu()
                
                elif user_input.lower() == 'ai':
                    self._ai_chat_mode()
                
                elif user_input.lower() == 'aianalyze':
                    self.run_ai_analysis()
                
                elif user_input.lower() == 'aireport':
                    self._ai_report()
                
                elif user_input.lower() == 'smart':
                    if not self.target:
                        target = Prompt.ask("[bold yellow]Enter target domain/IP[/bold yellow]")
                        success, msg = self.set_target(target)
                        if not success:
                            console.print(f"[bold red][!] {msg}[/bold red]")
                            continue
                        console.print(f"[green][+] {msg}[/green]")
                    self._scan_smart()
                    self.reports.save_json(self.results, self.target)
                
                elif user_input.lower() == 'wordlists':
                    self._show_wordlist_stats()
                
                elif user_input.lower() == 'aipayload':
                    self._ai_payload_gen()
                
                elif user_input.lower() == 'aitriage':
                    self._ai_triage_cmd()
                
                elif user_input.lower() == 'aitest':
                    self._ai_test()
                
                elif user_input.lower() == 'perf':
                    self._show_perf_stats()
                
                elif user_input.isdigit() and 0 <= int(user_input) <= 99:
                    if not self.target:
                        target = Prompt.ask("[bold yellow]Enter target domain/IP[/bold yellow]")
                        success, msg = self.set_target(target)
                        if not success:
                            console.print(f"[bold red][!] {msg}[/bold red]")
                            continue
                        console.print(f"[green][+] {msg}[/green]")
                    self.run_scan(user_input)
                
                else:
                    # Try to set as target
                    success, msg = self.set_target(user_input)
                    if success:
                        console.print(f"[green][+] {msg}[/green]")
                        # Ask for scan type
                        scan_type = Prompt.ask(
                            "[bold yellow]Select scan type (0-86, 99)[/bold yellow]",
                            default="0"
                        )
                        if scan_type.isdigit() and 0 <= int(scan_type) <= 99:
                            self.run_scan(scan_type)
                    else:
                        console.print(f"[bold red][!] {msg}[/bold red]")
                
            except KeyboardInterrupt:
                console.print("\n[bold yellow][!] Use 'exit' to quit[/bold yellow]")
            except EOFError:
                break
            except Exception as e:
                console.print(f"[bold red][!] Error: {str(e)}[/bold red]")
    
    def _config_menu(self):
        """Configuration menu for API keys"""
        console.print("\n[bold cyan][*] Configuration Manager[/bold cyan]")
        console.print("[cyan]Current API key status:[/cyan]")
        
        config_file = os.path.join(get_home(), '.zylon', 'config.json')
        config = {}
        if os.path.exists(config_file):
            with open(config_file) as f:
                config = json.load(f)
        
        keys = ['gemini_api_key', 'shodan_api_key', 'virustotal_api_key', 'hunter_api_key', 
                'securitytrails_api_key', 'censys_api_id', 'censys_api_secret',
                'github_api_key', 'ai_api_key']
        
        k_table = Table(box=box.ROUNDED, border_style="cyan")
        k_table.add_column("API Key", style="yellow")
        k_table.add_column("Status", style="green")
        for key in keys:
            val = config.get(key, '')
            status = "[green]Set[/green]" if val else "[red]Not Set[/red]"
            k_table.add_row(key, status)
        console.print(k_table)
        
        action = Prompt.ask("[yellow]Set API key? (y/n)[/yellow]", default="n")
        if action.lower() == 'y':
            key_name = Prompt.ask("[yellow]API key name (e.g. gemini_api_key)[/yellow]")
            key_val = Prompt.ask("[yellow]API key value[/yellow]")
            config[key_name] = key_val
            
            # Auto-configure Gemini
            if key_name == 'gemini_api_key':
                self.ai.set_gemini_key(key_val)
                console.print("[green][+] Gemini API key configured and saved![/green]")
            
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            console.print("[green][+] API key saved![/green]")
    
    def _report_menu(self):
        """Report viewing menu"""
        reports_dir = os.path.join(get_home(), '.zylon', 'reports')
        if os.path.exists(reports_dir):
            reports = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
            if reports:
                r_table = Table(title="Previous Scan Reports", box=box.ROUNDED)
                r_table.add_column("#", style="dim")
                r_table.add_column("Report", style="cyan")
                for i, r in enumerate(reports[-20:], 1):
                    r_table.add_row(str(i), r)
                console.print(r_table)
            else:
                console.print("[yellow][!] No reports found[/yellow]")
        else:
            console.print("[yellow][!] No reports directory found[/yellow]")

    def _ai_chat_mode(self):
        """Interactive AI chat mode using Gemini"""
        gemini_configured = bool(self.ai.gemini_api_key)
        if not gemini_configured:
            console.print("[bold yellow][!] Gemini API key not configured![/bold yellow]")
            console.print("[cyan]    Use 'config' command and set gemini_api_key[/cyan]")
            return

        console.print("\n[bold magenta]=== ZYLON AI Chat (Gemini) ===[/bold magenta]")
        console.print("[cyan]Type your security question. 'exit' to leave chat mode.[/cyan]")

        # Build context from current target
        context = ""
        if self.target:
            context = f"Current target: {self.target}"
            if self.results and self.results.get('findings'):
                context += f"\nScan results available: {list(self.results['findings'].keys())}"

        while True:
            try:
                console.print("[bold magenta]AI>[/bold magenta] ", end="")
                question = input().strip()
                if not question:
                    continue
                if question.lower() in ['exit', 'quit', 'q', 'back']:
                    break

                with console.status("[bold magenta]Gemini AI is thinking...[/bold magenta]"):
                    response = self.ai.ai_chat(question, context=context)

                console.print(Panel(response, title="[bold magenta]ZYLON AI[/bold magenta]",
                                   border_style="magenta"))

                # Update context with conversation
                context += f"\n\nQ: {question}\nA: {response[:200]}"

            except KeyboardInterrupt:
                break
            except EOFError:
                break

    def _ai_report(self):
        """Generate AI-powered bug bounty report"""
        if not self.results or not self.results.get('findings'):
            console.print("[bold yellow][!] Run a scan first before generating report[/bold yellow]")
            return

        gemini_configured = bool(self.ai.gemini_api_key)
        if not gemini_configured:
            console.print("[bold yellow][!] Gemini API key not configured. Use 'config' command.[/bold yellow]")
            return

        console.print("\n[bold magenta][*] AI-Powered Bug Bounty Report Generation[/bold magenta]")
        with console.status("[bold magenta]Gemini AI is writing your report...[/bold magenta]"):
            report = self.ai.ai_write_report(self.target, self.results.get('findings', {}))

        if report:
            console.print(Panel(report, title="[bold magenta]Bug Bounty Report[/bold magenta]",
                              border_style="magenta"))

            # Save report to file
            report_dir = os.path.join(get_home(), '.zylon', 'reports')
            os.makedirs(report_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(report_dir, f"ai_report_{self.target}_{timestamp}.md")
            with open(report_file, 'w') as f:
                f.write(f"# Bug Bounty Report - {self.target}\n\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n\n")
                f.write(report)
            console.print(f"\n[green][+] Report saved to: {report_file}[/green]")
        else:
            console.print("[bold yellow][!] Report generation failed[/bold yellow]")

    def _show_wordlist_stats(self):
        """Show built-in wordlist statistics"""
        console.print("\n[bold cyan][*] Built-in Wordlist Statistics[/bold cyan]")

        stats = self.v5_async.get_wordlist_stats()

        wl_table = Table(
            title="[bold]ZYLON Wordlists[/bold]",
            box=box.ROUNDED, border_style="cyan"
        )
        wl_table.add_column("Wordlist", style="yellow")
        wl_table.add_column("Entries", style="green")
        wl_table.add_column("Used By", style="cyan")

        wl_usage = {
            'directories': 'Scan 11, 85 (Dir Brute)',
            'subdomains': 'Scan 84 (Subdomain Brute)',
            'usernames': 'Scan 76 (Username Enum)',
            'passwords': 'Login brute force',
            'jwt_secrets': 'Scan 40 (JWT Scanner)',
            'ssrf_payloads': 'Scan 30 (SSRF)',
            'lfi_payloads': 'Scan 32 (LFI)',
        }

        for name, count in stats.items():
            usage = wl_usage.get(name, 'Various')
            count_str = str(count) if count > 0 else "[red]Not loaded[/red]"
            wl_table.add_row(name, count_str, usage)

        console.print(wl_table)
        console.print(f"\n[cyan]Wordlist path: {WORDLISTS_DIR}[/cyan]")
        total = sum(stats.values())
        console.print(f"[green]Total entries across all wordlists: {total}[/green]")


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        zylon = ZylonFusion()
        zylon.run()
    except Exception as e:
        console.print(f"[bold red][FATAL] {str(e)}[/bold red]")
        sys.exit(1)
