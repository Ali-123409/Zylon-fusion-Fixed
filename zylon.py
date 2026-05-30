#!/usr/bin/env python3
"""
 ███████╗██╗██████╗  ██████╗ ███████╗
 ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
   ███╔╝ ██║██████╔╝██║   ██║███████╗
  ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
 ███████╗██║██║     ╚██████╔╝███████║
 ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝

 ZYLON FUSION - Advanced Security Reconnaissance & Vulnerability Platform
 Fused from omino + wizard + custom Zylon techniques
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
[bold yellow]    FUSION - Advanced Security Reconnaissance & Vulnerability Platform[/bold yellow]
[bold cyan]    omino + wizard + Zylon Custom Techniques | Termux Non-Root[/bold cyan]
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
        info.add_row(" Root Access", "No (Non-Root Mode)" if os.geteuid() != 0 else "Yes")
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
            ("22", "Nuclear Scan (All Modules Combined)"),
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
            ("42", "Bug Bounty Full Recon Pipeline"),
            ("43", "Bug Bounty Full Vuln Pipeline"),
            ("99", "MEGA SCAN (Every Single Module)"),
            ("ai", "AI-Powered Vulnerability Analysis (Experimental)"),
            ("scope", "Set/Check Bug Bounty Scope"),
            ("poc", "Generate PoC for Last Finding"),
            ("config", "Configuration Manager (API Keys)"),
            ("report", "View/Export Previous Scan Reports"),
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
            '42': self._scan_bounty_recon,
            '43': self._scan_bounty_vuln,
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
            cloudflare = self.recon.check_cloudflare(ip) if ip else False
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
        if dns_records:
            dns_table = Table(title="DNS Records", box=box.ROUNDED, border_style="cyan")
            dns_table.add_column("Type", style="yellow")
            dns_table.add_column("Value", style="green")
            for rtype, values in dns_records.items():
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
        
        if dns_records:
            d_table = Table(title="DNS Records", box=box.DOUBLE, border_style="bright_cyan")
            d_table.add_column("Type", style="bold yellow")
            d_table.add_column("Value", style="green")
            for rtype, values in dns_records.items():
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
        console.print(f"[green][+] Tested {result['tested']} parameters, found {len(result.get('discovered', {}))} active, {len(result.get('reflected', []))} reflected")
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
        # Generate mega report
        self.reports.generate_html_report(self.results, self.target)
        console.print(f"\n[bold green][+] MEGA SCAN COMPLETE! Full report generated.[/bold green]")
    
    def run_ai_analysis(self):
        """AI-powered vulnerability analysis"""
        if not self.results or not self.results.get('findings'):
            console.print("[bold yellow][!] Run a scan first before AI analysis[/bold yellow]")
            return
        
        console.print("\n[bold magenta][*] AI-Powered Vulnerability Analysis[/bold magenta]")
        with console.status("[bold magenta]AI is analyzing scan results...[/bold magenta]"):
            analysis = self.ai.analyze_results(self.results)
        
        if analysis:
            console.print(Panel(
                analysis.get('summary', 'No analysis available'),
                title="[bold magenta]AI Analysis[/bold magenta]",
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
                    self.run_ai_analysis()
                
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
                            "[bold yellow]Select scan type (0-22)[/bold yellow]",
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
        
        keys = ['shodan_api_key', 'virustotal_api_key', 'hunter_api_key', 
                'securitytrails_api_key', 'censys_api_id', 'censys_api_secret',
                'ai_api_key']
        
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
            key_name = Prompt.ask("[yellow]API key name[/yellow]")
            key_val = Prompt.ask("[yellow]API key value[/yellow]")
            config[key_name] = key_val
            
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
