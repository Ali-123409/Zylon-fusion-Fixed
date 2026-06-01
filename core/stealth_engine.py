#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Stealth Scanning Engine
Fused from: ExRecon + WebSpy + BlackTrack
Capabilities:
  - TOR-routed scanning support
  - Proxy chain scanning
  - Random User-Agent rotation
  - Request timing randomization (anti-rate-limit)
  - IP rotation simulation (X-Forwarded-For, X-Real-IP)
  - Slow scanning mode (low and slow)
  - DNS-over-HTTPS for stealth resolution
  - Header manipulation for identity masking
  - Scan fingerprint randomization
  - Anti-detection techniques
  - Request throttling with jitter
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import json
import time
import random
import socket
import struct
import threading
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS, REQUEST_DELAY,
    COMMON_DIRS, API_ENDPOINTS
)

# ============================================================================
# ANSI COLORS
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ============================================================================
# EXTENDED USER-AGENT POOL
# ============================================================================

STEALTH_USER_AGENTS = [
    # Chrome - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # Chrome - macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Chrome - Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    # Firefox - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    # Firefox - macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Firefox - Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    # Safari - macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    # Edge - Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # Mobile - Android Chrome
    "Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    # Mobile - iPhone Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    # Mobile - iPad
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    # Bots / Crawlers (for search engine simulation)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    # SEO crawlers
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7; +http://www.semrush.com/bot.html)",
    # Monitoring tools
    "Mozilla/5.0 (compatible; PingdomBot/1.0; +http://www.pingdom.com/)",
    "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
]

# ============================================================================
# HEADER SETS FOR IDENTITY MASKING
# ============================================================================

STEALTH_HEADER_SETS = [
    # Normal browser
    {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
    },
    # API client
    {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
    },
    # Search engine bot
    {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'From': 'googlebot(at)googlebot.com',
    },
    # Security scanner (openly)
    {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
    },
    # Mobile browser
    {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
    },
]

# IP rotation headers
IP_ROTATION_HEADERS = {
    'X-Forwarded-For': lambda: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    'X-Real-IP': lambda: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    'X-Client-IP': lambda: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    'X-Remote-IP': lambda: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    'X-Originating-IP': lambda: f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
    'X-Forwarded-Host': lambda: f"proxy{random.randint(1,99)}.internal.local",
}

# DNS-over-HTTPS providers
DOH_PROVIDERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
    "https://dns.quad9.net/dns-query",
]

# TOR defaults
TOR_SOCKS_HOST = '127.0.0.1'
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051

# Stealth scan profiles
STEALTH_PROFILES = {
    'normal': {'delay_min': 0.1, 'delay_max': 0.5, 'jitter': 0.2, 'timeout': 10},
    'cautious': {'delay_min': 0.5, 'delay_max': 2.0, 'jitter': 0.5, 'timeout': 15},
    'sneaky': {'delay_min': 2.0, 'delay_max': 6.0, 'jitter': 1.5, 'timeout': 20},
    'paranoid': {'delay_min': 5.0, 'delay_max': 15.0, 'jitter': 3.0, 'timeout': 30},
}


# ============================================================================
# STEALTH SCANNING ENGINE
# ============================================================================

class StealthEngine:
    """
    Stealth Scanning Engine - Fused from ExRecon + WebSpy + BlackTrack
    Supports TOR routing, proxy chains, User-Agent rotation, timing randomization,
    IP rotation simulation, slow scanning, DNS-over-HTTPS, header manipulation,
    scan fingerprint randomization, and anti-detection techniques.
    """

    def __init__(self, session=None, profile='cautious'):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': random.choice(STEALTH_USER_AGENTS)})
        self.session.verify = False
        self.profile = profile
        self.profile_config = STEALTH_PROFILES.get(profile, STEALTH_PROFILES['cautious'])
        self.lock = threading.Lock()
        self.request_count = 0
        self.identity_count = 0
        self.tor_active = False
        self.proxy_active = False
        self.proxy_list = []
        self.current_proxy_index = 0
        self._stop_event = threading.Event()

    # ========================================================================
    # STEALTH SCAN (Wrap any scan function)
    # ========================================================================

    def stealth_scan(self, target, scan_func=None):
        """
        Run any scan in stealth mode.
        If scan_func is provided, wraps it with stealth measures.
        Otherwise, performs a basic stealth reconnaissance scan.
        """
        print(f"{CYAN}[ZYLON STEALTH] Starting stealth scan on {target} (profile: {self.profile}){RESET}")

        details = {
            'target': target,
            'profile': self.profile,
            'config': self.profile_config,
            'tor_used': self.tor_active,
            'proxy_used': self.proxy_active,
            'identities_rotated': 0,
            'requests_made': 0,
            'findings': [],
        }

        if not target.startswith('http'):
            target = f"https://{target}"

        # If a scan function is provided, wrap it with stealth
        if scan_func:
            print(f"{YELLOW}[*] Wrapping provided scan function with stealth measures{RESET}")
            result = self._execute_stealth_wrapped(target, scan_func)
            details['findings'] = result.get('findings', [])
            details['requests_made'] = self.request_count
            details['identities_rotated'] = self.identity_count

            return {
                'vulnerable': result.get('vulnerable', False),
                'findings': details['findings'],
                'details': details,
                'scan_type': 'stealth_scan',
            }

        # Otherwise, perform built-in stealth recon
        findings = []

        # Phase 1: Stealth HTTP reconnaissance
        print(f"{CYAN}[*] Phase 1: Stealth HTTP reconnaissance{RESET}")
        http_findings = self._stealth_http_recon(target)
        findings.extend(http_findings)
        self._print_progress("HTTP recon", len(http_findings))

        # Phase 2: Stealth directory discovery
        print(f"{CYAN}[*] Phase 2: Stealth directory discovery{RESET}")
        dir_findings = self._stealth_dir_scan(target)
        findings.extend(dir_findings)
        self._print_progress("Directory scan", len(dir_findings))

        # Phase 3: Stealth header analysis
        print(f"{CYAN}[*] Phase 3: Stealth security header analysis{RESET}")
        header_findings = self._stealth_header_analysis(target)
        findings.extend(header_findings)
        self._print_progress("Header analysis", len(header_findings))

        # Phase 4: Stealth technology fingerprinting
        print(f"{CYAN}[*] Phase 4: Stealth technology fingerprinting{RESET}")
        tech_findings = self._stealth_tech_fingerprint(target)
        findings.extend(tech_findings)
        self._print_progress("Tech fingerprint", len(tech_findings))

        details['findings'] = findings
        details['requests_made'] = self.request_count
        details['identities_rotated'] = self.identity_count

        print(f"{GREEN}[+] Stealth scan complete: {len(findings)} findings, "
              f"{self.request_count} requests, {self.identity_count} identity rotations{RESET}")

        return {
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'details': details,
            'scan_type': 'stealth_scan',
        }

    def _execute_stealth_wrapped(self, target, scan_func):
        """Execute a scan function with stealth wrapping"""
        try:
            # Rotate identity before scan
            self.rotate_identity()
            result = scan_func(target)
            self.request_count += 1
            return result if isinstance(result, dict) else {'vulnerable': False, 'findings': []}
        except Exception as e:
            return {'vulnerable': False, 'findings': [{'error': str(e)[:100]}]}

    def _stealth_http_recon(self, target):
        """Stealth HTTP reconnaissance"""
        findings = []
        self.rotate_identity()

        try:
            resp = self._stealth_request('GET', target)
            if resp:
                findings.append({
                    'type': 'http_info',
                    'status_code': resp.status_code,
                    'server': resp.headers.get('Server', 'Unknown'),
                    'powered_by': resp.headers.get('X-Powered-By', ''),
                    'content_type': resp.headers.get('Content-Type', ''),
                    'content_length': len(resp.text),
                    'redirects': len(resp.history) if hasattr(resp, 'history') else 0,
                })
        except Exception:
            pass

        return findings

    def _stealth_dir_scan(self, target):
        """Stealth directory discovery with randomized timing"""
        findings = []
        paths = random.sample(COMMON_DIRS, min(30, len(COMMON_DIRS)))
        random.shuffle(paths)

        for path in paths:
            if self._stop_event.is_set():
                break
            self.rotate_identity()
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))

            try:
                resp = self._stealth_request('GET', url)
                if resp and resp.status_code in [200, 301, 302, 403, 401]:
                    findings.append({
                        'type': 'directory',
                        'path': path,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                    })
            except Exception:
                pass

            # Random delay between requests
            self.random_delay()

        return findings

    def _stealth_header_analysis(self, target):
        """Stealth security header analysis"""
        findings = []
        self.rotate_identity()

        try:
            resp = self._stealth_request('GET', target)
            if resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}

                security_headers = [
                    'strict-transport-security', 'content-security-policy',
                    'x-content-type-options', 'x-frame-options',
                    'x-xss-protection', 'referrer-policy',
                    'permissions-policy', 'cross-origin-opener-policy',
                ]

                for header in security_headers:
                    if header not in headers:
                        findings.append({
                            'type': 'missing_header',
                            'header': header,
                            'severity': 'Medium',
                            'recommendation': f'Add {header} header',
                        })
        except Exception:
            pass

        return findings

    def _stealth_tech_fingerprint(self, target):
        """Stealth technology fingerprinting"""
        findings = []
        self.rotate_identity()

        try:
            resp = self._stealth_request('GET', target)
            if resp:
                # Check server header
                server = resp.headers.get('Server', '')
                if server:
                    findings.append({'type': 'technology', 'name': 'Server', 'value': server})

                # Check powered-by
                powered = resp.headers.get('X-Powered-By', '')
                if powered:
                    findings.append({'type': 'technology', 'name': 'Framework', 'value': powered})

                # Check cookies for framework hints
                for cookie in resp.cookies:
                    cname = cookie.name.lower()
                    if 'laravel' in cname:
                        findings.append({'type': 'technology', 'name': 'Laravel', 'value': cookie.name})
                    elif 'django' in cname or 'csrftoken' in cname:
                        findings.append({'type': 'technology', 'name': 'Django', 'value': cookie.name})
                    elif 'phpsessid' in cname:
                        findings.append({'type': 'technology', 'name': 'PHP', 'value': cookie.name})
                    elif 'rails' in cname:
                        findings.append({'type': 'technology', 'name': 'Ruby on Rails', 'value': cookie.name})

                # Check body for technology hints
                body = resp.text[:3000]
                if '__next_data__' in body:
                    findings.append({'type': 'technology', 'name': 'Next.js', 'value': 'Detected in body'})
                if 'react' in body.lower():
                    findings.append({'type': 'technology', 'name': 'React', 'value': 'Detected in body'})
                if 'vue' in body.lower() or '__vue__' in body:
                    findings.append({'type': 'technology', 'name': 'Vue.js', 'value': 'Detected in body'})

        except Exception:
            pass

        return findings

    # ========================================================================
    # TOR SETUP
    # ========================================================================

    def setup_tor(self):
        """
        Setup TOR connection for anonymous scanning.
        Checks if TOR is running, configures SOCKS proxy.
        """
        print(f"{MAGENTA}[ZYLON STEALTH] Setting up TOR connection...{RESET}")

        tor_available = False
        tor_port_open = False

        # Check if TOR SOCKS port is open
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((TOR_SOCKS_HOST, TOR_SOCKS_PORT))
            if result == 0:
                tor_port_open = True
            sock.close()
        except Exception:
            pass

        if tor_port_open:
            # Try to use TOR via requests SOCKS proxy
            try:
                # Check if PySocks is available
                import socks  # noqa: F401

                self.session.proxies = {
                    'http': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
                    'https': f'socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}',
                }

                # Verify TOR connection
                try:
                    resp = self.session.get('https://check.torproject.org/api/ip',
                                            timeout=15, verify=False)
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get('IsTor'):
                            tor_available = True
                            self.tor_active = True
                            print(f"{GREEN}[+] TOR connection active! Exit IP: {data.get('IP', 'unknown')}{RESET}")
                        else:
                            print(f"{YELLOW}[-] Connected but TOR not detected. May be misconfigured.{RESET}")
                    else:
                        print(f"{YELLOW}[-] TOR check failed: HTTP {resp.status_code}{RESET}")
                except Exception as e:
                    print(f"{YELLOW}[-] TOR verification failed: {str(e)[:60]}{RESET}")

            except ImportError:
                # PySocks not available - try system TOR without SOCKS
                print(f"{YELLOW}[-] PySocks not installed. Attempting HTTP proxy approach...{RESET}")

                # Try TOR as HTTP proxy (some setups)
                self.session.proxies = {
                    'http': f'http://{TOR_SOCKS_HOST}:8118',
                    'https': f'http://{TOR_SOCKS_HOST}:8118',
                }
                try:
                    resp = self.session.get('https://check.torproject.org/api/ip',
                                            timeout=15, verify=False)
                    if resp.status_code == 200 and resp.json().get('IsTor'):
                        tor_available = True
                        self.tor_active = True
                        print(f"{GREEN}[+] TOR (via Privoxy) connection active!{RESET}")
                except Exception:
                    print(f"{YELLOW}[-] TOR HTTP proxy also failed.{RESET}")

                if not tor_available:
                    self.session.proxies = {}
        else:
            print(f"{YELLOW}[-] TOR not running on {TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}{RESET}")
            print(f"{YELLOW}[*] Install TOR: pkg install tor && tor &{RESET}")
            print(f"{YELLOW}[*] Or install PySocks: pip3 install pysocks{RESET}")

        if not tor_available:
            print(f"{CYAN}[*] Continuing with stealth mode (no TOR) - using IP rotation headers{RESET}")
            self.tor_active = False

        return {
            'tor_available': tor_available,
            'tor_active': self.tor_active,
            'socks_port': TOR_SOCKS_PORT if tor_available else None,
        }

    def _request_tor_new_identity(self):
        """Request new TOR identity (NEWNYM signal)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((TOR_SOCKS_HOST, TOR_CONTROL_PORT))
            sock.sendall(b'AUTHENTICATE ""\r\n')
            resp = sock.recv(1024)
            if b'250' in resp:
                sock.sendall(b'SIGNAL NEWNYM\r\n')
                resp = sock.recv(1024)
                if b'250' in resp:
                    print(f"{GREEN}[+] TOR identity rotated{RESET}")
                    self.identity_count += 1
                    time.sleep(3)  # Wait for new circuit
            sock.sendall(b'QUIT\r\n')
            sock.close()
        except Exception:
            pass

    # ========================================================================
    # PROXY CHAIN SETUP
    # ========================================================================

    def setup_proxy(self, proxy_list):
        """
        Setup proxy chain for scanning.
        proxy_list: list of proxy URLs or file path to proxy list
        """
        print(f"{MAGENTA}[ZYLON STEALTH] Setting up proxy chain...{RESET}")

        # If proxy_list is a file path
        if isinstance(proxy_list, str):
            if os.path.isfile(proxy_list):
                try:
                    with open(proxy_list, 'r', errors='ignore') as f:
                        proxy_list = [line.strip() for line in f
                                      if line.strip() and not line.startswith('#')]
                except Exception as e:
                    print(f"{RED}[-] Error reading proxy file: {str(e)[:60]}{RESET}")
                    return {'proxy_active': False, 'error': str(e)[:80]}
            else:
                proxy_list = [proxy_list]

        self.proxy_list = []
        valid_proxies = []

        # Validate proxies
        for proxy in proxy_list[:50]:  # Limit to 50 proxies
            proxy = proxy.strip()
            if not proxy:
                continue

            # Normalize proxy format
            if not proxy.startswith('http://') and not proxy.startswith('https://') and not proxy.startswith('socks'):
                proxy = f'http://{proxy}'

            self.proxy_list.append(proxy)

            # Quick validation
            try:
                test_session = requests.Session()
                test_session.proxies = {'http': proxy, 'https': proxy}
                test_session.get('https://httpbin.org/ip', timeout=8, verify=False)
                valid_proxies.append(proxy)
            except Exception:
                pass

        if self.proxy_list:
            self.proxy_active = True
            # Set first proxy
            self._set_proxy(0)
            print(f"{GREEN}[+] Proxy chain configured: {len(self.proxy_list)} proxies ({len(valid_proxies)} validated){RESET}")
        else:
            print(f"{YELLOW}[-] No valid proxies found{RESET}")

        return {
            'proxy_active': self.proxy_active,
            'total_proxies': len(self.proxy_list),
            'validated_proxies': len(valid_proxies),
            'proxy_list': self.proxy_list[:10],
        }

    def _set_proxy(self, index):
        """Set current proxy by index"""
        if self.proxy_list and index < len(self.proxy_list):
            proxy = self.proxy_list[index % len(self.proxy_list)]
            self.session.proxies = {'http': proxy, 'https': proxy}
            self.current_proxy_index = index

    def _rotate_proxy(self):
        """Rotate to next proxy in the chain"""
        if self.proxy_list:
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
            self._set_proxy(self.current_proxy_index)
            self.identity_count += 1

    # ========================================================================
    # IDENTITY ROTATION
    # ========================================================================

    def rotate_identity(self):
        """
        Rotate User-Agent, headers, and optionally proxy/TOR identity.
        Makes each request appear to come from a different client.
        """
        # Rotate User-Agent
        new_ua = random.choice(STEALTH_USER_AGENTS)
        self.session.headers['User-Agent'] = new_ua

        # Rotate header set
        header_set = random.choice(STEALTH_HEADER_SETS)
        for key, value in header_set.items():
            self.session.headers[key] = value

        # Rotate IP-simulation headers
        for header, gen_func in IP_ROTATION_HEADERS.items():
            if random.random() < 0.3:  # 30% chance to add each IP header
                self.session.headers[header] = gen_func()

        # Rotate proxy if available
        if self.proxy_active and random.random() < 0.5:
            self._rotate_proxy()

        # Request new TOR identity if active
        if self.tor_active and random.random() < 0.2:
            self._request_tor_new_identity()

        # Add random session-level noise headers
        noise_headers = {
            'X-Request-ID': hashlib.md5(str(random.random()).encode()).hexdigest()[:12],
            'X-Session-ID': hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
        }
        for k, v in noise_headers.items():
            if random.random() < 0.5:
                self.session.headers[k] = v

        # Remove some headers randomly for fingerprint randomization
        headers_to_maybe_remove = ['DNT', 'Upgrade-Insecure-Requests', 'Sec-Fetch-Dest']
        for h in headers_to_maybe_remove:
            if h in self.session.headers and random.random() < 0.3:
                del self.session.headers[h]

        self.identity_count += 1

    # ========================================================================
    # REQUEST TIMING
    # ========================================================================

    def random_delay(self):
        """
        Random request timing with jitter.
        Implements anti-rate-limit and anti-detection timing.
        """
        config = self.profile_config
        delay_min = config['delay_min']
        delay_max = config['delay_max']
        jitter = config['jitter']

        # Base delay
        base_delay = random.uniform(delay_min, delay_max)

        # Add jitter (random variation)
        jitter_amount = random.uniform(-jitter, jitter)
        total_delay = max(0.05, base_delay + jitter_amount)

        # Occasional longer pause (5% chance - simulates human reading)
        if random.random() < 0.05:
            total_delay += random.uniform(3.0, 10.0)

        # Occasional burst prevention (10% chance - simulates connection reset)
        if random.random() < 0.1:
            total_delay += random.uniform(1.0, 5.0)

        time.sleep(total_delay)
        return total_delay

    # ========================================================================
    # STEALTH REQUEST
    # ========================================================================

    def _stealth_request(self, method, url, **kwargs):
        """Make a stealth HTTP request with all anti-detection measures"""
        if self._stop_event.is_set():
            return None

        # Apply timing
        self.random_delay()

        # Rotate identity before request
        if self.request_count > 0 and random.random() < 0.3:
            self.rotate_identity()

        try:
            timeout = kwargs.pop('timeout', self.profile_config['timeout'])
            resp = self.session.request(
                method=method,
                url=url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                **kwargs,
            )
            self.request_count += 1
            return resp
        except requests.exceptions.RequestException:
            self.request_count += 1
            return None

    # ========================================================================
    # SLOW SCAN MODE
    # ========================================================================

    def slow_scan(self, target):
        """
        Low and slow scanning mode.
        Sends requests very slowly to avoid detection by rate limiters and IDS.
        """
        print(f"{YELLOW}[ZYLON STEALTH] SLOW SCAN mode on {target}{RESET}")
        print(f"{YELLOW}[*] Using paranoid timing profile - this will take a while...{RESET}")

        # Save current profile and switch to paranoid
        original_profile = self.profile
        original_config = self.profile_config
        self.profile = 'paranoid'
        self.profile_config = STEALTH_PROFILES['paranoid']

        if not target.startswith('http'):
            target = f"https://{target}"

        findings = []
        details = {
            'target': target,
            'mode': 'slow',
            'profile': 'paranoid',
            'requests_made': 0,
            'elapsed_time': 0,
        }

        start_time = time.time()

        # Slow recon
        self.rotate_identity()
        try:
            resp = self._stealth_request('GET', target)
            if resp:
                findings.append({
                    'type': 'slow_recon',
                    'status_code': resp.status_code,
                    'server': resp.headers.get('Server', ''),
                    'content_length': len(resp.text),
                })
        except Exception:
            pass

        # Slow directory scan with long delays
        paths = random.sample(COMMON_DIRS, min(20, len(COMMON_DIRS)))
        for i, path in enumerate(paths):
            if self._stop_event.is_set():
                break

            self.rotate_identity()
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))

            try:
                resp = self._stealth_request('GET', url)
                if resp and resp.status_code in [200, 301, 302, 403, 401]:
                    findings.append({
                        'type': 'slow_dir',
                        'path': path,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                    })
                    print(f"  {GREEN}[+] {path} -> {resp.status_code} ({len(resp.text)}b){RESET}")
            except Exception:
                pass

            # Extra slow delay between each request
            self.random_delay()

            if (i + 1) % 5 == 0:
                elapsed = time.time() - start_time
                print(f"  {YELLOW}[*] Progress: {i+1}/{len(paths)} | "
                      f"Elapsed: {elapsed:.0f}s | Findings: {len(findings)}{RESET}")

        details['requests_made'] = self.request_count
        details['elapsed_time'] = time.time() - start_time

        # Restore original profile
        self.profile = original_profile
        self.profile_config = original_config

        print(f"{GREEN}[+] Slow scan complete: {len(findings)} findings in {details['elapsed_time']:.0f}s{RESET}")

        return {
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'details': details,
            'scan_type': 'slow_scan',
        }

    # ========================================================================
    # DNS-OVER-HTTPS RESOLUTION
    # ========================================================================

    def doh_resolve(self, domain, record_type='A'):
        """
        DNS-over-HTTPS resolution for stealth DNS lookups.
        Avoids leaking DNS queries to the ISP.
        """
        for provider in DOH_PROVIDERS:
            try:
                params = {
                    'name': domain,
                    'type': record_type,
                }
                headers = {
                    'Accept': 'application/dns-json',
                    'User-Agent': random.choice(STEALTH_USER_AGENTS),
                }

                resp = requests.get(
                    provider,
                    params=params,
                    headers=headers,
                    timeout=10,
                    verify=False,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    answers = data.get('Answer', [])
                    if answers:
                        return {
                            'domain': domain,
                            'record_type': record_type,
                            'answers': [{'name': a.get('name'), 'data': a.get('data'),
                                         'ttl': a.get('TTL')} for a in answers],
                            'provider': provider,
                            'status': data.get('Status', 0),
                        }
            except Exception:
                continue

        return {
            'domain': domain,
            'record_type': record_type,
            'answers': [],
            'error': 'All DoH providers failed',
        }

    # ========================================================================
    # STEALTH FULL SCAN
    # ========================================================================

    def stealth_full_scan(self, target):
        """
        Full stealth scan: TOR + proxy + rotation + slow mode
        Maximum anonymity and anti-detection.
        """
        print(f"{BOLD}{RED}[ZYLON STEALTH] FULL STEALTH SCAN on {target}{RESET}")

        if not target.startswith('http'):
            target = f"https://{target}"

        results = {}

        # Phase 1: Setup TOR (if available)
        print(f"\n{MAGENTA}=== Phase 1: TOR Setup ==={RESET}")
        tor_result = self.setup_tor()
        results['tor_setup'] = tor_result

        # Phase 2: DoH Resolution
        print(f"\n{CYAN}=== Phase 2: Stealth DNS Resolution ==={RESET}")
        parsed = urlparse(target)
        domain = parsed.hostname or target.replace('https://', '').replace('http://', '').split('/')[0]
        dns_result = self.doh_resolve(domain)
        results['dns_resolution'] = dns_result
        if dns_result.get('answers'):
            print(f"  {GREEN}[+] Resolved via DoH: {[a['data'] for a in dns_result['answers']]}{RESET}")

        # Phase 3: Stealth HTTP Recon
        print(f"\n{CYAN}=== Phase 3: Stealth HTTP Reconnaissance ==={RESET}")
        results['http_recon'] = self._stealth_http_recon(target)

        # Phase 4: Stealth Directory Scan
        print(f"\n{YELLOW}=== Phase 4: Stealth Directory Scan ==={RESET}")
        results['dir_scan'] = self._stealth_dir_scan(target)

        # Phase 5: Header Analysis
        print(f"\n{MAGENTA}=== Phase 5: Stealth Header Analysis ==={RESET}")
        results['header_analysis'] = self._stealth_header_analysis(target)

        # Phase 6: Technology Fingerprinting
        print(f"\n{CYAN}=== Phase 6: Stealth Tech Fingerprinting ==={RESET}")
        results['tech_fingerprint'] = self._stealth_tech_fingerprint(target)

        # Summary
        all_findings = []
        for key in ['http_recon', 'dir_scan', 'header_analysis', 'tech_fingerprint']:
            findings = results.get(key, [])
            if isinstance(findings, list):
                all_findings.extend(findings)

        print(f"\n{BOLD}{GREEN}[+] Full stealth scan complete: {len(all_findings)} findings{RESET}")
        print(f"{GREEN}[*] Total requests: {self.request_count} | Identity rotations: {self.identity_count}{RESET}")
        print(f"{GREEN}[*] TOR: {'Active' if self.tor_active else 'Not available'} | "
              f"Proxy: {'Active' if self.proxy_active else 'Not configured'}{RESET}")

        return {
            'vulnerable': len(all_findings) > 0,
            'findings': all_findings,
            'details': {
                'target': target,
                'tor_active': self.tor_active,
                'proxy_active': self.proxy_active,
                'total_requests': self.request_count,
                'identity_rotations': self.identity_count,
                'phases_completed': 6,
            },
            'scan_type': 'stealth_full_scan',
        }

    # ========================================================================
    # IDENTITY ROTATION ONLY
    # ========================================================================

    def rotate_identity_scan(self, target, count=10):
        """
        Perform requests with identity rotation only.
        Useful for testing how target responds to different identities.
        """
        print(f"{CYAN}[ZYLON STEALTH] Identity rotation scan ({count} rotations) on {target}{RESET}")

        if not target.startswith('http'):
            target = f"https://{target}"

        findings = []
        responses = []

        for i in range(count):
            self.rotate_identity()
            try:
                resp = self._stealth_request('GET', target)
                if resp:
                    response_info = {
                        'rotation': i + 1,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                        'user_agent': self.session.headers.get('User-Agent', '')[:60],
                        'forwarded_for': self.session.headers.get('X-Forwarded-For', ''),
                    }
                    responses.append(response_info)

                    # Check if response differs from previous
                    if len(responses) > 1:
                        prev = responses[-2]
                        if resp.status_code != prev['status_code']:
                            findings.append({
                                'type': 'status_code_diff',
                                'rotation': i + 1,
                                'current_status': resp.status_code,
                                'previous_status': prev['status_code'],
                                'note': 'Different status code with different identity',
                            })
                        if abs(len(resp.text) - prev['content_length']) > 100:
                            findings.append({
                                'type': 'content_diff',
                                'rotation': i + 1,
                                'current_length': len(resp.text),
                                'previous_length': prev['content_length'],
                                'note': 'Different response size with different identity',
                            })
            except Exception:
                pass

            self.random_delay()

        print(f"{GREEN}[+] Identity rotation complete: {count} rotations, {len(findings)} differences detected{RESET}")

        return {
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'details': {
                'target': target,
                'rotations': count,
                'responses': responses,
                'differences_detected': len(findings),
            },
            'scan_type': 'identity_rotation',
        }

    # ========================================================================
    # UTILITY
    # ========================================================================

    def _print_progress(self, phase, count):
        """Print progress update"""
        print(f"  {GREEN}[+] {phase}: {count} findings{RESET}")

    def stop(self):
        """Stop all running scans"""
        self._stop_event.set()

    # ========================================================================
    # MAIN ENTRY
    # ========================================================================

    def run(self, target, scan_type='stealth', **kwargs):
        """Main entry point"""
        scan_map = {
            'stealth': lambda: self.stealth_scan(target, kwargs.get('scan_func')),
            'tor': lambda: (self.setup_tor(), self.stealth_scan(target))[1],
            'proxy': lambda: (self.setup_proxy(kwargs.get('proxy_list', [])), self.stealth_scan(target))[1],
            'slow': lambda: self.slow_scan(target),
            'full': lambda: self.stealth_full_scan(target),
            'rotate': lambda: self.rotate_identity_scan(target, count=kwargs.get('count', 10)),
            'doh': lambda: self.doh_resolve(target),
        }

        if scan_type in scan_map:
            return scan_map[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}', 'available': list(scan_map.keys())},
            'scan_type': scan_type,
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='stealth', **kwargs):
    """
    Module-level run function for ZYLON FUSION integration.
    Returns dict: 'vulnerable', 'findings', 'details', 'scan_type'
    """
    profile = kwargs.pop('profile', 'cautious')
    engine = StealthEngine(
        session=kwargs.pop('session', None),
        profile=profile,
    )
    return engine.run(target, scan_type=scan_type, **kwargs)
