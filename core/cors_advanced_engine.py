#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - CORS Advanced Engine
============================================
Fused from: CorsonE (https://github.com/SbDuy/CorsonE)
           + CORScanner (https://github.com/chenjj/CORScanner)
           + CORSER (https://github.com/nicholasaleks/CORSer)
           + Custom Zylon Techniques
Capabilities:
  - CORS misconfiguration detection
  - Origin manipulation testing (evil.com, null, subdomain.evil.com, etc.)
  - Wildcard origin detection
  - Subdomain bypass testing
  - Null origin testing
  - HTTP/HTTPS origin mismatch
  - Credential inclusion testing
  - Pre-flight request analysis
  - Multi-origin testing
  - CORS + CSRF chain detection
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import time
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS, CORS_TEST_ORIGINS
)

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
# CORS TEST ORIGINS (Extended)
# ============================================================================

CORS_ADVANCED_ORIGINS = {
    # Basic cross-origin tests
    "evil.com": {
        "origin": "https://evil.com",
        "category": "cross_origin",
        "severity": "High",
        "description": "Unrelated cross-origin domain (evil.com)",
    },
    "attacker.com": {
        "origin": "https://attacker.com",
        "category": "cross_origin",
        "severity": "High",
        "description": "Unrelated cross-origin domain (attacker.com)",
    },
    "null_origin": {
        "origin": "null",
        "category": "null_origin",
        "severity": "Critical",
        "description": "Null origin (sandboxed iframe)",
    },
    # Subdomain bypass tests
    "subdomain_evil": {
        "origin": "https://evil.{target}",
        "category": "subdomain_bypass",
        "severity": "High",
        "description": "Attacker subdomain of target (evil.target.com)",
    },
    "target_evil_suffix": {
        "origin": "https://{target}.evil.com",
        "category": "suffix_bypass",
        "severity": "Medium",
        "description": "Target as suffix (target.evil.com)",
    },
    "target_evil_prefix": {
        "origin": "https://{target}evil.com",
        "category": "suffix_bypass",
        "severity": "Medium",
        "description": "Target as prefix without dot (targetevil.com)",
    },
    # Protocol mismatch
    "http_origin": {
        "origin": "http://{target}",
        "category": "protocol_mismatch",
        "severity": "Medium",
        "description": "HTTP origin for HTTPS site",
    },
    # Port-based bypass
    "port_bypass": {
        "origin": "https://{target}:1234",
        "category": "port_bypass",
        "severity": "Medium",
        "description": "Target with different port",
    },
    # Special origins
    "localhost": {
        "origin": "http://localhost",
        "category": "localhost",
        "severity": "Low",
        "description": "Localhost origin",
    },
    "127.0.0.1": {
        "origin": "http://127.0.0.1",
        "category": "localhost",
        "severity": "Low",
        "description": "Loopback IP origin",
    },
    # Backtick bypass (browser quirks)
    "backtick_bypass": {
        "origin": "https://`evil.com",
        "category": "browser_quirk",
        "severity": "Medium",
        "description": "Backtick bypass origin",
    },
    # Underscore bypass
    "underscore_bypass": {
        "origin": "https://evil_.{target}",
        "category": "browser_quirk",
        "severity": "Medium",
        "description": "Underscore bypass (evil_.target.com)",
    },
    # Prepend bypass
    "prepend_bypass": {
        "origin": "https://evil{target}",
        "category": "prepend_bypass",
        "severity": "Medium",
        "description": "Prepend without separator (eviltarget.com)",
    },
}

# HTTP methods for pre-flight testing
PREFLIGHT_METHODS = ["PUT", "DELETE", "PATCH", "OPTIONS"]

# Custom headers for pre-flight testing
PREFLIGHT_HEADERS = [
    "X-Custom-Header", "X-Api-Key", "Authorization",
    "Content-Type", "Accept", "X-Requested-With",
]


class CORSAdvancedEngine:
    """CORS Advanced Engine - Fused from CorsonE + CORScanner + CORSer + Custom Techniques"""

    def __init__(self, target_url=None, headers=None, cookies=None, timeout=DEFAULT_TIMEOUT,
                 threads=MAX_THREADS, proxy=None):
        self.target_url = target_url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else
                'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _get_target_domain(self, url):
        """Extract domain from URL"""
        parsed = urlparse(url if '://' in url else f"https://{url}")
        return parsed.hostname or url

    def _build_origin(self, origin_template, target):
        """Build origin URL by replacing {target} placeholder"""
        domain = self._get_target_domain(target)
        return origin_template.replace("{target}", domain)

    # ========================================================================
    # TEST SPECIFIC ORIGIN
    # ========================================================================

    def test_origin(self, url, origin):
        """Test a specific origin against the target URL

        Sends a request with the Origin header and checks if the server
        reflects it in Access-Control-Allow-Origin.
        """
        result = {
            "url": url,
            "origin": origin,
            "vulnerable": False,
            "acao_header": None,
            "acac_header": None,
            "status_code": None,
            "method": "GET",
            "findings": [],
        }

        try:
            headers = {
                'Origin': origin,
                'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
            }

            resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                   allow_redirects=False, verify=False)
            result["status_code"] = resp.status_code

            # Check Access-Control-Allow-Origin
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            result["acao_header"] = acao
            result["acac_header"] = acac

            if acao:
                # Check if origin is reflected (misconfiguration)
                if acao == origin or acao == '*':
                    result["vulnerable"] = True

                    # Determine severity based on credentials
                    if acac and acac.lower() == 'true':
                        severity = "Critical"
                        desc = f"Origin {origin} is reflected with credentials! ACAO={acao}, ACAC={acac}"
                    elif acao == '*':
                        severity = "Medium"
                        desc = f"Wildcard CORS: ACAO=*, but credentials not exposed"
                    else:
                        severity = "High"
                        desc = f"Origin {origin} is reflected in ACAO without credentials"

                    result["findings"].append({
                        "type": "cors_misconfiguration",
                        "severity": severity,
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "description": desc,
                    })
                elif origin in acao:
                    # Partial match - might be subdomain bypass
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "cors_partial_reflection",
                        "severity": "High",
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "description": f"Origin partially reflected: ACAO={acao} for Origin={origin}",
                    })

        except Exception as e:
            result["findings"].append({"type": "error", "error": str(e)})

        return result

    # ========================================================================
    # TEST NULL ORIGIN
    # ========================================================================

    def test_null_origin(self, url):
        """Test null origin - commonly accepted by misconfigured CORS

        Null origin is sent by sandboxed iframes and redirect origins.
        Accepting null origin is a serious misconfiguration.
        """
        self._print(f"  [*] Testing null origin on {url}", CYAN)

        result = {
            "url": url,
            "vulnerable": False,
            "findings": [],
            "details": {
                "origin": "null",
                "acao_header": None,
                "acac_header": None,
            },
            "scan_type": "cors_null_origin",
        }

        try:
            headers = {
                'Origin': 'null',
                'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
            }

            resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                   allow_redirects=False, verify=False)

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            result["details"]["acao_header"] = acao
            result["details"]["acac_header"] = acac

            if acao == 'null':
                result["vulnerable"] = True
                severity = "Critical" if acac.lower() == 'true' else "High"
                result["findings"].append({
                    "type": "cors_null_origin_accepted",
                    "severity": severity,
                    "acao": acao,
                    "acac": acac,
                    "description": f"Null origin accepted! ACAO=null, ACAC={acac}. "
                                   f"Attacker can use sandboxed iframe to bypass CORS.",
                })
                self._print(f"  [!!!] NULL ORIGIN ACCEPTED! ACAO=null, ACAC={acac}", RED)
            elif acao == '*':
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "cors_wildcard",
                    "severity": "Medium",
                    "acao": acao,
                    "description": "Wildcard CORS detected (ACAO=*)",
                })
                self._print(f"  [!] Wildcard CORS detected", YELLOW)
            else:
                self._print(f"  [-] Null origin not accepted", GREEN)

        except Exception as e:
            result["findings"].append({"type": "error", "error": str(e)})

        return result

    # ========================================================================
    # TEST SUBDOMAIN BYPASS
    # ========================================================================

    def test_subdomain_bypass(self, url):
        """Test subdomain bypass patterns for CORS

        Tests if the server accepts origins from subdomains of evil domains
        or if it incorrectly validates based on suffix matching.
        """
        self._print(f"  [*] Testing subdomain bypass on {url}", CYAN)

        domain = self._get_target_domain(url)
        result = {
            "url": url,
            "vulnerable": False,
            "findings": [],
            "details": {
                "domain": domain,
                "bypasses_found": [],
            },
            "scan_type": "cors_subdomain_bypass",
        }

        # Subdomain bypass test origins
        test_origins = [
            ("https://evil." + domain, "Attacker subdomain of target"),
            ("https://" + domain + ".evil.com", "Target as suffix of evil domain"),
            ("https://" + domain + "evil.com", "Target prefix without separator"),
            ("https://evil" + domain, "Prepend without separator"),
            ("https://evil_." + domain, "Underscore bypass"),
            ("http://" + domain, "HTTP origin for HTTPS site"),
            ("https://" + domain + ":1234", "Port bypass"),
        ]

        for origin, description in test_origins:
            try:
                headers = {
                    'Origin': origin,
                    'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
                }

                resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                       allow_redirects=False, verify=False)

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if acao == origin or (acao == '*' and origin != 'null'):
                    result["vulnerable"] = True
                    result["details"]["bypasses_found"].append({
                        "origin": origin,
                        "description": description,
                        "acao": acao,
                        "acac": acac,
                    })

                    severity = "High"
                    if acac and acac.lower() == 'true':
                        severity = "Critical"

                    result["findings"].append({
                        "type": "cors_subdomain_bypass",
                        "severity": severity,
                        "origin": origin,
                        "acao": acao,
                        "acac": acac,
                        "description": f"Subdomain bypass: {description}. Origin={origin} accepted. ACAO={acao}",
                    })
                    self._print(f"  [!] BYPASS: {description} -> {origin} (ACAO={acao}, ACAC={acac})", RED)
                else:
                    self._print(f"  [-] No bypass: {origin}", DIM + CYAN)

            except Exception:
                continue

        return result

    # ========================================================================
    # TEST WILDCARD
    # ========================================================================

    def test_wildcard(self, url):
        """Test for wildcard CORS (Access-Control-Allow-Origin: *)"""
        self._print(f"  [*] Testing wildcard CORS on {url}", CYAN)

        result = {
            "url": url,
            "vulnerable": False,
            "findings": [],
            "details": {
                "wildcard_detected": False,
                "acao_header": None,
                "acac_header": None,
            },
            "scan_type": "cors_wildcard",
        }

        try:
            # Test with random origin
            random_origin = f"https://random-test-{random.randint(10000,99999)}.com"
            headers = {
                'Origin': random_origin,
                'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
            }

            import random as _random
            resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                   allow_redirects=False, verify=False)

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')

            result["details"]["acao_header"] = acao
            result["details"]["acac_header"] = acac

            if acao == '*':
                result["vulnerable"] = True
                result["details"]["wildcard_detected"] = True

                # Wildcard with credentials is a spec violation
                if acac and acac.lower() == 'true':
                    result["findings"].append({
                        "type": "cors_wildcard_with_credentials",
                        "severity": "Medium",
                        "description": "Wildcard CORS with credentials (spec violation - browsers block this)",
                    })
                    self._print(f"  [!] Wildcard CORS with credentials (spec violation)", YELLOW)
                else:
                    result["findings"].append({
                        "type": "cors_wildcard",
                        "severity": "Low",
                        "description": "Wildcard CORS detected (ACAO=*). No credentials exposed, but any origin can read responses.",
                    })
                    self._print(f"  [?] Wildcard CORS detected (ACAO=*), no credentials", YELLOW)
            else:
                self._print(f"  [-] No wildcard CORS", GREEN)

        except Exception as e:
            result["findings"].append({"type": "error", "error": str(e)})

        return result

    # ========================================================================
    # TEST CREDENTIAL INCLUSION
    # ========================================================================

    def test_credential_inclusion(self, url):
        """Test if CORS allows credential inclusion with cross-origin requests

        This tests whether Access-Control-Allow-Credentials: true is set
        alongside a permissive Access-Control-Allow-Origin.
        """
        self._print(f"  [*] Testing credential inclusion on {url}", CYAN)

        domain = self._get_target_domain(url)
        result = {
            "url": url,
            "vulnerable": False,
            "findings": [],
            "details": {
                "credential_inclusion_vulnerable": False,
                "tested_origins": [],
            },
            "scan_type": "cors_credential_inclusion",
        }

        # Test with various origins including cookies
        test_origins = [
            f"https://evil.com",
            f"https://attacker.com",
            f"https://evil.{domain}",
            f"null",
        ]

        for origin in test_origins:
            actual_origin = origin if origin != "null" else "null"
            try:
                headers = {
                    'Origin': actual_origin,
                    'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
                }

                # Include cookies in the request
                resp = self.session.get(url, headers=headers, timeout=self.timeout,
                                       allow_redirects=False, verify=False)

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                result["details"]["tested_origins"].append({
                    "origin": actual_origin,
                    "acao": acao,
                    "acac": acac,
                })

                # Check if both ACAO reflects origin AND ACAC is true
                if (acao == actual_origin or acao == '*') and acac and acac.lower() == 'true':
                    result["vulnerable"] = True
                    result["details"]["credential_inclusion_vulnerable"] = True
                    result["findings"].append({
                        "type": "cors_credentials_exposed",
                        "severity": "Critical",
                        "origin": actual_origin,
                        "acao": acao,
                        "acac": acac,
                        "description": f"CORS allows credentials from cross-origin! "
                                       f"Origin={actual_origin}, ACAO={acao}, ACAC={acac}. "
                                       f"An attacker can steal user credentials/cookies.",
                    })
                    self._print(f"  [!!!] CREDENTIALS EXPOSED! Origin={actual_origin}, ACAC={acac}", RED)
                elif acao == actual_origin and (not acac or acac.lower() != 'true'):
                    result["findings"].append({
                        "type": "cors_origin_reflected_no_creds",
                        "severity": "High",
                        "origin": actual_origin,
                        "acao": acao,
                        "description": f"Origin reflected but credentials not included - data can still be read",
                    })
                    self._print(f"  [!] Origin reflected (no creds): {actual_origin}", YELLOW)

            except Exception:
                continue

        return result

    # ========================================================================
    # DETECT MISCONFIGURATION (FULL)
    # ========================================================================

    def detect_misconfig(self, url):
        """Full CORS misconfiguration detection

        Runs all CORS tests and aggregates results.
        """
        self._print(f"\n{BOLD}{CYAN}  Full CORS Misconfiguration Detection on {url}{RESET}", CYAN)

        domain = self._get_target_domain(url)
        result = {
            "url": url,
            "vulnerable": False,
            "findings": [],
            "details": {
                "domain": domain,
                "tests_run": [],
                "vulnerabilities": [],
                "csrf_chain_possible": False,
            },
            "scan_type": "cors_misconfiguration_detect",
        }

        # Test 1: Null origin
        null_result = self.test_null_origin(url)
        result["details"]["tests_run"].append("null_origin")
        if null_result.get("vulnerable"):
            result["vulnerable"] = True
            result["findings"].extend(null_result.get("findings", []))

        # Test 2: Wildcard
        wildcard_result = self.test_wildcard(url)
        result["details"]["tests_run"].append("wildcard")
        if wildcard_result.get("vulnerable"):
            result["vulnerable"] = True
            result["findings"].extend(wildcard_result.get("findings", []))

        # Test 3: Subdomain bypass
        bypass_result = self.test_subdomain_bypass(url)
        result["details"]["tests_run"].append("subdomain_bypass")
        if bypass_result.get("vulnerable"):
            result["vulnerable"] = True
            result["findings"].extend(bypass_result.get("findings", []))

        # Test 4: Credential inclusion
        cred_result = self.test_credential_inclusion(url)
        result["details"]["tests_run"].append("credential_inclusion")
        if cred_result.get("vulnerable"):
            result["vulnerable"] = True
            result["findings"].extend(cred_result.get("findings", []))

        # Test 5: Multi-origin testing with advanced patterns
        advanced_origins = [
            ("https://evil.com", "cross_origin"),
            ("https://attacker.com", "cross_origin"),
            (f"https://evil.{domain}", "subdomain_bypass"),
            (f"https://{domain}.evil.com", "suffix_bypass"),
            ("null", "null_origin"),
            (f"http://{domain}", "protocol_mismatch"),
            (f"https://{domain}:1234", "port_bypass"),
        ]

        for origin, category in advanced_origins:
            origin_result = self.test_origin(url, origin)
            if origin_result.get("vulnerable"):
                result["vulnerable"] = True
                result["findings"].extend(origin_result.get("findings", []))

        # Test 6: Pre-flight request analysis
        preflight_result = self._test_preflight(url)
        result["details"]["tests_run"].append("preflight")
        if preflight_result.get("vulnerable"):
            result["vulnerable"] = True
            result["findings"].extend(preflight_result.get("findings", []))

        # Test 7: CORS + CSRF chain detection
        csrf_chain = self._detect_csrf_chain(url, domain)
        result["details"]["tests_run"].append("cors_csrf_chain")
        result["details"]["csrf_chain_possible"] = csrf_chain.get("vulnerable", False)
        if csrf_chain.get("vulnerable"):
            result["vulnerable"] = True
            result["findings"].extend(csrf_chain.get("findings", []))

        return result

    # ========================================================================
    # PRE-FLIGHT REQUEST ANALYSIS
    # ========================================================================

    def _test_preflight(self, url):
        """Test pre-flight (OPTIONS) request handling"""
        result = {
            "vulnerable": False,
            "findings": [],
            "details": {},
        }

        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'PUT',
                'Access-Control-Request-Headers': 'X-Custom-Header,Authorization',
                'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
            }

            resp = self.session.options(url, headers=headers, timeout=self.timeout,
                                       allow_redirects=False, verify=False)

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            acam = resp.headers.get('Access-Control-Allow-Methods', '')
            acah = resp.headers.get('Access-Control-Allow-Headers', '')

            result["details"] = {
                "status_code": resp.status_code,
                "acao": acao,
                "acac": acac,
                "acam": acam,
                "acah": acah,
            }

            if acao == 'https://evil.com' or acao == '*':
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "cors_preflight_misconfig",
                    "severity": "High" if acac.lower() == 'true' else "Medium",
                    "acao": acao,
                    "acac": acac,
                    "allowed_methods": acam,
                    "allowed_headers": acah,
                    "description": f"Pre-flight allows cross-origin: ACAO={acao}, Methods={acam}, Headers={acah}",
                })
                self._print(f"  [!] Pre-flight misconfig: Methods={acam}, Headers={acah}", YELLOW)

            # Check for dangerous methods
            if acam:
                dangerous_methods = [m.strip() for m in acam.split(',')
                                    if m.strip().upper() in ['PUT', 'DELETE', 'PATCH']]
                if dangerous_methods and (acao == 'https://evil.com' or acao == '*'):
                    result["findings"].append({
                        "type": "cors_dangerous_methods",
                        "severity": "High",
                        "methods": dangerous_methods,
                        "description": f"Cross-origin dangerous methods allowed: {dangerous_methods}",
                    })

        except Exception:
            pass

        return result

    # ========================================================================
    # CORS + CSRF CHAIN DETECTION
    # ========================================================================

    def _detect_csrf_chain(self, url, domain):
        """Detect if CORS misconfiguration can be chained with CSRF

        If CORS allows cross-origin requests with credentials, and the
        application has state-changing endpoints, then CSRF is possible.
        """
        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "csrf_chain_possible": False,
                "state_changing_endpoints": [],
            },
        }

        # State-changing endpoints to check
        csrf_endpoints = [
            "/api/user", "/api/v1/user", "/api/profile",
            "/api/v1/profile", "/api/account", "/api/v1/account",
            "/api/settings", "/api/v1/settings", "/api/password",
            "/api/v1/password", "/api/email", "/api/v1/email",
            "/user/update", "/account/update", "/profile/update",
        ]

        for endpoint in csrf_endpoints:
            test_url = f"{url.rstrip('/')}{endpoint}"
            try:
                headers = {
                    'Origin': 'https://evil.com',
                    'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
                }

                # Test OPTIONS first
                resp = self.session.options(test_url, headers=headers, timeout=self.timeout,
                                           allow_redirects=False, verify=False)

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')
                acam = resp.headers.get('Access-Control-Allow-Methods', '')

                if (acao == 'https://evil.com' or acao == '*') and \
                   any(m.strip().upper() in ['POST', 'PUT', 'PATCH', 'DELETE']
                       for m in (acam.split(',') if acam else [])):
                    result["vulnerable"] = True
                    result["details"]["csrf_chain_possible"] = True
                    result["details"]["state_changing_endpoints"].append({
                        "endpoint": endpoint,
                        "acao": acao,
                        "acac": acac,
                        "methods": acam,
                    })

                    severity = "Critical" if acac.lower() == 'true' else "High"
                    result["findings"].append({
                        "type": "cors_csrf_chain",
                        "severity": severity,
                        "endpoint": endpoint,
                        "acao": acao,
                        "acac": acac,
                        "methods": acam,
                        "description": f"CORS + CSRF chain: {endpoint} allows cross-origin state changes "
                                       f"(ACAO={acao}, Methods={acam}, ACAC={acac})",
                    })
                    self._print(f"  [!!!] CORS+CSRF chain: {endpoint}", RED)

            except Exception:
                continue

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for CORS Advanced Engine

        Args:
            target: Target URL
            scan_type: Type of scan to run
                - 'origin': Test specific origin
                - 'null': Test null origin
                - 'subdomain': Test subdomain bypass
                - 'wildcard': Test wildcard origin
                - 'credential': Test credential inclusion
                - 'misconfig': Full misconfiguration detection
                - 'full': Complete CORS scan (all tests)
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  CORS ADVANCED ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: CorsonE + CORScanner + CORSer{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'origin': lambda: self.test_origin(url, kwargs.get('origin', 'https://evil.com')),
            'null': lambda: self.test_null_origin(url),
            'subdomain': lambda: self.test_subdomain_bypass(url),
            'wildcard': lambda: self.test_wildcard(url),
            'credential': lambda: self.test_credential_inclusion(url),
            'misconfig': lambda: self.detect_misconfig(url),
        }

        if scan_type == 'full':
            # Run all tests via detect_misconfig (which already runs everything)
            return self.detect_misconfig(url)

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
    engine = CORSAdvancedEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
