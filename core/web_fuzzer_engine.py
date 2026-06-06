#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Web Fuzzer Engine
Fused from: FFUF + Kiterunner + custom Zylon fuzzing techniques
Capabilities:
  - Content discovery fuzzing (directories, files, endpoints)
  - API endpoint brute-forcing (Kiterunner-style)
  - Parameter fuzzing (GET/POST)
  - Header fuzzing
  - Virtual host discovery
  - Subdomain fuzzing
  - Custom wordlist support
  - Recursive fuzzing
  - Response filtering (status, size, words, lines, regex)
  - Rate limiting and threading
  - JSON API fuzzing
  - Multiple HTTP methods
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import time
import json
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, urlencode, quote

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS, REQUEST_DELAY,
    COMMON_DIRS, API_ENDPOINTS
)

from core.shared_infra import shared_session, regex_cache

# ============================================================================
# ANSI COLORS
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ============================================================================
# FUZZING WORDLISTS
# ============================================================================

CONTENT_DISCOVERY_WORDLIST = [
    "/", "/admin", "/login", "/dashboard", "/api", "/api/v1", "/api/v2",
    "/backup", "/config", "/console", "/css", "/js", "/img", "/images",
    "/uploads", "/files", "/tmp", "/temp", "/test", "/debug", "/dev",
    "/staging", "/.env", "/.git", "/.git/HEAD", "/.git/config",
    "/.svn", "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/wp-admin", "/wp-login.php", "/wp-content", "/wp-includes",
    "/robots.txt", "/sitemap.xml", "/favicon.ico", "/crossdomain.xml",
    "/server-status", "/server-info", "/phpinfo.php",
    "/swagger-ui/", "/swagger/", "/api-docs", "/graphql",
    "/actuator", "/actuator/health", "/actuator/env",
    "/jenkins", "/.ssh", "/database", "/db",
    "/phpmyadmin", "/adminer", "/pgadmin",
    "/solr", "/elastic", "/kibana", "/grafana",
    "/.aws/credentials", "/.env.backup", "/.env.local",
    "/config.json", "/config.yml", "/package.json", "/composer.json",
    "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
    "/users", "/posts", "/comments", "/search", "/upload",
    "/download", "/export", "/import", "/docs", "/health",
    "/status", "/info", "/metrics", "/version", "/ping",
    "/auth", "/oauth", "/token", "/session", "/profile",
    "/settings", "/notifications", "/messages", "/webhooks",
    "/callbacks", "/events", "/logs", "/audit", "/reports",
    "/analytics", "/admin/users", "/admin/settings", "/admin/logs",
    "/api/users", "/api/posts", "/api/auth", "/api/admin",
    "/api/config", "/api/search", "/api/upload", "/api/download",
    "/v1/users", "/v1/auth", "/v1/admin", "/v1/data",
    "/v2/users", "/v2/auth", "/v2/admin", "/v2/data",
    "/graphql", "/graphiql", "/playground",
    "/.well-known/", "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/sitemap.xml", "/robots.txt", "/humans.txt",
    "/favicon.ico", "/apple-touch-icon.png",
    "/manifest.json", "/service-worker.js", "/sw.js",
    "/browserconfig.xml", "/.well-known/assetlinks.json",
]

API_FUZZ_WORDLIST = [
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/api/users", "/api/user", "/api/admin", "/api/me",
    "/api/auth", "/api/login", "/api/register", "/api/logout",
    "/api/config", "/api/settings", "/api/search", "/api/query",
    "/api/data", "/api/upload", "/api/download", "/api/export",
    "/api/import", "/api/files", "/api/docs", "/api/swagger",
    "/api/openapi", "/api/graphql", "/api/rest", "/api/health",
    "/api/status", "/api/profile", "/api/account", "/api/posts",
    "/api/comments", "/api/orders", "/api/products", "/api/cart",
    "/api/payment", "/api/checkout", "/api/webhook", "/api/callback",
    "/api/notification", "/api/message", "/api/email", "/api/token",
    "/api/verify", "/api/reset", "/api/confirm", "/api/activate",
    "/api/otp", "/api/2fa", "/api/session", "/api/role",
    "/api/permission", "/api/log", "/api/audit", "/api/report",
    "/api/dashboard", "/api/analytics", "/api/metrics", "/api/batch",
    "/swagger.json", "/swagger-ui", "/api-docs",
    "/openapi.json", "/openapi.yaml",
    "/v1/users", "/v1/auth", "/v1/admin", "/v1/data",
    "/v2/users", "/v2/auth", "/v2/admin", "/v2/data",
    "/rest/api", "/rest/v1", "/rest/v2",
    "/oauth/token", "/oauth/authorize", "/oauth/revoke",
    "/graphql", "/graphiql",
    "/health", "/status", "/info", "/metrics",
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/configprops", "/actuator/beans",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

PARAM_FUZZ_WORDS = [
    "id", "user", "username", "name", "email", "password", "pass",
    "token", "key", "api_key", "apikey", "secret", "query", "q",
    "search", "page", "limit", "offset", "sort", "order", "filter",
    "type", "action", "cmd", "command", "exec", "run", "file",
    "path", "dir", "folder", "url", "link", "redirect", "return",
    "next", "callback", "format", "output", "debug", "test", "admin",
    "role", "access", "permission", "auth", "session", "cookie",
    "lang", "locale", "timezone", "date", "time", "from", "to",
    "start", "end", "min", "max", "count", "total", "size",
    "width", "height", "color", "style", "theme", "view", "mode",
    "status", "state", "enabled", "active", "visible", "hidden",
    "source", "target", "source_ip", "dest", "port", "host",
    "domain", "subdomain", "protocol", "method", "header",
    "body", "data", "payload", "content", "message", "subject",
    "description", "title", "tag", "category", "group", "class",
    "item", "item_id", "product", "product_id", "order", "order_id",
    "invoice", "payment", "amount", "price", "currency", "tax",
    "discount", "coupon", "code", "voucher", "ref", "reference",
]

HEADER_FUZZ_WORDS = {
    "X-Forwarded-For": ["127.0.0.1", "localhost", "0.0.0.0", "::1"],
    "X-Original-URL": ["/admin", "/debug", "/internal", "/console"],
    "X-Rewrite-URL": ["/admin", "/debug", "/internal"],
    "X-Custom-IP-Authorization": ["127.0.0.1", "localhost"],
    "X-Forwarded-Host": ["localhost", "127.0.0.1", "evil.com"],
    "X-Host": ["localhost", "127.0.0.1"],
    "X-Forwarded-Server": ["localhost"],
    "X-Real-IP": ["127.0.0.1", "::1"],
    "X-Client-IP": ["127.0.0.1"],
    "X-Remote-IP": ["127.0.0.1"],
    "X-Remote-Addr": ["127.0.0.1"],
    "X-Originating-IP": ["127.0.0.1"],
    "X-Access-Token": ["admin", "root", "test"],
    "X-Forwarded-Proto": ["https", "http"],
    "X-Frame-Options": ["SAMEORIGIN", "DENY", "ALLOW-FROM"],
    "Authorization": ["Bearer admin", "Basic YWRtaW46YWRtaW4="],
    "Content-Type": ["application/json", "application/xml", "multipart/form-data"],
    "Accept": ["application/json", "text/html", "application/xml"],
    "X-Api-Key": ["admin", "test", "root", "secret"],
    "X-Auth-Token": ["admin", "test", "token"],
    "X-Request-ID": ["1", "test"],
}

VHOST_WORDLIST = [
    "www", "mail", "ftp", "localhost", "admin", "test", "dev",
    "staging", "api", "app", "portal", "blog", "shop", "cdn",
    "static", "media", "images", "assets", "docs", "support",
    "help", "forum", "wiki", "git", "svn", "ci", "jenkins",
    "internal", "intranet", "vpn", "remote", "db", "database",
    "mysql", "postgres", "redis", "elastic", "mongo", "backend",
    "frontend", "web", "mobile", "ios", "android", "s3",
    "storage", "bucket", "backup", "archive", "old", "new",
    "beta", "alpha", "demo", "preview", "sandbox", "uat",
    "prod", "production", "stage", "development", "qa",
]

HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"]

JSON_FUZZ_PAYLOADS = [
    {"id": 1}, {"id": -1}, {"id": 0}, {"id": 999999},
    {"id": "1"}, {"id": None}, {"id": True}, {"id": False},
    {"user": "admin"}, {"role": "admin"}, {"isAdmin": True},
    {"admin": True}, {"role": "superadmin"}, {"access": "full"},
    {"debug": True}, {"verbose": True}, {"test": True},
    {"$gt": ""}, {"$ne": ""}, {"$where": "1==1"},
    {"__proto__": {"admin": True}}, {"constructor": {"prototype": {"admin": True}}},
]


# ============================================================================
# WEB FUZZER ENGINE
# ============================================================================

class WebFuzzerEngine:
    """
    Web Fuzzer Engine - Fused from FFUF + Kiterunner + Zylon Custom
    Supports content discovery, API fuzzing, parameter fuzzing, header fuzzing,
    vhost discovery, subdomain fuzzing, recursive fuzzing, and JSON API fuzzing.
    """

    def __init__(self, session=None, threads=MAX_THREADS, delay=REQUEST_DELAY,
                 timeout=DEFAULT_TIMEOUT, rate_limit=None):
        self.session = session or shared_session
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = False
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.lock = threading.Lock()
        self.results = []
        self._stop_event = threading.Event()

    def _request(self, url, method="GET", headers=None, data=None, json_data=None):
        """Make HTTP request with rate limiting"""
        if self._stop_event.is_set():
            return None
        try:
            if self.rate_limit:
                time.sleep(1.0 / self.rate_limit)
            elif self.delay > 0:
                time.sleep(self.delay)

            resp = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                json=json_data,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            return resp
        except requests.exceptions.RequestException:
            return None

    def _filter_response(self, resp, filters=None):
        """Filter responses based on status, size, words, lines, regex"""
        if resp is None:
            return False
        if not filters:
            return resp.status_code < 400

        if 'status_codes' in filters:
            if resp.status_code not in filters['status_codes']:
                return False

        if 'size_filter' in filters:
            body_len = len(resp.text)
            if body_len in filters['size_filter']:
                return False

        if 'min_size' in filters:
            if len(resp.text) < filters['min_size']:
                return False

        if 'max_size' in filters:
            if len(resp.text) > filters['max_size']:
                return False

        if 'regex_filter' in filters:
            if regex_cache.search(filters['regex_filter'], resp.text):
                return False

        if 'regex_match' in filters:
            if not regex_cache.search(filters['regex_match'], resp.text):
                return False

        return True

    def _fuzz_single_path(self, base_url, path, method="GET", filters=None):
        """Fuzz a single path"""
        url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
        resp = self._request(url, method=method)
        if self._filter_response(resp, filters):
            result = {
                'url': url,
                'path': path,
                'method': method,
                'status_code': resp.status_code,
                'content_length': len(resp.text) if resp else 0,
                'word_count': len(resp.text.split()) if resp else 0,
                'line_count': resp.text.count('\n') + 1 if resp else 0,
                'title': self._extract_title(resp.text) if resp else '',
                'redirect': resp.headers.get('Location', '') if resp else '',
            }
            with self.lock:
                self.results.append(result)
            return result
        return None

    def _extract_title(self, html):
        """Extract page title from HTML"""
        match = regex_cache.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ''

    # ========================================================================
    # CONTENT DISCOVERY FUZZING
    # ========================================================================

    def fuzz_content(self, target, wordlist=None, filters=None):
        """
        Content discovery fuzzing - directories, files, endpoints
        FFUF-style with threading and response filtering
        """
        self.results = []
        self._stop_event.clear()

        if not target.startswith('http'):
            target = f"https://{target}"

        words = wordlist if wordlist else CONTENT_DISCOVERY_WORDLIST

        print(f"{CYAN}[ZYLON WEB FUZZER] Starting content discovery on {target}{RESET}")
        print(f"{CYAN}[*] Wordlist: {len(words)} entries | Threads: {self.threads}{RESET}")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for word in words:
                if self._stop_event.is_set():
                    break
                futures.append(executor.submit(self._fuzz_single_path, target, word, "GET", filters))

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    print(f"{YELLOW}[*] Progress: {completed}/{len(words)} | Found: {len(self.results)}{RESET}")

        findings = self.results
        print(f"{GREEN}[+] Content discovery complete: {len(findings)} results found{RESET}")

        return {
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'details': {
                'target': target,
                'total_tested': len(words),
                'total_found': len(findings),
                'interesting': [f for f in findings if f.get('status_code') in [200, 301, 302, 403, 401]],
            },
            'scan_type': 'content_discovery'
        }

    # ========================================================================
    # API ENDPOINT FUZZING
    # ========================================================================

    def fuzz_api(self, target, api_wordlist=None, filters=None):
        """
        API endpoint brute-forcing - Kiterunner-style
        Tests multiple HTTP methods and content types
        """
        self.results = []
        self._stop_event.clear()

        if not target.startswith('http'):
            target = f"https://{target}"

        words = api_wordlist if api_wordlist else API_FUZZ_WORDLIST

        print(f"{MAGENTA}[ZYLON API FUZZER] Starting API endpoint fuzzing on {target}{RESET}")
        print(f"{MAGENTA}[*] API wordlist: {len(words)} entries | Methods: GET, POST, PUT, DELETE{RESET}")

        api_findings = []
        lock = threading.Lock()

        def fuzz_api_endpoint(path):
            if self._stop_event.is_set():
                return
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))

            for method in ["GET", "POST", "PUT", "DELETE"]:
                resp = self._request(url, method=method)
                if resp and resp.status_code != 404:
                    result = {
                        'url': url,
                        'path': path,
                        'method': method,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                        'content_type': resp.headers.get('Content-Type', ''),
                        'server': resp.headers.get('Server', ''),
                    }
                    with lock:
                        api_findings.append(result)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(fuzz_api_endpoint, w) for w in words]
            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 30 == 0:
                    print(f"{YELLOW}[*] Progress: {completed}/{len(words)} | Found: {len(api_findings)}{RESET}")

        print(f"{GREEN}[+] API fuzzing complete: {len(api_findings)} endpoints found{RESET}")

        return {
            'vulnerable': len(api_findings) > 0,
            'findings': api_findings,
            'details': {
                'target': target,
                'total_tested': len(words),
                'total_found': len(api_findings),
                'methods_tested': ["GET", "POST", "PUT", "DELETE"],
                'authenticated_endpoints': [f for f in api_findings if f.get('status_code') in [401, 403]],
                'public_endpoints': [f for f in api_findings if f.get('status_code') == 200],
            },
            'scan_type': 'api_fuzz'
        }

    # ========================================================================
    # PARAMETER FUZZING
    # ========================================================================

    def fuzz_parameters(self, url, method='GET', filters=None):
        """
        Parameter fuzzing - GET/POST parameter discovery
        Tests common parameter names with various payloads
        """
        self.results = []
        self._stop_event.clear()

        if not url.startswith('http'):
            url = f"https://{url}"

        print(f"{CYAN}[ZYLON PARAM FUZZER] Starting parameter fuzzing on {url}{RESET}")
        print(f"{CYAN}[*] Method: {method} | Parameters: {len(PARAM_FUZZ_WORDS)}{RESET}")

        # Get baseline response
        baseline_resp = self._request(url, method=method)
        baseline_len = len(baseline_resp.text) if baseline_resp else 0
        baseline_code = baseline_resp.status_code if baseline_resp else 0

        param_findings = []
        lock = threading.Lock()

        test_values = ["test", "1", "admin", "true", "{{7*7}}", "' OR '1'='1", "<script>alert(1)</script>"]

        def fuzz_param(param_name):
            if self._stop_event.is_set():
                return
            for value in test_values:
                try:
                    if method.upper() == 'GET':
                        sep = '&' if '?' in url else '?'
                        test_url = f"{url}{sep}{param_name}={quote(value)}"
                        resp = self._request(test_url, method='GET')
                    else:
                        resp = self._request(url, method='POST', data={param_name: value})

                    if resp and (resp.status_code != baseline_code or abs(len(resp.text) - baseline_len) > 100):
                        result = {
                            'parameter': param_name,
                            'value': value,
                            'status_code': resp.status_code,
                            'content_length': len(resp.text),
                            'baseline_diff': len(resp.text) - baseline_len,
                            'method': method,
                            'url': url,
                        }
                        # Check for template injection
                        if '49' in resp.text and value == '{{7*7}}':
                            result['finding_type'] = 'SSTI'
                        # Check for SQL injection
                        if any(err in resp.text.lower() for err in ['sql', 'mysql', 'syntax error', 'ora-']):
                            result['finding_type'] = 'SQLi'
                        # Check for XSS
                        if value == "<script>alert(1)</script>" and value in resp.text:
                            result['finding_type'] = 'XSS'

                        with lock:
                            param_findings.append(result)
                except Exception:
                    pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(fuzz_param, p) for p in PARAM_FUZZ_WORDS]
            for future in as_completed(futures):
                pass

        print(f"{GREEN}[+] Parameter fuzzing complete: {len(param_findings)} parameters found{RESET}")

        return {
            'vulnerable': len(param_findings) > 0,
            'findings': param_findings,
            'details': {
                'url': url,
                'method': method,
                'total_params_tested': len(PARAM_FUZZ_WORDS),
                'total_found': len(param_findings),
                'ssti_params': [f for f in param_findings if f.get('finding_type') == 'SSTI'],
                'sqli_params': [f for f in param_findings if f.get('finding_type') == 'SQLi'],
                'xss_params': [f for f in param_findings if f.get('finding_type') == 'XSS'],
            },
            'scan_type': 'parameter_fuzz'
        }

    # ========================================================================
    # HEADER FUZZING
    # ========================================================================

    def fuzz_headers(self, url, filters=None):
        """
        Header fuzzing - test various headers for bypass/info leak
        """
        self.results = []
        self._stop_event.clear()

        if not url.startswith('http'):
            url = f"https://{url}"

        print(f"{MAGENTA}[ZYLON HEADER FUZZER] Starting header fuzzing on {url}{RESET}")

        # Get baseline
        baseline_resp = self._request(url)
        baseline_code = baseline_resp.status_code if baseline_resp else 0
        baseline_len = len(baseline_resp.text) if baseline_resp else 0
        baseline_headers = dict(baseline_resp.headers) if baseline_resp else {}

        header_findings = []

        for header_name, header_values in HEADER_FUZZ_WORDS.items():
            for value in header_values:
                resp = self._request(url, headers={header_name: value})
                if resp:
                    code_diff = resp.status_code != baseline_code
                    size_diff = abs(len(resp.text) - baseline_len) > 50
                    new_headers = set(resp.headers.keys()) - set(baseline_headers.keys())

                    if code_diff or size_diff or new_headers:
                        header_findings.append({
                            'header': header_name,
                            'value': value,
                            'status_code': resp.status_code,
                            'baseline_status': baseline_code,
                            'content_length': len(resp.text),
                            'baseline_length': baseline_len,
                            'new_headers': list(new_headers),
                            'finding_type': 'bypass' if code_diff and resp.status_code == 200 else 'info_leak',
                        })

        print(f"{GREEN}[+] Header fuzzing complete: {len(header_findings)} findings{RESET}")

        return {
            'vulnerable': len(header_findings) > 0,
            'findings': header_findings,
            'details': {
                'url': url,
                'total_headers_tested': sum(len(v) for v in HEADER_FUZZ_WORDS.values()),
                'total_found': len(header_findings),
                'bypass_findings': [f for f in header_findings if f.get('finding_type') == 'bypass'],
                'info_leak_findings': [f for f in header_findings if f.get('finding_type') == 'info_leak'],
            },
            'scan_type': 'header_fuzz'
        }

    # ========================================================================
    # VIRTUAL HOST DISCOVERY
    # ========================================================================

    def fuzz_vhost(self, target, filters=None):
        """
        Virtual host discovery - test different Host headers
        """
        self.results = []
        self._stop_event.clear()

        if not target.startswith('http'):
            target = f"https://{target}"

        parsed = urlparse(target)
        base_domain = parsed.hostname or target.replace('https://', '').replace('http://', '').split('/')[0]

        print(f"{CYAN}[ZYLON VHOST FUZZER] Starting vhost discovery on {base_domain}{RESET}")

        # Get baseline
        baseline_resp = self._request(target)
        baseline_code = baseline_resp.status_code if baseline_resp else 0
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        vhost_findings = []

        for vhost in VHOST_WORDLIST:
            test_host = f"{vhost}.{base_domain}"
            resp = self._request(target, headers={'Host': test_host})

            if resp:
                is_different = (resp.status_code != baseline_code or
                                abs(len(resp.text) - baseline_len) > 100)
                if is_different:
                    vhost_findings.append({
                        'vhost': test_host,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                        'baseline_status': baseline_code,
                        'baseline_length': baseline_len,
                        'title': self._extract_title(resp.text),
                        'server': resp.headers.get('Server', ''),
                    })

        print(f"{GREEN}[+] Vhost discovery complete: {len(vhost_findings)} virtual hosts found{RESET}")

        return {
            'vulnerable': len(vhost_findings) > 0,
            'findings': vhost_findings,
            'details': {
                'target': base_domain,
                'total_tested': len(VHOST_WORDLIST),
                'total_found': len(vhost_findings),
                'unique_vhosts': list(set(f['vhost'] for f in vhost_findings)),
            },
            'scan_type': 'vhost_discovery'
        }

    # ========================================================================
    # RECURSIVE FUZZING
    # ========================================================================

    def recursive_fuzz(self, target, depth=2, filters=None):
        """
        Recursive fuzzing - discover directories and recurse into them
        """
        self.results = []
        self._stop_event.clear()

        if not target.startswith('http'):
            target = f"https://{target}"

        print(f"{YELLOW}[ZYLON RECURSIVE FUZZER] Starting recursive fuzzing on {target} (depth={depth}){RESET}")

        all_findings = []
        discovered_dirs = set()
        scanned_paths = set()

        def _recurse(base_url, current_depth):
            if current_depth <= 0 or self._stop_event.is_set():
                return

            quick_paths = ["/admin", "/api", "/backup", "/config", "/console",
                           "/debug", "/dev", "/docs", "/internal", "/login",
                           "/private", "/secret", "/test", "/tmp", "/upload",
                           "/users", "/v1", "/v2", "/dashboard", "/manage"]

            # Catch-all detection: track response signatures
            response_signatures = []  # list of (status_code, content_length)
            catch_all_detected = False

            for path in quick_paths:
                if self._stop_event.is_set():
                    break
                full_path = base_url.rstrip('/') + path
                normalized = full_path.lower().rstrip('/')
                if normalized in scanned_paths:
                    continue
                scanned_paths.add(normalized)

                # Safety limit: stop if too many findings
                if len(all_findings) >= 500:
                    return

                resp = self._request(full_path)
                if resp and resp.status_code in [200, 301, 302, 403]:
                    finding = {
                        'url': full_path,
                        'path': path,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                        'depth': depth - current_depth + 1,
                        'title': self._extract_title(resp.text),
                    }
                    all_findings.append(finding)
                    response_signatures.append((resp.status_code, len(resp.text)))

                    # Catch-all detection: if last 5+ responses have same
                    # status and similar size, likely a catch-all route
                    if len(response_signatures) >= 5:
                        recent = response_signatures[-5:]
                        statuses = [s[0] for s in recent]
                        sizes = [s[1] for s in recent]
                        if len(set(statuses)) == 1:
                            avg_size = sum(sizes) / len(sizes)
                            if avg_size > 0 and all(abs(s - avg_size) < avg_size * 0.1 for s in sizes):
                                catch_all_detected = True

                    # Only recurse if NOT a catch-all
                    if (not catch_all_detected and
                            resp.status_code in [200, 301, 302] and
                            current_depth > 1 and
                            len(all_findings) < 500):
                        discovered_dirs.add(full_path)
                        _recurse(full_path, current_depth - 1)

        _recurse(target, depth)

        print(f"{GREEN}[+] Recursive fuzzing complete: {len(all_findings)} results (dirs: {len(discovered_dirs)}){RESET}")

        return {
            'vulnerable': len(all_findings) > 0,
            'findings': all_findings,
            'details': {
                'target': target,
                'max_depth': depth,
                'total_found': len(all_findings),
                'discovered_directories': list(discovered_dirs),
                'deep_results': [f for f in all_findings if f.get('depth', 1) > 1],
            },
            'scan_type': 'recursive_fuzz'
        }

    # ========================================================================
    # JSON API FUZZING
    # ========================================================================

    def fuzz_json_api(self, url, filters=None):
        """
        JSON API fuzzing - test JSON payloads against API endpoints
        """
        self.results = []
        self._stop_event.clear()

        if not url.startswith('http'):
            url = f"https://{url}"

        print(f"{MAGENTA}[ZYLON JSON FUZZER] Starting JSON API fuzzing on {url}{RESET}")

        # Get baseline
        baseline_resp = self._request(url, method='POST', json_data={})
        baseline_code = baseline_resp.status_code if baseline_resp else 0
        baseline_len = len(baseline_resp.text) if baseline_resp else 0

        json_findings = []

        for payload in JSON_FUZZ_PAYLOADS:
            for method in ["POST", "PUT", "PATCH"]:
                resp = self._request(url, method=method, json_data=payload)
                if resp:
                    code_diff = resp.status_code != baseline_code
                    size_diff = abs(len(resp.text) - baseline_len) > 50
                    is_error = resp.status_code >= 500

                    if code_diff or size_diff or is_error:
                        json_findings.append({
                            'payload': payload,
                            'method': method,
                            'status_code': resp.status_code,
                            'content_length': len(resp.text),
                            'finding_type': 'proto_pollution' if '__proto__' in str(payload) else 'nosql_injection' if '$' in str(payload) else 'data_manipulation',
                            'response_snippet': resp.text[:200] if resp.text else '',
                        })

        print(f"{GREEN}[+] JSON API fuzzing complete: {len(json_findings)} findings{RESET}")

        return {
            'vulnerable': len(json_findings) > 0,
            'findings': json_findings,
            'details': {
                'url': url,
                'total_payloads': len(JSON_FUZZ_PAYLOADS),
                'total_found': len(json_findings),
                'proto_pollution': [f for f in json_findings if f.get('finding_type') == 'proto_pollution'],
                'nosql_injection': [f for f in json_findings if f.get('finding_type') == 'nosql_injection'],
                'data_manipulation': [f for f in json_findings if f.get('finding_type') == 'data_manipulation'],
            },
            'scan_type': 'json_api_fuzz'
        }

    # ========================================================================
    # FULL SCAN
    # ========================================================================

    def full_scan(self, target, filters=None):
        """
        Full web fuzzer scan - content + API + params + headers + vhost
        """
        print(f"{BOLD}{RED}[ZYLON WEB FUZZER] FULL SCAN on {target}{RESET}")

        all_results = {}

        # Phase 1: Content Discovery
        print(f"\n{CYAN}=== Phase 1: Content Discovery ==={RESET}")
        all_results['content'] = self.fuzz_content(target, filters=filters)

        # Phase 2: API Fuzzing
        print(f"\n{MAGENTA}=== Phase 2: API Endpoint Fuzzing ==={RESET}")
        all_results['api'] = self.fuzz_api(target, filters=filters)

        # Phase 3: Parameter Fuzzing
        url = f"https://{target}" if not target.startswith('http') else target
        print(f"\n{CYAN}=== Phase 3: Parameter Fuzzing ==={RESET}")
        all_results['params'] = self.fuzz_parameters(url, filters=filters)

        # Phase 4: Header Fuzzing
        print(f"\n{MAGENTA}=== Phase 4: Header Fuzzing ==={RESET}")
        all_results['headers'] = self.fuzz_headers(url, filters=filters)

        # Phase 5: VHost Discovery
        print(f"\n{CYAN}=== Phase 5: Virtual Host Discovery ==={RESET}")
        all_results['vhost'] = self.fuzz_vhost(target, filters=filters)

        # Summary
        total_findings = sum(len(r.get('findings', [])) for r in all_results.values())
        vuln_types = [k for k, v in all_results.items() if v.get('vulnerable')]

        print(f"\n{BOLD}{GREEN}[+] FULL SCAN COMPLETE{RESET}")
        print(f"{GREEN}[*] Total findings: {total_findings}{RESET}")
        print(f"{GREEN}[*] Vulnerable categories: {', '.join(vuln_types)}{RESET}")

        return {
            'vulnerable': len(vuln_types) > 0,
            'findings': all_results,
            'details': {
                'target': target,
                'total_findings': total_findings,
                'vulnerable_categories': vuln_types,
                'content_discovery': len(all_results.get('content', {}).get('findings', [])),
                'api_endpoints': len(all_results.get('api', {}).get('findings', [])),
                'parameter_issues': len(all_results.get('params', {}).get('findings', [])),
                'header_issues': len(all_results.get('headers', {}).get('findings', [])),
                'vhosts': len(all_results.get('vhost', {}).get('findings', [])),
            },
            'scan_type': 'web_fuzzer_full'
        }

    # ========================================================================
    # MAIN ENTRY
    # ========================================================================

    def run(self, target, scan_type='content', **kwargs):
        """Main entry point"""
        scan_map = {
            'content': lambda: self.fuzz_content(target, **kwargs),
            'api': lambda: self.fuzz_api(target, **kwargs),
            'parameters': lambda: self.fuzz_parameters(target, **kwargs),
            'headers': lambda: self.fuzz_headers(target, **kwargs),
            'vhost': lambda: self.fuzz_vhost(target, **kwargs),
            'recursive': lambda: self.recursive_fuzz(target, **kwargs),
            'json_api': lambda: self.fuzz_json_api(target, **kwargs),
            'full': lambda: self.full_scan(target, **kwargs),
        }

        if scan_type in scan_map:
            return scan_map[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}', 'available': list(scan_map.keys())},
            'scan_type': scan_type
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='content', **kwargs):
    """
    Module-level run function for ZYLON FUSION integration.
    Returns dict: 'vulnerable', 'findings', 'details', 'scan_type'
    """
    engine = WebFuzzerEngine(
        threads=kwargs.pop('threads', MAX_THREADS),
        delay=kwargs.pop('delay', REQUEST_DELAY),
        timeout=kwargs.pop('timeout', DEFAULT_TIMEOUT),
    )
    return engine.run(target, scan_type=scan_type, **kwargs)
