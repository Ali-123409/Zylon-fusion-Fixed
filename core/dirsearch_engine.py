#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Dirsearch-Style Directory Brute Force Engine
Fused from: Dirsearch (https://github.com/maurosoria/dirsearch)
Capabilities:
  - Directory/file brute forcing
  - Recursive scanning capability
  - Extension-based filtering (php, asp, js, html, txt, etc.)
  - Multithreaded scanning with configurable threads
  - Response code filtering (200, 301, 302, 403, etc.)
  - Custom wordlist support
  - Content length filtering to remove false positives
  - Progress tracking
  - Default wordlist with 500+ common paths
  - Multiple HTTP methods (GET, HEAD, POST)
  - Rate limiting
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import time
import json
import random
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.shared_infra import shared_session, regex_cache, PayloadInjector

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
# DEFAULT WORDLIST (500+ common paths - from dirsearch + ZYLON custom)
# ============================================================================

DEFAULT_WORDLIST = [
    # Administrative
    "admin", "admin/", "admin/login", "admin/dashboard", "admin/console",
    "admin/config", "admin/settings", "admin panel", "administrator",
    "administrator/", "administrator/login", "backend", "backend/",
    "cpanel", "cpanel/", "control", "control/", "manage", "manage/",
    "manager", "manager/", "panel", "panel/", "sysadmin", "webadmin",
    # Authentication
    "login", "login/", "signin", "signin/", "signup", "signup/",
    "register", "register/", "logout", "logout/", "auth", "auth/",
    "oauth", "oauth/", "sso", "sso/", "forgot-password", "reset-password",
    # API endpoints
    "api", "api/", "api/v1", "api/v2", "api/v3", "api/v1/", "api/v2/",
    "api/docs", "api/swagger", "api/swagger.json", "api/openapi.json",
    "rest", "rest/", "graphql", "graphql/", "graphiql",
    "swagger-ui", "swagger-ui/", "swagger.json", "swagger.yaml",
    "openapi.json", "openapi.yaml", "api-docs", "api-docs/",
    # Config & sensitive
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.backup", ".env.bak", ".env.save", ".env.old",
    "config", "config/", "config.php", "config.yml", "config.yaml",
    "config.json", "config.ini", "config.asp", "config.aspx",
    "wp-config.php", "wp-config.php.bak", "settings.py", "settings.php",
    "application.properties", "application.yml", "appsettings.json",
    "web.config", "database.yml", "composer.json", "package.json",
    # CMS
    "wp-admin", "wp-admin/", "wp-login.php", "wp-content", "wp-includes",
    "wp-cron.php", "xmlrpc.php", "wp-json", "wp-json/",
    "administrator/", "joomla", "drupal",
    # Database
    "phpmyadmin", "phpmyadmin/", "adminer", "adminer.php",
    "pgadmin", "mongodb", "mysql", "db", "database", "database/",
    # Directories
    "backup", "backup/", "backups", "backups/", "old", "old/",
    "archive", "archive/", "temp", "temp/", "tmp", "tmp/",
    "test", "test/", "debug", "debug/", "dev", "dev/",
    "staging", "staging/", "beta", "beta/", "demo", "demo/",
    "upload", "upload/", "uploads", "uploads/", "files", "files/",
    "download", "download/", "downloads", "downloads/",
    "images", "images/", "img", "img/", "assets", "assets/",
    "static", "static/", "media", "media/", "public", "public/",
    "css", "css/", "js", "js/", "fonts", "fonts/",
    # Documentation
    "docs", "docs/", "documentation", "documentation/",
    "readme", "readme.md", "README.md", "README", "readme.txt",
    "changelog", "changelog.md", "CHANGELOG.md", "CHANGELOG",
    "license", "LICENSE", "LICENSE.md",
    # Server info & status
    "server-status", "server-info", "phpinfo.php", "info.php",
    "test.php", "pi.php", "status", "status/", "health", "health/",
    "metrics", "metrics/", "info", "info/",
    # Version control
    ".git", ".git/", ".git/HEAD", ".git/config", ".git/refs",
    ".git/refs/heads", ".git/refs/heads/master", ".git/refs/heads/main",
    ".svn", ".svn/", ".svn/entries", ".svn/wc.db",
    ".hg", ".hg/", ".hg/store", ".hg/hgrc",
    ".bzr", ".bzr/", ".bzr/checkout",
    # Docker & CI/CD
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".dockerenv", "Jenkinsfile", ".gitlab-ci.yml",
    ".travis.yml", "bitbucket-pipelines.yml",
    # Security
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".htaccess", ".htpasswd", ".DS_Store",
    "security.txt", ".well-known", ".well-known/",
    ".well-known/security.txt",
    # Cloud
    ".aws", ".aws/credentials", ".aws/config",
    "service-account.json", "credentials.json", "client_secret.json",
    "firebase", "firebase/",
    # Logs
    "logs", "logs/", "log", "log/",
    "error.log", "access.log", "debug.log", "app.log",
    # Sensitive files
    "id_rsa", "id_rsa.pub", "authorized_keys", "known_hosts",
    ".ssh", ".ssh/", "ssh_config",
    # Misc web paths
    "index", "index.php", "index.html", "index.asp", "index.aspx",
    "home", "home/", "main", "main/",
    "search", "search/", "query", "query/",
    "profile", "profile/", "account", "account/",
    "user", "user/", "users", "users/",
    "dashboard", "dashboard/", "console", "console/",
    "report", "report/", "reports", "reports/",
    "analytics", "analytics/", "tracking", "tracking/",
    "cart", "cart/", "checkout", "checkout/",
    "shop", "shop/", "store", "store/",
    "blog", "blog/", "news", "news/",
    "forum", "forum/", "wiki", "wiki/",
    "help", "help/", "support", "support/",
    "contact", "contact/", "about", "about/",
    "faq", "faq/", "terms", "terms/",
    "privacy", "privacy/", "legal", "legal/",
    # Spring Boot / Java
    "actuator", "actuator/", "actuator/health", "actuator/env",
    "actuator/mappings", "actuator/configprops", "actuator/beans",
    "actuator/info", "actuator/metrics", "actuator/trace",
    # Common file extensions to try
    "index.php.bak", "index.php~", "index.php.old",
    "index.html.bak", "index.html~", "index.html.old",
    "web.config.bak", "web.config~",
    # Cache & session
    "cache", "cache/", "session", "session/",
    # Webhooks
    "webhook", "webhook/", "webhooks", "webhooks/",
    "callback", "callback/", "notify", "notify/",
    # Monitoring
    "grafana", "grafana/", "prometheus", "prometheus/",
    "kibana", "kibana/", "elastic", "elastic/",
    "jenkins", "jenkins/", "ci", "ci/",
    # Mobile API
    "mobile", "mobile/", "api/mobile", "m", "m/",
    "android", "ios",
    # Additional paths
    "vendor", "vendor/", "node_modules", "node_modules/",
    "bower_components", "bower_components/",
    "dist", "dist/", "build", "build/",
    "src", "src/", "lib", "lib/",
    "bin", "bin/", "scripts", "scripts/",
    "tools", "tools/", "utils", "utils/",
    # Hidden paths
    ".hidden", ".secret", ".private", ".internal",
    "hidden", "secret", "private", "internal",
    # More admin paths
    "sys", "sys/", "system", "system/",
    "setup", "setup/", "install", "install/",
    "wizard", "wizard/", "init", "init/",
    # Proxy & forwarding
    "proxy", "proxy/", "gateway", "gateway/",
    "forward", "forward/", "redirect", "redirect/",
    # Additional web paths
    "bookmark", "bookmark/", "favorite", "favorite/",
    "rss", "rss/", "feed", "feed/",
    "atom", "atom/", "sitemap", "sitemap/",
    "calendar", "calendar/", "schedule", "schedule/",
    "mail", "mail/", "email", "email/",
    "newsletter", "newsletter/", "subscribe", "subscribe/",
    "unsubscribe", "unsubscribe/",
    "print", "print/", "export", "export/",
    "import", "import/", "download", "download/",
    "attachment", "attachment/", "embed", "embed/",
    "share", "share/", "social", "social/",
    "comment", "comment/", "review", "review/",
    "rating", "rating/", "vote", "vote/",
    "tag", "tag/", "category", "category/",
    "label", "label/", "flag", "flag/",
    "bookmark", "bookmark/", "snippet", "snippet/",
    "plugin", "plugin/", "plugins", "plugins/",
    "theme", "theme/", "themes", "themes/",
    "module", "module/", "modules", "modules/",
    "component", "component/", "components", "components/",
    "widget", "widget/", "widgets", "widgets/",
    "block", "block/", "blocks", "blocks/",
    "layout", "layout/", "layouts", "layouts/",
    "template", "template/", "templates", "templates/",
    "partial", "partial/", "partials", "partials/",
    "view", "view/", "views", "views/",
    "page", "page/", "pages", "pages/",
    "post", "post/", "posts", "posts/",
    "article", "article/", "articles", "articles/",
    "entry", "entry/", "entries", "entries/",
    "item", "item/", "items", "items/",
    "product", "product/", "products", "products/",
    "order", "order/", "orders", "orders/",
    "invoice", "invoice/", "invoices", "invoices/",
    "payment", "payment/", "payments", "payments/",
    "transaction", "transaction/", "transactions", "transactions/",
    "receipt", "receipt/", "receipts", "receipts/",
    "invoice", "invoice/", "invoices", "invoices/",
    "quote", "quote/", "quotes", "quotes/",
    "estimate", "estimate/", "estimates", "estimates/",
    "ticket", "ticket/", "tickets", "tickets/",
    "issue", "issue/", "issues", "issues/",
    "task", "task/", "tasks", "tasks/",
    "project", "project/", "projects", "projects/",
    "team", "team/", "teams", "teams/",
    "member", "member/", "members", "members/",
    "group", "group/", "groups", "groups/",
    "role", "role/", "roles", "roles/",
    "permission", "permission/", "permissions", "permissions/",
    "policy", "policy/", "policies", "policies/",
    "rule", "rule/", "rules", "rules/",
    "setting", "setting/", "settings", "settings/",
    "option", "option/", "options", "options/",
    "preference", "preference/", "preferences", "preferences/",
    "configuration", "configuration/", "configurations", "configurations/",
]

# Default extensions to scan
DEFAULT_EXTENSIONS = [
    "", ".php", ".asp", ".aspx", ".jsp", ".html", ".htm",
    ".js", ".css", ".txt", ".json", ".xml", ".yml", ".yaml",
    ".bak", ".old", ".save", ".tmp", ".swp", ".zip", ".tar.gz",
    ".log", ".sql", ".db", ".conf", ".cfg", ".ini", ".env",
]


class DirsearchEngine:
    """Dirsearch-Style Directory Brute Force Engine
    Fused from dirsearch with ZYLON enhancements
    v5.0 Nuclear: recursive scanning, extension filtering, multithreaded,
    progress tracking, custom wordlist, multiple HTTP methods, rate limiting
    """

    def __init__(self, target=None, threads=20, timeout=10, proxy=None,
                 extensions=None, wordlist=None, output_dir=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.extensions = extensions or [""]
        self.wordlist = wordlist or DEFAULT_WORDLIST
        self.output_dir = output_dir or os.path.join(os.path.expanduser("~"), ".zylon", "results")

        self.session = shared_session

        self.results = []
        self.found_paths = set()
        self.baseline_length = {}  # path -> content_length for false positive reduction
        self._stop_event = threading.Event()
        self._progress = {"total": 0, "scanned": 0, "found": 0}

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _log(self, msg, color=C):
        """Print colored log message"""
        print(f"  {color}{BOLD}[ZYLON-DIRB]{RESET} {color}{msg}{RESET}")

    def _get_base_url(self):
        """Get base URL from target"""
        if self.target.startswith('http'):
            return self.target.rstrip('/')
        return f"https://{self.target.rstrip('/')}"

    def _get_baseline(self, url):
        """Get baseline response for false positive comparison"""
        try:
            # Request a random path to get 404 baseline
            random_path = f"/{random.randint(100000, 999999)}_{random.randint(100000, 999999)}"
            resp = self.session.get(f"{url}{random_path}", timeout=self.timeout, allow_redirects=False)
            if resp:
                self.baseline_length['status'] = resp.status_code
                self.baseline_length['length'] = len(resp.text)
                self.baseline_length['text_sample'] = resp.text[:200]
        except Exception:
            self.baseline_length = {'status': 404, 'length': 0, 'text_sample': ''}

    def _is_false_positive(self, resp, path):
        """Check if a response is likely a false positive"""
        if not resp:
            return True

        # If status is 404, definitely false positive
        if resp.status_code == 404:
            return True

        # Check if response is same as 404 baseline
        baseline_status = self.baseline_length.get('status', 404)
        baseline_length = self.baseline_length.get('length', 0)
        baseline_sample = self.baseline_length.get('text_sample', '')

        # Some servers return 200 for custom 404 pages
        if resp.status_code == 200 and baseline_status == 200:
            # Compare content length (within 10% tolerance)
            if baseline_length > 0 and abs(len(resp.text) - baseline_length) < baseline_length * 0.1:
                # Compare content sample
                if resp.text[:200] == baseline_sample:
                    return True

        # Check for common custom 404 indicators
        custom_404_indicators = [
            "not found", "page not found", "doesn't exist",
            "no longer available", "has been removed",
            "error 404", "404 error", "404 -",
        ]
        text_lower = resp.text.lower()
        for indicator in custom_404_indicators:
            if indicator in text_lower and resp.status_code in (200, 301, 302):
                return True

        return False

    # ========================================================================
    # MAIN SCAN
    # ========================================================================

    def scan(self, target=None, extensions=None, threads=20):
        """Main directory scan

        Args:
            target: Target URL
            extensions: List of extensions to try (e.g., ['.php', '.asp'])
            threads: Number of concurrent threads

        Returns:
            dict with scan results
        """
        self.target = target or self.target
        exts = extensions or self.extensions
        threads = min(threads, 50)  # Cap at 50 threads
        base_url = self._get_base_url()

        self._log(f"Starting directory scan on {base_url}", C)
        self._log(f"  Wordlist: {len(self.wordlist)} paths | Extensions: {len(exts)} | Threads: {threads}", Y)

        results = {
            "target": base_url,
            "found": [],
            "total_scanned": 0,
            "total_found": 0,
            "scan_type": "directory_scan",
            "timestamp": datetime.now().isoformat(),
        }

        # Get baseline for false positive reduction
        self._get_baseline(base_url)

        # Build full path list with extensions
        paths_to_scan = []
        for path in self.wordlist:
            for ext in exts:
                # Avoid double extensions (e.g., admin/.php)
                if path.endswith('/') and ext:
                    continue
                # Avoid adding extension if path already has one
                if ext and '.' in path.split('/')[-1] and not path.endswith('/'):
                    continue
                full_path = f"/{path}{ext}" if not path.startswith('/') else f"{path}{ext}"
                # Clean up the path
                full_path = full_path.replace('//', '/')
                paths_to_scan.append(full_path)

        # Remove duplicates
        paths_to_scan = list(set(paths_to_scan))
        self._progress["total"] = len(paths_to_scan)
        self._progress["scanned"] = 0
        self._progress["found"] = 0

        self._log(f"  Total paths to scan: {len(paths_to_scan)}", Y)

        lock = threading.Lock()
        rate_limit = 0.05  # 50ms between requests per thread

        def scan_path(path):
            if self._stop_event.is_set():
                return None

            url = f"{base_url}{path}"
            time.sleep(rate_limit * random.random())  # Random jitter for rate limiting

            try:
                # Try HEAD first (faster)
                resp = self.session.head(url, timeout=self.timeout, allow_redirects=False)

                if resp and resp.status_code in (200, 301, 302, 403, 401, 500):
                    # Verify with GET if interesting
                    if resp.status_code in (200, 403, 401):
                        get_resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                        if get_resp and not self._is_false_positive(get_resp, path):
                            content_length = len(get_resp.text) if get_resp else 0
                            # Get redirect location if applicable
                            redirect = get_resp.headers.get('Location', '') if get_resp else ''

                            result = {
                                "path": path,
                                "url": url,
                                "status_code": get_resp.status_code,
                                "content_length": content_length,
                                "redirect": redirect,
                                "method": "HEAD+GET",
                            }
                            with lock:
                                self._progress["scanned"] += 1
                                self._progress["found"] += 1
                                self.results.append(result)
                                self.found_paths.add(path)

                            # Color based on status code
                            if get_resp.status_code == 200:
                                self._log(f"  {G}[{get_resp.status_code}] {path} ({content_length} bytes){RESET}", G)
                            elif get_resp.status_code in (301, 302):
                                self._log(f"  {C}[{get_resp.status_code}] {path} -> {redirect[:50]}{RESET}", C)
                            elif get_resp.status_code == 403:
                                self._log(f"  {Y}[{get_resp.status_code}] {path} (Forbidden){RESET}", Y)
                            elif get_resp.status_code == 401:
                                self._log(f"  {M}[{get_resp.status_code}] {path} (Auth Required){RESET}", M)
                            else:
                                self._log(f"  {R}[{get_resp.status_code}] {path}{RESET}", R)

                            return result
                    elif resp.status_code in (301, 302):
                        redirect = resp.headers.get('Location', '')
                        result = {
                            "path": path,
                            "url": url,
                            "status_code": resp.status_code,
                            "content_length": 0,
                            "redirect": redirect,
                            "method": "HEAD",
                        }
                        with lock:
                            self._progress["scanned"] += 1
                            self._progress["found"] += 1
                            self.results.append(result)
                            self.found_paths.add(path)

                        self._log(f"  {C}[{resp.status_code}] {path} -> {redirect[:50]}{RESET}", C)
                        return result

                with lock:
                    self._progress["scanned"] += 1

                # Progress update
                if self._progress["scanned"] % 100 == 0:
                    pct = (self._progress["scanned"] / max(self._progress["total"], 1)) * 100
                    self._log(f"  Progress: {self._progress['scanned']}/{self._progress['total']} "
                              f"({pct:.1f}%) - Found: {self._progress['found']}", DIM)

            except Exception:
                with lock:
                    self._progress["scanned"] += 1
                return None

            return None

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_path, path): path for path in paths_to_scan}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        results["found"] = self.results
        results["total_scanned"] = self._progress["scanned"]
        results["total_found"] = self._progress["found"]

        self._log(f"Scan complete: {results['total_found']} paths found "
                  f"({results['total_scanned']} scanned)", G)
        return results

    # ========================================================================
    # RECURSIVE SCAN
    # ========================================================================

    def recursive_scan(self, target=None, depth=2):
        """Recursive directory scan - discover subdirectories and scan them

        Args:
            target: Target URL
            depth: Maximum recursion depth

        Returns:
            dict with scan results
        """
        self.target = target or self.target
        base_url = self._get_base_url()

        self._log(f"Starting recursive directory scan on {base_url} (depth={depth})", C)

        results = {
            "target": base_url,
            "depth": depth,
            "found": [],
            "directories_discovered": [],
            "total_found": 0,
            "scan_type": "directory_recursive",
            "timestamp": datetime.now().isoformat(),
        }

        all_results = []
        discovered_dirs = set()
        current_dirs = {"/"}

        for d in range(1, depth + 1):
            self._log(f"  Depth {d}: Scanning {len(current_dirs)} directories", Y)

            new_dirs = set()
            for directory in current_dirs:
                if directory in discovered_dirs and d > 1:
                    continue

                # Scan this directory
                scan_url = f"{base_url}{directory}"
                dir_result = self.scan(scan_url)

                for finding in dir_result.get("found", []):
                    all_results.append(finding)
                    path = finding.get("path", "")
                    results["directories_discovered"].append({
                        "path": path,
                        "depth": d,
                        "status_code": finding.get("status_code"),
                    })

                    # If it's a directory (ends with / or redirects to /)
                    if path.endswith('/') or (finding.get("status_code") in (301, 302) and
                                             finding.get("redirect", "").endswith('/')):
                        clean_path = path.rstrip('/') + '/'
                        if clean_path not in discovered_dirs:
                            new_dirs.add(clean_path)
                            self._log(f"  {M}[NEW DIR] {clean_path} (depth {d}){RESET}", M)

                discovered_dirs.add(directory)

            current_dirs = new_dirs
            if not new_dirs:
                self._log(f"  No new directories found at depth {d}, stopping", Y)
                break

        results["found"] = all_results
        results["total_found"] = len(all_results)

        self._log(f"Recursive scan complete: {results['total_found']} paths found, "
                  f"{len(discovered_dirs)} directories", G)
        return results

    # ========================================================================
    # EXTENSION-BASED SCAN
    # ========================================================================

    def scan_with_extensions(self, target=None, ext_list=None):
        """Extension-based directory scanning

        Args:
            target: Target URL
            ext_list: List of extensions to scan (e.g., ['.php', '.asp', '.js'])

        Returns:
            dict with scan results
        """
        self.target = target or self.target
        exts = ext_list or DEFAULT_EXTENSIONS
        base_url = self._get_base_url()

        self._log(f"Starting extension-based scan on {base_url}", C)
        self._log(f"  Extensions: {', '.join(exts)} ({len(exts)} total)", Y)

        results = {
            "target": base_url,
            "extensions": exts,
            "found": [],
            "results_by_extension": {},
            "total_found": 0,
            "scan_type": "directory_extension",
            "timestamp": datetime.now().isoformat(),
        }

        all_results = []
        for ext in exts:
            self._log(f"  Scanning with extension: {ext if ext else '(no ext)'}", C)
            ext_result = self.scan(base_url, extensions=[ext])
            ext_findings = ext_result.get("found", [])
            results["results_by_extension"][ext or "none"] = len(ext_findings)
            all_results.extend(ext_findings)

        results["found"] = all_results
        results["total_found"] = len(all_results)

        self._log(f"Extension scan complete: {results['total_found']} paths found", G)
        return results

    # ========================================================================
    # FILTER RESULTS
    # ========================================================================

    def filter_results(self, results, status_codes=None, min_length=0):
        """Filter scan results by status code and content length

        Args:
            results: List of scan results
            status_codes: List of status codes to include (e.g., [200, 301, 403])
            min_length: Minimum content length to include

        Returns:
            Filtered list of results
        """
        filtered = []
        status_codes = status_codes or [200, 301, 302, 403, 401]

        for result in results:
            if result.get("status_code") in status_codes:
                if result.get("content_length", 0) >= min_length:
                    filtered.append(result)

        return filtered

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='quick', **kwargs):
        """Main entry point for Dirsearch engine

        Args:
            target: Target URL or domain
            scan_type: One of 'quick', 'recursive', 'extension', 'deep'
            **kwargs: Additional options (extensions, threads, depth, wordlist, proxy)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self.target = target
        self.extensions = kwargs.get('extensions', self.extensions)
        self.threads = kwargs.get('threads', self.threads)
        self.wordlist = kwargs.get('wordlist', self.wordlist)

        self._log(f"{BOLD}═══ ZYLON Dirsearch Engine v5.0 ═══{RESET}", M)
        self._log(f"Target: {target} | Scan: {scan_type} | Threads: {self.threads}", Y)

        scan_results = {}

        try:
            if scan_type == 'quick':
                extensions = kwargs.get('extensions', ['', '.php', '.html', '.js'])
                scan_results = self.scan(target, extensions=extensions, threads=self.threads)

            elif scan_type == 'recursive':
                depth = kwargs.get('depth', 2)
                scan_results = self.recursive_scan(target, depth=depth)

            elif scan_type == 'extension':
                ext_list = kwargs.get('ext_list', DEFAULT_EXTENSIONS)
                scan_results = self.scan_with_extensions(target, ext_list=ext_list)

            elif scan_type == 'deep':
                # Full deep scan: recursive + all extensions
                self._log(f"{BOLD}Running DEEP scan...{RESET}", M)

                # Phase 1: Quick scan for discovery
                quick_result = self.scan(target, extensions=[''], threads=self.threads)

                # Phase 2: Extension-based scan
                ext_result = self.scan_with_extensions(target, ext_list=DEFAULT_EXTENSIONS)

                # Phase 3: Recursive on discovered directories
                depth = kwargs.get('depth', 2)
                recursive_result = self.recursive_scan(target, depth=depth)

                # Combine all results
                all_found = []
                all_found.extend(quick_result.get("found", []))
                all_found.extend(ext_result.get("found", []))
                all_found.extend(recursive_result.get("found", []))

                # Deduplicate by URL
                seen_urls = set()
                unique_found = []
                for item in all_found:
                    url = item.get("url", "")
                    if url not in seen_urls:
                        seen_urls.add(url)
                        unique_found.append(item)

                # Filter results
                filtered = self.filter_results(unique_found, status_codes=[200, 301, 302, 403, 401])

                scan_results = {
                    "target": self._get_base_url(),
                    "found": filtered,
                    "total_found": len(filtered),
                    "quick_results": quick_result.get("total_found", 0),
                    "extension_results": ext_result.get("total_found", 0),
                    "recursive_results": recursive_result.get("total_found", 0),
                    "scan_type": "directory_deep",
                    "timestamp": datetime.now().isoformat(),
                }

                self._log(f"Deep scan complete: {len(filtered)} unique paths found", G)

            else:
                scan_results = {"error": f"Unknown scan type: {scan_type}"}

        except Exception as e:
            self._log(f"Scan error: {e}", R)
            scan_results["error"] = str(e)

        # Build return format
        findings_list = scan_results.get("found", [])
        interesting = [f for f in findings_list if f.get("status_code") in (200, 301, 302, 403, 401)]

        return {
            "vulnerable": len(interesting) > 0,
            "findings": findings_list,
            "details": scan_results,
            "scan_type": f"dirsearch_{scan_type}",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION (for ZYLON integration)
# ============================================================================

def run(target, scan_type='quick', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = DirsearchEngine(target=target, **kwargs)
    return engine.run(target, scan_type=scan_type, **kwargs)
