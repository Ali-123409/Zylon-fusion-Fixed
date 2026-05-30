"""
ZYLON FUSION - Advanced Reconnaissance Engine v2
Deep crawling, param mining, wayback URLs, Google dorking, GitHub secrets
Bug Bounty Hunter Edition - Termux Non-Root Compatible
"""

import re
import json
import socket
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import time
import random
import hashlib

import dns.resolver

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL, MAX_THREADS,
    REQUEST_DELAY
)

# DNS resolver compatibility (dnspython < 2.0 uses query, >= 2.0 uses resolve)
try:
    _dns_resolve = dns.resolver.resolve
except AttributeError:
    _dns_resolve = dns.resolver.query


class AdvancedRecon:
    """Bug Bounty Grade Advanced Reconnaissance Engine"""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = VERIFY_SSL
        self.crawled_urls = set()
        self.url_params = defaultdict(set)
        self.js_endpoints = set()
        self.api_endpoints = set()

    def _rotate_ua(self):
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # DEEP WEB CRAWLER - Multi-threaded recursive spider
    # ========================================================================

    def deep_crawl(self, base_url, max_depth=3, max_urls=500):
        """
        Recursive web crawler that discovers URLs, forms, and endpoints.
        This is critical for bug bounty - you can't find what you can't see.
        """
        results = {
            'urls': [],
            'forms': [],
            'parameters': {},
            'js_files': [],
            'api_endpoints': [],
            'emails': [],
            'external_links': [],
            'total_discovered': 0
        }

        visited = set()
        to_visit = [(base_url, 0)]
        domain = urlparse(base_url).netloc

        while to_visit and len(visited) < max_urls:
            url, depth = to_visit.pop(0)

            if url in visited or depth > max_depth:
                continue

            visited.add(url)

            try:
                self._rotate_ua()
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code != 200:
                    continue

                soup = BeautifulSoup(resp.text, 'html.parser')

                # Extract links
                for tag in soup.find_all('a', href=True):
                    href = tag['href']
                    if href.startswith('#') or href.startswith('javascript:'):
                        continue
                    abs_url = urljoin(url, href)
                    parsed = urlparse(abs_url)

                    # Internal links
                    if domain in parsed.netloc and abs_url not in visited:
                        to_visit.append((abs_url, depth + 1))
                        results['urls'].append(abs_url)

                        # Extract parameters
                        params = parse_qs(parsed.query)
                        for param_name in params:
                            self.url_params[param_name].add(abs_url)
                            if param_name not in results['parameters']:
                                results['parameters'][param_name] = []
                            results['parameters'][param_name].append(abs_url)

                    # External links
                    elif domain not in parsed.netloc:
                        results['external_links'].append(abs_url)

                # Extract forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    form_url = urljoin(url, action) if action else url
                    inputs = []
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        name = inp.get('name', '')
                        itype = inp.get('type', 'text')
                        ivalue = inp.get('value', '')
                        if name:
                            inputs.append({'name': name, 'type': itype, 'value': ivalue})

                    results['forms'].append({
                        'action': form_url,
                        'method': method,
                        'inputs': inputs,
                        'found_on': url
                    })

                # Extract JS files
                for script in soup.find_all('script', src=True):
                    js_url = urljoin(url, script['src'])
                    results['js_files'].append(js_url)

                # Extract emails
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
                results['emails'].extend(emails)

                # Extract API endpoints from inline scripts
                api_patterns = [
                    r'["\'](/api/[^"\']+)["\']',
                    r'["\'](/v[0-9]+/[^"\']+)["\']',
                    r'["\'](https?://[^"\']*api[^"\']*)["\']',
                    r'fetch\(["\']([^"\']+)["\']',
                    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                    r'\.get\(["\']([^"\']+)["\']',
                    r'\.post\(["\']([^"\']+)["\']',
                    r'\.put\(["\']([^"\']+)["\']',
                    r'\.delete\(["\']([^"\']+)["\']',
                    r'url:\s*["\']([^"\']+)["\']',
                    r'endpoint:\s*["\']([^"\']+)["\']',
                    r'["\'](/graphql)["\']',
                ]
                for pattern in api_patterns:
                    matches = re.findall(pattern, resp.text)
                    for match in matches:
                        full_url = urljoin(url, match)
                        self.api_endpoints.add(full_url)
                        results['api_endpoints'].append(full_url)

                time.sleep(REQUEST_DELAY)

            except Exception:
                continue

        # Deduplicate
        results['urls'] = list(set(results['urls']))
        results['js_files'] = list(set(results['js_files']))
        results['api_endpoints'] = list(set(results['api_endpoints']))
        results['emails'] = list(set(results['emails']))
        results['external_links'] = list(set(results['external_links']))
        results['total_discovered'] = (
            len(results['urls']) + len(results['forms']) +
            len(results['js_files']) + len(results['api_endpoints'])
        )

        return results

    # ========================================================================
    # PARAMETER MINER - Discover hidden parameters
    # ========================================================================

    def mine_parameters(self, url, custom_params=None):
        """
        Discover hidden parameters by testing common parameter names
        and observing response differences. Critical for finding:
        - IDOR parameters (user_id, account_id, etc.)
        - Admin parameters (admin, debug, test, etc.)
        - Internal parameters (internal, source, ref, etc.)
        """
        results = {
            'discovered': {},
            'tested': 0,
            'reflected': [],
            'behavior_change': []
        }

        # Bug bounty gold - parameters that often lead to vulns
        param_wordlist = [
            # IDOR / Access Control
            'id', 'user_id', 'uid', 'account_id', 'customer_id', 'client_id',
            'member_id', 'profile_id', 'order_id', 'transaction_id', 'file_id',
            'document_id', 'record_id', 'uuid', 'guid', 'oid',
            # Admin / Debug
            'admin', 'debug', 'test', 'dev', 'staging', 'internal',
            'access', 'role', 'permission', 'privilege', 'level', 'type',
            'mode', 'status', 'state', 'action', 'view', 'display',
            # Injection-prone
            'q', 'query', 'search', 'keyword', 'term', 'name', 'title',
            'description', 'comment', 'message', 'content', 'data',
            'input', 'text', 'value', 'param', 'arg', 'cmd', 'exec',
            # File / Path
            'file', 'path', 'dir', 'folder', 'url', 'link', 'redirect',
            'return', 'next', 'goto', 'dest', 'target', 'reference',
            'source', 'src', 'include', 'require', 'template', 'page',
            # API / Internal
            'api_key', 'apikey', 'token', 'auth', 'session', 'key',
            'callback', 'format', 'output', 'fields', 'select', 'where',
            'filter', 'sort', 'order', 'limit', 'offset', 'count',
            # Feature flags
            'enable', 'disable', 'flag', 'feature', 'beta', 'preview',
            'experimental', 'new', 'old', 'legacy', 'version',
        ]

        if custom_params:
            param_wordlist.extend(custom_params)

        # Get baseline response
        try:
            baseline = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            baseline_hash = hashlib.md5(baseline.text.encode()).hexdigest()
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception as e:
            return {'error': f'Cannot reach target: {str(e)[:100]}'}

        # Test each parameter
        for param in param_wordlist:
            try:
                self._rotate_ua()
                results['tested'] += 1

                # Test with different values
                test_values = ['1', 'test', 'admin', 'true', '0', '../', '{{7*7}}']
                for value in test_values[:3]:  # Limit to 3 values per param
                    test_url = f"{url}{'&' if '?' in url else '?'}{param}={quote(value)}"
                    resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
                    resp_len = len(resp.text)

                    # Check for reflection
                    if value in resp.text and value not in baseline.text:
                        if param not in results['reflected']:
                            results['reflected'].append({
                                'parameter': param,
                                'value': value,
                                'url': test_url,
                                'hint': 'Parameter value reflected - potential XSS/injection'
                            })

                    # Check for behavior change
                    if resp_hash != baseline_hash and abs(resp_len - baseline_len) > 100:
                        if param not in results['discovered']:
                            results['discovered'][param] = {
                                'status_diff': resp.status_code != baseline_status,
                                'size_diff': resp_len - baseline_len,
                                'urls_tested': [],
                                'hint': self._param_hint(param)
                            }
                        results['discovered'][param]['urls_tested'].append(test_url)

                    # Check for error messages
                    error_indicators = ['error', 'exception', 'traceback', 'stack', 'undefined',
                                       'null', 'NaN', 'SQL', 'syntax', 'invalid']
                    for indicator in error_indicators:
                        if indicator.lower() in resp.text.lower() and indicator.lower() not in baseline.text.lower():
                            if param not in results['discovered']:
                                results['discovered'][param] = {
                                    'status_diff': False,
                                    'size_diff': resp_len - baseline_len,
                                    'urls_tested': [],
                                    'hint': self._param_hint(param),
                                    'error_leak': indicator
                                }

                time.sleep(REQUEST_DELAY)

            except Exception:
                continue

        return results

    def _param_hint(self, param):
        """Generate vulnerability hint for a discovered parameter"""
        hints = {
            'id': 'Potential IDOR - try accessing other users\' resources',
            'user_id': 'Potential IDOR - test with different user IDs',
            'admin': 'Potential privilege escalation - try admin=true',
            'debug': 'May enable debug mode revealing sensitive info',
            'file': 'Potential LFI/Path Traversal',
            'path': 'Potential LFI/Path Traversal',
            'url': 'Potential SSRF or Open Redirect',
            'redirect': 'Potential Open Redirect',
            'callback': 'Potential JSONP XSS or SSRF',
            'template': 'Potential SSTI (Server-Side Template Injection)',
            'cmd': 'Potential Command Injection',
            'exec': 'Potential Command Injection',
            'query': 'Potential SQL Injection',
            'q': 'Potential SQL Injection or XSS',
            'api_key': 'May accept arbitrary API keys',
            'token': 'May accept forged tokens',
            'format': 'Potential Format Injection',
            'include': 'Potential LFI/RFI',
        }
        return hints.get(param, 'Active parameter - may be exploitable')

    # ========================================================================
    # WAYBACK URL DISCOVERY - Historical URL mining
    # ========================================================================

    def wayback_urls(self, domain, limit=1000):
        """
        Fetch historical URLs from Wayback Machine.
        Finds old endpoints, deprecated APIs, and forgotten pages
        that are often still live and vulnerable.
        """
        results = {'urls': [], 'unique_paths': [], 'unique_params': [], 'total': 0}

        try:
            api_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&fl=original&limit={limit}"
            resp = self.session.get(api_url, timeout=30)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if len(data) > 1:
                        urls = [row[0] for row in data[1:]]  # Skip header row
                        results['urls'] = urls
                        results['total'] = len(urls)

                        # Extract unique paths
                        paths = set()
                        params = set()
                        for url in urls:
                            parsed = urlparse(url)
                            paths.add(parsed.path)
                            query_params = parse_qs(parsed.query)
                            for p in query_params:
                                params.add(p)

                        results['unique_paths'] = list(paths)
                        results['unique_params'] = list(params)

                except json.JSONDecodeError:
                    # Fallback: parse as text
                    urls = [line.strip() for line in resp.text.split('\n') if line.strip()]
                    results['urls'] = urls
                    results['total'] = len(urls)

        except Exception as e:
            results['error'] = str(e)[:100]

        return results

    # ========================================================================
    # GOOGLE DORKING - Automated search queries
    # ========================================================================

    def google_dork(self, domain):
        """
        Automated Google dorking to find sensitive files, exposed pages,
        login portals, error messages, and more.
        Uses web scraping since no API key needed.
        """
        results = {'findings': [], 'total': 0}

        dorks = [
            # Sensitive files
            f'site:{domain} filetype:pdf',
            f'site:{domain} filetype:doc',
            f'site:{domain} filetype:xls',
            f'site:{domain} filetype:conf',
            f'site:{domain} filetype:bak',
            f'site:{domain} filetype:sql',
            f'site:{domain} filetype:log',
            f'site:{domain} filetype:env',
            f'site:{domain} filetype:yml',
            f'site:{domain} filetype:json',
            # Exposed pages
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} inurl:dashboard',
            f'site:{domain} inurl:console',
            f'site:{domain} inurl:config',
            f'site:{domain} inurl:setup',
            f'site:{domain} inurl:install',
            f'site:{domain} inurl:phpmyadmin',
            f'site:{domain} inurl:server-status',
            f'site:{domain} inurl:debug',
            # Error messages
            f'site:{domain} "sql syntax" "error"',
            f'site:{domain} "Warning:" "mysql"',
            f'site:{domain} "Fatal error"',
            f'site:{domain} "Stack Trace"',
            f'site:{domain} "not found" "error"',
            # Directory listing
            f'site:{domain} intitle:"index of"',
            f'site:{domain} intitle:"directory listing"',
            # Exposed credentials/info
            f'site:{domain} "password"',
            f'site:{domain} "api key"',
            f'site:{domain} "secret"',
            f'site:{domain} "token"',
            # Login pages
            f'site:{domain} inurl:wp-login.php',
            f'site:{domain} inurl:signin',
            f'site:{domain} inurl:auth',
        ]

        for dork in dorks:
            results['findings'].append({
                'dork': dork,
                'category': self._categorize_dork(dork),
                'severity': self._rate_dork_severity(dork),
                'url': f"https://www.google.com/search?q={quote(dork)}"
            })

        results['total'] = len(results['findings'])
        return results

    def _categorize_dork(self, dork):
        if 'filetype' in dork:
            return 'Sensitive Files'
        elif 'inurl' in dork:
            return 'Exposed Pages'
        elif any(x in dork.lower() for x in ['error', 'warning', 'fatal', 'sql']):
            return 'Error Messages'
        elif 'index of' in dork or 'directory' in dork:
            return 'Directory Listing'
        elif any(x in dork.lower() for x in ['password', 'api key', 'secret', 'token']):
            return 'Exposed Credentials'
        return 'General'

    def _rate_dork_severity(self, dork):
        high = ['filetype:sql', 'filetype:bak', 'filetype:env', 'filetype:conf',
                'password', 'api key', 'secret', 'token', 'phpmyadmin']
        medium = ['filetype:pdf', 'filetype:doc', 'admin', 'login', 'debug',
                  'error', 'warning', 'sql syntax']
        for h in high:
            if h in dork.lower():
                return 'High'
        for m in medium:
            if m in dork.lower():
                return 'Medium'
        return 'Low'

    # ========================================================================
    # GITHUB DORKING - Search for leaked secrets on GitHub
    # ========================================================================

    def github_dork(self, domain, api_token=None):
        """
        Search GitHub for leaked secrets, API keys, and credentials
        related to the target domain.
        """
        results = {'findings': [], 'total': 0}

        github_dorks = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret_key',
            f'"{domain}" access_token',
            f'"{domain}" private_key',
            f'"{domain}" AWS_SECRET_ACCESS_KEY',
            f'"{domain}" mongodb://',
            f'"{domain}" mysql://',
            f'"{domain}" smtp://',
            f'"{domain}" FTP_PASSWORD',
            f'"{domain}" filename:.env',
            f'"{domain}" filename:config.json',
            f'"{domain}" filename:credentials',
            f'"{domain}" filename:database.yml',
            f'"{domain}" filename:.htpasswd',
            f'"{domain}" filename:wp-config.php',
            f'"{domain}" filename:id_rsa',
            f'"{domain}" JIRA_TOKEN',
            f'"{domain}" SLACK_TOKEN',
            f'"{domain}" HEROKU_API_KEY',
        ]

        headers = {}
        if api_token:
            headers['Authorization'] = f'token {api_token}'

        for dork in github_dorks:
            try:
                search_url = f"https://api.github.com/search/code?q={quote(dork)}&per_page=5"
                resp = self.session.get(search_url, headers=headers, timeout=10)

                if resp.status_code == 200:
                    data = resp.json()
                    count = data.get('total_count', 0)
                    if count > 0:
                        for item in data.get('items', [])[:3]:
                            results['findings'].append({
                                'dork': dork,
                                'file': item.get('name', ''),
                                'repo': item.get('repository', {}).get('full_name', ''),
                                'url': item.get('html_url', ''),
                                'severity': 'High'
                            })
                elif resp.status_code == 403:
                    results['rate_limited'] = True
                    break

                time.sleep(2)  # GitHub API rate limiting

            except Exception:
                continue

        results['total'] = len(results['findings'])
        return results

    # ========================================================================
    # JS FILE ANALYSIS - Deep endpoint & secret extraction
    # ========================================================================

    def analyze_js_files(self, url, max_files=30):
        """
        Deep analysis of JavaScript files to extract:
        - API endpoints
        - Hidden parameters
        - Secret keys
        - Internal URLs
        - Route definitions
        - Event listeners
        """
        results = {
            'endpoints': [],
            'secrets': [],
            'hidden_params': [],
            'internal_urls': [],
            'interesting_strings': [],
            'files_analyzed': 0
        }

        try:
            # Collect JS files
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            js_urls = []
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                js_urls.append(js_url)

            # Also check for JS in script bundles
            for script in soup.find_all('script'):
                if script.string and 'src' not in str(script):
                    content = script.string
                    self._extract_js_intel(content, 'inline', results)

            # Analyze each JS file
            for js_url in js_urls[:max_files]:
                try:
                    self._rotate_ua()
                    js_resp = self.session.get(js_url, timeout=15, verify=VERIFY_SSL)
                    if js_resp.status_code == 200:
                        results['files_analyzed'] += 1
                        self._extract_js_intel(js_resp.text, js_url, results)
                except Exception:
                    continue

            # Deduplicate
            results['endpoints'] = list(set(results['endpoints']))
            results['secrets'] = list(set(results['secrets']))
            results['hidden_params'] = list(set(results['hidden_params']))
            results['internal_urls'] = list(set(results['internal_urls']))

        except Exception as e:
            results['error'] = str(e)[:100]

        return results

    def _extract_js_intel(self, content, source, results):
        """Extract intelligence from JavaScript content"""

        # API endpoints
        endpoint_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql)["\']',
            r'["\'](/auth/[^"\']+)["\']',
            r'["\'](/oauth/[^"\']+)["\']',
            r'["\'](/user/[^"\']+)["\']',
            r'["\'](/admin/[^"\']+)["\']',
            r'["\'](/internal/[^"\']+)["\']',
            r'["\'](/debug/[^"\']+)["\']',
            r'["\'](/graphql)["\']',
            r'["\'](/ws)["\']',
            r'baseURL:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
        ]
        for pattern in endpoint_patterns:
            matches = re.findall(pattern, content)
            results['endpoints'].extend(matches)

        # Hidden parameters in JS
        param_patterns = [
            r'params:\s*{([^}]+)}',
            r'data:\s*{([^}]+)}',
            r'body:\s*{([^}]+)}',
            r'query:\s*{([^}]+)}',
        ]
        for pattern in param_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Extract key names
                keys = re.findall(r'["\']?(\w+)["\']?\s*:', match)
                results['hidden_params'].extend(keys)

        # Secrets
        secret_patterns = [
            (r'api[_-]?key\s*[:=]\s*["\']([^"\']+)["\']', 'API Key'),
            (r'secret[_-]?key\s*[:=]\s*["\']([^"\']+)["\']', 'Secret Key'),
            (r'access[_-]?token\s*[:=]\s*["\']([^"\']+)["\']', 'Access Token'),
            (r'auth[_-]?token\s*[:=]\s*["\']([^"\']+)["\']', 'Auth Token'),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*', 'JWT Token'),
            (r'(?:mongodb|postgres|mysql|redis)://[^\s"\'<>]+', 'Database URI'),
            (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----', 'Private Key'),
        ]
        for pattern, stype in secret_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches[:3]:
                results['secrets'].append(f'[{stype}] {str(match)[:60]}')

        # Internal URLs
        url_patterns = [
            r'["\'](https?://[^"\']*(?:internal|staging|dev|test|admin|api)[^"\']*)["\']',
            r'["\'](https?://(?:10\.\d|172\.(?:1[6-9]|2\d|3[01])|192\.168)[^"\']*)["\']',
            r'["\'](wss?://[^"\']+)["\']',
        ]
        for pattern in url_patterns:
            matches = re.findall(pattern, content)
            results['internal_urls'].extend(matches)

    # ========================================================================
    # URL PROBER - Test which URLs are alive
    # ========================================================================

    def probe_urls(self, urls, max_threads=20):
        """Test which URLs return valid responses"""
        results = {'alive': [], 'redirects': [], 'errors': [], 'total': len(urls)}

        def probe(url):
            try:
                self._rotate_ua()
                resp = self.session.get(url, timeout=8, verify=VERIFY_SSL, allow_redirects=False)
                return url, resp.status_code, resp.headers.get('Location', ''), len(resp.text)
            except Exception:
                return url, None, None, 0

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(probe, u): u for u in urls[:500]}
            for future in as_completed(futures):
                url, status, location, size = future.result()
                if status:
                    if status in [200, 201, 204]:
                        results['alive'].append({'url': url, 'status': status, 'size': size})
                    elif status in [301, 302, 303, 307, 308]:
                        results['redirects'].append({'url': url, 'status': status, 'redirects_to': location})
                    elif status in [403, 401]:
                        results['alive'].append({'url': url, 'status': status, 'size': size, 'note': 'Access denied but exists'})
                else:
                    results['errors'].append(url)

        return results

    # ========================================================================
    # BROKEN LINK HIJACKING - Check for subdomain takeover
    # ========================================================================

    def check_subdomain_takeover(self, subdomains):
        """
        Check if subdomains point to dangling DNS records
        that could be taken over.
        """
        results = {'vulnerable': [], 'total_tested': 0}

        # Service fingerprints for takeover detection
        takeover_signatures = {
            'GitHub Pages': {'cname': 'github.io', 'body': ["There isn't a GitHub Pages site here", "404 There isn't a GitHub Pages site here"]},
            'Heroku': {'cname': 'herokuapp.com', 'body': ["No such app", "herokucdn.com/error-pages/no-such-app.html"]},
            'Shopify': {'cname': 'myshopify.com', 'body': ["Sorry, this shop is currently unavailable"]},
            'AWS S3': {'cname': 'amazonaws.com', 'body': ["NoSuchBucket", "The specified bucket does not exist"]},
            'Tumblr': {'cname': 'tumblr.com', 'body': ["Whatever you were looking for doesn't currently exist"]},
            'WordPress': {'cname': 'wordpress.com', 'body': ["Do you want to register", "wordpress.com is being parked"]},
            'Teamwork': {'cname': 'teamwork.com', 'body': ["Oops - We didn't find your site"]},
            'Help Scout': {'cname': 'helpscout.net', 'body': ["No settings were found for this company"]},
            'Ghost': {'cname': 'ghost.io', 'body': ["The thing you were looking for is no longer here"]},
            'Pantheon': {'cname': 'pantheon.io', 'body': ["404 error unknown site", "pantheon.io/404"]},
            'Tilda': {'cname': 'tilda.ws', 'body': ["Domain has been assigned", "tilda.ws"]},
            'Uptimerobot': {'cname': 'uptimerobot.com', 'body': ["Page not found", "uptimerobot.com"]},
            'Statuspage': {'cname': 'statuspage.io', 'body': ["You are being redirected", "statuspage.io"]},
            'Strikingly': {'cname': 'strikinglydns.com', 'body': ["But you can sign up", "strikingly.com"]},
            'Fly.io': {'cname': 'fly.dev', 'body': ["404 Not Found Error", "fly.dev"]},
        }

        for subdomain in subdomains:
            results['total_tested'] += 1
            try:
                # Resolve CNAME
                cname = None
                try:
                    answers = _dns_resolve(subdomain, 'CNAME')
                    if answers:
                        cname = str(answers[0]).rstrip('.')
                except Exception:
                    pass

                # Check HTTP response
                try:
                    url = f"https://{subdomain}"
                    resp = self.session.get(url, timeout=8, verify=VERIFY_SSL)
                    body = resp.text.lower()

                    for service, sig in takeover_signatures.items():
                        is_vulnerable = False

                        # Check CNAME match
                        if cname and sig['cname'] in cname:
                            # Check body for takeover indicator
                            for indicator in sig['body']:
                                if indicator.lower() in body:
                                    is_vulnerable = True
                                    break

                        if is_vulnerable:
                            results['vulnerable'].append({
                                'subdomain': subdomain,
                                'service': service,
                                'cname': cname,
                                'severity': 'High',
                                'evidence': f"CNAME points to {service} but resource doesn't exist"
                            })

                except Exception:
                    pass

            except Exception:
                continue

        return results
