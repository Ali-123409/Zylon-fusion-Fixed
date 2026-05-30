"""
ZYLON FUSION - Vulnerability Scanner Engine
Fuses: wizard SQLi/XSS/WordPress + omino vulnscan + Zylon custom vuln checks
Termux Non-Root Compatible
"""

import re
import json
import socket
import requests
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL, SQLI_PAYLOADS,
    SQLI_ERRORS, XSS_PAYLOADS, CORS_TEST_ORIGINS
)
import random


class VulnEngine:
    """Advanced Vulnerability Scanner Engine"""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = VERIFY_SSL

    def _rotate_ua(self):
        """Rotate user agent"""
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # SQL INJECTION SCANNER (from wizard + enhanced)
    # ========================================================================

    def scan_sqli(self, url):
        """Advanced SQL injection scanner with multiple detection methods"""
        result = {'vulnerable': False, 'findings': [], 'tested_urls': 0}

        # Collect URLs with parameters
        test_urls = self._collect_test_urls(url)
        result['tested_urls'] = len(test_urls)

        for test_url, params in test_urls:
            for param in params:
                for payload in SQLI_PAYLOADS:
                    try:
                        self._rotate_ua()
                        # Test with payload
                        test_params = dict(parse_qs(urlparse(test_url).query))
                        for k in test_params:
                            test_params[k] = [payload]

                        parsed = urlparse(test_url)
                        test_query = urlencode({k: v[0] for k, v in test_params.items()})
                        test_full = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                        resp = self.session.get(test_full, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                        # Check for SQL error patterns
                        for error in SQLI_ERRORS:
                            if error.lower() in resp.text.lower():
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f"SQL error: {error}",
                                    'type': 'Error-based SQLi'
                                })
                                break

                        # Check for time-based (basic)
                        if 'SLEEP' in payload.upper() or 'sleep' in payload:
                            import time
                            start = time.time()
                            try:
                                self.session.get(test_full, timeout=15, verify=VERIFY_SSL)
                            except:
                                pass
                            elapsed = time.time() - start
                            if elapsed >= 4.5:
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f"Time delay: {elapsed:.1f}s",
                                    'type': 'Time-based SQLi'
                                })

                        # Check for boolean-based
                        original_resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                        if resp.status_code != original_resp.status_code:
                            if abs(len(resp.text) - len(original_resp.text)) > 500:
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f"Response difference: {abs(len(resp.text) - len(original_resp.text))} bytes",
                                    'type': 'Boolean-based SQLi'
                                })

                    except Exception:
                        continue

        return result

    def _collect_test_urls(self, url):
        """Collect URLs with query parameters for testing"""
        test_urls = []
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Collect from current URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                test_urls.append((url, list(params.keys())))

            # Collect from forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(url, action) if action else url
                inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                if inputs:
                    test_urls.append((form_url, inputs))

            # Collect from links with parameters
            for tag in soup.find_all('a', href=True):
                href = urljoin(url, tag['href'])
                link_parsed = urlparse(href)
                link_params = parse_qs(link_parsed.query)
                if link_params and href not in [u[0] for u in test_urls]:
                    test_urls.append((href, list(link_params.keys())))

        except Exception:
            pass

        # Always test the main URL if no params found
        if not test_urls:
            parsed = urlparse(url)
            if parsed.query:
                test_urls.append((url, list(parse_qs(parsed.query).keys())))
            else:
                # Test common parameters
                test_urls.append((url + '?id=1', ['id']))
                test_urls.append((url + '?page=1', ['page']))
                test_urls.append((url + '?q=test', ['q']))

        return test_urls[:20]  # Limit to prevent excessive scanning

    # ========================================================================
    # XSS SCANNER (from wizard + enhanced)
    # ========================================================================

    def scan_xss(self, url):
        """Advanced XSS vulnerability scanner"""
        result = {'vulnerable': False, 'findings': [], 'tested_urls': 0}

        test_urls = self._collect_test_urls(url)
        result['tested_urls'] = len(test_urls)

        for test_url, params in test_urls:
            for param in params:
                for payload in XSS_PAYLOADS:
                    try:
                        self._rotate_ua()
                        # Build test URL
                        parsed = urlparse(test_url)
                        test_params = parse_qs(parsed.query)
                        test_params[param] = [payload]

                        test_query = urlencode({k: v[0] for k, v in test_params.items()})
                        test_full = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                        resp = self.session.get(test_full, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                        # Check if payload is reflected in response
                        if payload in resp.text:
                            # Verify it's not just in HTML comments
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            for comment in soup.find_all(string=lambda text: isinstance(text, str) and payload in text):
                                if '<script' in payload.lower() or 'onerror' in payload.lower() or 'onload' in payload.lower():
                                    result['vulnerable'] = True
                                    result['findings'].append({
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'type': 'Reflected XSS'
                                    })
                                    break

                        # Template injection check
                        if payload in ['{{7*7}}', '${7*7}']:
                            if '49' in resp.text:
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'url': test_url,
                                    'parameter': param,
                                    'payload': payload,
                                    'type': 'Server-Side Template Injection'
                                })

                    except Exception:
                        continue

        return result

    # ========================================================================
    # CORS MISCONFIGURATION (Zylon Custom)
    # ========================================================================

    def scan_cors(self, url):
        """Detect CORS misconfiguration"""
        result = {'misconfigured': False, 'findings': []}

        domain = urlparse(url).netloc
        test_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://evil.{domain}",
            f"https://{domain}.evil.com",
            "https://evil.com" + f".{domain}",
        ]

        for origin in test_origins:
            try:
                self._rotate_ua()
                headers = {'Origin': origin}
                resp = self.session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                acao = resp.headers.get('Access-Control-Allow-Origin', '')
                acac = resp.headers.get('Access-Control-Allow-Credentials', '')

                if acao:
                    # Check if origin is reflected back (vulnerable)
                    if acao == origin or acao == '*':
                        risk = 'High' if acac == 'true' or acao == '*' else 'Medium'
                        result['misconfigured'] = True
                        result['findings'].append({
                            'origin': origin,
                            'acao': acao,
                            'acac': acac,
                            'risk': risk,
                            'description': f"Origin {origin} is allowed. Credentials: {acac}"
                        })

                    # Check for null origin
                    if acao == 'null':
                        result['misconfigured'] = True
                        result['findings'].append({
                            'origin': origin,
                            'acao': acao,
                            'acac': acac,
                            'risk': 'High',
                            'description': 'Null origin is allowed - exploitable via iframe sandbox'
                        })

            except Exception:
                continue

        return result

    # ========================================================================
    # OPEN REDIRECT (Zylon Custom)
    # ========================================================================

    def scan_open_redirect(self, url):
        """Detect open redirect vulnerabilities"""
        result = {'vulnerable': False, 'findings': []}

        redirect_params = ['url', 'redirect', 'next', 'return', 'returnTo', 'returnUrl',
                          'goto', 'dest', 'destination', 'redir', 'redirect_uri',
                          'redirect_url', 'continue', 'target', 'forward', 'link',
                          'from', 'ref', 'callback', 'jump', 'jump_url', 'to']

        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            'https:///evil.com',
            '/\\\\evil.com',
            'https://evil.com%00',
            '//evil.com/',
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in redirect_params:
            for payload in redirect_payloads:
                try:
                    self._rotate_ua()
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL, allow_redirects=False)

                    # Check for redirect
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location:
                            result['vulnerable'] = True
                            result['findings'].append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'redirects_to': location
                            })

                    # Also check with redirects followed
                    resp_follow = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL, allow_redirects=True)
                    if 'evil.com' in resp_follow.url:
                        result['vulnerable'] = True
                        result['findings'].append({
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'redirects_to': resp_follow.url
                        })

                except Exception:
                    continue

        return result

    # ========================================================================
    # CRLF INJECTION (Zylon Custom)
    # ========================================================================

    def scan_crlf(self, url):
        """Detect CRLF injection vulnerabilities"""
        result = {'vulnerable': False, 'findings': []}

        crlf_payloads = [
            '%0d%0aInjected-Header: Zylon',
            '%0dInjected-Header: Zylon',
            '%0aInjected-Header: Zylon',
            '\r\nInjected-Header: Zylon',
            '%0d%0aSet-Cookie: zylon=injected',
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        test_params = list(params.keys()) if params else ['q', 'id', 'page']

        for param in test_params:
            for payload in crlf_payloads:
                try:
                    self._rotate_ua()
                    test_url = f"{base_url}?{param}={payload}"
                    resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    # Check if injected header appears in response
                    if 'Injected-Header' in resp.headers or 'zylon' in resp.headers.get('Set-Cookie', '').lower():
                        result['vulnerable'] = True
                        result['findings'].append({
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'Injected header reflected in response'
                        })

                except Exception:
                    continue

        return result

    # ========================================================================
    # WORDPRESS SCAN (from wizard + enhanced)
    # ========================================================================

    def scan_wordpress(self, url):
        """WordPress-specific security scan"""
        result = {'is_wordpress': False, 'findings': []}

        try:
            # Check if WordPress
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            wp_indicators = ['wp-content', 'wp-includes', 'wp-login', 'wordpress']
            if not any(ind in resp.text.lower() for ind in wp_indicators):
                result['is_wordpress'] = False
                result['findings'].append({'check': 'WordPress Detection', 'result': 'Not a WordPress site'})
                return result

            result['is_wordpress'] = True

            # WordPress version
            version = self._wp_detect_version(url)
            result['wp_version'] = version

            # Check various WordPress paths
            wp_checks = {
                'wp-login.php': {'path': '/wp-login.php', 'status': [200]},
                'wp-admin': {'path': '/wp-admin/', 'status': [200, 301, 302]},
                'xmlrpc.php': {'path': '/xmlrpc.php', 'status': [200], 'vuln': 'XML-RPC enabled - may allow brute force'},
                'wp-config.php.bak': {'path': '/wp-config.php.bak', 'status': [200], 'vuln': 'Config backup exposed!'},
                'readme.html': {'path': '/readme.html', 'status': [200], 'vuln': 'WordPress readme exposed - version disclosure'},
                'license.txt': {'path': '/license.txt', 'status': [200]},
                'wp-cron.php': {'path': '/wp-cron.php', 'status': [200], 'vuln': 'WP-Cron publicly accessible'},
                'debug.log': {'path': '/wp-content/debug.log', 'status': [200], 'vuln': 'Debug log exposed!'},
                'uploads directory': {'path': '/wp-content/uploads/', 'status': [200], 'vuln': 'Uploads directory listing enabled'},
                '.htaccess': {'path': '/.htaccess', 'status': [200], 'vuln': '.htaccess exposed!'},
                'wp-config.php~': {'path': '/wp-config.php~', 'status': [200], 'vuln': 'Config backup (tilde) exposed!'},
            }

            for check_name, check_info in wp_checks.items():
                try:
                    check_url = urljoin(url, check_info['path'])
                    check_resp = self.session.get(check_url, timeout=5, verify=VERIFY_SSL)
                    if check_resp.status_code in check_info.get('status', [200]):
                        finding = {'check': check_name, 'status': check_resp.status_code}
                        if 'vuln' in check_info:
                            finding['vulnerability'] = check_info['vuln']
                            result['findings'].append(finding)
                except:
                    pass

            # Check for WordPress REST API
            try:
                rest_resp = self.session.get(urljoin(url, '/wp-json/wp/v2/users'), timeout=5, verify=VERIFY_SSL)
                if rest_resp.status_code == 200:
                    try:
                        users = rest_resp.json()
                        if isinstance(users, list):
                            result['findings'].append({
                                'check': 'REST API User Enumeration',
                                'vulnerability': f'WP REST API exposes {len(users)} users',
                                'users': [u.get('slug', u.get('name', 'unknown')) for u in users[:10]]
                            })
                    except:
                        pass
            except:
                pass

        except Exception as e:
            result['error'] = str(e)[:100]

        return result

    def _wp_detect_version(self, url):
        """Detect WordPress version"""
        try:
            # Method 1: Meta generator
            resp = self.session.get(url, timeout=5, verify=VERIFY_SSL)
            match = re.search(r'content="WordPress (\d+\.\d+\.?\d*)"', resp.text)
            if match:
                return match.group(1)

            # Method 2: Readme
            readme_resp = self.session.get(urljoin(url, '/readme.html'), timeout=5, verify=VERIFY_SSL)
            if readme_resp.status_code == 200:
                match = re.search(r'Version (\d+\.\d+\.?\d*)', readme_resp.text)
                if match:
                    return match.group(1)

            # Method 3: RSS feed
            feed_resp = self.session.get(urljoin(url, '/feed/'), timeout=5, verify=VERIFY_SSL)
            if feed_resp.status_code == 200:
                match = re.search(r'wordpress.org/\?v=(\d+\.\d+\.?\d*)', feed_resp.text)
                if match:
                    return match.group(1)

        except Exception:
            pass
        return 'Unknown'
