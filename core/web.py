"""
ZYLON FUSION - Web Security Engine
Fuses: wizard web scanning + omino web analysis + Zylon custom web checks
Termux Non-Root Compatible
"""

import re
import json
import requests
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.var import (
    COMMON_DIRS, DEFAULT_TIMEOUT, MAX_THREADS, SECURITY_HEADERS, SENSITIVE_JS_PATTERNS, USER_AGENTS, VERIFY_SSL
)
from core.shared_infra import shared_session, regex_cache
import random


class WebEngine:
    """Advanced Web Security Scanning Engine"""

    def __init__(self, session=None):
        self.session = session or shared_session
        # User-Agent rotation handled by shared_session
        pass

    def _rotate_ua(self):
        """Rotate user agent"""
        # User-Agent rotation handled by shared_session
        pass

    # ========================================================================
    # SECURITY HEADERS ANALYSIS (from wizard + enhanced with omino's approach)
    # ========================================================================

    def analyze_security_headers(self, url):
        """Comprehensive security header analysis with scoring"""
        result = {
            'headers': {},
            'security_headers': {},
            'security_score': 0,
            'recommendations': [],
            'information_disclosure': []
        }

        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            result['headers'] = dict(resp.headers)

            # Check security headers
            for header_name, header_info in SECURITY_HEADERS.items():
                value = resp.headers.get(header_name, 'Missing')
                result['security_headers'][header_name] = {
                    'value': value,
                    'recommended': header_info['recommended'],
                    'weight': header_info['weight'],
                    'description': header_info.get('description', '')
                }

                if value != 'Missing':
                    result['security_score'] += header_info['weight']

            # Check for information disclosure headers
            info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime',
                          'X-Version', 'X-Generator', 'Via', 'X-Forwarded-For']
            for h in info_headers:
                if h in resp.headers:
                    result['information_disclosure'].append({
                        'header': h,
                        'value': resp.headers[h],
                        'risk': 'May reveal server technology details'
                    })

            # Generate recommendations
            if result['security_score'] < 30:
                result['recommendations'].append('CRITICAL: Implement security headers immediately')
            if result['security_headers'].get('Strict-Transport-Security', {}).get('value') == 'Missing':
                result['recommendations'].append('Add HSTS header for HTTPS enforcement')
            if result['security_headers'].get('Content-Security-Policy', {}).get('value') == 'Missing':
                result['recommendations'].append('Implement Content Security Policy to prevent XSS')
            if result['security_headers'].get('X-Frame-Options', {}).get('value') == 'Missing':
                result['recommendations'].append('Add X-Frame-Options to prevent clickjacking')
            if result['security_headers'].get('Permissions-Policy', {}).get('value') == 'Missing':
                result['recommendations'].append('Implement Permissions-Policy to control browser features')
            if result['information_disclosure']:
                result['recommendations'].append(
                    f'Remove information disclosure headers: {", ".join(h["header"] for h in result["information_disclosure"])}'
                )

        except Exception as e:
            result['error'] = str(e)[:100]

        return result

    # ========================================================================
    # DIRECTORY BRUTE FORCE (from wizard + enhanced)
    # ========================================================================

    def directory_bruteforce(self, url, wordlist=None, max_threads=MAX_THREADS):
        """Directory and file brute force"""
        results = {}

        if wordlist is None:
            wordlist = COMMON_DIRS

        def check_path(path):
            try:
                self._rotate_ua()
                full_url = urljoin(url, path)
                resp = self.session.get(full_url, timeout=5, verify=VERIFY_SSL, allow_redirects=False)

                if resp.status_code in [200, 301, 302, 403]:
                    size = len(resp.text) if hasattr(resp, 'text') else 0
                    return path, {
                        'status': resp.status_code,
                        'size': size,
                        'redirect': resp.headers.get('Location', '') if resp.status_code in [301, 302] else ''
                    }
            except Exception:
                pass
            return path, None

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(check_path, path): path for path in wordlist}
            for future in as_completed(futures):
                path, info = future.result()
                if info:
                    results[path] = info

        return results

    # ========================================================================
    # COOKIE SECURITY ANALYSIS (Zylon Custom)
    # ========================================================================

    def analyze_cookies(self, url):
        """Analyze cookie security attributes"""
        result = {}

        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

            for cookie in resp.cookies:
                issues = []

                info = {
                    'name': cookie.name,
                    'value': str(cookie.value)[:20] + '...' if len(str(cookie.value)) > 20 else str(cookie.value),
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('httponly') or 'httponly' in str(cookie).lower(),
                    'samesite': 'Unknown',
                    'issues': issues
                }

                # Determine SameSite
                set_cookie = resp.headers.get('Set-Cookie', '')
                if 'SameSite=Strict' in set_cookie:
                    info['samesite'] = 'Strict'
                elif 'SameSite=Lax' in set_cookie:
                    info['samesite'] = 'Lax'
                elif 'SameSite=None' in set_cookie:
                    info['samesite'] = 'None'
                else:
                    info['samesite'] = 'Not Set'

                # Security checks
                if not cookie.secure:
                    issues.append('Missing Secure flag - can be sent over HTTP')
                if not info['httponly']:
                    issues.append('Missing HttpOnly flag - accessible via JavaScript')
                if info['samesite'] in ['Not Set', 'None']:
                    issues.append('Missing/None SameSite - vulnerable to CSRF')
                if cookie.path == '/':
                    issues.append('Wide path scope (/) - accessible from all paths')

                # Check for sensitive cookie names
                sensitive_names = ['session', 'auth', 'token', 'password', 'secret', 'key', 'admin']
                if any(s in cookie.name.lower() for s in sensitive_names):
                    if issues:
                        issues.insert(0, 'SENSITIVE COOKIE with security issues!')

                result[cookie.name] = info

        except Exception as e:
            result = {'error': str(e)[:100]}

        return result

    # ========================================================================
    # JAVASCRIPT SENSITIVE DATA EXTRACTION (Zylon Custom)
    # ========================================================================

    def extract_js_secrets(self, url):
        """Extract sensitive data from JavaScript files"""
        result = {'findings': [], 'js_files_analyzed': 0}

        try:
            # Get main page
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Find all JS files
            js_urls = []
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                js_urls.append(js_url)

            # Also analyze inline scripts
            inline_scripts = []
            for script in soup.find_all('script'):
                if script.string and len(script.string) > 50:
                    inline_scripts.append(script.string)

            # Analyze inline scripts
            for script in inline_scripts:
                self._find_secrets_in_js(script, 'inline', result)

            # Analyze external JS files
            for js_url in js_urls[:20]:  # Limit to 20 JS files
                try:
                    js_resp = self.session.get(js_url, timeout=10, verify=VERIFY_SSL)
                    if js_resp.status_code == 200:
                        result['js_files_analyzed'] += 1
                        self._find_secrets_in_js(js_resp.text, js_url, result)
                except Exception:
                    continue

        except Exception as e:
            result['error'] = str(e)[:100]

        return result

    def _find_secrets_in_js(self, content, source, result):
        """Search for sensitive patterns in JavaScript content"""
        for secret_type, patterns in SENSITIVE_JS_PATTERNS.items():
            for pattern in patterns:
                try:
                    matches = regex_cache.findall(pattern, content, re.IGNORECASE)
                    for match in matches[:5]:  # Limit per type
                        # Don't add duplicates
                        value = str(match)[:80]
                        if not any(f['value'] == value and f['type'] == secret_type for f in result['findings']):
                            result['findings'].append({
                                'type': secret_type,
                                'value': value,
                                'source': source.split('/')[-1] if '/' in str(source) else source
                            })
                except Exception:
                    continue

    # ========================================================================
    # MIXED CONTENT ANALYSIS (Zylon Custom)
    # ========================================================================

    def check_mixed_content(self, url):
        """Check for mixed content issues (HTTP resources on HTTPS page)"""
        result = {'mixed_content': [], 'secure': True}

        if not url.startswith('https://'):
            return {'secure': False, 'note': 'Not using HTTPS'}

        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Check for HTTP resources
            http_resources = []
            for tag in soup.find_all(['img', 'script', 'link', 'iframe', 'video', 'audio', 'source']):
                src = tag.get('src', '') or tag.get('href', '')
                if src.startswith('http://'):
                    http_resources.append({
                        'tag': tag.name,
                        'url': src,
                        'type': 'active' if tag.name in ['script', 'iframe', 'link'] else 'passive'
                    })

            if http_resources:
                result['secure'] = False
                result['mixed_content'] = http_resources

        except Exception as e:
            result['error'] = str(e)[:100]

        return result

    # ========================================================================
    # BROKEN LINK DETECTOR (Zylon Custom)
    # ========================================================================

    def find_broken_links(self, url, max_links=50):
        """Find broken links on a page"""
        result = {'broken': [], 'total_checked': 0}

        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            links = set()
            for tag in soup.find_all('a', href=True):
                href = tag['href']
                if href.startswith('http'):
                    links.add(href)

            for link in list(links)[:max_links]:
                try:
                    r = self.session.head(link, timeout=5, verify=VERIFY_SSL, allow_redirects=True)
                    result['total_checked'] += 1
                    if r.status_code >= 400:
                        result['broken'].append({'url': link, 'status': r.status_code})
                except Exception:
                    result['broken'].append({'url': link, 'status': 'Error'})

        except Exception as e:
            result['error'] = str(e)[:100]

        return result

    # ========================================================================
    # INFORMATION DISCLOSURE CHECKS (Zylon Custom)
    # ========================================================================

    def check_info_disclosure(self, url):
        """Check for common information disclosure paths"""
        result = {'findings': []}

        disclosure_paths = [
            '/.git/HEAD', '/.git/config', '/.svn/entries', '/.DS_Store',
            '/.env', '/.env.backup', '/.env.local', '/.env.production',
            '/wp-config.php.bak', '/config.json', '/config.yml',
            '/package.json', '/composer.json', '/.htaccess',
            '/.htpasswd', '/server-status', '/server-info',
            '/phpinfo.php', '/info.php', '/test.php',
            '/debug', '/trace', '/.well-known/security.txt',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/robots.txt', '/sitemap.xml', '/favicon.ico',
            '/elmah.axd', '/trace.axd', '/error.log',
            '/debug.log', '/.dockerenv', '/Dockerfile',
        ]

        def check_path(path):
            try:
                full_url = urljoin(url, path)
                resp = self.session.get(full_url, timeout=5, verify=VERIFY_SSL)
                if resp.status_code == 200 and len(resp.text) > 0:
                    return {
                        'path': path,
                        'status': resp.status_code,
                        'size': len(resp.text),
                        'snippet': resp.text[:100].replace('\n', ' ').replace('\r', '')
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_path, p) for p in disclosure_paths]
            for future in as_completed(futures):
                finding = future.result()
                if finding:
                    result['findings'].append(finding)

        return result
