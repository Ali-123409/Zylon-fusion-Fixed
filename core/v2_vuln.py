#!/usr/bin/env python3
"""
ZYLON FUSION v2.0 - Advanced Vulnerability Engine 2
API Endpoint Discovery + Fuzzer | Rate Limit Tester | Sensitive File Scanner
Termux Non-Root Compatible
"""

import re
import json
import time
import requests
from urllib.parse import urlparse, urljoin, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

from core.var import *


class V2VulnEngine:
    """V2.0 Vulnerability: API Fuzzer, Rate Limit, Sensitive Files"""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENTS[0]})
        self.session.verify = VERIFY_SSL

    def _rotate_ua(self):
        import random
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # API ENDPOINT DISCOVERY + FUZZER
    # ========================================================================

    def discover_api_endpoints(self, base_url):
        """
        Discover hidden API endpoints and test for common API vulnerabilities.
        Tests: Auth bypass, mass assignment, info disclosure, method tampering.
        """
        results = {
            'base_url': base_url,
            'discovered_endpoints': [],
            'vulnerabilities': [],
            'swagger_docs': [],
            'total_tested': 0,
            'total_vulns': 0
        }

        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Phase 1: Discover API endpoints
        found_endpoints = []

        def test_endpoint(path):
            url = f"{origin}{path}"
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                return (path, resp.status_code, resp.headers.get('Content-Type', ''),
                        len(resp.content), resp)
            except Exception:
                return (path, 0, '', 0, None)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(test_endpoint, path): path for path in API_ENDPOINTS}
            for future in as_completed(futures):
                path, status, content_type, size, resp = future.result()
                results['total_tested'] += 1

                if status in [200, 201, 301, 302, 401, 403, 405]:
                    endpoint_info = {
                        'path': path,
                        'status_code': status,
                        'content_type': content_type,
                        'response_size': size,
                        'vulnerabilities': []
                    }

                    # Check for JSON response (API indicator)
                    if 'json' in content_type.lower() or 'api' in content_type.lower():
                        endpoint_info['is_api'] = True

                    # Check for Swagger/OpenAPI docs
                    if any(kw in path.lower() for kw in ['swagger', 'openapi', 'api-docs']):
                        endpoint_info['is_documentation'] = True
                        results['swagger_docs'].append(endpoint_info)

                    # Phase 2: Test for API vulnerabilities on discovered endpoints
                    if resp and status == 200:
                        vulns = self._test_api_vulns(origin, path, resp)
                        endpoint_info['vulnerabilities'] = vulns
                        results['vulnerabilities'].extend(vulns)

                    found_endpoints.append(endpoint_info)

        results['discovered_endpoints'] = found_endpoints
        results['total_endpoints'] = len(found_endpoints)
        results['total_vulns'] = len(results['vulnerabilities'])

        return results

    def _test_api_vulns(self, origin, path, get_resp):
        """Test an API endpoint for common vulnerabilities"""
        vulns = []
        url = f"{origin}{path}"

        # Test 1: Method tampering (try POST, PUT, DELETE, PATCH)
        for method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            try:
                resp = self.session.request(method, url, timeout=5,
                                           json={'test': 'zylon'},
                                           allow_redirects=False)
                if resp.status_code == 200 and method not in ['GET', 'HEAD']:
                    # Non-GET method accepted without auth - potential issue
                    if get_resp.status_code != 405:  # If GET also works
                        vulns.append({
                            'type': 'Method Tampering',
                            'endpoint': path,
                            'method': method,
                            'status': resp.status_code,
                            'severity': 'medium',
                            'description': f'{method} method accepted on {path} without authentication'
                        })
            except Exception:
                pass

        # Test 2: Auth bypass (try without any cookies/headers)
        try:
            clean_session = requests.Session()
            clean_session.headers.update({'User-Agent': USER_AGENTS[0]})
            resp = clean_session.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and get_resp.status_code == 200:
                # Check if response contains sensitive data
                try:
                    data = resp.json()
                    sensitive_keys = ['email', 'password', 'token', 'secret',
                                    'api_key', 'private', 'ssn', 'credit']
                    for key in sensitive_keys:
                        if key in str(data).lower():
                            vulns.append({
                                'type': 'Auth Bypass / Info Disclosure',
                                'endpoint': path,
                                'severity': 'high',
                                'description': f'Sensitive field "{key}" accessible without authentication'
                            })
                            break
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        # Test 3: Mass Assignment (try adding extra fields)
        try:
            extra_data = {'role': 'admin', 'is_admin': True, 'admin': True}
            resp = self.session.post(url, timeout=5, json=extra_data, allow_redirects=False)
            if resp.status_code in [200, 201]:
                try:
                    data = resp.json()
                    if any(k in str(data).lower() for k in ['admin', 'role']):
                        vulns.append({
                            'type': 'Mass Assignment',
                            'endpoint': path,
                            'severity': 'high',
                            'description': 'Server accepted admin role field - potential mass assignment'
                        })
                except (json.JSONDecodeError, ValueError):
                    pass
        except Exception:
            pass

        # Test 4: CORS on API
        try:
            resp = self.session.get(url, timeout=5,
                                   headers={'Origin': 'https://evil.com'},
                                   allow_redirects=False)
            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            if acao == 'https://evil.com' or acao == '*':
                vulns.append({
                    'type': 'CORS Misconfiguration',
                    'endpoint': path,
                    'severity': 'high' if acao == '*' else 'medium',
                    'description': f'API allows cross-origin from: {acao}'
                })
        except Exception:
            pass

        return vulns

    # ========================================================================
    # RATE LIMIT TESTER
    # ========================================================================

    def test_rate_limiting(self, base_url):
        """
        Test endpoints for missing rate limiting.
        Sends rapid requests and checks if they're all accepted.
        """
        results = {
            'base_url': base_url,
            'endpoints_tested': [],
            'missing_rate_limit': [],
            'total_tested': 0
        }

        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for endpoint in RATE_LIMIT_ENDPOINTS:
            url = f"{origin}{endpoint}"
            endpoint_result = {
                'endpoint': endpoint,
                'url': url,
                'requests_sent': 0,
                'successful': 0,
                'rate_limited': False,
                'rate_limit_after': None
            }

            # Send 20 rapid requests
            statuses = []
            for i in range(20):
                try:
                    # Test with common login data
                    data = {
                        'username': f'test{i}@zylon.com',
                        'email': f'test{i}@zylon.com',
                        'password': 'TestPassword123!'
                    }
                    resp = self.session.post(url, data=data, timeout=5, allow_redirects=False)
                    statuses.append(resp.status_code)
                    endpoint_result['requests_sent'] += 1

                    if resp.status_code in [200, 201, 302]:
                        endpoint_result['successful'] += 1
                    elif resp.status_code in [429, 503]:
                        endpoint_result['rate_limited'] = True
                        endpoint_result['rate_limit_after'] = i + 1
                        break

                except Exception:
                    statuses.append(0)
                    endpoint_result['requests_sent'] += 1

            # Analyze results
            if endpoint_result['requests_sent'] >= 15 and not endpoint_result['rate_limited']:
                # No rate limiting detected after 15+ requests
                endpoint_result['verdict'] = 'NO RATE LIMITING'
                results['missing_rate_limit'].append({
                    'endpoint': endpoint,
                    'url': url,
                    'successful_requests': endpoint_result['successful'],
                    'severity': 'high' if 'login' in endpoint.lower() or 'auth' in endpoint.lower() else 'medium',
                    'description': f'{endpoint_result["successful"]}/{endpoint_result["requests_sent"]} requests accepted without rate limiting'
                })
            elif endpoint_result['rate_limited']:
                endpoint_result['verdict'] = 'RATE LIMITED'
            else:
                endpoint_result['verdict'] = 'ENDPOINT NOT FOUND'

            results['endpoints_tested'].append(endpoint_result)
            results['total_tested'] += 1

        results['total_missing'] = len(results['missing_rate_limit'])

        return results

    # ========================================================================
    # SENSITIVE FILE DEEP SCANNER
    # ========================================================================

    def scan_sensitive_files(self, base_url):
        """
        Deep scan for sensitive files and paths.
        More comprehensive than basic directory brute force.
        Checks 100+ sensitive file patterns.
        """
        results = {
            'base_url': base_url,
            'found_files': [],
            'critical_exposures': [],
            'total_tested': 0,
            'total_found': 0
        }

        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Define severity categories
        critical_patterns = ['.env', 'credentials', 'password', 'secret',
                           'private_key', 'id_rsa', 'backup.sql', 'database.sql',
                           '.aws/credentials', 'wp-config.php']
        high_patterns = ['.git/', '.svn/', 'config.', 'backup.zip', 'dump.sql',
                        'phpinfo.php', 'server-status', 'phpmyadmin']

        def check_file(path):
            url = f"{origin}/{path.lstrip('/')}"
            try:
                resp = self.session.get(url, timeout=5, allow_redirects=False)
                return (path, url, resp.status_code, len(resp.content),
                       resp.headers.get('Content-Type', ''), resp)
            except Exception:
                return (path, url, 0, 0, '', None)

        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {executor.submit(check_file, path): path for path in SENSITIVE_FILES_DEEP}
            for future in as_completed(futures):
                path, url, status, size, content_type, resp = future.result()
                results['total_tested'] += 1

                if status in [200, 301, 302, 403]:
                    # Determine severity
                    severity = 'low'
                    if any(p in path.lower() for p in critical_patterns):
                        severity = 'critical'
                    elif any(p in path.lower() for p in high_patterns):
                        severity = 'high'
                    elif status == 403:
                        severity = 'info'  # Exists but forbidden
                    else:
                        severity = 'medium'

                    file_info = {
                        'path': path,
                        'url': url,
                        'status_code': status,
                        'size': size,
                        'content_type': content_type,
                        'severity': severity
                    }

                    # Check for actual content exposure
                    if resp and status == 200:
                        content = resp.text[:2000] if resp else ''

                        # Check for sensitive content
                        if any(p in path.lower() for p in ['.env', 'config.', 'wp-config']):
                            if any(kw in content.lower() for kw in ['password', 'secret', 'key=', 'db_', 'database']):
                                file_info['contains_secrets'] = True
                                severity = 'critical'
                                file_info['severity'] = 'critical'
                                results['critical_exposures'].append(file_info)

                        # Check for .git exposure
                        if path.startswith('.git/'):
                            if 'ref:' in content or '[core]' in content:
                                file_info['git_exposed'] = True
                                severity = 'critical'
                                file_info['severity'] = 'critical'
                                results['critical_exposures'].append(file_info)

                        # Check for database dump
                        if path.endswith('.sql'):
                            if any(kw in content.lower() for kw in ['create table', 'insert into', 'drop table']):
                                file_info['db_dump_exposed'] = True
                                severity = 'critical'
                                file_info['severity'] = 'critical'
                                results['critical_exposures'].append(file_info)

                    results['found_files'].append(file_info)

        results['total_found'] = len(results['found_files'])
        results['total_critical'] = len(results['critical_exposures'])

        return results
