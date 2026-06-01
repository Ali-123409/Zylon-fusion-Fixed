#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Session Security Engine
==============================================
Fused from: Flask-Unsign (https://github.com/Paradoxis/Flask-Unsign)
           + General Session Security Techniques + Custom Zylon Techniques
Capabilities:
  - Flask session cookie decoding/encoding/brute-forcing
  - Django session analysis
  - Express.js session cookie analysis
  - Laravel session analysis
  - PHP session analysis
  - JWT token analysis (complementary to jwt_engine.py)
  - Session fixation detection
  - Session hijacking vulnerability detection
  - Cookie security analysis (Secure, HttpOnly, SameSite flags)
  - Secret key brute-forcing for Flask
  - Session forgery/prediction testing
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import re
import time
import zlib
import threading
from datetime import datetime
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

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
# FLASK COMMON SECRET KEYS (for brute-forcing)
# ============================================================================

FLASK_COMMON_KEYS = [
    "secret", "secret-key", "secret_key", "changeme", "password",
    "flask", "flask-secret", "app", "app-secret", "mysecret",
    "supersecret", "development", "dev", "dev-key", "dev-secret",
    "testing", "test", "test-key", "test-secret", "production",
    "prod", "prod-key", "prod-secret", "staging", "stage",
    "debug", "default", "example", "sample", "demo",
    "key", "s3cr3t", "s3cret", "sekret", "my-secret",
    "my-secret-key", "app-key", "application-secret",
    "keyboard", "keyboard-cat", "this-is-a-secret",
    "change-me", "please-change-me", "replace-me",
    "notsecret", "not-a-secret", "notsosecret",
    "your-secret-key", "your-secret", "secretkey",
    "123456", "12345678", "1234567890", "abc123",
    "qwerty", "letmein", "welcome", "admin",
    "root", "toor", "pass", "passw0rd",
    "flask-unsign", "unsign", "crack", "cracked",
    "key1", "key2", "key123", "secret1", "secret123",
    "CHANGEME", "CHANGE-ME", "SECRET", "SECRET_KEY",
    "mysecretkey", "my-secret-key", "myappsecret",
    "app_secret", "app_secret_key", "flask_secret",
    "flask_secret_key", "flask-app-secret",
    "django-insecure", "insecure", "insecure-key",
    "developmentkey", "devkey", "testkey",
    "sk-secret", "sk-key", "sk-flask", "sk-app",
    "super-secret", "super-secret-key", "top-secret",
    "topsecret", "top-secret-key", "ultra-secret",
    "very-secret", "verysecret", "very-secret-key",
    "_session", "_secret", "session_key", "session-secret",
    "cookie-secret", "cookie-key", "signing-key",
    "signing_secret", "hmac-key", "hmac-secret",
    "my-flask-secret", "my_flask_key",
    "pw-secret", "password1", "p@ssw0rd", "p@ss",
    "this-is-secret", "this-is-a-secret-key",
    "do-not-use-in-production", "do-not-share",
    "TODO", "FIXME", "HACK", "XXX",
    "secret!", "Secret!", "SECRET!", "s3cr3t!",
    "openssl", "random", "urandom", "fernet",
    "jwt-secret", "jwt-key", "token-secret", "token-key",
]

# Additional Flask secret key patterns (from common repos/tutorials)
FLASK_KEY_PATTERNS = [
    "app.config['SECRET_KEY']", "os.environ.get('SECRET_KEY')",
    "os.getenv('SECRET_KEY')", "SECRET_KEY = '{}'",
]

# ============================================================================
# DJANGO SESSION SIGNATURE PATTERNS
# ============================================================================

DJANGO_HASH_ALGORITHMS = {
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

# ============================================================================
# COOKIE SECURITY FLAGS
# ============================================================================

COOKIE_SECURITY_FLAGS = {
    "Secure": {
        "description": "Cookie only sent over HTTPS",
        "severity": "High",
        "impact": "Cookie can be intercepted over HTTP",
    },
    "HttpOnly": {
        "description": "Cookie not accessible via JavaScript",
        "severity": "High",
        "impact": "XSS can steal cookie via document.cookie",
    },
    "SameSite": {
        "description": "Controls cross-site cookie sending",
        "severity": "Medium",
        "impact": "CSRF attacks possible without SameSite restriction",
        "valid_values": ["Strict", "Lax", "None"],
    },
    "Path": {
        "description": "Cookie scope to path",
        "severity": "Low",
        "impact": "Overly broad path increases attack surface",
    },
    "Domain": {
        "description": "Cookie scope to domain",
        "severity": "Low",
        "impact": "Overly broad domain increases attack surface",
    },
}

# ============================================================================
# SESSION FIXATION PAYLOADS
# ============================================================================

SESSION_FIXATION_TESTS = [
    {"name": "pre_auth_session_retained", "description": "Session ID not rotated after login"},
    {"name": "url_session_id", "description": "Session ID accepted in URL parameter"},
    {"name": "cookie_injection", "description": "New session cookie can be injected via Set-Cookie"},
    {"name": "session_cookie_no_rotate", "description": "Session cookie unchanged after privilege change"},
    {"name": "subdomain_session_fixation", "description": "Session cookie scoped to parent domain"},
]

# ============================================================================
# SESSION HIJACKING INDICATORS
# ============================================================================

SESSION_HIJACKING_INDICATORS = {
    "no_ip_binding": "Session not bound to client IP address",
    "no_user_agent_binding": "Session not bound to User-Agent",
    "long_session_expiry": "Session expiry too long (>24h)",
    "no_session_rotation": "Session not rotated on sensitive actions",
    "predictable_session_id": "Session ID appears sequential/predictable",
    "session_in_url": "Session ID exposed in URL",
    "weak_cookie_flags": "Missing Secure/HttpOnly/SameSite flags",
}


class SessionSecurityEngine:
    """Session Security Engine - Fused from Flask-Unsign + General Session Techniques"""

    def __init__(self, target_url=None, cookies=None, headers=None, timeout=DEFAULT_TIMEOUT,
                 threads=MAX_THREADS, proxy=None):
        self.target_url = target_url
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else
                'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _send_request(self, url, method="GET", data=None, headers=None, cookies=None,
                      allow_redirects=True):
        """Send HTTP request with error handling"""
        try:
            h = headers or self.headers
            c = cookies or self.cookies
            if method == "GET":
                resp = self.session.get(url, headers=h, cookies=c,
                                       timeout=self.timeout,
                                       allow_redirects=allow_redirects)
            elif method == "POST":
                resp = self.session.post(url, data=data, headers=h, cookies=c,
                                        timeout=self.timeout,
                                        allow_redirects=allow_redirects)
            elif method == "HEAD":
                resp = self.session.head(url, headers=h, cookies=c,
                                        timeout=self.timeout,
                                        allow_redirects=allow_redirects)
            else:
                resp = self.session.request(method, url, data=data, headers=h,
                                           cookies=c, timeout=self.timeout,
                                           allow_redirects=allow_redirects)
            return resp
        except Exception:
            return None

    # ========================================================================
    # FLASK SESSION OPERATIONS
    # ========================================================================

    def decode_flask_session(self, cookie_value):
        """Decode Flask session cookie (itsdangerous format)

        Flask sessions are encoded as: base64(json_payload).timestamp.signature
        The timestamp is a base62-encoded integer.
        The signature is HMAC-SHA1 by default.
        """
        self._print(f"[*] Decoding Flask session cookie...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "framework": "Flask",
                "decoded_payload": None,
                "timestamp": None,
                "signature_valid": False,
                "raw_components": None,
            },
            "scan_type": "flask_session_decode",
        }

        try:
            # Flask session format: payload.timestamp.signature
            parts = cookie_value.split('.')
            if len(parts) < 3:
                # Might be a compressed payload (starts with '.')
                if cookie_value.startswith('.'):
                    # Compressed Flask session
                    parts = cookie_value[1:].split('.')
                    if len(parts) >= 3:
                        payload_b64 = parts[0]
                        try:
                            # Add padding
                            padded = payload_b64 + '=' * (-len(payload_b64) % 4)
                            compressed = base64.urlsafe_b64decode(padded)
                            decompressed = zlib.decompress(compressed)
                            payload = json.loads(decompressed.decode('utf-8'))
                            result["details"]["decoded_payload"] = payload
                            result["details"]["compressed"] = True
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": "flask_session_decoded",
                                "payload": payload,
                                "compressed": True,
                            })
                            self._print(f"[+] Flask session decoded (compressed): {json.dumps(payload, indent=2)[:200]}", GREEN)
                            return result
                        except Exception as e:
                            result["findings"].append({
                                "type": "decode_error",
                                "error": f"Compressed decode failed: {str(e)}",
                            })

                result["findings"].append({
                    "type": "invalid_format",
                    "error": f"Expected at least 3 dot-separated parts, got {len(parts)}",
                })
                self._print(f"[-] Invalid Flask session format", YELLOW)
                return result

            payload_b64 = parts[0]
            timestamp_b64 = parts[1]
            signature_b64 = '.'.join(parts[2:])

            result["details"]["raw_components"] = {
                "payload": payload_b64[:50] + '...',
                "timestamp": timestamp_b64,
                "signature": signature_b64[:50] + '...',
            }

            # Decode payload
            try:
                padded = payload_b64 + '=' * (-len(payload_b64) % 4)
                decoded_bytes = base64.urlsafe_b64decode(padded)

                # Check if compressed (first byte is 0x78 for zlib)
                if decoded_bytes and decoded_bytes[0:1] == b'\x78':
                    try:
                        decompressed = zlib.decompress(decoded_bytes)
                        payload = json.loads(decompressed.decode('utf-8'))
                        result["details"]["compressed"] = True
                    except Exception:
                        payload = json.loads(decoded_bytes.decode('utf-8'))
                else:
                    payload = json.loads(decoded_bytes.decode('utf-8'))

                result["details"]["decoded_payload"] = payload
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "flask_session_decoded",
                    "payload": payload,
                })
                self._print(f"[+] Flask session decoded: {json.dumps(payload, indent=2)[:300]}", GREEN)
            except Exception as e:
                # Try raw decode
                try:
                    payload = json.loads(decoded_bytes.decode('utf-8', errors='ignore'))
                    result["details"]["decoded_payload"] = payload
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "flask_session_decoded_partial",
                        "payload": payload,
                    })
                except Exception:
                    result["findings"].append({
                        "type": "payload_decode_error",
                        "error": str(e),
                    })
                    self._print(f"[-] Could not decode payload: {str(e)}", YELLOW)

            # Decode timestamp
            try:
                ts_int = int(timestamp_b64, 16) if re.match(r'^[0-9a-f]+$', timestamp_b64, re.I) else int(timestamp_b64)
                dt = datetime.fromtimestamp(ts_int)
                result["details"]["timestamp"] = {
                    "raw": ts_int,
                    "datetime": dt.strftime('%Y-%m-%d %H:%M:%S'),
                }
            except Exception:
                pass

            # Check for security-sensitive data in payload
            if result["details"]["decoded_payload"]:
                sensitive_keys = ['user_id', 'username', 'email', 'role', 'admin',
                                  'is_admin', 'authenticated', 'password', 'token',
                                  'secret', 'api_key', 'csrf', 'session_id']
                found_sensitive = []
                for key in sensitive_keys:
                    if key in str(result["details"]["decoded_payload"]).lower():
                        found_sensitive.append(key)
                if found_sensitive:
                    result["findings"].append({
                        "type": "sensitive_data_in_session",
                        "keys": found_sensitive,
                        "severity": "High",
                        "description": "Session cookie contains sensitive data that could be exploited",
                    })
                    self._print(f"[!] Sensitive data found in session: {found_sensitive}", RED)

        except Exception as e:
            result["findings"].append({
                "type": "decode_error",
                "error": str(e),
            })
            self._print(f"[-] Flask session decode error: {str(e)}", RED)

        return result

    def encode_flask_session(self, data, secret_key):
        """Encode Flask session cookie with a given secret key

        Uses itsdangerous URLSafeTimedSerializer format.
        """
        self._print(f"[*] Encoding Flask session with provided key...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "framework": "Flask",
                "encoded_cookie": None,
                "algorithm": "HS256 (HMAC-SHA1)",
            },
            "scan_type": "flask_session_encode",
        }

        try:
            # Encode the payload
            if isinstance(data, str):
                data = json.loads(data)

            json_str = json.dumps(data, separators=(',', ':'))
            payload_b64 = base64.urlsafe_b64encode(json_str.encode()).rstrip(b'=').decode()

            # Generate timestamp
            timestamp = str(int(time.time()))

            # Generate HMAC-SHA1 signature
            message = f"{payload_b64}.{timestamp}".encode()
            if isinstance(secret_key, str):
                secret_key = secret_key.encode()

            sig = hmac.new(secret_key, message, hashlib.sha1).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

            cookie_value = f"{payload_b64}.{timestamp}.{sig_b64}"

            result["details"]["encoded_cookie"] = cookie_value
            result["vulnerable"] = True
            result["findings"].append({
                "type": "flask_session_encoded",
                "cookie": cookie_value,
                "payload": data,
            })
            self._print(f"[+] Flask session encoded: {cookie_value[:100]}...", GREEN)

        except Exception as e:
            result["findings"].append({
                "type": "encode_error",
                "error": str(e),
            })
            self._print(f"[-] Flask session encode error: {str(e)}", RED)

        return result

    def bruteforce_flask_key(self, cookie_value, wordlist=None):
        """Brute-force Flask secret key from session cookie

        Tries common keys and optionally a wordlist file.
        """
        self._print(f"[*] Brute-forcing Flask secret key...", MAGENTA)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "framework": "Flask",
                "key_found": None,
                "keys_tried": 0,
                "elapsed_seconds": 0,
            },
            "scan_type": "flask_session_bruteforce",
        }

        start_time = time.time()

        # Parse the cookie
        parts = cookie_value.split('.')
        if len(parts) < 3:
            result["findings"].append({
                "type": "invalid_format",
                "error": "Invalid Flask session cookie format",
            })
            self._print(f"[-] Invalid Flask session cookie format", YELLOW)
            return result

        payload_b64 = parts[0]
        timestamp_b64 = parts[1]
        signature_b64 = '.'.join(parts[2:])

        message = f"{payload_b64}.{timestamp_b64}".encode()

        # Decode expected signature
        try:
            sig_padded = signature_b64 + '=' * (-len(signature_b64) % 4)
            expected_sig = base64.urlsafe_b64decode(sig_padded)
        except Exception:
            result["findings"].append({
                "type": "signature_decode_error",
                "error": "Could not decode signature from cookie",
            })
            self._print(f"[-] Could not decode signature", YELLOW)
            return result

        # Build key list
        keys_to_try = list(FLASK_COMMON_KEYS)

        if wordlist and os.path.isfile(wordlist):
            try:
                with open(wordlist, 'r', errors='ignore') as f:
                    for line in f:
                        key = line.strip()
                        if key and key not in keys_to_try:
                            keys_to_try.append(key)
                self._print(f"[*] Loaded {len(keys_to_try)} keys from wordlist", CYAN)
            except Exception as e:
                self._print(f"[!] Could not read wordlist: {str(e)}", YELLOW)

        found_key = None
        keys_tried = 0

        def try_key(key):
            nonlocal found_key, keys_tried
            key_bytes = key.encode() if isinstance(key, str) else key
            # Try HMAC-SHA1 (Flask default)
            computed = hmac.new(key_bytes, message, hashlib.sha1).digest()
            if hmac.compare_digest(computed, expected_sig):
                found_key = key
                return True
            # Try HMAC-SHA256
            computed256 = hmac.new(key_bytes, message, hashlib.sha256).digest()
            if hmac.compare_digest(computed256, expected_sig):
                found_key = key
                return True
            with self.lock:
                keys_tried += 1
            return False

        # Use threading for parallel key testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(try_key, key): key for key in keys_to_try}
            for future in as_completed(futures):
                try:
                    if future.result():
                        break
                except Exception:
                    pass

        elapsed = time.time() - start_time
        result["details"]["keys_tried"] = keys_tried
        result["details"]["elapsed_seconds"] = round(elapsed, 2)

        if found_key:
            result["vulnerable"] = True
            result["details"]["key_found"] = found_key
            result["findings"].append({
                "type": "flask_key_cracked",
                "secret_key": found_key,
                "severity": "Critical",
                "description": f"Flask SECRET_KEY cracked: '{found_key}'. Session forgery possible.",
            })
            self._print(f"\n{BOLD}{GREEN}[+] FLASK SECRET KEY FOUND: '{found_key}'{RESET}", GREEN)
            self._print(f"    Keys tried: {keys_tried} in {elapsed:.2f}s", CYAN)

            # Auto-encode a test payload
            test_data = {"admin": True, "user_id": 1, "username": "admin"}
            encode_result = self.encode_flask_session(test_data, found_key)
            if encode_result["details"]["encoded_cookie"]:
                result["details"]["forged_cookie"] = encode_result["details"]["encoded_cookie"]
                result["findings"].append({
                    "type": "session_forgery_demo",
                    "forged_cookie": encode_result["details"]["encoded_cookie"],
                    "forged_payload": test_data,
                    "description": "Forged session cookie with admin privileges",
                })
                self._print(f"    Forged admin cookie: {encode_result['details']['encoded_cookie'][:80]}...", YELLOW)
        else:
            result["findings"].append({
                "type": "key_not_found",
                "keys_tried": keys_tried,
                "description": f"Secret key not found after trying {keys_tried} keys",
            })
            self._print(f"[-] Secret key not found ({keys_tried} keys tried in {elapsed:.2f}s)", YELLOW)

        return result

    # ========================================================================
    # DJANGO SESSION ANALYSIS
    # ========================================================================

    def analyze_django_session(self, cookie_value):
        """Analyze Django session cookie

        Django sessions are typically: sessionid=<hash>
        The session data is stored server-side, but the cookie format can reveal
        information. Django also uses signed cookies with itsdangerous.
        """
        self._print(f"[*] Analyzing Django session cookie...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "framework": "Django",
                "session_type": None,
                "decoded_data": None,
                "signature_algorithm": None,
                "is_signed_cookie": False,
            },
            "scan_type": "django_session_analysis",
        }

        # Check if this is a Django signed-cookie session
        # Format: json_payload:timestamp:signature
        if ':' in cookie_value:
            parts = cookie_value.split(':')
            if len(parts) == 3:
                result["details"]["is_signed_cookie"] = True
                result["details"]["session_type"] = "signed_cookie"

                try:
                    # Decode the payload part
                    payload_b64 = parts[0]
                    padded = payload_b64 + '=' * (-len(payload_b64) % 4)
                    decoded = base64.urlsafe_b64decode(padded)
                    data = json.loads(decoded.decode('utf-8'))
                    result["details"]["decoded_data"] = data
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "django_signed_cookie_decoded",
                        "data": data,
                        "description": "Django signed cookie session data decoded",
                    })
                    self._print(f"[+] Django signed cookie decoded: {json.dumps(data, indent=2)[:200]}", GREEN)
                except Exception as e:
                    result["findings"].append({
                        "type": "signed_cookie_decode_error",
                        "error": str(e),
                    })

                # Check timestamp
                try:
                    ts = int(parts[1])
                    dt = datetime.fromtimestamp(ts)
                    result["details"]["timestamp"] = dt.strftime('%Y-%m-%d %H:%M:%S')
                    # Check if session is very old
                    age_hours = (time.time() - ts) / 3600
                    if age_hours > 168:  # > 1 week
                        result["findings"].append({
                            "type": "long_lived_session",
                            "age_hours": round(age_hours, 1),
                            "severity": "Medium",
                            "description": f"Session cookie age: {age_hours:.1f} hours (> 1 week)",
                        })
                except Exception:
                    pass

        else:
            # Database-backed session - just a hash
            result["details"]["session_type"] = "database_backed"
            session_id = cookie_value.strip()

            # Analyze the session ID format
            if re.match(r'^[a-f0-9]{32}$', session_id, re.I):
                result["details"]["signature_algorithm"] = "MD5"
                result["findings"].append({
                    "type": "md5_session_id",
                    "severity": "Low",
                    "description": "Session ID appears to be MD5 hash - consider if predictable",
                })
            elif re.match(r'^[a-f0-9]{40}$', session_id, re.I):
                result["details"]["signature_algorithm"] = "SHA1"
                result["findings"].append({
                    "type": "sha1_session_id",
                    "severity": "Low",
                    "description": "Session ID appears to be SHA1 hash",
                })
            elif re.match(r'^[a-f0-9]{64}$', session_id, re.I):
                result["details"]["signature_algorithm"] = "SHA256"

            # Check for Django CSRF token pattern
            if len(session_id) < 20:
                result["findings"].append({
                    "type": "short_session_id",
                    "severity": "Medium",
                    "description": "Session ID is short and may be predictable",
                })
                result["vulnerable"] = True

            self._print(f"[*] Django database-backed session detected (ID: {session_id[:16]}...)", CYAN)

        # Check for Django-specific vulnerabilities
        if result["details"]["is_signed_cookie"]:
            result["findings"].append({
                "type": "signed_cookie_backend",
                "severity": "Medium",
                "description": "Django using signed cookie backend - data visible to client",
            })

        return result

    # ========================================================================
    # EXPRESS.JS SESSION ANALYSIS
    # ========================================================================

    def analyze_express_session(self, cookie_value):
        """Analyze Express.js session cookie (connect.sid / express.sid)

        Express sessions with express-session use: s:<base64_payload>.<signature>
        The signature is HMAC-SHA256 of the session ID using the session secret.
        """
        self._print(f"[*] Analyzing Express.js session cookie...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "framework": "Express.js",
                "session_type": None,
                "decoded_data": None,
                "session_id": None,
            },
            "scan_type": "express_session_analysis",
        }

        # Express session format: s:<payload>.<signature>
        if cookie_value.startswith('s:'):
            result["details"]["session_type"] = "express-session"
            inner = cookie_value[2:]  # Remove 's:' prefix

            if '.' in inner:
                parts = inner.rsplit('.', 1)
                payload = parts[0]
                signature = parts[1]

                result["details"]["session_id"] = payload[:32] + '...' if len(payload) > 32 else payload

                # Try to decode the payload (might be base64-encoded JSON)
                try:
                    padded = payload + '=' * (-len(payload) % 4)
                    decoded = base64.urlsafe_b64decode(padded)
                    data = json.loads(decoded.decode('utf-8'))
                    result["details"]["decoded_data"] = data
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "express_session_decoded",
                        "data": data,
                        "description": "Express.js session data decoded",
                    })
                    self._print(f"[+] Express.js session decoded: {json.dumps(data, indent=2)[:200]}", GREEN)
                except Exception:
                    # Might just be a random session ID
                    result["details"]["session_id"] = payload
                    self._print(f"[*] Express.js session ID: {payload[:32]}...", CYAN)

                # Check signature format
                if signature:
                    result["details"]["signature_present"] = True
                    result["details"]["signature_algorithm"] = "HMAC-SHA256"
                else:
                    result["findings"].append({
                        "type": "unsigned_session",
                        "severity": "Critical",
                        "description": "Express.js session has no signature - session tampering possible",
                    })
                    result["vulnerable"] = True
        else:
            # Might be a custom session format
            result["details"]["session_type"] = "custom"
            result["details"]["session_id"] = cookie_value[:32]

            # Try base64 decode
            try:
                padded = cookie_value + '=' * (-len(cookie_value) % 4)
                decoded = base64.urlsafe_b64decode(padded)
                try:
                    data = json.loads(decoded.decode('utf-8'))
                    result["details"]["decoded_data"] = data
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "custom_session_decoded",
                        "data": data,
                    })
                except Exception:
                    pass
            except Exception:
                pass

        return result

    # ========================================================================
    # LARAVEL SESSION ANALYSIS
    # ========================================================================

    def analyze_laravel_session(self, cookie_value):
        """Analyze Laravel session cookie

        Laravel encrypts session cookies by default using OpenSSL.
        Format: base64(json({iv, value, mac}))
        The 'value' field is encrypted, but the structure can be analyzed.
        """
        self._print(f"[*] Analyzing Laravel session cookie...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "framework": "Laravel",
                "encryption_enabled": None,
                "iv_length": None,
                "mac_present": False,
                "cipher_detected": None,
                "decoded_structure": None,
            },
            "scan_type": "laravel_session_analysis",
        }

        try:
            # Try to decode the outer base64
            padded = cookie_value + '=' * (-len(cookie_value) % 4)
            decoded = base64.urlsafe_b64decode(padded)

            # Try to parse as JSON
            data = json.loads(decoded.decode('utf-8'))

            if isinstance(data, dict) and 'iv' in data and 'value' in data:
                result["details"]["encryption_enabled"] = True
                result["details"]["mac_present"] = 'mac' in data
                result["details"]["decoded_structure"] = {
                    "iv_length": len(base64.b64decode(data['iv'])) if 'iv' in data else 0,
                    "value_length": len(data.get('value', '')),
                    "mac_present": 'mac' in data,
                }

                # Determine cipher from IV length
                iv_len = result["details"]["decoded_structure"]["iv_length"]
                if iv_len == 16:
                    result["details"]["cipher_detected"] = "AES-128-CBC"
                elif iv_len == 32:
                    result["details"]["cipher_detected"] = "AES-256-CBC"

                # Check for missing MAC (critical vulnerability)
                if 'mac' not in data or not data.get('mac'):
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "laravel_no_mac",
                        "severity": "Critical",
                        "description": "Laravel session cookie has no MAC - encryption oracle/padding oracle possible",
                    })
                    self._print(f"[!!!] Laravel session has no MAC - CRITICAL vulnerability!", RED)
                else:
                    # Check MAC length (should be SHA256 = 64 hex chars)
                    mac = data.get('mac', '')
                    if len(mac) == 64:
                        result["details"]["mac_algorithm"] = "SHA256"
                    elif len(mac) == 40:
                        result["details"]["mac_algorithm"] = "SHA1"
                        result["findings"].append({
                            "type": "laravel_weak_mac",
                            "severity": "Medium",
                            "description": "Laravel session uses SHA1 MAC instead of SHA256",
                        })

                result["findings"].append({
                    "type": "laravel_encrypted_session",
                    "cipher": result["details"]["cipher_detected"],
                    "description": "Laravel session cookie is encrypted (standard behavior)",
                })
                self._print(f"[*] Laravel encrypted session detected (cipher: {result['details']['cipher_detected']})", CYAN)

            elif isinstance(data, dict):
                # Might be unencrypted session data
                result["details"]["encryption_enabled"] = False
                result["details"]["decoded_structure"] = data
                result["vulnerable"] = True
                result["findings"].append({
                    "type": "laravel_unencrypted_session",
                    "severity": "Critical",
                    "data": data,
                    "description": "Laravel session cookie is NOT encrypted - data visible to client",
                })
                self._print(f"[!!!] Laravel session is UNENCRYPTED: {json.dumps(data)[:200]}", RED)

        except json.JSONDecodeError:
            # Not JSON - might be a plain session ID
            result["details"]["encryption_enabled"] = False
            result["details"]["session_id"] = cookie_value[:32]
            result["findings"].append({
                "type": "plain_session_id",
                "description": "Session appears to be a plain session ID (database-backed)",
            })
        except Exception as e:
            result["findings"].append({
                "type": "decode_error",
                "error": str(e),
            })

        return result

    # ========================================================================
    # COOKIE SECURITY ANALYSIS
    # ========================================================================

    def check_cookie_security(self, url):
        """Check cookie security flags (Secure, HttpOnly, SameSite)

        Analyzes all cookies set by the target URL.
        """
        self._print(f"[*] Checking cookie security flags on {url}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "cookies_analyzed": 0,
                "insecure_cookies": [],
                "secure_cookies": [],
                "security_score": 100,
            },
            "scan_type": "cookie_security_check",
        }

        try:
            resp = self._send_request(url)
            if not resp:
                result["findings"].append({
                    "type": "connection_error",
                    "description": f"Could not connect to {url}",
                })
                return result

            # Extract cookies from response
            cookies = []
            # From requests cookies
            for name, value in resp.cookies.items():
                cookie_info = {"name": name, "value": value[:50]}
                cookies.append(cookie_info)

            # From Set-Cookie headers (more detailed)
            for header in resp.headers.get('Set-Cookie', '').split(','):
                header = header.strip()
                if not header:
                    continue

                parts = header.split(';')
                name_value = parts[0].strip()
                if '=' in name_value:
                    name = name_value.split('=', 1)[0].strip()
                    value = name_value.split('=', 1)[1].strip()
                else:
                    name = name_value
                    value = ""

                cookie_attrs = {}
                for attr in parts[1:]:
                    attr = attr.strip()
                    if '=' in attr:
                        attr_name = attr.split('=', 1)[0].strip().lower()
                        attr_value = attr.split('=', 1)[1].strip()
                    else:
                        attr_name = attr.strip().lower()
                        attr_value = True
                    cookie_attrs[attr_name] = attr_value

                cookie_info = {
                    "name": name,
                    "value": value[:50],
                    "attributes": cookie_attrs,
                    "secure": 'secure' in cookie_attrs,
                    "httponly": 'httponly' in cookie_attrs,
                    "samesite": cookie_attrs.get('samesite', None),
                    "path": cookie_attrs.get('path', '/'),
                    "domain": cookie_attrs.get('domain', None),
                }

                # Analyze security of this cookie
                issues = []

                # Session-related cookies should have Secure flag
                session_keywords = ['session', 'sess', 'sid', 'token', 'auth', 'login', 'csrf']
                is_session_cookie = any(kw in name.lower() for kw in session_keywords)

                if is_session_cookie and not cookie_info["secure"]:
                    issues.append("Missing Secure flag - cookie sent over HTTP")
                    result["details"]["security_score"] -= 20

                if is_session_cookie and not cookie_info["httponly"]:
                    issues.append("Missing HttpOnly flag - accessible via JavaScript")
                    result["details"]["security_score"] -= 20

                if is_session_cookie and not cookie_info["samesite"]:
                    issues.append("Missing SameSite flag - vulnerable to CSRF")
                    result["details"]["security_score"] -= 15

                if cookie_info["samesite"] and str(cookie_info["samesite"]).lower() == 'none':
                    issues.append("SameSite=None - cookie sent with cross-site requests")
                    result["details"]["security_score"] -= 10

                # Check for overly broad domain
                if cookie_info["domain"]:
                    domain = str(cookie_info["domain"]).lstrip('.')
                    if '.' not in domain.replace('.', '', 1):
                        issues.append(f"Overly broad domain scope: {cookie_info['domain']}")
                        result["details"]["security_score"] -= 5

                cookie_info["issues"] = issues

                if issues:
                    result["vulnerable"] = True
                    result["details"]["insecure_cookies"].append(cookie_info)
                    result["findings"].append({
                        "type": "insecure_cookie",
                        "cookie_name": name,
                        "issues": issues,
                        "severity": "High" if is_session_cookie else "Low",
                    })
                    self._print(f"  [!] Cookie '{name}': {', '.join(issues)}", RED)
                else:
                    result["details"]["secure_cookies"].append(cookie_info)
                    self._print(f"  [+] Cookie '{name}': Secure", GREEN)

            result["details"]["cookies_analyzed"] = len(result["details"]["insecure_cookies"]) + len(result["details"]["secure_cookies"])
            result["details"]["security_score"] = max(0, result["details"]["security_score"])

            if result["vulnerable"]:
                self._print(f"\n[!] Cookie Security Score: {result['details']['security_score']}/100", YELLOW)
            else:
                self._print(f"[+] All cookies properly secured (Score: {result['details']['security_score']}/100)", GREEN)

        except Exception as e:
            result["findings"].append({
                "type": "scan_error",
                "error": str(e),
            })

        return result

    # ========================================================================
    # SESSION FIXATION TEST
    # ========================================================================

    def test_session_fixation(self, url):
        """Test for session fixation vulnerabilities

        Checks if:
        1. Pre-authentication session is retained after login
        2. Session ID is accepted in URL parameters
        3. Session cookie doesn't rotate on privilege change
        4. New session cookie can be injected
        """
        self._print(f"[*] Testing session fixation on {url}", MAGENTA)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "tests_run": 0,
                "tests_passed": 0,
                "tests_failed": 0,
                "session_rotated_after_auth": None,
                "session_accepted_in_url": None,
                "pre_auth_session": None,
                "post_auth_session": None,
            },
            "scan_type": "session_fixation_test",
        }

        # Test 1: Pre-auth session retained
        self._print(f"  [*] Test 1: Pre-authentication session retention", CYAN)
        try:
            # Get pre-auth session
            resp1 = self._send_request(url)
            if resp1:
                pre_auth_cookies = dict(resp1.cookies)
                result["details"]["pre_auth_session"] = str(pre_auth_cookies)

                # Simulate login by posting to common login endpoints
                login_paths = ['/login', '/auth/login', '/signin', '/api/login', '/api/auth']
                login_found = False
                for path in login_paths:
                    login_url = url.rstrip('/') + path
                    resp2 = self._send_request(login_url, method="POST",
                                               data={"username": "test", "password": "test"})
                    if resp2 and resp2.status_code in [200, 301, 302, 401, 403]:
                        login_found = True
                        post_auth_cookies = dict(resp2.cookies)
                        result["details"]["post_auth_session"] = str(post_auth_cookies)

                        # Compare sessions
                        for cookie_name in pre_auth_cookies:
                            if cookie_name in post_auth_cookies:
                                if pre_auth_cookies[cookie_name] == post_auth_cookies[cookie_name]:
                                    result["findings"].append({
                                        "type": "session_not_rotated",
                                        "cookie_name": cookie_name,
                                        "severity": "High",
                                        "description": f"Session cookie '{cookie_name}' not rotated after login attempt",
                                    })
                                    result["vulnerable"] = True
                                    result["details"]["session_rotated_after_auth"] = False
                                    self._print(f"    [!] Cookie '{cookie_name}' NOT rotated after login!", RED)
                                else:
                                    result["details"]["session_rotated_after_auth"] = True
                                    self._print(f"    [+] Cookie '{cookie_name}' rotated after login", GREEN)
                        break

                if not login_found:
                    self._print(f"    [*] No login endpoint found - skipping rotation test", YELLOW)

                result["details"]["tests_run"] += 1
        except Exception as e:
            result["findings"].append({"type": "test_error", "test": "pre_auth_retention", "error": str(e)})

        # Test 2: Session ID in URL
        self._print(f"  [*] Test 2: Session ID in URL parameter", CYAN)
        try:
            session_param_names = ['sessionid', 'sid', 'PHPSESSID', 'jsessionid', 'sess']
            for param in session_param_names:
                test_url = f"{url}{'&' if '?' in url else '?'}{param}=FIXATED_SESSION_TEST_12345"
                resp = self._send_request(test_url)
                if resp:
                    # Check if the server accepted our session parameter
                    if 'FIXATED_SESSION_TEST_12345' in str(dict(resp.cookies)):
                        result["findings"].append({
                            "type": "session_in_url_accepted",
                            "parameter": param,
                            "severity": "Critical",
                            "description": f"Session ID accepted via URL parameter '{param}' - enables session fixation",
                        })
                        result["vulnerable"] = True
                        result["details"]["session_accepted_in_url"] = True
                        self._print(f"    [!!!] Session accepted via URL param '{param}'!", RED)
                        break
            result["details"]["tests_run"] += 1
        except Exception as e:
            result["findings"].append({"type": "test_error", "test": "url_session", "error": str(e)})

        # Test 3: Cookie injection
        self._print(f"  [*] Test 3: Cookie injection test", CYAN)
        try:
            # Send request with injected session cookie
            injected_cookies = {"session": "injected_test_value", "sid": "injected_sid_123"}
            resp1 = self._send_request(url, cookies=injected_cookies)
            if resp1:
                resp_cookies = dict(resp1.cookies)
                # Check if server reflects our injected cookie
                for name, value in injected_cookies.items():
                    if name in resp_cookies and resp_cookies[name] == value:
                        result["findings"].append({
                            "type": "cookie_injection_accepted",
                            "cookie_name": name,
                            "severity": "High",
                            "description": f"Server accepted injected cookie '{name}' without validation",
                        })
                        result["vulnerable"] = True
                        self._print(f"    [!] Injected cookie '{name}' accepted!", RED)
            result["details"]["tests_run"] += 1
        except Exception as e:
            result["findings"].append({"type": "test_error", "test": "cookie_injection", "error": str(e)})

        # Test 4: Missing SameSite attribute check
        self._print(f"  [*] Test 4: SameSite attribute analysis", CYAN)
        try:
            resp = self._send_request(url)
            if resp:
                for cookie_header in resp.headers.get('Set-Cookie', '').split(','):
                    if not cookie_header.strip():
                        continue
                    if 'samesite' not in cookie_header.lower():
                        # Extract cookie name
                        name = cookie_header.split('=')[0].strip() if '=' in cookie_header else 'unknown'
                        session_kws = ['session', 'sid', 'token', 'auth', 'csrf']
                        if any(kw in name.lower() for kw in session_kws):
                            result["findings"].append({
                                "type": "missing_samesite",
                                "cookie_name": name,
                                "severity": "Medium",
                                "description": f"Session cookie '{name}' missing SameSite attribute",
                            })
                            result["vulnerable"] = True
                            self._print(f"    [!] Cookie '{name}' missing SameSite", YELLOW)
            result["details"]["tests_run"] += 1
        except Exception as e:
            result["findings"].append({"type": "test_error", "test": "samesite", "error": str(e)})

        # Summary
        result["details"]["tests_failed"] = len([f for f in result["findings"] if f.get("type") != "test_error"])

        if result["vulnerable"]:
            self._print(f"\n[!] SESSION FIXATION VULNERABILITIES FOUND: {result['details']['tests_failed']}", RED)
        else:
            self._print(f"[+] No session fixation vulnerabilities detected", GREEN)

        return result

    # ========================================================================
    # JWT TOKEN ANALYSIS (complementary)
    # ========================================================================

    def analyze_jwt_session(self, token):
        """Analyze JWT token used as session token (complementary to jwt_engine.py)

        Focuses on session-specific aspects rather than full JWT attack vectors.
        """
        self._print(f"[*] Analyzing JWT session token...", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "header": None,
                "payload": None,
                "session_issues": [],
            },
            "scan_type": "jwt_session_analysis",
        }

        try:
            parts = token.strip().split('.')
            if len(parts) != 3:
                result["findings"].append({"type": "invalid_jwt", "error": "Not a valid JWT token"})
                return result

            # Decode header
            h_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(h_b64))
            result["details"]["header"] = header

            # Decode payload
            p_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(p_b64))
            result["details"]["payload"] = payload

            # Session-specific checks
            # Check 1: alg:none
            if header.get('alg', '').lower() == 'none':
                result["findings"].append({
                    "type": "jwt_alg_none",
                    "severity": "Critical",
                    "description": "JWT uses 'none' algorithm - no signature verification",
                })
                result["vulnerable"] = True

            # Check 2: Missing expiration
            if 'exp' not in payload:
                result["findings"].append({
                    "type": "jwt_no_expiration",
                    "severity": "High",
                    "description": "JWT has no expiration claim - token valid forever",
                })
                result["vulnerable"] = True

            # Check 3: Long-lived token
            if 'exp' in payload and isinstance(payload['exp'], (int, float)):
                hours_valid = (payload['exp'] - time.time()) / 3600
                if hours_valid > 720:  # > 30 days
                    result["findings"].append({
                        "type": "jwt_long_lived",
                        "severity": "Medium",
                        "hours_valid": round(hours_valid, 1),
                        "description": f"JWT valid for {hours_valid:.0f} hours (> 30 days)",
                    })

            # Check 4: Sensitive data in payload
            sensitive_fields = ['password', 'secret', 'ssn', 'credit_card', 'api_key']
            for field in sensitive_fields:
                if field in str(payload).lower():
                    result["findings"].append({
                        "type": "jwt_sensitive_data",
                        "severity": "High",
                        "field": field,
                        "description": f"Sensitive data '{field}' found in JWT payload",
                    })
                    result["vulnerable"] = True

            # Check 5: Weak algorithm
            weak_algs = ['HS256', 'none', 'HS384']
            if header.get('alg') == 'HS256':
                result["findings"].append({
                    "type": "jwt_hmac_algorithm",
                    "severity": "Low",
                    "description": "JWT uses HMAC-SHA256 - vulnerable to brute force if weak key",
                })

            # Check 6: Not before (nbf) in the past
            if 'nbf' in payload and isinstance(payload['nbf'], (int, float)):
                if payload['nbf'] > time.time():
                    result["findings"].append({
                        "type": "jwt_future_nbf",
                        "severity": "Low",
                        "description": "JWT 'not before' is in the future",
                    })

            self._print(f"[+] JWT session analysis complete: {len(result['findings'])} issues found", 
                       RED if result["vulnerable"] else GREEN)

        except Exception as e:
            result["findings"].append({"type": "analysis_error", "error": str(e)})

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for Session Security Engine

        Args:
            target: Target URL or cookie value
            scan_type: Type of scan to run
                - 'flask_decode': Decode Flask session cookie
                - 'flask_encode': Encode Flask session cookie
                - 'flask_bruteforce': Brute-force Flask secret key
                - 'django': Analyze Django session
                - 'express': Analyze Express.js session
                - 'laravel': Analyze Laravel session
                - 'cookie_security': Check cookie security flags
                - 'session_fixation': Test session fixation
                - 'jwt_session': Analyze JWT session token
                - 'full': Run all applicable scans
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  SESSION SECURITY ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: Flask-Unsign + Session Security Techniques{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        overall_result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "scan_type": scan_type,
                "scans_run": [],
                "summary": {},
            },
            "scan_type": f"session_security_{scan_type}",
        }

        cookie_value = kwargs.get('cookie_value', target)
        secret_key = kwargs.get('secret_key', None)
        wordlist = kwargs.get('wordlist', None)

        if scan_type == 'flask_decode' or scan_type == 'full':
            self._print(f"\n{BOLD}[*] Flask Session Decode{RESET}", CYAN)
            r = self.decode_flask_session(cookie_value)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("flask_decode")
            overall_result["details"]["summary"]["flask_decode"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type == 'flask_bruteforce' or scan_type == 'full':
            self._print(f"\n{BOLD}[*] Flask Secret Key Brute-force{RESET}", MAGENTA)
            r = self.bruteforce_flask_key(cookie_value, wordlist)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("flask_bruteforce")
            overall_result["details"]["summary"]["flask_bruteforce"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if (scan_type in ['django', 'full']) and cookie_value:
            self._print(f"\n{BOLD}[*] Django Session Analysis{RESET}", CYAN)
            r = self.analyze_django_session(cookie_value)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("django")
            overall_result["details"]["summary"]["django"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if (scan_type in ['express', 'full']) and cookie_value:
            self._print(f"\n{BOLD}[*] Express.js Session Analysis{RESET}", CYAN)
            r = self.analyze_express_session(cookie_value)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("express")
            overall_result["details"]["summary"]["express"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if (scan_type in ['laravel', 'full']) and cookie_value:
            self._print(f"\n{BOLD}[*] Laravel Session Analysis{RESET}", CYAN)
            r = self.analyze_laravel_session(cookie_value)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("laravel")
            overall_result["details"]["summary"]["laravel"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type in ['cookie_security', 'full']:
            self._print(f"\n{BOLD}[*] Cookie Security Analysis{RESET}", CYAN)
            url = target if target.startswith('http') else f"https://{target}"
            r = self.check_cookie_security(url)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("cookie_security")
            overall_result["details"]["summary"]["cookie_security"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type in ['session_fixation', 'full']:
            self._print(f"\n{BOLD}[*] Session Fixation Test{RESET}", MAGENTA)
            url = target if target.startswith('http') else f"https://{target}"
            r = self.test_session_fixation(url)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("session_fixation")
            overall_result["details"]["summary"]["session_fixation"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type in ['jwt_session', 'full'] and cookie_value:
            self._print(f"\n{BOLD}[*] JWT Session Analysis{RESET}", CYAN)
            r = self.analyze_jwt_session(cookie_value)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("jwt_session")
            overall_result["details"]["summary"]["jwt_session"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type == 'flask_encode' and secret_key:
            self._print(f"\n{BOLD}[*] Flask Session Encode{RESET}", CYAN)
            data = kwargs.get('data', {"user": "admin", "authenticated": True})
            r = self.encode_flask_session(data, secret_key)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("flask_encode")
            overall_result["details"]["summary"]["flask_encode"] = r

        # Final summary
        total_findings = len(overall_result["findings"])
        critical = len([f for f in overall_result["findings"] if f.get("severity") == "Critical"])
        high = len([f for f in overall_result["findings"] if f.get("severity") == "High"])

        self._print(f"\n{BOLD}{'═'*50}{RESET}", CYAN)
        self._print(f"{BOLD}  SESSION SECURITY SCAN COMPLETE{RESET}", CYAN)
        self._print(f"  Scans run: {len(overall_result['details']['scans_run'])}", CYAN)
        self._print(f"  Total findings: {total_findings}", YELLOW)
        if critical:
            self._print(f"  Critical: {critical}", RED)
        if high:
            self._print(f"  High: {high}", RED)
        self._print(f"{BOLD}{'═'*50}{RESET}", CYAN)

        return overall_result


# ============================================================================
# MODULE-LEVEL run() FUNCTION (for ZYLON integration)
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = SessionSecurityEngine(target_url=target if target.startswith('http') else f"https://{target}")
    return engine.run(target, scan_type=scan_type, **kwargs)
