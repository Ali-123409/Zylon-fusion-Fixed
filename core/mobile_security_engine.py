#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Mobile Security Engine
==============================================
Fused from: Frida-iOS-Hook
           + Frida-Interception-and-Unpinning
           + DH-HackBar
           + Custom Zylon Techniques
Capabilities:
  - Android APK basic analysis (manifest parsing)
  - SSL pinning bypass techniques documentation
  - Mobile API security testing
  - Certificate pinning detection
  - Deep link testing
  - Android intent fuzzing
  - Mobile app traffic interception setup
  - API endpoint discovery for mobile apps
  - JWT/session testing for mobile APIs
  - WebView vulnerability detection
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import re
import json
import time
import hashlib
import threading
import random
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS,
    API_ENDPOINTS
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
# MOBILE SECURITY CONSTANTS
# ============================================================================

# Common Android deep link schemes
DEEP_LINK_SCHEMES = [
    "app://", "android-app://", "intent://",
    "market://", "play.google.com://",
    "fb://", "twitter://", "instagram://",
    "whatsapp://", "tel://", "sms://",
    "mailto://", "geo://", "maps://",
]

# Common mobile API paths
MOBILE_API_PATHS = [
    "/api/mobile/", "/api/v1/mobile/", "/api/v2/mobile/",
    "/mobile/api/", "/m/api/", "/mapi/",
    "/api/app/", "/api/native/", "/api/android/", "/api/ios/",
    "/api/v1/user/", "/api/v1/auth/",
    "/api/v1/account/", "/api/v1/profile/",
    "/api/v1/device/", "/api/v1/push/",
    "/api/v1/upload/", "/api/v1/media/",
    "/api/v1/payment/", "/api/v1/order/",
    "/api/v1/social/", "/api/v1/chat/",
    "/api/v1/search/", "/api/v1/location/",
    "/api/v2/user/", "/api/v2/auth/",
    "/api/auth/mobile/", "/api/auth/app/",
    "/api/token/", "/api/refresh/",
    "/api/register/", "/api/login/",
    "/api/verify/", "/api/otp/",
    "/api/device/register/", "/api/device/token/",
    "/api/push/register/", "/api/push/test/",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/apple-app-site-association",
    "/assetlinks.json",
]

# SSL pinning bypass techniques documentation
SSL_PINNING_BYPASS_TECHNIQUES = [
    {
        "name": "Frida SSL Unpinning",
        "tool": "frida",
        "description": "Universal SSL unpinning script for Android/iOS using Frida",
        "command": "frida -U -f com.target.app -l ssl_unpinning.js --no-pause",
        "requirements": "Frida, rooted device or frida-gadget",
        "platform": "Android/iOS",
    },
    {
        "name": "Objection SSL Disable",
        "tool": "objection",
        "description": "Disable SSL pinning using Objection (Frida-based)",
        "command": "objection -g com.target.app explore --startup-command 'android sslpinning disable'",
        "requirements": "Objection, Frida",
        "platform": "Android/iOS",
    },
    {
        "name": "XPosed/LSPosed JustTrustMe",
        "tool": "xposed",
        "description": "XPosed module to bypass SSL pinning in Android apps",
        "command": "Install JustTrustMe module via LSPosed/XPosed framework",
        "requirements": "Rooted Android, LSPosed/XPosed framework",
        "platform": "Android",
    },
    {
        "name": "SSL Kill Switch 2 (iOS)",
        "tool": "cydia",
        "description": "iOS tweak to disable SSL certificate validation",
        "command": "Install via Cydia on jailbroken iOS device",
        "requirements": "Jailbroken iOS, Cydia",
        "platform": "iOS",
    },
    {
        "name": "mitmproxy + Transparent Proxy",
        "tool": "mitmproxy",
        "description": "Set up transparent proxy with CA certificate installed on device",
        "command": "mitmproxy --mode transparent --set block_global=false",
        "requirements": "mitmproxy, CA cert installed on device",
        "platform": "Android/iOS",
    },
    {
        "name": "Burp Suite + CA Certificate",
        "tool": "burp",
        "description": "Configure Burp Suite proxy with CA cert on mobile device",
        "command": "Export Burp CA cert -> Install on device -> Configure proxy",
        "requirements": "Burp Suite, device proxy configuration",
        "platform": "Android/iOS",
    },
    {
        "name": "APK Patching (re-sign)",
        "tool": "apktool",
        "description": "Decompile APK, modify network_security_config.xml, re-sign",
        "command": "apktool d app.apk -> Edit network_security_config.xml -> apktool b -> jarsigner",
        "requirements": "apktool, jarsigner, zipalign",
        "platform": "Android",
    },
    {
        "name": "Android Emulator Proxy",
        "tool": "emulator",
        "description": "Configure Android emulator with proxy and CA cert",
        "command": "emulator -avd <name> -http-proxy http://127.0.0.1:8080",
        "requirements": "Android emulator, proxy tool",
        "platform": "Android",
    },
]

# Android intent action patterns for fuzzing
INTENT_ACTIONS = [
    "android.intent.action.VIEW",
    "android.intent.action.EDIT",
    "android.intent.action.PICK",
    "android.intent.action.GET_CONTENT",
    "android.intent.action.SEND",
    "android.intent.action.SENDTO",
    "android.intent.action.SEARCH",
    "android.intent.action.WEB_SEARCH",
    "android.intent.action.DIAL",
    "android.intent.action.CALL",
    "android.intent.action.INSTALL_PACKAGE",
    "android.intent.action.UNINSTALL_PACKAGE",
    "android.intent.action.MAIN",
    "android.settings.APPLICATION_DETAILS_SETTINGS",
]

# WebView vulnerability patterns
WEBVIEW_VULN_PATTERNS = [
    {
        "pattern": r"setJavaScriptEnabled\s*\(\s*true\s*\)",
        "vuln": "JavaScript enabled in WebView",
        "severity": "Medium",
        "description": "JavaScript execution enabled. Check for JS interface exposure.",
    },
    {
        "pattern": r"addJavascriptInterface\s*\(",
        "vuln": "JavaScript interface exposed",
        "severity": "High",
        "description": "Java objects exposed to JavaScript via addJavascriptInterface. "
                      "Pre-API 17 allows RCE via reflection.",
    },
    {
        "pattern": r"setAllowFileAccess\s*\(\s*true\s*\)",
        "vuln": "File access enabled in WebView",
        "severity": "High",
        "description": "WebView can access local files. May allow file theft via file:// URLs.",
    },
    {
        "pattern": r"setAllowFileAccessFromFileURLs\s*\(\s*true\s*\)",
        "vuln": "File access from file URLs enabled",
        "severity": "Critical",
        "description": "JavaScript in file:// context can access other local files.",
    },
    {
        "pattern": r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)",
        "vuln": "Universal access from file URLs enabled",
        "severity": "Critical",
        "description": "JavaScript in file:// context can access any origin including http/https.",
    },
    {
        "pattern": r"setDomStorageEnabled\s*\(\s*true\s*\)",
        "vuln": "DOM storage enabled",
        "severity": "Low",
        "description": "DOM storage enabled. Check for sensitive data storage in localStorage.",
    },
    {
        "pattern": r"loadUrl\s*\(\s*[\"']file://",
        "vuln": "Loading local file in WebView",
        "severity": "Medium",
        "description": "WebView loads local file. May be exploitable if content is controllable.",
    },
    {
        "pattern": r"onReceivedSslError\s*\([^)]*\)\s*\{[^}]*handler\.proceed\s*\(",
        "vuln": "SSL error ignored",
        "severity": "High",
        "description": "SSL certificate errors are ignored. Allows MITM attacks.",
    },
    {
        "pattern": r"setMixedContentMode\s*\(\s*0\s*\)|MIXED_CONTENT_ALWAYS_ALLOW",
        "vuln": "Mixed content allowed",
        "severity": "Medium",
        "description": "Mixed content (HTTP in HTTPS) allowed in WebView.",
    },
    {
        "pattern": r"setSavePassword\s*\(\s*true\s*\)",
        "vuln": "Password saving enabled",
        "severity": "Medium",
        "description": "WebView password saving enabled. Credentials may be stored insecurely.",
    },
]

# JWT/session test patterns for mobile APIs
MOBILE_JWT_TESTS = [
    {
        "name": "JWT alg:none bypass",
        "test": "Modify JWT header to use 'none' algorithm",
        "payload": '{"alg":"none","typ":"JWT"}.{"sub":"admin","iat":1516239022}.',
        "severity": "Critical",
    },
    {
        "name": "JWT RS256->HS256 confusion",
        "test": "Switch algorithm from RS256 to HS256 with public key",
        "payload": "Use public key as HMAC secret",
        "severity": "Critical",
    },
    {
        "name": "JWT kid injection",
        "test": "Inject SQL/path traversal into kid header",
        "payload": '{"alg":"HS256","kid":"../../dev/null"}',
        "severity": "High",
    },
    {
        "name": "JWT claim manipulation",
        "test": "Modify role/user claims in JWT payload",
        "payload": "Change 'role':'user' to 'role':'admin'",
        "severity": "High",
    },
    {
        "name": "Session fixation",
        "test": "Reuse session token across auth boundaries",
        "payload": "Set pre-auth session cookie and verify post-auth",
        "severity": "Medium",
    },
    {
        "name": "Token not invalidated on logout",
        "test": "Use token after logout",
        "payload": "Capture token -> logout -> reuse token",
        "severity": "Medium",
    },
]


class MobileSecurityEngine:
    """Mobile Security Engine - Fused from Frida-iOS-Hook + Frida-Interception + DH-HackBar + Custom"""

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

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _make_request(self, url, method='GET', headers=None, data=None, **kwargs):
        """Make HTTP request with error handling"""
        try:
            resp = self.session.request(
                method, url, headers=headers or {}, data=data,
                timeout=self.timeout, verify=False,
                allow_redirects=kwargs.get('allow_redirects', True),
                **{k: v for k, v in kwargs.items() if k != 'allow_redirects'}
            )
            return resp
        except Exception:
            return None

    # ========================================================================
    # APK METADATA ANALYSIS
    # ========================================================================

    def analyze_apk_metadata(self, apk_path):
        """Analyze APK basic metadata (manifest parsing)

        Args:
            apk_path: Path to APK file

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  APK Metadata Analysis{RESET}", CYAN)
        self._print(f"  [*] APK: {apk_path}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "apk_path": apk_path,
                "package_name": "",
                "version_name": "",
                "version_code": "",
                "min_sdk": "",
                "target_sdk": "",
                "permissions": [],
                "activities": [],
                "services": [],
                "receivers": [],
                "providers": [],
                "deep_links": [],
                "exported_components": [],
                "intent_filters": [],
                "network_security_config": "",
                "debuggable": False,
                "allow_backup": False,
            },
            "scan_type": "apk_metadata",
        }

        if not os.path.exists(apk_path):
            self._print(f"  [!] APK file not found: {apk_path}", RED)
            result["findings"].append({
                "type": "error",
                "description": f"APK file not found: {apk_path}",
            })
            return result

        # APK is a ZIP file - extract and parse AndroidManifest.xml
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                # List files in APK
                apk_files = zf.namelist()
                self._print(f"  [*] APK contains {len(apk_files)} files", CYAN)

                # Try to parse AndroidManifest.xml
                # Note: APK manifests are binary XML, we do basic extraction
                if 'AndroidManifest.xml' in apk_files:
                    try:
                        manifest_data = zf.read('AndroidManifest.xml')
                        # Binary XML parsing - extract readable strings
                        manifest_strings = self._extract_binary_xml_strings(manifest_data)
                        self._parse_manifest_strings(manifest_strings, result)
                    except Exception as e:
                        self._print(f"  [!] Manifest parsing limited: {str(e)[:80]}", YELLOW)
                        # Fallback: extract strings from binary
                        self._extract_apk_strings(zf, apk_files, result)

                # Check for network_security_config.xml
                for f in apk_files:
                    if 'network_security_config' in f.lower():
                        try:
                            nsc_data = zf.read(f)
                            nsc_text = nsc_data.decode('utf-8', errors='ignore')
                            result["details"]["network_security_config"] = f
                            if 'cleartextTrafficPermitted="true"' in nsc_text:
                                result["vulnerable"] = True
                                result["findings"].append({
                                    "type": "cleartext_traffic",
                                    "severity": "High",
                                    "description": "Network security config allows cleartext traffic! "
                                                  "Data can be intercepted over HTTP.",
                                })
                                self._print(f"  [!!!] Cleartext traffic permitted!", RED)
                        except Exception:
                            pass

                # Check for debug/release builds
                for f in apk_files:
                    if f.endswith('.so') or f.endswith('.dex'):
                        pass  # Binary files
                    elif f.endswith('.properties') or f.endswith('.xml'):
                        try:
                            content = zf.read(f).decode('utf-8', errors='ignore')
                            if 'debuggable' in content.lower():
                                result["details"]["debuggable"] = True
                                result["vulnerable"] = True
                                result["findings"].append({
                                    "type": "debuggable_app",
                                    "severity": "High",
                                    "description": "App appears to be debuggable! "
                                                  "Allows debugging and code injection.",
                                })
                                self._print(f"  [!!!] Debuggable app detected!", RED)
                        except Exception:
                            pass

                # Extract deep links from all XML files
                self._extract_deep_links_from_apk(zf, apk_files, result)

                # WebView vulnerability scan in code files
                self._scan_apk_webview_vulns(zf, apk_files, result)

        except zipfile.BadZipFile:
            self._print(f"  [!] Not a valid APK/ZIP file: {apk_path}", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Not a valid APK file: {apk_path}",
            })
        except Exception as e:
            self._print(f"  [!] APK analysis error: {str(e)[:80]}", RED)
            result["findings"].append({
                "type": "error",
                "description": f"APK analysis error: {str(e)[:100]}",
            })

        # Check for dangerous permissions
        dangerous_perms = [
            'READ_CONTACTS', 'WRITE_CONTACTS', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
            'READ_PHONE_STATE', 'CALL_PHONE', 'READ_SMS', 'SEND_SMS',
            'RECEIVE_SMS', 'READ_CALENDAR', 'WRITE_CALENDAR',
            'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
            'CAMERA', 'RECORD_AUDIO', 'READ_EXTERNAL_STORAGE',
            'WRITE_EXTERNAL_STORAGE', 'MANAGE_EXTERNAL_STORAGE',
            'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES',
        ]

        for perm in result["details"]["permissions"]:
            perm_upper = perm.upper()
            for danger_perm in dangerous_perms:
                if danger_perm in perm_upper:
                    result["findings"].append({
                        "type": "dangerous_permission",
                        "severity": "Medium",
                        "description": f"Dangerous permission requested: {perm}",
                    })
                    self._print(f"  [!] Dangerous permission: {perm}", YELLOW)
                    break

        # Check for exported components without permission
        for comp in result["details"]["exported_components"]:
            result["findings"].append({
                "type": "exported_component",
                "severity": "Medium",
                "description": f"Exported component: {comp}. May be accessible to other apps.",
            })
            self._print(f"  [!] Exported component: {comp}", YELLOW)

        # Summary
        self._print(f"  [*] Package: {result['details']['package_name'] or 'N/A'}", CYAN)
        self._print(f"  [*] Permissions: {len(result['details']['permissions'])}", CYAN)
        self._print(f"  [*] Deep links: {len(result['details']['deep_links'])}", CYAN)
        self._print(f"  [*] Exported components: {len(result['details']['exported_components'])}", CYAN)

        return result

    def _extract_binary_xml_strings(self, data):
        """Extract readable strings from binary XML data"""
        strings = []
        try:
            # Simple approach: extract ASCII-readable strings
            current_string = []
            for byte in data:
                if 32 <= byte <= 126:
                    current_string.append(chr(byte))
                else:
                    if len(current_string) >= 4:
                        strings.append(''.join(current_string))
                    current_string = []
            if len(current_string) >= 4:
                strings.append(''.join(current_string))
        except Exception:
            pass
        return strings

    def _parse_manifest_strings(self, strings, result):
        """Parse manifest strings for metadata"""
        for i, s in enumerate(strings):
            # Package name
            if s.startswith('com.') or s.startswith('org.') or s.startswith('io.'):
                if not result["details"]["package_name"]:
                    result["details"]["package_name"] = s

            # Permissions
            if 'permission' in s.lower() and '.' in s:
                if s not in result["details"]["permissions"]:
                    result["details"]["permissions"].append(s)

            # Activities
            if 'Activity' in s and '.' in s:
                if s not in result["details"]["activities"]:
                    result["details"]["activities"].append(s)

            # Deep link schemes
            if '://' in s and s not in result["details"]["deep_links"]:
                result["details"]["deep_links"].append(s)

            # Intent filters
            if 'android.intent.action' in s or 'android.intent.category' in s:
                if s not in result["details"]["intent_filters"]:
                    result["details"]["intent_filters"].append(s)

            # Version info
            if s.startswith('version'):
                try:
                    if i + 1 < len(strings):
                        result["details"]["version_name"] = strings[i + 1]
                except Exception:
                    pass

    def _extract_apk_strings(self, zf, apk_files, result):
        """Fallback: extract metadata strings from all files in APK"""
        for f in apk_files:
            if f.endswith('.xml') or f.endswith('.properties'):
                try:
                    content = zf.read(f).decode('utf-8', errors='ignore')
                    # Extract package names
                    packages = re.findall(r'(com\.[a-zA-Z0-9_.]+)', content)
                    for pkg in packages:
                        if not result["details"]["package_name"]:
                            result["details"]["package_name"] = pkg
                            break

                    # Extract permissions
                    perms = re.findall(r'(android\.permission\.\w+)', content)
                    for perm in perms:
                        if perm not in result["details"]["permissions"]:
                            result["details"]["permissions"].append(perm)

                    # Extract deep links
                    links = re.findall(r'(?:scheme|host|pathPrefix)\s*=\s*["\']([^"\']+)["\']', content)
                    for link in links:
                        if link not in result["details"]["deep_links"]:
                            result["details"]["deep_links"].append(link)

                    # Check for debuggable
                    if 'android:debuggable="true"' in content:
                        result["details"]["debuggable"] = True
                    if 'android:allowBackup="true"' in content:
                        result["details"]["allow_backup"] = True

                except Exception:
                    pass

    def _extract_deep_links_from_apk(self, zf, apk_files, result):
        """Extract deep link declarations from APK"""
        for f in apk_files:
            if f.endswith('.xml'):
                try:
                    content = zf.read(f).decode('utf-8', errors='ignore')
                    # Look for scheme declarations
                    schemes = re.findall(r'scheme\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
                    hosts = re.findall(r'host\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
                    paths = re.findall(r'pathPrefix\s*=\s*["\']([^"\']+)["\']', content, re.IGNORECASE)

                    for scheme in schemes:
                        for host in hosts:
                            deep_link = f"{scheme}://{host}"
                            if paths:
                                for path in paths:
                                    full_link = f"{deep_link}{path}"
                                    if full_link not in result["details"]["deep_links"]:
                                        result["details"]["deep_links"].append(full_link)
                            elif deep_link not in result["details"]["deep_links"]:
                                result["details"]["deep_links"].append(deep_link)
                except Exception:
                    pass

    def _scan_apk_webview_vulns(self, zf, apk_files, result):
        """Scan APK for WebView vulnerabilities"""
        for f in apk_files:
            if f.endswith('.xml') or f.endswith('.java') or f.endswith('.kt') or f.endswith('.smali'):
                try:
                    content = zf.read(f).decode('utf-8', errors='ignore')
                    for pattern_info in WEBVIEW_VULN_PATTERNS:
                        if re.search(pattern_info["pattern"], content):
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": "webview_vuln",
                                "severity": pattern_info["severity"],
                                "description": f"WebView vulnerability in {f}: {pattern_info['vuln']}. "
                                              f"{pattern_info['description']}",
                                "file": f,
                                "vuln": pattern_info["vuln"],
                            })
                            sev_color = RED if pattern_info["severity"] == "Critical" else (
                                MAGENTA if pattern_info["severity"] == "High" else YELLOW
                            )
                            self._print(f"  [!] WebView vuln in {f}: {pattern_info['vuln']}", sev_color)
                except Exception:
                    pass

    # ========================================================================
    # SSL PINNING DETECTION
    # ========================================================================

    def detect_ssl_pinning(self, url):
        """Detect SSL pinning on a target

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  SSL Pinning Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "ssl_pinning_detected": False,
                "pinning_type": "",
                "certificate_info": {},
                "hsts_enabled": False,
                "tls_version": "",
                "bypass_techniques": [],
            },
            "scan_type": "ssl_pinning_detection",
        }

        # Phase 1: Check HTTPS and TLS
        self._print(f"  [*] Phase 1: TLS/SSL Analysis...", CYAN)
        try:
            resp = self._make_request(url)
            if resp:
                # Check HSTS
                hsts = resp.headers.get('Strict-Transport-Security', '')
                if hsts:
                    result["details"]["hsts_enabled"] = True
                    self._print(f"  [+] HSTS enabled: {hsts[:50]}", GREEN)
                else:
                    result["findings"].append({
                        "type": "missing_hsts",
                        "severity": "Medium",
                        "description": "HSTS header missing. Vulnerable to SSL stripping.",
                    })
                    self._print(f"  [!] HSTS header missing", YELLOW)

                # Check certificate via headers
                server = resp.headers.get('Server', '')
                result["details"]["certificate_info"]["server"] = server

                # Check for pinning headers
                pkp = resp.headers.get('Public-Key-Pins', '')
                pkp_report = resp.headers.get('Public-Key-Pins-Report-Only', '')
                if pkp:
                    result["details"]["ssl_pinning_detected"] = True
                    result["details"]["pinning_type"] = "HTTP Public Key Pinning (HPKP)"
                    self._print(f"  [+] HPKP header detected (deprecated)", GREEN)
                if pkp_report:
                    result["details"]["ssl_pinning_detected"] = True
                    self._print(f"  [+] HPKP-Report-Only header detected", GREEN)

                # Check Expect-CT
                expect_ct = resp.headers.get('Expect-CT', '')
                if expect_ct:
                    result["details"]["certificate_info"]["expect_ct"] = True
                    self._print(f"  [+] Expect-CT header present", GREEN)

        except requests.exceptions.SSLError as e:
            result["findings"].append({
                "type": "ssl_error",
                "severity": "Info",
                "description": f"SSL error connecting: {str(e)[:100]}. "
                              f"Server may have strict TLS requirements (possible pinning).",
            })
            self._print(f"  [!] SSL connection error - server may enforce strict TLS", YELLOW)
        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"Connection error: {str(e)[:80]}",
            })

        # Phase 2: Check for common mobile API indicators
        self._print(f"  [*] Phase 2: Mobile API indicators...", CYAN)
        mobile_headers = {
            'User-Agent': 'okhttp/4.9.3',  # Common Android HTTP client
            'X-Mobile-App': 'android',
            'X-App-Version': '1.0.0',
            'X-Device-ID': 'test-device-123',
        }
        try:
            mobile_resp = self._make_request(url, headers=mobile_headers)
            if mobile_resp:
                # Compare with normal response
                normal_resp = self._make_request(url)
                if normal_resp:
                    if len(mobile_resp.content) != len(normal_resp.content):
                        self._print(f"  [!] Different response for mobile User-Agent", YELLOW)
                        result["findings"].append({
                            "type": "mobile_ua_differentiation",
                            "severity": "Low",
                            "description": "Server returns different content for mobile User-Agent",
                        })
        except Exception:
            pass

        # Phase 3: Document bypass techniques
        self._print(f"  [*] Phase 3: SSL Pinning Bypass Techniques...", CYAN)
        applicable_techniques = []

        for tech in SSL_PINNING_BYPASS_TECHNIQUES:
            applicable_techniques.append(tech)
            self._print(f"  [*] {tech['name']} ({tech['platform']})", DIM + CYAN)

        result["details"]["bypass_techniques"] = applicable_techniques

        result["findings"].append({
            "type": "ssl_pinning_info",
            "severity": "Info",
            "description": f"SSL pinning detection complete. "
                          f"Pinning detected: {result['details']['ssl_pinning_detected']}. "
                          f"HSTS: {result['details']['hsts_enabled']}. "
                          f"Bypass techniques documented: {len(applicable_techniques)}",
        })

        return result

    # ========================================================================
    # DEEP LINK TESTING
    # ========================================================================

    def test_deep_links(self, package_name):
        """Test deep link security for a mobile app

        Args:
            package_name: Android package name (e.g., com.example.app)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Deep Link Testing{RESET}", CYAN)
        self._print(f"  [*] Package: {package_name}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "package_name": package_name,
                "deep_links_found": [],
                "assetlinks": None,
                "aasa": None,
                "test_results": [],
            },
            "scan_type": "deep_link_testing",
        }

        # Phase 1: Check Android App Links (assetlinks.json)
        self._print(f"  [*] Phase 1: Checking Android App Links...", CYAN)
        # Try to find the domain from package name
        parts = package_name.split('.')
        if len(parts) >= 2:
            # Try common domain patterns from package name
            possible_domains = []
            if parts[0] in ('com', 'io', 'org', 'net', 'co'):
                domain = '.'.join(parts[1:3])
                possible_domains.append(domain)
                possible_domains.append(f"www.{domain}")

            for domain in possible_domains:
                assetlinks_url = f"https://{domain}/.well-known/assetlinks.json"
                try:
                    resp = self._make_request(assetlinks_url)
                    if resp and resp.status_code == 200:
                        try:
                            assetlinks = json.loads(resp.text)
                            result["details"]["assetlinks"] = {
                                "domain": domain,
                                "content": assetlinks,
                            }
                            self._print(f"  [+] Asset links found: {domain}", GREEN)

                            # Check for wildcard targets
                            for entry in assetlinks if isinstance(assetlinks, list) else []:
                                target = entry.get('target', {})
                                if target.get('namespace') == 'android_app':
                                    pkg = target.get('package_name', '')
                                    sha256 = ''
                                    for field in entry.get('sha256_cert_fingerprints', []):
                                        sha256 = field
                                    if pkg == package_name:
                                        self._print(f"  [+] Verified app link for {pkg}", GREEN)
                                    else:
                                        self._print(f"  [!] Asset links has different package: {pkg}", YELLOW)
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass

        # Phase 2: Check iOS Universal Links (apple-app-site-association)
        self._print(f"  [*] Phase 2: Checking iOS Universal Links...", CYAN)
        for domain in possible_domains if len(parts) >= 2 else []:
            aasa_urls = [
                f"https://{domain}/.well-known/apple-app-site-association",
                f"https://{domain}/apple-app-site-association",
            ]
            for aasa_url in aasa_urls:
                try:
                    resp = self._make_request(aasa_url)
                    if resp and resp.status_code == 200:
                        try:
                            aasa = json.loads(resp.text)
                            result["details"]["aasa"] = {
                                "domain": domain,
                                "content": aasa,
                            }
                            self._print(f"  [+] AASA found: {domain}", GREEN)
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass

        # Phase 3: Test common deep link patterns
        self._print(f"  [*] Phase 3: Testing deep link patterns...", CYAN)
        test_deep_links = [
            f"intent://#Intent;package={package_name};end",
            f"intent://#Intent;package={package_name};action=android.intent.action.VIEW;end",
            f"intent://example.com#Intent;package={package_name};scheme=https;end",
            f"android-app://{package_name}/https/example.com",
        ]

        # Also test common scheme patterns
        app_name = parts[-1] if parts else 'app'
        test_schemes = [
            f"{app_name}://",
            f"{app_name}://deep-link",
            f"{app_name}://open",
            f"{app_name}://home",
            f"{app_name}://login",
            f"{app_name}://reset-password",
            f"{app_name}://user/profile",
        ]

        for link in test_deep_links + test_schemes:
            result["details"]["deep_links_found"].append(link)
            self._print(f"  [*] Test: {link[:60]}", DIM + CYAN)

        # Security analysis
        self._print(f"  [*] Phase 4: Deep link security analysis...", CYAN)
        security_issues = []

        # Check if deep links can be invoked by any app
        if not result["details"]["assetlinks"]:
            security_issues.append("No verified App Links (assetlinks.json) - deep links can be hijacked")
            result["findings"].append({
                "type": "unverified_deep_links",
                "severity": "Medium",
                "description": "No verified Android App Links found. "
                              "Deep links can potentially be intercepted by malicious apps.",
            })

        # Test for sensitive deep link paths
        sensitive_paths = ['login', 'auth', 'reset-password', 'payment', 'transfer',
                          'admin', 'settings', 'debug', 'flag', 'config']
        for link in test_schemes:
            for sensitive in sensitive_paths:
                if sensitive in link.lower():
                    security_issues.append(f"Sensitive deep link path: {link}")
                    result["findings"].append({
                        "type": "sensitive_deep_link",
                        "severity": "Medium",
                        "description": f"Deep link with sensitive path: {link}. "
                                      f"May allow unauthorized access to sensitive functionality.",
                    })
                    self._print(f"  [!] Sensitive deep link: {link}", YELLOW)

        if security_issues:
            result["vulnerable"] = True
            self._print(f"  [!] {len(security_issues)} deep link security issue(s)", RED)
        else:
            self._print(f"  [-] No deep link security issues detected", GREEN)

        return result

    # ========================================================================
    # MOBILE API SECURITY
    # ========================================================================

    def test_mobile_api(self, base_url):
        """Test mobile API security

        Args:
            base_url: Base URL for API

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Mobile API Security Test{RESET}", CYAN)
        self._print(f"  [*] Target: {base_url}", CYAN)

        base_url = base_url if base_url.startswith('http') else f"https://{base_url}"
        base_url = base_url.rstrip('/')

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "base_url": base_url,
                "endpoints_discovered": [],
                "auth_tests": [],
                "rate_limit_tests": [],
                "session_tests": [],
                "total_endpoints_tested": 0,
            },
            "scan_type": "mobile_api_security",
        }

        # Phase 1: API Endpoint Discovery
        self._print(f"  [*] Phase 1: API Endpoint Discovery...", CYAN)
        all_paths = list(set(API_ENDPOINTS + MOBILE_API_PATHS))
        discovered_endpoints = []

        def check_endpoint(path):
            url = f"{base_url}{path}"
            try:
                resp = self._make_request(url, allow_redirects=False)
                if resp and resp.status_code not in (0, 404, 410, 502, 503):
                    return {
                        "path": path,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "content_type": resp.headers.get('Content-Type', ''),
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
            futures = {executor.submit(check_endpoint, p): p for p in all_paths}
            for future in as_completed(futures):
                ep = future.result()
                if ep:
                    discovered_endpoints.append(ep)
                    result["details"]["total_endpoints_tested"] += 1
                    self._print(f"  [+] {ep['path']} -> {ep['status_code']}", GREEN)

        result["details"]["endpoints_discovered"] = discovered_endpoints

        # Phase 2: Authentication testing
        self._print(f"  [*] Phase 2: Authentication Testing...", CYAN)
        auth_endpoints = [ep for ep in discovered_endpoints
                         if any(kw in ep['path'].lower() for kw in
                               ['auth', 'login', 'token', 'session', 'api/me', 'api/user'])]

        for ep in auth_endpoints:
            url = f"{base_url}{ep['path']}"
            # Test without auth
            try:
                resp = self._make_request(url)
                if resp and resp.status_code == 200:
                    # Check if sensitive data is returned without auth
                    try:
                        data = resp.json()
                        sensitive_keys = ['email', 'password', 'token', 'api_key', 'secret',
                                         'phone', 'address', 'ssn', 'credit_card']
                        found_sensitive = [k for k in sensitive_keys if k in json.dumps(data).lower()]
                        if found_sensitive:
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": "unauthenticated_access",
                                "severity": "Critical",
                                "description": f"Unauthenticated access to sensitive data at {ep['path']}. "
                                              f"Sensitive keys found: {found_sensitive}",
                            })
                            self._print(f"  [!!!] Unauthenticated sensitive data: {ep['path']}", RED)
                    except (json.JSONDecodeError, ValueError):
                        pass

                    result["details"]["auth_tests"].append({
                        "endpoint": ep['path'],
                        "status": "accessible_without_auth",
                        "status_code": resp.status_code,
                    })
                    self._print(f"  [!] Endpoint accessible without auth: {ep['path']}", YELLOW)
            except Exception:
                pass

        # Phase 3: JWT/Session Testing
        self._print(f"  [*] Phase 3: JWT/Session Testing...", CYAN)
        for ep in auth_endpoints:
            url = f"{base_url}{ep['path']}"
            # Test with modified JWT
            jwt_tests = [
                {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."},
                {"Authorization": "Bearer null"},
                {"Authorization": "Bearer undefined"},
                {"Authorization": "Bearer " + "A" * 50},
            ]

            for test_headers in jwt_tests:
                try:
                    resp = self._make_request(url, headers=test_headers)
                    if resp and resp.status_code == 200:
                        test_desc = list(test_headers.values())[0][:40]
                        result["details"]["session_tests"].append({
                            "endpoint": ep['path'],
                            "test": test_desc,
                            "status_code": resp.status_code,
                            "accepted": True,
                        })
                        self._print(f"  [!] Invalid JWT accepted at {ep['path']}", YELLOW)
                except Exception:
                    pass

        # Phase 4: Rate Limiting Test
        self._print(f"  [*] Phase 4: Rate Limiting Test...", CYAN)
        for ep in auth_endpoints[:3]:
            url = f"{base_url}{ep['path']}"
            statuses = []
            for i in range(10):
                try:
                    resp = self._make_request(url)
                    if resp:
                        statuses.append(resp.status_code)
                except Exception:
                    pass

            if statuses:
                rate_limited = any(s == 429 for s in statuses)
                result["details"]["rate_limit_tests"].append({
                    "endpoint": ep['path'],
                    "requests": len(statuses),
                    "rate_limited": rate_limited,
                    "last_status": statuses[-1],
                })
                if not rate_limited:
                    self._print(f"  [!] No rate limiting on {ep['path']}", YELLOW)
                    result["findings"].append({
                        "type": "no_rate_limiting",
                        "severity": "Medium",
                        "description": f"No rate limiting on {ep['path']}. "
                                      f"Vulnerable to brute force attacks.",
                    })

        # Phase 5: CORS Test for API
        self._print(f"  [*] Phase 5: CORS Test...", CYAN)
        cors_origins = [
            "https://evil.com",
            "null",
            f"https://attacker.{urlparse(base_url).hostname}",
        ]
        for ep in discovered_endpoints[:5]:
            url = f"{base_url}{ep['path']}"
            for origin in cors_origins:
                try:
                    resp = self._make_request(url, headers={"Origin": origin})
                    if resp:
                        acao = resp.headers.get('Access-Control-Allow-Origin', '')
                        if acao == origin or acao == '*':
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": "cors_misconfiguration",
                                "severity": "High",
                                "description": f"CORS misconfiguration on {ep['path']}. "
                                              f"Origin {origin} allowed: {acao}",
                            })
                            self._print(f"  [!!!] CORS misconfiguration: {ep['path']}", RED)
                except Exception:
                    pass

        if not result["vulnerable"]:
            self._print(f"  [-] No critical mobile API vulnerabilities detected", GREEN)

        return result

    # ========================================================================
    # WEBVIEW VULNERABILITY DETECTION
    # ========================================================================

    def detect_webview_vulns(self, url):
        """Detect WebView vulnerabilities in web content

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  WebView Vulnerability Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "js_interfaces": [],
                "deep_link_handlers": [],
                "custom_url_schemes": [],
                "script_injection_points": [],
                "postmessage_handlers": [],
                "mobile_meta_tags": [],
            },
            "scan_type": "webview_vuln_detection",
        }

        # Fetch page
        resp = self._make_request(url)
        if not resp:
            result["findings"].append({"type": "error", "description": f"Cannot connect to {url}"})
            return result

        html = resp.text

        # Phase 1: Check for mobile-specific meta tags
        self._print(f"  [*] Phase 1: Mobile meta tags...", CYAN)
        mobile_meta = re.findall(
            r'<meta[^>]+(apple-mobile-web-app|mobile-web-app-capable|viewport|format-detection)[^>]*>',
            html, re.IGNORECASE
        )
        if mobile_meta:
            result["details"]["mobile_meta_tags"] = mobile_meta
            self._print(f"  [+] Mobile meta tags found: {len(mobile_meta)}", GREEN)

        # Phase 2: Check for JavaScript bridge interfaces
        self._print(f"  [*] Phase 2: JavaScript bridge detection...", CYAN)
        js_bridge_patterns = [
            (r'window\.\w+Bridge', "JavaScript bridge object"),
            (r'window\.\w+Interface', "JavaScript interface object"),
            (r'postMessage\s*\(', "postMessage handler"),
            (r'addEventListener\s*\(\s*["\']message["\']', "Message event listener"),
            (r'ReactNativeWebView', "React Native WebView bridge"),
            (r'window\.webkit\.messageHandlers', "iOS WebView message handler"),
            (r'window\.Android', "Android JavaScript interface"),
            (r'\.prompt\s*\(\s*["\'].*?["\']', "WebView prompt() call"),
        ]

        for pattern, desc in js_bridge_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            if matches:
                self._print(f"  [!] {desc}: {matches[:3]}", YELLOW)
                result["details"]["js_interfaces"].append({
                    "pattern": pattern,
                    "description": desc,
                    "matches": matches[:5],
                })

        # Phase 3: Check for custom URL schemes
        self._print(f"  [*] Phase 3: Custom URL scheme detection...", CYAN)
        custom_schemes = re.findall(r'(?:href|src|action)\s*=\s*["\']([a-z][a-z0-9+.-]*):', html, re.IGNORECASE)
        known_schemes = {'http', 'https', 'mailto', 'tel', 'javascript', 'data', 'ftp', 'file'}
        for scheme in set(custom_schemes):
            if scheme.lower() not in known_schemes:
                result["details"]["custom_url_schemes"].append(scheme)
                self._print(f"  [!] Custom URL scheme: {scheme}://", YELLOW)

        # Phase 4: Check for script injection points via URL parameters
        self._print(f"  [*] Phase 4: Script injection point analysis...", CYAN)
        parsed = urlparse(url)
        params = parse_qs(parsed.query) if parsed.query else {}

        # Check if parameters are reflected
        for param_name, param_values in params.items():
            for value in param_values:
                if value in html:
                    # Parameter reflected - check context
                    injection_point = {
                        "parameter": param_name,
                        "value": value,
                        "reflected": True,
                    }

                    # Check if it's in a script context
                    script_contexts = re.findall(
                        rf'<script[^>]*>[^<]*{re.escape(value)}[^<]*</script>',
                        html, re.IGNORECASE | re.DOTALL
                    )
                    if script_contexts:
                        injection_point["context"] = "script"
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "script_injection",
                            "severity": "Critical",
                            "description": f"Parameter '{param_name}' reflected in script context. "
                                          f"Potential XSS in WebView.",
                        })
                        self._print(f"  [!!!] Script injection: {param_name}", RED)

                    # Check if in href/src context
                    attr_contexts = re.findall(
                        rf'(?:href|src|action)\s*=\s*["\'][^"\']*{re.escape(value)}[^"\']*["\']',
                        html, re.IGNORECASE
                    )
                    if attr_contexts:
                        injection_point["context"] = "attribute"
                        self._print(f"  [!] Parameter in attribute context: {param_name}", YELLOW)

                    result["details"]["script_injection_points"].append(injection_point)

        # Phase 5: Check for postMessage handlers (iframe communication)
        self._print(f"  [*] Phase 5: postMessage handler detection...", CYAN)
        postmsg_handlers = re.findall(
            r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(\w+)',
            html, re.IGNORECASE
        )
        if postmsg_handlers:
            result["details"]["postmessage_handlers"] = postmsg_handlers
            result["findings"].append({
                "type": "postmessage_handler",
                "severity": "Medium",
                "description": f"postMessage handlers detected: {postmsg_handlers}. "
                              f"Verify origin validation in message handlers.",
            })
            self._print(f"  [!] postMessage handlers: {postmsg_handlers}", YELLOW)

        # Phase 6: Check for deep link handling in JavaScript
        self._print(f"  [*] Phase 6: Deep link JS handlers...", CYAN)
        deeplink_patterns = re.findall(
            r'(?:window\.location|location\.href|navigate|openUrl|deepLink)\s*[=(]\s*["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        if deeplink_patterns:
            result["details"]["deep_link_handlers"] = deeplink_patterns[:10]
            self._print(f"  [!] Deep link handlers found: {len(deeplink_patterns)}", YELLOW)

        if not result["vulnerable"] and not result["findings"]:
            self._print(f"  [-] No critical WebView vulnerabilities detected", GREEN)

        return result

    # ========================================================================
    # CERTIFICATE PINNING TEST
    # ========================================================================

    def test_certificate_pinning(self, url):
        """Test certificate pinning effectiveness

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Certificate Pinning Test{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        url = url if url.startswith('http') else f"https://{url}"

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "certificate_valid": False,
                "certificate_info": {},
                "hsts_enabled": False,
                "hsts_max_age": 0,
                "hsts_includes_subdomains": False,
                "ct_required": False,
                "pinning_headers": [],
                "tls_config": {},
            },
            "scan_type": "certificate_pinning_test",
        }

        # Test 1: Certificate validation
        self._print(f"  [*] Test 1: Certificate validation...", CYAN)
        try:
            resp = self._make_request(url)
            if resp:
                result["details"]["certificate_valid"] = True
                self._print(f"  [+] Certificate is valid", GREEN)

                # Extract cert info from response headers
                result["details"]["certificate_info"] = {
                    "server": resp.headers.get('Server', ''),
                    "strict_transport_security": resp.headers.get('Strict-Transport-Security', ''),
                }

                # HSTS check
                hsts = resp.headers.get('Strict-Transport-Security', '')
                if hsts:
                    result["details"]["hsts_enabled"] = True
                    max_age_match = re.search(r'max-age=(\d+)', hsts)
                    if max_age_match:
                        result["details"]["hsts_max_age"] = int(max_age_match.group(1))
                    result["details"]["hsts_includes_subdomains"] = 'includesubdomains' in hsts.lower()
                    self._print(f"  [+] HSTS: max-age={result['details']['hsts_max_age']}, "
                                 f"includesSubDomains={result['details']['hsts_includes_subdomains']}", GREEN)
                else:
                    result["findings"].append({
                        "type": "no_hsts",
                        "severity": "Medium",
                        "description": "No HSTS header. Vulnerable to SSL stripping attacks "
                                      "on mobile devices.",
                    })
                    self._print(f"  [!] No HSTS - vulnerable to SSL stripping", YELLOW)

                # HPKP check (deprecated but still informative)
                pkp = resp.headers.get('Public-Key-Pins', '')
                if pkp:
                    result["details"]["pinning_headers"].append("Public-Key-Pins")
                    self._print(f"  [+] HPKP header present (deprecated)", GREEN)

                # Expect-CT
                expect_ct = resp.headers.get('Expect-CT', '')
                if expect_ct:
                    result["details"]["ct_required"] = True
                    self._print(f"  [+] Expect-CT present (Certificate Transparency)", GREEN)

        except requests.exceptions.SSLError:
            result["details"]["certificate_valid"] = False
            self._print(f"  [!] SSL error - certificate issues detected", YELLOW)
            result["findings"].append({
                "type": "ssl_error",
                "severity": "Low",
                "description": "SSL connection error. May indicate strict certificate validation.",
            })
        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"Connection error: {str(e)[:80]}",
            })
            return result

        # Test 2: Check for certificate transparency
        self._print(f"  [*] Test 2: Certificate Transparency check...", CYAN)
        hostname = urlparse(url).hostname
        if hostname:
            ct_url = f"https://crt.sh/?q={hostname}&output=json"
            try:
                ct_resp = self._make_request(ct_url, timeout=15)
                if ct_resp and ct_resp.status_code == 200:
                    try:
                        ct_data = json.loads(ct_resp.text)
                        cert_count = len(ct_data) if isinstance(ct_data, list) else 0
                        result["details"]["tls_config"]["ct_certs_found"] = cert_count
                        self._print(f"  [+] CT log entries: {cert_count}", GREEN)

                        # Check for unexpected certificates
                        issuer_count = {}
                        for cert in ct_data[:20] if isinstance(ct_data, list) else []:
                            issuer = cert.get('issuer_name', 'Unknown')
                            issuer_count[issuer] = issuer_count.get(issuer, 0) + 1

                        if len(issuer_count) > 1:
                            result["findings"].append({
                                "type": "multiple_cert_issuers",
                                "severity": "Medium",
                                "description": f"Multiple certificate issuers found in CT logs: "
                                              f"{list(issuer_count.keys())[:5]}. "
                                              f"Verify all certificates are authorized.",
                            })
                            self._print(f"  [!] Multiple certificate issuers in CT logs", YELLOW)
                    except (json.JSONDecodeError, ValueError):
                        pass
            except Exception:
                pass

        # Test 3: Mobile-specific certificate checks
        self._print(f"  [*] Test 3: Mobile-specific checks...", CYAN)

        # Check if server accepts connections with invalid SNI
        try:
            bad_sni_headers = {'Host': 'invalid.example.com'}
            resp = self._make_request(url, headers=bad_sni_headers)
            if resp and resp.status_code == 200:
                result["findings"].append({
                    "type": "sni_mismatch_accepted",
                    "severity": "Low",
                    "description": "Server accepts requests with mismatched Host header. "
                                  "Certificate pinning may not verify hostname properly.",
                })
                self._print(f"  [!] Server accepts mismatched SNI", YELLOW)
        except Exception:
            pass

        if not result["details"]["hsts_enabled"]:
            result["vulnerable"] = True

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='api', **kwargs):
        """Main entry point for Mobile Security Engine

        Args:
            target: Target URL, APK path, or package name
            scan_type: Type of scan
                - 'api': Mobile API security test
                - 'ssl_pinning': SSL pinning detection
                - 'deep_links': Deep link testing
                - 'webview': WebView vulnerability detection
                - 'cert_pinning': Certificate pinning test
                - 'apk': APK metadata analysis
                - 'full': Full mobile security scan
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  MOBILE SECURITY ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: Frida-iOS-Hook + Frida-Unpinning + DH-HackBar{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        scan_map = {
            'api': lambda: self.test_mobile_api(target or ''),
            'ssl_pinning': lambda: self.detect_ssl_pinning(target or ''),
            'deep_links': lambda: self.test_deep_links(target or ''),
            'webview': lambda: self.detect_webview_vulns(target or ''),
            'cert_pinning': lambda: self.test_certificate_pinning(target or ''),
            'apk': lambda: self.analyze_apk_metadata(target or ''),
        }

        if scan_type == 'full':
            return self._run_full(target, **kwargs)

        scan_func = scan_map.get(scan_type)
        if scan_func:
            return scan_func()
        else:
            return {
                "vulnerable": False,
                "findings": [],
                "details": {"error": f"Unknown scan type: {scan_type}"},
                "scan_type": scan_type,
            }

    def _run_full(self, target, **kwargs):
        """Full mobile security scan"""
        self._print(f"\n{BOLD}{CYAN}  Full Mobile Security Scan{RESET}", CYAN)

        all_results = {}

        # Phase 1: SSL Pinning Detection
        self._print(f"\n{BOLD}  === Phase 1: SSL Pinning Detection ==={RESET}", CYAN)
        all_results['ssl_pinning'] = self.detect_ssl_pinning(target or '')

        # Phase 2: Certificate Pinning Test
        self._print(f"\n{BOLD}  === Phase 2: Certificate Pinning Test ==={RESET}", CYAN)
        all_results['cert_pinning'] = self.test_certificate_pinning(target or '')

        # Phase 3: Mobile API Security
        self._print(f"\n{BOLD}  === Phase 3: Mobile API Security ==={RESET}", CYAN)
        all_results['api_security'] = self.test_mobile_api(target or '')

        # Phase 4: WebView Vulnerability Detection
        self._print(f"\n{BOLD}  === Phase 4: WebView Vulnerability Detection ==={RESET}", CYAN)
        all_results['webview_vulns'] = self.detect_webview_vulns(target or '')

        # Phase 5: Deep Link Testing (if package name provided)
        if kwargs.get('package_name'):
            self._print(f"\n{BOLD}  === Phase 5: Deep Link Testing ==={RESET}", CYAN)
            all_results['deep_links'] = self.test_deep_links(kwargs['package_name'])

        # Summary
        total_findings = sum(
            len(r.get('findings', [])) for r in all_results.values() if isinstance(r, dict)
        )
        any_vulnerable = any(
            r.get('vulnerable', False) for r in all_results.values() if isinstance(r, dict)
        )

        self._print(f"\n{BOLD}{CYAN}  ═══ MOBILE SECURITY SCAN SUMMARY ═══{RESET}", CYAN)
        self._print(f"  Total findings: {total_findings}", CYAN)
        self._print(f"  Vulnerable: {'YES' if any_vulnerable else 'NO'}",
                     RED if any_vulnerable else GREEN)

        return {
            "vulnerable": any_vulnerable,
            "findings": [],
            "details": all_results,
            "scan_type": "mobile_security_full",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='api', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = MobileSecurityEngine()
    return engine.run(target=target, scan_type=scan_type, **kwargs)
