#!/usr/bin/env python3
"""
ZYLON FUSION v2.0 - Advanced Hunting Engine 4
Username Enumeration | Email Security (DMARC/DKIM/SPF) | CSRF Detection |
Framework Detection | Client-Side JS Vulns | 403 Bypass | Cross-Domain |
CVE-to-Exploit Lookup

Bug Bounty Hunter Edition - Termux Non-Root Compatible
"""

import re
import json
import time
import socket
import random
import requests
from urllib.parse import urlparse, urljoin, urlencode, quote
from bs4 import BeautifulSoup

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from core.var import USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL

from core.shared_infra import shared_session, regex_cache


class V4HuntingEngine:
    """V4.0 Hunting Engine: 8 Advanced Bug Bounty Modules from Real-World Hunting"""

    def __init__(self, session=None):
        self.session = session or shared_session
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = VERIFY_SSL

    def _rotate_ua(self):
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # 76: USERNAME ENUMERATION SCANNER
    # ========================================================================

    def scan_username_enum(self, login_url, username_field='username',
                           password_field='password', extra_fields=None):
        """
        Enumerate valid usernames via differential error analysis.
        Submits multiple usernames with a wrong password and compares
        server responses to identify valid accounts.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 0,
            'confirmed_usernames': [],
            'differential_detected': False
        }

        common_usernames = [
            'admin', 'root', 'test', 'administrator', 'operator',
            'manager', 'info', 'support', 'webmaster', 'user',
            'demo', 'guest', 'backup', 'service', 'api',
            'deploy', 'jenkins', 'git', 'svn', 'ftp',
            'mail', 'postmaster', 'abuse', 'noc', 'security',
            'sysadmin', 'superadmin', 'system', 'monitor', 'log',
        ]

        # Attempt WHOIS-based username generation
        whois_usernames = self._generate_whois_usernames(login_url)
        if whois_usernames:
            common_usernames.extend(whois_usernames)
            common_usernames = list(dict.fromkeys(common_usernames))

        # Baseline: submit a clearly invalid username to capture the
        # "user not found" style response.
        baseline_username = f'zylon_noexist_{random.randint(10000,99999)}'
        baseline_password = 'ZylonWrongPass!49'

        baseline_responses = {}
        try:
            self._rotate_ua()
            form_data = {username_field: baseline_username,
                         password_field: baseline_password}
            if extra_fields and isinstance(extra_fields, dict):
                form_data.update(extra_fields)
            resp = self.session.post(login_url, data=form_data,
                                     timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL,
                                     allow_redirects=False)
            baseline_responses['status'] = resp.status_code
            baseline_responses['length'] = len(resp.text)
            baseline_responses['text_lower'] = resp.text.lower()
            baseline_responses['headers'] = dict(resp.headers)
        except Exception as e:
            result['findings'].append({
                'type': 'Connection Error',
                'severity': 'Info',
                'note': f'Could not reach login URL: {str(e)[:80]}'
            })
            return result

        result['tested'] += 1

        # Patterns that typically indicate "username not found"
        user_not_found_patterns = [
            'user not found', 'username not found', 'no account found',
            'no such user', 'does not exist', 'invalid username',
            'unknown user', 'account does not exist', 'no account',
            'not registered', 'unregistered', 'user does not exist',
            "doesn't exist", 'email not found', 'email not recognized',
        ]
        # Patterns that typically indicate "wrong password" (implies valid user)
        wrong_password_patterns = [
            'incorrect password', 'wrong password', 'invalid password',
            'password incorrect', 'password is incorrect', 'password wrong',
            'password does not match', 'bad password', 'invalid credentials',
            'incorrect credentials', 'authentication failed', 'auth failed',
            'login failed', 'signin failed', 'sign-in failed',
        ]

        baseline_is_user_not_found = any(
            p in baseline_responses['text_lower'] for p in user_not_found_patterns
        )
        baseline_is_wrong_password = any(
            p in baseline_responses['text_lower'] for p in wrong_password_patterns
        )

        # Test each username
        for username in common_usernames:
            result['tested'] += 1
            try:
                self._rotate_ua()
                form_data = {username_field: username,
                             password_field: baseline_password}
                if extra_fields and isinstance(extra_fields, dict):
                    form_data.update(extra_fields)

                resp = self.session.post(login_url, data=form_data,
                                         timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL,
                                         allow_redirects=False)
                resp_lower = resp.text.lower()
                resp_len = len(resp.text)

                # Method 1: Differential error message
                is_user_not_found = any(p in resp_lower for p in user_not_found_patterns)
                is_wrong_password = any(p in resp_lower for p in wrong_password_patterns)

                confirmed = False
                reason = ''

                # If baseline says "user not found" but this says "wrong password"
                if baseline_is_user_not_found and is_wrong_password and not is_user_not_found:
                    confirmed = True
                    reason = 'Differential error: baseline=not found, this=wrong password'
                # If baseline says "wrong password" but this says "user not found"
                elif baseline_is_wrong_password and is_user_not_found and not is_wrong_password:
                    confirmed = False  # This username is invalid
                # If response content length differs significantly from baseline
                elif not baseline_is_user_not_found and not baseline_is_wrong_password:
                    # No clear error categorization in baseline; use length diff
                    len_diff = abs(resp_len - baseline_responses['length'])
                    len_ratio = len_diff / max(baseline_responses['length'], 1)
                    if len_ratio > 0.05:  # >5% difference
                        # Check if the new response mentions wrong password
                        if is_wrong_password and not is_user_not_found:
                            confirmed = True
                            reason = 'Response differs + contains "wrong password" pattern'
                        elif not is_user_not_found:
                            # Ambiguous but notable difference
                            confirmed = True
                            reason = f'Response length differs by {len_ratio:.0%} ({resp_len} vs {baseline_responses["length"]})'

                # Method 2: Response code difference
                if resp.status_code != baseline_responses['status'] and not confirmed:
                    if resp.status_code in [200, 302] and baseline_responses['status'] not in [200, 302]:
                        confirmed = True
                        reason = f'Status code differs: {resp.status_code} vs baseline {baseline_responses["status"]}'

                if confirmed:
                    result['vulnerable'] = True
                    result['differential_detected'] = True
                    result['confirmed_usernames'].append(username)
                    result['findings'].append({
                        'type': 'Valid Username Confirmed',
                        'username': username,
                        'reason': reason,
                        'severity': 'Medium',
                        'note': 'Differential response confirms this username exists'
                    })

                time.sleep(0.15)  # Rate-limit friendliness

            except Exception:
                continue

        # Summary finding
        if result['confirmed_usernames']:
            result['findings'].append({
                'type': 'Username Enumeration Vulnerability',
                'severity': 'Medium',
                'confirmed_count': len(result['confirmed_usernames']),
                'note': f'Confirmed {len(result["confirmed_usernames"])} valid usernames via differential analysis'
            })

        return result

    def _generate_whois_usernames(self, url):
        """Generate username candidates from WHOIS data (owner name, email prefix)."""
        usernames = []
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0] if parsed.netloc else parsed.path

        # Attempt a simple WHOIS query via hackertarget API
        try:
            api_url = f'https://api.hackertarget.com/whois/?q={domain}'
            self._rotate_ua()
            resp = self.session.get(api_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                text = resp.text
                # Extract registrant name
                name_match = regex_cache.search(
                    r'Registrant\s*Name:\s*(.+)', text, re.IGNORECASE
                )
                if name_match:
                    name = name_match.group(1).strip()
                    # Generate username permutations from name
                    parts = name.lower().split()
                    if len(parts) >= 2:
                        first, last = parts[0], parts[-1]
                        usernames.extend([
                            first, last,
                            f'{first}.{last}', f'{first}_{last}',
                            f'{first}{last}', f'{first[0]}{last}',
                            f'{first}{last[0]}', f'{first[0]}.{last}',
                        ])
                    elif len(parts) == 1:
                        usernames.append(parts[0])

                # Extract registrant email
                email_match = regex_cache.search(
                    r'Registrant\s*Email:\s*([^\s@]+)@([^\s]+)', text, re.IGNORECASE
                )
                if email_match:
                    email_prefix = email_match.group(1).lower()
                    if email_prefix and len(email_prefix) > 2:
                        usernames.append(email_prefix)
                        # Also split on dots and dotscores
                        for part in email_prefix.split('.'):
                            if len(part) > 2:
                                usernames.append(part)
        except Exception:
            pass

        return list(dict.fromkeys(usernames))

    # ========================================================================
    # 77: DMARC/DKIM/SPF EMAIL SECURITY CHECKER
    # ========================================================================

    def scan_email_security(self, domain):
        """
        Check DMARC, DKIM, and SPF records for email security.
        Assess email spoofing risk.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 3,
            'dmarc': {},
            'dkim': {},
            'spf': {},
            'risk_score': 0,
            'risk_level': 'Unknown'
        }

        # --- DMARC Check ---
        dmarc_record = self._query_dns(f'_dmarc.{domain}', 'TXT')
        if dmarc_record:
            record_text = ''
            for r in dmarc_record:
                record_text += r + ' '
            record_text = record_text.strip()
            result['dmarc'] = {
                'found': True,
                'record': record_text
            }
            # Parse DMARC policy
            policy_match = regex_cache.search(r'p\s*=\s*(none|quarantine|reject)',
                                     record_text, re.IGNORECASE)
            if policy_match:
                policy = policy_match.group(1).lower()
                result['dmarc']['policy'] = policy
                if policy == 'none':
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'DMARC Policy None',
                        'severity': 'High',
                        'record': record_text,
                        'note': 'DMARC policy=none: emails failing DMARC are still delivered - spoofing possible'
                    })
                    result['risk_score'] += 40
                elif policy == 'quarantine':
                    result['findings'].append({
                        'type': 'DMARC Policy Quarantine',
                        'severity': 'Medium',
                        'record': record_text,
                        'note': 'DMARC policy=quarantine: failing emails go to spam but not rejected'
                    })
                    result['risk_score'] += 15
                elif policy == 'reject':
                    result['findings'].append({
                        'type': 'DMARC Policy Reject',
                        'severity': 'Info',
                        'record': record_text,
                        'note': 'DMARC policy=reject: properly configured - spoofing difficult'
                    })
            else:
                result['vulnerable'] = True
                result['findings'].append({
                    'type': 'DMARC Record Without Policy',
                    'severity': 'High',
                    'record': record_text,
                    'note': 'DMARC record exists but no policy (p=) defined - ineffective'
                })
                result['risk_score'] += 35

            # Check subdomain policy
            sp_match = regex_cache.search(r'sp\s*=\s*(none|quarantine|reject)',
                                 record_text, re.IGNORECASE)
            if not sp_match:
                result['findings'].append({
                    'type': 'DMARC Missing Subdomain Policy',
                    'severity': 'Low',
                    'note': 'No sp= (subdomain policy) set - subdomains may not be protected'
                })
                result['risk_score'] += 5

            # Check reporting
            rua_match = regex_cache.search(r'rua\s*=', record_text)
            ruf_match = regex_cache.search(r'ruf\s*=', record_text)
            if not rua_match and not ruf_match:
                result['findings'].append({
                    'type': 'DMARC No Reporting',
                    'severity': 'Low',
                    'note': 'No aggregate (rua) or forensic (ruf) reporting configured'
                })
                result['risk_score'] += 5
        else:
            result['vulnerable'] = True
            result['dmarc'] = {'found': False}
            result['findings'].append({
                'type': 'Missing DMARC Record',
                'severity': 'Critical',
                'note': 'No DMARC record found - email spoofing is trivially possible'
            })
            result['risk_score'] += 60

        # --- DKIM Check (brute-force selectors) ---
        dkim_selectors = [
            'default', 'selector1', 'selector2', 'google', 'mail',
            'dkim', 'sendgrid', 'ses', 'amazon', 'custom',
            'mx', 'smtp', 'mailgun', 'mandrill', 'postmark',
            'zoho', 'outlook', 'office365', 'microsoft', 'yandex',
            'mailchimp', 'sparkpost', 'fastmail', 'protonmail', 'relay',
        ]
        found_selectors = []
        for selector in dkim_selectors:
            dkim_records = self._query_dns(f'{selector}._domainkey.{domain}', 'TXT')
            if dkim_records:
                record_text = ' '.join(dkim_records)
                found_selectors.append({
                    'selector': selector,
                    'record': record_text
                })
                # Parse DKIM key type and length
                key_match = regex_cache.search(r'p=([A-Za-z0-9+/=]+)', record_text)
                if key_match:
                    key_data = key_match.group(1)
                    # Estimate key size from base64 length
                    key_bytes = len(key_data) * 3 // 4
                    if key_bytes < 128:  # < 1024-bit RSA
                        result['findings'].append({
                            'type': 'Weak DKIM Key',
                            'selector': selector,
                            'severity': 'Medium',
                            'note': f'DKIM key appears short ({key_bytes} bytes) - may be < 1024-bit RSA'
                        })
                        result['risk_score'] += 10

        result['dkim'] = {
            'selectors_tested': len(dkim_selectors),
            'selectors_found': found_selectors,
            'found': len(found_selectors) > 0
        }
        if not found_selectors:
            result['findings'].append({
                'type': 'No DKIM Record Found',
                'severity': 'Medium',
                'selectors_tested': len(dkim_selectors),
                'note': f'No DKIM records found for {len(dkim_selectors)} common selectors - email can be forged'
            })
            result['risk_score'] += 20

        # --- SPF Check ---
        spf_records = self._query_dns(domain, 'TXT')
        spf_record = None
        if spf_records:
            for r in spf_records:
                if r.strip().startswith('v=spf1'):
                    spf_record = r.strip()
                    break

        if spf_record:
            result['spf'] = {
                'found': True,
                'record': spf_record
            }
            # Parse SPF mechanisms
            mechanisms = spf_record.split()
            includes = [m for m in mechanisms if m.startswith('include:')]
            redirects = [m for m in mechanisms if m.startswith('redirect=')]

            result['spf']['includes'] = includes
            result['spf']['redirects'] = redirects

            # Check the all mechanism
            all_match = regex_cache.search(r'(\+all|\~all|\-all|\?all)', spf_record)
            if all_match:
                all_val = all_match.group(1)
                result['spf']['all_mechanism'] = all_val
                if all_val == '+all':
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'SPF +all (Pass All)',
                        'severity': 'Critical',
                        'record': spf_record,
                        'note': 'SPF +all: any server can send email as this domain - trivial spoofing'
                    })
                    result['risk_score'] += 50
                elif all_val == '~all':
                    result['findings'].append({
                        'type': 'SPF ~all (SoftFail)',
                        'severity': 'Low',
                        'record': spf_record,
                        'note': 'SPF ~all: soft fail - non-compliant receivers may still accept spoofed email'
                    })
                    result['risk_score'] += 5
                elif all_val == '?all':
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'SPF ?all (Neutral)',
                        'severity': 'High',
                        'record': spf_record,
                        'note': 'SPF ?all: neutral policy - effectively no protection'
                    })
                    result['risk_score'] += 30
                elif all_val == '-all':
                    result['findings'].append({
                        'type': 'SPF -all (HardFail)',
                        'severity': 'Info',
                        'record': spf_record,
                        'note': 'SPF -all: properly configured - unauthorized senders rejected'
                    })
            else:
                result['vulnerable'] = True
                result['findings'].append({
                    'type': 'SPF Missing All Mechanism',
                    'severity': 'High',
                    'record': spf_record,
                    'note': 'No "all" mechanism in SPF - default is ?all (neutral)'
                })
                result['risk_score'] += 25

            # Check for too many DNS lookups (>10 is RFC violation)
            dns_lookups = len(includes) + len(redirects)
            for m in mechanisms:
                if m.startswith('exists:') or m.startswith('a:') or m.startswith('mx:'):
                    dns_lookups += 1
            result['spf']['dns_lookups'] = dns_lookups
            if dns_lookups > 10:
                result['findings'].append({
                    'type': 'SPF Too Many DNS Lookups',
                    'severity': 'Medium',
                    'lookups': dns_lookups,
                    'note': f'SPF requires {dns_lookups} DNS lookups (max 10 per RFC) - may be ignored'
                })
                result['risk_score'] += 10
        else:
            result['vulnerable'] = True
            result['spf'] = {'found': False}
            result['findings'].append({
                'type': 'Missing SPF Record',
                'severity': 'Critical',
                'note': 'No SPF record found - any server can send email as this domain'
            })
            result['risk_score'] += 50

        # Calculate overall risk level
        score = min(result['risk_score'], 100)  # Cap at 100
        if score >= 60:
            result['risk_level'] = 'Critical'
        elif score >= 40:
            result['risk_level'] = 'High'
        elif score >= 20:
            result['risk_level'] = 'Medium'
        elif score >= 10:
            result['risk_level'] = 'Low'
        else:
            result['risk_level'] = 'Secure'

        result['risk_score'] = score

        return result

    def _query_dns(self, name, record_type='TXT'):
        """Query DNS records using dnspython or fallback."""
        if DNS_AVAILABLE:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                answers = resolver.resolve(name, record_type)
                return [str(rdata) for rdata in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout,
                    Exception):
                return None
        else:
            # Fallback: try using system dig/nslookup via socket-based approach
            # Minimal fallback using HTTP DNS APIs
            try:
                api_url = f'https://dns.google/resolve?name={name}&type={record_type}'
                self._rotate_ua()
                resp = self.session.get(api_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                if resp.status_code == 200:
                    data = resp.json()
                    if 'Answer' in data:
                        return [a.get('data', '') for a in data['Answer']
                                if a.get('type') in [16, 16]]  # TXT type = 16
            except Exception:
                pass
            return None

    # ========================================================================
    # 78: CSRF TOKEN DETECTION & LOGIN CSRF TESTER
    # ========================================================================

    def scan_csrf(self, url):
        """
        Detect missing CSRF tokens on forms and test for Login CSRF.
        If login form has no CSRF token + lockout policy, test Login CSRF DoS.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 0,
            'forms_analyzed': [],
            'login_csrf_vulnerable': False
        }

        # CSRF token field name patterns
        csrf_token_names = [
            'csrf', 'csrftoken', 'csrfmiddlewaretoken', 'csrf_token',
            '_token', 'token', 'authenticity_token', '_csrf_token',
            'anti_forgery_token', 'antiforgerytoken', 'xsrf-token',
            'xsrftoken', '_csrf', '__requestverificationtoken',
            'requestverificationtoken', 'csrfmiddlewaretoken',
            '_wpnonce', 'nonce', 'security', 'form_token',
            'formtoken', 'csrfkey', 'csrfmiddlewaretoken',
        ]

        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
        except Exception:
            result['findings'].append({
                'type': 'Connection Error',
                'severity': 'Info',
                'note': 'Could not connect to target URL'
            })
            return result

        soup = BeautifulSoup(resp.text, 'html.parser')
        forms = soup.find_all('form')

        if not forms:
            result['findings'].append({
                'type': 'No Forms Found',
                'severity': 'Info',
                'note': 'No HTML forms detected on the page'
            })
            return result

        login_form = None
        login_form_action = None

        for form in forms:
            result['tested'] += 1
            form_info = {
                'action': form.get('action', url),
                'method': form.get('method', 'GET').upper(),
                'has_csrf_token': False,
                'csrf_token_field': None,
                'inputs': [],
                'is_login_form': False
            }

            # Collect all hidden inputs
            hidden_inputs = form.find_all('input', {'type': 'hidden'})
            all_inputs = form.find_all('input')
            form_info['input_count'] = len(all_inputs)

            for inp in all_inputs:
                name = inp.get('name', '').lower()
                input_type = inp.get('type', 'text')
                form_info['inputs'].append({
                    'name': inp.get('name', ''),
                    'type': input_type
                })

                # Check if this is a CSRF token field
                if name and any(csrf_name in name for csrf_name in csrf_token_names):
                    form_info['has_csrf_token'] = True
                    form_info['csrf_token_field'] = inp.get('name', '')

            # Detect if this is a login form
            form_text = form.get_text().lower()
            form_action = (form.get('action') or '').lower()
            is_login = False
            login_indicators = [
                'login', 'signin', 'sign-in', 'sign_in', 'log-in',
                'authenticate', 'auth', 'session'
            ]
            for indicator in login_indicators:
                if indicator in form_action or indicator in form_text:
                    is_login = True
                    break
            # Also check for password field
            has_password = any(
                inp.get('type', '').lower() == 'password' for inp in all_inputs
            )
            if has_password and any(
                inp.get('name', '').lower() in ['username', 'user', 'email',
                                                  'login', 'account']
                for inp in all_inputs
            ):
                is_login = True

            form_info['is_login_form'] = is_login

            if is_login:
                login_form = form
                login_form_action = form.get('action', url)

            # Finding: form without CSRF token
            if not form_info['has_csrf_token']:
                severity = 'Medium'
                if is_login:
                    severity = 'High'
                result['vulnerable'] = True
                result['findings'].append({
                    'type': 'Form Missing CSRF Token',
                    'form_action': form_info['action'],
                    'form_method': form_info['method'],
                    'is_login_form': is_login,
                    'severity': severity,
                    'note': 'Form has no CSRF token - vulnerable to Cross-Site Request Forgery'
                })

            result['forms_analyzed'].append(form_info)

        # Login CSRF DoS Test
        if login_form and login_form_action:
            # Parse the login form to extract fields
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            action_url = urljoin(base, login_form_action) if login_form_action else url

            all_inputs = login_form.find_all('input')
            # Check if there's NO CSRF token on the login form
            login_has_csrf = False
            for inp in all_inputs:
                name = inp.get('name', '').lower()
                if any(csrf_name in name for csrf_name in csrf_token_names):
                    login_has_csrf = True
                    break

            if not login_has_csrf:
                result['tested'] += 1
                # Test: submit wrong password via forged request
                # If the server locks the account after N failed attempts,
                # then Login CSRF can DoS any account.
                form_data = {}
                for inp in all_inputs:
                    name = inp.get('name', '')
                    input_type = inp.get('type', 'text')
                    if not name:
                        continue
                    if input_type == 'password':
                        form_data[name] = 'ZylonCSRFTest_WrongPassword_!99'
                    elif input_type == 'hidden':
                        form_data[name] = inp.get('value', '')
                    elif input_type in ['text', 'email']:
                        # Try a test username/email
                        form_data[name] = 'zylon_csrf_test@localhost'

                try:
                    self._rotate_ua()
                    # Use a fresh session to simulate a forged request
                    forged_session = requests.Session()
                    forged_session.headers.update({
                        'User-Agent': random.choice(USER_AGENTS),
                        'Referer': url
                    })
                    forged_session.verify = VERIFY_SSL
                    resp = forged_session.post(
                        action_url, data=form_data,
                        timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL,
                        allow_redirects=False
                    )

                    # If the request is accepted (not blocked), Login CSRF is possible
                    if resp.status_code in [200, 301, 302, 401]:
                        result['login_csrf_vulnerable'] = True
                        result['vulnerable'] = True

                        # Generate CSRF PoC HTML
                        poc_html = self._generate_login_csrf_poc(
                            action_url, form_data
                        )
                        result['findings'].append({
                            'type': 'Login CSRF Vulnerable',
                            'login_url': action_url,
                            'severity': 'High',
                            'status_code': resp.status_code,
                            'poc_html': poc_html,
                            'note': 'Login form accepts forged requests without CSRF token. '
                                    'Combined with lockout policy, this enables Login CSRF DoS.'
                        })
                except Exception:
                    pass

        return result

    def _generate_login_csrf_poc(self, action_url, form_data):
        """Generate a CSRF exploit HTML PoC for login form."""
        inputs_html = ''
        for name, value in form_data.items():
            inputs_html += f'    <input type="hidden" name="{name}" value="{value}">\n'

        poc = f'''<!DOCTYPE html>
<html>
<head><title>Login CSRF PoC</title></head>
<body>
<h2>Login CSRF PoC - Auto-submit</h2>
<p>This form auto-submits to demonstrate Login CSRF DoS.</p>
<p>Target: {action_url}</p>
<form id="csrf_form" method="POST" action="{action_url}">
{inputs_html}
</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>'''
        return poc

    # ========================================================================
    # 79: FRAMEWORK DETECTION + SPECIFIC ATTACKS
    # ========================================================================

    def scan_framework(self, url):
        """
        Detect web framework and version, then test framework-specific
        endpoints and known CVEs.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 0,
            'detected_frameworks': [],
            'framework_details': {}
        }

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Collect page data
        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
        except Exception:
            result['findings'].append({
                'type': 'Connection Error',
                'severity': 'Info',
                'note': 'Could not connect to target'
            })
            return result

        page_text = resp.text
        page_lower = page_text.lower()
        headers = dict(resp.headers)
        header_lower = {k.lower(): v.lower() for k, v in headers.items()}
        cookies = {c.name.lower(): c.value for c in self.session.cookies}

        soup = BeautifulSoup(page_text, 'html.parser')

        # Collect JS files
        js_files = []
        for script in soup.find_all('script', src=True):
            js_files.append(script['src'])

        # Meta generator tags
        meta_generators = []
        for meta in soup.find_all('meta', attrs={'name': 'generator'}):
            content = meta.get('content', '')
            if content:
                meta_generators.append(content)

        # ---- Framework Signatures ----
        framework_sigs = {
            'Yii': {
                'indicators': {
                    'js_files': ['jquery.yiiactiveform', 'jquery.yii', 'yii.js'],
                    'cookies': ['phpsessid', 'yii'],
                    'headers': {},
                    'meta': ['yii'],
                    'body': ['yii.js', 'yii.csrf', 'yii.confirm'],
                },
                'endpoints': [
                    '/index.php?r=site/login', '/index.php?r=site/error',
                    '/index.php?r=site/captcha', '/index.php?r=gii',
                    '/index.php?r=debug', '/assets/',
                ],
                'cves': [
                    {'id': 'CVE-2022-02', 'desc': 'Yii debug mode info leak', 'severity': 'Medium'},
                ]
            },
            'Laravel': {
                'indicators': {
                    'js_files': [],
                    'cookies': ['laravel_session', 'xsrf-token'],
                    'headers': {},
                    'meta': ['laravel'],
                    'body': ['laravel', 'csrf-token', 'xsrf-token'],
                },
                'endpoints': [
                    '/.env', '/_debugbar', '/_debugbar/open',
                    '/telescope', '/telescope/requests', '/horizon',
                    '/api/user', '/api', '/storage/logs/laravel.log',
                    '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
                ],
                'cves': [
                    {'id': 'CVE-2021-3129', 'desc': 'Laravel <=8.4.2 debug mode RCE', 'severity': 'Critical'},
                    {'id': 'CVE-2024-52301', 'desc': 'Laravel potential info disclosure', 'severity': 'Medium'},
                ]
            },
            'Django': {
                'indicators': {
                    'js_files': [],
                    'cookies': ['csrftoken', 'sessionid'],
                    'headers': {},
                    'meta': ['django'],
                    'body': ['csrfmiddlewaretoken', 'csrfmiddlewaretoken'],
                },
                'endpoints': [
                    '/admin/', '/admin/login/', '/api/',
                    '/static/admin/', '/django_statistics/',
                    '/__debug__/', '/graphql/',
                ],
                'cves': [
                    {'id': 'CVE-2023-46695', 'desc': 'Django DoS via large username', 'severity': 'Medium'},
                    {'id': 'CVE-2023-41164', 'desc': 'Django potential strip_tags bypass', 'severity': 'Low'},
                ]
            },
            'Express.js': {
                'indicators': {
                    'js_files': [],
                    'cookies': ['connect.sid'],
                    'headers': {'x-powered-by': 'express'},
                    'meta': [],
                    'body': [],
                },
                'endpoints': [
                    '/api', '/api/v1', '/health', '/status',
                    '/env', '/info', '/metrics', '/debug',
                ],
                'cves': [
                    {'id': 'CVE-2024-29041', 'desc': 'Express open redirect', 'severity': 'Medium'},
                ]
            },
            'Spring Boot': {
                'indicators': {
                    'js_files': [],
                    'cookies': [],
                    'headers': {'x-application-context': ''},
                    'meta': [],
                    'body': ['whitelabel', 'this application has no explicit mapping'],
                },
                'endpoints': [
                    '/actuator', '/actuator/health', '/actuator/env',
                    '/actuator/beans', '/actuator/mappings', '/actuator/configprops',
                    '/actuator/info', '/actuator/metrics', '/actuator/trace',
                    '/actuator/loggers', '/actuator/heapdump', '/actuator/threaddump',
                    '/actuator/jolokia', '/env', '/configprops',
                ],
                'cves': [
                    {'id': 'CVE-2022-22965', 'desc': 'Spring4Shell RCE via data binding', 'severity': 'Critical'},
                    {'id': 'CVE-2022-22947', 'desc': 'Spring Cloud Gateway RCE', 'severity': 'Critical'},
                    {'id': 'CVE-2023-20861', 'desc': 'Spring Security bypass', 'severity': 'High'},
                ]
            },
            'Ruby on Rails': {
                'indicators': {
                    'js_files': ['rails.js', 'turbolinks'],
                    'cookies': [],
                    'headers': {'x-rack-cache': '', 'x-runtime': ''},
                    'meta': ['rails'],
                    'body': ['authenticity_token', 'csrf-param', '_method'],
                },
                'endpoints': [
                    '/rails/info', '/rails/info/properties',
                    '/rails/routes', '/admin', '/users/sign_in',
                    '/sidekiq', '/grape', '/api/v1',
                ],
                'cves': [
                    {'id': 'CVE-2023-22795', 'desc': 'Rails ReDoS in Action Dispatch', 'severity': 'Medium'},
                    {'id': 'CVE-2023-22792', 'desc': 'Rails ReDoS in Active Support', 'severity': 'Medium'},
                ]
            },
        }

        # Detect frameworks
        for fw_name, fw_sig in framework_sigs.items():
            detected = False
            detection_methods = []
            version = None

            # Check JS files
            for js_pattern in fw_sig['indicators'].get('js_files', []):
                for js_file in js_files:
                    if js_pattern.lower() in js_file.lower():
                        detected = True
                        detection_methods.append(f'JS file: {js_file}')
                        # Try version extraction from JS filename
                        ver_match = regex_cache.search(r'[\-_]?(\d+\.\d+[\.\d]*)', js_file)
                        if ver_match:
                            version = ver_match.group(1)

            # Check cookies
            for cookie_pattern in fw_sig['indicators'].get('cookies', []):
                if cookie_pattern in cookies:
                    detected = True
                    detection_methods.append(f'Cookie: {cookie_pattern}')

            # Check headers
            for header_key, header_val in fw_sig['indicators'].get('headers', {}).items():
                if header_key in header_lower:
                    if header_val and header_val in header_lower[header_key]:
                        detected = True
                        detection_methods.append(f'Header: {header_key}')
                    elif not header_val:
                        detected = True
                        detection_methods.append(f'Header: {header_key}={headers.get(header_key, header_lower.get(header_key, ""))}')

            # Check meta generator
            for meta_pattern in fw_sig['indicators'].get('meta', []):
                for mg in meta_generators:
                    if meta_pattern.lower() in mg.lower():
                        detected = True
                        detection_methods.append(f'Meta generator: {mg}')
                        ver_match = regex_cache.search(r'(\d+\.\d+[\.\d]*)', mg)
                        if ver_match:
                            version = ver_match.group(1)

            # Check body patterns
            for body_pattern in fw_sig['indicators'].get('body', []):
                if body_pattern.lower() in page_lower:
                    detected = True
                    detection_methods.append(f'Body pattern: {body_pattern}')

            if detected:
                fw_detail = {
                    'name': fw_name,
                    'version': version,
                    'detection_methods': detection_methods
                }
                result['detected_frameworks'].append(fw_name)
                result['framework_details'][fw_name] = fw_detail

                # Test framework-specific endpoints
                for endpoint in fw_sig['endpoints']:
                    result['tested'] += 1
                    test_url = urljoin(base, endpoint)
                    try:
                        self._rotate_ua()
                        test_resp = self.session.get(
                            test_url, timeout=DEFAULT_TIMEOUT,
                            verify=VERIFY_SSL, allow_redirects=False
                        )
                        if test_resp.status_code == 200:
                            severity = 'Medium'
                            # Elevate severity for sensitive endpoints
                            sensitive_kw = ['env', 'debug', 'heapdump', 'configprops',
                                            'mappings', 'loggers', '.env', 'trace',
                                            'threaddump', 'gii']
                            if any(kw in endpoint.lower() for kw in sensitive_kw):
                                severity = 'High'
                                result['vulnerable'] = True

                            content_preview = test_resp.text[:200].replace('\n', ' ').strip()
                            result['findings'].append({
                                'type': f'{fw_name} Endpoint Exposed',
                                'framework': fw_name,
                                'url': test_url,
                                'status_code': test_resp.status_code,
                                'content_length': len(test_resp.text),
                                'severity': severity,
                                'note': f'Framework-specific endpoint accessible: {endpoint}'
                            })
                        elif test_resp.status_code == 403:
                            result['findings'].append({
                                'type': f'{fw_name} Endpoint Exists (403)',
                                'framework': fw_name,
                                'url': test_url,
                                'status_code': 403,
                                'severity': 'Low',
                                'note': f'Endpoint exists but access denied (403)'
                            })
                    except Exception:
                        continue

                # Add known CVEs
                for cve in fw_sig['cves']:
                    result['findings'].append({
                        'type': f'{fw_name} Known CVE',
                        'cve_id': cve['id'],
                        'framework': fw_name,
                        'severity': cve['severity'],
                        'description': cve['desc'],
                        'note': f'Known CVE for {fw_name} - verify if version is affected'
                    })

        # Version detection from JS assets
        result['tested'] += 1
        for js_file in js_files[:20]:
            try:
                js_url = urljoin(url, js_file)
                self._rotate_ua()
                js_resp = self.session.get(js_url, timeout=DEFAULT_TIMEOUT,
                                           verify=VERIFY_SSL)
                if js_resp.status_code == 200:
                    js_text = js_resp.text[:5000]
                    # Check for version strings
                    ver_match = regex_cache.search(
                        r'(?:version|v)["\s:=]+["\']?(\d+\.\d+[\.\d\-]*)', js_text, re.I
                    )
                    if ver_match:
                        result['findings'].append({
                            'type': 'Version Detected in JS',
                            'js_file': js_file,
                            'version': ver_match.group(1),
                            'severity': 'Low',
                            'note': 'Software version exposed in JavaScript file'
                        })
            except Exception:
                continue

        if not result['detected_frameworks']:
            result['findings'].append({
                'type': 'No Framework Detected',
                'severity': 'Info',
                'note': 'Could not identify a specific web framework'
            })

        return result

    # ========================================================================
    # 80: CLIENT-SIDE JS LIBRARY VULNERABILITY SCANNER
    # ========================================================================

    def scan_js_libraries(self, url):
        """
        Extract JS library versions from loaded scripts and check
        against known CVE database.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 0,
            'libraries_found': [],
            'cve_matches': []
        }

        try:
            self._rotate_ua()
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
        except Exception:
            result['findings'].append({
                'type': 'Connection Error',
                'severity': 'Info',
                'note': 'Could not connect to target'
            })
            return result

        soup = BeautifulSoup(resp.text, 'html.parser')
        page_text = resp.text

        # Collect all script sources
        js_files = []
        for script in soup.find_all('script', src=True):
            js_files.append(urljoin(url, script['src']))

        # Also collect inline scripts
        inline_scripts = []
        for script in soup.find_all('script'):
            if script.string and len(script.string) > 50:
                inline_scripts.append(script.string)

        # Known CVE database for common JS libraries
        known_vulns = {
            'jquery': [
                {'min_ver': '0.0.0', 'max_ver': '3.5.0', 'cve': 'CVE-2020-11022',
                 'desc': 'jQuery XSS via .html() - cross-domain loading', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '3.5.0', 'cve': 'CVE-2020-11023',
                 'desc': 'jQuery XSS - passing HTML from untrusted sources', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '1.9.0', 'cve': 'CVE-2015-9251',
                 'desc': 'jQuery XSS via cross-domain ajax', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '3.4.1', 'cve': 'CVE-2019-11358',
                 'desc': 'jQuery prototype pollution via $.extend(true)', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '2.2.0', 'cve': 'CVE-2012-6708',
                 'desc': 'jQuery selector DOM manipulation XSS', 'severity': 'High'},
            ],
            'bootstrap': [
                {'min_ver': '0.0.0', 'max_ver': '3.4.1', 'cve': 'CVE-2019-8331',
                 'desc': 'Bootstrap XSS in tooltip/popover data-template', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '4.3.1', 'cve': 'CVE-2020-28502',
                 'desc': 'Bootstrap XSS in collapse data-parent', 'severity': 'Low'},
            ],
            'angular': [
                {'min_ver': '0.0.0', 'max_ver': '1.6.9', 'cve': 'CVE-2019-10768',
                 'desc': 'AngularJS prototype pollution via angular.merge', 'severity': 'High'},
                {'min_ver': '0.0.0', 'max_ver': '1.7.9', 'cve': 'CVE-2020-7676',
                 'desc': 'AngularJS ReDoS via angular.copy', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '1.8.0', 'cve': 'CVE-2021-33621',
                 'desc': 'AngularJS XSS via DOM manipulation', 'severity': 'High'},
            ],
            'react': [
                {'min_ver': '0.0.0', 'max_ver': '16.0.0', 'cve': 'CVE-2018-6341',
                 'desc': 'React ReDoS via crafted strings', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '18.2.0', 'cve': 'CVE-2023-43679',
                 'desc': 'React potential DoS via server-side rendering', 'severity': 'Low'},
            ],
            'lodash': [
                {'min_ver': '0.0.0', 'max_ver': '4.17.20', 'cve': 'CVE-2021-23337',
                 'desc': 'Lodash command injection via template', 'severity': 'High'},
                {'min_ver': '0.0.0', 'max_ver': '4.17.15', 'cve': 'CVE-2020-28500',
                 'desc': 'Lodash ReDoS via string operations', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '4.17.11', 'cve': 'CVE-2019-10744',
                 'desc': 'Lodash prototype pollution via zipObjectDeep', 'severity': 'High'},
            ],
            'three.js': [
                {'min_ver': '0.0.0', 'max_ver': '0.137.0', 'cve': 'CVE-2022-26678',
                 'desc': 'Three.js ReDoS via WebGLRenderer', 'severity': 'Low'},
            ],
            'vue': [
                {'min_ver': '0.0.0', 'max_ver': '2.6.13', 'cve': 'CVE-2021-32781',
                 'desc': 'Vue.js prototype pollution via merge', 'severity': 'Medium'},
                {'min_ver': '0.0.0', 'max_ver': '3.0.9', 'cve': 'CVE-2021-42787',
                 'desc': 'Vue.js template compilation ReDoS', 'severity': 'Medium'},
            ],
            'gsap': [
                {'min_ver': '0.0.0', 'max_ver': '3.11.0', 'cve': 'N/A',
                 'desc': 'GSAP no critical CVEs but check for outdated version', 'severity': 'Low'},
            ],
        }

        # Extract library versions from script tags and inline scripts
        found_libs = []

        # --- jQuery Detection ---
        for js_file in js_files:
            result['tested'] += 1
            fname = js_file.split('/')[-1].lower()
            # From filename
            ver = self._extract_version_from_filename(fname, 'jquery')
            if ver:
                found_libs.append({'name': 'jQuery', 'version': ver, 'source': js_file})
                continue

            # From file content
            try:
                self._rotate_ua()
                js_resp = self.session.get(js_file, timeout=DEFAULT_TIMEOUT,
                                           verify=VERIFY_SSL)
                if js_resp.status_code == 200:
                    content = js_resp.text[:3000]
                    ver = self._extract_jquery_version(content)
                    if ver:
                        found_libs.append({'name': 'jQuery', 'version': ver, 'source': js_file})
                    # Check for other libraries in content
                    ver = self._extract_version_from_content(content, 'lodash')
                    if ver:
                        found_libs.append({'name': 'lodash', 'version': ver, 'source': js_file})
                    ver = self._extract_version_from_content(content, 'three')
                    if ver:
                        found_libs.append({'name': 'three.js', 'version': ver, 'source': js_file})
            except Exception:
                continue

        # --- Bootstrap Detection ---
        for js_file in js_files:
            fname = js_file.split('/')[-1].lower()
            ver = self._extract_version_from_filename(fname, 'bootstrap')
            if ver:
                found_libs.append({'name': 'Bootstrap', 'version': ver, 'source': js_file})

        # Check CSS files for Bootstrap version
        for link in soup.find_all('link', rel='stylesheet', href=True):
            href = link['href'].lower()
            if 'bootstrap' in href:
                ver = self._extract_version_from_filename(href, 'bootstrap')
                if ver:
                    found_libs.append({'name': 'Bootstrap', 'version': ver,
                                       'source': urljoin(url, link['href'])})

        # --- Angular Detection ---
        ng_version = soup.find(attrs={'ng-version': True})
        if ng_version:
            ver = ng_version.get('ng-version', '')
            if ver:
                found_libs.append({'name': 'Angular', 'version': ver,
                                   'source': 'ng-version attribute'})

        # Check inline scripts for Angular
        for script_text in inline_scripts:
            ang_match = regex_cache.search(r'angular\.version\.full\s*=\s*["\']([\d.]+)["\']',
                                  script_text)
            if ang_match:
                found_libs.append({'name': 'Angular', 'version': ang_match.group(1),
                                   'source': 'inline script'})

        # --- React Detection ---
        for script_text in inline_scripts:
            react_match = regex_cache.search(
                r'React\.version\s*[=:]\s*["\']([\d.]+)["\']', script_text
            )
            if react_match:
                found_libs.append({'name': 'React', 'version': react_match.group(1),
                                   'source': 'inline script'})
            # Check for __NEXT_DATA__ (Next.js uses React)
            if '__NEXT_DATA__' in script_text:
                next_match = regex_cache.search(r'"buildId"\s*:\s*"[^"]*?"', script_text)
                if next_match:
                    found_libs.append({'name': 'React', 'version': 'unknown (Next.js)',
                                       'source': '__NEXT_DATA__'})

        # --- Vue.js Detection ---
        for script_text in inline_scripts:
            vue_match = regex_cache.search(r'Vue\.version\s*[=:]\s*["\']([\d.]+)["\']',
                                  script_text)
            if vue_match:
                found_libs.append({'name': 'Vue', 'version': vue_match.group(1),
                                   'source': 'inline script'})

        # --- GSAP Detection ---
        for script_text in inline_scripts:
            gsap_match = regex_cache.search(r'gsap\.version\s*[=:]\s*["\']([\d.]+)["\']',
                                   script_text)
            if gsap_match:
                found_libs.append({'name': 'GSAP', 'version': gsap_match.group(1),
                                   'source': 'inline script'})

        # --- lodash Detection ---
        for js_file in js_files:
            fname = js_file.split('/')[-1].lower()
            ver = self._extract_version_from_filename(fname, 'lodash')
            if ver:
                found_libs.append({'name': 'lodash', 'version': ver, 'source': js_file})

        # Deduplicate
        seen = set()
        unique_libs = []
        for lib in found_libs:
            key = f"{lib['name']}:{lib['version']}"
            if key not in seen:
                seen.add(key)
                unique_libs.append(lib)
        found_libs = unique_libs
        result['libraries_found'] = found_libs

        # Check found libraries against known vulnerabilities
        vulnerable_libs = set()
        for lib in found_libs:
            lib_name = lib['name'].lower().replace('.js', '')
            lib_version = lib['version']

            # Skip "unknown" versions
            if 'unknown' in lib_version:
                lib['vulnerable'] = False
                continue

            lib['vulnerable'] = False
            if lib_name in known_vulns:
                for vuln in known_vulns[lib_name]:
                    if self._version_in_range(lib_version, vuln['min_ver'],
                                              vuln['max_ver']):
                        result['vulnerable'] = True
                        lib['vulnerable'] = True
                        vulnerable_libs.add(f"{lib['name']}:{lib_version}")
                        cve_finding = {
                            'type': 'Outdated JS Library',
                            'library': lib['name'],
                            'installed_version': lib_version,
                            'fixed_version': vuln['max_ver'],
                            'cve': vuln['cve'],
                            'description': vuln['desc'],
                            'severity': vuln['severity'],
                            'source': lib['source'],
                            'note': f'{lib["name"]} {lib_version} < {vuln["max_ver"]} - {vuln["cve"]}'
                        }
                        result['findings'].append(cve_finding)
                        result['cve_matches'].append(cve_finding)

        # Risk score per outdated library
        if result['cve_matches']:
            critical = sum(1 for c in result['cve_matches']
                           if c['severity'] == 'Critical')
            high = sum(1 for c in result['cve_matches']
                       if c['severity'] == 'High')
            medium = sum(1 for c in result['cve_matches']
                         if c['severity'] == 'Medium')
            result['findings'].append({
                'type': 'JS Library Vulnerability Summary',
                'severity': 'High' if high or critical else 'Medium',
                'critical_count': critical,
                'high_count': high,
                'medium_count': medium,
                'total_cves': len(result['cve_matches']),
                'note': f'Found {len(result["cve_matches"])} CVEs across {len(found_libs)} libraries'
            })

        return result

    def _extract_version_from_filename(self, filename, lib_name):
        """Extract version number from a JS/CSS filename."""
        patterns = [
            regex_cache.compile(re.escape(lib_name) + r'[\-_]?(\d+\.\d+[\.\d]*)', re.I),
            regex_cache.compile(re.escape(lib_name) + r'\.min\.(\d+\.\d+[\.\d]*)', re.I),
            regex_cache.compile(re.escape(lib_name) + r'[\-](\d+\.\d+[\.\d]*)', re.I),
        ]
        for pattern in patterns:
            match = pattern.search(filename)
            if match:
                return match.group(1)
        return None

    def _extract_jquery_version(self, content):
        """Extract jQuery version from JS content."""
        patterns = [
            r'jquery\.fn\.jquery\s*=\s*["\']([\d.]+)["\']',
            r'jquery\.version\s*=\s*["\']([\d.]+)["\']',
            r'jQuery\s+v([\d.]+)',
            r'jquery[.\-]([\d]+\.[\d]+[\d.]*)\.(?:min\.)?js',
        ]
        for pattern in patterns:
            match = regex_cache.search(pattern, content, re.I)
            if match:
                return match.group(1)
        return None

    def _extract_version_from_content(self, content, lib_name):
        """Extract library version from JS content."""
        patterns = [
            regex_cache.compile(re.escape(lib_name) + r'\.version\s*=\s*["\']([\d.]+)["\']', re.I),
            regex_cache.compile(re.escape(lib_name) + r'\s+version\s*:\s*["\']([\d.]+)["\']', re.I),
            regex_cache.compile(r'VERSION\s*=\s*["\']([\d.]+)["\']', re.I),
        ]
        for pattern in patterns:
            match = pattern.search(content)
            if match:
                return match.group(1)
        return None

    def _version_in_range(self, version, min_ver, max_ver):
        """Check if a version string falls within [min_ver, max_ver)."""
        try:
            def normalize(v):
                return [int(x) for x in v.split('.')]
            v = normalize(version)
            mn = normalize(min_ver)
            mx = normalize(max_ver)
            # Pad to same length
            max_len = max(len(v), len(mn), len(mx))
            while len(v) < max_len:
                v.append(0)
            while len(mn) < max_len:
                mn.append(0)
            while len(mx) < max_len:
                mx.append(0)
            return v >= mn and v < mx
        except (ValueError, IndexError):
            # If we can't parse, assume vulnerable
            return True

    # ========================================================================
    # 81: 403 BYPASS TESTER
    # ========================================================================

    def scan_403_bypass(self, url):
        """
        Test a 403 URL for bypass techniques including method tampering,
        path traversal, URL encoding, header bypasses, and more.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 0,
            'successful_bypasses': [],
            'original_status': None
        }

        # Verify the URL returns 403
        try:
            self._rotate_ua()
            baseline = self.session.get(url, timeout=DEFAULT_TIMEOUT,
                                        verify=VERIFY_SSL, allow_redirects=False)
            result['original_status'] = baseline.status_code
            if baseline.status_code != 403:
                result['findings'].append({
                    'type': 'Not 403',
                    'severity': 'Info',
                    'status_code': baseline.status_code,
                    'note': f'URL returns {baseline.status_code}, not 403. Testing anyway.'
                })
        except Exception as e:
            result['findings'].append({
                'type': 'Connection Error',
                'severity': 'Info',
                'note': f'Cannot connect: {str(e)[:80]}'
            })
            return result

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path
        query = parsed.query

        # Bypass success = any non-403 response with meaningful content
        baseline_length = len(baseline.text)

        def is_bypass(resp, method='GET'):
            """Check if response indicates a successful bypass."""
            if resp.status_code == 403:
                return False
            if resp.status_code in [200, 201, 204, 301, 302]:
                # Also verify the content is not a generic error page
                if len(resp.text) > 100 and abs(len(resp.text) - baseline_length) > 50:
                    return True
                if resp.status_code == 200 and len(resp.text) > 200:
                    return True
            return False

        # 1. Method Tampering
        methods = ['PUT', 'PATCH', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT',
                    'HEAD', 'POST', 'PROPFIND', 'PROPPATCH']
        for method in methods:
            result['tested'] += 1
            try:
                self._rotate_ua()
                resp = self.session.request(
                    method, url, timeout=DEFAULT_TIMEOUT,
                    verify=VERIFY_SSL, allow_redirects=False,
                    headers={'Content-Length': '0'}
                )
                if is_bypass(resp, method):
                    result['vulnerable'] = True
                    bypass_info = {
                        'type': 'Method Tampering Bypass',
                        'method': method,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                        'severity': 'High',
                        'note': f'{method} request bypasses 403 - returns {resp.status_code}'
                    }
                    result['successful_bypasses'].append(bypass_info)
                    result['findings'].append(bypass_info)
            except Exception:
                continue

        # 2. Path Traversal / Path Tricks
        path_tricks = []
        # /admin..;/
        if path:
            dirname = path.rstrip('/')
            basename = path.split('/')[-1] if '/' in path else path
            path_tricks = [
                f"{dirname}..;/",
                f"{dirname}/.",
                f"/./{basename}",
                f"{dirname}%2f",
                f"{dirname}/",
                f"{dirname}%2e%2e%2f",
                f"{dirname}..%2f",
                f"{dirname}/..;/",
                f"{dirname}/..;/",
                f"/..{path}",
                f"{dirname}%23",
                f"{dirname}%3F",
                f"{dirname};;",
                f"{dirname}/;/",
                f"{dirname}/.;",
            ]

        for trick_path in path_tricks:
            result['tested'] += 1
            test_url = f"{base}{trick_path}"
            if query:
                test_url += f"?{query}"
            try:
                self._rotate_ua()
                resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT,
                                        verify=VERIFY_SSL, allow_redirects=False)
                if is_bypass(resp):
                    result['vulnerable'] = True
                    bypass_info = {
                        'type': 'Path Traversal Bypass',
                        'technique': trick_path,
                        'url': test_url,
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                        'severity': 'High',
                        'note': f'Path trick "{trick_path}" bypasses 403'
                    }
                    result['successful_bypasses'].append(bypass_info)
                    result['findings'].append(bypass_info)
            except Exception:
                continue

        # 3. URL Encoding Bypasses
        if path:
            encoded_tricks = []
            # Double URL encoding
            double_encoded = quote(quote(path, safe=''), safe='')
            encoded_tricks.append(double_encoded)

            # Single char encoding (encode first char of last path segment)
            segments = path.split('/')
            if segments:
                last_seg = segments[-1]
                if last_seg:
                    # Encode first character
                    first_char = last_seg[0]
                    encoded_first = '%' + hex(ord(first_char))[2:].upper()
                    new_last = encoded_first + last_seg[1:]
                    segments[-1] = new_last
                    encoded_tricks.append('/'.join(segments))

            # Full URL encoding of path
            single_encoded = quote(path, safe='/')
            encoded_tricks.append(single_encoded)

            # Unicode encoding tricks
            if path.strip('/'):
                segments = path.strip('/').split('/')
                if segments:
                    # Unicode for /
                    unicode_path = path.replace('/', '%ef%bc%8f')
                    encoded_tricks.append(unicode_path)

            for trick in encoded_tricks:
                result['tested'] += 1
                test_url = f"{base}{trick}"
                if query:
                    test_url += f"?{query}"
                try:
                    self._rotate_ua()
                    resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT,
                                            verify=VERIFY_SSL, allow_redirects=False)
                    if is_bypass(resp):
                        result['vulnerable'] = True
                        bypass_info = {
                            'type': 'URL Encoding Bypass',
                            'technique': trick,
                            'url': test_url,
                            'status_code': resp.status_code,
                            'severity': 'High',
                            'note': f'URL-encoded path bypasses 403'
                        }
                        result['successful_bypasses'].append(bypass_info)
                        result['findings'].append(bypass_info)
                except Exception:
                    continue

        # 4. Header Bypasses
        header_bypasses = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': 'localhost'},
            {'X-Forwarded-For': '::1'},
            {'X-Original-URL': path},
            {'X-Rewrite-URL': path},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Host': 'localhost'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Forwarded-For': '0.0.0.0'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Access-Token': 'admin'},
            {'Referer': base},
            {'Referer': url},
            {'Origin': base},
        ]

        for extra_headers in header_bypasses:
            result['tested'] += 1
            try:
                self._rotate_ua()
                headers = dict(self.session.headers)
                headers.update(extra_headers)
                resp = self.session.get(
                    url, headers=headers, timeout=DEFAULT_TIMEOUT,
                    verify=VERIFY_SSL, allow_redirects=False
                )
                if is_bypass(resp):
                    result['vulnerable'] = True
                    header_name = list(extra_headers.keys())[0]
                    bypass_info = {
                        'type': 'Header Bypass',
                        'header': f'{header_name}: {extra_headers[header_name]}',
                        'status_code': resp.status_code,
                        'content_length': len(resp.text),
                        'severity': 'High',
                        'note': f'Header {header_name} bypasses 403'
                    }
                    result['successful_bypasses'].append(bypass_info)
                    result['findings'].append(bypass_info)
            except Exception:
                continue

        # 5. HTTP Version (try HTTP/1.0)
        result['tested'] += 1
        try:
            # Using requests, we can't easily force HTTP/1.0, but we can
            # test with a modified approach
            self._rotate_ua()
            resp = self.session.get(
                url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL,
                allow_redirects=False
            )
            # Note: requests always uses HTTP/1.1, but we note the check
        except Exception:
            pass

        # 6. Fragment tricks
        fragment_tricks = []
        if path:
            fragment_tricks = [
                f"{path}?#",
                f"{path}#",
                f"{path}?%23",
                f"{path}?test=1",
                f"{path}??",
                f"{path}???",
            ]

        for trick in fragment_tricks:
            result['tested'] += 1
            test_url = f"{base}{trick}"
            try:
                self._rotate_ua()
                resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT,
                                        verify=VERIFY_SSL, allow_redirects=False)
                if is_bypass(resp):
                    result['vulnerable'] = True
                    bypass_info = {
                        'type': 'Fragment Bypass',
                        'technique': trick,
                        'status_code': resp.status_code,
                        'severity': 'Medium',
                        'note': f'Fragment trick bypasses 403'
                    }
                    result['successful_bypasses'].append(bypass_info)
                    result['findings'].append(bypass_info)
            except Exception:
                continue

        # 7. Verb tampering with Content-Length: 0
        for method in ['POST', 'PUT', 'PATCH']:
            result['tested'] += 1
            try:
                self._rotate_ua()
                resp = self.session.request(
                    method, url, timeout=DEFAULT_TIMEOUT,
                    verify=VERIFY_SSL, allow_redirects=False,
                    headers={'Content-Length': '0', 'Content-Type': 'application/x-www-form-urlencoded'}
                )
                if resp.status_code != 403 and resp.status_code not in [405, 501]:
                    # Different from 403 and "Method Not Allowed"
                    if is_bypass(resp, method):
                        result['vulnerable'] = True
                        bypass_info = {
                            'type': 'Verb + Content-Length Bypass',
                            'method': method,
                            'status_code': resp.status_code,
                            'severity': 'High',
                            'note': f'{method} with Content-Length:0 bypasses 403'
                        }
                        result['successful_bypasses'].append(bypass_info)
                        result['findings'].append(bypass_info)
            except Exception:
                continue

        # Summary
        if result['successful_bypasses']:
            result['findings'].append({
                'type': '403 Bypass Summary',
                'severity': 'High',
                'total_bypasses': len(result['successful_bypasses']),
                'note': f'{len(result["successful_bypasses"])} bypass techniques succeeded out of {result["tested"]} tested'
            })
        else:
            result['findings'].append({
                'type': 'No 403 Bypass Found',
                'severity': 'Info',
                'tested': result['tested'],
                'note': f'No bypass found after {result["tested"]} tests'
            })

        return result

    # ========================================================================
    # 82: CROSS-DOMAIN DISCOVERY
    # ========================================================================

    def scan_cross_domain(self, domain):
        """
        Find sibling domains on the same IP, probe them for
        security posture, and correlate WHOIS data.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 0,
            'target_ip': None,
            'sibling_domains': [],
            'correlated_orgs': [],
            'shared_vulnerabilities': []
        }

        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
            result['target_ip'] = ip
        except socket.gaierror:
            result['findings'].append({
                'type': 'DNS Resolution Failed',
                'severity': 'Info',
                'note': f'Cannot resolve {domain}'
            })
            return result

        # Discover sibling domains
        sibling_domains = []

        # Source 1: Shodan InternetDB (free, no key)
        result['tested'] += 1
        try:
            shodan_url = f'https://internetdb.shodan.io/{ip}'
            self._rotate_ua()
            resp = self.session.get(shodan_url, timeout=DEFAULT_TIMEOUT,
                                    verify=VERIFY_SSL)
            if resp.status_code == 200:
                data = resp.json()
                shodan_domains = data.get('domains', [])
                hostnames = data.get('hostnames', [])
                for d in shodan_domains + hostnames:
                    if d and d != domain:
                        sibling_domains.append(d)
                # Also collect other Shodan data
                if data.get('cpes'):
                    result['findings'].append({
                        'type': 'CPEs Found (Shodan)',
                        'severity': 'Medium',
                        'cpes': data.get('cpes', [])[:10],
                        'note': 'Software CPEs identified - check for known CVEs'
                    })
                if data.get('vulns'):
                    result['vulnerable'] = True
                    result['findings'].append({
                        'type': 'Known Vulnerabilities (Shodan)',
                        'severity': 'High',
                        'vulns': data.get('vulns', [])[:10],
                        'note': f'Host has {len(data.get("vulns", []))} known vulnerabilities'
                    })
                if data.get('ports'):
                    result['findings'].append({
                        'type': 'Open Ports (Shodan)',
                        'severity': 'Low',
                        'ports': data.get('ports', []),
                        'note': f'Open ports detected: {data.get("ports", [])}'
                    })
        except Exception:
            pass

        # Source 2: HackerTarget Reverse IP
        result['tested'] += 1
        try:
            api_url = f'https://api.hackertarget.com/reverseiplookup/?q={ip}'
            self._rotate_ua()
            resp = self.session.get(api_url, timeout=DEFAULT_TIMEOUT,
                                    verify=VERIFY_SSL)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                domains = [d.strip() for d in resp.text.strip().split('\n') if d.strip()]
                for d in domains:
                    if d and d != domain:
                        sibling_domains.append(d)
        except Exception:
            pass

        # Deduplicate
        sibling_domains = sorted(list(set(sibling_domains)))
        result['sibling_domains'] = sibling_domains

        if not sibling_domains:
            result['findings'].append({
                'type': 'No Sibling Domains Found',
                'severity': 'Info',
                'note': f'No other domains found on IP {ip}'
            })
        else:
            result['findings'].append({
                'type': 'Sibling Domains Discovered',
                'severity': 'Medium',
                'count': len(sibling_domains),
                'domains': sibling_domains[:20],
                'note': f'{len(sibling_domains)} domains share the same IP'
            })

        # Probe each discovered domain
        probed_results = []
        for sib_domain in sibling_domains[:10]:
            result['tested'] += 1
            probe = {
                'domain': sib_domain,
                'title': None,
                'server': None,
                'framework': None,
                'security_headers': {},
                'status': None
            }
            try:
                for scheme in ['https', 'http']:
                    test_url = f'{scheme}://{sib_domain}'
                    try:
                        self._rotate_ua()
                        resp = self.session.get(test_url, timeout=DEFAULT_TIMEOUT,
                                                verify=VERIFY_SSL,
                                                allow_redirects=True)
                        if resp.status_code == 200:
                            probe['status'] = resp.status_code
                            probe['server'] = resp.headers.get('Server', '')
                            probe['security_headers'] = {
                                'X-Frame-Options': resp.headers.get('X-Frame-Options', 'Missing'),
                                'Content-Security-Policy': 'Present' if resp.headers.get('Content-Security-Policy') else 'Missing',
                                'Strict-Transport-Security': 'Present' if resp.headers.get('Strict-Transport-Security') else 'Missing',
                                'X-Content-Type-Options': resp.headers.get('X-Content-Type-Options', 'Missing'),
                            }
                            soup = BeautifulSoup(resp.text, 'html.parser')
                            title = soup.find('title')
                            if title:
                                probe['title'] = title.get_text(strip=True)

                            # Detect framework
                            for meta in soup.find_all('meta', attrs={'name': 'generator'}):
                                probe['framework'] = meta.get('content', '')
                                break
                            if not probe['framework']:
                                powered = resp.headers.get('X-Powered-By', '')
                                if powered:
                                    probe['framework'] = powered
                            break
                    except Exception:
                        continue
            except Exception:
                pass
            probed_results.append(probe)

        result['probed_domains'] = probed_results

        # WHOIS correlation across domains
        org_map = {}
        for check_domain in [domain] + sibling_domains[:5]:
            result['tested'] += 1
            try:
                whois_url = f'https://api.hackertarget.com/whois/?q={check_domain}'
                self._rotate_ua()
                resp = self.session.get(whois_url, timeout=DEFAULT_TIMEOUT,
                                        verify=VERIFY_SSL)
                if resp.status_code == 200 and 'error' not in resp.text.lower():
                    text = resp.text
                    org_match = regex_cache.search(
                        r'Registrant\s*Organization:\s*(.+)', text, re.I
                    )
                    if org_match:
                        org = org_match.group(1).strip().lower()
                        if org and org not in ['n/a', 'none', '']:
                            if org not in org_map:
                                org_map[org] = []
                            org_map[org].append(check_domain)
            except Exception:
                continue

        # If multiple domains share the same org, they're correlated
        for org, domains in org_map.items():
            if len(domains) > 1:
                result['correlated_orgs'].append({
                    'organization': org,
                    'domains': domains,
                    'note': f'{len(domains)} domains registered by same org'
                })

        # Identify shared vulnerabilities
        missing_headers_domains = []
        for probe in probed_results:
            sh = probe.get('security_headers', {})
            if sh.get('X-Frame-Options') == 'Missing':
                missing_headers_domains.append(probe['domain'])

        if len(missing_headers_domains) > 1:
            result['vulnerable'] = True
            result['shared_vulnerabilities'].append({
                'type': 'Shared Missing Security Headers',
                'domains': missing_headers_domains,
                'severity': 'Medium',
                'note': 'Multiple sibling domains missing X-Frame-Options'
            })
            result['findings'].append({
                'type': 'Cross-Domain Shared Vulnerability',
                'severity': 'Medium',
                'vuln': 'Missing X-Frame-Options',
                'affected_domains': missing_headers_domains,
                'note': f'{len(missing_headers_domains)} domains share the same vulnerability'
            })

        return result

    # ========================================================================
    # 83: CVE-TO-EXPLOIT LOOKUP ENGINE
    # ========================================================================

    def scan_cve_lookup(self, software_name, version=None):
        """
        Look up CVEs for a given software name and version using
        NVD API and CIRCL API. Rate and group by severity.
        """
        result = {
            'vulnerable': False,
            'findings': [],
            'tested': 2,
            'software': software_name,
            'version': version,
            'cves': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': []
            },
            'total_cves': 0,
            'exploitable_cves': []
        }

        # Parse vendor/product from software name
        # e.g., "Apache/2.4.52" -> vendor=apache, product=apache_http_server
        vendor, product = self._parse_software_name(software_name)

        cve_data = []

        # Source 1: NVD API
        try:
            nvd_params = {
                'keywordSearch': product,
                'resultsPerPage': 40
            }
            if version:
                nvd_params['keywordSearch'] = f'{product} {version}'

            nvd_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
            self._rotate_ua()
            resp = self.session.get(nvd_url, params=nvd_params,
                                    timeout=30, verify=VERIFY_SSL)
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get('vulnerabilities', [])
                for vuln in vulnerabilities[:40]:
                    cve_item = vuln.get('cve', {})
                    cve_id = cve_item.get('id', '')

                    # Get description
                    descriptions = cve_item.get('descriptions', [])
                    desc = ''
                    for d in descriptions:
                        if d.get('lang') == 'en':
                            desc = d.get('value', '')
                            break

                    # Get CVSS score
                    cvss_score = None
                    cvss_version = None
                    metrics = cve_item.get('metrics', {})
                    for cvss_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if cvss_key in metrics:
                            cvss_data = metrics[cvss_key][0]
                            cvss_info = cvss_data.get('cvssData', {})
                            cvss_score = cvss_info.get('baseScore')
                            cvss_version = cvss_info.get('version')
                            break

                    # Check if exploitable
                    is_exploitable = self._check_exploitability(cve_id, desc)

                    cve_entry = {
                        'cve_id': cve_id,
                        'description': desc[:300] if desc else '',
                        'cvss_score': cvss_score,
                        'cvss_version': cvss_version,
                        'exploitable': is_exploitable,
                        'source': 'NVD'
                    }
                    cve_data.append(cve_entry)
        except Exception:
            pass

        # Source 2: CIRCL API
        try:
            circl_url = f'https://cve.circl.lu/api/search/{vendor}/{product}'
            self._rotate_ua()
            resp = self.session.get(circl_url, timeout=30, verify=VERIFY_SSL)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    for item in data[:40]:
                        cve_id = item.get('id', '')
                        # Avoid duplicates from NVD
                        if any(c['cve_id'] == cve_id for c in cve_data):
                            continue

                        desc = item.get('summary', '')[:300]
                        cvss_score = item.get('cvss')
                        is_exploitable = self._check_exploitability(cve_id, desc)

                        cve_entry = {
                            'cve_id': cve_id,
                            'description': desc,
                            'cvss_score': cvss_score,
                            'cvss_version': None,
                            'exploitable': is_exploitable,
                            'source': 'CIRCL'
                        }
                        cve_data.append(cve_entry)
        except Exception:
            pass

        # Group by severity
        for cve in cve_data:
            score = cve.get('cvss_score')
            if score is None:
                result['cves']['low'].append(cve)
                continue

            try:
                score_val = float(score)
            except (ValueError, TypeError):
                result['cves']['low'].append(cve)
                continue

            if score_val >= 9.0:
                result['cves']['critical'].append(cve)
            elif score_val >= 7.0:
                result['cves']['high'].append(cve)
            elif score_val >= 4.0:
                result['cves']['medium'].append(cve)
            else:
                result['cves']['low'].append(cve)

        result['total_cves'] = len(cve_data)

        # Filter exploitable CVEs
        for cve in cve_data:
            if cve.get('exploitable'):
                result['exploitable_cves'].append(cve)

        # Determine vulnerability
        if result['cves']['critical'] or result['cves']['high']:
            result['vulnerable'] = True

        # Generate findings
        for severity in ['critical', 'high', 'medium', 'low']:
            cves_in_group = result['cves'][severity]
            if cves_in_group:
                top_cves = cves_in_group[:5]
                cve_ids = [c['cve_id'] for c in top_cves]
                finding_severity = severity.capitalize()
                if severity in ['critical', 'high']:
                    finding_severity = severity.capitalize()

                result['findings'].append({
                    'type': f'{severity.capitalize()} Severity CVEs',
                    'severity': finding_severity,
                    'count': len(cves_in_group),
                    'top_cves': [{'id': c['cve_id'],
                                  'cvss': c.get('cvss_score'),
                                  'exploitable': c.get('exploitable', False),
                                  'desc': c.get('description', '')[:100]}
                                 for c in top_cves],
                    'note': f'{len(cves_in_group)} {severity} CVEs found for {software_name}'
                })

        # Exploitable CVEs summary
        if result['exploitable_cves']:
            result['findings'].append({
                'type': 'Exploitable CVEs',
                'severity': 'Critical',
                'count': len(result['exploitable_cves']),
                'cve_ids': [c['cve_id'] for c in result['exploitable_cves'][:10]],
                'note': f'{len(result["exploitable_cves"])} CVEs with known exploits or PoCs'
            })

        # Overall risk assessment
        crit_count = len(result['cves']['critical'])
        high_count = len(result['cves']['high'])
        exploit_count = len(result['exploitable_cves'])

        risk_note = f'{software_name}'
        if version:
            risk_note += f' {version}'
        risk_note += f': {crit_count} Critical, {high_count} High, {exploit_count} Exploitable'

        result['findings'].append({
            'type': 'CVE Risk Assessment',
            'severity': 'Critical' if crit_count > 0 or exploit_count > 0
                        else 'High' if high_count > 0 else 'Info',
            'note': risk_note
        })

        return result

    def _parse_software_name(self, software_name):
        """Parse software name into vendor and product for CIRCL API."""
        # Handle formats like "Apache/2.4.52", "nginx/1.18.0"
        name = software_name
        if '/' in name:
            parts = name.split('/')
            name = parts[0].strip()

        name_lower = name.lower().strip()

        # Common mappings
        name_map = {
            'apache': ('apache', 'http_server'),
            'apache httpd': ('apache', 'http_server'),
            'nginx': ('nginx', 'nginx'),
            'php': ('php', 'php'),
            'openssl': ('openssl', 'openssl'),
            'wordpress': ('wordpress', 'wordpress'),
            'drupal': ('drupal', 'drupal'),
            'joomla': ('joomla', 'joomla'),
            'tomcat': ('apache', 'tomcat'),
            'mysql': ('oracle', 'mysql'),
            'postgresql': ('postgresql', 'postgresql'),
            'redis': ('redis', 'redis'),
            'node.js': ('nodejs', 'nodejs'),
            'express': ('expressjs', 'express'),
            'django': ('djangoproject', 'django'),
            'flask': ('palletsprojects', 'flask'),
            'rails': ('rubyonrails', 'rails'),
            'spring': ('vmware', 'spring_framework'),
            'jenkins': ('cloudbees', 'jenkins'),
            'struts': ('apache', 'struts'),
            'iis': ('microsoft', 'internet_information_services'),
            'jetty': ('eclipse', 'jetty'),
            'sqlite': ('sqlite', 'sqlite'),
        }

        if name_lower in name_map:
            return name_map[name_lower]

        # Default: use name as both vendor and product
        return name_lower, name_lower

    def _check_exploitability(self, cve_id, description):
        """Check if a CVE has known exploits based on description patterns."""
        if not description:
            return False

        desc_lower = description.lower()

        exploit_indicators = [
            'exploit', 'remote code execution', 'rce',
            'arbitrary code execution', 'command injection',
            'proof of concept', 'poc', 'poc available',
            'public exploit', 'weaponized', 'in the wild',
            'arbitrary file read', 'arbitrary file write',
            'sql injection', 'authentication bypass',
            'privilege escalation', 'arbitrary execution',
            'metasploit', 'remote attacker can',
            'unauthenticated', 'no authentication required',
        ]

        for indicator in exploit_indicators:
            if indicator in desc_lower:
                return True

        # Check for known exploit-containing CVE ID patterns
        # (some well-known exploit CVEs)
        known_exploit_cves = {
            'CVE-2021-44228', 'CVE-2021-45046',  # Log4Shell
            'CVE-2022-22965',  # Spring4Shell
            'CVE-2022-1388',   # F5 BIG-IP
            'CVE-2021-26855',  # ProxyLogon
            'CVE-2023-44487',  # HTTP/2 Rapid Reset
            'CVE-2023-38545',  # curl SOCKS5
            'CVE-2024-3094',   # XZ Utils
        }
        if cve_id in known_exploit_cves:
            return True

        return False

    # ========================================================================
    # UTILITY: Run all V4 scans
    # ========================================================================

    def run_all_v4(self, target, options=None):
        """
        Run all V4 hunting modules against a target.
        Returns a comprehensive results dict.
        """
        results = {
            'engine': 'V4 Hunting Engine',
            'target': target,
            'scans': {},
            'summary': {
                'total_scans': 8,
                'completed': 0,
                'vulnerabilities_found': 0
            }
        }

        options = options or {}
        parsed = urlparse(target)
        domain = parsed.netloc.split(':')[0] if parsed.netloc else parsed.path

        # Scan 76: Username Enumeration
        try:
            results['scans']['username_enum'] = self.scan_username_enum(
                target,
                username_field=options.get('username_field', 'username'),
                password_field=options.get('password_field', 'password'),
                extra_fields=options.get('extra_fields')
            )
            results['summary']['completed'] += 1
        except Exception as e:
            results['scans']['username_enum'] = {'error': str(e)}

        # Scan 77: Email Security
        try:
            results['scans']['email_security'] = self.scan_email_security(domain)
            results['summary']['completed'] += 1
        except Exception as e:
            results['scans']['email_security'] = {'error': str(e)}

        # Scan 78: CSRF Detection
        try:
            results['scans']['csrf'] = self.scan_csrf(target)
            results['summary']['completed'] += 1
        except Exception as e:
            results['scans']['csrf'] = {'error': str(e)}

        # Scan 79: Framework Detection
        try:
            results['scans']['framework'] = self.scan_framework(target)
            results['summary']['completed'] += 1
        except Exception as e:
            results['scans']['framework'] = {'error': str(e)}

        # Scan 80: JS Library Vulns
        try:
            results['scans']['js_libraries'] = self.scan_js_libraries(target)
            results['summary']['completed'] += 1
        except Exception as e:
            results['scans']['js_libraries'] = {'error': str(e)}

        # Scan 81: 403 Bypass
        try:
            results['scans']['403_bypass'] = self.scan_403_bypass(target)
            results['summary']['completed'] += 1
        except Exception as e:
            results['scans']['403_bypass'] = {'error': str(e)}

        # Scan 82: Cross-Domain Discovery
        try:
            results['scans']['cross_domain'] = self.scan_cross_domain(domain)
            results['summary']['completed'] += 1
        except Exception as e:
            results['scans']['cross_domain'] = {'error': str(e)}

        # Scan 83: CVE Lookup (requires software name, skip if not provided)
        sw_name = options.get('software_name', '')
        sw_ver = options.get('software_version', None)
        if sw_name:
            try:
                results['scans']['cve_lookup'] = self.scan_cve_lookup(
                    sw_name, version=sw_ver
                )
                results['summary']['completed'] += 1
            except Exception as e:
                results['scans']['cve_lookup'] = {'error': str(e)}
        else:
            results['scans']['cve_lookup'] = {
                'note': 'Skipped - provide software_name in options'
            }

        # Count total vulnerabilities
        vuln_count = 0
        for scan_name, scan_result in results['scans'].items():
            if isinstance(scan_result, dict):
                vuln_count += len(scan_result.get('findings', []))
                if scan_result.get('vulnerable'):
                    vuln_count += 1
        results['summary']['vulnerabilities_found'] = vuln_count

        return results
