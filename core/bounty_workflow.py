"""
ZYLON FUSION - Bug Bounty Workflow Engine
CVSS Scoring, PoC Generator, Scope Checker, Report Builder
Bug Bounty Hunter Edition
"""

import os
import json
import time
from datetime import datetime
from urllib.parse import urlparse


class BugBountyWorkflow:
    """
    Bug Bounty Workflow Engine
    Helps hunters manage scope, severity, PoCs, and reports
    """

    def __init__(self):
        self.config_dir = os.path.join(os.path.expanduser("~"), '.zylon')
        self.scope_file = os.path.join(self.config_dir, 'scope.json')
        self.findings_file = os.path.join(self.config_dir, 'findings.json')
        self.scope = self._load_scope()
        self.findings = self._load_findings()

    # ========================================================================
    # SCOPE MANAGEMENT
    # ========================================================================

    def _load_scope(self):
        """Load scope configuration"""
        if os.path.exists(self.scope_file):
            try:
                with open(self.scope_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return {'domains': [], 'excludes': [], 'program': '', 'platform': ''}

    def _save_scope(self):
        """Save scope configuration"""
        os.makedirs(self.config_dir, exist_ok=True)
        with open(self.scope_file, 'w') as f:
            json.dump(self.scope, f, indent=2)

    def set_scope(self, domains, excludes=None, program='', platform=''):
        """Set the bug bounty program scope"""
        self.scope = {
            'domains': domains if isinstance(domains, list) else [domains],
            'excludes': excludes or [],
            'program': program,
            'platform': platform,
            'set_date': datetime.now().isoformat()
        }
        self._save_scope()
        return self.scope

    def check_in_scope(self, target):
        """Check if a target is within the bug bounty scope"""
        if not self.scope.get('domains'):
            return {'in_scope': True, 'note': 'No scope defined - assuming in scope'}

        target_domain = target.replace('www.', '').split('/')[0].split(':')[0]

        in_scope = False
        for scope_domain in self.scope['domains']:
            scope_domain = scope_domain.replace('www.', '').strip()
            if target_domain == scope_domain or target_domain.endswith(f'.{scope_domain}'):
                in_scope = True
                break

        # Check exclusions
        for exclude in self.scope.get('excludes', []):
            exclude = exclude.replace('www.', '').strip()
            if target_domain == exclude or target_domain.endswith(f'.{exclude}'):
                return {'in_scope': False, 'reason': f'Explicitly excluded: {exclude}'}

        if in_scope:
            return {'in_scope': True, 'program': self.scope.get('program', '')}
        return {'in_scope': False, 'reason': 'Not in defined scope domains'}

    # ========================================================================
    # FINDINGS MANAGEMENT
    # ========================================================================

    def _load_findings(self):
        """Load saved findings"""
        if os.path.exists(self.findings_file):
            try:
                with open(self.findings_file) as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _save_findings(self):
        """Save findings"""
        os.makedirs(self.config_dir, exist_ok=True)
        with open(self.findings_file, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)

    def add_finding(self, finding):
        """Add a new finding with auto-triage"""
        # Auto-assign severity
        if 'severity' not in finding:
            finding['severity'] = self._auto_severity(finding)

        # Auto-assign CVSS
        if 'cvss' not in finding:
            finding['cvss'] = self._calculate_cvss(finding)

        # Check scope
        scope_check = self.check_in_scope(finding.get('target', ''))
        finding['in_scope'] = scope_check.get('in_scope', True)

        # Check for duplicates
        is_duplicate = self._check_duplicate(finding)
        finding['is_duplicate'] = is_duplicate

        # Add metadata
        finding['id'] = f"ZYLO-{len(self.findings) + 1:04d}"
        finding['timestamp'] = datetime.now().isoformat()
        finding['status'] = 'new'

        self.findings.append(finding)
        self._save_findings()

        return finding

    def _check_duplicate(self, new_finding):
        """Check if finding is a duplicate"""
        for existing in self.findings:
            if (existing.get('type') == new_finding.get('type') and
                existing.get('parameter') == new_finding.get('parameter') and
                existing.get('target') == new_finding.get('target')):
                return True
        return False

    # ========================================================================
    # CVSS SCORING
    # ========================================================================

    def _calculate_cvss(self, finding):
        """Calculate CVSS v3.1 score based on finding characteristics"""
        base_score = 0.0

        vuln_type = finding.get('type', '').lower()
        severity = finding.get('severity', 'medium').lower()

        # Map severity to base CVSS ranges
        severity_cvss = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 0.0,
        }

        base_score = severity_cvss.get(severity, 5.0)

        # Adjust based on vulnerability type
        type_adjustments = {
            'rce': 3.0,        # Remote Code Execution
            'ssrf': 2.0,       # Server-Side Request Forgery
            'sqli': 2.5,       # SQL Injection
            'xss': 1.0,        # Cross-Site Scripting
            'idor': 1.5,       # Insecure Direct Object Reference
            'xxe': 2.0,        # XML External Entity
            'ssti': 2.5,       # Server-Side Template Injection
            'lfi': 2.0,        # Local File Inclusion
            'rfi': 2.5,        # Remote File Inclusion
            'cors': 1.0,       # CORS Misconfiguration
            'open_redirect': 0.5,
            'info_disclosure': 0.5,
            'cache_poisoning': 1.5,
            'request_smuggling': 2.0,
            'host_header': 1.0,
            'jwt': 1.5,
            'broken_auth': 2.0,
            'race_condition': 1.5,
        }

        for vtype, adjustment in type_adjustments.items():
            if vtype in vuln_type:
                base_score = min(base_score + adjustment, 10.0)
                break

        # Round to 1 decimal
        return round(base_score, 1)

    def _auto_severity(self, finding):
        """Auto-assign severity based on finding type"""
        vuln_type = finding.get('type', '').lower()

        critical_types = ['rce', 'sqli', 'ssrf', 'xxe', 'ssti', 'lfi', 'rfi', 'jwt_none']
        high_types = ['idor', 'xss', 'broken_auth', 'cache_poisoning', 'request_smuggling', 'race_condition']
        medium_types = ['cors', 'open_redirect', 'crlf', 'host_header', 'info_disclosure']
        low_types = ['missing_header', 'cookie_flag']

        for ct in critical_types:
            if ct in vuln_type:
                return 'Critical'
        for ht in high_types:
            if ht in vuln_type:
                return 'High'
        for mt in medium_types:
            if mt in vuln_type:
                return 'Medium'
        for lt in low_types:
            if lt in vuln_type:
                return 'Low'
        return 'Medium'

    # ========================================================================
    # POC (Proof of Concept) GENERATOR
    # ========================================================================

    def generate_poc(self, finding):
        """Generate a Proof of Concept for a finding"""
        vuln_type = finding.get('type', '').lower()

        poc_generators = {
            'sqli': self._poc_sqli,
            'xss': self._poc_xss,
            'ssrf': self._poc_ssrf,
            'ssti': self._poc_ssti,
            'cors': self._poc_cors,
            'open_redirect': self._poc_open_redirect,
            'idor': self._poc_idor,
            'lfi': self._poc_lfi,
            'xxe': self._poc_xxe,
        }

        generator = poc_generators.get(vuln_type, self._poc_generic)
        return generator(finding)

    def _poc_sqli(self, finding):
        url = finding.get('url', '')
        param = finding.get('parameter', '')
        payload = finding.get('payload', '')
        return {
            'title': f'SQL Injection in parameter "{param}"',
            'description': f'The parameter `{param}` is vulnerable to SQL injection.',
            'steps': [
                f'1. Navigate to: {url}',
                f'2. Inject payload in `{param}`: {payload}',
                f'3. Observe SQL error or anomalous response',
            ],
            'curl_command': f'curl -v "{url}?{param}={payload}"',
            'impact': 'An attacker can extract, modify, or delete data from the database. In some cases, RCE is possible.',
            'remediation': 'Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.',
        }

    def _poc_xss(self, finding):
        url = finding.get('url', '')
        param = finding.get('parameter', '')
        payload = finding.get('payload', '')
        return {
            'title': f'Reflected XSS in parameter "{param}"',
            'description': f'The parameter `{param}` reflects user input without sanitization.',
            'steps': [
                f'1. Navigate to: {url}',
                f'2. Inject payload in `{param}`: {payload}',
                f'3. Observe JavaScript execution in the response',
            ],
            'curl_command': f'curl -v "{url}?{param}={payload}"',
            'impact': 'An attacker can execute arbitrary JavaScript in the victim\'s browser, steal sessions, redirect users, or perform actions on their behalf.',
            'remediation': 'Implement context-aware output encoding. Use Content-Security-Policy headers. Validate and sanitize all user input.',
        }

    def _poc_ssrf(self, finding):
        param = finding.get('parameter', '')
        payload = finding.get('payload', '')
        return {
            'title': f'SSRF via parameter "{param}"',
            'description': f'The parameter `{param}` allows making requests to internal resources.',
            'steps': [
                f'1. Identify the parameter: {param}',
                f'2. Inject internal URL: {payload}',
                f'3. Observe response containing internal resource data',
            ],
            'impact': 'An attacker can access internal services, cloud metadata (AWS credentials), and scan internal networks.',
            'remediation': 'Implement URL allowlists. Block requests to private IP ranges and cloud metadata endpoints. Use network segmentation.',
        }

    def _poc_ssti(self, finding):
        param = finding.get('parameter', '')
        payload = finding.get('payload', '')
        engine = finding.get('engine', 'Unknown')
        return {
            'title': f'SSTI in parameter "{param}" ({engine})',
            'description': f'The parameter `{param}` is processed by the template engine ({engine}) without sanitization.',
            'steps': [
                f'1. Identify template engine: {engine}',
                f'2. Inject payload in `{param}`: {payload}',
                f'3. Confirm code execution via arithmetic evaluation',
            ],
            'impact': 'Remote Code Execution is possible through the template engine.',
            'remediation': 'Never pass user input directly to template engines. Use sandbox environments. Implement input validation.',
        }

    def _poc_cors(self, finding):
        origin = finding.get('origin', '')
        return {
            'title': 'CORS Misconfiguration',
            'description': 'The server reflects arbitrary Origins in Access-Control-Allow-Origin with credentials allowed.',
            'steps': [
                f'1. Send request with Origin: {origin}',
                '2. Observe ACAO header reflecting the origin',
                '3. Observe ACAC: true (credentials allowed)',
            ],
            'curl_command': f'curl -v -H "Origin: {origin}" "https://target.com"',
            'impact': 'An attacker can make cross-origin requests with credentials, stealing sensitive data from authenticated users.',
            'remediation': 'Implement strict Origin allowlists. Never reflect arbitrary Origins. Avoid using Access-Control-Allow-Credentials with wildcard Origins.',
        }

    def _poc_open_redirect(self, finding):
        param = finding.get('parameter', '')
        payload = finding.get('payload', '')
        url = finding.get('url', '')
        return {
            'title': f'Open Redirect via parameter "{param}"',
            'description': f'The parameter `{param}` redirects to arbitrary URLs.',
            'steps': [
                f'1. Navigate to: {url}',
                f'2. Set `{param}` to external URL: {payload}',
                f'3. Observe redirect to attacker-controlled URL',
            ],
            'impact': 'Can be used in phishing attacks, OAuth token theft, and as a vector for other vulnerabilities.',
            'remediation': 'Validate redirect destinations against an allowlist. Use relative paths instead of absolute URLs.',
        }

    def _poc_idor(self, finding):
        param = finding.get('parameter', '')
        test_val = finding.get('test_value', '')
        return {
            'title': f'IDOR in parameter "{param}"',
            'description': f'The parameter `{param}` allows accessing other users\' resources without authorization.',
            'steps': [
                f'1. Authenticate as User A',
                f'2. Access resource with `{param}`={test_val}',
                f'3. Observe data belonging to another user',
            ],
            'impact': 'Unauthorized access to other users\' data, potentially including PII, financial data, or admin functions.',
            'remediation': 'Implement proper authorization checks. Verify the authenticated user owns the requested resource.',
        }

    def _poc_lfi(self, finding):
        param = finding.get('parameter', '')
        payload = finding.get('payload', '')
        return {
            'title': f'Local File Inclusion via parameter "{param}"',
            'description': f'The parameter `{param}` allows reading arbitrary files from the server.',
            'steps': [
                f'1. Identify file-accepting parameter: {param}',
                f'2. Inject path traversal: {payload}',
                f'3. Observe file contents in response',
            ],
            'impact': 'An attacker can read sensitive files including configuration, credentials, and source code.',
            'remediation': 'Validate file paths against an allowlist. Use chroot jails. Never pass user input directly to file system operations.',
        }

    def _poc_xxe(self, finding):
        endpoint = finding.get('endpoint', '')
        return {
            'title': 'XML External Entity (XXE) Injection',
            'description': 'The XML parser processes external entity declarations, allowing file read and SSRF.',
            'steps': [
                f'1. Send XML request to: {endpoint}',
                '2. Include DOCTYPE with external entity: <!ENTITY xxe SYSTEM "file:///etc/passwd">',
                '3. Reference entity in XML body: &xxe;',
                '4. Observe file contents in response',
            ],
            'impact': 'File disclosure, SSRF, and in some cases Remote Code Execution.',
            'remediation': 'Disable external entity processing. Use JSON instead of XML where possible. Implement XML parser hardening.',
        }

    def _poc_generic(self, finding):
        return {
            'title': f'{finding.get("type", "Unknown")} Vulnerability',
            'description': finding.get('evidence', 'Vulnerability detected'),
            'steps': [
                f'1. Target: {finding.get("url", "N/A")}',
                f'2. Parameter: {finding.get("parameter", "N/A")}',
                f'3. Payload: {finding.get("payload", "N/A")}',
                f'4. Verify the finding manually',
            ],
            'impact': 'Impact depends on the specific vulnerability type and context.',
            'remediation': 'Follow OWASP guidelines for the specific vulnerability type.',
        }

    # ========================================================================
    # BUG BOUNTY REPORT GENERATOR
    # ========================================================================

    def generate_bug_bounty_report(self, finding, format='markdown'):
        """Generate a bug bounty report in the specified format"""
        poc = self.generate_poc(finding)

        if format == 'markdown':
            return self._report_markdown(finding, poc)
        elif format == 'hackerone':
            return self._report_hackerone(finding, poc)
        elif format == 'bugcrowd':
            return self._report_bugcrowd(finding, poc)
        else:
            return self._report_markdown(finding, poc)

    def _report_markdown(self, finding, poc):
        """Generate Markdown report"""
        severity = finding.get('severity', 'Medium')
        cvss = finding.get('cvss', 'N/A')

        report = f"""# {poc.get('title', 'Security Vulnerability')}

## Summary
{poc.get('description', 'N/A')}

## Severity
**{severity}** | CVSS: {cvss}

## Steps to Reproduce
"""
        for step in poc.get('steps', []):
            report += f"{step}\n\n"

        if poc.get('curl_command'):
            report += f"""## Proof of Concept (cURL)
```bash
{poc['curl_command']}
```

"""

        report += f"""## Impact
{poc.get('impact', 'N/A')}

## Remediation
{poc.get('remediation', 'N/A')}

## References
- OWASP: https://owasp.org/www-community/{finding.get('type', '').replace('_', '-')}
- CWE: https://cwe.mitre.org/

---
*Report generated by ZYLON FUSION | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""
        return report

    def _report_hackerone(self, finding, poc):
        """Generate HackerOne format report"""
        severity = finding.get('severity', 'Medium')
        cvss = finding.get('cvss', 'N/A')

        report = f"""## Title: {poc.get('title', 'Security Vulnerability')}

### Severity: {severity}

### Description:
{poc.get('description', 'N/A')}

### Steps To Reproduce:
"""
        for i, step in enumerate(poc.get('steps', []), 1):
            report += f"{step}\n"

        report += f"""
### Supporting Material/References:
- CVSS Score: {cvss}
- Vulnerability Type: {finding.get('type', 'Unknown')}
- Target: {finding.get('target', 'N/A')}
"""
        if poc.get('curl_command'):
            report += f"- cURL PoC: `{poc['curl_command']}`\n"

        report += f"""
### Impact:
{poc.get('impact', 'N/A')}
"""
        return report

    def _report_bugcrowd(self, finding, poc):
        """Generate Bugcrowd format report"""
        return self._report_hackerone(finding, poc)  # Similar format

    # ========================================================================
    # FINDINGS SUMMARY
    # ========================================================================

    def get_findings_summary(self):
        """Get a summary of all findings"""
        summary = {
            'total': len(self.findings),
            'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0},
            'by_type': {},
            'in_scope': 0,
            'duplicates': 0,
            'new': 0,
        }

        for f in self.findings:
            sev = f.get('severity', 'Medium')
            summary['by_severity'][sev] = summary['by_severity'].get(sev, 0) + 1

            vtype = f.get('type', 'Unknown')
            summary['by_type'][vtype] = summary['by_type'].get(vtype, 0) + 1

            if f.get('in_scope'):
                summary['in_scope'] += 1
            if f.get('is_duplicate'):
                summary['duplicates'] += 1
            if f.get('status') == 'new':
                summary['new'] += 1

        return summary
