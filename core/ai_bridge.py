"""
ZYLON FUSION - AI Bridge Module
AI-powered vulnerability analysis using Gemini API
Termux Non-Root Compatible
"""

import os
import json
import requests
from core.var import HOME_DIR, DEFAULT_TIMEOUT

# Gemini API key (configurable)
GEMINI_API_KEY = ""


class AIBridge:
    """
    AI Bridge for ZYLON FUSION
    Provides AI-powered vulnerability analysis
    Supports: Gemini API (primary), OpenAI-compatible endpoints (secondary)
    """

    def __init__(self):
        self.config_dir = os.path.join(HOME_DIR, '.zylon')
        self.config_file = os.path.join(self.config_dir, 'config.json')
        self.api_key = None
        self.gemini_api_key = None
        self.api_endpoint = None
        self.ai_provider = 'gemini'  # 'gemini' or 'openai'
        self._load_config()

    def _load_config(self):
        """Load AI configuration"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file) as f:
                    config = json.load(f)
                self.api_key = config.get('ai_api_key', '')
                self.gemini_api_key = config.get('gemini_api_key', '')
                self.api_endpoint = config.get('ai_endpoint', 'https://api.openai.com/v1')
                self.ai_provider = config.get('ai_provider', 'gemini')
        except Exception:
            pass

    def set_gemini_key(self, api_key):
        """Configure Gemini API key"""
        self.gemini_api_key = api_key
        self.ai_provider = 'gemini'
        self._save_config()

    def set_api_key(self, api_key, endpoint=None):
        """Configure AI API key (OpenAI-compatible)"""
        self.api_key = api_key
        if endpoint:
            self.api_endpoint = endpoint
        self.ai_provider = 'openai'
        self._save_config()

    def _save_config(self):
        """Save configuration to file"""
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file) as f:
                    config = json.load(f)
            config['ai_api_key'] = self.api_key or ''
            config['gemini_api_key'] = self.gemini_api_key or ''
            config['ai_endpoint'] = self.api_endpoint or 'https://api.openai.com/v1'
            config['ai_provider'] = self.ai_provider
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

    def analyze_results(self, results):
        """
        Analyze scan results using AI.
        Tries Gemini first, falls back to OpenAI-compatible.
        """
        if not results or not results.get('findings'):
            return {'summary': 'No scan results to analyze'}

        findings = results['findings']
        target = results.get('target', 'Unknown')

        # Build analysis prompt from findings
        vuln_count = 0
        info_count = 0
        issues = []

        for category, data in findings.items():
            if isinstance(data, dict):
                if data.get('vulnerable') or data.get('misconfigured') or data.get('exposed'):
                    vuln_count += 1
                    issues.append(f"[CRITICAL] {category}: Vulnerability detected")
                elif data.get('issues') and len(data.get('issues', [])) > 0:
                    info_count += 1
                    for issue in data.get('issues', [])[:3]:
                        issues.append(f"[ISSUE] {category}: {issue}")
                elif data.get('findings') and isinstance(data.get('findings'), list) and len(data['findings']) > 0:
                    vuln_count += 1
                    for finding in data['findings'][:3]:
                        issues.append(f"[FINDING] {category}: {finding}")

        # Risk assessment
        risk_level = 'Low'
        risk_color = 'green'
        if vuln_count >= 3:
            risk_level = 'Critical'
            risk_color = 'red'
        elif vuln_count >= 1:
            risk_level = 'High'
            risk_color = 'yellow'
        elif info_count >= 3:
            risk_level = 'Medium'
            risk_color = 'orange'

        # Build summary
        summary_parts = [
            f"Target: {target}",
            f"Risk Level: {risk_level}",
            f"Vulnerabilities Found: {vuln_count}",
            f"Informational Issues: {info_count}",
            "",
            "Key Findings:",
        ]
        for issue in issues[:15]:
            summary_parts.append(f"  - {issue}")

        if not issues:
            summary_parts.append("  - No significant vulnerabilities detected")

        summary_parts.extend([
            "",
            "Recommendations:",
        ])

        if vuln_count > 0:
            summary_parts.append("  - IMMEDIATE ACTION: Address critical vulnerabilities")
            summary_parts.append("  - Validate all findings manually before taking action")
            summary_parts.append("  - Check for compensating controls")
        if info_count > 0:
            summary_parts.append("  - Review informational findings for security hardening")
            summary_parts.append("  - Implement missing security headers")
            summary_parts.append("  - Review cookie security attributes")

        # Try Gemini AI analysis first
        ai_analysis = None
        if self.gemini_api_key:
            ai_analysis = self._query_gemini(results, issues)
        if not ai_analysis and self.api_key:
            ai_analysis = self._query_openai(results, issues)

        if ai_analysis:
            summary_parts.extend(["", "AI-Powered Deep Analysis:", ai_analysis])

        return {
            'summary': '\n'.join(summary_parts),
            'risk_level': risk_level,
            'vulnerability_count': vuln_count,
            'info_count': info_count,
            'issues': issues,
            'ai_analysis': ai_analysis
        }

    def _query_gemini(self, results, issues):
        """
        Query Gemini API for deep vulnerability analysis.
        Uses Gemini 1.5 Flash for speed + Gemini Pro for depth.
        """
        try:
            api_key = self.gemini_api_key
            if not api_key:
                return None

            # Build prompt
            prompt = f"""You are an expert cybersecurity analyst. Analyze these vulnerability scan findings and provide:

1. **Risk Severity Assessment** - Rate each finding (Critical/High/Medium/Low/Info)
2. **Attack Vector Analysis** - How each vulnerability can be exploited
3. **Exploit Chain Possibilities** - Which vulnerabilities can be chained together
4. **Remediation Priorities** - What to fix first with specific steps
5. **Proof of Concept Ideas** - Brief PoC concepts for valid findings

Target: {results.get('target', 'Unknown')}
Scan Type: {results.get('scan_type', 'Unknown')}

Findings:
{json.dumps(issues[:25], indent=2)}

Raw Findings Summary:
{json.dumps({k: str(v)[:200] for k, v in results.get('findings', {}).items()}, indent=2)}

Provide a concise, technical analysis with actionable recommendations."""

            # Gemini API endpoint
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 2048,
                    "topP": 0.8,
                    "topK": 40
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"}
                ]
            }

            resp = requests.post(
                url,
                json=payload,
                timeout=60,
                headers={'Content-Type': 'application/json'}
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    if parts:
                        return parts[0].get('text', '')
            else:
                return f"Gemini API error: {resp.status_code}"

        except requests.exceptions.Timeout:
            return "Gemini API: Request timed out (try again)"
        except Exception as e:
            return f"Gemini API unavailable: {str(e)[:80]}"

        return None

    def _query_openai(self, results, issues):
        """
        Query OpenAI-compatible endpoint for deep analysis.
        """
        try:
            if not self.api_key:
                return None

            prompt = f"""Analyze these security scan findings and provide:
1. Risk severity assessment
2. Attack vector analysis
3. Remediation priorities
4. Potential exploit chains

Findings:
{json.dumps(issues[:20], indent=2)}

Provide a concise technical analysis."""

            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            payload = {
                'model': 'gpt-4',
                'messages': [
                    {'role': 'system', 'content': 'You are a cybersecurity expert analyzing vulnerability scan results. Provide technical, actionable analysis.'},
                    {'role': 'user', 'content': prompt}
                ],
                'max_tokens': 1000,
                'temperature': 0.3
            }

            resp = requests.post(
                f"{self.api_endpoint}/chat/completions",
                headers=headers,
                json=payload,
                timeout=30
            )

            if resp.status_code == 200:
                data = resp.json()
                return data.get('choices', [{}])[0].get('message', {}).get('content', '')

        except Exception as e:
            return f"AI analysis unavailable: {str(e)[:50]}"

        return None

    def ai_chat(self, message, context=None):
        """
        Interactive AI chat for security questions.
        Uses Gemini API for intelligent responses.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return "No Gemini API key configured. Use 'config' command to set it."

        try:
            system_prompt = """You are ZYLON AI, a cybersecurity expert assistant built into the ZYLON FUSION security toolkit.
You help bug bounty hunters and penetration testers with:
- Vulnerability analysis and exploitation guidance
- Payload crafting and bypass techniques
- Reconnaissance methodology
- Report writing for bug bounty submissions
- Security tool usage advice

Always provide technical, actionable responses. Focus on practical exploitation and remediation."""

            if context:
                system_prompt += f"\n\nCurrent scan context:\n{context[:1000]}"

            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

            payload = {
                "contents": [{
                    "parts": [{"text": f"{system_prompt}\n\nUser question: {message}"}]
                }],
                "generationConfig": {
                    "temperature": 0.4,
                    "maxOutputTokens": 2048,
                    "topP": 0.8,
                    "topK": 40
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"}
                ]
            }

            resp = requests.post(
                url,
                json=payload,
                timeout=60,
                headers={'Content-Type': 'application/json'}
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    if parts:
                        return parts[0].get('text', '')
            else:
                return f"Gemini API error: {resp.status_code}"

        except requests.exceptions.Timeout:
            return "Request timed out"
        except Exception as e:
            return f"AI chat error: {str(e)[:80]}"

        return "No response from AI"

    def ai_smart_scan(self, target, scan_results):
        """
        AI-powered smart scan analysis.
        Given initial scan results, AI recommends which additional scans to run
        and identifies the most promising attack vectors.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

        try:
            prompt = f"""You are a bug bounty hunter analyzing initial reconnaissance results.
Based on these findings, recommend the NEXT scans to run and WHY.

Target: {target}

Initial Findings:
{json.dumps({k: str(v)[:300] for k, v in scan_results.items()}, indent=2)}

Available ZYLON scan modules:
- Scan 9: SQL Injection
- Scan 10: XSS
- Scan 13: CORS
- Scan 14: Open Redirect
- Scan 15: CRLF Injection
- Scan 30: SSRF
- Scan 31: SSTI
- Scan 32: Path Traversal/LFI
- Scan 33: XXE
- Scan 36: Prototype Pollution
- Scan 38: HTTP Request Smuggling
- Scan 40: JWT
- Scan 76: Username Enumeration
- Scan 77: Email Security (DMARC/DKIM/SPF)
- Scan 78: CSRF Token Detection
- Scan 79: Framework Detection
- Scan 80: Client-Side JS Library Vulns
- Scan 81: 403 Bypass
- Scan 82: Cross-Domain Discovery
- Scan 83: CVE-to-Exploit Lookup

Respond with:
1. Top 5 recommended scans with reasons
2. Most promising attack vectors
3. Potential vulnerability chains
4. Specific payloads to try based on the tech stack detected"""

            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 2048,
                    "topP": 0.8,
                    "topK": 40
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"}
                ]
            }

            resp = requests.post(
                url,
                json=payload,
                timeout=60,
                headers={'Content-Type': 'application/json'}
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    if parts:
                        return parts[0].get('text', '')

        except Exception:
            pass

        return None

    def ai_generate_payload(self, vuln_type, context):
        """
        AI-powered payload generation.
        Given a vulnerability type and context, generate custom payloads.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

        try:
            prompt = f"""You are a security researcher generating test payloads for authorized bug bounty testing.
Vulnerability type: {vuln_type}
Context: {context}

Generate 10 specific test payloads for this vulnerability type tailored to the context.
For each payload, explain what it tests and the expected behavior if vulnerable.
Format as a numbered list."""

            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }],
                "generationConfig": {
                    "temperature": 0.5,
                    "maxOutputTokens": 2048,
                    "topP": 0.9,
                    "topK": 40
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"}
                ]
            }

            resp = requests.post(
                url,
                json=payload,
                timeout=60,
                headers={'Content-Type': 'application/json'}
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    if parts:
                        return parts[0].get('text', '')

        except Exception:
            pass

        return None

    def ai_write_report(self, target, findings):
        """
        AI-powered bug bounty report generation.
        Creates a professional vulnerability report for submission.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

        try:
            prompt = f"""You are writing a professional bug bounty vulnerability report.
Generate a complete, submission-ready report following standard bug bounty format.

Target: {target}

Vulnerability Findings:
{json.dumps(findings, indent=2, default=str)[:3000]}

Format:
# [Vulnerability Title]
## Severity: [Critical/High/Medium/Low]
## Description
[Clear description of the vulnerability]
## Steps to Reproduce
1. [Step 1]
2. [Step 2]
...
## Impact
[Business impact assessment]
## Remediation
[Specific fix recommendations]
## References
[Relevant CVEs, CWEs, or documentation]"""

            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"

            payload_req = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 4096,
                    "topP": 0.8,
                    "topK": 40
                },
                "safetySettings": [
                    {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                    {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_ONLY_HIGH"}
                ]
            }

            resp = requests.post(
                url,
                json=payload_req,
                timeout=60,
                headers={'Content-Type': 'application/json'}
            )

            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get('candidates', [])
                if candidates:
                    parts = candidates[0].get('content', {}).get('parts', [])
                    if parts:
                        return parts[0].get('text', '')

        except Exception:
            pass

        return None
