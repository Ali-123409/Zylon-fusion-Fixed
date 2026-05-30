"""
ZYLON FUSION - AI Bridge Module
Future AI integration hooks for automated vulnerability analysis
Termux Non-Root Compatible
"""

import os
import json
from core.var import HOME_DIR


class AIBridge:
    """
    AI Bridge for ZYLON FUSION
    Provides hooks for AI-powered vulnerability analysis
    Supports: OpenAI, local LLMs, and custom AI endpoints
    """

    def __init__(self):
        self.config_dir = os.path.join(HOME_DIR, '.zylon')
        self.config_file = os.path.join(self.config_dir, 'config.json')
        self.api_key = None
        self.api_endpoint = None
        self._load_config()

    def _load_config(self):
        """Load AI configuration"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file) as f:
                    config = json.load(f)
                self.api_key = config.get('ai_api_key', '')
                self.api_endpoint = config.get('ai_endpoint', 'https://api.openai.com/v1')
        except Exception:
            pass

    def analyze_results(self, results):
        """
        Analyze scan results using AI
        Currently returns a structured analysis template.
        In future: will connect to LLM for intelligent analysis.
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

        # Try AI-powered analysis if API key is configured
        if self.api_key:
            ai_analysis = self._query_ai(results, issues)
            if ai_analysis:
                summary_parts.extend(["", "AI-Powered Deep Analysis:", ai_analysis])

        return {
            'summary': '\n'.join(summary_parts),
            'risk_level': risk_level,
            'vulnerability_count': vuln_count,
            'info_count': info_count,
            'issues': issues,
        }

    def _query_ai(self, results, issues):
        """
        Query AI endpoint for deep analysis
        Placeholder for future AI integration
        """
        try:
            import requests
            if not self.api_key:
                return None

            # Build prompt
            prompt = f"""Analyze these security scan findings and provide:
1. Risk severity assessment
2. Attack vector analysis
3. Remediation priorities
4. Potential exploit chains

Findings:
{json.dumps(issues[:20], indent=2)}

Provide a concise technical analysis."""

            # OpenAI-compatible endpoint
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

    def set_api_key(self, api_key, endpoint=None):
        """Configure AI API key"""
        self.api_key = api_key
        if endpoint:
            self.api_endpoint = endpoint

        # Save to config
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file) as f:
                    config = json.load(f)
            config['ai_api_key'] = api_key
            if endpoint:
                config['ai_endpoint'] = endpoint
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass
