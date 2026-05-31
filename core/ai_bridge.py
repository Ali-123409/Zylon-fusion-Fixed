"""
ZYLON FUSION v2.3 - AI Bridge Module
AI-powered vulnerability analysis using Google Gemini API
Uses X-goog-api-key header for authentication (more secure than URL param)
Supports gemini-flash-latest model with automatic fallback
Termux Non-Root Compatible
"""

import os
import json
import time
import requests
from core.var import HOME_DIR, DEFAULT_TIMEOUT

# Gemini API Configuration
GEMINI_API_KEY = __import__('base64').b64decode('QVEuQWI4Uk42THBaVTc0eDJfQ0NUQTllM3BZclRsM1NPSVBCckNUZmZlbUVCZ01oSlRjMHc=').decode()
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
GEMINI_MODEL = "gemini-flash-latest"
GEMINI_FALLBACK_MODEL = "gemini-2.0-flash"
GEMINI_MAX_RETRIES = 2
GEMINI_RETRY_DELAY = 5  # seconds between retries on rate limit


class AIBridge:
    """
    AI Bridge for ZYLON FUSION v2.3
    Provides AI-powered vulnerability analysis via Google Gemini API
    
    Authentication: X-goog-api-key header (more secure than URL param)
    Primary Model: gemini-flash-latest (auto-updates to latest Flash)
    Fallback: gemini-2.0-flash
    """

    def __init__(self):
        self.config_dir = os.path.join(HOME_DIR, '.zylon')
        self.config_file = os.path.join(self.config_dir, 'config.json')
        self.api_key = None
        self.gemini_api_key = None
        self.api_endpoint = None
        self.ai_provider = 'gemini'  # 'gemini' or 'openai'
        self.model = GEMINI_MODEL
        self.fallback_model = GEMINI_FALLBACK_MODEL
        self._request_count = 0
        self._last_error = None
        self._load_config()

    def _load_config(self):
        """Load AI configuration from ~/.zylon/config.json, fallback to hardcoded key"""
        # Start with hardcoded default key
        self.gemini_api_key = GEMINI_API_KEY
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file) as f:
                    config = json.load(f)
                self.api_key = config.get('ai_api_key', '')
                # Config file key overrides hardcoded default
                if config.get('gemini_api_key', ''):
                    self.gemini_api_key = config.get('gemini_api_key', '')
                self.api_endpoint = config.get('ai_endpoint', 'https://api.openai.com/v1')
                self.ai_provider = config.get('ai_provider', 'gemini')
                self.model = config.get('gemini_model', GEMINI_MODEL)
        except Exception:
            pass

    def set_gemini_key(self, api_key):
        """Configure Gemini API key and save to config"""
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
        """Save configuration to ~/.zylon/config.json"""
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file) as f:
                    config = json.load(f)
            config['ai_api_key'] = self.api_key or ''
            config['gemini_api_key'] = self.gemini_api_key or ''
            config['ai_endpoint'] = self.api_endpoint or 'https://api.openai.com/v1'
            config['ai_provider'] = self.ai_provider
            config['gemini_model'] = self.model
            os.makedirs(self.config_dir, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass

    # ========================================================================
    # CORE GEMINI API CALL - Uses X-goog-api-key header
    # ========================================================================

    def _call_gemini(self, prompt, max_tokens=2048, temperature=0.3, retries=GEMINI_MAX_RETRIES):
        """
        Core method to call Gemini API.
        Uses X-goog-api-key header instead of URL parameter for better security.
        Automatically retries on rate limits with exponential backoff.
        Falls back to secondary model if primary fails.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None, "No Gemini API key configured"

        models_to_try = [self.model, self.fallback_model]

        for model_name in models_to_try:
            url = f"{GEMINI_BASE_URL}/{model_name}:generateContent"

            headers = {
                'Content-Type': 'application/json',
                'X-goog-api-key': api_key,  # Header-based auth (more secure)
            }

            payload = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }],
                "generationConfig": {
                    "temperature": temperature,
                    "maxOutputTokens": max_tokens,
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

            for attempt in range(retries + 1):
                try:
                    self._request_count += 1
                    resp = requests.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=90
                    )

                    if resp.status_code == 200:
                        data = resp.json()
                        candidates = data.get('candidates', [])
                        if candidates:
                            parts = candidates[0].get('content', {}).get('parts', [])
                            if parts:
                                self._last_error = None
                                return parts[0].get('text', ''), None
                        return None, "Empty response from Gemini"

                    elif resp.status_code == 429:
                        # Rate limited - retry with backoff
                        if attempt < retries:
                            wait_time = GEMINI_RETRY_DELAY * (2 ** attempt)
                            self._last_error = f"Rate limited, retrying in {wait_time}s..."
                            time.sleep(wait_time)
                            continue
                        else:
                            # Try fallback model
                            self._last_error = f"Rate limited on {model_name}"
                            break  # Break to try next model

                    elif resp.status_code == 400:
                        error_msg = resp.json().get('error', {}).get('message', 'Bad request')
                        if "location is not supported" in error_msg:
                            self._last_error = "Gemini API not available in your region"
                            return None, self._last_error
                        self._last_error = f"Bad request: {error_msg[:100]}"
                        break  # Don't retry bad requests

                    elif resp.status_code == 403:
                        self._last_error = "Invalid Gemini API key"
                        return None, self._last_error

                    else:
                        self._last_error = f"Gemini API error: {resp.status_code}"
                        if attempt < retries:
                            time.sleep(GEMINI_RETRY_DELAY)
                            continue
                        break

                except requests.exceptions.Timeout:
                    self._last_error = "Gemini API: Request timed out"
                    if attempt < retries:
                        time.sleep(GEMINI_RETRY_DELAY)
                        continue
                    break

                except requests.exceptions.ConnectionError:
                    self._last_error = "Gemini API: Connection error"
                    if attempt < retries:
                        time.sleep(GEMINI_RETRY_DELAY * 2)
                        continue
                    break

                except Exception as e:
                    self._last_error = f"Gemini API error: {str(e)[:80]}"
                    if attempt < retries:
                        time.sleep(GEMINI_RETRY_DELAY)
                        continue
                    break

        return None, self._last_error or "All models failed"

    # ========================================================================
    # ANALYZE SCAN RESULTS
    # ========================================================================

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
            prompt = f"""You are an expert cybersecurity analyst. Analyze these vulnerability scan findings and provide:

1. **Risk Severity Assessment** - Rate each finding (Critical/High/Medium/Low/Info)
2. **Attack Vector Analysis** - How each vulnerability can be exploited
3. **Exploit Chain Possibilities** - Which vulnerabilities can be chained together
4. **Remediation Priorities** - What to fix first with specific steps
5. **Proof of Concept Ideas** - Brief PoC concepts for valid findings

Target: {target}
Scan Type: {results.get('scan_type', 'Unknown')}

Findings:
{json.dumps(issues[:25], indent=2)}

Raw Findings Summary:
{json.dumps({k: str(v)[:200] for k, v in findings.items()}, indent=2)}

Provide a concise, technical analysis with actionable recommendations."""

            ai_analysis, error = self._call_gemini(prompt, max_tokens=2048, temperature=0.3)
            if error and not ai_analysis:
                summary_parts.append(f"\n[AI Analysis unavailable: {error}]")

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

    # ========================================================================
    # OPENAI FALLBACK
    # ========================================================================

    def _query_openai(self, results, issues):
        """Query OpenAI-compatible endpoint as fallback"""
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

    # ========================================================================
    # AI CHAT - Interactive Security Assistant
    # ========================================================================

    def ai_chat(self, message, context=None):
        """
        Interactive AI chat for security questions.
        Uses Gemini API with X-goog-api-key header.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return "No Gemini API key configured. Use 'config' command to set it."

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

        prompt = f"{system_prompt}\n\nUser question: {message}"

        response, error = self._call_gemini(prompt, max_tokens=2048, temperature=0.4)

        if response:
            return response
        if error:
            return f"AI chat error: {error}"
        return "No response from AI"

    # ========================================================================
    # AI SMART SCAN - Recommends next steps based on initial recon
    # ========================================================================

    def ai_smart_scan(self, target, scan_results):
        """
        AI-powered smart scan analysis.
        Given initial scan results, AI recommends which additional scans to run
        and identifies the most promising attack vectors.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

        prompt = f"""You are a bug bounty hunter analyzing initial reconnaissance results.
Based on these findings, recommend the NEXT scans to run and WHY.

Target: {target}

Initial Findings:
{json.dumps({k: str(v)[:300] for k, v in scan_results.items()}, indent=2)}

Available ZYLON scan modules:
- Scan 0: Full Recon
- Scan 9: SQL Injection
- Scan 10: XSS
- Scan 11: Directory Brute Force
- Scan 13: CORS
- Scan 14: Open Redirect
- Scan 15: CRLF Injection
- Scan 23: Deep Web Crawler
- Scan 24: Parameter Mining
- Scan 25: Wayback URLs
- Scan 30: SSRF
- Scan 31: SSTI
- Scan 32: Path Traversal/LFI
- Scan 33: XXE
- Scan 36: Prototype Pollution
- Scan 38: HTTP Request Smuggling
- Scan 40: JWT Scanner
- Scan 44: API Fuzzer
- Scan 45: Rate Limit Tester
- Scan 50-55: Origin IP Finder
- Scan 56: GraphQL
- Scan 57: DOM XSS
- Scan 76: Username Enumeration
- Scan 77: Email Security (DMARC/DKIM/SPF)
- Scan 78: CSRF Token Detection
- Scan 79: Framework Detection
- Scan 80: Client-Side JS Library Vulns
- Scan 81: 403 Bypass
- Scan 82: Cross-Domain Discovery
- Scan 83: CVE-to-Exploit Lookup
- Scan 84: Subdomain Brute Force (Active DNS)
- Scan 85: Directory Brute Force (Async High-Speed)

Respond with:
1. Top 5 recommended scans with reasons
2. Most promising attack vectors
3. Potential vulnerability chains
4. Specific payloads to try based on the tech stack detected"""

        response, error = self._call_gemini(prompt, max_tokens=2048, temperature=0.3)
        return response

    # ========================================================================
    # AI PAYLOAD GENERATOR - Context-aware payload crafting
    # ========================================================================

    def ai_generate_payload(self, vuln_type, context):
        """
        AI-powered payload generation.
        Given a vulnerability type and context, generate custom payloads.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

        prompt = f"""You are a security researcher generating test payloads for authorized bug bounty testing.
Vulnerability type: {vuln_type}
Context: {context}

Generate 10 specific test payloads for this vulnerability type tailored to the context.
For each payload, explain what it tests and the expected behavior if vulnerable.
Format as a numbered list."""

        response, error = self._call_gemini(prompt, max_tokens=2048, temperature=0.5)
        return response

    # ========================================================================
    # AI REPORT WRITER - Professional bug bounty reports
    # ========================================================================

    def ai_write_report(self, target, findings):
        """
        AI-powered bug bounty report generation.
        Creates a professional vulnerability report for submission.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

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

        response, error = self._call_gemini(prompt, max_tokens=4096, temperature=0.3)
        return response

    # ========================================================================
    # AI VULN TRIAGE - Prioritize and classify findings
    # ========================================================================

    def ai_triage(self, target, findings_list):
        """
        AI-powered vulnerability triage.
        Classifies findings by severity, groups related issues,
        and identifies which are likely false positives.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

        prompt = f"""You are a senior security analyst performing vulnerability triage.
Classify each finding, identify false positives, and prioritize.

Target: {target}

Findings to Triage:
{json.dumps(findings_list[:30], indent=2, default=str)[:4000]}

For each finding, provide:
1. **Classification**: Confirmed / Likely / Suspected / Likely False Positive / False Positive
2. **Severity**: Critical / High / Medium / Low / Info
3. **Confidence**: High / Medium / Low
4. **Reasoning**: Brief explanation of your classification
5. **Action Required**: Immediate / Short-term / Long-term / No action

Also identify:
- Findings that are likely the same root cause
- Findings that can be chained together
- Findings that are likely false positives due to WAF/security controls"""

        response, error = self._call_gemini(prompt, max_tokens=3000, temperature=0.2)
        return response

    # ========================================================================
    # AI RECON ADVISOR - Suggests recon strategy
    # ========================================================================

    def ai_recon_advisor(self, target, recon_data):
        """
        AI-powered reconnaissance advisor.
        Given partial recon results, suggests the most effective
        next steps for maximum bug bounty impact.
        """
        api_key = self.gemini_api_key
        if not api_key:
            return None

        prompt = f"""You are an expert bug bounty recon advisor.
Based on the reconnaissance data below, suggest the most effective next steps.

Target: {target}

Reconnaissance Data:
{json.dumps({k: str(v)[:300] for k, v in recon_data.items()}, indent=2)}

Provide:
1. **Attack Surface Assessment** - What's exposed and interesting
2. **High-Value Targets** - Which subdomains/paths likely have bugs
3. **Technology-Specific Attacks** - Based on detected tech stack
4. **Recommended Scan Priority** - Which ZYLON scans to run next
5. **Custom Wordlist Suggestions** - What to add to wordlists for this target
6. **Potential Bug Classes** - Most likely vulnerability types for this target"""

        response, error = self._call_gemini(prompt, max_tokens=2048, temperature=0.3)
        return response

    # ========================================================================
    # UTILITY METHODS
    # ========================================================================

    def get_status(self):
        """Get AI Bridge status information"""
        return {
            'provider': self.ai_provider,
            'model': self.model,
            'fallback_model': self.fallback_model,
            'api_key_set': bool(self.gemini_api_key),
            'openai_key_set': bool(self.api_key),
            'total_requests': self._request_count,
            'last_error': self._last_error,
        }

    def test_connection(self):
        """Test Gemini API connection and return status"""
        if not self.gemini_api_key:
            return False, "No API key configured"

        response, error = self._call_gemini(
            "Respond with exactly: ZYLON_AI_CONNECTED",
            max_tokens=20,
            temperature=0.0,
            retries=0
        )

        if response:
            return True, f"Connected to {self.model}"
        return False, error or "Connection failed"
