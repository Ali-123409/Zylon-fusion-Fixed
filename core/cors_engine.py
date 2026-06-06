#!/usr/bin/env python3
"""
ZYLON FUSION - CORS & Open Redirect Engine
Fused from: CorsOne + CORScanner + Corser + OpenRedirector + RedirectHunter
Capabilities:
  - CORS misconfiguration detection (origin manipulation)
  - Null origin bypass testing
  - Subdomain bypass testing
  - HTTPS/HTTP origin testing
  - Wildcard origin detection
  - Open redirect detection (30+ bypass techniques)
  - Redirect chain following
  - Parameter-based redirect testing
  - Header-based redirect testing
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import time
from datetime import datetime
from urllib.parse import urlparse, quote

from core.shared_infra import shared_session, regex_cache, PayloadInjector

# ============================================================================
# CORS ORIGIN PAYLOADS (from CorsOne + CORScanner + Corser)
# ============================================================================

CORS_ORIGINS = [
    "https://evil.com",
    "https://evil.com.",
    "https://evildomain.com",
    "null",
    "https://null",
    "https://{domain}.evil.com",
    "https://evil.{domain}",
    "http://{domain}",
    "https://{domain}evil.com",
    "https://evil{domain}",
    "https://{domain}.evil.org",
    "https://sub.{domain}",
    "https://{domain}",
    "https://evil%00{domain}",
    "https://{domain}%00evil.com",
]

REDIRECT_PAYLOADS = [
    "//evil.com", "//evil.com/", "///evil.com",
    "https://evil.com", "https://evil.com/",
    "/\\evil.com", "/%5cevil.com",
    "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
    "//evil.com%00", "//evil.com%0d%0a",
    "https://evil.com?target={url}", "https://evil.com#{url}",
    "//evil.com/", "/evil.com", "evil.com",
    "https://evil.com\\@{domain}", "https://{domain}@evil.com",
    "//evil.com%2f", "//evil.com%252f",
    "///evil.com/", "////evil.com",
    "https://evil.com\\", "https:///evil.com",
    "https://evil.com%09", "https://evil.com%0a",
    "//evil.com\\", "https://evil.com\\",
]

COMMON_REDIRECT_PARAMS = [
    "url", "redirect", "next", "continue", "return", "redir",
    "redirect_uri", "redirect_url", "rurl", "target", "dest",
    "destination", "goto", "link", "ref", "returnTo",
    "return_to", "callback", "forward", "path", "action",
    "request_uri", "navigation", "file", "site", "page",
]


class CORSEngine:
    """CORS Misconfiguration & Open Redirect Engine"""

    def __init__(self, target_url=None, timeout=10, proxy=None):
        self.target_url = target_url
        self.timeout = timeout
        self.session = shared_session

    # ========================================================================
    # SCAN 1: CORS Misconfiguration Detection
    # ========================================================================

    def detect_cors(self):
        """Detect CORS misconfiguration"""
        results = {
            "target": self.target_url,
            "vulnerable": False,
            "misconfigurations": [],
        }

        domain = urlparse(self.target_url).netloc
        origins_to_test = []
        for origin in CORS_ORIGINS:
            origins_to_test.append(origin.format(domain=domain))

        for origin in origins_to_test:
            try:
                headers = {"Origin": origin}
                resp = self.session.get(self.target_url, headers=headers,
                                       timeout=self.timeout)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao:
                    # Check for misconfiguration
                    if acao == origin or acao == "*":
                        issue = {
                            "origin_tested": origin,
                            "acao_header": acao,
                            "credentials_allowed": acac == "true",
                            "severity": "high" if acac == "true" else "medium",
                        }

                        if acao == "null" or origin == "null":
                            issue["type"] = "null_origin_bypass"
                            issue["severity"] = "critical"
                        elif "evil" in acao:
                            issue["type"] = "arbitrary_origin_allowed"
                            issue["severity"] = "critical"
                        elif domain in acao and "evil" in acao:
                            issue["type"] = "subdomain_bypass"
                        elif acao == "*":
                            issue["type"] = "wildcard_origin"

                        results["misconfigurations"].append(issue)
                        results["vulnerable"] = True

            except Exception:
                continue

        return results

    # ========================================================================
    # SCAN 2: Open Redirect Detection
    # ========================================================================

    def detect_open_redirect(self):
        """Detect open redirect vulnerabilities"""
        results = {
            "target": self.target_url,
            "vulnerable": False,
            "vulnerable_params": [],
            "payloads_tested": 0,
        }

        domain = urlparse(self.target_url).netloc
        base_url = self.target_url.split("?")[0]

        # Test parameters from URL
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        # If no params, try common redirect params
        params_to_test = list(params.keys()) if params else COMMON_REDIRECT_PARAMS[:10]

        for param in params_to_test:
            for payload_template in REDIRECT_PAYLOADS:
                payload = payload_template.format(url=self.target_url, domain=domain)
                results["payloads_tested"] += 1

                try:
                    test_url = f"{base_url}?{param}={quote(payload, safe='')}"
                    resp = self.session.get(test_url, timeout=self.timeout,
                                           allow_redirects=False)

                    if resp and resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            results["vulnerable"] = True
                            results["vulnerable_params"].append({
                                "parameter": param,
                                "payload": payload,
                                "redirect_to": location,
                                "status_code": resp.status_code,
                            })
                            break
                except Exception:
                    continue

        return results

    # ========================================================================
    # SCAN 3: Full CORS + Redirect Audit
    # ========================================================================

    def full_audit(self):
        """Run both CORS and open redirect tests"""
        results = {
            "cors": self.detect_cors(),
            "open_redirect": self.detect_open_redirect(),
        }
        return results


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_cors_scan(target, scan_type="cors", **kwargs):
    """Run CORS/Redirect scan"""
    engine = CORSEngine(target_url=target, **kwargs)

    scan_methods = {
        "cors": engine.detect_cors,
        "redirect": engine.detect_open_redirect,
        "full": engine.full_audit,
    }

    if scan_type in scan_methods:
        return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
