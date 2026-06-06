#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Subdomain Takeover Advanced Engine
=========================================================
Fused from: SubOver (https://github.com/Ice3man543/SubOver)
           + subdomain-takeover (0x94)
           + Custom Zylon Techniques
Capabilities:
  - 30+ service detection for subdomain takeover
  - CNAME-based validation
  - DNS resolution verification
  - Response body pattern matching
  - Multi-threaded scanning
  - Vulnerability severity scoring
  - Service-specific verification
  - Mass subdomain scanning from file
  - Integration with subdomain discovery
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import json
import time
import threading
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    COMMON_DIRS, DEFAULT_TIMEOUT, MAX_THREADS, USER_AGENTS
)
from core.shared_infra import shared_session, regex_cache

# ============================================================================
# ANSI COLOR CODES (Termux-compatible)
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

# ============================================================================
# ADVANCED TAKEOVER SIGNATURES (30+ services)
# ============================================================================

TAKEOVER_ADVANCED_SIGNATURES = {
    # Cloud / CDN Services
    "GitHub Pages": {
        "cname": ["github.io", "githubusercontent.com"],
        "response": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)"],
        "status": [404],
        "severity": "High",
        "verification": "Create a GitHub repository with the subdomain name",
    },
    "Heroku": {
        "cname": ["herokuapp.com", "herokussl.com"],
        "response": ["No such app", "herokucdn", "There's nothing here"],
        "status": [404],
        "severity": "High",
        "verification": "Create a Heroku app with the subdomain name",
    },
    "AWS S3 Bucket": {
        "cname": ["s3.amazonaws.com", "s3-website", "aws.com"],
        "response": ["NoSuchBucket", "The specified bucket does not exist", "Code: NoSuchBucket"],
        "status": [404],
        "severity": "Critical",
        "verification": "Create an S3 bucket with the subdomain name",
    },
    "AWS CloudFront": {
        "cname": ["cloudfront.net"],
        "response": ["Bad Request", "ERROR: The request could not be satisfied"],
        "status": [400, 403],
        "severity": "High",
        "verification": "Create a CloudFront distribution pointing to the domain",
    },
    "Shopify": {
        "cname": ["shopify.com", "myshopify.com"],
        "response": ["Sorry, this shop is currently unavailable", "Only one step left!"],
        "status": [410, 404],
        "severity": "High",
        "verification": "Create a Shopify store with the subdomain name",
    },
    "Tumblr": {
        "cname": ["tumblr.com"],
        "response": ["Whatever you were looking for doesn't currently exist", "Whatever you were looking for doesn't currently exist"],
        "status": [404],
        "severity": "High",
        "verification": "Create a Tumblr blog with the subdomain name",
    },
    "WordPress": {
        "cname": ["wordpress.com"],
        "response": ["Do you want to register", "wordpress.com is no longer available"],
        "status": [200, 404],
        "severity": "Medium",
        "verification": "Register a WordPress site with the subdomain name",
    },
    "Teamwork": {
        "cname": ["teamwork.com"],
        "response": ["Oops - We didn't find your site", "teamwork.com site not found"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Teamwork project with the subdomain name",
    },
    "Help Scout": {
        "cname": ["helpscout.net"],
        "response": ["No settings were found for this company", "Help Scout"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Help Scout account with the subdomain name",
    },
    "Cargo": {
        "cname": ["cargocollective.com"],
        "response": ["If you're moving your domain away from Cargo", "This domain is unclaimed"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Cargo site with the subdomain name",
    },
    "Statuspage": {
        "cname": ["statuspage.io"],
        "response": ["You are being redirected", "Statuspage"],
        "status": [301, 302],
        "severity": "Medium",
        "verification": "Create a Statuspage with the subdomain name",
    },
    "Surge": {
        "cname": ["surge.sh"],
        "response": ["project not found", "surge.sh"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Surge project with the subdomain name",
    },
    "Bitbucket": {
        "cname": ["bitbucket.io"],
        "response": ["Repository not found", "bitbucket.io"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Bitbucket repository with the subdomain name",
    },
    "Intercom": {
        "cname": ["intercom.help"],
        "response": ["This page is reserved for artistic dogs", "Intercom"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create an Intercom help center with the subdomain name",
    },
    "Webflow": {
        "cname": ["webflow.io"],
        "response": ["The page you're looking for doesn't exist or has been moved", "webflow.io"],
        "status": [404],
        "severity": "High",
        "verification": "Create a Webflow site with the subdomain name",
    },
    "Readme": {
        "cname": ["readme.io"],
        "response": ["Project doesnt exist", "readme.io"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Readme project with the subdomain name",
    },
    "Fly": {
        "cname": ["fly.dev"],
        "response": ["404 Not Found", "fly.dev"],
        "status": [404],
        "severity": "Medium",
        "verification": "Deploy a Fly app with the subdomain name",
    },
    "Vercel": {
        "cname": ["vercel.app", "now.sh"],
        "response": ["The deployment could not be found", "VERCEL", "This deployment does not exist"],
        "status": [404],
        "severity": "High",
        "verification": "Create a Vercel project with the subdomain name",
    },
    "Netlify": {
        "cname": ["netlify.app", "netlify.com"],
        "response": ["Not Found", "netlify", "DEPLOY_NOT_FOUND"],
        "status": [404],
        "severity": "High",
        "verification": "Create a Netlify site with the subdomain name",
    },
    "Pantheon": {
        "cname": ["pantheon.io"],
        "response": ["404 error unknown site", "Pantheon"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Pantheon site with the subdomain name",
    },
    "Zendesk": {
        "cname": ["zendesk.com"],
        "response": ["Help Center Closed", "Zendesk", "this Help Center no longer exists"],
        "status": [404],
        "severity": "High",
        "verification": "Create a Zendesk help center with the subdomain name",
    },
    "Freshdesk": {
        "cname": ["freshdesk.com"],
        "response": ["There is no helpdesk here", "Freshdesk"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Freshdesk account with the subdomain name",
    },
    "GitLab": {
        "cname": ["gitlab.io"],
        "response": ["The page you're looking for could not be found", "GitLab Pages"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a GitLab Pages project with the subdomain name",
    },
    "Uservoice": {
        "cname": ["uservoice.com"],
        "response": ["This UserVoice subdomain is currently available", "UserVoice"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a UserVoice forum with the subdomain name",
    },
    # Additional services
    "Azure": {
        "cname": ["azurewebsites.net", "azure.com", "cloudapp.net"],
        "response": ["404 Web Site not found", "Azure", "The resource you are looking for has been removed"],
        "status": [404],
        "severity": "High",
        "verification": "Create an Azure web app with the subdomain name",
    },
    "Google Cloud Storage": {
        "cname": ["storage.googleapis.com", "c.storage.googleapis.com"],
        "response": ["The specified bucket does not exist", "NoSuchBucket"],
        "status": [404],
        "severity": "High",
        "verification": "Create a GCS bucket with the subdomain name",
    },
    "Firebase": {
        "cname": ["firebaseapp.com", "firebase.io"],
        "response": ["The requested URL was not found", "Firebase"],
        "status": [404],
        "severity": "High",
        "verification": "Create a Firebase project with the subdomain name",
    },
    "Fastly": {
        "cname": ["fastly.net", "fastlylb.net"],
        "response": ["Fastly error: unknown domain", "Please check that this domain has been added"],
        "status": [500, 503],
        "severity": "Medium",
        "verification": "Create a Fastly service with the subdomain name",
    },
    "DigitalOcean": {
        "cname": ["digitaloceanspaces.com", "ondigitalocean.app"],
        "response": ["404 Not Found", "DigitalOcean"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a DigitalOcean app with the subdomain name",
    },
    "Stripe": {
        "cname": ["stripe.com"],
        "response": ["The page you requested doesn't exist", "Stripe"],
        "status": [404],
        "severity": "Low",
        "verification": "Create a Stripe payment link with the subdomain name",
    },
    "Pingdom": {
        "cname": ["pingdom.net"],
        "response": ["This page is not available", "pingdom"],
        "status": [404],
        "severity": "Low",
        "verification": "Create a Pingdom status page with the subdomain name",
    },
    "Tilda": {
        "cname": ["tilda.ws"],
        "response": ["Domain has been assigned", "tilda"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Tilda site with the subdomain name",
    },
    "UptimeRobot": {
        "cname": ["stats.uptimerobot.com"],
        "response": ["page not found", "UptimeRobot"],
        "status": [404],
        "severity": "Low",
        "verification": "Create an UptimeRobot status page with the subdomain name",
    },
    "SmartJobBoard": {
        "cname": ["smartjobboard.com"],
        "response": ["This job board website is either expired or its domain is unclaimed"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a SmartJobBoard with the subdomain name",
    },
    "Wix": {
        "cname": ["wix.com", "editor.wix.com"],
        "response": ["This domain is not connected to a website", "wix"],
        "status": [404],
        "severity": "Medium",
        "verification": "Create a Wix site with the subdomain name",
    },
}

# Severity scoring weights
SEVERITY_SCORES = {
    "Critical": 10,
    "High": 7,
    "Medium": 4,
    "Low": 1,
}


class TakeoverAdvancedEngine:
    """Subdomain Takeover Advanced Engine - Fused from SubOver + 0x94 + Custom Techniques"""

    def __init__(self, target_url=None, headers=None, cookies=None, timeout=DEFAULT_TIMEOUT,
                 threads=MAX_THREADS, proxy=None):
        self.target_url = target_url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = shared_session
        # SSL verification handled by shared_session
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    # ========================================================================
    # CNAME VERIFICATION
    # ========================================================================

    def verify_cname(self, domain):
        """Verify CNAME record for a domain

        Returns CNAME target if found, None otherwise.
        """
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cname_target = str(rdata.target).rstrip('.')
                return cname_target
        except dns.resolver.NXDOMAIN:
            self._print(f"  [-] CNAME: {domain} -> NXDOMAIN", YELLOW)
        except dns.resolver.NoAnswer:
            self._print(f"  [-] CNAME: {domain} -> No CNAME record", YELLOW)
        except dns.resolver.Timeout:
            self._print(f"  [-] CNAME: {domain} -> Timeout", YELLOW)
        except Exception:
            # Fallback: try socket resolution
            try:
                socket.getaddrinfo(domain, None)
                # Domain resolves but no CNAME - might be A record
            except socket.gaierror:
                # Domain doesn't resolve at all - potential takeover
                return "__NO_RESOLUTION__"
        return None

    # ========================================================================
    # RESPONSE BODY VERIFICATION
    # ========================================================================

    def verify_response(self, domain, service):
        """Verify subdomain takeover via response body pattern matching

        Args:
            domain: Subdomain to check
            service: Service name to verify against
        Returns:
            dict with verification results
        """
        result = {
            "domain": domain,
            "service": service,
            "vulnerable": False,
            "status_code": None,
            "response_match": None,
            "error": None,
        }

        sig = TAKEOVER_ADVANCED_SIGNATURES.get(service)
        if not sig:
            return result

        # Try HTTP and HTTPS
        for scheme in ['https', 'http']:
            try:
                url = f"{scheme}://{domain}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False, verify=False)
                result["status_code"] = resp.status_code

                # Check response body patterns
                body = resp.text if resp.text else ""
                for pattern in sig.get("response", []):
                    if pattern.lower() in body.lower():
                        result["vulnerable"] = True
                        result["response_match"] = pattern
                        return result

                # Check status code
                if resp.status_code in sig.get("status", []):
                    result["response_match"] = f"status_code_{resp.status_code}"
                    # Status code match alone isn't conclusive, but suspicious
                    if any(p.lower() in body.lower() for p in sig.get("response", [])):
                        result["vulnerable"] = True

            except requests.exceptions.SSLError:
                continue
            except requests.exceptions.ConnectionError:
                # Connection refused / reset - domain may not resolve
                continue
            except Exception:
                continue

        return result

    # ========================================================================
    # CHECK SINGLE SUBDOMAIN
    # ========================================================================

    def check_subdomain(self, subdomain):
        """Check a single subdomain for takeover vulnerability

        Process:
        1. Resolve DNS / Get CNAME
        2. Match CNAME to known service
        3. Verify via HTTP response
        4. Score severity
        """
        self._print(f"  [*] Checking: {subdomain}", CYAN)

        result = {
            "subdomain": subdomain,
            "vulnerable": False,
            "findings": [],
            "details": {
                "cname": None,
                "service": None,
                "severity": None,
                "severity_score": 0,
                "verification": None,
                "dns_resolves": False,
            },
            "scan_type": "subdomain_takeover_check",
        }

        # Step 1: Get CNAME
        cname = self.verify_cname(subdomain)
        result["details"]["cname"] = cname

        if cname == "__NO_RESOLUTION__":
            # Domain doesn't resolve - check if it has a dangling CNAME
            result["findings"].append({
                "type": "dns_no_resolution",
                "severity": "Low",
                "description": f"Subdomain {subdomain} does not resolve (potential dangling DNS)",
            })
            result["details"]["dns_resolves"] = False
        elif cname:
            result["details"]["dns_resolves"] = True
            self._print(f"  [+] CNAME: {subdomain} -> {cname}", GREEN)

            # Step 2: Match CNAME to known service
            matched_service = None
            for service_name, service_sig in TAKEOVER_ADVANCED_SIGNATURES.items():
                for cname_pattern in service_sig.get("cname", []):
                    if cname_pattern.lower() in cname.lower():
                        matched_service = service_name
                        break
                if matched_service:
                    break

            if matched_service:
                result["details"]["service"] = matched_service
                self._print(f"  [+] Service matched: {matched_service}", GREEN)

                # Step 3: Verify via HTTP response
                verify_result = self.verify_response(subdomain, matched_service)
                if verify_result.get("vulnerable"):
                    result["vulnerable"] = True
                    severity = TAKEOVER_ADVANCED_SIGNATURES[matched_service].get("severity", "Medium")
                    result["details"]["severity"] = severity
                    result["details"]["severity_score"] = SEVERITY_SCORES.get(severity, 0)
                    result["details"]["verification"] = TAKEOVER_ADVANCED_SIGNATURES[matched_service].get("verification", "")

                    result["findings"].append({
                        "type": "subdomain_takeover",
                        "severity": severity,
                        "service": matched_service,
                        "cname": cname,
                        "response_match": verify_result.get("response_match"),
                        "description": f"SUBDOMAIN TAKEOVER: {subdomain} -> {matched_service} (CNAME: {cname})",
                    })
                    self._print(f"  [!!!] TAKEOVER VULNERABLE: {subdomain} -> {matched_service}", RED)
                else:
                    result["findings"].append({
                        "type": "service_cname_no_takeover",
                        "severity": "Info",
                        "service": matched_service,
                        "cname": cname,
                        "description": f"CNAME points to {matched_service} but takeover not confirmed",
                    })
                    self._print(f"  [-] CNAME points to {matched_service} but no takeover pattern found", YELLOW)
            else:
                result["findings"].append({
                    "type": "unknown_cname",
                    "severity": "Info",
                    "cname": cname,
                    "description": f"CNAME points to {cname} - no known takeover service match",
                })
        else:
            # No CNAME but domain might still resolve via A record
            try:
                socket.getaddrinfo(subdomain, None)
                result["details"]["dns_resolves"] = True
            except socket.gaierror:
                result["details"]["dns_resolves"] = False

        return result

    # ========================================================================
    # MASS CHECKING
    # ========================================================================

    def mass_check(self, subdomains):
        """Mass check multiple subdomains for takeover

        Args:
            subdomains: List of subdomains to check, or path to file
        """
        # Load from file if string path provided
        if isinstance(subdomains, str) and os.path.isfile(subdomains):
            loaded_subdomains = []
            try:
                with open(subdomains, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            loaded_subdomains.append(line)
                self._print(f"  [+] Loaded {len(loaded_subdomains)} subdomains from file", GREEN)
                subdomains = loaded_subdomains
            except Exception as e:
                self._print(f"  [-] Error loading subdomains file: {e}", RED)
                return {"vulnerable": False, "findings": [], "details": {}, "scan_type": "mass_check"}
        elif not isinstance(subdomains, list):
            subdomains = [subdomains]

        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  TAKEOVER ENGINE - Mass Scan{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Subdomains: {len(subdomains)}{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "subdomains_checked": 0,
                "vulnerable_subdomains": [],
                "services_found": [],
                "total_subdomains": len(subdomains),
            },
            "scan_type": "subdomain_takeover_mass",
        }

        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
            futures = {executor.submit(self.check_subdomain, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                result["details"]["subdomains_checked"] += 1
                try:
                    r = future.result()
                    if r.get("vulnerable"):
                        result["vulnerable"] = True
                        result["details"]["vulnerable_subdomains"].append(r["subdomain"])
                        for finding in r.get("findings", []):
                            if finding.get("type") == "subdomain_takeover":
                                result["details"]["services_found"].append(r["details"].get("service"))
                    result["findings"].extend(r.get("findings", []))
                except Exception:
                    pass

        # Summary
        self._print(f"\n  [*] Checked: {result['details']['subdomains_checked']}/{result['details']['total_subdomains']}", CYAN)
        self._print(f"  [*] Vulnerable: {len(result['details']['vulnerable_subdomains'])}", CYAN)

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, domain, scan_type='full', **kwargs):
        """Main entry point for Takeover Advanced Engine

        Args:
            domain: Target domain or subdomain
            scan_type: Type of scan to run
                - 'check': Check single subdomain
                - 'mass': Mass check from list
                - 'cname': CNAME verification only
                - 'verify': Service-specific verification
                - 'full': Full scan (CNAME + Response + Severity)
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  SUBDOMAIN TAKEOVER ADVANCED ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: SubOver + 0x94 + Custom Zylon{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  30+ Service Detection | Severity Scoring{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        if scan_type == 'check':
            return self.check_subdomain(domain)
        elif scan_type == 'mass':
            subdomains = kwargs.get('subdomains', [domain])
            return self.mass_check(subdomains)
        elif scan_type == 'cname':
            cname = self.verify_cname(domain)
            return {
                'vulnerable': cname is not None and cname != "__NO_RESOLUTION__",
                'findings': [{"type": "cname", "domain": domain, "cname": cname}],
                'details': {"domain": domain, "cname": cname},
                'scan_type': 'cname_verify',
            }
        elif scan_type == 'verify':
            service = kwargs.get('service')
            if not service:
                return {
                    'vulnerable': False,
                    'findings': [],
                    'details': {"error": "Service name required for verify scan"},
                    'scan_type': 'service_verify',
                }
            return self.verify_response(domain, service)
        elif scan_type == 'full':
            # Full scan: check the domain + common subdomains
            result = {
                "vulnerable": False,
                "findings": [],
                "details": {
                    "domain": domain,
                    "subdomains_checked": 0,
                    "vulnerable_subdomains": [],
                    "services_found": [],
                },
                "scan_type": "subdomain_takeover_full",
            }

            # Common subdomains to check
            common_subs = [
                f"www.{domain}", f"mail.{domain}", f"ftp.{domain}",
                f"admin.{domain}", f"dev.{domain}", f"staging.{domain}",
                f"api.{domain}", f"app.{domain}", f"blog.{domain}",
                f"shop.{domain}", f"cdn.{domain}", f"test.{domain}",
                f"portal.{domain}", f"vpn.{domain}", f"remote.{domain}",
                f"old.{domain}", f"beta.{domain}", f"docs.{domain}",
                f"status.{domain}", f"support.{domain}",
            ]

            # Add any extra subdomains from kwargs
            extra_subs = kwargs.get('subdomains', [])
            if isinstance(extra_subs, list):
                common_subs.extend(extra_subs)

            # Remove duplicates
            common_subs = list(set(common_subs))

            mass_result = self.mass_check(common_subs)
            result["vulnerable"] = mass_result.get("vulnerable", False)
            result["findings"] = mass_result.get("findings", [])
            result["details"]["subdomains_checked"] = mass_result.get("details", {}).get("subdomains_checked", 0)
            result["details"]["vulnerable_subdomains"] = mass_result.get("details", {}).get("vulnerable_subdomains", [])
            result["details"]["services_found"] = mass_result.get("details", {}).get("services_found", [])

            return result

        return {
            'vulnerable': False,
            'findings': [],
            'details': {"error": f"Unknown scan type: {scan_type}"},
            'scan_type': scan_type,
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION (ZYLON FUSION INTEGRATION)
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = TakeoverAdvancedEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
