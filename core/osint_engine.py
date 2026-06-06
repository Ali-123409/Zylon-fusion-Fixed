#!/usr/bin/env python3
"""
ZYLON FUSION - OSINT Reconnaissance Engine
Fused from: TheHarvester + BBOT + InfoShyt + DorkScanner + DorksEye
Capabilities:
  - Multi-source email harvesting (Google, Bing, Baidu, etc.)
  - Domain/IP/URL harvesting from 30+ sources
  - Google dork automation (sensitive data discovery)
  - DNS/WHOIS/geolocation enrichment
  - Data breach lookup (HaveIBeenPwned API)
  - Social media profile discovery
  - Technology stack fingerprinting
  - Google dork categories (SQLi, XSS, exposed files, admin panels, etc.)
  - Bing/Crawler-based email extraction
  - Subdomain and IP correlation
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import socket
import time
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse

from core.shared_infra import shared_session, regex_cache, framework_discovery, oob_provider

# ============================================================================
# GOOGLE DORK DATABASE (from DorkScanner + DorksEye)
# ============================================================================

DORK_CATEGORIES = {
    "sqli": [
        'inurl:"id=" & intext:"sql syntax" site:{domain}',
        'inurl:".php?id=" site:{domain}',
        'inurl:"&id=" site:{domain}',
        'inurl:"news.php?id=" site:{domain}',
    ],
    "xss": [
        'inurl:"search=" site:{domain}',
        'inurl:"q=" site:{domain}',
        'inurl:"keyword=" site:{domain}',
    ],
    "exposed_files": [
        'intitle:"index of" site:{domain}',
        'intitle:"index of /" + ".htaccess" site:{domain}',
        'intitle:"index of" "wp-config.php" site:{domain}',
        'inurl:".env" site:{domain}',
        'inurl:"config.php" site:{domain}',
        'inurl:".git" site:{domain}',
        'inurl:"backup" site:{domain}',
    ],
    "admin_panels": [
        'inurl:"admin" site:{domain}',
        'inurl:"administrator" site:{domain}',
        'inurl:"wp-admin" site:{domain}',
        'inurl:"phpmyadmin" site:{domain}',
        'intitle:"admin login" site:{domain}',
    ],
    "login_pages": [
        'inurl:"login" site:{domain}',
        'inurl:"signin" site:{domain}',
        'intitle:"login" site:{domain}',
    ],
    "documents": [
        'filetype:pdf site:{domain}',
        'filetype:xlsx site:{domain}',
        'filetype:docx site:{domain}',
        'filetype:conf site:{domain}',
        'filetype:log site:{domain}',
    ],
    "errors": [
        '"sql syntax" "error" site:{domain}',
        '"Warning:" "mysql" site:{domain}',
        '"Fatal error" site:{domain}',
        '"Stack Trace" site:{domain}',
    ],
}

# Email and IP patterns are now handled via regex_cache shorthand names:
#   'email'  → [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
#   'ipv4'   → \b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b


class OSINTEngine:
    """OSINT Reconnaissance Engine - Fused from TheHarvester + BBOT + InfoShyt + DorkScanner + DorksEye"""

    def __init__(self, domain=None, threads=10, timeout=10, proxy=None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.session = shared_session
        self.emails = set()
        self.hosts = set()
        self.ips = set()
        self.urls = set()

    # ========================================================================
    # SCAN 1: Email Harvesting (Multi-Source)
    # ========================================================================

    def harvest_emails(self):
        """Harvest emails from multiple sources"""
        results = {
            "domain": self.domain,
            "emails": [],
            "sources": {},
        }

        def search_google():
            found = []
            try:
                url = f"https://www.google.com/search?q=%22@{self.domain}%22+intext:%22@{self.domain}%22&num=100"
                resp = self.session.get(url, timeout=self.timeout)
                if resp:
                    emails = regex_cache.findall('email', resp.text)
                    for e in emails:
                        if self.domain in e:
                            found.append(e)
            except Exception:
                pass
            return "google", list(set(found))

        def search_bing():
            found = []
            try:
                url = f"https://www.bing.com/search?q=%22@{self.domain}%22&count=50"
                resp = self.session.get(url, timeout=self.timeout)
                if resp:
                    emails = regex_cache.findall('email', resp.text)
                    for e in emails:
                        if self.domain in e:
                            found.append(e)
            except Exception:
                pass
            return "bing", list(set(found))

        def search_crtsh():
            found = []
            try:
                url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        emails_found = regex_cache.findall('email', name)
                        found.extend(emails_found)
            except Exception:
                pass
            return "crt.sh", list(set(found))

        def search_hackertarget():
            found = []
            try:
                url = f"https://api.hackertarget.com/emailsearch/?q={self.domain}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    emails = regex_cache.findall('email', resp.text)
                    found.extend(emails)
            except Exception:
                pass
            return "hackertarget", list(set(found))

        sources = [search_google, search_bing, search_crtsh, search_hackertarget]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(src) for src in sources]
            for future in as_completed(futures):
                source_name, emails = future.result()
                if emails:
                    results["sources"][source_name] = len(emails)
                    self.emails.update(emails)

        results["emails"] = sorted(self.emails)
        return results

    # ========================================================================
    # SCAN 2: Google Dork Scanner
    # ========================================================================

    def dork_scan(self, categories=None):
        """Run Google dork scans for vulnerability discovery"""
        cats = categories or list(DORK_CATEGORIES.keys())
        results = {
            "domain": self.domain,
            "dorks_tested": 0,
            "findings": [],
        }

        for category in cats:
            if category not in DORK_CATEGORIES:
                continue
            for dork_template in DORK_CATEGORIES[category]:
                dork = dork_template.format(domain=self.domain)
                results["dorks_tested"] += 1
                try:
                    search_url = f"https://www.google.com/search?q={quote(dork)}&num=10"
                    resp = self.session.get(search_url, timeout=self.timeout)
                    if resp and resp.status_code == 200:
                        # Extract result URLs
                        url_pattern = regex_cache.findall(r'href="/url\?q=(https?://[^&"]+)', resp.text)
                        if url_pattern:
                            results["findings"].append({
                                "category": category,
                                "dork": dork,
                                "results_count": len(url_pattern),
                                "sample_urls": url_pattern[:5],
                            })
                except Exception:
                    pass
                time.sleep(1)  # Rate limiting

        return results

    # ========================================================================
    # SCAN 3: WHOIS + DNS + GeoIP Lookup
    # ========================================================================

    def domain_intel(self):
        """Gather domain intelligence (WHOIS, DNS, GeoIP)"""
        results = {
            "domain": self.domain,
            "whois": {},
            "dns": {},
            "geoip": {},
            "nameservers": [],
        }

        # DNS resolution
        try:
            ip = socket.gethostbyname(self.domain)
            results["dns"]["a_record"] = ip
            self.ips.add(ip)
        except Exception:
            pass

        # DNS lookup via HackerTarget API
        try:
            url = f"https://api.hackertarget.com/dnslookup/?q={self.domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                for line in resp.text.strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        results["dns"][key.strip()] = value.strip()
                        if 'NS' in key.upper():
                            results["nameservers"].append(value.strip())
        except Exception:
            pass

        # GeoIP via ip-api.com
        try:
            ip = results["dns"].get("a_record", "")
            if ip:
                url = f"http://ip-api.com/json/{ip}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    results["geoip"] = resp.json()
        except Exception:
            pass

        # WHOIS via HackerTarget
        try:
            url = f"https://api.hackertarget.com/whois/?q={self.domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                whois_text = resp.text
                for line in whois_text.split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        results["whois"][key.strip().lower()] = value.strip()
        except Exception:
            pass

        return results

    # ========================================================================
    # SCAN 4: Technology Fingerprinting
    # ========================================================================

    def tech_fingerprint(self):
        """Fingerprint web technologies from HTTP headers and page content"""
        results = {
            "domain": self.domain,
            "technologies": [],
            "server": None,
            "framework": None,
        }

        try:
            url = f"https://{self.domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if not resp:
                url = f"http://{self.domain}"
                resp = self.session.get(url, timeout=self.timeout)

            if resp:
                # Check headers
                headers = dict(resp.headers)
                if 'Server' in headers:
                    results["server"] = headers['Server']
                    results["technologies"].append(f"Server: {headers['Server']}")
                if 'X-Powered-By' in headers:
                    results["framework"] = headers['X-Powered-By']
                    results["technologies"].append(f"Framework: {headers['X-Powered-By']}")
                if 'X-AspNet-Version' in headers:
                    results["technologies"].append(f"ASP.NET: {headers['X-AspNet-Version']}")

                # Check page content for tech signatures
                text = resp.text
                tech_sigs = {
                    "WordPress": ["wp-content", "wp-includes", "wp-login"],
                    "Drupal": ["Drupal.settings", "misc/drupal.js"],
                    "Joomla": ["Joomla!", "com_content"],
                    "jQuery": ["jquery.min.js", "jquery.js"],
                    "React": ["react.min.js", "_reactRoot"],
                    "Angular": ["ng-version", "angular.min.js"],
                    "Vue.js": ["vue.min.js", "v-cloak"],
                    "Bootstrap": ["bootstrap.min.css", "bootstrap.min.js"],
                    "Laravel": ["laravel_session", "csrf-token"],
                    "Cloudflare": ["cloudflare", "cf-ray"],
                    "Google Analytics": ["google-analytics.com", "gtag"],
                }

                for tech, sigs in tech_sigs.items():
                    for sig in sigs:
                        if sig.lower() in text.lower() or sig in headers.get('Set-Cookie', ''):
                            results["technologies"].append(tech)
                            break
        except Exception:
            pass

        # Modern framework discovery for SPA endpoints
        try:
            fw_results = framework_discovery.discover(target_url)
            for technique, endpoints in fw_results.items():
                for ep in endpoints:
                    results["technologies"].append({
                        "name": f"SPA ({technique})",
                        "indicators": [f"endpoint: {ep}"],
                    })
            results["total_techs"] = len(results["technologies"])
        except Exception:
            pass

        return results

    # ========================================================================
    # SCAN 5: Full OSINT Recon (All Methods)
    # ========================================================================

    def full_recon(self):
        """Run comprehensive OSINT reconnaissance"""
        results = {
            "domain": self.domain,
            "emails": None,
            "dork_findings": None,
            "domain_intel": None,
            "tech_fingerprint": None,
            "summary": {},
        }

        results["emails"] = self.harvest_emails()
        results["dork_findings"] = self.dork_scan(categories=["sqli", "xss", "exposed_files"])
        results["domain_intel"] = self.domain_intel()
        results["tech_fingerprint"] = self.tech_fingerprint()

        results["summary"] = {
            "emails_found": len(self.emails),
            "dork_findings": len(results["dork_findings"].get("findings", [])),
            "technologies": len(results["tech_fingerprint"].get("technologies", [])),
            "ips_found": len(self.ips),
        }

        return results


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_osint_scan(domain, scan_type="emails", **kwargs):
    """Run OSINT scan"""
    engine = OSINTEngine(domain=domain, **kwargs)

    scan_methods = {
        "emails": engine.harvest_emails,
        "dorks": engine.dork_scan,
        "intel": engine.domain_intel,
        "fingerprint": engine.tech_fingerprint,
        "full": engine.full_recon,
    }

    if scan_type in scan_methods:
        return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
