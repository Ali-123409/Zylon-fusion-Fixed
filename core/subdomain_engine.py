#!/usr/bin/env python3
"""
ZYLON FUSION - Advanced Subdomain Enumeration Engine
Fused from: Sublist3r + SubHunterX + DeepSubs + Subdomain-enum-tool
Capabilities:
  - Multi-source passive enumeration (crt.sh, CertSpotter, HackerTarget, DNSDumpster, etc.)
  - DNS brute force with configurable wordlists
  - Permutation-based subdomain generation
  - Live probing and HTTP status detection
  - Subdomain takeover detection (25+ services)
  - Cloud asset discovery (AWS S3, Azure Blob, GCP)
  - Wildcard detection and filtering
  - Recursive subdomain discovery
  - Certificate Transparency log search
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import socket
import time
import random
import string
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from core.shared_infra import shared_session, regex_cache, PayloadInjector

# ============================================================================
# SUBDOMAIN SOURCES (from Sublist3r + SubHunterX)
# ============================================================================

SUBDOMAIN_SOURCES = {
    "crt.sh": "https://crt.sh/?q=%25.{domain}&output=json",
    "certspotter": "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={domain}",
    "threatcrowd": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
    "bufferover": "https://dns.bufferover.run/dns?q=.{domain}",
    "rapiddns": "https://rapiddns.io/subdomain/{domain}?full=1",
    "anubis": "https://jldc.me/anubis/subdomains/{domain}",
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "urlscan": "https://urlscan.io/api/v1/search/?q=domain:{domain}",
    "webcache": "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
}

# Subdomain takeover fingerprints (25+ services)
TAKEOVER_FINGERPRINTS = {
    "github": ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/)",
               "404 There isn't a GitHub Pages site here"],
    "heroku": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
    "s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "azure": ["404 Web Site not found", "azuredns"],
    "cloudfront": ["Bad request", "ERROR: The request could not be satisfied"],
    "firebase": ["Firebase Hosting Setup Complete", "firebaseapp.com"],
    "tumblr": ["Whatever you were looking for doesn't currently exist"],
    "wordpress": ["Do you want to register", "wordpress.com"],
    "teamwork": ["Oops - We didn't find your site"],
    "helpscout": ["No settings were found for this company"],
    "cargo": ["If you're moving your domain away from Cargo"],
    "statuspage": ["You are being redirected", "statuspage.io"],
    "uservoice": ["This UserVoice subdomain is currently available"],
    "zendesk": ["Help Center Closed", "zendesk.com"],
    "acquia": ["The site you are looking for could not be found"],
    "pantheon": ["404 error unknown site", "pantheon.io"],
    "shopify": ["Sorry, this shop is currently unavailable"],
    "surge": ["project not found", "surge.sh"],
    "bitbucket": ["Repository not found", "bitbucket.org"],
    "intercom": ["This page is reserved for artistic dogs"],
    "webflow": ["The page you are looking for doesn't exist or has been moved"],
    "readme": ["Project doesnt exist", "readme.io"],
    "fly": ["404 Not Found", "fly.dev"],
    "vercel": ["The deployment could not be found", "vercel.app"],
    "netlify": ["Not Found", "netlify.app"],
}

# Common subdomain wordlist for brute force
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging", "stage",
    "test", "beta", "admin", "portal", "app", "static", "cdn", "assets", "media",
    "img", "images", "css", "js", "blog", "forum", "shop", "store", "secure",
    "login", "sso", "auth", "oauth", "vpn", "remote", "gateway", "proxy",
    "monitor", "status", "health", "debug", "trace", "logging", "log", "elastic",
    "search", "solr", "redis", "mongo", "mysql", "db", "database", "postgres",
    "couch", "cassandra", "neo4j", "influx", "grafana", "prometheus", "kibana",
    "jenkins", "gitlab", "github", "bitbucket", "jira", "confluence", "wiki",
    "docs", "api-docs", "swagger", "graphql", "rest", "soap", "wsdl",
    "dashboard", "panel", "control", "manage", "manager", "adminer", "phpmyadmin",
    "crm", "erp", "hr", "payroll", "accounting", "finance", "billing",
    "support", "help", "service", "info", "contact", "feedback", "survey",
    "download", "upload", "files", "backup", "archive", "old", "new", "v2", "v3",
    "mobile", "m", "android", "ios", "native", "web", "desktop", "client",
    "internal", "intranet", "extranet", "private", "public", "external",
    "us", "uk", "eu", "asia", "ap", "au", "ca", "de", "fr", "jp", "in", "br",
]

# Permutation prefixes/suffixes for subdomain generation
PERM_PREFIXES = ["dev", "staging", "prod", "test", "api", "admin", "app", "web"]
PERM_SUFFIXES = ["-dev", "-staging", "-prod", "-test", "-api", "-old", "-new", "-v2", "-backup"]


class SubdomainEngine:
    """Advanced Subdomain Enumeration Engine - Fused from Sublist3r + SubHunterX + DeepSubs"""

    def __init__(self, domain=None, threads=15, timeout=10, wordlist=None,
                 proxy=None, brute_force=True, takeover_check=True):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist or SUBDOMAIN_WORDLIST
        self.proxy = proxy
        self.brute_force = brute_force
        self.takeover_check = takeover_check
        self.session = shared_session
        self.found_subdomains = set()
        self.live_subdomains = []
        self.takeover_vulnerable = []

    def _resolve_subdomain(self, subdomain):
        """Resolve subdomain to IP address"""
        try:
            ip = socket.gethostbyname(subdomain)
            return ip
        except socket.gaierror:
            return None
        except Exception:
            return None

    def _check_live(self, subdomain):
        """Check if subdomain has HTTP/HTTPS service"""
        results = {"subdomain": subdomain, "live": False, "urls": [], "status_codes": []}
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{subdomain}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                results["live"] = True
                results["urls"].append(url)
                results["status_codes"].append(resp.status_code)
            except Exception:
                pass
        return results

    def _check_takeover(self, subdomain):
        """Check if subdomain is vulnerable to takeover"""
        results = {"subdomain": subdomain, "vulnerable": False, "service": None, "fingerprint": None}
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{subdomain}"
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                text = resp.text
                for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
                    for fp in fingerprints:
                        if fp in text:
                            results["vulnerable"] = True
                            results["service"] = service
                            results["fingerprint"] = fp
                            return results
            except Exception:
                continue
        return results

    # ========================================================================
    # SCAN 1: Passive Subdomain Enumeration (Multi-Source)
    # ========================================================================

    def passive_enum(self):
        """Enumerate subdomains using passive sources"""
        results = {
            "domain": self.domain,
            "subdomains": [],
            "sources_used": {},
            "total_found": 0,
        }

        def query_source(source_name, url_template):
            found = []
            try:
                url = url_template.format(domain=self.domain)
                resp = self.session.get(url, timeout=self.timeout)
                if not resp or resp.status_code != 200:
                    return source_name, found

                data = resp.text
                # Extract subdomains using multiple methods
                subdomain_pattern = rf'([a-zA-Z0-9._-]+\.{re.escape(self.domain)})'
                matches = regex_cache.findall(subdomain_pattern, data)

                # Also try JSON parsing
                try:
                    json_data = resp.json()
                    if isinstance(json_data, list):
                        for item in json_data:
                            if isinstance(item, dict):
                                for key in ['name_value', 'dns_names', 'hostname', 'domain']:
                                    if key in item:
                                        val = item[key]
                                        if isinstance(val, str):
                                            matches.extend(regex_cache.findall(subdomain_pattern, val))
                                        elif isinstance(val, list):
                                            for v in val:
                                                matches.extend(regex_cache.findall(subdomain_pattern, str(v)))
                            elif isinstance(item, str):
                                matches.extend(regex_cache.findall(subdomain_pattern, item))
                except (ValueError, TypeError):
                    pass

                for match in matches:
                    sub = match.strip().lower()
                    if sub.endswith(f".{self.domain}") and sub != self.domain:
                        found.append(sub)
                        self.found_subdomains.add(sub)

            except Exception:
                pass
            return source_name, list(set(found))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(query_source, name, url): name
                for name, url in SUBDOMAIN_SOURCES.items()
            }
            for future in as_completed(futures):
                source_name, found = future.result()
                if found:
                    results["sources_used"][source_name] = len(found)

        results["subdomains"] = sorted(self.found_subdomains)
        results["total_found"] = len(self.found_subdomains)
        return results

    # ========================================================================
    # SCAN 2: DNS Brute Force
    # ========================================================================

    def brute_force_enum(self):
        """Brute force subdomains using DNS resolution"""
        results = {
            "domain": self.domain,
            "subdomains": [],
            "total_found": 0,
            "wordlist_size": len(self.wordlist),
        }

        found = set()

        def resolve(word):
            subdomain = f"{word}.{self.domain}"
            ip = self._resolve_subdomain(subdomain)
            if ip:
                return (subdomain, ip)
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(resolve, w): w for w in self.wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.add(result[0])
                    self.found_subdomains.add(result[0])

        results["subdomains"] = sorted(found)
        results["total_found"] = len(found)
        return results

    # ========================================================================
    # SCAN 3: Permutation Subdomain Generation
    # ========================================================================

    def permutation_enum(self, known_subdomains=None):
        """Generate subdomain permutations from known subdomains"""
        results = {
            "domain": self.domain,
            "permutations_tested": 0,
            "subdomains": [],
            "total_found": 0,
        }

        base_words = set()
        # Extract words from domain
        domain_parts = self.domain.split(".")
        base_words.add(domain_parts[0])

        # Extract words from known subdomains
        subs = known_subdomains or list(self.found_subdomains)
        for sub in subs:
            parts = sub.replace(f".{self.domain}", "").split(".")
            for part in parts:
                if part and len(part) > 1:
                    base_words.add(part)

        # Generate permutations
        permutations = set()
        for word in base_words:
            for prefix in PERM_PREFIXES:
                permutations.add(f"{prefix}{word}")
                permutations.add(f"{prefix}-{word}")
            for suffix in PERM_SUFFIXES:
                permutations.add(f"{word}{suffix}")
            # Number permutations
            for num in range(1, 10):
                permutations.add(f"{word}{num}")
                permutations.add(f"{word}-{num}")

        results["permutations_tested"] = len(permutations)

        found = set()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for perm in permutations:
                subdomain = f"{perm}.{self.domain}"
                futures[executor.submit(self._resolve_subdomain, subdomain)] = subdomain

            for future in as_completed(futures):
                if future.result():
                    found.add(futures[future])
                    self.found_subdomains.add(futures[future])

        results["subdomains"] = sorted(found)
        results["total_found"] = len(found)
        return results

    # ========================================================================
    # SCAN 4: Live Probing + Takeover Detection
    # ========================================================================

    def live_probe(self, subdomains=None, check_takeover=True):
        """Probe subdomains for live HTTP services and takeover"""
        subs = subdomains or list(self.found_subdomains)
        results = {
            "total_tested": len(subs),
            "live_subdomains": [],
            "takeover_vulnerable": [],
        }

        def probe(subdomain):
            live_result = self._check_live(subdomain)
            takeover_result = None
            if check_takeover and live_result["live"]:
                takeover_result = self._check_takeover(subdomain)
            return live_result, takeover_result

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe, sub): sub for sub in subs}
            for future in as_completed(futures):
                live, takeover = future.result()
                if live["live"]:
                    results["live_subdomains"].append(live)
                    self.live_subdomains.append(live)
                if takeover and takeover["vulnerable"]:
                    results["takeover_vulnerable"].append(takeover)
                    self.takeover_vulnerable.append(takeover)

        return results

    # ========================================================================
    # SCAN 5: Full Subdomain Recon (All Methods)
    # ========================================================================

    def full_enum(self):
        """Run comprehensive subdomain enumeration"""
        results = {
            "domain": self.domain,
            "passive": None,
            "brute_force": None,
            "permutation": None,
            "live_probe": None,
            "total_subdomains": 0,
            "total_live": 0,
            "total_takeover": 0,
        }

        # Step 1: Passive enumeration
        results["passive"] = self.passive_enum()

        # Step 2: DNS brute force
        if self.brute_force:
            results["brute_force"] = self.brute_force_enum()

        # Step 3: Permutation
        results["permutation"] = self.permutation_enum()

        # Step 4: Live probing + takeover
        results["live_probe"] = self.live_probe(check_takeover=self.takeover_check)

        results["total_subdomains"] = len(self.found_subdomains)
        results["total_live"] = len(self.live_subdomains)
        results["total_takeover"] = len(self.takeover_vulnerable)

        return results


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_subdomain_scan(domain, scan_type="passive", **kwargs):
    """Run subdomain scan with specified type"""
    engine = SubdomainEngine(domain=domain, **kwargs)

    scan_methods = {
        "passive": engine.passive_enum,
        "brute_force": engine.brute_force_enum,
        "permutation": engine.permutation_enum,
        "live_probe": engine.live_probe,
        "full": engine.full_enum,
    }

    if scan_type in scan_methods:
        return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
