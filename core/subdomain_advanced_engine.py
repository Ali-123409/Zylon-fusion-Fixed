#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Advanced Subdomain Enumeration Engine
Fused from: Sublist3r + SubHunterX + DeepSubs
Capabilities:
  - Multi-source passive enumeration (crt.sh, certspotter, hackertarget, virustotal,
    threatcrowd, dnsdumpster, securitytrails, bufferover, rapiddns, anubis, alienvault)
  - DNS brute force with built-in wordlist + custom wordlist support
  - Certificate transparency log search (deep)
  - Live subdomain probing (HTTP/HTTPS check with status codes)
  - Subdomain takeover detection (25+ services using TAKEOVER_SIGNATURES from var.py)
  - Cloud asset discovery (S3 buckets, Azure blobs, GCP storage)
  - Recursive enumeration (find sub-subdomains up to configurable depth)
  - Rate limiting and threading with configurable concurrency
  - Results deduplication and validation
  - Export results to file
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import socket
import time
import json
import os
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# ============================================================================
# ANSI COLOR CODES
# ============================================================================

R = "\033[91m"   # Red
G = "\033[92m"   # Green
Y = "\033[93m"   # Yellow
C = "\033[96m"   # Cyan
M = "\033[95m"   # Magenta
B = "\033[94m"   # Blue
W = "\033[97m"   # White
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ============================================================================
# ADVANCED PASSIVE SOURCES (expanded from Sublist3r + SubHunterX + DeepSubs)
# ============================================================================

ADVANCED_SUBDOMAIN_SOURCES = {
    "crt.sh": {
        "url": "https://crt.sh/?q=%25.{domain}&output=json",
        "method": "json",
        "extract_fields": ["name_value", "common_name"],
    },
    "certspotter": {
        "url": "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names",
        "method": "json",
        "extract_fields": ["dns_names", "not_before"],
    },
    "hackertarget": {
        "url": "https://api.hackertarget.com/hostsearch/?q={domain}",
        "method": "text",
        "delimiter": "\n",
    },
    "virustotal": {
        "url": "https://www.virustotal.com/ui/domains/{domain}/subdomains?limit=40",
        "method": "json",
        "extract_fields": ["id"],
        "headers": {"User-Agent": "Mozilla/5.0"},
    },
    "threatcrowd": {
        "url": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
        "method": "json",
        "extract_fields": ["subdomains"],
    },
    "dnsdumpster": {
        "url": "https://dnsdumpster.com/",
        "method": "post",
        "post_data": "targetip={domain}",
    },
    "securitytrails": {
        "url": "https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        "method": "json",
        "extract_fields": ["subdomains"],
    },
    "bufferover": {
        "url": "https://dns.bufferover.run/dns?q=.{domain}",
        "method": "json",
        "extract_fields": ["FDNS_A", "RDNS"],
    },
    "rapiddns": {
        "url": "https://rapiddns.io/subdomain/{domain}?full=1",
        "method": "regex",
    },
    "anubis": {
        "url": "https://jldc.me/anubis/subdomains/{domain}",
        "method": "json_list",
    },
    "alienvault": {
        "url": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
        "method": "json",
        "extract_fields": ["address"],
        "nested_key": "passive_dns",
    },
    "urlscan": {
        "url": "https://urlscan.io/api/v1/search/?q=domain:{domain}",
        "method": "json",
        "extract_fields": ["page"],
        "nested_key": "results",
    },
    "webarchive": {
        "url": "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey",
        "method": "json_list",
    },
}

# Extended subdomain wordlist for brute force
ADVANCED_SUBDOMAIN_WORDLIST = [
    "www", "www2", "www3", "mail", "mail2", "mail3", "ftp", "ftp2",
    "webmail", "smtp", "pop", "pop3", "imap", "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
    "mx", "mx1", "mx2", "mx0", "email", "relay", "mxpool",
    "api", "api2", "api-v1", "api-v2", "api-dev", "api-staging",
    "dev", "staging", "stage", "test", "beta", "alpha", "qa", "uat", "sandbox",
    "admin", "admin2", "administrator", "panel", "control", "manage", "manager",
    "portal", "app", "app2", "my", "user", "users", "account", "accounts",
    "static", "static2", "cdn", "cdn2", "assets", "media", "img", "images",
    "css", "js", "fonts", "files", "uploads", "upload", "download", "downloads",
    "blog", "news", "forum", "wiki", "docs", "documentation", "help", "support",
    "shop", "store", "secure", "checkout", "cart", "billing", "payment", "pay",
    "login", "login2", "signin", "sso", "auth", "oauth", "register", "signup",
    "vpn", "remote", "gateway", "proxy", "reverse", "forward",
    "monitor", "monitoring", "status", "health", "ping", "uptime", "grafana",
    "debug", "trace", "logging", "log", "logs", "error", "errors",
    "elastic", "elasticsearch", "search", "solr", "kibana",
    "redis", "redis2", "mongo", "mongodb", "mysql", "mysql2", "db", "database",
    "postgres", "postgresql", "couch", "couchdb", "cassandra", "neo4j", "influx",
    "prometheus", "jenkins", "jenkins2", "gitlab", "github", "bitbucket",
    "jira", "confluence", "slack", "teams", "trello",
    "crm", "erp", "hr", "payroll", "accounting", "finance",
    "internal", "intranet", "extranet", "private", "public", "external", "local",
    "backup", "backup2", "archive", "old", "new", "legacy", "v2", "v3", "v4",
    "mobile", "m", "android", "ios", "native", "web", "desktop", "client",
    "us", "uk", "eu", "asia", "ap", "au", "ca", "de", "fr", "jp", "in", "br",
    "analytics", "tracking", "report", "reports", "dashboard", "metrics",
    "webhook", "webhooks", "callback", "notifications", "push", "realtime",
    "cache", "cached", "lb", "loadbalancer", "nginx", "apache", "haproxy",
    "devops", "ci", "cd", "deploy", "deployment", "release", "artifacts",
    "s3", "storage", "blob", "bucket", "minio", "ceph",
    "rabbitmq", "kafka", "queue", "worker", "scheduler", "cron",
    "ws", "wss", "socket", "websocket", "stream", "streaming",
    "graph", "graphql", "gql", "rest", "soap", "rpc", "grpc",
    "swagger", "openapi", "api-docs", "postman",
    "staging-api", "prod-api", "dev-api", "test-api",
    "origin", "backend", "front", "frontend", "server", "srv", "node",
]

# Cloud asset patterns
CLOUD_ASSET_PATTERNS = {
    "AWS S3": {
        "url_template": "https://{name}.s3.amazonaws.com",
        "names": ["{domain}", "www-{domain}", "{domain}-assets", "{domain}-static",
                  "{domain}-media", "{domain}-uploads", "{domain}-backup",
                  "{domain}-logs", "{domain}-data", "{domain}-public"],
        "exists_check": "ListBucketResult",
        "public_indicator": "<Name>",
    },
    "Azure Blob": {
        "url_template": "https://{name}.blob.core.windows.net",
        "names": ["{domain}", "{domain}data", "{domain}storage", "{domain}assets"],
        "exists_check": "EnumerationResults",
        "public_indicator": "<Blob>",
    },
    "Google Cloud Storage": {
        "url_template": "https://storage.googleapis.com/{name}",
        "names": ["{domain}", "{domain}-storage", "{domain}-assets", "{domain}-data"],
        "exists_check": "<ListBucketResult",
        "public_indicator": "<Contents>",
    },
    "DigitalOcean Spaces": {
        "url_template": "https://{name}.ams3.digitaloceanspaces.com",
        "names": ["{domain}", "{domain}-assets", "{domain}-storage"],
        "exists_check": "ListBucketResult",
        "public_indicator": "<Name>",
    },
    "Firebase": {
        "url_template": "https://{name}.firebaseio.com/.json",
        "names": ["{domain}", "{domain}-dev", "{domain}-prod", "{domain}-staging"],
        "exists_check": '"',
        "public_indicator": "null",
    },
}


class SubdomainAdvancedEngine:
    """Advanced Subdomain Enumeration Engine - Fused from Sublist3r + SubHunterX + DeepSubs
    v5.0 Nuclear: 7 scan modes, 13+ passive sources, cloud assets, recursive enum,
    takeover detection using TAKEOVER_SIGNATURES from var.py
    """

    def __init__(self, domain=None, threads=15, timeout=10, wordlist=None,
                 proxy=None, output_dir=None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.wordlist = wordlist or ADVANCED_SUBDOMAIN_WORDLIST
        self.proxy = proxy
        self.output_dir = output_dir or os.path.join(os.path.expanduser("~"), ".zylon", "results")
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            ])
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.found_subdomains = set()
        self.subdomain_sources = {}  # subdomain -> [sources]
        self.live_subdomains = []
        self.takeover_vulnerable = []
        self.cloud_assets_found = []

        # Import TAKEOVER_SIGNATURES from var
        try:
            from core.var import TAKEOVER_SIGNATURES
            self.takeover_signatures = TAKEOVER_SIGNATURES
        except ImportError:
            self.takeover_signatures = {}

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _log(self, msg, color=C):
        """Print colored log message"""
        print(f"  {color}{BOLD}[ZYLON-SUB]{RESET} {color}{msg}{RESET}")

    def _resolve_subdomain(self, subdomain):
        """Resolve subdomain to IP address"""
        try:
            return socket.gethostbyname(subdomain)
        except (socket.gaierror, Exception):
            return None

    def _validate_subdomain(self, subdomain):
        """Validate that a subdomain belongs to the target domain"""
        subdomain = subdomain.strip().lower()
        if not subdomain:
            return None
        # Remove wildcards
        subdomain = subdomain.lstrip('*.')
        # Must end with our domain
        if subdomain.endswith(f".{self.domain}") or subdomain == self.domain:
            # Basic validation
            if re.match(r'^[a-zA-Z0-9._-]+$', subdomain):
                return subdomain
        return None

    def _extract_subdomains_from_text(self, text):
        """Extract subdomains from response text using regex"""
        pattern = rf'([a-zA-Z0-9._-]+\.{re.escape(self.domain)})'
        matches = re.findall(pattern, text)
        validated = set()
        for match in matches:
            sub = self._validate_subdomain(match)
            if sub and sub != self.domain:
                validated.add(sub)
        return validated

    def _add_subdomain(self, subdomain, source):
        """Add a discovered subdomain with dedup"""
        subdomain = self._validate_subdomain(subdomain)
        if subdomain:
            self.found_subdomains.add(subdomain)
            if subdomain not in self.subdomain_sources:
                self.subdomain_sources[subdomain] = []
            if source not in self.subdomain_sources[subdomain]:
                self.subdomain_sources[subdomain].append(source)

    def _export_results(self, results, filename_suffix):
        """Export results to JSON file"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            filename = os.path.join(self.output_dir,
                                     f"subdomain_{self.domain}_{filename_suffix}_{int(time.time())}.json")
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self._log(f"Results exported to {filename}", G)
            return filename
        except Exception as e:
            self._log(f"Export failed: {e}", R)
            return None

    # ========================================================================
    # SCAN 1: PASSIVE ENUMERATION (Multi-Source, 13+ sources)
    # ========================================================================

    def passive_enum(self, domain=None):
        """Multi-source passive subdomain enumeration"""
        self.domain = domain or self.domain
        self._log(f"Starting passive enumeration for {self.domain} (13+ sources)", C)

        results = {
            "domain": self.domain,
            "subdomains": [],
            "sources_used": {},
            "total_found": 0,
            "scan_type": "passive_advanced",
            "timestamp": datetime.now().isoformat(),
        }

        def query_source(source_name, source_config):
            found = []
            try:
                url = source_config["url"].format(domain=self.domain)
                headers = source_config.get("headers", {})

                if source_config.get("method") == "post":
                    resp = self.session.post(url, data=source_config.get("post_data", ""),
                                             timeout=self.timeout, headers=headers)
                else:
                    resp = self.session.get(url, timeout=self.timeout, headers=headers)

                if not resp or resp.status_code != 200:
                    return source_name, found

                method = source_config.get("method", "text")

                if method in ("json", "json_list"):
                    try:
                        json_data = resp.json()

                        if method == "json_list" and isinstance(json_data, list):
                            # List of strings or dicts
                            for item in json_data:
                                if isinstance(item, str):
                                    subs = self._extract_subdomains_from_text(item)
                                    found.extend(subs)
                                elif isinstance(item, dict):
                                    for field in source_config.get("extract_fields", []):
                                        val = item.get(field, "")
                                        if isinstance(val, str):
                                            found.extend(self._extract_subdomains_from_text(val))
                                        elif isinstance(val, list):
                                            for v in val:
                                                found.extend(self._extract_subdomains_from_text(str(v)))
                        elif isinstance(json_data, dict):
                            # Check nested key first
                            nested_key = source_config.get("nested_key")
                            if nested_key and nested_key in json_data:
                                json_data = json_data[nested_key]
                                if isinstance(json_data, list):
                                    for item in json_data:
                                        if isinstance(item, dict):
                                            for field in source_config.get("extract_fields", []):
                                                val = item.get(field, "")
                                                if isinstance(val, str):
                                                    found.extend(self._extract_subdomains_from_text(val))
                                                elif isinstance(val, list):
                                                    for v in val:
                                                        found.extend(self._extract_subdomains_from_text(str(v)))
                                                elif isinstance(val, dict):
                                                    # For nested dicts like 'page'
                                                    for sub_val in val.values():
                                                        if isinstance(sub_val, str):
                                                            found.extend(self._extract_subdomains_from_text(sub_val))

                            # Check direct fields
                            for field in source_config.get("extract_fields", []):
                                val = json_data.get(field)
                                if val is None:
                                    continue
                                if isinstance(val, str):
                                    found.extend(self._extract_subdomains_from_text(val))
                                elif isinstance(val, list):
                                    for v in val:
                                        if isinstance(v, str):
                                            found.extend(self._extract_subdomains_from_text(v))

                    except (ValueError, TypeError, AttributeError):
                        pass

                elif method == "regex":
                    found.extend(self._extract_subdomains_from_text(resp.text))

                elif method == "text":
                    found.extend(self._extract_subdomains_from_text(resp.text))

            except Exception as e:
                pass

            return source_name, list(set(found))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(query_source, name, config): name
                for name, config in ADVANCED_SUBDOMAIN_SOURCES.items()
            }
            for future in as_completed(futures):
                source_name, found = future.result()
                if found:
                    results["sources_used"][source_name] = len(found)
                    for sub in found:
                        self._add_subdomain(sub, source_name)
                    self._log(f"  [{source_name}] Found {len(found)} subdomains", G)

        results["subdomains"] = sorted(self.found_subdomains)
        results["total_found"] = len(self.found_subdomains)
        self._log(f"Passive enum complete: {results['total_found']} unique subdomains from "
                  f"{len(results['sources_used'])} sources", G)
        return results

    # ========================================================================
    # SCAN 2: DNS BRUTE FORCE (Advanced)
    # ========================================================================

    def brute_force(self, domain=None, wordlist=None):
        """DNS brute force subdomain enumeration"""
        self.domain = domain or self.domain
        wl = wordlist or self.wordlist
        self._log(f"Starting DNS brute force for {self.domain} ({len(wl)} words)", C)

        results = {
            "domain": self.domain,
            "subdomains": [],
            "total_found": 0,
            "wordlist_size": len(wl),
            "scan_type": "brute_force_advanced",
            "timestamp": datetime.now().isoformat(),
        }

        found = set()
        lock = threading.Lock()
        progress = {"count": 0}

        def resolve(word):
            subdomain = f"{word}.{self.domain}"
            ip = self._resolve_subdomain(subdomain)
            with lock:
                progress["count"] += 1
                if progress["count"] % 50 == 0:
                    self._log(f"  Brute force progress: {progress['count']}/{len(wl)}", DIM)
            if ip:
                return (subdomain, ip)
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(resolve, w): w for w in wl}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ip = result
                    found.add(subdomain)
                    self._add_subdomain(subdomain, "bruteforce")
                    self._log(f"  [BRUTE] {subdomain} -> {ip}", G)

        results["subdomains"] = sorted(found)
        results["total_found"] = len(found)
        self._log(f"Brute force complete: {results['total_found']} subdomains found", G)
        return results

    # ========================================================================
    # SCAN 3: CERTIFICATE TRANSPARENCY SEARCH (Deep)
    # ========================================================================

    def cert_search(self, domain=None):
        """Deep certificate transparency log search"""
        self.domain = domain or self.domain
        self._log(f"Starting Certificate Transparency search for {self.domain}", C)

        results = {
            "domain": self.domain,
            "subdomains": [],
            "total_found": 0,
            "cert_sources": {},
            "scan_type": "cert_transparency",
            "timestamp": datetime.now().isoformat(),
        }

        found = set()

        # crt.sh - primary CT source
        def search_crtsh():
            ct_found = set()
            try:
                url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
                resp = self.session.get(url, timeout=20)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        for field in ['name_value', 'common_name']:
                            val = entry.get(field, '')
                            if val:
                                for name in val.split('\n'):
                                    sub = self._validate_subdomain(name.strip())
                                    if sub and sub != self.domain:
                                        ct_found.add(sub)
            except Exception:
                pass
            return "crt.sh", ct_found

        # CertSpotter
        def search_certspotter():
            ct_found = set()
            try:
                url = f"https://api.certspotter.com/v1/issuances?domain={self.domain}&include_subdomains=true&expand=dns_names"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    for entry in resp.json():
                        for name in entry.get('dns_names', []):
                            sub = self._validate_subdomain(name)
                            if sub and sub != self.domain:
                                ct_found.add(sub)
            except Exception:
                pass
            return "certspotter", ct_found

        # Google CT
        def search_google_ct():
            ct_found = set()
            try:
                url = f"https://google.transparencyreport.googleapis.com/v1/https/certificates/search?domain={self.domain}"
                # This may not be available, fallback to crt.sh pagination
                # Try alternate: censys cert search
                pass
            except Exception:
                pass
            return "google_ct", ct_found

        ct_sources = [search_crtsh, search_certspotter, search_google_ct]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(src) for src in ct_sources]
            for future in as_completed(futures):
                source_name, ct_found = future.result()
                if ct_found:
                    results["cert_sources"][source_name] = len(ct_found)
                    for sub in ct_found:
                        found.add(sub)
                        self._add_subdomain(sub, source_name)
                    self._log(f"  [CT-{source_name}] Found {len(ct_found)} subdomains", G)

        results["subdomains"] = sorted(found)
        results["total_found"] = len(found)
        self._log(f"Cert Transparency search complete: {results['total_found']} subdomains", G)
        return results

    # ========================================================================
    # SCAN 4: LIVE PROBING (HTTP/HTTPS check)
    # ========================================================================

    def live_probe(self, subdomains=None):
        """Check which subdomains have live HTTP/HTTPS services"""
        subs = subdomains or list(self.found_subdomains)
        if isinstance(subdomains, dict):
            subs = list(subdomains.keys()) if subdomains else list(self.found_subdomains)
        self._log(f"Probing {len(subs)} subdomains for live HTTP/HTTPS", C)

        results = {
            "total_tested": len(subs),
            "live_subdomains": [],
            "dead_subdomains": [],
            "scan_type": "live_probe",
            "timestamp": datetime.now().isoformat(),
        }

        def probe(subdomain):
            probe_result = {
                "subdomain": subdomain,
                "live": False,
                "urls": [],
                "status_codes": [],
                "titles": [],
                "ip": None,
            }
            # Resolve IP first
            ip = self._resolve_subdomain(subdomain)
            if ip:
                probe_result["ip"] = ip

            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{subdomain}"
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                    probe_result["live"] = True
                    probe_result["urls"].append(url)
                    probe_result["status_codes"].append(resp.status_code)
                    # Try to extract title
                    try:
                        title_match = re.search(r'<title[^>]*>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
                        if title_match:
                            probe_result["titles"].append(title_match.group(1).strip()[:100])
                    except Exception:
                        pass
                except requests.exceptions.SSLError:
                    # SSL error but host is reachable
                    try:
                        url = f"http://{subdomain}"
                        resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                        probe_result["live"] = True
                        probe_result["urls"].append(url)
                        probe_result["status_codes"].append(resp.status_code)
                    except Exception:
                        pass
                except Exception:
                    pass
            return probe_result

        live_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(probe, sub): sub for sub in subs}
            for future in as_completed(futures):
                result = future.result()
                if result["live"]:
                    results["live_subdomains"].append(result)
                    self.live_subdomains.append(result)
                    live_count += 1
                else:
                    results["dead_subdomains"].append(result["subdomain"])

        self._log(f"Live probe complete: {live_count}/{len(subs)} subdomains alive", G)
        return results

    # ========================================================================
    # SCAN 5: SUBDOMAIN TAKEOVER DETECTION
    # ========================================================================

    def check_takeover(self, subdomains=None):
        """Check for subdomain takeover vulnerability using TAKEOVER_SIGNATURES"""
        subs = subdomains or list(self.found_subdomains)
        if isinstance(subdomains, dict):
            subs = list(subdomains.keys()) if subdomains else list(self.found_subdomains)
        self._log(f"Checking {len(subs)} subdomains for takeover ({len(self.takeover_signatures)} signatures)", C)

        results = {
            "total_tested": len(subs),
            "takeover_vulnerable": [],
            "services_checked": list(self.takeover_signatures.keys()),
            "scan_type": "takeover_check",
            "timestamp": datetime.now().isoformat(),
        }

        def check_sub(subdomain):
            # First check CNAME
            cname = None
            try:
                import dns.resolver
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).rstrip('.')
                    break
            except Exception:
                pass

            # Check via HTTP response
            takeover_result = {
                "subdomain": subdomain,
                "vulnerable": False,
                "service": None,
                "fingerprint": None,
                "cname": cname,
            }

            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{subdomain}"
                    resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                    text = resp.text

                    for service, sigs in self.takeover_signatures.items():
                        if isinstance(sigs, dict):
                            # var.py TAKEOVER_SIGNATURES format
                            response_sig = sigs.get("response", "")
                            cname_sig = sigs.get("cname", "")
                            status_codes = sigs.get("status", [])

                            if response_sig and response_sig in text:
                                if not status_codes or resp.status_code in status_codes:
                                    takeover_result["vulnerable"] = True
                                    takeover_result["service"] = service
                                    takeover_result["fingerprint"] = response_sig
                                    return takeover_result

                            if cname and cname_sig and cname_sig in cname:
                                takeover_result["vulnerable"] = True
                                takeover_result["service"] = service
                                takeover_result["fingerprint"] = f"CNAME match: {cname_sig}"
                                return takeover_result

                    # Also check one more round if response body has obvious signatures
                    # This is the fallback for the fingerprints from subdomain_engine
                    for service, fingerprints in self.takeover_signatures.items():
                        if isinstance(fingerprints, list):
                            for fp in fingerprints:
                                if isinstance(fp, str) and fp in text:
                                    takeover_result["vulnerable"] = True
                                    takeover_result["service"] = service
                                    takeover_result["fingerprint"] = fp
                                    return takeover_result

                except Exception:
                    continue

            return takeover_result

        vuln_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_sub, sub): sub for sub in subs}
            for future in as_completed(futures):
                result = future.result()
                if result["vulnerable"]:
                    results["takeover_vulnerable"].append(result)
                    self.takeover_vulnerable.append(result)
                    vuln_count += 1
                    self._log(f"  {R}[TAKEOVER] {result['subdomain']} -> {result['service']} "
                              f"({result['fingerprint'][:50]}){RESET}", R)

        if vuln_count == 0:
            self._log("No takeover vulnerabilities found", G)
        else:
            self._log(f"Found {vuln_count} potential takeover vulnerabilities!", R)
        return results

    # ========================================================================
    # SCAN 6: CLOUD ASSET DISCOVERY
    # ========================================================================

    def cloud_assets(self, domain=None):
        """Discover cloud assets (S3 buckets, Azure blobs, GCP storage, Firebase)"""
        self.domain = domain or self.domain
        self._log(f"Discovering cloud assets for {self.domain}", C)

        results = {
            "domain": self.domain,
            "cloud_assets": [],
            "total_found": 0,
            "scan_type": "cloud_assets",
            "timestamp": datetime.now().isoformat(),
        }

        def check_cloud_asset(provider, config, name):
            asset_url = config["url_template"].format(name=name)
            try:
                resp = self.session.get(asset_url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    exists_check = config.get("exists_check", "")
                    public_indicator = config.get("public_indicator", "")
                    is_public = public_indicator in resp.text if public_indicator else False
                    is_exists = exists_check in resp.text if exists_check else True

                    if is_exists or is_public:
                        return {
                            "provider": provider,
                            "name": name,
                            "url": asset_url,
                            "status_code": resp.status_code,
                            "public": is_public,
                            "exists": is_exists,
                            "response_size": len(resp.text),
                        }
            except Exception:
                pass
            return None

        # Generate all check combinations
        checks = []
        for provider, config in CLOUD_ASSET_PATTERNS.items():
            domain_base = self.domain.replace(".", "-")
            for name_template in config["names"]:
                name = name_template.format(domain=domain_base)
                checks.append((provider, config, name))

        found_assets = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_cloud_asset, p, c, n): (p, n) for p, c, n in checks}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_assets.append(result)
                    self.cloud_assets_found.append(result)
                    status = f"{R}PUBLIC" if result["public"] else f"{Y}EXISTS"
                    self._log(f"  [{result['provider']}] {result['url']} - {status}{RESET}", G)

        results["cloud_assets"] = found_assets
        results["total_found"] = len(found_assets)
        self._log(f"Cloud asset discovery complete: {results['total_found']} assets found", G)
        return results

    # ========================================================================
    # SCAN 7: RECURSIVE ENUMERATION
    # ========================================================================

    def recursive_enum(self, domain=None, depth=2):
        """Recursive subdomain enumeration - find sub-subdomains"""
        self.domain = domain or self.domain
        self._log(f"Starting recursive enumeration for {self.domain} (depth={depth})", C)

        results = {
            "domain": self.domain,
            "depth": depth,
            "all_subdomains": [],
            "recursive_findings": [],
            "total_found": 0,
            "scan_type": "recursive_enum",
            "timestamp": datetime.now().isoformat(),
        }

        # Start with passive enum for base subdomains
        all_subs = set()

        # Level 1: Get base subdomains
        self._log(f"  Depth 1: Enumerating {self.domain}", C)
        passive_result = self.passive_enum(self.domain)
        base_subs = set(passive_result.get("subdomains", []))
        all_subs.update(base_subs)
        self._log(f"  Depth 1: Found {len(base_subs)} base subdomains", G)

        # Level 2+: For each subdomain, try to find sub-subdomains
        current_level_subs = base_subs
        for d in range(2, depth + 1):
            self._log(f"  Depth {d}: Checking {len(current_level_subs)} subdomains for sub-subdomains", C)
            next_level_subs = set()

            for sub in list(current_level_subs)[:50]:  # Limit to prevent explosion
                try:
                    url = f"https://crt.sh/?q=%25.{sub}&output=json"
                    resp = self.session.get(url, timeout=15)
                    if resp and resp.status_code == 200:
                        data = resp.json()
                        for entry in data:
                            for field in ['name_value', 'common_name']:
                                val = entry.get(field, '')
                                if val:
                                    for name in val.split('\n'):
                                        validated = self._validate_subdomain(name.strip())
                                        if validated and validated not in all_subs:
                                            next_level_subs.add(validated)
                                            self._add_subdomain(validated, f"recursive_depth{d}")
                                            results["recursive_findings"].append({
                                                "subdomain": validated,
                                                "parent": sub,
                                                "depth": d,
                                                "source": "crt.sh",
                                            })
                except Exception:
                    continue
                time.sleep(0.3)  # Rate limit

            all_subs.update(next_level_subs)
            current_level_subs = next_level_subs
            self._log(f"  Depth {d}: Found {len(next_level_subs)} new sub-subdomains", G)

            if not next_level_subs:
                break

        results["all_subdomains"] = sorted(all_subs)
        results["total_found"] = len(all_subs)
        self._log(f"Recursive enum complete: {results['total_found']} total subdomains "
                  f"(+{len(results['recursive_findings'])} recursive)", G)
        return results

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, domain, scan_type='full', **kwargs):
        """Main entry point for subdomain advanced engine

        Args:
            domain: Target domain
            scan_type: One of 'passive', 'bruteforce', 'cert', 'takeover',
                       'cloud', 'recursive', 'full'
            **kwargs: Additional options (wordlist, depth, subdomains list, etc.)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self.domain = domain
        self._log(f"{BOLD}═══ ZYLON Advanced Subdomain Engine v5.0 ═══{RESET}", M)
        self._log(f"Target: {domain} | Scan: {scan_type}", Y)

        scan_results = {}
        findings_list = []

        try:
            if scan_type == 'passive':
                scan_results = self.passive_enum(domain)

            elif scan_type == 'bruteforce':
                wordlist = kwargs.get('wordlist', None)
                scan_results = self.brute_force(domain, wordlist=wordlist)

            elif scan_type == 'cert':
                scan_results = self.cert_search(domain)

            elif scan_type == 'takeover':
                subdomains = kwargs.get('subdomains', None)
                # If no subdomains provided, do a quick passive enum first
                if not subdomains:
                    self._log("No subdomains provided, running passive enum first...", Y)
                    passive = self.passive_enum(domain)
                    subdomains = passive.get("subdomains", [])
                scan_results = self.check_takeover(subdomains)

            elif scan_type == 'cloud':
                scan_results = self.cloud_assets(domain)

            elif scan_type == 'recursive':
                depth = kwargs.get('depth', 2)
                scan_results = self.recursive_enum(domain, depth=depth)

            elif scan_type == 'full':
                # Full recon: passive + brute + cert + live + takeover + cloud
                self._log(f"{BOLD}Running FULL SUBDOMAIN RECONNAISSANCE{RESET}", M)

                # Phase 1: Passive
                passive_result = self.passive_enum(domain)
                scan_results["passive"] = passive_result

                # Phase 2: Certificate transparency
                cert_result = self.cert_search(domain)
                scan_results["cert_transparency"] = cert_result

                # Phase 3: DNS brute force
                brute_result = self.brute_force(domain)
                scan_results["brute_force"] = brute_result

                # Phase 4: Live probing
                live_result = self.live_probe(list(self.found_subdomains))
                scan_results["live_probe"] = live_result

                # Phase 5: Takeover check
                takeover_result = self.check_takeover(list(self.found_subdomains))
                scan_results["takeover"] = takeover_result

                # Phase 6: Cloud assets
                cloud_result = self.cloud_assets(domain)
                scan_results["cloud_assets"] = cloud_result

                # Summary
                scan_results["summary"] = {
                    "total_subdomains": len(self.found_subdomains),
                    "live_subdomains": len(self.live_subdomains),
                    "takeover_vulnerable": len(self.takeover_vulnerable),
                    "cloud_assets_found": len(self.cloud_assets_found),
                }
                self._log(f"{BOLD}═══ FULL RECON SUMMARY ═══{RESET}", M)
                self._log(f"  Total subdomains: {len(self.found_subdomains)}", C)
                self._log(f"  Live subdomains: {len(self.live_subdomains)}", G)
                self._log(f"  Takeover vuln: {len(self.takeover_vulnerable)}", R if self.takeover_vulnerable else G)
                self._log(f"  Cloud assets: {len(self.cloud_assets_found)}", Y)

            else:
                scan_results = {"error": f"Unknown scan type: {scan_type}"}

        except Exception as e:
            scan_results = {"error": str(e)}
            self._log(f"Scan error: {e}", R)

        # Build findings list for vulnerability reporting
        if self.takeover_vulnerable:
            for t in self.takeover_vulnerable:
                findings_list.append({
                    "type": "subdomain_takeover",
                    "subdomain": t.get("subdomain"),
                    "service": t.get("service"),
                    "severity": "high",
                })
        if self.cloud_assets_found:
            for a in self.cloud_assets_found:
                if a.get("public"):
                    findings_list.append({
                        "type": "public_cloud_asset",
                        "provider": a.get("provider"),
                        "url": a.get("url"),
                        "severity": "medium",
                    })

        # Export results
        self._export_results(scan_results, scan_type)

        return {
            "vulnerable": len(findings_list) > 0,
            "findings": findings_list,
            "details": scan_results,
            "scan_type": f"subdomain_advanced_{scan_type}",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(domain, scan_type='full', **kwargs):
    """Module-level entry point for ZYLON integration"""
    engine = SubdomainAdvancedEngine(domain=domain)
    return engine.run(domain, scan_type=scan_type, **kwargs)
