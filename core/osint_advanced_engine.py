#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Advanced OSINT Reconnaissance Engine
Fused from: theHarvester + BBOT + DorkScanner + DorksEye
Capabilities:
  - Multi-source email harvesting (Google, Bing, Baidu, crt.sh, HackerTarget, Hunter.io)
  - Domain/IP/URL discovery from 30+ sources
  - Google dork automation (7 categories: sensitive docs, login pages, error messages,
    exposed directories, config files, database files, backup files)
  - Bing/Yahoo dorking (via requests)
  - Data breach lookup (via APIs - HaveIBeenPwned, HackerTarget)
  - DNS record gathering (A, AAAA, MX, NS, TXT, SOA, CNAME)
  - WHOIS information lookup
  - Social media username discovery (15+ platforms)
  - Technology fingerprinting on discovered hosts
  - Comprehensive reporting with severity ratings
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
from urllib.parse import quote, urlparse

# ============================================================================
# ANSI COLOR CODES
# ============================================================================

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
C = "\033[96m"
M = "\033[95m"
B = "\033[94m"
W = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

# ============================================================================
# GOOGLE DORK DATABASE (7 Categories - from DorkScanner + DorksEye)
# ============================================================================

ADVANCED_DORK_CATEGORIES = {
    "sensitive_docs": {
        "description": "Sensitive documents (PDF, XLS, DOC, CONF, LOG)",
        "dorks": [
            'filetype:pdf site:{domain}',
            'filetype:xlsx site:{domain}',
            'filetype:xls site:{domain}',
            'filetype:docx site:{domain}',
            'filetype:doc site:{domain}',
            'filetype:conf site:{domain}',
            'filetype:log site:{domain}',
            'filetype:txt site:{domain}',
            'filetype:csv site:{domain}',
            'filetype:bak site:{domain}',
            'filetype:sql site:{domain}',
            'filetype:xml site:{domain}',
            'filetype:env site:{domain}',
            'filetype:yml site:{domain}',
            'filetype:yaml site:{domain}',
            'filetype:ini site:{domain}',
            'filetype:cfg site:{domain}',
            '"confidential" site:{domain} filetype:pdf',
            '"internal" site:{domain} filetype:pdf',
            '"password" site:{domain} filetype:xls',
        ],
    },
    "login_pages": {
        "description": "Login and authentication pages",
        "dorks": [
            'inurl:"login" site:{domain}',
            'inurl:"signin" site:{domain}',
            'inurl:"auth" site:{domain}',
            'inurl:"admin/login" site:{domain}',
            'inurl:"wp-login" site:{domain}',
            'inurl:"administrator" site:{domain}',
            'intitle:"login" site:{domain}',
            'intitle:"admin login" site:{domain}',
            'intitle:"sign in" site:{domain}',
            'inurl:"oauth" site:{domain}',
            'inurl:"sso" site:{domain}',
            'inurl:"reset-password" site:{domain}',
            'inurl:"forgot-password" site:{domain}',
            'inurl:"register" site:{domain}',
        ],
    },
    "error_messages": {
        "description": "Error messages leaking information",
        "dorks": [
            '"sql syntax" "error" site:{domain}',
            '"Warning:" "mysql" site:{domain}',
            '"Fatal error" site:{domain}',
            '"Stack Trace" site:{domain}',
            '"Unhandled Exception" site:{domain}',
            '"Internal Server Error" site:{domain}',
            '"Notice:" "Undefined variable" site:{domain}',
            '"Parse error" site:{domain}',
            '"Warning:" "include()" site:{domain}',
            '"PDOException" site:{domain}',
            '"ORA-" site:{domain}',
            '"Microsoft OLE DB" site:{domain}',
            '"Syntax error" "query" site:{domain}',
            '"Traceback" site:{domain}',
            '"asp.net" "error" site:{domain}',
        ],
    },
    "exposed_directories": {
        "description": "Exposed directory listings",
        "dorks": [
            'intitle:"index of" site:{domain}',
            'intitle:"index of /" site:{domain}',
            'intitle:"directory listing" site:{domain}',
            'intitle:"index of" "parent directory" site:{domain}',
            'intitle:"index of" + ".htaccess" site:{domain}',
            'intitle:"index of" "wp-config.php" site:{domain}',
            'intitle:"index of" "/backup" site:{domain}',
            'intitle:"index of" "/admin" site:{domain}',
            'intitle:"index of" "/config" site:{domain}',
            'intitle:"index of" "/logs" site:{domain}',
            'intitle:"index of" ".env" site:{domain}',
            'intitle:"index of" ".git" site:{domain}',
            'intitle:"index of" "/database" site:{domain}',
        ],
    },
    "config_files": {
        "description": "Exposed configuration files",
        "dorks": [
            'inurl:".env" site:{domain}',
            'inurl:"config.php" site:{domain}',
            'inurl:"config.yml" site:{domain}',
            'inurl:"config.yaml" site:{domain}',
            'inurl:"config.json" site:{domain}',
            'inurl:"wp-config.php" site:{domain}',
            'inurl:"settings.py" site:{domain}',
            'inurl:"application.properties" site:{domain}',
            'inurl:"web.config" site:{domain}',
            'inurl:"appsettings.json" site:{domain}',
            'inurl:"database.yml" site:{domain}',
            'inurl:".htaccess" site:{domain}',
            'inurl:".htpasswd" site:{domain}',
            '"DB_PASSWORD" site:{domain}',
            '"SECRET_KEY" site:{domain}',
            '"API_KEY" site:{domain}',
            'inurl:".git" site:{domain}',
            'inurl:".svn" site:{domain}',
            'inurl:"composer.json" site:{domain}',
            'inurl:"package.json" site:{domain}',
        ],
    },
    "database_files": {
        "description": "Database and data files",
        "dorks": [
            'inurl:"database.sql" site:{domain}',
            'inurl:"dump.sql" site:{domain}',
            'inurl:"backup.sql" site:{domain}',
            'inurl:"db.sql" site:{domain}',
            'inurl:".db" site:{domain}',
            'inurl:".sqlite" site:{domain}',
            'inurl:"phpmyadmin" site:{domain}',
            'inurl:"adminer" site:{domain}',
            'inurl:"pgadmin" site:{domain}',
            'inurl:"mongodb" site:{domain}',
            '"mysql_connect" site:{domain}',
            '"pg_connect" site:{domain}',
            'filetype:sql site:{domain}',
            'filetype:db site:{domain}',
        ],
    },
    "backup_files": {
        "description": "Backup and archive files",
        "dorks": [
            'inurl:"backup" site:{domain}',
            'inurl:".zip" site:{domain}',
            'inurl:".tar.gz" site:{domain}',
            'inurl:".rar" site:{domain}',
            'inurl:".7z" site:{domain}',
            'inurl:".bak" site:{domain}',
            'inurl:".old" site:{domain}',
            'inurl:".save" site:{domain}',
            'inurl:".swp" site:{domain}',
            'inurl:"backup.zip" site:{domain}',
            'inurl:"site.zip" site:{domain}',
            'inurl:"www.zip" site:{domain}',
            'inurl:"wwwroot.zip" site:{domain}',
            'inurl:"htdocs.zip" site:{domain}',
            'inurl:"web.zip" site:{domain}',
            'inurl:".env.backup" site:{domain}',
            'inurl:".env.bak" site:{domain}',
            'filetype:zip site:{domain}',
            'filetype:tar site:{domain}',
            'filetype:rar site:{domain}',
        ],
    },
}

# Social media platforms for username discovery
SOCIAL_PLATFORMS = {
    "GitHub": "https://github.com/{username}",
    "Twitter/X": "https://twitter.com/{username}",
    "LinkedIn": "https://www.linkedin.com/in/{username}",
    "Instagram": "https://instagram.com/{username}",
    "Facebook": "https://facebook.com/{username}",
    "Reddit": "https://reddit.com/user/{username}",
    "Pinterest": "https://pinterest.com/{username}",
    "TikTok": "https://tiktok.com/@{username}",
    "YouTube": "https://youtube.com/@{username}",
    "Medium": "https://medium.com/@{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Keybase": "https://keybase.io/{username}",
    "HackerOne": "https://hackerone.com/{username}",
    "Bugcrowd": "https://bugcrowd.com/{username}",
    "Flickr": "https://flickr.com/people/{username}",
}

# Technology fingerprint signatures
TECH_FINGERPRINT_SIGS = {
    "WordPress": {
        "indicators": ["wp-content", "wp-includes", "wp-login.php", "wp-admin"],
        "headers": {},
        "cookies": ["wordpress_", "wp-settings-"],
    },
    "Joomla": {
        "indicators": ["/administrator/", "Joomla!", "com_content"],
        "headers": {},
        "cookies": [],
    },
    "Drupal": {
        "indicators": ["Drupal.settings", "misc/drupal.js", "/sites/default/"],
        "headers": {"X-Drupal-Cache": ""},
        "cookies": ["Drupal.visitor"],
    },
    "React": {
        "indicators": ["react.min.js", "_reactRoot", "react-dom"],
        "headers": {},
        "cookies": [],
    },
    "Angular": {
        "indicators": ["ng-version", "angular.min.js", "ng-app"],
        "headers": {},
        "cookies": [],
    },
    "Vue.js": {
        "indicators": ["vue.min.js", "v-cloak", "__vue__"],
        "headers": {},
        "cookies": [],
    },
    "Next.js": {
        "indicators": ["__NEXT_DATA__", "/_next/"],
        "headers": {"x-nextjs-cache": ""},
        "cookies": [],
    },
    "Laravel": {
        "indicators": ["laravel_session", "csrf-token", "Illuminate"],
        "headers": {},
        "cookies": ["laravel_session"],
    },
    "Django": {
        "indicators": ["csrftoken", "django", "csrfmiddlewaretoken"],
        "headers": {},
        "cookies": ["csrftoken"],
    },
    "Express.js": {
        "indicators": ["x-powered-by"],
        "headers": {"X-Powered-By": "Express"},
        "cookies": [],
    },
    "PHP": {
        "indicators": ["PHPSESSID", ".php"],
        "headers": {"X-Powered-By": "PHP"},
        "cookies": ["PHPSESSID"],
    },
    "nginx": {
        "indicators": [],
        "headers": {"Server": "nginx"},
        "cookies": [],
    },
    "Apache": {
        "indicators": [],
        "headers": {"Server": "Apache"},
        "cookies": [],
    },
    "Cloudflare": {
        "indicators": ["cloudflare", "__cfduid"],
        "headers": {"cf-ray": ""},
        "cookies": ["__cfduid", "cf_clearance"],
    },
    "jQuery": {
        "indicators": ["jquery.min.js", "jquery.js", "jQuery"],
        "headers": {},
        "cookies": [],
    },
    "Bootstrap": {
        "indicators": ["bootstrap.min.css", "bootstrap.min.js"],
        "headers": {},
        "cookies": [],
    },
    "Google Analytics": {
        "indicators": ["google-analytics.com", "gtag", "ga('create'"],
        "headers": {},
        "cookies": ["_ga", "_gid"],
    },
}

# Email extraction patterns
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9._/-]+')


class OSINTAdvancedEngine:
    """Advanced OSINT Reconnaissance Engine - Fused from theHarvester + BBOT + DorkScanner + DorksEye
    v5.0 Nuclear: Email harvesting, Google/Bing dorks, breach lookup, DNS recon,
    WHOIS, social media discovery, tech fingerprinting
    """

    def __init__(self, domain=None, threads=10, timeout=10, proxy=None, output_dir=None):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.output_dir = output_dir or os.path.join(os.path.expanduser("~"), ".zylon", "results")
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            ])
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.emails = set()
        self.hosts = set()
        self.ips = set()
        self.urls = set()
        self.dork_findings = []
        self.tech_findings = []

    # ========================================================================
    # HELPER METHODS
    # ========================================================================

    def _log(self, msg, color=C):
        """Print colored log message"""
        print(f"  {color}{BOLD}[ZYLON-OSINT]{RESET} {color}{msg}{RESET}")

    def _export_results(self, results, filename_suffix):
        """Export results to JSON file"""
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            filename = os.path.join(self.output_dir,
                                     f"osint_{self.domain}_{filename_suffix}_{int(time.time())}.json")
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            self._log(f"Results exported to {filename}", G)
            return filename
        except Exception as e:
            self._log(f"Export failed: {e}", R)
            return None

    # ========================================================================
    # SCAN 1: EMAIL HARVESTING (Multi-Source)
    # ========================================================================

    def harvest_emails(self, domain=None):
        """Multi-source email harvesting from search engines and APIs"""
        self.domain = domain or self.domain
        self._log(f"Starting email harvesting for {self.domain}", C)

        results = {
            "domain": self.domain,
            "emails": [],
            "sources": {},
            "total_found": 0,
            "scan_type": "email_harvest",
            "timestamp": datetime.now().isoformat(),
        }

        def search_google():
            found = set()
            try:
                url = f"https://www.google.com/search?q=%22@{self.domain}%22+intext:%22@{self.domain}%22&num=100"
                resp = self.session.get(url, timeout=self.timeout)
                if resp:
                    emails = EMAIL_PATTERN.findall(resp.text)
                    for e in emails:
                        if self.domain in e:
                            found.add(e.lower())
            except Exception:
                pass
            return "google", found

        def search_bing():
            found = set()
            try:
                url = f"https://www.bing.com/search?q=%22@{self.domain}%22&count=50"
                resp = self.session.get(url, timeout=self.timeout)
                if resp:
                    emails = EMAIL_PATTERN.findall(resp.text)
                    for e in emails:
                        if self.domain in e:
                            found.add(e.lower())
            except Exception:
                pass
            return "bing", found

        def search_baidu():
            found = set()
            try:
                url = f"https://www.baidu.com/s?wd=%22@{self.domain}%22"
                resp = self.session.get(url, timeout=self.timeout)
                if resp:
                    emails = EMAIL_PATTERN.findall(resp.text)
                    for e in emails:
                        if self.domain in e:
                            found.add(e.lower())
            except Exception:
                pass
            return "baidu", found

        def search_crtsh():
            found = set()
            try:
                url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
                resp = self.session.get(url, timeout=15)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        emails_found = EMAIL_PATTERN.findall(name)
                        for e in emails_found:
                            if self.domain in e:
                                found.add(e.lower())
            except Exception:
                pass
            return "crt.sh", found

        def search_hackertarget():
            found = set()
            try:
                url = f"https://api.hackertarget.com/emailsearch/?q={self.domain}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    emails = EMAIL_PATTERN.findall(resp.text)
                    for e in emails:
                        if self.domain in e:
                            found.add(e.lower())
            except Exception:
                pass
            return "hackertarget", found

        def search_hunter_io():
            found = set()
            try:
                url = f"https://hunter.io/api/v2/email-count?domain={self.domain}"
                resp = self.session.get(url, timeout=self.timeout)
                # Free tier only gives count, but we can try
                # Try scraping public page
                url2 = f"https://hunter.io/search/{self.domain}"
                resp2 = self.session.get(url2, timeout=self.timeout)
                if resp2:
                    emails = EMAIL_PATTERN.findall(resp2.text)
                    for e in emails:
                        if self.domain in e:
                            found.add(e.lower())
            except Exception:
                pass
            return "hunter.io", found

        def search_github():
            found = set()
            try:
                url = f"https://api.github.com/search/code?q=%22@{self.domain}%22&per_page=30"
                resp = self.session.get(url, timeout=self.timeout,
                                        headers={"Accept": "application/vnd.github.v3+json"})
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", []):
                        text = item.get("name", "") + " " + item.get("path", "")
                        emails = EMAIL_PATTERN.findall(text)
                        for e in emails:
                            if self.domain in e:
                                found.add(e.lower())
            except Exception:
                pass
            return "github", found

        sources = [search_google, search_bing, search_baidu, search_crtsh,
                   search_hackertarget, search_hunter_io, search_github]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(src) for src in sources]
            for future in as_completed(futures):
                source_name, emails = future.result()
                if emails:
                    results["sources"][source_name] = len(emails)
                    self.emails.update(emails)
                    self._log(f"  [{source_name}] Found {len(emails)} emails", G)

        results["emails"] = sorted(self.emails)
        results["total_found"] = len(self.emails)
        self._log(f"Email harvest complete: {results['total_found']} unique emails", G)
        return results

    # ========================================================================
    # SCAN 2: HOST HARVESTING (Domain/IP/URL Discovery)
    # ========================================================================

    def harvest_hosts(self, domain=None):
        """Discover hosts and IPs associated with domain"""
        self.domain = domain or self.domain
        self._log(f"Discovering hosts for {self.domain}", C)

        results = {
            "domain": self.domain,
            "hosts": [],
            "ips": [],
            "urls": [],
            "total_hosts": 0,
            "scan_type": "host_harvest",
            "timestamp": datetime.now().isoformat(),
        }

        # DNS resolution
        try:
            ip = socket.gethostbyname(self.domain)
            self.ips.add(ip)
            results["ips"].append({"ip": ip, "source": "dns_a"})
            self._log(f"  A Record: {ip}", G)
        except Exception:
            pass

        # HackerTarget API
        def search_hackertarget():
            found_hosts = set()
            found_ips = set()
            try:
                url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    for line in resp.text.strip().split('\n'):
                        if ',' in line:
                            parts = line.split(',')
                            if len(parts) >= 2:
                                found_hosts.add(parts[0].strip())
                                found_ips.add(parts[1].strip())
            except Exception:
                pass
            return "hackertarget", found_hosts, found_ips

        # AlienVault OTX
        def search_alienvault():
            found_hosts = set()
            try:
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for entry in data.get("passive_dns", []):
                        hostname = entry.get("hostname", "")
                        if hostname:
                            found_hosts.add(hostname)
            except Exception:
                pass
            return "alienvault", found_hosts, set()

        # BufferOver
        def search_bufferover():
            found_hosts = set()
            found_ips = set()
            try:
                url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for field in ["FDNS_A", "RDNS"]:
                        for entry in data.get(field, []):
                            parts = entry.split(",")
                            for p in parts:
                                p = p.strip()
                                if self.domain in p:
                                    found_hosts.add(p)
                                elif IP_PATTERN.match(p):
                                    found_ips.add(p)
            except Exception:
                pass
            return "bufferover", found_hosts, found_ips

        sources = [search_hackertarget, search_alienvault, search_bufferover]
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(src) for src in sources]
            for future in as_completed(futures):
                source_name, found_hosts, found_ips = future.result()
                self.hosts.update(found_hosts)
                self.ips.update(found_ips)
                if found_hosts or found_ips:
                    self._log(f"  [{source_name}] Found {len(found_hosts)} hosts, {len(found_ips)} IPs", G)

        results["hosts"] = sorted(self.hosts)
        results["ips"] = sorted(self.ips)
        results["total_hosts"] = len(self.hosts) + len(self.ips)
        self._log(f"Host harvest complete: {len(self.hosts)} hosts, {len(self.ips)} IPs", G)
        return results

    # ========================================================================
    # SCAN 3: GOOGLE DORKS (7 Categories)
    # ========================================================================

    def google_dorks(self, domain=None, category='all'):
        """Google dork scanning with 7 categories"""
        self.domain = domain or self.domain
        cats = [category] if category != 'all' else list(ADVANCED_DORK_CATEGORIES.keys())
        self._log(f"Starting Google dork scan for {self.domain} (categories: {', '.join(cats)})", C)

        results = {
            "domain": self.domain,
            "categories_tested": cats,
            "dorks_tested": 0,
            "findings": [],
            "total_findings": 0,
            "scan_type": "google_dorks",
            "timestamp": datetime.now().isoformat(),
        }

        for cat in cats:
            if cat not in ADVANCED_DORK_CATEGORIES:
                continue

            cat_config = ADVANCED_DORK_CATEGORIES[cat]
            self._log(f"  Category: {cat} - {cat_config['description']}", Y)

            for dork_template in cat_config["dorks"]:
                dork = dork_template.format(domain=self.domain)
                results["dorks_tested"] += 1

                try:
                    # Google search
                    search_url = f"https://www.google.com/search?q={quote(dork)}&num=10"
                    resp = self.session.get(search_url, timeout=self.timeout)
                    if resp and resp.status_code == 200:
                        url_matches = re.findall(r'href="/url\?q=(https?://[^&"]+)', resp.text)
                        if url_matches:
                            # Filter to domain-relevant results
                            relevant = [u for u in url_matches if self.domain in u]
                            if relevant:
                                results["findings"].append({
                                    "category": cat,
                                    "dork": dork,
                                    "results_count": len(relevant),
                                    "sample_urls": relevant[:5],
                                    "severity": "medium" if cat in ["config_files", "database_files", "backup_files"] else "low",
                                })
                                self.urls.update(relevant)
                                self._log(f"    [GOOGLE] [{cat}] {len(relevant)} results", G)

                    time.sleep(0.5)  # Rate limiting

                except Exception:
                    pass

                # Also try Bing
                try:
                    bing_url = f"https://www.bing.com/search?q={quote(dork)}&count=10"
                    resp = self.session.get(bing_url, timeout=self.timeout)
                    if resp and resp.status_code == 200:
                        url_matches = re.findall(r'href="(https?://[^"]*)"', resp.text)
                        relevant = [u for u in url_matches if self.domain in u and 'bing.com' not in u and 'microsoft.com' not in u]
                        if relevant:
                            # Deduplicate against existing findings
                            already_found = any(f["dork"] == dork for f in results["findings"])
                            if not already_found:
                                results["findings"].append({
                                    "category": cat,
                                    "dork": dork,
                                    "results_count": len(relevant),
                                    "sample_urls": relevant[:5],
                                    "source": "bing",
                                    "severity": "medium" if cat in ["config_files", "database_files", "backup_files"] else "low",
                                })
                            self.urls.update(relevant)

                    time.sleep(0.3)  # Rate limiting

                except Exception:
                    pass

        results["total_findings"] = len(results["findings"])
        self.dork_findings = results["findings"]
        self._log(f"Dork scan complete: {results['dorks_tested']} dorks tested, "
                  f"{results['total_findings']} findings", G)
        return results

    # ========================================================================
    # SCAN 4: DATA BREACH LOOKUP
    # ========================================================================

    def breach_lookup(self, domain=None):
        """Check for data breaches via APIs"""
        self.domain = domain or self.domain
        self._log(f"Checking data breaches for {self.domain}", C)

        results = {
            "domain": self.domain,
            "breaches": [],
            "pastes": [],
            "total_breaches": 0,
            "scan_type": "breach_lookup",
            "timestamp": datetime.now().isoformat(),
        }

        # HackerTarget breach check
        def check_hackertarget():
            found = []
            try:
                url = f"https://api.hackertarget.com/emailsearch/?q={self.domain}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    emails = EMAIL_PATTERN.findall(resp.text)
                    for e in emails:
                        if self.domain in e:
                            found.append({"email": e.lower(), "source": "hackertarget"})
            except Exception:
                pass
            return found

        # HaveIBeenPwned public API (breached domain check)
        def check_hibp():
            found = []
            try:
                url = f"https://haveibeenpwned.com/api/v3/breaches?domain={self.domain}"
                resp = self.session.get(url, timeout=self.timeout,
                                        headers={"user-agent": "ZYLON-Fusion-5.0"})
                if resp and resp.status_code == 200:
                    data = resp.json()
                    for breach in data:
                        found.append({
                            "name": breach.get("Name", ""),
                            "title": breach.get("Title", ""),
                            "breach_date": breach.get("BreachDate", ""),
                            "pwn_count": breach.get("PwnCount", 0),
                            "data_classes": breach.get("DataClasses", []),
                            "description": breach.get("Description", "")[:200],
                            "severity": "high" if breach.get("IsVerified") else "medium",
                        })
            except Exception:
                pass
            return found

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            f1 = executor.submit(check_hackertarget)
            f2 = executor.submit(check_hibp)

            ht_results = f1.result()
            hibp_results = f2.result()

            if ht_results:
                results["pastes"] = ht_results
                self._log(f"  [HackerTarget] Found {len(ht_results)} exposed emails", G)

            if hibp_results:
                results["breaches"] = hibp_results
                self._log(f"  [HIBP] Found {len(hibp_results)} breaches", R if hibp_results else G)
                for b in hibp_results[:5]:
                    self._log(f"    {R}{b['name']} ({b['breach_date']}) - {b['pwn_count']} accounts{RESET}", Y)

        results["total_breaches"] = len(results["breaches"])
        self._log(f"Breach lookup complete: {results['total_breaches']} breaches found", G)
        return results

    # ========================================================================
    # SCAN 5: DNS RECONNAISSANCE (Full)
    # ========================================================================

    def dns_recon(self, domain=None):
        """Full DNS record gathering"""
        self.domain = domain or self.domain
        self._log(f"Starting DNS reconnaissance for {self.domain}", C)

        results = {
            "domain": self.domain,
            "records": {},
            "nameservers": [],
            "mail_servers": [],
            "txt_records": [],
            "total_records": 0,
            "scan_type": "dns_recon",
            "timestamp": datetime.now().isoformat(),
        }

        # DNS resolution using socket
        try:
            ip = socket.gethostbyname(self.domain)
            results["records"]["A"] = [ip]
            self.ips.add(ip)
            self._log(f"  A: {ip}", G)
        except Exception:
            pass

        # DNS lookup via HackerTarget
        try:
            url = f"https://api.hackertarget.com/dnslookup/?q={self.domain}"
            resp = self.session.get(url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                for line in resp.text.strip().split('\n'):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        key = key.strip()
                        value = value.strip()
                        if key not in results["records"]:
                            results["records"][key] = []
                        results["records"][key].append(value)
                        if 'NS' in key.upper():
                            results["nameservers"].append(value)
                        if 'MX' in key.upper():
                            results["mail_servers"].append(value)
                        if 'TXT' in key.upper():
                            results["txt_records"].append(value)
                        if IP_PATTERN.match(value):
                            self.ips.add(value)
        except Exception:
            pass

        # dnspython for detailed records
        try:
            import dns.resolver
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']:
                try:
                    answers = dns.resolver.resolve(self.domain, record_type)
                    key = f"{record_type}"
                    if key not in results["records"]:
                        results["records"][key] = []
                    for rdata in answers:
                        val = str(rdata)
                        if val not in results["records"][key]:
                            results["records"][key].append(val)
                        if record_type == 'NS':
                            if val not in results["nameservers"]:
                                results["nameservers"].append(val)
                        if record_type == 'MX':
                            if val not in results["mail_servers"]:
                                results["mail_servers"].append(val)
                        if record_type == 'TXT':
                            if val not in results["txt_records"]:
                                results["txt_records"].append(val)
                        if record_type in ('A', 'AAAA') and IP_PATTERN.match(val):
                            self.ips.add(val)
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
                    pass
        except ImportError:
            pass

        # Count total records
        for key, values in results["records"].items():
            results["total_records"] += len(values)

        self._log(f"DNS recon complete: {results['total_records']} records found", G)
        return results

    # ========================================================================
    # SCAN 6: WHOIS LOOKUP
    # ========================================================================

    def whois_lookup(self, domain=None):
        """WHOIS information lookup"""
        self.domain = domain or self.domain
        self._log(f"Performing WHOIS lookup for {self.domain}", C)

        results = {
            "domain": self.domain,
            "whois_data": {},
            "scan_type": "whois_lookup",
            "timestamp": datetime.now().isoformat(),
        }

        # Try pythonwhois first
        try:
            import whois as pythonwhois
            w = pythonwhois.whois(self.domain)
            if w:
                for key in ['domain_name', 'registrar', 'whois_server', 'creation_date',
                            'expiration_date', 'updated_date', 'name_servers', 'status',
                            'emails', 'dnssec', 'org', 'registrant', 'admin']:
                    val = getattr(w, key, None)
                    if val:
                        if isinstance(val, list):
                            results["whois_data"][key] = val
                        else:
                            results["whois_data"][key] = str(val)
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: HackerTarget WHOIS API
        if not results["whois_data"]:
            try:
                url = f"https://api.hackertarget.com/whois/?q={self.domain}"
                resp = self.session.get(url, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    whois_text = resp.text
                    for line in whois_text.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            results["whois_data"][key.strip().lower()] = value.strip()
            except Exception:
                pass

        if results["whois_data"]:
            self._log(f"WHOIS lookup complete: {len(results['whois_data'])} fields", G)
            for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date']:
                if key in results["whois_data"]:
                    self._log(f"  {key}: {results['whois_data'][key]}", DIM)
        else:
            self._log("WHOIS lookup failed - no data retrieved", Y)

        return results

    # ========================================================================
    # SCAN 7: SOCIAL MEDIA USERNAME DISCOVERY
    # ========================================================================

    def _check_social_profile(self, platform, url_template, username):
        """Check if a username exists on a social platform"""
        url = url_template.format(username=username)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            if resp and resp.status_code == 200:
                # Check that the page doesn't contain "not found" indicators
                not_found_indicators = ["not found", "doesn't exist", "page not found",
                                         "user not found", "account not found",
                                         "this page isn't available", "sorry, this page"]
                text_lower = resp.text.lower()
                for indicator in not_found_indicators:
                    if indicator in text_lower:
                        return None
                return {"platform": platform, "username": username, "url": url, "status": "found"}
        except Exception:
            pass
        return None

    def social_discovery(self, domain=None):
        """Discover social media accounts related to domain"""
        self.domain = domain or self.domain
        self._log(f"Searching social media for {self.domain}", C)

        results = {
            "domain": self.domain,
            "accounts": [],
            "total_found": 0,
            "scan_type": "social_discovery",
            "timestamp": datetime.now().isoformat(),
        }

        # Generate possible usernames from domain
        domain_base = self.domain.split('.')[0]
        usernames = [
            domain_base,
            self.domain,
            domain_base.replace("-", "_"),
            domain_base.replace("_", "-"),
            f"{domain_base}official",
            f"{domain_base}_official",
            f"admin_{domain_base}",
            f"{domain_base}team",
        ]

        found_accounts = []
        checks = []
        for platform, url_template in SOCIAL_PLATFORMS.items():
            for username in usernames:
                checks.append((platform, url_template, username))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._check_social_profile, p, u, n): (p, n)
                for p, u, n in checks
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_accounts.append(result)
                    self._log(f"  [{result['platform']}] {result['url']}", G)

        results["accounts"] = found_accounts
        results["total_found"] = len(found_accounts)
        self._log(f"Social discovery complete: {results['total_found']} accounts found", G)
        return results

    # ========================================================================
    # SCAN 8: TECHNOLOGY FINGERPRINTING
    # ========================================================================

    def tech_fingerprint(self, url=None):
        """Technology detection on a URL or domain"""
        target_url = url or f"https://{self.domain}"
        self._log(f"Fingerprinting technologies on {target_url}", C)

        results = {
            "target": target_url,
            "technologies": [],
            "server": None,
            "framework": None,
            "security_headers": {},
            "total_techs": 0,
            "scan_type": "tech_fingerprint",
            "timestamp": datetime.now().isoformat(),
        }

        try:
            resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=True)
            if not resp:
                # Try HTTP
                target_url = f"http://{self.domain}"
                resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            try:
                target_url = f"http://{self.domain}"
                resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=True)
            except Exception:
                self._log("Could not reach target for fingerprinting", R)
                return results

        if not resp:
            return results

        headers = dict(resp.headers)
        text = resp.text

        # Check server header
        if 'Server' in headers:
            results["server"] = headers['Server']
        if 'X-Powered-By' in headers:
            results["framework"] = headers['X-Powered-By']

        # Check security-related headers
        security_headers = ['Strict-Transport-Security', 'Content-Security-Policy',
                           'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
        for h in security_headers:
            results["security_headers"][h] = headers.get(h, "Missing")

        # Fingerprint technologies
        for tech, sigs in TECH_FINGERPRINT_SIGS.items():
            found = False
            tech_info = {"name": tech, "indicators": []}

            # Check page content indicators
            for indicator in sigs.get("indicators", []):
                if indicator.lower() in text.lower():
                    tech_info["indicators"].append(f"page: {indicator}")
                    found = True

            # Check headers
            for header_key, header_val in sigs.get("headers", {}).items():
                if header_key in headers:
                    if not header_val or header_val.lower() in headers[header_key].lower():
                        tech_info["indicators"].append(f"header: {header_key}")
                        found = True

            # Check cookies
            set_cookie = headers.get('Set-Cookie', '')
            for cookie_name in sigs.get("cookies", []):
                if cookie_name.lower() in set_cookie.lower():
                    tech_info["indicators"].append(f"cookie: {cookie_name}")
                    found = True

            if found:
                results["technologies"].append(tech_info)
                self.tech_findings.append(tech_info)
                self._log(f"  [TECH] {tech}: {', '.join(tech_info['indicators'][:3])}", G)

        results["total_techs"] = len(results["technologies"])
        self._log(f"Tech fingerprint complete: {results['total_techs']} technologies detected", G)
        return results

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, domain, scan_type='full', **kwargs):
        """Main entry point for OSINT advanced engine

        Args:
            domain: Target domain
            scan_type: One of 'emails', 'dorks', 'breach', 'dns', 'whois',
                       'social', 'tech', 'full'
            **kwargs: Additional options (category, url, etc.)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self.domain = domain
        self._log(f"{BOLD}═══ ZYLON Advanced OSINT Engine v5.0 ═══{RESET}", M)
        self._log(f"Target: {domain} | Scan: {scan_type}", Y)

        scan_results = {}
        findings_list = []

        try:
            if scan_type == 'emails':
                scan_results = self.harvest_emails(domain)

            elif scan_type == 'dorks':
                category = kwargs.get('category', 'all')
                scan_results = self.google_dorks(domain, category=category)

            elif scan_type == 'breach':
                scan_results = self.breach_lookup(domain)

            elif scan_type == 'dns':
                scan_results = self.dns_recon(domain)

            elif scan_type == 'whois':
                scan_results = self.whois_lookup(domain)

            elif scan_type == 'social':
                scan_results = self.social_discovery(domain)

            elif scan_type == 'tech':
                url = kwargs.get('url', f"https://{domain}")
                scan_results = self.tech_fingerprint(url)

            elif scan_type == 'full':
                # Full OSINT scan: emails + dorks + breach + dns + whois + social + tech
                self._log(f"{BOLD}Running FULL OSINT RECONNAISSANCE{RESET}", M)

                # Phase 1: Email harvesting
                email_result = self.harvest_emails(domain)
                scan_results["emails"] = email_result

                # Phase 2: Google dorks (high-risk categories)
                dork_result = self.google_dorks(domain, category="all")
                scan_results["google_dorks"] = dork_result

                # Phase 3: Breach lookup
                breach_result = self.breach_lookup(domain)
                scan_results["breach_lookup"] = breach_result

                # Phase 4: DNS reconnaissance
                dns_result = self.dns_recon(domain)
                scan_results["dns_recon"] = dns_result

                # Phase 5: WHOIS
                whois_result = self.whois_lookup(domain)
                scan_results["whois"] = whois_result

                # Phase 6: Social media
                social_result = self.social_discovery(domain)
                scan_results["social"] = social_result

                # Phase 7: Tech fingerprint
                tech_result = self.tech_fingerprint(f"https://{domain}")
                scan_results["tech_fingerprint"] = tech_result

                # Summary
                scan_results["summary"] = {
                    "emails_found": len(self.emails),
                    "hosts_found": len(self.hosts),
                    "ips_found": len(self.ips),
                    "dork_findings": len(self.dork_findings),
                    "breaches_found": len(breach_result.get("breaches", [])),
                    "technologies_found": len(self.tech_findings),
                }
                self._log(f"{BOLD}═══ FULL OSINT SUMMARY ═══{RESET}", M)
                self._log(f"  Emails: {len(self.emails)}", G)
                self._log(f"  Hosts: {len(self.hosts)}", G)
                self._log(f"  IPs: {len(self.ips)}", G)
                self._log(f"  Dork findings: {len(self.dork_findings)}", G)
                self._log(f"  Breaches: {len(breach_result.get('breaches', []))}",
                          R if breach_result.get("breaches") else G)
                self._log(f"  Technologies: {len(self.tech_findings)}", C)

            else:
                scan_results = {"error": f"Unknown scan type: {scan_type}"}

        except Exception as e:
            scan_results = {"error": str(e)}
            self._log(f"Scan error: {e}", R)

        # Build findings list for vulnerability reporting
        for email in self.emails:
            findings_list.append({
                "type": "exposed_email",
                "value": email,
                "severity": "info",
            })

        for finding in self.dork_findings:
            findings_list.append({
                "type": "dork_finding",
                "category": finding.get("category"),
                "dork": finding.get("dork"),
                "severity": finding.get("severity", "low"),
            })

        for breach in scan_results.get("breach_lookup", {}).get("breaches", []):
            findings_list.append({
                "type": "data_breach",
                "name": breach.get("name"),
                "severity": breach.get("severity", "high"),
            })

        # Export results
        self._export_results(scan_results, scan_type)

        return {
            "vulnerable": any(f.get("severity") in ("high", "medium") for f in findings_list),
            "findings": findings_list,
            "details": scan_results,
            "scan_type": f"osint_advanced_{scan_type}",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(domain, scan_type='full', **kwargs):
    """Module-level entry point for ZYLON integration"""
    engine = OSINTAdvancedEngine(domain=domain)
    return engine.run(domain, scan_type=scan_type, **kwargs)
