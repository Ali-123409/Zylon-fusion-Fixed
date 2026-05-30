"""
ZYLON FUSION - Origin IP Finder Engine
Advanced CDN/WAF Bypass - Find Real Server IP Behind Cloudflare, Akamai, Sucuri, etc.
Termux Non-Root Compatible - All API/web-based, no raw sockets needed

22 Advanced Techniques:
 1. CDN Detection & Fingerprinting
 2. DNS Historical Record Lookup (SecurityTrails, ViewDNS)
 3. SSL/TLS Certificate Transparency (crt.sh, Censys)
 4. Subdomain Resolution & CDN IP Filtering
 5. DNS Record Mining (MX, TXT, SPF, NS, SOA)
 6. CNAME Chain Following
 7. Web Archive History (Wayback Machine)
 8. Shodan Internet-Wide Search
 9. Censys Certificate & Host Search
10. Favicon Hash Fingerprinting
11. Email Header IP Extraction (SPF/DKIM)
12. Error Page IP Leakage Detection
13. Server Status/Info Page Mining
14. XML/Sitemap Internal IP Parsing
15. Internal Resource IP Leak (JS/CSS/Images)
16. DNS Zone Transfer Attempt (AXFR)
17. Cloud Provider Metadata Detection
18. ASN/Prefix IP Range Scanning
19. Direct IP Verification with Host Header
20. HTTP Response Header Fingerprinting
21. Multi-Resolver DNS Cross-Validation
22. SPF/DKIM/DMARC IP Range Extraction
"""

import os
import re
import json
import socket
import hashlib
import random
import base64
import ssl
import requests
import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import dns.xfr
from urllib.parse import urlparse, urljoin
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from bs4 import BeautifulSoup

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL, MAX_THREADS
)

# DNS resolver compatibility (dnspython < 2.0 uses query, >= 2.0 uses resolve)
try:
    _dns_resolve = dns.resolver.resolve
except AttributeError:
    _dns_resolve = dns.resolver.query


# Use CDN_IP_RANGES, PUBLIC_DNS_RESOLVERS, and ERROR_TRIGGER_PATHS from var.py for consistency
from core.var import CDN_IP_RANGES, PUBLIC_DNS_RESOLVERS, ERROR_TRIGGER_PATHS

# Additional CDN/Cloud ranges not in var.py (IPv4 only - no IPv6 to avoid type comparison crashes)
_CDN_EXTRA_RANGES = {
    'StackPath': [
        '151.139.0.0/16', '209.107.0.0/17',
    ],
    'Microsoft Azure CDN': [
        '13.107.0.0/16',
    ],
    # AWS Global Accelerator & additional CloudFront ranges
    'AWS Cloud': [
        '13.248.0.0/16',   # AWS Global Accelerator
        '75.2.0.0/16',     # AWS Global Accelerator
        '76.223.0.0/17',   # AWS Global Accelerator
        '76.223.128.0/17', # AWS Global Accelerator
        '99.79.0.0/16',    # AWS
        '52.0.0.0/11',     # AWS EC2 (wide range)
        '54.0.0.0/8',      # AWS (partial)
        '3.0.0.0/8',       # AWS EC2
        '18.0.0.0/8',      # AWS EC2
        '35.0.0.0/8',      # AWS/GCP overlap
    ],
    # Google Cloud / Google Infrastructure
    'Google Cloud': [
        '35.192.0.0/12',   # Google Cloud
        '35.208.0.0/12',   # Google Cloud
        '35.224.0.0/12',   # Google Cloud
        '35.240.0.0/13',   # Google Cloud
        '34.0.0.0/9',      # Google Cloud
        '34.128.0.0/10',   # Google Cloud
        '104.154.0.0/16',  # Google Cloud
        '104.196.0.0/14',  # Google Cloud
        '130.211.0.0/16',  # Google Cloud Load Balancer
        '35.199.0.0/16',   # Google Cloud DNS
        '173.194.0.0/16',  # Google Infrastructure (Mail, etc.)
        '172.217.0.0/16',  # Google Infrastructure
        '142.250.0.0/15',  # Google Infrastructure
        '192.178.0.0/15',  # Google Infrastructure
        '64.233.160.0/19', # Google Infrastructure
        '66.102.0.0/20',   # Google Infrastructure
        '66.249.64.0/19',  # Google Infrastructure
        '72.14.192.0/18',  # Google Infrastructure
        '74.125.0.0/16',   # Google Infrastructure
        '209.85.128.0/17', # Google Infrastructure
        '216.58.192.0/19', # Google Infrastructure
        '216.239.32.0/19', # Google Infrastructure
    ],
    # Azure Hosting
    'Azure Hosting': [
        '20.0.0.0/8',      # Azure (wide range)
        '40.64.0.0/10',    # Azure
        '40.112.0.0/13',   # Azure
        '52.96.0.0/12',    # Azure/Office 365
        '52.224.0.0/11',   # Azure
        '104.40.0.0/13',   # Azure
        '137.116.0.0/15',  # Azure
        '138.91.0.0/16',   # Azure
        '157.55.0.0/16',   # Azure/Office 365
        '191.232.0.0/13',  # Azure
    ],
    # DigitalOcean
    'DigitalOcean': [
        '104.131.0.0/16', '104.236.0.0/16', '128.199.0.0/16',
        '138.68.0.0/16',  '138.197.0.0/16', '159.65.0.0/16',
        '159.89.0.0/16',  '165.227.0.0/16', '167.99.0.0/16',
        '206.189.0.0/16',
    ],
    # Cloudflare WARP/VPN
    'Cloudflare Additional': [
        '162.159.192.0/24', '172.86.96.0/20',
    ],
}

# Merge extra ranges into CDN_IP_RANGES (only IPv4-safe entries)
for _cdn_name, _ranges in _CDN_EXTRA_RANGES.items():
    CDN_IP_RANGES[_cdn_name] = _ranges

# Known mail/infrastructure hostnames that should NEVER be treated as origin IPs
_MAIL_HOST_PATTERNS = [
    'google.com', 'googlemail.com', 'googlemail.l.google.com',
    '1e100.net',  # Google infrastructure
    'mcsv.net', 'rsgsv.net',  # Mailchimp
    'sendgrid.net', 'sendgrid.com',  # SendGrid
    'mailgun.org', 'mailgun.com',  # Mailgun
    'hubspotemail.net',  # HubSpot
    'mail.zendesk.com',  # Zendesk
    'icpbounce.com',  # Adobe/Marketo
    'outlook.com', 'hotmail.com', 'office365.us',  # Microsoft
    'amazonses.com',  # Amazon SES
    'sparkpostmail.com',  # SparkPost
    'postmarkapp.com',  # Postmark
    'yahooinc.com', 'yahoo.com',  # Yahoo
    'zoho.com',  # Zoho Mail
]


import threading

# Thread-local storage for per-thread requests sessions (requests.Session is NOT thread-safe)
_thread_local = threading.local()


def _get_thread_session():
    """Get or create a thread-local requests session for thread safety"""
    if not hasattr(_thread_local, 'session'):
        _thread_local.session = requests.Session()
        _thread_local.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        _thread_local.session.verify = VERIFY_SSL
    return _thread_local.session


class OriginIPEngine:
    """Advanced Origin IP Finder - CDN/WAF Bypass Engine
    Termux Non-Root Compatible"""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = VERIFY_SSL
        self.found_ips = {}  # ip -> [sources that found it]
        self.cdn_detected = None
        self.is_behind_cdn = False

    def _rotate_ua(self):
        """Rotate user agent"""
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    def _is_cdn_ip(self, ip):
        """Check if an IP belongs to a known CDN/proxy/cloud provider"""
        try:
            import ipaddress
            target_ip = ipaddress.ip_address(ip)
            for cdn_name, ranges in CDN_IP_RANGES.items():
                for cidr in ranges:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        # Skip IPv6 networks when checking IPv4 addresses (avoids TypeError)
                        if target_ip.version != network.version:
                            continue
                        if target_ip in network:
                            return cdn_name
                    except (ValueError, TypeError):
                        continue
        except (ValueError, TypeError):
            pass
        return None

    def _is_mail_infrastructure(self, hostname):
        """Check if a hostname belongs to a known mail/infrastructure provider"""
        if not hostname:
            return False
        hostname_lower = hostname.lower().rstrip('.')
        for pattern in _MAIL_HOST_PATTERNS:
            if hostname_lower == pattern or hostname_lower.endswith('.' + pattern):
                return True
        return False

    def _classify_ip_source(self, source_str):
        """Classify the type of IP source for confidence adjustment
        Returns: 'origin' (likely real origin), 'mail' (email infra),
                 'dns' (DNS infra), 'spf' (SPF/mail sender), 'generic'
        """
        source_lower = source_str.lower()
        if 'mx-record' in source_lower or 'mx' in source_lower:
            return 'mail'
        if 'spf' in source_lower or 'dkim' in source_lower:
            return 'spf'
        if 'ns-record' in source_lower or 'soa' in source_lower or 'nameserver' in source_lower:
            return 'dns'
        if 'subdomain' in source_lower or 'crt.sh' in source_lower or 'censys' in source_lower:
            return 'origin'
        if 'cname' in source_lower or 'history' in source_lower or 'wayback' in source_lower:
            return 'origin'
        if 'shodan' in source_lower or 'viewdns' in source_lower or 'hackertarget' in source_lower:
            return 'origin'
        return 'generic'

    @staticmethod
    def _clean_domain(domain):
        """Clean domain: strip protocol, path, port, and leading www. only"""
        domain = domain.strip()
        # Strip protocol
        for proto in ('https://', 'http://'):
            if domain.lower().startswith(proto):
                domain = domain[len(proto):]
        # Strip path
        domain = domain.split('/')[0]
        # Strip port
        domain = domain.split(':')[0]
        # Strip leading www. only (not embedded)
        if domain.lower().startswith('www.'):
            domain = domain[4:]
        return domain

    def _resolve_domain(self, domain, resolver=None):
        """Resolve domain to IP using optional specific DNS resolver"""
        try:
            clean = self._clean_domain(domain)
            if resolver:
                custom_resolver = dns.resolver.Resolver()
                custom_resolver.nameservers = [resolver]
                custom_resolver.timeout = 5
                custom_resolver.lifetime = 5
                # Use compatible resolver call (dnspython <2.0 uses query, >=2.0 uses resolve)
                try:
                    answers = custom_resolver.resolve(clean, 'A')
                except AttributeError:
                    answers = custom_resolver.query(clean, 'A')
                return str(answers[0])
            else:
                return socket.gethostbyname(clean)
        except Exception:
            return None

    def _add_ip(self, ip, source, confidence='medium', details=None, ip_type='origin'):
        """Add a discovered IP to the results with metadata
        ip_type: 'origin' (possible origin IP), 'mail' (email infrastructure),
                 'dns' (DNS infrastructure), 'spf' (SPF/mail sender), 'cdn' (CDN/proxy)
        """
        if not ip or not self._is_valid_public_ip(ip):
            return
        cdn_name = self._is_cdn_ip(ip)
        if cdn_name:
            # CDN/cloud IPs - record but always mark as CDN
            if ip not in self.found_ips:
                self.found_ips[ip] = {
                    'sources': [],
                    'confidence': 'low',
                    'is_cdn': True,
                    'cdn_provider': cdn_name,
                    'ip_type': 'cdn',
                    'details': {}
                }
            self.found_ips[ip]['sources'].append(source)
        else:
            # Check if hostname is mail infrastructure
            hostname = details.get('hostname', details.get('mx_hostname', details.get('spf_include', ''))) if details else ''
            if self._is_mail_infrastructure(hostname) or ip_type in ('mail', 'spf'):
                # Mail/SPF infrastructure - record separately, NOT as origin candidate
                if ip not in self.found_ips:
                    self.found_ips[ip] = {
                        'sources': [],
                        'confidence': 'very_low',
                        'is_cdn': False,
                        'cdn_provider': None,
                        'ip_type': ip_type if ip_type in ('mail', 'spf') else 'mail',
                        'details': {}
                    }
                self.found_ips[ip]['sources'].append(source)
                if details:
                    self.found_ips[ip]['details'].update(details)
                return  # Never upgrade confidence for mail IPs
            elif ip_type == 'dns':
                # DNS infrastructure - record but NOT as origin candidate
                if ip not in self.found_ips:
                    self.found_ips[ip] = {
                        'sources': [],
                        'confidence': 'very_low',
                        'is_cdn': False,
                        'cdn_provider': None,
                        'ip_type': 'dns',
                        'details': {}
                    }
                self.found_ips[ip]['sources'].append(source)
                if details:
                    self.found_ips[ip]['details'].update(details)
                return  # Never upgrade confidence for DNS IPs
            else:
                # Possible origin IP
                if ip not in self.found_ips:
                    self.found_ips[ip] = {
                        'sources': [],
                        'confidence': confidence,
                        'is_cdn': False,
                        'cdn_provider': None,
                        'ip_type': 'origin',
                        'details': {}
                    }
                self.found_ips[ip]['sources'].append(source)
                if details:
                    self.found_ips[ip]['details'].update(details)
                # Upgrade confidence if found by multiple sources
                if len(self.found_ips[ip]['sources']) >= 3:
                    self.found_ips[ip]['confidence'] = 'high'
                elif len(self.found_ips[ip]['sources']) >= 2:
                    self.found_ips[ip]['confidence'] = 'medium'

    def _is_valid_public_ip(self, ip):
        """Validate that an IP is a valid public IPv4 address"""
        if not isinstance(ip, str) or not ip or ip.startswith('range:'):
            return False
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            # Only accept IPv4 for consistency
            if addr.version != 4:
                return False
            if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast or addr.is_link_local:
                return False
            return True
        except (ValueError, TypeError):
            return False

    def _load_config(self):
        """Load API keys from config"""
        config_file = os.path.join(os.path.expanduser("~"), '.zylon', 'config.json')
        config = {}
        if os.path.exists(config_file):
            try:
                with open(config_file) as f:
                    config = json.load(f)
            except Exception:
                pass
        return config

    # ========================================================================
    # TECHNIQUE 1: CDN DETECTION & FINGERPRINTING
    # ========================================================================

    def detect_cdn(self, domain):
        """Detect if the target is behind a CDN/WAF and identify which one"""
        result = {
            'behind_cdn': False,
            'cdn_provider': None,
            'evidence': [],
            'current_ip': None,
        }

        domain = self._clean_domain(domain)

        # Resolve current IP
        current_ip = self._resolve_domain(domain)
        result['current_ip'] = current_ip

        if current_ip:
            cdn_name = self._is_cdn_ip(current_ip)
            if cdn_name:
                result['behind_cdn'] = True
                result['cdn_provider'] = cdn_name
                result['evidence'].append(f'Current IP {current_ip} belongs to {cdn_name} CDN range')

        # Check HTTP headers for CDN indicators
        try:
            self._rotate_ua()
            resp = self.session.get(f"https://{domain}", timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
            headers = dict(resp.headers)

            # Only use highly specific, unique header indicators to avoid false positives
            # Generic headers like 'x-cache' are excluded since they match multiple CDNs
            cdn_header_indicators = {
                'Cloudflare': ['cf-ray', 'cf-cache-status', 'server=cloudflare'],
                'Akamai': ['x-akamai-transformed', 'x-akamai-staging', 'akamai'],
                'AWS CloudFront': ['x-amz-cf-id', 'x-amz-requestid', 'x-cache-hits'],
                'Sucuri': ['x-sucuri-id', 'x-sucuri-cache'],
                'Incapsula': ['x-iinfo', 'x-cdn', 'incap_ses'],
                'Fastly': ['x-fastly-request-id', 'x-served-by'],
                'StackPath': ['x-stackpath-requestid'],
                'Microsoft Azure CDN': ['x-azure-ref'],
                'CDN77': ['x-77'],
                'KeyCDN': ['x-edge-location'],
            }

            header_keys_lower = [k.lower() for k in headers.keys()]

            for cdn_name, indicators in cdn_header_indicators.items():
                for indicator in indicators:
                    # Check header names and values
                    if '=' in indicator:
                        hname, hval = indicator.split('=', 1)
                        if hname.lower() in header_keys_lower:
                            if hval.lower() in str(headers.get(hname, '')).lower():
                                result['behind_cdn'] = True
                                if result['cdn_provider'] is None:
                                    result['cdn_provider'] = cdn_name
                                result['evidence'].append(f'Header match: {hname}={headers.get(hname, "")}')
                    else:
                        # Use exact header name match instead of substring
                        if indicator.lower() in header_keys_lower:
                            result['behind_cdn'] = True
                            if result['cdn_provider'] is None:
                                result['cdn_provider'] = cdn_name
                            result['evidence'].append(f'Header found: {indicator}')

            # Check cookies for CDN indicators
            for cookie in resp.cookies:
                cookie_name = cookie.name.lower()
                cdn_cookie_indicators = {
                    'Cloudflare': ['__cfduid', 'cf_clearance'],
                    'Incapsula': ['visid_incap', 'incap_ses'],
                    'Akamai': ['akamai'],
                }
                for cdn_name, cookie_names in cdn_cookie_indicators.items():
                    for cn in cookie_names:
                        if cn in cookie_name:
                            result['behind_cdn'] = True
                            if result['cdn_provider'] is None:
                                result['cdn_provider'] = cdn_name
                            result['evidence'].append(f'Cookie found: {cookie.name}')

        except Exception:
            pass

        self.cdn_detected = result
        self.is_behind_cdn = result['behind_cdn']
        return result

    # ========================================================================
    # TECHNIQUE 2: DNS HISTORICAL RECORDS
    # ========================================================================

    def dns_history_lookup(self, domain):
        """Query historical DNS records - IPs before CDN was enabled"""
        domain = self._clean_domain(domain)
        historical_ips = []

        # Method 1: SecurityTrails API (requires API key)
        config = self._load_config()
        api_key = config.get('securitytrails_api_key', '')
        if api_key:
            try:
                self._rotate_ua()
                url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
                headers = {'APIKEY': api_key}
                resp = self.session.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    for record in data.get('records', []):
                        for ip_obj in record.get('values', []):
                            ip = ip_obj.get('ip', '')
                            if ip and self._is_valid_public_ip(ip):
                                historical_ips.append({
                                    'ip': ip,
                                    'first_seen': record.get('first_seen', ''),
                                    'last_seen': record.get('last_seen', ''),
                                    'source': 'SecurityTrails'
                                })
                                self._add_ip(ip, 'SecurityTrails-History', 'medium',
                                           {'first_seen': record.get('first_seen', '')})
            except Exception:
                pass

        # Method 2: ViewDNS.info historical DNS
        try:
            self._rotate_ua()
            url = f"https://viewdns.info/iphistory/?domain={domain}"
            resp = self.session.get(url, timeout=10, headers={'Accept': 'text/html'})
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, 'html.parser')
                table = soup.find('table', {'border': '1'})
                if table:
                    rows = table.find_all('tr')[1:]  # Skip header
                    for row in rows:
                        cols = row.find_all('td')
                        if len(cols) >= 2:
                            ip_text = cols[0].get_text(strip=True)
                            # Extract IPs from the cell
                            ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_text)
                            for ip in ips:
                                if self._is_valid_public_ip(ip):
                                    historical_ips.append({
                                        'ip': ip,
                                        'source': 'ViewDNS'
                                    })
                                    self._add_ip(ip, 'ViewDNS-History', 'medium')
        except Exception:
            pass

        # Method 3: DNS History API (hackertarget)
        try:
            self._rotate_ua()
            url = f"https://api.hackertarget.com/dnshistory/?q={domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                for line in resp.text.strip().split('\n'):
                    parts = line.split(',')
                    if len(parts) >= 2:
                        ip = parts[-1].strip()
                        if self._is_valid_public_ip(ip):
                            historical_ips.append({
                                'ip': ip,
                                'source': 'HackerTarget-DNSHistory'
                            })
                            self._add_ip(ip, 'HackerTarget-History', 'low')
        except Exception:
            pass

        return historical_ips

    # ========================================================================
    # TECHNIQUE 3: SSL/TLS CERTIFICATE TRANSPARENCY
    # ========================================================================

    def cert_transparency_search(self, domain):
        """Search Certificate Transparency logs for IPs via crt.sh and Censys"""
        domain = self._clean_domain(domain)
        found_ips = []

        # Method 1: crt.sh - Extract IPs from certificate data
        try:
            self._rotate_ua()
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self.session.get(url, timeout=20, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                seen_names = set()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name and name not in seen_names and '*' not in name:
                            seen_names.add(name)
                            # Try to resolve subdomain names that might point to origin
                            try:
                                ip = socket.gethostbyname(name)
                                if ip and self._is_valid_public_ip(ip):
                                    found_ips.append({
                                        'ip': ip,
                                        'hostname': name,
                                        'source': 'crt.sh'
                                    })
                                    self._add_ip(ip, f'crt.sh({name})', 'medium', {'hostname': name})
                            except Exception:
                                pass
        except Exception:
            pass

        # Method 2: Censys Search (requires API key)
        config = self._load_config()
        censys_id = config.get('censys_api_id', '')
        censys_secret = config.get('censys_api_secret', '')
        if censys_id and censys_secret:
            try:
                self._rotate_ua()
                url = "https://search.censys.io/api/v2/certificates/search"
                query = f"names: {domain}"
                params = {'q': query, 'per_page': 50}
                auth = (censys_id, censys_secret)
                resp = self.session.get(url, params=params, auth=auth, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    for cert in data.get('result', {}).get('hits', []):
                        for name in cert.get('names', []):
                            if '*' not in name and name.endswith(domain):
                                try:
                                    ip = socket.gethostbyname(name)
                                    if ip and self._is_valid_public_ip(ip):
                                        found_ips.append({
                                            'ip': ip,
                                            'hostname': name,
                                            'source': 'Censys'
                                        })
                                        self._add_ip(ip, f'Censys({name})', 'high', {'hostname': name})
                                except Exception:
                                    pass
            except Exception:
                pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 4: SUBDOMAIN RESOLUTION & CDN IP FILTERING
    # ========================================================================

    def subdomain_resolution(self, domain):
        """Find subdomains and resolve them - many subdomains bypass CDN"""
        domain = self._clean_domain(domain)
        found_ips = []
        non_cdn_subs = []

        # Collect subdomains from multiple sources
        all_subdomains = set()

        # Source 1: crt.sh
        try:
            self._rotate_ua()
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self.session.get(url, timeout=15, verify=False)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    for name in entry.get('name_value', '').split('\n'):
                        name = name.strip().lower()
                        if name.endswith(domain) and '*' not in name:
                            all_subdomains.add(name)
        except Exception:
            pass

        # Source 2: bufferover.run
        try:
            self._rotate_ua()
            url = f"https://dns.bufferover.run/dns?q=.{domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for item in data.get('FDNS_A', []):
                    parts = item.split(',')
                    if len(parts) >= 2:
                        sub = parts[1].strip().lower()
                        if sub.endswith(domain):
                            all_subdomains.add(sub)
                            # Bufferover already gives us IP mappings
                            ip = parts[0].strip()
                            if self._is_valid_public_ip(ip):
                                self._add_ip(ip, f'bufferover({sub})', 'medium', {'hostname': sub})
                                found_ips.append({'ip': ip, 'hostname': sub, 'source': 'bufferover.run'})
        except Exception:
            pass

        # Source 3: hackertarget
        try:
            self._rotate_ua()
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                for line in resp.text.strip().split('\n'):
                    if ',' in line:
                        sub, ip = line.split(',', 1)
                        sub = sub.strip().lower()
                        ip = ip.strip()
                        if sub.endswith(domain):
                            all_subdomains.add(sub)
                            if self._is_valid_public_ip(ip):
                                self._add_ip(ip, f'hackertarget({sub})', 'medium', {'hostname': sub})
                                found_ips.append({'ip': ip, 'hostname': sub, 'source': 'hackertarget'})
        except Exception:
            pass

        # Source 4: RapidDNS
        try:
            self._rotate_ua()
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                matches = re.findall(r'(?:https?://)?([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', resp.text)
                for m in matches:
                    all_subdomains.add(m.lower())
        except Exception:
            pass

        # Source 5: AlienVault OTX
        try:
            self._rotate_ua()
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname and hostname.endswith(domain):
                        all_subdomains.add(hostname.lower())
                    # OTX also provides direct IP mappings
                    ip = entry.get('address', '')
                    if self._is_valid_public_ip(ip) and hostname:
                        self._add_ip(ip, f'AlienVault({hostname})', 'medium', {'hostname': hostname})
                        found_ips.append({'ip': ip, 'hostname': hostname, 'source': 'AlienVault'})
        except Exception:
            pass

        # Now resolve all subdomains and filter CDN IPs
        def resolve_sub(sub):
            try:
                ip = socket.gethostbyname(sub)
                return sub, ip
            except Exception:
                return sub, None

        # Use thread-local session for subdomain resolution to avoid thread-safety issues
        def resolve_sub_cdn(sub):
            try:
                ip = socket.gethostbyname(sub)
                if ip and self._is_valid_public_ip(ip):
                    cdn = self._is_cdn_ip(ip)
                    if not cdn:
                        return sub, ip, False
                    return sub, ip, True
            except Exception:
                pass
            return sub, None, False

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = {executor.submit(resolve_sub_cdn, sub): sub for sub in all_subdomains}
            for future in as_completed(futures):
                sub, ip, is_cdn = future.result()
                if ip and self._is_valid_public_ip(ip):
                    if not is_cdn:
                        non_cdn_subs.append({'subdomain': sub, 'ip': ip})
                        self._add_ip(ip, f'subdomain-resolve({sub})', 'high', {'hostname': sub})
                        found_ips.append({'ip': ip, 'hostname': sub, 'source': 'subdomain-resolve'})
                    # else: CDN IP, still recorded via _add_ip

        return {'total_subdomains': len(all_subdomains), 'non_cdn_ips': non_cdn_subs, 'all_ips': found_ips}

    # ========================================================================
    # TECHNIQUE 5: DNS RECORD MINING (MX, TXT, SPF, NS, SOA)
    # ========================================================================

    def dns_record_mining(self, domain):
        """Mine DNS records for origin IP leaks - MX, TXT, SPF, NS, SOA
        Note: MX/SPF/NS/SOA IPs are classified as infrastructure, NOT origin IPs,
        since they belong to mail/DNS providers (Google, Cloudflare, etc.)
        Only direct ip4: entries in SPF and non-mail TXT IPs are potential origin leaks."""
        domain = self._clean_domain(domain)
        found_ips = []

        # MX Records - Record for reference but classify as mail infrastructure
        # MX records almost always point to third-party mail providers (Google, Microsoft, etc.)
        # NOT the website's origin server
        try:
            mx_records = _dns_resolve(domain, 'MX')
            for mx in mx_records:
                mx_host = str(mx.exchange).rstrip('.')
                try:
                    mx_ip = socket.gethostbyname(mx_host)
                    if self._is_valid_public_ip(mx_ip):
                        self._add_ip(mx_ip, f'MX-Record({mx_host})', 'very_low',
                                   {'mx_hostname': mx_host, 'preference': mx.preference},
                                   ip_type='mail')
                        found_ips.append({'ip': mx_ip, 'hostname': mx_host, 'source': 'MX-Record',
                                        'ip_type': 'mail', 'note': 'Mail server - NOT origin IP'})
                except Exception:
                    pass
        except Exception:
            pass

        # TXT Records - May contain SPF with IP ranges
        try:
            txt_records = _dns_resolve(domain, 'TXT')
            for txt in txt_records:
                txt_str = str(txt).strip('"')
                # Extract IPs from SPF records
                if 'v=spf1' in txt_str:
                    # ip4: and ip6: directives - these MAY reveal origin IP
                    # if the site sends mail from the same server
                    ip4_matches = re.findall(r'ip4:([\d./]+)', txt_str)
                    for ip_range in ip4_matches:
                        if '/' in ip_range:
                            # CIDR range - record the range info
                            found_ips.append({'ip_range': ip_range, 'source': 'SPF-TXT', 'record': txt_str})
                        else:
                            if self._is_valid_public_ip(ip_range):
                                # SPF ip4 entries MIGHT be origin (if mail server = web server)
                                # But usually they're mail providers - classify as 'spf'
                                self._add_ip(ip_range, 'SPF-TXT', 'low', {'spf_record': txt_str},
                                           ip_type='spf')
                                found_ips.append({'ip': ip_range, 'source': 'SPF-TXT',
                                                'ip_type': 'spf', 'note': 'Mail sender IP - unlikely origin'})
                # Include/redirect directives - these are ALWAYS third-party mail providers
                include_matches = re.findall(r'include:([a-zA-Z0-9._-]+)', txt_str)
                for inc_host in include_matches:
                    try:
                        inc_ip = socket.gethostbyname(inc_host)
                        if self._is_valid_public_ip(inc_ip):
                            self._add_ip(inc_ip, f'SPF-Include({inc_host})', 'very_low',
                                       {'spf_include': inc_host}, ip_type='spf')
                            found_ips.append({'ip': inc_ip, 'hostname': inc_host, 'source': 'SPF-Include',
                                            'ip_type': 'spf', 'note': 'Mail provider - NOT origin IP'})
                    except Exception:
                        pass
                # Look for any IP addresses in TXT records (not SPF)
                if 'v=spf1' not in txt_str:
                    all_ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', txt_str)
                    for ip in all_ips:
                        if self._is_valid_public_ip(ip):
                            self._add_ip(ip, 'TXT-Record', 'low', {'txt_record': txt_str[:100]})
                            found_ips.append({'ip': ip, 'source': 'TXT-Record'})
        except Exception:
            pass

        # NS Records - These are DNS hosting provider IPs, NOT the origin
        # (e.g., Cloudflare nameservers, Route53, etc.)
        try:
            ns_records = _dns_resolve(domain, 'NS')
            for ns in ns_records:
                ns_host = str(ns).rstrip('.')
                try:
                    ns_ip = socket.gethostbyname(ns_host)
                    if self._is_valid_public_ip(ns_ip):
                        self._add_ip(ns_ip, f'NS-Record({ns_host})', 'very_low',
                                   {'ns_hostname': ns_host}, ip_type='dns')
                        found_ips.append({'ip': ns_ip, 'hostname': ns_host, 'source': 'NS-Record',
                                        'ip_type': 'dns', 'note': 'DNS nameserver - NOT origin IP'})
                except Exception:
                    pass
        except Exception:
            pass

        # SOA Record - Contains primary nameserver info, also DNS infrastructure
        try:
            soa_records = _dns_resolve(domain, 'SOA')
            for soa in soa_records:
                soa_str = str(soa)
                # Extract MNAME (primary nameserver) from SOA
                parts = soa_str.split()
                if parts:
                    primary_ns = parts[0].rstrip('.')
                    try:
                        ns_ip = socket.gethostbyname(primary_ns)
                        if self._is_valid_public_ip(ns_ip):
                            self._add_ip(ns_ip, f'SOA-Record({primary_ns})', 'very_low',
                                       {'soa_mname': primary_ns}, ip_type='dns')
                            found_ips.append({'ip': ns_ip, 'hostname': primary_ns, 'source': 'SOA-Record',
                                            'ip_type': 'dns', 'note': 'DNS primary NS - NOT origin IP'})
                    except Exception:
                        pass
        except Exception:
            pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 6: CNAME CHAIN FOLLOWING
    # ========================================================================

    def cname_chain_follow(self, domain):
        """Follow CNAME records to find origin - CNAME may point to origin before CDN"""
        domain = self._clean_domain(domain)
        cname_chain = []
        found_ips = []

        try:
            current = domain
            max_depth = 10
            for _ in range(max_depth):
                try:
                    answers = _dns_resolve(current, 'CNAME')
                    if answers:
                        cname = str(answers[0]).rstrip('.')
                        cname_chain.append({'from': current, 'to': cname})

                        # Try to resolve the CNAME target
                        try:
                            cname_ip = socket.gethostbyname(cname)
                            if self._is_valid_public_ip(cname_ip):
                                self._add_ip(cname_ip, f'CNAME-Chain({cname})', 'medium',
                                           {'cname_from': current, 'cname_to': cname})
                                found_ips.append({
                                    'ip': cname_ip,
                                    'hostname': cname,
                                    'source': 'CNAME-Chain',
                                    'chain': ' -> '.join([c['to'] for c in cname_chain])
                                })
                        except Exception:
                            pass

                        current = cname
                    else:
                        break
                except dns.resolver.NoAnswer:
                    break
                except dns.resolver.NXDOMAIN:
                    break
                except Exception:
                    break
        except Exception:
            pass

        # Also check CNAME for common subdomains
        common_subs = ['www', 'mail', 'ftp', 'admin', 'webmail', 'dev', 'staging', 'api',
                       'app', 'portal', 'test', 'old', 'beta', 'blog', 'shop', 'cdn']
        for sub in common_subs:
            try:
                answers = _dns_resolve(f'{sub}.{domain}', 'CNAME')
                if answers:
                    cname = str(answers[0]).rstrip('.')
                    try:
                        cname_ip = socket.gethostbyname(cname)
                        if self._is_valid_public_ip(cname_ip):
                            self._add_ip(cname_ip, f'CNAME-Sub({sub}.{domain})', 'medium',
                                       {'cname': cname})
                            found_ips.append({
                                'ip': cname_ip,
                                'hostname': cname,
                                'source': f'CNAME-Sub({sub})',
                            })
                    except Exception:
                        pass
            except Exception:
                continue

        return {'chain': cname_chain, 'ips': found_ips}

    # ========================================================================
    # TECHNIQUE 7: WEB ARCHIVE HISTORY (Wayback Machine)
    # ========================================================================

    def web_archive_history(self, domain):
        """Check Wayback Machine for historical records that may contain pre-CDN IPs"""
        domain = self._clean_domain(domain)
        found_ips = []

        # Wayback Machine CDX API - get historical snapshots
        try:
            self._rotate_ua()
            url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=timestamp,original&limit=50"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                if len(data) > 1:
                    # First row is header, rest are data
                    for row in data[1:]:
                        timestamp = row[0] if len(row) > 0 else ''
                        original_url = row[1] if len(row) > 1 else ''
                        # Check for IP addresses in the original URL
                        ips_in_url = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', original_url)
                        for ip in ips_in_url:
                            if self._is_valid_public_ip(ip):
                                self._add_ip(ip, f'Wayback-URL({timestamp})', 'medium',
                                           {'wayback_timestamp': timestamp, 'url': original_url})
                                found_ips.append({
                                    'ip': ip,
                                    'source': 'Wayback-URL',
                                    'timestamp': timestamp
                                })
        except Exception:
            pass

        # Wayback Machine - resolve historical DNS
        try:
            self._rotate_ua()
            url = f"https://web.archive.org/web/2020*/{domain}"
            resp = self.session.get(url, timeout=10, verify=False)
            # This is less reliable but may contain cached DNS info
        except Exception:
            pass

        # ViewDNS IP History fallback
        try:
            self._rotate_ua()
            url = f"https://viewdns.info/iphistory/?domain={domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', resp.text)
                for ip in ips:
                    if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                        self._add_ip(ip, 'ViewDNS-IPHistory', 'medium')
                        found_ips.append({'ip': ip, 'source': 'ViewDNS-IPHistory'})
        except Exception:
            pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 8: SHODAN INTERNET-WIDE SEARCH
    # ========================================================================

    def shodan_search(self, domain):
        """Search Shodan for the domain - may find origin IP directly"""
        domain = self._clean_domain(domain)
        found_ips = []

        config = self._load_config()
        api_key = config.get('shodan_api_key', '')

        if not api_key:
            return [{'error': 'Shodan API key not configured. Use "config" command to set it.'}]

        try:
            self._rotate_ua()
            # Search Shodan for the domain
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:{domain}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get('matches', []):
                    ip = match.get('ip_str', '')
                    port = match.get('port', '')
                    org = match.get('org', '')
                    hostnames = match.get('hostnames', [])
                    if ip and self._is_valid_public_ip(ip):
                        cdn = self._is_cdn_ip(ip)
                        if not cdn:
                            self._add_ip(ip, f'Shodan(hostname:{domain})', 'high',
                                       {'port': port, 'org': org, 'hostnames': hostnames})
                            found_ips.append({
                                'ip': ip,
                                'port': port,
                                'org': org,
                                'hostnames': hostnames,
                                'source': 'Shodan'
                            })
        except Exception:
            pass

        # Shodan SSL search - find hosts with matching SSL certificate
        try:
            self._rotate_ua()
            url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=ssl.cert.subject.cn:{domain}"
            resp = self.session.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get('matches', []):
                    ip = match.get('ip_str', '')
                    if ip and self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                        self._add_ip(ip, f'Shodan-SSL({domain})', 'high',
                                   {'ssl_match': True})
                        found_ips.append({
                            'ip': ip,
                            'source': 'Shodan-SSL',
                            'port': match.get('port', '')
                        })
        except Exception:
            pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 9: CENSYS CERTIFICATE & HOST SEARCH
    # ========================================================================

    def censys_search(self, domain):
        """Search Censys for certificate and host data"""
        domain = self._clean_domain(domain)
        found_ips = []

        config = self._load_config()
        censys_id = config.get('censys_api_id', '')
        censys_secret = config.get('censys_api_secret', '')

        if not censys_id or not censys_secret:
            return [{'error': 'Censys API credentials not configured. Use "config" command.'}]

        # Search for hosts with matching certificates
        try:
            self._rotate_ua()
            url = "https://search.censys.io/api/v2/hosts/search"
            params = {'q': f'services.tls.certificates.leaf.names: {domain}', 'per_page': 50}
            auth = (censys_id, censys_secret)
            resp = self.session.get(url, params=params, auth=auth, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for hit in data.get('result', {}).get('hits', []):
                    ip = hit.get('ip', '')
                    if ip and self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                        self._add_ip(ip, 'Censys-Host', 'high',
                                   {'censys_services': hit.get('services', [])})
                        found_ips.append({
                            'ip': ip,
                            'source': 'Censys-Host',
                            'services': [s.get('port', '') for s in hit.get('services', [])]
                        })
        except Exception:
            pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 10: FAVICON HASH FINGERPRINTING
    # ========================================================================

    def favicon_hash_search(self, domain):
        """Compute favicon hash and search Shodan for matching servers"""
        domain = self._clean_domain(domain)
        result = {'favicon_hash': None, 'matching_hosts': []}

        # Step 1: Fetch favicon and compute mmh3 hash
        try:
            self._rotate_ua()
            for proto in ['https', 'http']:
                try:
                    favicon_url = f"{proto}://{domain}/favicon.ico"
                    resp = self.session.get(favicon_url, timeout=10, verify=False)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        # Compute favicon hash (Shodan's method)
                        encoded = base64.b64encode(resp.content)
                        hash_val = hashlib.md5(resp.content).hexdigest()
                        result['favicon_hash'] = hash_val
                        break
                except Exception:
                    continue
        except Exception:
            pass

        # Step 2: Search Shodan for matching favicon hash
        if result['favicon_hash']:
            config = self._load_config()
            api_key = config.get('shodan_api_key', '')
            if api_key:
                try:
                    self._rotate_ua()
                    # Shodan uses mmh3 hash, we'll use http.favicon.hash search
                    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=http.favicon.hash:{result['favicon_hash']}"
                    resp = self.session.get(url, timeout=15)
                    if resp.status_code == 200:
                        data = resp.json()
                        for match in data.get('matches', []):
                            ip = match.get('ip_str', '')
                            if ip and self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                                self._add_ip(ip, 'Shodan-FaviconHash', 'medium',
                                           {'favicon_hash': result['favicon_hash']})
                                result['matching_hosts'].append({
                                    'ip': ip,
                                    'port': match.get('port', ''),
                                    'org': match.get('org', ''),
                                    'hostnames': match.get('hostnames', [])
                                })
                except Exception:
                    pass

        return result

    # ========================================================================
    # TECHNIQUE 11: EMAIL HEADER IP EXTRACTION
    # ========================================================================

    def email_header_ip_extract(self, domain):
        """Extract IPs from SPF/DKIM records that may reveal mail server origin"""
        domain = self._clean_domain(domain)
        found_ips = []

        # Parse SPF record for IP ranges and include directives
        try:
            txt_records = _dns_resolve(domain, 'TXT')
            for txt in txt_records:
                txt_str = str(txt).strip('"')
                if 'v=spf1' in txt_str:
                    # Extract ip4 directives
                    for match in re.finditer(r'ip4:([\d./]+)', txt_str):
                        ip_or_range = match.group(1)
                        if '/' not in ip_or_range and self._is_valid_public_ip(ip_or_range):
                            self._add_ip(ip_or_range, 'SPF-Direct-IP', 'medium',
                                       {'spf_record': txt_str})
                            found_ips.append({'ip': ip_or_range, 'source': 'SPF-Direct-IP'})

                    # Resolve include directives
                    for match in re.finditer(r'include:([a-zA-Z0-9._-]+)', txt_str):
                        include_host = match.group(1)
                        try:
                            include_ip = socket.gethostbyname(include_host)
                            if self._is_valid_public_ip(include_ip):
                                self._add_ip(include_ip, f'SPF-Include({include_host})', 'low',
                                           {'spf_record': txt_str})
                                found_ips.append({
                                    'ip': include_ip,
                                    'hostname': include_host,
                                    'source': 'SPF-Include'
                                })
                        except Exception:
                            pass

                    # Extract redirect targets
                    for match in re.finditer(r'redirect=([a-zA-Z0-9._-]+)', txt_str):
                        redirect_host = match.group(1)
                        try:
                            redirect_ip = socket.gethostbyname(redirect_host)
                            if self._is_valid_public_ip(redirect_ip):
                                self._add_ip(redirect_ip, f'SPF-Redirect({redirect_host})', 'low',
                                           {'spf_record': txt_str})
                                found_ips.append({
                                    'ip': redirect_ip,
                                    'hostname': redirect_host,
                                    'source': 'SPF-Redirect'
                                })
                        except Exception:
                            pass
        except Exception:
            pass

        # DKIM records - may reveal mail server infrastructure
        dkim_selectors = ['default', 'google', 'selector1', 'selector2', 's1', 's2',
                         'k1', 'k2', 'mail', 'smtp', 'email', 'dkim']
        for selector in dkim_selectors:
            try:
                dkim_records = _dns_resolve(f'{selector}._domainkey.{domain}', 'TXT')
                for dkim in dkim_records:
                    dkim_str = str(dkim).strip('"')
                    # Look for IPs in DKIM record
                    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', dkim_str)
                    for ip in ips:
                        if self._is_valid_public_ip(ip):
                            self._add_ip(ip, f'DKIM({selector})', 'low', {'dkim_record': dkim_str})
                            found_ips.append({'ip': ip, 'source': f'DKIM({selector})'})
            except Exception:
                continue

        # DMARC record
        try:
            dmarc_records = _dns_resolve(f'_dmarc.{domain}', 'TXT')
            for dmarc in dmarc_records:
                dmarc_str = str(dmarc).strip('"')
                if 'v=DMARC1' in dmarc_str:
                    # Extract rua/ruf reporting URIs which may contain hostnames
                    for match in re.finditer(r'ru[a-z]=mailto:([^@]+)@([a-zA-Z0-9._-]+)', dmarc_str):
                        report_host = match.group(2)
                        try:
                            report_ip = socket.gethostbyname(report_host)
                            if self._is_valid_public_ip(report_ip):
                                self._add_ip(report_ip, f'DMARC-Report({report_host})', 'low',
                                           {'dmarc_record': dmarc_str})
                                found_ips.append({
                                    'ip': report_ip,
                                    'hostname': report_host,
                                    'source': 'DMARC-Report'
                                })
                        except Exception:
                            pass
        except Exception:
            pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 12: ERROR PAGE IP LEAKAGE
    # ========================================================================

    def error_page_ip_leak(self, domain):
        """Trigger error pages that may expose internal/origin IPs"""
        domain = self._clean_domain(domain)
        found_ips = []

        def check_path(path):
            try:
                session = _get_thread_session()
                session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
                url = f"https://{domain}{path}"
                resp = session.get(url, timeout=8, verify=False, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 403, 404, 500, 502, 503]:
                    # Search for IP addresses in the response
                    body = resp.text
                    headers_str = str(dict(resp.headers))
                    combined = body + ' ' + headers_str

                    # Look for IP addresses
                    ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', combined)
                    for ip in ips:
                        if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                            return ip, path, resp.status_code
            except Exception:
                pass
            return None, None, None

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_path, p): p for p in ERROR_TRIGGER_PATHS}
            for future in as_completed(futures):
                ip, path, status = future.result()
                if ip:
                    self._add_ip(ip, f'ErrorPage-Leak({path})', 'medium',
                               {'path': path, 'status_code': status})
                    found_ips.append({
                        'ip': ip,
                        'source': f'ErrorPage-Leak({path})',
                        'status_code': status
                    })

        return found_ips

    # ========================================================================
    # TECHNIQUE 13: SERVER STATUS/INFO PAGE MINING
    # ========================================================================

    def server_status_mining(self, domain):
        """Check for server-status, phpinfo, and other info pages"""
        domain = self._clean_domain(domain)
        found_ips = []

        info_paths = [
            '/server-status', '/server-info', '/phpinfo.php', '/info.php',
            '/.env', '/.env.local', '/.env.production', '/.env.backup',
            '/debug', '/trace', '/actuator/env', '/actuator/info',
            '/status', '/health', '/metrics', '/var/log',
            '/nginx_status', '/apc.php', '/apcu.php',
            '/?XDEBUG_SESSION_START', '/.git/config', '/wp-config.php.bak',
        ]

        def check_info_path(path):
            try:
                session = _get_thread_session()
                session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
                url = f"https://{domain}{path}"
                resp = session.get(url, timeout=8, verify=False)
                if resp.status_code == 200:
                    body = resp.text
                    # Search for internal/private IPs that may be in the page
                    private_ips = re.findall(
                        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
                        r'172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|'
                        r'192\.168\.\d{1,3}\.\d{1,3})\b',
                        body
                    )
                    # Also search for public IPs
                    all_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', body)
                    results = []
                    for ip in all_ips:
                        if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                            results.append(('public', ip))
                    for ip_tuple in private_ips:
                        ip = ip_tuple[0] if isinstance(ip_tuple, tuple) else ip_tuple
                        results.append(('private', ip))
                    if results:
                        return path, results
            except Exception:
                pass
            return None, None

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(check_info_path, p): p for p in info_paths}
            for future in as_completed(futures):
                path, results = future.result()
                if results:
                    for ip_type, ip in results:
                        if ip_type == 'public':
                            self._add_ip(ip, f'ServerInfo({path})', 'medium',
                                       {'info_path': path})
                        found_ips.append({
                            'ip': ip,
                            'type': ip_type,
                            'source': f'ServerInfo({path})',
                        })

        return found_ips

    # ========================================================================
    # TECHNIQUE 14: XML/SITEMAP INTERNAL IP PARSING
    # ========================================================================

    def sitemap_ip_parse(self, domain):
        """Parse sitemap.xml and robots.txt for internal IP references"""
        domain = self._clean_domain(domain)
        found_ips = []

        # Parse sitemap.xml
        for sitemap_path in ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.txt']:
            try:
                self._rotate_ua()
                url = f"https://{domain}{sitemap_path}"
                resp = self.session.get(url, timeout=10, verify=False)
                if resp.status_code == 200:
                    # Look for IP addresses in sitemap content
                    ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
                    for ip in ips:
                        if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                            self._add_ip(ip, f'Sitemap({sitemap_path})', 'low')
                            found_ips.append({'ip': ip, 'source': f'Sitemap({sitemap_path})'})

                    # Also look for direct IP URLs in sitemap
                    ip_urls = re.findall(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
                    for ip in ip_urls:
                        if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                            self._add_ip(ip, f'Sitemap-URL({sitemap_path})', 'medium')
                            found_ips.append({'ip': ip, 'source': f'Sitemap-URL({sitemap_path})'})
            except Exception:
                pass

        # Parse robots.txt
        try:
            self._rotate_ua()
            url = f"https://{domain}/robots.txt"
            resp = self.session.get(url, timeout=10, verify=False)
            if resp.status_code == 200:
                ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', resp.text)
                for ip in ips:
                    if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                        self._add_ip(ip, 'Robots.txt', 'low')
                        found_ips.append({'ip': ip, 'source': 'Robots.txt'})
        except Exception:
            pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 15: INTERNAL RESOURCE IP LEAK (JS/CSS/Images)
    # ========================================================================

    def resource_ip_leak(self, domain):
        """Check JavaScript, CSS, and image resources for direct IP references"""
        domain = self._clean_domain(domain)
        found_ips = []

        try:
            self._rotate_ua()
            url = f"https://{domain}"
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
            if resp.status_code != 200:
                return found_ips

            html = resp.text
            soup = BeautifulSoup(html, 'html.parser')

            # Collect all resource URLs
            resource_urls = []

            # JavaScript files
            for script in soup.find_all('script', src=True):
                resource_urls.append(urljoin(url, script['src']))

            # CSS files
            for link in soup.find_all('link', rel='stylesheet', href=True):
                resource_urls.append(urljoin(url, link['href']))

            # Images
            for img in soup.find_all('img', src=True):
                resource_urls.append(urljoin(url, img['src']))

            # Also check inline scripts and the HTML itself for IP patterns
            all_ips = re.findall(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', html)
            for ip in all_ips:
                if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                    self._add_ip(ip, 'HTML-Resource-Link', 'medium')
                    found_ips.append({'ip': ip, 'source': 'HTML-Resource-Link'})

            # Check each resource file for IP references
            def check_resource(res_url):
                try:
                    session = _get_thread_session()
                    session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
                    r = session.get(res_url, timeout=8, verify=False)
                    if r.status_code == 200:
                        # Search for IP addresses in the resource
                        ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', r.text)
                        resource_results = []
                        for ip in ips:
                            if self._is_valid_public_ip(ip) and not self._is_cdn_ip(ip):
                                resource_results.append(ip)
                        return res_url, resource_results
                except Exception:
                    pass
                return None, None

            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(check_resource, rurl): rurl for rurl in resource_urls[:30]}
                for future in as_completed(futures):
                    res_url, ips = future.result()
                    if ips:
                        for ip in ips:
                            self._add_ip(ip, f'Resource({res_url[:50]})', 'medium',
                                       {'resource_url': res_url})
                            found_ips.append({'ip': ip, 'source': f'Resource({res_url[:50]})'})

        except Exception:
            pass

        return found_ips

    # ========================================================================
    # TECHNIQUE 16: DNS ZONE TRANSFER ATTEMPT (AXFR)
    # ========================================================================

    def dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer against nameservers - may reveal all records"""
        domain = self._clean_domain(domain)
        found_ips = []
        zone_data = []

        try:
            # Get nameservers
            ns_records = _dns_resolve(domain, 'NS')
            nameservers = [str(ns).rstrip('.') for ns in ns_records]

            for ns in nameservers:
                try:
                    ns_ip = socket.gethostbyname(ns)
                except Exception:
                    continue

                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
                    for name, node in zone.nodes.items():
                        name_str = str(name)
                        rdatasets = node.rdatasets
                        for rdataset in rdatasets:
                            for rdata in rdataset:
                                rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                                rdata_str = str(rdata)
                                zone_data.append({
                                    'name': f'{name_str}.{domain}' if name_str != '@' else domain,
                                    'type': rdtype,
                                    'value': rdata_str
                                })
                                # Extract IPs from zone data
                                if rdtype in ['A', 'AAAA']:
                                    if self._is_valid_public_ip(rdata_str):
                                        hostname = f'{name_str}.{domain}' if name_str != '@' else domain
                                        self._add_ip(rdata_str, f'ZoneTransfer({ns})', 'high',
                                                   {'hostname': hostname})
                                        found_ips.append({
                                            'ip': rdata_str,
                                            'hostname': hostname,
                                            'source': f'ZoneTransfer({ns})'
                                        })
                except dns.xfr.TransferError:
                    pass
                except Exception:
                    pass
        except Exception:
            pass

        return {'zone_data': zone_data, 'ips': found_ips}

    # ========================================================================
    # TECHNIQUE 17: CLOUD PROVIDER METADATA DETECTION
    # ========================================================================

    def cloud_metadata_detect(self, domain):
        """Check if origin is hosted on cloud providers (AWS, Azure, GCP)"""
        domain = self._clean_domain(domain)
        result = {'cloud_provider': None, 'evidence': [], 'found_ips': []}

        # Check if any found IPs belong to cloud provider ranges
        cloud_ranges = {
            'AWS': [
                '3.0.0.0/8', '4.0.0.0/8', '13.0.0.0/8', '14.0.0.0/8',
                '15.0.0.0/8', '16.0.0.0/8', '18.0.0.0/8', '23.0.0.0/8',
                '35.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8', '99.77.0.0/16',
                '100.24.0.0/13', '107.20.0.0/14', '174.129.0.0/16',
                '176.32.0.0/16', '205.251.0.0/16', '216.182.0.0/16',
            ],
            'Azure': [
                '4.128.0.0/10', '13.64.0.0/11', '13.96.0.0/13',
                '20.0.0.0/8', '40.64.0.0/10', '52.96.0.0/12',
                '104.40.0.0/13', '137.116.0.0/15', '138.91.0.0/16',
                '168.61.0.0/16', '191.232.0.0/13',
            ],
            'GCP': [
                '8.34.208.0/20', '8.35.192.0/20', '8.35.240.0/21',
                '35.184.0.0/14', '35.188.0.0/15', '35.190.0.0/17',
                '35.192.0.0/14', '35.196.0.0/15', '35.198.0.0/16',
                '35.199.0.0/16', '35.200.0.0/13', '35.208.0.0/12',
                '35.224.0.0/12', '35.240.0.0/13', '104.154.0.0/15',
                '104.196.0.0/14', '107.167.160.0/19',
            ],
        }

        try:
            import ipaddress
            for ip, info in self.found_ips.items():
                if not ip or info.get('is_cdn') or ip.startswith('range:'):
                    continue
                if not self._is_valid_public_ip(ip):
                    continue
                try:
                    addr = ipaddress.ip_address(ip)
                    for provider, ranges in cloud_ranges.items():
                        for cidr in ranges:
                            try:
                                network = ipaddress.ip_network(cidr, strict=False)
                                if addr.version != network.version:
                                    continue
                                if addr in network:
                                    result['cloud_provider'] = provider
                                    result['evidence'].append(f'IP {ip} belongs to {provider} range {cidr}')
                                    break
                            except (ValueError, TypeError):
                                continue
                except (ValueError, TypeError):
                    continue
        except Exception:
            pass

        # Check DNS for cloud-specific records
        try:
            txt_records = _dns_resolve(domain, 'TXT')
            for txt in txt_records:
                txt_str = str(txt).strip('"').lower()
                if 'amazonaws.com' in txt_str or 'aws' in txt_str:
                    result['cloud_provider'] = 'AWS'
                    result['evidence'].append(f'AWS reference in TXT record')
                elif 'azure' in txt_str or 'microsoft' in txt_str:
                    result['cloud_provider'] = 'Azure'
                    result['evidence'].append(f'Azure reference in TXT record')
                elif 'google' in txt_str or 'cloud.google' in txt_str:
                    result['cloud_provider'] = 'GCP'
                    result['evidence'].append(f'GCP reference in TXT record')
        except Exception:
            pass

        return result

    # ========================================================================
    # TECHNIQUE 18: ASN/PREFIX IP RANGE SCANNING
    # ========================================================================

    def asn_prefix_lookup(self, domain):
        """Find organization's ASN and IP ranges - origin may be in the same range"""
        domain = self._clean_domain(domain)
        result = {'asn': None, 'org': None, 'ip_ranges': [], 'found_ips': []}

        # Get current IP info
        current_ip = self._resolve_domain(domain)
        if not current_ip:
            return result

        # Use IP info APIs to find ASN
        try:
            self._rotate_ua()
            resp = self.session.get(f"https://ipinfo.io/{current_ip}/json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                asn = data.get('org', '')
                result['org'] = data.get('org', '')
                if asn:
                    # Extract ASN number
                    asn_match = re.search(r'AS(\d+)', asn)
                    if asn_match:
                        result['asn'] = asn_match.group(1)
        except Exception:
            pass

        # Get ASN prefix data
        if result['asn']:
            try:
                self._rotate_ua()
                url = f"https://api.bgpview.io/asn/{result['asn']}/prefixes"
                resp = self.session.get(url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    for prefix in data.get('data', {}).get('ipv4_prefixes', []):
                        cidr = prefix.get('prefix', '')
                        if cidr:
                            result['ip_ranges'].append({
                                'prefix': cidr,
                                'name': prefix.get('name', ''),
                                'description': prefix.get('description', '')
                            })
            except Exception:
                pass

        return result

    # ========================================================================
    # TECHNIQUE 19: DIRECT IP VERIFICATION WITH HOST HEADER
    # ========================================================================

    def verify_origin_ip(self, domain, ip):
        """Verify a found IP actually serves the target domain by connecting with Host header"""
        domain = self._clean_domain(domain)
        verification = {
            'ip': ip,
            'verified': False,
            'methods': [],
            'response_similarity': 0,
            'evidence': []
        }

        # Method 1: HTTP with Host header
        for port in [80, 443, 8080, 8443]:
            try:
                self._rotate_ua()
                proto = 'https' if port in [443, 8443] else 'http'
                url = f"{proto}://{ip}:{port}/"
                headers = {
                    'Host': domain,
                    'User-Agent': random.choice(USER_AGENTS),
                    'Accept': 'text/html',
                }
                resp = self.session.get(url, headers=headers, timeout=8, verify=False, allow_redirects=False)

                if resp.status_code in [200, 301, 302]:
                    verification['verified'] = True
                    verification['methods'].append(f'HTTP-{port}')

                    # Compare response with the actual domain response
                    try:
                        domain_resp = self.session.get(f"https://{domain}/", timeout=8, verify=False)
                        # Compare title, body hash, headers
                        domain_soup = BeautifulSoup(domain_resp.text, 'html.parser')
                        domain_title = domain_soup.title.string if domain_soup.title else ''

                        ip_soup = BeautifulSoup(resp.text, 'html.parser')
                        ip_title = ip_soup.title.string if ip_soup.title else ''

                        if domain_title and ip_title and domain_title.strip() == ip_title.strip():
                            verification['response_similarity'] += 40
                            verification['evidence'].append(f'Title match: {domain_title}')

                        # Compare body length
                        domain_len = len(domain_resp.text)
                        ip_len = len(resp.text)
                        if abs(domain_len - ip_len) < max(domain_len, ip_len) * 0.3:
                            verification['response_similarity'] += 20
                            verification['evidence'].append(f'Similar body length: domain={domain_len}, ip={ip_len}')

                        # Compare key headers
                        for header in ['server', 'x-powered-by', 'x-aspnet-version']:
                            domain_h = domain_resp.headers.get(header, '')
                            ip_h = resp.headers.get(header, '')
                            if domain_h and ip_h and domain_h == ip_h:
                                verification['response_similarity'] += 15
                                verification['evidence'].append(f'{header} match: {domain_h}')
                    except Exception:
                        pass

                    break  # Found on this port, no need to check others

            except Exception:
                continue

        # Method 2: SSL certificate verification
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8)
            conn = context.wrap_socket(sock, server_hostname=domain)
            conn.connect((ip, 443))
            cert = conn.getpeercert(binary_form=False)
            if cert:
                # Check if domain is in SANs
                for ext in cert.get('subjectAltName', []):
                    if domain in ext[1] or f'*.{domain}' in ext[1]:
                        verification['verified'] = True
                        verification['methods'].append('SSL-Cert-Match')
                        verification['response_similarity'] += 30
                        verification['evidence'].append(f'SSL cert covers: {ext[1]}')
                        break
            conn.close()
        except Exception:
            pass

        return verification

    # ========================================================================
    # TECHNIQUE 20: HTTP RESPONSE HEADER FINGERPRINTING
    # ========================================================================

    def header_fingerprint(self, domain):
        """Compare HTTP response headers between domain and found IPs"""
        domain = self._clean_domain(domain)
        result = {'domain_fingerprint': None, 'ip_matches': []}

        # Get domain's response fingerprint
        try:
            self._rotate_ua()
            domain_resp = self.session.get(f"https://{domain}/", timeout=10, verify=False)
            domain_headers = dict(domain_resp.headers)
            domain_body_hash = hashlib.md5(domain_resp.text.encode()).hexdigest()[:12]

            result['domain_fingerprint'] = {
                'server': domain_headers.get('Server', ''),
                'x_powered_by': domain_headers.get('X-Powered-By', ''),
                'body_hash': domain_body_hash,
                'content_length': len(domain_resp.text),
                'status_code': domain_resp.status_code,
            }
        except Exception:
            return result

        # Compare with found non-CDN IPs
        for ip, info in self.found_ips.items():
            if info.get('is_cdn') or not self._is_valid_public_ip(ip):
                continue
            try:
                self._rotate_ua()
                for port in [80, 443]:
                    proto = 'https' if port == 443 else 'http'
                    url = f"{proto}://{ip}:{port}/"
                    headers = {'Host': domain, 'User-Agent': random.choice(USER_AGENTS)}
                    try:
                        ip_resp = self.session.get(url, headers=headers, timeout=8, verify=False)
                        match_score = 0
                        match_details = []

                        # Server header match
                        ip_server = ip_resp.headers.get('Server', '')
                        if ip_server and ip_server == result['domain_fingerprint']['server']:
                            match_score += 25
                            match_details.append(f'Server: {ip_server}')

                        # X-Powered-By match
                        ip_powered = ip_resp.headers.get('X-Powered-By', '')
                        if ip_powered and ip_powered == result['domain_fingerprint']['x_powered_by']:
                            match_score += 25
                            match_details.append(f'X-Powered-By: {ip_powered}')

                        # Body hash similarity
                        ip_body_hash = hashlib.md5(ip_resp.text.encode()).hexdigest()[:12]
                        if ip_body_hash == domain_body_hash:
                            match_score += 40
                            match_details.append('Body hash match')

                        # Content length similarity
                        if abs(len(ip_resp.text) - result['domain_fingerprint']['content_length']) < 500:
                            match_score += 10
                            match_details.append('Similar content length')

                        if match_score >= 30:
                            result['ip_matches'].append({
                                'ip': ip,
                                'match_score': match_score,
                                'details': match_details,
                                'port': port
                            })
                    except Exception:
                        continue
            except Exception:
                continue

        return result

    # ========================================================================
    # TECHNIQUE 21: MULTI-RESOLVER DNS CROSS-VALIDATION
    # ========================================================================

    def multi_resolver_validation(self, domain):
        """Resolve domain across multiple DNS resolvers to catch inconsistent CDN routing"""
        domain = self._clean_domain(domain)
        result = {'resolver_results': {}, 'unique_ips': [], 'suspicious_ips': []}

        for resolver in PUBLIC_DNS_RESOLVERS:
            try:
                ip = self._resolve_domain(domain, resolver)
                if ip:
                    if resolver not in result['resolver_results']:
                        result['resolver_results'][resolver] = []
                    result['resolver_results'][resolver].append(ip)
                    if ip not in result['unique_ips']:
                        result['unique_ips'].append(ip)
            except Exception:
                result['resolver_results'][resolver] = ['error']

        # IPs that appear from some resolvers but not all might be origin
        ip_counts = Counter()
        for resolver, ips in result['resolver_results'].items():
            for ip in ips:
                if ip != 'error':
                    ip_counts[ip] += 1

        total_resolvers = len(PUBLIC_DNS_RESOLVERS)
        for ip, count in ip_counts.items():
            # If an IP appears from some resolvers but not all, it might be origin leaking through
            if 0 < count < total_resolvers and self._is_valid_public_ip(ip):
                cdn = self._is_cdn_ip(ip)
                if not cdn:
                    result['suspicious_ips'].append({
                        'ip': ip,
                        'seen_by': count,
                        'total_resolvers': total_resolvers,
                        'ratio': f'{count}/{total_resolvers}'
                    })
                    self._add_ip(ip, f'MultiResolver({count}/{total_resolvers})', 'low',
                               {'resolver_ratio': f'{count}/{total_resolvers}'})

        return result

    # ========================================================================
    # TECHNIQUE 22: SPF/DKIM/DMARC IP RANGE EXTRACTION
    # ========================================================================

    def spf_dkim_dmarc_extract(self, domain):
        """Deep extraction of IP ranges from SPF, DKIM, and DMARC records"""
        domain = self._clean_domain(domain)
        result = {'spf_ips': [], 'dkim_hosts': [], 'dmarc_info': {}, 'found_ips': []}

        # SPF deep extraction - follow all includes recursively
        visited_includes = set()

        def parse_spf(spf_domain, depth=0):
            if depth > 5 or spf_domain in visited_includes:
                return
            visited_includes.add(spf_domain)
            try:
                txt_records = _dns_resolve(spf_domain, 'TXT')
                for txt in txt_records:
                    txt_str = str(txt).strip('"')
                    if 'v=spf1' in txt_str:
                        result['spf_ips'].append({'domain': spf_domain, 'record': txt_str})

                        # Extract direct IPs - classify as SPF (mail infrastructure)
                        for match in re.finditer(r'ip4:([\d./]+)', txt_str):
                            ip_or_range = match.group(1)
                            if '/' not in ip_or_range and self._is_valid_public_ip(ip_or_range):
                                self._add_ip(ip_or_range, f'SPF-Deep({spf_domain})', 'low',
                                           ip_type='spf')
                                result['found_ips'].append(ip_or_range)

                        # Follow includes recursively
                        for match in re.finditer(r'include:([a-zA-Z0-9._-]+)', txt_str):
                            parse_spf(match.group(1), depth + 1)

                        # Follow redirects
                        for match in re.finditer(r'redirect=([a-zA-Z0-9._-]+)', txt_str):
                            parse_spf(match.group(1), depth + 1)
            except Exception:
                pass

        parse_spf(domain)

        # DMARC detailed extraction
        try:
            dmarc_records = _dns_resolve(f'_dmarc.{domain}', 'TXT')
            for dmarc in dmarc_records:
                dmarc_str = str(dmarc).strip('"')
                if 'v=DMARC1' in dmarc_str:
                    result['dmarc_info'] = {
                        'record': dmarc_str,
                        'policy': re.search(r'p=([a-z]+)', dmarc_str),
                        'subdomain_policy': re.search(r'sp=([a-z]+)', dmarc_str),
                        'pct': re.search(r'pct=(\d+)', dmarc_str),
                    }
        except Exception:
            pass

        return result

    # ========================================================================
    # MAIN ORCHESTRATOR - RUN ALL TECHNIQUES
    # ========================================================================

    def find_origin_ip(self, domain):
        """Run all 22 origin IP finding techniques and compile results"""
        domain = self._clean_domain(domain)
        self.found_ips = {}

        results = {
            'target': domain,
            'timestamp': datetime.now().isoformat(),
            'cdn_detection': None,
            'origin_ips': [],
            'all_techniques': {},
        }

        # Phase 1: CDN Detection (must run first)
        results['cdn_detection'] = self.detect_cdn(domain)

        # Phase 2: Run all discovery techniques (parallel where possible)
        technique_results = {}

        # Group 1: DNS-based techniques (fast, run in parallel)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.dns_record_mining, domain): 'dns_mining',
                executor.submit(self.cname_chain_follow, domain): 'cname_chain',
                executor.submit(self.multi_resolver_validation, domain): 'multi_resolver',
                executor.submit(self.spf_dkim_dmarc_extract, domain): 'spf_dkim_dmarc',
                executor.submit(self.dns_zone_transfer, domain): 'zone_transfer',
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    technique_results[name] = future.result(timeout=30)
                except Exception:
                    technique_results[name] = {'error': 'Technique failed'}

        # Group 2: Web/API-based techniques (may be slower)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.dns_history_lookup, domain): 'dns_history',
                executor.submit(self.cert_transparency_search, domain): 'cert_transparency',
                executor.submit(self.subdomain_resolution, domain): 'subdomain_resolution',
                executor.submit(self.web_archive_history, domain): 'web_archive',
                executor.submit(self.shodan_search, domain): 'shodan',
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    technique_results[name] = future.result(timeout=30)
                except Exception:
                    technique_results[name] = {'error': 'Technique failed'}

        # Group 3: Secondary techniques
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(self.censys_search, domain): 'censys',
                executor.submit(self.favicon_hash_search, domain): 'favicon_hash',
                executor.submit(self.email_header_ip_extract, domain): 'email_headers',
                executor.submit(self.error_page_ip_leak, domain): 'error_page_leak',
                executor.submit(self.server_status_mining, domain): 'server_status',
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    technique_results[name] = future.result(timeout=30)
                except Exception:
                    technique_results[name] = {'error': 'Technique failed'}

        # Group 4: Deep analysis techniques
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(self.sitemap_ip_parse, domain): 'sitemap_parse',
                executor.submit(self.resource_ip_leak, domain): 'resource_leak',
                executor.submit(self.cloud_metadata_detect, domain): 'cloud_metadata',
                executor.submit(self.asn_prefix_lookup, domain): 'asn_prefix',
            }
            for future in as_completed(futures):
                name = futures[future]
                try:
                    technique_results[name] = future.result(timeout=30)
                except Exception:
                    technique_results[name] = {'error': 'Technique failed'}

        results['all_techniques'] = technique_results

        # Phase 3: Header fingerprinting (needs found IPs)
        results['header_fingerprint'] = self.header_fingerprint(domain)

        # Phase 4: Compile final origin IP list
        # Filter by IP type: only 'origin' type IPs are real candidates
        # mail/spf/dns IPs are infrastructure, not origin servers
        origin_candidates = []
        infra_ips = []
        for ip, info in self.found_ips.items():
            if isinstance(ip, str) and ip.startswith('range:'):
                continue  # Skip IP ranges for now
            ip_type = info.get('ip_type', 'origin')
            if info.get('is_cdn'):
                continue
            if ip_type in ('mail', 'spf', 'dns'):
                infra_ips.append({
                    'ip': ip,
                    'confidence': info['confidence'],
                    'sources': info['sources'],
                    'ip_type': ip_type,
                    'details': info.get('details', {}),
                    'note': 'Infrastructure - NOT origin IP',
                })
                continue
            # Only include origin-type IPs with medium or high confidence
            if info.get('confidence') in ['medium', 'high']:
                origin_candidates.append({
                    'ip': ip,
                    'confidence': info['confidence'],
                    'sources': info['sources'],
                    'source_count': len(info['sources']),
                    'ip_type': ip_type,
                    'details': info.get('details', {}),
                })

        # Sort by confidence and source count
        origin_candidates.sort(key=lambda x: (
            1 if x['confidence'] == 'high' else 0,
            x['source_count']
        ), reverse=True)

        # Phase 5: Verify ALL origin candidates (not just top 5)
        verified_origins = []
        for candidate in origin_candidates:
            verification = self.verify_origin_ip(domain, candidate['ip'])
            candidate['verification'] = verification
            if verification['verified']:
                candidate['confidence'] = 'high'  # Verified = high confidence
                verified_origins.append(candidate)

        results['origin_ips'] = verified_origins if verified_origins else origin_candidates
        results['all_candidate_ips'] = origin_candidates
        results['infrastructure_ips'] = infra_ips
        results['cdn_ips'] = [
            {'ip': ip, 'cdn_provider': info.get('cdn_provider')}
            for ip, info in self.found_ips.items()
            if info.get('is_cdn')
        ]

        return results

    # ========================================================================
    # QUICK SCAN - Run only the most effective techniques
    # ========================================================================

    def quick_find(self, domain):
        """Run quick origin IP scan with only the most effective techniques"""
        domain = self._clean_domain(domain)
        self.found_ips = {}

        results = {
            'target': domain,
            'timestamp': datetime.now().isoformat(),
            'cdn_detection': None,
            'origin_ips': [],
            'infrastructure_ips': [],  # Mail/DNS/SPF IPs (not origin)
            'cdn_ips': [],             # CDN/proxy IPs
        }

        # CDN Detection
        results['cdn_detection'] = self.detect_cdn(domain)

        if not results['cdn_detection']['behind_cdn']:
            current_ip = self._resolve_domain(domain)
            if current_ip:
                results['origin_ips'] = [{'ip': current_ip, 'confidence': 'high',
                                         'sources': ['direct-resolve'], 'ip_type': 'origin'}]
                return results

        # Quick techniques: most effective first
        self.dns_record_mining(domain)
        self.subdomain_resolution(domain)
        self.cert_transparency_search(domain)
        self.dns_history_lookup(domain)
        self.error_page_ip_leak(domain)
        self.cname_chain_follow(domain)

        # Compile results - separate by IP type
        origin_candidates = []
        infra_ips = []
        cdn_ips = []

        for ip, info in self.found_ips.items():
            if isinstance(ip, str) and ip.startswith('range:'):
                continue
            ip_type = info.get('ip_type', 'origin')
            entry = {
                'ip': ip,
                'confidence': info['confidence'],
                'sources': info['sources'],
                'source_count': len(info['sources']),
                'ip_type': ip_type,
            }
            if info.get('is_cdn'):
                entry['cdn_provider'] = info.get('cdn_provider', '')
                cdn_ips.append(entry)
            elif ip_type in ('mail', 'spf', 'dns'):
                entry['note'] = 'Mail/DNS infrastructure - NOT origin IP'
                infra_ips.append(entry)
            else:
                origin_candidates.append(entry)

        origin_candidates.sort(key=lambda x: (1 if x['confidence'] == 'high' else 0, x['source_count']), reverse=True)

        # Verify ALL origin candidates (not just top one)
        for candidate in origin_candidates:
            verification = self.verify_origin_ip(domain, candidate['ip'])
            candidate['verification'] = verification

        results['origin_ips'] = origin_candidates
        results['infrastructure_ips'] = infra_ips
        results['cdn_ips'] = cdn_ips
        return results
