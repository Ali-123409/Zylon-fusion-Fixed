"""
ZYLON FUSION - Reconnaissance Engine
Fuses: omino OSINT/recon + wizard basic recon + Zylon custom techniques
Termux Non-Root Compatible - All API/web-based, no raw sockets needed
"""

import os
import re
import json
import socket
import requests
import dns.resolver
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, VERIFY_SSL, WAF_SIGNATURES,
    TECH_SIGNATURES, CLOUD_BUCKET_PATTERNS, COMMON_DIRS
)
import random

from core.shared_infra import shared_session, regex_cache, framework_discovery


class ReconEngine:
    """Advanced Reconnaissance Engine - omino + wizard + Zylon fusion"""

    def __init__(self, session=None):
        self.session = session or shared_session
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = VERIFY_SSL
        self.cache = {}

    def _rotate_ua(self):
        """Rotate user agent"""
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # BASIC RECONNAISSANCE (from wizard + enhanced)
    # ========================================================================

    def get_title(self, url):
        """Extract page title with multiple methods"""
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')
            if soup.title and soup.title.string:
                return soup.title.string.strip()
            # Fallback: OG title
            og = soup.find('meta', property='og:title')
            if og and og.get('content'):
                return og['content'].strip()
            # Fallback: H1
            h1 = soup.find('h1')
            if h1:
                return h1.get_text().strip()
            return "No title found"
        except Exception as e:
            return f"Error: {str(e)[:50]}"

    def detect_cms(self, url):
        """Detect CMS with weighted confidence scoring"""
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            html = resp.text.lower()
            headers = dict(resp.headers)
            soup = BeautifulSoup(resp.text, 'html.parser')
            cookies = {c.name: c.value for c in resp.cookies}

            detected = []

            for cms_name, sig in TECH_SIGNATURES.items():
                weight = 0
                # Check meta generator
                if 'meta' in sig and len(sig['meta']) >= 2:
                    meta_tag = soup.find('meta', attrs={'name': sig['meta'][0]})
                    if meta_tag and sig['meta'][1].lower() in str(meta_tag.get('content', '')).lower():
                        weight += 40
                # Check files/paths in HTML
                for fpath in sig.get('files', []):
                    if fpath.lower() in html:
                        weight += 20
                # Check headers
                for hname, hval in sig.get('headers', {}).items():
                    if hname in headers:
                        if not hval or hval.lower() in headers[hname].lower():
                            weight += 25
                # Check cookies
                for cname in sig.get('cookies', []):
                    if any(cname.lower() in c.lower() for c in cookies):
                        weight += 15
                # Check JS patterns
                for pattern in sig.get('js_patterns', []):
                    if pattern.lower() in html:
                        weight += 20

                if weight >= 20:
                    detected.append({'name': cms_name, 'confidence': min(weight, 100), 'category': 'CMS/Framework'})

            detected.sort(key=lambda x: x['confidence'], reverse=True)
            if detected:
                return detected[0]['name']
            return 'Unknown'
        except Exception:
            return 'Unknown'

    def check_cloudflare(self, ip=None, url=None):
        """Check if target is behind Cloudflare"""
        try:
            # Check target's headers for Cloudflare indicators
            if url:
                try:
                    resp = self.session.get(url, timeout=5, verify=VERIFY_SSL)
                    if any(h in resp.headers for h in ['cf-ray', 'cf-cache-status']):
                        return True
                    if 'cloudflare' in resp.headers.get('server', '').lower():
                        return True
                except Exception:
                    pass
            # Check via DNS IP ranges
            if ip:
                # Cloudflare IP ranges
                cf_ranges = [
                    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22',
                    '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
                    '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
                    '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
                    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
                ]
                import ipaddress
                try:
                    target_ip = ipaddress.ip_address(ip)
                    for cidr in cf_ranges:
                        if target_ip in ipaddress.ip_network(cidr):
                            return True
                except ValueError:
                    pass
            return False
        except Exception:
            return False

    def analyze_robots(self, url):
        """Analyze robots.txt for sensitive paths"""
        try:
            robots_url = urljoin(url, '/robots.txt')
            resp = self.session.get(robots_url, timeout=5, verify=VERIFY_SSL)
            if resp.status_code != 200:
                return {'exists': False, 'analysis': 'No robots.txt found'}

            content = resp.text
            disallowed = []
            sitemaps = []
            sensitive = []

            for line in content.split('\n'):
                line = line.strip()
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path:
                        disallowed.append(path)
                        # Check for sensitive paths
                        for kw in ['admin', 'login', 'config', 'backup', 'db', 'secret', 'private', '.env']:
                            if kw in path.lower():
                                sensitive.append(path)
                elif line.lower().startswith('sitemap:'):
                    sitemap = line.split(':', 1)[1].strip()
                    sitemaps.append(sitemap)

            return {
                'exists': True,
                'disallowed_count': len(disallowed),
                'sitemaps_count': len(sitemaps),
                'sensitive_paths': sensitive,
                'disallowed': disallowed[:20],
                'sitemaps': sitemaps[:5]
            }
        except Exception as e:
            return {'exists': False, 'error': str(e)[:100]}

    # ========================================================================
    # WHOIS LOOKUP (from wizard + enhanced)
    # ========================================================================

    def whois_lookup(self, domain):
        """WHOIS domain lookup"""
        try:
            import whois as pythonwhois
            # python-whois API: whois.query() for the correct interface
            if hasattr(pythonwhois, 'query'):
                w = pythonwhois.query(domain)
                result = {}
                if w:
                    for field in ['name', 'registrar', 'registrant', 'creation_date',
                                 'expiration_date', 'updated_date', 'name_servers', 'status',
                                 'emails', 'dnssec', 'org', 'country']:
                        val = getattr(w, field, None)
                        if val:
                            result[field] = str(val)
                return result if result else {'error': 'WHOIS returned no data'}
            elif hasattr(pythonwhois, 'whois'):
                w = pythonwhois.whois(domain)
                result = {}
                if w:
                    for field in ['domain_name', 'registrar', 'whois_server', 'creation_date',
                                 'expiration_date', 'updated_date', 'name_servers', 'status',
                                 'emails', 'dnssec', 'org', 'country']:
                        val = getattr(w, field, None)
                        if val:
                            result[field] = str(val)
                return result if result else {'error': 'WHOIS returned no data'}
            else:
                return self._whois_web(domain)
        except ImportError:
            # Fallback: web-based WHOIS
            return self._whois_web(domain)
        except Exception as e:
            # Try web-based fallback before returning error
            try:
                return self._whois_web(domain)
            except Exception:
                return {'error': str(e)[:100]}

    def _whois_web(self, domain):
        """Web-based WHOIS lookup fallback"""
        try:
            url = f"https://whois.freeaitools.me/{domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data
            return {'error': 'Web WHOIS lookup failed'}
        except Exception as e:
            return {'error': str(e)[:100]}

    # ========================================================================
    # SUBDOMAIN DISCOVERY (from omino recon + enhanced multi-source)
    # ========================================================================

    def discover_subdomains(self, domain):
        """Multi-source subdomain discovery (omino's approach - API based, no root needed)"""
        subdomains = {}
        sources = {
            'crt.sh': self._subdomains_crtsh,
            'bufferover.run': self._subdomains_bufferover,
            'rapiddns': self._subdomains_rapiddns,
            'dnsdumpster': self._subdomains_dnsdumpster,
            'securitytrails': self._subdomains_securitytrails,
            'hackertarget': self._subdomains_hackertarget,
            'virustotal': self._subdomains_virustotal,
            'threatcrowd': self._subdomains_threatcrowd,
            'alienvault': self._subdomains_alienvault,
            'jldc': self._subdomains_jldc,
        }

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(func, domain): name for name, func in sources.items()}
            for future in as_completed(futures):
                source_name = futures[future]
                try:
                    results = future.result(timeout=15)
                    for sub in results:
                        if sub not in subdomains:
                            subdomains[sub] = []
                        subdomains[sub].append(source_name)
                except Exception:
                    pass

        return subdomains

    def _subdomains_crtsh(self, domain):
        """crt.sh certificate transparency"""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = self.session.get(url, timeout=15, verify=VERIFY_SSL)
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for n in name.split('\n'):
                        n = n.strip().lower()
                        if n.endswith(domain) and '*' not in n:
                            subs.add(n)
                return subs
        except Exception:
            pass
        return set()

    def _subdomains_bufferover(self, domain):
        """dns.bufferover.run API"""
        try:
            url = f"https://dns.bufferover.run/dns?q=.{domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for item in data.get('FDNS_A', []):
                    parts = item.split(',')
                    if len(parts) >= 2:
                        sub = parts[1].strip().lower()
                        if sub.endswith(domain):
                            subs.add(sub)
                return subs
        except Exception:
            pass
        return set()

    def _subdomains_rapiddns(self, domain):
        """RapidDNS API"""
        try:
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            resp = self.session.get(url, timeout=10, headers={'Accept': 'text/html'})
            if resp.status_code == 200:
                subs = set()
                matches = regex_cache.findall(r'(?:https?://)?([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', resp.text)
                for m in matches:
                    subs.add(m.lower())
                return subs
        except Exception:
            pass
        return set()

    def _subdomains_dnsdumpster(self, domain):
        """DNSDumpster (web scraping)"""
        try:
            url = "https://dnsdumpster.com/"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                # Get CSRF token
                soup = BeautifulSoup(resp.text, 'html.parser')
                token = soup.find('input', {'name': 'csrfmiddlewaretoken'})
                if token:
                    token = token.get('value', '')
                    data = {'csrfmiddlewaretoken': token, 'targetip': domain, 'user': 'free'}
                    headers = {'Referer': url}
                    resp = self.session.post(url, data=data, headers=headers, timeout=15)
                    # Parse results
                    subs = set()
                    matches = regex_cache.findall(r'([a-zA-Z0-9._-]+\.' + re.escape(domain) + r')', resp.text)
                    for m in matches:
                        subs.add(m.lower())
                    return subs
        except Exception:
            pass
        return set()

    def _subdomains_securitytrails(self, domain):
        """SecurityTrails API (requires API key)"""
        try:
            config_file = os.path.join(os.path.expanduser("~"), '.zylon', 'config.json')
            if os.path.exists(config_file):
                with open(config_file) as f:
                    config = json.load(f)
                api_key = config.get('securitytrails_api_key', '')
                if api_key:
                    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                    headers = {'APIKEY': api_key}
                    resp = self.session.get(url, headers=headers, timeout=10)
                    if resp.status_code == 200:
                        data = resp.json()
                        subs = set()
                        for sub in data.get('subdomains', []):
                            subs.add(f"{sub}.{domain}".lower())
                        return subs
        except Exception:
            pass
        return set()

    def _subdomains_hackertarget(self, domain):
        """HackerTarget API"""
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200 and 'error' not in resp.text.lower():
                subs = set()
                for line in resp.text.strip().split('\n'):
                    if ',' in line:
                        sub = line.split(',')[0].strip().lower()
                        if sub.endswith(domain):
                            subs.add(sub)
                return subs
        except Exception:
            pass
        return set()

    def _subdomains_virustotal(self, domain):
        """VirusTotal API (requires API key)"""
        try:
            config_file = os.path.join(os.path.expanduser("~"), '.zylon', 'config.json')
            if os.path.exists(config_file):
                with open(config_file) as f:
                    config = json.load(f)
                api_key = config.get('virustotal_api_key', '')
                if api_key:
                    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}"
                    resp = self.session.get(url, timeout=15)
                    if resp.status_code == 200:
                        data = resp.json()
                        return set(data.get('subdomains', []))
        except Exception:
            pass
        return set()

    def _subdomains_threatcrowd(self, domain):
        """ThreatCrowd API"""
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return set(data.get('subdomains', []))
        except Exception:
            pass
        return set()

    def _subdomains_alienvault(self, domain):
        """AlienVault OTX API"""
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '')
                    if hostname and hostname.endswith(domain):
                        subs.add(hostname.lower())
                return subs
        except Exception:
            pass
        return set()

    def _subdomains_jldc(self, domain):
        """jldc.me subdomain finder"""
        try:
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            resp = self.session.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return set(data) if isinstance(data, list) else set()
        except Exception:
            pass
        return set()

    # ========================================================================
    # WAF DETECTION (Zylon Custom)
    # ========================================================================

    def detect_waf(self, url):
        """Detect Web Application Firewall with fingerprinting"""
        result = {'detected': False, 'name': 'None', 'confidence': 0, 'details': {}}

        try:
            # Normal request
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            headers = dict(resp.headers)
            cookies = {c.name: c.value for c in resp.cookies}
            body = resp.text.lower()

            # Malicious request to trigger WAF
            waf_trigger_url = url + "/?id=1' OR '1'='1' -- <script>alert(1)</script>"
            try:
                resp_mal = self.session.get(waf_trigger_url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
                blocked = resp_mal.status_code in [403, 406, 429, 501, 999]
                mal_headers = dict(resp_mal.headers)
                mal_body = resp_mal.text.lower()
            except:
                blocked = False
                mal_headers = {}
                mal_body = ""

            for waf_name, sig in WAF_SIGNATURES.items():
                weight = 0
                # Check headers
                for h in sig.get('headers', []):
                    if h.lower() in ' '.join(headers.keys()).lower():
                        weight += 30
                    if h.lower() in ' '.join(headers.values()).lower():
                        weight += 20
                # Check cookies
                for c in sig.get('cookies', []):
                    if any(c.lower() in ck.lower() for ck in cookies):
                        weight += 25
                # Check body for WAF indicators
                for indicator in sig.get('body', []):
                    if indicator.lower() in body or indicator.lower() in mal_body:
                        weight += 20
                # Check if blocked with WAF status code
                if blocked and resp_mal.status_code in sig.get('status_code', []):
                    weight += 15

                if weight > result['confidence']:
                    result = {
                        'detected': weight >= 30,
                        'name': waf_name,
                        'confidence': min(weight, 100),
                        'details': {
                            'blocked_malicious': blocked,
                            'block_status_code': resp_mal.status_code if blocked else None,
                        }
                    }

            return result

        except Exception as e:
            return {'detected': False, 'error': str(e)[:100]}

    # ========================================================================
    # TECHNOLOGY FINGERPRINTING (Zylon Custom - Enhanced)
    # ========================================================================

    def fingerprint_tech(self, url):
        """Fingerprint technology stack"""
        technologies = []

        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            html = resp.text
            headers = dict(resp.headers)
            soup = BeautifulSoup(html, 'html.parser')
            cookies = {c.name: c.value for c in resp.cookies}

            for tech_name, sig in TECH_SIGNATURES.items():
                confidence = 0
                category = 'Unknown'

                # Meta generator check
                if 'meta' in sig and len(sig['meta']) >= 2:
                    meta = soup.find('meta', attrs={'name': sig['meta'][0]})
                    if meta and sig['meta'][1].lower() in str(meta.get('content', '')).lower():
                        confidence += 50
                        category = 'CMS'

                # File/path check in HTML
                for fpath in sig.get('files', []):
                    if fpath.lower() in html.lower():
                        confidence += 30
                        if category == 'Unknown':
                            category = 'Framework'

                # Header check
                for hname, hval in sig.get('headers', {}).items():
                    if hname in headers:
                        if not hval or hval.lower() in headers[hname].lower():
                            confidence += 40
                            if category == 'Unknown':
                                category = 'Server'

                # Cookie check
                for cname in sig.get('cookies', []):
                    if any(cname.lower() in c.lower() for c in cookies):
                        confidence += 25
                        if category == 'Unknown':
                            category = 'Framework'

                # JS pattern check
                for pattern in sig.get('js_patterns', []):
                    if pattern.lower() in html.lower():
                        confidence += 30
                        if category == 'Unknown':
                            category = 'Frontend'

                if confidence >= 20:
                    technologies.append({
                        'name': tech_name,
                        'confidence': min(confidence, 100),
                        'category': category
                    })

            # Server header
            server = headers.get('Server', '')
            if server and not any(t['name'] == server for t in technologies):
                technologies.append({'name': server, 'confidence': 90, 'category': 'Server'})

            # X-Powered-By header
            powered_by = headers.get('X-Powered-By', '')
            if powered_by and not any(t['name'] == powered_by for t in technologies):
                technologies.append({'name': powered_by, 'confidence': 85, 'category': 'Runtime'})

            technologies.sort(key=lambda x: x['confidence'], reverse=True)

            result = {'technologies': technologies, 'total': len(technologies)}

            # Modern SPA Framework Discovery
            try:
                spa_results = framework_discovery.discover(url)
                for category, endpoints in spa_results.items():
                    if endpoints:
                        result[f'spa_{category}'] = endpoints
            except Exception:
                pass

            return result

        except Exception as e:
            return {'technologies': [], 'error': str(e)[:100]}

    # ========================================================================
    # CLOUD BUCKET DETECTION (Zylon Custom)
    # ========================================================================

    def detect_cloud_buckets(self, domain):
        """Check for exposed cloud storage buckets"""
        result = {'exposed': False, 'findings': []}

        # Common bucket name patterns
        bucket_names = [
            domain, f"www.{domain}", domain.replace('.', '-'),
            f"{domain}-backup", f"{domain}-media", f"{domain}-assets",
            f"{domain}-logs", f"{domain}-data", f"{domain}-uploads",
        ]

        for provider, url_template in CLOUD_BUCKET_PATTERNS.items():
            for name in bucket_names:
                bucket_url = url_template.format(name=name)
                try:
                    resp = self.session.head(bucket_url, timeout=5, verify=VERIFY_SSL)
                    if resp.status_code == 200:
                        result['exposed'] = True
                        result['findings'].append({
                            'provider': provider,
                            'url': bucket_url,
                            'status': f'Accessible ({resp.status_code})'
                        })
                    elif resp.status_code == 403:
                        # Bucket exists but access denied - still interesting
                        result['findings'].append({
                            'provider': provider,
                            'url': bucket_url,
                            'status': 'Exists but access denied (403)'
                        })
                except:
                    pass

        return result

    # ========================================================================
    # EXTRACT SOCIAL LINKS (from wizard)
    # ========================================================================

    def extract_social_links(self, url):
        """Extract social media links from page"""
        social_domains = {
            'facebook': ['facebook.com', 'fb.com'],
            'twitter': ['twitter.com', 'x.com'],
            'linkedin': ['linkedin.com'],
            'instagram': ['instagram.com'],
            'youtube': ['youtube.com', 'youtu.be'],
            'github': ['github.com'],
            'reddit': ['reddit.com'],
            'telegram': ['t.me', 'telegram.org'],
            'discord': ['discord.gg', 'discord.com'],
        }

        results = {}
        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            for tag in soup.find_all(['a', 'link']):
                href = tag.get('href', '')
                for platform, domains in social_domains.items():
                    for domain in domains:
                        if domain in href.lower():
                            if platform not in results:
                                results[platform] = []
                            if href not in results[platform]:
                                results[platform].append(href)

            return results
        except Exception:
            return {}

    # ========================================================================
    # EXTRACT LINKS (from wizard + enhanced)
    # ========================================================================

    def extract_links(self, url):
        """Extract and categorize all links from page"""
        result = {'internal': [], 'external': [], 'emails': [], 'js_files': [], 'css_files': []}

        try:
            domain = urlparse(url).netloc.replace('www.', '')
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=VERIFY_SSL)
            soup = BeautifulSoup(resp.text, 'html.parser')

            for tag in soup.find_all('a', href=True):
                href = tag['href']
                if href.startswith('#') or href.startswith('javascript:'):
                    continue
                abs_url = urljoin(url, href)
                if domain in abs_url:
                    result['internal'].append(abs_url)
                else:
                    result['external'].append(abs_url)

            for tag in soup.find_all('script', src=True):
                result['js_files'].append(urljoin(url, tag['src']))

            for tag in soup.find_all('link', rel='stylesheet', href=True):
                result['css_files'].append(urljoin(url, tag['href']))

            # Extract emails
            emails = regex_cache.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', resp.text)
            result['emails'] = list(set(emails))

            # Deduplicate
            for key in ['internal', 'external', 'js_files', 'css_files']:
                result[key] = list(set(result[key]))

            return result
        except Exception as e:
            return {'error': str(e)[:100]}


