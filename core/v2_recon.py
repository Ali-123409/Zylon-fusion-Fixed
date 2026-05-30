#!/usr/bin/env python3
"""
ZYLON FUSION v2.0 - Advanced Reconnaissance Engine 2
Email Enumeration | Broken Link Hijacking | Tech Version + CVE Lookup
Termux Non-Root Compatible
"""

import re
import socket
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from core.var import *


class V2ReconEngine:
    """V2.0 Reconnaissance: Email Enum, Broken Links, Tech+CVE"""

    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENTS[0]})
        self.session.verify = VERIFY_SSL

    def _rotate_ua(self):
        import random
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})

    # ========================================================================
    # EMAIL ENUMERATION
    # ========================================================================

    def enumerate_emails(self, domain):
        """
        Discover email addresses associated with a domain.
        Sources: Google, GitHub, Gravatar, crt.sh, and pattern generation.
        """
        results = {
            'domain': domain,
            'emails': [],
            'patterns_generated': [],
            'sources': {}
        }
        found_emails = set()

        # Source 1: Google search scraping (via DuckDuckGo HTML - no API key)
        try:
            ddg_url = f"https://html.duckduckgo.com/html/?q=%22%40{domain}%22+email"
            resp = self.session.get(ddg_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                email_re = re.compile(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain))
                emails = email_re.findall(resp.text)
                for email in emails:
                    found_emails.add(email.lower().strip())
                    results['sources'].setdefault('duckduckgo', []).append(email.lower().strip())
        except Exception:
            pass

        # Source 2: crt.sh certificate transparency
        try:
            crt_url = f"https://crt.sh/?q=%{domain}&output=json"
            resp = self.session.get(crt_url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                email_re = re.compile(r'[a-zA-Z0-9._%+-]+@' + re.escape(domain))
                for entry in data:
                    name = entry.get('name_value', '')
                    emails = email_re.findall(name)
                    for email in emails:
                        found_emails.add(email.lower().strip())
                        results['sources'].setdefault('crt.sh', []).append(email.lower().strip())
        except Exception:
            pass

        # Source 3: GitHub API (public, no key needed for basic search)
        try:
            gh_url = f"https://api.github.com/search/users?q={domain}+in:email"
            resp = self.session.get(gh_url, timeout=DEFAULT_TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                for user in data.get('items', [])[:10]:
                    username = user.get('login', '')
                    # Try common patterns
                    for pattern in ['{first}@{domain}', '{first}.{last}@{domain}']:
                        email = pattern.replace('{first}', username.lower()).replace('{last}', username.lower()).replace('{domain}', domain)
                        if '@' in email:
                            found_emails.add(email)
                            results['sources'].setdefault('github', []).append(email)
        except Exception:
            pass

        # Source 4: Pattern-based generation
        common_names = ['admin', 'info', 'support', 'contact', 'webmaster',
                       'security', 'dev', 'ops', 'hr', 'legal', 'sales',
                       'marketing', 'noreply', 'no-reply', 'postmaster',
                       'abuse', 'hostmaster', 'dns', 'tech', 'help']
        for name in common_names:
            email = f"{name}@{domain}"
            found_emails.add(email)
            results['patterns_generated'].append(email)

        # Source 5: DNS MX record check (indicates email capability)
        mx_records = []
        if DNS_AVAILABLE:
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                for rdata in answers:
                    mx_records.append(str(rdata.exchange).rstrip('.'))
            except Exception:
                pass

        results['emails'] = sorted(list(found_emails))
        results['mx_records'] = mx_records
        results['total_found'] = len(found_emails)

        return results

    # ========================================================================
    # BROKEN LINK HIJACKING
    # ========================================================================

    def check_broken_links(self, url):
        """
        Find broken external links on a page that could be hijacked.
        Checks all <a href> links for 404/410/500 status codes.
        """
        results = {
            'url': url,
            'broken_links': [],
            'total_links': 0,
            'external_links': 0,
            'hijackable': []
        }

        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT)
            soup = BeautifulSoup(resp.text, 'html.parser')
        except Exception as e:
            results['error'] = str(e)
            return results

        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc

        # Collect all links
        links = []
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip()
            if not href or href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                continue
            full_url = urljoin(url, href)
            links.append(full_url)

        results['total_links'] = len(links)

        # Filter external links
        external_links = []
        for link in links:
            try:
                parsed = urlparse(link)
                if parsed.netloc and parsed.netloc != base_domain and not parsed.netloc.endswith('.' + base_domain):
                    external_links.append(link)
                    results['external_links'] += 1
            except Exception:
                pass

        # Check external links for broken status (threaded)
        def check_link(link):
            try:
                r = self.session.head(link, timeout=8, allow_redirects=True)
                if r.status_code in [405, 501, 503]:
                    r = self.session.get(link, timeout=8, allow_redirects=True)
                return (link, r.status_code, r.headers.get('server', ''))
            except requests.exceptions.ConnectionError:
                return (link, 0, 'connection_failed')
            except Exception:
                return (link, 0, 'error')

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_link, link): link for link in external_links}
            for future in as_completed(futures):
                link, status, server = future.result()
                if status in BROKEN_LINK_CODES:
                    broken_info = {
                        'url': link,
                        'status_code': status,
                        'server': server,
                        'domain': urlparse(link).netloc,
                        'hijackable': False
                    }

                    # Check if domain is available for registration
                    try:
                        domain = urlparse(link).netloc
                        old_timeout = socket.getdefaulttimeout()
                        socket.setdefaulttimeout(5)
                        try:
                            socket.gethostbyname(domain)
                        except socket.gaierror:
                            broken_info['hijackable'] = True
                            results['hijackable'].append(broken_info)
                        except socket.timeout:
                            pass  # DNS timeout ≠ available
                        finally:
                            socket.setdefaulttimeout(old_timeout)
                    except Exception:
                        pass

                    results['broken_links'].append(broken_info)

        results['total_broken'] = len(results['broken_links'])
        results['total_hijackable'] = len(results['hijackable'])

        return results

    # ========================================================================
    # TECHNOLOGY VERSION + CVE LOOKUP
    # ========================================================================

    def detect_tech_versions(self, url):
        """
        Detect technology versions from HTTP headers, meta tags, and page content.
        Then look up known CVEs for each detected version.
        """
        results = {
            'url': url,
            'technologies': [],
            'cves': [],
            'risk_summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        }

        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT)
        except Exception as e:
            results['error'] = str(e)
            return results

        headers = dict(resp.headers)
        soup = BeautifulSoup(resp.text, 'html.parser')
        page_text = resp.text

        # Detect versions from TECH_VERSION_SIGNATURES
        for tech_name, sig in TECH_VERSION_SIGNATURES.items():
            version = None
            source = None

            # Check headers
            if 'header' in sig and sig.get('header'):
                header_val = headers.get(sig['header'], '')
                if header_val and 'regex' in sig:
                    match = re.search(sig['regex'], header_val)
                    if match:
                        version = match.group(1)
                        source = f"Header: {sig['header']}"

            # Check meta tags
            if not version and 'meta' in sig:
                meta_tag = soup.find('meta', {'name': sig['meta']})
                if meta_tag:
                    content = meta_tag.get('content', '')
                    if 'regex' in sig:
                        match = re.search(sig['regex'], content)
                        if match:
                            version = match.group(1)
                            source = f"Meta: {sig['meta']}"

            # Check JS patterns
            if not version and 'js_pattern' in sig:
                match = re.search(sig['js_pattern'], page_text, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    source = "JavaScript"

            # Check cookie-based detection
            if not version and 'cookie' in sig:
                cookies = resp.cookies
                for cookie in cookies:
                    if sig['cookie'] in cookie.name:
                        version = 'detected (version unknown)'
                        source = f"Cookie: {cookie.name}"
                        break

            if version:
                tech_info = {
                    'name': tech_name,
                    'version': version,
                    'source': source,
                    'cves': []
                }

                # CVE lookup if we have a real version number
                if version and version != 'detected (version unknown)':
                    cves = self._lookup_cves(tech_name, version)
                    tech_info['cves'] = cves
                    results['cves'].extend(cves)

                    # Count by severity
                    for cve in cves:
                        severity = cve.get('severity', 'medium').lower()
                        if severity in results['risk_summary']:
                            results['risk_summary'][severity] += 1

                results['technologies'].append(tech_info)

        # Also check common headers that weren't in signatures
        server_header = headers.get('Server', '')
        if server_header and not any(t['name'] in ['Apache', 'nginx'] for t in results['technologies']):
            results['technologies'].append({
                'name': 'Server',
                'version': server_header,
                'source': 'Header: Server',
                'cves': []
            })

        powered_by = headers.get('X-Powered-By', '')
        if powered_by and not any(t['name'] == 'PHP' or t['name'] == 'Express' for t in results['technologies']):
            results['technologies'].append({
                'name': 'X-Powered-By',
                'version': powered_by,
                'source': 'Header: X-Powered-By',
                'cves': []
            })

        results['total_techs'] = len(results['technologies'])
        results['total_cves'] = len(results['cves'])

        return results

    def _lookup_cves(self, tech_name, version):
        """Look up CVEs for a specific technology and version using CIRCL API"""
        cves = []

        try:
            # Use CIRCL API for CVE lookup
            api_url = f"{CVE_API}/search/{tech_name}/{version}"
            resp = self.session.get(api_url, timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                for cve_entry in data[:10]:  # Limit to top 10
                    cve_info = {
                        'id': cve_entry.get('id', 'Unknown'),
                        'summary': cve_entry.get('summary', '')[:200],
                        'severity': 'medium',
                        'cvss': cve_entry.get('cvss', 0),
                        'url': f"https://nvd.nist.gov/vuln/detail/{cve_entry.get('id', '')}"
                    }

                    # Determine severity from CVSS score
                    cvss = float(cve_info.get('cvss', 0))
                    if cvss >= 9.0:
                        cve_info['severity'] = 'critical'
                    elif cvss >= 7.0:
                        cve_info['severity'] = 'high'
                    elif cvss >= 4.0:
                        cve_info['severity'] = 'medium'
                    else:
                        cve_info['severity'] = 'low'

                    cves.append(cve_info)
        except Exception:
            # Fallback: try NVD API
            try:
                nvd_url = f"{NVD_API}?keywordSearch={tech_name}+{version}&resultsPerPage=5"
                resp = self.session.get(nvd_url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    for vuln in data.get('vulnerabilities', []):
                        cve_data = vuln.get('cve', {})
                        cve_id = cve_data.get('id', 'Unknown')
                        descriptions = cve_data.get('descriptions', [])
                        summary = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')[:200]

                        # Try to get CVSS
                        metrics = cve_data.get('metrics', {})
                        cvss_score = 0
                        severity = 'medium'
                        if 'cvssMetricV31' in metrics:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0)
                            severity = cvss_data.get('baseSeverity', 'MEDIUM').lower()
                        elif 'cvssMetricV2' in metrics:
                            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0)
                            severity = cvss_data.get('baseSeverity', 'MEDIUM').lower()

                        cves.append({
                            'id': cve_id,
                            'summary': summary,
                            'severity': severity,
                            'cvss': cvss_score,
                            'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                        })
            except Exception:
                pass

        return cves
