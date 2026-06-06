"""
ZYLON FUSION - Network Engine
Fuses: omino's nmap/port scanning + wizard's network tools + Zylon custom
Termux Non-Root Compatible - Connect scan only (no SYN scan)
"""

import re
import json
import socket
import ssl
import random
import requests
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.var import (
    DEFAULT_PORTS, DEFAULT_TIMEOUT, MAX_THREADS, QUICK_PORTS, USER_AGENTS, VERIFY_SSL
)
from core.shared_infra import shared_session, regex_cache

# DNS resolver compatibility (dnspython < 2.0 uses query, >= 2.0 uses resolve)
try:
    _dns_resolve = dns.resolver.resolve
except AttributeError:
    _dns_resolve = dns.resolver.query


class NetworkEngine:
    """Advanced Network Scanning Engine - Termux Non-Root Compatible"""

    def __init__(self, session=None):
        self.session = session or shared_session
        # User-Agent rotation handled by shared_session
        pass

    # ========================================================================
    # DNS RESOLUTION
    # ========================================================================

    def resolve_ip(self, domain):
        """Resolve domain to IP address"""
        try:
            domain = domain.replace('www.', '').split(':')[0]
            return socket.gethostbyname(domain)
        except Exception:
            return None

    # ========================================================================
    # DNS LOOKUP (from wizard + omino's dig approach)
    # ========================================================================

    def dns_lookup(self, domain):
        """Comprehensive DNS record enumeration"""
        records = {}
        domain = domain.replace('www.', '').replace('http://', '').replace('https://', '').split('/')[0]

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']

        for rtype in record_types:
            try:
                answers = _dns_resolve(domain, rtype)
                records[rtype] = [str(rdata) for rdata in answers]
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                pass
            except Exception:
                pass

        # Additional checks
        try:
            # DMARC
            dmarc = _dns_resolve(f'_dmarc.{domain}', 'TXT')
            records['DMARC'] = [str(rdata) for rdata in dmarc]
        except Exception:
            pass

        return records if records else {'error': 'No DNS records found'}

    # ========================================================================
    # GEO-IP LOOKUP (from wizard)
    # ========================================================================

    def get_geolocation(self, ip):
        """Get geolocation for an IP address using free API"""
        try:
            resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('status') == 'success':
                    return data
        except Exception:
            pass

        # Fallback API
        try:
            resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                loc = data.get('loc', ',').split(',')
                return {
                    'country': data.get('country'),
                    'city': data.get('city'),
                    'regionName': data.get('region'),
                    'isp': data.get('org'),
                    'org': data.get('org'),
                    'lat': loc[0] if len(loc) >= 1 else None,
                    'lon': loc[1] if len(loc) >= 2 else None,
                    'timezone': data.get('timezone'),
                }
        except Exception:
            pass

        return None

    # ========================================================================
    # PORT SCANNER (Termux Non-Root Compatible - Connect Scan Only)
    # ========================================================================

    def port_scan(self, host, ports=None, timeout=2, max_threads=MAX_THREADS):
        """
        TCP Connect port scanner - NO ROOT REQUIRED
        Uses standard socket connect() instead of SYN scan
        """
        if ports is None:
            ports = QUICK_PORTS

        open_ports = {}

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, port))
                sock.close()

                if result == 0:
                    service = DEFAULT_PORTS.get(port, 'unknown')
                    banner = self._grab_banner(host, port)
                    return port, {'service': service, 'banner': banner, 'state': 'open'}
            except Exception:
                pass
            return port, None

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(scan_port, p): p for p in ports}
            for future in as_completed(futures):
                port, info = future.result()
                if info:
                    open_ports[port] = info

        return open_ports

    def _grab_banner(self, host, port, timeout=3):
        """Grab service banner from open port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send HTTP request for web ports
            if port in [80, 8080, 8443, 8888, 9090]:
                sock.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            elif port in [443]:
                # SSL banner grab
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssock = context.wrap_socket(sock, server_hostname=host)
                ssock.send(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                banner = ssock.recv(1024).decode('utf-8', errors='ignore').strip()
                ssock.close()
                sock.close()
                return banner[:200]

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:200]
        except Exception:
            return None

    # ========================================================================
    # BANNER GRABBING (from wizard + enhanced)
    # ========================================================================

    def banner_grab(self, domain, ports=None):
        """Grab banners from common services"""
        if ports is None:
            ports = [21, 22, 25, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080, 8443]

        ip = self.resolve_ip(domain)
        if not ip:
            return {}

        banners = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for port in ports:
                futures[executor.submit(self._grab_banner, ip, port, 3)] = port

            for future in as_completed(futures):
                port = futures[future]
                try:
                    banner = future.result()
                    if banner:
                        banners[port] = banner
                except Exception:
                    pass

        return banners

    # ========================================================================
    # SSL/TLS ANALYSIS (Zylon Custom + enhanced from wizard)
    # ========================================================================

    def ssl_analyze(self, domain):
        """Analyze SSL/TLS certificate and configuration"""
        result = {
            'issues': [],
            'valid': False,
            'expired': False,
            'self_signed': False,
            'weak_protocol': False,
        }

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(DEFAULT_TIMEOUT)
            conn = context.wrap_socket(sock, server_hostname=domain)
            conn.connect((domain, 443))

            # Get certificate
            cert = None
            try:
                cert = conn.getpeercert(binary_form=False)
            except ssl.SSLError:
                # If cert validation fails, try with CERT_NONE and binary form
                try:
                    conn.close()
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.settimeout(DEFAULT_TIMEOUT)
                    context2 = ssl.create_default_context()
                    context2.check_hostname = False
                    context2.verify_mode = ssl.CERT_NONE
                    conn = context2.wrap_socket(sock2, server_hostname=domain)
                    conn.connect((domain, 443))
                    cert = conn.getpeercert(binary_form=False)
                except Exception:
                    cert = None
            if cert:
                result['valid'] = True

                # Subject
                subject = dict(x[0] for x in cert.get('subject', []))
                result['subject'] = subject

                # Issuer
                issuer = dict(x[0] for x in cert.get('issuer', []))
                result['issuer'] = issuer.get('organizationName', 'Unknown')

                # Validity dates
                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')
                result['valid_from'] = not_before
                result['valid_to'] = not_after

                # Check expiration
                if not_after:
                    try:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if expiry < datetime.now():
                            result['expired'] = True
                            result['issues'].append(f"Certificate expired on {not_after}")
                        # Check if expiring within 30 days
                        days_left = (expiry - datetime.now()).days
                        if days_left < 30:
                            result['issues'].append(f"Certificate expires in {days_left} days")
                        result['days_until_expiry'] = days_left
                    except Exception:
                        pass

                # SANs
                sans = []
                for ext in cert.get('subjectAltName', []):
                    sans.append(ext[1])
                result['san_count'] = len(sans)
                result['sans'] = sans[:10]

                # Check for wildcard
                if any('*' in san for san in sans):
                    result['wildcard'] = True
                    result['issues'].append("Wildcard certificate detected - may be overly permissive")

            # Protocol version
            protocol = conn.version()
            result['protocol'] = protocol

            # Check for weak protocols
            if protocol in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                result['weak_protocol'] = True
                result['issues'].append(f"Weak protocol detected: {protocol}")

            # Cipher suite
            cipher = conn.cipher()
            if cipher:
                result['cipher'] = cipher[0]
                result['cipher_strength'] = cipher[2] if len(cipher) > 2 else 'Unknown'

                # Check for weak ciphers
                weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                for wc in weak_ciphers:
                    if wc in cipher[0].upper():
                        result['issues'].append(f"Weak cipher: {cipher[0]}")
                        break

            conn.close()

            # Check for HSTS
            try:
                resp = self.session.get(f"https://{domain}", timeout=5, verify=False)
                hsts = resp.headers.get('Strict-Transport-Security', '')
                if hsts:
                    result['hsts'] = hsts
                else:
                    result['issues'].append("HSTS header not set")
            except Exception:
                pass

        except ssl.SSLError as e:
            result['valid'] = False
            result['error'] = f"SSL Error: {str(e)[:100]}"
            result['issues'].append(f"SSL Error: {str(e)[:100]}")
        except Exception as e:
            result['valid'] = False
            result['error'] = str(e)[:100]

        return result

    # ========================================================================
    # REVERSE IP LOOKUP (from wizard)
    # ========================================================================

    def reverse_ip(self, ip):
        """Reverse DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None

    # ========================================================================
    # MX RECORD ANALYSIS (from wizard + enhanced)
    # ========================================================================

    def mx_analysis(self, domain):
        """Analyze MX records with security checks"""
        result = {'mx_records': [], 'spf': None, 'dmarc': None, 'security_score': 0}

        domain = domain.replace('www.', '').split('/')[0]

        try:
            mx_records = _dns_resolve(domain, 'MX')
            for mx in mx_records:
                host = str(mx.exchange).rstrip('.')
                try:
                    ip = socket.gethostbyname(host)
                except:
                    ip = 'Unknown'
                result['mx_records'].append({
                    'hostname': host,
                    'preference': mx.preference,
                    'ip': ip
                })
        except Exception:
            pass

        # SPF
        try:
            txt_records = _dns_resolve(domain, 'TXT')
            for txt in txt_records:
                txt_str = str(txt).strip('"')
                if 'v=spf1' in txt_str:
                    result['spf'] = txt_str
                    result['security_score'] += 40
                    if '-all' in txt_str:
                        result['security_score'] += 10
                    break
        except Exception:
            pass

        # DMARC
        try:
            dmarc_records = _dns_resolve(f'_dmarc.{domain}', 'TXT')
            for dmarc in dmarc_records:
                dmarc_str = str(dmarc).strip('"')
                if 'v=DMARC1' in dmarc_str:
                    result['dmarc'] = dmarc_str
                    result['security_score'] += 50
                    break
        except Exception:
            pass

        return result


