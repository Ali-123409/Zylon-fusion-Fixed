#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Bug Bounty Management Engine
===================================================
Fused from: BBRF (Bug Bounty Reconnaissance Framework)
           + BugBountyTools
           + Custom Zylon Techniques
Capabilities:
  - Bug bounty program scope management
  - Target tracking and organization
  - Scan result management and deduplication
  - Finding severity classification
  - Report generation for bug bounty submissions
  - Program scope validation
  - Historical finding tracking
  - Multi-program management
  - Scope change monitoring
  - Asset inventory management
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import sys
import re
import json
import time
import hashlib
import threading
import random
from datetime import datetime
from urllib.parse import urlparse, urljoin

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    API_ENDPOINTS, COMMON_DIRS, CONFIG_DIR, DEFAULT_TIMEOUT, MAX_THREADS, USER_AGENTS
)
from core.shared_infra import shared_session, regex_cache, PayloadInjector

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
# SEVERITY DEFINITIONS
# ============================================================================

SEVERITY_LEVELS = {
    "Critical": {
        "cvss_range": (9.0, 10.0),
        "color": RED,
        "description": "Immediate exploitation possible, severe impact",
        "examples": ["RCE", "SQLi with data extraction", "Auth bypass", "SSRF to internal access"],
    },
    "High": {
        "cvss_range": (7.0, 8.9),
        "color": MAGENTA,
        "description": "Significant security impact",
        "examples": ["Stored XSS", "IDOR with sensitive data", "Privilege escalation", "Significant info disclosure"],
    },
    "Medium": {
        "cvss_range": (4.0, 6.9),
        "color": YELLOW,
        "description": "Moderate security impact",
        "examples": ["Reflected XSS", "CSRF", "Open redirect", "Moderate info leak"],
    },
    "Low": {
        "cvss_range": (0.1, 3.9),
        "color": CYAN,
        "description": "Limited security impact",
        "examples": ["Verbose errors", "Missing headers", "Low-impact info disclosure"],
    },
    "Info": {
        "cvss_range": (0.0, 0.0),
        "color": DIM,
        "description": "Informational finding",
        "examples": ["Banner disclosure", "Technology fingerprint", "Comment exposure"],
    },
}

# ============================================================================
# BOUNTY DATA STORAGE
# ============================================================================

BOUNTY_DATA_DIR = os.path.join(CONFIG_DIR, "bounty")
PROGRAMS_FILE = os.path.join(BOUNTY_DATA_DIR, "programs.json")
FINDINGS_FILE = os.path.join(BOUNTY_DATA_DIR, "findings.json")
SCOPE_FILE = os.path.join(BOUNTY_DATA_DIR, "scope_history.json")


class BountyMgmtEngine:
    """Bug Bounty Management Engine - Fused from BBRF + BugBountyTools + Custom Techniques"""

    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=MAX_THREADS, proxy=None):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = shared_session
        # SSL verification handled by shared_session
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()
        self.programs = {}
        self.findings = []
        self.scope_history = []
        self._load_data()

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _load_data(self):
        """Load bounty data from disk"""
        os.makedirs(BOUNTY_DATA_DIR, exist_ok=True)

        if os.path.exists(PROGRAMS_FILE):
            try:
                with open(PROGRAMS_FILE, 'r') as f:
                    self.programs = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.programs = {}

        if os.path.exists(FINDINGS_FILE):
            try:
                with open(FINDINGS_FILE, 'r') as f:
                    self.findings = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.findings = []

        if os.path.exists(SCOPE_FILE):
            try:
                with open(SCOPE_FILE, 'r') as f:
                    self.scope_history = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.scope_history = []

    def _save_data(self):
        """Save bounty data to disk"""
        os.makedirs(BOUNTY_DATA_DIR, exist_ok=True)
        try:
            with open(PROGRAMS_FILE, 'w') as f:
                json.dump(self.programs, f, indent=2, default=str)
            with open(FINDINGS_FILE, 'w') as f:
                json.dump(self.findings, f, indent=2, default=str)
            with open(SCOPE_FILE, 'w') as f:
                json.dump(self.scope_history, f, indent=2, default=str)
        except IOError as e:
            self._print(f"  [!] Error saving data: {e}", RED)

    def _deduplicate_finding(self, finding):
        """Generate dedup hash for a finding"""
        dedup_str = (
            f"{finding.get('program', '')}"
            f"{finding.get('type', '')}"
            f"{finding.get('target', '')}"
            f"{finding.get('endpoint', '')}"
        )
        return hashlib.md5(dedup_str.encode()).hexdigest()

    # ========================================================================
    # PROGRAM MANAGEMENT
    # ========================================================================

    def add_program(self, name, scope_url):
        """Add a bug bounty program

        Args:
            name: Program name (e.g., 'HackerOne - example.com')
            scope_url: Scope URL or domain pattern

        Returns:
            dict with program info
        """
        self._print(f"\n{BOLD}{CYAN}  Adding Bug Bounty Program{RESET}", CYAN)
        self._print(f"  [*] Program: {name}", CYAN)
        self._print(f"  [*] Scope: {scope_url}", CYAN)

        program_id = hashlib.md5(f"{name}".encode()).hexdigest()[:12]

        # Parse scope
        parsed_scope = self._parse_scope(scope_url)

        program = {
            "id": program_id,
            "name": name,
            "scope_url": scope_url,
            "scope": parsed_scope,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "active",
            "findings_count": 0,
            "assets": [],
            "scope_changes": [],
        }

        # Try to fetch program scope if URL provided
        if scope_url.startswith('http'):
            try:
                resp = self.session.get(scope_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    # Try to extract scope from page
                    domains = regex_cache.findall(
                        r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)',
                        resp.text
                    )
                    unique_domains = list(set(domains))[:50]
                    for domain in unique_domains:
                        if domain not in program["scope"]["domains"]:
                            program["scope"]["domains"].append(domain)

                    # Detect IPs
                    ips = regex_cache.findall(
                        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                        resp.text
                    )
                    unique_ips = list(set(ips))[:20]
                    for ip in unique_ips:
                        if ip not in program["scope"]["ips"]:
                            program["scope"]["ips"].append(ip)

                    self._print(f"  [+] Discovered {len(unique_domains)} domains in scope", GREEN)
                    self._print(f"  [+] Discovered {len(unique_ips)} IPs in scope", GREEN)

            except Exception as e:
                self._print(f"  [!] Could not fetch scope URL: {str(e)[:80]}", YELLOW)

        self.programs[program_id] = program
        self._save_data()

        self._print(f"  [+] Program '{name}' added (ID: {program_id})", GREEN)
        self._print(f"  [+] Scope: {len(program['scope']['domains'])} domains, "
                     f"{len(program['scope']['ips'])} IPs", GREEN)

        return {
            "program_id": program_id,
            "name": name,
            "scope": program["scope"],
            "added": True,
        }

    def _parse_scope(self, scope_url):
        """Parse scope URL/pattern into structured scope"""
        scope = {
            "domains": [],
            "ips": [],
            "cidrs": [],
            "wildcards": [],
            "exclusions": [],
        }

        # If it's a domain
        if regex_cache.match(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$', scope_url):
            scope["domains"].append(scope_url)

        # If it's a wildcard
        elif scope_url.startswith('*.'):
            scope["wildcards"].append(scope_url)
            base_domain = scope_url[2:]
            scope["domains"].append(base_domain)

        # If it's an IP
        elif regex_cache.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', scope_url):
            scope["ips"].append(scope_url)

        # If it's a CIDR
        elif regex_cache.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', scope_url):
            scope["cidrs"].append(scope_url)

        # If it's a URL, extract domain
        elif scope_url.startswith('http'):
            parsed = urlparse(scope_url)
            domain = parsed.hostname
            if domain:
                scope["domains"].append(domain)

        return scope

    def list_programs(self):
        """List all bug bounty programs

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Bug Bounty Programs List{RESET}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "programs": [],
                "total_programs": 0,
                "total_findings": 0,
                "active_programs": 0,
            },
            "scan_type": "list_programs",
        }

        if not self.programs:
            self._print(f"  [-] No programs configured", YELLOW)
            return result

        for pid, prog in self.programs.items():
            prog_info = {
                "id": pid,
                "name": prog.get("name", "Unknown"),
                "status": prog.get("status", "unknown"),
                "scope_domains": len(prog.get("scope", {}).get("domains", [])),
                "scope_ips": len(prog.get("scope", {}).get("ips", [])),
                "findings_count": prog.get("findings_count", 0),
                "created_at": prog.get("created_at", "Unknown"),
            }
            result["details"]["programs"].append(prog_info)
            result["details"]["total_findings"] += prog.get("findings_count", 0)
            if prog.get("status") == "active":
                result["details"]["active_programs"] += 1

            self._print(
                f"  [{prog.get('status', '?').upper()}] {prog.get('name', 'Unknown')} "
                f"(Domains: {prog_info['scope_domains']}, Findings: {prog_info['findings_count']})",
                GREEN if prog.get("status") == "active" else YELLOW
            )

        result["details"]["total_programs"] = len(self.programs)
        self._print(f"  [*] Total: {len(self.programs)} programs, "
                     f"{result['details']['active_programs']} active", CYAN)

        return result

    # ========================================================================
    # FINDING MANAGEMENT
    # ========================================================================

    def add_finding(self, program, finding):
        """Add a finding to a program

        Args:
            program: Program name or ID
            finding: Finding dict with type, target, endpoint, etc.

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Adding Finding to Program{RESET}", CYAN)
        self._print(f"  [*] Program: {program}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "program": program,
                "finding_added": False,
                "dedup_status": "new",
                "severity": "Info",
            },
            "scan_type": "add_finding",
        }

        # Find program
        prog = self._find_program(program)
        if not prog:
            self._print(f"  [!] Program '{program}' not found", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Program '{program}' not found",
            })
            return result

        program_id = prog["id"]

        # Add metadata to finding
        finding["program_id"] = program_id
        finding["program_name"] = prog["name"]
        finding["timestamp"] = datetime.now().isoformat()
        finding["id"] = hashlib.md5(
            f"{finding.get('type', '')}{finding.get('target', '')}{time.time()}".encode()
        ).hexdigest()[:10]

        # Classify severity
        severity = self.classify_severity(finding)
        finding["severity"] = severity
        result["details"]["severity"] = severity

        # Deduplicate
        dedup_hash = self._deduplicate_finding(finding)
        finding["dedup_hash"] = dedup_hash

        existing_hashes = [f.get("dedup_hash") for f in self.findings
                          if f.get("program_id") == program_id]

        if dedup_hash in existing_hashes:
            self._print(f"  [!] Duplicate finding detected (hash: {dedup_hash})", YELLOW)
            result["details"]["dedup_status"] = "duplicate"
            # Update existing finding if new info
            for existing in self.findings:
                if existing.get("dedup_hash") == dedup_hash:
                    existing["last_seen"] = datetime.now().isoformat()
                    existing["occurrence_count"] = existing.get("occurrence_count", 1) + 1
                    break
            self._save_data()
            return result

        # Add finding
        finding["occurrence_count"] = 1
        finding["first_seen"] = finding["timestamp"]
        finding["last_seen"] = finding["timestamp"]
        finding["status"] = "new"
        self.findings.append(finding)

        # Update program counter
        self.programs[program_id]["findings_count"] = (
            self.programs[program_id].get("findings_count", 0) + 1
        )
        self.programs[program_id]["updated_at"] = datetime.now().isoformat()

        self._save_data()

        result["details"]["finding_added"] = True
        result["vulnerable"] = severity in ("Critical", "High", "Medium")
        result["findings"].append({
            "type": "new_finding",
            "severity": severity,
            "description": f"New finding added: {finding.get('type', 'Unknown')} "
                          f"on {finding.get('target', 'Unknown')} "
                          f"[{severity}]",
            "finding_id": finding["id"],
        })

        sev_color = SEVERITY_LEVELS.get(severity, {}).get("color", CYAN)
        self._print(f"  [+] Finding added: {finding.get('type', 'Unknown')} "
                     f"[{severity}]", sev_color)

        return result

    def _find_program(self, program_ref):
        """Find program by name or ID"""
        # Check by ID
        if program_ref in self.programs:
            return self.programs[program_ref]

        # Check by name
        for pid, prog in self.programs.items():
            if prog.get("name", "").lower() == program_ref.lower():
                return prog
            if program_ref.lower() in prog.get("name", "").lower():
                return prog

        return None

    def classify_severity(self, finding):
        """Classify finding severity

        Args:
            finding: Finding dict

        Returns:
            str: Severity level (Critical/High/Medium/Low/Info)
        """
        finding_type = finding.get("type", "").lower()
        description = finding.get("description", "").lower()
        endpoint = finding.get("endpoint", "").lower()

        # Critical severity indicators
        critical_patterns = [
            "rce", "remote code execution", "command injection",
            "sql injection", "sqli", "authentication bypass", "auth bypass",
            "server-side request forgery", "ssrf", "internal access",
            "arbitrary file read", "arbitrary file write",
            "deserialization", "unsafe deserialization",
            "privilege escalation", "admin access",
        ]

        # High severity indicators
        high_patterns = [
            "stored xss", "persistent xss", "xss stored",
            "idor", "insecure direct object",
            "csrf", "cross-site request forgery",
            "broken authentication", "session hijacking",
            "information disclosure", "sensitive data exposure",
            "path traversal", "local file inclusion", "lfi",
            "blind sqli", "blind sql injection",
            "nosql injection", "xxe", "xml external entity",
            "jwt forgery", "token manipulation",
            "prototype pollution", "cache poisoning",
        ]

        # Medium severity indicators
        medium_patterns = [
            "reflected xss", "xss reflected", "dom xss", "dom-based xss",
            "open redirect", "url redirect",
            "cors misconfiguration", "cors bypass",
            "clickjacking", "frameable",
            "subdomain takeover", "dns takeover",
            "rate limit", "brute force",
            "crlf injection", "http response splitting",
            "websocket", "smuggling",
        ]

        # Low severity indicators
        low_patterns = [
            "missing header", "security header",
            "cookie flag", "httponly", "secure flag", "samesite",
            "verbose error", "stack trace",
            "information leak", "version disclosure",
            "mixed content", "insecure transport",
            "captcha bypass", "email enumeration",
        ]

        # Check in order of severity
        text_to_check = f"{finding_type} {description} {endpoint}"

        for pattern in critical_patterns:
            if pattern in text_to_check:
                return "Critical"

        for pattern in high_patterns:
            if pattern in text_to_check:
                return "High"

        for pattern in medium_patterns:
            if pattern in text_to_check:
                return "Medium"

        for pattern in low_patterns:
            if pattern in text_to_check:
                return "Low"

        # Use CVSS score if available
        cvss = finding.get("cvss", 0)
        if cvss:
            for level, info in SEVERITY_LEVELS.items():
                low, high = info["cvss_range"]
                if low <= cvss <= high:
                    return level

        return "Info"

    # ========================================================================
    # REPORT GENERATION
    # ========================================================================

    def generate_report(self, program, format='md'):
        """Generate report for bug bounty submission

        Args:
            program: Program name or ID
            format: Report format ('md', 'json', 'txt')

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Generating Bug Bounty Report{RESET}", CYAN)
        self._print(f"  [*] Program: {program}", CYAN)
        self._print(f"  [*] Format: {format}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "program": program,
                "format": format,
                "report_path": "",
                "findings_count": 0,
                "severity_breakdown": {},
            },
            "scan_type": "generate_report",
        }

        # Find program
        prog = self._find_program(program)
        if not prog:
            self._print(f"  [!] Program '{program}' not found", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Program '{program}' not found",
            })
            return result

        program_id = prog["id"]

        # Get program findings
        prog_findings = [f for f in self.findings if f.get("program_id") == program_id]

        if not prog_findings:
            self._print(f"  [-] No findings for program '{prog['name']}'", YELLOW)
            return result

        # Severity breakdown
        severity_breakdown = {}
        for f in prog_findings:
            sev = f.get("severity", "Info")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        result["details"]["findings_count"] = len(prog_findings)
        result["details"]["severity_breakdown"] = severity_breakdown

        # Sort findings by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        prog_findings.sort(key=lambda x: severity_order.get(x.get("severity", "Info"), 5))

        # Generate report content
        if format == 'md':
            report = self._generate_md_report(prog, prog_findings, severity_breakdown)
        elif format == 'json':
            report = json.dumps({
                "program": prog["name"],
                "generated_at": datetime.now().isoformat(),
                "findings_count": len(prog_findings),
                "severity_breakdown": severity_breakdown,
                "findings": prog_findings,
            }, indent=2, default=str)
        else:
            report = self._generate_txt_report(prog, prog_findings, severity_breakdown)

        # Save report
        os.makedirs(REPORTS_DIR, exist_ok=True)
        ext = 'md' if format == 'md' else ('json' if format == 'json' else 'txt')
        report_filename = f"bounty_{prog['name'].replace(' ', '_').replace('/', '-')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{ext}"
        report_path = os.path.join(REPORTS_DIR, report_filename)

        with open(report_path, 'w') as f:
            f.write(report)

        result["details"]["report_path"] = report_path
        result["vulnerable"] = any(f.get("severity") in ("Critical", "High") for f in prog_findings)

        for f in prog_findings:
            result["findings"].append({
                "type": f.get("type", "Unknown"),
                "severity": f.get("severity", "Info"),
                "description": f.get("description", ""),
            })

        self._print(f"  [+] Report saved: {report_path}", GREEN)
        self._print(f"  [+] Findings: {len(prog_findings)} "
                     f"(Critical: {severity_breakdown.get('Critical', 0)}, "
                     f"High: {severity_breakdown.get('High', 0)}, "
                     f"Medium: {severity_breakdown.get('Medium', 0)}, "
                     f"Low: {severity_breakdown.get('Low', 0)}, "
                     f"Info: {severity_breakdown.get('Info', 0)})", CYAN)

        return result

    def _generate_md_report(self, prog, findings, severity_breakdown):
        """Generate Markdown format report"""
        lines = []
        lines.append(f"# Bug Bounty Report - {prog['name']}")
        lines.append(f"")
        lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Program:** {prog['name']}")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append(f"")
        lines.append(f"## Severity Breakdown")
        lines.append(f"")
        lines.append(f"| Severity | Count |")
        lines.append(f"|----------|-------|")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in severity_breakdown:
                lines.append(f"| {sev} | {severity_breakdown[sev]} |")
        lines.append(f"")

        lines.append(f"## Scope")
        lines.append(f"")
        scope = prog.get("scope", {})
        if scope.get("domains"):
            lines.append(f"### Domains")
            for d in scope["domains"][:30]:
                lines.append(f"- `{d}`")
            lines.append(f"")
        if scope.get("ips"):
            lines.append(f"### IPs")
            for ip in scope["ips"][:20]:
                lines.append(f"- `{ip}`")
            lines.append(f"")

        lines.append(f"## Findings")
        lines.append(f"")

        for i, f in enumerate(findings, 1):
            lines.append(f"### Finding #{i}: {f.get('type', 'Unknown')}")
            lines.append(f"")
            lines.append(f"- **Severity:** {f.get('severity', 'Info')}")
            lines.append(f"- **Target:** {f.get('target', 'Unknown')}")
            lines.append(f"- **Endpoint:** `{f.get('endpoint', 'N/A')}`")
            lines.append(f"- **First Seen:** {f.get('first_seen', 'Unknown')}")
            lines.append(f"- **Last Seen:** {f.get('last_seen', 'Unknown')}")
            lines.append(f"- **Occurrences:** {f.get('occurrence_count', 1)}")
            lines.append(f"- **Status:** {f.get('status', 'new')}")
            lines.append(f"")
            if f.get("description"):
                lines.append(f"**Description:** {f['description']}")
                lines.append(f"")
            if f.get("payload"):
                lines.append(f"**Payload:**")
                lines.append(f"```")
                lines.append(f"{f['payload'][:500]}")
                lines.append(f"```")
                lines.append(f"")
            if f.get("evidence"):
                lines.append(f"**Evidence:**")
                lines.append(f"```")
                lines.append(f"{f['evidence'][:500]}")
                lines.append(f"```")
                lines.append(f"")
            if f.get("remediation"):
                lines.append(f"**Remediation:** {f['remediation']}")
                lines.append(f"")

        lines.append(f"---")
        lines.append(f"*Generated by ZYLON FUSION v5.0.0 Bug Bounty Management Engine*")
        lines.append(f"")

        return "\n".join(lines)

    def _generate_txt_report(self, prog, findings, severity_breakdown):
        """Generate plain text format report"""
        lines = []
        lines.append(f"=" * 70)
        lines.append(f"BUG BOUNTY REPORT - {prog['name']}")
        lines.append(f"=" * 70)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Program: {prog['name']}")
        lines.append(f"Total Findings: {len(findings)}")
        lines.append(f"")
        lines.append(f"SEVERITY BREAKDOWN:")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in severity_breakdown:
                lines.append(f"  {sev}: {severity_breakdown[sev]}")
        lines.append(f"")

        for i, f in enumerate(findings, 1):
            lines.append(f"--- Finding #{i} ---")
            lines.append(f"Type: {f.get('type', 'Unknown')}")
            lines.append(f"Severity: {f.get('severity', 'Info')}")
            lines.append(f"Target: {f.get('target', 'Unknown')}")
            lines.append(f"Endpoint: {f.get('endpoint', 'N/A')}")
            lines.append(f"Description: {f.get('description', 'N/A')}")
            lines.append(f"First Seen: {f.get('first_seen', 'Unknown')}")
            lines.append(f"Status: {f.get('status', 'new')}")
            lines.append(f"")

        lines.append(f"Generated by ZYLON FUSION v5.0.0")
        return "\n".join(lines)

    # ========================================================================
    # SCOPE VALIDATION
    # ========================================================================

    def validate_scope(self, target, program):
        """Validate if a target is within program scope

        Args:
            target: Target domain/IP/URL to validate
            program: Program name or ID

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Scope Validation{RESET}", CYAN)
        self._print(f"  [*] Target: {target}", CYAN)
        self._print(f"  [*] Program: {program}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "target": target,
                "program": program,
                "in_scope": False,
                "scope_type": "",
                "matched_rule": "",
            },
            "scan_type": "validate_scope",
        }

        # Find program
        prog = self._find_program(program)
        if not prog:
            self._print(f"  [!] Program '{program}' not found", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Program '{program}' not found",
            })
            return result

        scope = prog.get("scope", {})
        target_lower = target.lower().rstrip('/')

        # Extract domain from target
        if target_lower.startswith('http'):
            parsed = urlparse(target_lower)
            target_domain = parsed.hostname or target_lower
        else:
            target_domain = target_lower.split('/')[0].split(':')[0]

        # Check exact domain match
        for domain in scope.get("domains", []):
            if target_domain.lower() == domain.lower():
                result["details"]["in_scope"] = True
                result["details"]["scope_type"] = "exact_domain"
                result["details"]["matched_rule"] = domain
                self._print(f"  [+] IN SCOPE: Exact domain match ({domain})", GREEN)
                break

        # Check wildcard match
        if not result["details"]["in_scope"]:
            for wildcard in scope.get("wildcards", []):
                pattern = wildcard.lstrip('*.')
                if target_domain.lower().endswith(pattern.lower()):
                    result["details"]["in_scope"] = True
                    result["details"]["scope_type"] = "wildcard"
                    result["details"]["matched_rule"] = wildcard
                    self._print(f"  [+] IN SCOPE: Wildcard match ({wildcard})", GREEN)
                    break

        # Check IP match
        if not result["details"]["in_scope"]:
            for ip in scope.get("ips", []):
                if target_domain == ip:
                    result["details"]["in_scope"] = True
                    result["details"]["scope_type"] = "ip"
                    result["details"]["matched_rule"] = ip
                    self._print(f"  [+] IN SCOPE: IP match ({ip})", GREEN)
                    break

        # Check exclusions
        if result["details"]["in_scope"]:
            for exclusion in scope.get("exclusions", []):
                excl_pattern = exclusion.lstrip('*.')
                if target_domain.lower().endswith(excl_pattern.lower()) or target_domain.lower() == excl_pattern.lower():
                    result["details"]["in_scope"] = False
                    result["details"]["scope_type"] = "excluded"
                    result["details"]["matched_rule"] = exclusion
                    self._print(f"  [!] EXCLUDED: {exclusion}", RED)
                    break

        if result["details"]["in_scope"]:
            result["findings"].append({
                "type": "scope_validation",
                "severity": "Info",
                "description": f"Target '{target}' is IN SCOPE for '{prog['name']}' "
                              f"(matched: {result['details']['matched_rule']})",
            })
        else:
            result["findings"].append({
                "type": "scope_validation",
                "severity": "Info",
                "description": f"Target '{target}' is OUT OF SCOPE for '{prog['name']}'",
            })
            self._print(f"  [-] OUT OF SCOPE", YELLOW)

        return result

    # ========================================================================
    # SCOPE CHANGE MONITORING
    # ========================================================================

    def monitor_scope_changes(self, program):
        """Monitor scope changes for a program

        Args:
            program: Program name or ID

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Scope Change Monitoring{RESET}", CYAN)
        self._print(f"  [*] Program: {program}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "program": program,
                "changes_detected": False,
                "new_domains": [],
                "removed_domains": [],
                "scope_snapshot": {},
            },
            "scan_type": "scope_monitor",
        }

        prog = self._find_program(program)
        if not prog:
            self._print(f"  [!] Program '{program}' not found", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Program '{program}' not found",
            })
            return result

        # If program has a scope_url, try to re-fetch
        scope_url = prog.get("scope_url", "")
        current_domains = set(prog.get("scope", {}).get("domains", []))
        new_domains = set()

        if scope_url.startswith('http'):
            try:
                resp = self.session.get(scope_url, timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    discovered = regex_cache.findall(
                        r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)',
                        resp.text
                    )
                    new_domains = set(d.lower() for d in discovered[:50])
            except Exception:
                pass

        # Compare
        added = new_domains - current_domains
        removed = current_domains - new_domains

        if added or removed:
            result["details"]["changes_detected"] = True
            result["details"]["new_domains"] = list(added)
            result["details"]["removed_domains"] = list(removed)

            if added:
                self._print(f"  [!] New domains in scope: {list(added)[:10]}", GREEN)
                result["findings"].append({
                    "type": "scope_expansion",
                    "severity": "Info",
                    "description": f"New scope domains: {list(added)[:10]}",
                    "new_domains": list(added),
                })
            if removed:
                self._print(f"  [!] Removed domains from scope: {list(removed)[:10]}", YELLOW)
                result["findings"].append({
                    "type": "scope_reduction",
                    "severity": "Info",
                    "description": f"Removed scope domains: {list(removed)[:10]}",
                    "removed_domains": list(removed),
                })

            # Update scope history
            scope_change = {
                "timestamp": datetime.now().isoformat(),
                "program_id": prog["id"],
                "added": list(added),
                "removed": list(removed),
            }
            self.scope_history.append(scope_change)
            self._save_data()
        else:
            self._print(f"  [-] No scope changes detected", GREEN)

        result["details"]["scope_snapshot"] = {
            "current_domains": list(current_domains),
            "discovered_domains": list(new_domains),
        }

        return result

    # ========================================================================
    # ASSET INVENTORY
    # ========================================================================

    def asset_inventory(self, program):
        """Manage asset inventory for a program

        Args:
            program: Program name or ID

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Asset Inventory{RESET}", CYAN)
        self._print(f"  [*] Program: {program}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "program": program,
                "domains": [],
                "ips": [],
                "urls": [],
                "technologies": [],
                "total_assets": 0,
            },
            "scan_type": "asset_inventory",
        }

        prog = self._find_program(program)
        if not prog:
            self._print(f"  [!] Program '{program}' not found", RED)
            result["findings"].append({
                "type": "error",
                "description": f"Program '{program}' not found",
            })
            return result

        scope = prog.get("scope", {})
        assets = prog.get("assets", [])

        # Collect from scope
        domains = scope.get("domains", [])
        ips = scope.get("ips", [])

        # Try to discover additional assets from each domain
        discovered_urls = []
        for domain in domains[:10]:
            try:
                url = f"https://{domain}"
                resp = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
                if resp.status_code < 400:
                    discovered_urls.append(url)
                    # Extract links from page
                    links = regex_cache.findall(r'href=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                    for link in links[:20]:
                        full_url = urljoin(url, link)
                        if domain in full_url:
                            discovered_urls.append(full_url)
            except Exception:
                pass

        # Deduplicate URLs
        unique_urls = list(set(discovered_urls))

        result["details"]["domains"] = domains
        result["details"]["ips"] = ips
        result["details"]["urls"] = unique_urls
        result["details"]["total_assets"] = len(domains) + len(ips) + len(unique_urls) + len(assets)

        self._print(f"  [+] Domains: {len(domains)}", GREEN)
        self._print(f"  [+] IPs: {len(ips)}", GREEN)
        self._print(f"  [+] URLs discovered: {len(unique_urls)}", GREEN)
        self._print(f"  [+] Total assets: {result['details']['total_assets']}", CYAN)

        return result

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='manage', **kwargs):
        """Main entry point for Bug Bounty Management Engine

        Args:
            target: Target domain/IP/URL or program name
            scan_type: Type of scan/operation
                - 'manage': Program management (list programs)
                - 'add_program': Add a program
                - 'add_finding': Add a finding
                - 'classify': Classify severity
                - 'report': Generate report
                - 'validate': Validate scope
                - 'monitor': Monitor scope changes
                - 'inventory': Asset inventory
                - 'full': Full management cycle
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  BUG BOUNTY MANAGEMENT ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: BBRF + BugBountyTools + Custom{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        scan_map = {
            'manage': lambda: self.list_programs(),
            'add_program': lambda: self.add_program(
                kwargs.get('name', target or 'Unknown'),
                kwargs.get('scope_url', target or '')
            ),
            'add_finding': lambda: self.add_finding(
                kwargs.get('program', target or ''),
                kwargs.get('finding', {})
            ),
            'classify': lambda: {
                "vulnerable": False,
                "findings": [],
                "details": {
                    "severity": self.classify_severity(kwargs.get('finding', {})),
                    "finding": kwargs.get('finding', {}),
                },
                "scan_type": "classify_severity",
            },
            'report': lambda: self.generate_report(
                target or '',
                format=kwargs.get('format', 'md')
            ),
            'validate': lambda: self.validate_scope(
                target or '',
                kwargs.get('program', '')
            ),
            'monitor': lambda: self.monitor_scope_changes(target or ''),
            'inventory': lambda: self.asset_inventory(target or ''),
        }

        if scan_type == 'full':
            return self._run_full(target, **kwargs)

        scan_func = scan_map.get(scan_type)
        if scan_func:
            return scan_func()
        else:
            return {
                "vulnerable": False,
                "findings": [],
                "details": {"error": f"Unknown scan type: {scan_type}"},
                "scan_type": scan_type,
            }

    def _run_full(self, target, **kwargs):
        """Full management cycle"""
        self._print(f"\n{BOLD}{CYAN}  Full Bug Bounty Management Cycle{RESET}", CYAN)

        all_results = {}

        # Phase 1: List programs
        self._print(f"\n{BOLD}  === Phase 1: Program Overview ==={RESET}", CYAN)
        all_results['programs'] = self.list_programs()

        # Phase 2: Validate scope if target given
        if target:
            self._print(f"\n{BOLD}  === Phase 2: Scope Validation ==={RESET}", CYAN)
            for pid, prog in self.programs.items():
                if prog.get("status") == "active":
                    scope_result = self.validate_scope(target, prog["name"])
                    all_results[f'scope_{pid}'] = scope_result

            # Phase 3: Asset inventory for matching programs
            self._print(f"\n{BOLD}  === Phase 3: Asset Inventory ==={RESET}", CYAN)
            for pid, prog in self.programs.items():
                if prog.get("status") == "active":
                    inv_result = self.asset_inventory(prog["name"])
                    all_results[f'inventory_{pid}'] = inv_result

        # Phase 4: Scope change monitoring
        self._print(f"\n{BOLD}  === Phase 4: Scope Monitoring ==={RESET}", CYAN)
        for pid, prog in list(self.programs.items())[:5]:
            if prog.get("scope_url", "").startswith("http"):
                monitor_result = self.monitor_scope_changes(prog["name"])
                all_results[f'monitor_{pid}'] = monitor_result

        # Phase 5: Findings summary
        self._print(f"\n{BOLD}  === Phase 5: Findings Summary ==={RESET}", CYAN)
        severity_counts = {}
        for f in self.findings:
            sev = f.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        all_results['findings_summary'] = {
            "vulnerable": any(sev in ("Critical", "High") for sev in severity_counts),
            "findings": [],
            "details": {
                "total_findings": len(self.findings),
                "severity_breakdown": severity_counts,
            },
            "scan_type": "findings_summary",
        }

        self._print(f"  [*] Total findings across all programs: {len(self.findings)}", CYAN)
        for sev, count in sorted(severity_counts.items()):
            self._print(f"  [*] {sev}: {count}", SEVERITY_LEVELS.get(sev, {}).get("color", CYAN))

        return {
            "vulnerable": any(r.get("vulnerable", False) for r in all_results.values() if isinstance(r, dict)),
            "findings": [],
            "details": all_results,
            "scan_type": "bounty_mgmt_full",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='manage', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = BountyMgmtEngine()
    return engine.run(target=target, scan_type=scan_type, **kwargs)
