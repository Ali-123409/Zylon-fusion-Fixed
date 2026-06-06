#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Git Security Advanced Engine
====================================================
Fused from: GitDorker (https://github.com/david3107/GitDorker)
           + Git-Hound (https://github.com/tillson/git-hound)
           + dvcs-ripper (https://github.com/kost/dvcs-ripper)
           + Custom Zylon Techniques
Capabilities:
  - Git repository exposure detection (.git/HEAD, .git/config)
  - Git directory dumping and source code recovery
  - GitHub dorking for secrets (API keys, tokens, passwords)
  - GitHub Code Search API integration
  - SVN/HG/BZR exposure detection
  - Source code analysis for secrets
  - Commit history analysis
  - Sensitive file detection in repos
  - .env file discovery
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import sys
import json
import time
import hashlib
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS
)

from core.shared_infra import shared_session, regex_cache

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
# GIT EXPOSURE DETECTION PATHS
# ============================================================================

GIT_EXPOSURE_PATHS = [
    ".git/HEAD",
    ".git/config",
    ".git/description",
    ".git/index",
    ".git/COMMIT_EDITMSG",
    ".git/logs/HEAD",
    ".git/logs/refs/heads/master",
    ".git/logs/refs/heads/main",
    ".git/refs/heads/master",
    ".git/refs/heads/main",
    ".git/refs/stash",
    ".git/packed-refs",
    ".git/info/refs",
    ".git/info/exclude",
    ".git/hooks/",
    ".git/objects/",
]

# ============================================================================
# SVN/HG/BZR EXPOSURE PATHS
# ============================================================================

SVN_EXPOSURE_PATHS = [
    ".svn/entries",
    ".svn/wc.db",
    ".svn/prop-base/",
    ".svn/props/",
    ".svn/text-base/",
    ".svn/pristine/",
    ".svn/tmp/",
    ".svn/all-wcprops",
    ".svn/dir-prop-base",
    ".svn/.metadata",
]

HG_EXPOSURE_PATHS = [
    ".hg/store",
    ".hg/hgrc",
    ".hg/00manifest.i",
    ".hg/00changelog.i",
    ".hg/requires",
    ".hg/branch",
    ".hg/tags.cache",
    ".hg/dirstate",
    ".hg/bookmarks",
    ".hg/phaseroots",
]

BZR_EXPOSURE_PATHS = [
    ".bzr/branch-format",
    ".bzr/checkout/",
    ".bzr/repository/",
    ".bzr/branch/",
    ".bzr/branch-lock",
]

# ============================================================================
# GITHUB DORK QUERIES
# ============================================================================

GITHUB_DORKS = [
    # API Keys & Tokens
    '"{domain}" filename:.env',
    '"{domain}" filename:config.json',
    '"{domain}" filename:credentials',
    '"{domain}" filename:.htpasswd',
    '"{domain}" filename:id_rsa',
    '"{domain}" filename:id_dsa',
    '"{domain}" filename:.npmrc',
    '"{domain}" filename:.bash_history',
    '"{domain}" filename:wp-config.php',
    '"{domain}" filename:settings.py',
    '"{domain}" filename:database.yml',
    '"{domain}" filename:application.properties',
    # AWS & Cloud
    '"{domain}" filename:.aws/credentials',
    '"{domain}" AKIA',
    '"{domain}" aws_secret_access_key',
    '"{domain}" filename:service-account.json',
    # Generic secrets
    '"{domain}" password',
    '"{domain}" secret_key',
    '"{domain}" api_key',
    '"{domain}" private_key',
    '"{domain}" token',
    '"{domain}" authorization',
    '"{domain}" BEGIN RSA PRIVATE KEY',
    # Database connections
    '"{domain}" mongodb://',
    '"{domain}" mysql://',
    '"{domain}" postgres://',
    '"{domain}" redis://',
    # Framework-specific
    '"{domain}" filename:Gemfile.lock',
    '"{domain}" filename:composer.json',
    '"{domain}" filename:package.json',
    '"{domain}" filename:Pipfile.lock',
    '"{domain}" filename:requirements.txt',
    '"{domain}" filename:Dockerfile',
    '"{domain}" filename:docker-compose.yml',
]

# ============================================================================
# SECRET DETECTION PATTERNS
# ============================================================================

SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "Critical",
        "description": "AWS Access Key ID detected",
    },
    "AWS Secret Key": {
        "pattern": r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}",
        "severity": "Critical",
        "description": "AWS Secret Access Key detected",
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "High",
        "description": "Google API Key detected",
    },
    "GitHub Token": {
        "pattern": r"gh[ps]_[A-Za-z0-9_]{36,}",
        "severity": "Critical",
        "description": "GitHub Personal Access Token detected",
    },
    "Slack Token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,34}",
        "severity": "High",
        "description": "Slack Token detected",
    },
    "Stripe API Key": {
        "pattern": r"[sr]k_live_[0-9a-zA-Z]{24,}",
        "severity": "Critical",
        "description": "Stripe API Key detected",
    },
    "Private Key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "Critical",
        "description": "Private Key detected",
    },
    "Database URL": {
        "pattern": r"(?i)(mysql|postgres|mongodb|redis)://[^\s'\"<>]+",
        "severity": "High",
        "description": "Database connection string detected",
    },
    "JWT Token": {
        "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "severity": "Medium",
        "description": "JWT Token detected",
    },
    "Generic API Key": {
        "pattern": r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"][A-Za-z0-9]{20,}['\"]",
        "severity": "High",
        "description": "Generic API Key detected",
    },
    "Generic Password": {
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^\s'\"]{6,}['\"]",
        "severity": "High",
        "description": "Password in source code detected",
    },
    "Generic Secret": {
        "pattern": r"(?i)(secret[_-]?key|secret[_-]?token|auth[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9]{20,}['\"]",
        "severity": "High",
        "description": "Secret/Token in source code detected",
    },
    "SendGrid API Key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "High",
        "description": "SendGrid API Key detected",
    },
    "Twilio API Key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "High",
        "description": "Twilio API Key detected",
    },
    "Heroku API Key": {
        "pattern": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        "severity": "Medium",
        "description": "Heroku API Key (UUID format) detected",
    },
    "Environment Variable": {
        "pattern": r"(?i)(DB_PASSWORD|SECRET_KEY|PRIVATE_KEY|AUTH_KEY|ACCESS_TOKEN)\s*=\s*[^\s]+",
        "severity": "High",
        "description": "Sensitive environment variable detected",
    },
}

# ============================================================================
# SENSITIVE FILES IN REPOS
# ============================================================================

SENSITIVE_REPO_FILES = [
    ".env", ".env.production", ".env.staging", ".env.local",
    "config.json", "config.yml", "config.yaml", "config.ini",
    "settings.py", "settings.json", "settings.yml",
    "wp-config.php", "database.yml", "application.properties",
    "application.yml", "appsettings.json", "web.config",
    ".htpasswd", ".htaccess", ".npmrc", ".netrc",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".aws/credentials", ".aws/config",
    "credentials.json", "client_secret.json",
    "service-account.json", "service-account-key.json",
    "docker-compose.yml", "Dockerfile",
    ".gitlab-ci.yml", "Jenkinsfile",
    "terraform.tfvars", "terraform.tfstate",
    "backup.sql", "dump.sql", "database.sql",
    "package.json", "composer.json", "Gemfile",
    "requirements.txt", "Pipfile",
]


# ============================================================================
# GIT SECURITY ADVANCED ENGINE
# ============================================================================

class GitAdvancedEngine:
    """Git Security Advanced Engine - Fused from GitDorker + Git-Hound + dvcs-ripper + Custom Techniques"""

    def __init__(self, timeout=DEFAULT_TIMEOUT, threads=MAX_THREADS, proxy=None):
        self.timeout = timeout
        self.threads = threads
        self.proxy = proxy
        self.session = shared_session
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else 'Mozilla/5.0'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.lock = threading.Lock()
        self.github_token = None

        # Try to load GitHub token from config
        try:
            config_file = os.path.join(os.path.expanduser('~'), '.zylon', 'config.json')
            if os.path.exists(config_file):
                with open(config_file) as f:
                    config = json.load(f)
                    self.github_token = config.get('github_api_key')
        except Exception:
            pass

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    # ========================================================================
    # GIT EXPOSURE DETECTION
    # ========================================================================

    def detect_git_exposure(self, url):
        """Detect .git exposure

        Checks if the target has an exposed .git directory that
        can be accessed over HTTP, potentially leaking source code.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Git Exposure Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        base_url = url if url.startswith('http') else f"https://{url}"
        base_url = base_url.rstrip('/')

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": base_url,
                "exposed_paths": [],
                "git_head_content": None,
                "git_config_content": None,
                "branch_info": None,
            },
            "scan_type": "git_exposure_detection",
        }

        def check_path(path):
            try:
                full_url = f"{base_url}/{path}"
                resp = self.session.get(full_url, timeout=self.timeout, verify=False,
                                       allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    return {
                        "path": path,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                        "content": resp.text[:500],
                    }
            except Exception:
                pass
            return None

        # Check critical git paths
        critical_paths = [".git/HEAD", ".git/config", ".git/index"]
        exposed = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_path, path): path for path in critical_paths}
            for future in as_completed(futures):
                found = future.result()
                if found:
                    exposed.append(found)
                    self._print(f"  [!] EXPOSED: {found['path']} ({found['content_length']} bytes)", RED)

        # Check additional paths if critical ones are exposed
        if exposed:
            additional_paths = [p for p in GIT_EXPOSURE_PATHS if p not in critical_paths]
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(check_path, path): path for path in additional_paths}
                for future in as_completed(futures):
                    found = future.result()
                    if found:
                        exposed.append(found)
                        self._print(f"  [!] EXPOSED: {found['path']} ({found['content_length']} bytes)", YELLOW)

        result["details"]["exposed_paths"] = exposed

        if exposed:
            result["vulnerable"] = True

            # Parse HEAD content
            for item in exposed:
                if item["path"] == ".git/HEAD":
                    result["details"]["git_head_content"] = item["content"].strip()
                    # Extract branch
                    if "ref:" in item["content"]:
                        branch_ref = item["content"].split("ref:")[-1].strip()
                        result["details"]["branch_info"] = branch_ref
                        self._print(f"  [*] Git branch ref: {branch_ref}", CYAN)

                if item["path"] == ".git/config":
                    result["details"]["git_config_content"] = item["content"]
                    # Extract remote URL
                    remote_match = regex_cache.search(r'url\s*=\s*(.+)', item["content"])
                    if remote_match:
                        remote_url = remote_match.group(1).strip()
                        self._print(f"  [!!!] Git remote URL exposed: {remote_url}", RED)
                        result["findings"].append({
                            "type": "git_remote_exposed",
                            "severity": "Critical",
                            "description": f"Git remote URL exposed: {remote_url}. "
                                          f"This reveals the internal repository location.",
                            "remote_url": remote_url,
                        })

            # Check for index file (can be used to dump all files)
            index_exposed = any(item["path"] == ".git/index" for item in exposed)

            result["findings"].append({
                "type": "git_directory_exposed",
                "severity": "Critical",
                "description": f".git directory is exposed! Found {len(exposed)} accessible paths. "
                              f"Full source code may be recoverable via git dumping.",
                "exposed_count": len(exposed),
                "index_exposed": index_exposed,
                "head_content": result["details"]["git_head_content"],
            })
            self._print(f"  [!!!] GIT DIRECTORY EXPOSED! {len(exposed)} paths accessible!", RED)

        else:
            self._print(f"  [-] No git exposure detected", GREEN)

        return result

    # ========================================================================
    # GIT REPO DUMPING
    # ========================================================================

    def dump_git_repo(self, url):
        """Dump exposed git repo

        Attempts to recover source code from an exposed .git directory
        by fetching git objects and reconstructing the repository.

        Args:
            url: Target URL with exposed .git directory

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Git Repository Dumping{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        base_url = url if url.startswith('http') else f"https://{url}"
        base_url = base_url.rstrip('/')

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": base_url,
                "files_recovered": [],
                "commits_found": 0,
                "objects_found": 0,
                "total_size": 0,
            },
            "scan_type": "git_repo_dump",
        }

        # First verify .git is exposed
        try:
            head_resp = self.session.get(f"{base_url}/.git/HEAD", timeout=self.timeout,
                                        verify=False, allow_redirects=False)
            if head_resp.status_code != 200:
                result["findings"].append({
                    "type": "info",
                    "severity": "Info",
                    "description": ".git/HEAD not accessible - cannot dump repository",
                })
                self._print(f"  [-] .git/HEAD not accessible", YELLOW)
                return result
        except Exception as e:
            result["findings"].append({
                "type": "error",
                "description": f"Failed to check .git/HEAD: {str(e)}",
            })
            return result

        result["vulnerable"] = True
        files_recovered = []
        total_size = 0

        # Step 1: Get branch reference
        branch_ref = None
        head_content = head_resp.text.strip()
        if "ref:" in head_content:
            branch_ref = head_content.split("ref:")[-1].strip()
            self._print(f"  [*] Branch ref: {branch_ref}", CYAN)

        # Step 2: Try to get commit hash from refs
        commit_hash = None
        if branch_ref:
            try:
                ref_resp = self.session.get(f"{base_url}/.git/{branch_ref}", timeout=self.timeout,
                                           verify=False, allow_redirects=False)
                if ref_resp.status_code == 200:
                    commit_hash = ref_resp.text.strip()
                    self._print(f"  [*] Latest commit: {commit_hash}", CYAN)
                    files_recovered.append({
                        "path": f".git/{branch_ref}",
                        "type": "ref",
                        "content": commit_hash,
                    })
            except Exception:
                pass

        # Step 3: Try to fetch packed-refs
        try:
            packed_resp = self.session.get(f"{base_url}/.git/packed-refs", timeout=self.timeout,
                                          verify=False, allow_redirects=False)
            if packed_resp.status_code == 200:
                self._print(f"  [*] packed-refs found", CYAN)
                files_recovered.append({
                    "path": ".git/packed-refs",
                    "type": "ref_file",
                    "content": packed_resp.text[:1000],
                })
                # Extract commit hashes from packed-refs
                for line in packed_resp.text.split('\n'):
                    if line and not line.startswith('#') and not line.startswith('^'):
                        parts = line.split()
                        if parts and len(parts[0]) == 40:
                            commit_hash = parts[0]
        except Exception:
            pass

        # Step 4: Try to fetch the commit object
        if commit_hash:
            obj_dir = commit_hash[:2]
            obj_file = commit_hash[2:]
            try:
                obj_resp = self.session.get(
                    f"{base_url}/.git/objects/{obj_dir}/{obj_file}",
                    timeout=self.timeout, verify=False, allow_redirects=False
                )
                if obj_resp.status_code == 200:
                    self._print(f"  [*] Commit object retrieved ({len(obj_resp.content)} bytes)", CYAN)
                    files_recovered.append({
                        "path": f".git/objects/{obj_dir}/{obj_file}",
                        "type": "object",
                        "size": len(obj_resp.content),
                    })
                    total_size += len(obj_resp.content)
                    result["details"]["objects_found"] += 1
            except Exception:
                pass

        # Step 5: Try to access the index file for file listing
        try:
            index_resp = self.session.get(f"{base_url}/.git/index", timeout=self.timeout,
                                         verify=False, allow_redirects=False)
            if index_resp.status_code == 200:
                self._print(f"  [*] Index file retrieved ({len(index_resp.content)} bytes)", CYAN)
                total_size += len(index_resp.content)
                files_recovered.append({
                    "path": ".git/index",
                    "type": "index",
                    "size": len(index_resp.content),
                })
        except Exception:
            pass

        # Step 6: Try common source files directly
        common_source_paths = [
            "index.php", "index.html", "config.php", "wp-config.php",
            "README.md", "composer.json", "package.json",
            ".env", "settings.py", "application.properties",
        ]

        def check_source_file(path):
            try:
                resp = self.session.get(f"{base_url}/{path}", timeout=self.timeout,
                                       verify=False, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    return {
                        "path": path,
                        "type": "source_file",
                        "size": len(resp.content),
                        "content_preview": resp.text[:200],
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_source_file, path): path for path in common_source_paths}
            for future in as_completed(futures):
                found = future.result()
                if found:
                    files_recovered.append(found)
                    total_size += found["size"]
                    self._print(f"  [+] Found: {found['path']} ({found['size']} bytes)", GREEN)

        # Step 7: Try to find .env specifically
        try:
            env_resp = self.session.get(f"{base_url}/.env", timeout=self.timeout,
                                       verify=False, allow_redirects=False)
            if env_resp.status_code == 200 and len(env_resp.content) > 0:
                env_content = env_resp.text
                # Scan for secrets in .env
                secrets_found = self._scan_text_for_secrets(env_content)
                if secrets_found:
                    self._print(f"  [!!!] SECRETS IN .env FILE!", RED)
                    for secret in secrets_found[:5]:
                        self._print(f"    - [{secret['severity']}] {secret['type']}: {secret['match'][:60]}...", RED)

                    result["findings"].extend([{
                        "type": "env_file_secret",
                        "severity": s["severity"],
                        "description": f"Secret found in .env file: {s['type']} - {s['description']}",
                        "secret_type": s["type"],
                        "match_preview": s["match"][:60],
                    } for s in secrets_found[:5]])

                files_recovered.append({
                    "path": ".env",
                    "type": "env_file",
                    "size": len(env_resp.content),
                    "secrets_count": len(secrets_found),
                })
        except Exception:
            pass

        result["details"]["files_recovered"] = files_recovered
        result["details"]["total_size"] = total_size
        result["details"]["commits_found"] = 1 if commit_hash else 0

        if files_recovered:
            result["findings"].append({
                "type": "git_dump_success",
                "severity": "Critical",
                "description": f"Successfully recovered {len(files_recovered)} files from exposed .git "
                              f"directory. Total size: {total_size} bytes. "
                              f"Full source code recovery may be possible using git-dumper or similar tools.",
                "files_count": len(files_recovered),
                "total_size": total_size,
            })
            self._print(f"  [!!!] RECOVERED {len(files_recovered)} files ({total_size} bytes)!", RED)

        return result

    # ========================================================================
    # GITHUB DORK SEARCH
    # ========================================================================

    def github_dork_search(self, query):
        """GitHub dorking for secrets

        Uses GitHub Code Search API to find secrets, API keys,
        and sensitive information related to the target domain.

        Args:
            query: Domain or search query to dork

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  GitHub Dork Search{RESET}", CYAN)
        self._print(f"  [*] Query: {query}", CYAN)

        domain = query.replace('https://', '').replace('http://', '').split('/')[0]

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "domain": domain,
                "queries_run": 0,
                "results_found": [],
                "secrets_found": [],
            },
            "scan_type": "github_dork_search",
        }

        if self.github_token:
            self._print(f"  [+] GitHub API token found - using authenticated search", GREEN)
            self._run_github_api_search(domain, result)
        else:
            self._print(f"  [*] No GitHub API token - using web scraping search", YELLOW)
            self._run_github_web_search(domain, result)

        return result

    def _run_github_api_search(self, domain, result):
        """Run GitHub Code Search API with authentication"""
        headers = {
            'Authorization': f'token {self.github_token}',
            'Accept': 'application/vnd.github.v3+json',
        }

        # Generate dork queries
        queries = [dork.format(domain=domain) for dork in GITHUB_DORKS]

        for query in queries[:15]:  # Limit to avoid rate limiting
            try:
                url = f"https://api.github.com/search/code?q={quote(query)}&per_page=5"
                resp = self.session.get(url, headers=headers, timeout=self.timeout, verify=False)

                result["details"]["queries_run"] += 1

                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get('items', [])

                    for item in items[:3]:
                        repo_name = item.get('repository', {}).get('full_name', 'unknown')
                        file_path = item.get('path', 'unknown')
                        html_url = item.get('html_url', '')

                        result["details"]["results_found"].append({
                            "repo": repo_name,
                            "file": file_path,
                            "url": html_url,
                            "query": query,
                        })

                        self._print(f"  [!] Found: {repo_name}:{file_path}", YELLOW)

                        # Check if the result contains secrets
                        try:
                            raw_url = item.get('html_url', '').replace('github.com', 'raw.githubusercontent.com')
                            raw_url = raw_url.replace('/blob/', '/')
                            raw_resp = self.session.get(raw_url, headers=headers,
                                                       timeout=self.timeout, verify=False)
                            if raw_resp.status_code == 200:
                                secrets = self._scan_text_for_secrets(raw_resp.text)
                                for secret in secrets[:3]:
                                    result["details"]["secrets_found"].append({
                                        "repo": repo_name,
                                        "file": file_path,
                                        "type": secret["type"],
                                        "severity": secret["severity"],
                                        "match": secret["match"][:80],
                                    })
                        except Exception:
                            pass

                elif resp.status_code == 403:
                    self._print(f"  [!] GitHub API rate limited", YELLOW)
                    break

                time.sleep(1)  # Rate limiting

            except Exception as e:
                self._print(f"  [-] Query failed: {str(e)[:50]}", DIM)
                continue

        if result["details"]["secrets_found"]:
            result["vulnerable"] = True
            for secret in result["details"]["secrets_found"][:5]:
                result["findings"].append({
                    "type": "github_secret_exposed",
                    "severity": secret["severity"],
                    "description": f"Secret found in GitHub: {secret['type']} in "
                                  f"{secret['repo']}:{secret['file']}",
                    "repo": secret["repo"],
                    "file": secret["file"],
                    "secret_type": secret["type"],
                    "match_preview": secret["match"][:60],
                })
            self._print(f"  [!!!] {len(result['details']['secrets_found'])} secrets found on GitHub!", RED)

        elif result["details"]["results_found"]:
            result["findings"].append({
                "type": "github_dork_results",
                "severity": "Medium",
                "description": f"Found {len(result['details']['results_found'])} potentially sensitive "
                              f"files on GitHub (manual review recommended)",
                "results_count": len(result["details"]["results_found"]),
            })

    def _run_github_web_search(self, domain, result):
        """Run GitHub web-based search (no API token)"""
        # Use GitHub search with limited queries
        search_queries = [
            f'"{domain}" password',
            f'"{domain}" secret_key',
            f'"{domain}" api_key',
            f'"{domain}" filename:.env',
            f'"{domain}" filename:config',
            f'"{domain}" BEGIN RSA PRIVATE KEY',
            f'"{domain}" AWS',
        ]

        for query in search_queries:
            try:
                search_url = f"https://github.com/search?q={quote(query)}&type=code"
                resp = self.session.get(search_url, timeout=self.timeout, verify=False,
                                       headers={'Accept': 'text/html'})

                result["details"]["queries_run"] += 1

                if resp.status_code == 200:
                    # Simple parsing of results (GitHub returns HTML)
                    # Look for repository references
                    repo_matches = regex_cache.findall(r'href="/([^/]+/[^/]+)/blob/([^"]+)"', resp.text)
                    seen_repos = set()
                    for repo, path in repo_matches[:5]:
                        if repo not in seen_repos:
                            seen_repos.add(repo)
                            result["details"]["results_found"].append({
                                "repo": repo,
                                "file": path,
                                "query": query,
                            })
                            self._print(f"  [?] Potential result: {repo} (query: {query[:40]}...)", YELLOW)

                time.sleep(2)  # Be gentle with GitHub

            except Exception:
                continue

        if result["details"]["results_found"]:
            result["findings"].append({
                "type": "github_dork_results_unverified",
                "severity": "Medium",
                "description": f"Found {len(result['details']['results_found'])} potential results "
                              f"on GitHub (unverified - add GitHub API key for full search)",
                "results_count": len(result["details"]["results_found"]),
            })

    # ========================================================================
    # SVN/HG/BZR EXPOSURE DETECTION
    # ========================================================================

    def detect_svn_exposure(self, url):
        """SVN exposure detection

        Checks if the target has exposed SVN metadata that could
        leak source code or sensitive information.

        Args:
            url: Target URL

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  SVN/HG/BZR Exposure Detection{RESET}", CYAN)
        self._print(f"  [*] Target: {url}", CYAN)

        base_url = url if url.startswith('http') else f"https://{url}"
        base_url = base_url.rstrip('/')

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "url": base_url,
                "svn_exposed": False,
                "hg_exposed": False,
                "bzr_exposed": False,
                "exposed_paths": [],
            },
            "scan_type": "svn_hg_bzr_exposure",
        }

        all_paths = []
        for path in SVN_EXPOSURE_PATHS:
            all_paths.append(("SVN", path))
        for path in HG_EXPOSURE_PATHS:
            all_paths.append(("HG", path))
        for path in BZR_EXPOSURE_PATHS:
            all_paths.append(("BZR", path))

        def check_vcs_path(vcs_type, path):
            try:
                full_url = f"{base_url}/{path}"
                resp = self.session.get(full_url, timeout=self.timeout, verify=False,
                                       allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    return {
                        "vcs_type": vcs_type,
                        "path": path,
                        "status_code": resp.status_code,
                        "content_length": len(resp.content),
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_vcs_path, vcs, path): (vcs, path)
                      for vcs, path in all_paths}
            for future in as_completed(futures):
                found = future.result()
                if found:
                    result["details"]["exposed_paths"].append(found)
                    if found["vcs_type"] == "SVN":
                        result["details"]["svn_exposed"] = True
                    elif found["vcs_type"] == "HG":
                        result["details"]["hg_exposed"] = True
                    elif found["vcs_type"] == "BZR":
                        result["details"]["bzr_exposed"] = True
                    self._print(f"  [!] {found['vcs_type']} EXPOSED: {found['path']}", RED)

        if result["details"]["exposed_paths"]:
            result["vulnerable"] = True

            vcs_types = []
            if result["details"]["svn_exposed"]:
                vcs_types.append("SVN")
            if result["details"]["hg_exposed"]:
                vcs_types.append("Mercurial")
            if result["details"]["bzr_exposed"]:
                vcs_types.append("Bazaar")

            result["findings"].append({
                "type": "vcs_exposure",
                "severity": "Critical",
                "description": f"VCS metadata exposed: {', '.join(vcs_types)}. "
                              f"Found {len(result['details']['exposed_paths'])} accessible paths. "
                              f"Source code may be recoverable using dvcs-ripper or similar tools.",
                "vcs_types": vcs_types,
                "exposed_count": len(result["details"]["exposed_paths"]),
            })

            # SVN-specific: check for wc.db (can contain full repository info)
            svn_wc = [p for p in result["details"]["exposed_paths"]
                      if p["path"] == ".svn/wc.db"]
            if svn_wc:
                result["findings"].append({
                    "type": "svn_wc_db_exposed",
                    "severity": "Critical",
                    "description": "SVN wc.db file is exposed! This SQLite database contains "
                                  "the full working copy state and can be used to recover source code.",
                })

        else:
            self._print(f"  [-] No SVN/HG/BZR exposure detected", GREEN)

        return result

    # ========================================================================
    # REPO SECRET SCANNING
    # ========================================================================

    def scan_repo_secrets(self, repo_url):
        """Scan repo for secrets

        Analyzes a repository URL (GitHub, GitLab, etc.) for
        leaked secrets, API keys, and sensitive information.

        Args:
            repo_url: Repository URL to scan

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}  Repository Secret Scanning{RESET}", CYAN)
        self._print(f"  [*] Target: {repo_url}", CYAN)

        result = {
            "vulnerable": False,
            "findings": [],
            "details": {
                "repo_url": repo_url,
                "files_scanned": 0,
                "secrets_found": [],
            },
            "scan_type": "repo_secret_scan",
        }

        # Determine repo type and fetch files
        if 'github.com' in repo_url:
            self._scan_github_repo(repo_url, result)
        else:
            # Generic: try to fetch common sensitive files
            self._scan_generic_repo(repo_url, result)

        if result["details"]["secrets_found"]:
            result["vulnerable"] = True
            for secret in result["details"]["secrets_found"]:
                result["findings"].append({
                    "type": "repo_secret",
                    "severity": secret["severity"],
                    "description": f"{secret['type']} found in {secret.get('file', 'repository')}: "
                                  f"{secret['description']}",
                    "secret_type": secret["type"],
                    "file": secret.get("file", "unknown"),
                    "match_preview": secret.get("match", "")[:60],
                })

            self._print(f"  [!!!] {len(result['details']['secrets_found'])} secrets found!", RED)
        else:
            self._print(f"  [-] No secrets found", GREEN)

        return result

    def _scan_github_repo(self, repo_url, result):
        """Scan a GitHub repository for secrets"""
        # Parse repo URL
        parts = repo_url.rstrip('/').split('/')
        if len(parts) >= 5:
            owner = parts[-2]
            repo = parts[-1]
        else:
            self._print(f"  [!] Invalid GitHub repo URL", RED)
            return

        # Fetch repository tree
        headers = {}
        if self.github_token:
            headers = {
                'Authorization': f'token {self.github_token}',
                'Accept': 'application/vnd.github.v3+json',
            }

        try:
            tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
            resp = self.session.get(tree_url, headers=headers, timeout=self.timeout, verify=False)

            if resp.status_code == 200:
                data = resp.json()
                tree = data.get('tree', [])

                # Find sensitive files
                for item in tree:
                    if item.get('type') == 'blob':
                        file_path = item.get('path', '')
                        file_lower = file_path.lower()
                        filename = file_lower.split('/')[-1]

                        # Check against sensitive file list
                        if any(sf.lower() == filename or sf.lower() == file_lower
                               for sf in SENSITIVE_REPO_FILES):
                            # Fetch the file content
                            try:
                                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{file_path}"
                                raw_resp = self.session.get(raw_url, headers=headers,
                                                           timeout=self.timeout, verify=False)
                                if raw_resp.status_code == 200:
                                    result["details"]["files_scanned"] += 1
                                    secrets = self._scan_text_for_secrets(raw_resp.text)
                                    for secret in secrets:
                                        result["details"]["secrets_found"].append({
                                            "type": secret["type"],
                                            "severity": secret["severity"],
                                            "description": secret["description"],
                                            "file": file_path,
                                            "match": secret["match"][:80],
                                        })
                                    self._print(f"  [!] Sensitive file: {file_path} "
                                               f"({len(secrets)} secrets)", YELLOW)
                            except Exception:
                                pass

                self._print(f"  [*] Scanned {result['details']['files_scanned']} sensitive files", CYAN)

        except Exception as e:
            self._print(f"  [!] GitHub repo scan failed: {e}", RED)

    def _scan_generic_repo(self, repo_url, result):
        """Scan a generic repository for secrets"""
        base_url = repo_url.rstrip('/')

        # Try fetching common sensitive files
        for sensitive_file in SENSITIVE_REPO_FILES[:20]:
            try:
                file_url = f"{base_url}/{sensitive_file}"
                resp = self.session.get(file_url, timeout=self.timeout, verify=False,
                                       allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    result["details"]["files_scanned"] += 1
                    secrets = self._scan_text_for_secrets(resp.text)
                    for secret in secrets:
                        result["details"]["secrets_found"].append({
                            "type": secret["type"],
                            "severity": secret["severity"],
                            "description": secret["description"],
                            "file": sensitive_file,
                            "match": secret["match"][:80],
                        })
                    if secrets:
                        self._print(f"  [!] Secrets in {sensitive_file}: {len(secrets)} found", RED)
            except Exception:
                continue

    def _scan_text_for_secrets(self, text):
        """Scan text content for secrets using regex patterns"""
        secrets = []
        for secret_name, config in SECRET_PATTERNS.items():
            try:
                matches = regex_cache.findall(config["pattern"], text)
                for match in matches[:3]:  # Limit matches per pattern
                    secrets.append({
                        "type": secret_name,
                        "severity": config["severity"],
                        "description": config["description"],
                        "match": str(match)[:100] if match else "",
                    })
            except re.error:
                continue
        return secrets

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='detect', **kwargs):
        """Main entry point for Git Security Advanced Engine

        Args:
            target: Target URL or domain
            scan_type: Type of scan to run
                - 'detect': Git exposure detection
                - 'dump': Git repository dump
                - 'dork': GitHub dork search
                - 'svn': SVN/HG/BZR exposure detection
                - 'secrets': Repository secret scanning
                - 'full': Full Git security scan
        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"\n{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  GIT SECURITY ADVANCED ENGINE - v5.0.0{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}  Fused from: GitDorker + Git-Hound + dvcs-ripper{RESET}", CYAN)
        self._print(f"{BOLD}{CYAN}═══════════════════════════════════════════════════{RESET}", CYAN)

        url = target if target.startswith('http') else f"https://{target}"

        scan_map = {
            'detect': lambda: self.detect_git_exposure(url),
            'dump': lambda: self.dump_git_repo(url),
            'dork': lambda: self.github_dork_search(target),
            'svn': lambda: self.detect_svn_exposure(url),
            'secrets': lambda: self.scan_repo_secrets(kwargs.get('repo_url', url)),
        }

        if scan_type == 'full':
            all_findings = []
            all_details = {}
            any_vulnerable = False

            tests = [
                ("Git Exposure", lambda: self.detect_git_exposure(url)),
                ("SVN/HG/BZR Exposure", lambda: self.detect_svn_exposure(url)),
                ("GitHub Dork Search", lambda: self.github_dork_search(target)),
                ("Git Repo Dump", lambda: self.dump_git_repo(url)),
            ]

            for test_name, test_func in tests:
                self._print(f"\n  {BOLD}{YELLOW}[Phase] {test_name}{RESET}", YELLOW)
                try:
                    test_result = test_func()
                    if test_result.get('vulnerable'):
                        any_vulnerable = True
                    all_findings.extend(test_result.get('findings', []))
                    all_details[test_name] = test_result.get('details', {})
                except Exception as e:
                    all_details[test_name] = {"error": str(e)}

            return {
                'vulnerable': any_vulnerable,
                'findings': all_findings,
                'details': all_details,
                'scan_type': 'git_full_security',
            }

        scan_func = scan_map.get(scan_type)
        if scan_func:
            return scan_func()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {"error": f"Unknown scan type: {scan_type}"},
            'scan_type': scan_type,
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION (ZYLON FUSION INTEGRATION)
# ============================================================================

def run(target, scan_type='detect', **kwargs):
    """Module-level run function for ZYLON FUSION integration"""
    engine = GitAdvancedEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
