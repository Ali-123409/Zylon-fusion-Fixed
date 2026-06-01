#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Cloud Security Advanced Engine
=====================================================
Fused from: CloudEnum (https://github.com/initstring/cloud_enum)
           + CloudSploit (https://github.com/aquasecurity/cloudsploit)
           + Cloud-Misconfig-Scanner
           + Custom Zylon Cloud Techniques
Capabilities:
  - Multi-cloud resource enumeration (AWS S3, Azure Blob, GCP Storage,
    DigitalOcean Spaces, Firebase Realtime DB)
  - AWS S3 bucket discovery and content listing (permutation + keyword)
  - Azure Blob container enumeration
  - GCP Storage bucket discovery
  - DigitalOcean Spaces enumeration
  - Firebase Realtime Database discovery
  - Cloud metadata extraction (AWS, GCP, Azure, DigitalOcean, Oracle)
  - Cloud misconfiguration detection (public buckets, exposed creds,
    open permissions, CORS misconfigs)
  - API key / credential scanning for cloud services (AWS AKIA, Google AIza,
    Azure tenant, SendGrid, Stripe, etc.)
  - Keyword-based scanning for cloud resources
  - Cloud provider fingerprinting (via headers, DNS, responses)
  - SSRF-to-cloud exploitation chain (metadata + IAM extraction)
Termux Compatible | No Root Required | Python 3.13+
"""

import re
import json
import time
import base64
import hashlib
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    USER_AGENTS, DEFAULT_TIMEOUT, MAX_THREADS, CLOUD_BUCKET_PATTERNS
)

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
# CLOUD METADATA ENDPOINTS (SSRF-to-Cloud)
# ============================================================================

CLOUD_METADATA_ENDPOINTS = {
    "AWS": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        "paths": [
            "iam/security-credentials/",
            "iam/info",
            "hostname",
            "instance-id",
            "instance-type",
            "local-ipv4",
            "public-ipv4",
            "availability-zone",
            "identity-credentials/ec2/security-credentials/ec2-instance",
            "spot/instance-action",
        ],
        "token_url": "http://169.254.169.254/latest/api/token",
        "token_header": "X-aws-ec2-metadata-token",
    },
    "GCE": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "paths": [
            "instance/name",
            "instance/hostname",
            "instance/zone",
            "instance/machine-type",
            "project/attributes/ssh-keys",
            "instance/service-accounts/default/token",
            "instance/service-accounts/default/email",
            "instance/attributes/kube-env",
        ],
    },
    "Azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "paths": [],
    },
    "DigitalOcean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "headers": {},
        "paths": [
            "id",
            "hostname",
            "interfaces/private/0/ipv4/address",
            "public-ipv4",
            "region/nickname",
            "floating_ip/ipv4/ip",
            "tags",
        ],
    },
    "Oracle": {
        "url": "http://169.254.169.254/opc/v1/",
        "headers": {},
        "paths": [
            "instance/",
            "instance/name",
            "instance/shape",
            "instance/metadata/",
        ],
    },
    "Alibaba": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "headers": {},
        "paths": [
            "instance-id",
            "hostname",
            "region-id",
            "ram/security-credentials/",
        ],
    },
}

# ============================================================================
# S3 BUCKET PERMUTATION PATTERNS (from CloudEnum)
# ============================================================================

S3_PERMUTATIONS = [
    "{name}", "{name}-backup", "{name}-data", "{name}-media",
    "{name}-static", "{name}-assets", "{name}-uploads", "{name}-logs",
    "{name}-public", "{name}-private", "{name}-dev", "{name}-prod",
    "{name}-staging", "{name}-test", "{name}-www", "{name}-site",
    "{name}-bucket", "{name}-storage", "{name}-files", "{name}-docs",
    "{name}-db", "{name}-database", "{name}-dump", "{name}-exports",
    "{name}-reports", "{name}-config", "{name}-config-backup",
    "{name}-internal", "{name}-infra", "{name}-deploy",
    "{name}-terraform", "{name}-cloudformation", "{name}-secrets",
    "{name}-credentials", "{name}-keys", "{name}-archive",
    "{name}-tmp", "{name}-temp", "{name}-cache",
]

# Azure Blob container naming patterns
AZURE_BLOB_PATTERNS = [
    "{name}", "{name}-container", "{name}-data", "{name}-backups",
    "{name}-media", "{name}-public", "{name}-private", "{name}-files",
    "{name}-logs", "{name}-storage", "{name}-assets", "{name}-uploads",
    "{name}-dev", "{name}-prod", "{name}-staging", "{name}-test",
    "{name}-config", "{name}-archive", "{name}-export",
]

# GCP Storage bucket patterns
GCP_STORAGE_PATTERNS = [
    "{name}", "{name}-bucket", "{name}-data", "{name}-media",
    "{name}-storage", "{name}-backups", "{name}-public", "{name}-private",
    "{name}-staging", "{name}-prod", "{name}-dev", "{name}-test",
    "{name}-artifacts", "{name}-cloudbuild", "{name}-terraform",
    "{name}.appspot.com",
]

# DigitalOcean Spaces patterns
DO_SPACES_REGIONS = [
    "nyc3", "ams3", "sgp1", "sfo2", "sfo3", "fra1", "syd1",
]
DO_SPACES_PATTERNS = [
    "{name}", "{name}-backup", "{name}-data", "{name}-media",
    "{name}-storage", "{name}-files", "{name}-assets",
]

# ============================================================================
# CLOUD CREDENTIAL REGEX PATTERNS
# ============================================================================

CLOUD_CREDENTIAL_PATTERNS = {
    "AWS Access Key ID": {
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "Critical",
        "description": "AWS IAM Access Key ID found",
    },
    "AWS Secret Access Key": {
        "regex": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[\"'][a-zA-Z0-9/+=]{40}[\"']",
        "severity": "Critical",
        "description": "AWS Secret Access Key found",
    },
    "Google API Key": {
        "regex": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "High",
        "description": "Google Cloud API Key found",
    },
    "Google OAuth Token": {
        "regex": r"ya29\.[0-9A-Za-z_-]+",
        "severity": "High",
        "description": "Google OAuth access token found",
    },
    "Azure Tenant ID": {
        "regex": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "Medium",
        "description": "Possible Azure Tenant/Subscription ID found",
    },
    "Azure Storage Key": {
        "regex": r"(?i)(?:AccountKey|storage[_\-]?key)\s*[=:]\s*[\"'][a-zA-Z0-9+/=]{88}[\"']",
        "severity": "Critical",
        "description": "Azure Storage Account Key found",
    },
    "SendGrid API Key": {
        "regex": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "High",
        "description": "SendGrid API Key found",
    },
    "Stripe API Key": {
        "regex": r"[sr]k_(live|test)_[a-zA-Z0-9]{24,34}",
        "severity": "Critical",
        "description": "Stripe API Key found",
    },
    "Twilio Account SID": {
        "regex": r"AC[a-zA-Z0-9]{32}",
        "severity": "High",
        "description": "Twilio Account SID found",
    },
    "Slack Token": {
        "regex": r"xox[baprs]-[0-9a-zA-Z-]{10,}",
        "severity": "High",
        "description": "Slack token found",
    },
    "Firebase URL": {
        "regex": r"https://[a-zA-Z0-9-]+\.firebaseio\.com",
        "severity": "High",
        "description": "Firebase Realtime Database URL found",
    },
    "Heroku API Key": {
        "regex": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "severity": "Medium",
        "description": "Possible Heroku API Key found",
    },
    "Private Key": {
        "regex": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "Critical",
        "description": "Private key found",
    },
    "JWT Token": {
        "regex": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        "severity": "Medium",
        "description": "JWT token found",
    },
}

# ============================================================================
# CLOUD MISCONFIGURATION SIGNATURES
# ============================================================================

CLOUD_MISCONFIG_CHECKS = {
    "s3_public_read": {
        "description": "S3 bucket allows public read access",
        "severity": "High",
        "check": "GET / returns 200 with ListBucketResult",
    },
    "s3_public_write": {
        "description": "S3 bucket allows public write access",
        "severity": "Critical",
        "check": "PUT to bucket succeeds without auth",
    },
    "s3_acl_exposed": {
        "description": "S3 bucket ACL is publicly accessible",
        "severity": "High",
        "check": "GET /?acl returns 200",
    },
    "s3_policy_exposed": {
        "description": "S3 bucket policy is publicly accessible",
        "severity": "High",
        "check": "GET /?policy returns 200",
    },
    "azure_blob_public": {
        "description": "Azure Blob container allows anonymous access",
        "severity": "High",
        "check": "GET to container returns 200 with listing",
    },
    "gcp_storage_public": {
        "description": "GCP Storage bucket is publicly accessible",
        "severity": "High",
        "check": "GET to bucket returns 200 with listing",
    },
    "firebase_open_rules": {
        "description": "Firebase Realtime DB has open security rules",
        "severity": "Critical",
        "check": "GET to .json returns data without auth",
    },
    "cors_wildcard": {
        "description": "Cloud resource allows CORS from any origin",
        "severity": "Medium",
        "check": "Access-Control-Allow-Origin: * in response",
    },
    "metadata_exposed": {
        "description": "Cloud metadata endpoint accessible via SSRF",
        "severity": "Critical",
        "check": "169.254.169.254 returns instance metadata",
    },
    "env_file_exposed": {
        "description": ".env file containing cloud credentials exposed",
        "severity": "Critical",
        "check": "GET /.env returns 200 with key=value pairs",
    },
}

# ============================================================================
# CLOUD PROVIDER FINGERPRINT SIGNATURES
# ============================================================================

CLOUD_PROVIDER_FINGERPRINTS = {
    "AWS": {
        "headers": ["x-amz-request-id", "x-amz-id-2", "x-amz-bucket-region",
                     "x-amz-cf-id", "x-amz-version-id"],
        "cookies": ["aws-waf-token"],
        "body_patterns": ["<Code>AccessDenied</Code>", "aws", "s3.amazonaws.com",
                          "cloudfront.net", "<ListBucketResult"],
        "dns_patterns": ["awsdns", "amazonaws.com"],
    },
    "GCP": {
        "headers": ["x-goog-request-id", "x-goog-storage-class",
                     "x-goog-metageneration", "x-guploader-uploadid"],
        "cookies": ["GCP_IAAP"],
        "body_patterns": ["storage.googleapis.com", "cloud.google.com",
                          "firebaseapp.com", "<ListBucketResult"],
        "dns_patterns": ["google", "googleapis.com"],
    },
    "Azure": {
        "headers": ["x-ms-request-id", "x-ms-version", "x-ms-blob-type",
                     "x-ms-lease-status", "server: Windows-Azure-Blob"],
        "cookies": ["AppServiceAuthSession"],
        "body_patterns": ["blob.core.windows.net", "azurewebsites.net",
                          "azure.com", "<EnumerationResults"],
        "dns_patterns": ["azure", "windows.net"],
    },
    "DigitalOcean": {
        "headers": ["x-do-request-id"],
        "cookies": [],
        "body_patterns": ["digitaloceanspaces.com", "digitalocean.com"],
        "dns_patterns": ["digitalocean"],
    },
    "Firebase": {
        "headers": [],
        "cookies": [],
        "body_patterns": ["firebaseio.com", "firebaseapp.com",
                          "firebase.google.com"],
        "dns_patterns": ["firebase"],
    },
}


class CloudAdvancedEngine:
    """Cloud Security Advanced Engine - Fused from CloudEnum + CloudSploit + Cloud-Misconfig-Scanner

    Provides comprehensive cloud security assessment including:
    - Multi-cloud resource enumeration (AWS S3, Azure Blob, GCP Storage, DO Spaces, Firebase)
    - Cloud metadata extraction via SSRF
    - Cloud credential scanning
    - Misconfiguration detection
    - Provider fingerprinting
    """

    def __init__(self, target=None, threads=MAX_THREADS, timeout=DEFAULT_TIMEOUT, proxy=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': USER_AGENTS[0] if USER_AGENTS else
                'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

        # Results storage
        self.findings = []
        self.s3_buckets = []
        self.azure_blobs = []
        self.gcp_buckets = []
        self.do_spaces = []
        self.firebase_dbs = []
        self.metadata_extracted = {}
        self.credentials_found = []
        self.misconfigs_found = []
        self.provider_fingerprint = {}

    def _print(self, msg, color=CYAN):
        """Thread-safe colored print"""
        with self.lock:
            print(f"{color}{msg}{RESET}")

    def _send_request(self, url, method="GET", headers=None, data=None, timeout=None):
        """Send HTTP request with error handling"""
        try:
            t = timeout or self.timeout
            if method == "GET":
                resp = self.session.get(url, headers=headers, timeout=t, allow_redirects=True)
            elif method == "PUT":
                resp = self.session.put(url, headers=headers, data=data, timeout=t)
            elif method == "POST":
                resp = self.session.post(url, headers=headers, data=data, timeout=t)
            else:
                resp = self.session.request(method, url, headers=headers, data=data, timeout=t)
            return resp
        except Exception:
            return None

    # ========================================================================
    # AWS S3 BUCKET DISCOVERY
    # ========================================================================

    def enum_s3_buckets(self, keyword):
        """S3 bucket discovery via permutation scanning

        Args:
            keyword: Base name for bucket name permutations

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Enumerating AWS S3 buckets for keyword: {keyword}", CYAN)
        findings = []
        buckets_found = []
        total_tested = 0

        # Generate bucket name permutations
        bucket_names = [p.format(name=keyword) for p in S3_PERMUTATIONS]
        # Add common variations
        bucket_names.extend([
            keyword.replace("-", ""),
            keyword.replace(".", "-"),
            keyword.replace(".", ""),
            f"{keyword}-cdn",
            f"{keyword}-uploads",
            f"{keyword}-backups",
            f"{keyword}-sql",
            f"{keyword}-elastic",
        ])
        # Deduplicate
        bucket_names = list(dict.fromkeys(bucket_names))
        total_tested = len(bucket_names)

        def check_bucket(name):
            url = f"https://{name}.s3.amazonaws.com/"
            try:
                resp = self._send_request(url)
                if resp is None:
                    return None
                if resp.status_code == 200:
                    # Public bucket - list contents
                    contents = []
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(resp.text)
                        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
                        for key in root.findall('.//s3:Key', ns):
                            contents.append(key.text)
                    except Exception:
                        pass

                    bucket_info = {
                        "name": name,
                        "url": url,
                        "status": "public_readable",
                        "contents": contents[:30],
                        "content_count": len(contents),
                    }
                    buckets_found.append(bucket_info)
                    findings.append({
                        "type": "public_s3_bucket",
                        "severity": "High",
                        "bucket": name,
                        "url": url,
                        "content_count": len(contents),
                        "description": f"Public S3 bucket found: {name} ({len(contents)} objects)",
                    })
                    self._print(f"  [+] PUBLIC S3 bucket: {name} ({len(contents)} objects)", GREEN)

                    # Check ACL exposure
                    acl_resp = self._send_request(f"{url}?acl")
                    if acl_resp and acl_resp.status_code == 200:
                        findings.append({
                            "type": "s3_acl_exposed",
                            "severity": "High",
                            "bucket": name,
                            "description": f"S3 bucket ACL is publicly accessible: {name}",
                        })
                        self._print(f"    [!] ACL exposed for: {name}", RED)

                    # Check policy exposure
                    policy_resp = self._send_request(f"{url}?policy")
                    if policy_resp and policy_resp.status_code == 200:
                        findings.append({
                            "type": "s3_policy_exposed",
                            "severity": "High",
                            "bucket": name,
                            "description": f"S3 bucket policy is publicly accessible: {name}",
                        })

                    return bucket_info

                elif resp.status_code == 403:
                    # Bucket exists but access denied
                    bucket_info = {
                        "name": name,
                        "url": url,
                        "status": "exists_but_denied",
                    }
                    buckets_found.append(bucket_info)
                    findings.append({
                        "type": "existing_s3_bucket",
                        "severity": "Medium",
                        "bucket": name,
                        "description": f"Existing S3 bucket (access denied): {name}",
                    })
                    self._print(f"  [*] Existing S3 bucket (403): {name}", YELLOW)
                    return bucket_info

                # 404 = does not exist
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_bucket, bn): bn for bn in bucket_names}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        self.s3_buckets.extend(buckets_found)
        self._print(f"  [*] Tested {total_tested} bucket names, found {len(buckets_found)}", CYAN)

        return {
            "vulnerable": any(f["severity"] == "High" for f in findings),
            "findings": findings,
            "details": {
                "keyword": keyword,
                "buckets_found": buckets_found,
                "total_tested": total_tested,
                "public_count": len([b for b in buckets_found if b.get("status") == "public_readable"]),
                "denied_count": len([b for b in buckets_found if b.get("status") == "exists_but_denied"]),
            },
            "scan_type": "cloud_s3_enum",
        }

    # ========================================================================
    # AZURE BLOB ENUMERATION
    # ========================================================================

    def enum_azure_blobs(self, keyword):
        """Azure Blob container enumeration via permutation scanning

        Args:
            keyword: Base name for container name permutations

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Enumerating Azure Blob containers for keyword: {keyword}", CYAN)
        findings = []
        containers_found = []
        total_tested = 0

        # Azure requires lowercase, 3-63 chars, alphanumeric + hyphens
        clean_keyword = re.sub(r'[^a-z0-9-]', '-', keyword.lower()).strip('-')
        if len(clean_keyword) < 3:
            clean_keyword = clean_keyword.ljust(3, '0')

        container_names = [p.format(name=clean_keyword) for p in AZURE_BLOB_PATTERNS]
        # Additional variations
        container_names.extend([
            clean_keyword,
            f"{clean_keyword}-container",
            f"{clean_keyword}backup",
            f"{clean_keyword}data",
        ])
        container_names = list(dict.fromkeys(container_names))
        total_tested = len(container_names)

        def check_azure_container(name):
            # Azure Blob Storage account pattern
            url = f"https://{name}.blob.core.windows.net/"
            try:
                resp = self._send_request(url)
                if resp is None:
                    return None

                if resp.status_code == 200:
                    # Container is publicly accessible
                    contents = []
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(resp.text)
                        for blob in root.findall('.//{http://schemas.microsoft.com/storage/2010-07-28}Name'):
                            contents.append(blob.text)
                    except Exception:
                        pass

                    container_info = {
                        "name": name,
                        "url": url,
                        "status": "public_readable",
                        "contents": contents[:30],
                        "content_count": len(contents),
                    }
                    containers_found.append(container_info)
                    findings.append({
                        "type": "public_azure_blob",
                        "severity": "High",
                        "container": name,
                        "url": url,
                        "content_count": len(contents),
                        "description": f"Public Azure Blob container: {name} ({len(contents)} blobs)",
                    })
                    self._print(f"  [+] PUBLIC Azure Blob: {name} ({len(contents)} blobs)", GREEN)
                    return container_info

                elif resp.status_code == 403:
                    # Account exists but access denied
                    container_info = {
                        "name": name,
                        "url": url,
                        "status": "exists_but_denied",
                    }
                    containers_found.append(container_info)
                    findings.append({
                        "type": "existing_azure_blob",
                        "severity": "Medium",
                        "container": name,
                        "description": f"Existing Azure Blob (access denied): {name}",
                    })
                    self._print(f"  [*] Existing Azure Blob (403): {name}", YELLOW)
                    return container_info

            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_azure_container, cn): cn for cn in container_names}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        self.azure_blobs.extend(containers_found)
        self._print(f"  [*] Tested {total_tested} container names, found {len(containers_found)}", CYAN)

        return {
            "vulnerable": any(f["severity"] == "High" for f in findings),
            "findings": findings,
            "details": {
                "keyword": keyword,
                "containers_found": containers_found,
                "total_tested": total_tested,
                "public_count": len([c for c in containers_found if c.get("status") == "public_readable"]),
                "denied_count": len([c for c in containers_found if c.get("status") == "exists_but_denied"]),
            },
            "scan_type": "cloud_azure_blob_enum",
        }

    # ========================================================================
    # GCP STORAGE DISCOVERY
    # ========================================================================

    def enum_gcp_storage(self, keyword):
        """GCP Storage bucket discovery via API and permutation

        Args:
            keyword: Base name for bucket name permutations

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Enumerating GCP Storage buckets for keyword: {keyword}", CYAN)
        findings = []
        buckets_found = []
        total_tested = 0

        clean_keyword = keyword.lower().replace(".", "-").replace("_", "-")

        bucket_names = [p.format(name=clean_keyword) for p in GCP_STORAGE_PATTERNS]
        bucket_names.extend([
            clean_keyword,
            f"{clean_keyword}-data",
            f"{clean_keyword}-media",
            f"{clean_keyword}.appspot.com",
            f"artifacts.{clean_keyword}.appspot.com",
            f"staging.{clean_keyword}.appspot.com",
        ])
        bucket_names = list(dict.fromkeys(bucket_names))
        total_tested = len(bucket_names)

        def check_gcp_bucket(name):
            url = f"https://storage.googleapis.com/{name}/"
            try:
                resp = self._send_request(url)
                if resp is None:
                    return None

                if resp.status_code == 200:
                    contents = []
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(resp.text)
                        for key in root.findall('.//{http://doc.google-storage.com/}Key'):
                            contents.append(key.text)
                        # Also try alternate namespace
                        for key in root.findall('.//Key'):
                            if key.text and key.text not in contents:
                                contents.append(key.text)
                    except Exception:
                        pass

                    bucket_info = {
                        "name": name,
                        "url": url,
                        "status": "public_readable",
                        "contents": contents[:30],
                        "content_count": len(contents),
                    }
                    buckets_found.append(bucket_info)
                    findings.append({
                        "type": "public_gcp_bucket",
                        "severity": "High",
                        "bucket": name,
                        "url": url,
                        "content_count": len(contents),
                        "description": f"Public GCP Storage bucket: {name} ({len(contents)} objects)",
                    })
                    self._print(f"  [+] PUBLIC GCP Storage: {name} ({len(contents)} objects)", GREEN)
                    return bucket_info

                elif resp.status_code == 403:
                    bucket_info = {
                        "name": name,
                        "url": url,
                        "status": "exists_but_denied",
                    }
                    buckets_found.append(bucket_info)
                    findings.append({
                        "type": "existing_gcp_bucket",
                        "severity": "Medium",
                        "bucket": name,
                        "description": f"Existing GCP Storage (access denied): {name}",
                    })
                    self._print(f"  [*] Existing GCP Storage (403): {name}", YELLOW)
                    return bucket_info

            except Exception:
                pass
            return None

        # Also try the GCP Storage API listing
        try:
            api_url = f"https://storage.googleapis.com/storage/v1/b?project={keyword}"
            resp = self._send_request(api_url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for b in data.get("items", []):
                        bname = b.get("name", "")
                        if bname:
                            bucket_info = {
                                "name": bname,
                                "url": f"https://storage.googleapis.com/{bname}/",
                                "status": "discovered_via_api",
                            }
                            buckets_found.append(bucket_info)
                            findings.append({
                                "type": "gcp_bucket_api",
                                "severity": "Medium",
                                "bucket": bname,
                                "description": f"GCP Storage bucket found via API: {bname}",
                            })
                            self._print(f"  [+] GCP Storage (API): {bname}", GREEN)
                except Exception:
                    pass
        except Exception:
            pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_gcp_bucket, bn): bn for bn in bucket_names}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        self.gcp_buckets.extend(buckets_found)
        self._print(f"  [*] Tested {total_tested} bucket names, found {len(buckets_found)}", CYAN)

        return {
            "vulnerable": any(f["severity"] == "High" for f in findings),
            "findings": findings,
            "details": {
                "keyword": keyword,
                "buckets_found": buckets_found,
                "total_tested": total_tested,
                "public_count": len([b for b in buckets_found if b.get("status") == "public_readable"]),
                "denied_count": len([b for b in buckets_found if b.get("status") == "exists_but_denied"]),
            },
            "scan_type": "cloud_gcp_storage_enum",
        }

    # ========================================================================
    # CHECK PUBLIC ACCESS
    # ========================================================================

    def check_public_access(self, bucket_url):
        """Check public access to a cloud storage bucket/URL

        Tests multiple access methods:
        - Direct GET (read)
        - ACL query (?acl)
        - Policy query (?policy)
        - CORS preflight
        - Write test (safe method only)

        Args:
            bucket_url: URL of the cloud storage bucket

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Checking public access for: {bucket_url}", CYAN)
        findings = []
        access_results = {}

        # Normalize URL
        bucket_url = bucket_url.rstrip('/')

        # 1. Direct read access
        resp = self._send_request(f"{bucket_url}/")
        if resp and resp.status_code == 200:
            access_results["read"] = True
            findings.append({
                "type": "public_read_access",
                "severity": "High",
                "url": bucket_url,
                "description": "Bucket allows public read access",
            })
            self._print(f"  [!] PUBLIC READ access: {bucket_url}", RED)

            # Try to determine provider from response
            provider = self._fingerprint_from_response(resp)
            if provider:
                access_results["provider"] = provider
        else:
            access_results["read"] = False

        # 2. ACL access
        resp_acl = self._send_request(f"{bucket_url}/?acl")
        if resp_acl and resp_acl.status_code == 200:
            access_results["acl"] = True
            findings.append({
                "type": "public_acl_access",
                "severity": "High",
                "url": f"{bucket_url}/?acl",
                "description": "Bucket ACL is publicly accessible",
            })
            self._print(f"  [!] ACL accessible: {bucket_url}/?acl", RED)

        # 3. Policy access
        resp_policy = self._send_request(f"{bucket_url}/?policy")
        if resp_policy and resp_policy.status_code == 200:
            access_results["policy"] = True
            findings.append({
                "type": "public_policy_access",
                "severity": "High",
                "url": f"{bucket_url}/?policy",
                "description": "Bucket policy is publicly accessible",
            })
            self._print(f"  [!] Policy accessible: {bucket_url}/?policy", RED)

        # 4. CORS check
        cors_headers = {
            "Origin": "https://evil.com",
        }
        resp_cors = self._send_request(f"{bucket_url}/", headers=cors_headers)
        if resp_cors:
            acao = resp_cors.headers.get("Access-Control-Allow-Origin", "")
            if acao in ("*", "https://evil.com"):
                access_results["cors_wildcard"] = True
                findings.append({
                    "type": "cors_wildcard",
                    "severity": "Medium",
                    "url": bucket_url,
                    "acao": acao,
                    "description": f"Bucket allows CORS from: {acao}",
                })
                self._print(f"  [!] CORS wildcard: {acao}", YELLOW)

        # 5. Versioning check
        resp_ver = self._send_request(f"{bucket_url}/?versioning")
        if resp_ver and resp_ver.status_code == 200:
            access_results["versioning_exposed"] = True
            findings.append({
                "type": "versioning_exposed",
                "severity": "Low",
                "url": f"{bucket_url}/?versioning",
                "description": "Bucket versioning info is accessible",
            })

        # 6. Logging check
        resp_log = self._send_request(f"{bucket_url}/?logging")
        if resp_log and resp_log.status_code == 200:
            access_results["logging_exposed"] = True
            findings.append({
                "type": "logging_exposed",
                "severity": "Low",
                "url": f"{bucket_url}/?logging",
                "description": "Bucket logging config is accessible",
            })

        self._print(f"  [*] Public access check complete: {len(findings)} issues", CYAN)

        return {
            "vulnerable": any(f["severity"] in ("High", "Critical") for f in findings),
            "findings": findings,
            "details": access_results,
            "scan_type": "cloud_public_access_check",
        }

    # ========================================================================
    # CLOUD METADATA EXTRACTION
    # ========================================================================

    def extract_metadata(self, target):
        """Cloud metadata extraction via SSRF chain

        Attempts to extract cloud instance metadata from the target
        by testing SSRF payloads against known metadata endpoints.

        Args:
            target: Target URL to test for SSRF metadata access

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Extracting cloud metadata from: {target}", CYAN)
        findings = []
        metadata_results = {
            "cloud_provider": None,
            "metadata_extracted": {},
            "credentials_found": [],
        }

        # Parse target URL
        parsed = urlparse(target if '://' in target else f"https://{target}")
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Test each cloud provider's metadata endpoint
        for provider, config in CLOUD_METADATA_ENDPOINTS.items():
            meta_url = config["url"]
            headers = config.get("headers", {})

            # Method 1: Direct access (works if running on cloud instance)
            try:
                resp = self._send_request(meta_url, headers=headers, timeout=5)
                if resp and resp.status_code == 200 and len(resp.text) > 10:
                    metadata_results["cloud_provider"] = provider
                    metadata_results["metadata_extracted"]["root"] = resp.text[:500]
                    findings.append({
                        "type": "cloud_metadata_direct",
                        "severity": "Critical",
                        "provider": provider,
                        "description": f"Direct access to {provider} metadata endpoint",
                    })
                    self._print(f"  [!!!] DIRECT {provider} metadata access!", RED)

                    # Extract sub-paths
                    for path in config.get("paths", []):
                        try:
                            path_resp = self._send_request(meta_url + path, headers=headers)
                            if path_resp and path_resp.status_code == 200:
                                metadata_results["metadata_extracted"][path] = path_resp.text[:500]

                                # Check for IAM credentials
                                if "AccessKeyId" in path_resp.text or "SecretAccessKey" in path_resp.text:
                                    try:
                                        creds = path_resp.json()
                                        metadata_results["credentials_found"].append({
                                            "provider": provider,
                                            "access_key_id": creds.get("AccessKeyId", "")[:10] + "...",
                                            "secret_access_key": "(found, redacted)",
                                            "token": bool(creds.get("Token")),
                                        })
                                        findings.append({
                                            "type": "cloud_iam_credentials",
                                            "severity": "Critical",
                                            "provider": provider,
                                            "path": path,
                                            "description": f"IAM credentials extracted from {provider} metadata!",
                                        })
                                        self._print(f"  [!!!] IAM CREDS EXTRACTED from {provider}!", RED)
                                    except Exception:
                                        pass

                                self._print(f"  [+] {provider} metadata: {path}", GREEN)
                        except Exception:
                            pass
                    break  # Found provider, stop checking others
            except Exception:
                pass

            # Method 2: SSRF via common parameters
            ssrf_params = ["url", "uri", "path", "dest", "redirect", "link",
                           "site", "reference", "return", "next", "target",
                           "rurl", "img", "load", "src", "callback", "fetch",
                           "data", "input", "file", "page", "proxy"]
            meta_encoded = quote(meta_url, safe='')

            for param in ssrf_params:
                test_urls = [
                    f"{base_url}/?{param}={meta_encoded}",
                    f"{base_url}/?{param}={meta_url}",
                ]
                for test_url in test_urls:
                    try:
                        resp = self._send_request(test_url, headers=headers, timeout=5)
                        if resp and resp.status_code == 200:
                            # Check if response contains metadata content
                            if any(indicator in resp.text for indicator in
                                   ["ami-id", "instance-id", "hostname", "local-ipv4",
                                    "availability-zone", "instance-type", "project-id"]):
                                metadata_results["cloud_provider"] = provider
                                metadata_results["metadata_extracted"][f"ssrf_{param}"] = resp.text[:500]
                                findings.append({
                                    "type": "cloud_metadata_ssrf",
                                    "severity": "Critical",
                                    "provider": provider,
                                    "parameter": param,
                                    "url": test_url,
                                    "description": f"SSRF to {provider} metadata via param '{param}'",
                                })
                                self._print(f"  [!!!] SSRF to {provider} metadata via '{param}'!", RED)
                                break
                    except Exception:
                        pass
                if metadata_results["cloud_provider"]:
                    break
            if metadata_results["cloud_provider"]:
                break

            # Method 3: AWS IMDSv2 token-based access
            if provider == "AWS" and "token_url" in config:
                try:
                    token_resp = self._send_request(
                        config["token_url"],
                        method="PUT",
                        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
                    )
                    if token_resp and token_resp.status_code == 200:
                        token = token_resp.text
                        token_header = {config["token_header"]: token}
                        meta_resp = self._send_request(meta_url, headers={**headers, **token_header})
                        if meta_resp and meta_resp.status_code == 200:
                            metadata_results["cloud_provider"] = provider
                            metadata_results["metadata_extracted"]["imdsv2"] = meta_resp.text[:500]
                            findings.append({
                                "type": "cloud_metadata_imdsv2",
                                "severity": "Critical",
                                "provider": provider,
                                "description": f"AWS IMDSv2 metadata accessed with token",
                            })
                            self._print(f"  [!!!] AWS IMDSv2 metadata accessed!", RED)
                except Exception:
                    pass

        self.metadata_extracted.update(metadata_results)
        self._print(f"  [*] Metadata extraction complete: provider={metadata_results.get('cloud_provider', 'none')}", CYAN)

        return {
            "vulnerable": any(f["severity"] == "Critical" for f in findings),
            "findings": findings,
            "details": metadata_results,
            "scan_type": "cloud_metadata_extraction",
        }

    # ========================================================================
    # CREDENTIAL SCANNING
    # ========================================================================

    def scan_credentials(self, target):
        """Scan for exposed cloud credentials in target responses

        Fetches the target and scans for cloud API keys, tokens, and secrets
        using regex pattern matching.

        Args:
            target: Target URL to scan for exposed credentials

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Scanning for exposed cloud credentials on: {target}", CYAN)
        findings = []
        credentials_found = []

        # Normalize URL
        url = target if '://' in target else f"https://{target}"

        # Collect content from multiple pages
        pages_to_scan = [url]
        paths_to_check = ["/", "/.env", "/.env.local", "/.env.production",
                          "/.git/config", "/config.json", "/config.yml",
                          "/appsettings.json", "/credentials.json",
                          "/service-account.json", "/.aws/credentials"]

        for path in paths_to_check:
            test_url = f"{url.rstrip('/')}{path}"
            resp = self._send_request(test_url, timeout=8)
            if resp and resp.status_code == 200 and len(resp.text) > 10:
                content = resp.text
                # Also check headers
                content += "\n" + "\n".join(f"{k}: {v}" for k, v in resp.headers.items())

                for cred_name, cred_config in CLOUD_CREDENTIAL_PATTERNS.items():
                    try:
                        matches = re.findall(cred_config["regex"], content)
                        if matches:
                            # Deduplicate
                            unique_matches = list(set(matches))[:5]
                            for match in unique_matches:
                                match_str = str(match)[:60]  # Truncate for safety
                                cred_finding = {
                                    "type": "cloud_credential",
                                    "severity": cred_config["severity"],
                                    "credential_type": cred_name,
                                    "match": match_str,
                                    "url": test_url,
                                    "description": cred_config["description"],
                                }
                                credentials_found.append(cred_finding)
                                findings.append(cred_finding)
                                color = RED if cred_config["severity"] == "Critical" else YELLOW
                                self._print(f"  [!] {cred_config['severity']}: {cred_name} at {path}", color)
                    except Exception:
                        pass

                # Check for .env key-value pairs
                if path.startswith("/.env"):
                    env_pattern = r"(?i)(AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL|SECRET_KEY|API_KEY|PRIVATE_KEY|TOKEN)\s*[=:]\s*[\"']?([^\s\"']+)"
                    env_matches = re.findall(env_pattern, content)
                    for key, value in env_matches:
                        cred_finding = {
                            "type": "env_credential",
                            "severity": "Critical",
                            "credential_type": key,
                            "match": f"{key}=***",
                            "url": test_url,
                            "description": f"Exposed .env credential: {key}",
                        }
                        credentials_found.append(cred_finding)
                        findings.append(cred_finding)
                        self._print(f"  [!!!] .env credential: {key}=***", RED)

        self.credentials_found.extend(credentials_found)
        self._print(f"  [*] Credential scan complete: {len(credentials_found)} found", CYAN)

        return {
            "vulnerable": any(f["severity"] in ("Critical", "High") for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "credentials_found": credentials_found,
                "pages_scanned": len(paths_to_check),
                "total_creds": len(credentials_found),
            },
            "scan_type": "cloud_credential_scan",
        }

    # ========================================================================
    # MISCONFIGURATION DETECTION
    # ========================================================================

    def detect_misconfigs(self, target):
        """Detect cloud misconfigurations

        Checks for:
        - Public bucket access
        - Exposed credentials
        - Open permissions
        - CORS misconfigurations
        - Missing security headers
        - Exposed cloud-specific files
        - Firebase open rules
        - DigitalOcean Spaces exposure

        Args:
            target: Target URL/domain to scan

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Detecting cloud misconfigurations for: {target}", CYAN)
        findings = []
        misconfigs_found = []

        url = target if '://' in target else f"https://{target}"
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_name = domain.split('.')[0]

        # 1. Check for exposed .env file
        resp = self._send_request(f"{url}/.env")
        if resp and resp.status_code == 200 and any(
            kw in resp.text.lower() for kw in ["key=", "secret=", "password=", "token="]
        ):
            misconfigs_found.append({
                "type": "env_file_exposed",
                "severity": "Critical",
                "url": f"{url}/.env",
                "description": ".env file containing secrets is publicly accessible",
            })
            findings.append({
                "type": "env_file_exposed",
                "severity": "Critical",
                "description": ".env file with secrets exposed",
            })
            self._print(f"  [!!!] .env file exposed!", RED)

        # 2. Check for exposed .aws/credentials
        resp = self._send_request(f"{url}/.aws/credentials")
        if resp and resp.status_code == 200 and "aws_access_key_id" in resp.text.lower():
            misconfigs_found.append({
                "type": "aws_credentials_exposed",
                "severity": "Critical",
                "url": f"{url}/.aws/credentials",
                "description": "AWS credentials file publicly accessible",
            })
            findings.append({
                "type": "aws_credentials_exposed",
                "severity": "Critical",
                "description": "AWS credentials file exposed",
            })
            self._print(f"  [!!!] AWS credentials file exposed!", RED)

        # 3. Check S3 bucket public access
        s3_url = f"https://{base_name}.s3.amazonaws.com/"
        resp = self._send_request(s3_url)
        if resp and resp.status_code == 200:
            misconfigs_found.append({
                "type": "public_s3_bucket",
                "severity": "High",
                "url": s3_url,
                "description": "S3 bucket with public read access",
            })
            findings.append({
                "type": "public_s3_bucket",
                "severity": "High",
                "description": f"Public S3 bucket: {base_name}",
            })
            self._print(f"  [!] Public S3 bucket: {base_name}", RED)

        # 4. Check Azure Blob public access
        azure_url = f"https://{base_name}.blob.core.windows.net/"
        resp = self._send_request(azure_url)
        if resp and resp.status_code == 200:
            misconfigs_found.append({
                "type": "public_azure_blob",
                "severity": "High",
                "url": azure_url,
                "description": "Azure Blob container with public access",
            })
            findings.append({
                "type": "public_azure_blob",
                "severity": "High",
                "description": f"Public Azure Blob: {base_name}",
            })
            self._print(f"  [!] Public Azure Blob: {base_name}", RED)

        # 5. Check GCP Storage public access
        gcp_url = f"https://storage.googleapis.com/{base_name}/"
        resp = self._send_request(gcp_url)
        if resp and resp.status_code == 200:
            misconfigs_found.append({
                "type": "public_gcp_bucket",
                "severity": "High",
                "url": gcp_url,
                "description": "GCP Storage bucket with public access",
            })
            findings.append({
                "type": "public_gcp_bucket",
                "severity": "High",
                "description": f"Public GCP bucket: {base_name}",
            })
            self._print(f"  [!] Public GCP bucket: {base_name}", RED)

        # 6. Check Firebase Realtime Database open rules
        firebase_url = f"https://{base_name}.firebaseio.com/.json"
        resp = self._send_request(firebase_url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                if data and len(str(data)) > 10:
                    misconfigs_found.append({
                        "type": "firebase_open_rules",
                        "severity": "Critical",
                        "url": firebase_url,
                        "description": "Firebase Realtime DB has open security rules",
                    })
                    findings.append({
                        "type": "firebase_open_rules",
                        "severity": "Critical",
                        "description": f"Open Firebase DB: {base_name}.firebaseio.com",
                    })
                    self._print(f"  [!!!] Open Firebase DB: {base_name}.firebaseio.com", RED)
            except Exception:
                pass

        # 7. Check DigitalOcean Spaces
        for region in DO_SPACES_REGIONS:
            do_url = f"https://{base_name}.{region}.digitaloceanspaces.com/"
            resp = self._send_request(do_url)
            if resp and resp.status_code == 200:
                misconfigs_found.append({
                    "type": "public_do_space",
                    "severity": "High",
                    "url": do_url,
                    "region": region,
                    "description": f"DigitalOcean Space with public access ({region})",
                })
                findings.append({
                    "type": "public_do_space",
                    "severity": "High",
                    "description": f"Public DO Space: {base_name} ({region})",
                })
                self._print(f"  [!] Public DO Space: {base_name} ({region})", RED)
                break

        # 8. CORS misconfiguration check
        cors_resp = self._send_request(url, headers={"Origin": "https://evil.com"})
        if cors_resp:
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                misconfigs_found.append({
                    "type": "cors_wildcard",
                    "severity": "Medium",
                    "url": url,
                    "description": "CORS allows any origin (Access-Control-Allow-Origin: *)",
                })
                findings.append({
                    "type": "cors_wildcard",
                    "severity": "Medium",
                    "description": "CORS wildcard on main domain",
                })
                self._print(f"  [!] CORS wildcard found", YELLOW)
            elif acao == "https://evil.com":
                misconfigs_found.append({
                    "type": "cors_origin_reflection",
                    "severity": "High",
                    "url": url,
                    "description": "CORS reflects arbitrary origin (origin reflection)",
                })
                findings.append({
                    "type": "cors_origin_reflection",
                    "severity": "High",
                    "description": "CORS origin reflection vulnerability",
                })
                self._print(f"  [!] CORS origin reflection!", RED)

        # 9. Check for exposed cloud service files
        cloud_files = [
            "/.gcloud.json", "/.azure/config", "/service-account.json",
            "/client_secret.json", "/credentials.json", "/.firebase.json",
            "/terraform.tfvars", "/terraform.tfstate",
            "/cloud-config.yml", "/deploy-config.json",
        ]
        for cf_path in cloud_files:
            cf_resp = self._send_request(f"{url}{cf_path}")
            if cf_resp and cf_resp.status_code == 200 and len(cf_resp.text) > 20:
                misconfigs_found.append({
                    "type": "cloud_config_exposed",
                    "severity": "High",
                    "url": f"{url}{cf_path}",
                    "file": cf_path,
                    "description": f"Cloud config file exposed: {cf_path}",
                })
                findings.append({
                    "type": "cloud_config_exposed",
                    "severity": "High",
                    "description": f"Cloud config exposed: {cf_path}",
                })
                self._print(f"  [!] Cloud config exposed: {cf_path}", RED)

        # 10. Check missing security headers for cloud-hosted apps
        main_resp = self._send_request(url)
        if main_resp:
            missing_headers = []
            required_cloud_headers = [
                "Strict-Transport-Security",
                "X-Content-Type-Options",
                "X-Frame-Options",
            ]
            for h in required_cloud_headers:
                if h.lower() not in {k.lower(): v for k, v in main_resp.headers.items()}:
                    missing_headers.append(h)

            if missing_headers:
                misconfigs_found.append({
                    "type": "missing_security_headers",
                    "severity": "Medium",
                    "missing": missing_headers,
                    "description": f"Missing security headers: {', '.join(missing_headers)}",
                })
                findings.append({
                    "type": "missing_security_headers",
                    "severity": "Medium",
                    "description": f"Missing headers: {', '.join(missing_headers)}",
                })

        self.misconfigs_found.extend(misconfigs_found)
        self._print(f"  [*] Misconfiguration scan complete: {len(misconfigs_found)} issues", CYAN)

        return {
            "vulnerable": any(f["severity"] in ("Critical", "High") for f in findings),
            "findings": findings,
            "details": {
                "target": target,
                "misconfigs_found": misconfigs_found,
                "total_checks": len(CLOUD_MISCONFIG_CHECKS),
                "critical_count": len([m for m in misconfigs_found if m["severity"] == "Critical"]),
                "high_count": len([m for m in misconfigs_found if m["severity"] == "High"]),
                "medium_count": len([m for m in misconfigs_found if m["severity"] == "Medium"]),
            },
            "scan_type": "cloud_misconfiguration_scan",
        }

    # ========================================================================
    # CLOUD PROVIDER FINGERPRINTING
    # ========================================================================

    def _fingerprint_from_response(self, resp):
        """Identify cloud provider from HTTP response"""
        if not resp:
            return None

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:5000] if resp.text else ""

        for provider, sigs in CLOUD_PROVIDER_FINGERPRINTS.items():
            score = 0
            for header in sigs.get("headers", []):
                if header.lower() in headers_lower:
                    score += 2
            for pattern in sigs.get("body_patterns", []):
                if pattern.lower() in body.lower():
                    score += 1
            if score >= 2:
                return provider
        return None

    def fingerprint_provider(self, target):
        """Fingerprint cloud provider hosting the target

        Args:
            target: Target URL/domain to fingerprint

        Returns:
            dict with provider identification details
        """
        self._print(f"[*] Fingerprinting cloud provider for: {target}", CYAN)
        url = target if '://' in target else f"https://{target}"

        resp = self._send_request(url)
        provider = self._fingerprint_from_response(resp)

        result = {
            "target": target,
            "provider": provider or "Unknown",
            "confidence": "High" if provider else "Low",
            "indicators": {},
        }

        if resp:
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}

            # Check each provider
            for prov, sigs in CLOUD_PROVIDER_FINGERPRINTS.items():
                indicators = []
                for header in sigs.get("headers", []):
                    if header.lower() in headers_lower:
                        indicators.append(f"Header: {header}")
                for pattern in sigs.get("body_patterns", []):
                    if pattern.lower() in (resp.text or "").lower():
                        indicators.append(f"Body: {pattern[:30]}")
                if indicators:
                    result["indicators"][prov] = indicators

        self.provider_fingerprint.update(result)
        self._print(f"  [*] Provider: {result['provider']} (confidence: {result['confidence']})", CYAN)

        return result

    # ========================================================================
    # DIGITALOCEAN SPACES ENUMERATION
    # ========================================================================

    def enum_do_spaces(self, keyword):
        """Enumerate DigitalOcean Spaces

        Args:
            keyword: Base name for Space name permutations

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Enumerating DigitalOcean Spaces for: {keyword}", CYAN)
        findings = []
        spaces_found = []
        total_tested = 0

        clean_keyword = keyword.lower().replace(".", "-").replace("_", "-")

        space_names = [p.format(name=clean_keyword) for p in DO_SPACES_PATTERNS]
        space_names = list(dict.fromkeys(space_names))

        for region in DO_SPACES_REGIONS:
            for name in space_names:
                total_tested += 1
                do_url = f"https://{name}.{region}.digitaloceanspaces.com/"
                try:
                    resp = self._send_request(do_url)
                    if resp and resp.status_code == 200:
                        space_info = {
                            "name": name,
                            "url": do_url,
                            "region": region,
                            "status": "public_readable",
                        }
                        spaces_found.append(space_info)
                        findings.append({
                            "type": "public_do_space",
                            "severity": "High",
                            "name": name,
                            "region": region,
                            "description": f"Public DO Space: {name} ({region})",
                        })
                        self._print(f"  [+] Public DO Space: {name} ({region})", GREEN)
                    elif resp and resp.status_code == 403:
                        space_info = {
                            "name": name,
                            "url": do_url,
                            "region": region,
                            "status": "exists_but_denied",
                        }
                        spaces_found.append(space_info)
                        findings.append({
                            "type": "existing_do_space",
                            "severity": "Medium",
                            "name": name,
                            "region": region,
                            "description": f"Existing DO Space (denied): {name} ({region})",
                        })
                except Exception:
                    pass

        self.do_spaces.extend(spaces_found)
        self._print(f"  [*] Tested {total_tested} Space names, found {len(spaces_found)}", CYAN)

        return {
            "vulnerable": any(f["severity"] == "High" for f in findings),
            "findings": findings,
            "details": {
                "keyword": keyword,
                "spaces_found": spaces_found,
                "total_tested": total_tested,
            },
            "scan_type": "cloud_do_spaces_enum",
        }

    # ========================================================================
    # FIREBASE ENUMERATION
    # ========================================================================

    def enum_firebase(self, keyword):
        """Enumerate Firebase Realtime Databases

        Args:
            keyword: Base name for Firebase DB discovery

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self._print(f"[*] Enumerating Firebase Realtime DBs for: {keyword}", CYAN)
        findings = []
        dbs_found = []

        clean_keyword = keyword.lower().replace(".", "-").replace("_", "-")

        firebase_names = [
            clean_keyword,
            f"{clean_keyword}-dev",
            f"{clean_keyword}-prod",
            f"{clean_keyword}-staging",
            f"{clean_keyword}-test",
            f"{clean_keyword}-default",
        ]

        for name in firebase_names:
            fb_url = f"https://{name}.firebaseio.com/.json"
            try:
                resp = self._send_request(fb_url)
                if resp and resp.status_code == 200:
                    try:
                        data = resp.json()
                        if data:
                            db_info = {
                                "name": name,
                                "url": f"https://{name}.firebaseio.com/",
                                "status": "open_access",
                                "data_size": len(resp.text),
                            }
                            dbs_found.append(db_info)
                            findings.append({
                                "type": "firebase_open_db",
                                "severity": "Critical",
                                "name": name,
                                "description": f"Open Firebase DB: {name}.firebaseio.com",
                            })
                            self._print(f"  [!!!] Open Firebase DB: {name}.firebaseio.com", RED)
                    except Exception:
                        pass
                elif resp and resp.status_code == 401:
                    # Database exists but requires auth
                    db_info = {
                        "name": name,
                        "url": f"https://{name}.firebaseio.com/",
                        "status": "requires_auth",
                    }
                    dbs_found.append(db_info)
                    findings.append({
                        "type": "firebase_existing_db",
                        "severity": "Low",
                        "name": name,
                        "description": f"Existing Firebase DB (auth required): {name}",
                    })
                    self._print(f"  [*] Firebase DB (auth required): {name}", YELLOW)
            except Exception:
                pass

        self.firebase_dbs.extend(dbs_found)
        self._print(f"  [*] Firebase enumeration complete: {len(dbs_found)} found", CYAN)

        return {
            "vulnerable": any(f["severity"] == "Critical" for f in findings),
            "findings": findings,
            "details": {
                "keyword": keyword,
                "databases_found": dbs_found,
                "total_tested": len(firebase_names),
            },
            "scan_type": "cloud_firebase_enum",
        }

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='full', **kwargs):
        """Main entry point for cloud security scanning

        Args:
            target: Target domain/IP/URL
            scan_type: Type of scan to run
                - 's3': AWS S3 bucket enumeration
                - 'azure': Azure Blob enumeration
                - 'gcp': GCP Storage enumeration
                - 'metadata': Cloud metadata extraction
                - 'credentials': Credential scanning
                - 'misconfig': Misconfiguration detection
                - 'full': Complete cloud security assessment
            **kwargs: Additional arguments (keyword, ssrf_url, etc.)

        Returns:
            dict with 'vulnerable', 'findings', 'details', 'scan_type'
        """
        self.target = target
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        base_name = domain.split('.')[0]
        keyword = kwargs.get('keyword', base_name)

        findings_list = []
        scan_results = {}

        try:
            if scan_type == 's3':
                result = self.enum_s3_buckets(keyword)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'azure':
                result = self.enum_azure_blobs(keyword)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'gcp':
                result = self.enum_gcp_storage(keyword)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'metadata':
                result = self.extract_metadata(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'credentials':
                result = self.scan_credentials(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'misconfig':
                result = self.detect_misconfigs(target)
                findings_list.extend(result.get("findings", []))
                scan_results = result.get("details", {})

            elif scan_type == 'full':
                self._print(f"\n{BOLD}{'='*60}{RESET}", MAGENTA)
                self._print(f"{BOLD} CLOUD SECURITY ADVANCED - FULL SCAN{RESET}", MAGENTA)
                self._print(f"{BOLD}{'='*60}{RESET}", MAGENTA)

                # Phase 1: Provider fingerprinting
                self._print(f"\n{BOLD}[Phase 1/7] Provider Fingerprinting{RESET}", CYAN)
                fp_result = self.fingerprint_provider(target)
                scan_results["fingerprint"] = fp_result

                # Phase 2: S3 enumeration
                self._print(f"\n{BOLD}[Phase 2/7] AWS S3 Bucket Enumeration{RESET}", CYAN)
                s3_result = self.enum_s3_buckets(keyword)
                findings_list.extend(s3_result.get("findings", []))
                scan_results["s3"] = s3_result.get("details", {})

                # Phase 3: Azure Blob enumeration
                self._print(f"\n{BOLD}[Phase 3/7] Azure Blob Enumeration{RESET}", CYAN)
                azure_result = self.enum_azure_blobs(keyword)
                findings_list.extend(azure_result.get("findings", []))
                scan_results["azure"] = azure_result.get("details", {})

                # Phase 4: GCP Storage enumeration
                self._print(f"\n{BOLD}[Phase 4/7] GCP Storage Enumeration{RESET}", CYAN)
                gcp_result = self.enum_gcp_storage(keyword)
                findings_list.extend(gcp_result.get("findings", []))
                scan_results["gcp"] = gcp_result.get("details", {})

                # Phase 5: Metadata extraction
                self._print(f"\n{BOLD}[Phase 5/7] Cloud Metadata Extraction{RESET}", CYAN)
                meta_result = self.extract_metadata(target)
                findings_list.extend(meta_result.get("findings", []))
                scan_results["metadata"] = meta_result.get("details", {})

                # Phase 6: Credential scanning
                self._print(f"\n{BOLD}[Phase 6/7] Credential Scanning{RESET}", CYAN)
                cred_result = self.scan_credentials(target)
                findings_list.extend(cred_result.get("findings", []))
                scan_results["credentials"] = cred_result.get("details", {})

                # Phase 7: Misconfiguration detection
                self._print(f"\n{BOLD}[Phase 7/7] Misconfiguration Detection{RESET}", CYAN)
                misconfig_result = self.detect_misconfigs(target)
                findings_list.extend(misconfig_result.get("findings", []))
                scan_results["misconfigs"] = misconfig_result.get("details", {})

                # Also enumerate DO and Firebase
                self._print(f"\n{BOLD}[Bonus] DigitalOcean Spaces + Firebase{RESET}", CYAN)
                do_result = self.enum_do_spaces(keyword)
                findings_list.extend(do_result.get("findings", []))
                scan_results["digitalocean"] = do_result.get("details", {})

                fb_result = self.enum_firebase(keyword)
                findings_list.extend(fb_result.get("findings", []))
                scan_results["firebase"] = fb_result.get("details", {})

                # Summary
                critical = len([f for f in findings_list if f.get("severity") == "Critical"])
                high = len([f for f in findings_list if f.get("severity") == "High"])
                medium = len([f for f in findings_list if f.get("severity") == "Medium"])

                self._print(f"\n{BOLD}{'='*60}{RESET}", MAGENTA)
                self._print(f"{BOLD} CLOUD SECURITY SCAN COMPLETE{RESET}", MAGENTA)
                self._print(f"{BOLD}{'='*60}{RESET}", MAGENTA)
                self._print(f"  Critical: {RED}{critical}{RESET}")
                self._print(f"  High:     {YELLOW}{high}{RESET}")
                self._print(f"  Medium:   {CYAN}{medium}{RESET}")

                scan_results["summary"] = {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "total_findings": len(findings_list),
                    "s3_buckets_found": len(self.s3_buckets),
                    "azure_blobs_found": len(self.azure_blobs),
                    "gcp_buckets_found": len(self.gcp_buckets),
                    "do_spaces_found": len(self.do_spaces),
                    "firebase_dbs_found": len(self.firebase_dbs),
                    "credentials_found": len(self.credentials_found),
                    "misconfigs_found": len(self.misconfigs_found),
                    "provider": fp_result.get("provider", "Unknown"),
                }
            else:
                scan_results = {"error": f"Unknown scan type: {scan_type}"}

        except Exception as e:
            scan_results = {"error": str(e)}
            self._print(f"  [!] Scan error: {e}", RED)

        return {
            "vulnerable": len(findings_list) > 0,
            "findings": findings_list,
            "details": scan_results,
            "scan_type": f"cloud_advanced_{scan_type}",
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level entry point for ZYLON integration

    Args:
        target: Target domain/IP/URL
        scan_type: Scan type ('s3', 'azure', 'gcp', 'metadata',
                   'credentials', 'misconfig', 'full')
        **kwargs: Additional arguments (keyword, threads, etc.)

    Returns:
        dict with 'vulnerable', 'findings', 'details', 'scan_type'
    """
    threads = kwargs.get('threads', MAX_THREADS)
    timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
    proxy = kwargs.get('proxy', None)

    engine = CloudAdvancedEngine(
        target=target, threads=threads, timeout=timeout, proxy=proxy
    )
    return engine.run(target, scan_type=scan_type, **kwargs)
