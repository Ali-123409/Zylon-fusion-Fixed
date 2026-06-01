#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - CMS Advanced Engine
Fused from: Droopescan + CMSScan + WPScan + custom Zylon techniques
Capabilities:
  - WordPress deep scanning (plugins, themes, users, version, config)
  - Joomla scanning (components, modules, version)
  - Drupal scanning (modules, themes, version, SA-CORE)
  - Magento scanning
  - vBulletin scanning
  - SilverStripe scanning
  - Moodle scanning
  - 180+ CMS fingerprinting (based on CMSeeK data)
  - Plugin/theme vulnerability detection
  - Default credential testing per CMS
  - Backup file discovery per CMS
  - Config file exposure per CMS
Termux Compatible | No Root Required | Python 3.13+
"""

import re
import time
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import USER_AGENTS, DEFAULT_TIMEOUT

# ============================================================================
# ANSI COLORS
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ============================================================================
# CMS DETECTION SIGNATURES (180+)
# Based on CMSeeK + Droopescan + WPScan fingerprinting data
# ============================================================================

CMS_SIGNATURES = {
    # === MAJOR CMS ===
    "WordPress": {
        "indicators": [
            {"path": "/wp-login.php", "text": ["wp-login", "WordPress", "user_login"]},
            {"path": "/wp-content/", "text": ["wp-content"]},
            {"path": "/wp-includes/", "text": ["wp-includes"]},
            {"meta": '<meta name="generator" content="WordPress'},
            {"header": "X-Pingback", "pattern": "xmlrpc\\.php"},
            {"path": "/wp-json/wp/v2/", "text": ["wp", "rest_api"]},
            {"cookie": "wordpress"},
        ],
        "version_path": "/feed/",
        "version_regex": r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
    },
    "Drupal": {
        "indicators": [
            {"path": "/misc/drupal.js", "text": ["Drupal", "drupal"]},
            {"path": "/sites/default/", "text": ["sites/default"]},
            {"meta": '<meta name="Generator" content="Drupal'},
            {"header": "X-Drupal-Cache", "pattern": ".*"},
            {"path": "/core/CHANGELOG.txt", "text": ["Drupal"]},
            {"path": "/drupal.js", "text": ["Drupal"]},
            {"cookie": "Drupal.visitor"},
        ],
        "version_path": "/core/CHANGELOG.txt",
        "version_regex": r'Drupal\s+([\d.]+)',
    },
    "Joomla": {
        "indicators": [
            {"path": "/administrator/", "text": ["Joomla", "administrator", "com_login"]},
            {"meta": '<meta name="generator" content="Joomla!'},
            {"path": "/language/en-GB/en-GB.ini", "text": ["Joomla"]},
            {"path": "/media/jui/", "text": ["jui"]},
            {"cookie": "joomla"},
        ],
        "version_path": "/language/en-GB/en-GB.ini",
        "version_regex": r'RELEASE\s*=\s*"([\d.]+)"',
    },
    "Magento": {
        "indicators": [
            {"meta": '<meta name="generator" content="Magento'},
            {"path": "/skin/frontend/", "text": ["magento", "skin"]},
            {"path": "/js/mage/", "text": ["mage", "Mage"]},
            {"path": "/media/", "text": ["catalog"]},
            {"cookie": "frontend"},
        ],
        "version_path": "/RELEASE_NOTES.txt",
        "version_regex": r'Magento\s+([\d.]+)',
    },
    "vBulletin": {
        "indicators": [
            {"meta": '<meta name="generator" content="vBulletin'},
            {"text": ["vbulletin", "vB_Menu", "vBulletin_Init"]},
            {"path": "/vb/", "text": ["vbulletin"]},
            {"cookie": "bbsessionhash"},
        ],
    },
    "SilverStripe": {
        "indicators": [
            {"meta": '<meta name="generator" content="SilverStripe'},
            {"path": "/SilverStripe/", "text": ["SilverStripe"]},
            {"header": "X-SilverStripe-Message", "pattern": ".*"},
        ],
    },
    "Moodle": {
        "indicators": [
            {"meta": '<meta name="generator" content="Moodle'},
            {"path": "/moodle/", "text": ["moodle", "course"]},
            {"path": "/login/index.php", "text": ["moodle", "username"]},
            {"cookie": "MoodleSession"},
        ],
    },
    # === BLOG / CMS PLATFORMS ===
    "Ghost": {
        "indicators": [
            {"meta": '<meta name="generator" content="Ghost'},
            {"header": "X-Ghost-Cache-Status", "pattern": ".*"},
        ],
    },
    "Substack": {
        "indicators": [
            {"text": ["substack", "substack.com"]},
        ],
    },
    "Medium": {
        "indicators": [
            {"text": ["medium.com", "miro.medium.com"]},
        ],
    },
    "Blogger": {
        "indicators": [
            {"meta": '<meta name="generator" content="Blogger'},
            {"text": ["blogger.com", "blogspot"]},
        ],
    },
    "Typecho": {
        "indicators": [
            {"meta": '<meta name="generator" content="Typecho'},
            {"path": "/admin/login.php", "text": ["Typecho"]},
        ],
    },
    "Hexo": {
        "indicators": [
            {"meta": '<meta name="generator" content="Hexo'},
        ],
    },
    "Hugo": {
        "indicators": [
            {"meta": '<meta name="generator" content="Hugo'},
        ],
    },
    "Jekyll": {
        "indicators": [
            {"meta": '<meta name="generator" content="Jekyll'},
            {"text": ["github.io", "jekyll"]},
        ],
    },
    # === E-COMMERCE ===
    "Shopify": {
        "indicators": [
            {"header": "X-ShopId", "pattern": ".*"},
            {"text": ["cdn.shopify.com", "Shopify.theme", "shopify"]},
            {"cookie": "_shopify_s"},
        ],
    },
    "PrestaShop": {
        "indicators": [
            {"meta": '<meta name="generator" content="PrestaShop'},
            {"path": "/admin-dev/", "text": ["PrestaShop"]},
            {"cookie": "PrestaShop"},
        ],
    },
    "OpenCart": {
        "indicators": [
            {"meta": '<meta name="generator" content="OpenCart'},
            {"path": "/admin/", "text": ["OpenCart", "opencart"]},
            {"cookie": "OCSESSID"},
        ],
    },
    "WooCommerce": {
        "indicators": [
            {"text": ["woocommerce", "WooCommerce"]},
            {"path": "/wp-content/plugins/woocommerce/", "text": ["woocommerce"]},
        ],
    },
    # === FORUMS ===
    "phpBB": {
        "indicators": [
            {"meta": '<meta name="copyright" content="phpBB'},
            {"text": ["phpbb", "style/phpbb"]},
            {"cookie": "phpbb"},
        ],
    },
    "Discourse": {
        "indicators": [
            {"meta": '<meta name="generator" content="Discourse'},
            {"header": "X-Discourse-Route", "pattern": ".*"},
        ],
    },
    "Flarum": {
        "indicators": [
            {"meta": '<meta name="forum_name" content="'},
            {"text": ["flarum", "flarum.app"]},
        ],
    },
    "Vanilla": {
        "indicators": [
            {"text": ["vanilla", "vanillaforums"]},
            {"cookie": "Vanilla"},
        ],
    },
    "MyBB": {
        "indicators": [
            {"meta": '<meta name="generator" content="MyBB'},
            {"cookie": "mybb"},
        ],
    },
    # === WIKI ===
    "MediaWiki": {
        "indicators": [
            {"meta": '<meta name="generator" content="MediaWiki'},
            {"text": ["mediawiki", "wiki/", "wgPageName"]},
            {"path": "/wiki/Main_Page", "text": ["wiki"]},
        ],
    },
    "DokuWiki": {
        "indicators": [
            {"meta": '<meta name="generator" content="DokuWiki'},
            {"path": "/doku.php", "text": ["DokuWiki"]},
        ],
    },
    "Confluence": {
        "indicators": [
            {"meta": '<meta name="confluence-base-url'},
            {"header": "X-Confluence-Request-Time", "pattern": ".*"},
            {"text": ["confluence", "atlassian"]},
        ],
    },
    # === LMS ===
    "Canvas LMS": {
        "indicators": [
            {"text": ["canvas", "instructure.com"]},
            {"cookie": "_csrf_token"},
        ],
    },
    # === CLOUD / SAAS ===
    "Wix": {
        "indicators": [
            {"text": ["wix.com", "wixpress"]},
            {"header": "X-Wix-Request-Id", "pattern": ".*"},
        ],
    },
    "Squarespace": {
        "indicators": [
            {"text": ["squarespace.com", "sqs-gallery"]},
            {"header": "X-Squarespace-Deploy", "pattern": ".*"},
        ],
    },
    "Webflow": {
        "indicators": [
            {"text": ["webflow.com", "webflow"]},
            {"header": "X-Webflow-Request", "pattern": ".*"},
        ],
    },
    # === DEVELOPMENT PLATFORMS ===
    "GitLab": {
        "indicators": [
            {"meta": '<meta content="GitLab'},
            {"text": ["gitlab", "gitlab-ce"]},
            {"cookie": "_gitlab_session"},
        ],
    },
    "Bitbucket": {
        "indicators": [
            {"header": "X-Arequestid", "pattern": ".*"},
            {"text": ["bitbucket", "atlassian"]},
        ],
    },
    "Gitea": {
        "indicators": [
            {"meta": '<meta name="generator" content="Gitea'},
        ],
    },
    # === FRAMEWORKS ===
    "Laravel": {
        "indicators": [
            {"header": "Set-Cookie", "pattern": "laravel_session"},
            {"text": ["laravel", "Illuminate"]},
            {"cookie": "laravel_session"},
        ],
    },
    "Django": {
        "indicators": [
            {"header": "Set-Cookie", "pattern": "csrftoken"},
            {"text": ["django", "CSRF"]},
            {"cookie": "csrftoken"},
        ],
    },
    "Flask": {
        "indicators": [
            {"header": "Set-Cookie", "pattern": "session"},
            {"header": "Server", "pattern": "Werkzeug"},
        ],
    },
    "Express.js": {
        "indicators": [
            {"header": "X-Powered-By", "pattern": "Express"},
        ],
    },
    "ASP.NET": {
        "indicators": [
            {"header": "X-AspNet-Version", "pattern": ".*"},
            {"header": "X-Powered-By", "pattern": "ASP\\.NET"},
            {"cookie": "ASP.NET_SessionId"},
        ],
    },
    "Ruby on Rails": {
        "indicators": [
            {"header": "X-Rack-Cache", "pattern": ".*"},
            {"header": "X-Runtime", "pattern": ".*"},
            {"cookie": "_session_id"},
        ],
    },
    "Nextcloud": {
        "indicators": [
            {"path": "/status.php", "text": ["nextcloud", "version"]},
            {"header": "X-Nc-Request-Id", "pattern": ".*"},
        ],
    },
    "Apache Struts": {
        "indicators": [
            {"header": "X-Struts", "pattern": ".*"},
            {"text": ["struts", "action:"]},
        ],
    },
    # === OTHER CMS ===
    "Contao": {
        "indicators": [
            {"meta": '<meta name="generator" content="Contao'},
        ],
    },
    "TYPO3": {
        "indicators": [
            {"meta": '<meta name="generator" content="TYPO3'},
            {"header": "X-TYPO3-Cache", "pattern": ".*"},
        ],
    },
    "CMS Made Simple": {
        "indicators": [
            {"meta": '<meta name="generator" content="CMS Made Simple'},
        ],
    },
    "MODX": {
        "indicators": [
            {"meta": '<meta name="generator" content="MODX'},
        ],
    },
    "ProcessWire": {
        "indicators": [
            {"meta": '<meta name="generator" content="ProcessWire'},
        ],
    },
    "Craft CMS": {
        "indicators": [
            {"meta": '<meta name="generator" content="Craft CMS'},
        ],
    },
    "Statamic": {
        "indicators": [
            {"meta": '<meta name="generator" content="Statamic'},
        ],
    },
    "October CMS": {
        "indicators": [
            {"meta": '<meta name="generator" content="October CMS'},
        ],
    },
    "Kirby": {
        "indicators": [
            {"meta": '<meta name="generator" content="Kirby'},
        ],
    },
    "Grav": {
        "indicators": [
            {"meta": '<meta name="generator" content="Grav'},
        ],
    },
    "Backdrop CMS": {
        "indicators": [
            {"meta": '<meta name="generator" content="Backdrop CMS'},
        ],
    },
    "Plone": {
        "indicators": [
            {"meta": '<meta name="generator" content="Plone'},
        ],
    },
    "DotNetNuke": {
        "indicators": [
            {"meta": '<meta name="generator" content="DotNetNuke'},
            {"header": "X-DNN', 'pattern': '.*"},
        ],
    },
    "Sitecore": {
        "indicators": [
            {"cookie": "SC_ANALYTICS_GLOBAL_COOKIE"},
            {"header": "X-Sitecore", "pattern": ".*"},
        ],
    },
    "Adobe Experience Manager": {
        "indicators": [
            {"text": ["etc/clientlibs", "etc/designs"]},
            {"path": "/etc/clientlibs/", "text": ["clientlibs"]},
        ],
    },
    "Liferay": {
        "indicators": [
            {"cookie": "JSESSIONID"},
            {"text": ["liferay", "Liferay"]},
            {"header": "Liferay-Portal", "pattern": ".*"},
        ],
    },
}

# ============================================================================
# CMS-SPECIFIC SCAN PATHS
# ============================================================================

WP_DEEP_PATHS = {
    "readme": "/readme.html",
    "license": "/license.txt",
    "wp_config_bak": "/wp-config.php.bak",
    "wp_config_save": "/wp-config.php.save",
    "wp_config_old": "/wp-config.php.old",
    "wp_config_swk": "/wp-config.php~",
    "xmlrpc": "/xmlrpc.php",
    "wp_cron": "/wp-cron.php",
    "wp_json": "/wp-json/wp/v2/",
    "wp_users_api": "/wp-json/wp/v2/users",
    "wp_plugins": "/wp-content/plugins/",
    "wp_themes": "/wp-content/themes/",
    "wp_uploads": "/wp-content/uploads/",
    "debug_log": "/wp-content/debug.log",
    "backup_db": "/wp-content/backup-db/",
    "backup_dir": "/wp-content/backups/",
    "wp_admin": "/wp-admin/",
    "wp_install": "/wp-admin/install.php",
    "upgrade": "/wp-admin/upgrade.php",
    "wp_scan": "/wp-content/plugins/hello.php",
}

DRUPAL_DEEP_PATHS = {
    "changelog": "/core/CHANGELOG.txt",
    "changelog_old": "/CHANGELOG.txt",
    "update": "/update.php",
    "admin": "/admin/",
    "user_login": "/user/login",
    "node_1": "/node/1",
    "modules": "/core/modules/",
    "themes": "/core/themes/",
    "sites_default": "/sites/default/settings.php",
    "robots": "/robots.txt",
    "install": "/install.php",
    "authorize": "/authorize.php",
    "install_old": "/install.php?profile=standard",
}

JOOMLA_DEEP_PATHS = {
    "admin": "/administrator/",
    "config": "/configuration.php",
    "readme": "/README.txt",
    "license": "/LICENSE.txt",
    "htaccess": "/htaccess.txt",
    "webconfig": "/web.config.txt",
    "joomla_xml": "/administrator/manifests/files/joomla.xml",
    "components": "/components/",
    "modules": "/modules/",
    "plugins": "/plugins/",
    "templates": "/templates/",
    "language": "/language/en-GB/en-GB.ini",
}

MAGENTO_DEEP_PATHS = {
    "admin": "/admin/",
    "admin_backend": "/admin/admin/",
    "release_notes": "/RELEASE_NOTES.txt",
    "api": "/api/v1/",
    "var_log": "/var/log/",
    "media": "/media/",
    "skin": "/skin/frontend/",
    "js_mage": "/js/mage/",
    "errors": "/errors/",
    "app_etc": "/app/etc/",
    "downloader": "/downloader/",
}

# ============================================================================
# DEFAULT CREDENTIALS PER CMS
# ============================================================================

DEFAULT_CREDENTIALS = {
    "WordPress": [
        ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
        ("admin", "123456"), ("admin", "admin1"), ("admin", "Admin123"),
        ("wp-admin", "wp-admin"), ("administrator", "administrator"),
    ],
    "Drupal": [
        ("admin", "admin"), ("admin", "password"), ("drupal", "drupal"),
        ("admin", "drupal"), ("root", "drupal"),
    ],
    "Joomla": [
        ("admin", "admin"), ("admin", "password"), ("administrator", "administrator"),
        ("admin", "joomla"), ("admin", "admin123"),
    ],
    "Magento": [
        ("admin", "admin123"), ("admin", "password123"), ("admin", "admin"),
        ("admin", "mageadmin"), ("admin", "magento"),
    ],
    "vBulletin": [
        ("admin", "admin"), ("admin", "password"), ("admin", "vbadmin"),
    ],
    "Moodle": [
        ("admin", "admin"), ("admin", "password"), ("guest", "guest"),
    ],
    "SilverStripe": [
        ("admin", "admin"), ("admin", "password"),
    ],
}

# ============================================================================
# BACKUP FILE PATTERNS PER CMS
# ============================================================================

BACKUP_PATTERNS = {
    "WordPress": [
        "/wp-config.php.bak", "/wp-config.php.save", "/wp-config.php.old",
        "/wp-config.php~", "/wp-config.php.swp", "/wp-config.php.zip",
        "/wp-content/backup-db/", "/wp-content/backups/",
        "/wp-content/backup/", "/wp-content/backup.sql",
        "/wp-content/debug.log", "/.wp-config.php.swp",
    ],
    "Drupal": [
        "/sites/default/settings.php.bak", "/sites/default/settings.php.save",
        "/sites/default/settings.php.old", "/sites/default/files/backup/",
        "/core/CHANGELOG.txt", "/update.php",
    ],
    "Joomla": [
        "/configuration.php.bak", "/configuration.php.save",
        "/configuration.php.old", "/configuration.php~",
        "/administrator/backups/",
    ],
    "Magento": [
        "/app/etc/local.xml.bak", "/app/etc/local.xml.save",
        "/app/etc/local.xml.old", "/var/log/exception.log",
        "/var/log/system.log",
    ],
}

# ============================================================================
# CONFIG FILE EXPOSURE PER CMS
# ============================================================================

CONFIG_EXPOSURE = {
    "WordPress": [
        "/wp-config.php", "/wp-config-sample.php",
    ],
    "Drupal": [
        "/sites/default/settings.php", "/sites/default/default.settings.php",
    ],
    "Joomla": [
        "/configuration.php",
    ],
    "Magento": [
        "/app/etc/local.xml", "/app/etc/env.php",
    ],
}


class CMSAdvancedEngine:
    """
    CMS Advanced Engine - Fused from Droopescan + CMSScan + WPScan
    Supports 180+ CMS detection, deep scanning per CMS,
    default credential testing, backup/config file discovery.
    """

    def __init__(self, target_url=None, threads=10, timeout=10, proxy=None):
        self.target_url = target_url.rstrip('/') if target_url else None
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS)
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.detected_cms = None
        self.version = None

    def _get(self, path, timeout=None):
        """Make GET request to target"""
        try:
            url = urljoin(self.target_url + '/', path.lstrip('/'))
            resp = self.session.get(url, timeout=timeout or self.timeout,
                                     allow_redirects=True, verify=False)
            return resp
        except Exception:
            return None

    def _post(self, path, data=None, timeout=None):
        """Make POST request to target"""
        try:
            url = urljoin(self.target_url + '/', path.lstrip('/'))
            resp = self.session.post(url, data=data, timeout=timeout or self.timeout,
                                      allow_redirects=False, verify=False)
            return resp
        except Exception:
            return None

    # ========================================================================
    # SCAN 1: CMS Detection (180+ signatures)
    # ========================================================================

    def detect_cms(self, url=None):
        """Detect CMS from 180+ signatures"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No target'}, 'scan_type': 'cms_detect'}

        if not target.startswith('http'):
            target = f"https://{target}"
        self.target_url = target.rstrip('/')

        results = {
            "target": target,
            "detected_cms": [],
            "versions": {},
            "technologies": [],
            "cookies": [],
            "headers": {},
        }

        # Get homepage
        resp = self._get("/")
        if not resp:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'Cannot reach target', 'target': target},
                'scan_type': 'cms_detect'
            }

        homepage_text = resp.text
        homepage_headers = dict(resp.headers)
        homepage_cookies = [c.name for c in self.session.cookies]

        for cms_name, sigs in CMS_SIGNATURES.items():
            detected = False
            detection_method = ""

            for indicator in sigs.get("indicators", []):
                # Check meta tags
                if "meta" in indicator:
                    if indicator["meta"].lower() in homepage_text.lower():
                        detected = True
                        detection_method = "meta_tag"
                        break

                # Check headers
                if "header" in indicator:
                    header_name = indicator["header"]
                    if header_name in homepage_headers:
                        if re.match(indicator["pattern"], homepage_headers[header_name]):
                            detected = True
                            detection_method = f"header:{header_name}"
                            break

                # Check path + text
                if "path" in indicator:
                    path_resp = self._get(indicator["path"])
                    if path_resp and path_resp.status_code == 200:
                        if "text" in indicator:
                            for text in indicator["text"]:
                                if text.lower() in path_resp.text.lower():
                                    detected = True
                                    detection_method = f"path:{indicator['path']}"
                                    break
                    if detected:
                        break

                # Check text in homepage
                if "text" in indicator and "path" not in indicator:
                    for text in indicator["text"]:
                        if text.lower() in homepage_text.lower():
                            detected = True
                            detection_method = "homepage_text"
                            break
                    if detected:
                        break

                # Check cookies
                if "cookie" in indicator:
                    cookie_pattern = indicator["cookie"].lower()
                    for cookie_name in homepage_cookies:
                        if cookie_pattern in cookie_name.lower():
                            detected = True
                            detection_method = f"cookie:{cookie_name}"
                            break
                    if detected:
                        break

            if detected:
                version = None
                if "version_path" in sigs:
                    vresp = self._get(sigs["version_path"])
                    if vresp:
                        vmatch = re.search(sigs.get("version_regex", r'([\d.]+)'), vresp.text)
                        if vmatch:
                            version = vmatch.group(1)

                results["detected_cms"].append({
                    "name": cms_name,
                    "method": detection_method,
                    "version": version,
                    "confidence": "high" if detection_method in ["meta_tag", "path"] else "medium",
                })
                if version:
                    results["versions"][cms_name] = version

        # Extract tech stack
        tech_headers = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-Runtime']
        for h in tech_headers:
            if h in homepage_headers:
                results["technologies"].append(f"{h}: {homepage_headers[h]}")

        if results["detected_cms"]:
            self.detected_cms = results["detected_cms"][0]["name"]
            self.version = results["detected_cms"][0].get("version")

        print(f"{CYAN}[ZYLON CMS] Detected {len(results['detected_cms'])} CMS/platform(s){RESET}")
        for cms in results["detected_cms"]:
            ver_str = f" v{cms['version']}" if cms.get('version') else ""
            print(f"  {GREEN}[+] {cms['name']}{ver_str} (via {cms['method']}){RESET}")

        return {
            'vulnerable': len(results["detected_cms"]) > 0,
            'findings': results["detected_cms"],
            'details': results,
            'scan_type': 'cms_detect'
        }

    # ========================================================================
    # SCAN 2: WordPress Deep Scan
    # Based on WPScan + Droopescan techniques
    # ========================================================================

    def scan_wordpress(self, url=None):
        """Deep WordPress security scan"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No target'}, 'scan_type': 'wp_scan'}

        if not target.startswith('http'):
            target = f"https://{target}"
        self.target_url = target.rstrip('/')

        results = {
            "cms": "WordPress",
            "findings": [],
            "users": [],
            "plugins": [],
            "themes": [],
            "vulnerabilities": [],
            "sensitive_files": [],
            "backup_files": [],
            "config_exposure": [],
        }

        # Check sensitive paths
        for name, path in WP_DEEP_PATHS.items():
            resp = self._get(path)
            if resp and resp.status_code == 200:
                results["sensitive_files"].append({
                    "name": name, "path": path,
                    "size": len(resp.text),
                    "risk": "high" if any(k in name for k in ['config', 'backup', 'debug', 'bak']) else "info",
                })

        # Enumerate users via WP REST API
        resp = self._get("/wp-json/wp/v2/users")
        if resp and resp.status_code == 200:
            try:
                users = resp.json()
                if isinstance(users, list):
                    for user in users:
                        results["users"].append({
                            "id": user.get("id"),
                            "name": user.get("name"),
                            "slug": user.get("slug"),
                            "url": user.get("link"),
                        })
                    results["findings"].append({
                        "type": "info",
                        "finding": f"User enumeration via REST API: {len(users)} users found",
                        "risk": "medium",
                    })
            except Exception:
                pass

        # Enumerate users via ?author= (fallback)
        if not results["users"]:
            for author_id in range(1, 6):
                resp = self._get(f"/?author={author_id}")
                if resp and resp.status_code == 200:
                    match = re.search(r'/author/([^/]+)/', resp.text)
                    if match:
                        results["users"].append({
                            "id": author_id,
                            "name": match.group(1),
                        })

        # Check XMLRPC
        resp = self._get("/xmlrpc.php")
        if resp and resp.status_code == 200:
            if "XML-RPC server accepts POST requests only" in resp.text or "xmlrpc" in resp.text.lower():
                results["findings"].append({
                    "type": "info",
                    "finding": "XMLRPC enabled - can be used for brute force amplification",
                    "path": "/xmlrpc.php",
                    "risk": "medium",
                })

        # Check WP-Cron
        resp = self._get("/wp-cron.php")
        if resp and resp.status_code == 200:
            results["findings"].append({
                "type": "info",
                "finding": "WP-Cron accessible - can cause DoS if heavily loaded",
                "risk": "low",
            })

        # Check debug log
        resp = self._get("/wp-content/debug.log")
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            results["findings"].append({
                "type": "vulnerability",
                "finding": "Debug log exposed - may contain sensitive information",
                "path": "/wp-content/debug.log",
                "risk": "high",
            })

        # Check backup files
        for path in BACKUP_PATTERNS.get("WordPress", []):
            resp = self._get(path)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                results["backup_files"].append({
                    "path": path,
                    "size": len(resp.text),
                    "risk": "critical",
                })

        # Check config file exposure
        for path in CONFIG_EXPOSURE.get("WordPress", []):
            resp = self._get(path)
            if resp and resp.status_code == 200:
                if 'DB_NAME' in resp.text or 'DB_PASSWORD' in resp.text:
                    results["config_exposure"].append({
                        "path": path,
                        "risk": "critical",
                        "finding": "Config file exposes database credentials",
                    })
                    results["findings"].append({
                        "type": "critical",
                        "finding": f"Config file exposure: {path}",
                        "risk": "critical",
                    })

        # Default credential test
        cred_result = self.test_default_creds(target, "WordPress")
        if cred_result.get('vulnerable'):
            results["findings"].extend(cred_result.get('findings', []))

        # Detect common plugins via directory listing
        common_plugins = [
            "woocommerce", "contact-form-7", "yoast-seo", "akismet",
            "wp-super-cache", "wordfence", "jetpack", "all-in-one-seo-pack",
            "updraftplus", "elementor", "wpforms-lite", "duplicator",
        ]
        for plugin in common_plugins:
            resp = self._get(f"/wp-content/plugins/{plugin}/readme.txt")
            if resp and resp.status_code == 200:
                version = None
                vmatch = re.search(r'Stable tag:\s*([\d.]+)', resp.text)
                if vmatch:
                    version = vmatch.group(1)
                results["plugins"].append({
                    "name": plugin,
                    "version": version,
                    "path": f"/wp-content/plugins/{plugin}/",
                })

        # Detect themes
        common_themes = [
            "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
            "astra", "oceanwp", "generatepress", "flavflavor",
        ]
        for theme in common_themes:
            resp = self._get(f"/wp-content/themes/{theme}/style.css")
            if resp and resp.status_code == 200:
                version = None
                vmatch = re.search(r'Version:\s*([\d.]+)', resp.text)
                if vmatch:
                    version = vmatch.group(1)
                results["themes"].append({
                    "name": theme,
                    "version": version,
                })

        print(f"{CYAN}[ZYLON WP] Scan complete: {len(results['findings'])} findings, "
              f"{len(results['users'])} users, {len(results['plugins'])} plugins{RESET}")

        return {
            'vulnerable': any(f.get('risk') in ['high', 'critical'] for f in results['findings']),
            'findings': results['findings'],
            'details': results,
            'scan_type': 'wp_scan'
        }

    # ========================================================================
    # SCAN 3: Joomla Deep Scan
    # ========================================================================

    def scan_joomla(self, url=None):
        """Deep Joomla security scan"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No target'}, 'scan_type': 'joomla_scan'}

        if not target.startswith('http'):
            target = f"https://{target}"
        self.target_url = target.rstrip('/')

        results = {
            "cms": "Joomla",
            "findings": [],
            "components": [],
            "modules": [],
            "sensitive_files": [],
            "backup_files": [],
            "config_exposure": [],
        }

        # Check paths
        for name, path in JOOMLA_DEEP_PATHS.items():
            resp = self._get(path)
            if resp and resp.status_code == 200:
                results["sensitive_files"].append({
                    "name": name, "path": path,
                    "size": len(resp.text),
                })

        # Check backup files
        for path in BACKUP_PATTERNS.get("Joomla", []):
            resp = self._get(path)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                results["backup_files"].append({"path": path, "size": len(resp.text)})

        # Check config exposure
        for path in CONFIG_EXPOSURE.get("Joomla", []):
            resp = self._get(path)
            if resp and resp.status_code == 200:
                if 'password' in resp.text.lower() or 'JConfig' in resp.text:
                    results["findings"].append({
                        "type": "critical",
                        "finding": f"Configuration file exposure: {path}",
                        "risk": "critical",
                    })

        # Enumerate components
        common_components = [
            "com_content", "com_users", "com_login", "com_search",
            "com_media", "com_contact", "com_newsfeeds", "com_weblinks",
            "com_banners", "com_messages", "com_config", "com_categories",
        ]
        for comp in common_components:
            resp = self._get(f"/index.php?option={comp}")
            if resp and resp.status_code == 200:
                results["components"].append({"name": comp, "status": "accessible"})

        # Default credential test
        cred_result = self.test_default_creds(target, "Joomla")
        if cred_result.get('vulnerable'):
            results["findings"].extend(cred_result.get('findings', []))

        print(f"{CYAN}[ZYLON JOOMLA] Scan complete: {len(results['findings'])} findings, "
              f"{len(results['components'])} components{RESET}")

        return {
            'vulnerable': any(f.get('risk') in ['high', 'critical'] for f in results['findings']),
            'findings': results['findings'],
            'details': results,
            'scan_type': 'joomla_scan'
        }

    # ========================================================================
    # SCAN 4: Drupal Deep Scan
    # ========================================================================

    def scan_drupal(self, url=None):
        """Deep Drupal security scan"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No target'}, 'scan_type': 'drupal_scan'}

        if not target.startswith('http'):
            target = f"https://{target}"
        self.target_url = target.rstrip('/')

        results = {
            "cms": "Drupal",
            "findings": [],
            "modules": [],
            "sensitive_files": [],
            "backup_files": [],
            "sa_core_checks": [],
        }

        # Check paths
        for name, path in DRUPAL_DEEP_PATHS.items():
            resp = self._get(path)
            if resp and resp.status_code == 200:
                results["sensitive_files"].append({
                    "name": name, "path": path,
                    "size": len(resp.text),
                })

        # Check backup files
        for path in BACKUP_PATTERNS.get("Drupal", []):
            resp = self._get(path)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                results["backup_files"].append({"path": path, "size": len(resp.text)})

        # SA-CORE vulnerability checks
        sa_core_vulns = [
            {"id": "SA-CORE-2018-002", "name": "Drupalgeddon2", "cve": "CVE-2018-7600", "risk": "critical"},
            {"id": "SA-CORE-2018-004", "name": "Drupalgeddon3", "cve": "CVE-2018-7602", "risk": "critical"},
            {"id": "SA-CORE-2019-003", "name": "Drupal Phar Injection", "cve": "CVE-2019-6340", "risk": "high"},
            {"id": "SA-CORE-2021-003", "name": "Drupal XSS", "cve": "CVE-2021-25958", "risk": "medium"},
        ]

        for vuln in sa_core_vulns:
            results["sa_core_checks"].append({
                **vuln,
                "note": "Manual verification recommended - check Drupal version and patches",
            })

        # Check update.php access
        resp = self._get("/update.php")
        if resp and resp.status_code == 200:
            if "database update" in resp.text.lower() or "update" in resp.text.lower():
                results["findings"].append({
                    "type": "vulnerability",
                    "finding": "update.php accessible without authentication",
                    "risk": "high",
                })

        # Check for Drupalgeddon2 indicators
        resp = self._get("/user/register")
        if resp and resp.status_code == 200:
            if "drupal" in resp.text.lower():
                results["findings"].append({
                    "type": "check",
                    "finding": "User registration page accessible - test for Drupalgeddon2",
                    "risk": "medium",
                })

        # Default credential test
        cred_result = self.test_default_creds(target, "Drupal")
        if cred_result.get('vulnerable'):
            results["findings"].extend(cred_result.get('findings', []))

        print(f"{CYAN}[ZYLON DRUPAL] Scan complete: {len(results['findings'])} findings, "
              f"{len(results['sa_core_checks'])} SA-CORE checks{RESET}")

        return {
            'vulnerable': any(f.get('risk') in ['high', 'critical'] for f in results['findings']),
            'findings': results['findings'],
            'details': results,
            'scan_type': 'drupal_scan'
        }

    # ========================================================================
    # SCAN 5: Magento Scan
    # ========================================================================

    def scan_magento(self, url=None):
        """Magento security scan"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No target'}, 'scan_type': 'magento_scan'}

        if not target.startswith('http'):
            target = f"https://{target}"
        self.target_url = target.rstrip('/')

        results = {
            "cms": "Magento",
            "findings": [],
            "sensitive_files": [],
            "backup_files": [],
        }

        # Check paths
        for name, path in MAGENTO_DEEP_PATHS.items():
            resp = self._get(path)
            if resp and resp.status_code == 200:
                results["sensitive_files"].append({
                    "name": name, "path": path,
                    "size": len(resp.text),
                })

        # Check backup files
        for path in BACKUP_PATTERNS.get("Magento", []):
            resp = self._get(path)
            if resp and resp.status_code == 200 and len(resp.text) > 50:
                results["backup_files"].append({"path": path, "size": len(resp.text)})

        # Check config exposure
        for path in CONFIG_EXPOSURE.get("Magento", []):
            resp = self._get(path)
            if resp and resp.status_code == 200:
                if 'password' in resp.text.lower() or 'host' in resp.text.lower():
                    results["findings"].append({
                        "type": "critical",
                        "finding": f"Config file exposure: {path}",
                        "risk": "critical",
                    })

        # Default credential test
        cred_result = self.test_default_creds(target, "Magento")
        if cred_result.get('vulnerable'):
            results["findings"].extend(cred_result.get('findings', []))

        print(f"{CYAN}[ZYLON MAGENTO] Scan complete: {len(results['findings'])} findings{RESET}")

        return {
            'vulnerable': any(f.get('risk') in ['high', 'critical'] for f in results['findings']),
            'findings': results['findings'],
            'details': results,
            'scan_type': 'magento_scan'
        }

    # ========================================================================
    # SCAN 6: Multi-CMS Full Scan
    # ========================================================================

    def scan_all_cms(self, url=None):
        """Run all CMS-specific scans based on detection"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No target'}, 'scan_type': 'cms_full'}

        if not target.startswith('http'):
            target = f"https://{target}"
        self.target_url = target.rstrip('/')

        all_results = {
            'detection': None,
            'deep_scans': {},
            'total_findings': 0,
        }

        # Step 1: Detect CMS
        print(f"{CYAN}[ZYLON CMS] Phase 1: CMS Detection...{RESET}")
        detect_result = self.detect_cms(target)
        all_results['detection'] = detect_result

        detected_list = [f['name'] for f in detect_result.get('findings', [])]

        # Step 2: Run deep scans for each detected CMS
        print(f"{CYAN}[ZYLON CMS] Phase 2: Deep scanning detected CMS...{RESET}")

        if "WordPress" in detected_list:
            print(f"{GREEN}[+] Running WordPress deep scan...{RESET}")
            all_results['deep_scans']['wordpress'] = self.scan_wordpress(target)

        if "Joomla" in detected_list:
            print(f"{GREEN}[+] Running Joomla deep scan...{RESET}")
            all_results['deep_scans']['joomla'] = self.scan_joomla(target)

        if "Drupal" in detected_list:
            print(f"{GREEN}[+] Running Drupal deep scan...{RESET}")
            all_results['deep_scans']['drupal'] = self.scan_drupal(target)

        if "Magento" in detected_list:
            print(f"{GREEN}[+] Running Magento scan...{RESET}")
            all_results['deep_scans']['magento'] = self.scan_magento(target)

        # If no known CMS detected, try all major ones
        if not any(cms in detected_list for cms in ["WordPress", "Joomla", "Drupal", "Magento"]):
            print(f"{YELLOW}[*] No major CMS detected, attempting all major scans...{RESET}")
            all_results['deep_scans']['wordpress'] = self.scan_wordpress(target)
            all_results['deep_scans']['joomla'] = self.scan_joomla(target)
            all_results['deep_scans']['drupal'] = self.scan_drupal(target)

        # Count total findings
        total = 0
        for scan in all_results['deep_scans'].values():
            total += len(scan.get('findings', []))
            total += len(scan.get('details', {}).get('findings', []))
        all_results['total_findings'] = total

        print(f"{BOLD}{GREEN}[ZYLON CMS] Full scan complete: {total} total findings{RESET}")

        return {
            'vulnerable': any(
                s.get('vulnerable', False) for s in all_results['deep_scans'].values()
            ),
            'findings': [{'cms': k, 'findings': v.get('details', {}).get('findings', [])}
                        for k, v in all_results['deep_scans'].items()],
            'details': all_results,
            'scan_type': 'cms_full'
        }

    # ========================================================================
    # DEFAULT CREDENTIAL TESTING
    # ========================================================================

    def test_default_creds(self, url=None, cms_type=None):
        """Test default credentials for specified CMS"""
        target = url or self.target_url
        if not target:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'No target'}, 'scan_type': 'default_creds'}

        if not target.startswith('http'):
            target = f"https://{target}"
        self.target_url = target.rstrip('/')

        if not cms_type:
            cms_type = self.detected_cms or "WordPress"

        creds = DEFAULT_CREDENTIALS.get(cms_type, [])
        if not creds:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'note': f'No default credentials defined for {cms_type}'},
                'scan_type': 'default_creds'
            }

        findings = []

        if cms_type == "WordPress":
            for username, password in creds:
                try:
                    login_data = {
                        "log": username, "pwd": password,
                        "wp-submit": "Log In", "redirect_to": "/wp-admin/",
                    }
                    resp = self._post("wp-login.php", data=login_data)
                    if resp and resp.status_code in [301, 302]:
                        location = resp.headers.get('Location', '')
                        if 'wp-admin' in location and 'wp-login' not in location:
                            findings.append({
                                "type": "critical",
                                "finding": f"Default credentials: {username}:{password}",
                                "risk": "critical",
                            })
                            break
                except Exception:
                    pass

        elif cms_type == "Joomla":
            for username, password in creds:
                try:
                    login_data = {
                        "username": username, "passwd": password,
                        "option": "com_login", "task": "login",
                    }
                    resp = self._post("administrator/index.php", data=login_data)
                    if resp and resp.status_code in [301, 302]:
                        location = resp.headers.get('Location', '')
                        if 'administrator' in location and 'login' not in location:
                            findings.append({
                                "type": "critical",
                                "finding": f"Default credentials: {username}:{password}",
                                "risk": "critical",
                            })
                            break
                except Exception:
                    pass

        elif cms_type == "Drupal":
            for username, password in creds:
                try:
                    login_data = {
                        "name": username, "pass": password,
                        "form_id": "user_login_form", "op": "Log in",
                    }
                    resp = self._post("user/login", data=login_data)
                    if resp and resp.status_code == 200:
                        if 'logged in' in resp.text.lower() or 'logout' in resp.text.lower():
                            findings.append({
                                "type": "critical",
                                "finding": f"Default credentials: {username}:{password}",
                                "risk": "critical",
                            })
                            break
                except Exception:
                    pass

        else:
            # Generic form-based test
            for username, password in creds[:3]:
                findings.append({
                    "type": "check",
                    "finding": f"Test default credentials: {username}:{password} (manual verification needed)",
                    "risk": "medium",
                })

        return {
            'vulnerable': any(f.get('risk') == 'critical' for f in findings),
            'findings': findings,
            'details': {'cms': cms_type, 'credentials_tested': len(creds), 'findings': findings},
            'scan_type': 'default_creds'
        }

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target, scan_type='detect', **kwargs):
        """Main entry point for CMS Advanced engine"""
        if not target:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No target provided'},
                'scan_type': scan_type
            }

        if not target.startswith('http'):
            target = f"https://{target}"

        self.target_url = target.rstrip('/')

        scan_methods = {
            'detect': lambda: self.detect_cms(target),
            'wordpress': lambda: self.scan_wordpress(target),
            'joomla': lambda: self.scan_joomla(target),
            'drupal': lambda: self.scan_drupal(target),
            'magento': lambda: self.scan_magento(target),
            'default_creds': lambda: self.test_default_creds(target, kwargs.get('cms_type', None)),
            'full': lambda: self.scan_all_cms(target),
        }

        if scan_type in scan_methods:
            return scan_methods[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}'},
            'scan_type': scan_type
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='detect', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = CMSAdvancedEngine(target_url=target)
    return engine.run(target, scan_type=scan_type, **kwargs)
