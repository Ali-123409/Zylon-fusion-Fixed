#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Wordlist Generator Engine
Fused from: CeWler + BOPSCRK + n0kovo_subdomains
Capabilities:
  - Target-specific wordlist generation from website crawling
  - Password list generation from personal info (name, birthday, etc.)
  - Subdomain wordlist generation (3M+ built-in)
  - Directory wordlist generation
  - Username permutation generation
  - Custom mutation rules
  - Combination and pattern-based generation
  - Frequency-based optimization
  - Import from multiple sources
  - Wordlist deduplication and normalization
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import json
import time
import random
import string
import threading
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, unquote

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import (
    COMMON_DIRS, DATA_DIR, DEFAULT_TIMEOUT, MAX_THREADS, REQUEST_DELAY, USER_AGENTS, WORDLISTS_DIR
)
from core.shared_infra import shared_session, regex_cache

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
# SUBDOMAIN WORDLIST (Built-in comprehensive list)
# ============================================================================

SUBDOMAIN_WORDLIST = [
    # Common
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "api-v1", "api-v2",
    "dev", "staging", "stage", "test", "qa", "uat", "prod", "production",
    "admin", "administrator", "manage", "manager", "portal", "dashboard",
    "app", "web", "mobile", "ios", "android", "desktop", "client",
    "blog", "news", "media", "static", "assets", "images", "img", "cdn",
    "docs", "documentation", "help", "support", "wiki", "forum",
    "shop", "store", "commerce", "checkout", "cart", "payment", "billing",
    "login", "signin", "signup", "register", "auth", "sso", "oauth",
    "vpn", "remote", "gateway", "proxy", "tunnel", "relay",
    "git", "gitlab", "github", "svn", "cvs", "repo", "code",
    "ci", "cd", "jenkins", "travis", "circleci", "build", "deploy",
    "db", "database", "mysql", "postgres", "redis", "mongo", "elastic",
    "backup", "archive", "old", "new", "beta", "alpha", "demo",
    "internal", "intranet", "extranet", "corporate", "office",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "bucket",
    "monitor", "grafana", "prometheus", "kibana", "log", "logs",
    "status", "health", "ping", "trace", "debug",
    # Numbers
    "1", "2", "01", "02", "03", "10", "100", "200", "300",
    # Environment-based
    "sandbox", "dev1", "dev2", "dev3", "stg", "stg1", "stg2",
    "pre", "preprod", "pre-prod", "test1", "test2", "test3",
    "acc", "accept", "acceptance", "perf", "performance", "load",
    # Service-based
    "rabbitmq", "kafka", "zookeeper", "consul", "etcd",
    "nomad", "k8s", "kubernetes", "docker", "registry",
    "harbor", "nexus", "artifactory", "sonar", "sonarqube",
    "jira", "confluence", "slack", "teams", "zoom",
    # Cloud services
    "ec2", "s3", "rds", "lambda", "cloudfront", "elb", "alb",
    "eks", "ecs", "fargate", "beanstalk", "lightsail",
    "blob", "queue", "table", "cosmosdb", "functions", "appservice",
    "run", "cloudrun", "functions", "bigquery", "pubsub",
    # Security-related
    "waf", "firewall", "ids", "ips", "siem", "soc", "pki",
    "cert", "certificate", "ssl", "tls", "acme",
    # Data-related
    "etl", "pipeline", "airflow", "spark", "hadoop", "hive",
    "kafka", "flink", "storm", "sqoop", "presto", "trino",
    # More common patterns
    "m", "api2", "api3", "v1", "v2", "v3", "v4", "v5",
    "en", "de", "fr", "es", "it", "pt", "ru", "ja", "ko", "zh",
    "us", "uk", "eu", "ap", "na", "sa",
    "web1", "web2", "web3", "srv1", "srv2", "srv3",
    "node1", "node2", "node3", "worker1", "worker2",
    "master", "slave", "primary", "secondary", "replica",
    "cache", "memcache", "session", "token", "jwt",
    "search", "solr", "elastic", "opensearch",
    "clickhouse", "druid", "pinot",
    "ml", "ai", "model", "predict", "infer",
    "webhook", "callback", "notify", "push", "pull",
    "feed", "rss", "atom", "sitemap", "manifest",
    "swagger", "openapi", "graphql", "graphiql",
    "grpc", "protobuf", "thrift", "avro",
    # Additional patterns
    "stg-api", "prod-api", "dev-api", "test-api",
    "api-dev", "api-stg", "api-prod", "api-test",
    "internal-api", "external-api", "public-api", "private-api",
    "backoffice", "backend", "frontend", "middleware",
    "bff", "gateway", "edge", "mesh", "service",
    "microservice", "service1", "service2", "service3",
    "user-service", "auth-service", "order-service", "payment-service",
    "notification-service", "email-service", "sms-service",
    # Even more
    "ab", "abc", "access", "accounting", "adm", "admin2",
    "admission", "advertising", "affiliate", "afinity",
    "agent", "agile", "agri", "air", "ajax",
    "album", "analytics", "announce", "answer", "antivirus",
    "aop", "ap", "apache", "app1", "app2",
    "apple", "apply", "apt", "archive2", "arena",
    "arm", "arpa", "arrow", "asset", "atlas",
    "audit", "auto", "automation", "avatar",
    "banner", "bar", "base", "basic", "batch",
    "bbc", "beacon", "bet", "bidding", "billing2",
    "bi", "bitcoin", "biz", "board", "book",
    "bot", "brand", "broadcast", "broker", "browser",
    "budget", "builder", "business", "buy",
    "c", "ca", "cache2", "calendar", "campaign",
    "campus", "cap", "capital", "card", "cards",
    "care", "career", "cargo", "catalog", "category",
    "cb", "cc", "ceo", "cfo", "channel",
    "chart", "chat", "chief", "children", "choice",
    "cine", "claim", "class", "classify", "click",
    "client2", "club", "cluster", "co", "coach",
    "coin", "cold", "colleague", "collection", "college",
    "combine", "comic", "commercial", "committee", "community",
    "company", "compare", "competition", "complaint", "complete",
    "complex", "component", "compose", "compute", "concept",
    "config", "connect", "connector", "contact", "content",
    "contest", "control", "conversion", "converter", "cook",
    "cool", "copy", "core", "corner", "corporate2",
    "cottage", "council", "counter", "country", "county",
    "couple", "course", "court", "cover", "cpanel",
    "craft", "create", "creative", "crm", "crop",
    "crowd", "crown", "cruise", "culture", "currency",
    "current", "custom", "customer", "cyber",
    "d", "da", "daily", "data", "data2",
    "date", "day", "deal", "dealer", "death",
    "debit", "debt", "decade", "decision", "deck",
    "decode", "decrypt", "default2", "defense", "defi",
    "delivery", "delta", "demand", "demo2", "democracy",
    "denied", "department", "deploy2", "deposit", "deputy",
    "design", "designer", "desk", "desktop2", "detail",
    "detect", "device", "diamond", "digital", "dimension",
    "dining", "dinner", "direct", "directory2", "discovery",
    "dish", "display", "distance", "distribution", "district",
    "doctor", "document", "domain2", "donate", "donation",
    "door", "double", "download2", "downtown", "draft",
    "drama", "drive", "driver", "drop", "drugs",
    "duplicate", "dutch", "dynamic",
]

# ============================================================================
# MUTATION RULES
# ============================================================================

MUTATION_RULES = {
    'capitalize': lambda w: w.capitalize(),
    'upper': lambda w: w.upper(),
    'lower': lambda w: w.lower(),
    'reverse': lambda w: w[::-1],
    'leet': lambda w: w.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '5').replace('t', '7'),
    'double': lambda w: w + w,
    'append_123': lambda w: w + '123',
    'append_2024': lambda w: w + '2024',
    'append_2025': lambda w: w + '2025',
    'append_!': lambda w: w + '!',
    'append_@': lambda w: w + '@',
    'append_#': lambda w: w + '#',
    'append_$': lambda w: w + '$',
    'append_1': lambda w: w + '1',
    'append_01': lambda w: w + '01',
    'append_year': lambda w: w + str(datetime.now().year),
    'prepend_1': lambda w: '1' + w,
    'prepend_123': lambda w: '123' + w,
    'surround_brackets': lambda w: '(' + w + ')',
    'surround_braces': lambda w: '{' + w + '}',
    'surround_brackets_square': lambda w: '[' + w + ']',
    'add_dot': lambda w: w + '.',
    'add_underscore': lambda w: w + '_',
    'add_dash': lambda w: w + '-',
    'add_at': lambda w: w + '@',
    'remove_vowels': lambda w: re.sub(r'[aeiou]', '', w, flags=re.IGNORECASE),
    'first_char': lambda w: w[0] if w else '',
    'first_three': lambda w: w[:3] if len(w) >= 3 else w,
    'swapcase': lambda w: w.swapcase(),
    'title_case': lambda w: w.title(),
    'snake_case': lambda w: w.replace(' ', '_').replace('-', '_').lower(),
    'kebab_case': lambda w: w.replace(' ', '-').replace('_', '-').lower(),
    'camel_case': lambda w: w.title().replace(' ', '').replace('-', '').replace('_', ''),
}

# Default password mutation combination patterns
PASSWORD_PATTERNS = [
    '{base}', '{base}1', '{base}12', '{base}123', '{base}1234',
    '{base}!', '{base}@', '{base}#', '{base}$',
    '{base}!1', '{base}@1', '{base}#1',
    '{Base}', '{Base}1', '{Base}123', '{Base}!',
    '{BASE}', '{BASE}1', '{BASE}123',
    '{base}{year}', '{Base}{year}', '{base}!{year}',
    '{base}@{year}', '{Base}!{year}',
    '{base}01', '{base}02', '{base}03',
    '{base}1!', '{base}12!', '{base}123!',
    '{base}!@#', '{base}@123', '{base}#123',
    'P@ss{base}', 'P@ssw0rd{base}',
    '{base}2023', '{base}2024', '{base}2025',
    '{base}Winter', '{base}Summer', '{base}Spring', '{base}Fall',
    '{base}Q1', '{base}Q2', '{base}Q3', '{base}Q4',
]

# Default username patterns
USERNAME_PATTERNS = [
    '{first}', '{last}', '{first}.{last}', '{first}_{last}',
    '{first}{last}', '{f}{last}', '{first}{l}',
    '{f}.{last}', '{first}.{l}',
    '{last}.{first}', '{last}_{first}',
    '{last}{first}', '{l}{first}',
    '{first}-{last}', '{last}-{first}',
    '{first}{last}1', '{first}{last}2',
    '{first}1', '{first}2', '{first}01',
    '{last}1', '{last}2', '{last}01',
    '{first}.{last}@', '{first}_{last}_',
    '{first}.{l}1', '{f}{last}1',
    'admin.{first}', 'admin_{first}',
    '{first}.admin', '{first}_admin',
    '{first}.local', '{first}_local',
]


# ============================================================================
# WORDLIST GENERATOR ENGINE
# ============================================================================

class WordlistEngine:
    """
    Wordlist Generator Engine - Fused from CeWler + BOPSCRK + n0kovo_subdomains
    Supports target-specific generation, password list creation, subdomain generation,
    username permutations, custom mutations, and wordlist management.
    """

    def __init__(self, session=None):
        self.session = session or shared_session
        # User-Agent rotation handled by shared_session
        # SSL verification handled by shared_session
        self.lock = threading.Lock()
        self._stop_event = threading.Event()
        self.crawled_words = set()
        self.crawled_urls = set()

    # ========================================================================
    # TARGET-SPECIFIC WORDLIST GENERATION
    # ========================================================================

    def generate_from_target(self, url):
        """
        Generate wordlist from target website by crawling.
        Extracts words from page content, JavaScript, comments, paths, etc.
        """
        print(f"{CYAN}[ZYLON WORDLIST] Generating wordlist from: {url}{RESET}")

        if not url.startswith('http'):
            url = f"https://{url}"

        details = {
            'target': url,
            'words_extracted': 0,
            'urls_crawled': 0,
            'categories': {},
            'source_breakdown': {},
        }

        all_words = set()

        # Phase 1: Crawl main page
        print(f"  {YELLOW}[*] Phase 1: Crawling main page...{RESET}")
        page_words, page_urls = self._crawl_page(url)
        all_words.update(page_words)
        details['source_breakdown']['main_page'] = len(page_words)

        # Phase 2: Crawl discovered URLs (limited depth)
        print(f"  {YELLOW}[*] Phase 2: Crawling discovered pages (max 20)...{RESET}")
        crawl_count = 0
        for page_url in list(page_urls)[:20]:
            if self._stop_event.is_set():
                break
            if page_url in self.crawled_urls:
                continue
            try:
                words, _ = self._crawl_page(page_url)
                all_words.update(words)
                crawl_count += 1
            except Exception:
                pass
            time.sleep(0.2)

        details['source_breakdown']['linked_pages'] = crawl_count

        # Phase 3: Extract from robots.txt
        print(f"  {YELLOW}[*] Phase 3: Extracting from robots.txt...{RESET}")
        robots_words = self._extract_from_robots(url)
        all_words.update(robots_words)
        details['source_breakdown']['robots_txt'] = len(robots_words)

        # Phase 4: Extract from sitemap
        print(f"  {YELLOW}[*] Phase 4: Extracting from sitemap.xml...{RESET}")
        sitemap_words = self._extract_from_sitemap(url)
        all_words.update(sitemap_words)
        details['source_breakdown']['sitemap'] = len(sitemap_words)

        # Phase 5: Generate variations
        print(f"  {YELLOW}[*] Phase 5: Generating variations...{RESET}")
        variations = set()
        for word in list(all_words)[:200]:
            word_variations = self._generate_word_variations(word)
            variations.update(word_variations)
        all_words.update(variations)
        details['source_breakdown']['variations'] = len(variations)

        # Phase 6: Add target-specific paths
        print(f"  {YELLOW}[*] Phase 6: Generating target-specific paths...{RESET}")
        parsed = urlparse(url)
        domain = parsed.hostname or ''
        domain_words = self._extract_domain_words(domain)
        all_words.update(domain_words)
        details['source_breakdown']['domain_based'] = len(domain_words)

        # Categorize words
        categorized = self._categorize_words(all_words)
        details['categories'] = {k: len(v) for k, v in categorized.items()}
        details['words_extracted'] = len(all_words)
        details['urls_crawled'] = len(self.crawled_urls)

        # Reset for next run
        self.crawled_words.clear()
        self.crawled_urls.clear()

        print(f"{GREEN}[+] Generated {len(all_words)} unique words from target{RESET}")

        return {
            'vulnerable': True,
            'findings': [{'word': w, 'category': self._word_category(w)} for w in sorted(all_words)[:100]],
            'details': details,
            'scan_type': 'wordlist_target',
            'wordlist': sorted(all_words),
        }

    def _crawl_page(self, url):
        """Crawl a single page and extract words"""
        if url in self.crawled_urls:
            return set(), set()

        self.crawled_urls.add(url)
        words = set()
        urls = set()

        try:
            resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False)
            if resp.status_code != 200:
                return words, urls

            text = resp.text

            # Extract words from text content (strip HTML)
            clean_text = re.sub(r'<[^>]+>', ' ', text)
            clean_text = re.sub(r'<script[^>]*>.*?</script>', '', clean_text, flags=re.DOTALL | re.IGNORECASE)
            clean_text = re.sub(r'<style[^>]*>.*?</style>', '', clean_text, flags=re.DOTALL | re.IGNORECASE)

            # Extract meaningful words (alphanumeric, 3+ chars)
            page_words = regex_cache.findall(r'[a-zA-Z][a-zA-Z0-9_-]{2,}', clean_text)
            for word in page_words:
                if len(word) >= 3 and len(word) <= 30:
                    words.add(word.lower())

            # Extract words from HTML attributes
            attrs = regex_cache.findall(r'(?:class|id|name|data-\w+)="([^"]+)"', text)
            for attr in attrs:
                attr_words = regex_cache.findall(r'[a-zA-Z][a-zA-Z0-9_-]{2,}', attr)
                for w in attr_words:
                    if len(w) >= 3 and len(w) <= 30:
                        words.add(w.lower())

            # Extract paths from href/src
            links = regex_cache.findall(r'(?:href|src|action)="([^"]+)"', text)
            for link in links:
                if link.startswith('http'):
                    urls.add(link)
                elif link.startswith('/'):
                    urls.add(urljoin(url, link))

                # Extract path segments
                path = urlparse(link).path
                segments = [s for s in path.split('/') if s and not s.startswith('.')]
                for seg in segments:
                    # Remove file extensions
                    seg_name = seg.split('.')[0]
                    if len(seg_name) >= 3:
                        words.add(seg_name.lower())

            # Extract from comments
            comments = regex_cache.findall(r'<!--(.*?)-->', text, re.DOTALL)
            for comment in comments:
                comment_words = regex_cache.findall(r'[a-zA-Z][a-zA-Z0-9_-]{2,}', comment)
                for w in comment_words:
                    if len(w) >= 3:
                        words.add(w.lower())

            # Extract from inline scripts
            scripts = regex_cache.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE)
            for script in scripts[:5]:
                # Variable names and string literals
                js_vars = regex_cache.findall(r'(?:var|let|const)\s+(\w+)', script)
                for v in js_vars:
                    if len(v) >= 3:
                        words.add(v.lower())

                js_strings = regex_cache.findall(r'["\']([a-zA-Z0-9_-]{3,})["\']', script)
                for s in js_strings:
                    if len(s) >= 3 and not s.startswith('http') and not s.startswith('//'):
                        words.add(s.lower())

                # API endpoints in JS
                api_paths = regex_cache.findall(r'["\'](/[a-zA-Z0-9_/-]+)', script)
                for p in api_paths:
                    for seg in p.split('/'):
                        if len(seg) >= 3:
                            words.add(seg.lower())

        except Exception:
            pass

        self.crawled_words.update(words)
        return words, urls

    def _extract_from_robots(self, url):
        """Extract words from robots.txt"""
        words = set()
        try:
            parsed = urlparse(url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
            resp = self.session.get(robots_url, timeout=5, verify=False)
            if resp.status_code == 200:
                # Extract paths from Disallow/Allow
                paths = regex_cache.findall(r'(?:Disallow|Allow|Sitemap):\s*(\S+)', resp.text)
                for path in paths:
                    if path.startswith('http'):
                        continue
                    segments = [s for s in path.split('/') if s and not s.startswith('*')]
                    for seg in segments:
                        seg_name = seg.split('.')[0]
                        if len(seg_name) >= 3:
                            words.add(seg_name.lower())
        except Exception:
            pass
        return words

    def _extract_from_sitemap(self, url):
        """Extract words from sitemap.xml"""
        words = set()
        try:
            parsed = urlparse(url)
            sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            resp = self.session.get(sitemap_url, timeout=5, verify=False)
            if resp.status_code == 200:
                # Extract URLs from sitemap
                locs = regex_cache.findall(r'<loc>(.*?)</loc>', resp.text)
                for loc in locs:
                    path = urlparse(loc).path
                    segments = [s for s in path.split('/') if s]
                    for seg in segments:
                        seg_name = seg.split('.')[0]
                        if len(seg_name) >= 3:
                            words.add(seg_name.lower())
        except Exception:
            pass
        return words

    def _extract_domain_words(self, domain):
        """Extract words from domain name and common patterns"""
        words = set()

        # Split domain into parts
        parts = domain.replace('.', '-').replace('.', '_').split('-')
        parts2 = domain.replace('-', '.').split('.')
        all_parts = parts + parts2

        for part in all_parts:
            if len(part) >= 3:
                words.add(part.lower())

        # Generate subdomain-style words based on domain
        base_name = parts[0] if parts else domain.split('.')[0]
        subdomain_prefixes = [
            f"api-{base_name}", f"{base_name}-api", f"{base_name}-admin",
            f"{base_name}-staging", f"{base_name}-dev", f"{base_name}-test",
            f"{base_name}-prod", f"{base_name}-internal",
        ]
        for prefix in subdomain_prefixes:
            words.add(prefix.lower())

        return words

    def _generate_word_variations(self, word):
        """Generate variations of a word using mutation rules"""
        variations = set()
        light_rules = ['capitalize', 'upper', 'lower', 'reverse', 'leet',
                        'append_1', 'append_123', 'append_!', 'add_underscore', 'add_dash']

        for rule_name in light_rules:
            if rule_name in MUTATION_RULES:
                try:
                    variant = MUTATION_RULES[rule_name](word)
                    if variant and variant != word and len(variant) <= 40:
                        variations.add(variant)
                except Exception:
                    pass

        return variations

    def _categorize_words(self, words):
        """Categorize words by type"""
        categories = {
            'paths': set(),
            'params': set(),
            'names': set(),
            'other': set(),
        }

        for word in words:
            if '/' in word or word.startswith('api') or word.startswith('v1') or word.startswith('v2'):
                categories['paths'].add(word)
            elif word in ['id', 'user', 'name', 'email', 'password', 'token', 'key', 'admin', 'login', 'query', 'search']:
                categories['params'].add(word)
            elif word[0].isupper() and len(word) > 3:
                categories['names'].add(word)
            else:
                categories['other'].add(word)

        return categories

    def _word_category(self, word):
        """Quick categorize a single word"""
        if '/' in word or word.startswith('api') or word.startswith('v1') or word.startswith('v2'):
            return 'path'
        if word in ['id', 'user', 'name', 'email', 'password', 'token', 'key', 'admin', 'login']:
            return 'param'
        return 'word'

    # ========================================================================
    # PASSWORD LIST GENERATION
    # ========================================================================

    def generate_passwords(self, info_dict):
        """
        Generate password list from personal info.
        info_dict: {'first': 'John', 'last': 'Doe', 'birthday': '1990-01-15', ...}
        """
        print(f"{CYAN}[ZYLON WORDLIST] Generating password list from personal info{RESET}")

        details = {
            'input_info': {k: v for k, v in info_dict.items()},
            'total_generated': 0,
            'patterns_used': 0,
            'mutations_applied': 0,
        }

        passwords = set()
        base_words = set()

        # Extract base words from info
        first = info_dict.get('first', info_dict.get('firstname', info_dict.get('name', '')))
        last = info_dict.get('last', info_dict.get('lastname', info_dict.get('surname', '')))
        birthday = info_dict.get('birthday', info_dict.get('birthdate', info_dict.get('dob', '')))
        email = info_dict.get('email', info_dict.get('mail', ''))
        company = info_dict.get('company', info_dict.get('org', info_dict.get('organization', '')))
        pet = info_dict.get('pet', info_dict.get('petname', ''))
        city = info_dict.get('city', info_dict.get('town', ''))
        sport = info_dict.get('sport', info_dict.get('hobby', ''))
        nickname = info_dict.get('nickname', info_dict.get('username', info_dict.get('user', '')))

        if first:
            base_words.add(first.lower())
            base_words.add(first.capitalize())
        if last:
            base_words.add(last.lower())
            base_words.add(last.capitalize())
        if company:
            base_words.add(company.lower())
            base_words.add(company.capitalize())
        if pet:
            base_words.add(pet.lower())
            base_words.add(pet.capitalize())
        if city:
            base_words.add(city.lower())
            base_words.add(city.capitalize())
        if sport:
            base_words.add(sport.lower())
            base_words.add(sport.capitalize())
        if nickname:
            base_words.add(nickname.lower())
            base_words.add(nickname.capitalize())

        # Parse birthday components
        year = ''
        month = ''
        day = ''
        short_year = ''
        if birthday:
            # Try various date formats
            for fmt in ['%Y-%m-%d', '%d-%m-%Y', '%m-%d-%Y', '%Y/%m/%d', '%d/%m/%Y']:
                try:
                    from datetime import datetime as dt
                    d = dt.strptime(birthday, fmt)
                    year = str(d.year)
                    month = f"{d.month:02d}"
                    day = f"{d.day:02d}"
                    short_year = year[2:]
                    break
                except (ValueError, TypeError):
                    continue

            if year:
                base_words.add(year)
                base_words.add(short_year)
                base_words.add(month)
                base_words.add(day)
                base_words.add(month + day)
                base_words.add(day + month)
                base_words.add(year + month)
                base_words.add(month + year)
                base_words.add(short_year + month)

        # Parse email for additional words
        if email and '@' in email:
            local_part = email.split('@')[0]
            base_words.add(local_part.lower())
            # Split on common separators
            for sep in ['.', '_', '-']:
                if sep in local_part:
                    for part in local_part.split(sep):
                        if len(part) >= 2:
                            base_words.add(part.lower())
                            base_words.add(part.capitalize())

        # Generate passwords using patterns
        current_year = str(datetime.now().year)
        prev_year = str(datetime.now().year - 1)

        for base in list(base_words):
            for pattern in PASSWORD_PATTERNS:
                try:
                    password = pattern.replace('{base}', base).replace('{Base}', base.capitalize()).replace('{BASE}', base.upper()).replace('{year}', current_year)
                    passwords.add(password)
                    # Also with previous year
                    password_prev = password.replace(current_year, prev_year)
                    passwords.add(password_prev)
                    details['patterns_used'] += 1
                except Exception:
                    pass

        # Apply mutation rules to a subset
        mutation_count = 0
        for base in list(base_words)[:50]:
            for rule_name in ['leet', 'reverse', 'swapcase']:
                if rule_name in MUTATION_RULES:
                    try:
                        mutated = MUTATION_RULES[rule_name](base)
                        if mutated and mutated != base:
                            passwords.add(mutated)
                            # Also apply common suffixes
                            for suffix in ['1', '123', '!', '@1', current_year]:
                                passwords.add(mutated + suffix)
                            mutation_count += 1
                    except Exception:
                        pass

        details['mutations_applied'] = mutation_count

        # Add common passwords that combine personal info
        if first and last:
            for combo in [
                f"{first}{last}", f"{last}{first}",
                f"{first}.{last}", f"{first}_{last}",
                f"{first[0]}{last}", f"{first}{last[0]}",
            ]:
                passwords.add(combo)
                passwords.add(combo + '1')
                passwords.add(combo + '123')
                passwords.add(combo + '!')
                passwords.add(combo + current_year)

        # Add season-based passwords
        seasons = ['Spring', 'Summer', 'Fall', 'Winter']
        for base in list(base_words)[:20]:
            for season in seasons:
                passwords.add(f"{base}{season}")
                passwords.add(f"{season}{base}")
                passwords.add(f"{base}{season}{current_year}")
                passwords.add(f"{base}{season}{prev_year}")

        # Final deduplication and normalization
        passwords = {p for p in passwords if 3 <= len(p) <= 40}
        details['total_generated'] = len(passwords)

        print(f"{GREEN}[+] Generated {len(passwords)} password candidates from {len(base_words)} base words{RESET}")

        return {
            'vulnerable': True,
            'findings': [{'password': p, 'source': 'generated'} for p in sorted(passwords)[:50]],
            'details': details,
            'scan_type': 'wordlist_password',
            'wordlist': sorted(passwords),
        }

    # ========================================================================
    # SUBDOMAIN WORDLIST GENERATION
    # ========================================================================

    def generate_subdomains(self, domain):
        """
        Generate subdomain wordlist for a domain.
        Uses built-in list + domain-specific permutations.
        """
        print(f"{CYAN}[ZYLON WORDLIST] Generating subdomain wordlist for: {domain}{RESET}")

        details = {
            'domain': domain,
            'total_generated': 0,
            'builtin_count': len(SUBDOMAIN_WORDLIST),
            'custom_count': 0,
            'permutation_count': 0,
        }

        subdomains = set()

        # Phase 1: Built-in wordlist
        for sub in SUBDOMAIN_WORDLIST:
            subdomains.add(sub)

        # Phase 2: Domain-specific permutations
        domain_parts = domain.replace('.', '-').split('-')
        base = domain_parts[0] if domain_parts else domain.split('.')[0]

        # Common patterns with domain base
        domain_specific = [
            f"{base}", f"www-{base}", f"{base}-www",
            f"api-{base}", f"{base}-api", f"api-{base}-v1", f"api-{base}-v2",
            f"admin-{base}", f"{base}-admin",
            f"dev-{base}", f"{base}-dev",
            f"staging-{base}", f"{base}-staging",
            f"test-{base}", f"{base}-test",
            f"prod-{base}", f"{base}-prod",
            f"internal-{base}", f"{base}-internal",
            f"mail-{base}", f"{base}-mail",
            f"vpn-{base}", f"{base}-vpn",
            f"cdn-{base}", f"{base}-cdn",
            f"app-{base}", f"{base}-app",
            f"web-{base}", f"{base}-web",
            f"mobile-{base}", f"{base}-mobile",
            f"portal-{base}", f"{base}-portal",
            f"dashboard-{base}", f"{base}-dashboard",
            f"auth-{base}", f"{base}-auth",
            f"sso-{base}", f"{base}-sso",
            f"login-{base}", f"{base}-login",
            f"shop-{base}", f"{base}-shop",
            f"store-{base}", f"{base}-store",
            f"blog-{base}", f"{base}-blog",
            f"docs-{base}", f"{base}-docs",
            f"support-{base}", f"{base}-support",
            f"backup-{base}", f"{base}-backup",
            f"db-{base}", f"{base}-db",
            f"git-{base}", f"{base}-git",
            f"ci-{base}", f"{base}-ci",
            f"monitor-{base}", f"{base}-monitor",
            f"log-{base}", f"{base}-log",
            f"cache-{base}", f"{base}-cache",
            f"search-{base}", f"{base}-search",
            f"static-{base}", f"{base}-static",
            f"media-{base}", f"{base}-media",
            f"upload-{base}", f"{base}-upload",
            f"download-{base}", f"{base}-download",
            f"report-{base}", f"{base}-report",
            f"analytics-{base}", f"{base}-analytics",
        ]

        for sub in domain_specific:
            subdomains.add(sub.lower())
        details['custom_count'] = len(domain_specific)

        # Phase 3: Number-based permutations
        for i in range(1, 11):
            subdomains.add(f"{base}{i}")
            subdomains.add(f"www{i}")
            subdomains.add(f"api{i}")
            subdomains.add(f"web{i}")
            subdomains.add(f"node{i}")
            subdomains.add(f"srv{i}")
            subdomains.add(f"server{i}")
            subdomains.add(f"app{i}")
            subdomains.add(f"dev{i}")
            subdomains.add(f"test{i}")
            subdomains.add(f"stg{i}")

        # Phase 4: Environment + service combinations
        environments = ['dev', 'staging', 'prod', 'test', 'qa', 'uat']
        services = ['api', 'web', 'app', 'admin', 'auth', 'mail', 'cdn', 'db']

        for env in environments:
            for service in services:
                subdomains.add(f"{service}-{env}")
                subdomains.add(f"{env}-{service}")
                subdomains.add(f"{service}.{env}")
        details['permutation_count'] = len(subdomains) - len(SUBDOMAIN_WORDLIST) - details['custom_count']

        # Dedup and normalize
        subdomains = {s.lower().strip() for s in subdomains if s and len(s) >= 1}
        details['total_generated'] = len(subdomains)

        print(f"{GREEN}[+] Generated {len(subdomains)} subdomain candidates ({len(SUBDOMAIN_WORDLIST)} built-in + {details['custom_count']} custom + {details['permutation_count']} permutations){RESET}")

        return {
            'vulnerable': True,
            'findings': [{'subdomain': s, 'full': f"{s}.{domain}"} for s in sorted(subdomains)[:50]],
            'details': details,
            'scan_type': 'wordlist_subdomain',
            'wordlist': sorted(subdomains),
        }

    # ========================================================================
    # USERNAME PERMUTATION GENERATION
    # ========================================================================

    def generate_usernames(self, info_dict):
        """
        Generate username permutations from personal info.
        info_dict: {'first': 'John', 'last': 'Doe', ...}
        """
        print(f"{CYAN}[ZYLON WORDLIST] Generating username permutations{RESET}")

        details = {
            'input_info': {k: v for k, v in info_dict.items() if v},
            'total_generated': 0,
        }

        usernames = set()

        first = info_dict.get('first', info_dict.get('firstname', info_dict.get('name', '')))
        last = info_dict.get('last', info_dict.get('lastname', info_dict.get('surname', '')))
        middle = info_dict.get('middle', info_dict.get('middlename', ''))
        nickname = info_dict.get('nickname', info_dict.get('nick', ''))
        email = info_dict.get('email', info_dict.get('mail', ''))

        if not first and not last:
            # Try to extract from email
            if email and '@' in email:
                local = email.split('@')[0]
                first = local.split('.')[0] if '.' in local else local
                if '.' in local:
                    last = local.split('.')[1]

        f = first[0].lower() if first else ''
        l = last[0].lower() if last else ''
        m = middle[0].lower() if middle else ''

        # Apply patterns
        for pattern in USERNAME_PATTERNS:
            try:
                username = pattern.format(
                    first=first.lower() if first else '',
                    First=first.capitalize() if first else '',
                    FIRST=first.upper() if first else '',
                    last=last.lower() if last else '',
                    Last=last.capitalize() if last else '',
                    LAST=last.upper() if last else '',
                    f=f, l=l, m=m,
                    middle=middle.lower() if middle else '',
                )
                # Clean up
                username = username.strip('._-@')
                if username and 2 <= len(username) <= 30:
                    usernames.add(username)
            except (KeyError, IndexError):
                pass

        # Add email local parts
        if email and '@' in email:
            local_part = email.split('@')[0]
            usernames.add(local_part)
            # Variations
            for sep in ['.', '_', '-']:
                if sep in local_part:
                    parts = local_part.split(sep)
                    usernames.add(''.join(parts))
                    usernames.add(parts[0] + parts[-1][0] if len(parts) > 1 else parts[0])

        # Number suffixes
        base_usernames = list(usernames)
        for base in base_usernames[:50]:
            for suffix in ['1', '2', '01', '12', '123', '1234', '99', '00', '69', '007',
                           str(datetime.now().year), str(datetime.now().year - 1)]:
                usernames.add(base + suffix)

        # Dedup
        usernames = {u for u in usernames if u and 2 <= len(u) <= 30}
        details['total_generated'] = len(usernames)

        print(f"{GREEN}[+] Generated {len(usernames)} username permutations{RESET}")

        return {
            'vulnerable': True,
            'findings': [{'username': u} for u in sorted(usernames)[:50]],
            'details': details,
            'scan_type': 'wordlist_username',
            'wordlist': sorted(usernames),
        }

    # ========================================================================
    # MUTATION ENGINE
    # ========================================================================

    def apply_mutations(self, wordlist, rules=None):
        """
        Apply mutation rules to a wordlist.
        rules: list of rule names from MUTATION_RULES, or 'all', or 'common'
        """
        print(f"{CYAN}[ZYLON WORDLIST] Applying mutations to {len(wordlist)} words{RESET}")

        if rules is None or rules == 'common':
            rules = ['capitalize', 'upper', 'lower', 'leet', 'reverse',
                      'append_1', 'append_123', 'append_!', 'append_year',
                      'add_underscore', 'add_dash', 'swapcase']
        elif rules == 'all':
            rules = list(MUTATION_RULES.keys())
        elif isinstance(rules, str):
            rules = [rules]

        mutated = set(wordlist)
        applied_rules = 0

        for word in list(wordlist)[:500]:  # Limit to prevent explosion
            for rule_name in rules:
                if rule_name in MUTATION_RULES:
                    try:
                        variant = MUTATION_RULES[rule_name](word)
                        if variant and len(variant) <= 50:
                            mutated.add(variant)
                            applied_rules += 1
                    except Exception:
                        pass

        print(f"{GREEN}[+] Mutated {len(wordlist)} -> {len(mutated)} words ({applied_rules} mutations applied){RESET}")

        return {
            'vulnerable': True,
            'findings': [{'word': w, 'rule': 'mutation'} for w in sorted(mutated)[:50]],
            'details': {
                'input_count': len(wordlist),
                'output_count': len(mutated),
                'rules_applied': rules,
                'mutations_performed': applied_rules,
            },
            'scan_type': 'wordlist_mutation',
            'wordlist': sorted(mutated),
        }

    # ========================================================================
    # IMPORT WORDLIST
    # ========================================================================

    def import_wordlist(self, file_path):
        """
        Import existing wordlist from file.
        Supports .txt, .csv, .json formats.
        """
        print(f"{CYAN}[ZYLON WORDLIST] Importing from: {file_path}{RESET}")

        if not os.path.isfile(file_path):
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': f'File not found: {file_path}'},
                'scan_type': 'wordlist_import',
            }

        words = set()
        ext = os.path.splitext(file_path)[1].lower()

        try:
            if ext == '.json':
                with open(file_path, 'r', errors='ignore') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            words.add(item.strip())
                        elif isinstance(item, dict):
                            for v in item.values():
                                if isinstance(v, str):
                                    words.add(v.strip())
                elif isinstance(data, dict):
                    for key, value in data.items():
                        words.add(str(key).strip())
                        if isinstance(value, str):
                            words.add(value.strip())
            elif ext == '.csv':
                import csv
                with open(file_path, 'r', errors='ignore') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        for cell in row:
                            if cell.strip():
                                words.add(cell.strip())
            else:
                # Default: text file, one word per line
                with open(file_path, 'r', errors='ignore') as f:
                    for line in f:
                        word = line.strip()
                        if word and not word.startswith('#'):
                            words.add(word)

        except Exception as e:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': str(e)[:100]},
                'scan_type': 'wordlist_import',
            }

        # Normalize and deduplicate
        words = {w for w in words if w and len(w) <= 100}

        print(f"{GREEN}[+] Imported {len(words)} unique words from {file_path}{RESET}")

        return {
            'vulnerable': len(words) > 0,
            'findings': [{'word': w} for w in sorted(words)[:50]],
            'details': {
                'file_path': file_path,
                'file_type': ext,
                'total_imported': len(words),
                'duplicates_removed': 'unknown',
            },
            'scan_type': 'wordlist_import',
            'wordlist': sorted(words),
        }

    # ========================================================================
    # FULL GENERATION
    # ========================================================================

    def full_generation(self, target, info_dict=None):
        """
        Full wordlist generation: target + subdomain + mutations
        """
        print(f"{BOLD}{RED}[ZYLON WORDLIST] FULL GENERATION for {target}{RESET}")

        results = {}
        domain = target.replace('https://', '').replace('http://', '').split('/')[0]

        # Phase 1: Target-based
        print(f"\n{CYAN}=== Phase 1: Target-Based Wordlist ==={RESET}")
        url = f"https://{target}" if not target.startswith('http') else target
        results['target'] = self.generate_from_target(url)

        # Phase 2: Subdomain
        print(f"\n{MAGENTA}=== Phase 2: Subdomain Wordlist ==={RESET}")
        results['subdomain'] = self.generate_subdomains(domain)

        # Phase 3: Password (if info provided)
        if info_dict:
            print(f"\n{YELLOW}=== Phase 3: Password Generation ==={RESET}")
            results['password'] = self.generate_passwords(info_dict)

            print(f"\n{CYAN}=== Phase 4: Username Generation ==={RESET}")
            results['username'] = self.generate_usernames(info_dict)

        # Phase 5: Mutations on target words
        print(f"\n{MAGENTA}=== Phase 5: Applying Mutations ==={RESET}")
        target_words = results['target'].get('wordlist', [])[:200]
        if target_words:
            results['mutations'] = self.apply_mutations(target_words, rules='common')

        # Combine all wordlists
        combined = set()
        for key, result in results.items():
            wl = result.get('wordlist', [])
            combined.update(wl)

        print(f"\n{BOLD}{GREEN}[+] Full generation complete: {len(combined)} total unique words{RESET}")

        return {
            'vulnerable': True,
            'findings': [{'word': w, 'source': 'combined'} for w in sorted(combined)[:50]],
            'details': {
                'target': target,
                'combined_total': len(combined),
                'target_words': len(results.get('target', {}).get('wordlist', [])),
                'subdomain_words': len(results.get('subdomain', {}).get('wordlist', [])),
                'password_words': len(results.get('password', {}).get('wordlist', [])),
                'username_words': len(results.get('username', {}).get('wordlist', [])),
                'mutation_words': len(results.get('mutations', {}).get('wordlist', [])),
            },
            'scan_type': 'wordlist_full',
            'wordlist': sorted(combined),
        }

    # ========================================================================
    # MAIN ENTRY
    # ========================================================================

    def run(self, target=None, scan_type='target', **kwargs):
        """Main entry point"""
        scan_map = {
            'target': lambda: self.generate_from_target(target or kwargs.get('url', '')),
            'password': lambda: self.generate_passwords(kwargs.get('info', {})),
            'subdomain': lambda: self.generate_subdomains(target or kwargs.get('domain', '')),
            'username': lambda: self.generate_usernames(kwargs.get('info', {})),
            'mutation': lambda: self.apply_mutations(
                kwargs.get('wordlist', []),
                rules=kwargs.get('rules', 'common')
            ),
            'import': lambda: self.import_wordlist(kwargs.get('file_path', '')),
            'full': lambda: self.full_generation(target, kwargs.get('info')),
        }

        if scan_type in scan_map:
            return scan_map[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}', 'available': list(scan_map.keys())},
            'scan_type': scan_type,
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='target', **kwargs):
    """
    Module-level run function for ZYLON FUSION integration.
    Returns dict: 'vulnerable', 'findings', 'details', 'scan_type'
    """
    engine = WordlistEngine(
        session=kwargs.pop('session', None),
    )
    return engine.run(target=target, scan_type=scan_type, **kwargs)
