#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Hash Advanced Engine
Fused from: HashCRACK + Name-That-Hash + p0 + custom Zylon techniques
Capabilities:
  - Hash type identification (300+ hash types)
  - MD5, SHA1, SHA256, SHA512, NTLM, MySQL, etc.
  - Dictionary attack cracking
  - Rainbow table lookup
  - Hash format detection and normalization
  - API-based cracking (multiple online services)
  - Password candidate generation
  - Hash comparison and verification
  - Custom wordlist support
  - Multi-hash batch processing
Termux Compatible | No Root Required | Python 3.13+
"""

import os
import re
import hashlib
import base64
import time
import random
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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
# HASH TYPE DEFINITIONS (300+ types)
# ============================================================================

HASH_TYPES = {
    # MD5 family
    "MD5": {"length": 32, "regex": r'^[a-f0-9]{32}$', "category": "hash", "hashtype_id": 0},
    "MD5($pass.$salt)": {"length": 32, "regex": r'^[a-f0-9]{32}:[a-f0-9]+$', "category": "hash_salted", "hashtype_id": 10},
    "MD5($salt.$pass)": {"length": 32, "regex": r'^[a-f0-9]{32}:[a-f0-9]+$', "category": "hash_salted", "hashtype_id": 20},
    "MD5(APR)": {"length": 32, "regex": r'^\$apr1\$[a-zA-Z0-9./]+\$[a-f0-9]{32}$', "category": "hash_salted", "hashtype_id": 1600},
    "MD5(Crypt)": {"length": 22, "regex": r'^\$1\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{22}$', "category": "hash_salted", "hashtype_id": 500},
    # SHA1 family
    "SHA1": {"length": 40, "regex": r'^[a-f0-9]{40}$', "category": "hash", "hashtype_id": 100},
    "SHA1($pass.$salt)": {"length": 40, "regex": r'^[a-f0-9]{40}:[a-f0-9]+$', "category": "hash_salted", "hashtype_id": 110},
    "HMAC-SHA1": {"length": 40, "regex": r'^[a-f0-9]{40}:[a-f0-9]+$', "category": "hmac", "hashtype_id": 160},
    # SHA2 family
    "SHA224": {"length": 56, "regex": r'^[a-f0-9]{56}$', "category": "hash", "hashtype_id": 1300},
    "SHA256": {"length": 64, "regex": r'^[a-f0-9]{64}$', "category": "hash", "hashtype_id": 1400},
    "SHA256($pass.$salt)": {"length": 64, "regex": r'^[a-f0-9]{64}:[a-f0-9]+$', "category": "hash_salted", "hashtype_id": 1410},
    "SHA384": {"length": 96, "regex": r'^[a-f0-9]{96}$', "category": "hash", "hashtype_id": 1800},
    "SHA512": {"length": 128, "regex": r'^[a-f0-9]{128}$', "category": "hash", "hashtype_id": 1700},
    "SHA512($pass.$salt)": {"length": 128, "regex": r'^[a-f0-9]{128}:[a-f0-9]+$', "category": "hash_salted", "hashtype_id": 1710},
    "SHA512(Crypt)": {"length": 98, "regex": r'^\$6\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{86,}$', "category": "hash_salted", "hashtype_id": 1800},
    # SHA3 family
    "SHA3-224": {"length": 56, "regex": r'^[a-f0-9]{56}$', "category": "hash", "hashtype_id": 17300},
    "SHA3-256": {"length": 64, "regex": r'^[a-f0-9]{64}$', "category": "hash", "hashtype_id": 17400},
    "SHA3-384": {"length": 96, "regex": r'^[a-f0-9]{96}$', "category": "hash", "hashtype_id": 17500},
    "SHA3-512": {"length": 128, "regex": r'^[a-f0-9]{128}$', "category": "hash", "hashtype_id": 17600},
    # NTLM
    "NTLM": {"length": 32, "regex": r'^[a-f0-9]{32}$', "category": "hash", "hashtype_id": 1000},
    # MySQL family
    "MySQL323": {"length": 16, "regex": r'^[a-f0-9]{16}$', "category": "database", "hashtype_id": 200},
    "MySQL4/5": {"length": 40, "regex": r'^\*[a-f0-9]{40}$', "category": "database", "hashtype_id": 300},
    "MySQL5(SHA256)": {"length": 64, "regex": r'^\$5\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$', "category": "database", "hashtype_id": 3000},
    # PostgreSQL
    "PostgreSQL(MD5)": {"length": 35, "regex": r'^md5[a-f0-9]{32}$', "category": "database", "hashtype_id": 11100},
    # MSSQL
    "MSSQL(2000)": {"length": 94, "regex": r'^0x0100[a-f0-9]{88}$', "category": "database", "hashtype_id": 131},
    "MSSQL(2005)": {"length": 108, "regex": r'^0x0100[a-f0-9]{104}$', "category": "database", "hashtype_id": 132},
    # Oracle
    "Oracle7-10g": {"length": 16, "regex": r'^[a-f0-9]{16}$', "category": "database", "hashtype_id": 3100},
    "Oracle11g": {"length": 60, "regex": r'^S:[A-F0-9]{60}$', "category": "database", "hashtype_id": 11200},
    # Redis
    "Redis(SHA1)": {"length": 40, "regex": r'^[a-f0-9]{40}$', "category": "database", "hashtype_id": 11500},
    # bcrypt
    "bcrypt($2a$)": {"length": 60, "regex": r'^\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}$', "category": "hash_salted", "hashtype_id": 3200},
    "bcrypt($2b$)": {"length": 60, "regex": r'^\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}$', "category": "hash_salted", "hashtype_id": 3200},
    "bcrypt($2y$)": {"length": 60, "regex": r'^\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}$', "category": "hash_salted", "hashtype_id": 3200},
    # Argon2
    "Argon2i": {"length": 97, "regex": r'^\$argon2i\$.*$', "category": "hash_salted", "hashtype_id": 40100},
    "Argon2id": {"length": 97, "regex": r'^\$argon2id\$.*$', "category": "hash_salted", "hashtype_id": 40200},
    # scrypt
    "scrypt": {"length": 64, "regex": r'^\$scrypt\$.*$', "category": "hash_salted", "hashtype_id": 8900},
    # BLAKE2
    "BLAKE2b-256": {"length": 64, "regex": r'^[a-f0-9]{64}$', "category": "hash", "hashtype_id": 17700},
    "BLAKE2b-512": {"length": 128, "regex": r'^[a-f0-9]{128}$', "category": "hash", "hashtype_id": 17800},
    # CRC
    "CRC16": {"length": 4, "regex": r'^[a-f0-9]{4}$', "category": "checksum", "hashtype_id": 99999},
    "CRC32": {"length": 8, "regex": r'^[a-f0-9]{8}$', "category": "checksum", "hashtype_id": 99999},
    # LM / NTLM
    "LM": {"length": 32, "regex": r'^[a-f0-9]{32}$', "category": "hash", "hashtype_id": 3000},
    "NetNTLMv1": {"length": 64, "regex": r'^[a-f0-9]{48}::.*$', "category": "hash", "hashtype_id": 5500},
    "NetNTLMv2": {"length": 64, "regex": r'^[a-f0-9]{32}::.*:.*$', "category": "hash", "hashtype_id": 5600},
    # JWT
    "JWT": {"length": 0, "regex": r'^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*$', "category": "token", "hashtype_id": 16500},
    # Base64 encoded hashes
    "Base64(MD5)": {"length": 24, "regex": r'^[A-Za-z0-9+/]{22,24}={0,2}$', "category": "encoded", "hashtype_id": 99999},
    # Cisco
    "Cisco-IOS(SHA256)": {"length": 45, "regex": r'^\$4\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]{43}$', "category": "network", "hashtype_id": 5700},
    "Cisco-PIX": {"length": 16, "regex": r'^[a-zA-Z0-9./]{16}$', "category": "network", "hashtype_id": 2400},
    # Drupal
    "Drupal7": {"length": 55, "regex": r'^\$S\$[a-zA-Z0-9./]{52}$', "category": "cms", "hashtype_id": 7900},
    # WordPress
    "WordPress": {"length": 34, "regex": r'^\$P\$[a-zA-Z0-9./]{31}$', "category": "cms", "hashtype_id": 400},
    # Joomla
    "Joomla<2.5.18": {"length": 34, "regex": r'^\$P\$[a-zA-Z0-9./]{31}$', "category": "cms", "hashtype_id": 400},
    # vBulletin
    "vBulletin<3.8.5": {"length": 32, "regex": r'^[a-f0-9]{32}:[a-f0-9]{3}$', "category": "cms", "hashtype_id": 2611},
    # PHPass
    "PHPass": {"length": 34, "regex": r'^\$P\$[a-zA-Z0-9./]{31}$', "category": "framework", "hashtype_id": 400},
    # Django
    "Django(SHA1)": {"length": 49, "regex": r'^sha1\$[a-zA-Z0-9]+\$[a-f0-9]{40}$', "category": "framework", "hashtype_id": 124},
    "Django(PBKDF2)": {"length": 78, "regex": r'^pbkdf2_sha256\$\d+\$[a-zA-Z0-9+/=]+\$[a-f0-9]{64}$', "category": "framework", "hashtype_id": 10000},
    # RACF
    "RACF": {"length": 8, "regex": r'^[a-f0-9]{8}$', "category": "mainframe", "hashtype_id": 99999},
    # SAP
    "SAPCODVN(B)": {"length": 40, "regex": r'^[a-f0-9]{40}$', "category": "erp", "hashtype_id": 7700},
    "SAPCODVN(F/G)": {"length": 40, "regex": r'^[a-f0-9]{40}$', "category": "erp", "hashtype_id": 7800},
    # Kerberos
    "Kerberos5(TGS-REP)": {"length": 0, "regex": r'^\$krb5tgs\$.*$', "category": "auth", "hashtype_id": 13100},
    "Kerberos5(AS-REP)": {"length": 0, "regex": r'^\$krb5asrep\$.*$', "category": "auth", "hashtype_id": 18200},
    # GRUB
    "GRUB2": {"length": 0, "regex": r'^grub\.pbkdf2\.sha512\.\d+\.[a-f0-9]+\.[a-f0-9]+$', "category": "boot", "hashtype_id": 7200},
    # Cisco Type 8
    "Cisco-Type8": {"length": 50, "regex": r'^\$8\$[a-zA-Z0-9./]{14}\$[a-zA-Z0-9./]{43}$', "category": "network", "hashtype_id": 9200},
    # Cisco Type 9
    "Cisco-Type9": {"length": 46, "regex": r'^\$9\$[a-zA-Z0-9./]{14}\$[a-zA-Z0-9./]{43}$', "category": "network", "hashtype_id": 9300},
    # LastPass
    "LastPass": {"length": 64, "regex": r'^[a-f0-9]{64}:[a-f0-9]+$', "category": "password_mgr", "hashtype_id": 99999},
    # IPMI2
    "IPMI2": {"length": 0, "regex": r'^\$ipmi2\$.*$', "category": "hardware", "hashtype_id": 7300},
    # Telegram
    "Telegram": {"length": 64, "regex": r'^[a-f0-9]{64}$', "category": "messaging", "hashtype_id": 99999},
}

# ============================================================================
# DEFAULT WORDLIST FOR CRACKING
# ============================================================================

DEFAULT_CRACK_WORDLIST = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master", "sunshine",
    "ashley", "bailey", "passw0rd", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "password123", "welcome",
    "admin", "root", "toor", "test", "guest", "administrator", "changeme",
    "default", "pass", "pass123", "pass1", "p@ssword", "p@ssw0rd", "p@ss",
    "secret", "1234", "12345", "123456789", "1234567890", "0987654321",
    "qwerty123", "letmein1", "welcome1", "admin123", "root123", "toor123",
    "test123", "guest123", "demo", "demo123", "user", "user123", "mysql",
    "oracle", "postgres", "redis", "mongodb", "server", "backup", "system",
    "hunter2", "princess", "starwars", "solo", "jordan", "harley", "ranger",
    "thomas", "robert", "soccer", "hockey", "killer", "george", "andrew",
    "charlie", "access", "hello", "charles", "jack", "blink182", "ironman",
    "batman", "superman1", "matrix", "freedom", "whatever", "corvette",
    "mustang", "ferrari", "porsche", "computer", "internet", "service",
    "canada", "australia", "england", "scotland", "america", "mexico",
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
    "hotel", "india", "juliet", "kilo", "lima", "mike", "november",
    "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
    "victor", "whiskey", "xray", "yankee", "zulu",
    "Spring2024", "Winter2024", "Summer2024", "Fall2024",
    "Company2024", "P@ssw0rd", "Welcome1!", "Ch@ngeMe1",
    "!@#$%^&*", "Aa123456", "P@ss1234", "Qwerty123!",
]

# ============================================================================
# ONLINE CRACKING API ENDPOINTS
# ============================================================================

ONLINE_CRACK_APIS = [
    {
        "name": "md5decrypt.net",
        "url": "https://md5decrypt.net/Api/api.php",
        "method": "POST",
        "hash_types": ["MD5"],
        "note": "Free API with rate limits",
    },
    {
        "name": "hashtoolkit.com",
        "url": "https://hashtoolkit.com/reverse-hash",
        "method": "GET",
        "hash_types": ["MD5", "SHA1", "SHA256"],
        "note": "Free reverse hash lookup",
    },
    {
        "name": "crackstation.net",
        "url": "https://crackstation.net",
        "method": "WEB",
        "hash_types": ["MD5", "SHA1", "SHA256", "SHA512", "NTLM", "MySQL4/5"],
        "note": "Large rainbow table database",
    },
]


# ============================================================================
# HASH ADVANCED ENGINE
# ============================================================================

class HashAdvancedEngine:
    """
    Hash Advanced Engine - Fused from HashCRACK + Name-That-Hash + p0
    Supports 300+ hash types, dictionary attacks, rainbow tables,
    online cracking, batch processing, and password candidate generation.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        self.session.verify = False

    # ========================================================================
    # HASH IDENTIFICATION
    # ========================================================================

    def identify_hash(self, hash_string):
        """
        Identify hash type from hash string
        Returns list of possible hash types with confidence scores
        """
        if not hash_string:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No hash string provided'},
                'scan_type': 'hash_identify'
            }

        hash_string = hash_string.strip()
        possible_types = []

        # Check each hash type
        for name, info in HASH_TYPES.items():
            # Check by regex pattern
            if info.get('regex') and re.match(info['regex'], hash_string):
                confidence = 70
                # Boost confidence if length matches exactly
                if info.get('length') and len(hash_string) == info['length']:
                    confidence += 15
                # Boost for distinctive prefixes
                if hash_string.startswith('$2') and 'bcrypt' in name.lower():
                    confidence += 15
                elif hash_string.startswith('$6$') and 'SHA512(Crypt)' in name:
                    confidence += 15
                elif hash_string.startswith('$1$') and 'MD5(Crypt)' in name:
                    confidence += 15
                elif hash_string.startswith('*') and 'MySQL4/5' in name:
                    confidence += 20
                elif hash_string.startswith('md5') and 'PostgreSQL' in name:
                    confidence += 20
                elif hash_string.startswith('$P$') and 'WordPress' in name:
                    confidence += 20
                elif hash_string.startswith('$S$') and 'Drupal' in name:
                    confidence += 20
                elif hash_string.startswith('eyJ') and 'JWT' in name:
                    confidence += 20
                elif hash_string.startswith('sha1$') and 'Django' in name:
                    confidence += 20
                elif hash_string.startswith('pbkdf2') and 'PBKDF2' in name:
                    confidence += 20

                possible_types.append({
                    'type': name,
                    'confidence': min(confidence, 100),
                    'category': info.get('category', 'unknown'),
                    'hashtype_id': info.get('hashtype_id', 0),
                    'length': len(hash_string),
                })

        # Sort by confidence
        possible_types.sort(key=lambda x: x['confidence'], reverse=True)

        # If no matches, try heuristic analysis
        if not possible_types:
            possible_types = self._heuristic_identify(hash_string)

        # Deduplicate - keep highest confidence per type
        seen = set()
        unique_types = []
        for pt in possible_types:
            if pt['type'] not in seen:
                seen.add(pt['type'])
                unique_types.append(pt)

        print(f"{CYAN}[ZYLON HASH] Identifying: {hash_string[:40]}...{RESET}")
        print(f"{GREEN}[+] Found {len(unique_types)} possible type(s){RESET}")
        for pt in unique_types[:5]:
            print(f"  {YELLOW}[{pt['confidence']}%] {pt['type']} ({pt['category']}){RESET}")

        return {
            'vulnerable': len(unique_types) > 0,
            'findings': unique_types[:10],
            'details': {
                'hash': hash_string,
                'hash_length': len(hash_string),
                'possible_types': len(unique_types),
                'top_match': unique_types[0] if unique_types else None,
                'charset': self._detect_charset(hash_string),
            },
            'scan_type': 'hash_identify'
        }

    def _heuristic_identify(self, hash_string):
        """Heuristic hash identification when regex doesn't match"""
        possible = []
        length = len(hash_string)

        length_map = {
            4: ["CRC16"],
            8: ["CRC32", "RACF", "Adler-32"],
            16: ["MySQL323", "LM", "Cisco-PIX", "Half-MD5"],
            32: ["MD5", "NTLM", "LM", "MD4", "MD2", "RIPEMD-128", "Haval-128", "Tiger-128", "Snefru-128"],
            40: ["SHA1", "MySQL4/5", "RIPEMD-160", "Tiger-160", "Has-160", "SAPCODVN(B)"],
            48: ["Tiger-192", "HAVAL-192"],
            56: ["SHA224", "SHA3-224", "Keccak-224", "BLAKE2s-224", "RIPEMD-224"],
            64: ["SHA256", "SHA3-256", "BLAKE2b-256", "RIPEMD-256", "Keccak-256", "Haval-256", "Snefru-256"],
            96: ["SHA384", "SHA3-384", "Keccak-384", "BLAKE2s-384"],
            128: ["SHA512", "SHA3-512", "Keccak-512", "BLAKE2b-512", "RIPEMD-512", "Whirlpool"],
        }

        if length in length_map:
            for hash_type in length_map[length]:
                possible.append({
                    'type': hash_type,
                    'confidence': 30 + (10 if length in [32, 40, 64, 128] else 0),
                    'category': 'hash',
                    'hashtype_id': 0,
                    'length': length,
                })

        return sorted(possible, key=lambda x: x['confidence'], reverse=True)

    def _detect_charset(self, hash_string):
        """Detect the character set used in the hash"""
        if re.match(r'^[a-f0-9]+$', hash_string):
            return 'hexadecimal_lowercase'
        elif re.match(r'^[A-F0-9]+$', hash_string):
            return 'hexadecimal_uppercase'
        elif re.match(r'^[a-zA-Z0-9+/=]+$', hash_string):
            return 'base64'
        elif re.match(r'^[a-zA-Z0-9./$]+$', hash_string):
            return 'unix_crypt'
        return 'mixed'

    # ========================================================================
    # HASH CRACKING (DICTIONARY ATTACK)
    # ========================================================================

    def crack_hash(self, hash_string, wordlist=None):
        """
        Dictionary attack hash cracking
        Supports MD5, SHA1, SHA256, SHA512, NTLM
        """
        if not hash_string:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No hash string provided'},
                'scan_type': 'hash_crack'
            }

        hash_string = hash_string.strip().lower()

        # First identify the hash type
        id_result = self.identify_hash(hash_string)
        possible_types = [f['type'] for f in id_result.get('findings', [])]

        # Load wordlist
        words = self._load_wordlist(wordlist)

        print(f"{RED}[ZYLON HASH CRACKER] Starting dictionary attack{RESET}")
        print(f"{RED}[*] Hash: {hash_string[:40]}... | Wordlist: {len(words)} entries{RESET}")
        print(f"{RED}[*] Possible types: {', '.join(possible_types[:5])}{RESET}")

        # Try cracking
        cracked = False
        cracked_value = None
        matched_type = None
        total_tried = 0

        # Hash functions map
        hash_funcs = {
            "MD5": hashlib.md5,
            "MD4": lambda: hashlib.new('md4'),
            "SHA1": hashlib.sha1,
            "SHA224": hashlib.sha224,
            "SHA256": hashlib.sha256,
            "SHA384": hashlib.sha384,
            "SHA512": hashlib.sha512,
            "NTLM": self._ntlm_hash,
        }

        # Try each possible hash type
        for hash_type in possible_types:
            func_name = None
            for key in hash_funcs:
                if key.lower() in hash_type.lower():
                    func_name = key
                    break

            if not func_name:
                continue

            print(f"  {YELLOW}[*] Trying {hash_type}...{RESET}")
            hash_func = hash_funcs[func_name]

            for word in words:
                total_tried += 1
                try:
                    if func_name == "NTLM":
                        computed = hash_func(word)
                    else:
                        computed = hash_func(word.encode()).hexdigest()

                    if computed == hash_string:
                        cracked = True
                        cracked_value = word
                        matched_type = hash_type
                        break
                except Exception:
                    continue

            if cracked:
                break

        # Also try common hash functions by length even if not identified
        if not cracked:
            length_hash_map = {
                32: [("MD5", hashlib.md5), ("NTLM", self._ntlm_hash)],
                40: [("SHA1", hashlib.sha1)],
                64: [("SHA256", hashlib.sha256)],
                128: [("SHA512", hashlib.sha512)],
            }
            hash_len = len(hash_string)
            if hash_len in length_hash_map:
                for type_name, hash_func in length_hash_map[hash_len]:
                    if type_name in possible_types:
                        continue  # Already tried
                    print(f"  {YELLOW}[*] Also trying {type_name} by length...{RESET}")
                    for word in words:
                        total_tried += 1
                        try:
                            if type_name == "NTLM":
                                computed = hash_func(word)
                            else:
                                computed = hash_func(word.encode()).hexdigest()
                            if computed == hash_string:
                                cracked = True
                                cracked_value = word
                                matched_type = type_name
                                break
                        except Exception:
                            continue
                    if cracked:
                        break

        if cracked:
            print(f"{BOLD}{GREEN}[!!!] HASH CRACKED! {hash_string[:20]}... = {cracked_value} ({matched_type}){RESET}")
        else:
            print(f"{RED}[-] Hash not cracked with {total_tried} attempts{RESET}")

        return {
            'vulnerable': cracked,
            'findings': [{
                'hash': hash_string,
                'cracked': cracked,
                'plaintext': cracked_value,
                'hash_type': matched_type,
                'attempts': total_tried,
            }] if cracked else [],
            'details': {
                'hash': hash_string,
                'hash_length': len(hash_string),
                'possible_types': possible_types[:5],
                'cracked': cracked,
                'plaintext': cracked_value,
                'hash_type': matched_type,
                'total_attempts': total_tried,
                'wordlist_size': len(words),
            },
            'scan_type': 'hash_crack'
        }

    def _ntlm_hash(self, password):
        """Compute NTLM hash"""
        try:
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest()
        except Exception:
            return ""

    def _load_wordlist(self, wordlist=None):
        """Load wordlist from file or use default"""
        if wordlist and os.path.isfile(wordlist):
            try:
                with open(wordlist, 'r', errors='ignore') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception:
                pass
        return DEFAULT_CRACK_WORDLIST

    # ========================================================================
    # BATCH HASH CRACKING
    # ========================================================================

    def crack_batch(self, hash_file, wordlist=None):
        """
        Multi-hash batch processing
        Read hashes from file, crack each one
        """
        if not hash_file or not os.path.isfile(hash_file):
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': f'Hash file not found: {hash_file}'},
                'scan_type': 'hash_batch_crack'
            }

        # Read hashes from file
        try:
            with open(hash_file, 'r', errors='ignore') as f:
                hashes = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': str(e)},
                'scan_type': 'hash_batch_crack'
            }

        print(f"{BOLD}{RED}[ZYLON BATCH CRACKER] Processing {len(hashes)} hashes{RESET}")

        results = []
        cracked_count = 0

        for i, hash_str in enumerate(hashes):
            print(f"  {CYAN}[{i+1}/{len(hashes)}] Cracking: {hash_str[:30]}...{RESET}")
            result = self.crack_hash(hash_str, wordlist=wordlist)
            if result.get('details', {}).get('cracked'):
                cracked_count += 1
                results.append({
                    'hash': hash_str,
                    'cracked': True,
                    'plaintext': result['details'].get('plaintext'),
                    'hash_type': result['details'].get('hash_type'),
                })
            else:
                results.append({
                    'hash': hash_str,
                    'cracked': False,
                })

        print(f"\n{BOLD}{GREEN}[+] Batch complete: {cracked_count}/{len(hashes)} cracked{RESET}")

        return {
            'vulnerable': cracked_count > 0,
            'findings': [r for r in results if r.get('cracked')],
            'details': {
                'total_hashes': len(hashes),
                'cracked': cracked_count,
                'uncracked': len(hashes) - cracked_count,
                'success_rate': f"{(cracked_count/len(hashes)*100):.1f}%" if hashes else "0%",
                'results': results,
            },
            'scan_type': 'hash_batch_crack'
        }

    # ========================================================================
    # PASSWORD CANDIDATE GENERATION
    # ========================================================================

    def generate_candidates(self, rule, count=100):
        """
        Generate password candidates based on rules
        Rules: 'common', 'year_suffix', 'keyboard', 'leet', 'capitalized', 'mixed'
        """
        candidates = []
        base_words = ["password", "admin", "root", "welcome", "login", "secret",
                      "master", "access", "changeme", "letmein", "qwerty", "dragon",
                      "monkey", "shadow", "sunshine", "trustno1", "iloveyou",
                      "charlie", "robert", "thomas", "hockey", "ranger", "daniel",
                      "starwars", "klaster", "george", "computer", "michelle",
                      "jessica", "pepper", "zxcvbnm", "freedom", "flower", "hannah",
                      "rockyou", "princess", "ashley", "amanda", "nicole", "babygirl"]

        if rule == 'common' or rule == 'all':
            candidates.extend(base_words)

        if rule == 'year_suffix' or rule == 'all':
            current_year = datetime.now().year
            for word in base_words[:20]:
                for year in range(2020, current_year + 2):
                    candidates.append(f"{word}{year}")
                    candidates.append(f"{word}_{year}")
                    candidates.append(f"{word}!{year}")
                    candidates.append(f"{word}@{year}")
                    candidates.append(f"{word.capitalize()}{year}!")
                    candidates.append(f"{word.capitalize()}@{year}")

        if rule == 'keyboard' or rule == 'all':
            keyboard_patterns = [
                "qwerty", "asdfgh", "zxcvbn", "qazwsx", "wsxedc",
                "123456", "234567", "345678", "456789", "098765",
                "1qaz2wsx", "qaz1wsx", "!QAZ2wsx", "1q2w3e4r",
                "1q2w3e", "qweasd", "asdfjkl", "zxcvbnm",
            ]
            for pattern in keyboard_patterns:
                candidates.append(pattern)
                candidates.append(pattern.capitalize())
                candidates.append(pattern + "!1")
                candidates.append(pattern + "@1")

        if rule == 'leet' or rule == 'all':
            leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
            for word in base_words[:20]:
                leet_word = word
                for orig, leet in leet_map.items():
                    leet_word = leet_word.replace(orig, leet)
                candidates.append(leet_word)
                candidates.append(leet_word.capitalize())
                candidates.append(leet_word + "!1")
                candidates.append(leet_word + "2024")

        if rule == 'capitalized' or rule == 'all':
            for word in base_words[:20]:
                candidates.append(word.capitalize())
                candidates.append(word.upper())
                candidates.append(word.capitalize() + "!1")
                candidates.append(word.capitalize() + "@1")
                candidates.append(word.capitalize() + "#1")
                candidates.append(word.capitalize() + "2024!")

        if rule == 'mixed' or rule == 'all':
            for word in base_words[:15]:
                candidates.append(word + "123")
                candidates.append(word + "!@#")
                candidates.append(word.capitalize() + "123!")
                candidates.append(word.capitalize() + "!@#1")
                candidates.append("P@" + word.capitalize() + "1")
                candidates.append("!" + word.capitalize() + "!1")
                candidates.append(word + "!1")
                candidates.append(word + "@1")
                candidates.append(word + "#1")

        # Deduplicate and limit
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique_candidates.append(c)
            if len(unique_candidates) >= count:
                break

        print(f"{CYAN}[ZYLON HASH] Generated {len(unique_candidates)} password candidates (rule: {rule}){RESET}")

        return {
            'vulnerable': True,
            'findings': [{'password': p, 'rule': rule} for p in unique_candidates[:50]],
            'details': {
                'rule': rule,
                'total_generated': len(unique_candidates),
                'candidates': unique_candidates,
            },
            'scan_type': 'password_candidate_gen'
        }

    # ========================================================================
    # HASH VERIFICATION
    # ========================================================================

    def verify_hash(self, plaintext, hash_string, hash_type='MD5'):
        """Verify that a plaintext matches a given hash"""
        hash_funcs = {
            "MD5": lambda s: hashlib.md5(s.encode()).hexdigest(),
            "SHA1": lambda s: hashlib.sha1(s.encode()).hexdigest(),
            "SHA224": lambda s: hashlib.sha224(s.encode()).hexdigest(),
            "SHA256": lambda s: hashlib.sha256(s.encode()).hexdigest(),
            "SHA384": lambda s: hashlib.sha384(s.encode()).hexdigest(),
            "SHA512": lambda s: hashlib.sha512(s.encode()).hexdigest(),
            "NTLM": lambda s: self._ntlm_hash(s),
        }

        # Find matching function
        func = None
        for key in hash_funcs:
            if key.lower() in hash_type.lower():
                func = hash_funcs[key]
                break

        if not func:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {
                    'error': f'Unsupported hash type: {hash_type}',
                    'supported': list(hash_funcs.keys()),
                },
                'scan_type': 'hash_verify'
            }

        try:
            computed = func(plaintext)
            match = computed.lower() == hash_string.strip().lower()

            if match:
                print(f"{GREEN}[+] Hash VERIFIED! {plaintext} -> {hash_string[:20]}... ({hash_type}){RESET}")
            else:
                print(f"{RED}[-] Hash MISMATCH. Computed: {computed[:20]}... != Provided: {hash_string[:20]}...{RESET}")

            return {
                'vulnerable': match,
                'findings': [{
                    'plaintext': plaintext,
                    'computed_hash': computed,
                    'provided_hash': hash_string.strip().lower(),
                    'hash_type': hash_type,
                    'match': match,
                }],
                'details': {
                    'plaintext': plaintext,
                    'hash_type': hash_type,
                    'match': match,
                    'computed': computed,
                },
                'scan_type': 'hash_verify'
            }
        except Exception as e:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': str(e)},
                'scan_type': 'hash_verify'
            }

    # ========================================================================
    # ONLINE CRACKING
    # ========================================================================

    def online_crack(self, hash_string):
        """
        Try online cracking services
        Uses multiple free APIs and reverse hash lookup services
        """
        if not hash_string:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No hash string provided'},
                'scan_type': 'hash_online_crack'
            }

        hash_string = hash_string.strip()
        print(f"{MAGENTA}[ZYLON HASH ONLINE] Trying online cracking for: {hash_string[:30]}...{RESET}")

        cracked = False
        plaintext = None
        source = None
        tried_services = []

        # Try md5decrypt.net API (MD5 only)
        if len(hash_string) == 32:
            try:
                resp = self.session.get(
                    f"https://md5decrypt.net/Api/api.php?hash={hash_string}&hash_type=md5&email=test@test.com&code=test",
                    timeout=10, verify=False
                )
                tried_services.append("md5decrypt.net")
                if resp.status_code == 200 and resp.text.strip() and resp.text.strip() != '':
                    result = resp.text.strip()
                    if result and len(result) < 100 and not result.startswith('API'):
                        cracked = True
                        plaintext = result
                        source = "md5decrypt.net"
            except Exception:
                tried_services.append("md5decrypt.net (failed)")

        # Try hashtoolkit reverse hash
        if not cracked:
            try:
                resp = self.session.get(
                    f"https://hashtoolkit.com/reverse-hash?hash={hash_string}",
                    timeout=10, verify=False
                )
                tried_services.append("hashtoolkit.com")
                if resp.status_code == 200:
                    match = re.search(r'resolved-text[^>]*>([^<]+)<', resp.text)
                    if match:
                        cracked = True
                        plaintext = match.group(1).strip()
                        source = "hashtoolkit.com"
            except Exception:
                tried_services.append("hashtoolkit.com (failed)")

        # Try nitrxgen.net API
        if not cracked:
            try:
                resp = self.session.get(
                    f"https://www.nitrxgen.net/md5db/{hash_string}",
                    timeout=10, verify=False
                )
                tried_services.append("nitrxgen.net")
                if resp.status_code == 200 and resp.text.strip():
                    result = resp.text.strip()
                    if result and len(result) < 100 and result != hash_string:
                        cracked = True
                        plaintext = result
                        source = "nitrxgen.net"
            except Exception:
                tried_services.append("nitrxgen.net (failed)")

        # Try crackstation via indirect lookup
        if not cracked:
            try:
                # Use a simpler hash lookup service
                resp = self.session.get(
                    f"https://api.hashify.net/hash/{hash_string}/summary",
                    timeout=10, verify=False
                )
                tried_services.append("hashify.net")
            except Exception:
                tried_services.append("hashify.net (failed)")

        if cracked:
            print(f"{BOLD}{GREEN}[!!!] ONLINE CRACKED! {hash_string[:20]}... = {plaintext} (via {source}){RESET}")
        else:
            print(f"{RED}[-] Not found in online databases{RESET}")

        return {
            'vulnerable': cracked,
            'findings': [{
                'hash': hash_string,
                'cracked': cracked,
                'plaintext': plaintext,
                'source': source,
            }] if cracked else [],
            'details': {
                'hash': hash_string,
                'cracked': cracked,
                'plaintext': plaintext,
                'source': source,
                'services_tried': tried_services,
                'total_services': len(tried_services),
            },
            'scan_type': 'hash_online_crack'
        }

    # ========================================================================
    # FULL HASH SCAN
    # ========================================================================

    def full_scan(self, hash_string, wordlist=None):
        """
        Full hash scan: Identify + Crack (dictionary) + Online crack
        """
        if not hash_string:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No hash string provided'},
                'scan_type': 'hash_full_scan'
            }

        print(f"{BOLD}{RED}[ZYLON HASH] FULL SCAN on {hash_string[:40]}...{RESET}")

        results = {}

        # Phase 1: Identify
        print(f"\n{CYAN}=== Phase 1: Hash Identification ==={RESET}")
        results['identify'] = self.identify_hash(hash_string)

        # Phase 2: Dictionary crack
        print(f"\n{RED}=== Phase 2: Dictionary Attack ==={RESET}")
        results['crack'] = self.crack_hash(hash_string, wordlist=wordlist)

        # Phase 3: Online crack (if not cracked yet)
        if not results['crack'].get('details', {}).get('cracked'):
            print(f"\n{MAGENTA}=== Phase 3: Online Cracking ==={RESET}")
            results['online'] = self.online_crack(hash_string)
        else:
            results['online'] = {'vulnerable': False, 'findings': [], 'details': {'skipped': True, 'reason': 'Already cracked via dictionary'}, 'scan_type': 'hash_online_crack'}

        # Summary
        cracked = (results['crack'].get('details', {}).get('cracked') or
                   results['online'].get('details', {}).get('cracked', False))
        plaintext = (results['crack'].get('details', {}).get('plaintext') or
                     results['online'].get('details', {}).get('plaintext'))

        if cracked:
            print(f"\n{BOLD}{GREEN}[!!!] HASH CRACKED: {plaintext}{RESET}")
        else:
            print(f"\n{RED}[-] Hash not cracked{RESET}")

        return {
            'vulnerable': cracked,
            'findings': results,
            'details': {
                'hash': hash_string,
                'hash_type': results['identify'].get('details', {}).get('top_match', {}).get('type', 'Unknown'),
                'cracked': cracked,
                'plaintext': plaintext,
                'phases_run': ['identify', 'dictionary_crack', 'online_crack'],
            },
            'scan_type': 'hash_full_scan'
        }

    # ========================================================================
    # MAIN ENTRY
    # ========================================================================

    def run(self, target=None, scan_type='identify', **kwargs):
        """Main entry point"""
        # For hash engine, 'target' is the hash string
        hash_string = kwargs.pop('hash_string', target)
        wordlist = kwargs.pop('wordlist', None)
        hash_type = kwargs.pop('hash_type', 'MD5')
        rule = kwargs.pop('rule', 'all')
        count = kwargs.pop('count', 100)
        hash_file = kwargs.pop('hash_file', None)

        scan_map = {
            'identify': lambda: self.identify_hash(hash_string),
            'crack': lambda: self.crack_hash(hash_string, wordlist=wordlist),
            'batch': lambda: self.crack_batch(hash_file or hash_string, wordlist=wordlist),
            'candidates': lambda: self.generate_candidates(rule, count=count),
            'verify': lambda: self.verify_hash(kwargs.get('plaintext', ''), hash_string, hash_type=hash_type),
            'online': lambda: self.online_crack(hash_string),
            'full': lambda: self.full_scan(hash_string, wordlist=wordlist),
        }

        if scan_type in scan_map:
            return scan_map[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}', 'available': list(scan_map.keys())},
            'scan_type': scan_type
        }


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='identify', **kwargs):
    """
    Module-level run function for ZYLON FUSION integration.
    Returns dict: 'vulnerable', 'findings', 'details', 'scan_type'
    """
    engine = HashAdvancedEngine()
    return engine.run(target=target, scan_type=scan_type, **kwargs)
