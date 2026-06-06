#!/usr/bin/env python3
"""
ZYLON FUSION v2.5 NUCLEAR - Ciphey Auto-Decode Engine
=====================================================
Fused from: Ciphey (https://github.com/Ciphey/Ciphey)
Purpose: Automatic cipher/text/encoding detection and decoding
Architecture: BFS-based multi-decoder search with plaintext detection
             (Pure Python reimplementation - no Rust dependency)
Python 3.13 Compatible | Termux Non-Root
"""

import os
import re
import sys
import base64
import binascii
import string
import hashlib
import hmac as hmac_module
from collections import deque
from urllib.parse import unquote, unquote_plus

from core.shared_infra import shared_session, regex_cache

# ============================================================================
# PLAINTEXT DETECTION
# ============================================================================

class PlaintextChecker:
    """Determines if decoded text is meaningful plaintext"""
    
    # Common English words for frequency analysis
    COMMON_WORDS = {
        'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
        'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
        'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her',
        'she', 'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there',
        'their', 'what', 'so', 'up', 'out', 'if', 'about', 'who', 'get',
        'which', 'go', 'me', 'when', 'make', 'can', 'like', 'time', 'no',
        'just', 'him', 'know', 'take', 'people', 'into', 'year', 'your',
        'good', 'some', 'could', 'them', 'see', 'other', 'than', 'then',
        'now', 'look', 'only', 'come', 'its', 'over', 'think', 'also',
        'back', 'after', 'use', 'two', 'how', 'our', 'work', 'first',
        'well', 'way', 'even', 'new', 'want', 'because', 'any', 'these',
        'give', 'day', 'most', 'us', 'password', 'admin', 'secret', 'key',
        'login', 'token', 'user', 'root', 'flag', 'ctf', 'hack', 'test',
        'hello', 'world', 'email', 'name', 'data', 'code', 'server',
    }
    
    # Patterns that indicate plaintext
    PLAINTEXT_PATTERNS = [
        r'https?://',           # URLs
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Emails
        r'\bpassword\b',        # Common words
        r'\bsecret\b',
        r'\badmin\b',
        r'\btoken\b',
        r'\bflag\{',            # CTF flags
        r'\bCTF\{',
        r'\{.*:.*\}',           # JSON-like
        r'<[a-z][\s\S]*>',     # HTML tags
        r'\bSELECT\b.*\bFROM\b',  # SQL
        r'\bapi[_-]?key\b',
    ]
    
    @classmethod
    def is_plaintext(cls, text):
        """Check if text is likely plaintext using multiple heuristics"""
        if not text or len(text) < 2:
            return False, 0.0
        
        if isinstance(text, bytes):
            try:
                text = text.decode('utf-8')
            except (UnicodeDecodeError, AttributeError):
                return False, 0.0
        
        score = 0.0
        max_score = 100.0
        
        # Check 1: Printable character ratio
        printable_count = sum(1 for c in text if c in string.printable)
        printable_ratio = printable_count / len(text) if text else 0
        if printable_ratio > 0.95:
            score += 30
        elif printable_ratio > 0.85:
            score += 20
        elif printable_ratio > 0.7:
            score += 10
        
        # Check 2: Common English word presence
        words = regex_cache.findall(r'\b[a-z]+\b', text.lower())
        if words:
            word_match = sum(1 for w in words if w in cls.COMMON_WORDS)
            word_ratio = word_match / len(words) if words else 0
            if word_ratio > 0.3:
                score += 25
            elif word_ratio > 0.15:
                score += 15
            elif word_ratio > 0.05:
                score += 8
        
        # Check 3: Pattern matching
        for pattern in cls.PLAINTEXT_PATTERNS:
            if regex_cache.search(pattern, text, re.IGNORECASE):
                score += 10
                break
        
        # Check 4: Space/word structure
        space_count = text.count(' ')
        if space_count > 0 and len(text) > 10:
            avg_word_len = len(text.replace(' ', '')) / (space_count + 1)
            if 3 < avg_word_len < 10:
                score += 15
            elif 2 < avg_word_len < 15:
                score += 8
        
        # Check 5: No excessive special characters
        special_ratio = sum(1 for c in text if c not in string.printable[:94]) / len(text)
        if special_ratio < 0.05:
            score += 10
        
        # Check 6: Entropy check (too high = likely still encoded)
        entropy = cls._shannon_entropy(text)
        if entropy < 3.5:
            score += 10
        elif entropy < 4.5:
            score += 5
        
        is_plain = score >= 40
        return is_plain, min(score / max_score, 1.0)
    
    @staticmethod
    def _shannon_entropy(text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        freq = {}
        for c in text:
            freq[c] = freq.get(c, 0) + 1
        length = len(text)
        entropy = 0.0
        import math
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


# ============================================================================
# DECODER CLASSES
# ============================================================================

class BaseDecoder:
    """Base class for all decoders"""
    name = "base"
    tags = []
    
    @classmethod
    def can_decode(cls, text):
        """Quick check if this decoder might apply"""
        return True
    
    @classmethod
    def decode(cls, text):
        """Attempt to decode text. Returns decoded string or None."""
        raise NotImplementedError


class Base64Decoder(BaseDecoder):
    name = "base64"
    tags = ["base64", "base", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        if len(text) < 4:
            return False
        clean = text.strip().replace('\n', '').replace(' ', '')
        if len(clean) % 4 != 0:
            return False
        return bool(regex_cache.match(r'^[A-Za-z0-9+/=]+$', clean))
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip().replace('\n', '').replace(' ', '')
            padding = 4 - len(clean) % 4
            if padding != 4:
                clean += '=' * padding
            decoded = base64.b64decode(clean)
            result = decoded.decode('utf-8')
            if result != text and len(result) > 0:
                return result
        except Exception:
            pass
        return None


class Base64URLDecoder(BaseDecoder):
    name = "base64url"
    tags = ["base64", "url", "base", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        if len(text) < 4:
            return False
        clean = text.strip().replace('\n', '').replace(' ', '')
        return bool(regex_cache.match(r'^[A-Za-z0-9_-]=*$', clean)) and '-' in clean or '_' in clean
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip().replace('\n', '').replace(' ', '')
            padding = 4 - len(clean) % 4
            if padding != 4:
                clean += '=' * padding
            decoded = base64.urlsafe_b64decode(clean)
            result = decoded.decode('utf-8')
            if result != text and len(result) > 0:
                return result
        except Exception:
            pass
        return None


class Base32Decoder(BaseDecoder):
    name = "base32"
    tags = ["base32", "base", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip().replace('\n', '').replace(' ', '').replace('=', '')
        if len(clean) < 8:
            return False
        return bool(regex_cache.match(r'^[A-Z2-7]+$', clean))
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip().replace('\n', '').replace(' ', '')
            padding = (8 - len(clean) % 8) % 8
            clean += '=' * padding
            decoded = base64.b32decode(clean)
            result = decoded.decode('utf-8')
            if result != text and len(result) > 0:
                return result
        except Exception:
            pass
        return None


class HexDecoder(BaseDecoder):
    name = "hex"
    tags = ["hex", "hexadecimal", "base", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip().replace(' ', '').replace('0x', '').replace('\\x', '').replace(':', '').replace(';', '')
        if len(clean) < 2 or len(clean) % 2 != 0:
            return False
        return bool(regex_cache.match(r'^[0-9a-fA-F]+$', clean))
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip()
            # Remove common hex prefixes/separators
            clean = clean.replace('0x', '').replace('\\x', '').replace(':', '').replace(';', '').replace(' ', '')
            if len(clean) % 2 != 0:
                return None
            decoded = bytes.fromhex(clean)
            result = decoded.decode('utf-8')
            if result != text and len(result) > 0:
                return result
        except Exception:
            pass
        return None


class BinaryDecoder(BaseDecoder):
    name = "binary"
    tags = ["binary", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip().replace(' ', '')
        return len(clean) >= 8 and len(clean) % 8 == 0 and all(c in '01' for c in clean)
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip().replace(' ', '')
            if len(clean) % 8 != 0:
                return None
            chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
            result = ''.join(chars)
            if result != text:
                return result
        except Exception:
            pass
        return None


class URLDecoder(BaseDecoder):
    name = "url"
    tags = ["url", "decoder", "percent"]
    
    @classmethod
    def can_decode(cls, text):
        return '%' in text and len(text) >= 3
    
    @classmethod
    def decode(cls, text):
        try:
            result = unquote_plus(text)
            if result != text:
                return result
        except Exception:
            pass
        return None


class CaesarDecoder(BaseDecoder):
    name = "caesar"
    tags = ["caesar", "substitution", "classic", "rot"]
    
    @classmethod
    def can_decode(cls, text):
        return any(c.isalpha() for c in text)
    
    @classmethod
    def decode(cls, text):
        """Try all 25 shifts, return best plaintext match"""
        best_result = None
        best_score = 0
        
        for shift in range(1, 26):
            result = cls._shift(text, shift)
            is_plain, score = PlaintextChecker.is_plaintext(result)
            if is_plain and score > best_score:
                best_score = score
                best_result = result
        
        return best_result
    
    @classmethod
    def _shift(cls, text, shift):
        result = []
        for c in text:
            if c.isupper():
                result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            elif c.islower():
                result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(c)
        return ''.join(result)


class ROT13Decoder(BaseDecoder):
    name = "rot13"
    tags = ["rot13", "caesar", "substitution", "reciprocal"]
    
    @classmethod
    def can_decode(cls, text):
        return any(c.isalpha() for c in text)
    
    @classmethod
    def decode(cls, text):
        return CaesarDecoder._shift(text, 13)


class ROT47Decoder(BaseDecoder):
    name = "rot47"
    tags = ["rot47", "substitution", "reciprocal"]
    
    @classmethod
    def can_decode(cls, text):
        return any(33 <= ord(c) <= 126 for c in text)
    
    @classmethod
    def decode(cls, text):
        result = []
        for c in text:
            if 33 <= ord(c) <= 126:
                result.append(chr(33 + (ord(c) - 33 + 47) % 94))
            else:
                result.append(c)
        return ''.join(result)


class AtbashDecoder(BaseDecoder):
    name = "atbash"
    tags = ["atbash", "substitution", "reciprocal"]
    
    @classmethod
    def can_decode(cls, text):
        return any(c.isalpha() for c in text)
    
    @classmethod
    def decode(cls, text):
        result = []
        for c in text:
            if c.isupper():
                result.append(chr(ord('Z') - (ord(c) - ord('A'))))
            elif c.islower():
                result.append(chr(ord('z') - (ord(c) - ord('a'))))
            else:
                result.append(c)
        return ''.join(result)


class ReverseDecoder(BaseDecoder):
    name = "reverse"
    tags = ["reverse", "reciprocal"]
    
    @classmethod
    def can_decode(cls, text):
        return len(text) > 2
    
    @classmethod
    def decode(cls, text):
        result = text[::-1]
        return result if result != text else None


class MorseDecoder(BaseDecoder):
    name = "morse"
    tags = ["morse", "signals", "decoder"]
    
    MORSE_TABLE = {
        '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
        '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
        '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
        '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
        '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
        '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
        '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
        '----.': '9', '.-.-.-': '.', '--..--': ',', '..--..': '?', '.----.': "'",
        '-.-.--': '!', '-..-.': '/', '-.--.': '(', '-.--.-': ')', '.-...': '&',
        '---...': ':', '-.-.-.': ';', '-...-': '=', '.-.-.': '+', '-....-': '-',
        '..--.-': '_', '.-..-.': '"', '...-..-': '$', '.--.-.': '@',
    }
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip()
        morse_chars = set('.- /|')
        return len(clean) > 3 and all(c in morse_chars for c in clean)
    
    @classmethod
    def decode(cls, text):
        try:
            # Split by word separator (multiple spaces, /, |, or newlines)
            words = re.split(r'\s{2,}|/|\|', text.strip())
            result = []
            for word in words:
                word = word.strip()
                if not word:
                    continue
                # Split by letter separator (single space)
                letters = word.split()
                decoded_word = ''
                for letter in letters:
                    if letter in cls.MORSE_TABLE:
                        decoded_word += cls.MORSE_TABLE[letter]
                    else:
                        return None
                result.append(decoded_word)
            if result:
                return ' '.join(result)
        except Exception:
            pass
        return None


class Base58Decoder(BaseDecoder):
    name = "base58"
    tags = ["base58", "base", "decoder"]
    
    ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip()
        if len(clean) < 2:
            return False
        return all(c in cls.ALPHABET for c in clean)
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip()
            num = 0
            for c in clean:
                num = num * 58 + cls.ALPHABET.index(c)
            result = num.to_bytes((num.bit_length() + 7) // 8, 'big').decode('utf-8')
            if result != text:
                return result
        except Exception:
            pass
        return None


class Base85Decoder(BaseDecoder):
    name = "base85"
    tags = ["base85", "base", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip()
        if len(clean) < 5:
            return False
        # ASCII85 typically wrapped in <~ ... ~>
        return True
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip()
            if clean.startswith('<~') and clean.endswith('~>'):
                clean = clean[2:-2]
            decoded = base64.a85decode(clean)
            result = decoded.decode('utf-8')
            if result != text:
                return result
        except Exception:
            pass
        return None


class A1Z26Decoder(BaseDecoder):
    name = "a1z26"
    tags = ["a1z26", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip().replace(' ', '-').replace(',', '-')
        parts = clean.split('-')
        return len(parts) >= 2 and all(p.isdigit() and 1 <= int(p) <= 26 for p in parts if p)
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip().replace(' ', '-').replace(',', '-')
            parts = clean.split('-')
            result = ''
            for p in parts:
                if p.isdigit():
                    num = int(p)
                    if 1 <= num <= 26:
                        result += chr(num + 64)  # A=1, B=2, ...
                    else:
                        return None
                elif p == '':
                    result += ' '
                else:
                    return None
            return result
        except Exception:
            pass
        return None


class VigenereDecoder(BaseDecoder):
    name = "vigenere"
    tags = ["vigenere", "substitution", "classical"]
    
    # Common short keys to try
    COMMON_KEYS = ['key', 'secret', 'password', 'abc', 'test', 'crypto',
                   'cipher', 'code', 'hack', 'admin', 'lock', 'open']
    
    @classmethod
    def can_decode(cls, text):
        return len(text) > 5 and any(c.isalpha() for c in text)
    
    @classmethod
    def decode(cls, text):
        """Try common keys and return best match"""
        best_result = None
        best_score = 0
        
        for key in cls.COMMON_KEYS:
            result = cls._decrypt(text, key)
            is_plain, score = PlaintextChecker.is_plaintext(result)
            if is_plain and score > best_score:
                best_score = score
                best_result = result
        
        return best_result
    
    @classmethod
    def _decrypt(cls, text, key):
        result = []
        key_idx = 0
        for c in text:
            if c.isalpha():
                shift = ord(key[key_idx % len(key)].lower()) - ord('a')
                if c.isupper():
                    result.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
                else:
                    result.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
                key_idx += 1
            else:
                result.append(c)
        return ''.join(result)


class RailFenceDecoder(BaseDecoder):
    name = "railfence"
    tags = ["railfence", "transposition", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        return len(text) > 4 and any(c.isalpha() for c in text)
    
    @classmethod
    def decode(cls, text):
        """Try rails 2-5 and return best match"""
        best_result = None
        best_score = 0
        
        alpha_text = ''.join(c for c in text if c.isalpha())
        for rails in range(2, min(6, len(alpha_text))):
            result = cls._decrypt(alpha_text, rails)
            is_plain, score = PlaintextChecker.is_plaintext(result)
            if is_plain and score > best_score:
                best_score = score
                best_result = result
        
        return best_result
    
    @classmethod
    def _decrypt(cls, text, rails):
        if rails < 2 or len(text) < rails:
            return None
        n = len(text)
        fence = [[None] * n for _ in range(rails)]
        dirs = [1] + [0] * (rails - 1)
        rail = 0
        for i in range(n):
            fence[rail][i] = True
            if rail == 0:
                dirs = [1] * rails
            elif rail == rails - 1:
                dirs = [-1] * rails
            rail += dirs[0]
        
        idx = 0
        for r in range(rails):
            for c in range(n):
                if fence[r][c] is True:
                    fence[r][c] = text[idx]
                    idx += 1
        
        result = []
        rail = 0
        dirs = [1] + [0] * (rails - 1)
        for i in range(n):
            result.append(fence[rail][i])
            if rail == 0:
                dirs = [1] * rails
            elif rail == rails - 1:
                dirs = [-1] * rails
            rail += dirs[0]
        
        return ''.join(result) if result else None


class OctalDecoder(BaseDecoder):
    name = "octal"
    tags = ["octal", "decoder"]
    
    @classmethod
    def can_decode(cls, text):
        clean = text.strip().replace(' ', '')
        parts = clean.split('\\') if '\\' in clean else clean.split(' ')
        return any(all(c in '01234567' for c in p) for p in parts if p)
    
    @classmethod
    def decode(cls, text):
        try:
            clean = text.strip()
            if '\\' in clean:
                parts = clean.split('\\')
            else:
                parts = clean.split(' ')
            result = ''
            for p in parts:
                p = p.strip()
                if not p:
                    continue
                val = int(p, 8)
                if 0 < val < 256:
                    result += chr(val)
                else:
                    return None
            if result and result != text:
                return result
        except Exception:
            pass
        return None


class HashIdentifier:
    """Identify hash types by pattern matching"""
    
    HASH_PATTERNS = [
        ('MD5', r'^[a-f0-9]{32}$', 32),
        ('MD4', r'^[a-f0-9]{32}$', 32),
        ('SHA-1', r'^[a-f0-9]{40}$', 40),
        ('SHA-224', r'^[a-f0-9]{56}$', 56),
        ('SHA-256', r'^[a-f0-9]{64}$', 64),
        ('SHA-384', r'^[a-f0-9]{96}$', 96),
        ('SHA-512', r'^[a-f0-9]{128}$', 128),
        ('MySQL 3.x', r'^[a-f0-9]{16}$', 16),
        ('MySQL 4.x+', r'^\*[a-f0-9]{40}$', 41),
        ('NTLM', r'^[a-f0-9]{32}$', 32),
        ('CRC32', r'^[a-f0-9]{8}$', 8),
        ('CRC16', r'^[a-f0-9]{4}$', 4),
        ('SHA3-256', r'^[a-f0-9]{64}$', 64),
        ('SHA3-512', r'^[a-f0-9]{128}$', 128),
        ('BLAKE2s', r'^[a-f0-9]{64}$', 64),
        ('BLAKE2b', r'^[a-f0-9]{128}$', 128),
        (' bcrypt', r'^\$2[aby]?\$\d{2}\$', 0),
        ('JWT', r'^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$', 0),
    ]
    
    @classmethod
    def identify(cls, text):
        """Identify possible hash types"""
        clean = text.strip().lower()
        matches = []
        
        for name, pattern, length in cls.HASH_PATTERNS:
            if length > 0 and len(clean) != length:
                continue
            if regex_cache.match(pattern, clean):
                matches.append(name)
        
        # Special checks
        if clean.startswith('$2a$') or clean.startswith('$2b$') or clean.startswith('$2y$'):
            if 'bcrypt' not in str(matches):
                matches.append('bcrypt')
        
        if clean.startswith('eyJ') and clean.count('.') == 2:
            if 'JWT' not in str(matches):
                matches.append('JWT')
        
        return matches


# ============================================================================
# MAIN CIPHEY ENGINE
# ============================================================================

class CipheyEngine:
    """
    ZYLON Ciphey Auto-Decode Engine
    BFS-based search through all decoders to find plaintext
    """
    
    ALL_DECODERS = [
        Base64Decoder,
        Base64URLDecoder,
        Base32Decoder,
        HexDecoder,
        BinaryDecoder,
        URLDecoder,
        ROT13Decoder,
        ROT47Decoder,
        AtbashDecoder,
        CaesarDecoder,
        ReverseDecoder,
        MorseDecoder,
        Base58Decoder,
        Base85Decoder,
        A1Z26Decoder,
        VigenereDecoder,
        RailFenceDecoder,
        OctalDecoder,
    ]
    
    MAX_DEPTH = 15
    MAX_QUEUE_SIZE = 10000
    SEEN_LIMIT = 5000
    
    def __init__(self):
        self.results = []
        self.seen = set()
        self.decoder_chain = []
    
    def auto_decode(self, encoded_text, max_depth=None):
        """
        Main auto-decode function using BFS
        Returns list of (decoded_text, decoder_chain, confidence) tuples
        """
        if max_depth:
            self.MAX_DEPTH = max_depth
        
        self.results = []
        self.seen = set()
        
        # Clean input
        text = encoded_text.strip()
        if not text:
            return []
        
        # First check if already plaintext
        is_plain, score = PlaintextChecker.is_plaintext(text)
        if is_plain and score > 0.7:
            return [(text, ["input (already plaintext)"], score)]
        
        # BFS search
        queue = deque()
        queue.append((text, [], 0))  # (current_text, chain, depth)
        self.seen.add(text)
        
        while queue and len(self.results) < 5:
            if len(self.seen) > self.SEEN_LIMIT:
                break
            
            current_text, chain, depth = queue.popleft()
            
            if depth >= self.MAX_DEPTH:
                continue
            
            for decoder in self.ALL_DECODERS:
                # Skip reciprocal decoders if they were just used (prevent loops)
                if chain and 'reciprocal' in decoder.tags and chain[-1] == decoder.name:
                    continue
                
                if not decoder.can_decode(current_text):
                    continue
                
                try:
                    result = decoder.decode(current_text)
                except Exception:
                    continue
                
                if result is None or result == current_text:
                    continue
                
                if result in self.seen:
                    continue
                
                new_chain = chain + [decoder.name]
                self.seen.add(result)
                
                # Check if result is plaintext
                is_plain, score = PlaintextChecker.is_plaintext(result)
                
                if is_plain:
                    self.results.append((result, new_chain, score))
                
                # Continue searching even after finding plaintext
                # (might find better results)
                if len(queue) < self.MAX_QUEUE_SIZE:
                    queue.append((result, new_chain, depth + 1))
        
        # Sort by confidence
        self.results.sort(key=lambda x: x[2], reverse=True)
        return self.results
    
    def identify_hash(self, text):
        """Identify possible hash types"""
        return HashIdentifier.identify(text)
    
    def try_specific_decoder(self, text, decoder_name):
        """Try a specific decoder"""
        for decoder in self.ALL_DECODERS:
            if decoder.name == decoder_name:
                if decoder.can_decode(text):
                    return decoder.decode(text)
        return None
    
    def list_decoders(self):
        """List all available decoders"""
        return [(d.name, d.tags) for d in self.ALL_DECODERS]


# ============================================================================
# CONSOLE INTERFACE (for ZYLON integration)
# ============================================================================

def run_ciphey_scan(console=None):
    """Interactive Ciphey scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    
    console.print(Panel(
        "[bold cyan]CIPHEY AUTO-DECODE ENGINE[/bold cyan]\n"
        "[yellow]Fused from: Ciphey | BFS Multi-Decoder Search[/yellow]\n"
        "[green]Supports: Base64, Base32, Hex, Binary, URL, ROT13/47, Caesar, Atbash, Morse,\n"
        "          Base58, Base85, A1Z26, Vigenere, RailFence, Octal, Hash ID[/green]",
        border_style="bright_cyan"
    ))
    
    text = Prompt.ask("[cyan]Enter encoded/hashed text to decode[/cyan]")
    if not text.strip():
        console.print("[red][-] No input provided![/red]")
        return
    
    engine = CipheyEngine()
    
    # Step 1: Check if it's a hash
    hash_types = engine.identify_hash(text.strip())
    if hash_types:
        console.print(f"\n[yellow][*] Hash Detection: This looks like: {', '.join(hash_types)}[/yellow]")
        console.print("[yellow]    Note: Hashes cannot be decoded, only cracked with a wordlist.[/yellow]")
    
    # Step 2: Check if it's a JWT
    if text.strip().startswith('eyJ') and text.strip().count('.') == 2:
        console.print("\n[yellow][*] JWT Token detected! Use JWT Scanner (option 40) for full analysis.[/yellow]")
        try:
            parts = text.strip().split('.')
            import json
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            console.print(f"[green]    Header: {json.dumps(header, indent=2)}[/green]")
            console.print(f"[green]    Payload: {json.dumps(payload, indent=2)}[/green]")
        except Exception:
            pass
    
    # Step 3: Auto-decode
    console.print(f"\n[cyan][*] Running auto-decode BFS search...[/cyan]")
    
    with console.status("[bold green]Searching for plaintext...", spinner="dots"):
        results = engine.auto_decode(text)
    
    if results:
        console.print(f"\n[bold green][+] Found {len(results)} possible decode(s)![/bold green]")
        
        for i, (decoded, chain, confidence) in enumerate(results[:5], 1):
            table = Table(title=f"Result #{i}", box=None, show_header=False)
            table.add_column("Key", style="cyan")
            table.add_column("Value", style="green")
            table.add_row("Decoded Text", decoded[:500])
            table.add_row("Decoder Chain", " → ".join(chain))
            table.add_row("Confidence", f"{confidence:.1%}")
            console.print(table)
            console.print()
    else:
        console.print("\n[yellow][!] Could not auto-decode the input.[/yellow]")
        console.print("[cyan][*] Trying individual decoders...[/cyan]")
        
        for decoder in CipheyEngine.ALL_DECODERS:
            if decoder.can_decode(text.strip()):
                try:
                    result = decoder.decode(text.strip())
                    if result:
                        console.print(f"[green]  [{decoder.name}] {result[:200]}[/green]")
                except Exception:
                    pass
    
    # Step 4: Offer hash identification
    if hash_types:
        console.print(f"\n[cyan][*] Detected hash types: {', '.join(hash_types)}[/cyan]")


def run_hash_identifier(console=None):
    """Hash identification mode"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    from rich.prompt import Prompt
    
    console.print("\n[bold cyan]HASH IDENTIFIER[/bold cyan]")
    text = Prompt.ask("[cyan]Enter hash to identify[/cyan]")
    
    engine = CipheyEngine()
    results = engine.identify_hash(text.strip())
    
    if results:
        console.print(f"\n[green][+] Possible hash types:[/green]")
        for r in results:
            console.print(f"  [cyan]- {r}[/cyan]")
    else:
        console.print("\n[yellow][-] Could not identify hash type.[/yellow]")
        console.print("[cyan]    Supported: MD5, SHA-1, SHA-256, SHA-512, bcrypt, MySQL, NTLM, etc.[/cyan]")


# ============================================================================
# MAIN (standalone testing)
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = ' '.join(sys.argv[1:])
        engine = CipheyEngine()
        results = engine.auto_decode(text)
        if results:
            for decoded, chain, confidence in results:
                print(f"[{confidence:.1%}] {' -> '.join(chain)}: {decoded}")
        else:
            print("Could not decode")
    else:
        run_ciphey_scan()
