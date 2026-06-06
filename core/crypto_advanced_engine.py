#!/usr/bin/env python3
"""
ZYLON FUSION v5.0 - Crypto Engine Advanced
Fused from: Ciphey enhancements + p0-Cracking-Tool + OWASP ZSC + custom Zylon techniques
Capabilities:
  - Automatic encoding detection and decoding
  - Multi-layer encoding/encryption detection
  - Base64, Base32, Hex, URL, HTML entity decoding
  - ROT13, ROT47, Caesar cipher detection
  - Vigenere cipher detection
  - XOR cipher detection and cracking
  - RSA key analysis
  - JWT token structure analysis
  - AES/DES detection hints
  - Hash format identification
  - Custom cipher detection via frequency analysis
  - Encoding chain detection (e.g., base64(hex(rot13(text))))
Termux Compatible | No Root Required | Python 3.13+
"""

import re
import base64
import hashlib
import struct
import json
import math
import string
from datetime import datetime
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.var import USER_AGENTS, DEFAULT_TIMEOUT
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
# ENGLISH LETTER FREQUENCIES (for frequency analysis)
# ============================================================================

ENGLISH_FREQ = {
    'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
    'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
    'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
    'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
    'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
    'z': 0.074,
}

# Common English bigrams for validation
COMMON_BIGRAMS = ['th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
                   'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
                   'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le']

# Common English words for plaintext scoring
COMMON_WORDS = {'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i',
                'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
                'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
                'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
                'so', 'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me'}


# ============================================================================
# CRYPTO ADVANCED ENGINE
# ============================================================================

class CryptoAdvancedEngine:
    """
    Crypto Advanced Engine - Fused from Ciphey + p0-Cracking-Tool + OWASP ZSC
    Supports automatic decoding, multi-layer encoding detection,
    cipher cracking (XOR, Caesar, Vigenere), JWT analysis, frequency analysis.
    """

    def __init__(self):
        self.session = shared_session
        # User-Agent rotation and SSL verification handled by shared_session

    # ========================================================================
    # AUTOMATIC DECODING
    # ========================================================================

    def auto_decode(self, text):
        """
        Automatically detect and decode encoded/ciphered text.
        Tries all decoders and returns the most likely plaintext.
        
        Args:
            text: The encoded/ciphered text to decode
        """
        if not text:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No text provided'},
                'scan_type': 'auto_decode'
            }

        text = text.strip()
        results = {
            'input': text,
            'input_length': len(text),
            'decodings': [],
            'best_match': None,
            'timestamp': datetime.now().isoformat()
        }

        decoders = [
            ('Base64', self._try_base64),
            ('Base32', self._try_base32),
            ('Hex', self._try_hex),
            ('URL Encoding', self._try_url_decode),
            ('HTML Entities', self._try_html_entities),
            ('ROT13', self._try_rot13),
            ('ROT47', self._try_rot47),
            ('Caesar Cipher', self._try_caesar),
            ('Binary', self._try_binary),
            ('Octal', self._try_octal),
            ('Reverse', self._try_reverse),
            ('Atbash', self._try_atbash),
            ('Morse Code', self._try_morse),
            ('ASCII Numbers', self._try_ascii_numbers),
        ]

        for decoder_name, decoder_func in decoders:
            try:
                decoded_results = decoder_func(text)
                for decoded in decoded_results:
                    if decoded and decoded != text:
                        score = self._score_plaintext(decoded)
                        results['decodings'].append({
                            'type': decoder_name,
                            'decoded': decoded[:500],
                            'score': score,
                            'is_plaintext': score > 50,
                        })
            except Exception:
                pass

        # Sort by score
        results['decodings'].sort(key=lambda x: x['score'], reverse=True)

        if results['decodings']:
            results['best_match'] = results['decodings'][0]

        # Print results
        print(f"{CYAN}[ZYLON CRYPTO] Auto-decode: {text[:40]}...{RESET}")
        for d in results['decodings'][:5]:
            marker = f"{GREEN}[!]" if d['is_plaintext'] else f"{YELLOW}[?]"
            print(f"  {marker} {d['type']}: {d['decoded'][:60]}... (score: {d['score']:.0f}){RESET}")

        return {
            'vulnerable': len(results['decodings']) > 0,
            'findings': results['decodings'][:10],
            'details': results,
            'scan_type': 'auto_decode'
        }

    # ========================================================================
    # ENCODING DETECTION
    # ========================================================================

    def detect_encoding(self, text):
        """
        Detect the encoding/cipher type of the given text.
        Returns list of possible encodings with confidence.
        
        Args:
            text: Text to analyze
        """
        if not text:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No text provided'},
                'scan_type': 'detect_encoding'
            }

        text = text.strip()
        detected = []

        # Base64 detection
        if regex_cache.match(r'^[A-Za-z0-9+/]{4,}={0,2}$', text) and len(text) % 4 == 0:
            try:
                decoded = base64.b64decode(text)
                if decoded and len(decoded) > 0:
                    decoded_str = decoded.decode('utf-8', errors='ignore')
                    if self._is_printable(decoded_str):
                        detected.append({'type': 'Base64', 'confidence': 90})
                    else:
                        detected.append({'type': 'Base64 (binary)', 'confidence': 60})
            except Exception:
                pass

        # Base32 detection
        if regex_cache.match(r'^[A-Z2-7]+=*$', text.upper()) and len(text) % 8 <= 7:
            try:
                padded = text + '=' * ((8 - len(text) % 8) % 8)
                decoded = base64.b32decode(padded.upper())
                if decoded:
                    detected.append({'type': 'Base32', 'confidence': 80})
            except Exception:
                pass

        # Hex detection
        if regex_cache.match(r'^[0-9a-fA-F]+$', text) and len(text) % 2 == 0:
            detected.append({'type': 'Hex', 'confidence': 85})
        elif regex_cache.match(r'^[0-9a-fA-F\s]+$', text):
            detected.append({'type': 'Hex (with spaces)', 'confidence': 70})

        # URL encoding detection
        if '%' in text and regex_cache.search(r'%[0-9A-Fa-f]{2}', text):
            detected.append({'type': 'URL Encoding', 'confidence': 95})

        # HTML entity detection
        if '&' in text and (';' in text) and regex_cache.search(r'&#?\w+;', text):
            detected.append({'type': 'HTML Entities', 'confidence': 90})

        # ROT13 detection (if text has letter substitution pattern)
        rot13_test = self._apply_rot13(text)
        if rot13_test != text and self._score_plaintext(rot13_test) > self._score_plaintext(text):
            detected.append({'type': 'ROT13', 'confidence': 50})

        # Caesar cipher detection
        best_caesar = self._best_caesar_shift(text)
        if best_caesar and best_caesar['score'] > 50:
            detected.append({
                'type': f"Caesar Cipher (shift={best_caesar['shift']})",
                'confidence': min(int(best_caesar['score']), 80),
            })

        # Binary detection
        if regex_cache.match(r'^[01\s]+$', text):
            detected.append({'type': 'Binary', 'confidence': 90})

        # JWT detection
        if regex_cache.match(r'^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$', text):
            detected.append({'type': 'JWT Token', 'confidence': 95})

        # Hash detection
        hash_types = self._detect_hash_format(text)
        if hash_types:
            detected.extend(hash_types)

        # XOR detection (if looks like random but consistent length)
        if all(32 <= ord(c) < 127 for c in text) and len(text) > 10:
            freq = Counter(text)
            if len(freq) < len(text) * 0.6:  # Low entropy suggests XOR
                detected.append({'type': 'XOR Cipher (possible)', 'confidence': 30})

        # Vigenere detection
        if text.isalpha() and len(text) > 20:
            ic = self._index_of_coincidence(text)
            if 0.060 < ic < 0.070:  # English IC range
                detected.append({'type': 'Vigenere Cipher (possible)', 'confidence': 40})

        # Sort by confidence
        detected.sort(key=lambda x: x['confidence'], reverse=True)

        print(f"{CYAN}[ZYLON CRYPTO] Encoding detection: {text[:40]}...{RESET}")
        for d in detected[:5]:
            print(f"  {YELLOW}[{d['confidence']}%] {d['type']}{RESET}")

        return {
            'vulnerable': len(detected) > 0,
            'findings': detected,
            'details': {
                'input': text[:100],
                'input_length': len(text),
                'possible_types': len(detected),
                'top_match': detected[0] if detected else None,
            },
            'scan_type': 'detect_encoding'
        }

    # ========================================================================
    # MULTI-LAYER DECODING (Chain Detection)
    # ========================================================================

    def decode_chain(self, text, max_depth=5):
        """
        Detect and decode multi-layer encoding chains.
        e.g., base64(hex(rot13(text)))
        
        Args:
            text: The multiply-encoded text
            max_depth: Maximum decoding depth (default 5)
        """
        if not text:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No text provided'},
                'scan_type': 'decode_chain'
            }

        text = text.strip()
        chain = []
        current = text
        depth = 0

        print(f"{CYAN}[ZYLON CRYPTO] Chain decode: {text[:40]}... (max depth: {max_depth}){RESET}")

        while depth < max_depth and current:
            decoded = False

            # Try each decoder
            decoders = [
                ('Base64', self._try_base64),
                ('Base32', self._try_base32),
                ('Hex', self._try_hex),
                ('URL Encoding', self._try_url_decode),
                ('HTML Entities', self._try_html_entities),
                ('ROT13', self._try_rot13),
                ('ROT47', self._try_rot47),
            ]

            best_decode = None
            best_score = self._score_plaintext(current)

            for decoder_name, decoder_func in decoders:
                try:
                    results = decoder_func(current)
                    for decoded in results:
                        if decoded and decoded != current:
                            score = self._score_plaintext(decoded)
                            if score > best_score:
                                best_score = score
                                best_decode = (decoder_name, decoded)
                except Exception:
                    pass

            if best_decode and best_score > 40:
                decoder_name, decoded_text = best_decode
                chain.append({
                    'step': depth + 1,
                    'decoder': decoder_name,
                    'input': current[:100],
                    'output': decoded_text[:100],
                    'score': best_score,
                })
                current = decoded_text
                depth += 1
                decoded = True
                print(f"  {GREEN}[Step {depth}] {decoder_name}: {decoded_text[:60]}... (score: {best_score:.0f}){RESET}")

                # If score is very high, we've reached plaintext
                if best_score > 80:
                    break
            else:
                # Also try Caesar cipher at each step
                caesar_result = self._best_caesar_shift(current)
                if caesar_result and caesar_result['score'] > best_score + 10:
                    chain.append({
                        'step': depth + 1,
                        'decoder': f"Caesar (shift={caesar_result['shift']})",
                        'input': current[:100],
                        'output': caesar_result['text'][:100],
                        'score': caesar_result['score'],
                    })
                    current = caesar_result['text']
                    depth += 1
                    decoded = True
                    print(f"  {GREEN}[Step {depth}] Caesar-{caesar_result['shift']}: "
                          f"{caesar_result['text'][:60]}... (score: {caesar_result['score']:.0f}){RESET}")
                    if caesar_result['score'] > 80:
                        break
                else:
                    break

        return {
            'vulnerable': len(chain) > 0,
            'findings': chain,
            'details': {
                'input': text[:100],
                'final_output': current[:500],
                'chain_length': len(chain),
                'chain': chain,
                'fully_decoded': self._score_plaintext(current) > 70,
            },
            'scan_type': 'decode_chain'
        }

    # ========================================================================
    # XOR CRACKING
    # ========================================================================

    def crack_xor(self, ciphertext):
        """
        Crack XOR cipher by trying all single-byte keys and
        scoring results by English plaintext likelihood.
        
        Args:
            ciphertext: XOR-encrypted text (or hex representation)
        """
        if not ciphertext:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No ciphertext provided'},
                'scan_type': 'xor_crack'
            }

        ciphertext = ciphertext.strip()

        # Try to decode from hex first
        raw = None
        try:
            if regex_cache.match(r'^[0-9a-fA-F]+$', ciphertext) and len(ciphertext) % 2 == 0:
                raw = bytes.fromhex(ciphertext)
            else:
                raw = ciphertext.encode('utf-8', errors='ignore')
        except Exception:
            raw = ciphertext.encode('utf-8', errors='ignore')

        if not raw:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'Could not process ciphertext'},
                'scan_type': 'xor_crack'
            }

        print(f"{CYAN}[ZYLON CRYPTO] XOR cracking: {ciphertext[:40]}...{RESET}")

        results = []

        # Try single-byte XOR keys
        for key in range(256):
            try:
                decrypted = bytes([b ^ key for b in raw])
                decrypted_str = decrypted.decode('utf-8', errors='ignore')

                if decrypted_str and self._is_mostly_printable(decrypted_str):
                    score = self._score_plaintext(decrypted_str)
                    if score > 30:
                        results.append({
                            'key': key,
                            'key_hex': hex(key),
                            'key_char': chr(key) if 32 <= key < 127 else f'\\x{key:02x}',
                            'plaintext': decrypted_str[:500],
                            'score': score,
                        })
            except Exception:
                continue

        # Sort by score
        results.sort(key=lambda x: x['score'], reverse=True)

        # Try multi-byte XOR keys (2-4 bytes)
        multi_results = []
        for key_len in range(2, 5):
            best_key = self._find_multi_byte_xor_key(raw, key_len)
            if best_key:
                try:
                    key_bytes = bytes(best_key)
                    decrypted = bytes([raw[i] ^ key_bytes[i % key_len] for i in range(len(raw))])
                    decrypted_str = decrypted.decode('utf-8', errors='ignore')
                    if decrypted_str and self._is_mostly_printable(decrypted_str):
                        score = self._score_plaintext(decrypted_str)
                        if score > 40:
                            multi_results.append({
                                'key': key_bytes.hex(),
                                'key_length': key_len,
                                'plaintext': decrypted_str[:500],
                                'score': score,
                            })
                except Exception:
                    pass

        multi_results.sort(key=lambda x: x['score'], reverse=True)

        # Print top results
        for r in results[:3]:
            print(f"  {GREEN}[Key=0x{r['key_hex']}] {r['plaintext'][:60]}... "
                  f"(score: {r['score']:.0f}){RESET}")

        if multi_results:
            print(f"  {MAGENTA}[Multi-byte XOR] Found {len(multi_results)} possible keys{RESET}")
            for r in multi_results[:2]:
                print(f"    {YELLOW}[Key={r['key']}] {r['plaintext'][:60]}... "
                      f"(score: {r['score']:.0f}){RESET}")

        return {
            'vulnerable': len(results) > 0 or len(multi_results) > 0,
            'findings': results[:5] + multi_results[:3],
            'details': {
                'ciphertext': ciphertext[:100],
                'single_byte_results': len(results),
                'multi_byte_results': len(multi_results),
                'best_single_byte': results[0] if results else None,
                'best_multi_byte': multi_results[0] if multi_results else None,
            },
            'scan_type': 'xor_crack'
        }

    # ========================================================================
    # CAESAR CIPHER CRACKING
    # ========================================================================

    def crack_caesar(self, ciphertext):
        """
        Crack Caesar cipher by trying all 25 shifts.
        Uses frequency analysis to score each result.
        
        Args:
            ciphertext: Caesar-encrypted text
        """
        if not ciphertext:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No ciphertext provided'},
                'scan_type': 'caesar_crack'
            }

        ciphertext = ciphertext.strip()
        results = []

        print(f"{CYAN}[ZYLON CRYPTO] Caesar cracking: {ciphertext[:40]}...{RESET}")

        for shift in range(1, 26):
            decrypted = self._apply_caesar(ciphertext, shift)
            if decrypted != ciphertext:
                score = self._score_plaintext(decrypted)
                results.append({
                    'shift': shift,
                    'reverse_shift': 26 - shift,
                    'plaintext': decrypted[:500],
                    'score': score,
                    'is_likely': score > 60,
                })

        # Sort by score
        results.sort(key=lambda x: x['score'], reverse=True)

        for r in results[:3]:
            marker = f"{GREEN}[!!!]" if r['is_likely'] else f"{YELLOW}[?]"
            print(f"  {marker} Shift={r['shift']}: {r['plaintext'][:60]}... "
                  f"(score: {r['score']:.0f}){RESET}")

        return {
            'vulnerable': any(r['is_likely'] for r in results),
            'findings': results[:10],
            'details': {
                'ciphertext': ciphertext[:100],
                'total_shifts': len(results),
                'best_match': results[0] if results else None,
                'likely_shift': results[0]['shift'] if results and results[0]['is_likely'] else None,
            },
            'scan_type': 'caesar_crack'
        }

    # ========================================================================
    # FREQUENCY ANALYSIS
    # ========================================================================

    def analyze_frequency(self, text):
        """
        Perform frequency analysis on text.
        Useful for cipher identification and cracking.
        
        Args:
            text: Text to analyze
        """
        if not text:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No text provided'},
                'scan_type': 'frequency_analysis'
            }

        text = text.strip()
        alpha_only = ''.join(c.lower() for c in text if c.isalpha())

        if not alpha_only:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No alphabetic characters found'},
                'scan_type': 'frequency_analysis'
            }

        # Letter frequency
        letter_freq = Counter(alpha_only)
        total_letters = len(alpha_only)
        freq_percent = {k: round(v / total_letters * 100, 2) for k, v in letter_freq.items()}

        # Sort by frequency
        sorted_freq = sorted(freq_percent.items(), key=lambda x: x[1], reverse=True)

        # Index of Coincidence
        ic = self._index_of_coincidence(alpha_only)

        # Chi-squared test against English
        chi_squared = self._chi_squared_test(alpha_only)

        # Identify most likely cipher type
        cipher_type = "Unknown"
        cipher_confidence = 0

        if ic > 0.060 and ic < 0.070:
            cipher_type = "Simple substitution (Caesar, monoalphabetic)"
            cipher_confidence = 70
        elif ic > 0.035 and ic < 0.050:
            cipher_type = "Polyalphabetic (Vigenere, Beaufort)"
            cipher_confidence = 60
        elif ic < 0.035:
            cipher_type = "Random/polyalphabetic with long key"
            cipher_confidence = 40
        elif ic > 0.070:
            cipher_type = "Transposition cipher or plaintext"
            cipher_confidence = 50

        # Most frequent letter
        most_freq = sorted_freq[0] if sorted_freq else ('?', 0)

        # Estimated shift (assuming Caesar cipher)
        estimated_shift = 0
        if most_freq[0] != 'e':
            estimated_shift = (ord(most_freq[0]) - ord('e')) % 26

        # Bigram analysis
        bigrams = [alpha_only[i:i+2] for i in range(len(alpha_only) - 1)]
        bigram_freq = Counter(bigrams)
        top_bigrams = bigram_freq.most_common(10)

        # Print results
        print(f"{CYAN}[ZYLON CRYPTO] Frequency Analysis{RESET}")
        print(f"  {YELLOW}Total letters: {total_letters}{RESET}")
        print(f"  {YELLOW}Index of Coincidence: {ic:.4f}{RESET}")
        print(f"  {YELLOW}Chi-squared: {chi_squared:.2f}{RESET}")
        print(f"  {YELLOW}Likely cipher: {cipher_type} ({cipher_confidence}%){RESET}")
        print(f"  {YELLOW}Top 5 letters: {', '.join(f'{l}:{f}%' for l, f in sorted_freq[:5])}{RESET}")
        print(f"  {YELLOW}Estimated Caesar shift: {estimated_shift}{RESET}")

        return {
            'vulnerable': True,
            'findings': [{
                'cipher_type': cipher_type,
                'confidence': cipher_confidence,
                'ic': ic,
                'estimated_shift': estimated_shift,
                'most_frequent_letter': most_freq[0],
                'chi_squared': chi_squared,
            }],
            'details': {
                'text_length': len(text),
                'alpha_length': total_letters,
                'letter_frequency': freq_percent,
                'sorted_frequency': sorted_freq,
                'index_of_coincidence': ic,
                'chi_squared': chi_squared,
                'cipher_type': cipher_type,
                'cipher_confidence': cipher_confidence,
                'estimated_caesar_shift': estimated_shift,
                'top_bigrams': top_bigrams,
                'most_frequent': most_freq,
                'english_comparison': {
                    'top_english': 'ETAOINSHRDLC',
                    'top_text': ''.join(l for l, _ in sorted_freq[:12]),
                },
            },
            'scan_type': 'frequency_analysis'
        }

    # ========================================================================
    # JWT TOKEN ANALYSIS
    # ========================================================================

    def analyze_jwt(self, token):
        """Analyze JWT token structure"""
        if not token or '.' not in token:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'Not a valid JWT token'},
                'scan_type': 'jwt_analysis'
            }

        parts = token.split('.')
        if len(parts) != 3:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'JWT must have 3 parts (header.payload.signature)'},
                'scan_type': 'jwt_analysis'
            }

        findings = []

        try:
            # Decode header
            header_padded = parts[0] + '=' * ((4 - len(parts[0]) % 4) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            # Decode payload
            payload_padded = parts[1] + '=' * ((4 - len(parts[1]) % 4) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            # Analyze header
            alg = header.get('alg', 'none')
            if alg == 'none':
                findings.append({
                    'type': 'critical',
                    'finding': 'JWT uses "none" algorithm - authentication bypass possible',
                    'risk': 'critical',
                })
            elif alg.startswith('HS'):
                findings.append({
                    'type': 'info',
                    'finding': f'JWT uses symmetric algorithm {alg} - potential key confusion attack',
                    'risk': 'medium',
                })
            elif alg.startswith('RS') or alg.startswith('ES'):
                findings.append({
                    'type': 'info',
                    'finding': f'JWT uses asymmetric algorithm {alg}',
                    'risk': 'low',
                })

            # Check for empty signature
            if not parts[2]:
                findings.append({
                    'type': 'critical',
                    'finding': 'JWT has empty signature - trivially forgeable',
                    'risk': 'critical',
                })

            # Analyze payload
            if 'exp' not in payload:
                findings.append({
                    'type': 'warning',
                    'finding': 'JWT has no expiration claim (exp)',
                    'risk': 'medium',
                })

            if 'iat' in payload:
                findings.append({
                    'type': 'info',
                    'finding': f'JWT issued at: {payload["iat"]}',
                    'risk': 'info',
                })

            sensitive_fields = ['password', 'secret', 'key', 'token', 'credential']
            for field in sensitive_fields:
                if field in str(payload).lower():
                    findings.append({
                        'type': 'warning',
                        'finding': f'JWT payload may contain sensitive field: {field}',
                        'risk': 'high',
                    })

            return {
                'vulnerable': any(f.get('risk') in ['critical', 'high'] for f in findings),
                'findings': findings,
                'details': {
                    'header': header,
                    'payload': payload,
                    'algorithm': alg,
                    'has_signature': bool(parts[2]),
                    'findings': findings,
                },
                'scan_type': 'jwt_analysis'
            }

        except Exception as e:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': f'JWT decode error: {str(e)}'},
                'scan_type': 'jwt_analysis'
            }

    # ========================================================================
    # RSA KEY ANALYSIS
    # ========================================================================

    def analyze_rsa_key(self, key_data):
        """Analyze RSA key for common vulnerabilities"""
        findings = []

        if 'BEGIN RSA PRIVATE KEY' in key_data or 'BEGIN PRIVATE KEY' in key_data:
            findings.append({
                'type': 'critical',
                'finding': 'RSA private key exposed - immediate compromise possible',
                'risk': 'critical',
            })

            # Check key size hints
            if 'RSA-1024' in key_data or '1024' in key_data:
                findings.append({
                    'type': 'warning',
                    'finding': 'RSA-1024 key detected - considered weak, should use 2048+',
                    'risk': 'high',
                })

        if 'BEGIN PUBLIC KEY' in key_data:
            findings.append({
                'type': 'info',
                'finding': 'Public key detected - check key size and usage',
                'risk': 'info',
            })

        return {
            'vulnerable': any(f.get('risk') in ['critical', 'high'] for f in findings),
            'findings': findings,
            'details': {'key_type': 'private' if 'PRIVATE' in key_data else 'public', 'findings': findings},
            'scan_type': 'rsa_analysis'
        }

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='auto', **kwargs):
        """Main entry point for Crypto Advanced engine"""
        if not target:
            return {
                'vulnerable': False,
                'findings': [],
                'details': {'error': 'No target text provided'},
                'scan_type': scan_type
            }

        scan_methods = {
            'auto': lambda: self.auto_decode(target),
            'detect': lambda: self.detect_encoding(target),
            'chain': lambda: self.decode_chain(target, max_depth=kwargs.get('max_depth', 5)),
            'xor': lambda: self.crack_xor(target),
            'caesar': lambda: self.crack_caesar(target),
            'frequency': lambda: self.analyze_frequency(target),
            'jwt': lambda: self.analyze_jwt(target),
            'rsa': lambda: self.analyze_rsa_key(target),
            'full': lambda: self._full_analysis(target),
        }

        if scan_type in scan_methods:
            return scan_methods[scan_type]()

        return {
            'vulnerable': False,
            'findings': [],
            'details': {'error': f'Unknown scan type: {scan_type}'},
            'scan_type': scan_type
        }

    def _full_analysis(self, text):
        """Full crypto analysis combining all methods"""
        print(f"{BOLD}{CYAN}[ZYLON CRYPTO] Full Analysis{RESET}")

        results = {}

        # Phase 1: Auto decode
        print(f"\n{CYAN}=== Phase 1: Auto Decode ==={RESET}")
        results['auto_decode'] = self.auto_decode(text)

        # Phase 2: Encoding detection
        print(f"\n{YELLOW}=== Phase 2: Encoding Detection ==={RESET}")
        results['detect_encoding'] = self.detect_encoding(text)

        # Phase 3: Chain decode
        print(f"\n{MAGENTA}=== Phase 3: Chain Decode ==={RESET}")
        results['decode_chain'] = self.decode_chain(text)

        # Phase 4: XOR crack
        print(f"\n{RED}=== Phase 4: XOR Crack ==={RESET}")
        results['xor_crack'] = self.crack_xor(text)

        # Phase 5: Caesar crack
        print(f"\n{GREEN}=== Phase 5: Caesar Crack ==={RESET}")
        results['caesar_crack'] = self.crack_caesar(text)

        # Phase 6: Frequency analysis
        print(f"\n{CYAN}=== Phase 6: Frequency Analysis ==={RESET}")
        results['frequency'] = self.analyze_frequency(text)

        # Summary
        total_findings = sum(
            len(r.get('findings', [])) for r in results.values()
        )

        print(f"\n{BOLD}{GREEN}[ZYLON CRYPTO] Full analysis complete: {total_findings} total findings{RESET}")

        return {
            'vulnerable': any(r.get('vulnerable', False) for r in results.values()),
            'findings': [{'phase': k, 'findings': v.get('findings', [])} for k, v in results.items()],
            'details': results,
            'scan_type': 'crypto_full'
        }

    # ========================================================================
    # DECODER HELPER FUNCTIONS
    # ========================================================================

    def _try_base64(self, text):
        """Try Base64 decoding"""
        results = []
        try:
            # Standard Base64
            padded = text + '=' * ((4 - len(text) % 4) % 4)
            decoded = base64.b64decode(padded)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if decoded_str and self._is_mostly_printable(decoded_str) and len(decoded_str) > 0:
                results.append(decoded_str)
        except Exception:
            pass

        try:
            # URL-safe Base64
            padded = text + '=' * ((4 - len(text) % 4) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if decoded_str and self._is_mostly_printable(decoded_str) and len(decoded_str) > 0:
                results.append(decoded_str)
        except Exception:
            pass

        return results

    def _try_base32(self, text):
        """Try Base32 decoding"""
        results = []
        try:
            padded = text.upper() + '=' * ((8 - len(text) % 8) % 8)
            decoded = base64.b32decode(padded)
            decoded_str = decoded.decode('utf-8', errors='ignore')
            if decoded_str and self._is_mostly_printable(decoded_str) and len(decoded_str) > 0:
                results.append(decoded_str)
        except Exception:
            pass
        return results

    def _try_hex(self, text):
        """Try Hex decoding"""
        results = []
        try:
            clean = text.replace(' ', '').replace('0x', '').replace('\\x', '')
            if regex_cache.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0 and len(clean) >= 2:
                decoded = bytes.fromhex(clean).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 0:
                    results.append(decoded)
        except Exception:
            pass
        return results

    def _try_url_decode(self, text):
        """Try URL decoding"""
        results = []
        try:
            from urllib.parse import unquote
            decoded = unquote(text)
            if decoded != text:
                results.append(decoded)
        except Exception:
            pass
        return results

    def _try_html_entities(self, text):
        """Try HTML entity decoding"""
        results = []
        try:
            import html
            decoded = html.unescape(text)
            if decoded != text:
                results.append(decoded)
        except Exception:
            pass
        return results

    def _try_rot13(self, text):
        """Try ROT13 decoding"""
        results = []
        try:
            decoded = self._apply_rot13(text)
            if decoded != text:
                results.append(decoded)
        except Exception:
            pass
        return results

    def _try_rot47(self, text):
        """Try ROT47 decoding"""
        results = []
        try:
            decoded = self._apply_rot47(text)
            if decoded != text:
                results.append(decoded)
        except Exception:
            pass
        return results

    def _try_caesar(self, text):
        """Try all Caesar cipher shifts"""
        results = []
        for shift in range(1, 26):
            try:
                decoded = self._apply_caesar(text, shift)
                if decoded != text:
                    results.append(decoded)
            except Exception:
                pass
        return results

    def _try_binary(self, text):
        """Try binary decoding"""
        results = []
        try:
            clean = text.replace(' ', '')
            if regex_cache.match(r'^[01]+$', clean) and len(clean) % 8 == 0:
                decoded = ''
                for i in range(0, len(clean), 8):
                    byte = clean[i:i+8]
                    decoded += chr(int(byte, 2))
                if decoded and self._is_mostly_printable(decoded):
                    results.append(decoded)
        except Exception:
            pass
        return results

    def _try_octal(self, text):
        """Try octal decoding"""
        results = []
        try:
            parts = text.split()
            decoded = ''
            for part in parts:
                if regex_cache.match(r'^[0-7]+$', part):
                    val = int(part, 8)
                    if 0 <= val < 256:
                        decoded += chr(val)
            if decoded and len(decoded) > 1:
                results.append(decoded)
        except Exception:
            pass
        return results

    def _try_reverse(self, text):
        """Try reverse text"""
        results = []
        try:
            decoded = text[::-1]
            if decoded != text:
                results.append(decoded)
        except Exception:
            pass
        return results

    def _try_atbash(self, text):
        """Try Atbash cipher (reverse alphabet)"""
        results = []
        try:
            decoded = ''
            for c in text:
                if c.isalpha():
                    if c.isupper():
                        decoded += chr(ord('Z') - (ord(c) - ord('A')))
                    else:
                        decoded += chr(ord('z') - (ord(c) - ord('a')))
                else:
                    decoded += c
            if decoded != text:
                results.append(decoded)
        except Exception:
            pass
        return results

    def _try_morse(self, text):
        """Try Morse code decoding"""
        MORSE_MAP = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
            '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
            '----.': '9',
        }
        results = []
        try:
            if '.' in text and '-' in text:
                words = text.split(' / ')
                decoded_words = []
                for word in words:
                    letters = word.split(' ')
                    decoded_word = ''
                    for letter in letters:
                        if letter in MORSE_MAP:
                            decoded_word += MORSE_MAP[letter]
                    if decoded_word:
                        decoded_words.append(decoded_word)
                decoded = ' '.join(decoded_words)
                if decoded and len(decoded) > 0:
                    results.append(decoded)
        except Exception:
            pass
        return results

    def _try_ascii_numbers(self, text):
        """Try decoding ASCII numbers (comma or space separated)"""
        results = []
        try:
            # Comma-separated
            if ',' in text:
                parts = text.split(',')
            else:
                parts = text.split()

            decoded = ''
            valid = True
            for part in parts:
                part = part.strip()
                if part.isdigit():
                    val = int(part)
                    if 32 <= val < 127:
                        decoded += chr(val)
                    else:
                        valid = False
                        break
                else:
                    valid = False
                    break

            if valid and decoded and len(decoded) > 1:
                results.append(decoded)
        except Exception:
            pass
        return results

    # ========================================================================
    # UTILITY FUNCTIONS
    # ========================================================================

    def _apply_rot13(self, text):
        """Apply ROT13 transformation"""
        result = ''
        for c in text:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                result += chr(base + (ord(c) - base + 13) % 26)
            else:
                result += c
        return result

    def _apply_rot47(self, text):
        """Apply ROT47 transformation"""
        result = ''
        for c in text:
            if 33 <= ord(c) <= 126:
                result += chr(33 + ((ord(c) - 33 + 47) % 94))
            else:
                result += c
        return result

    def _apply_caesar(self, text, shift):
        """Apply Caesar cipher with given shift"""
        result = ''
        for c in text:
            if c.isalpha():
                base = ord('a') if c.islower() else ord('A')
                result += chr(base + (ord(c) - base + shift) % 26)
            else:
                result += c
        return result

    def _score_plaintext(self, text):
        """
        Score text for English plaintext likelihood (0-100).
        Higher score = more likely to be English plaintext.
        """
        if not text:
            return 0

        score = 0
        alpha_only = ''.join(c.lower() for c in text if c.isalpha())

        if not alpha_only:
            return 0

        # Letter frequency chi-squared
        chi = self._chi_squared_test(alpha_only)
        if chi < 50:
            score += 40
        elif chi < 100:
            score += 25
        elif chi < 200:
            score += 10

        # Common word presence
        words = regex_cache.findall(r'\b[a-z]+\b', text.lower())
        if words:
            common_count = sum(1 for w in words if w in COMMON_WORDS)
            word_ratio = common_count / len(words)
            score += min(word_ratio * 40, 30)

        # Printable ratio
        printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\n\r\t')
        printable_ratio = printable / len(text) if text else 0
        score += printable_ratio * 20

        # Space frequency (English has ~15-20% spaces)
        space_ratio = text.count(' ') / len(text) if text else 0
        if 0.10 < space_ratio < 0.25:
            score += 10

        return min(score, 100)

    def _chi_squared_test(self, text):
        """Chi-squared test against English letter frequencies"""
        freq = Counter(text.lower())
        total = sum(freq.values())
        if total == 0:
            return float('inf')

        chi = 0
        for letter in string.ascii_lowercase:
            observed = freq.get(letter, 0)
            expected = total * ENGLISH_FREQ.get(letter, 0) / 100
            if expected > 0:
                chi += (observed - expected) ** 2 / expected

        return chi

    def _index_of_coincidence(self, text):
        """Calculate Index of Coincidence"""
        freq = Counter(text.lower())
        n = len(text)
        if n <= 1:
            return 0

        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic

    def _best_caesar_shift(self, text):
        """Find the best Caesar cipher shift"""
        best = None
        best_score = 0

        for shift in range(1, 26):
            decoded = self._apply_caesar(text, shift)
            if decoded != text:
                score = self._score_plaintext(decoded)
                if score > best_score:
                    best_score = score
                    best = {'shift': shift, 'text': decoded, 'score': score}

        return best

    def _is_printable(self, text):
        """Check if text is mostly printable"""
        if not text:
            return False
        printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\n\r\t')
        return printable / len(text) > 0.9

    def _is_mostly_printable(self, text):
        """Check if text is at least 70% printable"""
        if not text:
            return False
        printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\n\r\t')
        return printable / len(text) > 0.7

    def _detect_hash_format(self, text):
        """Detect common hash formats"""
        results = []
        t = text.strip().lower()

        if regex_cache.match(r'^[a-f0-9]{32}$', t):
            results.append({'type': 'MD5/NTLM Hash', 'confidence': 75})
        elif regex_cache.match(r'^[a-f0-9]{40}$', t):
            results.append({'type': 'SHA1 Hash', 'confidence': 75})
        elif regex_cache.match(r'^[a-f0-9]{64}$', t):
            results.append({'type': 'SHA256 Hash', 'confidence': 75})
        elif regex_cache.match(r'^[a-f0-9]{128}$', t):
            results.append({'type': 'SHA512 Hash', 'confidence': 75})
        elif regex_cache.match(r'^\$2[aby]\$', t):
            results.append({'type': 'bcrypt Hash', 'confidence': 95})
        elif regex_cache.match(r'^\$6\$', t):
            results.append({'type': 'SHA-512-Crypt Hash', 'confidence': 95})
        elif regex_cache.match(r'^\$1\$', t):
            results.append({'type': 'MD5-Crypt Hash', 'confidence': 95})
        elif regex_cache.match(r'^\*[a-f0-9]{40}$', t):
            results.append({'type': 'MySQL5 Hash', 'confidence': 90})

        return results

    def _find_multi_byte_xor_key(self, data, key_len):
        """Find multi-byte XOR key using frequency analysis"""
        if len(data) < key_len * 2:
            return None

        best_key = []
        for pos in range(key_len):
            best_byte = 0
            best_score = 0
            for key_byte in range(256):
                score = 0
                count = 0
                for i in range(pos, len(data), key_len):
                    decrypted = data[i] ^ key_byte
                    if chr(decrypted).lower() in 'etaoinsrhld ':
                        score += 1
                    count += 1
                if count > 0 and score / count > best_score:
                    best_score = score / count
                    best_byte = key_byte
            best_key.append(best_byte)

        return best_key


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target=None, scan_type='auto', **kwargs):
    """Module-level run function for ZYLON integration"""
    engine = CryptoAdvancedEngine()
    return engine.run(target, scan_type=scan_type, **kwargs)
