#!/usr/bin/env python3
"""
ZYLON FUSION v5.0.0 - Business Logic Vulnerability Engine
Based on: BizLogic (https://github.com/ekomsSavior/bizlogic)
Capabilities:
  - Price manipulation detection
  - Quantity fraud detection
  - Privilege escalation via business logic flaws
  - Bypass payment flow testing
  - Race condition in business operations
  - Discount/coupon abuse detection
  - Cart manipulation testing
  - User role escalation detection
  - Multi-step business flow testing
  - API business logic flaw detection
Termux Compatible | No Root Required | Python 3.13+
"""

import requests
import re
import os
import time
import random
import string
import json
import copy
import hashlib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Thread, Event

# ============================================================================
# ANSI COLORS (Termux compatible)
# ============================================================================

RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ============================================================================
# BUSINESS LOGIC TEST PAYLOADS
# ============================================================================

# Price manipulation test values
PRICE_MANIPULATION_PAYLOADS = [
    {"price": 0},
    {"price": -1},
    {"price": 0.01},
    {"price": -999},
    {"price": 0.00},
    {"price": "0"},
    {"price": "-1"},
    {"price": 0.001},
    {"amount": 0},
    {"amount": -1},
    {"amount": 0.01},
    {"total": 0},
    {"total": -1},
    {"cost": 0},
    {"cost": -1},
]

# Quantity fraud test values
QUANTITY_FRAUD_PAYLOADS = [
    {"quantity": -1},
    {"quantity": 0},
    {"quantity": 999999},
    {"quantity": -999},
    {"quantity": 0.5},
    {"quantity": -0.5},
    {"quantity": 1.5},
    {"qty": -1},
    {"qty": 0},
    {"qty": 999999},
    {"count": -1},
    {"count": 0},
    {"count": 999999},
]

# Discount/coupon abuse payloads
DISCOUNT_ABUSE_PAYLOADS = [
    {"discount": 100},
    {"discount": 999},
    {"discount": -1},
    {"coupon": "FREE100"},
    {"coupon": "ADMIN"},
    {"coupon": "TEST"},
    {"coupon": "BUGBOUNTY"},
    {"discount_percent": 100},
    {"discount_percent": 200},
    {"discount_percent": -1},
    {"promo_code": "FREE"},
    {"promo_code": "ADMIN"},
    {"promo_code": "TEST"},
    {"voucher": "100OFF"},
    {"voucher": "FREE"},
]

# Cart manipulation payloads
CART_MANIPULATION_PAYLOADS = [
    {"cart_id": "other_user_cart"},
    {"item_id": "premium_item"},
    {"price": 0.01},
    {"quantity": -1},
    {"total": 0},
    {"subtotal": 0},
    {"discount": 100},
    {"user_id": "admin"},
    {"is_paid": True},
    {"status": "completed"},
    {"payment_status": "paid"},
    {"order_status": "delivered"},
]

# Privilege escalation payloads
PRIVILEGE_ESCALATION_PAYLOADS = [
    {"role": "admin"},
    {"role": "administrator"},
    {"role": "superadmin"},
    {"role": "manager"},
    {"is_admin": True},
    {"is_admin": 1},
    {"is_admin": "true"},
    {"admin": True},
    {"admin": 1},
    {"user_type": "admin"},
    {"user_role": "admin"},
    {"permission": "admin"},
    {"access_level": 10},
    {"access_level": 999},
    {"is_premium": True},
    {"is_vip": True},
    {"group": "admin"},
    {"groups": ["admin"]},
]

# Payment bypass test patterns
PAYMENT_BYPASS_PAYLOADS = [
    {"payment_status": "completed"},
    {"payment_status": "paid"},
    {"payment_status": "success"},
    {"status": "completed"},
    {"status": "paid"},
    {"status": "approved"},
    {"paid": True},
    {"paid": 1},
    {"is_paid": True},
    {"is_paid": 1},
    {"transaction_status": "completed"},
    {"order_status": "completed"},
    {"bypass_payment": True},
    {"skip_payment": True},
    {"free_order": True},
    {"amount": 0},
    {"amount": 0.01},
    {"total": 0},
    {"price": 0},
]

# Common business API endpoints
BUSINESS_API_ENDPOINTS = [
    "/api/cart", "/api/cart/add", "/api/cart/update", "/api/cart/remove",
    "/api/checkout", "/api/order", "/api/order/create", "/api/order/update",
    "/api/payment", "/api/payment/process", "/api/payment/verify",
    "/api/discount", "/api/coupon", "/api/coupon/apply", "/api/coupon/validate",
    "/api/user", "/api/user/update", "/api/user/profile",
    "/api/product", "/api/product/update", "/api/product/price",
    "/api/subscription", "/api/subscription/update",
    "/api/transfer", "/api/withdraw", "/api/deposit",
    "/api/refund", "/api/refund/create",
    "/api/invoice", "/api/invoice/create",
    "/cart", "/checkout", "/order", "/payment",
    "/account", "/profile", "/settings",
    "/api/v1/cart", "/api/v1/order", "/api/v1/payment",
    "/api/v2/cart", "/api/v2/order", "/api/v2/payment",
]

# Role escalation test endpoints
ROLE_ESCALATION_ENDPOINTS = [
    "/api/user/role", "/api/user/upgrade", "/api/admin",
    "/api/user/admin", "/api/settings", "/api/config",
    "/api/permissions", "/api/access", "/api/privilege",
    "/admin", "/dashboard", "/manage", "/control",
    "/api/v1/admin", "/api/v1/user/role",
]


class BizLogicEngine:
    """Business Logic Vulnerability Detection Engine - Based on BizLogic"""

    def __init__(self, target_url=None, headers=None, cookies=None, proxy=None,
                 timeout=10, threads=10, auth_token=None):
        self.target_url = target_url
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.proxy = proxy
        self.timeout = timeout
        self.threads = threads
        self.auth_token = auth_token
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36',
            'Content-Type': 'application/json',
        })
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        if auth_token:
            self.session.headers.update({'Authorization': f'Bearer {auth_token}'})
        self._lock = Lock()

    def _send_request(self, url, method="GET", data=None, json_data=None, headers=None):
        """Send HTTP request with error handling"""
        try:
            h = headers or dict(self.session.headers)
            if method == "GET":
                resp = self.session.get(url, headers=h, cookies=self.cookies,
                                       timeout=self.timeout, allow_redirects=True)
            elif method == "POST":
                resp = self.session.post(url, data=data, json=json_data, headers=h,
                                        cookies=self.cookies, timeout=self.timeout,
                                        allow_redirects=True)
            elif method == "PUT":
                resp = self.session.put(url, data=data, json=json_data, headers=h,
                                       cookies=self.cookies, timeout=self.timeout,
                                       allow_redirects=True)
            elif method == "PATCH":
                resp = self.session.patch(url, data=data, json=json_data, headers=h,
                                         cookies=self.cookies, timeout=self.timeout,
                                         allow_redirects=True)
            elif method == "DELETE":
                resp = self.session.delete(url, headers=h, cookies=self.cookies,
                                          timeout=self.timeout, allow_redirects=True)
            else:
                resp = self.session.get(url, headers=h, cookies=self.cookies,
                                       timeout=self.timeout, allow_redirects=True)
            return resp
        except Exception:
            return None

    def _get_base_url(self, url=None):
        """Get base URL from target"""
        target = url or self.target_url
        if not target:
            return None
        if not target.startswith('http'):
            target = f"https://{target}"
        return target.rstrip('/')

    def _detect_api_endpoints(self, base_url):
        """Discover business API endpoints"""
        discovered = []
        for endpoint in BUSINESS_API_ENDPOINTS:
            url = f"{base_url}{endpoint}"
            resp = self._send_request(url, method="GET")
            if resp and resp.status_code in [200, 201, 401, 403, 405]:
                discovered.append({
                    'endpoint': endpoint,
                    'url': url,
                    'status_code': resp.status_code,
                    'methods': self._detect_methods(url, resp),
                })
        return discovered

    def _detect_methods(self, url, initial_resp):
        """Detect supported HTTP methods"""
        methods = []
        for method in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            resp = self._send_request(url, method=method)
            if resp and resp.status_code != 405:
                methods.append(method)
        return methods

    def _compare_responses(self, original, modified, label=""):
        """Compare original vs modified response to detect logic flaws"""
        if not original or not modified:
            return None

        differences = {
            'label': label,
            'status_diff': original.status_code != modified.status_code,
            'length_diff': abs(len(original.text) - len(modified.text)),
            'content_diff': False,
            'details': {},
        }

        # Status code difference
        if differences['status_diff']:
            differences['details']['original_status'] = original.status_code
            differences['details']['modified_status'] = modified.status_code

        # Significant content length difference (>10%)
        orig_len = len(original.text)
        mod_len = len(modified.text)
        if orig_len > 0 and abs(orig_len - mod_len) / max(orig_len, 1) > 0.1:
            differences['content_diff'] = True
            differences['details']['original_length'] = orig_len
            differences['details']['modified_length'] = mod_len

        # Check for success indicators in modified response
        success_indicators = [
            'success', 'completed', 'approved', 'paid', 'confirmed',
            'order placed', 'payment processed', 'saved', 'updated',
            'created', 'delivered', 'confirmed', 'activated',
        ]
        mod_text_lower = modified.text.lower()
        orig_text_lower = original.text.lower()
        for indicator in success_indicators:
            if indicator in mod_text_lower and indicator not in orig_text_lower:
                differences['content_diff'] = True
                differences['details']['success_indicator'] = indicator

        # Check for error indicators absent in modified
        error_indicators = ['error', 'invalid', 'denied', 'failed', 'unauthorized']
        for indicator in error_indicators:
            if indicator in orig_text_lower and indicator not in mod_text_lower:
                differences['content_diff'] = True
                differences['details']['error_removed'] = indicator

        return differences if (differences['status_diff'] or differences['content_diff']) else None

    # ========================================================================
    # SCAN: Price Manipulation Detection
    # ========================================================================

    def test_price_manipulation(self, url=None):
        """Test for price manipulation vulnerabilities"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_price_manipulation'}

        print(f"{CYAN}{BOLD}[BizLogic] Price Manipulation Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'manipulation_found': 0,
            },
            'scan_type': 'bizlogic_price_manipulation',
        }

        # Discover relevant endpoints
        price_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                          if any(kw in e for kw in ['cart', 'order', 'checkout', 'product', 'payment'])]

        for endpoint in price_endpoints[:10]:
            endpoint_url = f"{base}{endpoint}"

            # Get baseline response
            baseline = self._send_request(endpoint_url, method="GET")
            if not baseline or baseline.status_code == 404:
                continue

            results['details']['endpoints_tested'].append(endpoint)

            # Test price manipulation payloads
            for payload in PRICE_MANIPULATION_PAYLOADS:
                # Try POST
                resp = self._send_request(endpoint_url, method="POST", json_data=payload)
                diff = self._compare_responses(baseline, resp, f"price_manipulation_post_{list(payload.keys())[0]}")
                if diff:
                    results['vulnerable'] = True
                    results['details']['manipulation_found'] += 1
                    results['findings'].append({
                        'type': 'price_manipulation',
                        'endpoint': endpoint,
                        'method': 'POST',
                        'payload': payload,
                        'difference': diff,
                        'severity': 'critical',
                    })

                # Try PUT
                resp = self._send_request(endpoint_url, method="PUT", json_data=payload)
                diff = self._compare_responses(baseline, resp, f"price_manipulation_put_{list(payload.keys())[0]}")
                if diff:
                    results['vulnerable'] = True
                    results['details']['manipulation_found'] += 1
                    results['findings'].append({
                        'type': 'price_manipulation',
                        'endpoint': endpoint,
                        'method': 'PUT',
                        'payload': payload,
                        'difference': diff,
                        'severity': 'critical',
                    })

                # Try PATCH
                resp = self._send_request(endpoint_url, method="PATCH", json_data=payload)
                diff = self._compare_responses(baseline, resp, f"price_manipulation_patch_{list(payload.keys())[0]}")
                if diff:
                    results['vulnerable'] = True
                    results['details']['manipulation_found'] += 1
                    results['findings'].append({
                        'type': 'price_manipulation',
                        'endpoint': endpoint,
                        'method': 'PATCH',
                        'payload': payload,
                        'difference': diff,
                        'severity': 'critical',
                    })

        print(f"{GREEN}[BizLogic] Price Manipulation: {results['details']['manipulation_found']} issues found{RESET}")
        return results

    # ========================================================================
    # SCAN: Quantity Fraud Detection
    # ========================================================================

    def test_quantity_fraud(self, url=None):
        """Test for quantity fraud vulnerabilities"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_quantity_fraud'}

        print(f"{CYAN}{BOLD}[BizLogic] Quantity Fraud Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'fraud_found': 0,
            },
            'scan_type': 'bizlogic_quantity_fraud',
        }

        qty_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                        if any(kw in e for kw in ['cart', 'order', 'product', 'checkout'])]

        for endpoint in qty_endpoints[:8]:
            endpoint_url = f"{base}{endpoint}"
            baseline = self._send_request(endpoint_url, method="GET")
            if not baseline or baseline.status_code == 404:
                continue

            results['details']['endpoints_tested'].append(endpoint)

            for payload in QUANTITY_FRAUD_PAYLOADS:
                for method in ['POST', 'PUT', 'PATCH']:
                    resp = self._send_request(endpoint_url, method=method, json_data=payload)
                    diff = self._compare_responses(baseline, resp, f"quantity_fraud_{method}_{list(payload.keys())[0]}")
                    if diff:
                        results['vulnerable'] = True
                        results['details']['fraud_found'] += 1
                        results['findings'].append({
                            'type': 'quantity_fraud',
                            'endpoint': endpoint,
                            'method': method,
                            'payload': payload,
                            'difference': diff,
                            'severity': 'high',
                        })

        print(f"{GREEN}[BizLogic] Quantity Fraud: {results['details']['fraud_found']} issues found{RESET}")
        return results

    # ========================================================================
    # SCAN: Privilege Escalation via Business Logic
    # ========================================================================

    def test_privilege_escalation(self, url=None):
        """Test for privilege escalation via business logic flaws"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_privilege_escalation'}

        print(f"{MAGENTA}{BOLD}[BizLogic] Privilege Escalation Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'escalation_found': 0,
            },
            'scan_type': 'bizlogic_privilege_escalation',
        }

        # Test user/profile endpoints with escalation payloads
        user_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                         if any(kw in e for kw in ['user', 'profile', 'account', 'settings'])]

        for endpoint in user_endpoints[:8]:
            endpoint_url = f"{base}{endpoint}"
            baseline = self._send_request(endpoint_url, method="GET")
            if not baseline:
                continue

            results['details']['endpoints_tested'].append(endpoint)

            for payload in PRIVILEGE_ESCALATION_PAYLOADS[:10]:
                for method in ['POST', 'PUT', 'PATCH']:
                    resp = self._send_request(endpoint_url, method=method, json_data=payload)
                    diff = self._compare_responses(baseline, resp, f"priv_esc_{method}_{list(payload.keys())[0]}")
                    if diff:
                        # Verify it's not just a generic error
                        if resp and resp.status_code in [200, 201]:
                            results['vulnerable'] = True
                            results['details']['escalation_found'] += 1
                            results['findings'].append({
                                'type': 'privilege_escalation',
                                'endpoint': endpoint,
                                'method': method,
                                'payload': payload,
                                'difference': diff,
                                'severity': 'critical',
                            })

        # Test role-specific endpoints
        for endpoint in ROLE_ESCALATION_ENDPOINTS[:5]:
            endpoint_url = f"{base}{endpoint}"
            for payload in PRIVILEGE_ESCALATION_PAYLOADS[:5]:
                resp = self._send_request(endpoint_url, method="POST", json_data=payload)
                if resp and resp.status_code in [200, 201]:
                    results['vulnerable'] = True
                    results['details']['escalation_found'] += 1
                    results['findings'].append({
                        'type': 'privilege_escalation',
                        'endpoint': endpoint,
                        'method': 'POST',
                        'payload': payload,
                        'status_code': resp.status_code,
                        'severity': 'critical',
                    })

        print(f"{GREEN}[BizLogic] Privilege Escalation: {results['details']['escalation_found']} issues found{RESET}")
        return results

    # ========================================================================
    # SCAN: Payment Bypass Testing
    # ========================================================================

    def test_payment_bypass(self, url=None):
        """Test for payment bypass vulnerabilities"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_payment_bypass'}

        print(f"{RED}{BOLD}[BizLogic] Payment Bypass Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'bypass_found': 0,
            },
            'scan_type': 'bizlogic_payment_bypass',
        }

        payment_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                            if any(kw in e for kw in ['payment', 'checkout', 'order'])]

        for endpoint in payment_endpoints[:8]:
            endpoint_url = f"{base}{endpoint}"
            baseline = self._send_request(endpoint_url, method="GET")
            if not baseline:
                continue

            results['details']['endpoints_tested'].append(endpoint)

            for payload in PAYMENT_BYPASS_PAYLOADS:
                for method in ['POST', 'PUT', 'PATCH']:
                    resp = self._send_request(endpoint_url, method=method, json_data=payload)
                    diff = self._compare_responses(baseline, resp, f"payment_bypass_{method}_{list(payload.keys())[0]}")
                    if diff:
                        # Check for payment success indicators
                        if resp and resp.status_code in [200, 201]:
                            success_words = ['success', 'completed', 'paid', 'approved', 'confirmed']
                            if any(w in resp.text.lower() for w in success_words):
                                results['vulnerable'] = True
                                results['details']['bypass_found'] += 1
                                results['findings'].append({
                                    'type': 'payment_bypass',
                                    'endpoint': endpoint,
                                    'method': method,
                                    'payload': payload,
                                    'difference': diff,
                                    'severity': 'critical',
                                })

        print(f"{GREEN}[BizLogic] Payment Bypass: {results['details']['bypass_found']} issues found{RESET}")
        return results

    # ========================================================================
    # SCAN: Race Condition in Business Operations
    # ========================================================================

    def test_race_condition(self, url=None):
        """Test for race condition in business operations"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_race_condition'}

        print(f"{YELLOW}{BOLD}[BizLogic] Race Condition Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'race_found': 0,
            },
            'scan_type': 'bizlogic_race_condition',
        }

        race_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                         if any(kw in e for kw in ['payment', 'checkout', 'order', 'transfer',
                                                    'withdraw', 'deposit', 'coupon', 'discount'])]

        for endpoint in race_endpoints[:6]:
            endpoint_url = f"{base}{endpoint}"
            results['details']['endpoints_tested'].append(endpoint)

            # Test concurrent requests (race condition)
            num_concurrent = 10
            barrier = Event()
            responses = []
            responses_lock = Lock()

            def race_request():
                """Send concurrent request for race condition testing"""
                barrier.wait(timeout=5)
                try:
                    payload = {"amount": 100, "action": "process"}
                    resp = self._send_request(endpoint_url, method="POST", json_data=payload)
                    with responses_lock:
                        responses.append(resp)
                except Exception:
                    pass

            # Create threads
            threads = []
            for _ in range(num_concurrent):
                t = Thread(target=race_request)
                t.daemon = True
                threads.append(t)

            # Start all threads
            for t in threads:
                t.start()

            # Release barrier simultaneously
            time.sleep(0.1)
            barrier.set()

            # Wait for all threads
            for t in threads:
                t.join(timeout=self.timeout + 5)

            # Analyze responses
            successful_responses = [r for r in responses if r and r.status_code in [200, 201]]
            if len(successful_responses) > 1:
                # Multiple successes = potential race condition
                results['vulnerable'] = True
                results['details']['race_found'] += 1
                results['findings'].append({
                    'type': 'race_condition',
                    'endpoint': endpoint,
                    'concurrent_requests': num_concurrent,
                    'successful_responses': len(successful_responses),
                    'expected_successes': 1,
                    'severity': 'high',
                    'description': f'Race condition: {len(successful_responses)} successful responses out of {num_concurrent} concurrent requests',
                })

            # Test coupon/discount race condition specifically
            coupon_payload = {"coupon": "RACE_TEST", "discount": 50}
            coupon_responses = []
            coupon_barrier = Event()

            def coupon_race():
                coupon_barrier.wait(timeout=5)
                try:
                    resp = self._send_request(endpoint_url, method="POST", json_data=coupon_payload)
                    with responses_lock:
                        coupon_responses.append(resp)
                except Exception:
                    pass

            threads = []
            for _ in range(num_concurrent):
                t = Thread(target=coupon_race)
                t.daemon = True
                threads.append(t)
            for t in threads:
                t.start()
            time.sleep(0.1)
            coupon_barrier.set()
            for t in threads:
                t.join(timeout=self.timeout + 5)

            coupon_successes = [r for r in coupon_responses if r and r.status_code in [200, 201]]
            if len(coupon_successes) > 1:
                results['vulnerable'] = True
                results['details']['race_found'] += 1
                results['findings'].append({
                    'type': 'coupon_race_condition',
                    'endpoint': endpoint,
                    'concurrent_requests': num_concurrent,
                    'successful_responses': len(coupon_successes),
                    'severity': 'high',
                    'description': f'Coupon race: {len(coupon_successes)} successful coupon applications',
                })

        print(f"{GREEN}[BizLogic] Race Condition: {results['details']['race_found']} issues found{RESET}")
        return results

    # ========================================================================
    # SCAN: Discount/Coupon Abuse Detection
    # ========================================================================

    def test_discount_abuse(self, url=None):
        """Test for discount/coupon abuse vulnerabilities"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_discount_abuse'}

        print(f"{CYAN}{BOLD}[BizLogic] Discount/Coupon Abuse Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'abuse_found': 0,
            },
            'scan_type': 'bizlogic_discount_abuse',
        }

        discount_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                             if any(kw in e for kw in ['discount', 'coupon', 'promo', 'voucher', 'cart', 'checkout'])]

        for endpoint in discount_endpoints[:8]:
            endpoint_url = f"{base}{endpoint}"
            baseline = self._send_request(endpoint_url, method="GET")
            if not baseline:
                continue

            results['details']['endpoints_tested'].append(endpoint)

            for payload in DISCOUNT_ABUSE_PAYLOADS:
                for method in ['POST', 'PUT', 'PATCH']:
                    resp = self._send_request(endpoint_url, method=method, json_data=payload)
                    diff = self._compare_responses(baseline, resp, f"discount_abuse_{method}")
                    if diff:
                        results['vulnerable'] = True
                        results['details']['abuse_found'] += 1
                        results['findings'].append({
                            'type': 'discount_abuse',
                            'endpoint': endpoint,
                            'method': method,
                            'payload': payload,
                            'difference': diff,
                            'severity': 'high',
                        })

        # Test stacking multiple coupons
        stack_payload = {
            "coupons": ["COUPON1", "COUPON2", "COUPON3"],
            "discount": 300,
            "apply_all": True,
        }
        for endpoint in discount_endpoints[:3]:
            endpoint_url = f"{base}{endpoint}"
            resp = self._send_request(endpoint_url, method="POST", json_data=stack_payload)
            if resp and resp.status_code in [200, 201]:
                results['vulnerable'] = True
                results['details']['abuse_found'] += 1
                results['findings'].append({
                    'type': 'coupon_stacking',
                    'endpoint': endpoint,
                    'method': 'POST',
                    'payload': stack_payload,
                    'severity': 'high',
                })

        print(f"{GREEN}[BizLogic] Discount Abuse: {results['details']['abuse_found']} issues found{RESET}")
        return results

    # ========================================================================
    # SCAN: Cart Manipulation Testing
    # ========================================================================

    def test_cart_manipulation(self, url=None):
        """Test for cart manipulation vulnerabilities"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_cart_manipulation'}

        print(f"{YELLOW}{BOLD}[BizLogic] Cart Manipulation Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'manipulation_found': 0,
            },
            'scan_type': 'bizlogic_cart_manipulation',
        }

        cart_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                         if any(kw in e for kw in ['cart', 'checkout', 'order'])]

        for endpoint in cart_endpoints[:8]:
            endpoint_url = f"{base}{endpoint}"
            baseline = self._send_request(endpoint_url, method="GET")
            if not baseline:
                continue

            results['details']['endpoints_tested'].append(endpoint)

            for payload in CART_MANIPULATION_PAYLOADS:
                for method in ['POST', 'PUT', 'PATCH']:
                    resp = self._send_request(endpoint_url, method=method, json_data=payload)
                    diff = self._compare_responses(baseline, resp, f"cart_manipulation_{method}")
                    if diff:
                        results['vulnerable'] = True
                        results['details']['manipulation_found'] += 1
                        results['findings'].append({
                            'type': 'cart_manipulation',
                            'endpoint': endpoint,
                            'method': method,
                            'payload': payload,
                            'difference': diff,
                            'severity': 'high',
                        })

        # Test IDOR-style cart access
        idor_payloads = [
            {"cart_id": "1"},
            {"cart_id": "2"},
            {"cart_id": "0001"},
            {"user_id": "1"},
            {"user_id": "admin"},
            {"order_id": "1"},
        ]
        for endpoint in cart_endpoints[:3]:
            endpoint_url = f"{base}{endpoint}"
            for payload in idor_payloads:
                resp = self._send_request(endpoint_url, method="POST", json_data=payload)
                if resp and resp.status_code in [200, 201]:
                    results['vulnerable'] = True
                    results['details']['manipulation_found'] += 1
                    results['findings'].append({
                        'type': 'cart_idor',
                        'endpoint': endpoint,
                        'method': 'POST',
                        'payload': payload,
                        'severity': 'high',
                    })

        print(f"{GREEN}[BizLogic] Cart Manipulation: {results['details']['manipulation_found']} issues found{RESET}")
        return results

    # ========================================================================
    # SCAN: Role Escalation Detection
    # ========================================================================

    def test_role_escalation(self, url=None):
        """Test for user role escalation via API manipulation"""
        base = self._get_base_url(url)
        if not base:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic_role_escalation'}

        print(f"{MAGENTA}{BOLD}[BizLogic] Role Escalation Test: {base}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': base,
                'timestamp': datetime.now().isoformat(),
                'endpoints_tested': [],
                'escalation_found': 0,
            },
            'scan_type': 'bizlogic_role_escalation',
        }

        # Test user update endpoints with role modification
        user_endpoints = [e for e in BUSINESS_API_ENDPOINTS
                         if any(kw in e for kw in ['user', 'profile', 'account', 'settings'])]

        role_payloads = [
            {"role": "admin"},
            {"role": "administrator"},
            {"role": "superadmin"},
            {"is_admin": True},
            {"is_admin": 1},
            {"user_type": "admin"},
            {"user_role": "admin"},
            {"permissions": ["admin", "read", "write", "delete"]},
            {"access_level": 999},
            {"group": "admin"},
        ]

        for endpoint in user_endpoints[:8]:
            endpoint_url = f"{base}{endpoint}"
            baseline = self._send_request(endpoint_url, method="GET")
            if not baseline:
                continue

            results['details']['endpoints_tested'].append(endpoint)

            for payload in role_payloads:
                for method in ['PUT', 'PATCH']:
                    resp = self._send_request(endpoint_url, method=method, json_data=payload)
                    if resp and resp.status_code in [200, 201]:
                        # Check if role was actually changed
                        diff = self._compare_responses(baseline, resp, f"role_esc_{method}")
                        if diff:
                            results['vulnerable'] = True
                            results['details']['escalation_found'] += 1
                            results['findings'].append({
                                'type': 'role_escalation',
                                'endpoint': endpoint,
                                'method': method,
                                'payload': payload,
                                'difference': diff,
                                'severity': 'critical',
                            })

        # Test admin endpoints with regular user session
        for endpoint in ROLE_ESCALATION_ENDPOINTS[:5]:
            endpoint_url = f"{base}{endpoint}"
            resp = self._send_request(endpoint_url, method="GET")
            if resp and resp.status_code == 200:
                results['vulnerable'] = True
                results['details']['escalation_found'] += 1
                results['findings'].append({
                    'type': 'role_escalation_access',
                    'endpoint': endpoint,
                    'method': 'GET',
                    'status_code': 200,
                    'description': 'Admin endpoint accessible without admin privileges',
                    'severity': 'critical',
                })

        print(f"{GREEN}[BizLogic] Role Escalation: {results['details']['escalation_found']} issues found{RESET}")
        return results

    # ========================================================================
    # MAIN ENTRY POINT
    # ========================================================================

    def run(self, target=None, scan_type='full', **kwargs):
        """Main entry point for BizLogic Engine"""
        url = target or self.target_url
        if not url:
            return {'vulnerable': False, 'findings': [], 'details': {'error': 'no_target'}, 'scan_type': 'bizlogic'}

        scan_methods = {
            'full': lambda: self._full_scan(url),
            'price': lambda: self.test_price_manipulation(url),
            'quantity': lambda: self.test_quantity_fraud(url),
            'privilege': lambda: self.test_privilege_escalation(url),
            'payment': lambda: self.test_payment_bypass(url),
            'race': lambda: self.test_race_condition(url),
            'discount': lambda: self.test_discount_abuse(url),
            'cart': lambda: self.test_cart_manipulation(url),
            'role': lambda: self.test_role_escalation(url),
        }

        if scan_type in scan_methods:
            return scan_methods[scan_type]()
        return self._full_scan(url)

    def _full_scan(self, url):
        """Full business logic vulnerability scan"""
        print(f"{RED}{BOLD}[BizLogic] Full Scan: {url}{RESET}")
        results = {
            'vulnerable': False,
            'findings': [],
            'details': {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'phases_completed': [],
                'total_issues': 0,
            },
            'scan_type': 'bizlogic_full',
        }

        # Phase 1: Price Manipulation
        print(f"{CYAN}  [Phase 1/7] Price Manipulation...{RESET}")
        price_result = self.test_price_manipulation(url)
        results['findings'].extend(price_result.get('findings', []))
        results['details']['phases_completed'].append('price_manipulation')

        # Phase 2: Quantity Fraud
        print(f"{CYAN}  [Phase 2/7] Quantity Fraud...{RESET}")
        qty_result = self.test_quantity_fraud(url)
        results['findings'].extend(qty_result.get('findings', []))
        results['details']['phases_completed'].append('quantity_fraud')

        # Phase 3: Privilege Escalation
        print(f"{CYAN}  [Phase 3/7] Privilege Escalation...{RESET}")
        priv_result = self.test_privilege_escalation(url)
        results['findings'].extend(priv_result.get('findings', []))
        results['details']['phases_completed'].append('privilege_escalation')

        # Phase 4: Payment Bypass
        print(f"{CYAN}  [Phase 4/7] Payment Bypass...{RESET}")
        pay_result = self.test_payment_bypass(url)
        results['findings'].extend(pay_result.get('findings', []))
        results['details']['phases_completed'].append('payment_bypass')

        # Phase 5: Race Condition
        print(f"{CYAN}  [Phase 5/7] Race Condition...{RESET}")
        race_result = self.test_race_condition(url)
        results['findings'].extend(race_result.get('findings', []))
        results['details']['phases_completed'].append('race_condition')

        # Phase 6: Discount Abuse
        print(f"{CYAN}  [Phase 6/7] Discount/Coupon Abuse...{RESET}")
        disc_result = self.test_discount_abuse(url)
        results['findings'].extend(disc_result.get('findings', []))
        results['details']['phases_completed'].append('discount_abuse')

        # Phase 7: Cart Manipulation
        print(f"{CYAN}  [Phase 7/7] Cart Manipulation...{RESET}")
        cart_result = self.test_cart_manipulation(url)
        results['findings'].extend(cart_result.get('findings', []))
        results['details']['phases_completed'].append('cart_manipulation')

        # Summary
        results['details']['total_issues'] = len(results['findings'])
        if results['findings']:
            results['vulnerable'] = True

        print(f"{GREEN}[BizLogic] Full scan complete: {results['details']['total_issues']} total issues{RESET}")
        return results


# ============================================================================
# MODULE-LEVEL RUN FUNCTION
# ============================================================================

def run(target, scan_type='full', **kwargs):
    """Module-level entry point for BizLogic Engine"""
    engine = BizLogicEngine(
        target_url=target,
        headers=kwargs.get('headers'),
        cookies=kwargs.get('cookies'),
        proxy=kwargs.get('proxy'),
        timeout=kwargs.get('timeout', 10),
        threads=kwargs.get('threads', 10),
        auth_token=kwargs.get('auth_token'),
    )
    return engine.run(target=target, scan_type=scan_type, **kwargs)
